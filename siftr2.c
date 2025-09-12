/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007-2009
 * 	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010, The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by Lawrence Stewart under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/******************************************************
 * Statistical Information For TCP Research (SIFTR2)
 *
 * A FreeBSD kernel module that adds very basic intrumentation to the
 * TCP stack, allowing internal stats to be recorded to a log file
 * for experimental, debugging and performance analysis purposes.
 ******************************************************/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf_ring.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/hash.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/sbuf.h>
#include <sys/sdt.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/tim_filter.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <machine/atomic.h>
#include <machine/in_cksum.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_kdtrace.h>
#include <netinet/in_fib.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_hpts.h>
#include <netinet/cc/cc.h>
#include <netinet/cc/cc_newreno.h>
#include <netinet/tcp_stacks/sack_filter.h>
#include <netinet/tcp_stacks/tcp_rack.h>

/*
 * The version number X.Y refers:
 * X is the major version number and Y has backward compatible changes
 */
#define MODVERSION	__CONCAT(2,2)
#define MODVERSION_STR	__XSTRING(2) "." __XSTRING(2)
#define SYS_NAME "FreeBSD"

enum {
	HOOK = 0, UNHOOK = 1, SIFTR_DISABLE = 0, SIFTR_ENABLE = 1,
	SIFTR_IPMODE = 4, SIFTR_EXPECTED_MAX_TCP_FLOWS = 65536,
	SIFTR_LOG_FILE_MODE = 0644, RING_SIZE = 65536, BATCHBUF_SIZE = 4096,
	/*
	 * Hard upper limit on the length of log messages. Bump this up if you
	 * add new data fields such that the line length could exceed the below
	 * value.
	 */
	MAX_LOG_MSG_LEN = 200,
};

static MALLOC_DEFINE(M_SIFTR, "siftr2", "ring buffer used by SIFTR2");
static MALLOC_DEFINE(M_SIFTR_PKTNODE, "siftr2_pktnode", "SIFTR2 pkt_node struct");
static MALLOC_DEFINE(M_SIFTR_FLOW_INFO, "siftr2_flow_info", "SIFTR2 flow_info struct");
static MALLOC_DEFINE(M_SIFTR_HASHNODE, "siftr2_hashnode", "SIFTR2 flow_hash_node struct");

/* siftr2_pktnode: used as links in the pkt manager queue. */
struct pkt_node {
	/* Direction pkt is travelling. */
	enum {
		DIR_IN = 0,
		DIR_OUT = 1,
	}			direction;
	/* Timestamp of pkt as noted in the pfil hook. */
	struct timeval		tval;
	/* Flowid for the connection. */
	uint32_t		flowid;
	/* Congestion Window (bytes). */
	uint32_t		snd_cwnd;
	/* Slow Start Threshold (bytes). */
	uint32_t		snd_ssthresh;
	/* Sending Window (bytes). */
	uint32_t		snd_wnd;
	/* Receive Window (bytes). */
	uint32_t		rcv_wnd;
	/* TCP control block flags. */
	u_int			t_flags;
	/* More tcpcb flags storage */
	u_int			t_flags2;
	/* Current state of the TCP FSM. */
	uint8_t			conn_state;
	/* Smoothed RTT (usecs). */
	uint32_t		srtt;
	/* Retransmission timeout (usec). */
	uint32_t		rto;
	/* Size of the TCP send buffer in bytes. */
	u_int			snd_buf_hiwater;
	/* Current num bytes in the send socket buffer. */
	u_int			snd_buf_cc;
	/* Size of the TCP receive buffer in bytes. */
	u_int			rcv_buf_hiwater;
	/* Current num bytes in the receive socket buffer. */
	u_int			rcv_buf_cc;
	/* Number of bytes inflight that we are waiting on ACKs for. */
	uint32_t		pipe;
	/* Number of segments currently in the reassembly queue. */
	int			t_segqlen;
	/* Flow type for the connection. */
	/* TCP sequence number */
	tcp_seq			th_seq;
	/* TCP acknowledgement number */
	tcp_seq			th_ack;
	/* the length of TCP segment payload in bytes */
	uint32_t		data_sz;
};

struct flow_info
{
	/* permanent info */
	char	laddr[INET_ADDRSTRLEN];		/* local IP address */
	char	faddr[INET_ADDRSTRLEN];		/* foreign IP address */
	uint16_t	lport;			/* local TCP port */
	uint16_t	fport;			/* foreign TCP port */
	uint32_t	key;			/* flowid of the connection */
	uint8_t		ipver;			/* IP version */
	uint32_t	flowtype;		/* Flow type for the connection. */

	/* infrequently change info */
	enum {
		FBSD = 0,
		RACK = 1,
	}		stack_type;		/* net stack name: freebsd or rack */
	enum {
		CUBIC = 0,
		NEWRENO = 1,
	}		tcp_cc;			/* TCP congestion control name */
	uint32_t	mss;			/* Max Segment Size (bytes). */
	u_char		sack_enabled;		/* Is SACK enabled? */
	u_char		snd_scale;		/* Window scaling for snd window. */
	u_char		rcv_scale;		/* Window scaling for recv window. */

	uint32_t	nrecord;		/* num of records in the log */
	uint32_t	ntrans;			/* num of all transfers (in/out) */
};

/* siftr2_hashnode */
struct flow_hash_node
{
	uint16_t counter;
	uint32_t last_cwnd;
	struct flow_info const_info;
	LIST_ENTRY(flow_hash_node) nodes;
};

static volatile bool siftr_exit_pkt_manager_thread = 0;
static bool     siftr_enabled = 0;
static bool     siftr_cwnd_filter = 0;
static uint16_t siftr_port_filter = 0;
static uint32_t siftr_pkts_per_log = 1;

static struct buf_ring *siftr_br = NULL;
static struct vnode *siftr_vnode = NULL;
static struct ucred *siftr_vnode_cred = NULL;

static uint32_t siftr_ring_drops = 0;	/* producer drops when full */
static uint32_t max_str_size = 0;
static uint32_t global_flow_cnt = 0;
static uint32_t gen_flowid_cnt = 0;	/* count of generating flowid */

static char siftr_logfile[PATH_MAX] = "/var/log/siftr2.log";
static char siftr_logfile_shadow[PATH_MAX] = "/var/log/siftr2.log";
static u_long siftr_hashmask;
LIST_HEAD(listhead, flow_hash_node) *counter_hash;
static struct mtx siftr_pkt_mgr_mtx;
static struct thread *siftr_pkt_manager_thr = NULL;
static char direction[2] = {'i','o'};
static eventhandler_tag siftr_shutdown_tag;
static int wait_for_pkt;

/* Required function prototypes. */
static int siftr_sysctl_enabled_handler(SYSCTL_HANDLER_ARGS);
static int siftr_sysctl_logfile_name_handler(SYSCTL_HANDLER_ARGS);
static int siftr_open_log(struct thread *td);
static int siftr_write_log(struct thread *td, char *buf, size_t len);

/* Declare the net.inet.siftr2 sysctl tree and populate it. */

SYSCTL_DECL(_net_inet_siftr2);

SYSCTL_NODE(_net_inet, OID_AUTO, siftr2, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "siftr2 related settings");

SYSCTL_PROC(_net_inet_siftr2, OID_AUTO, enabled,
    CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    &siftr_enabled, 0, &siftr_sysctl_enabled_handler, "IU",
    "switch siftr2 module operations on/off");

SYSCTL_PROC(_net_inet_siftr2, OID_AUTO, logfile,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_NEEDGIANT, &siftr_logfile_shadow,
    sizeof(siftr_logfile_shadow), &siftr_sysctl_logfile_name_handler, "A",
    "file to save siftr2 log messages to");

SYSCTL_UINT(_net_inet_siftr2, OID_AUTO, ppl, CTLFLAG_RW,
    &siftr_pkts_per_log, 1,
    "number of packets between generating a log message");

SYSCTL_U16(_net_inet_siftr2, OID_AUTO, port_filter, CTLFLAG_RW,
    &siftr_port_filter, 0,
    "enable packet filter on a TCP port");

SYSCTL_BOOL(_net_inet_siftr2, OID_AUTO, cwnd_filter, CTLFLAG_RW,
    &siftr_cwnd_filter, 0,
    "enable packet filter to record only variance of TCP congestion window");

/* Begin functions. */

static inline struct flow_hash_node *
siftr_find_flow(struct listhead *counter_list, uint32_t id)
{
	struct flow_hash_node *hash_node;
	/*
	 * If the list is not empty i.e. the hash index has
	 * been used by another flow previously.
	 */
	if (LIST_FIRST(counter_list) != NULL) {
		/*
		 * Loop through the hash nodes in the list.
		 * There should normally only be 1 hash node in the list.
		 */
		LIST_FOREACH(hash_node, counter_list, nodes) {
			/*
			 * Check if the key for the pkt we are currently
			 * processing is the same as the key stored in the
			 * hash node we are currently processing.
			 * If they are the same, then we've found the
			 * hash node that stores the counter for the flow
			 * the pkt belongs to.
			 */
			if (hash_node->const_info.key == id) {
				return hash_node;
			}
		}
	}

	return NULL;
}

static inline struct flow_hash_node *
siftr_new_hash_node(struct flow_info info)
{
	struct flow_hash_node *hash_node;
	struct listhead *counter_list;

	counter_list = counter_hash + (info.key & siftr_hashmask);
	/* Create a new hash node to store the flow's constant info. */
	hash_node = malloc(sizeof(struct flow_hash_node), M_SIFTR_HASHNODE,
			   M_NOWAIT|M_ZERO);

	if (hash_node != NULL) {
		/* Initialise our new hash node list entry. */
		hash_node->counter = 0;
		hash_node->last_cwnd = 0;
		hash_node->const_info = info;
		LIST_INSERT_HEAD(counter_list, hash_node, nodes);
		global_flow_cnt++;
		return hash_node;
	} else {
		panic("%s: malloc failed", __func__);
		return NULL;
	}
}

static int
siftr_process_pkt(struct pkt_node * pkt_node, char buf[])
{
	struct flow_hash_node *hash_node;
	struct listhead *counter_list;
	int ret_sz;

	if (pkt_node->flowid == 0) {
		panic("%s: flowid not available", __func__);
	}

	counter_list = counter_hash + (pkt_node->flowid & siftr_hashmask);
	hash_node = siftr_find_flow(counter_list, pkt_node->flowid);

	if (hash_node == NULL) {
		panic("%s: hash_node == NULL", __func__);
	}

	hash_node->const_info.ntrans++;

	if (siftr_cwnd_filter) {
		/* Check if we have a variance of the cwnd to record. */
		if (hash_node->last_cwnd == pkt_node->snd_cwnd) {
			if (siftr_pkts_per_log > 1) {
				/*
				 * Taking the remainder of the counter divided
				 * by the current value of siftr_pkts_per_log
				 * and storing that in counter provides a neat
				 * way to modulate the frequency of log
				 * messages being written to the log file.
				 */
				hash_node->counter = (hash_node->counter + 1) %
						     siftr_pkts_per_log;
				/*
				 * If we have not seen enough packets since the
				 * last time we wrote a log message for this
				 * connection, return.
				 */
				if (hash_node->counter > 0) {
					return (0);
				}
			} else {
				return (0);
			}
		} else {
			hash_node->last_cwnd = pkt_node->snd_cwnd;
			hash_node->counter = 0;
		}
	} else if (siftr_pkts_per_log > 1) {
		hash_node->counter = (hash_node->counter + 1) %
				     siftr_pkts_per_log;
		if (hash_node->counter > 0) {
			return (0);
		}
	}

	hash_node->const_info.nrecord++;

	/* Construct a log message.
	 * cc xxx: check vasprintf()? */
	ret_sz = sprintf(buf,
	    "%c,%jd.%06ld,%08x,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
	    "%u,%u\n",
	    direction[pkt_node->direction],
	    (intmax_t)pkt_node->tval.tv_sec,
	    pkt_node->tval.tv_usec,
	    pkt_node->flowid,
	    pkt_node->snd_cwnd,
	    pkt_node->snd_ssthresh,
	    pkt_node->snd_wnd,
	    pkt_node->rcv_wnd,
	    pkt_node->t_flags,
	    pkt_node->t_flags2,
	    pkt_node->conn_state,
	    pkt_node->srtt,
	    pkt_node->rto,
	    pkt_node->snd_buf_hiwater,
	    pkt_node->snd_buf_cc,
	    pkt_node->rcv_buf_hiwater,
	    pkt_node->rcv_buf_cc,
	    pkt_node->pipe,
	    pkt_node->t_segqlen,
	    pkt_node->th_seq,
	    pkt_node->th_ack,
	    pkt_node->data_sz);

	if (ret_sz >= MAX_LOG_MSG_LEN) {
		panic("%s: record size %d larger than max record size %d",
		      __func__, ret_sz, MAX_LOG_MSG_LEN);
	} else if (ret_sz < 0) {
		panic("%s: an encoding error occurred, return value %d",
		      __func__, ret_sz);
	}

	return (ret_sz);
}

static void
siftr_pkt_manager_thread(void *arg)
{
	struct pkt_node *pn;
	uint8_t draining = 2;
	char batchbuf[BATCHBUF_SIZE];
	size_t batchlen = 0;
	int linelen = 0;

	mtx_lock(&siftr_pkt_mgr_mtx);
	while (draining) {
		/* Sleep briefly or until signaled; allow wakeups from producer */
		mtx_sleep(&wait_for_pkt, &siftr_pkt_mgr_mtx, PWAIT, "pktwait", 1);
		mtx_unlock(&siftr_pkt_mgr_mtx);

		/* Drain all available packets in the ring */
		while ((pn = buf_ring_dequeue_sc(siftr_br)) != NULL) {
			/* Ensure there is room for at least one full record */
			if (batchlen + MAX_LOG_MSG_LEN > BATCHBUF_SIZE) {
				siftr_write_log(curthread, batchbuf, batchlen);
				batchlen = 0;
			}

			linelen = siftr_process_pkt(pn, &batchbuf[batchlen]);
			batchlen += linelen;
			if (max_str_size < linelen) {
				max_str_size = linelen;
			}
			free(pn, M_SIFTR_PKTNODE);
		}

		/* Flush any accumulated batch if idle */
		if (batchlen > 0) {
			siftr_write_log(curthread, batchbuf, batchlen);
			batchlen = 0;
		}

		mtx_lock(&siftr_pkt_mgr_mtx);
		if (siftr_exit_pkt_manager_thread)
			draining--;
	}
	mtx_unlock(&siftr_pkt_mgr_mtx);
	kthread_exit();
}

/*
 * Look up an inpcb for a packet. Return the inpcb pointer if found, or NULL
 * otherwise.
 */
static inline struct inpcb *
siftr_findinpcb(struct ip *ip, struct mbuf *m, uint16_t sport, uint16_t dport,
		int dir)
{
	struct inpcb *inp;

	/* We need the tcbinfo lock. */
	INP_INFO_WUNLOCK_ASSERT(&V_tcbinfo);

	if (dir == PFIL_IN)
		inp = in_pcblookup(&V_tcbinfo, ip->ip_src, sport, ip->ip_dst,
				   dport, INPLOOKUP_RLOCKPCB, m->m_pkthdr.rcvif);

	else
		inp = in_pcblookup(&V_tcbinfo, ip->ip_dst, dport, ip->ip_src,
				   sport, INPLOOKUP_RLOCKPCB, m->m_pkthdr.rcvif);

	/* If we can't find the inpcb, bail. */
	return (inp);
}

static inline uint32_t
siftr_get_flowid(struct inpcb *inp, uint32_t *phashtype)
{
	if (inp->inp_flowid == 0) {
		gen_flowid_cnt++;
		return fib4_calc_packet_hash(inp->inp_laddr, inp->inp_faddr,
					     inp->inp_lport, inp->inp_fport,
					     IPPROTO_TCP, phashtype);
	} else {
		*phashtype = inp->inp_flowtype;
		return inp->inp_flowid;
	}
}

static inline void
siftr_siftdata(struct pkt_node *pn, struct inpcb *inp, struct tcpcb *tp,
	       int dir, int inp_locally_locked, struct ip *ip,
	       struct flow_hash_node *hash_node)
{
	struct tcphdr *th = (struct tcphdr *)((caddr_t)ip + (ip->ip_hl << 2));

	pn->snd_cwnd = tp->snd_cwnd;
	pn->snd_wnd = tp->snd_wnd;
	pn->rcv_wnd = tp->rcv_wnd;
	pn->t_flags2 = tp->t_flags2;
	pn->snd_ssthresh = tp->snd_ssthresh;
	pn->conn_state = tp->t_state;

	if (hash_node->const_info.stack_type == FBSD) {
		pn->srtt = ((uint64_t)tp->t_srtt * tick) >> TCP_RTT_SHIFT;
	} else if (hash_node->const_info.stack_type == RACK) {
		struct tcp_rack *rack = (struct tcp_rack *)tp->t_fb_ptr;
		pn->srtt = rack->rc_rack_rtt;
	}
	pn->t_flags = tp->t_flags;
	pn->rto = tp->t_rxtcur * tick;
	pn->snd_buf_hiwater = inp->inp_socket->so_snd.sb_hiwat;
	pn->snd_buf_cc = sbused(&inp->inp_socket->so_snd);
	pn->rcv_buf_hiwater = inp->inp_socket->so_rcv.sb_hiwat;
	pn->rcv_buf_cc = sbused(&inp->inp_socket->so_rcv);
	pn->pipe = tcp_compute_pipe(tp);
	pn->t_segqlen = tp->t_segqlen;

	/* We've finished accessing the tcb so release the lock. */
	if (inp_locally_locked)
		INP_RUNLOCK(inp);

	pn->direction = (dir == PFIL_IN ? DIR_IN : DIR_OUT);
	pn->flowid = hash_node->const_info.key;
	pn->th_seq = ntohl(th->th_seq);
	pn->th_ack = ntohl(th->th_ack);
	pn->data_sz = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (th->th_off << 2);

	/*
	 * Significantly more accurate than using getmicrotime(), but slower!
	 * Gives true microsecond resolution at the expense of a hit to
	 * maximum pps throughput processing when SIFTR is loaded and enabled.
	 */
	microtime(&pn->tval);
}

/*
 * pfil hook that is called for each IPv4 packet making its way through the
 * stack in either direction.
 * The pfil subsystem holds a non-sleepable mutex somewhere when
 * calling our hook function, so we can't sleep at all.
 * It's very important to use the M_NOWAIT flag with all function calls
 * that support it so that they won't sleep, otherwise you get a panic.
 */
static pfil_return_t
siftr_chkpkt(struct mbuf **m, struct ifnet *ifp, int flags,
    void *ruleset __unused, struct inpcb *inp)
{
	struct pkt_node *pn;
	struct ip *ip;
	struct tcphdr *th;
	struct tcpcb *tp;
	int inp_locally_locked, dir;
	uint32_t hash_id, hash_type;
	struct listhead *counter_list;
	struct flow_hash_node *hash_node;

	inp_locally_locked = 0;
	dir = PFIL_DIR(flags);

	/*
	 * m_pullup is not required here because ip_{input|output}
	 * already do the heavy lifting for us.
	 */

	ip = mtod(*m, struct ip *);

	/* Only continue processing if the packet is TCP. */
	if (ip->ip_p != IPPROTO_TCP)
		goto ret;

	/*
	 * Create a tcphdr struct starting at the correct offset
	 * in the IP packet. ip->ip_hl gives the ip header length
	 * in 4-byte words, so multiply it to get the size in bytes.
	 */
	th = (struct tcphdr *)((caddr_t)ip + (ip->ip_hl << 2));

	/*
	 * Only pkts selected by the tcp port filter
	 * can be inserted into the pkt_queue
	 */
	if ((siftr_port_filter != 0) &&
	    (siftr_port_filter != ntohs(th->th_sport)) &&
	    (siftr_port_filter != ntohs(th->th_dport))) {
		goto ret;
	}

	/*
	 * If the pfil hooks don't provide a pointer to the
	 * inpcb, we need to find it ourselves and lock it.
	 */
	if (inp == NULL) {
		/* Find the corresponding inpcb for this pkt. */
		inp = siftr_findinpcb(ip, *m, th->th_sport, th->th_dport, dir);

		if (inp == NULL)
			goto ret;
		else
			inp_locally_locked = 1;
	}

	INP_LOCK_ASSERT(inp);

	/* Find the TCP control block that corresponds with this packet */
	tp = intotcpcb(inp);

	/*
	 * If we can't find the TCP control block (happens occasionaly for a
	 * packet sent during the shutdown phase of a TCP connection), or the
	 * TCP control block has not initialized (happens during TCPS_SYN_SENT),
	 * bail.
	 */
	if (tp == NULL || tp->t_state < TCPS_ESTABLISHED) {
		goto inp_unlock;
	}

	hash_id = siftr_get_flowid(inp, &hash_type);
	counter_list = counter_hash + (hash_id & siftr_hashmask);
	hash_node = siftr_find_flow(counter_list, hash_id);

	/* If this flow hasn't been seen before, we create a new entry. */
	if (hash_node == NULL) {
		struct flow_info info;

		inet_ntoa_r(inp->inp_laddr, info.laddr);
		inet_ntoa_r(inp->inp_faddr, info.faddr);
		info.lport = ntohs(inp->inp_lport);
		info.fport = ntohs(inp->inp_fport);
		info.key = hash_id;
		info.ipver = INP_IPV4;
		info.flowtype = hash_type;

		/* short hand for stack type check */
		if (tp->t_fb->tfb_tcp_block_name[0] == 'f') {
			info.stack_type = FBSD;
		} else if (tp->t_fb->tfb_tcp_block_name[0] == 'r') {
			info.stack_type = RACK;
		}
		/* short hand for TCP congestion control check */
		if (CC_ALGO(tp)->name[0] == 'c') {
			info.tcp_cc = CUBIC;
		} else if (CC_ALGO(tp)->name[0] == 'n') {
			info.tcp_cc = NEWRENO;
		}
		info.mss = tcp_maxseg(tp);
		info.sack_enabled = (tp->t_flags & TF_SACK_PERMIT) != 0;
		info.snd_scale = tp->snd_scale;
		info.rcv_scale = tp->rcv_scale;
		info.nrecord = 0;
		info.ntrans = 0;

		hash_node = siftr_new_hash_node(info);
	}

	if (hash_node == NULL) {
		goto inp_unlock;
	}
	pn = malloc(sizeof(struct pkt_node), M_SIFTR_PKTNODE, M_NOWAIT|M_ZERO);

	if (pn == NULL) {
		panic("%s: malloc failed", __func__);
		goto inp_unlock;
	}

	siftr_siftdata(pn, inp, tp, dir, inp_locally_locked, ip, hash_node);

	if (buf_ring_enqueue(siftr_br, pn) != 0) {
		/* drop if full */
		atomic_add_32(&siftr_ring_drops, 1);
		free(pn, M_SIFTR_PKTNODE);
	} else {
		/* nudge consumer */
		wakeup(&wait_for_pkt);
	}
	goto ret;

inp_unlock:
	if (inp_locally_locked)
		INP_RUNLOCK(inp);

ret:
	return (PFIL_PASS);
}


VNET_DEFINE_STATIC(pfil_hook_t, siftr_inet_hook);
#define	V_siftr_inet_hook	VNET(siftr_inet_hook)
static int
siftr_pfil(int action)
{
	struct pfil_hook_args pha = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN | PFIL_OUT,
		.pa_modname = "siftr2",
		.pa_rulname = "default",
	};
	struct pfil_link_args pla = {
		.pa_version = PFIL_VERSION,
		.pa_flags = PFIL_IN | PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR,
	};

	VNET_ITERATOR_DECL(vnet_iter);

	VNET_LIST_RLOCK();
	VNET_FOREACH(vnet_iter) {
		CURVNET_SET(vnet_iter);

		if (action == HOOK) {
			pha.pa_mbuf_chk = siftr_chkpkt;
			pha.pa_type = PFIL_TYPE_IP4;
			V_siftr_inet_hook = pfil_add_hook(&pha);
			pla.pa_hook = V_siftr_inet_hook;
			pla.pa_head = V_inet_pfil_head;
			(void)pfil_link(&pla);
		} else if (action == UNHOOK) {
			pfil_remove_hook(V_siftr_inet_hook);
		}
		CURVNET_RESTORE();
	}
	VNET_LIST_RUNLOCK();

	return (0);
}

static int
siftr_sysctl_logfile_name_handler(SYSCTL_HANDLER_ARGS)
{
	int error;

	error = sysctl_handle_string(oidp, arg1, arg2, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	/* Update active filename if changed */
	if (strncmp(siftr_logfile, arg1, arg2) != 0)
		strlcpy(siftr_logfile, arg1, arg2);
	return (0);
}

static int
compare_nrecord(const void *_a, const void *_b)
{
	const struct flow_info *a, *b;

	a = (const struct flow_info *)_a;
	b = (const struct flow_info *)_b;

	if (a->nrecord < b->nrecord)
		return (-1);
	else if (a->nrecord > b->nrecord)
		return (1);

	return (0);
}

/*
 * Open the log file for writing. The O_TRUNC flag will truncate the file to
 * zero length if the file already exists, effectively cleaning it. O_CREAT
 * creates the file if it does not already exist. UIO_SYSSPACE is used because
 * the data being written is in kernel space.
 */
static int
siftr_open_log(struct thread *td)
{
	struct file *fp;
	int err, flags;

	flags = FWRITE | O_NOFOLLOW | O_CREAT | O_TRUNC;
	if ((err = kern_openatfp(td, AT_FDCWD, siftr_logfile, UIO_SYSSPACE,
				 flags, SIFTR_LOG_FILE_MODE, &fp)) != 0) {
		printf("failed in kern_openatfp(), error %d\n", err);
		return (err);
	}

	siftr_vnode = fp->f_vnode;
	/* keep vnode around; increment ref */
	siftr_vnode_cred = crhold(td->td_ucred);

	return (err);
}

/* Write to logfile */
static int
siftr_write_log(struct thread *td, char *buf, size_t len)
{
	struct iovec iov;
	struct uio uio;
	struct mount *mp;
	int err;

	/* Set up uio for writing */
	iov.iov_base = buf;
	iov.iov_len = len;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = iov.iov_len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = td;

	/* Write the data */
	if ((err = vn_start_write(siftr_vnode, &mp, V_WAIT)) != 0) {
		printf("Failed in vn_start_write(): error %d\n", err);
		return err;
	}
	vn_lock(siftr_vnode, LK_EXCLUSIVE | LK_RETRY);
	if ((err = VOP_WRITE(siftr_vnode, &uio, IO_APPEND | IO_UNIT,
			     siftr_vnode_cred)) != 0) {
		printf("Failed in VOP_WRITE(): error %d\n", err);
	}
	VOP_UNLOCK(siftr_vnode);
	vn_finished_write(mp);

	return err;
}

static int
siftr_manage_ops(uint8_t action)
{
	struct timeval tval;
	struct flow_hash_node *counter, *tmp_counter;
	struct sbuf *s;
	int i, j, error;
	struct flow_info *arr;

	error = 0;
	arr = NULL;

	/* Init an autosizing sbuf that initially holds 200 chars. */
	if ((s = sbuf_new(NULL, NULL, 200, SBUF_AUTOEXTEND)) == NULL)
		return (ENOMEM);

	if (action == SIFTR_ENABLE && siftr_pkt_manager_thr == NULL) {
		/* Initialize buf_ring */
		siftr_br = buf_ring_alloc(RING_SIZE, M_SIFTR, M_NOWAIT, NULL);
		if (siftr_br == NULL) {
			return (ENOMEM);
		}

		if ((error = siftr_open_log(curthread)) != 0) {
			return error;
		}

		siftr_exit_pkt_manager_thread = 0;
		global_flow_cnt = siftr_ring_drops = max_str_size = gen_flowid_cnt = 0;

		kthread_add(&siftr_pkt_manager_thread, NULL, NULL,
		    &siftr_pkt_manager_thr, RFNOWAIT, 0,
		    "siftr_pkt_manager_thr");

		siftr_pfil(HOOK);

		microtime(&tval);

		sbuf_printf(s,
		    "enable_time_secs=%jd\tenable_time_usecs=%06ld\t"
		    "siftrver=%s\tsysname=%s\tsysver=%u\tipmode=%u\n",
		    (intmax_t)tval.tv_sec, tval.tv_usec, MODVERSION_STR,
		    SYS_NAME, __FreeBSD_version, SIFTR_IPMODE);

		sbuf_finish(s);
//		printf("%s", sbuf_data(s));
		error = siftr_write_log(curthread, sbuf_data(s), sbuf_len(s));
	} else if (action == SIFTR_DISABLE && siftr_pkt_manager_thr != NULL) {
		/*
		 * Remove the pfil hook functions. All threads currently in
		 * the hook functions are allowed to exit before siftr_pfil()
		 * returns.
		 */
		siftr_pfil(UNHOOK);

		/* This will block until the pkt manager thread unlocks it. */
		mtx_lock(&siftr_pkt_mgr_mtx);

		/* Tell the pkt manager thread that it should exit now. */
		siftr_exit_pkt_manager_thread = 1;

		/*
		 * Wake the pkt_manager thread so it realises that
		 * siftr_exit_pkt_manager_thread == 1 and exits gracefully.
		 * The wakeup won't be delivered until we unlock
		 * siftr_pkt_mgr_mtx so this isn't racy.
		 */
		wakeup(&wait_for_pkt);

		/* Wait for the pkt_manager thread to exit. */
		mtx_sleep(siftr_pkt_manager_thr, &siftr_pkt_mgr_mtx, PWAIT,
		    "thrwait", 0);

		siftr_pkt_manager_thr = NULL;
		mtx_unlock(&siftr_pkt_mgr_mtx);

		microtime(&tval);

		sbuf_printf(s,
		    "disable_time_secs=%jd\tdisable_time_usecs=%06ld\t"
		    "global_flow_cnt=%u\t"
		    "ring_drops=%u\tmax_str_size=%u\tgen_flowid_cnt=%u\t",
		    (intmax_t)tval.tv_sec, tval.tv_usec,
		    global_flow_cnt, siftr_ring_drops, max_str_size,
		    gen_flowid_cnt);

		/* Create an array to store all flows' keys and records. */
		arr = malloc(sizeof(struct flow_info) * global_flow_cnt,
			     M_SIFTR_FLOW_INFO, M_NOWAIT|M_ZERO);

		if (arr == NULL) {
			panic("%s: malloc failed for an array of flows", __func__);
		}
		/*
		 * Iterate over the flow hash, printing a summary of each
		 * flowid seen and freeing any malloc'd memory.
		 * The hash consists of an array of LISTs (man 3 queue).
		 */
		for (i = 0, j = 0; i <= siftr_hashmask; i++) {
			LIST_FOREACH_SAFE(counter, counter_hash + i, nodes,
			    tmp_counter) {
					arr[j++] = counter->const_info;
				free(counter, M_SIFTR_HASHNODE);
			}
			LIST_INIT(counter_hash + i);
		}

		if (j > global_flow_cnt) {
			panic("%s: arr[%d] overflow", __func__, j);
		}

		/* sort into ascending ordered list by flow's nrecord */
		qsort(arr, global_flow_cnt, sizeof(arr[0]), compare_nrecord);
		sbuf_printf(s, "flow_list=");
		for (j = 0; j < global_flow_cnt; j++) {
			sbuf_printf(s, "%08x,%s,%hu,%s,%hu,%d,%d,%u,%u,%u,%u,%u,%u;",
					arr[j].key,
					arr[j].laddr, arr[j].lport,
					arr[j].faddr, arr[j].fport,
					arr[j].stack_type, arr[j].tcp_cc,
					arr[j].mss, arr[j].sack_enabled,
					arr[j].snd_scale, arr[j].rcv_scale,
					arr[j].nrecord, arr[j].ntrans);
		}

		sbuf_printf(s, "\n");
		sbuf_finish(s);
//		printf("%s", sbuf_data(s));

		error = siftr_write_log(curthread, sbuf_data(s), sbuf_len(s));

		global_flow_cnt = siftr_ring_drops = max_str_size = gen_flowid_cnt = 0;
		free(arr, M_SIFTR_FLOW_INFO);

		/* destroy ring */
		if (siftr_br != NULL) {
			buf_ring_free(siftr_br, M_SIFTR);
			siftr_br = NULL;
		}
		/* Close logfile vnode if opened */
		if (siftr_vnode != NULL) {
			vn_close(siftr_vnode, FWRITE, curthread->td_ucred, curthread);
			siftr_vnode = NULL;
		}
		if (siftr_vnode_cred != NULL) {
			crfree(siftr_vnode_cred);
			siftr_vnode_cred = NULL;
		}
	} else
		error = EINVAL;

	sbuf_delete(s);

	/*
	 * XXX: Should be using ret to check if any functions fail
	 * and set error appropriately
	 */

	return (error);
}

static int
siftr_sysctl_enabled_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	uint32_t new;

	new = siftr_enabled;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr != NULL) {
		if (new > 1)
			return (EINVAL);
		else if (new != siftr_enabled) {
			if ((error = siftr_manage_ops(new)) == 0) {
				siftr_enabled = new;
			} else {
				siftr_manage_ops(SIFTR_DISABLE);
			}
		}
	}

	return (error);
}

static void
siftr_shutdown_handler(void *arg, int howto)
{
	if ((howto & RB_NOSYNC) != 0 || SCHEDULER_STOPPED())
		return;

	if (siftr_enabled == 1) {
		siftr_manage_ops(SIFTR_DISABLE);
	}
}

/*
 * Module is being unloaded or machine is shutting down. Take care of cleanup.
 */
static int
deinit_siftr(void)
{
	/* Cleanup. */
	EVENTHANDLER_DEREGISTER(shutdown_pre_sync, siftr_shutdown_tag);
	siftr_manage_ops(SIFTR_DISABLE);
	hashdestroy(counter_hash, M_SIFTR, siftr_hashmask);
	mtx_destroy(&siftr_pkt_mgr_mtx);

	return (0);
}

/*
 * Module has just been loaded into the kernel.
 */
static int
init_siftr(void)
{
	siftr_shutdown_tag = EVENTHANDLER_REGISTER(shutdown_pre_sync,
	    siftr_shutdown_handler, NULL, SHUTDOWN_PRI_FIRST);

	/* Initialise our flow counter hash table. */
	counter_hash = hashinit(SIFTR_EXPECTED_MAX_TCP_FLOWS, M_SIFTR,
	    &siftr_hashmask);

	mtx_init(&siftr_pkt_mgr_mtx, "siftr_pkt_mgr_mtx", NULL, MTX_DEF);

	/* Print message to the user's current terminal. */
	uprintf("\nStatistical Information For TCP Research (SIFTR) %s\n",
	    MODVERSION_STR);

	return (0);
}

/*
 * This is the function that is called to load and unload the module.
 * When the module is loaded, this function is called once with
 * "what" == MOD_LOAD
 * When the module is unloaded, this function is called twice with
 * "what" = MOD_QUIESCE first, followed by "what" = MOD_UNLOAD second
 * When the system is shut down e.g. CTRL-ALT-DEL or using the shutdown command,
 * this function is called once with "what" = MOD_SHUTDOWN
 * When the system is shut down, the handler isn't called until the very end
 * of the shutdown sequence i.e. after the disks have been synced.
 */
static int
siftr_load_handler(module_t mod, int what, void *arg)
{
	int ret;

	switch (what) {
	case MOD_LOAD:
		ret = init_siftr();
		break;

	case MOD_QUIESCE:
	case MOD_SHUTDOWN:
		ret = deinit_siftr();
		break;

	case MOD_UNLOAD:
		ret = 0;
		break;

	default:
		ret = EINVAL;
		break;
	}

	return (ret);
}

static moduledata_t siftr_mod = {
	.name = "siftr2",
	.evhand = siftr_load_handler,
};

/*
 * Param 1: name of the kernel module
 * Param 2: moduledata_t struct containing info about the kernel module
 *          and the execution entry point for the module
 * Param 3: From sysinit_sub_id enumeration in /usr/include/sys/kernel.h
 *          Defines the module initialisation order
 * Param 4: From sysinit_elem_order enumeration in /usr/include/sys/kernel.h
 *          Defines the initialisation order of this kld relative to others
 *          within the same subsystem as defined by param 3
 */
DECLARE_MODULE(siftr, siftr_mod, SI_SUB_LAST, SI_ORDER_ANY);
MODULE_VERSION(siftr, MODVERSION);
