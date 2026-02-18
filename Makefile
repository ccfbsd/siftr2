# $FreeBSD$

KMOD=	siftr2
SRCS=	siftr2.c
SRCS+=	vnode_if.h

.if defined(DEBUG)
CFLAGS+= -O0 -g -DINVARIANT_SUPPORT -DINVARIANTS -DWITNESS -DKASAN -DKMSAN
.endif

debug:
	${MAKE} DEBUG=1 all

.include <bsd.kmod.mk>
