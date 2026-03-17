# $FreeBSD$

KMOD=	siftr2
SRCS=	siftr2.c
SRCS+=	vnode_if.h

# Default to current directory builds; no install target needed.
# The artifacts (siftr2.ko, siftr2.ko.debug, siftr2.ko.full) will appear here.

# Try to infer MACHINE/MACHINE_CPUARCH/KERNCONF
MACHINE!= /usr/bin/uname -m
MACHINE_CPUARCH!= /usr/bin/uname -p
KERNCONF!= /usr/bin/uname -i

# Compute a candidate KERNBUILDDIR for the running system.
# Users can override this explicitly if they have a custom path.
KERNBUILDDIR?= /usr/obj/usr/src/${MACHINE}.${MACHINE_CPUARCH}/sys/${KERNCONF}

# Helper to test if KERNBUILDDIR exists; if not, leave it empty so we won't pass it.
.if !exists(${KERNBUILDDIR})
KERNBUILDDIR=
.endif

# Debug build: split symbols and DWARF info.
.if defined(DEBUG)
MK_SPLIT_KERNEL_DEBUG?= yes
DEBUG_FLAGS+= -O0 -g

# If you want to always force the macros, keep the next line.
# But it's safer to rely on opt_global.h via KERNBUILDDIR when available.
# DEBUG_FLAGS+= -DINVARIANT_SUPPORT -DINVARIANTS -DWITNESS -DKASAN -DKMSAN
.endif

check:
	@if [ -n "${KERNBUILDDIR}" ] && [ -f "${KERNBUILDDIR}/opt_global.h" ]; then \
		echo "Reading ${KERNBUILDDIR}/opt_global.h"; \
		egrep 'INVAR|WITNESS|KASAN|KMSAN' ${KERNBUILDDIR}/opt_global.h || echo "No debug options found"; \
	else \
		echo "KERNBUILDDIR not set or opt_global.h missing"; \
	fi

# Convenience target: build with DEBUG=1, and pass KERNBUILDDIR only if it exists.
debug:
.if defined(KERNBUILDDIR) && !empty(KERNBUILDDIR)
	@echo "Using KERNBUILDDIR=${KERNBUILDDIR}"
	${MAKE} DEBUG=1 KERNBUILDDIR=${KERNBUILDDIR} all
.else
	@echo "KERNBUILDDIR not found; building debug without kernel options headers."
	${MAKE} DEBUG=1 all
.endif

# Optional convenience targets for loading/unloading from the current dir
load:
	${KMODLOAD} -v ${.OBJDIR}/${KMOD}.ko

unload:
	${KMODUNLOAD} -v ${KMOD}

CLEANFILES+= ${KMOD}.ko.debug ${KMOD}.ko.full .depend.${KMOD}.o
.include <bsd.kmod.mk>
