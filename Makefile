# $FreeBSD$

KMOD=	siftr2
SRCS=	siftr2.c
SRCS+=	vnode_if.h

.include <bsd.kmod.mk>
