# $FreeBSD$

CXGBEI = ${.CURDIR}/../../../dev/cxgbe/cxgbei
CXGBE = ${.CURDIR}/../../../dev/cxgbe
.PATH: ${CXGBEI} ${CXGBE}/common

KMOD=	cxgbei

SRCS=  cxgbei.c
SRCS+= cxgbei_ulp2_ddp.c
SRCS+=  icl_cxgbei.c
SRCS+=  bus_if.h
SRCS+=  device_if.h
SRCS+=  opt_inet.h
SRCS+=  opt_inet6.h
SRCS+=  opt_ofed.h
SRCS+=  pci_if.h
SRCS+=	opt_cam.h
SRCS+=	icl_conn_if.h

CFLAGS+= -I${CXGBE}
#CFLAGS +=-DTCP_OFFLOAD

MFILES=	kern/bus_if.m kern/device_if.m dev/iscsi/icl_conn_if.m dev/pci/pci_if.m
#MFILES=	dev/iscsi/icl_conn_if.m dev/pci/pci_if.m

.include <bsd.kmod.mk>
