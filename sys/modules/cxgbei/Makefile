# $FreeBSD$

CXGBEI = ${.CURDIR}/../../dev/cxgbei
CXGBE = ${.CURDIR}/../../dev/cxgbe
.PATH: ${CXGBEI} ${CXGBE}/common

KMOD=	cxgbei	

#SRCS= cxgbei_ofld.c icl_cxgbei.c cxgbi_ulp2_ddp.c
#SRCS= cxgbei_ofld.c cxgbi_ulp2_ddp.c
#SRCS+=  bus_if.h device_if.h opt_sched.h pci_if.h pcib_if.h opt_ktr.h opt_cam.h
SRCS=   bus_if.h
SRCS+=  device_if.h
SRCS+=  opt_inet.h
SRCS+=  opt_inet6.h
SRCS+=  opt_ofed.h
SRCS+=  pci_if.h
SRCS+=	opt_cam.h
SRCS+=  cxgbei_ofld.c
SRCS+=  icl_cxgbei.c
SRCS+= 	cxgbi_ulp2_ddp.c 
SRCS+=	icl_conn_if.c
SRCS+=	icl_conn_if.h

CFLAGS+= -I${CXGBE}
CFLAGS +=-DTCP_OFFLOAD
CFLAGS +=-DCHELSIO_OFFLOAD
CFLAGS+= -I${.CURDIR}/../../ofed/include

MFILES=	kern/bus_if.m kern/device_if.m dev/iscsi/icl_conn_if.m dev/pci/pci_if.m

.include <bsd.kmod.mk>
