# $FreeBSD$
# Makefile to be moved to sys/modules/cxgbei

CXGBESRC = ${.CURDIR}/../cxgbe

CFLAGS+= -I${CXGBESRC}

CFLAGS +=-DTCP_OFFLOAD
CFLAGS +=-DCHELSIO_OFFLOAD
CFLAGS += -O2 -g

KMOD= cxgbei

SRCS= cxgbei_ofld.c cxgbi_ulp2_ddp.c
SRCS+=  bus_if.h device_if.h opt_sched.h pci_if.h pcib_if.h opt_ktr.h opt_cam.h

clean:
	rm -rf *.o *.ko* export_syms @ machine x86
	rm -f bus_if.h device_if.h opt_sched.h pci_if.h pcib_if.h opt_ktr.h opt_cam.h

.include <bsd.kmod.mk>
