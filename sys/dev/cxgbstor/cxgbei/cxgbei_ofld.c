/*
 * Chelsio T5xx support
 */

#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/toecore.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>

#include <common/common.h>
#include <common/t4_msg.h>
#include <common/t4_regs.h>     /* for PCIE_MEM_ACCESS */
#include <tom/t4_tom.h>
#include "cxgbei_ofld.h"

#include "cxgbi_ulp2_ddp.h"
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_da.h>
#include <cam/ctl/ctl_io.h>
#include <cam/ctl/ctl.h>
#include <cam/ctl/ctl_backend.h>
#include <cam/ctl/ctl_error.h>
#include <cam/ctl/ctl_frontend.h>
#include <cam/ctl/ctl_frontend_internal.h>
#include <cam/ctl/ctl_debug.h>
#include <cam/ctl/ctl_ha.h>
#include <cam/ctl/ctl_ioctl.h>
#include <cam/ctl/ctl_private.h>

#include "/usr/src/sys/dev/iscsi/icl.h"
#include "/usr/src/sys/dev/iscsi/iscsi_proto.h"
#include "/usr/src/sys/dev/iscsi/iscsi_ioctl.h"
#include "/usr/src/sys/dev/iscsi/iscsi.h"
#include "/usr/src/sys/cam/ctl/ctl_frontend_iscsi.h"

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_xpt.h>
#include <cam/cam_debug.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt_sim.h>
#include <cam/cam_xpt_periph.h>
#include <cam/cam_periph.h>
#include <cam/cam_compat.h>
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_message.h>

struct ulp_mbuf_cb * get_ulp_mbuf_cb(struct mbuf *m)
{
	struct m_tag    *mtag = NULL;

	mtag = m_tag_get(CXGBE_ISCSI_MBUF_TAG, sizeof(struct ulp_mbuf_cb),
				M_NOWAIT);
	if (mtag == NULL) {
		printf("%s: mtag alloc failed\n", __func__);
		return NULL;
	}
	bzero(mtag + 1, sizeof(struct ulp_mbuf_cb));
	m_tag_prepend(m, mtag);

	return ((struct ulp_mbuf_cb *)(mtag + 1));
}

static struct ulp_mbuf_cb * find_ulp_mbuf_cb(struct mbuf *m)
{
        struct m_tag    *mtag = NULL;

        if ((mtag = m_tag_find(m, CXGBE_ISCSI_MBUF_TAG, NULL)) == NULL)
                return (NULL);
	//printf("%s: m:%p m_tag:%p\n", __func__, m, mtag);

        return ((struct ulp_mbuf_cb *)(mtag + 1));
}

#define T4_DDP

#ifdef T4_DDP
static char ppod_use_ulp_mem_write = 1;
#endif

#ifdef T4_DDP
/*
 * functions to program the pagepod in h/w
 */
#define MEMWIN0_BASE	0x1b800
static int pcie_memwin_set_pagepod(struct cxgbi_ulp2_ddp_info *ddp,
				struct toepcb *toep, void *ppod_hdr,
				struct dma_segments *ds, unsigned int naddr,
				unsigned int idx, unsigned int cnt)
{
	struct pagepod *ppod = (struct pagepod *)ppod_hdr;
	struct adapter *adap = toep->port->adapter;
	volatile uint32_t addr = MEMWIN0_BASE;
	bus_addr_t *bus_addr;	
	unsigned int ppaddr = idx * sizeof(struct pagepod) +
					adap->vres.iscsi.start;
	int i;

	for (i = 0; i < cnt; i++, idx++, ppaddr += sizeof(struct pagepod)) {
		mtx_lock(&ddp->win0_lock);

		/* move window to first pagepod */
		t4_write_reg(adap,
			PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 0),
			ppaddr);
		t4_read_reg(adap,
			PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 0));

		for ( ; naddr; naddr -= PPOD_PAGES) {
			unsigned int j = min(naddr, PPOD_PAGES + 1);

			t4_write_reg64(adap, addr, ppod->vld_tid_pgsz_tag_color);
			t4_write_reg64(adap, addr + 8, ppod->len_offset);
			t4_write_reg64(adap, addr + 16, 0);
			addr += 24;

			for ( ; j; j--, addr += 8, ds++) {
				bus_addr = (bus_addr_t *)cpu_to_be64(ds->phys_addr);
				t4_write_reg64(adap, addr, (unsigned long long)bus_addr);
			}
			if (naddr <= PPOD_PAGES) {
				for ( ; naddr <= PPOD_PAGES; naddr++, addr += 8)
					t4_write_reg64(adap, addr, 0);
				break;
			}
			ds--;
		}
		t4_read_reg(adap, MEMWIN0_BASE);   /* flush */
		mtx_unlock(&ddp->win0_lock);
	}
	return 0;
}
static int pcie_memwin_clear_pagepod(struct cxgbi_ulp2_ddp_info *ddp, unsigned int idx,
				unsigned int cnt)
{
	struct toedev *tdev = ddp->tdev;
	struct adapter *adap = (struct adapter *)tdev->tod_softc;
	volatile uint32_t addr = MEMWIN0_BASE; //check this
	unsigned int ppaddr = idx * sizeof(struct pagepod) +
				adap->vres.iscsi.start;
	int i, j;

	for (i = 0; i < cnt; i++, idx++, ppaddr += sizeof(struct pagepod)) {
		mtx_lock(&ddp->win0_lock);

		/* move window to first pagepod */
		t4_write_reg(adap,
			PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 0),
			ppaddr);
		t4_read_reg(adap,
			PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, 0));

		t4_write_reg64(adap, addr, 0);
		t4_write_reg64(adap, addr + 8, 0);
		t4_write_reg64(adap, addr + 16, 0);
		addr += 24;

		for (j = 0; j < (PPOD_PAGES + 1); j++,  addr += 8)
			t4_write_reg64(adap, addr, 0);

		t4_read_reg(adap, MEMWIN0_BASE);   /* flush */
		mtx_unlock(&ddp->win0_lock);
	}
	return 0;
}

static void* t4_tdev2ddp(void *tdev)
{
	struct adapter *sc = ((struct toedev *)tdev)->tod_softc;
	return (sc->iscsi_softc);
}
static void inline ppod_set(struct pagepod *ppod,
			struct cxgbi_ulp2_pagepod_hdr *hdr,
			struct cxgbi_ulp2_gather_list *gl,
			unsigned int pidx)
{
	int i;
	//struct cxgbi_ulp2_pagepod_hdr *hdr1 = NULL;

	memcpy(ppod, hdr, sizeof(*hdr));
#if 0
	printf("%s: ppod_tag_color:0x%lx len_offset:0x%lx\n",
		__func__, ppod->vld_tid_pgsz_tag_color, ppod->len_offset);
	hdr1 = (struct cxgbi_ulp2_pagepod_hdr *)ppod;
	printf("%s: vld_tid:0x%x pgsz_clor:0x%x max_offset:0x%x page_offset:0x%x\n",
		__func__, hdr1->vld_tid, hdr1->pgsz_tag_clr, hdr1->maxoffset, hdr1->pgoffset);	
#endif

	for (i = 0; i < (PPOD_PAGES + 1); i++, pidx++) {
		ppod->addr[i] = pidx < gl->nelem ?
			cpu_to_be64(gl->dma_sg[pidx].phys_addr) : 0ULL;
		//printf("%s: i:%d ppod->addr[%d]:0x%lx\n", __func__, i, i, ppod->addr[i]);
	}
}

static void inline ppod_clear(struct pagepod *ppod)
{
	memset(ppod, 0, sizeof(*ppod));
}

static inline void ulp_mem_io_set_hdr(struct adapter *sc, int tid, struct ulp_mem_io *req,
				unsigned int wr_len, unsigned int dlen,
				unsigned int pm_addr)
{
	struct ulptx_idata *idata = (struct ulptx_idata *)(req + 1);

	INIT_ULPTX_WR(req, wr_len, 0, 0);
	//req->cmd = htonl(V_ULPTX_CMD(ULP_TX_MEM_WRITE));
	req->cmd = cpu_to_be32(V_ULPTX_CMD(ULP_TX_MEM_WRITE) |
				V_ULP_MEMIO_ORDER(is_t4(sc)) |
				V_T5_ULP_MEMIO_IMM(is_t5(sc)));
	req->dlen = htonl(V_ULP_MEMIO_DATA_LEN(dlen >> 5));
	req->len16 = htonl(DIV_ROUND_UP(wr_len - sizeof(req->wr), 16)
				| V_FW_WR_FLOWID(tid));
	req->lock_addr = htonl(V_ULP_MEMIO_ADDR(pm_addr >> 5));

	idata->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	idata->len = htonl(dlen);
}

#define PPOD_SIZE		sizeof(struct pagepod)
#define ULPMEM_IDATA_MAX_NPPODS 1	/* 256/PPOD_SIZE */
#define PCIE_MEMWIN_MAX_NPPODS 16	/* 1024/PPOD_SIZE */

static int ppod_write_idata(struct cxgbi_ulp2_ddp_info *ddp,
			struct cxgbi_ulp2_pagepod_hdr *hdr,
			unsigned int idx, unsigned int npods,
			struct cxgbi_ulp2_gather_list *gl,
			unsigned int gl_pidx, struct toepcb *toep)
{
	unsigned int dlen = PPOD_SIZE * npods;
	unsigned int pm_addr = idx * PPOD_SIZE + ddp->llimit;
	unsigned int wr_len = roundup(sizeof(struct ulp_mem_io) +
				 sizeof(struct ulptx_idata) + dlen, 16);
	struct ulp_mem_io *req;
	struct ulptx_idata *idata;
	struct pagepod *ppod;
	unsigned int i;
	struct wrqe *wr;
	struct adapter *sc = toep->port->adapter;

	wr = alloc_wrqe(wr_len, toep->ctrlq);
	if (wr == NULL) {
		printf("%s: alloc wrqe failed\n", __func__);
		return 0;
	}

	req = wrtod(wr);
	memset(req, 0, wr_len);
	ulp_mem_io_set_hdr(sc, toep->tid, req, wr_len, dlen, pm_addr);
	idata = (struct ulptx_idata *)(req + 1);

	//printf("%s: idx:%d pm_addr:0x%x\n", __func__, idx, pm_addr);
	ppod = (struct pagepod *)(idata + 1);
	for (i = 0; i < npods; i++, ppod++, gl_pidx += PPOD_PAGES) {
		if (!hdr) /* clear the pagepod */
			ppod_clear(ppod);
		else /* set the pagepod */
			ppod_set(ppod, hdr, gl, gl_pidx);
	}

	t4_wrq_tx(sc, wr);
	return 0;
}

static int t4_ddp_set_map(struct cxgbi_ulp2_ddp_info *ddp,
			void *isockp, struct cxgbi_ulp2_pagepod_hdr *hdr,
			unsigned int idx, unsigned int npods,
			struct cxgbi_ulp2_gather_list *gl, int reply)
{
	iscsi_socket *isock = (iscsi_socket *)isockp;
	struct socket *sk;
	struct toepcb *toep;
	struct tcpcb *tp;
	int err = -1; //ENOTSUPP;

	if (!isock) {
		printf("%s: isock NULL.\n", __func__);
		return err;
	}
	sk = isock->sock;
	tp = so_sototcpcb(sk);
	toep = tp->t_toe;

	/*
 	 * on T4, if we use a mix of IMMD and DSGL with ULP_MEM_WRITE,
 	 * the order would not be garanteed, so we will stick with IMMD
 	 */
	gl->tid = toep->tid;
	gl->port_id = toep->port->port_id;
	gl->egress_dev = (void *)toep->port->ifp;

	if (ppod_use_ulp_mem_write) {
		unsigned int pidx = 0;
		unsigned int w_npods = 0;
		unsigned int cnt;
		/* send via immediate data */
		for (; w_npods < npods; idx += cnt, w_npods += cnt,
			pidx += PPOD_PAGES) {
			cnt = npods - w_npods;
			if (cnt > ULPMEM_IDATA_MAX_NPPODS)
				cnt = ULPMEM_IDATA_MAX_NPPODS;
			err = ppod_write_idata(ddp, hdr, idx, cnt, gl,
						pidx, toep);
			if (err < 0) {
				printf("%s ppod_write_idata failed\n", __func__);
				break;
			}
		}
	} else {
		struct pagepod ppod;	/* only use the header portion */

		memcpy(&ppod, hdr, sizeof(struct cxgbi_ulp2_pagepod_hdr));
		err = pcie_memwin_set_pagepod(ddp, toep, (void *)&ppod,
					gl->dma_sg, gl->nelem,
					idx, npods);
	}
	return err;
}

static void t4_ddp_clear_map(struct cxgbi_ulp2_ddp_info *ddp,
			struct cxgbi_ulp2_gather_list *gl,
			unsigned int tag, unsigned int idx, unsigned int npods,
			iscsi_socket *isock)
{
	struct socket *sk;
	struct toepcb *toep;
	struct tcpcb *tp;

	int err = -1; //ENOTSUPP;
	
	sk = isock->sock;
	tp = so_sototcpcb(sk);
	toep = tp->t_toe;

	//printf("%s: tag:0x%x idx:0x%x npods:0x%x\n", __func__, tag, idx, npods);
	if (ppod_use_ulp_mem_write) {
		/* send via immediate data */
		unsigned int pidx = 0;
		unsigned int w_npods = 0;
		unsigned int cnt;

		for (; w_npods < npods; idx += cnt, w_npods += cnt,
			pidx += PPOD_PAGES) {
			cnt = npods - w_npods;
			if (cnt > ULPMEM_IDATA_MAX_NPPODS)
				cnt = ULPMEM_IDATA_MAX_NPPODS;
			err = ppod_write_idata(ddp, NULL, idx, cnt, gl, 0, toep);
			if (err < 0)
				break;
		}
	} else {
		err = pcie_memwin_clear_pagepod(ddp, idx, npods);
	}
}

typedef struct offload_device {
	LIST_ENTRY(offload_device) link;
	unsigned char d_version;
	unsigned char d_tx_hdrlen;      /* CPL_TX_DATA, < 256 */
	unsigned char d_ulp_rx_datagap; /* for coalesced iscsi msg */
	unsigned char filler;

	unsigned int d_flag;
        unsigned int d_payload_tmax;
        unsigned int d_payload_rmax;

	struct cxgbi_ulp2_tag_format d_tag_format;
	void    *d_tdev;
	void    *d_pdev;
	void* (*tdev2ddp)(void *tdev);
}offload_device;

/*
 * cxgbei device management
 * maintains a list of the cxgbei devices
 */
LIST_HEAD(, offload_device) odev_list = LIST_HEAD_INITIALIZER(head);
//MTX_SYSINIT(odev_list_mtx, &odev_list_mtx, "odev_list_mtx", MTX_DEF);

static void t4_unregister_cpl_handler_with_tom(struct adapter *sc);
static offload_device *offload_device_new(void *tdev)
{
	offload_device *odev = NULL;
	odev = malloc(sizeof(struct offload_device),
			M_CXGBEIOFLD, M_NOWAIT | M_ZERO);
	if (odev) {
		odev->d_tdev = tdev;
		LIST_INSERT_HEAD(&odev_list, odev, link);
	}

	return odev;
}

static offload_device *offload_device_find(struct toedev *tdev)
{
	offload_device *odev = NULL;

	if(!LIST_EMPTY(&odev_list)) {
		LIST_FOREACH(odev, &odev_list, link) {
		if (odev->d_tdev == tdev)
			break;
		}
	}
	return odev;
}
static void cxgbei_odev_cleanup(offload_device *odev)
{
	struct toedev *tdev = odev->d_tdev;
	struct adapter *sc = (struct adapter *)tdev->tod_softc;

	/* de-register ULP CPL handlers with TOM */
	t4_unregister_cpl_handler_with_tom(sc);
	if (odev->d_flag & ODEV_FLAG_ULP_DDP_ENABLED) {
		if (sc->iscsi_softc)
			cxgbi_ulp2_ddp_cleanup((struct cxgbi_ulp2_ddp_info **)&sc->iscsi_softc);
	}
	return;
}

static void offload_device_remove()
{
	offload_device *odev = NULL;

	if(LIST_EMPTY(&odev_list))
		return;

	LIST_FOREACH(odev, &odev_list, link) {
		LIST_REMOVE(odev, link);
		cxgbei_odev_cleanup(odev);
		free(odev, M_CXGBEIOFLD);
	}
	return;
}

static int cxgbei_map_sg(cxgbei_sgl_t *sgl, struct ccb_scsiio *csio)
{
	unsigned int data_len = csio->dxfer_len;
	unsigned int sgoffset = (uint64_t)csio->data_ptr & PAGE_MASK;
	unsigned int nsge = (csio->dxfer_len + sgoffset + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned char *sgaddr = csio->data_ptr;
	unsigned int len = 0;

	sgl->sg_addr = sgaddr;
	sgl->sg_offset = sgoffset;
	if (data_len <  (PAGE_SIZE - sgoffset))
		len = data_len;
	else
		len = PAGE_SIZE - sgoffset;

	sgl->sg_length = len;

	data_len -= len;
	sgaddr += len;
	sgl = sgl+1;
	
	while(data_len > 0) {
		sgl->sg_addr = sgaddr;
		len = (data_len < PAGE_SIZE)? data_len: PAGE_SIZE;
		sgl->sg_length = len;
	        sgaddr += len;
		data_len -= len;
		sgl = sgl + 1;
	}

	return nsge;
}

static int cxgbei_map_sg_tgt(cxgbei_sgl_t *sgl, union ctl_io *io)
{
        unsigned int data_len;// = csio->dxfer_len;
        unsigned int sgoffset;// = (uint64_t)csio->data_ptr & PAGE_MASK;
        unsigned int nsge;// = (csio->dxfer_len + sgoffset + PAGE_SIZE - 1) >> PAGE_SHIFT;
        unsigned char *sgaddr;// = csio->data_ptr;
        unsigned int len = 0, index = 0, ctl_sg_count, i;
        struct ctl_sg_entry ctl_sg_entry, *ctl_sglist;

        if (io->scsiio.kern_sg_entries > 0) {
                ctl_sglist = (struct ctl_sg_entry *)io->scsiio.kern_data_ptr;
                ctl_sg_count = io->scsiio.kern_sg_entries;
        } else {
                ctl_sglist = &ctl_sg_entry;
                ctl_sglist->addr = io->scsiio.kern_data_ptr;
                ctl_sglist->len = io->scsiio.kern_data_len;
                ctl_sg_count = 1;
        }

        sgaddr = sgl->sg_addr = ctl_sglist[index].addr;
        sgoffset = sgl->sg_offset = (uint64_t)sgl->sg_addr & PAGE_MASK;
	data_len = ctl_sglist[index].len;

	//printf("%s: sgaddr:%p sgoffset:0x%x data_len:0x%x\n", __func__, sgaddr, sgoffset, data_len);
        if (data_len <  (PAGE_SIZE - sgoffset))
                len = data_len;
        else
                len = PAGE_SIZE - sgoffset;

        sgl->sg_length = len;

	//printf("%s: ctl_sg_cnt:%d sgaddr:%p sgoffset:0x%x sglen:0x%x\n", __func__, ctl_sg_count, sgaddr, sgoffset, len);
        data_len -= len;
        sgaddr += len;
        sgl = sgl+1;

	len = 0;
        for (i = 0;  i< ctl_sg_count; i++)
                len += ctl_sglist[i].len;
        nsge = (len + sgoffset + PAGE_SIZE -1) >> PAGE_SHIFT;
	//printf("%s: total_len:0x%x nsge:%d\n", __func__, len, nsge);
        while(data_len > 0) {
                sgl->sg_addr = sgaddr;
                len = (data_len < PAGE_SIZE)? data_len: PAGE_SIZE;
                sgl->sg_length = len;
		//printf("%s: sgaddr:%p sg_len:0x%zx data_len:0x%x\n", __func__, sgl->sg_addr, sgl->sg_length, data_len);
                sgaddr += len;
                data_len -= len;
                sgl = sgl + 1;
                if (data_len == 0) {
                        if (index == ctl_sg_count - 1)
                                break;
                        index++;
                        sgaddr = ctl_sglist[index].addr;
                        data_len = ctl_sglist[index].len;
			//printf("%s: index:%d sgaddr:%p data_len:0x%x\n", __func__, index, sgaddr, data_len);
		}
        }

	//printf("%s: returning nsge:%d\n", __func__, nsge);
        return nsge;
}

static int t4_sk_ddp_tag_reserve(iscsi_socket *isock, unsigned int xferlen,
                                cxgbei_sgl_t *sgl, unsigned int sgcnt,
                                unsigned int *ddp_tag)
{
        offload_device *odev = isock->s_odev;
        struct toedev *tdev = odev->d_tdev;
        struct cxgbi_ulp2_gather_list *gl;
        int err = -EINVAL;

        gl = cxgbi_ulp2_ddp_make_gl_from_iscsi_sgvec(xferlen, sgl, sgcnt,
                                        odev->d_tdev, 0);
        if (gl) {
                err = cxgbi_ulp2_ddp_tag_reserve(odev->tdev2ddp(tdev),
                                                isock,
                                                isock->s_tid,
                                                &odev->d_tag_format,
                                                ddp_tag, gl,
                                                0, 0);
                if (err < 0) {
			printf("%s: ddp_tag_reserve failed\n", __func__);
                        cxgbi_ulp2_ddp_release_gl(gl, odev->d_tdev);
		}
        }

        return err;
}

static unsigned int
cxgbei_task_reserve_itt(struct icl_conn *ic, struct ccb_scsiio *scmd, struct iscsi_outstanding *task)
{
	int xferlen = scmd->dxfer_len;
	cxgbei_task_data *tdata = NULL;
	cxgbei_sgl_t *sge = NULL;
	struct socket *so = ic->ic_socket;
        iscsi_socket *isock = (iscsi_socket *)(so)->so_emuldata;
	int err = -1;
        offload_device *odev = isock->s_odev;

	//printf("%s: ENTRY xferlen:0x%x task:%p itt:0x%x\n",
	//	__func__, xferlen, task, task->io_initiator_task_tag);
	if (!task) {
		printf("%s: task is NULL\n", __func__);
		return 0;
	}
	tdata = (cxgbei_task_data *)(task->ofld_priv);
	if (!xferlen || !tdata) {
		//printf("%s: tdata is NULL\n", __func__);
		goto out;
	}
	if (xferlen < DDP_THRESHOLD)
		goto out;

	if ((scmd->ccb_h.flags & CAM_DIR_MASK) == CAM_DIR_IN) {
		tdata->nsge = cxgbei_map_sg(tdata->sgl, scmd);
		if (tdata->nsge == 0) {
			printf("%s: map_sg failed\n", __func__);
			return 0;
		}
		sge = tdata->sgl;

		tdata->sc_ddp_tag = task->io_initiator_task_tag;

		if (cxgbi_ulp2_sw_tag_usable(&odev->d_tag_format, tdata->sc_ddp_tag)) {
			err = t4_sk_ddp_tag_reserve(isock, scmd->dxfer_len, sge, tdata->nsge, &tdata->sc_ddp_tag);
		} else {
			printf("%s: sc_ddp_tag:0x%x not usable\n", __func__, tdata->sc_ddp_tag);
		}
	}
out:
	if (err < 0)
		tdata->sc_ddp_tag = cxgbi_ulp2_set_non_ddp_tag(&odev->d_tag_format, task->io_initiator_task_tag);

	
	return tdata->sc_ddp_tag;
}

static unsigned int
cxgbei_task_reserve_ttt(struct icl_conn *ic, struct cfiscsi_data_wait *cdw, union ctl_io *io)
{
	struct socket *so = ic->ic_socket;
        iscsi_socket *isock = (iscsi_socket *)(so)->so_emuldata;
	cxgbei_task_data *tdata = NULL;
        offload_device *odev = isock->s_odev;
	int xferlen, err = -1;
	cxgbei_sgl_t *sge = NULL;

	if (!cdw) {
		printf("%s: cdw is NULL\n", __func__);
		return 0;
	}
	xferlen = (io->scsiio.kern_data_len - io->scsiio.ext_data_filled);
	tdata = (cxgbei_task_data *)(cdw->ofld_priv);
	//printf("%s: xferlen:0x%x tdata:%p sizeof(cxgbei_task_data):0x%lx\n",
	//	__func__, xferlen, tdata, sizeof(cxgbei_task_data));
	if (!xferlen || !tdata)
		goto out;
	if (xferlen < DDP_THRESHOLD)
		goto out;
	tdata->nsge = cxgbei_map_sg_tgt(tdata->sgl, io);
	if (tdata->nsge == 0) {
		printf("%s: map_sg failed\n", __func__);
		return 0;
	}
	//printf("%s: nsge:%d sgl:%p\n", __func__, tdata->nsge, tdata->sgl);
	sge = tdata->sgl;

	tdata->sc_ddp_tag = cdw->cdw_target_transfer_tag;
	if (cxgbi_ulp2_sw_tag_usable(&odev->d_tag_format, tdata->sc_ddp_tag)) {
		err = t4_sk_ddp_tag_reserve(isock, xferlen, sge, tdata->nsge, &tdata->sc_ddp_tag);
	} else {
		printf("%s: sc_ddp_tag:0x%x not usable\n", __func__, tdata->sc_ddp_tag);
	}
out:
	if (err < 0)
		tdata->sc_ddp_tag = cxgbi_ulp2_set_non_ddp_tag(&odev->d_tag_format, cdw->cdw_target_transfer_tag);
	//printf("%s: returning tag:0x%x\n", __func__, tdata->sc_ddp_tag);
	return tdata->sc_ddp_tag;
}

static int t4_sk_ddp_tag_release(iscsi_socket *isock, unsigned int ddp_tag)
{
        offload_device *odev = isock->s_odev;
        struct toedev *tdev = odev->d_tdev;

        cxgbi_ulp2_ddp_tag_release(odev->tdev2ddp(tdev), ddp_tag, isock);
        return 0;
}
static struct cxgbi_ulp2_ddp_info* t4_ddp_init(struct ifnet *dev,
						struct toedev *tdev)
{
	struct cxgbi_ulp2_ddp_info *ddp;
	struct adapter *sc = tdev->tod_softc;
	struct ulp_iscsi_info uinfo;

	memset(&uinfo, 0, sizeof(struct ulp_iscsi_info));
	uinfo.llimit = sc->vres.iscsi.start;
	uinfo.ulimit = sc->vres.iscsi.start + sc->vres.iscsi.size - 1;
	uinfo.max_rxsz = uinfo.max_txsz = G_MAXRXDATA(t4_read_reg(sc, A_TP_PARA_REG2));

	if (!sc->vres.iscsi.size) {
		printf("iSCSI capabilities not enabled.\n");
		return NULL;
	}
	printf("T4, ddp 0x%x ~ 0x%x, size %u, iolen %u, tdev->ulp ddp:0x%p.\n",
		uinfo.llimit, uinfo.ulimit, sc->vres.iscsi.size, uinfo.max_rxsz, sc->iscsi_softc);

	cxgbi_ulp2_ddp_init((void *)tdev,
			(struct cxgbi_ulp2_ddp_info **)&sc->iscsi_softc,
			&uinfo);
	ddp = (struct cxgbi_ulp2_ddp_info *)sc->iscsi_softc;
        if (ddp) {
		unsigned int pgsz_order[4];
		int i;

		for (i = 0; i < 4; i++)
			pgsz_order[i] = uinfo.pgsz_factor[i];

		t4_iscsi_init(dev, uinfo.tagmask, pgsz_order);

		ddp->ddp_set_map = t4_ddp_set_map;
		ddp->ddp_clear_map = t4_ddp_clear_map;
	}
	return ddp;
}
#endif /* T4_DDP */

static struct socket * cpl_find_sock(struct adapter *sc, struct mbuf *m)
{
        struct socket *sk;
        struct cpl_iscsi_hdr *cpl =  mtod(m, struct cpl_iscsi_hdr *);
        unsigned int hwtid = GET_TID(cpl);
        struct toepcb *toep = lookup_tid(sc, hwtid);
        struct inpcb *inp = toep->inp;

        INP_WLOCK(inp);
	sk = inp->inp_socket;
        INP_WUNLOCK(inp);
        if (!sk)
                printf("T4 CPL tid 0x%x, sk NULL.\n", hwtid);
        return sk;
}

static void process_rx_iscsi_hdr(struct socket *sk, struct mbuf *m)
{
        struct tcpcb *tp = so_sototcpcb(sk);
        struct toepcb *toep = tp->t_toe;
	//struct inpcb *inp = toep->inp;

        struct cpl_iscsi_hdr *cpl =  mtod(m, struct cpl_iscsi_hdr *);
        struct ulp_mbuf_cb *cb;
        struct mbuf *lmbuf;
        struct ulp_mbuf_cb *lcb;
        unsigned char *byte;
        iscsi_socket *isock = (iscsi_socket *)(sk)->so_emuldata;
	//unsigned char *buf;
	//int i = 0;
	unsigned int hlen, dlen, plen;
	//struct sockbuf *sb = &sk->so_rcv;

        if (!isock)
                goto err_out;

        if(!toep)
                goto err_out;
	if ((m->m_flags & M_PKTHDR) == 0) {
                printf("m:%p doesn't have a M_PKTHDR can't allocate m_tag\n", m);
        }

	/* allocate m_tag to hold ulp info */
        cb = get_ulp_mbuf_cb(m);
        if (cb == NULL) {
                printf("Error allocation m_tag\n");
                return;
        }
        cb->seq = ntohl(cpl->seq);
	//printf("%s: ENTRY m :%p cb:%p seq = 0x%x cb->ulp_mode:%d sizeof-cpl:0x%lx \n",
	//		__func__, m, cb, cb->seq,  cb->ulp_mode, sizeof(*cpl));

        /* strip off CPL header */
        m_adj(m, sizeof(*cpl));

#if 0
        buf = mtod(m, unsigned char *);
        //if (buf[32] != 0x0) {
              printf("ISCSI Packet: m_len:%d", m->m_len);
              for (i = 0; i< 48; i++) {
                      if(!(i % 16))
                              printf("\n");
                      printf("0x%02x ", *buf++);
              }
        //}
                              printf("\n");
#endif

	/* figure out if this is the pdu header or data */
        cb->ulp_mode = ULP_MODE_ISCSI;
	mtx_lock(&isock->iscsi_rcv_mbufq.lock);
        if (!isock->mbuf_ulp_lhdr) {
                iscsi_socket *isock = (iscsi_socket *)(sk)->so_emuldata;

                isock->mbuf_ulp_lhdr = lmbuf = m;
                lcb = cb;
                cb->flags = SBUF_ULP_FLAG_HDR_RCVD |
                        SBUF_ULP_FLAG_COALESCE_OFF;
                /* we only update tp->rcv_nxt once per pdu */
                if (cb->seq != tp->rcv_nxt) {
                        printf(
                                "tid 0x%x, CPL_ISCSI_HDR, BAD seq got 0x%x exp 0x%x.\n",
                                toep->tid,
                                cb->seq, tp->rcv_nxt);
				mtx_unlock(&isock->iscsi_rcv_mbufq.lock);
                        goto err_out;
                }
                byte = m->m_data;
		hlen = ntohs(cpl->len);
		dlen = ntohl(*(unsigned int *)(byte + 4)) & 0xFFFFFF;

		plen = ntohs(cpl->pdu_len_ddp);
                //lcb->ulp.iscsi.pdulen = ntohs(cpl->pdu_len_ddp);
                lcb->ulp.iscsi.pdulen = (hlen + dlen + 3) & (~0x3); //ntohs(cpl->pdu_len_ddp);
                /* workaround for cpl->pdu_len_ddp since it does not include
                   the data digest count */
		if (dlen)	
                        lcb->ulp.iscsi.pdulen += isock->s_dcrc_len;

                /* take into account of padding bytes */
//                if (lcb->ulp.iscsi.pdulen & 0x3)
//                       lcb->ulp.iscsi.pdulen += 4 - (lcb->ulp.iscsi.pdulen & 0x3);

                tp->rcv_nxt += lcb->ulp.iscsi.pdulen;
                if (tp->rcv_wnd <= lcb->ulp.iscsi.pdulen)
                        printf("%s: Negative wnd rcv_wnd:0x%lx pdulen:0x%x\n",
                                __func__, tp->rcv_wnd, lcb->ulp.iscsi.pdulen);
                tp->rcv_wnd -= lcb->ulp.iscsi.pdulen;
                tp->t_rcvtime = ticks;
        } else {
		lmbuf = isock->mbuf_ulp_lhdr;
                lcb = find_ulp_mbuf_cb(lmbuf);
		if (lcb == NULL) {
			printf("%s: lmbuf:%p lcb is NULL\n", __func__, lmbuf);
			goto err_out;
		}
                lcb->flags |= SBUF_ULP_FLAG_DATA_RCVD |
                                SBUF_ULP_FLAG_COALESCE_OFF;
                cb->flags = SBUF_ULP_FLAG_DATA_RCVD;

		/* padding. TODO */
		if ((m->m_len % 4) != 0) {
                	m->m_len += 4 - (m->m_len % 4);
		}
                //printf("sk 0x%p, tid 0x%x skb 0x%p, pdu data, pdulen:%d header 0x%p.\n",
                 //       sk, toep->tid, m, lcb->ulp.iscsi.pdulen, lmbuf);
        }

#if 0
	printf("%s: m:%p len:%d cb:%p lmbuf:%p lcb:%p llen:%d pdulen:%d\n",
		__func__, m, m->m_len, cb, lmbuf, lcb, lmbuf->m_len, lcb->ulp.iscsi.pdulen);
#endif
	mbufq_tail(&isock->iscsi_rcv_mbufq, m);
	mtx_unlock(&isock->iscsi_rcv_mbufq.lock);
        return;

err_out:
        m_freem(m);
        return;
}

/* handover received PDU to iscsi_initiator */
static void iscsi_conn_receive_pdu(struct iscsi_socket *isock)
{
	struct icl_pdu *response = NULL;
	struct icl_conn *ic = (struct icl_conn*)isock->s_conn;
	struct mbuf *m;
        struct ulp_mbuf_cb *cb = NULL;
	int data_len;

	response = icl_pdu_new(isock->s_conn, M_NOWAIT);
	if (response == NULL) {
		printf("%s: failed to alloc icl_pdu\n", __func__);
		return;
	}
	m = mbufq_peek(&isock->iscsi_rcv_mbufq);
	if (m) {
                cb = find_ulp_mbuf_cb(m);
		if (cb == NULL) {
			printf("%s: m:%p cb is NULL\n", __func__, m);
			goto err_out;
		}
		if (!(cb->flags & SBUF_ULP_FLAG_STATUS_RCVD))
			goto err_out;
	} 
	/* BHS */
	mbufq_dequeue(&isock->iscsi_rcv_mbufq);
	data_len = cb->ulp.iscsi.pdulen;

	//printf("%s: response:%p m:%p m_len:%d data_len:%d\n",
	//	__func__, response, m, m->m_len, data_len);
	response->ip_bhs_mbuf = m;
	response->ip_bhs = mtod(response->ip_bhs_mbuf, struct iscsi_bhs *);

	/* data */
	if (cb->flags & SBUF_ULP_FLAG_DATA_RCVD) {
		m = mbufq_peek(&isock->iscsi_rcv_mbufq);
		if (!m) {
			printf("%s:No Data\n", __func__);
			goto err_out;
		}
		mbufq_dequeue(&isock->iscsi_rcv_mbufq);
		response->ip_data_mbuf = m;
		response->ip_data_len += response->ip_data_mbuf->m_len;
	} else {
		/* Data is DDP'ed */
		response->ip_ofld_prv0 = 1; /* indicate iscsi-inititor that data is DDP'ed */
	}
	(ic->ic_receive)(response);
	return;

err_out:
	free(response, M_CXGBEIOFLD);
	return;
}

static void process_rx_data_ddp(struct socket *sk, struct mbuf *m)
{
        struct cpl_rx_data_ddp *cpl = mtod(m, struct cpl_rx_data_ddp *);//cplhdr(m);
        struct tcpcb *tp = so_sototcpcb(sk);
        struct toepcb *toep = tp->t_toe;
	struct inpcb *inp = toep->inp;
        struct mbuf *lmbuf;
        struct ulp_mbuf_cb *lcb, *lcb1;
        unsigned int val;
        iscsi_socket *isock = (iscsi_socket *)(sk)->so_emuldata;

	//printf("%s: ENTRY m:%p mbuf_ulp_lhdr:%p\n", __func__, m, isock->mbuf_ulp_lhdr);
	if (!isock->mbuf_ulp_lhdr) {
                printf("tid 0x%x, rcv RX_DATA_DDP w/o pdu header.\n",
                        toep->tid);
                m_freem(m);
                return;
        }
	mtx_lock(&isock->iscsi_rcv_mbufq.lock);
        lmbuf = isock->mbuf_ulp_lhdr;
        if (lmbuf->m_nextpkt) {
                lcb1 = find_ulp_mbuf_cb(lmbuf->m_nextpkt);
                lcb1->flags |= SBUF_ULP_FLAG_STATUS_RCVD;
        }
        lcb = find_ulp_mbuf_cb(isock->mbuf_ulp_lhdr);
        if (!lcb) {
                printf("mtag NULL lmbuf :%p\n", lmbuf);
		mtx_unlock(&isock->iscsi_rcv_mbufq.lock);
                return;
        }
        lcb->flags |= SBUF_ULP_FLAG_STATUS_RCVD;

	//printf("%s: mbuf_ulp_lhdr:%p lcb:%p mnextpkt:%p lcb1:%p\n",
	//	__func__, isock->mbuf_ulp_lhdr, lcb, lmbuf->m_nextpkt, lcb1);
        isock->mbuf_ulp_lhdr = NULL;

	 if (ntohs(cpl->len) != lcb->ulp.iscsi.pdulen) {
                printf("tid 0x%x, RX_DATA_DDP pdulen %u != %u.\n",
                        toep->tid, ntohs(cpl->len), lcb->ulp.iscsi.pdulen);
                printf("%s: lmbuf:%p lcb:%p lcb->flags:0x%x\n", __func__, lmbuf, lcb, lcb->flags);
        }

        lcb->ulp.iscsi.ddigest = ntohl(cpl->ulp_crc);

        val = ntohl(cpl->ddpvld);
        if (val & F_DDP_PADDING_ERR)
                lcb->flags |= SBUF_ULP_FLAG_PAD_ERROR;
        if (val & F_DDP_HDRCRC_ERR)
                lcb->flags |= SBUF_ULP_FLAG_HCRC_ERROR;
        if (val & F_DDP_DATACRC_ERR)
                lcb->flags |= SBUF_ULP_FLAG_DCRC_ERROR;
        if (!(lcb->flags & SBUF_ULP_FLAG_DATA_RCVD)) {
                lcb->flags |= SBUF_ULP_FLAG_DATA_DDPED;
	}
#ifdef __T4_DBG_DDP_FAILURE__
//      else
        {
                unsigned char *bhs = lmbuf->m_data;
                unsigned char opcode = bhs[0];
                unsigned int dlen = ntohl(*(unsigned int *)(bhs + 4)) & 0xFFFFFF;
                unsigned int ttt = ntohl(*(unsigned int *)(bhs + 20));
                unsigned int offset = ntohl(*(unsigned int *)(bhs + 40));

                if (dlen >= 2096) 
		{
                /* data_out and should be ddp'ed */
                if ((opcode & 0x3F) == 0x05 && ttt != 0xFFFFFFFF) {
                        printf("CPL_RX_DATA_DDP: tid 0x%x, data-out %s ddp'ed (%u+%u), ttt 0x%x, seq 0x%x, ddpvld 0x%x.\n",
                        toep->tid,
                        (lcb->flags & SBUF_ULP_FLAG_DATA_DDPED) ? "IS" : "NOT",
                        offset, dlen, ttt, ntohl(cpl->seq), ntohl(cpl->ddpvld));
                }
                if ((opcode & 0x3F) == 0x25) {
                        //if (!(lcb->flags & SBUF_ULP_FLAG_DATA_DDPED))
                        printf("CPL_RX_DATA_DDP: tid 0x%x, data-in %s ddp'ed (%u+%u), seq 0x%x, ddpvld 0x%x.\n",
                        toep->tid,
                        (lcb->flags & SBUF_ULP_FLAG_DATA_DDPED) ? "IS" : "NOT",
                        offset, dlen, ntohl(cpl->seq), ntohl(cpl->ddpvld));
                }
                }
        }
#endif

	iscsi_conn_receive_pdu(isock);

	/* update rx credits */
	INP_WLOCK(inp);
	SOCK_LOCK(sk);
	toep->sb_cc += lcb->ulp.iscsi.pdulen;
	SOCK_UNLOCK(sk);
	//printf("sk:%p sb_cc 0x%x, rcv_nxt 0x%x rcv_wnd:0x%lx.\n",
	 //     sk, toep->sb_cc, tp->rcv_nxt, tp->rcv_wnd);
	t4_rcvd(&toep->td->tod, tp);
	INP_WUNLOCK(inp);
	mtx_unlock(&isock->iscsi_rcv_mbufq.lock);
	m_freem(m);
}

static void
drop_fw_acked_ulp_data(struct socket *sk, struct toepcb *toep, int len)
{
        struct mbuf *m, *next;
	struct ulp_mbuf_cb *cb;
        iscsi_socket *isock = (iscsi_socket *)(sk)->so_emuldata;
	struct icl_pdu *req;

        if(len == 0 || !isock)
                return;

        mtx_lock(&isock->ulp2_wrq.lock);
        while(len > 0) {
                m = mbufq_dequeue(&isock->ulp2_wrq);
                if(!m) break;

		//printf("%s: m:%p m_len:%d plen:%d\n", __func__, m, m->m_len, len);
                for(next = m; next !=NULL; next = next->m_next)
                        len -= next->m_len;

		//m_freem(m);
		cb = find_ulp_mbuf_cb(m);

		if (cb && isock && cb->pdu) {
			req = (struct icl_pdu *)cb->pdu;
			req->ip_bhs_mbuf = NULL;
			icl_pdu_free(req); /* check this */
		}
		m_freem(m);
        }
        mtx_unlock(&isock->ulp2_wrq.lock);
        return;
}

static void process_fw4_ack(struct socket *sk, int *plen)
{
	struct tcpcb *tp = so_sototcpcb(sk);
	struct toepcb *toep = tp->t_toe;

	drop_fw_acked_ulp_data(sk, toep, *plen);

        return;
}

static int do_set_tcb_rpl(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	return 0;
}

static int do_rx_iscsi_hdr(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	struct socket *sk; 
	struct adapter *sc = iq->adapter;
	sk = cpl_find_sock(sc, m); 

	//printf("%s: sk:%p calling process_rx_iscsi m:%p\n", __func__, sk, m);
	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_rx_iscsi_hdr(sk, m);
	return 0;
}

static int do_rx_data_ddp(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	printf("%s: \n", __func__);
        return 0;
}

static int do_rx_iscsi_ddp(struct sge_iq *iq, const struct rss_header *rss, struct mbuf *m)
{
	struct socket *sk; 
	struct adapter *sc; // = iq->adapter;
	const struct cpl_rx_iscsi_ddp *cpl = (const void *)(rss + 1);

	if (!iq) {
		printf("%s: iq is NULL",__func__);
		return 0;
	}
	sc = iq->adapter;
	if (!sc) {
		printf("%s: sc is NULL",__func__);
		return 0;
	}
	m = m_get(M_NOWAIT, MT_DATA);
        if (m == NULL)
                CXGBE_UNIMPLEMENTED("mbuf alloc failure");
        memcpy(mtod(m, unsigned char *), cpl, sizeof(struct cpl_rx_iscsi_ddp));
	sk = cpl_find_sock(sc, m); 

	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_rx_data_ddp(sk, m);
	return 0;
}
static int t4_ulp_mbuf_push(struct socket *so, struct mbuf *m)
{
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	struct inpcb *inp = so_sotoinpcb(so);
	//struct sockbuf *sb = &so->so_snd;
	iscsi_socket *isock = (iscsi_socket *)(so)->so_emuldata;;

	/* append mbuf to ULP queue */
	//SOCKBUF_LOCK(sb);
	mtx_lock(&isock->ulp2_writeq.lock);
	mbufq_tail(&isock->ulp2_writeq, m);
	mtx_unlock(&isock->ulp2_writeq.lock);
	//SOCKBUF_UNLOCK(sb);

	INP_WLOCK(inp);
	t4_ulp_push_frames(toep->td->tod.tod_softc, toep, 0);
	INP_WUNLOCK(inp);
        return 0;
}

static struct mbuf *iscsi_queue_handler_callback(struct socket *sk,
                                        unsigned int cmd, int *qlen)
{
        iscsi_socket *isock;
        struct mbuf *m0 = NULL;

        if (!sk)
                return NULL;
        isock = (iscsi_socket *)(sk)->so_emuldata;

        if (!isock)
                return NULL;

        switch(cmd) {
                case 0:/* PEEK */
                        m0 = mbufq_peek(&isock->ulp2_writeq);
                break;
                case 1:/* QUEUE_LEN */
                        *qlen = mbufq_len(&isock->ulp2_writeq);
                        m0 = mbufq_peek(&isock->ulp2_writeq);
                break;
                case 2:/* DEQUEUE */
                        //SOCKBUF_LOCK(&sk->so_snd);
			mtx_lock(&isock->ulp2_writeq.lock);
                        m0 = mbufq_dequeue(&isock->ulp2_writeq);
			mtx_unlock(&isock->ulp2_writeq.lock);
                        //SOCKBUF_UNLOCK(&sk->so_snd);

                        mtx_lock(&isock->ulp2_wrq.lock);
                        mbufq_tail(&isock->ulp2_wrq, m0);
                        mtx_unlock(&isock->ulp2_wrq.lock);

                        m0 = mbufq_peek(&isock->ulp2_writeq);
                break;
        }
        return m0;
}

static void iscsi_cpl_handler_callback(struct tom_data *td, struct socket *sk,
                                        void *m, unsigned int op)
{
        //printf("iscsi_cpl_handler_callback: sk 0x%p, rcv op 0x%x from TOM.\n", sk, op);
        switch (op) {
        case CPL_ISCSI_HDR:
                process_rx_iscsi_hdr(sk, m);
                break;
        case CPL_RX_DATA_DDP:
                process_rx_data_ddp(sk, m);
                break;
        case CPL_SET_TCB_RPL:
                //process_set_tcb_rpl(sk, m);
                break;
        case CPL_FW4_ACK:
                process_fw4_ack(sk, m);
                break;
        default:
                printf("sk 0x%p, op 0x%x from TOM, NOT supported.\n",
                                sk, op);
                break;
        }
}

static void t4_register_cpl_handler_with_tom(struct adapter *sc)
{
	t4tom_register_cpl_iscsi_callback(iscsi_cpl_handler_callback);
	t4tom_register_queue_iscsi_callback(iscsi_queue_handler_callback);
	//if (!t4tom_cpl_handler_registered(sc, CPL_ISCSI_HDR)) {
		t4_register_cpl_handler(sc, CPL_ISCSI_HDR, do_rx_iscsi_hdr);
		t4_register_cpl_handler(sc, CPL_ISCSI_DATA, do_rx_iscsi_hdr);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_ISCSI_HDR_REGISTERED_BIT;
		//os_log_info("%s: register t4 cpl handler CPL_ISCSI_HDR.\n", __func__);
//	} else 
//		printf("t4 cpl handler: CPL_ISCSI_HDR already registered!\n");

	if (!t4tom_cpl_handler_registered(sc, CPL_SET_TCB_RPL)) {
		t4_register_cpl_handler(sc, CPL_SET_TCB_RPL, do_set_tcb_rpl);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_SET_TCB_RPL_REGISTERED_BIT;
		printf("register t4 cpl handler CPL_SET_TCB_RPL.\n");
	} else
		printf("t4 cpl handler CPL_SET_TCB_RPL NOT registered.\n");

	t4_register_cpl_handler(sc, CPL_RX_ISCSI_DDP, do_rx_iscsi_ddp);

	if (!t4tom_cpl_handler_registered(sc, CPL_RX_DATA_DDP)) {
		t4_register_cpl_handler(sc, CPL_RX_DATA_DDP, do_rx_data_ddp);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_RX_DATA_DDP_REGISTERED_BIT;
		printf("register t4 cpl handler CPL_RX_DATA_DDP.\n");
	} else
		printf("t4 cpl handler CPL_RX_DATA_DDP NOT registered.\n");
}

static void t4_unregister_cpl_handler_with_tom(struct adapter *sc)
{
	/* de-register CPL handles */
	t4tom_register_cpl_iscsi_callback(NULL);
	t4tom_register_queue_iscsi_callback(NULL);
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_ISCSI_HDR_REGISTERED_BIT)) {
		t4_register_cpl_handler(sc, CPL_ISCSI_HDR, NULL);
		t4_register_cpl_handler(sc, CPL_ISCSI_DATA, NULL);
	}
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_SET_TCB_RPL_REGISTERED_BIT))
		t4_register_cpl_handler(sc, CPL_SET_TCB_RPL, NULL);
	t4_register_cpl_handler(sc, CPL_RX_ISCSI_DDP, NULL);
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_RX_DATA_DDP_REGISTERED_BIT))
		t4_register_cpl_handler(sc, CPL_RX_DATA_DDP, NULL);
}

static
int send_set_tcb_field(struct socket *sk, u16 word, u64 mask, u64 val,
                                int no_reply)
{
        struct wrqe *wr;
        struct cpl_set_tcb_field *req;
        struct inpcb *inp = sotoinpcb(sk);
        struct tcpcb *tp = intotcpcb(inp);
        struct toepcb *toep = tp->t_toe;

        wr = alloc_wrqe(sizeof(*req), toep->ctrlq);
        if (wr == NULL)
                return -1;
        req = wrtod(wr);

        INIT_TP_WR_MIT_CPL(req, CPL_SET_TCB_FIELD, toep->tid);
        req->reply_ctrl = htobe16(V_NO_REPLY(no_reply) |
                V_QUEUENO(toep->ofld_rxq->iq.abs_id));
        req->word_cookie = htobe16(V_WORD(word) | V_COOKIE(0));
        req->mask = htobe64(mask);
        req->val = htobe64(val);

        t4_wrq_tx(toep->td->tod.tod_softc, wr);
	printf("%s: toep:%p set ULP_MODE=2\n", __func__, toep);
        return 0;
}

static int cxgbei_set_ulp_mode(struct socket *so, struct toepcb *toep,
				unsigned char hcrc, unsigned char dcrc)
{
	int rv = 0, val = 0;

	toep->ulp_mode = ULP_MODE_ISCSI;
	if (hcrc)
		val |= ULP_CRC_HEADER;
	if (dcrc)
		val |= ULP_CRC_DATA;
	val <<= 4;
	val |= ULP_MODE_ISCSI;
	rv = send_set_tcb_field(so, 0, 0xfff, val, 0);
	return rv;
}

#if 0
/* count how many bits needed for a given unsigned value */
static inline int uint_bits_needed (unsigned long v)
{
        int i = 0;

        for (v >>= 1; v > 0; v >>= 1, i++)
                ;
        return i;
}

static void remove_cxgbei_dev(offload_device *odev)
{
}
#endif
static offload_device *add_cxgbei_dev(struct ifnet *dev, struct toedev *tdev)
{
#ifdef T4_DDP
        struct cxgbi_ulp2_ddp_info *ddp;
#endif
	offload_device *odev = NULL;
	odev = offload_device_new(tdev);
	if (odev == NULL) {
		printf("%s: odev is NULL\n", __func__);
		return odev;
	}
	printf("%s:New T4 %s, tdev 0x%p, odev 0x%p.\n",
			__func__, dev->if_xname, tdev, odev);
	odev->d_tdev = tdev;
	odev->d_ulp_rx_datagap = sizeof(struct cpl_iscsi_hdr_no_rss);
	odev->d_flag = ODEV_FLAG_ULP_CRC_ENABLED;

	odev->tdev2ddp = t4_tdev2ddp;
	ddp = t4_ddp_init(dev, tdev);
	if (ddp) {
		printf("T4 %s, odev 0x%p, ddp 0x%p initialized.\n",
			dev->if_xname, odev, ddp);

		odev->d_flag |= ODEV_FLAG_ULP_DDP_ENABLED;
		cxgbi_ulp2_adapter_ddp_info(ddp,
			(struct cxgbi_ulp2_tag_format *)&odev->d_tag_format,
			&odev->d_payload_tmax, &odev->d_payload_rmax);
	}
	return odev;
}

static void iscsi_ofld_ddp_handler_callback(void *conn, void *scmd, void *task, unsigned int *itt, int mode)
{
	if (mode) { /* target */
		*itt = htonl(cxgbei_task_reserve_ttt(conn, scmd, task));
	} else { /* initiator */
		*itt = htonl(cxgbei_task_reserve_itt(conn, scmd, task));
	}
	return;
}

static void iscsi_ofld_cleanup_handler_callback(void *conn, void *ofld_priv)
{
	struct icl_conn *ic = (struct icl_conn *)conn;
	//struct iscsi_outstanding *task = (struct iscsi_outstanding *)io;
	cxgbei_task_data *tdata = NULL;
	struct socket *so = NULL;
        iscsi_socket *isock = NULL;
        offload_device *odev = NULL;

	if (!ic->ic_socket) return;

	so = ic->ic_socket;

	isock = (iscsi_socket *)(so)->so_emuldata;
	if (!isock) return;
	odev = isock->s_odev;

	//if (!task) return;

	tdata = (cxgbei_task_data *)(ofld_priv);
	if (!tdata) return;	
	
	if (cxgbi_ulp2_is_ddp_tag(&odev->d_tag_format, tdata->sc_ddp_tag))
		t4_sk_ddp_tag_release(isock, tdata->sc_ddp_tag);
	memset(tdata, 0, sizeof(*tdata));	
	//task->ofld_priv = NULL;
	return;
}
static void t4_sk_tx_mbuf_setmode(struct icl_pdu *req, void *toep, void *mbuf,
				unsigned char mode, unsigned char hcrc, unsigned char dcrc)
{
	struct mbuf *m = (struct mbuf *)mbuf;
	struct ulp_mbuf_cb *cb;

	cb = get_ulp_mbuf_cb(m);
	if (!cb)
		return;
	cb->ulp_mode = ULP_MODE_ISCSI << 4;
	if (hcrc)
		cb->ulp_mode |= 1;
	if (dcrc)
		cb->ulp_mode |= 2;
	cb->pdu = req;
	return;
}

static int cxgbei_pdu_finalize(struct icl_pdu *request)
{
	size_t padding = 0, pdu_len;
	uint32_t zero = 0;
	int ok;

	icl_pdu_set_data_segment_length(request, request->ip_data_len);

	pdu_len = sizeof(struct iscsi_bhs) + request->ip_data_len +
				icl_pdu_padding(request);

	//printf("%s: ip_bhs_mbuf:%p ip_data_mbuf:%p pdu_len:%zu\n",
	//	__func__, request->ip_bhs_mbuf, request->ip_data_mbuf, pdu_len);

	if (request->ip_data_len != 0) {
		padding = icl_pdu_padding(request);
		if (padding > 0) {
			ok = m_append(request->ip_data_mbuf, padding,
			    (void *)&zero);
			if (ok != 1) {
				printf("WARNING:failed to append padding\n");
				return (1);
			}
		}

		m_cat(request->ip_bhs_mbuf, request->ip_data_mbuf);
		request->ip_data_mbuf = NULL;
	}
	//printf("padding:%zu ip_bhs_mbuf->m_next:%p ip_bhs_mbuf->m_nextpkt:%p\n",
	//	padding, request->ip_bhs_mbuf->m_next, request->ip_bhs_mbuf->m_nextpkt);

	request->ip_bhs_mbuf->m_pkthdr.len = pdu_len;

	return (0);
}

static int iscsi_ofld_tx_handler_callback(void *conn, void *ioreq)
{
	struct icl_conn *ic = (struct icl_conn *)conn;
	struct icl_pdu *req = (struct icl_pdu *)ioreq;
	struct mbuf *m = req->ip_bhs_mbuf;
	struct socket *so = ic->ic_socket;
	struct tcpcb *tp = so_sototcpcb(so);

	//printf("%s: m:%p ic_header_crc32c:%d ic_data_crc32c:%d\n",
	//	__func__, m, ic->ic_header_crc32c, ic->ic_data_crc32c);

	cxgbei_pdu_finalize(req);
	t4_sk_tx_mbuf_setmode(req, tp->t_toe, m, 2,
		ic->ic_header_crc32c ? ISCSI_HEADER_DIGEST_SIZE : 0,
		(req->ip_data_len && ic->ic_data_crc32c) ? ISCSI_DATA_DIGEST_SIZE : 0);
	
	t4_ulp_mbuf_push(ic->ic_socket, m);
	return 0;
}
static uint32_t
iscsi_ofld_parse_itt_handler_callback(struct socket *so, uint32_t itt)
{
        offload_device *odev = NULL;
        iscsi_socket *isock = (iscsi_socket *)(so)->so_emuldata;

	if (!isock) return itt;

	odev = isock->s_odev;
	return cxgbi_ulp2_tag_nonrsvd_bits(&odev->d_tag_format, ntohl(itt));
}

/* called from TOM, socket is passed as argument  */
static int iscsi_ofld_conn_handler_callback(struct socket *so, void *conn)
{
	struct tcpcb *tp = so_sototcpcb(so);
	struct toepcb *toep = tp->t_toe;
	struct adapter *sc = NULL;
	struct toedev *tdev = NULL;
	iscsi_socket *isock = NULL;
	struct ifnet *ifp = NULL;
	unsigned int tid = toep->tid;
	offload_device *odev = NULL;
	struct icl_conn *ic = (struct icl_conn*)conn;

	if (!toep) return -1;

	ifp = toep->port->ifp;

	if (!ifp) return -1;

	if (!(sototcpcb(so)->t_flags & TF_TOE) ||
                !(ifp->if_capenable & IFCAP_TOE)) {
		printf("ERR: TOE not enabled on interface:%s\n", ifp->if_xname);
		return -1;
	}

	/* if ULP_MODE is set by TOE driver, treat it as non-offloaded */
	if (toep->ulp_mode) {
		printf("T4 sk 0x%p, ulp mode already set 0x%x.\n",
				so, toep->ulp_mode);
		return -1;
	}
	sc = toep->port->adapter;
	tdev = &toep->td->tod;
	/* if toe dev is not set, treat it as non-offloaded */
	if (!tdev) {
		printf("T4 sk 0x%p, tdev NULL.\n", so);
		return -1;
	}

	isock = (iscsi_socket *)malloc(sizeof(iscsi_socket), M_CXGBEIOFLD, M_NOWAIT | M_ZERO);
	if (!isock) {
		printf("T4 sk 0x%p, isock alloc failed.\n", so);
		return -1;
	}
	isock->mbuf_ulp_lhdr = NULL;
	isock->sock = so;
	isock->s_conn = conn;
	mtx_init(&isock->iscsi_rcv_mbufq.lock,"isock_lock" , NULL, MTX_DEF);	
	mtx_init(&isock->ulp2_wrq.lock,"ulp2_wrq lock" , NULL, MTX_DEF);	
	mtx_init(&isock->ulp2_writeq.lock,"ulp2_writeq lock" , NULL, MTX_DEF);	
	so->so_emuldata = isock;
	so->so_options |=  0x8000; //SO_NO_DDP;
	printf("%s: sc:%p toep:%p iscsi_start:0x%x iscsi_size:0x%x caps:%d :%s.\n",
	__func__, sc, toep, sc->vres.iscsi.start, sc->vres.iscsi.size, sc->iscsicaps, sc->lockname);
	/* register ULP CPL handlers with TOM */
	/* Register CPL_RX_ISCSI_HDR, CPL_RX_DATA_DDP callbacks with TOM */
	t4_register_cpl_handler_with_tom(sc);

	//sc->iscsi_softc = NULL;
//#ifdef CXGBEI_DDP
	/* DDP initialization. Once for each tdev */
	/* TODO. check if DDP is already configured for this tdev */
	odev = offload_device_find(tdev);
	if (odev == NULL) /* for each tdev we have a corresponding odev */
	{
		if ((odev = add_cxgbei_dev(ifp, tdev)) == NULL) {
			printf("T4 sk 0x%p, tdev %s, 0x%p, odev NULL.\n",
						so, ifp->if_xname, tdev);
			return -1;
		}
	}
//#endif /* CXGBEI_DDP */

	printf("%s: tdev:%p sc->iscsi_softc:%p odev:%p\n", __func__, tdev, sc->iscsi_softc, odev);
	isock->s_odev = odev;
	isock->s_tid = tid;
	/* Move connection to ULP mode, SET_TCB_FIELD */
	cxgbei_set_ulp_mode(so, toep,
		ic->ic_header_crc32c, ic->ic_data_crc32c);

	isock->s_hcrc_len = (ic->ic_header_crc32c ? 4 : 0);
	isock->s_dcrc_len = (ic->ic_data_crc32c ? 4 : 0);
	return 0;
}

static int iscsi_ofld_conn_cleanup_handler_callback(struct socket *so)
{
	iscsi_socket *isock = NULL;
	isock = (iscsi_socket *)(so)->so_emuldata;
	if (!isock) return 0;

	free(isock, M_CXGBEIOFLD);
	return 0;
}

static int cxgbei_init(void)
{
	t4tom_register_iscsi_ofld_callback(iscsi_ofld_conn_handler_callback);
	t4tom_register_iscsi_ofld_conn_cleanup_callback(iscsi_ofld_conn_cleanup_handler_callback);
	t4tom_register_iscsi_ofld_ddp_callback(iscsi_ofld_ddp_handler_callback);
	t4tom_register_iscsi_ofld_cleanup_callback(iscsi_ofld_cleanup_handler_callback);
	t4tom_register_iscsi_ofld_tx_callback(iscsi_ofld_tx_handler_callback);
	t4tom_register_iscsi_ofld_parse_itt_callback(iscsi_ofld_parse_itt_handler_callback);

	return cxgbi_ulp2_init();
}

static void cxgbei_cleanup(void)
{
	cxgbi_ulp2_exit();
	t4tom_register_iscsi_ofld_callback(NULL);
	t4tom_register_iscsi_ofld_conn_cleanup_callback(NULL);
	t4tom_register_iscsi_ofld_ddp_callback(NULL);
	t4tom_register_iscsi_ofld_cleanup_callback(NULL);
	t4tom_register_iscsi_ofld_tx_callback(NULL);
	t4tom_register_iscsi_ofld_parse_itt_callback(NULL);
	offload_device_remove();
	printf("cxgbei_cleanup module: unloaded Sucessfully.\n");
}

static int
cxgbei_loader(struct module *mod, int cmd, void *arg)
{
	int err = 0;

	switch (cmd) {
	case MOD_LOAD:
		err = cxgbei_init();
		if (err != 0) {
			printf("cxgbei_init failed for chiscsi_t4.\n");
			err = (ENOMEM);
			break;
		}
		printf("cxgbei module loaded Sucessfully.\n");
		break;
	case MOD_UNLOAD:
		cxgbei_cleanup();
		printf("cxgbei cleanup completed sucessfully.\n");
		break;
	default:
		err = (EINVAL);
		break;
	}

	return (err);
}

static moduledata_t cxgbei_mod = {
	"cxgbei",
	cxgbei_loader,
	NULL,
};

MODULE_VERSION(cxgbei, 1);
DECLARE_MODULE(cxgbei, cxgbei_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_DEPEND(cxgbei, t4_tom, 1, 1, 1);
MODULE_DEPEND(cxgbei, cxgbe, 1, 1, 1);
MODULE_DEPEND(cxgbei, icl, 1, 1, 1);
