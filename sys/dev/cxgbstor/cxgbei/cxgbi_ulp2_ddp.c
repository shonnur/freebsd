/*
 * cxgbi_ulp2_ddp.c: Chelsio S4xx iSCSI DDP Manager.
 *
 * Copyright (c) 2010 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Karen Xie (kxie@chelsio.com)
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

#define ddp_log_error(fmt...) printf("cxgbi_ulp2_ddp: ERR! " fmt)
#define ddp_log_warn(fmt...)  printf("cxgbi_ulp2_ddp: WARN! " fmt)
#define ddp_log_info(fmt...)  printf("cxgbi_ulp2_ddp: " fmt)

//#define __DEBUG_CXGBI_DDP__
#ifdef __DEBUG_CXGBI_DDP__
#define ddp_log_debug(fmt, args...) \
	printf("cxgbi_ulp2_ddp: %s - " fmt, __func__ , ## args)
#else
#define ddp_log_debug(fmt...)
#endif

static inline int cxgbi_counter_dec_and_read(volatile int *p)
{	
	atomic_subtract_acq_int(p, 1);
	return atomic_load_acq_int(p);
}

#define RSVD_PAGE_MAX   2
struct page *chrsvd_pages[RSVD_PAGE_MAX] = {NULL, NULL};
void *chrsvd_pages_addr[RSVD_PAGE_MAX] = {NULL, NULL};

int cxgbi_ulp2_init(void)
{
        int i;

        for (i = 0; i < RSVD_PAGE_MAX; i++) {
        	chrsvd_pages[i] = (struct page *)malloc(PAGE_SIZE,
					M_CXGBEIOFLD, M_NOWAIT|M_ZERO);
                if (!chrsvd_pages[i]) {
                        printf("ddp rsvd page %d OOM.\n", i);
                        return -ISCSI_ENOMEM;
                }
        }

        return 0;
}

void cxgbi_ulp2_exit(void)
{
        int i;
        for (i = 0; i < RSVD_PAGE_MAX; i++)
                if (chrsvd_pages[i]) {
			free(chrsvd_pages[i], M_CXGBEIOFLD);
                        chrsvd_pages[i] = NULL;
                }
}

static inline int get_order(unsigned long size)
{
        int order;

        size = (size - 1) >> PAGE_SHIFT;
        order = 0;
        while (size) {
                order++;
                size >>= 1;
        }
        return (order);
}

/*
 * Map a single buffer address.
 */
static void
ulp2_dma_map_addr(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	bus_addr_t *ba = arg;
	if (error)
		return;

	KASSERT(nseg == 1, ("%s: %d segments returned!", __func__, nseg));

	*ba = segs->ds_addr;
}

static int
ulp2_dma_tag_create(struct cxgbi_ulp2_ddp_info *ddp)
{
	int rc;


	rc = bus_dma_tag_create(NULL, 1, 0, BUS_SPACE_MAXADDR,
                BUS_SPACE_MAXADDR, NULL, NULL, UINT32_MAX , 8,
                BUS_SPACE_MAXSIZE, BUS_DMA_ALLOCNOW, NULL, NULL, &ddp->ulp_ddp_tag);

	if (rc != 0) {
		printf("%s(%d): bus_dma_tag_create() "
			"failed (rc = %d)!\n",
			__FILE__, __LINE__, rc);
		return rc;
        }
	return 0;
}

/*
 * iSCSI Direct Data Placement
 *
 * T3/4 ulp2 h/w can directly place the iSCSI Data-In or Data-Out PDU's
 * payload into pre-posted final destination host-memory buffers based on the
 * Initiator Task Tag (ITT) in Data-In or Target Task Tag (TTT) in Data-Out
 * PDUs.
 *
 * The host memory address is programmed into h/w in the format of pagepod
 * entries.
 * The location of the pagepod entry is encoded into ddp tag which is used or
 * is the base for ITT/TTT.
 */

unsigned char ddp_page_order[DDP_PGIDX_MAX] = {0, 1, 2, 4};
unsigned char ddp_page_shift[DDP_PGIDX_MAX] = {12, 13, 14, 16};
unsigned char page_idx = DDP_PGIDX_MAX;

static inline int ddp_find_unused_entries(struct cxgbi_ulp2_ddp_info *ddp,
					  unsigned int start, unsigned int max,
					  unsigned int count,
					  struct cxgbi_ulp2_gather_list *gl)
{
	unsigned int i, j, k;

	/* not enough entries */
	if ((max - start) < count)
		return -EBUSY;

	max -= count;
	mtx_lock(&ddp->map_lock);
	for (i = start; i < max;) {
		for (j = 0, k = i; j < count; j++, k++) {
			if (ddp->gl_map[k])
				break;
		}
		if (j == count) {
			for (j = 0, k = i; j < count; j++, k++)
				ddp->gl_map[k] = gl;
			mtx_unlock(&ddp->map_lock);
			return i;
		}
		i += j + 1;
	}
	mtx_unlock(&ddp->map_lock);
	return -EBUSY;
}

static inline void ddp_unmark_entries(struct cxgbi_ulp2_ddp_info *ddp,
				      int start, int count)
{
	mtx_lock(&ddp->map_lock);
	memset(&ddp->gl_map[start], 0,
	       count * sizeof(struct cxgbi_ulp2_gather_list *));
	mtx_unlock(&ddp->map_lock);
}

/**
 * cxgbi_ulp2_ddp_find_page_index - return ddp page index for a given page size
 * @pgsz: page size
 * return the ddp page index, if no match is found return DDP_PGIDX_MAX.
 */
int cxgbi_ulp2_ddp_find_page_index(unsigned long pgsz)
{
	int i;

	for (i = 0; i < DDP_PGIDX_MAX; i++) {
		if (pgsz == (1UL << ddp_page_shift[i]))
			return i;
	}
	ddp_log_info("ddp page size 0x%lx not supported.\n", pgsz);
	return DDP_PGIDX_MAX;
}

static int cxgbi_ulp2_ddp_adjust_page_table(void)
{
	int i;
	unsigned int base_order, order;

	if (PAGE_SIZE < (1UL << ddp_page_shift[0])) {
		ddp_log_info("PAGE_SIZE %u too small, min. %lu.\n",
				PAGE_SIZE, 1UL << ddp_page_shift[0]);
		return -EINVAL;
	}

	base_order = get_order(1UL << ddp_page_shift[0]);
	order = get_order(1 << PAGE_SHIFT);
	for (i = 0; i < DDP_PGIDX_MAX; i++) {
		/* first is the kernel page size, then just doubling the size */
		ddp_page_order[i] = order - base_order + i;
		ddp_page_shift[i] = PAGE_SHIFT + i;
	}
	return 0;
}

	
static inline void ddp_gl_unmap(struct toedev *tdev,
				struct cxgbi_ulp2_gather_list *gl)
{
	int i;
	struct adapter *sc = tdev->tod_softc;
	struct cxgbi_ulp2_ddp_info *ddp = sc->iscsi_softc;

	if (!gl->pages[0])
		return;

	for (i = 0; i < gl->nelem; i++) {
		bus_dmamap_unload(ddp->ulp_ddp_tag, gl->dma_sg[i].bus_map);
		bus_dmamap_destroy(ddp->ulp_ddp_tag, gl->dma_sg[i].bus_map);
	}
}

static inline int ddp_gl_map(struct toedev *tdev,
			     struct cxgbi_ulp2_gather_list *gl)
{
	int i, rc;
	bus_addr_t pa;
	struct cxgbi_ulp2_ddp_info *ddp;
	struct adapter *sc = tdev->tod_softc;

	ddp = (struct cxgbi_ulp2_ddp_info *)sc->iscsi_softc;
	if (!ddp) {
		printf("%s: ERROR tdev:%p sc:%p ddp:%p\n", __func__, tdev, sc, ddp);
		return -ENOMEM;
	}
	mtx_lock(&ddp->map_lock);
	for (i = 0; i < gl->nelem; i++) {
		rc = bus_dmamap_create(ddp->ulp_ddp_tag, 0, &gl->dma_sg[i].bus_map);
		if (rc != 0) {
			ddp_log_error("unable to map page 0x%p.\n", gl->pages[i]);
			goto unmap;
		}
		rc = bus_dmamap_load(ddp->ulp_ddp_tag, gl->dma_sg[i].bus_map,
				gl->pages[i], PAGE_SIZE, ulp2_dma_map_addr,
				&pa, BUS_DMA_NOWAIT);
		if (rc != 0) {
			ddp_log_error("unable to load page 0x%p.\n", gl->pages[i]);
			goto unmap;
		}
		gl->dma_sg[i].phys_addr = pa;
	}
	mtx_unlock(&ddp->map_lock);

	return i;

unmap:
	if (i) {
		unsigned int nelem = gl->nelem;

		gl->nelem = i;
		ddp_gl_unmap(tdev, gl);
		gl->nelem = nelem;
	}
	return -ENOMEM;
}

/**
 * cxgbi_ulp2_ddp_make_gl_from_iscsi_sgvec - build ddp page buffer list
 * @xferlen: total buffer length
 * @sgl: page buffer scatter-gather list (struct cxgbei_sgl_t)
 * @sgcnt: # of page buffers
 * @gfp: allocation mode
 *
 * construct a ddp page buffer list from the scsi scattergather list.
 * coalesce buffers as much as possible, and obtain dma addresses for
 * each page.
 *
 * Return the cxgbi_ulp2_gather_list constructed from the page buffers if the
 * memory can be used for ddp. Return NULL otherwise.
 */
struct cxgbi_ulp2_gather_list *cxgbi_ulp2_ddp_make_gl_from_iscsi_sgvec
			(unsigned int xferlen, cxgbei_sgl_t *sgl,
			 unsigned int sgcnt, void *tdev,
			 int gfp)
{
	struct cxgbi_ulp2_gather_list *gl;
	cxgbei_sgl_t *sg = sgl;
	struct page *sgpage = (struct page *)((u64)sg->sg_addr & (~PAGE_MASK));
	unsigned int sglen = sg->sg_length;
	unsigned int sgoffset = (u64)sg->sg_addr & PAGE_MASK;
	unsigned int npages = (xferlen + sgoffset + PAGE_SIZE - 1) >>
			      PAGE_SHIFT;
	int i = 1, j = 0;

	//printf("%s: xferlen:0x%x ddp_threshold:0x%x\n", __func__, xferlen, DDP_THRESHOLD);
	if (xferlen <= DDP_THRESHOLD) {
		//printf("%s:xfer %u < threshold %u, no ddp.\n",
		//	      __func__, xferlen, DDP_THRESHOLD);
		return NULL;
	}

	gl = malloc(sizeof(struct cxgbi_ulp2_gather_list) +
		     //npages * (sizeof(dma_addr_t) + sizeof(struct page *)),
		     npages * (sizeof(struct dma_segments) + sizeof(struct page *)),
			M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!gl) {
		printf("%s: gl alloc failed\n", __func__);
		return NULL;
	}

	gl->pages = (struct page **)&gl->dma_sg[npages];
	gl->length = xferlen;
	gl->offset = sgoffset;
	gl->pages[0] = sgpage;
	//printf("%s: xferlen:0x%x gl->length:0x%x gl->offset:0x%x sg_addr:%p npages:%d\n",
	//	 __func__, xferlen, gl->length, gl->offset, sg->sg_addr, npages);

	for (i = 1, sg = sg_next(sg); i < sgcnt; i++, sg = sg_next(sg)) {
		//struct page *page = sg->sg_page;
		struct page *page = sg->sg_addr;

		if (sgpage == page && sg->sg_offset == sgoffset + sglen)
			sglen += sg->sg_length;
		else {
			/* make sure the sgl is fit for ddp:
			 * each has the same page size, and
			 * all of the middle pages are used completely
			 */
			if ((j && sgoffset) ||
			    ((i != sgcnt - 1) &&
			     //((sglen + sgoffset) & ~PAGE_MASK))){
			     ((sglen + sgoffset) & ~CHISCSI_PAGE_MASK))){
				printf("%s:error_out1 i:%d j:%d sgoffset:%d sgcnt:%d sglen:%d\n",__func__, i, j, sgoffset, sgcnt, sglen);
				goto error_out;
			}

			j++;
			if (j == gl->nelem || sg->sg_offset) {
				printf("%s: error_out2 j:%d gl->nelem:%d sg_offset:%lu\n", __func__, j,  gl->nelem,  sg->sg_offset);
				goto error_out;
			}
			gl->pages[j] = page;
			sglen = sg->sg_length;
			sgoffset = sg->sg_offset;
			sgpage = page;
		}
	}
	gl->nelem = ++j;

	if (ddp_gl_map(tdev, gl) < 0)
		goto error_out;

	return gl;

error_out:
	printf("%s error_out sgcnt:%d xferlen:%d\n", __func__, sgcnt, xferlen);
	free(gl, M_DEVBUF);
	return NULL;
}

/*
 * temp. function for handling the sgl that start from the middle of the 
 * data xfer.
 */
static int check_sgl_dma_addr_set(cxgbei_sgl_t *sgl, unsigned int sgcnt)
{
	int i;
	cxgbei_sgl_t *sg;

	for (i = 0, sg = sgl; i < sgcnt; i++, sg = sg_next(sg)) {
		if (!sg->sg_dma_addr || !(sg->sg_flag & ISCSI_SG_SBUF_DMABLE)) {
			ddp_log_info("sg %d, invalid for dma, flag 0x%x, dma %p.\n",
					i, sg->sg_flag, sg->sg_dma_addr);
			return -EINVAL;
		} 
	}

	return 0;
}

static int check_sgl_dma_addr_for_ddp(cxgbei_sgl_t *sgl, unsigned int sgcnt,
				unsigned int xfer_total,
				unsigned int xfer_offset, unsigned int dlen)
{
	int i;
	cxgbei_sgl_t *sg, *sg_last;

	/* all middle pages should be fully used */
	for (i = 1, sg = sg_next(sgl); i < sgcnt - 1; i++, sg = sg_next(sg)) {
		/* make sure the dma address is page-aligned (i.e., page
		 * offset = 0) */
		if ((u64)sg->sg_dma_addr & ~CHISCSI_PAGE_MASK) {
			ddp_log_info("mid sg %d/%u, dma %p NOT aligned.\n",
					i, sgcnt, sg->sg_dma_addr);
			return -EINVAL;
		}
		/* and the length is multiple of PAGE_SIZE */
		if (sg->sg_length % PAGE_SIZE) {
			ddp_log_info("mid sg %d/%u, len %lu NOT N*pages.\n",
					i, sgcnt, sg->sg_length);
			return -EINVAL;
		}
	}
	if (sgcnt > 1)
		sg_last = sg;
	else
		sg_last = sgl;
	sg = sgl;
	
	/* last page: make sure the dma address is page-aligned 
 	 * (i.e., page offset = 0) */
	if (sgcnt > 1 && (u64)sg_last->sg_dma_addr & ~CHISCSI_PAGE_MASK) {
		ddp_log_info("last sg %d/%d, dma %p NOT page aligned.\n",
				sgcnt - 1, sgcnt, sg_last->sg_dma_addr);
		return -EINVAL;
	}

	if ((xfer_offset + dlen) < xfer_total) {
		/* not all of the data buffers are present, make sure the last
		 * page are fully used, since it is a middle page for the
		 * complete transfer */
		if (sgcnt > 1 && sg_last->sg_length % PAGE_SIZE) {
			ddp_log_info("partial %u+%u/%u, last sg %u/%u, %lu NOT N pages.\n",
					xfer_offset, dlen, xfer_total,
					sgcnt - 1, sgcnt, sg_last->sg_length);
			return -EINVAL;
		}
	} else if (sgcnt == 1) {
		/* last buffer */
		if (xfer_offset && (u64)sg->sg_dma_addr & ~CHISCSI_PAGE_MASK) {
			ddp_log_info("last %u+%u/%u, sg 0/%u dma %p NOT aligned.\n",
					xfer_offset, dlen, xfer_total,
					sgcnt, sg->sg_dma_addr);
			return -EINVAL;
		}
                return 0;
	}

	if (xfer_offset) {
		/* not all of the data buffers are present, make sure the first 
		   page are fully used, since it is a middle page for the
		   complete transfer */
		if (sg->sg_length % PAGE_SIZE) {
			ddp_log_info("partial %u+%u/%u, sg 0/%u len %lu NOT N pages.\n",
					xfer_offset, dlen, xfer_total,
					sgcnt, sg->sg_length);
			return -EINVAL;
		}
		if ((u64)sg->sg_dma_addr & ~CHISCSI_PAGE_MASK) {
			ddp_log_info("partial %u+%u/%u, sg 0/%u dma %p NOT aligned.\n",
					xfer_offset, dlen, xfer_total,
					sgcnt, sg->sg_dma_addr);
			return -EINVAL;
		}
	}

	/* if first page is not page_aligned, we need to break it into multiple
	 * pages. With all pages fully used except the first one,
	 * so make sure it ends on the page boundary */
	if (sgcnt > 1 && ((sg->sg_length + (u64)sg->sg_dma_addr) & ~CHISCSI_PAGE_MASK)) {
		ddp_log_info("%u+%u/%u, sg 1/%u dma %p + %lu NOT aligned.\n",
				xfer_offset, dlen, xfer_total, sgcnt,
				sg->sg_dma_addr, sg->sg_length);
		return -EINVAL;
	}

	return 0;
}

/**
 * cxgbi_ulp2_ddp_release_gl - release a page buffer list
 * @gl: a ddp page buffer list
 * @pdev: pci_dev used for pci_unmap
 * free a ddp page buffer list resulted from cxgbi_ulp2_ddp_make_gl().
 */
void cxgbi_ulp2_ddp_release_gl(struct cxgbi_ulp2_gather_list *gl,
			   void *tdev)
{
	ddp_gl_unmap(tdev, gl);
	free(gl, M_DEVBUF);
}

/**
 * cxgbi_ulp2_ddp_tag_reserve - set up ddp for a data transfer
 * @ddp: adapter's ddp info
 * @tid: connection id
 * @tformat: tag format
 * @tagp: contains s/w tag initially, will be updated with ddp/hw tag
 * @gl: the page momory list
 * @gfp: allocation mode
 *
 * ddp setup for a given page buffer list and construct the ddp tag.
 * return 0 if success, < 0 otherwise.
 */
int cxgbi_ulp2_ddp_tag_reserve(struct cxgbi_ulp2_ddp_info *ddp,
				void *isock, unsigned int tid,
				struct cxgbi_ulp2_tag_format *tformat,
				u32 *tagp, struct cxgbi_ulp2_gather_list *gl,
				int gfp, int reply)
{
	struct cxgbi_ulp2_pagepod_hdr hdr;
	unsigned int npods;
	int idx = -1;
	int err = -ENOMEM;
	u32 sw_tag = *tagp;
	u32 tag;

	if (page_idx >= DDP_PGIDX_MAX || !ddp || !gl || !gl->nelem ||
		gl->length < DDP_THRESHOLD) {
		ddp_log_info("pgidx %u, xfer %u/%u, NO ddp.\n",
			      page_idx, gl->length, DDP_THRESHOLD);
		return -EINVAL;
	}

	npods = (gl->nelem + IPPOD_PAGES_MAX - 1) >> IPPOD_PAGES_SHIFT;

	if (ddp->idx_last == ddp->nppods)
		idx = ddp_find_unused_entries(ddp, 0, ddp->nppods, npods, gl);
	else {
		idx = ddp_find_unused_entries(ddp, ddp->idx_last + 1,
					      ddp->nppods, npods, gl);
		if (idx < 0 && ddp->idx_last >= npods) {
			idx = ddp_find_unused_entries(ddp, 0,
				min(ddp->idx_last + npods, ddp->nppods),
						      npods, gl);
		}
	}
	if (idx < 0) {
		ddp_log_info("xferlen %u, gl %u, npods %u NO DDP.\n",
			      gl->length, gl->nelem, npods);
		return idx;
	}

	tag = cxgbi_ulp2_ddp_tag_base(idx, ddp, tformat, sw_tag);
	//printf("%s: sw_tag:0x%x idx:0x%x tag:0x%x\n", __func__, sw_tag, idx, tag);

	hdr.rsvd = 0;
	hdr.vld_tid = htonl(F_IPPOD_VALID | V_IPPOD_TID(tid));
	hdr.pgsz_tag_clr = htonl(tag & ddp->rsvd_tag_mask);
	hdr.maxoffset = htonl(gl->length);
	hdr.pgoffset = htonl(gl->offset);

	err = ddp->ddp_set_map(ddp, isock, &hdr, idx, npods, gl, reply);
	if (err < 0)
		goto unmark_entries;

	ddp->idx_last = idx;
	*tagp = tag;
	return 0;

unmark_entries:
	ddp_unmark_entries(ddp, idx, npods);
	return err;
}

/**
 * cxgbi_ulp2_ddp_tag_release - release a ddp tag
 * @ddp: adapter's ddp info
 * @tag: ddp tag
 * ddp cleanup for a given ddp tag and release all the resources held
 */
void cxgbi_ulp2_ddp_tag_release(struct cxgbi_ulp2_ddp_info *ddp, u32 tag, iscsi_socket *isock)
{
	u32 idx;

	if (!ddp) {
		printf("%s:release ddp tag 0x%x, ddp NULL.\n", __func__, tag);
		return;
	}
	 if (!isock) {
		printf("%s: isock is NULL\n", __func__);
		return;
	}

	idx = (tag >> IPPOD_IDX_SHIFT) & ddp->idx_mask;
	//printf("%s: tag:0x%x idx:0x%x nppods:0x%x\n", __func__, tag, idx, ddp->nppods);
	if (idx < ddp->nppods) {
		struct cxgbi_ulp2_gather_list *gl = ddp->gl_map[idx];
		unsigned int npods;

		if (!gl || !gl->nelem) {
			ddp_log_error("release 0x%x, idx 0x%x, gl 0x%p, %u.\n",
				      tag, idx, gl, gl ? gl->nelem : 0);
			return;
		}
		npods = (gl->nelem + IPPOD_PAGES_MAX - 1) >> IPPOD_PAGES_SHIFT;
		ddp_log_debug("ddp tag 0x%x, release idx 0x%x, npods %u.\n",
			      tag, idx, npods);
		ddp->ddp_clear_map(ddp, gl, tag, idx, npods, isock);
		ddp_unmark_entries(ddp, idx, npods);
		cxgbi_ulp2_ddp_release_gl(gl, ddp->tdev);
	} else
		ddp_log_error("ddp tag 0x%x, idx 0x%x > max 0x%x.\n",
			      tag, idx, ddp->nppods);
}

/**
 * cxgbi_ulp2_adapter_ddp_info - read the adapter's ddp information
 * @ddp: adapter's ddp info
 * @tformat: tag format
 * @txsz: max tx pdu payload size, filled in by this func.
 * @rxsz: max rx pdu payload size, filled in by this func.
 * setup the tag format for a given iscsi entity
 */
int cxgbi_ulp2_adapter_ddp_info(struct cxgbi_ulp2_ddp_info *ddp,
			    struct cxgbi_ulp2_tag_format *tformat,
			    unsigned int *txsz, unsigned int *rxsz)
{
	unsigned char idx_bits;

	if (!tformat)
		return -EINVAL;

	if (!ddp)
		return -EINVAL;

	idx_bits = 32 - tformat->sw_bits;
	tformat->sw_bits = ddp->idx_bits;
	tformat->rsvd_bits = ddp->idx_bits;
	tformat->rsvd_shift = IPPOD_IDX_SHIFT;
	tformat->rsvd_mask = (1 << tformat->rsvd_bits) - 1;

	ddp_log_info("tag format: sw %u, rsvd %u,%u, mask 0x%x.\n",
		      tformat->sw_bits, tformat->rsvd_bits,
		      tformat->rsvd_shift, tformat->rsvd_mask);

	*txsz = min(ULP2_MAX_PDU_PAYLOAD,
			ddp->max_txsz - ISCSI_PDU_NONPAYLOAD_LEN);
	*rxsz = min(ULP2_MAX_PDU_PAYLOAD,
			ddp->max_rxsz - ISCSI_PDU_NONPAYLOAD_LEN);
	ddp_log_info("max payload size: %u/%u, %u/%u.\n",
		     *txsz, ddp->max_txsz, *rxsz, ddp->max_rxsz);
	return 0;
}

/**
 * cxgbi_ulp2_ddp_cleanup - release the cxgbX adapter's ddp resource
 * @tdev: t4cdev adapter
 * release all the resource held by the ddp pagepod manager for a given
 * adapter if needed
 */
void cxgbi_ulp2_ddp_cleanup(struct cxgbi_ulp2_ddp_info **ddp_pp)
{
	int i = 0;
	struct cxgbi_ulp2_ddp_info *ddp = *ddp_pp;

	if (!ddp) {
		ddp_log_error("%s: ddp NULL.\n", __func__);
		return;
	}

	ddp_log_info("tdev, release ddp 0x%p, ref %d.\n",
			ddp, atomic_load_acq_int(&ddp->refcnt));

	if (ddp && (cxgbi_counter_dec_and_read(&ddp->refcnt) == 0)) {
		*ddp_pp = NULL;
		while (i < ddp->nppods) {
			struct cxgbi_ulp2_gather_list *gl = ddp->gl_map[i];
			if (gl) {
				int npods = (gl->nelem + IPPOD_PAGES_MAX - 1)
						>> IPPOD_PAGES_SHIFT;
				printf("tdev, ddp %d + %d.\n",
						i, npods);
				free(gl, M_DEVBUF);
				i += npods;
			} else
				i++;
		}
		if (ddp->rsvd_page_phys_addr)
			bus_dmamap_unload(ddp->ulp_ddp_tag, ddp->ulp_ddp_map); //check this
		cxgbi_ulp2_free_big_mem(ddp);
	}
}

/**
 * ddp_init - initialize the cxgb3/4 adapter's ddp resource
 * @tdev_name: device name
 * @tdev: device
 * @ddp: adapter's ddp info
 * @uinfo: adapter's iscsi info
 * initialize the ddp pagepod manager for a given adapter
 */
static void ddp_init(void *tdev,
			struct cxgbi_ulp2_ddp_info **ddp_pp,
			struct ulp_iscsi_info *uinfo)
{
	struct cxgbi_ulp2_ddp_info *ddp = *ddp_pp;
	unsigned int ppmax, bits;
	int i, rc;
	bus_addr_t pa = 0;

	if (uinfo->ulimit <= uinfo->llimit) {
		ddp_log_warn("tdev, ddp 0x%x >= 0x%x.\n",
			uinfo->llimit, uinfo->ulimit);
		return;
	}
	if (ddp) {
		atomic_add_acq_int(&ddp->refcnt, 1);
		ddp_log_warn("tdev, ddp 0x%p already set up, %d.\n",
				ddp, atomic_load_acq_int(&ddp->refcnt));
		return;
	}

	ppmax = (uinfo->ulimit - uinfo->llimit + 1) >> IPPOD_SIZE_SHIFT;
	if (ppmax <= 1024) {
		ddp_log_warn("tdev, ddp 0x%x ~ 0x%x, nppod %u < 1K.\n",
			uinfo->llimit, uinfo->ulimit, ppmax);
		return;
	}
	bits = (fls(ppmax) - 1) + 1;

	if (bits > IPPOD_IDX_MAX_SIZE)
		bits = IPPOD_IDX_MAX_SIZE;
	ppmax = (1 << (bits - 1)) - 1;

	ddp = cxgbi_ulp2_alloc_big_mem(sizeof(struct cxgbi_ulp2_ddp_info) +
			ppmax * (sizeof(struct cxgbi_ulp2_gather_list *) +
			sizeof(struct mbuf*)));
			//sizeof(unsigned char) + sizeof(struct mbuf*)));
	if (!ddp) {
		ddp_log_info("unable to alloc ddp 0x%d, ddp disabled.\n",
			     ppmax);
		return;
	}
	//ddp->colors = (unsigned char *)(ddp + 1);
	ddp->gl_map = (struct cxgbi_ulp2_gather_list **)(ddp + 1);
	*ddp_pp = ddp;

	//ddp->gl_map = (struct cxgbi_ulp2_gather_list **)(ddp->colors +
	//		ppmax * sizeof(unsigned char));
	mtx_init(&ddp->map_lock, "ddp lock", NULL,
			MTX_DEF | MTX_DUPOK| MTX_RECURSE);

	mtx_init(&ddp->win0_lock, "win0 lock", NULL,
				MTX_DEF | MTX_DUPOK| MTX_RECURSE);
	atomic_set_acq_int(&ddp->refcnt, 1);

	/* dma_tag create */
	rc = ulp2_dma_tag_create(ddp);
	if(rc) {
		ddp_log_info("unable to alloc ddp 0x%d, ddp disabled.\n",
			     ppmax);
		return;
	}

	ddp->tdev = tdev;
	ddp->max_txsz = min(uinfo->max_txsz, ULP2_MAX_PKT_SIZE);
	ddp->max_rxsz = min(uinfo->max_rxsz, ULP2_MAX_PKT_SIZE);
	ddp->llimit = uinfo->llimit;
	ddp->ulimit = uinfo->ulimit;
	ddp->nppods = ppmax;
	ddp->idx_last = ppmax;
	ddp->idx_bits = bits;
	ddp->idx_mask = (1 << bits) - 1;
	ddp->rsvd_tag_mask = (1 << (bits + IPPOD_IDX_SHIFT)) - 1;

	ddp_log_info("gl map 0x%p, idx_last %u.\n", ddp->gl_map, ddp->idx_last);
	uinfo->tagmask = ddp->idx_mask << IPPOD_IDX_SHIFT;
	for (i = 0; i < DDP_PGIDX_MAX; i++)
		uinfo->pgsz_factor[i] = ddp_page_order[i];
	uinfo->ulimit = uinfo->llimit + (ppmax << IPPOD_SIZE_SHIFT);

	printf("nppods %u, bits %u, mask 0x%x,0x%x pkt %u/%u,"
			" %u/%u.\n",
			ppmax, ddp->idx_bits, ddp->idx_mask,
			ddp->rsvd_tag_mask, ddp->max_txsz, uinfo->max_txsz,
			ddp->max_rxsz, uinfo->max_rxsz);

	rc = bus_dmamap_create(ddp->ulp_ddp_tag, 0, &ddp->ulp_ddp_map);
	if (rc != 0) {
		printf("bus_dmamap_Create failed\n");
		return;
	}

	rc = bus_dmamap_load(ddp->ulp_ddp_tag, ddp->ulp_ddp_map,
				chrsvd_pages[1], MJUMPAGESIZE, ulp2_dma_map_addr,
				//&pa, BUS_DMA_NOWAIT);
				&pa, 0);
	if (rc != 0) {
		ddp_log_error("unable to map rsvd page 0x%p.\n",
			chrsvd_pages[1]);
		return;
	}
	ddp->rsvd_page_phys_addr = pa;
}

/**
 * cxgbi_ulp2_ddp_init - initialize ddp functions
 */
void cxgbi_ulp2_ddp_init(void *tdev,
			struct cxgbi_ulp2_ddp_info **ddp_pp,
			struct ulp_iscsi_info *uinfo)
{
	if (page_idx == DDP_PGIDX_MAX) {
		page_idx = cxgbi_ulp2_ddp_find_page_index(PAGE_SIZE);

		if (page_idx == DDP_PGIDX_MAX) {
			if (cxgbi_ulp2_ddp_adjust_page_table() < 0) {
				ddp_log_info("PAGE_SIZE %x, ddp disabled.\n",
						PAGE_SIZE);
				return;
			}
		}
		page_idx = cxgbi_ulp2_ddp_find_page_index(PAGE_SIZE);
	}

	ddp_init(tdev, ddp_pp, uinfo);
}
