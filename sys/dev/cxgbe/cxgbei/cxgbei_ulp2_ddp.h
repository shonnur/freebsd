/*
 * cxgbei_ulp2_ddp.h: Chelsio iSCSI DDP Manager.
 *
 */

#ifndef __CXGBI_ULP2_DDP_H__
#define __CXGBI_ULP2_DDP_H__

#include <sys/malloc.h>
#include <sys/sglist.h>

#include <sys/pciio.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>

/*
 * Structure used to return information to the iscsi layer.
 */
struct ulp_iscsi_info {
	unsigned int    offset;
	unsigned int    llimit;
	unsigned int    ulimit;
	unsigned int    tagmask;
	unsigned char   pgsz_factor[4];
	unsigned int    max_rxsz;
	unsigned int    max_txsz;
};

/**
 * struct cxgbei_ulp2_tag_format - cxgb3i ulp tag format for an iscsi entity
 *
 * @sw_bits:	# of bits used by iscsi software layer
 * @rsvd_bits:	# of bits used by h/w
 * @rsvd_shift:	h/w bits shift left
 * @rsvd_mask:	reserved bit mask
 */
typedef struct cxgbei_ulp2_tag_format {
	unsigned char sw_bits; //idx_bits
	unsigned char rsvd_bits; 
	unsigned char rsvd_shift; //color bits 
	unsigned char filler[1];
	uint32_t rsvd_mask;
}cxgbei_ulp2_tag_format;

#define CHISCSI_PAGE_MASK   (~(PAGE_SIZE-1))
#define DDP_THRESHOLD	2048

/*
 * cxgb3i ddp tag are 32 bits, it consists of reserved bits used by h/w and
 * non-reserved bits that can be used by the iscsi s/w.
 * The reserved bits are identified by the rsvd_bits and rsvd_shift fields
 * in struct cxgbei_ulp2_tag_format.
 *
 * The upper most reserved bit can be used to check if a tag is ddp tag or not:
 * 	if the bit is 0, the tag is a valid ddp tag
 */

/**
 * cxgbei_ulp2_is_ddp_tag - check if a given tag is a hw/ddp tag
 * @tformat: tag format information
 * @tag: tag to be checked
 *
 * return true if the tag is a ddp tag, false otherwise.
 */
static inline int cxgbei_ulp2_is_ddp_tag(struct cxgbei_ulp2_tag_format *tformat, uint32_t tag)
{
	return !(tag & (1 << (tformat->rsvd_bits + tformat->rsvd_shift - 1)));
}

/**
 * cxgbei_ulp2_sw_tag_usable - check if s/w tag has enough bits left for hw bits
 * @tformat: tag format information
 * @sw_tag: s/w tag to be checked
 *
 * return true if the tag can be used for hw ddp tag, false otherwise.
 */
static inline int cxgbei_ulp2_sw_tag_usable(struct cxgbei_ulp2_tag_format *tformat,
					uint32_t sw_tag)
{
	sw_tag >>= (32 - tformat->rsvd_bits + tformat->rsvd_shift);
	//printf("newsw_tag:0x%x !sw_tag:0x%x rsvd_bits:%d rsvd_shift:%d\n",
	//		sw_tag, !sw_tag, tformat->rsvd_bits, tformat->rsvd_shift);
	return !sw_tag;
}

/**
 * cxgbei_ulp2_set_non_ddp_tag - mark a given s/w tag as an invalid ddp tag
 * @tformat: tag format information
 * @sw_tag: s/w tag to be checked
 *
 * insert 1 at the upper most reserved bit to mark it as an invalid ddp tag.
 */
static inline uint32_t cxgbei_ulp2_set_non_ddp_tag(struct cxgbei_ulp2_tag_format *tformat,
					 uint32_t sw_tag)
{
	uint32_t rsvd_bits = tformat->rsvd_bits + tformat->rsvd_shift;
	if (sw_tag) {
                u32 v1 = sw_tag & ((1 << (rsvd_bits - 1)) - 1);
                u32 v2 = (sw_tag >> (rsvd_bits - 1)) << rsvd_bits;
		//printf("%s: sw_tag:0x%x v1:0x%x v2:0x%x returning:0x%x\n",
		//	__func__, sw_tag, v1, v2, (v2 | (1 << (rsvd_bits - 1)) | v1));
                return v2 | (1 << (rsvd_bits - 1)) | v1;
        }

	//printf("%s: sw_tag:0x%x returning:0x%x\n",
	//		__func__, sw_tag, (sw_tag | (1 << (rsvd_bits - 1))));
        return sw_tag | (1 << (rsvd_bits - 1)) ;
}

/**
 * cxgbei_ulp2_tag_rsvd_bits - get the reserved bits used by the h/w
 * @tformat: tag format information
 * @tag: tag to be checked
 *
 * return the reserved bits in the tag
 */
static inline uint32_t cxgbei_ulp2_tag_rsvd_bits(struct cxgbei_ulp2_tag_format *tformat,
				       uint32_t tag)
{
	if (cxgbei_ulp2_is_ddp_tag(tformat, tag))
		return (tag >> tformat->rsvd_shift) & tformat->rsvd_mask;
	return 0;
}

/**
 * cxgbei_ulp2_tag_nonrsvd_bits - get the non-reserved bits used by the s/w
 * @tformat: tag format information
 * @tag: tag to be checked
 *
 * return the non-reserved bits in the tag.
 */
static inline uint32_t
cxgbei_ulp2_tag_nonrsvd_bits(struct cxgbei_ulp2_tag_format *tformat, uint32_t tag)
{
	uint32_t rsvd_bits = tformat->rsvd_bits + tformat->rsvd_shift;

	if (cxgbei_ulp2_is_ddp_tag(tformat, tag)) {
		return tag >> rsvd_bits;
	} else{
		uint32_t v1 = tag & ((1 << (rsvd_bits - 1)) - 1);
		uint32_t v2 = (tag >> rsvd_bits) << (rsvd_bits - 1);
		return v2 | v1;
	}
}

struct dma_segments {
	bus_dmamap_t bus_map;
	bus_addr_t phys_addr;
};
/**
 * struct cxgbei_ulp2_gather_list - cxgb3i direct data placement memory
 *
 * @tag:	ddp tag
 * @length:	total data buffer length
 * @offset:	initial offset to the 1st page
 * @nelem:	# of pages
 * @pages:	page pointers
 * @phys_addr:	physical address
 */
struct cxgbei_ulp2_gather_list {
	uint32_t tag;
	uint32_t tid;
	uint32_t port_id;		/* t4 only */
	void *egress_dev;		/* t4 only */
	unsigned int length;
	unsigned int offset;
	unsigned int nelem;
	bus_size_t	mapsize;
	bus_dmamap_t	bus_map;
	bus_dma_segment_t	*segments;
	struct page	**pages;
	struct dma_segments dma_sg[0];
};

struct cxgbei_ulp2_pagepod_hdr;
/**
 * struct cxgbei_ulp2_ddp_info - cxgb3i direct data placement for pdu payload
 *
 * @list:	list head to link elements
 * @refcnt:	count of iscsi entities using it
 * @tdev:	pointer to tXcdev used by cxgbX driver
 * @max_txsz:	max tx packet size for ddp
 * @max_rxsz:	max rx packet size for ddp
 * @llimit:	lower bound of the page pod memory
 * @ulimit:	upper bound of the page pod memory
 * @nppods:	# of page pod entries
 * @idx_last:	page pod entry last used
 * @idx_bits:	# of bits the pagepod index would take
 * @idx_mask:	pagepod index mask
 * @rsvd_tag_mask: tag mask
 * @map_lock:	lock to synchonize access to the page pod map
 * @gl_map:	ddp memory gather list
 */
struct cxgbei_ulp2_ddp_info {
	SLIST_ENTRY(cxgbei_ulp2_ddp_info)      cxgbei_ulp2_ddp_list;
	volatile int refcnt;
	void *tdev;	/* could be t3cdev or t4cdev */
	unsigned int max_txsz;
	unsigned int max_rxsz;
	unsigned int llimit;
	unsigned int ulimit;
	unsigned int nppods;
	unsigned int idx_last;
	unsigned char idx_bits;
	unsigned char filler[3];
	uint32_t idx_mask;
	uint32_t rsvd_tag_mask;
	bus_addr_t rsvd_page_phys_addr;

	int (*ddp_set_map)(struct cxgbei_ulp2_ddp_info *ddp,
			void *isock,
			struct cxgbei_ulp2_pagepod_hdr *hdr,
			unsigned int idx, unsigned int npods,
			struct cxgbei_ulp2_gather_list *gl, int reply);
	void (*ddp_clear_map)(struct cxgbei_ulp2_ddp_info *ddp,
			struct cxgbei_ulp2_gather_list *gl,
			unsigned int tag, unsigned int idx,
			unsigned int npods,
			iscsi_socket *isock);

	struct mtx map_lock;
	bus_dma_tag_t ulp_ddp_tag;
	bus_dmamap_t ulp_ddp_map;
	struct cxgbei_ulp2_gather_list **gl_map;
};
static inline uint32_t cxgbei_ulp2_ddp_tag_base(unsigned int idx, struct cxgbei_ulp2_ddp_info *ddp, 
			struct cxgbei_ulp2_tag_format *tformat, uint32_t sw_tag)
{
	//ddp->colors[idx]++;
        //if (ddp->colors[idx] == (1 << 6))
         //       ddp->colors[idx] = 0;

	//printf("%s: sw_tag:0x%x ",__func__, sw_tag);
        sw_tag <<= (tformat->rsvd_bits + tformat->rsvd_shift);

	//printf("newsw_tag:0x%x idx:0x%x\n", sw_tag, idx);
        //return sw_tag | (idx << 6) | ddp->colors[idx];
        return sw_tag | (idx << 6);// | ddp->colors[idx];
}

#define ISCSI_PDU_NONPAYLOAD_LEN	312 /* bhs(48) + ahs(256) + digest(8) */

/*
 * align pdu size to multiple of 512 for better performance
 */
#define cxgbei_align_pdu_size(n) do { n = (n) & (~511); } while (0)

#define ULP2_DFLT_PKT_SIZE	8192
#define ULP2_MAX_PKT_SIZE	16224
#define ULP2_MAX_PDU_PAYLOAD	(ULP2_MAX_PKT_SIZE - ISCSI_PDU_NONPAYLOAD_LEN)
#define IPPOD_PAGES_MAX		4
#define IPPOD_PAGES_SHIFT	2	/* 4 pages per pod */

/*
 * struct pagepod_hdr, pagepod - pagepod format
 */
struct cxgbei_ulp2_pagepod_hdr {
	uint32_t vld_tid;
	uint32_t pgsz_tag_clr;
	uint32_t maxoffset;
	uint32_t pgoffset;
	uint64_t rsvd;
};

struct cxgbei_ulp2_pagepod {
	struct cxgbei_ulp2_pagepod_hdr hdr;
	uint64_t addr[IPPOD_PAGES_MAX + 1];
};

#define IPPOD_SIZE		sizeof(struct cxgbei_ulp2_pagepod) /* 64 */
#define IPPOD_SIZE_SHIFT	6

#define IPPOD_COLOR_SHIFT	0
#define IPPOD_COLOR_SIZE	6
#define IPPOD_COLOR_MASK	((1 << IPPOD_COLOR_SIZE) - 1)

#define IPPOD_IDX_SHIFT		IPPOD_COLOR_SIZE
#define IPPOD_IDX_MAX_SIZE	24

#define S_IPPOD_TID    0
#define M_IPPOD_TID    0xFFFFFF
#define V_IPPOD_TID(x) ((x) << S_IPPOD_TID)

#define S_IPPOD_VALID    24
#define V_IPPOD_VALID(x) ((x) << S_IPPOD_VALID)
#define F_IPPOD_VALID    V_IPPOD_VALID(1U)

#define S_IPPOD_COLOR    0
#define M_IPPOD_COLOR    0x3F
#define V_IPPOD_COLOR(x) ((x) << S_IPPOD_COLOR)

#define S_IPPOD_TAG    6
#define M_IPPOD_TAG    0xFFFFFF
#define V_IPPOD_TAG(x) ((x) << S_IPPOD_TAG)

#define S_IPPOD_PGSZ    30
#define M_IPPOD_PGSZ    0x3
#define V_IPPOD_PGSZ(x) ((x) << S_IPPOD_PGSZ)

/*
 * ddp page size array
 */
#define DDP_PGIDX_MAX 	4
extern unsigned char ddp_page_order[DDP_PGIDX_MAX];
extern unsigned char page_idx;


/*
 * large memory chunk allocation/release
 * use vmalloc() if kmalloc() fails
 */
static inline void *cxgbei_ulp2_alloc_big_mem(unsigned int size)
{
	void *p = NULL;

 	p =  malloc(size, M_TEMP, M_NOWAIT | M_ZERO);

	return p;
}

static inline void cxgbei_ulp2_free_big_mem(void *addr)
{
	free(addr, M_TEMP);
}
int cxgbei_ulp2_ddp_tag_reserve(struct cxgbei_ulp2_ddp_info *ddp,
				void *isock, unsigned int tid,
				struct cxgbei_ulp2_tag_format *, uint32_t *tag,
				struct cxgbei_ulp2_gather_list *, int gfp, int reply);
void cxgbei_ulp2_ddp_tag_release(struct cxgbei_ulp2_ddp_info *ddp, uint32_t tag, iscsi_socket *isock);

struct cxgbei_ulp2_gather_list *cxgbei_ulp2_ddp_make_gl(unsigned int xferlen,
				struct sglist *sgl,
				unsigned int sgcnt,
				struct pci_conf *pdev,
				int gfp);

struct cxgbei_ulp2_gather_list *cxgbei_ulp2_ddp_make_gl_from_iscsi_sgvec(
				unsigned int xferlen,
				cxgbei_sgl_t *sgl,
				unsigned int sgcnt,
				void *tdev,
				int gfp);

void cxgbei_ulp2_ddp_release_gl(struct cxgbei_ulp2_gather_list *gl,
				void *tdev);

int cxgbei_ulp2_ddp_find_page_index(unsigned long pgsz);
int cxgbei_ulp2_adapter_ddp_info(struct cxgbei_ulp2_ddp_info *ddp,
				struct cxgbei_ulp2_tag_format *,
				unsigned int *txsz, unsigned int *rxsz);

void cxgbei_ulp2_ddp_cleanup(struct cxgbei_ulp2_ddp_info **ddp_pp);
void cxgbei_ulp2_ddp_init(void *tdev,
			struct cxgbei_ulp2_ddp_info **ddp_pp,
			struct ulp_iscsi_info *uinfo);
int cxgbei_ulp2_init(void);
void cxgbei_ulp2_exit(void);
#endif
