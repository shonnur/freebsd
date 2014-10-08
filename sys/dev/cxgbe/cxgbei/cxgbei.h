/*
 * Chelsio T5xx iSCSI driver
 */
#ifndef __CXGBEI_OFLD_H__
#define __CXGBEI_OFLD_H__
#include "mbufq.h"

typedef struct iscsi_socket {
	/* iscsi private */
        unsigned char   s_flag;
        unsigned char   s_cpuno;        /* bind to cpuno */
        unsigned char   s_mode;         /* offload mode */
        unsigned char   s_txhold;

        unsigned char   s_ddp_pgidx;    /* ddp page selection */
        unsigned char   s_hcrc_len;
        unsigned char   s_dcrc_len;
        unsigned char   filler[1];

        unsigned int    s_tid;          /* for debug only */
        unsigned int    s_tmax;
        unsigned int    s_rmax;
        unsigned int    s_mss;
        void            *s_odev;        /* offload device, if any */
        void            *s_appdata;     /* upperlayer data pointer */
        void            *s_private;     /* underlying socket related info. */
        void            *s_conn;	/* ic_conn pointer */
	struct socket	*sock;
        struct mbuf_head iscsi_rcv_mbufq;/* Ingress direction - ULP stores mbufs */
        struct mbuf_head ulp2_writeq;	/* Ingress direction - ULP stores mbufs */
        struct mbuf_head ulp2_wrq;	/* Ingress direction - ULP stores mbufs */

	struct mbuf *mbuf_ulp_lhdr;
	struct mbuf *mbuf_ulp_ldata;
}iscsi_socket;

#define ISCSI_SG_SBUF_DMABLE            0x1
#define ISCSI_SG_SBUF_DMA_ONLY          0x2     /*private*/
#define ISCSI_SG_BUF_ALLOC              0x10
#define ISCSI_SG_PAGE_ALLOC             0x20
#define ISCSI_SG_SBUF_MAP_NEEDED        0x40
#define ISCSI_SG_SBUF_MAPPED            0x80

#define ISCSI_SG_SBUF_LISTHEAD          0x100
#define ISCSI_SG_SBUF_LISTTAIL          0x200
#define ISCSI_SG_SBUF_XFER_DONE         0x400

enum iscsi_errors {
        ISCSI_GOOD,
        ISCSI_EFAIL,            /* general failure */
        ISCSI_EUSER,            /* copy from/to user space failed */
        ISCSI_ECHRDEV,          /* unable to register ioctl device */
        ISCSI_ECMD,             /* unknown control command */
        ISCSI_EREQ,             /* unknown control command request */
        ISCSI_ENOBUF,           /* no ioctl buffer */
        ISCSI_ENONODE,          /* initiator/target not found */
        ISCSI_ENONAME,          /* initiator/target name missing */
        ISCSI_ENOTFOUND,        /* entity not found */
        ISCSI_ENOMATCH,         /* no match found */
        ISCSI_EMISMATCH,        /* mismatch */
        ISCSI_EOPFAILED,        /* operation failed */
        ISCSI_EDUP,             /* duplicate, already existed */
        ISCSI_EOVERLAP,         /* overlapping values */
        ISCSI_EMULTI,           /* multiple values */
        ISCSI_EKEY,             /* invalid key */
        ISCSI_EFORMAT,          /* invalid format */
        ISCSI_EFORMAT_STR,      /* string unterminated */
        ISCSI_EFORMAT_LONG,     /* longer than max. */
        ISCSI_EFORMAT_SHORT,    /* short than min. */
        ISCSI_EFORMAT_BIG,      /* larger than max. */
        ISCSI_ENOMEM,           /* out of memory */
        ISCSI_ENOTREADY,        /* busy */
        ISCSI_EBUSY,            /* busy */
        ISCSI_EFULL,            /* full */
        ISCSI_EINVAL,           /* invalid value */
        ISCSI_EINVAL_OOR,       /* invalid value, out of range */
        ISCSI_EINVAL_STATE,     /* invalid state */
        ISCSI_EZERO,            /* all zero value */
        ISCSI_ESOCK,
        ISCSI_EIO,
        ISCSI_ETHREAD,

        ISCSI_ENULL,            /* null pointer */
        ISCSI_ENOTSUPP,         /* functionality not supported */
        ISCSI_ESBUF_R,          /* socket buffer read error */

};
typedef struct cxgbei_sgl {
        int     sg_flag;
        void    *sg_addr;
        void    *sg_dma_addr;
        size_t  sg_offset;
        size_t  sg_length;
} cxgbei_sgl_t;

#define cxgbei_scsi_for_each_sg(_sgl, _sgel, _n, _i)      \
        for (_i = 0, _sgel = (cxgbei_sgl_t*) (_sgl); _i < _n; _i++, \
                        _sgel++)
#define sg_dma_addr(_sgel)      _sgel->sg_dma_addr
#define sg_virt(_sgel)          _sgel->sg_addr
#define sg_len(_sgel)           _sgel->sg_length
#define sg_off(_sgel)           _sgel->sg_offset
#define sg_next(_sgel)          _sgel + 1

static MALLOC_DEFINE(M_CXGBEIOFLD, "cxgbei", "Chelsio iSCSI offload driver");

#define SBUF_ULP_FLAG_HDR_RCVD          0x1
#define SBUF_ULP_FLAG_DATA_RCVD         0x2
#define SBUF_ULP_FLAG_STATUS_RCVD       0x4
#define SBUF_ULP_FLAG_COALESCE_OFF      0x8
#define SBUF_ULP_FLAG_HCRC_ERROR        0x10
#define SBUF_ULP_FLAG_DCRC_ERROR        0x20
#define SBUF_ULP_FLAG_PAD_ERROR         0x40
#define SBUF_ULP_FLAG_DATA_DDPED        0x80

/* Flags for return value of CPL message handlers */
enum {
        CPL_RET_BUF_DONE = 1,   // buffer processing done, buffer may be freed
        CPL_RET_BAD_MSG = 2,    // bad CPL message (e.g., unknown opcode)
        CPL_RET_UNKNOWN_TID = 4 // unexpected unknown TID
};


/*
 * Similar to tcp_skb_cb but with ULP elements added to support DDP, iSCSI,
 * etc.
 */
struct ulp_mbuf_cb {
        uint8_t ulp_mode;                    /* ULP mode/submode of sk_buff */
        uint8_t flags;                       /* TCP-like flags */
        uint32_t seq;                        /* TCP sequence number */
        union { /* ULP-specific fields */
                struct {
                        uint32_t ddigest;    /* ULP rx_data_ddp selected field */
                        uint32_t pdulen;     /* ULP rx_data_ddp selected field */
                } iscsi;
                struct {
                        uint32_t offset;     /* ULP DDP offset notification */
                        uint8_t flags;       /* ULP DDP flags ... */
                } ddp;
        } ulp;
        uint8_t ulp_data[16];                /* scratch area for ULP */
        void *pdu;                      /* pdu pointer */
};

/* allocate m_tag */
struct ulp_mbuf_cb * get_ulp_mbuf_cb(struct mbuf *m);

typedef struct cxgbei_task_data {
	cxgbei_sgl_t sgl[256];
	unsigned int	nsge;
	unsigned int	sc_ddp_tag;
}cxgbei_task_data;

static unsigned char t4tom_cpl_handler_register_flag;
enum {
	TOM_CPL_ISCSI_HDR_REGISTERED_BIT,
	TOM_CPL_SET_TCB_RPL_REGISTERED_BIT,
	TOM_CPL_RX_DATA_DDP_REGISTERED_BIT
};

#define ODEV_FLAG_ULP_CRC_ENABLED       0x1
#define ODEV_FLAG_ULP_DDP_ENABLED       0x2
#define ODEV_FLAG_ULP_TX_ALLOC_DIGEST   0x4
#define ODEV_FLAG_ULP_RX_PAD_INCLUDED   0x8

#define ODEV_FLAG_ULP_ENABLED   \
        (ODEV_FLAG_ULP_CRC_ENABLED | ODEV_FLAG_ULP_DDP_ENABLED)

int cxgbei_conn_set_ulp_mode(struct socket *so, void *conn);
int cxgbei_conn_close(struct socket *so);
void cxgbei_conn_task_reserve_itt(void *conn, void **prv, void *scmd,
			unsigned int *itt);
void cxgbei_conn_transfer_reserve_ttt(void *conn, void **prv,
			void *scmd, unsigned int *ttt);
void cxgbei_cleanup_task(void *conn, void *ofld_priv);
int cxgbei_conn_xmit_pdu(void *conn, void *ioreq);
#endif
