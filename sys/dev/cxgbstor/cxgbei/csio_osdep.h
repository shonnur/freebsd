/*-
 * Copyright (c) 2011 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: Praveen Madhavan <praveenm@chelsio.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

#ifndef __CSIO_OSDEP_H__
#define __CSIO_OSDEP_H__

#ifdef _KERNEL
#include <sys/cdefs.h>
#include <sys/ctype.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/param.h>
//#ifdef _KERNEL
#include <sys/endian.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/kernel.h>
#include <vm/uma.h>
#endif
#if 0
#include <sys/bus.h>
#include <machine/bus.h>
#include <sys/rman.h>
#include <sys/bus_dma.h>
#endif
#ifdef _KERNEL
#include <sys/callout.h>
#include <sys/lock.h>
#include <sys/taskqueue.h>
#include <sys/firmware.h>
#include <sys/linker.h>
//#include <arpa/inet.h>
#endif

#if 0
#include <cam/cam.h>
#include <cam/cam_debug.h>
#include <cam/cam_ccb.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt.h>
#include <cam/cam_xpt_sim.h>
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_message.h>
#endif

#if BYTE_ORDER == BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#elif BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#else
#error "Must set BYTE_ORDER"
#endif

#define csio_os_msecs()		(1000*ticks / hz)	
#define	csio_mdelay(__m)	DELAY((__m) * 1000)
#define	csio_udelay(__u)	DELAY((__u))
#define csio_msleep(__m)	DELAY((__m) * 1000)

#define MINIMUM(a,b)    (((a) < (b)) ? (a) : (b))
#define MAXIMUM(a,b)    (((a) > (b)) ? (a) : (b))

#if 0
static inline int
ilog2(long x)
{
	KASSERT(x > 0 && powerof2(x), ("%s: invalid arg %ld", __func__, x));

	return (flsl(x) - 1);
}

static inline char *
strstrip(char *s)
{
	char c, *r, *trim_at;

	while (isspace(*s))
		s++;
	r = trim_at = s;

	 while ((c = *s++) != 0) {
		if (!isspace(c))
			trim_at = s;
	}
	*trim_at = 0;

	return (r);
}
#endif

//extern
//char *_strdup(const char *src)


extern void *csio_alloc(const char *fname, unsigned int size,
	char wait, char contiguous);

extern void csio_free(const char *fname, void *p);
extern char *csio_strdup(const char *str);

#define os_alloc(s,w,c)         csio_alloc(__FUNCTION__, s, w, c)
#define os_free(p)              csio_free(__FUNCTION__, p)

typedef uma_zone_t		os_zone_t;
#define os_zalloc(z,f)		uma_zalloc(z, M_ZERO | M_WAITOK)
#define os_zfree(z,p)		uma_zfree(z, p)
#define os_strcmp	strcmp
#define os_strncmp	strncmp
#define os_strcpy	strcpy
#define os_strncpy	strncpy
#define os_strdup	csio_strdup
#define os_strlen	strlen
#define os_strtoul	strtoul

/* lock flavors */
#define lockq_nolock(Q)		{}
#define unlockq_nolock(Q)	{}

#define os_lock_size		sizeof(struct mtx)
#define os_lock(L)		mtx_lock(L)
#define os_unlock(L)		mtx_unlock(L)
#define os_unlock_irq(L)	mtx_unlock(L)
#define os_lock_irq(L)		mtx_lock(L)
#define os_lock_destroy(L) 	\
	do { \
		if (mtx_initialized(L)) \
			mtx_destroy(L); \
	} while (0)

#define os_lock_init(L, M)	mtx_init(L, M, NULL, \
				MTX_DEF | MTX_DUPOK| MTX_RECURSE);

#define os_counter_size		sizeof(volatile int)
#define os_get_random_bytes(P, L)	arc4rand(P, L, 0);
#define os_counter_inc(P)	atomic_add_acq_int(P, 1);
#define os_counter_dec(P)	atomic_subtract_acq_int(P, 1);
#define os_counter_set(P, V)	atomic_set_acq_int(P, V);
#define os_counter_read(P)	atomic_load_acq_int(P)
#define os_counter_add(P,V)	atomic_add_acq_int(P, V);

int  os_atoi(char *str);


static inline int os_counter_dec_and_read(volatile int *p)
{	
	atomic_subtract_acq_int(p, 1);
	return atomic_load_acq_int(p);
}

/**
 * hweight32 - returns the hamming weight of a 32-bit word
 * @x: the word to weigh
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 * (i.e.,) counting no.of 1's in a given word.
 */

static inline uint8_t 
hweight32(uint32_t word32)
{
        uint32_t res = word32 - ((word32 >> 1) & 0x55555555);
        res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
        res = (res + (res >> 4)) & 0x0F0F0F0F;
        res = res + (res >> 8);
        return (res + (res >> 16)) & 0x000000FF;

} /* weight32 */

/* Byte swappers */
#define os_ntohs(x)	ntohs(x)
#define os_htons(x)	htons(x)
#define os_ntohl(x)	ntohl(x)
#define os_htonl(x)	htonl(x)
#define os_ntohll(x)	le64toh(x)
#define os_htonll(x)	htole64(x)
#define os_le32_to_host(x)	le32toh(x)
#define le16_to_cpu(x) 	le16toh(x)
#define le32_to_cpu(x) 	le32toh(x)
#define le64_to_cpu(x) 	le64toh(x)

/* Compiler Optimizations */
#define likely(_cond)	((_cond))
#define unlikely(_cond)	((_cond))

#define container_of(p, s, f) ((s *)(((uint8_t *)(p)) - offsetof(s, f)))

typedef unsigned long   csio_oss_osticks_t;
typedef bus_addr_t	dma_addr_t;

#define L1_CACHE_BYTES    CACHE_LINE_SIZE
#define OS_PAGE_MASK	PAGE_MASK
#define OS_PAGE_SIZE	PAGE_SIZE
#define OS_PAGE_SHIFT	PAGE_SHIFT

/* Sleep/wakeup */
struct csio_oss_cmpl {
	struct mtx lock;
	int flags;
};

typedef struct csio_oss_cmpl csio_cmpl_t;
void csio_cmpl_init(struct csio_oss_cmpl *);
void csio_sleep(struct csio_oss_cmpl *);
void csio_wakeup(struct csio_oss_cmpl *);

/* Reference counting */
struct csio_oss_kref {
	volatile uint32_t refcount;  
	void 		*obj;
	void 		(*freeobj)(void *);
};
typedef struct csio_oss_kref csio_kref_t;
void csio_kref_init(struct csio_oss_kref *, void *, void (*)(void *));
void csio_kref_get(struct csio_oss_kref *);
int csio_kref_put(struct csio_oss_kref *);

#define csio_scsi_dump_evil_req(req)

/* atomic bit operation */
int     os_test_bit_atomic(volatile void *, int);
void    os_set_bit_atomic(volatile void *, int);
void    os_clear_bit_atomic(volatile void *, int);
int     os_test_and_set_bit_atomic(volatile void *, int);
int     os_test_and_clear_bit_atomic(volatile void  *, int);

#ifdef CHTGT_MEM_DEBUG
void chtgt_dump_mlist(void);
#endif /* CHTGT_MEM_DEBUG */
#endif  /* ifndef __CSIO_OSDEP_H__ */
