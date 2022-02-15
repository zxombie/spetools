/*-
 * Copyright (c) 2022 The FreeBSD Foundation
 *
 * This software was developed by Andrew Turner under sponsorship from
 * the FreeBSD Foundation.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct spe_decode_ctx;

struct spe_decode_ctx *spe_decode_ctx_alloc(void);
void spe_decode_ctx_free(struct spe_decode_ctx *);
void spe_decode_ctx_set_log_level(struct spe_decode_ctx *, int);

#define	SPE_FLAG_MUST_COPY	0x01	/* We must copy the data before using */
bool spe_decode_ctx_add(struct spe_decode_ctx *, uint32_t, void *, size_t);
bool spe_decode_ctx_release(struct spe_decode_ctx *, void *);

#define	SPE_HEADER_SKIP_PADDING	0x01
bool spe_packet_peek_header(struct spe_decode_ctx *, uint16_t *, int *);
bool spe_packet_get_header(struct spe_decode_ctx *, int, uint16_t *, int *);

bool spe_packet_data_len(struct spe_decode_ctx *, int *);
bool spe_packet_get_data(struct spe_decode_ctx *, uint64_t *, int *);
bool spe_packet_skip(struct spe_decode_ctx *);

typedef enum {
	SPE_PKT_INVALID,
	SPE_PKT_UNKNOWN,
	SPE_PKT_ADDRESS,
	SPE_PKT_CONTEXT,
	SPE_PKT_COUNTER,
	SPE_PKT_DATA_SOURCE,
	SPE_PKT_END,
	SPE_PKT_EVENTS,
	SPE_PKT_OPERATION_TYPE,
	SPE_PKT_PADDING,
	SPE_PKT_TIMESTAMP,
	SPE_PKT_MAX,
} spe_packet_type;

typedef void (spe_packet_cb)(struct spe_decode_ctx *, void *, spe_packet_type,
    uint16_t, uint64_t);

void spe_packet_decode_set_callback_data(struct spe_decode_ctx *, void *);
bool spe_packet_decode_set_callback(struct spe_decode_ctx *, spe_packet_type,
    spe_packet_cb *);
#define	SPE_PACKET_DECODE_SKIP_PADDING	0x01
bool spe_packet_decode_next(struct spe_decode_ctx *, int flags);

#define	SPE_ADDRESS_INDEX(h)	({					\
	uint16_t __header = (h);					\
	((__header & 0x0300) >> 5) | (__header & 0x0007);		\
})
#define	SPE_ADDRESS_IDX_PC_VA		0x00
#define	SPE_ADDRESS_IDX_B_TARGET	0x01
#define	SPE_ADDRESS_IDX_DATA_VA		0x02
#define	SPE_ADDRESS_IDX_DATA_PA		0x03
#define	SPE_ADDRESS_IDX_PREV_B_TARGET	0x04

/* Macros to extract address packet fields: */
/* Non-secure state field - data physical and instruction packets */
#define	SPE_ADDRESS_NS(p)		(((p) >> 63) & 0x1)
/* MTE tag checked/unchecked field - data physical packets */
#define	SPE_ADDRESS_CH(p)		(((p) >> 62) & 0x1)
/* Exception level field - instruction packets */
#define	SPE_ADDRESS_EL(p)		(((p) >> 61) & 0x3)
/* MTE physical address tag - data physical packets */
#define	SPE_ADDRESS_PAT(p)		(((p) >> 56) & 0xf)
/* TBI tag field - data virtual packets */
#define	SPE_ADDRESS_TAG(p)		(((p) >> 56) & 0xff)
/* Address field - all address packets */
#define	SPE_ADDRESS_ADDR(p)		((p) & 0xfffffffffffffful)
/* Sign extended address field */
#define	SPE_ADDRESS_ADDR_SE(p)		({				\
	int64_t __addr = SPE_ADDRESS_ADDR(p);				\
	__addr <<= 8;							\
	(uint64_t)(__addr >> 8);					\
})

#define	SPE_COUNTER_INDEX(h)	({					\
	uint16_t __header = (h);					\
	(uint16_t)(((__header & 0x0300) >> 5) | (__header & 0x0007));	\
})

#define	SPE_OPERATION_TYPE_CLASS(h)	(uint16_t)((h) & 0x3)
#define	SPE_OPERATION_TYPE_OTHER	0x0
#define	SPE_OPERATION_TYPE_LOAD_STORE	0x1
#define	SPE_OPERATION_TYPE_BRANCH	0x2
