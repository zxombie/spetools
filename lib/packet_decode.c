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

#include <assert.h>

#include "spedecode.h"
#include "spedecode_internal.h"

#define	PADDING_VAL			0x00
#define	PADDING_MASK			0xff
#define	PADDING_WIDTH			1

#define	END_VAL				0x01
#define	END_MASK			0xff
#define	END_WIDTH			1

#define	TIMESTAMP_VAL			0x71
#define	TIMESTAMP_MASK			0xff
#define	TIMESTAMP_WIDTH			1

#define	EVENTS_VAL			0x42
#define	EVENTS_MASK			0xcf
#define	EVENTS_WIDTH			1

#define	DATA_SOURCE_VAL			0x43
#define	DATA_SOURCE_MASK		0xcf
#define	DATA_SOURCE_WIDTH		1

#define	CONTEXT_VAL			0x64
#define	CONTEXT_MASK			0xfc
#define	CONTEXT_WIDTH			1

#define	OPERATION_TYPE_VAL		0x48
#define	OPERATION_TYPE_MASK		0xfc
#define	OPERATION_TYPE_WIDTH		1

#define	ADDRESS_SHORT_VAL		0xb0
#define	ADDRESS_SHORT_MASK		0xf8
#define	ADDRESS_SHORT_WIDTH		1

#define	ADDRESS_LONG_VAL		0x20b0
#define	ADDRESS_LONG_MASK		0xfcf8
#define	ADDRESS_LONG_WIDTH		2

#define	COUNTER_SHORT_VAL		0x98
#define	COUNTER_SHORT_MASK		0xf8
#define	COUNTER_SHORT_WIDTH		1

#define	COUNTER_LONG_VAL		0x2098
#define	COUNTER_LONG_MASK		0xfcf8
#define	COUNTER_LONG_WIDTH		2

static struct {
	uint16_t val;
	uint16_t mask;
	uint8_t width;
	spe_packet_type type;
#define	SPE_ENTRY(_type, _extra)					\
	{								\
		.val = _type ## _extra ## _VAL,				\
		.mask = _type ## _extra ## _MASK,			\
		.width = _type ## _extra ## _WIDTH,			\
		.type = SPE_PKT_ ## _type,				\
	}
} spe_headers[] = {
	SPE_ENTRY(ADDRESS, _SHORT),
	SPE_ENTRY(ADDRESS, _LONG),
	SPE_ENTRY(CONTEXT, ),
	SPE_ENTRY(COUNTER, _SHORT),
	SPE_ENTRY(COUNTER, _LONG),
	SPE_ENTRY(DATA_SOURCE, ),
	SPE_ENTRY(END, ),
	SPE_ENTRY(EVENTS, ),
	SPE_ENTRY(OPERATION_TYPE, ),
	SPE_ENTRY(PADDING, ),
	SPE_ENTRY(TIMESTAMP, ),
};

void
spe_packet_decode_set_callback_data(struct spe_decode_ctx *ctx, void *data)
{

	ctx->packet_cb_data = data;
}

bool
spe_packet_decode_set_callback(struct spe_decode_ctx *ctx, spe_packet_type type,
    spe_packet_cb *cb)
{
	if (type < 0 || type >= SPE_PKT_MAX) {
		SPE_LOG(ctx, 1, "Invalid packet type %x\n", type);
		SPE_FAIL_POINT();
		return (false);
	}

	ctx->packet_cb[type] = cb;
	return (true);
}

spe_packet_type
spe_packet_decode_type(struct spe_decode_ctx *ctx, uint16_t header,
    int header_len)
{
	if (header_len < 0 || header_len > 2) {
		SPE_LOG(ctx, 1, "Invalid header length %d", header_len);
		SPE_FAIL_POINT();
		return (SPE_PKT_INVALID);
	}

	for (size_t i = 0; i < SPE_NITEMS(spe_headers); i++) {
		assert(spe_headers[i].width >= 1);
		assert(spe_headers[i].width <= 2);

		if (spe_headers[i].width == header_len &&
		    (header & spe_headers[i].mask) == spe_headers[i].val) {
			return (spe_headers[i].type);
		}
	}

	return (SPE_PKT_UNKNOWN);
}

bool
spe_packet_decode_next(struct spe_decode_ctx *ctx, int flags)
{
	spe_packet_cb *cb;
	spe_packet_type type;
	uint64_t data;
	uint16_t header;
	int header_len, data_len, header_flags;

	header_flags = 0;
	if ((flags & SPE_PACKET_DECODE_SKIP_PADDING) != 0) {
		header_flags |= SPE_HEADER_SKIP_PADDING;
	}
	if (!spe_packet_get_header(ctx, header_flags, &header, &header_len)) {
		SPE_LOG(ctx, 2, "No packet header");
		return (false);
	}

	if (!spe_packet_get_data(ctx, &data, &data_len)) {
		SPE_LOG(ctx, 2, "No packet header");
		return (false);
	}

	type = spe_packet_decode_type(ctx, header, header_len);
	cb = ctx->packet_cb[type];
	if (cb != NULL) {
		cb(ctx, ctx->packet_cb_data, type, header, data);
	}

	return (true);
}
