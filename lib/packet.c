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
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "spedecode.h"
#include "spedecode_internal.h"

bool
spe_packet_peek_header(struct spe_decode_ctx *ctx, uint16_t *headerp,
    int *header_lenp)
{
	int header_len;
	uint16_t header;

	if (!ctx->header) {
		if (ctx->have_header) {
			*headerp = ctx->last_header;
			*header_lenp = ctx->last_header_len;
			return (true);
		}
		SPE_LOG(ctx, 1, "Not in header");
		SPE_FAIL_POINT();
		return (false);
	}

	assert(ctx->off <= ctx->len);
	if (ctx->off == ctx->len) {
		return (false);
	}

	header = *((uint8_t *)ctx->buf + ctx->off);
	header_len = 1;

	/* Handle the extended header */
	if (header >= 0x20 && header < 0x40) {
		/* The second half of the header is missing */
		if (ctx->off + 1 == ctx->len) {
			return (false);
		}
		header <<= 8;
		header |= *((uint8_t *)ctx->buf + ctx->off + 1);
		header_len = 2;
	}

	*headerp = header;
	*header_lenp = header_len;

	return (true);
}

bool
spe_packet_get_header(struct spe_decode_ctx *ctx, int flags, uint16_t *headerp,
    int *header_lenp)
{
	int header_len;
	uint16_t header;

	do {
		if (!spe_packet_peek_header(ctx, &header, &header_len)) {
			return (false);
		}

		assert(header_len > 0);
		assert(header_len <= 2);

		ctx->last_header = header;
		ctx->last_header_len = header_len;
		ctx->have_header = true;
		ctx->off += header_len;
		assert(ctx->off <= ctx->len);
	} while (header == 0 && (flags & SPE_HEADER_SKIP_PADDING) != 0);

	ctx->header = false;
	*headerp = header;
	*header_lenp = header_len;

	return (true);
}

bool
spe_packet_data_len(struct spe_decode_ctx *ctx, int *data_lenp)
{
	int data_len;
	uint16_t header;

	if (ctx->header) {
		SPE_LOG(ctx, 1, "Not in data");
		SPE_FAIL_POINT();
		return (false);
	}

	/* There are no packets to skip */
	if (ctx->off == ctx->len) {
		SPE_LOG(ctx, 2, "No data to read");
		return (false);
	}

	header = ctx->last_header;

	assert(ctx->last_header_len > 0);
	assert(ctx->last_header_len <= 2);

	if (header < 0x20) {
		data_len = 0;
	} else {
		/* The data length is encoded in the header */
		data_len = 1 << ((header >> 4) & 3);
	}

	if ((size_t)data_len > (ctx->len - ctx->off)) {
		SPE_LOG(ctx, 1, "Data too long");
		return (false);
	}

	*data_lenp = data_len;

	return (true);
}

bool
spe_packet_get_data(struct spe_decode_ctx *ctx, uint64_t *datap,
    int *data_lenp)
{
	int data_len;

	if (!spe_packet_data_len(ctx, &data_len)) {
		return (false);
	}

	assert((size_t)data_len <= (ctx->len - ctx->off));

	if (datap != NULL) {
		assert(data_lenp != NULL);
		*datap = 0;
		*data_lenp = data_len;
		if (data_len > 0) {
			/* XXX: Endian safe? */
			memcpy(datap, (uint8_t *)ctx->buf + ctx->off, data_len);
		}
	}
	ctx->off += data_len;
	ctx->header = true;
	ctx->have_header = false;
	assert(ctx->off <= ctx->len);

	return (true);
}

bool
spe_packet_skip(struct spe_decode_ctx *ctx)
{
	return (spe_packet_get_data(ctx, NULL, NULL));
}
