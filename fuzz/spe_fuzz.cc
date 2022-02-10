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

extern "C" {
#include <spedecode.h>
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *in_data, size_t in_size)
{
	struct spe_decode_ctx *ctx;
	uint64_t data;
	uint16_t header;
	int header_len, data_len;
	int ctx_flags, data_flags;
	int ret;
	bool skip;

	ctx_flags = 0;
	for (int i = 0; i < sizeof(ctx_flags) && in_size >= 1; i++) {
		ctx_flags <<= 8;
		ctx_flags |= *in_data;
		in_data++;
		in_size--;
	}

	data_flags = 0;
	for (int i = 0; i < sizeof(data_flags) && in_size >= 1; i++) {
		data_flags <<= 8;
		data_flags |= *in_data;
		in_data++;
		in_size--;
	}

	ctx = spe_decode_ctx_alloc();
	if (ctx == NULL) {
		return (1);
	}

	/*spe_decode_ctx_set_log_level(ctx, 3);*/

	ret = 0;
	skip = false;
	while (true) {
		if (in_size > 0) {
			if (!spe_decode_ctx_add(ctx, ctx_flags,
			    (void *)in_data, in_size)) {
				ret = 1;
				goto out;
			}
			in_data++;
			in_size--;
		}

		spe_packet_peek_header(ctx, &header, &header_len);
		if (!spe_packet_get_header(ctx, data_flags, &header,
		    &header_len)) {
			break;
		}

		spe_packet_data_len(ctx, &data_len);
		if (skip) {
			if (!spe_packet_skip(ctx)) {
				break;
			}
		} else {
			if (!spe_packet_get_data(ctx, &data, &data_len)) {
				break;
			}
		}
		skip = !skip;
	}

out:
	spe_decode_ctx_free(ctx);
	return (ret);
}
