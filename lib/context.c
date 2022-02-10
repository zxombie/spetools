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
#include <stdlib.h>
#include <string.h>

#include "spedecode.h"
#include "spedecode_internal.h"

/*
 * Allocates a new SPE context.
 */
struct spe_decode_ctx *
spe_decode_ctx_alloc(void)
{
	struct spe_decode_ctx *ctx;

	ctx = calloc(sizeof(*ctx), 1);
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->header = true;

	return (ctx);
}

/*
 * Frees the SPE data context.
 */
void
spe_decode_ctx_free(struct spe_decode_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if ((ctx->flags & SPE_OWN_BUF) != 0) {
		free(ctx->buf);
	}
	free(ctx);
}

void
spe_decode_ctx_set_log_level(struct spe_decode_ctx *ctx, int level)
{
	ctx->log_level = level;
}

/*
 * Adds new data to the SPE context.
 *
 * The SPE_FLAG_MUST_COPY can be set to ensure data is copied rather than
 * referenced, e.g. if the data may change after this function returns.
 *
 * If the SPE_FLAG_MUST_COPY flag is unset spe_decode_ctx_release needs to
 * be called before freeing the buffer to ensure it's not referenced by
 * the SPE context.
 */
bool
spe_decode_ctx_add(struct spe_decode_ctx *ctx, uint32_t flags, void *data,
    size_t len)
{
	/* Release the current buffer if it's unused */
	if (ctx->off == ctx->len && ctx->buf != NULL) {
		SPE_LOG(ctx, 3, "Release buffer");
		if ((ctx->flags & SPE_OWN_BUF) != 0) {
			SPE_LOG(ctx, 3, "Free buffer %p", ctx->buf);
			free(ctx->buf);
		}
		ctx->buf = NULL;
		ctx->off = 0;
		ctx->len = 0;
	}

	if (ctx->buf == NULL) {
		SPE_LOG(ctx, 3, "New buffer");
		/*
		 * No buffer, we can just use the given buffer, or allocate
		 * a new buffer
		 */
		if ((flags & SPE_FLAG_MUST_COPY) == 0) {
			SPE_LOG(ctx, 3, "Copy buffer");
			ctx->buf = data;
			/* We don't own the buffer */
			ctx->flags &= ~SPE_OWN_BUF;
		} else {
			SPE_LOG(ctx, 3, "Alloc buffer");
			ctx->buf = calloc(len, 1);
			if (ctx->buf == NULL) {
				SPE_LOG(ctx, 2,
				    "Unable to allocate new buffer");
				return (false);
			}
			memcpy(ctx->buf, data, len);
			ctx->flags |= SPE_OWN_BUF;
		}
		ctx->len = len;
		ctx->off = 0;
		return (true);
	}

	SPE_LOG(ctx, 3, "Copy into buffer");
	if ((ctx->flags & SPE_OWN_BUF) != 0 && ctx->off == 0) {
		void *tmp;

		SPE_LOG(ctx, 3, "Realloc buffer");
		/*
		 * We own the buffer, and have not read from it, just realloc
		 * it.
		 */
		tmp = realloc(ctx->buf, ctx->len + len);
		if (tmp == NULL) {
			return (false);
		}

		ctx->buf = tmp;
	} else {
		void *tmp;
		size_t tail_len;

		SPE_LOG(ctx, 3, "Allocate new buffer");
		/*
		 * We don't own the buffer or some of it has been consumed
		 * so we need to allocate one large enough for any remaining
		 * data and the new data.
		 */

		assert(ctx->len >= ctx->off);
		tail_len = ctx->len - ctx->off;
		SPE_LOG(ctx, 3, "Buffer tail length %zx (%zx - %zx)", tail_len,
		    ctx->len, ctx->off);
		SPE_LOG(ctx, 3, "Buffer size %zx (%zx + %zx)", tail_len + len,
		    tail_len, len);
		tmp = calloc(tail_len + len, 1);
		if (tmp == NULL) {
			return (false);
		}

		/* Copy the tail data */
		memcpy(tmp, (uint8_t *)ctx->buf + ctx->off, tail_len);

		if ((ctx->flags & SPE_OWN_BUF) != 0) {
			free(ctx->buf);
		}
		ctx->buf = tmp;
		ctx->off = 0;
		ctx->len = tail_len;
		ctx->flags |= SPE_OWN_BUF;
	}

	if (len > 0) {
		memcpy((uint8_t *)ctx->buf + ctx->len, data, len);
		ctx->len += len;
	}

	return (true);
}

/*
 * Release a buffer that was previously added using spe_decode_ctx_add with
 * the SPE_FLAG_MUST_COPY flag unset. This tells the context it must copy
 * any unprocessed data before returning.
 */
bool
spe_decode_ctx_release(struct spe_decode_ctx *ctx, void *buf)
{
	void *tmp;
	size_t len;

	if (ctx->buf == buf) {
		assert((ctx->flags & SPE_OWN_BUF) == 0);
		assert(ctx->len >= ctx->off);

		len = ctx->len - ctx->off;
		if (len == 0) {
			ctx->buf = NULL;
		} else {
			tmp = calloc(len, 1);
			if (tmp == NULL) {
				return (false);
			}

			memcpy(tmp, (uint8_t *)ctx->buf + ctx->off, len);
			ctx->buf = tmp;
			ctx->flags |= SPE_OWN_BUF;
		}
	}

	return (true);
}
