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
#include <stdio.h>

struct spe_decode_ctx {
	void *buf;
	size_t off;
	size_t len;
#define	SPE_OWN_BUF	0x01	/* We own buf so can realloc */
	int flags;
	bool header;
	bool have_header;
	uint16_t last_header;
	int last_header_len;
	int log_level;
	void *packet_cb_data;
	spe_packet_cb *packet_cb[SPE_PKT_MAX];
};

#define	SPE_LOG(ctx, level, ...)					\
	do {								\
		if ((ctx)->log_level >= (level)) {			\
			fprintf(stderr, "%s:%d ", __func__, __LINE__);	\
			fprintf(stderr, __VA_ARGS__);			\
			fprintf(stderr, "\n");				\
		}							\
	} while (0)

#if defined(SPE_FUZZ_TARGET)
#define	SPE_FAIL_POINT()	__builtin_trap()
#else
#define	SPE_FAIL_POINT()	do {} while (0)
#endif

#define	SPE_NITEMS(x)		(sizeof((x)) / sizeof((x)[0]))
