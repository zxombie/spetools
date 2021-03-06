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

#if defined(SPE_MMAP)
#include <sys/mman.h>
#endif
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_MSC_VER)
#include <unistd.h>
typedef	ssize_t read_t;
#define	SPE_NORETURN	__attribute__((__noreturn__))
#else
/* No unistd.h on MSVC, use io.h for close */
#include <io.h>
/* Use the MSVC name for these functions */
#define	open		_open
#define	close		_close
#define	read		_read
#define	O_CLOEXEC	0
typedef	int read_t;
#define	SPE_NORETURN	__declspec(noreturn)
#endif

#include <spedecode.h>

static void
usage(void)
{
	fprintf(stderr, "spe_decode file [file ...]\n");
	exit(1);
}

SPE_NORETURN static void
spe_errx(int rv, const char *fmt, ...)
{
	va_list args;

	fprintf(stderr, "spe_decode: ");
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	exit(rv);
}

SPE_NORETURN static void
spe_err(int rv, const char *fmt, ...)
{
	va_list args;
	int errno_save;

	errno_save = errno;

	fprintf(stderr, "spe_decode: ");
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, ": %s\n", strerror(errno_save));

	exit(rv);
}

static void
address_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	int index;

	(void)ctx;
	(void)priv;
	(void)type;

	printf("Address ");

	index = SPE_ADDRESS_INDEX(header);
	switch (index) {
	case SPE_ADDRESS_IDX_PC_VA:
	case SPE_ADDRESS_IDX_B_TARGET:
	case SPE_ADDRESS_IDX_DATA_VA:
	case SPE_ADDRESS_IDX_DATA_PA:
	case SPE_ADDRESS_IDX_PREV_B_TARGET:
		printf("Index: %x ", index);
		printf("Addr: %"PRIx64" ", SPE_ADDRESS_ADDR_SE(data));
		if (index == SPE_ADDRESS_IDX_DATA_VA) {
			printf("Tag: %"PRIx64" ", SPE_ADDRESS_TAG(data));
		} else if (index == SPE_ADDRESS_IDX_DATA_PA) {
			printf("NS: %"PRIx64" Checked: %s Phys tag: %"PRIx64" ",
			    SPE_ADDRESS_NS(data),
			    (SPE_ADDRESS_CH(data) != 0) ? "true" : "false",
			    SPE_ADDRESS_PAT(data));
		} else {
			printf("NS: %"PRIx64" EL: %"PRIx64" ",
			    SPE_ADDRESS_NS(data),
			    SPE_ADDRESS_EL(data));
		}
		printf("\n");
		break;
	default:
		printf("Unknown Index: %x\n", index);
		break;
	};
}

static void
context_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;
	(void)header;

	printf("Context: %"PRIx64"\n", data);
}

static void
counter_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;

	printf("Counter: %"PRIx16" %"PRIu64"\n", SPE_COUNTER_INDEX(header),
	    data);
}

static void
data_source_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;
	(void)header;

	printf("Data source: %"PRIx64"\n", data);
}

static void
end_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;
	(void)header;
	(void)data;

	printf("===\n");
}

static void
events_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;
	(void)header;

	printf("Events: %"PRIx64"\n", data);
}

static void
operation_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;

	printf("Operation type: Class: %"PRIx16" Subclass: %"PRIx64"\n",
	    SPE_OPERATION_TYPE_CLASS(header),
	    data);
}

static void
timestamp_packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;
	(void)header;

	printf("Timestamp: %"PRId64"\n", data);
	/* This is the last packet in this record (if enabled) */
	printf("===\n");
}

static void
packet(struct spe_decode_ctx *ctx, void *priv, spe_packet_type type,
    uint16_t header, uint64_t data)
{
	(void)ctx;
	(void)priv;
	(void)type;

	printf("header: %"PRIx16" data: %"PRIx64"\n", header, data);
}

static void
process(struct spe_decode_ctx *ctx, const char *file)
{
	struct stat sb;
	void *buf;
	int error, fd;
#if !defined(SPE_MMAP)
	char *cur;
	size_t remaining;
#endif

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		spe_err(1, "Unable to open \"%s\"", file);
	}

	error = fstat(fd, &sb);
	if (error == -1) {
		spe_err(1, "Unable to stat \"%s\"", file);
	}

#if defined(SPE_MMAP)
	buf = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		spe_err(1, "Unable to mmap \"%s\"", file);
	}
#else
	buf = calloc(sb.st_size, 1);
	if (buf == NULL) {
		spe_err(1, "Unable to allocate %zu bytes", sb.st_size);
	}
	remaining = sb.st_size;
	cur = buf;
	while (remaining > 0) {
		read_t read_len;

		read_len = read(fd, cur, remaining);
		if (read_len == -1) {
			spe_err(1, "Unable to read from \"%s\"", file);
		}
		assert((size_t)read_len <= remaining);
		remaining -= read_len;
		cur += read_len;
	}
#endif

	if (!spe_decode_ctx_add(ctx, 0, buf, sb.st_size)) {
		spe_errx(1, "Unable to add data from \"%s\" to the context",
		    file);
	}

	while (spe_packet_decode_next(ctx, SPE_PACKET_DECODE_SKIP_PADDING)) {
		/* Do nada */
	}

	if (!spe_decode_ctx_release(ctx, buf)) {
		spe_errx(1, "Unable to release buffer from the context");
	}

#if defined(SPE_MMAP)
	munmap(buf, sb.st_size);
#endif

	close(fd);

}

int
main(int argc, char *argv[])
{
	struct spe_decode_ctx *ctx;

	if (argc < 2) {
		usage();
	}

	ctx = spe_decode_ctx_alloc();
	if (ctx == NULL) {
		spe_errx(1, "Unable to allocate a decode context");
	}

	spe_packet_decode_set_callback(ctx, SPE_PKT_INVALID, packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_UNKNOWN, packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_ADDRESS, address_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_CONTEXT, context_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_COUNTER, counter_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_DATA_SOURCE,
	    data_source_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_END, end_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_EVENTS, events_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_OPERATION_TYPE,
	    operation_packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_PADDING, packet);
	spe_packet_decode_set_callback(ctx, SPE_PKT_TIMESTAMP,
	    timestamp_packet);

	for (int i = 1; i < argc; i++) {
		process(ctx, argv[i]);
	}

	spe_decode_ctx_free(ctx);

	return (0);
}
