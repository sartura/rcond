/*
 * Copyright (C) 2014 Sartura, Ltd.
 *
 * Author: Luka Perkov <luka.perkov@sartura.hr>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef __MISC_RCOND_H__
#define __MISC_RCOND_H__

#define PROJECT_NAME "rcond"

#define __debug(fmt, ...) do { \
		fprintf(stderr, "%s: %s (%d): %s: "fmt"\n", PROJECT_NAME, __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__ ); \
	} while (0)

#ifndef typeof
#define typeof __typeof
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

#endif /* __MISC_RCOND_H__ */
