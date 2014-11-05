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

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "tcp-client.h"
#include "misc.h"

static void on_close(uv_handle_t *handle);
static void on_write(uv_write_t *req, int status);
static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_connect(uv_connect_t *req, int status);

static uv_tcp_t conn;
static uv_connect_t connect_req;

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->base = malloc(suggested_size);
	if (buf->base)
		buf->len = suggested_size;
	else
		buf->len = 0;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	if (nread >= 0) {
		__debug("buf->base: '%.*s'", (int) buf->len, buf->base);

		/* TODO: send data to other socket */
		uv_write_t request;
		uv_write(&request, stream, buf, 1, on_write);
	} else {
		__debug("%s", uv_err_name(nread));
		uv_close((uv_handle_t *) stream, on_close);
	}

	free(buf->base);

	__debug("done");
}

static void on_write(uv_write_t *req, int status)
{
	if (status) {
		__debug("%s", uv_err_name(status));
		uv_close((uv_handle_t *) req->handle, on_close);
		return;
	}

	__debug("done");
}

void on_close(uv_handle_t *handle)
{
	__debug("done");
}

void on_connect(uv_connect_t *req, int status)
{
	uv_read_start(req->handle, on_alloc, on_read);

	__debug("done");
}

int tcp_client_init() {
	struct sockaddr_in addr;
	int rc = 0;

	rc = uv_ip4_addr("127.0.0.1", 8080, &addr);
	if (rc) goto out;

	rc = uv_tcp_init(uv_default_loop(), &conn);
	if (rc) goto out;

	uv_tcp_connect(&connect_req, &conn, (const struct sockaddr *) &addr, on_connect);
out:
	return rc;
}
