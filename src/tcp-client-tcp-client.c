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
#include <string.h>
#include <uv.h>

#include "tcp-client-tcp-client.h"
#include "misc.h"

void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

static void on_close(uv_handle_t *handle);

static void on_write(uv_write_t *req, int status);

static void on_read_left(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_connect_left(uv_connect_t *req, int status);

static void on_read_right(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_connect_right(uv_connect_t *req, int status);

static uv_tcp_t conn_left;
static uv_connect_t connect_req_left;

static uv_tcp_t conn_right;
static uv_connect_t connect_req_right;


void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->base = malloc(suggested_size);
	if (buf->base)
		buf->len = suggested_size;
	else
		buf->len = 0;
}

void on_close(uv_handle_t *handle)
{
	__debug("done");
}

static void on_write(uv_write_t *req, int status)
{
	write_req_t *wr = (write_req_t *) req;

	free(wr->buf.base);
	free(wr);

	if (status == 0)
		return;

	__debug("%s\n", uv_err_name(status));
}

static void on_read_left(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	write_req_t *wr;

	if (nread >= 0) {
		wr = (write_req_t *) malloc(sizeof *wr);
		if (!wr) {
			free(buf->base);
			__debug("no memory");
			return;
		}

		wr->buf = uv_buf_init(buf->base, nread);

		uv_write(&wr->req, (uv_stream_t *) &conn_right, &wr->buf, 1, on_write);
	} else {
		free(buf->base);
		uv_close((uv_handle_t *) stream, on_close);

		__debug("%s", uv_err_name(nread));
	}
}

static void on_connect_left(uv_connect_t *req, int status)
{
	uv_read_start(req->handle, on_alloc, on_read_left);

	__debug("done");
}

static void on_read_right(uv_stream_t *stream, ssize_t nread, const uv_buf_t* buf)
{
	write_req_t *wr;

	if (nread >= 0) {
		wr = (write_req_t *) malloc(sizeof *wr);
		if (!wr) {
			free(buf->base);
			__debug("no memory");
			return;
		}

		wr->buf = uv_buf_init(buf->base, nread);

		uv_write(&wr->req, (uv_stream_t *) &conn_left, &wr->buf, 1, on_write);
	} else {
		free(buf->base);
		uv_close((uv_handle_t *) stream, on_close);

		__debug("%s", uv_err_name(nread));
	}
}

static void on_connect_right(uv_connect_t *req, int status)
{
	uv_read_start(req->handle, on_alloc, on_read_right);

	__debug("done");
}

int tcp_client_tcp_client_init(const char* addr_left, int port_left, const char* addr_right, int port_right)
{
	struct sockaddr_in sock_addr_left;
	struct sockaddr_in sock_addr_right;
	int rc = 0;

	rc = uv_ip4_addr(addr_left, port_left, &sock_addr_left);
	if (rc) goto out;

	rc = uv_tcp_init(uv_default_loop(), &conn_left);
	if (rc) goto out;

	rc = uv_ip4_addr(addr_right, port_right, &sock_addr_right);
	if (rc) goto out;

	rc = uv_tcp_init(uv_default_loop(), &conn_right);
	if (rc) goto out;

	uv_tcp_connect(&connect_req_left, &conn_left, (const struct sockaddr *) &sock_addr_left, on_connect_left);
	uv_tcp_connect(&connect_req_right, &conn_right, (const struct sockaddr *) &sock_addr_right, on_connect_right);

out:
	if (rc) __debug("%s", uv_err_name(rc));
	return rc;
}
