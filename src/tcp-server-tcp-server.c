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
#include <sys/socket.h>
#include <uv.h>

#include "tcp-server-tcp-server.h"
#include "misc.h"

void on_server_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

static void on_server_close(uv_handle_t *handle);

static void on_server_write(uv_write_t *req, int status);

static void on_server_read_left(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_server_new_connection_left(uv_stream_t *server, int status);

static void on_server_read_right(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_server_new_connection_right(uv_stream_t *server, int status);

static uv_tcp_t server_left;
static uv_tcp_t client_from_left;

static uv_tcp_t server_right;
static uv_tcp_t client_from_right;

static struct sockaddr_in bind_addr_left;
static struct sockaddr_in bind_addr_right;

void on_server_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->base = malloc(suggested_size);
	if (buf->base)
		buf->len = suggested_size;
	else
		buf->len = 0;
}

void on_server_close(uv_handle_t *handle)
{
	__debug("done");
}

static void on_server_write(uv_write_t *req, int status)
{
	write_req_t *wr = (write_req_t *) req;

	free(wr->buf.base);
	free(wr);

	if (status == 0)
		return;

	__debug("%s\n", uv_err_name(status));
}

static void on_server_read_left(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
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

		uv_write(&wr->req, (uv_stream_t *) &client_from_right, &wr->buf, 1, on_server_write);
	} else {
		free(buf->base);
		uv_close((uv_handle_t *) stream, on_server_close);

		__debug("%s", uv_err_name(nread));
	}
}

void on_server_new_connection_left(uv_stream_t *server, int status)
{
	if (status == -1) {
		// error!
		return;
	}

	uv_tcp_init(uv_default_loop(), &client_from_left);

	client_from_left.data = server;

	if (uv_accept(server, (uv_stream_t *) &client_from_left) == 0) {
		uv_read_start((uv_stream_t *) &client_from_left, on_server_alloc, on_server_read_left);
	} else {
		uv_close((uv_handle_t *) &client_from_left, on_server_close);
	}

	__debug("done");
}

void on_server_read_right(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
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

		uv_write(&wr->req, (uv_stream_t *) &client_from_left, &wr->buf, 1, on_server_write);
	} else {
		free(buf->base);
		uv_close((uv_handle_t *) stream, on_server_close);

		__debug("%s", uv_err_name(nread));
	}
}

void on_server_new_connection_right(uv_stream_t *server, int status)
{
	if (status == -1) {
		return;
	}

	uv_tcp_init(uv_default_loop(), &client_from_right);

	client_from_right.data = server;

	if (uv_accept(server, (uv_stream_t *) &client_from_right) == 0) {
		uv_read_start((uv_stream_t *) &client_from_right, on_server_alloc, on_server_read_right);
	} else {
		uv_close((uv_handle_t*) &client_from_right, on_server_close);
	}

	__debug("done");
}

void tcp_server_tcp_server_close()
{
	uv_close((uv_handle_t *) &server_left, on_server_close);
	uv_close((uv_handle_t *) &server_right, on_server_close);
}

int tcp_server_tcp_server_init(const char* addr_left, int port_left, const char* addr_right, int port_right)
{
	int rc = 0;

	rc = uv_ip4_addr(addr_left, port_left, &bind_addr_left);
	if (rc) goto out;

	rc = uv_tcp_init(uv_default_loop(), &server_left);
	if (rc) goto out;

	uv_tcp_bind(&server_left, (struct sockaddr *) &bind_addr_left, 0);
	rc = uv_listen((uv_stream_t *) &server_left, 128, on_server_new_connection_left);
	if (rc) goto out;

	rc = uv_ip4_addr(addr_right, port_right, &bind_addr_right);
	if (rc) goto out;

	rc = uv_tcp_init(uv_default_loop(), &server_right);
	if (rc) goto out;

	uv_tcp_bind(&server_right, (struct sockaddr *) &bind_addr_right, 0);
	rc = uv_listen((uv_stream_t *) &server_right, 128, on_server_new_connection_right);
	if (rc) goto out;

out:
	if (rc) __debug("%s", uv_err_name(rc));
	return rc;
}
