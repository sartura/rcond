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

typedef struct client_t client_t;

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void on_close(uv_handle_t *handle);
static void on_write(uv_write_t *req, int status);
static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void on_connect(uv_connect_t *req, int status);

static void tcp_client_init(client_t *client);

struct client_t {
    uv_tcp_t handle;
	uv_connect_t *connect_req;
	struct sockaddr_in sock_addr;
	struct client_t *bridge;
    int request_num;
};

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	buf->base = malloc(suggested_size);
	if (buf->base)
		buf->len = suggested_size;
	else
		buf->len = 0;
}

static void on_close(uv_handle_t *handle)
{
	client_t *client = (client_t *) handle->data;

	free(client->connect_req);
	client->connect_req = NULL;

	tcp_client_init(client);
	// free(client);

	// free(handle);
	// handle = NULL;

	// uv_stop(uv_default_loop());
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

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t* buf)
{
	client_t *client = (client_t *) stream->data;
	write_req_t *wr;

	if (nread >= 0) {
#if 0
		if (!(&client->bridge->handle))
			goto error;
#endif

		wr = (write_req_t *) malloc(sizeof *wr);
		if (!wr)
			goto error;

		wr->buf = uv_buf_init(buf->base, nread);

		uv_write(&wr->req, (uv_stream_t *) &client->bridge->handle, &wr->buf, 1, on_write);
	} else {
		uv_close((uv_handle_t *) stream, on_close);
		goto error;
	}

	return;

error:
	free(buf->base);
	__debug("%s", uv_err_name(nread));
}

static void on_connect(uv_connect_t *req, int status)
{
	uv_read_start(req->handle, on_alloc, on_read);

	__debug("done");
}

static void tcp_client_init(client_t *client)
{
	int rc = 0;

	rc = uv_tcp_init(uv_default_loop(), &client->handle);
	if (rc) // FIXME
		return;

	client->connect_req = (uv_connect_t *) malloc(sizeof(uv_connect_t));
	uv_tcp_connect(client->connect_req, &client->handle, (const struct sockaddr *) &client->sock_addr, on_connect);
}

int tcp_client_tcp_client_init(const char *addr_left, int port_left, const char *addr_right, int port_right)
{
	client_t *client_left, *client_right;
	int rc = 0;

	client_left = (client_t *) malloc(sizeof(client_t));
	client_right = (client_t *) malloc(sizeof(client_t));

	if (!client_left || !client_right) {
		goto out;
	}

	rc = uv_ip4_addr(addr_right, port_right, &client_right->sock_addr);
	if (rc) goto out;

	rc = uv_ip4_addr(addr_right, port_left, &client_left->sock_addr);
	if (rc) goto out;

	client_left->handle.data = client_left;
	client_right->handle.data = client_right;

	client_left->bridge = client_right;
	client_right->bridge = client_left;

	tcp_client_init(client_left);
	tcp_client_init(client_right);

	return rc;

out:
	free(client_left);
	free(client_right);

	if (rc) __debug("%s", uv_err_name(rc));

	return rc;
}
