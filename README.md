# Minimal HTTP/2 Examples (nghttp2)

This repository provides educational minimal examples for HTTP/2 in C using **nghttp2** and **OpenSSL**.

Current content:
- Client example (`src/http2-client.c`)
- Server example (`src/http2-server.c`)

## Client Example Overview

The client example is intentionally minimal and focuses on core nghttp2 usage.

To keep the flow readable:
- blocking I/O is used
- only one stream is handled
- error handling is simplified

The goal is to understand **how nghttp2 is integrated**, not to provide production-ready code.

## High-Level Flow (Client)

1. Open a TCP connection
2. Start a TLS handshake
3. Negotiate HTTP/2 via ALPN (`"h2"`)
4. Create an nghttp2 client session
5. Submit initial `SETTINGS`
6. Submit one `GET` request
7. Send serialized HTTP/2 frames
8. Read TLS data from the server
9. Feed received bytes back into nghttp2
10. Handle response events via callbacks
11. Exit when the stream closes

## Core nghttp2 Interaction Model

```c
nghttp2_session_callbacks_new(&cbs);
nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_cb);
nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv_cb);
nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_cb);

nghttp2_session_client_new(&session, cbs, &ctx);

nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1);
stream_id = nghttp2_submit_request(session, NULL, hdrs, hdrslen, NULL, NULL);

while (!ctx.stream_closed) {
  nghttp2_session_send(session);

  n = SSL_read(ssl, buf, sizeof(buf));

  nghttp2_session_mem_recv(session, buf, n);
}
```

## Responsibilities: nghttp2 vs Application

nghttp2 does:
- serialize HTTP/2 frames
- parse received HTTP/2 frames
- manage stream state
- trigger callbacks

nghttp2 does not:
- open sockets
- perform TLS handshakes
- negotiate ALPN
- read/write sockets directly

In this example:
- TCP: `socket()`, `connect()`
- TLS: OpenSSL (`SSL_connect`)
- ALPN: during TLS handshake
- HTTP/2 framing and parsing: nghttp2

## Send / Receive Model

Sending:
- Call `nghttp2_session_send(session)`
- nghttp2 serializes pending frames
- nghttp2 calls `send_cb()`
- app writes those bytes over TLS

Receiving:
- Read encrypted bytes via `SSL_read()`
- Feed bytes with `nghttp2_session_mem_recv()`
- nghttp2 parses frames and triggers callbacks

## HTTP/2 Request Headers

HTTP/2 uses pseudo-headers instead of the HTTP/1.1 request line.

HTTP/1.1:

```http
GET /hello HTTP/1.1
Host: example.com
```

HTTP/2 equivalent:

```text
:method = GET
:scheme = https
:authority = example.com:443
:path = /hello
```

These are passed to `nghttp2_submit_request()`.

## Important Callbacks (Client)

- `send_cb`: called when nghttp2 has outbound serialized bytes
- `on_header_cb`: called per header field
- `on_frame_recv_cb`: called per frame
- `on_data_chunk_recv_cb`: called per DATA payload chunk
- `on_stream_close_cb`: called when stream closes

## Deliberately Omitted (for clarity)

- nonblocking I/O
- multiple concurrent streams
- request body uploads
- redirects
- GOAWAY handling
- advanced error handling

## Build and Run (Client)

Build:

```bash
gcc -Wall -Wextra -O2 src/http2-client.c -o client $(pkg-config --cflags --libs libnghttp2 openssl)
```

Run:

```bash
./client example.com 443 /
```

## Recommended Reading Order

1. `main()`
2. `nghttp2_submit_settings()`
3. `nghttp2_submit_request()`
4. `flush_outbound()` -> `nghttp2_session_send()`
5. `read_tls_and_feed()` -> `nghttp2_session_mem_recv()`
6. callback implementations

## Summary

The key loop is:

submit request -> serialize frames -> send via TLS -> read via TLS -> feed to nghttp2 -> handle callbacks

This model is the foundation for building more advanced HTTP/2 clients and servers.

## Server Example Overview

The server example is intentionally minimal and focuses on core nghttp2 server flow.

The server supports two startup modes:
- `./http2-server 8080` for h2c prior knowledge
- `./http2-server 8443 server.key server.crt` for TLS + ALPN `h2`

To keep the flow readable:
- blocking I/O is used
- one connection is handled at a time
- error handling is simplified

The goal is to understand how transport setup and nghttp2 callbacks fit together.

## High-Level Flow (Server)

1. Parse CLI args and choose h2c or TLS mode
2. In TLS mode, initialize OpenSSL and create `SSL_CTX`
3. Create a TCP listen socket
4. Accept one connection
5. Perform transport setup:
   - plain TCP for h2c
   - TLS handshake + ALPN check for HTTPS
6. Create nghttp2 server session and register callbacks
7. Submit initial server `SETTINGS`
8. Flush outbound frames with `nghttp2_session_send()`
9. Loop:
   - read TCP/TLS bytes
   - feed bytes to `nghttp2_session_mem_recv()`
   - handle callbacks and generated frames
   - flush outbound frames
10. Submit a response when request `END_STREAM` is observed
11. Clean up stream state on stream close
12. Close the connection

## h2c vs TLS (Server)

- h2c mode in this sample assumes prior knowledge (HTTP/2 from first bytes)
- TLS mode negotiates HTTP/2 via ALPN (`h2`)
- HTTP/1.1 Upgrade to h2c is intentionally not implemented

## Callback Granularity (Server)

- `on_header_callback()`: per decoded header field (not per frame)
- `on_data_chunk_recv_callback()`: per DATA chunk
- `on_frame_recv_callback()`: per frame (used to inspect `END_STREAM`)
- `on_stream_close_callback()`: stream-lifecycle cleanup point

## Stream-Local State Pattern

The server uses a common event-driven pattern:
- allocate response body state on heap (`stream_body_t`)
- attach it with `nghttp2_session_set_stream_user_data()`
- provide payload lazily via `data_read_callback()`
- free it in `on_stream_close_callback()`

This is an application-side attachment point for callback-to-callback state transfer.

## Build and Run (Server)

Build:

```bash
gcc -Wall -Wextra -O2 src/http2-server.c -o http2-server $(pkg-config --cflags --libs libnghttp2 openssl)
```

Run (h2c):

```bash
./http2-server 8080
curl -v --http2-prior-knowledge http://127.0.0.1:8080/
```

Run (TLS + ALPN h2):

```bash
./http2-server 8443 server.key server.crt
curl -v -k --http2 https://127.0.0.1:8443/
```
