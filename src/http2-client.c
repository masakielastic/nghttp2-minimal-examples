/*
 * What this example demonstrates:
 * 1. Open a TCP connection and start TLS with ALPN "h2".
 * 2. Create an nghttp2 client session.
 * 3. Send the HTTP/2 client preface and initial SETTINGS.
 * 4. Submit one GET request.
 * 5. Receive response headers and body via nghttp2 callbacks.
 *
 * This is intentionally blocking and single-stream.
 * It is designed for learning, not for production use.
 *
 * Deliberately omitted for clarity:
 * - nonblocking I/O
 * - multiple concurrent streams
 * - request body upload
 * - HPACK / frame logging
 * - redirect handling
 * - timeout / retry logic
 * - graceful GOAWAY handling
 *
 * Build:
 *   gcc -Wall -Wextra -O2 client.c -o client \
 *      $(pkg-config --cflags --libs libnghttp2 openssl)
 *
 * Run:
 *   ./client example.com 443 /
 */

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * This helper points nghttp2_nv to existing string storage.
 * The pointed strings must remain valid while nghttp2 uses them.
 * Fine for this minimal example, but real code should document ownership clearly.
 */
#define MAKE_NV(NAME, VALUE)                                                   \
  (nghttp2_nv){                                                                \
      (uint8_t *)(NAME), (uint8_t *)(VALUE),                                   \
      (uint16_t)strlen(NAME), (uint16_t)strlen(VALUE),                         \
      NGHTTP2_NV_FLAG_NONE                                                     \
  }

#define RECV_BUF_SIZE (16 * 1024)
#define MAX_CONCURRENT_STREAMS 100
#define USER_AGENT "nghttp2-blocking-client/0.1"

/*
 * Per-session application state.
 *
 * This sample handles only one request stream, so we track:
 * - ssl: TLS connection used by send_cb / SSL_read
 * - stream_id: the single request stream we care about
 * - stream_closed: loop termination flag
 *
 * A multi-stream client would need a richer stream table/map.
 */
typedef struct {
  SSL *ssl;
  int32_t stream_id;
  int stream_closed;
} client_ctx;

/* ---- Declarations ---- */
static int tcp_connect(const char *host, const char *port);
static SSL_CTX *sslctx_create(void);
static int ssl_handshake(SSL_CTX *ctx, int fd, const char *host, SSL **out_ssl);
static int flush_outbound(nghttp2_session *session);
static int read_tls_and_feed(nghttp2_session *session, SSL *ssl,
                             uint8_t *rbuf, size_t rbuf_len);

static ssize_t send_cb(nghttp2_session *session,
                       const uint8_t *data, size_t length,
                       int flags, void *user_data);
static int on_header_cb(nghttp2_session *session,
                        const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen,
                        uint8_t flags, void *user_data);
static int on_frame_recv_cb(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            void *user_data);
static int on_data_chunk_recv_cb(nghttp2_session *session,
                                 uint8_t flags, int32_t stream_id,
                                 const uint8_t *data, size_t len,
                                 void *user_data);
static int on_stream_close_cb(nghttp2_session *session,
                              int32_t stream_id, uint32_t error_code,
                              void *user_data);

/*
 * High-level flow:
 * 1. Resolve host and connect TCP.
 * 2. Perform TLS handshake with SNI and ALPN.
 * 3. Verify that ALPN negotiated "h2".
 * 4. Create nghttp2 session and register callbacks.
 * 5. Submit initial SETTINGS.
 * 6. Submit one request HEADERS.
 * 7. Repeatedly:
 *    - let nghttp2 serialize outbound frames
 *    - send them over TLS
 *    - read TLS bytes
 *    - feed them back into nghttp2
 * 8. Stop when the stream is closed.
 */
/* ---- Main (control flow first) ---- */
int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s <host> <port> <path>\n", argv[0]);
    return 2;
  }
  const char *host = argv[1];
  const char *port = argv[2];
  const char *path = argv[3];

  /* OpenSSL init */
  SSL_library_init();
  SSL_load_error_strings();

  int exit_code = 1;
  int fd = -1;
  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  nghttp2_session_callbacks *cbs = NULL;
  nghttp2_session *session = NULL;
  client_ctx ctx;
  uint8_t rbuf[RECV_BUF_SIZE];

  memset(&ctx, 0, sizeof(ctx));
  ctx.stream_id = -1;

  fd = tcp_connect(host, port);
  if (fd < 0) goto cleanup;

  ssl_ctx = sslctx_create();
  if (!ssl_ctx) {
    fprintf(stderr, "SSL_CTX create failed\n");
    goto cleanup;
  }

  if (ssl_handshake(ssl_ctx, fd, host, &ssl) != 0) {
    goto cleanup;
  }
  ctx.ssl = ssl;

  /* nghttp2 session init */
  if (nghttp2_session_callbacks_new(&cbs) != 0) {
    fprintf(stderr, "callbacks_new failed\n");
    goto cleanup;
  }

  nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
  nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_cb);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv_cb);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_cb);

  if (nghttp2_session_client_new(&session, cbs, &ctx) != 0) {
    fprintf(stderr, "client_new failed\n");
    goto cleanup;
  }

  nghttp2_session_callbacks_del(cbs);
  cbs = NULL;

  /*
   * Queue the client's initial SETTINGS frame.
   * submit_* APIs enqueue frames; they are not sent immediately.
   * When nghttp2_session_send() runs, nghttp2 serializes the client
   * connection preface and any pending frames.
   */
  nghttp2_settings_entry iv[1];
  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  /* Included mainly as an example of sending a SETTINGS parameter. */
  iv[0].value = MAX_CONCURRENT_STREAMS;

  if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1) != 0) {
    fprintf(stderr, "submit_settings failed\n");
    goto cleanup;
  }

  /* Build request headers */
  char authority[512];
  int nw = snprintf(authority, sizeof(authority), "%s:%s", host, port);
  if (nw < 0 || (size_t)nw >= sizeof(authority)) {
    fprintf(stderr, "authority buffer too small\n");
    goto cleanup;
  }

  /*
   * HTTP/2 uses pseudo-headers for request control data.
   * These replace the request line in HTTP/1.1:
   *
   *   GET /path HTTP/1.1
   *   Host: example.com
   *
   * becomes:
   *   :method = GET
   *   :scheme = https
   *   :authority = example.com:443
   *   :path = /path
   */
  nghttp2_nv hdrs[] = {
      MAKE_NV(":method", "GET"),
      MAKE_NV(":scheme", "https"),
      MAKE_NV(":authority", authority),
      /* path should be an HTTP/2 :path value such as "/" or "/index.html". */
      MAKE_NV(":path", path),
      /* Regular application headers can be mixed with pseudo-headers. */
      MAKE_NV("user-agent", USER_AGENT),
      MAKE_NV("accept", "*/*"),
  };

  ctx.stream_id = nghttp2_submit_request(session, NULL, hdrs,
                                         (size_t)(sizeof(hdrs) / sizeof(hdrs[0])),
                                         NULL, NULL);
  if (ctx.stream_id < 0) {
    fprintf(stderr, "submit_request failed\n");
    goto cleanup;
  }
  fprintf(stderr, "Submitted request on stream %d\n", ctx.stream_id);

  /*
   * Important model:
   * - nghttp2 does not read from the socket by itself.
   * - nghttp2 does not write to the socket by itself.
   *
   * Instead:
   * - session_send() asks nghttp2 to serialize outbound HTTP/2 bytes
   *   and push them through send_cb().
   * - session_mem_recv() lets us feed received bytes back into nghttp2,
   *   which parses frames and triggers callbacks.
   */
  while (!ctx.stream_closed) {
    if (flush_outbound(session) != 0) goto cleanup;
    if (read_tls_and_feed(session, ssl, rbuf, sizeof(rbuf)) != 0) goto cleanup;
  }

  exit_code = 0;

cleanup:
  if (session) {
    /* Flush any remaining outbound (e.g., GOAWAY/ACK). */
    (void)nghttp2_session_send(session);
    nghttp2_session_del(session);
  }
  if (cbs) nghttp2_session_callbacks_del(cbs);
  if (ssl) {
    /* Simplified: production code should handle SSL_shutdown()'s two-phase behavior. */
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  if (ssl_ctx) SSL_CTX_free(ssl_ctx);
  if (fd >= 0) close(fd);
  return exit_code;
}

/* ---- TLS/TCP helpers ---- */
static int tcp_connect(const char *host, const char *port) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = NULL;
  int gai = getaddrinfo(host, port, &hints, &res);
  if (gai != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
    return -1;
  }

  int fd = -1;
  for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }

  freeaddrinfo(res);
  if (fd < 0) fprintf(stderr, "tcp_connect: failed\n");
  return fd;
}

/*
 * Advertise support for HTTP/2 during TLS handshake.
 * nghttp2 itself does not negotiate ALPN for us;
 * TLS negotiation happens outside nghttp2.
 */
static SSL_CTX *sslctx_create(void) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) return NULL;

  /* Verify server cert */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
    SSL_CTX_free(ctx);
    return NULL;
  }

  /* ALPN: offer h2 */
  static const unsigned char alpn_protos[] = {2, 'h', '2'};
  if (SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos)) != 0) {
    SSL_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

static int ssl_handshake(SSL_CTX *ctx, int fd, const char *host, SSL **out_ssl) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) return -1;

  /* Tell the server which hostname we want (SNI). */
  if (SSL_set_tlsext_host_name(ssl, host) != 1) {
    fprintf(stderr, "SSL_set_tlsext_host_name failed\n");
    SSL_free(ssl);
    return -1;
  }

  if (SSL_set_fd(ssl, fd) != 1) {
    fprintf(stderr, "SSL_set_fd failed\n");
    SSL_free(ssl);
    return -1;
  }

  /* Complete the TLS handshake. */
  if (SSL_connect(ssl) != 1) {
    fprintf(stderr, "SSL_connect failed\n");
    SSL_free(ssl);
    return -1;
  }

  /* Confirm that TLS negotiated HTTP/2 via ALPN. */
  const unsigned char *alpn = NULL;
  unsigned int alpn_len = 0;
  SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
  if (!(alpn_len == 2 && memcmp(alpn, "h2", 2) == 0)) {
    fprintf(stderr, "Server did not negotiate h2 via ALPN\n");
    SSL_free(ssl);
    return -1;
  }

  /* Verify certificate chain and hostname. */
  X509 *cert = SSL_get_peer_certificate(ssl);
  if (!cert) {
    fprintf(stderr, "No server certificate\n");
    SSL_free(ssl);
    return -1;
  }
  long vr = SSL_get_verify_result(ssl);
  if (vr != X509_V_OK) {
    fprintf(stderr, "Certificate verify failed: %s\n", X509_verify_cert_error_string(vr));
    X509_free(cert);
    SSL_free(ssl);
    return -1;
  }
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (X509_check_host(cert, host, 0, 0, NULL) != 1) {
    fprintf(stderr, "Hostname verification failed\n");
    X509_free(cert);
    SSL_free(ssl);
    return -1;
  }
#endif
  X509_free(cert);

  *out_ssl = ssl;
  return 0;
}

/* Send all pending outbound HTTP/2 frames. */
static int flush_outbound(nghttp2_session *session) {
  int rv = nghttp2_session_send(session);
  if (rv != 0) {
    fprintf(stderr, "session_send: %s\n", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* Read TLS bytes and feed them into nghttp2's parser. */
static int read_tls_and_feed(nghttp2_session *session, SSL *ssl,
                             uint8_t *rbuf, size_t rbuf_len) {
  /*
   * One SSL_read() call may contain:
   * - part of one HTTP/2 frame
   * - exactly one frame
   * - multiple frames
   *
   * nghttp2_session_mem_recv() handles buffering/parsing for us.
   */
  int n = SSL_read(ssl, rbuf, (int)rbuf_len);
  if (n <= 0) {
    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) {
      fprintf(stderr, "TLS connection closed\n");
    } else {
      fprintf(stderr, "SSL_read error: %d\n", err);
    }
    return -1;
  }

  ssize_t fed = nghttp2_session_mem_recv(session, rbuf, (size_t)n);
  if (fed < 0) {
    fprintf(stderr, "mem_recv: %s\n", nghttp2_strerror((int)fed));
    return -1;
  }
  /*
   * In this sample, we pass exactly one SSL_read() buffer to mem_recv()
   * and treat it as fully handed off to nghttp2.
   * More advanced designs may handle consumed-byte accounting (fed vs n)
   * more strictly across staged input buffers.
   */
  return 0;
}

/* ---- nghttp2 callbacks ---- */
/*
 * nghttp2 calls this when it has serialized outbound HTTP/2 bytes.
 * Our job is only to deliver those bytes over TLS.
 */
static ssize_t send_cb(nghttp2_session *session,
                       const uint8_t *data, size_t length,
                       int flags, void *user_data) {
  (void)session;
  (void)flags;
  client_ctx *c = (client_ctx *)user_data;

  size_t off = 0;
  while (off < length) {
    int n = SSL_write(c->ssl, data + off, (int)(length - off));
    if (n <= 0) {
      int err = SSL_get_error(c->ssl, n);
      fprintf(stderr, "SSL_write error: %d\n", err);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    off += (size_t)n;
  }
  return (ssize_t)length;
}

/* Per-header-field callback, not per-frame callback. */
static int on_header_cb(nghttp2_session *session,
                        const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen,
                        uint8_t flags, void *user_data) {
  (void)session;
  (void)flags;
  client_ctx *c = (client_ctx *)user_data;

  if (frame->hd.type == NGHTTP2_HEADERS &&
      frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
      frame->hd.stream_id == c->stream_id) {
    fprintf(stderr, "H: %.*s: %.*s\n",
            (int)namelen, (const char *)name,
            (int)valuelen, (const char *)value);
  }
  return 0;
}

/* Per-frame callback: useful for understanding frame-level events. */
static int on_frame_recv_cb(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            void *user_data) {
  (void)session;
  client_ctx *c = (client_ctx *)user_data;
  /*
   * Frame-level view only:
   * - Even when a HEADERS frame arrives, individual header fields are
   *   delivered via on_header_cb().
   * - Even when a DATA frame arrives, body payload bytes are delivered
   *   via on_data_chunk_recv_cb().
   */

  if (frame->hd.type == NGHTTP2_SETTINGS) {
    fprintf(stderr, "Received SETTINGS%s\n",
            (frame->hd.flags & NGHTTP2_FLAG_ACK) ? " ACK" : "");
  }

  if (frame->hd.stream_id == c->stream_id &&
      (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
    fprintf(stderr, "END_STREAM seen on frame type=%u\n", frame->hd.type);
  }

  if (frame->hd.stream_id == c->stream_id) {
    if (frame->hd.type == NGHTTP2_HEADERS &&
        frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      fprintf(stderr, "Received response headers (stream=%d)\n", c->stream_id);
    }
    if (frame->hd.type == NGHTTP2_DATA) {
      /* data chunks handled in on_data_chunk_recv_cb */
    }
  }
  return 0;
}

/* Per-data-chunk callback: body bytes may arrive in multiple chunks. */
static int on_data_chunk_recv_cb(nghttp2_session *session,
                                 uint8_t flags, int32_t stream_id,
                                 const uint8_t *data, size_t len,
                                 void *user_data) {
  (void)session;
  (void)flags;
  client_ctx *c = (client_ctx *)user_data;

  if (stream_id == c->stream_id) {
    /* Body to stdout */
    if (fwrite(data, 1, len, stdout) != len) {
      fprintf(stderr, "fwrite failed\n");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    fflush(stdout);
  }
  return 0;
}

/* Callback when the request stream is closed by either endpoint. */
static int on_stream_close_cb(nghttp2_session *session,
                              int32_t stream_id, uint32_t error_code,
                              void *user_data) {
  (void)session;
  client_ctx *c = (client_ctx *)user_data;

  /*
   * error_code == NGHTTP2_NO_ERROR usually means a normal end of stream.
   * Non-zero often indicates a reset or protocol-related failure.
   */
  if (stream_id == c->stream_id) {
    fprintf(stderr, "\nStream closed (id=%d, error=%u: %s)\n",
            stream_id, error_code, nghttp2_http2_strerror(error_code));
    c->stream_closed = 1;
  }
  return 0;
}
