// tls_h2_server.c
// Minimal blocking HTTP/2 server in two modes:
// - h2c (cleartext) with prior knowledge
// - TLS + ALPN "h2"
// Single-thread, handles one connection at a time.

#define _POSIX_C_SOURCE 200809L

#include <nghttp2/nghttp2.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define RECV_BUF_SIZE (16 * 1024)
#define MAX_CONCURRENT_STREAMS 100
static const uint8_t RESPONSE_PAYLOAD[] = "Hello HTTP/2 over TLS\n";

typedef struct {
  int fd;
  SSL *ssl;
  int use_tls;
} conn_t;

typedef struct {
  const uint8_t *data;
  size_t len;
  size_t off;
} stream_body_t;

/* ---- Declarations ---- */
static void die(const char *msg);
static void openssl_die(const char *msg);
static void print_usage(FILE *out, const char *prog);

static int flush_outbound(nghttp2_session *session);
static int read_and_feed(nghttp2_session *session, conn_t *conn,
                         uint8_t *buf, size_t buf_len);

static int alpn_select_cb(SSL *ssl,
                          const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in,
                          unsigned int inlen,
                          void *arg);
static SSL_CTX *create_ssl_ctx(const char *cert_pem, const char *key_pem);

static ssize_t send_callback(nghttp2_session *session,
                             const uint8_t *data, size_t length,
                             int flags, void *user_data);
static ssize_t data_read_callback(nghttp2_session *session,
                                  int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data);
static int submit_simple_response(nghttp2_session *session, int32_t stream_id);
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data);
static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags,
                                       int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data);
static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data);
static int on_stream_close_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data);
static nghttp2_session *setup_h2_session(conn_t *conn);

static int create_listen_socket(const char *ip, uint16_t port);
static void serve_one_connection(SSL_CTX *ctx, int client_fd, int use_tls);

/*
 * High-level flow:
 * 1. Parse mode from args:
 *    - <PORT>            => h2c (prior knowledge)
 *    - <PORT> <KEY> <CERT> => TLS + ALPN h2
 * 2. Create listen socket.
 * 3. Accept one TCP client at a time.
 * 4. For each client, run nghttp2 read/feed + send loop until done.
 */
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  const char *ip = "127.0.0.1";
  uint16_t port = 0;
  const char *cert_pem = "server.crt";
  const char *key_pem = "server.key";
  int use_tls = 0;

  if (argc >= 2 &&
      (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    print_usage(stdout, argv[0]);
    return 0;
  }

  if (!(argc == 2 || argc == 4)) {
    print_usage(stderr, argv[0]);
    return 2;
  }

  char *endp = NULL;
  unsigned long p = strtoul(argv[1], &endp, 10);
  if (argv[1][0] == '\0' || endp == NULL || *endp != '\0' || p == 0 || p > 65535) {
    fprintf(stderr, "Invalid port: %s\n", argv[1]);
    print_usage(stderr, argv[0]);
    return 2;
  }
  port = (uint16_t)p;

  if (argc == 4) {
    key_pem = argv[2];
    cert_pem = argv[3];
    use_tls = 1;
  }

  SSL_CTX *ctx = NULL;
  if (use_tls) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ctx = create_ssl_ctx(cert_pem, key_pem);
  }

  int lfd = create_listen_socket(ip, port);
  if (use_tls) {
    fprintf(stderr, "Listening on https://%s:%u (HTTP/2 via ALPN h2)\n", ip, port);
    fprintf(stderr, "Try: nghttp -v https://%s:%u/ --no-verify-peer\n", ip, port);
    fprintf(stderr, "Try: curl -v -k --http2 https://%s:%u/\n", ip, port);
  } else {
    fprintf(stderr, "Listening on http://%s:%u (h2c prior-knowledge)\n", ip, port);
    fprintf(stderr, "Try: nghttp -v http://%s:%u/\n", ip, port);
    fprintf(stderr, "Try: curl -v --http2-prior-knowledge http://%s:%u/\n", ip, port);
  }

  for (;;) {
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int cfd = accept(lfd, (struct sockaddr *)&caddr, &clen);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      die("accept");
    }
    serve_one_connection(ctx, cfd, use_tls); /* sequential / blocking */
  }

  close(lfd);
  if (ctx) SSL_CTX_free(ctx);
  EVP_cleanup();
  return 0;
}

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static void openssl_die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  ERR_print_errors_fp(stderr);
  exit(1);
}

static void print_usage(FILE *out, const char *prog) {
  fprintf(out, "Usage: %s <PORT> [<PRIVATE_KEY> <CERT>]\n", prog);
  fprintf(out, "\n");
  fprintf(out, "Examples:\n");
  fprintf(out, "  %s 8080\n", prog);
  fprintf(out, "  %s 8443 server.key server.crt\n", prog);
  fprintf(out, "\n");
  fprintf(out, "Test with curl (h2c):\n");
  fprintf(out, "  curl -v --http2-prior-knowledge http://127.0.0.1:8080/\n");
  fprintf(out, "\n");
  fprintf(out, "Test with curl (TLS+h2):\n");
  fprintf(out, "  curl -v -k --http2 https://127.0.0.1:8443/\n");
}

static int flush_outbound(nghttp2_session *session) {
  int rv = nghttp2_session_send(session);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_session_send error: %s\n", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

static int read_and_feed(nghttp2_session *session, conn_t *conn,
                         uint8_t *buf, size_t buf_len) {
  ssize_t n = 0;

  /*
   * One read() call may contain:
   * - part of one HTTP/2 frame
   * - exactly one frame
   * - multiple frames
   *
   * nghttp2_session_mem_recv() handles buffering/parsing for us.
   */
  if (conn->use_tls) {
    n = SSL_read(conn->ssl, buf, (int)buf_len);
    if (n == 0) return 1; /* peer closed TLS connection */
    if (n < 0) {
      int err = SSL_get_error(conn->ssl, (int)n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0; /* rare in blocking mode */
      }
      fprintf(stderr, "SSL_read failed (err=%d)\n", err);
      ERR_print_errors_fp(stderr);
      return -1;
    }
  } else {
    n = recv(conn->fd, buf, buf_len, 0);
    if (n == 0) return 1; /* peer closed TCP connection */
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return 0;
      }
      perror("recv");
      return -1;
    }
  }

  ssize_t fed = nghttp2_session_mem_recv(session, buf, (size_t)n);
  if (fed < 0) {
    fprintf(stderr, "nghttp2_session_mem_recv error: %s\n", nghttp2_strerror((int)fed));
    return -1;
  }
  /*
   * In this sample, we pass exactly one read() buffer to mem_recv()
   * and treat it as fully handed off to nghttp2.
   * More advanced designs may handle consumed-byte accounting (fed vs n)
   * more strictly across staged input buffers.
   */
  return 0;
}

/* ---------- OpenSSL (ALPN h2) ---------- */

static int alpn_select_cb(SSL *ssl,
                          const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in,
                          unsigned int inlen,
                          void *arg) {
  (void)ssl;
  (void)arg;
  /* "h2" in ALPN wire format: length-prefixed. */
  static const unsigned char h2[] = {0x02, 'h', '2'};

  if (SSL_select_next_proto((unsigned char **)out, outlen, h2, sizeof(h2), in, inlen) ==
      OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

static SSL_CTX *create_ssl_ctx(const char *cert_pem, const char *key_pem) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) openssl_die("SSL_CTX_new failed");

  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
    openssl_die("SSL_CTX_set_min_proto_version failed");
  }

  if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
    openssl_die("SSL_CTX_use_certificate_file failed");
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1) {
    openssl_die("SSL_CTX_use_PrivateKey_file failed");
  }
  if (SSL_CTX_check_private_key(ctx) != 1) {
    openssl_die("SSL_CTX_check_private_key failed");
  }

  SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

#ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

  return ctx;
}

/* ---------- nghttp2 callbacks ---------- */

/* nghttp2 calls this when it has serialized outbound HTTP/2 bytes. */
static ssize_t send_callback(nghttp2_session *session,
                             const uint8_t *data, size_t length,
                             int flags, void *user_data) {
  (void)session;
  (void)flags;
  conn_t *conn = (conn_t *)user_data;

  size_t off = 0;
  while (off < length) {
    if (conn->use_tls) {
      int n = SSL_write(conn->ssl, data + off, (int)(length - off));
      if (n <= 0) {
        int err = SSL_get_error(conn->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          return NGHTTP2_ERR_WOULDBLOCK;
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      off += (size_t)n;
    } else {
      ssize_t n = send(conn->fd, data + off, length - off, MSG_NOSIGNAL);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return NGHTTP2_ERR_WOULDBLOCK;
        }
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      off += (size_t)n;
    }
  }
  return (ssize_t)length;
}

static ssize_t data_read_callback(nghttp2_session *session,
                                  int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data) {
  (void)session;
  (void)stream_id;
  (void)user_data;
  stream_body_t *body = (stream_body_t *)source->ptr;

  size_t remain = body->len - body->off;
  size_t ncopy = remain < length ? remain : length;
  if (ncopy > 0) {
    memcpy(buf, body->data + body->off, ncopy);
    body->off += ncopy;
  }
  if (body->off >= body->len) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return (ssize_t)ncopy;
}

static int submit_simple_response(nghttp2_session *session, int32_t stream_id) {
  stream_body_t *body = (stream_body_t *)calloc(1, sizeof(stream_body_t));
  if (!body) return NGHTTP2_ERR_CALLBACK_FAILURE;
  body->data = RESPONSE_PAYLOAD;
  body->len = sizeof(RESPONSE_PAYLOAD) - 1;
  body->off = 0;

  nghttp2_session_set_stream_user_data(session, stream_id, body);

  char content_length[32];
  int nw = snprintf(content_length, sizeof(content_length), "%zu", body->len);
  if (nw < 0 || (size_t)nw >= sizeof(content_length)) {
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    free(body);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  nghttp2_nv hdrs[] = {
      {(uint8_t *)":status", (uint8_t *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
      {(uint8_t *)"content-type", (uint8_t *)"text/plain; charset=utf-8",
       12, 24, NGHTTP2_NV_FLAG_NONE},
      {(uint8_t *)"content-length", (uint8_t *)content_length,
       14, (uint16_t)strlen(content_length), NGHTTP2_NV_FLAG_NONE},
  };

  nghttp2_data_provider dp;
  memset(&dp, 0, sizeof(dp));
  dp.source.ptr = body;
  dp.read_callback = data_read_callback;

  int rv = nghttp2_submit_response(session, stream_id, hdrs,
                                   (size_t)(sizeof(hdrs) / sizeof(hdrs[0])), &dp);
  if (rv != 0) {
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    free(body);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

/* Per-header-field callback, not per-frame callback. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags, void *user_data) {
  (void)session;
  (void)flags;
  (void)user_data;

  if (frame->hd.type == NGHTTP2_HEADERS &&
      frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    fprintf(stderr, "Req-H (stream=%d): %.*s: %.*s\n",
            frame->hd.stream_id,
            (int)namelen, (const char *)name,
            (int)valuelen, (const char *)value);
  }
  return 0;
}

/* Per-data-chunk callback: request body bytes may arrive in multiple chunks. */
static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags,
                                       int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data) {
  (void)session;
  (void)flags;
  (void)data;
  (void)user_data;
  fprintf(stderr, "Req-DATA chunk (stream=%d, len=%zu)\n", stream_id, len);
  return 0;
}

/* Per-frame callback: useful for understanding frame-level events. */
static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data) {
  (void)user_data;

  if (frame->hd.type == NGHTTP2_SETTINGS) {
    fprintf(stderr, "Received SETTINGS%s\n",
            (frame->hd.flags & NGHTTP2_FLAG_ACK) ? " ACK" : "");
  }

  if (frame->hd.stream_id > 0 && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
    fprintf(stderr, "END_STREAM seen on frame type=%u (stream=%d)\n",
            frame->hd.type, frame->hd.stream_id);

    if ((frame->hd.type == NGHTTP2_HEADERS &&
         frame->headers.cat == NGHTTP2_HCAT_REQUEST) ||
        frame->hd.type == NGHTTP2_DATA) {
      if (submit_simple_response(session, frame->hd.stream_id) != 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
  }

  return 0;
}

static int on_stream_close_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data) {
  (void)error_code;
  (void)user_data;
  stream_body_t *body = (stream_body_t *)nghttp2_session_get_stream_user_data(session, stream_id);
  if (body) {
    free(body);
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
  }
  return 0;
}

static nghttp2_session *setup_h2_session(conn_t *conn) {
  nghttp2_session_callbacks *cbs = NULL;
  nghttp2_session *session = NULL;

  if (nghttp2_session_callbacks_new(&cbs) != 0) return NULL;

  nghttp2_session_callbacks_set_send_callback(cbs, send_callback);
  nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_callback);

  if (nghttp2_session_server_new(&session, cbs, conn) != 0) {
    nghttp2_session_callbacks_del(cbs);
    return NULL;
  }
  nghttp2_session_callbacks_del(cbs);

  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS}};
  if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, 1) != 0) {
    nghttp2_session_del(session);
    return NULL;
  }

  return session;
}

/* ---------- TCP helpers ---------- */

static int create_listen_socket(const char *ip, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) die("socket");

  int yes = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
    die("setsockopt");
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
    fprintf(stderr, "inet_pton failed for %s\n", ip);
    exit(1);
  }

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
  if (listen(fd, 16) < 0) die("listen");
  return fd;
}

/* ---------- per-connection loop ---------- */

static void serve_one_connection(SSL_CTX *ctx, int client_fd, int use_tls) {
  conn_t conn;
  memset(&conn, 0, sizeof(conn));
  conn.fd = client_fd;
  conn.use_tls = use_tls;

  if (use_tls) {
    conn.ssl = SSL_new(ctx);
    if (!conn.ssl) {
      close(client_fd);
      return;
    }
    if (SSL_set_fd(conn.ssl, client_fd) != 1) {
      fprintf(stderr, "SSL_set_fd failed\n");
      SSL_free(conn.ssl);
      close(client_fd);
      return;
    }

    int r = SSL_accept(conn.ssl);
    if (r != 1) {
      int err = SSL_get_error(conn.ssl, r);
      fprintf(stderr, "SSL_accept failed (err=%d)\n", err);
      ERR_print_errors_fp(stderr);
      SSL_free(conn.ssl);
      close(client_fd);
      return;
    }

    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(conn.ssl, &alpn, &alpn_len);
    if (!(alpn_len == 2 && memcmp(alpn, "h2", 2) == 0)) {
      fprintf(stderr, "Client did not negotiate h2 via ALPN (got: %.*s). Closing.\n",
              (int)alpn_len, alpn ? (const char *)alpn : "");
      SSL_shutdown(conn.ssl);
      SSL_free(conn.ssl);
      close(client_fd);
      return;
    }
  }

  nghttp2_session *session = setup_h2_session(&conn);
  if (!session) {
    if (conn.ssl) {
      SSL_shutdown(conn.ssl);
      SSL_free(conn.ssl);
    }
    close(client_fd);
    return;
  }

  if (flush_outbound(session) != 0) {
    nghttp2_session_del(session);
    if (conn.ssl) {
      SSL_shutdown(conn.ssl);
      SSL_free(conn.ssl);
    }
    close(client_fd);
    return;
  }

  uint8_t buf[RECV_BUF_SIZE];

  for (;;) {
    int rr = read_and_feed(session, &conn, buf, sizeof(buf));
    if (rr > 0) break;
    if (rr < 0) break;
    if (flush_outbound(session) != 0) break;

    if (nghttp2_session_want_read(session) == 0 &&
        nghttp2_session_want_write(session) == 0) {
      break;
    }
  }

  nghttp2_session_del(session);
  if (conn.ssl) {
    SSL_shutdown(conn.ssl);
    SSL_free(conn.ssl);
  }
  close(client_fd);
}
