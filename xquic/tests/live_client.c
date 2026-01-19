/**
 * live_client_transport_full.c
 *
 * QUIC Transport(ALPN="transport") live client (reliable stream) with:
 *  - xqc_connect() + ALPN=transport
 *  - -u/-m/-i options kept (compatible with your migration workflow)
 *  - xqc_log(...) / qlog / keylog output support (to stderr or files)
 *  - crash diagnostics (SIGSEGV/SIGABRT backtrace) + ignore SIGPIPE
 *
 * Run examples:
 *   # connectivity (dump first 16 bytes)
 *   ./live_client -a 192.168.68.125 -p 8443 -u /live -3 -l d -c b 2>live_client.log | head -c 16 | xxd
 *
 *   # with migration bound to NIC (Linux)
 *   ./live_client -a 192.168.68.125 -p 8443 -u /live -m -i enp6s20 -3 -l d -c b 2>live_client.log | \
 *     ffplay -fflags nobuffer -flags low_delay -analyzeduration 0 -probesize 32 -f mpegts -i pipe:0
 *
 * Optional log files:
 *   -O <clog>   : write xquic log to file instead of stderr
 *   -Q <qlog>   : write qlog events to file
 *   -K <keylog> : write TLS keylog to file (for Wireshark)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <fcntl.h>

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>
#else
#include "getopt.h"
#include <winsock2.h>
#endif

#include <event2/event.h>
#include <xquic/xquic.h>

/* tests helpers */
#include "platform.h"

#ifdef __linux__
#include <execinfo.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "rebind.h"
#endif

#ifndef XQC_PACKET_TMP_BUF_LEN
#define XQC_PACKET_TMP_BUF_LEN 1500
#endif

#define XQC_ALPN_TRANSPORT "transport"
#define XQC_MAX_LOG_LINE   4096

#define LOGE(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

extern xqc_usec_t xqc_now(void);

/* ================= addr formatting ================= */
static void format_ip(const struct sockaddr *sa, char *out, size_t out_len)
{
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!sa) {
        return;
    }
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in4 = (const struct sockaddr_in *)sa;
        (void)inet_ntop(AF_INET, &in4->sin_addr, out, out_len);
#ifdef AF_INET6
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        (void)inet_ntop(AF_INET6, &in6->sin6_addr, out, out_len);
#endif
    } else {
        snprintf(out, out_len, "unknown");
    }
}

/* ================= ctx/conn/stream ================= */
typedef struct live_ctx_s   live_ctx_t;
typedef struct live_conn_s  live_conn_t;
typedef struct live_stream_s live_stream_t;

struct live_stream_s {
    xqc_stream_t  *stream;
    uint64_t       recv_bytes;
    xqc_usec_t     start_us;
    xqc_usec_t     first_byte_us;
    int            fin_recvd;
};

struct live_conn_s {
    live_ctx_t            *ctx;

    int                    fd;
    struct event          *ev_socket;

    struct sockaddr_storage peer_addr;
    socklen_t              peer_addrlen;

    struct sockaddr_storage local_addr;
    socklen_t              local_addrlen;

    xqc_cid_t              cid;
    xqc_connection_t      *quic_conn;

    live_stream_t         *stream;

    /* migration */
    int                    enable_migration;  /* -m */
    char                   ifname[64];        /* -i */
    int                    bind_dev;          /* SO_BINDTODEVICE */
    int                    mig_active;
    xqc_usec_t             mig_ts_start;
};

struct live_ctx_s {
    struct event_base     *eb;
    struct event          *ev_engine;
    xqc_engine_t          *engine;

    /* options */
    char                   server_addr[64];
    int                    server_port;
    char                   host[128];
    char                   uri[256];

    char                   log_level; /* e/d/i/w/s */
    char                   cong_ctl;  /* b/c/r */
    int                    write_stdout; /* -3 */

    int                    enable_migration; /* -m */
    char                   ifname[64];       /* -i */
    int                    allow_server_migration; /* -S: do not connect UDP */

    /* migration acceleration flags */
    int                    delay_challenge;   /* -D */
    int                    immediate_resend;  /* -2 */

    /* xquic logs */
    int                    log_fd;    /* -O */
    int                    qlog_fd;   /* -Q */
    int                    keylog_fd; /* -K */

    live_conn_t           *conn;
};

static live_ctx_t g_ctx;

/* ================= crash diagnostics ================= */
static void crash_handler(int sig, siginfo_t *si, void *unused)
{
    (void)unused;
    LOGE("[FATAL] signal=%d (%s) addr=%p errno=%d (%s)\n",
         sig, strsignal(sig),
         si ? si->si_addr : NULL,
         errno, strerror(errno));

#ifdef __linux__
    void *bt[64];
    int n = backtrace(bt, (int)(sizeof(bt)/sizeof(bt[0])));
    if (n > 0) {
        backtrace_symbols_fd(bt, n, fileno(stderr));
        LOGE("\n");
    }
#endif
    _Exit(128 + sig);
}

static void install_crash_handlers(void)
{
#ifndef XQC_SYS_WINDOWS
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS,  &sa, NULL);
#endif

    /* downstream (head/ffplay) may close pipe -> SIGPIPE; ignore and handle EPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif
}

/* ================= persistence helpers (default save/load) ================= */
static void make_path(char *dst, size_t dstlen, const char *prefix, const char *host, const char *suffix)
{
    if (!dst || dstlen == 0) return;
    const char *h = (host && host[0]) ? host : "unknown";
    snprintf(dst, dstlen, ".xquic_%s_%s%s", prefix, h, suffix ? suffix : "");
}

static int write_blob_file(const char *path, const void *data, size_t len)
{
    if (!path || !data || len == 0) return -1;
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
        LOGE("[live_client] write %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t wn = write(fd, data, len);
    if (wn != (ssize_t)len) {
        LOGE("[live_client] write %s short: %zd/%zu errno=%d(%s)\n", path, wn, len, errno, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    LOGE("[live_client] saved %zu bytes -> %s\n", len, path);
    return 0;
}

static int read_blob_file(const char *path, unsigned char **out, size_t *out_len)
{
    if (!path || !out || !out_len) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0) { close(fd); return -1; }
    (void)lseek(fd, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { close(fd); return -1; }
    ssize_t rn = read(fd, buf, (size_t)sz);
    close(fd);
    if (rn != sz) { free(buf); return -1; }
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

/* ================= xquic log callbacks ================= */
static void live_write_log_common(int fd, const void *buf, size_t count)
{
    if (!buf || count == 0) return;
    if (fd >= 0) {
        (void)write(fd, buf, count);
        if (((const char*)buf)[count - 1] != '\n') (void)write(fd, "\n", 1);
        return;
    }
    fwrite(buf, 1, count, stderr);
    if (((const char*)buf)[count - 1] != '\n') fputc('\n', stderr);
    fflush(stderr);
}

void live_xquic_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    (void)lvl;
    live_ctx_t *ctx = (live_ctx_t*)engine_user_data;
    int fd = (ctx && ctx->log_fd >= 0) ? ctx->log_fd : -1;
    live_write_log_common(fd, buf, count);
}

void live_xquic_write_qlog(qlog_event_importance_t importance, const void *buf, size_t count, void *engine_user_data)
{
    (void)importance;
    live_ctx_t *ctx = (live_ctx_t*)engine_user_data;
    int fd = (ctx && ctx->qlog_fd >= 0) ? ctx->qlog_fd : -1;
    /* qlog is typically JSON lines; still safe */
    live_write_log_common(fd, buf, count);
}

void live_keylog_cb(const xqc_cid_t *cid, const char *line, void *engine_user_data)
{
    (void)cid; (void)engine_user_data;
    live_ctx_t *ctx = &g_ctx;
    if (!line) return;
    if (ctx->keylog_fd >= 0) {
        (void)write(ctx->keylog_fd, line, strlen(line));
        (void)write(ctx->keylog_fd, "\n", 1);
        return;
    }
    /* default: also print to stderr (optional) */
    /* LOGE("[KEYLOG] %s\n", line); */
}

/* ================= engine timer ================= */
static void engine_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    live_ctx_t *ctx = (live_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
}

static void set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    live_ctx_t *ctx = (live_ctx_t *)user_data;
    struct timeval tv;
    tv.tv_sec  = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

/* ================= socket helpers ================= */
static int bind_to_interface(int fd, const char *ifname)
{
#ifdef __linux__
    if (ifname && ifname[0]) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
            LOGE("[live_client] SO_BINDTODEVICE(%s) failed: %s (may need sudo/cap_net_admin)\n",
                 ifname, strerror(errno));
            return -1;
        }
        LOGE("[live_client] bound to interface: %s\n", ifname);
    }
#else
    (void)fd; (void)ifname;
#endif
    return 0;
}

static int create_udp_socket_and_connect(live_conn_t *c)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("[live_client] socket() failed: %s\n", strerror(errno));
        return -1;
    }

#ifndef XQC_SYS_WINDOWS
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

    int size = 1 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));

#if !defined(__APPLE__)
    if (!c->ctx->allow_server_migration) {
        if (connect(fd, (struct sockaddr *)&c->peer_addr, c->peer_addrlen) < 0) {
            LOGE("[live_client] connect() failed: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
    }
#endif

#ifdef __linux__
    if (c->enable_migration && c->bind_dev) {
        (void)bind_to_interface(fd, c->ifname);
    }
#endif

    c->local_addrlen = sizeof(c->local_addr);
    if (getsockname(fd, (struct sockaddr *)&c->local_addr, &c->local_addrlen) != 0) {
        c->local_addrlen = 0;
    }

    c->fd = fd;
    return 0;
}

/* xquic send callback */
static ssize_t write_socket_cb(const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen, void *user_data)
{
    /* IMPORTANT: in xquic, the write_socket() user_data is the per-connection user_data
     * passed to xqc_connect()/xqc_server_accept(), NOT the engine user_data.
     */
    /* Use peer_addr/peer_addrlen to allow sending to new peer addresses
     * discovered during migration (server-side address change). */

    live_conn_t *c = (live_conn_t *)user_data;
    if (!c) {
        LOGE("[live_client] write_socket_cb: user_data(NULL conn)\n");
        set_sys_errno(EINVAL);
        return XQC_SOCKET_ERROR;
    }

    int fd = c->fd;
    if (fd < 0) {
        LOGE("[live_client] write_socket_cb: invalid fd=%d\n", fd);
        set_sys_errno(EINVAL);
        return XQC_SOCKET_ERROR;
    }

    ssize_t res;
    do {
        set_sys_errno(0);
        /* Prefer sendto so we can target the specific peer_addr provided
         * by the engine, even when the socket is connected. */
        if (peer_addr && peer_addrlen > 0) {
            res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        } else {
            res = send(fd, buf, size, 0);
        }
        if (res < 0) {
            int e = get_sys_errno();
            /* Treat transient routing/address errors during migration as retryable */
            if (e == EAGAIN || e == EWOULDBLOCK ||
                e == EADDRNOTAVAIL || e == ENETUNREACH ||
                e == EHOSTUNREACH || e == ENETDOWN) {
                return XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    return res;
}

static ssize_t write_socket_ex_cb(uint64_t path_id,
                                  const unsigned char *buf, size_t size,
                                  const struct sockaddr *peer_addr,
                                  socklen_t peer_addrlen, void *user_data)
{
    (void)path_id;
    return write_socket_cb(buf, size, peer_addr, peer_addrlen, user_data);
}

/* ================= required transport callbacks (session/tp) ================= */
static void save_session_cb(const char *data, size_t data_len, void *user_data)
{
    if (!data || data_len == 0) return;
    live_conn_t *c = (live_conn_t *)user_data;
    const char *host = c && c->ctx ? (c->ctx->host[0] ? c->ctx->host : c->ctx->server_addr) : "";
    char path[256];
    make_path(path, sizeof(path), "session", host, ".bin");
    (void)write_blob_file(path, data, data_len);
}

static void save_tp_cb(const char *tp_buf, size_t tp_len, void *user_data)
{
    if (!tp_buf || tp_len == 0) return;
    live_conn_t *c = (live_conn_t *)user_data;
    const char *host = c && c->ctx ? (c->ctx->host[0] ? c->ctx->host : c->ctx->server_addr) : "";
    char path[256];
    make_path(path, sizeof(path), "tp", host, ".bin");
    (void)write_blob_file(path, tp_buf, tp_len);
}

/* QUIC NEW_TOKEN frame -> required client callback */
static void save_token_cb(const unsigned char *token, uint32_t token_len, void *user_data)
{
    if (!token || token_len == 0) return;
    live_conn_t *c = (live_conn_t *)user_data;
    const char *host = c && c->ctx ? (c->ctx->host[0] ? c->ctx->host : c->ctx->server_addr) : "";
    char path[256];
    make_path(path, sizeof(path), "token", host, ".bin");
    (void)write_blob_file(path, token, token_len);
}

/* socket read -> engine */
static void socket_read_handler(live_conn_t *c)
{
    unsigned char packet[XQC_PACKET_TMP_BUF_LEN];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    for (;;) {
        ssize_t n = recvfrom(c->fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            int e = get_sys_errno();
            if (e == EAGAIN || e == EWOULDBLOCK) break;
            LOGE("[live_client] recvfrom error: %s\n", strerror(e));
            break;
        }

        xqc_usec_t recv_time = xqc_now();
        const struct sockaddr *local_addr = (c->local_addrlen > 0)
            ? (const struct sockaddr *)&c->local_addr : NULL;
        socklen_t local_len = (c->local_addrlen > 0) ? c->local_addrlen : 0;

        (void)xqc_engine_packet_process(g_ctx.engine,
                                        packet, (size_t)n,
                                        local_addr, local_len,
                                        (const struct sockaddr *)&peer, peer_len,
                                        recv_time, NULL);
    }

    xqc_engine_finish_recv(g_ctx.engine);
}

static void socket_event_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    live_conn_t *c = (live_conn_t *)arg;
    if (what & EV_READ) {
        socket_read_handler(c);
    }
}

/* ================= migration handling ================= */
static int recreate_socket_for_migration(live_conn_t *c)
{
    live_ctx_t *ctx = c->ctx;
    char old_ip[64] = "";
    char peer_ip[64] = "";
    if (c->local_addrlen > 0) {
        format_ip((const struct sockaddr *)&c->local_addr, old_ip, sizeof(old_ip));
    }
    if (c->peer_addrlen > 0) {
        format_ip((const struct sockaddr *)&c->peer_addr, peer_ip, sizeof(peer_ip));
    }

    if (c->ev_socket) {
        event_del(c->ev_socket);
        event_free(c->ev_socket);
        c->ev_socket = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }

    if (create_udp_socket_and_connect(c) != 0) {
        LOGE("[live_client] recreate socket failed\n");
        return -1;
    }

    c->ev_socket = event_new(ctx->eb, c->fd, EV_READ | EV_PERSIST, socket_event_cb, c);
    event_add(c->ev_socket, NULL);

    c->mig_active = 1;
    c->mig_ts_start = xqc_now();
    {
        char new_ip[64] = "";
        if (c->local_addrlen > 0) {
            format_ip((const struct sockaddr *)&c->local_addr, new_ip, sizeof(new_ip));
        }
        LOGE("[live_client] IP change: local %s -> %s, peer=%s, if=%s (fd=%d)\n",
             old_ip[0] ? old_ip : "-",
             new_ip[0] ? new_ip : "-",
             peer_ip[0] ? peer_ip : "-",
             c->ifname,
             c->fd);
        LOGE("[live_client] IP change -> new fd=%d, trigger ping + continue_send\n", c->fd);
    }
    /* Send a small burst of pings to speed up PATH validation.
       This helps if initial packets are lost due to ARP/ND warm-up. */
    for (int i = 0; i < 3; i++) {
        xqc_conn_send_ping(ctx->engine, &c->cid, NULL);
        xqc_conn_continue_send(ctx->engine, &c->cid);
    }

    return 0;
}

#ifdef __linux__
static int on_ip_change(void *arg)
{
    live_conn_t *c = (live_conn_t *)arg;
    return recreate_socket_for_migration(c);
}
#endif

/* ================= app(proto) callbacks for ALPN=transport ================= */
static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                              void *user_data, void *conn_proto_data)
{
    (void)cid; (void)conn_proto_data;
    live_conn_t *c = (live_conn_t *)user_data;
    c->quic_conn = conn;
    xqc_conn_set_alp_user_data(conn, c);
    LOGE("[live_client] conn_create\n");
    return 0;
}

static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                             void *user_data, void *conn_proto_data)
{
    (void)conn; (void)cid; (void)conn_proto_data;
    live_conn_t *c = (live_conn_t *)user_data;
    LOGE("[live_client] conn_close\n");
    if (c && c->ctx && c->ctx->eb) {
        event_base_loopbreak(c->ctx->eb);
    }
    return 0;
}

static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *conn_proto_data)
{
    (void)conn_proto_data;
    live_conn_t *c = (live_conn_t *)user_data;
    LOGE("[live_client] handshake finished\n");

    if (!c->stream) {
        live_stream_t *s = calloc(1, sizeof(*s));
        if (!s) return;

        s->start_us = xqc_now();
        xqc_stream_t *stream = xqc_stream_create_with_direction(conn, XQC_STREAM_BIDI, s);
        if (!stream) {
            LOGE("[live_client] stream_create_with_direction failed\n");
            free(s);
            return;
        }
        s->stream = stream;
        c->stream = s;

        /* use -u as a tag to keep CLI compatibility */
        char req[512];
        snprintf(req, sizeof(req), "START %s\n", c->ctx->uri);

        ssize_t n = xqc_stream_send(stream, req, strlen(req), 1 /*fin*/);
        if (n < 0) {
            LOGE("[live_client] stream_send START failed: %zd\n", n);
        } else {
            LOGE("[live_client] sent request: %s", req);
        }

        xqc_conn_continue_send(c->ctx->engine, &c->cid);
    }
}

static int stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    (void)stream; (void)user_data;
    return 0;
}

static int stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    unsigned char fin = 0;
    live_stream_t *s = (live_stream_t *)user_data;
    if (!s) return 0;

    uint8_t buf[64 * 1024];
    for (;;) {
        ssize_t n = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (n == -XQC_EAGAIN) break;
        if (n < 0) {
            LOGE("[live_client] stream_recv error: %zd\n", n);
            break;
        }
        if (n == 0) break;

        if (!s->first_byte_us) {
            s->first_byte_us = xqc_now();
            LOGE("[live_client] first byte in %"PRIu64" us\n",
                 (uint64_t)(s->first_byte_us - s->start_us));
        }

        s->recv_bytes += (uint64_t)n;

        if (g_ctx.write_stdout) {
            size_t wn = fwrite(buf, 1, (size_t)n, stdout);
            if (wn != (size_t)n) {
                LOGE("[live_client] fwrite failed: wn=%zu n=%zd errno=%d (%s)\n",
                     wn, n, errno, strerror(errno));
                if (g_ctx.eb) event_base_loopbreak(g_ctx.eb);
                break;
            }
        }

        if (g_ctx.conn && g_ctx.conn->mig_active) {
            xqc_usec_t now = xqc_now();
            LOGE("[live_client] first byte after migration in %"PRIu64" us\n",
                 (uint64_t)(now - g_ctx.conn->mig_ts_start));
            g_ctx.conn->mig_active = 0;
        }
    }

    if (fin) {
        s->fin_recvd = 1;
        LOGE("[live_client] fin received, total=%"PRIu64"\n", s->recv_bytes);
        xqc_stream_close(stream);
    }
    return 0;
}

static int stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    (void)stream;
    live_stream_t *s = (live_stream_t *)user_data;
    if (s) free(s);
    if (g_ctx.eb) event_base_loopbreak(g_ctx.eb);
    return 0;
}

/* ================= signal ================= */
static void stop_handler(int sig)
{
    (void)sig;
    if (g_ctx.eb) event_base_loopbreak(g_ctx.eb);
}

/* ================= usage ================= */
static void usage(const char *prog)
{
    LOGE("Usage: %s [Options]\n"
         "  -a <addr>   server addr (default 127.0.0.1)\n"
         "  -p <port>   server port (default 8443)\n"
         "  -h <host>   SNI/host (default = server addr)\n"
         "  -u <uri>    keep for compatibility (default /live)\n"
         "  -3          write received bytes to stdout\n"
         "  -l <lvl>    log level e/d/i/w/s (default e)\n"
         "  -c <algo>   cc: b=bbr(default), c=cubic, r=reno\n"
         "  -m          enable migration (Linux netlink)\n"
         "  -i <ifname> interface for migration + bind socket to device\n"
         "  -S          allow server IP migration (skip UDP connect)\n"
         "  -D          delay PATH_CHALLENGE validation (optimistic switch)\n"
         "  -2          immediate resend of unacked data after migration\n"
         "  -O <file>   xquic log file (default stderr)\n"
         "  -Q <file>   qlog file (optional)\n"
         "  -K <file>   TLS keylog file (optional)\n",
         prog);
}

int main(int argc, char **argv)
{
    memset(&g_ctx, 0, sizeof(g_ctx));
    snprintf(g_ctx.server_addr, sizeof(g_ctx.server_addr), "%s", "127.0.0.1");
    g_ctx.server_port = 8443;
    snprintf(g_ctx.uri, sizeof(g_ctx.uri), "%s", "/live");
    g_ctx.log_level = 'e';
    g_ctx.cong_ctl  = 'b';
    g_ctx.write_stdout = 0;

    g_ctx.log_fd = -1;
    g_ctx.qlog_fd = -1;
    g_ctx.keylog_fd = -1;

    int ch;
    while ((ch = getopt(argc, argv, "a:p:h:u:3l:c:mi:SD2O:Q:K:")) != -1) {
        switch (ch) {
            case 'a': snprintf(g_ctx.server_addr, sizeof(g_ctx.server_addr), "%s", optarg); break;
            case 'p': g_ctx.server_port = atoi(optarg); break;
            case 'h': snprintf(g_ctx.host, sizeof(g_ctx.host), "%s", optarg); break;
            case 'u': snprintf(g_ctx.uri, sizeof(g_ctx.uri), "%s", optarg); break;
            case '3': g_ctx.write_stdout = 1; break;
            case 'l': g_ctx.log_level = optarg[0]; break;
            case 'c': g_ctx.cong_ctl  = optarg[0]; break;
            case 'm': g_ctx.enable_migration = 1; break;
            case 'i': snprintf(g_ctx.ifname, sizeof(g_ctx.ifname), "%s", optarg); break;
            case 'S': g_ctx.allow_server_migration = 1; break;
            case 'D': g_ctx.delay_challenge = 1; break;
            case '2': g_ctx.immediate_resend = 1; break;
            case 'O': g_ctx.log_fd = open(optarg, O_WRONLY|O_CREAT|O_APPEND, 0644); break;
            case 'Q': g_ctx.qlog_fd = open(optarg, O_WRONLY|O_CREAT|O_APPEND, 0644); break;
            case 'K': g_ctx.keylog_fd = open(optarg, O_WRONLY|O_CREAT|O_APPEND, 0644); break;
            default: usage(argv[0]); return 0;
        }
    }
    if (!g_ctx.host[0]) snprintf(g_ctx.host, sizeof(g_ctx.host), "%s", g_ctx.server_addr);

    xqc_platform_init_env();

    /* keep stdout/stderr unbuffered for pipe & crash logs */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    install_crash_handlers();

#ifndef XQC_SYS_WINDOWS
    signal(SIGINT,  stop_handler);
    signal(SIGTERM, stop_handler);
#endif

    /* resolve server addr (IPv4 only) */
    struct sockaddr_in peer4;
    memset(&peer4, 0, sizeof(peer4));
    peer4.sin_family = AF_INET;
    peer4.sin_port   = htons((uint16_t)g_ctx.server_port);
    if (inet_pton(AF_INET, g_ctx.server_addr, &peer4.sin_addr) != 1) {
        LOGE("[live_client] invalid server addr: %s\n", g_ctx.server_addr);
        return -1;
    }

    g_ctx.eb = event_base_new();
    if (!g_ctx.eb) {
        LOGE("[live_client] event_base_new failed\n");
        return -1;
    }
    g_ctx.ev_engine = event_new(g_ctx.eb, -1, 0, engine_timer_cb, &g_ctx);

    live_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->ctx = &g_ctx;
    c->fd = -1;
    memcpy(&c->peer_addr, &peer4, sizeof(peer4));
    c->peer_addrlen = sizeof(peer4);

    c->enable_migration = g_ctx.enable_migration;
    snprintf(c->ifname, sizeof(c->ifname), "%s", g_ctx.ifname);
    c->bind_dev = (g_ctx.enable_migration && g_ctx.ifname[0]) ? 1 : 0;

    g_ctx.conn = c;

    if (create_udp_socket_and_connect(c) != 0) return -1;
    c->ev_socket = event_new(g_ctx.eb, c->fd, EV_READ | EV_PERSIST, socket_event_cb, c);
    event_add(c->ev_socket, NULL);

    /* engine config */
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        LOGE("[live_client] get_default_config failed\n");
        return -1;
    }
    switch (g_ctx.log_level) {
        case 'e': config.cfg_log_level = XQC_LOG_ERROR; break;
        case 'i': config.cfg_log_level = XQC_LOG_INFO;  break;
        case 'w': config.cfg_log_level = XQC_LOG_WARN;  break;
        case 's': config.cfg_log_level = XQC_LOG_STATS; break;
        case 'd':
        default:  config.cfg_log_level = XQC_LOG_DEBUG; break;
    }

    /* migration acceleration flags from server tests: delay_challenge & immediate_resend */
    config.delay_challenge = g_ctx.delay_challenge ? 1 : 0;
    config.immediate_resend = g_ctx.immediate_resend ? 1 : 0;

    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
    engine_ssl.ciphers = XQC_TLS_CIPHERS;
    engine_ssl.groups  = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cb = {
        .set_event_timer = set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = live_xquic_write_log,
            .xqc_log_write_stat = live_xquic_write_log,
            .xqc_qlog_event_write = live_xquic_write_qlog,
        },
        .keylog_cb = live_keylog_cb,
    };

    xqc_transport_callbacks_t tcbs;
    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.write_socket = write_socket_cb;
    tcbs.write_socket_ex = write_socket_ex_cb;
    tcbs.save_token = save_token_cb;
    tcbs.save_session_cb = save_session_cb;
    tcbs.save_tp_cb = save_tp_cb;

    g_ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &engine_ssl, &engine_cb, &tcbs, &g_ctx);
    if (!g_ctx.engine) {
        LOGE("[live_client] xqc_engine_create failed\n");
        return -1;
    }

    /* conn settings */
    xqc_cong_ctrl_callback_t cc = xqc_bbr_cb;
#ifdef XQC_ENABLE_RENO
    if (g_ctx.cong_ctl == 'r') cc = xqc_reno_cb;
#endif
    if (g_ctx.cong_ctl == 'c') cc = xqc_cubic_cb;

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.pacing_on = 0;
    /* Enable periodic client ping to help keep the path validated */
    conn_settings.ping_on = 1;
    conn_settings.cong_ctrl_callback = cc;
    conn_settings.cc_params.customize_on = 0;

    /* ACK behavior tuning: reduce delay and increase frequency to avoid cwnd stall on migration */
    conn_settings.max_ack_delay = 5;           /* ms: send ACK quickly after receiving */
    conn_settings.ack_frequency = 1;           /* ACK every ack-eliciting packet */
    conn_settings.adaptive_ack_frequency = 1;  /* allow runtime adjustment */

    /* Allow active migration by clearing disable_active_migration via multipath. */
    conn_settings.enable_multipath = 1;
    conn_settings.init_max_path_id = 2;
    /* Proactive multipath pinging for quicker validation after IP change. */
    conn_settings.mp_ping_on = 1;
    /* Permit ACKs to be sent on any available path, not only the receive path. */
    conn_settings.mp_ack_on_any_path = 1;

    /* register ALPN=transport callbacks */
    xqc_app_proto_callbacks_t ap_cbs;
    memset(&ap_cbs, 0, sizeof(ap_cbs));
    ap_cbs.conn_cbs.conn_create_notify = conn_create_notify;
    ap_cbs.conn_cbs.conn_close_notify  = conn_close_notify;
    ap_cbs.conn_cbs.conn_handshake_finished = conn_handshake_finished;

    ap_cbs.stream_cbs.stream_write_notify = stream_write_notify;
    ap_cbs.stream_cbs.stream_read_notify  = stream_read_notify;
    ap_cbs.stream_cbs.stream_close_notify = stream_close_notify;

    xqc_engine_register_alpn(g_ctx.engine, XQC_ALPN_TRANSPORT, strlen(XQC_ALPN_TRANSPORT), &ap_cbs, NULL);

    /* connect */
    xqc_conn_ssl_config_t conn_ssl;
    memset(&conn_ssl, 0, sizeof(conn_ssl));
    conn_ssl.cert_verify_flag = 0;

    /* default: load persisted artifacts for resumption/0-RTT */
    unsigned char *saved_token = NULL; size_t saved_token_len = 0;
    unsigned char *saved_sess = NULL;  size_t saved_sess_len = 0;
    unsigned char *saved_tp = NULL;    size_t saved_tp_len = 0;
    {
        char path[256];
        const char *host = g_ctx.host[0] ? g_ctx.host : g_ctx.server_addr;
        make_path(path, sizeof(path), "token", host, ".bin");
        (void)read_blob_file(path, &saved_token, &saved_token_len);
        make_path(path, sizeof(path), "session", host, ".bin");
        if (read_blob_file(path, &saved_sess, &saved_sess_len) == 0) {
            conn_ssl.session_ticket_data = (char *)saved_sess;
            conn_ssl.session_ticket_len  = saved_sess_len;
        }
        make_path(path, sizeof(path), "tp", host, ".bin");
        if (read_blob_file(path, &saved_tp, &saved_tp_len) == 0) {
            conn_ssl.transport_parameter_data    = (char *)saved_tp;
            conn_ssl.transport_parameter_data_len = saved_tp_len;
        }
    }

    const xqc_cid_t *cid = xqc_connect(g_ctx.engine, &conn_settings,
                                       saved_token, (unsigned)saved_token_len,
                                       g_ctx.host,       /* SNI */
                                       0,                /* no_crypt */
                                       &conn_ssl,
                                       (struct sockaddr *)&c->peer_addr, c->peer_addrlen,
                                       XQC_ALPN_TRANSPORT,
                                       c);
    if (!cid) {
        LOGE("[live_client] xqc_connect(transport) failed\n");
        return -1;
    }
    memcpy(&c->cid, cid, sizeof(*cid));

#ifdef __linux__
    if (g_ctx.enable_migration) {
        if (!g_ctx.ifname[0]) {
            LOGE("[live_client] -m requires -i <ifname>\n");
        } else {
            register_netlink_event(g_ctx.eb, on_ip_change, c, g_ctx.ifname);
            LOGE("[live_client] migration enabled on ifname=%s\n", g_ctx.ifname);
        }
    }
#endif

    LOGE("[live_client] start: server=%s:%d alpn=%s uri=%s stdout=%d mig=%d if=%s\n",
         g_ctx.server_addr, g_ctx.server_port, XQC_ALPN_TRANSPORT, g_ctx.uri,
         g_ctx.write_stdout, g_ctx.enable_migration, g_ctx.ifname);

    event_base_dispatch(g_ctx.eb);

    /* cleanup */
    if (c->ev_socket) { event_del(c->ev_socket); event_free(c->ev_socket); }
    if (c->fd >= 0) close(c->fd);

    /* destroy QUIC engine before freeing connection user_data to avoid UAF in callbacks */
    if (g_ctx.engine) { xqc_engine_destroy(g_ctx.engine); g_ctx.engine = NULL; }

    free(c);
    g_ctx.conn = NULL;
    if (g_ctx.ev_engine) { event_free(g_ctx.ev_engine); g_ctx.ev_engine = NULL; }
    if (g_ctx.eb) { event_base_free(g_ctx.eb); g_ctx.eb = NULL; }

    free(saved_token);
    free(saved_sess);
    free(saved_tp);

    if (g_ctx.log_fd >= 0) close(g_ctx.log_fd);
    if (g_ctx.qlog_fd >= 0) close(g_ctx.qlog_fd);
    if (g_ctx.keylog_fd >= 0) close(g_ctx.keylog_fd);

    return 0;
}
