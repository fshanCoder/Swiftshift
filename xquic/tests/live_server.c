/**
 * live_server_transport_full.c
 *
 * QUIC Transport(ALPN="transport") live server (reliable stream) with:
 *  - register ALPN=transport and stream callbacks
 *  - when first bidi stream created, start pumping stdin to stream (-z)
 *  - xqc_log(...) / qlog output support (to stderr or files)
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
#include "platform.h"

/* access stream internal stats (tests may include internal headers) */
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"

#ifdef __linux__
#include <execinfo.h>
#endif

#ifndef XQC_PACKET_TMP_BUF_LEN
#define XQC_PACKET_TMP_BUF_LEN 1500
#endif

#define XQC_ALPN_TRANSPORT "transport"
#define LOGE(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)

extern xqc_usec_t xqc_now(void);

typedef struct srv_ctx_s    srv_ctx_t;
typedef struct srv_conn_s   srv_conn_t;
typedef struct srv_stream_s srv_stream_t;

struct srv_stream_s {
    xqc_stream_t *stream;
    uint8_t      *pending;
    size_t        pending_len;
    size_t        pending_off;
    int           stdin_eof;
};

struct srv_conn_s {
    srv_ctx_t        *ctx;
    xqc_connection_t *conn;
    xqc_cid_t         cid;
};

struct srv_ctx_s {
    struct event_base *eb;
    struct event      *ev_engine;
    struct event      *ev_socket;
    struct event      *ev_stdin_tick;

    xqc_engine_t      *engine;
    int                fd;

    char               listen_addr[64];
    int                listen_port;
    char               log_level;
    char               cong_ctl;
    int                stdin_mode; /* -z */
    int                delay_challenge;   /* -D: delay PATH_CHALLENGE validation */
    int                immediate_resend;  /* -2: immediate resend after migration */
    int                force_stream_high_pri; /* -H: set transport stream HIGH priority */

    /* xquic logs */
    int                log_fd;  /* -O */
    int                qlog_fd; /* -Q */

    srv_stream_t      *live_stream;

    struct event      *ev_pri_reset;
    uint32_t           last_rebind_count;
    int                pri_boost_active;
};

static srv_ctx_t g_sctx;

/* crash handler */
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
    if (n > 0) backtrace_symbols_fd(bt, n, fileno(stderr));
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
#endif
}

/* xquic log callbacks */
static void write_log_common(int fd, const void *buf, size_t count)
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

void srv_xquic_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data)
{
    (void)lvl;
    srv_ctx_t *ctx = (srv_ctx_t*)engine_user_data;
    int fd = (ctx && ctx->log_fd >= 0) ? ctx->log_fd : -1;
    write_log_common(fd, buf, count);
}

void srv_xquic_write_qlog(qlog_event_importance_t imp, const void *buf, size_t count, void *engine_user_data)
{
    (void)imp;
    srv_ctx_t *ctx = (srv_ctx_t*)engine_user_data;
    int fd = (ctx && ctx->qlog_fd >= 0) ? ctx->qlog_fd : -1;
    write_log_common(fd, buf, count);
}

/* engine timer */
static void engine_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    srv_ctx_t *ctx = (srv_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
}

static void set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    srv_ctx_t *ctx = (srv_ctx_t *)user_data;
    struct timeval tv;
    tv.tv_sec  = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

/* UDP socket */
static int create_udp_socket(const char *ip, int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("[live_server] socket() failed: %s\n", strerror(errno));
        return -1;
    }

#ifndef XQC_SYS_WINDOWS
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

    int size = 1 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        LOGE("[live_server] invalid listen addr: %s\n", ip);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOGE("[live_server] bind(%s:%d) failed: %s\n", ip, port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t write_socket_cb(const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr,
                               socklen_t peer_addrlen, void *user_data)
{
    /* On server side, xquic may call write_socket with user_data=NULL for some control packets.
     * We use the global server socket fd (single-socket server), like tests/test_server.c.
     */
    (void)user_data;

    if (g_sctx.fd < 0) {
        set_sys_errno(EINVAL);
        return XQC_SOCKET_ERROR;
    }

    ssize_t res;
    do {
        set_sys_errno(0);
        res = sendto(g_sctx.fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            int e = get_sys_errno();
            if (e == EAGAIN || e == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
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

static void socket_read_handler(srv_ctx_t *ctx)
{
    unsigned char packet[XQC_PACKET_TMP_BUF_LEN];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    for (;;) {
        ssize_t n = recvfrom(ctx->fd, packet, sizeof(packet), 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            int e = get_sys_errno();
            if (e == EAGAIN || e == EWOULDBLOCK) break;
            LOGE("[live_server] recvfrom error: %s\n", strerror(e));
            break;
        }

        xqc_usec_t recv_time = xqc_now();
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons((uint16_t)ctx->listen_port);
        (void)inet_pton(AF_INET, ctx->listen_addr, &local_addr.sin_addr);
        socklen_t local_len = sizeof(local_addr);

        (void)xqc_engine_packet_process(ctx->engine,
                                        packet, (size_t)n,
                                        (const struct sockaddr *)&local_addr, local_len,
                                        (const struct sockaddr *)&peer, peer_len,
                                        recv_time, NULL);
    }

    xqc_engine_finish_recv(ctx->engine);
}

static void socket_event_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    srv_ctx_t *ctx = (srv_ctx_t *)arg;
    if (what & EV_READ) socket_read_handler(ctx);
}

/* accept/refuse */
static int server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                         const xqc_cid_t *cid, void *user_data)
{
    (void)engine; (void)user_data;
    srv_conn_t *uc = calloc(1, sizeof(*uc));
    if (!uc) return -1;
    uc->ctx = &g_sctx;
    uc->conn = conn;
    memcpy(&uc->cid, cid, sizeof(*cid));
    xqc_conn_set_transport_user_data(conn, uc);
    return 0;
}

static void server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
                          const xqc_cid_t *cid, void *user_data)
{
    (void)engine; (void)conn; (void)cid;
    srv_conn_t *uc = (srv_conn_t *)user_data;
    if (uc) free(uc);
}

/* stream send helper */
static void try_send(srv_ctx_t *ctx)
{
    srv_stream_t *ls = ctx->live_stream;
    if (!ls || !ls->stream) return;

    while (ls->pending && ls->pending_off < ls->pending_len) {
        size_t left = ls->pending_len - ls->pending_off;
        ssize_t n = xqc_stream_send(ls->stream, ls->pending + ls->pending_off, left, 0);
        if (n == -XQC_EAGAIN) return;
        if (n < 0) { LOGE("[live_server] stream_send error: %zd\n", n); return; }
        ls->pending_off += (size_t)n;
    }
    if (ls->pending && ls->pending_off >= ls->pending_len) {
        free(ls->pending);
        ls->pending = NULL;
        ls->pending_len = ls->pending_off = 0;
    }

    if (ls->stdin_eof) {
        (void)xqc_stream_send(ls->stream, NULL, 0, 1);
        return;
    }
    if (!ctx->stdin_mode) return;

#ifndef XQC_SYS_WINDOWS
    uint8_t buf[16 * 1024];
    ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));
    if (r == 0) {
        ls->stdin_eof = 1;
        (void)xqc_stream_send(ls->stream, NULL, 0, 1);
        return;
    }
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        LOGE("[live_server] read(stdin) error: %s\n", strerror(errno));
        return;
    }

    ssize_t n = xqc_stream_send(ls->stream, buf, (size_t)r, 0);
    if (n == -XQC_EAGAIN) {
        ls->pending = malloc((size_t)r);
        if (!ls->pending) return;
        memcpy(ls->pending, buf, (size_t)r);
        ls->pending_len = (size_t)r;
        ls->pending_off = 0;
        return;
    }
    if (n < 0) { LOGE("[live_server] stream_send error: %zd\n", n); return; }
    if ((size_t)n < (size_t)r) {
        size_t remain = (size_t)r - (size_t)n;
        ls->pending = malloc(remain);
        if (!ls->pending) return;
        memcpy(ls->pending, buf + n, remain);
        ls->pending_len = remain;
        ls->pending_off = 0;
        return;
    }
#endif
}

/* reset stream priority after temporary boost */
static void pri_reset_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    srv_ctx_t *ctx = (srv_ctx_t *)arg;
    if (ctx->live_stream && ctx->live_stream->stream) {
        xqc_stream_set_priority(ctx->live_stream->stream, XQC_STREAM_PRI_NORMAL);
        LOGE("[live_server] stream priority reset to NORMAL\n");
    }
    ctx->pri_boost_active = 0;
}

/* periodic stdin tick */
static void stdin_tick_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    srv_ctx_t *ctx = (srv_ctx_t *)arg;
    if (ctx->force_stream_high_pri && ctx->live_stream && ctx->live_stream->stream) {
        srv_conn_t *uc = (srv_conn_t *)xqc_get_conn_user_data_by_stream(ctx->live_stream->stream);
        if (uc) {
            xqc_conn_stats_t st = xqc_conn_get_stats(ctx->engine, &uc->cid);
            if (st.total_rebind_count > ctx->last_rebind_count) {
                ctx->last_rebind_count = st.total_rebind_count;
                xqc_usec_t pto = xqc_conn_get_max_pto(uc->conn);
                xqc_usec_t delay = 3 * xqc_max(pto, 20000);

                xqc_stream_set_priority(ctx->live_stream->stream, XQC_STREAM_PRI_HIGH);
                ctx->pri_boost_active = 1;
                LOGE("[live_server] migration detected, boost stream priority for %" PRIu64 "us\n", delay);

                if (!ctx->ev_pri_reset) {
                    ctx->ev_pri_reset = evtimer_new(ctx->eb, pri_reset_cb, ctx);
                }

                if (ctx->ev_pri_reset) {
                    struct timeval tv = { .tv_sec = delay / 1000000, .tv_usec = delay % 1000000 };
                    evtimer_add(ctx->ev_pri_reset, &tv);
                }
            }
        }
    }
    try_send(ctx);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 2000 };
    evtimer_add(ctx->ev_stdin_tick, &tv);
}

/* app callbacks */
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
                             void *user_data, void *conn_proto_data)
{
    (void)conn; (void)cid; (void)conn_proto_data;
    srv_conn_t *uc = (srv_conn_t *)user_data;
    if (uc) free(uc);
    return 0;
}

static int stream_create_notify(xqc_stream_t *stream, void *user_data)
{
    (void)user_data;
    if (g_sctx.live_stream) {
        xqc_stream_close(stream);
        return 0;
    }

    srv_stream_t *ls = calloc(1, sizeof(*ls));
    if (!ls) return -1;

    ls->stream = stream;
    xqc_stream_set_user_data(stream, ls);
    if (g_sctx.force_stream_high_pri) {
        xqc_stream_set_priority(stream, XQC_STREAM_PRI_NORMAL);
        LOGE("[live_server] enable temp HIGH priority on migration (3*PTO)\n");
        srv_conn_t *uc = (srv_conn_t *)xqc_get_conn_user_data_by_stream(stream);
        if (uc) {
            xqc_conn_stats_t st = xqc_conn_get_stats(g_sctx.engine, &uc->cid);
            g_sctx.last_rebind_count = st.total_rebind_count;
        }
    } else {
        xqc_stream_set_priority(stream, XQC_STREAM_PRI_NORMAL);
        LOGE("[live_server] set stream priority: NORMAL\n");
    }
    g_sctx.live_stream = ls;

    LOGE("[live_server] stream created, start pumping stdin\n");

#ifndef XQC_SYS_WINDOWS
    if (g_sctx.stdin_mode) {
        int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0) (void)fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    if (!g_sctx.ev_stdin_tick) {
        g_sctx.ev_stdin_tick = evtimer_new(g_sctx.eb, stdin_tick_cb, &g_sctx);
    }
    struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
    evtimer_add(g_sctx.ev_stdin_tick, &tv);

    return 0;
}

static int stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    (void)stream; (void)user_data;
    try_send(&g_sctx);
    return 0;
}

static int stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    (void)user_data;
    /* drain client's START request */
    unsigned char fin = 0;
    char buf[1024];
    for (;;) {
        ssize_t n = xqc_stream_recv(stream, buf, sizeof(buf), &fin);
        if (n == -XQC_EAGAIN) break;
        if (n <= 0) break;
    }
    return 0;
}

static int stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    srv_stream_t *ls = (srv_stream_t *)user_data;
    /* print total_rebind_count when stream finishes */
    do {
        srv_conn_t *uc = (srv_conn_t *)xqc_get_conn_user_data_by_stream(stream);
        if (uc) {
            xqc_conn_stats_t st = xqc_conn_get_stats(g_sctx.engine, &uc->cid);
            LOGE("[live_server] total_rebind_count=%u total_rebind_valid=%u\n",
                 st.total_rebind_count, st.total_rebind_valid);
        }
    } while (0);
    /* print retransmission stats for this stream */
    do {
        if (stream) {
            LOGE("[live_server] retrans_pkt_cnt=%u sent_pkt_cnt=%u\n",
                 stream->stream_stats.retrans_pkt_cnt,
                 stream->stream_stats.sent_pkt_cnt);
        }
    } while (0);
    if (ls) {
        if (ls->pending) free(ls->pending);
        free(ls);
    }
    g_sctx.live_stream = NULL;
    return 0;
}

/* signal */
static void stop_handler(int sig)
{
    (void)sig;
    if (g_sctx.eb) event_base_loopbreak(g_sctx.eb);
}

static void usage(const char *prog)
{
    LOGE("Usage: %s [Options]\n"
         "  -a <addr>   listen addr (default 0.0.0.0)\n"
         "  -p <port>   listen port (default 8443)\n"
         "  -z          read stdin and stream to client\n"
         "  -D          delay path validation (non-blocking auth)\n"
         "  -2          immediate resend after migration\n"
         "  -H          temp HIGH priority for 3*PTO after migration\n"
         "  -l <lvl>    log level e/d/i/w/s (default e)\n"
         "  -c <algo>   cc: b=bbr(default), c=cubic, r=reno\n"
         "  -O <file>   xquic log file (default stderr)\n"
         "  -Q <file>   qlog file (optional)\n",
         prog);
}

 int
 read_file_data( char * data, size_t data_len, char *filename)
 {
     int ret = 0;
     size_t total_len, read_len;
     FILE *fp = fopen(filename, "rb");
     if (fp == NULL) {
         ret = -1;
         goto end;
     }
 
     fseek(fp, 0, SEEK_END);
     total_len = ftell(fp);
     fseek(fp, 0, SEEK_SET);
     if (total_len > data_len) {
         ret = -1;
         goto end;
     }
 
     read_len = fread(data, 1, total_len, fp);
     if (read_len != total_len) {
         ret = -1;
         goto end;
     }
 
     ret = read_len;
 
 end:
     if (fp) {
         fclose(fp);
     }
     return ret;
 
 }

int main(int argc, char **argv)
{
    memset(&g_sctx, 0, sizeof(g_sctx));
    snprintf(g_sctx.listen_addr, sizeof(g_sctx.listen_addr), "%s", "0.0.0.0");
    g_sctx.listen_port = 8443;
    g_sctx.log_level = 'e';
    g_sctx.cong_ctl  = 'b';
    g_sctx.stdin_mode = 0;
    g_sctx.delay_challenge = 0;
    g_sctx.immediate_resend = 0;
    g_sctx.force_stream_high_pri = 0;
    g_sctx.fd = -1;
    g_sctx.log_fd = -1;
    g_sctx.qlog_fd = -1;

    int ch;
    while ((ch = getopt(argc, argv, "a:p:zl:c:O:Q:D2H")) != -1) {
        switch (ch) {
            case 'a': snprintf(g_sctx.listen_addr, sizeof(g_sctx.listen_addr), "%s", optarg); break;
            case 'p': g_sctx.listen_port = atoi(optarg); break;
            case 'z': g_sctx.stdin_mode = 1; break;
            case 'D': g_sctx.delay_challenge = 1; break;
            case '2': g_sctx.immediate_resend = 1; break;
            case 'H': g_sctx.force_stream_high_pri = 1; break;
            case 'l': g_sctx.log_level = optarg[0]; break;
            case 'c': g_sctx.cong_ctl  = optarg[0]; break;
            case 'O': g_sctx.log_fd = open(optarg, O_WRONLY|O_CREAT|O_APPEND, 0644); break;
            case 'Q': g_sctx.qlog_fd = open(optarg, O_WRONLY|O_CREAT|O_APPEND, 0644); break;
            default: usage(argv[0]); return 0;
        }
    }

    xqc_platform_init_env();
    setvbuf(stderr, NULL, _IONBF, 0);
    install_crash_handlers();

#ifndef XQC_SYS_WINDOWS
    signal(SIGINT,  stop_handler);
    signal(SIGTERM, stop_handler);
#endif

    g_sctx.eb = event_base_new();
    if (!g_sctx.eb) { LOGE("[live_server] event_base_new failed\n"); return -1; }
    g_sctx.ev_engine = event_new(g_sctx.eb, -1, 0, engine_timer_cb, &g_sctx);

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        LOGE("[live_server] get_default_config failed\n");
        return -1;
    }
    /* migration acceleration flags from test_server: delay_challenge & immediate_resend */
    config.delay_challenge = g_sctx.delay_challenge ? 1 : 0;
    config.immediate_resend = g_sctx.immediate_resend ? 1 : 0;
    switch (g_sctx.log_level) {
        case 'e': config.cfg_log_level = XQC_LOG_ERROR; break;
        case 'i': config.cfg_log_level = XQC_LOG_INFO;  break;
        case 'w': config.cfg_log_level = XQC_LOG_WARN;  break;
        case 's': config.cfg_log_level = XQC_LOG_STATS; break;
        case 'd':
        default:  config.cfg_log_level = XQC_LOG_DEBUG; break;
    }

    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
    engine_ssl.ciphers = XQC_TLS_CIPHERS;
    engine_ssl.groups  = XQC_TLS_GROUPS;

    /* same as tests: run from tests/ or provide these files in cwd */
    engine_ssl.private_key_file = "./server.key";
    engine_ssl.cert_file        = "./server.crt";

    char g_session_ticket_file[] = "session_ticket.key";
    char g_session_ticket_key[2048];
    int ticket_key_len  = read_file_data(g_session_ticket_key, sizeof(g_session_ticket_key), g_session_ticket_file);
         if (ticket_key_len < 0) {
         engine_ssl.session_ticket_key_data = NULL;
         engine_ssl.session_ticket_key_len = 0;
 
     } else {
         engine_ssl.session_ticket_key_data = g_session_ticket_key;
         engine_ssl.session_ticket_key_len = ticket_key_len;
     }

    xqc_engine_callback_t engine_cb = {
        .set_event_timer = set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = srv_xquic_write_log,
            .xqc_log_write_stat = srv_xquic_write_log,
            .xqc_qlog_event_write = srv_xquic_write_qlog,
        },
    };

    xqc_transport_callbacks_t tcbs;
    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.server_accept = server_accept;
    tcbs.server_refuse = server_refuse;
    tcbs.write_socket = write_socket_cb;
    tcbs.write_socket_ex = write_socket_ex_cb;

    g_sctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &engine_ssl, &engine_cb, &tcbs, &g_sctx);
    if (!g_sctx.engine) { LOGE("[live_server] xqc_engine_create failed\n"); return -1; }

    xqc_cong_ctrl_callback_t cc = xqc_bbr_cb;
#ifdef XQC_ENABLE_RENO
    if (g_sctx.cong_ctl == 'r') cc = xqc_reno_cb;
#endif
    if (g_sctx.cong_ctl == 'c') cc = xqc_cubic_cb;

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.pacing_on = 0;
    conn_settings.ping_on = 0;
    conn_settings.cong_ctrl_callback = cc;
    conn_settings.cc_params.customize_on = 0;
    xqc_server_set_conn_settings(g_sctx.engine, &conn_settings);

    xqc_app_proto_callbacks_t ap_cbs;
    memset(&ap_cbs, 0, sizeof(ap_cbs));
    ap_cbs.conn_cbs.conn_close_notify  = conn_close_notify;
    ap_cbs.stream_cbs.stream_create_notify = stream_create_notify;
    ap_cbs.stream_cbs.stream_write_notify  = stream_write_notify;
    ap_cbs.stream_cbs.stream_read_notify   = stream_read_notify;
    ap_cbs.stream_cbs.stream_close_notify  = stream_close_notify;

    xqc_engine_register_alpn(g_sctx.engine, XQC_ALPN_TRANSPORT, strlen(XQC_ALPN_TRANSPORT), &ap_cbs, NULL);

    g_sctx.fd = create_udp_socket(g_sctx.listen_addr, g_sctx.listen_port);
    if (g_sctx.fd < 0) return -1;

    g_sctx.ev_socket = event_new(g_sctx.eb, g_sctx.fd, EV_READ | EV_PERSIST, socket_event_cb, &g_sctx);
    event_add(g_sctx.ev_socket, NULL);

    LOGE("[live_server] start: listen=%s:%d alpn=%s stdin_mode=%d\n",
         g_sctx.listen_addr, g_sctx.listen_port, XQC_ALPN_TRANSPORT, g_sctx.stdin_mode);

    event_base_dispatch(g_sctx.eb);

    if (g_sctx.ev_stdin_tick) { evtimer_del(g_sctx.ev_stdin_tick); event_free(g_sctx.ev_stdin_tick); }
    if (g_sctx.ev_pri_reset) { evtimer_del(g_sctx.ev_pri_reset); event_free(g_sctx.ev_pri_reset); }
    if (g_sctx.ev_socket) { event_del(g_sctx.ev_socket); event_free(g_sctx.ev_socket); }
#ifndef XQC_SYS_WINDOWS
    if (g_sctx.fd >= 0) close(g_sctx.fd);
#endif
    if (g_sctx.engine) xqc_engine_destroy(g_sctx.engine);
    if (g_sctx.ev_engine) event_free(g_sctx.ev_engine);
    if (g_sctx.eb) event_base_free(g_sctx.eb);
    if (g_sctx.log_fd >= 0) close(g_sctx.log_fd);
    if (g_sctx.qlog_fd >= 0) close(g_sctx.qlog_fd);

    return 0;
}
