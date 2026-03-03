/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

 #include <xquic/xquic.h>
 #include "src/transport/xqc_engine.h"
 #include "src/common/xqc_str.h"
 #include "src/common/xqc_random.h"
 #include "src/common/xqc_priority_q.h"
 #include "src/common/xqc_str_hash.h"
 #include "src/common/xqc_hash.h"
 #include "src/transport/xqc_defs.h"
 #include "src/transport/xqc_conn.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
 #include "src/transport/xqc_stream.h"
 #include "src/transport/xqc_packet_parser.h"
 #include "src/transport/xqc_frame_parser.h"
 #include "src/transport/xqc_packet_in.h"
 #include "src/transport/xqc_packet.h"
 #include "src/transport/xqc_cid.h"
 #include "src/transport/xqc_utils.h"
 #include "src/transport/xqc_timer.h"
 #include "src/transport/xqc_datagram.h"
 #include "src/http3/xqc_h3_conn.h"
 #include "src/tls/xqc_tls.h"
 #include "src/transport/xqc_datagram.h"
 #include "src/transport/xqc_reinjection.h"
 #include "src/transport/xqc_packet_out.h"
 
 
 extern const xqc_qpack_ins_cb_t xqc_h3_qpack_ins_cb;

#define XQC_MIGR_SPEC_FLIGHT_MAX        (64 * 1024)
#define XQC_MIGR_HANDOVER_MAX           4
#define XQC_MIGR_HANDOVER_WIN_US        (30 * 1000 * 1000)
#define XQC_MIGR_BUCKET_CAP             8
#define XQC_MIGR_BUCKET_REFILL_PER_SEC  4
#define XQC_MIGR_GLOBAL_TENTATIVE_MAX   256
 
 xqc_config_t default_client_config = {
     .cfg_log_level             = XQC_LOG_WARN,
     .cfg_log_event             = 1,
     .cfg_qlog_importance       = EVENT_IMPORTANCE_EXTRA,
     .cfg_log_timestamp         = 1,
     .cfg_log_level_name        = 1,
     .conn_pool_size            = 4096,
     .streams_hash_bucket_size  = 1024,
     .conns_hash_bucket_size    = 1024,
     .hash_conflict_threshold   = XQC_HASH_DEFAULT_CONFLICT_THRESHOLD,
     .conns_active_pq_capacity  = 128,
     .conns_wakeup_pq_capacity  = 128,
     .support_version_count     = 1,
     .support_version_list[0]   = XQC_VERSION_V1_VALUE,
     .cid_len                   = XQC_DEFAULT_CID_LEN,
     .cid_negotiate             = 0,
     .reset_token_key           = {0},
     .reset_token_keylen        = 0,
     .sendmmsg_on               = 0,
     .enable_h3_ext             = 0,
     .manually_triggered_send   = 0,
 };
 
 
 xqc_config_t default_server_config = {
     .cfg_log_level             = XQC_LOG_WARN,
     .cfg_log_event             = 1,
     .cfg_qlog_importance       = EVENT_IMPORTANCE_EXTRA,
     .cfg_log_timestamp         = 1,
     .cfg_log_level_name        = 1,
     .conn_pool_size            = 4096,
     .streams_hash_bucket_size  = 1024,
     .conns_hash_bucket_size    = 1024*1024, /* too many connections will affect lookup performance */
     .hash_conflict_threshold   = XQC_HASH_DEFAULT_CONFLICT_THRESHOLD,
     .conns_active_pq_capacity  = 1024,
     .conns_wakeup_pq_capacity  = 16*1024,
     .support_version_count     = 2,
     .support_version_list      = {XQC_VERSION_V1_VALUE, XQC_IDRAFT_VER_29_VALUE},
     .cid_len                   = XQC_DEFAULT_CID_LEN,
     .cid_negotiate             = 0,
     .reset_token_key           = {0},
     .reset_token_keylen        = 0,
     .sendmmsg_on               = 0,
     .enable_h3_ext             = 0,
     .manually_triggered_send   = 0,
 };
 
 
 void
 xqc_engine_free_alpn_list(xqc_engine_t *engine);

static xqc_bool_t
xqc_engine_migr_prefix_key(const struct sockaddr *peer_addr, uint8_t *key, uint8_t *key_len)
{
    if (peer_addr == NULL || key == NULL || key_len == NULL) {
        return XQC_FALSE;
    }

    if (peer_addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)peer_addr;
        xqc_memcpy(key, &sin->sin_addr, sizeof(sin->sin_addr));
        key[3] = 0; /* /24 */
        *key_len = 4;
        return XQC_TRUE;
    }

    if (peer_addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)peer_addr;
        xqc_memcpy(key, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
        xqc_memzero(key + 8, 8); /* /64 */
        *key_len = 16;
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

static xqc_migr_bucket_t *
xqc_engine_migr_bucket_get(xqc_engine_t *engine, const uint8_t *key, uint8_t key_len, xqc_usec_t now)
{
    xqc_migr_bucket_t *empty = NULL;
    xqc_migr_bucket_t *oldest = NULL;

    for (uint32_t i = 0; i < XQC_MIGR_BUCKET_TABLE_SIZE; ++i) {
        xqc_migr_bucket_t *b = &engine->migr_buckets[i];
        if (b->in_use) {
            if (b->key_len == key_len && xqc_memcmp(b->key, key, key_len) == 0) {
                return b;
            }
            if (oldest == NULL || b->last_ts < oldest->last_ts) {
                oldest = b;
            }
        } else if (empty == NULL) {
            empty = b;
        }
    }

    xqc_migr_bucket_t *b = empty ? empty : oldest;
    if (b) {
        xqc_memzero(b, sizeof(*b));
        xqc_memcpy(b->key, key, key_len);
        b->key_len = key_len;
        b->in_use = 1;
        b->tokens = XQC_MIGR_BUCKET_CAP;
        b->last_ts = now;
    }

    return b;
}

static xqc_bool_t
xqc_engine_migr_bucket_try_take(xqc_engine_t *engine, const struct sockaddr *peer_addr, xqc_usec_t now)
{
    uint8_t key[16];
    uint8_t key_len = 0;
    if (!xqc_engine_migr_prefix_key(peer_addr, key, &key_len)) {
        return XQC_FALSE;
    }

    xqc_migr_bucket_t *bucket = xqc_engine_migr_bucket_get(engine, key, key_len, now);
    if (bucket == NULL) {
        return XQC_FALSE;
    }

    if (now > bucket->last_ts) {
        uint64_t delta = now - bucket->last_ts;
        uint64_t add = (delta * XQC_MIGR_BUCKET_REFILL_PER_SEC) / 1000000;
        if (add > 0) {
            bucket->tokens = (uint32_t)xqc_min((uint64_t)XQC_MIGR_BUCKET_CAP, (uint64_t)bucket->tokens + add);
            bucket->last_ts = now;
        }
    }

    if (bucket->tokens == 0) {
        return XQC_FALSE;
    }

    bucket->tokens--;
    return XQC_TRUE;
}

static xqc_bool_t
xqc_engine_migr_has_pending_rebinding(xqc_connection_t *conn)
{
    xqc_list_head_t *p, *n;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(p, n, &conn->conn_paths_list) {
        path = xqc_list_entry(p, xqc_path_ctx_t, path_list);
        if (path->rebinding_addrlen != 0) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

static void
xqc_engine_migr_clear_rebinding(xqc_connection_t *conn)
{
    xqc_list_head_t *p, *n;
    xqc_path_ctx_t *path;
    xqc_list_for_each_safe(p, n, &conn->conn_paths_list) {
        path = xqc_list_entry(p, xqc_path_ctx_t, path_list);
        if (path->rebinding_addrlen != 0) {
            path->rebinding_addrlen = 0;
            path->rebinding_check_response = 0;
            if (path->path_send_ctl) {
                xqc_timer_unset(&path->path_send_ctl->path_timer_manager, XQC_TIMER_NAT_REBINDING);
            }
        }
    }
}

static void
xqc_engine_migr_cancel_tentative(xqc_engine_t *engine, xqc_connection_t *conn, const char *reason)
{
    if (!conn->migr_tentative_active) {
        return;
    }

    if (engine->migr_tentative_active > 0) {
        engine->migr_tentative_active--;
    }
    conn->migr_tentative_active = 0;
    conn->migr_tentative_path_id = 0;
    conn->migr_tentative_deadline = 0;
    xqc_engine_migr_clear_rebinding(conn);

    xqc_log(conn->log, XQC_LOG_DEBUG, "|migr|cancel tentative|reason:%s|", reason ? reason : "-");
}

static void
xqc_engine_migr_reclaim_tentative(xqc_engine_t *engine, xqc_connection_t *conn, xqc_usec_t now)
{
    if (!conn->migr_tentative_active) {
        return;
    }

    if ((conn->migr_tentative_deadline != 0 && now > conn->migr_tentative_deadline)
        || !xqc_engine_migr_has_pending_rebinding(conn))
    {
        xqc_engine_migr_cancel_tentative(engine, conn, "reclaim");
    }
}

static size_t
xqc_engine_migr_calc_spec_budget(xqc_connection_t *conn, xqc_path_ctx_t *path)
{
    if (path == NULL || path->path_send_ctl == NULL) {
        return 0;
    }

    uint64_t rate = xqc_send_ctl_get_pacing_rate(path->path_send_ctl);
    xqc_usec_t pto = xqc_conn_get_max_pto(conn);
    if (rate == 0 || pto == 0) {
        return 0;
    }

    uint64_t budget = (rate * 3 * pto) / 1000000;
    budget = xqc_min(budget, (uint64_t)XQC_MIGR_SPEC_FLIGHT_MAX);
    return (size_t)budget;
}

static xqc_bool_t
xqc_engine_migr_allow_speculative(xqc_engine_t *engine, xqc_connection_t *conn,
    xqc_path_ctx_t *path, const struct sockaddr *peer_addr, xqc_usec_t now, size_t *spec_budget)
{
    if (!(conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
        return XQC_FALSE;
    }

    if (conn->migr_spec_disable_until != 0 && now < conn->migr_spec_disable_until) {
        return XQC_FALSE;
    }

    if (conn->migr_window_start == 0
        || now - conn->migr_window_start > XQC_MIGR_HANDOVER_WIN_US)
    {
        conn->migr_window_start = now;
        conn->migr_window_count = 0;
    }
    conn->migr_window_count++;
    if (conn->migr_window_count > XQC_MIGR_HANDOVER_MAX) {
        conn->migr_spec_disable_until = now + XQC_MIGR_HANDOVER_WIN_US;
        return XQC_FALSE;
    }

    if (engine->migr_tentative_active >= XQC_MIGR_GLOBAL_TENTATIVE_MAX) {
        return XQC_FALSE;
    }

    *spec_budget = xqc_engine_migr_calc_spec_budget(conn, path);
    if (*spec_budget == 0) {
        return XQC_FALSE;
    }

    if (!xqc_engine_migr_bucket_try_take(engine, peer_addr, now)) {
        return XQC_FALSE;
    }

    return XQC_TRUE;
}
 
 
 xqc_int_t
 xqc_set_config(xqc_config_t *dst, const xqc_config_t *src)
 {
     if (src->conn_pool_size > 0) {
         dst->conn_pool_size = src->conn_pool_size;
     }
 
     if (src->streams_hash_bucket_size > 0) {
         dst->streams_hash_bucket_size = src->streams_hash_bucket_size;
     }
 
     if (src->conns_hash_bucket_size > 0) {
         dst->conns_hash_bucket_size = src->conns_hash_bucket_size;
     }
     if (src->hash_conflict_threshold > 0) {
         dst->hash_conflict_threshold = src->hash_conflict_threshold;
     }
 
     if (src->conns_active_pq_capacity > 0) {
         dst->conns_active_pq_capacity = src->conns_active_pq_capacity;
     }
 
     if (src->conns_wakeup_pq_capacity > 0) {
         dst->conns_wakeup_pq_capacity = src->conns_wakeup_pq_capacity;
     }
 
     if (src->support_version_count > 0 && src->support_version_count <= XQC_SUPPORT_VERSION_MAX) {
         dst->support_version_count = src->support_version_count;
         for (int i = 0; i < src->support_version_count; ++i) {
             dst->support_version_list[i] = src->support_version_list[i];
         }
 
     } else if (src->support_version_count > XQC_SUPPORT_VERSION_MAX) {
         return XQC_ERROR;
     }
 
     if (src->cid_len > 0 && src->cid_len <= XQC_MAX_CID_LEN) {
         dst->cid_len = src->cid_len;
 
     } else if (src->cid_len > XQC_MAX_CID_LEN) {
         return XQC_ERROR;
     }
 
     if (src->reset_token_keylen <= XQC_RESET_TOKEN_MAX_KEY_LEN) {
         dst->reset_token_keylen = src->reset_token_keylen;
 
         if (src->reset_token_keylen > 0) {
             memcpy(dst->reset_token_key, src->reset_token_key, src->reset_token_keylen);
         }
     }
 
     dst->cid_negotiate = src->cid_negotiate;
     dst->cfg_log_level = src->cfg_log_level;
     dst->cfg_log_event = src->cfg_log_event;
     dst->cfg_qlog_importance = src->cfg_qlog_importance;
     dst->cfg_log_timestamp = src->cfg_log_timestamp;
     dst->cfg_log_level_name = src->cfg_log_level_name;
     dst->sendmmsg_on = src->sendmmsg_on;
     dst->enable_h3_ext = src->enable_h3_ext;
 
     // : set delay_challenge flag
     dst->delay_challenge = src->delay_challenge;
     dst->immediate_resend = src->immediate_resend;
     
     return XQC_OK;
 }
 
 
 xqc_int_t
 xqc_engine_get_default_config(xqc_config_t *config, xqc_engine_type_t engine_type)
 {
     if (engine_type == XQC_ENGINE_SERVER) {
         return xqc_set_config(config, &default_server_config);
 
     } else {
         return xqc_set_config(config, &default_client_config);
     }
 }
 
 
 xqc_int_t
 xqc_engine_set_config(xqc_engine_t *engine, const xqc_config_t *engine_config)
 {
     return xqc_set_config(engine->config, engine_config);
 }
 
 
 xqc_config_t *
 xqc_engine_config_create(xqc_engine_type_t engine_type)
 {
     xqc_config_t *config = xqc_malloc(sizeof(xqc_config_t));
     if (config == NULL) {
         return NULL;
     }
 
     xqc_memzero(config, sizeof(xqc_config_t));
 
     if (engine_type == XQC_ENGINE_SERVER) {
         xqc_set_config(config, &default_server_config);
 
     } else if (engine_type == XQC_ENGINE_CLIENT) {
         xqc_set_config(config, &default_client_config);
     }
 
     return config;
 }
 
 
 void
 xqc_engine_config_destroy(xqc_config_t *config)
 {
     xqc_free(config);
 }
 
 
 void
 xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level)
 {
     xqc_log_level_set(engine->log, log_level);
 }
 
 
 xqc_str_hash_table_t *
 xqc_engine_conns_hash_create(xqc_config_t *config, uint8_t *key, size_t key_len, xqc_log_t *log)
 {
     xqc_str_hash_table_t *hash_table = xqc_malloc(sizeof(xqc_str_hash_table_t));
     if (hash_table == NULL) {
         return NULL;
     }
 
     if (xqc_str_hash_init(hash_table, xqc_default_allocator,
             config->conns_hash_bucket_size, config->hash_conflict_threshold,
             key, key_len, log))
     {
         goto fail;
     }
 
     return hash_table;
 
 fail:
     xqc_free(hash_table);
     return NULL;
 }
 
 
 void
 xqc_engine_conns_hash_destroy(xqc_str_hash_table_t *hash_table)
 {
     xqc_str_hash_release(hash_table);
     xqc_free(hash_table);
 }
 
 
 int xqc_engine_conn_pq_operator(xqc_pq_t *pq, xqc_pq_element_t *e)
 {
     xqc_connection_t **conn;
     conn = (xqc_connection_t**)e->data;
     if (conn && *conn) {
         (*conn)->wakeup_pq_index = xqc_pq_element_index(pq, e);
     }
     return XQC_OK;
 }
 
 xqc_pq_t *
 xqc_engine_conns_pq_create(xqc_config_t *config, uint8_t is_wakeup)
 {
     xqc_pq_t *q = xqc_malloc(sizeof(xqc_pq_t));
     if (q == NULL) {
         return NULL;
     }
 
     size_t capacity = is_wakeup == 1 ? 
                       config->conns_wakeup_pq_capacity : 
                       config->conns_active_pq_capacity;
 
     xqc_memzero(q, sizeof(xqc_pq_t));
     if (xqc_pq_init(q, sizeof(xqc_conns_pq_elem_t),
         capacity, xqc_default_allocator, 
         xqc_pq_revert_cmp, xqc_engine_conn_pq_operator))
     {
         goto fail;
     }
 
     return q;
 
 fail:
     xqc_pq_destroy(q);
     xqc_free(q);
     return NULL;
 }
 
 
 xqc_connection_t *
 xqc_engine_conns_hash_find(xqc_engine_t *engine, const xqc_cid_t *cid, char type)
 {
     xqc_connection_t    *xqc_conn;
     if (cid == NULL || cid->cid_len == 0) {
         return NULL;
     }
 
     uint64_t hash;
     xqc_str_t str;
     str.data = (unsigned char *)cid->cid_buf;
     str.len = cid->cid_len;
 
     if (type == 's') {
         /* search by endpoint's cid */
         hash = xqc_siphash_get_hash(&engine->conns_hash->siphash_ctx, cid->cid_buf, cid->cid_len);
         return xqc_str_hash_find(engine->conns_hash, hash, str);
 
     } else {
         /* search by peer's cid */
         hash = xqc_siphash_get_hash(&engine->conns_hash_dcid->siphash_ctx, cid->cid_buf, cid->cid_len);
         xqc_conn = xqc_str_hash_find(engine->conns_hash_dcid, hash, str);
         if (xqc_conn == NULL) {
             xqc_log(engine->log, XQC_LOG_ERROR, "|xquic find dcid error|dcid:%s|",
                     xqc_dcid_str(engine, cid));
         }
         return xqc_conn;
     }
 }
 
 xqc_connection_t *
 xqc_engine_get_conn_by_scid(xqc_engine_t *engine, const xqc_cid_t *cid)
 {
     return xqc_engine_conns_hash_find(engine, cid, 's');
 }
 
 void
 xqc_engine_conns_pq_destroy(xqc_pq_t *q)
 {
     xqc_pq_destroy(q);
     xqc_free(q);
 }
 
 xqc_usec_t
 xqc_engine_wakeup_after(xqc_engine_t *engine)
 {
     xqc_conns_pq_elem_t *el = xqc_conns_pq_top(engine->conns_wait_wakeup_pq);
     if (el) {
         xqc_usec_t now = xqc_monotonic_timestamp();
         xqc_log(engine->log, XQC_LOG_DEBUG, "|wakeup:%ui|now:%ui|diff:%ui|",
                 el->time_us, now, el->time_us - now);
         return el->time_us > now ? el->time_us - now : 1;
 
     }
 
     xqc_log(engine->log, XQC_LOG_DEBUG, "|NULL wakeup top|");
     return 0;
 }
 
 void
 xqc_engine_wakeup_once(xqc_engine_t *engine)
 {
     /* if interval is smaller, trigger the event with the new interval */
     if (engine->eng_callback.set_event_timer) {
         engine->eng_callback.set_event_timer(1, engine->user_data);
     }
 }
 
 
 xqc_int_t
 xqc_engine_schedule_reset(xqc_engine_t *engine,
     const struct sockaddr *peer_addr, socklen_t peer_addrlen, xqc_usec_t now)
 {
     /* Can send 2 reset packets in 5 seconds */
     if (now - engine->reset_sent_cnt_cleared > 5000 * 1000) {
         memset(engine->reset_sent_cnt, 0, sizeof(engine->reset_sent_cnt));
         engine->reset_sent_cnt_cleared = now;
     }
 
     uint32_t hash = xqc_murmur_hash2((unsigned char *)peer_addr, peer_addrlen);
     hash = hash % XQC_RESET_CNT_ARRAY_LEN;
     xqc_log(engine->log, XQC_LOG_DEBUG, "|hash:%ud|cnt:%ud|", hash, (unsigned int)engine->reset_sent_cnt[hash]);
 
     if (engine->reset_sent_cnt[hash] < 2) {
         engine->reset_sent_cnt[hash]++;
         return XQC_OK;
     }
 
     return XQC_ERROR;
 }
 
 void
 xqc_engine_set_callback(xqc_engine_t *engine, const xqc_engine_callback_t *engine_callback,
     const xqc_transport_callbacks_t *transport_cbs)
 {
     engine->eng_callback = *engine_callback;
     engine->transport_cbs = *transport_cbs;
 
     if (engine_callback->realtime_ts) {
         xqc_realtime_timestamp = engine_callback->realtime_ts;
     }
 
     if (engine_callback->monotonic_ts) {
         xqc_monotonic_timestamp = engine_callback->monotonic_ts;
     }
 }
 
 
 /**
  * @brief check the legitimacy of engine config
  */
 xqc_bool_t
 xqc_engine_check_config(xqc_engine_type_t engine_type, const xqc_config_t *engine_config,
     const xqc_engine_ssl_config_t *ssl_config, const xqc_transport_callbacks_t *transport_cbs)
 {
     /* mismatch of sendmmsg_on enable and write_mmsg & write_mmsg_ex callback function */
     if (engine_config && engine_config->sendmmsg_on && transport_cbs->write_mmsg == NULL && transport_cbs->write_mmsg_ex == NULL) {
         return XQC_FALSE;
     }
 
     return XQC_TRUE;
 }
 
 /**
  * Create new xquic engine.
  * @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT
  */
 xqc_engine_t *
 xqc_engine_create(xqc_engine_type_t engine_type, 
     const xqc_config_t *engine_config,
     const xqc_engine_ssl_config_t *ssl_config,
     const xqc_engine_callback_t *engine_callback, 
     const xqc_transport_callbacks_t *transport_cbs,
     void *user_data)
 {
     xqc_engine_t *engine = NULL;
     uint8_t sipkey[XQC_SIPHASH_KEY_SIZE];
 
     /* check input parameter */
     if (xqc_engine_check_config(engine_type, engine_config, ssl_config, transport_cbs)
         == XQC_FALSE)
     {
         return NULL;
     }
 
     engine = xqc_malloc(sizeof(xqc_engine_t));
     if (engine == NULL) {
         goto fail;
     }
     xqc_memzero(engine, sizeof(xqc_engine_t));
 
     engine->eng_type = engine_type;
 
     /* init alpn list */
     xqc_init_list_head(&engine->alpn_reg_list);
 
     engine->config = xqc_engine_config_create(engine_type);
     if (engine->config == NULL) {
         goto fail;
     }
 
     if (engine_config != NULL
         && xqc_engine_set_config(engine, engine_config) != XQC_OK) 
     {
         goto fail;
     }
 
     xqc_engine_set_callback(engine, engine_callback, transport_cbs);
     engine->user_data = user_data;
     engine->log = xqc_log_init(engine->config->cfg_log_level,
                                engine->config->cfg_log_event,
                                engine->config->cfg_qlog_importance,
                                engine->config->cfg_log_timestamp,
                                engine->config->cfg_log_level_name, engine,
                                &engine->eng_callback.log_callbacks, engine->user_data);
     if (engine->log == NULL) {
         goto fail;
     }
 
     engine->rand_generator = xqc_random_generator_create(engine->log);
     if (engine->rand_generator == NULL) {
         goto fail;
     }
     xqc_get_random(engine->rand_generator, sipkey, sizeof(sipkey));
     
 
     engine->conns_hash = xqc_engine_conns_hash_create(engine->config, sipkey, sizeof(sipkey), engine->log);
     if (engine->conns_hash == NULL) {
         goto fail;
     }
 
     engine->conns_hash_dcid = xqc_engine_conns_hash_create(engine->config, sipkey, sizeof(sipkey), engine->log);
     if (engine->conns_hash_dcid == NULL) {
         goto fail;
     }
 
     engine->conns_hash_sr_token = xqc_engine_conns_hash_create(engine->config, sipkey, sizeof(sipkey), engine->log);
     if (engine->conns_hash_sr_token == NULL) {
         goto fail;
     }
 
     engine->conns_active_pq = xqc_engine_conns_pq_create(engine->config, 0);
     if (engine->conns_active_pq == NULL) {
         goto fail;
     }
 
     engine->conns_wait_wakeup_pq = xqc_engine_conns_pq_create(engine->config, 1);
     if (engine->conns_wait_wakeup_pq == NULL) {
         goto fail;
     }
 
     /* create tls context */
     if (ssl_config != NULL) {
         engine->tls_ctx = xqc_tls_ctx_create((xqc_tls_type_t)engine->eng_type, ssl_config,
                                              &xqc_conn_tls_cbs, engine->log);
         if (NULL == engine->tls_ctx) {
             xqc_log(engine->log, XQC_LOG_ERROR, "|create tls context error");
             goto fail;
         }
 
     } else {
         goto fail;
     }
 
     engine->default_conn_settings = internal_default_conn_settings;
 
     return engine;
 
 fail:
     xqc_engine_destroy(engine);
     return NULL;
 }
 
 
 void
 xqc_engine_destroy(xqc_engine_t *engine)
 {
     xqc_connection_t *conn;
 
     if (engine == NULL) {
         return;
     }
 
     if (engine->log) {
         xqc_log(engine->log, XQC_LOG_DEBUG, "|begin|");
     }
 
     xqc_engine_free_alpn_list(engine);
 
     /* free destroy first, then destroy others */
     if (engine->conns_active_pq) {
         while (!xqc_pq_empty(engine->conns_active_pq)) {
             conn = xqc_conns_pq_pop_top_conn(engine->conns_active_pq);
             if (conn == NULL) {
                 if (engine->log) {
                     xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
                 }
                 continue;
             }
 
             conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
             /* active connections should never present in the wakeup queue */
             xqc_conn_destroy(conn);
         }
     }
 
     if (engine->conns_wait_wakeup_pq) {
         while (!xqc_pq_empty(engine->conns_wait_wakeup_pq)) {
             /* get conn from pq top and pop */
             conn = xqc_conns_pq_pop_top_conn(engine->conns_wait_wakeup_pq);
             if (conn == NULL) {
                 if (engine->log) {
                     xqc_log(engine->log, XQC_LOG_ERROR, "|NULL ptr, skip|");
                 }
                 continue;
             }
             conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
             xqc_conn_destroy(conn);
         }
     }
 
     if (engine->conns_active_pq) {
         xqc_engine_conns_pq_destroy(engine->conns_active_pq);
         engine->conns_active_pq = NULL;
     }
 
     if (engine->conns_wait_wakeup_pq) {
         xqc_engine_conns_pq_destroy(engine->conns_wait_wakeup_pq);
         engine->conns_wait_wakeup_pq = NULL;
     }
 
     if (engine->tls_ctx) {
         xqc_tls_ctx_destroy(engine->tls_ctx);
         engine->tls_ctx = NULL;
     }
 
     if (engine->config) {
         xqc_engine_config_destroy(engine->config);
         engine->config = NULL;
     }
 
     if (engine->rand_generator) {
         xqc_random_generator_destroy(engine->rand_generator);
         engine->rand_generator = NULL;
     }
 
     if (engine->conns_hash) {
         xqc_engine_conns_hash_destroy(engine->conns_hash);
         engine->conns_hash = NULL;
     }
 
     if (engine->conns_hash_dcid) {
         xqc_engine_conns_hash_destroy(engine->conns_hash_dcid);
         engine->conns_hash_dcid = NULL;
     }
 
     if (engine->conns_hash_sr_token) {
         xqc_engine_conns_hash_destroy(engine->conns_hash_sr_token);
         engine->conns_hash_sr_token = NULL;
     }
 
     if (engine->tls_ctx) {
         xqc_tls_ctx_destroy(engine->tls_ctx);
     }
 
     if (engine->log) {
         xqc_log_release(engine->log);
     }
 
     xqc_free(engine);
 }
 
 
 xqc_int_t
 xqc_engine_send_reset(xqc_engine_t *engine, xqc_cid_t *dcid,
     const struct sockaddr *peer_addr, socklen_t peer_addrlen,
     const struct sockaddr *local_addr, socklen_t local_addrlen,
     size_t input_pkt_size, void *user_data)
 {
     unsigned char           buf[XQC_PACKET_OUT_BUF_CAP];
     xqc_int_t               size;
     size_t                  max_sr_pkt_len;
     xqc_stateless_reset_pt  stateless_cb;
 
     max_sr_pkt_len = input_pkt_size - XQC_STATELESS_RESET_PKT_SUBTRAHEND;
     if (max_sr_pkt_len < XQC_STATELESS_RESET_PKT_MIN_LEN) {
         /* XQUIC will not send SR to a packet smaller than 21 bytes to avoid
            Stateless Reset Looping */
         return XQC_OK;
     }
 
     max_sr_pkt_len = xqc_min(max_sr_pkt_len, XQC_STATELESS_RESET_PKT_MAX_LEN);
     size = xqc_gen_reset_packet(dcid, buf, engine->config->reset_token_key,
                                 engine->config->reset_token_keylen,
                                 max_sr_pkt_len, engine->rand_generator);
     if (size < 0) {
         return size;
     }
 
     stateless_cb = engine->transport_cbs.stateless_reset;
     if (stateless_cb) {
         size = (xqc_int_t)stateless_cb(buf, (size_t)size, peer_addr, peer_addrlen,
                                        local_addr, local_addrlen, user_data);
         if (size < 0) {
             return size;
         }
     }
 
     xqc_log(engine->log, XQC_LOG_INFO, "|<==|xqc_engine_send_reset ok|size:%d|", size);
     return XQC_OK;
 }
 
 
 #define XQC_CHECK_UNDECRYPT_PACKETS() do {                      \
     if (XQC_UNLIKELY(xqc_conn_has_undecrypt_packets(conn))) {   \
         xqc_conn_process_undecrypt_packets(conn);               \
         XQC_CHECK_IMMEDIATE_CLOSE();                            \
     }                                                           \
 } while(0);                                                     \
 
 #define XQC_CHECK_IMMEDIATE_CLOSE() do {                        \
     if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_IMMEDIATE_CLOSE_FLAGS)) {     \
         xqc_conn_immediate_close(conn);                         \
         goto end;                                               \
     }                                                           \
 } while(0);                                                     \
 
 
 void
 xqc_engine_process_conn(xqc_connection_t *conn, xqc_usec_t now)
 {
     xqc_log(conn->log, XQC_LOG_DEBUG, "|conn:%p|state:%s|flag:%s|now:%ui|",
             conn, xqc_conn_state_2_str(conn->conn_state), xqc_conn_flag_2_str(conn, conn->conn_flag), now);
 
     int ret;
     xqc_bool_t wait_scid, wait_dcid;
 
     xqc_conn_timer_expire(conn, now);
 
     /* notify closing event as soon as possible */
     xqc_conn_closing_notify(conn);
 
     if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_TIME_OUT)) {
         conn->conn_state = XQC_CONN_STATE_CLOSED;
         xqc_log_event(conn->log, CON_CONNECTION_STATE_UPDATED, conn);
         return;
     }
     XQC_CHECK_IMMEDIATE_CLOSE();
 
     if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_LINGER_CLOSING)) {
         if (xqc_send_queue_out_queue_empty(conn->conn_send_queue)) {
             xqc_conn_log(conn, XQC_LOG_DEBUG, "|out queue empty, close connection|");
             xqc_timer_unset(&conn->conn_timer_manager, XQC_TIMER_LINGER_CLOSE);
             xqc_conn_immediate_close(conn);
             conn->conn_flag &= ~XQC_CONN_FLAG_LINGER_CLOSING;
         }
         goto end;
     }
 
     if (XQC_UNLIKELY(conn->conn_state >= XQC_CONN_STATE_CLOSING)) {
         goto end;
     }
 
     XQC_CHECK_UNDECRYPT_PACKETS();
     xqc_process_crypto_read_streams(conn);
     XQC_CHECK_UNDECRYPT_PACKETS();
     xqc_process_crypto_write_streams(conn);
     XQC_CHECK_UNDECRYPT_PACKETS();
     XQC_CHECK_IMMEDIATE_CLOSE();
 
     if (XQC_UNLIKELY(!xqc_list_empty(&conn->conn_send_queue->sndq_buff_1rtt_packets)
         && conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT)) {
         xqc_conn_write_buffed_1rtt_packets(conn);
     }
     XQC_CHECK_IMMEDIATE_CLOSE();
 
     if (conn->conn_flag & XQC_CONN_FLAG_CAN_SEND_1RTT) {
         xqc_process_read_streams(conn);
         if (xqc_send_queue_can_write(conn->conn_send_queue)) {
             if (conn->conn_send_queue->sndq_full) {
                 if (xqc_send_queue_release_enough_space(conn->conn_send_queue)) {
                     conn->conn_send_queue->sndq_full = XQC_FALSE;
                     xqc_process_write_streams(conn);
                     xqc_datagram_notify_write(conn);
                 }
 
             } else {
                 xqc_process_write_streams(conn);
                 if (conn->conn_flag & XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT) {
                     xqc_datagram_notify_write(conn);
                     conn->conn_flag &= ~XQC_CONN_FLAG_DGRAM_WAIT_FOR_1RTT;
                 }
             }
 
         } else {
             xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_send_queue_can_write false|");
         }
     }
     XQC_CHECK_IMMEDIATE_CLOSE();
 
     if (conn->ack_flag) {
         ret = xqc_write_ack_or_mp_ack_or_ext_ack_to_packets(conn);
         if (ret) {
             xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ack_or_mp_ack_or_ext_ack_to_packets error|");
             XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
         }
     }
 
     XQC_CHECK_IMMEDIATE_CLOSE();
 
     ret = xqc_conn_try_add_new_conn_id(conn, 0);
     if (ret) {
         xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conn_try_add_new_conn_id error|");
     }
 
     if (conn->enable_multipath) {
         if ((conn->conn_flag & XQC_CONN_FLAG_MP_WAIT_MP_READY)
             && xqc_conn_get_available_path_id(conn, NULL) == XQC_OK) 
         {
             conn->conn_flag |= XQC_CONN_FLAG_MP_READY_NOTIFY;
             conn->conn_flag &= ~XQC_CONN_FLAG_MP_WAIT_MP_READY;
         }
     }
 
     /* for multi-path */
     if (conn->conn_flag & XQC_CONN_FLAG_MP_READY_NOTIFY) {
         if (conn->transport_cbs.ready_to_create_path_notify) {
             conn->transport_cbs.ready_to_create_path_notify(&conn->scid_set.user_scid,
                                                             xqc_conn_get_user_data(conn));
         }
         conn->conn_flag &= ~XQC_CONN_FLAG_MP_READY_NOTIFY;
     }
 
     if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_PING)) {
         ret = xqc_conn_send_ping_internal(conn, NULL, XQC_FALSE);
         if (ret) {
             xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_write_ping_to_packet error|");
             XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
         }
     }
     XQC_CHECK_IMMEDIATE_CLOSE();
 
     /* server send version negotiation */
     if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_VERSION_NEGOTIATION)) {
         ret = xqc_conn_send_version_negotiation(conn);
         if (ret) {
             xqc_log(conn->log, XQC_LOG_ERROR, "|send version negotiation error|");
         }
     }
 
     /* PMTUD probing */
     if (XQC_UNLIKELY(conn->conn_flag & XQC_CONN_FLAG_PMTUD_PROBING)) {
         xqc_conn_ptmud_probing(conn);
     }
 
 end:
     conn->packet_need_process_count = 0;
     conn->conn_flag &= ~XQC_CONN_FLAG_NEED_RUN;
     return;
 }
 
 
 void xqc_engine_finish_recv (xqc_engine_t *engine) {
     xqc_engine_main_logic_internal(engine);
 }
 
 void xqc_engine_finish_send (xqc_engine_t *engine) {
     xqc_engine_main_logic_internal(engine);
 }
 
 
 void xqc_engine_main_logic_internal(xqc_engine_t *engine) {
     if (engine->eng_flag & XQC_ENG_FLAG_NO_DESTROY) {
         return;
     }
 
     engine->eng_flag |= XQC_ENG_FLAG_NO_DESTROY;
     xqc_engine_main_logic(engine);
     engine->eng_flag &= ~XQC_ENG_FLAG_NO_DESTROY;
 }
 
 void 
 xqc_engine_conn_logic(xqc_engine_t *engine, xqc_connection_t *conn)
 {
     if (engine->eng_flag & XQC_ENG_FLAG_RUNNING) {
         xqc_log(conn->log, XQC_LOG_DEBUG, 
                 "|engine is running on conn:%s|", xqc_conn_addr_str(conn));
         return;
     }
 
     engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
 
     xqc_usec_t now = xqc_monotonic_timestamp();
     xqc_usec_t wake_after;
     xqc_engine_process_conn(conn, now);
         
     if (XQC_LIKELY(conn->conn_state != XQC_CONN_STATE_CLOSED)) {
         conn->last_ticked_time = now;
         xqc_conn_schedule_packets_to_paths(conn);
 
         if (xqc_engine_is_sendmmsg_on(engine, conn)) {
             xqc_conn_transmit_pto_probe_packets_batch(conn);
             xqc_conn_retransmit_lost_packets_batch(conn);
             xqc_conn_send_packets_batch(conn);
 
         } else {
             xqc_conn_transmit_pto_probe_packets(conn);
             xqc_conn_retransmit_lost_packets(conn);
             xqc_conn_send_packets(conn);
         }
 
         if (conn->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_AFTER_SEND) {
             xqc_conn_reinject_unack_packets(conn, XQC_REINJ_UNACK_AFTER_SEND);
             xqc_conn_send_packets(conn);
         }
 
         if (XQC_LIKELY(conn->conn_state != XQC_CONN_STATE_CLOSED)) {
             conn->next_tick_time = xqc_conn_next_wakeup_time(conn);
             if (XQC_LIKELY(conn->next_tick_time != 0)) {
                 xqc_engine_remove_active_queue(engine, conn);
                 xqc_engine_add_wakeup_queue(engine, conn);
                 goto finish;
             }
         }
     }
 
     conn->next_tick_time = 0;
     xqc_engine_remove_active_queue(engine, conn);
     xqc_engine_add_wakeup_queue(engine, conn);
 
 finish:
     if (!xqc_pq_empty(engine->conns_active_pq)) {
         /* If there are other acitve connections, we must wakeup immediately. */
         xqc_engine_wakeup_once(engine);
 
     } else {
         wake_after = xqc_engine_wakeup_after(engine);
         if (wake_after > 0) {
             engine->eng_callback.set_event_timer(wake_after, engine->user_data);
         }
     }
     
     engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
     xqc_log(engine->log, XQC_LOG_DEBUG, "|END|");
     return;
 }
 
 
 /**
  * Process all connections
  */
 void
 xqc_engine_main_logic(xqc_engine_t *engine)
 {
     if (engine->eng_flag & XQC_ENG_FLAG_RUNNING) {
         xqc_log(engine->log, XQC_LOG_DEBUG, "|engine is running|");
         return;
     }
     engine->eng_flag |= XQC_ENG_FLAG_RUNNING;
 
     xqc_usec_t now = xqc_monotonic_timestamp();
     xqc_connection_t *conn;
 
     xqc_log(engine->log, XQC_LOG_DEBUG, "|BEGIN|now:%ui|", now);
 
     while (!xqc_pq_empty(engine->conns_wait_wakeup_pq)) {
         xqc_conns_pq_elem_t *el = xqc_conns_pq_top(engine->conns_wait_wakeup_pq);
         if (XQC_UNLIKELY(el == NULL || el->conn == NULL)) {
             xqc_log(engine->log, XQC_LOG_ERROR, "|wakeup|NULL ptr, skip|");
             xqc_conns_pq_pop(engine->conns_wait_wakeup_pq);    /* no push between top and pop */
             continue;
         }
         conn = el->conn;
 
         if (el->time_us <= now) {
             xqc_engine_remove_wakeup_queue(engine, conn);
             if (xqc_engine_add_active_queue(engine, conn) != XQC_OK) {
                 xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|");
                 XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
             }
 
         } else {
             break;
         }
     }
 
     while (!xqc_pq_empty(engine->conns_active_pq)) {
         conn = xqc_conns_pq_pop_top_conn(engine->conns_active_pq);
 
         if (XQC_UNLIKELY(conn == NULL)) {
             xqc_log(engine->log, XQC_LOG_ERROR, "|active|NULL ptr, skip|");
             continue;
         }
 
         now = xqc_monotonic_timestamp();
         xqc_engine_process_conn(conn, now);
         
         if (XQC_LIKELY(conn->conn_state != XQC_CONN_STATE_CLOSED)) {
             conn->last_ticked_time = now;
             xqc_conn_schedule_packets_to_paths(conn);
 
             if (xqc_engine_is_sendmmsg_on(engine, conn)) {
                 xqc_conn_transmit_pto_probe_packets_batch(conn);
                 xqc_conn_retransmit_lost_packets_batch(conn);
                 xqc_conn_send_packets_batch(conn);
 
             } else {
                 xqc_conn_transmit_pto_probe_packets(conn);
                 xqc_conn_retransmit_lost_packets(conn);
                 xqc_conn_send_packets(conn);
             }
 
             if (conn->conn_settings.mp_enable_reinjection & XQC_REINJ_UNACK_AFTER_SEND) {
                 xqc_conn_reinject_unack_packets(conn, XQC_REINJ_UNACK_AFTER_SEND);
                 xqc_conn_send_packets(conn);
             }
 
             if (XQC_LIKELY(conn->conn_state != XQC_CONN_STATE_CLOSED)) {
                 conn->next_tick_time = xqc_conn_next_wakeup_time(conn);
                 if (XQC_LIKELY(conn->next_tick_time != 0)) {
                     conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
                     xqc_engine_add_wakeup_queue(engine, conn);
                     continue;
                 }
             }
         }
 
         /* conn should be destroyed ( closed or next_tick_time = 0) */
         conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
         if (!(engine->eng_flag & XQC_ENG_FLAG_NO_DESTROY)) {
             xqc_log(engine->log, XQC_LOG_INFO, "|conn:%p|%s|"
                     "conn_state:%ud|next_tick_time:%ui", 
                     conn, xqc_conn_addr_str(conn),
                     conn->conn_state, conn->next_tick_time);
             xqc_conn_destroy(conn);
 
         } else {
             conn->next_tick_time = 0;
             xqc_engine_add_wakeup_queue(engine, conn);
         }
     }
 
     xqc_usec_t wake_after = xqc_engine_wakeup_after(engine);
     if (wake_after > 0) {
         engine->eng_callback.set_event_timer(wake_after, engine->user_data);
     }
 
     engine->eng_flag &= ~XQC_ENG_FLAG_RUNNING;
 
     xqc_log(engine->log, XQC_LOG_DEBUG, "|END|now:%ui|", now);
     return;
 }
 
 
 xqc_int_t
 xqc_engine_handle_stateless_reset(xqc_engine_t *engine,
     const unsigned char *buf, size_t buf_size, xqc_usec_t recv_time,
     xqc_connection_t **c)
 {
     xqc_int_t          ret;
     const uint8_t     *sr_token;
     xqc_connection_t  *conn;
     uint64_t           hash;
     xqc_str_t          str;
 
     ret = -XQC_ERROR;
 
     /* parse stateless reset token from packet */
     sr_token = NULL;
     ret = xqc_packet_parse_stateless_reset(buf, buf_size, &sr_token);
     if (XQC_OK != ret) {
         xqc_log(engine->log, XQC_LOG_DEBUG, "|not a stateless reset pkt");
         return ret;
     }
 
     if (NULL == sr_token) {
         return -XQC_ERROR;
     }
 
     hash = xqc_siphash_get_hash(&engine->conns_hash_sr_token->siphash_ctx,
                                 sr_token, XQC_STATELESS_RESET_TOKENLEN); 
     str.data = (unsigned char *)sr_token;
     str.len = XQC_STATELESS_RESET_TOKENLEN;
 
     /* try to find connection with sr_token */
     conn = xqc_str_hash_find(engine->conns_hash_sr_token, hash, str);
     if (NULL == conn) {
         /* can't find connection with sr_token */
         xqc_log(engine->log, XQC_LOG_DEBUG, "|can't find conn with sr|sr:%s",
                 xqc_sr_token_str(engine, sr_token));
         return -XQC_ERROR;
     }
 
     *c = conn;
     ret = xqc_conn_handle_stateless_reset(conn, sr_token);
     if (XQC_OK != ret) {
         /* sr_token state not match between engine and connection */
         xqc_log(conn->log, XQC_LOG_ERROR, "|sr token state mismatch|");
         return -XQC_ESTATE;
     }
 
     return XQC_OK;
 }
 
 
 #ifdef XQC_COMPAT_GENERATE_SR_PKT
 xqc_int_t
 xqc_engine_handle_deprecated_stateless_reset(xqc_engine_t *engine,
     const unsigned char *buf, size_t buf_size, const xqc_cid_t *scid,
     xqc_usec_t recv_time, xqc_connection_t **c)
 {
     xqc_connection_t   *conn;
     xqc_int_t           ret;
 
     /* compat with the original stateless reset mechanism */
     if (!xqc_is_deprecated_reset_packet((xqc_cid_t *)scid, buf, buf_size,
                                         engine->config->reset_token_key,
                                         engine->config->reset_token_keylen))
     {
         return -XQC_ERROR;
     }
 
     /* reset is associated with peer's cid */
     conn = xqc_engine_conns_hash_find(engine, scid, 'd');
     if (NULL == conn) {
         return -XQC_ERROR;
     }
 
     *c = conn;
     ret = xqc_conn_handle_deprecated_stateless_reset(conn, scid);
 
     return ret;
 }
 #endif
 
 xqc_int_t
 xqc_engine_process_sr_pkt(xqc_engine_t *engine, const unsigned char *buf,
     size_t buf_size, const xqc_cid_t *cid, xqc_usec_t recv_time,
     xqc_connection_t **c)
 {
     xqc_int_t   ret;
 
     /* try handle the unknown packet as standard Stateless Reset */
     ret = xqc_engine_handle_stateless_reset(engine, buf, buf_size,
                                             recv_time, c);
     if (XQC_OK == ret) {
         return XQC_OK;
     }
 
 #ifdef XQC_COMPAT_GENERATE_SR_PKT
     /* if not a standard Stateless Reset packet */
     ret = xqc_engine_handle_deprecated_stateless_reset(engine, buf, buf_size,
                                                        cid, recv_time, c);
     if (XQC_OK == ret) {
         return XQC_OK;
     }
 #endif
 
     return ret;
 }

void xqc_conn_server_resend_immediately(xqc_connection_t *conn, size_t spec_budget)
{
    if (conn == NULL || conn->conn_send_queue == NULL) {
        return;
    }

    if (spec_budget == 0) {
        return;
    }

    xqc_send_queue_t *send_queue = conn->conn_send_queue;
    xqc_list_head_t *unacked_head = &send_queue->sndq_unacked_packets[XQC_PNS_APP_DATA];

    xqc_list_head_t *pos, *next;
    xqc_packet_out_t *po;
    int copied = 0;
    size_t copied_bytes = 0;

    xqc_list_for_each_safe(pos, next, unacked_head) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);

        /* 仅重传携带 STREAM 帧的应用数据包，且避免重复重传 */
        if (po->po_stream_frames_idx == 0 || (po->po_flag & XQC_POF_RETRANSED)) {
            continue;
        }

        if (copied_bytes + po->po_used_size > spec_budget) {
            break;
        }

        xqc_send_queue_copy_to_lost(po, send_queue, XQC_TRUE);
        copied++;
        copied_bytes += po->po_used_size;
    }

    if (copied == 0) {
        return;
    }

    /* 立即调度并发送重传包，走标准重传路径，保持队列与计数一致 */
    xqc_conn_schedule_packets(conn, &send_queue->sndq_lost_packets, XQC_TRUE, XQC_SEND_TYPE_RETRANS);
    xqc_conn_retransmit_lost_packets(conn);

    /* 重置 loss detection timer，避免 PTO 快速重复触发 */
    xqc_path_ctx_t *path;
    xqc_list_head_t *p, *n;
    xqc_list_for_each_safe(p, n, &conn->conn_paths_list) {
        path = xqc_list_entry(p, xqc_path_ctx_t, path_list);
        if (path->path_send_ctl) {
            xqc_send_ctl_set_loss_detection_timer(path->path_send_ctl);
        }
    }
}



 /**
  * Pass received UDP packet payload into xquic engine.
  * @param recv_time   UDP packet received time in microsecond
  */
 xqc_int_t
 xqc_engine_packet_process(xqc_engine_t *engine,
     const unsigned char *packet_in_buf, size_t packet_in_size,
     const struct sockaddr *local_addr, socklen_t local_addrlen,
     const struct sockaddr *peer_addr, socklen_t peer_addrlen,
     xqc_usec_t recv_time, void *user_data)
 {
     xqc_int_t ret;
     xqc_connection_t *conn = NULL;
     xqc_cid_t dcid, scid;   /* dcid: cid of peer; scid: cid of endpoint */
     xqc_log_level_t lvl;
 
     xqc_cid_init_zero(&dcid);
     xqc_cid_init_zero(&scid);
 
     /* reverse packet's dcid/scid to endpoint's scid/dcid */
     ret = xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len,
                                (unsigned char *)packet_in_buf, packet_in_size);
     if (XQC_UNLIKELY(ret != XQC_OK)) {
         xqc_log_event(engine->log, TRA_PACKET_DROPPED, "fail to parse cid", ret, "unknown", 0);
         return -XQC_EILLPKT;
     }
 
     conn = xqc_engine_conns_hash_find(engine, &scid, 's');
 
     /* can't find a connection by the cid from the packet */
     if (XQC_UNLIKELY(conn == NULL)) {
 
         if (XQC_PACKET_IS_LONG_HEADER(packet_in_buf)) {
             /* server creates connection when receiving a initial/0-rtt packet */
             if (engine->eng_type == XQC_ENGINE_SERVER
                 && (XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_INIT
                 || XQC_PACKET_LONG_HEADER_GET_TYPE(packet_in_buf) == XQC_PTYPE_0RTT)
                      && (local_addr != NULL && peer_addr != NULL))
             {
                 conn = xqc_conn_server_create(engine, local_addr, local_addrlen,
                                             peer_addr, peer_addrlen, &dcid, &scid,
                                             &engine->default_conn_settings, user_data);
                 xqc_log_event(engine->log, CON_SERVER_LISTENING, peer_addr, peer_addrlen);
                 if (conn == NULL) {
                     xqc_log(engine->log, XQC_LOG_ERROR, "|fail to create connection|");
                     return -XQC_ECREATE_CONN;
                 }
             }
 
         } else {
             /* stateless reset is pretended to be a short header packet */
             ret = xqc_engine_process_sr_pkt(engine, packet_in_buf,
                                             packet_in_size, &scid, recv_time,
                                             &conn);
             if (ret == XQC_OK && NULL != conn) {
                 /* SR processed */
                 goto after_process;
             }
 
             xqc_log(engine->log, XQC_LOG_DEBUG, "|not a stateless reset pkt, "
                     "will try send stateless reset pkt");
         }
     }
 
     /* can't find a conneciton, send stateless reset */
     if (NULL == conn) {
         if (xqc_engine_schedule_reset(engine, peer_addr, peer_addrlen, recv_time) != XQC_OK) {
             return -XQC_ECONN_NFOUND;
         }
 
         lvl = XQC_LOG_STATS;
         if (engine->eng_type == XQC_ENGINE_CLIENT) {
             lvl = XQC_LOG_REPORT;
         }
 
         xqc_log(engine->log, lvl, "|fail to find connection, send reset|"
                 "size:%uz|scid:%s|recv_time:%ui|peer_addr:%s|local_addr:%s",
                 packet_in_size, xqc_scid_str(engine, &scid), recv_time,
                 xqc_peer_addr_str(engine, peer_addr, peer_addrlen),
                 xqc_local_addr_str(engine, local_addr, local_addrlen));
 
         ret = xqc_engine_send_reset(engine, &scid, peer_addr, peer_addrlen,
                                     local_addr, local_addrlen, packet_in_size,
                                     user_data);
         if (ret) {
             xqc_log(engine->log, XQC_LOG_ERROR, "|fail to send reset|");
         }
 
         return -XQC_ECONN_NFOUND;
     }
 
 process:
     xqc_log(engine->log, XQC_LOG_INFO, "|==>|conn:%p|size:%uz|state:%s|recv_time:%ui|",
             conn, packet_in_size, xqc_conn_state_2_str(conn->conn_state), recv_time);
 
     if (XQC_UNLIKELY(conn->local_addrlen == 0)) {
         ret = xqc_memcpy_with_cap(conn->local_addr, sizeof(conn->local_addr), 
                                   local_addr, local_addrlen);
         if (ret == XQC_OK) {
             conn->local_addrlen = local_addrlen;
 
         } else {
             xqc_log(conn->log, XQC_LOG_ERROR, 
                     "|local addr too large|addr_len:%d|", (int)local_addrlen);
         }
         xqc_log_event(conn->log, CON_CONNECTION_STARTED, conn, XQC_LOG_LOCAL_EVENT);
     }

    xqc_engine_migr_reclaim_tentative(engine, conn, recv_time);
 
    /* NAT rebinding: handle on both server and client
     * When receiving from a new peer address (same CID), validate via PATH_CHALLENGE. */
    if ((engine->eng_type == XQC_ENGINE_SERVER || engine->eng_type == XQC_ENGINE_CLIENT)
         && (peer_addr != NULL && peer_addrlen != 0)
         && !xqc_is_same_addr_as_any_path(conn, peer_addr))
     {
        xqc_path_ctx_t *path = xqc_conn_find_path_by_scid(conn, &scid);

         size_t spec_budget = 0;
         xqc_bool_t allow_speculative = XQC_FALSE;
         if (engine->config->delay_challenge && path != NULL) {
             allow_speculative = xqc_engine_migr_allow_speculative(engine, conn, path, peer_addr, recv_time, &spec_budget);
         }

         if (!allow_speculative && conn->migr_tentative_active) {
             xqc_engine_migr_cancel_tentative(engine, conn, "fallback");
         }

         if (allow_speculative) {
             if (conn->migr_tentative_active
                 && conn->migr_tentative_path_id != path->path_id)
             {
                 xqc_engine_migr_cancel_tentative(engine, conn, "new tentative");
             }

             if (!conn->migr_tentative_active) {
                 conn->migr_tentative_active = 1;
                 engine->migr_tentative_active++;
             }
             conn->migr_tentative_path_id = path->path_id;
             conn->migr_tentative_deadline = recv_time + 3 * xqc_conn_get_max_pto(conn);
         }

         if(engine->config->delay_challenge && allow_speculative) {
            /* quiet: avoid noisy stdout during NAT rebinding */
             /* set rebinding_addr */
             ret = xqc_memcpy_with_cap(path->rebinding_addr, sizeof(path->rebinding_addr),
                                       peer_addr, peer_addrlen);
             if (ret != XQC_OK) {
                 xqc_log(conn->log, XQC_LOG_ERROR,
                         "|REBINDING|peer addr too large|addr_len:%d|", (int)peer_addrlen);
             } else {
                 path->rebinding_addrlen = peer_addrlen;
                 path->rebinding_check_response = 0;
                 /* optimistically switch to new addr and keep path ACTIVE */
                 xqc_set_path_state(path, XQC_PATH_STATE_ACTIVE);
                 xqc_memcpy(path->peer_addr, path->rebinding_addr, path->rebinding_addrlen);
                 path->peer_addrlen = path->rebinding_addrlen;
                 path->addr_str_len = 0;
                 /* send PATH_CHALLENGE once */
                 ret = xqc_conn_send_path_challenge(conn, path);
                 if (ret != XQC_OK) {
                     xqc_log(engine->log, XQC_LOG_ERROR,
                             "|REBINDING|xqc_conn_send_path_challenge error|conn:%p|path:%ui|ret:%d|",
                             conn, path->path_id, ret);
                     path->rebinding_addrlen = 0;
                 } else {
                     /* downgraded to DEBUG to avoid surfacing in normal runs */
                     xqc_log(conn->log, XQC_LOG_DEBUG,
                         "|REBINDING|path:%ui|send PATH_CHALLENGE|addr:%s|",
                         path->path_id, xqc_path_addr_str(path));
                     path->rebinding_count++;
                     /* set NAT_REBINDING timer with a sane floor */
                     xqc_usec_t pto = xqc_conn_get_max_pto(conn);
                     pto = xqc_max(pto, 20000); /* 20ms minimum */
                     xqc_timer_set(&path->path_send_ctl->path_timer_manager,
                                   XQC_TIMER_NAT_REBINDING, recv_time, 3 * pto);
                            if(engine->config->immediate_resend){
                                xqc_conn_server_resend_immediately(conn, spec_budget); /* 立即重发未确认的数据包 */
                     }
                     /* 迁移后发送一次 PING，促使对端快速回 ACK，解除 inflight≈cwnd 的阻塞 */
                    //  if (xqc_path_send_ping_to_probe(path, XQC_PNS_APP_DATA, XQC_PATH_SPECIFIED_BY_PATH_ID) == XQC_OK) {
                    //      printf(" : Send PING(after rebinding) on path %u\n", path->path_id);
                    //  }
                 }
                 if ((path->rebinding_check_response == 0)
                             && xqc_is_same_addr(peer_addr, (struct sockaddr *)path->rebinding_addr))
                 {
                     /* PATH_RESPONSE recv from rebinding_addr */
                     path->rebinding_check_response = 1;
                     xqc_log(conn->log, XQC_LOG_DEBUG,
                             "|REBINDING|path:%ui|recv_addr = rebinding_addr|check PATH_RESPONSE|",
                             path->path_id);
                 }
             }
         }
         else {
             if ((path != NULL) && (path->path_state == XQC_PATH_STATE_ACTIVE)) {
                 if ((path->rebinding_addrlen == 0)
                     && !xqc_timer_is_set(&path->path_send_ctl->path_timer_manager, XQC_TIMER_NAT_REBINDING))
                 {
                     /* set rebinding_addr & send PATH_CHALLENGE */
                     ret = xqc_memcpy_with_cap(path->rebinding_addr, sizeof(path->rebinding_addr), 
                                               peer_addr, peer_addrlen);
                     if (ret == XQC_OK) {
                         path->rebinding_addrlen = peer_addrlen;
     
                     } else {
                         xqc_log(conn->log, XQC_LOG_ERROR, 
                                 "|REBINDING|peer addr too large|addr_len:%d|", (int)peer_addrlen);
                     }
                     ret = xqc_conn_send_path_challenge(conn, path);
                     if (ret == XQC_OK) {
                         xqc_log(conn->log, XQC_LOG_DEBUG, "|REBINDING|path:%ui|send PATH_CHALLENGE|addr:%s|", path->path_id, xqc_path_addr_str(path));
                         path->rebinding_count++;
                         xqc_usec_t pto = xqc_max(xqc_conn_get_max_pto(conn), 20000);
                         xqc_timer_set(&path->path_send_ctl->path_timer_manager,
                                       XQC_TIMER_NAT_REBINDING, recv_time, 3 * pto);
     
                     } else {
                         xqc_log(engine->log, XQC_LOG_ERROR, "|REBINDING|xqc_conn_send_path_challenge error|conn:%p|path:%ui|ret:%d|", conn, path->path_id, ret);
                         path->rebinding_addrlen = 0;
                     }
     
                 } else if ((path->rebinding_check_response == 0)
                            && xqc_is_same_addr(peer_addr, (struct sockaddr *)path->rebinding_addr))
                 {
                     /* PATH_RESPONSE recv from rebinding_addr */
                     path->rebinding_check_response = 1;
                     xqc_log(conn->log, XQC_LOG_DEBUG, "|REBINDING|path:%ui|recv_addr = rebinding_addr|check PATH_RESPONSE|", path->path_id);
                 }
             }
         }
 
 
     }
     /* process packets */
     ret = xqc_conn_process_packet(conn, packet_in_buf, packet_in_size, recv_time);
 
     conn->rcv_pkt_stats.conn_udp_pkts++;
 
     if (ret) {
         xqc_log(engine->log, XQC_LOG_ERROR, "|fail to process packets|conn:%p|ret:%d|", conn, ret);
         XQC_CONN_ERR(conn, TRA_FRAME_ENCODING_ERROR);
         goto after_process;
     }

    xqc_engine_migr_reclaim_tentative(engine, conn, recv_time);
 
     // 每次只会从一个fd上接收一批数据包，所以这里是ok的
     // 需要识别五元组信息是否和前面的path一致
     // 1个fd，所以只会有一条new_path的frame
     if (conn->conn_type == XQC_CONN_TYPE_SERVER
         && conn->conn_flag & XQC_CONN_FLAG_RECV_NEW_PATH)
     {
         conn->conn_flag &= ~XQC_CONN_FLAG_RECV_NEW_PATH;
         ret = xqc_conn_server_init_path_addr(conn, conn->validating_path_id,
                                              local_addr, local_addrlen,
                                              peer_addr, peer_addrlen);
         if (ret != XQC_OK) {
             xqc_log(engine->log, XQC_LOG_ERROR,
                     "|xqc_conn_update_path_addr error|conn:%p|ret:%d|path:%ui|",
                     conn, ret, conn->validating_path_id);
             goto after_process;
         }
     }
 
     xqc_conn_process_packet_recved_path(conn, &scid, packet_in_size, recv_time);
 
     xqc_timer_set(&conn->conn_timer_manager, XQC_TIMER_CONN_IDLE,
                   recv_time, xqc_conn_get_idle_timeout(conn) * 1000);
 
 after_process:
     xqc_engine_remove_wakeup_queue(engine, conn);
     
     if (xqc_engine_add_active_queue(engine, conn) != XQC_OK) {
         xqc_log(engine->log, XQC_LOG_ERROR, "|xqc_conns_pq_push error|conn:%p|", conn);
         XQC_CONN_ERR(conn, TRA_INTERNAL_ERROR);
         xqc_conn_destroy(conn);
         return -XQC_EFATAL;
     }
 
     /* main logic */
     if (++conn->packet_need_process_count >= XQC_MAX_PACKET_PROCESS_BATCH
         || conn->conn_err != 0 || conn->conn_flag & XQC_CONN_FLAG_NEED_RUN)
     {
         xqc_engine_main_logic_internal(engine);
         if (xqc_engine_conns_hash_find(engine, &scid, 's') == NULL) {
             /* to inform upper module when destroy connection in main logic  */
             return  -XQC_ECONN_NFOUND;
         }
     }
 
     return ret;
 }
 
 
 
 
 
 
 
 
 uint8_t
 xqc_engine_config_get_cid_len(xqc_engine_t *engine)
 {
     return engine->config->cid_len;
 }
 
 
 xqc_int_t
 xqc_engine_add_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
     xqc_app_proto_callbacks_t *ap_cbs, void *alp_ctx)
 {
     /* register alpn in tls context */
     xqc_int_t ret = xqc_tls_ctx_register_alpn(engine->tls_ctx, alpn, alpn_len);
     if (ret != XQC_OK) {
         return ret;
     }
 
     xqc_alpn_registration_t *registration = xqc_calloc(1, sizeof(xqc_alpn_registration_t));
     if (NULL == registration) {
         xqc_log(engine->log, XQC_LOG_ERROR, "|create alpn registration error!");
         return -XQC_EMALLOC;
     }
 
     registration->alpn = xqc_malloc(alpn_len + 1);
     if (NULL == registration->alpn) {
         xqc_log(engine->log, XQC_LOG_ERROR, "|create alpn buffer error!");
         xqc_free(registration);
         return -XQC_EMALLOC;
     }
 
     xqc_init_list_head(&registration->head);
     xqc_memcpy(registration->alpn, alpn, alpn_len);
     registration->alpn[alpn_len] = '\0';
     registration->alpn_len = alpn_len;
     registration->ap_cbs = *ap_cbs;
     registration->alp_ctx = alp_ctx;
 
     xqc_list_add_tail(&registration->head, &engine->alpn_reg_list);
 
     xqc_log(engine->log, XQC_LOG_INFO, "|alpn registered|alpn:%s|", alpn);
     return XQC_OK;
 }
 
 
 xqc_int_t
 xqc_engine_register_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
     xqc_app_proto_callbacks_t *ap_cbs, void *alp_ctx)
 {
     xqc_list_head_t *pos, *next;
     xqc_alpn_registration_t *alpn_reg;
 
     if (NULL == alpn || 0 == alpn_len || alpn_len > XQC_MAX_ALPN_LEN) {
         return -XQC_EPARAM;
     }
 
     /* check if alpn exists */
     xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
         alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
         if (alpn_len == alpn_reg->alpn_len
             && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
         {
             /* if found registration, update */
             alpn_reg->ap_cbs = *ap_cbs;
             alpn_reg->alp_ctx = alp_ctx;
             return XQC_OK;
         }
     }
 
     /* not registered, add into alpn_reg_list */
     return xqc_engine_add_alpn(engine, alpn, alpn_len, ap_cbs, alp_ctx);
 }
 
 void* 
 xqc_engine_get_alpn_ctx(xqc_engine_t *engine, const char *alpn, size_t alpn_len)
 {
     xqc_list_head_t *pos, *next;
     xqc_alpn_registration_t *alpn_reg;
 
     xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
         alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
         if (alpn_reg && alpn_len == alpn_reg->alpn_len
             && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
         {
             return alpn_reg->alp_ctx;
         }
     }
 
     return NULL; 
 }
 
 
 xqc_int_t
 xqc_engine_unregister_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len)
 {
     xqc_list_head_t *pos, *next;
     xqc_alpn_registration_t *alpn_reg;
 
     xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
         alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
         if (alpn_reg && alpn_len == alpn_reg->alpn_len
             && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
         {
             xqc_list_del(&alpn_reg->head);
 
             /* remove registration */
             if (alpn_reg->alpn) {
                 xqc_free(alpn_reg->alpn);
             }
 
             xqc_free(alpn_reg);
 
             return xqc_tls_ctx_unregister_alpn(engine->tls_ctx, alpn, alpn_len);
         }
     }
 
     return -XQC_EALPN_NOT_REGISTERED;
 }
 
 
 xqc_int_t
 xqc_engine_get_alpn_callbacks(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
     xqc_app_proto_callbacks_t *cbs)
 {
     xqc_list_head_t *pos, *next;
     xqc_alpn_registration_t *alpn_reg;
 
     if (NULL == alpn || 0 == alpn_len) {
         return -XQC_EPARAM;
     }
 
     xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
         alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
         if (alpn_len == alpn_reg->alpn_len
             && xqc_memcmp(alpn, alpn_reg->alpn, alpn_len) == 0)
         {
             /* if found registration, update */
             *cbs = alpn_reg->ap_cbs;
             return XQC_OK;
         }
     }
 
     return -XQC_EALPN_NOT_SUPPORTED;
 }
 
 void
 xqc_engine_free_alpn_list(xqc_engine_t *engine)
 {
     /* free alpn registrations */
     xqc_list_head_t *pos, *next;
     xqc_alpn_registration_t *alpn_reg;
     xqc_list_for_each_safe(pos, next, &engine->alpn_reg_list) {
         alpn_reg = xqc_list_entry(pos, xqc_alpn_registration_t, head);
 
         if (alpn_reg) {
             if (alpn_reg->alpn) {
                 xqc_free(alpn_reg->alpn);
             }
 
             xqc_list_del(&alpn_reg->head);
             xqc_free(alpn_reg);
         }
     }
 }
 
 xqc_bool_t
 xqc_engine_is_sendmmsg_on(xqc_engine_t *engine, xqc_connection_t *conn)
 {
     return engine->config->sendmmsg_on
         && (engine->transport_cbs.write_mmsg || engine->transport_cbs.write_mmsg_ex)
         && (!conn->conn_settings.disable_send_mmsg);
 }
 
 
 void* 
 xqc_engine_get_priv_ctx(xqc_engine_t *engine)
 {
     return engine->priv_ctx;
 }
 
 
 xqc_int_t 
 xqc_engine_set_priv_ctx(xqc_engine_t *engine, void *priv_ctx)
 {
     if (engine->priv_ctx) {
         return -XQC_ESTATE;
     }
 
     engine->priv_ctx = priv_ctx;
     return XQC_OK;
 }
 
 
 xqc_int_t 
 xqc_engine_add_wakeup_queue(xqc_engine_t *engine, xqc_connection_t *conn)
 { 
     if (!(conn->conn_flag & (XQC_CONN_FLAG_WAIT_WAKEUP | XQC_CONN_FLAG_TICKING))) {
         if(xqc_conns_pq_push(engine->conns_wait_wakeup_pq, 
                              conn, conn->next_tick_time) != XQC_OK)
         {
             return -XQC_EMALLOC;
         }
         xqc_log(conn->log, XQC_LOG_DEBUG, "|next_tick_time:%ui|", conn->next_tick_time);
         conn->conn_flag |= XQC_CONN_FLAG_WAIT_WAKEUP;
     } 
     return XQC_OK;
 }
 
 xqc_int_t 
 xqc_engine_remove_wakeup_queue(xqc_engine_t *engine, xqc_connection_t *conn)
 {
     if ((conn->conn_flag & XQC_CONN_FLAG_WAIT_WAKEUP)) {
         xqc_log(conn->log, XQC_LOG_DEBUG, "|next_tick_time:%ui|pq_index:%ud|", conn->next_tick_time, conn->wakeup_pq_index);
         xqc_conns_pq_remove(engine->conns_wait_wakeup_pq, conn);
         
         conn->conn_flag &= ~XQC_CONN_FLAG_WAIT_WAKEUP;
     }
     return XQC_OK;
 }
 
 xqc_int_t 
 xqc_engine_add_active_queue(xqc_engine_t *engine, xqc_connection_t *conn)
 {
     xqc_int_t ret = XQC_OK;
     if (!(conn->conn_flag & (XQC_CONN_FLAG_WAIT_WAKEUP | XQC_CONN_FLAG_TICKING))) {
         ret = xqc_conns_pq_push(engine->conns_active_pq, 
                                 conn, conn->last_ticked_time);
         if (ret == 0) {
             xqc_log(conn->log, XQC_LOG_DEBUG, "|last_ticked_time:%ui|", conn->last_ticked_time);
             conn->conn_flag |= XQC_CONN_FLAG_TICKING;
             ret = XQC_OK;
         }
     }
     return ret;
 }
 
 xqc_int_t 
 xqc_engine_remove_active_queue(xqc_engine_t *engine, xqc_connection_t *conn)
 {
     if ((conn->conn_flag & XQC_CONN_FLAG_TICKING)) {
         xqc_log(conn->log, XQC_LOG_DEBUG, "|last_ticked_time:%ui|pd_index:%ud|", conn->last_ticked_time, conn->wakeup_pq_index);
         xqc_conns_pq_remove(engine->conns_active_pq, conn);
         conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
     }
     return XQC_OK;
 }
 
