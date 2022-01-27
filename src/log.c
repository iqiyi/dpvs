/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <string.h>
#include <syslog.h>
#include <rte_mempool.h>
#include <signal.h>
#include "netif.h"
#include "sys_time.h"
#include "log.h"
#include "dpdk.h"
#include "global_data.h"

#define DPVS_LOG_RING_SIZE      4096

#define LOG_INTERNAL_TIME       5
#define LOG_SLOW_INTERNAL_TIME  (60*10)

#define TIMEZONE        0
#define DAY             (60*60*24)
#define YEARFIRST       2001
#define YEARSTART       (365*(YEARFIRST-1970) + 8)
#define YEAR400         (365*4*100 + (4*(100/4 - 1) + 1))
#define YEAR100         (365*100 + (100/4 - 1))
#define YEAR004         (365*4 + 1)
#define YEAR001         365

bool g_dpvs_log_async_mode = false;
lcoreid_t g_dpvs_log_core = DPVS_MAX_LCORE;
uint8_t g_dpvs_log_tslen = 0;                   // timestamp length

static bool dpvs_log_thread_ready = false;
static int log_internal = LOG_INTERNAL_TIME;
static log_buf_t w_buf;
static log_stats_t log_stats_info[DPVS_MAX_LCORE];
static struct rte_ring *log_ring;
static struct rte_mempool *dp_vs_log_pool;
static int log_pool_size  = DPVS_LOG_POOL_SIZE_DEF;
static int log_pool_cache = DPVS_LOG_CACHE_SIZE_DEF;

void dpvs_set_log_pool_size(int size)
{
    assert(size > DPVS_LOG_POOL_SIZE_MIN);
    log_pool_size = size;
}

static int log_send(struct dpvs_log *msg)
{
    int res;

    res = rte_ring_enqueue(log_ring, msg);
    if (unlikely(-EDQUOT == res)) {
        return EDPVS_DPDKAPIFAIL;
    } else if (unlikely(-ENOBUFS == res)) {
        return EDPVS_DPDKAPIFAIL;
    } else if (res) {
        return EDPVS_DPDKAPIFAIL;
    }
    return EDPVS_OK;
}

static inline void dpvs_log_thread_lcore_set(lcoreid_t core_num)
{
    g_dpvs_log_core = core_num;
}

static struct dpvs_log *dpvs_log_msg_make(int level, int type, lcoreid_t cid,
        size_t len, const void *data)
{
    struct dpvs_log *log_msg;

    if (unlikely(rte_mempool_get(dp_vs_log_pool, (void **)&log_msg) != 0))
        return NULL;

    if (unlikely(len + sizeof(struct dpvs_log) > DPVS_LOG_MAX_LINE_LEN))
        len = DPVS_LOG_MAX_LINE_LEN - sizeof(struct dpvs_log); // truncated

    log_msg->log_level = level;
    log_msg->log_type = type;
    log_msg->cid = cid;
    log_msg->log_len = len;
    if (len)
        rte_memcpy(log_msg->data, data, len);

    return log_msg;
}

static void dpvs_log_free(struct dpvs_log *log_msg)
{
    if (!log_msg)
        return;
    rte_mempool_put(dp_vs_log_pool, log_msg);
}

static unsigned int log_BKDRHash(char *str, int len)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;

    while (len--) {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}

static uint64_t log_get_time(char *time, int time_len)
{
    time_t tm;
    long sec = 0;
    int yy = 0, mm = 0, dd = 0, hh = 0, mi = 0, ss = 0;
    int ad = 0;
    int y400 = 0, y100 = 0, y004 = 0, y001 = 0;
    int m[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int i;

    tm = sys_current_time();
    sec = tm + (60 * 60) * TIMEZONE;
    ad = sec / DAY;
    ad = ad - YEARSTART;
    y400 = ad / YEAR400;
    y100 = (ad - y400 * YEAR400) / YEAR100;
    y004 = (ad - y400 * YEAR400 - y100 * YEAR100) / YEAR004;
    y001 = (ad - y400 * YEAR400 - y100 * YEAR100 - y004 * YEAR004) / YEAR001;
    yy = y400 * 4 * 100 + y100 * 100 + y004 * 4 + y001 * 1 + YEARFIRST;
    dd = (ad - y400 * YEAR400 - y100 * YEAR100 - y004 * YEAR004) % YEAR001 + 1;

    if (0 == yy % 1000) {
        if (0 == (yy / 1000) % 4 ) {
            m[1] = 29;
        }
    } else {
        if (0 == yy % 4) {
            m[1] = 29;
        }
    }

    for (i = 0; i < 12; i++) {
        if(dd - m[i] <= 0) {
            break;
        } else {
            dd = dd -m[i];
        }
    }

    mm = i + 1;
    hh = sec / (60 * 60) % 24;
    mi = sec / 60 - sec / (60 * 60) * 60;
    ss = sec - sec / 60 * 60;
    snprintf(time, time_len, "%04d-%02d-%02d %02d:%02d:%02d", yy, mm, dd, hh, mi, ss);
    return tm;
}

static int dpvs_async_log(uint32_t level, uint32_t logtype,
        uint64_t now, lcoreid_t cid, char *log, size_t len, size_t tslen)
{
    struct dpvs_log *msg;
    unsigned int log_hash_new;

    log_hash_new = log_BKDRHash(log + tslen, len);
    if ((log_hash_new == log_stats_info[cid].log_hash) &&
            (now - log_stats_info[cid].log_begin < log_internal * g_cycles_per_sec)) {
        log_stats_info[cid].missed++;
        return EDPVS_EXIST;
    }

    /* add time info and send out to log ring */
    if (tslen) {
        log_get_time(log, LOG_SYS_TIME_LEN);
        log[LOG_SYS_TIME_LEN - 1] = ' ';
        len += LOG_SYS_TIME_LEN;
    }
    log_stats_info[cid].log_hash = log_hash_new;
    log_stats_info[cid].log_begin = now;

    msg = dpvs_log_msg_make(level, logtype, cid, len, log);
    if (unlikely(!msg))
        return EDPVS_NOMEM;

    if (log_send(msg) != EDPVS_OK) {
        dpvs_log_free(msg);
        /* log ring is full, need to set limit rate */
        // fprintf(stderr, "log ring is full !\n");
        log_stats_info[cid].slow = 1;
        log_stats_info[cid].slow_begin = now;
        return EDPVS_OVERLOAD;
    }
    return EDPVS_OK;
}

int dpvs_log(uint32_t level, uint32_t logtype, const char *func, int line, const char *format, ...)
{
    va_list ap;
    lcoreid_t cid;
    uint64_t now;
    size_t capa, len = 0, tslen = g_dpvs_log_tslen;
    char log_buf[DPVS_LOG_MAX_LINE_LEN];

    if (level > rte_log_get_global_level())
        return EDPVS_INVAL;

    va_start(ap, format);

    do {
        if (!g_dpvs_log_async_mode || !g_dpvs_log_core || !dpvs_log_thread_ready) {
            rte_vlog(level, logtype, format, ap);
            break;
        }
        /* async log is not used for ctrl message */
        if (logtype != RTE_LOGTYPE_USER1) {
            rte_vlog(level, logtype, format, ap);
            break;
        }

        now = rte_get_timer_cycles();
        cid = rte_lcore_id();
        capa = sizeof(log_buf) - tslen;
        if (log_stats_info[cid].slow) {
            /* set log limit rate to 5 sec and keep for 10 mins */
            if (now - log_stats_info[cid].slow_begin > LOG_SLOW_INTERNAL_TIME * g_cycles_per_sec) {
                log_stats_info[cid].slow = 0;
            }
            if ((now - log_stats_info[cid].log_begin) < log_internal * g_cycles_per_sec) {
                log_stats_info[cid].missed++;
                break;
            }
            /* just output func and line if log is too fast */
            len = snprintf(log_buf + tslen, capa, "%s:%d\n", func, line);
            if (unlikely(len > capa))
                len = capa; // truncated
            dpvs_async_log(level, logtype, now, cid, log_buf, len, tslen);
            break;
        }
        len = vsnprintf(log_buf + tslen, sizeof(log_buf) - tslen, format, ap);
        if (unlikely(len > capa))
            len = capa; // truncated
        dpvs_async_log(level, logtype, now, cid, log_buf, len, tslen);
    } while (0);

    va_end(ap);
    return EDPVS_OK;
}

static void log_buf_flush(FILE *f)
{
    if (f == NULL) {
        w_buf.buf[w_buf.pos] = '\0';
        syslog(w_buf.level, "%s", w_buf.buf);
    } else {
        fwrite(w_buf.buf, w_buf.pos, sizeof(w_buf.buf[0]), f);
        fflush(f);
    }
    w_buf.pos = 0;
}

static inline void log_buf_timeout_flush(FILE *f, int timeout, uint64_t now)
{
    if (unlikely(w_buf.pos && (now - w_buf.time
                    >= timeout * g_cycles_per_sec))) {
        log_buf_flush(f);
    }
}

static void log_slave_process(void)
{
    struct dpvs_log *msg_log;
    uint64_t now = rte_get_timer_cycles();
    FILE *f = rte_log_get_stream();

    /* dequeue LOG from ring, no lock for ring and w_buf */
    while (0 == rte_ring_dequeue(log_ring, (void **)&msg_log)) {
        if (w_buf.pos + msg_log->log_len >= LOG_BUF_MAX_LEN) {
            log_buf_flush(f);
        }
        if (!w_buf.pos) {
            w_buf.level = msg_log->log_level - 1;
            w_buf.time = now;
        }
        strncpy(w_buf.buf + w_buf.pos, msg_log->data, sizeof(w_buf.buf) - w_buf.pos);
        w_buf.pos += msg_log->log_len;
        log_buf_timeout_flush(f, log_internal, now);
        dpvs_log_free(msg_log);
    }
    log_buf_timeout_flush(f, log_internal, now);
}

static void log_slave_loop_func(void)
{
    dpvs_log_thread_ready = true;

    while (1) {
        log_slave_process();
    }
}

static void log_signal_handler(int signum)
{
    if (signum == SIGABRT || signum == SIGSEGV) {
        fprintf(stderr, "\nSignal %d received, preparing to exit...\n", signum);
    }
    log_slave_process();
    log_buf_flush(rte_log_get_stream());
    signal(signum, SIG_DFL);
    kill(getpid(), signum);
}

int log_slave_init(void)
{
    char ring_name[16];
    int lcore_id;
    char log_pool_name[32];

    if (!g_dpvs_log_async_mode)
        return EDPVS_DISABLED;

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_get_lcore_state(lcore_id) == FINISHED) {
            rte_eal_wait_lcore(lcore_id);
            dpvs_log_thread_lcore_set(lcore_id);
            break;
        }
    }
    if (!rte_lcore_is_enabled(lcore_id))
        return EDPVS_NONEALCORE;
    if (lcore_id >= DPVS_MAX_LCORE || g_lcore_role[lcore_id] != LCORE_ROLE_IDLE)
        return EDPVS_BUSY;

    snprintf(ring_name, sizeof(ring_name), "log_ring_w%d", g_dpvs_log_core);
    log_ring = rte_ring_create(ring_name, DPVS_LOG_RING_SIZE,
                   SOCKET_ID_ANY , RING_F_SC_DEQ);
    if (unlikely(NULL == log_ring)) {
        fprintf(stderr, "fail to init log slave core\n");
        return EDPVS_DPDKAPIFAIL;
    }
    /* use memory pool for log msg */
    snprintf(log_pool_name, sizeof(log_pool_name), "log_msg_pool");
    dp_vs_log_pool = rte_mempool_create(log_pool_name,
                                log_pool_size,
                                DPVS_LOG_MAX_LINE_LEN,
                                log_pool_cache,
                                0, NULL, NULL, NULL, NULL,
                                0, 0);
    if (!dp_vs_log_pool) {
        return EDPVS_DPDKAPIFAIL;
    }

    signal(SIGABRT, log_signal_handler);
    signal(SIGSEGV, log_signal_handler);

    rte_eal_remote_launch((lcore_function_t *)log_slave_loop_func, NULL, lcore_id);

    return EDPVS_OK;
}
