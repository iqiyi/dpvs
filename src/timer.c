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
/*
 * timer.c: timer for DPVS.
 *
 * raychen@qiyi.com, Apr 2016, initial.
 * raychen@qiyi.com, Jul 2017, refator with size/level configurable wheels,
 *                             instead of fixed size ms/sec/min wheels.
 */
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include <assert.h>
#include "list.h"
#include "conf/common.h"
#include "timer.h"
#include "dpdk.h"
#include "rte_timer.h"
#include "rte_spinlock.h"
#include "parser/parser.h"
#include "global_data.h"

#ifdef CONFIG_TIMER_DEBUG
#include "debug.h"
#endif

#define DTIMER
#define RTE_LOGTYPE_DTIMER      RTE_LOGTYPE_USER1

/*
 * the use case of dpvs timer is huge number of connections has concentrated
 * timeouts like 120s/60s, while other timeout values are not that much.
 *
 * to prevent too many timers need migrated from higher level to lower,
 * which leads to performance issue, timer need a big "first" level wheel
 * (hash) to "cover" most (millions of) connections.
 *
 * we can use different hash size for levels, consider hashs of non-first
 * level can be much smaller. but let's make things easier, pick up same size,
 * just assuming the memory is big enough.
 */

#define DPVS_TIMER_HZ           1000

/*
 * with 1000hz, if LEVEL_SIZE is 2<<18 and LEVEL_DEPTH is 2:
 * it's about 524s for first wheel and 8.7 years for all wheels.
 */
/* __NOTE__: make sure (LEVEL_SIZE ** LEVEL_DEPTH) > TIMER_MAX_TICKS. */
#define LEVEL_SIZE              (2<<18)
#define LEVEL_DEPTH             2

/* about 49 days with 1000hz, see dpvs_tick_t */
#define TIMER_MAX_TICKS         0xffffffff
#define TIMER_MAX_SECS          (TIMER_MAX_TICKS / DPVS_TIMER_HZ)

struct timer_scheduler {
    /* wheels and cursors */
    rte_spinlock_t      lock;
    uint32_t            cursors[LEVEL_DEPTH];
    struct list_head    *hashs[LEVEL_DEPTH];

    /* leverage dpdk rte_timer to drive us */
    struct rte_timer    rte_tim;
};

/* per-core timer. */
static RTE_DEFINE_PER_LCORE(struct timer_scheduler, timer_sched);
/* global timer. */
static struct timer_scheduler g_timer_sched;


static inline void timer_sched_lock(struct timer_scheduler *sched)
{
    if (unlikely(sched == &g_timer_sched))
        rte_spinlock_lock(&sched->lock);
    return;
}

static inline void timer_sched_unlock(struct timer_scheduler *sched)
{
    if (unlikely(sched == &g_timer_sched))
        rte_spinlock_unlock(&sched->lock);
    return;
}

dpvs_tick_t timeval_to_ticks(const struct timeval *tv)
{
    uint64_t ticks;

    ticks = tv->tv_sec * DPVS_TIMER_HZ + \
            tv->tv_usec * DPVS_TIMER_HZ / 1000000;

    if (unlikely(ticks >= TIMER_MAX_TICKS))
        return TIMER_MAX_TICKS;

    return (dpvs_tick_t)ticks;
}

void ticks_to_timeval(const dpvs_tick_t ticks, struct timeval *tv)
{
    tv->tv_sec = ticks / DPVS_TIMER_HZ;
    tv->tv_usec = ticks % DPVS_TIMER_HZ * 1000000 / DPVS_TIMER_HZ;
}

/* ticks for each level's step */
static inline dpvs_tick_t get_level_ticks(int level)
{
    dpvs_tick_t ticks = 1;
    assert(level >= 0 && level < LEVEL_DEPTH);

    while (--level >= 0)
        ticks *= LEVEL_SIZE;

    return ticks;
}

static inline bool timer_pending(const struct dpvs_timer *timer)
{
    return (timer->list.prev != LIST_POISON2
            && timer->list.prev != NULL
            && timer->list.prev != &timer->list);
}

/* call me with lock */
static int __dpvs_timer_sched(struct timer_scheduler *sched,
                              struct dpvs_timer *timer, struct timeval *delay,
                              dpvs_timer_cb_t handler, void *arg, bool period)
{
    uint32_t off, hash;
    int level;

    assert(timer);

#ifdef CONFIG_TIMER_DEBUG
    /* just for debug */
    if (unlikely((uint64_t)handler > 0x7ffffffffULL)) {
        char trace[8192];
        dpvs_backtrace(trace, sizeof(trace));
        RTE_LOG(WARNING, DTIMER, "[%02d]: timer %p new handler possibly invalid: %p -> %p\n%s",
                rte_lcore_id(), timer, timer->handler, handler, trace);
    }
    if (unlikely(timer->handler && timer->handler != handler)) {
        char trace[8192];
        dpvs_backtrace(trace, sizeof(trace));
        RTE_LOG(WARNING, DTIMER, "[%02d]: timer %p handler possibly changed maliciously: %p ->%p\n%s",
                rte_lcore_id(), timer, timer->handler, handler, trace);
    }
#endif

    assert(delay && handler);

    if (timer_pending(timer))
        RTE_LOG(WARNING, DTIMER, "schedule a pending timer ?\n");

    timer->handler = handler;
    timer->priv = arg;
    timer->is_period = period;
    timer->delay = timeval_to_ticks(delay);

    if (unlikely(timer->delay >= TIMER_MAX_TICKS)) {
        RTE_LOG(WARNING, DTIMER, "exceed timer range\n");
        return EDPVS_INVAL;
    }

    /*
     * to schedule a 0 delay timer is not make sence.
     * and it will never stopped (periodic) or never triggered (one-shut).
     */
    if (unlikely(!timer->delay)) {
        RTE_LOG(INFO, DTIMER, "trigger 0 delay timer at next tick.\n");
        timer->delay = 1;
    }

    timer->left = timer->delay;
    /* add to corresponding wheel, from higher level to lower. */
    for (level = LEVEL_DEPTH - 1; level >= 0; level--) {
        off = timer->delay / get_level_ticks(level);
        if (off > 0) {
            hash = (sched->cursors[level] + off) % LEVEL_SIZE;
            list_add_tail(&timer->list, &sched->hashs[level][hash]);
#ifdef CONFIG_TIMER_DEBUG
            assert(timer->handler == handler);
#endif
            /* store the remainder */
            timer->left = timer->left % get_level_ticks(level);
            for (level = level - 1; level >= 0; level--)
                timer->left += sched->cursors[level] * get_level_ticks(level);
            return EDPVS_OK;
        }
    }

    /* not adopted by any wheel (never happend) */
    RTE_LOG(WARNING, DTIMER, "unexpected error\n");
    return EDPVS_INVAL;
}

/* call me with lock */
static void __time_now(struct timer_scheduler *sched, struct timeval *now)
{
    dpvs_tick_t ticks = 0;
    int l;

    for (l = LEVEL_DEPTH - 1; l >= 0; l--)
        ticks += sched->cursors[l] * get_level_ticks(l);
    ticks_to_timeval(ticks, now);
}

static void timer_expire(struct timer_scheduler *sched, struct dpvs_timer *timer)
{
    dpvs_timer_cb_t handler;
    void *priv;
    int err;
    struct timeval delay;
    assert(timer && timer->handler);

    /* remove from hash table first, since timer may
     * set by handler, could not remove it after it. */
    handler = timer->handler;
    priv    = timer->priv;
    if (timer_pending(timer))
        list_del(&timer->list);

#ifdef CONFIG_TIMER_DEBUG
    if (unlikely(!handler || (uint64_t)handler > 0x7ffffffffULL)) {
        char trace[8192];
        dpvs_backtrace(trace, sizeof(trace));
        RTE_LOG(WARNING, DTIMER, "[%02d]: invalid timer(%p) handler "
                "-- name:%s, handler:%p, priv:%p, trace:\n%s",
                rte_lcore_id(), timer, timer->name, timer->handler,
                timer->priv, trace);
    }
#endif

    err = handler(priv);

    if (err != DTIMER_OK || !timer->is_period)
        return;

    /* re-schedule for periodic timer */
    ticks_to_timeval(timer->delay, &delay);
    err = __dpvs_timer_sched(sched, timer, &delay, timer->handler,
                             timer->priv, timer->is_period);
    if (err != EDPVS_OK)
        RTE_LOG(ERR, DTIMER, "%s: fail to re-schedule\n", __func__);
}

#ifdef CONFIG_TIMER_MEASURE
static inline void deviation_measure(void)
{
    static struct timeval tv_prev[DPVS_MAX_LCORE];
    static uint32_t count[DPVS_MAX_LCORE];
    struct timeval tv_now, tv_elapse;

    if (count[rte_lcore_id()]++ % DPVS_TIMER_HZ == 0) {
        gettimeofday(&tv_now, NULL);
        timersub(&tv_now, &tv_prev[rte_lcore_id()], &tv_elapse);
        tv_prev[rte_lcore_id()] = tv_now;

        printf("[%d] %s: round %u elapse %6lu.%06lu\n",
                rte_lcore_id(), __func__, count[rte_lcore_id()] - 1,
                tv_elapse.tv_sec, tv_elapse.tv_usec);
    }
}
#endif

/*
 * it takes exactly one tick between invokations,
 * except system (including timer handles) takes more than
 * one tick to get rte_timer_manage() called.
 * we needn't calculate ticks elapsed by ourself.
 */
static void rte_timer_tick_cb(struct rte_timer *tim, void *arg)
{
    struct timer_scheduler *sched = arg;
    struct dpvs_timer *timer;
    struct list_head *head;
    uint64_t hash, off;
    int level, lower;
    uint32_t *cursor;
    bool carry;

    assert(tim && sched);

#ifdef CONFIG_TIMER_MEASURE
    deviation_measure();
#endif

    /* drive timer to move and handle expired timers. */
    timer_sched_lock(sched);
    for (level = 0; level < LEVEL_DEPTH; level++) {
        cursor = &sched->cursors[level];
        (*cursor)++;

        if (likely(*cursor < LEVEL_SIZE)) {
            carry = false;
        } else {
            /* reset the cursor and handle next level later. */
            *cursor = 0;
            carry = true;
        }

        head = &sched->hashs[level][*cursor];
        while (!list_empty(head)) {
            timer = list_first_entry(head, struct dpvs_timer, list);
            /* is all lower levels ticks empty ? */
            if (!timer->left) {
                timer_expire(sched, timer);
            } else {
                /* drop to lower level wheel, note it may not drop to
                 * "next" lower level wheel. */
                list_del(&timer->list);

                for (lower = level; lower >= 0; lower--) {
                    off = timer->left / get_level_ticks(lower);
                    if (off > 0) {
                        hash = (sched->cursors[lower] + off) % LEVEL_SIZE;
                        list_add_tail(&timer->list, &sched->hashs[lower][hash]);
                        /*
                         * store the remainder
                         * all lower cursor must be 0
                         * so it's not necessary to calculate the offset
                         * see __dpvs_timer_sched for details
                         */
                        timer->left = timer->left % get_level_ticks(lower);
                        break;
                    }
                }
            }
        }
        if (!carry)
            break;
    }
    timer_sched_unlock(sched);
}

static int timer_init_schedler(struct timer_scheduler *sched, lcoreid_t cid)
{
    int i, l;

    rte_spinlock_init(&sched->lock);


    timer_sched_lock(sched);
    for (l = 0; l < LEVEL_DEPTH; l++) {
        sched->cursors[l] = 0;

        sched->hashs[l] = rte_malloc(NULL,
                                     sizeof(struct list_head) * LEVEL_SIZE, 0);
        if (!sched->hashs[l]) {
            RTE_LOG(ERR, DTIMER, "[%02d] no memory.\n", cid);
            timer_sched_unlock(sched);
            return EDPVS_NOMEM;
        }

        for (i = 0; i < LEVEL_SIZE; i++)
            INIT_LIST_HEAD(&sched->hashs[l][i]);
    }
    timer_sched_unlock(sched);

    rte_timer_init(&sched->rte_tim);
    /* ticks should be exactly same with precision */
    if (rte_timer_reset(&sched->rte_tim, g_cycles_per_sec / DPVS_TIMER_HZ,
                        PERIODICAL, cid, rte_timer_tick_cb, sched) != 0) {
        RTE_LOG(ERR, DTIMER, "[%02d] fail to reset rte timer.\n", cid);
        return EDPVS_INVAL;
    }

    RTE_LOG(DEBUG, DTIMER, "[%02d] timer initialized %p.\n", cid, sched);
    return EDPVS_OK;
}

static int timer_term_schedler(struct timer_scheduler *sched)
{
    struct dpvs_timer *timer, *next;
    int i, l;

    rte_timer_stop_sync(&sched->rte_tim);

    /* delete all pending timers */
    timer_sched_lock(sched);

    for (l = 0; l < LEVEL_DEPTH; l++) {
        for (i = 0; i < LEVEL_SIZE; i++) {
            list_for_each_entry_safe(timer, next, &sched->hashs[l][i], list)
                list_del(&timer->list);
        }

        rte_free(sched->hashs[l]);
        sched->cursors[l] = 0;
    }

    timer_sched_unlock(sched);

    return EDPVS_OK;
}

static int timer_lcore_init(void *arg)
{
    lcoreid_t cid = rte_lcore_id();

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    return timer_init_schedler(&RTE_PER_LCORE(timer_sched), rte_lcore_id());
}

static int timer_lcore_term(void *arg)
{
    lcoreid_t cid = rte_lcore_id();

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    return timer_term_schedler(&RTE_PER_LCORE(timer_sched));
}

int dpvs_timer_init(void)
{
    lcoreid_t cid;
    int err;

    /* per-lcore timer */
    rte_eal_mp_remote_launch(timer_lcore_init, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        err = rte_eal_wait_lcore(cid);
        if (err < 0) {
            RTE_LOG(ERR, DTIMER, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
            return err;
        }
    }

    /* global timer */
    return timer_init_schedler(&g_timer_sched, rte_get_main_lcore());
}

int dpvs_timer_term(void)
{
    lcoreid_t cid;
    int err;

    /* per-lcore timer */
    rte_eal_mp_remote_launch(timer_lcore_term, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        err = rte_eal_wait_lcore(cid);
        if (err < 0) {
            RTE_LOG(WARNING, DTIMER, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    /* global timer */
    return timer_term_schedler(&g_timer_sched);
}

static inline struct timer_scheduler *this_lcore_sched(bool global)
{
    /* any lcore (including master and slaves) can use global timer,
     * but only slave lcores can use per-lcore timer. */
    if (!global && rte_lcore_id() == rte_get_main_lcore()) {
        RTE_LOG(ERR, DTIMER, "try get per-lcore timer from master\n");
        return NULL;
    }
    return global ? &g_timer_sched : &RTE_PER_LCORE(timer_sched);
}

int dpvs_timer_sched_nolock(struct dpvs_timer *timer, struct timeval *delay,
                     dpvs_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay || !handler
            || delay->tv_sec >= TIMER_MAX_SECS)
        return EDPVS_INVAL;

    err = __dpvs_timer_sched(sched, timer, delay, handler, arg, false);

    return err;
}

int dpvs_timer_sched(struct dpvs_timer *timer, struct timeval *delay,
                     dpvs_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay || !handler
            || delay->tv_sec >= TIMER_MAX_SECS)
        return EDPVS_INVAL;

    timer_sched_lock(sched);
    err = __dpvs_timer_sched(sched, timer, delay, handler, arg, false);
    timer_sched_unlock(sched);

    return err;
}

int dpvs_timer_sched_abs_nolock(struct dpvs_timer *timer, struct timeval *expire,
                         dpvs_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;
    struct timeval now, delta;

    if (!sched || !timer || !expire || !handler)
        return EDPVS_INVAL;

    __time_now(sched, &now);
    if (!timercmp(expire, &now, >)) {
        /* consider the diff between user call dpvs_time_now() and NOW,
         * it's possible timer already expired although rarely.
         * to schedule an 1-tick timer ? no, let's trigger it now.
         * note we cannot call timer_expire() direcly. */
        handler(arg);
        return EDPVS_OK;
    } else {
        timersub(expire, &now, &delta);
        if (delta.tv_sec >= TIMER_MAX_SECS) {
            return EDPVS_INVAL;
        }
    }

    err = __dpvs_timer_sched(sched, timer, &delta, handler, arg, false);

    return err;
}

int dpvs_timer_sched_abs(struct dpvs_timer *timer, struct timeval *expire,
                         dpvs_timer_cb_t handler, void *arg, bool global)
{
    int err;
    struct timer_scheduler *sched = this_lcore_sched(global);

    timer_sched_lock(sched);
    err = dpvs_timer_sched_abs_nolock(timer, expire, handler, arg, global);
    timer_sched_unlock(sched);

    return err;
}

int dpvs_timer_sched_period_nolock(struct dpvs_timer *timer,
        struct timeval *intv, dpvs_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !intv || !handler || intv->tv_sec >= TIMER_MAX_SECS)
        return EDPVS_INVAL;

    err = __dpvs_timer_sched(sched, timer, intv, handler, arg, true);

    return err;
}

int dpvs_timer_sched_period(struct dpvs_timer *timer, struct timeval *intv,
                            dpvs_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !intv || !handler || intv->tv_sec >= TIMER_MAX_SECS)
        return EDPVS_INVAL;

    timer_sched_lock(sched);
    err = __dpvs_timer_sched(sched, timer, intv, handler, arg, true);
    timer_sched_unlock(sched);

    return err;
}

int dpvs_timer_cancel_nolock(struct dpvs_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);

    if (!sched || !timer)
        return EDPVS_INVAL;

    if (timer_pending(timer))
        list_del(&timer->list);

    return EDPVS_OK;
}

int dpvs_timer_cancel(struct dpvs_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);

    if (!sched || !timer)
        return EDPVS_INVAL;

    timer_sched_lock(sched);
    if (timer_pending(timer))
        list_del(&timer->list);
    timer_sched_unlock(sched);

    return EDPVS_OK;
}

int dpvs_timer_reset_nolock(struct dpvs_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    struct timeval delay;
    int err;

    if (!sched || !timer)
        return EDPVS_INVAL;

    if (timer_pending(timer))
        list_del(&timer->list);

    ticks_to_timeval(timer->delay, &delay);
    err = __dpvs_timer_sched(sched, timer, &delay, timer->handler,
                             timer->priv, timer->is_period);
    return err;
}

int dpvs_timer_reset(struct dpvs_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    struct timeval delay;
    int err;

    if (!sched || !timer)
        return EDPVS_INVAL;

    timer_sched_lock(sched);
    if (timer_pending(timer))
        list_del(&timer->list);

    ticks_to_timeval(timer->delay, &delay);
    err = __dpvs_timer_sched(sched, timer, &delay, timer->handler,
                             timer->priv, timer->is_period);
    timer_sched_unlock(sched);

    return err;
}

int dpvs_timer_update_nolock(struct dpvs_timer *timer, struct timeval *delay, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay)
        return EDPVS_INVAL;

    if (timer_pending(timer))
        list_del(&timer->list);
    err = __dpvs_timer_sched(sched, timer, delay,
            timer->handler, timer->priv, timer->is_period);

    return err;
}

int dpvs_timer_update(struct dpvs_timer *timer, struct timeval *delay, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay)
        return EDPVS_INVAL;

    timer_sched_lock(sched);
    if (timer_pending(timer))
        list_del(&timer->list);
    err = __dpvs_timer_sched(sched, timer, delay,
            timer->handler, timer->priv, timer->is_period);
    timer_sched_unlock(sched);

    return err;
}

int dpvs_time_now_nolock(struct timeval *now, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    if (!sched || !now)
        return EDPVS_INVAL;

    __time_now(sched, now);

    return EDPVS_OK;
}

int dpvs_time_now(struct timeval *now, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    if (!sched || !now)
        return EDPVS_INVAL;

    timer_sched_lock(sched);
    __time_now(sched, now);
    timer_sched_unlock(sched);

    return EDPVS_OK;
}

void dpvs_time_rand_delay(struct timeval *tv, long delay_us)
{
    assert(delay_us > 0);

    long rand;
    uint64_t t_us;

    /* we use lrand48 instead of random for performance consideration.
     * lrand48 is not thread-safe, but it does not matter here. */
    rand = lrand48() % delay_us;
    t_us = tv->tv_sec * 1000000 + tv->tv_usec + rand;

    tv->tv_sec = t_us / 1000000;
    tv->tv_usec = t_us % 1000000;
}

/*
 * config file
 */
#define TIMER_SCHED_INTERVAL_DEF    10
#define TIMER_SCHED_INTERVAL_MIN    1
#define TIMER_SCHED_INTERVAL_MAX    10000000

static rte_atomic32_t g_sched_interval;

int dpvs_timer_sched_interval_get(void)
{
    return rte_atomic32_read(&g_sched_interval);
}

static void timer_sched_interval_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int sched_interval = 0;

    if (!str)
        return;

    sched_interval = atoi(str);
    FREE_PTR(str);

    if (sched_interval < TIMER_SCHED_INTERVAL_MIN ||
            sched_interval > TIMER_SCHED_INTERVAL_MAX) {
        RTE_LOG(WARNING, DTIMER, "invalid sched_interval config %d, "
                "using default %d\n", sched_interval,
                TIMER_SCHED_INTERVAL_DEF);
        sched_interval = TIMER_SCHED_INTERVAL_DEF;
    }
    RTE_LOG(INFO, DTIMER, "sched_interval = %d\n", sched_interval);
    rte_atomic32_set(&g_sched_interval, sched_interval);
}

void timer_keyword_value_init(void)
{
    rte_atomic32_set(&g_sched_interval, TIMER_SCHED_INTERVAL_DEF);
}

void install_timer_keywords(void)
{
    install_keyword_root("timer_defs", NULL);
    install_keyword("schedule_interval", timer_sched_interval_handler,
                    KW_TYPE_NORMAL);
}
