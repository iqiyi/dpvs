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
#ifndef __DPVS_TIMER_H__
#define __DPVS_TIMER_H__
#include <stdint.h>
#include <sys/time.h>
#include "list.h"

/*
 * __NOTE__
 * timer handler should be as quick as possible
 * and do not block.
 */
enum {
    DTIMER_OK = 0,
    DTIMER_STOP,
};

typedef int (*dpvs_timer_cb_t)(void *arg);


typedef uint32_t dpvs_tick_t;

/* it's internal struct, user should never modify it directly. */
struct dpvs_timer {
#ifdef CONFIG_TIMER_DEBUG
    char name[32];
#endif
    struct list_head    list;

    dpvs_timer_cb_t     handler;
    void                *priv;
    bool                is_period;

    /*
     * 'delay' for one-short timer
     * 'interval' for periodic timer.
     */
    dpvs_tick_t         delay;
    dpvs_tick_t         left;
};

dpvs_tick_t timeval_to_ticks(const struct timeval *tv);
void ticks_to_timeval(const dpvs_tick_t ticks, struct timeval *tv);

int dpvs_timer_init(void);
int dpvs_timer_term(void);

/**
 * if @global is 'true' it's system wide timer, or it's per-lcore.
 * for per-lcore module pls set global to 'false'otherwise
 * set @global to 'true'. a timer is global or not must be consistent
 * all the time, DO NOT mix up.
 *
 * the 'nolock' api is used in timer handlers to avoid deadlock.
 *
 * NOTE: any lcore (including master and slaves) can use global timer,
 * but only slaves can use per-lcore timer.
 */
int dpvs_time_now(struct timeval *now, bool global);
int dpvs_time_now_nolock(struct timeval *now, bool global);

/* schedule one-shot timer expire at "time_now" + @delay */
int dpvs_timer_sched(struct dpvs_timer *timer, struct timeval *delay,
                     dpvs_timer_cb_t handler, void *arg, bool global);
int dpvs_timer_sched_nolock(struct dpvs_timer *timer, struct timeval *delay,
                     dpvs_timer_cb_t handler, void *arg, bool global);

/* schedule one-shot timer expire at @expire
 * it's abstract time not delta value */
int dpvs_timer_sched_abs(struct dpvs_timer *timer, struct timeval *expire,
                         dpvs_timer_cb_t handler, void *arg, bool global);
int dpvs_timer_sched_abs_nolock(struct dpvs_timer *timer, struct timeval *expire,
                         dpvs_timer_cb_t handler, void *arg, bool global);

/* schedule periodic timer with interval @intv */
int dpvs_timer_sched_period(struct dpvs_timer *timer, struct timeval *intv,
                            dpvs_timer_cb_t handler, void *arg, bool global);
int dpvs_timer_sched_period_nolock(struct dpvs_timer *timer, struct timeval *intv,
                            dpvs_timer_cb_t handler, void *arg, bool global);

int dpvs_timer_cancel(struct dpvs_timer *timer, bool global);
int dpvs_timer_cancel_nolock(struct dpvs_timer *timer, bool global);

/* restart the timer, for both one-shot and periodic */
int dpvs_timer_reset(struct dpvs_timer *timer, bool global);
int dpvs_timer_reset_nolock(struct dpvs_timer *timer, bool global);

/* set timer with new delay (one-shot) or interval (periodic) */
int dpvs_timer_update(struct dpvs_timer *timer,
                      struct timeval *delay, bool global);
int dpvs_timer_update_nolock(struct dpvs_timer *timer,
                      struct timeval *delay, bool global);

void dpvs_time_rand_delay(struct timeval *tv, long delay_us);

/* config file */
int dpvs_timer_sched_interval_get(void);
void timer_keyword_value_init(void);
void install_timer_keywords(void);

#endif /* __DPVS_TIMER_H__ */
