/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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
/**
 * queue scheduler for traffic control module.
 * see linux/net/sched/sch_generic.c
 *     linux/net/sched/sch_api.c
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#ifndef __DPVS_TC_SCH_H__
#define __DPVS_TC_SCH_H__
#include <assert.h>
#include "common.h"
#ifdef __DPVS__
#include "dpdk.h"
#include "timer.h"
#endif /* __DPVS__ */

enum {
    QSCH_F_INGRESS          = 0x00000001,
    QSCH_F_INVISIBLE        = 0x00000002,
};

struct qsch_qstats {
    uint32_t                qlen;
    uint32_t                backlog;
    uint32_t                drops;
    uint32_t                requeues;
    uint32_t                overlimits;
};

struct qsch_bstats {
    uint64_t                bytes;
    uint32_t                packets;
};

#ifdef __DPVS__

struct Qsch_ops {
    char                    name[TCNAMESIZ];
    uint32_t                priv_size;

    int                     (*enqueue)(struct Qsch *sch, struct rte_mbuf *mbuf);
    struct rte_mbuf *       (*dequeue)(struct Qsch *sch);
    struct rte_mbuf *       (*peek)(struct Qsch *sch);

    int                     (*init)(struct Qsch *sch, const void *arg);
    void                    (*reset)(struct Qsch *sch);
    void                    (*destroy)(struct Qsch *sch);
    int                     (*change)(struct Qsch *sch, const void *arg);
    int                     (*dump)(struct Qsch *sch, void *arg);

    /* internal use */
    struct list_head        list;       /* global sch ops list */
    rte_atomic32_t          refcnt;
};

/* queue scheduler, see kernel Qdisc */
struct Qsch {
    tc_handle_t             handle;
    tc_handle_t             parent;

    struct list_head        cls_list;   /* classifiers */
    int                     cls_cnt;
    struct hlist_node       hlist;      /* netif_tc.qsch_hash node */
    struct netif_tc         *tc;
    rte_atomic32_t          refcnt;

    uint32_t                limit;
    struct tc_mbuf_head     q[RTE_MAX_LCORE];
    uint32_t                flags;

    struct Qsch_ops         *ops;

    /* per-lcore statistics */
    struct qsch_qstats      qstats[RTE_MAX_LCORE];
    struct qsch_bstats      bstats[RTE_MAX_LCORE];

    struct dpvs_timer       rc_timer;

#define this_q      q[rte_lcore_id()]
#define this_qstats qstats[rte_lcore_id()]
#define this_bstats bstats[rte_lcore_id()]
};

struct qsch_rate {
    uint64_t                rate_bytes_ps; /* B/s */
};

static inline void *qsch_priv(struct Qsch *sch)
{
    return (char *)sch + TC_ALIGN(sizeof(struct Qsch));
}

static inline struct netif_port *qsch_dev(struct Qsch *sch)
{
    return sch->tc->dev;
}

/* length to time (nanosec) */
static inline uint64_t qsch_l2t_ns(const struct qsch_rate *rate, uint64_t len)
{
    if (!rate->rate_bytes_ps)
        return ~0U;

    return len * 1000000000 / rate->rate_bytes_ps;
}

static inline uint64_t qsch_t2l_ns(const struct qsch_rate *rate, uint64_t ns)
{
    return rate->rate_bytes_ps * ns / 1000000000;
}

/* generic scheduler helper routines */
static inline int qsch_drop(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    rte_pktmbuf_free(mbuf);
    sch->this_qstats.drops++;
    return EDPVS_DROP;
}

static inline int __qsch_enqueue_tail(struct Qsch *sch, struct rte_mbuf *mbuf,
                                      struct tc_mbuf_head *qh)
{
    struct tc_mbuf *tm;
    assert(sch && sch->tc && sch->tc->tc_mbuf_pool && mbuf);

    if (unlikely(rte_mempool_get(sch->tc->tc_mbuf_pool, (void **)&tm) != 0)) {
        RTE_LOG(WARNING, TC, "%s: no memory\n", __func__);
        qsch_drop(sch, mbuf);
        return EDPVS_NOMEM;
    }

    tm->mbuf = mbuf;
    list_add_tail(&tm->list, &qh->mbufs);
    qh->qlen++;
    sch->this_qstats.backlog += mbuf->pkt_len;
    sch->this_qstats.qlen++;

    return EDPVS_OK;
}

static inline int qsch_enqueue_tail(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    return __qsch_enqueue_tail(sch, mbuf, &sch->this_q);
}

static inline struct rte_mbuf *__qsch_dequeue_head(struct Qsch *sch,
                                                   struct tc_mbuf_head *qh)
{
    struct tc_mbuf *tm;
    struct rte_mbuf *mbuf;

    tm = list_first_entry(&qh->mbufs, struct tc_mbuf, list);
    if (unlikely(!tm))
        return NULL;

    list_del(&tm->list);
    mbuf = tm->mbuf;
    qh->qlen--;
    sch->this_qstats.backlog -= mbuf->pkt_len;
    sch->this_bstats.packets += 1;
    sch->this_bstats.bytes += mbuf->pkt_len;
    sch->this_qstats.qlen--;

    rte_mempool_put(sch->tc->tc_mbuf_pool, tm);
    return mbuf;
}

static inline struct rte_mbuf *qsch_dequeue_head(struct Qsch *sch)
{
    return __qsch_dequeue_head(sch, &sch->this_q);
}

static inline struct rte_mbuf *qsch_peek_head(struct Qsch *sch)
{
    struct tc_mbuf *tm;

    tm = list_first_entry(&sch->this_q.mbufs, struct tc_mbuf, list);
    if (unlikely(!tm))
        return NULL;

    return tm->mbuf;
}

static inline void __qsch_reset_queue(struct Qsch *sch,
                                      struct tc_mbuf_head *qh)
{
    struct tc_mbuf *tm, *n;

    list_for_each_entry_safe(tm, n, &qh->mbufs, list) {
        qsch_drop(sch, tm->mbuf);
        rte_mempool_put(sch->tc->tc_mbuf_pool, tm);
    }
    INIT_LIST_HEAD(&qh->mbufs);
    qh->qlen = 0;
    sch->this_qstats.qlen = 0;
    sch->this_qstats.backlog = 0;
}

static inline void qsch_reset_queue(struct Qsch *sch)
{
    return __qsch_reset_queue(sch, &sch->this_q);
}

/* Qsch APIs */
struct Qsch *qsch_create(struct netif_port *dev, const char *kind,
                         tc_handle_t parent, tc_handle_t handle,
                         const void *arg, int *errp);
struct Qsch *qsch_create_dflt(struct netif_port *dev, struct Qsch_ops *ops,
                              tc_handle_t parent);
void qsch_destroy(struct Qsch *sch);
int qsch_change(struct Qsch *sch, const void *arg);
void qsch_reset(struct Qsch *sch);
void qsch_stats(struct Qsch *sch, struct qsch_qstats *qstats,
                struct qsch_bstats *bstats);

void qsch_hash_add(struct Qsch *sch, bool invisible);
void qsch_hash_del(struct Qsch *sch);

struct Qsch *qsch_lookup(const struct netif_tc *tc, tc_handle_t handle);
struct Qsch *qsch_lookup_noref(const struct netif_tc *tc, tc_handle_t handle);
void qsch_do_sched(struct Qsch *sch);

static inline void qsch_get(struct Qsch *sch)
{
    rte_atomic32_inc(&sch->refcnt);
}

static inline void qsch_put(struct Qsch *sch)
{
    rte_atomic32_dec(&sch->refcnt);
}

int fifo_set_limit(struct Qsch *sch, unsigned int limit);
struct Qsch *fifo_create_dflt(struct Qsch *sch, struct Qsch_ops *ops,
                              unsigned int limit);

#endif /* __DPVS__ */

#endif /* __DPVS_TC_SCH_H__ */
