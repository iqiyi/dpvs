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
 * generic queue scheduler code for traffic control module.
 * see linux/net/sched/sch_generic.c
 *     linux/net/sched/sch_api.c
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <linux/pkt_sched.h>
#include "netif.h"
#include "tc/tc.h"
#include "tc/sch.h"

/* may configurable in the future. */
static int dev_tx_weight = 64;
static int qsch_recycle_timeout = 5;

static inline int sch_hash(tc_handle_t handle, int hash_size)
{
    return handle % hash_size;
}

static inline int sch_qlen(struct Qsch *sch)
{
    return sch->this_q.qlen;
}

/* return current queue length (num of packets in queue),
 * or 0 if queue is empty or throttled. */
static inline int sch_dequeue_xmit(struct Qsch *sch, int *npkt)
{
    struct rte_mbuf *mbuf;

    *npkt = 1; /* TODO: bulk dequeue */
    mbuf = sch->ops->dequeue(sch);
    if (unlikely(!mbuf))
        return 0;

    netif_hard_xmit(mbuf, netif_port_get(mbuf->port));
    return sch_qlen(sch);
}

static inline struct Qsch *sch_alloc(struct netif_tc *tc, struct Qsch_ops *ops)
{
    struct Qsch *sch;
    unsigned int size = TC_ALIGN(sizeof(*sch)) + ops->priv_size;
    lcoreid_t cid;

    sch = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
    if (!sch)
        return NULL;

    for (cid = 0; cid < NELEMS(sch->q); cid++)
        tc_mbuf_head_init(&sch->q[cid]);

    INIT_LIST_HEAD(&sch->cls_list);
    INIT_HLIST_NODE(&sch->hlist);
    sch->tc = tc;
    sch->ops = ops;
    rte_atomic32_set(&sch->refcnt, 1);

    return sch;
}

static inline void sch_free(struct Qsch *sch)
{
    rte_free(sch);
}

static void __qsch_destroy(struct Qsch *sch)
{
    struct Qsch_ops *ops = sch->ops;

    if (ops->reset)
        ops->reset(sch);
    if (ops->destroy)
        ops->destroy(sch);

    tc_qsch_ops_put(ops);
    sch_free(sch);
}

static int sch_recycle(void *arg)
{
    struct Qsch *sch = arg;

    if (rte_atomic32_read(&sch->refcnt)) {
        dpvs_timer_reset(&sch->rc_timer, true);
        RTE_LOG(WARNING, TC, "%s: sch %u is in use.\n", __func__, sch->handle);
        return DTIMER_OK;
    }

    __qsch_destroy(sch);
    return DTIMER_STOP;
}

static void sch_dying(struct Qsch *sch)
{
    struct timeval timeout = { qsch_recycle_timeout, 0 };

    dpvs_timer_sched(&sch->rc_timer, &timeout, sch_recycle, sch, true);
}

static inline tc_handle_t sch_alloc_handle(struct netif_port *dev)
{
    int i = 0x8000;
    static uint32_t autohandle = TC_H_MAKE(0x80000000U, 0);

    do {
        autohandle += TC_H_MAKE(0x10000U, 0);
        if (autohandle == TC_H_MAKE(TC_H_ROOT, 0))
            autohandle = TC_H_MAKE(0x80000000U, 0);
        if (!qsch_lookup_noref(&dev->tc, autohandle))
            return autohandle;
    } while    (--i > 0);

    return 0;
}

struct Qsch *qsch_create(struct netif_port *dev, const char *kind,
                         tc_handle_t parent, tc_handle_t handle,
                         const void *arg, int *errp)
{
    int err;
    struct Qsch_ops *ops = NULL;
    struct Qsch *sch = NULL;
    struct netif_tc *tc = netif_tc(dev);
    assert(dev && kind && errp);

    err = EDPVS_NOTSUPP;
    ops = tc_qsch_ops_lookup(kind);
    if (!ops)
        goto errout;

    err = EDPVS_NOMEM;
    sch = sch_alloc(tc, ops);
    if (!sch)
        goto errout;

    sch->parent = parent;

    if (handle == TC_H_INGRESS) {
        sch->flags |= QSCH_F_INGRESS;
        handle = TC_H_MAKE(TC_H_INGRESS, 0);

        /* already exist ? */
        if (tc->qsch_ingress) {
            err = EDPVS_EXIST;
            goto errout;
        }
    } else { /* egress */
        struct Qsch *q;

        if (handle == 0) {
            handle = sch_alloc_handle(dev);
            if (!handle)
                goto errout;
        }

        /* already exist ? */
        q = qsch_lookup_noref(tc, handle);
        if (q) {
            err = EDPVS_EXIST;
            goto errout;
        }

        /* if use this API, parent must not be root
         * and must be exist */
        if (parent == TC_H_ROOT) {
            err = EDPVS_INVAL;
            goto errout;
        } else {
            q = qsch_lookup_noref(tc, parent);
            if (!q) {
                err = EDPVS_NOTEXIST;
                goto errout;
            }
        }
    }

    sch->handle = handle;

    if (ops->init && (err = ops->init(sch, arg)) != EDPVS_OK) {
        if (ops->destroy)
            ops->destroy(sch);
        goto errout;
    }

    if (sch->flags & QSCH_F_INGRESS) {
        tc->qsch_ingress = sch;
        sch->tc->qsch_cnt++;
    } else
        qsch_hash_add(sch, false);
    *errp = EDPVS_OK;
    return sch;

errout:
    if (sch)
        sch_free(sch);
    if (ops)
        tc_qsch_ops_put(ops);
    *errp = err;
    return NULL;
}

struct Qsch *qsch_create_dflt(struct netif_port *dev, struct Qsch_ops *ops,
                              tc_handle_t parent)
{
    int err;
    struct Qsch *sch;
    assert(dev && ops);

    tc_qsch_ops_get(ops);

    sch = sch_alloc(&dev->tc, ops);
    if (!sch) {
        tc_qsch_ops_put(ops);
        return NULL;
    }

    sch->parent = parent;

    if (ops->init && (err = ops->init(sch, NULL)) != EDPVS_OK) {
        tc_qsch_ops_put(ops);
        qsch_destroy(sch);
        return NULL;
    }

    return sch;
}

void qsch_destroy(struct Qsch *sch)
{
    if (sch->flags & QSCH_F_INGRESS) {
        assert(sch->tc->qsch_ingress == sch);
        sch->tc->qsch_ingress = NULL;
        sch->tc->qsch_cnt--;
    } else if (sch == sch->tc->qsch) {
        sch->tc->qsch = NULL;
        sch->tc->qsch_cnt--;
    } else {
        qsch_hash_del(sch);
    }

    if (!rte_atomic32_dec_and_test(&sch->refcnt)) {
        RTE_LOG(WARNING, TC, "%s: sch %u is in use.\n", __func__, sch->handle);
        sch_dying(sch);
        return;
    }

    __qsch_destroy(sch);
}

int qsch_change(struct Qsch *sch, const void *arg)
{
    if (!sch->ops->change)
        return EDPVS_NOTSUPP;

    return sch->ops->change(sch, arg);
}

void qsch_reset(struct Qsch *sch)
{
    lcoreid_t cid;

    if (sch->ops->reset)
        sch->ops->reset(sch);

    for (cid = 0; cid < NELEMS(sch->q); cid++)
        sch->q[cid].qlen = 0;
}

void qsch_hash_add(struct Qsch *sch, bool invisible)
{
    int hash;
    assert(sch && sch->tc && sch->tc->qsch_hash);

    if (sch->parent == TC_H_ROOT || (sch->flags & QSCH_F_INGRESS))
        return;

    hash = sch_hash(sch->handle, sch->tc->qsch_hash_size);
    hlist_add_head(&sch->hlist, &sch->tc->qsch_hash[hash]);
    sch->tc->qsch_cnt++;

    if (invisible)
        sch->flags |= QSCH_F_INVISIBLE;
}

void qsch_hash_del(struct Qsch *sch)
{
    assert(sch && sch->tc && sch->tc->qsch_hash);

    if (sch->parent == TC_H_ROOT || (sch->flags & QSCH_F_INGRESS))
        return;

    hlist_del_init(&sch->hlist);
    sch->tc->qsch_cnt--;
}

struct Qsch *qsch_lookup_noref(const struct netif_tc *tc, tc_handle_t handle)
{
    int hash;
    struct Qsch *sch;
    assert(tc->qsch_hash && tc->qsch_hash_size);

    if (likely(tc->qsch && tc->qsch->handle == handle))
        return tc->qsch;

    hash = sch_hash(handle, tc->qsch_hash_size);
    hlist_for_each_entry(sch, &tc->qsch_hash[hash], hlist) {
        if (likely(sch->handle == handle))
            return sch;
    }

    if (tc->qsch_ingress && tc->qsch_ingress->handle == handle)
        return tc->qsch_ingress;

    return NULL;
}

struct Qsch *qsch_lookup(const struct netif_tc *tc, tc_handle_t handle)
{
    struct Qsch *sch = NULL;

    sch = qsch_lookup_noref(tc, handle);
    if (sch)
        qsch_get(sch);

    return sch;
}

void qsch_do_sched(struct Qsch *sch)
{
    int quota = dev_tx_weight;
    int npkt;

    while (quota > 0 && sch_dequeue_xmit(sch, &npkt))
        quota -= npkt;

    return;
}
