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
#include "scheduler.h"

/* may configurable in the future. */
static int dev_tx_weight = 64;

static struct list_head qsch_head[DPVS_MAX_LCORE];
#define this_qsch_head qsch_head[rte_lcore_id()]

static inline int sch_hash(tc_handle_t handle, int hash_size)
{
    return handle % hash_size;
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

    if (sch->flags & QSCH_F_INGRESS)
        netif_rcv_mbuf(sch->tc->dev, rte_lcore_id(), mbuf, false);
    else
        netif_hard_xmit(mbuf, sch->tc->dev);

    return sch->q.qlen;
}

static inline struct Qsch *sch_alloc(struct netif_tc *tc, struct Qsch_ops *ops)
{
    struct Qsch *sch;
    unsigned int size = TC_ALIGN(sizeof(*sch)) + ops->priv_size;

    sch = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
    if (!sch)
        return NULL;

    tc_mbuf_head_init(&sch->q);
    INIT_LIST_HEAD(&sch->cls_list);
    INIT_HLIST_NODE(&sch->hlist);

    sch->tc = tc;
    sch->ops = ops;
    sch->refcnt = 1;

    return sch;
}

tc_handle_t sch_alloc_handle(struct netif_tc *tc)
{
    int i = 0x8000;
    static uint32_t autohandle = TC_H_MAKE(0x80000000U, 0);

    do {
        autohandle += TC_H_MAKE(0x10000U, 0);
        if (autohandle == TC_H_MAKE(TC_H_ROOT, 0))
            autohandle = TC_H_MAKE(0x80000000U, 0);
        if (!qsch_lookup_noref(tc, autohandle))
            return autohandle;
    } while (--i > 0);

    return 0;
}

struct Qsch *qsch_create(struct netif_port *dev, const char *kind,
                         tc_handle_t parent, tc_handle_t handle,
                         const void *arg, int *errp)
{
    int err;
    struct Qsch_ops *ops = NULL;
    struct Qsch *sch = NULL, *psch = NULL;
    struct netif_tc *tc = netif_tc(dev);
    assert(dev && kind && errp);

    err = EDPVS_INVAL;
    ops = tc_qsch_ops_lookup(kind);
    if (!ops) {
        err = EDPVS_NOTSUPP;
        goto errout;
    }

    sch = sch_alloc(tc, ops);
    if (!sch) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    if (parent != 0) {
        psch = qsch_lookup_noref(tc, parent);
        if (!psch) {
            err = EDPVS_NOTEXIST;
            goto errout;
        }
    }
    sch->parent = parent;

    if (handle == TC_H_INGRESS) {
        sch->flags |= QSCH_F_INGRESS;
        if (tc->qsch_ingress) {
            err = EDPVS_EXIST;
            goto errout;
        }
    } else if (handle == TC_H_ROOT) {
        if (tc->qsch) {
            err = EDPVS_EXIST;
            goto errout;
        }
    } else {
        if (handle == 0 || parent == 0) {
            err = EDPVS_INVAL;
            goto errout;
        }

        sch->flags |= (psch->flags & QSCH_F_INGRESS);

        if (qsch_lookup_noref(tc, handle)) {
            err = EDPVS_EXIST;
            goto errout;
        }
    }
    sch->handle = handle;

    if (ops->init && (err = ops->init(sch, arg)) != EDPVS_OK) {
        if (ops->destroy)
            ops->destroy(sch);
        goto errout;
    }

    qsch_hash_add(sch, false);

    *errp = EDPVS_OK;
    return sch;

errout:
    if (sch)
        sch_free(sch);
    *errp = err;
    return NULL;
}

void qsch_destroy(struct Qsch *sch)
{
    qsch_hash_del(sch);
    qsch_put(sch);
}

int qsch_change(struct Qsch *sch, const void *arg)
{
    if (!sch->ops->change)
        return EDPVS_NOTSUPP;

    return sch->ops->change(sch, arg);
}

void qsch_hash_add(struct Qsch *sch, bool invisible)
{
    int hash;
    assert(sch && sch->tc && sch->tc->qsch_hash);

    if (sch->handle == TC_H_INGRESS) {
        sch->tc->qsch_ingress = sch;
    } else if (sch->handle == TC_H_ROOT) {
        sch->tc->qsch= sch;
    } else {
        hash = sch_hash(sch->handle, sch->tc->qsch_hash_size);
        hlist_add_head(&sch->hlist, &sch->tc->qsch_hash[hash]);
    }

    list_add_tail(&sch->list_node, &this_qsch_head);

    sch->tc->qsch_cnt++;

    if (invisible)
        sch->flags |= QSCH_F_INVISIBLE;
}

void qsch_hash_del(struct Qsch *sch)
{
    assert(sch && sch->tc && sch->tc->qsch_hash);

    if (sch == sch->tc->qsch_ingress) {
        sch->tc->qsch_ingress = NULL;
    } else if (sch == sch->tc->qsch) {
        sch->tc->qsch = NULL;
    } else {
        hlist_del_init(&sch->hlist);
    }

    list_del(&sch->list_node);

    sch->tc->qsch_cnt--;
}

struct Qsch *qsch_lookup_noref(const struct netif_tc *tc, tc_handle_t handle)
{
    int hash;
    struct Qsch *sch;
    assert(tc->qsch_hash && tc->qsch_hash_size);

    if (tc->qsch && tc->qsch->handle == handle)
        return tc->qsch;

    if (tc->qsch_ingress && tc->qsch_ingress->handle == handle)
        return tc->qsch_ingress;

    hash = sch_hash(handle, tc->qsch_hash_size);
    hlist_for_each_entry(sch, &tc->qsch_hash[hash], hlist) {
        if (sch->handle == handle)
            return sch;
    }

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

static void qsch_sched_all(void *dummy)
{
    struct Qsch *sch;
    lcoreid_t cid = rte_lcore_id();

    list_for_each_entry(sch, &qsch_head[cid], list_node) {
        if (sch->flags & QSCH_F_INGRESS) {
            if (sch->tc->dev->flag & NETIF_PORT_FLAG_TC_INGRESS)
                qsch_do_sched(sch);
        } else {
            if (sch->tc->dev->flag & NETIF_PORT_FLAG_TC_EGRESS)
                qsch_do_sched(sch);
        }
    }
}

static struct dpvs_lcore_job qsch_sched_job = {
    .name = "qsch_sched",
    .func = qsch_sched_all,
    .data = NULL,
    .type = LCORE_JOB_LOOP,
};

int qsch_init(void)
{
    int i, err;

    for (i = 0; i < DPVS_MAX_LCORE; i++)
        INIT_LIST_HEAD(&qsch_head[i]);

    err = dpvs_lcore_job_register(&qsch_sched_job, LCORE_ROLE_FWD_WORKER);
    if (err != EDPVS_OK)
        return err;

    return qsch_shm_init();
}

int qsch_term(void)
{
    int err;

    err = dpvs_lcore_job_unregister(&qsch_sched_job, LCORE_ROLE_FWD_WORKER);
    if (err != EDPVS_OK)
        return err;

    return qsch_shm_term();
}
