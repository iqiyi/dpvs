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
 * traffic control module of DPVS.
 * see linux/net/sched/ for reference.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <linux/pkt_sched.h>
#include "list.h"
#include "netif.h"
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"

extern struct Qsch_ops pfifo_sch_ops;
extern struct Qsch_ops bfifo_sch_ops;
extern struct Qsch_ops pfifo_fast_ops;
extern struct Qsch_ops tbf_sch_ops;
extern struct tc_cls_ops match_cls_ops;

static struct list_head qsch_ops_base;
static rte_rwlock_t qsch_ops_lock;
static struct Qsch_ops *default_qsch_ops = &pfifo_fast_ops;

static struct list_head cls_ops_base;
static rte_rwlock_t cls_ops_lock;

/* make them configurable only if really needed. */
static int tc_qsch_hash_size = 64;
static int tc_mbuf_pool_size = 8192; /* shared by all Qsch, enough ? */
static int tc_mbuf_cache_size = 128;

static struct rte_mempool *tc_mbuf_pools[DPVS_MAX_SOCKET];

/* call with qsch_ops_lock */
static struct Qsch_ops *__qsch_ops_lookup(const char *name)
{
    struct Qsch_ops *ops;

    list_for_each_entry(ops, &qsch_ops_base, list) {
        if (strcmp(ops->name, name) == 0)
            return ops;
    }

    return NULL;
}

int tc_register_qsch(struct Qsch_ops *ops)
{
    int err = EDPVS_OK;

    rte_rwlock_write_lock(&qsch_ops_lock);
    if (__qsch_ops_lookup(ops->name)) {
        err = EDPVS_EXIST;
    } else {
        list_add_tail(&ops->list, &qsch_ops_base);
        rte_atomic32_set(&ops->refcnt, 1);
    }
    rte_rwlock_write_unlock(&qsch_ops_lock);
    return err;
}

int tc_unregister_qsch(struct Qsch_ops *ops)
{
    int err = EDPVS_OK;

    rte_rwlock_write_lock(&qsch_ops_lock);
    if (rte_atomic32_dec_and_test(&ops->refcnt))
        list_del(&ops->list);
    else
        err = EDPVS_BUSY;
    rte_rwlock_write_unlock(&qsch_ops_lock);

    return err;
}

void tc_qsch_ops_get(struct Qsch_ops *ops)
{
    rte_atomic32_inc(&ops->refcnt);
}

void tc_qsch_ops_put(struct Qsch_ops *ops)
{
    rte_atomic32_dec(&ops->refcnt);
}

struct Qsch_ops *tc_qsch_ops_lookup(const char *name)
{
    struct Qsch_ops *ops;

    rte_rwlock_read_lock(&qsch_ops_lock);
    ops = __qsch_ops_lookup(name);
    if (ops)
        tc_qsch_ops_get(ops);
    rte_rwlock_read_unlock(&qsch_ops_lock);

    return ops;
}

/* call with cls_ops_lock */
static struct tc_cls_ops *__cls_ops_lookup(const char *name)
{
    struct tc_cls_ops *ops;

    list_for_each_entry(ops, &cls_ops_base, list) {
        if (strcmp(ops->name, name) == 0)
            return ops;
    }

    return NULL;
}

int tc_register_cls(struct tc_cls_ops *ops)
{
    int err = EDPVS_OK;

    rte_rwlock_write_lock(&cls_ops_lock);
    if (__cls_ops_lookup(ops->name)) {
        err = EDPVS_EXIST;
    } else {
        list_add_tail(&ops->list, &cls_ops_base);
        rte_atomic32_set(&ops->refcnt, 1);
    }
    rte_rwlock_write_unlock(&cls_ops_lock);
    return err;
}

int tc_unregister_cls(struct tc_cls_ops *ops)
{
    int err = EDPVS_OK;

    rte_rwlock_write_lock(&cls_ops_lock);
    if (rte_atomic32_dec_and_test(&ops->refcnt))
        list_del(&ops->list);
    else
        err = EDPVS_BUSY;
    rte_rwlock_write_unlock(&cls_ops_lock);

    return err;
}

struct tc_cls_ops *tc_cls_ops_get(const char *name)
{
    struct tc_cls_ops *ops;

    rte_rwlock_read_lock(&cls_ops_lock);
    ops = __cls_ops_lookup(name);
    if (ops)
        rte_atomic32_inc(&ops->refcnt);
    rte_rwlock_read_unlock(&cls_ops_lock);

    return ops;
}

void tc_cls_ops_put(struct tc_cls_ops *ops)
{
    rte_atomic32_dec(&ops->refcnt);
}

struct rte_mbuf *tc_handle_egress(struct netif_tc *tc,
                                  struct rte_mbuf *mbuf, int *ret)
{
    int err = EDPVS_OK;
    struct Qsch *sch, *child_sch = NULL;
    struct tc_cls *cls;
    struct tc_cls_result cls_res;
    const int max_reclassify_loop = 8;
    int limit = 0;

    assert(tc && mbuf && ret);

    /* start from egress root qsch */
    sch = tc->qsch;
    if (unlikely(!sch)) {
        *ret = EDPVS_OK;
        return mbuf;
    }

    qsch_get(sch);

    /*
     * classify the traffic first.
     * support classify for child schedulers only.
     * it no classifier matchs, than use current scheduler.
     */
again:
    list_for_each_entry(cls, &sch->cls_list, list) {
        if (unlikely(mbuf->packet_type != cls->pkt_type &&
                     cls->pkt_type != htons(ETH_P_ALL)))
            continue;

        err = cls->ops->classify(cls, mbuf, &cls_res);
        switch (err) {
        case TC_ACT_OK:
            break;
        case TC_ACT_SHOT:
            goto drop;
        default:
            continue;
        }

        if (unlikely(cls_res.drop))
            goto drop;

        child_sch = qsch_lookup(sch->tc, cls_res.sch_id);

        if (unlikely(!child_sch)) {
            RTE_LOG(WARNING, TC, "%s: target Qsch not exist.\n",
                    __func__);
            continue;
        }

        if (unlikely(child_sch->parent != sch->handle)) {
            RTE_LOG(WARNING, TC, "%s: classified to non-children scheduler\n",
                    __func__);
            qsch_put(child_sch);
            continue;
        }

        /* pass the packet to child scheduler */
        qsch_put(sch);
        sch = child_sch;

        if (unlikely(limit++ >= max_reclassify_loop)) {
            RTE_LOG(DEBUG, TC, "%s: exceed reclassify max loop.\n",
                    __func__);
            goto drop;
        }

        /* classify again for new selected Qsch */
        goto again;
    }

    /* this scheduler has no queue (for classify only) ? */
    if (unlikely(!sch->ops->enqueue))
        goto out; /* no need to set @ret */

    /* mbuf is always consumed (queued or dropped) */
    err = sch->ops->enqueue(sch, mbuf);
    mbuf = NULL;
    *ret = err;

    /* try dequeue and xmit */
    qsch_do_sched(sch);

out:
    qsch_put(sch);
    return mbuf;

drop:
    *ret = qsch_drop(sch, mbuf);
    qsch_put(sch);
    return NULL;
}

int tc_init_dev(struct netif_port *dev)
{
    int hash, size;
    struct netif_tc *tc = netif_tc(dev);

    memset(tc, 0, sizeof(*tc));

    rte_rwlock_init(&tc->lock);

    rte_rwlock_write_lock(&tc->lock);

    tc->dev = dev;
    tc->tc_mbuf_pool = tc_mbuf_pools[dev->socket];

    /* egress "root" Qsch, which handle is 0, parent is TC_H_ROOT. */
    tc->qsch = qsch_create_dflt(dev, default_qsch_ops, TC_H_ROOT);
    if (!tc->qsch) {
        rte_rwlock_write_unlock(&tc->lock);
        tc_destroy_dev(dev);
        return EDPVS_NOMEM;
    }

    tc->qsch_cnt = 1;
    tc->qsch_ingress = NULL;

    tc->qsch_hash_size = tc_qsch_hash_size;
    size = sizeof(struct hlist_head) * tc->qsch_hash_size;

    tc->qsch_hash = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);
    if (!tc->qsch_hash) {
        rte_rwlock_write_unlock(&tc->lock);
        tc_destroy_dev(dev);
        return EDPVS_NOMEM;
    }

    for (hash = 0; hash < tc->qsch_hash_size; hash++)
        INIT_HLIST_HEAD(&tc->qsch_hash[hash]);

    rte_rwlock_write_unlock(&tc->lock);
    return EDPVS_OK;
}

int tc_destroy_dev(struct netif_port *dev)
{
    struct netif_tc *tc = netif_tc(dev);
    struct Qsch *sch;
    struct hlist_node *n;
    int hash;

    rte_rwlock_write_lock(&tc->lock);

    if (tc->qsch_hash) {
        for (hash = 0; hash < tc->qsch_hash_size; hash++) {
            hlist_for_each_entry_safe(sch, n, &tc->qsch_hash[hash], hlist)
                qsch_destroy(sch);
        }

        rte_free(tc->qsch_hash);
    }

    if (tc->qsch)
        qsch_destroy(tc->qsch);

    if (tc->qsch_ingress)
        qsch_destroy(tc->qsch_ingress);

    tc->qsch_cnt = 0;

    rte_rwlock_write_unlock(&tc->lock);

    return EDPVS_OK;
}

int tc_init(void)
{
    int s;

    /* scheduler */
    rte_rwlock_init(&qsch_ops_lock);
    INIT_LIST_HEAD(&qsch_ops_base);

    tc_register_qsch(&pfifo_sch_ops);
    tc_register_qsch(&bfifo_sch_ops);
    tc_register_qsch(&pfifo_fast_ops);
    tc_register_qsch(&tbf_sch_ops);

    /* classifier */
    rte_rwlock_init(&cls_ops_lock);
    INIT_LIST_HEAD(&cls_ops_base);

    tc_register_cls(&match_cls_ops);

    /* per-NUMA socket mempools for queued tc_mbuf{} */
    for (s = 0; s < get_numa_nodes(); s++) {
        char plname[64];

        snprintf(plname, sizeof(plname), "tc_mbuf_pool_%d", s);

        tc_mbuf_pools[s] = rte_mempool_create(plname, tc_mbuf_pool_size,
                                              sizeof(struct tc_mbuf),
                                              tc_mbuf_cache_size,
                                              0, NULL, NULL, NULL, NULL,
                                              s, 0);
        if (!tc_mbuf_pools[s])
            return EDPVS_NOMEM;
    }

    return EDPVS_OK;
}
