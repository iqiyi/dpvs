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

extern int netif_pktpool_nb_mbuf;
extern int netif_pktpool_mbuf_cache;

extern struct Qsch_ops pfifo_sch_ops;
extern struct Qsch_ops bfifo_sch_ops;
extern struct Qsch_ops pfifo_fast_ops;
extern struct Qsch_ops tbf_sch_ops;
extern struct tc_cls_ops match_cls_ops;
extern struct tc_cls_ops ipset_cls_ops;

static struct list_head qsch_ops_base;
static struct list_head cls_ops_base;

static int tc_qsch_hash_size = 64;

static struct rte_mempool *tc_mbuf_pools[DPVS_MAX_SOCKET];

struct Qsch_ops *tc_qsch_ops_lookup(const char *name)
{
    struct Qsch_ops *ops;

    list_for_each_entry(ops, &qsch_ops_base, list) {
        if (strcmp(ops->name, name) == 0)
            return ops;
    }

    return NULL;
}

/* call on init stage */
int tc_register_qsch(struct Qsch_ops *ops)
{
    if (tc_qsch_ops_lookup(ops->name))
        return EDPVS_EXIST;

    list_add_tail(&ops->list, &qsch_ops_base);
    return EDPVS_OK;
}

int tc_unregister_qsch(struct Qsch_ops *ops)
{
    if (!tc_qsch_ops_lookup(ops->name))
        return EDPVS_NOTEXIST;

    list_del(&ops->list);

    return EDPVS_OK;
}

struct tc_cls_ops *tc_cls_ops_lookup(const char *name)
{
    struct tc_cls_ops *ops;

    list_for_each_entry(ops, &cls_ops_base, list) {
        if (strcmp(ops->name, name) == 0)
            return ops;
    }

    return NULL;
}

/* call on init stage */
int tc_register_cls(struct tc_cls_ops *ops)
{
    if (tc_cls_ops_lookup(ops->name))
        return EDPVS_EXIST;

    list_add_tail(&ops->list, &cls_ops_base);
    return EDPVS_OK;
}

int tc_unregister_cls(struct tc_cls_ops *ops)
{
    if (!tc_cls_ops_lookup(ops->name))
        return EDPVS_NOTEXIST;

    list_del(&ops->list);

    return EDPVS_OK;
}

struct rte_mbuf *tc_hook(struct netif_tc *tc, struct rte_mbuf *mbuf,
                         tc_hook_type_t type, int *ret)
{
    int err = EDPVS_OK;
    struct Qsch *sch, *child_sch;
    struct tc_cls *cls;
    struct tc_cls_result cls_res;
    const int max_reclassify_loop = 8;
    int limit = 0;
    uint32_t flags;
    __be16 pkt_type;

    assert(tc && mbuf && ret);
    sch = child_sch = NULL;
    flags = (type == TC_HOOK_INGRESS) ? QSCH_F_INGRESS : 0;

    /* start from root qsch */
    if (flags & QSCH_F_INGRESS) {
        sch = tc->qsch_ingress;
        /* mbuf->packet_type was not set by DPVS for ingress */
        pkt_type = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *)->ether_type;
    } else {
        sch = tc->qsch;
        pkt_type = rte_cpu_to_be_16(mbuf->packet_type);
    }
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
        if (unlikely(cls->pkt_type != pkt_type &&
                     cls->pkt_type != htons(ETH_P_ALL)))
            continue;

        if ((cls->sch->flags & QSCH_F_INGRESS) ^ flags)
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

    if (unlikely((sch->flags & QSCH_F_INGRESS) && type != TC_HOOK_INGRESS) ||
            (!(sch->flags & QSCH_F_INGRESS) && type != TC_HOOK_EGRESS)) {
        RTE_LOG(WARNING, TC, "%s: classified to qsch of incorrect type\n", __func__);
        goto out;
    }

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

static int __tc_destroy_dev(struct netif_port *dev, struct netif_tc *tc)
{
    struct Qsch *sch;
    struct hlist_node *n;
    int hash;

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

    return EDPVS_OK;
}

int tc_destroy_dev(struct netif_port *dev)
{
    int i, err = EDPVS_OK;

    assert(dev);

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        err = __tc_destroy_dev(dev, &dev->tc[i]);
        if (err != EDPVS_OK) {
            RTE_LOG(WARNING, TC, "%s: fail to destroy %s's tc[%d]\n", __func__, dev->name, i);
        }
    }

    return err;
}

static inline int __tc_init_dev(struct netif_port *dev, struct netif_tc *tc)
{
    int hash, size;

    memset(tc, 0, sizeof(*tc));

    tc->dev = dev;
    tc->tc_mbuf_pool = tc_mbuf_pools[dev->socket];

    tc->qsch_cnt = 0;
    tc->qsch_ingress = NULL;

    tc->qsch_hash_size = tc_qsch_hash_size;
    size = sizeof(struct hlist_head) * tc->qsch_hash_size;

    tc->qsch_hash = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);
    if (!tc->qsch_hash) {
        __tc_destroy_dev(dev, tc);
        return EDPVS_NOMEM;
    }

    for (hash = 0; hash < tc->qsch_hash_size; hash++)
        INIT_HLIST_HEAD(&tc->qsch_hash[hash]);

    return EDPVS_OK;
}

int tc_init_dev(struct netif_port *dev)
{
    int i, err = EDPVS_OK;

    assert(dev);

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        err = __tc_init_dev(dev, &dev->tc[i]);
        if (err != EDPVS_OK)
            break;
    }

    if (err != EDPVS_OK) {
        for (--i; i >= 0; i--) {
            __tc_destroy_dev(dev, &dev->tc[i]);
        }
    }

    return err;
}

int tc_init(void)
{
    int s, err;
    int tc_mbuf_pool_size = netif_pktpool_nb_mbuf;
    int tc_mbuf_cache_size = netif_pktpool_mbuf_cache;

    if ((err = qsch_init()) != EDPVS_OK)
        return err;

    /* scheduler */
    INIT_LIST_HEAD(&qsch_ops_base);
    tc_register_qsch(&pfifo_sch_ops);
    tc_register_qsch(&bfifo_sch_ops);
    tc_register_qsch(&pfifo_fast_ops);
    tc_register_qsch(&tbf_sch_ops);

    /* classifier */
    INIT_LIST_HEAD(&cls_ops_base);
    tc_register_cls(&match_cls_ops);
    tc_register_cls(&ipset_cls_ops);

    /* per-NUMA socket mempools for queued tc_mbuf{} */
    for (s = 0; s < get_numa_nodes(); s++) {
        char plname[64];

        snprintf(plname, sizeof(plname), "tc_mbuf_pool_%d", s);

        is_power2(tc_mbuf_pool_size, 1, &tc_mbuf_pool_size);
        tc_mbuf_pools[s] = rte_mempool_create(plname, tc_mbuf_pool_size - 1,
                                              sizeof(struct tc_mbuf),
                                              tc_mbuf_cache_size,
                                              0, NULL, NULL, NULL, NULL,
                                              s, 0);
        if (!tc_mbuf_pools[s])
            return EDPVS_NOMEM;
    }

    return EDPVS_OK;
}

int tc_term(void)
{
    int s;

    tc_unregister_qsch(&pfifo_sch_ops);
    tc_unregister_qsch(&bfifo_sch_ops);
    tc_unregister_qsch(&pfifo_fast_ops);
    tc_unregister_qsch(&tbf_sch_ops);

    tc_unregister_cls(&match_cls_ops);
    tc_unregister_cls(&ipset_cls_ops);

    for (s = 0; s < get_numa_nodes(); s++) {
        if (tc_mbuf_pools[s]) {
            rte_mempool_free(tc_mbuf_pools[s]);
        }
    }

    qsch_term();

    return EDPVS_OK;
}
