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

#include <assert.h>
#include "route6.h"
#include "route6_hlist.h"
#include "linux_ipv6.h"

#define RT6_HLIST_MAX_BUCKET_BITS   8
#define RT6_HLIST_MAX_BUCKETS       (1U<<RT6_HLIST_MAX_BUCKET_BITS)

#define this_rt6_htable     (RTE_PER_LCORE(dpvs_rt6_htable).htable)
#define this_rt6_nroutes    (RTE_PER_LCORE(dpvs_rt6_htable).nroutes)

#define g_nroutes           this_rt6_nroutes

struct rt6_hlist
{
    int plen;
    int nroutes;
    int nbuckets;               /* never change after init */
    struct list_head node;      /* list node of htable */
    struct list_head hlist[0];
};

struct rt6_htable
{
    int nroutes;
    struct list_head htable;    /* list head of rt6_hlist */
};

static RTE_DEFINE_PER_LCORE(struct rt6_htable, dpvs_rt6_htable);

static int rt6_hlist_setup_lcore(void *arg)
{
    this_rt6_nroutes = 0;
    INIT_LIST_HEAD(&this_rt6_htable);
    return EDPVS_OK;
}

static int rt6_hlist_destroy_lcore(void *arg)
{
    int i;
    struct rt6_hlist *hlist, *hnext;
    struct route6 *rt6, *rnext;

    list_for_each_entry_safe(hlist, hnext, &this_rt6_htable, node)
    {
        for (i = 0; i < hlist->nbuckets; i++) {
            list_for_each_entry_safe(rt6, rnext, &hlist->hlist[i], hnode) {
                list_del(&rt6->hnode);
                route6_free(rt6);
                hlist->nroutes--;
                this_rt6_nroutes--;
            }
        }
        assert(hlist->nroutes == 0);
        rte_free(hlist);
    }

    assert(this_rt6_nroutes == 0);
    return EDPVS_OK;
}

static uint32_t rt6_hlist_count(void)
{
    return g_nroutes;
}

static int rt6_hlist_buckets(int plen)
{
    /* caller should ensure 0 <= plen <= 128 */
    if (plen < RT6_HLIST_MAX_BUCKET_BITS)
        return (1U << plen);
    else
        return RT6_HLIST_MAX_BUCKETS;
}

static inline int rt6_hlist_hashkey(const struct in6_addr *addr, int plen, int nbuckets)
{
    struct in6_addr pfx;

    ipv6_addr_prefix(&pfx, addr, plen);
    return rte_jhash_32b((const uint32_t *)&pfx, 4, 0) % nbuckets;
}

static inline bool rt6_match(const struct route6 *rt6, const struct dp_vs_route6_conf *cf)
{
    /* Note: Do not use `ipv6_masked_addr_cmp` here for performance consideration
     *      here. We ensure the route6 entry is masked when added to route table. */
    if (ipv6_addr_cmp(&rt6->rt6_dst.addr.in6, &cf->dst.addr.in6) != 0)
        return false;
    if (rt6->rt6_dst.plen != cf->dst.plen)
        return false;
    if (rt6->rt6_dev && strlen(cf->ifname) != 0) {
        struct netif_port *dev;
        dev = netif_port_get_by_name(cf->ifname);
        if (!dev || dev->id != rt6->rt6_dev->id)
            return false;
    }

    /* other fields to be checked? */

    return true;
}

static struct route6 *__rt6_hlist_get(const struct dp_vs_route6_conf *cf,
        struct rt6_hlist **phlist)
{
    int hashkey;
    struct rt6_hlist *hlist;
    struct route6 *rt6;

    list_for_each_entry(hlist, &this_rt6_htable, node) {
        if (hlist->plen > cf->dst.plen)
            continue;
        if (hlist->plen < cf->dst.plen)
            break;
        hashkey = rt6_hlist_hashkey(&cf->dst.addr.in6, hlist->plen, hlist->nbuckets);
        list_for_each_entry(rt6, &hlist->hlist[hashkey], hnode) {
            if (rt6_match(rt6, cf)) {
                if (phlist)
                    *phlist = hlist;
                return rt6;
            }
        }
    }

    return NULL;
}

static inline struct route6 *rt6_hlist_get(const struct dp_vs_route6_conf *cf)
{
    return __rt6_hlist_get(cf, NULL);
}

static int rt6_hlist_add_lcore(const struct dp_vs_route6_conf *cf)
{
    struct rt6_hlist *hlist = NULL;
    struct route6 *rt6;
    int hashkey;
    bool hlist_exist = false;
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif

    if (rt6_hlist_get(cf))
        return EDPVS_EXIST;

    list_for_each_entry(hlist, &this_rt6_htable, node) {
        if (hlist->plen <= cf->dst.plen) {
            if (hlist->plen == cf->dst.plen)
                hlist_exist = true;
            break;
        }
    }

    if (!hlist_exist) { /* hlist for this prefix not exist, create it! */
        int i, nbuckets, size;
        struct rt6_hlist *new_hlist;

        nbuckets = rt6_hlist_buckets(cf->dst.plen);
        size = sizeof(struct rt6_hlist) + nbuckets * sizeof(struct list_head);
        new_hlist = rte_zmalloc("rt6_hlist", size, 0);
        if (unlikely(!new_hlist)) {
            RTE_LOG(ERR, RT6, "[%d] %s: fail to alloc rt6_hlist\n",
                    rte_lcore_id(), __func__);
            return EDPVS_NOMEM;
        }

        new_hlist->plen = cf->dst.plen;
        new_hlist->nbuckets = nbuckets;
        new_hlist->nroutes = 0;
        for (i = 0; i < nbuckets; i++)
            INIT_LIST_HEAD(&new_hlist->hlist[i]);

        /* add new_hlist to plen-sorted htable */
        __list_add(&new_hlist->node, hlist->node.prev, &hlist->node);

#ifdef DPVS_ROUTE6_DEBUG
        RTE_LOG(DEBUG, RT6, "[%d] %s: new rt6_hlist: plen=%d, nbuckets=%d\n",
                rte_lcore_id(), __func__, new_hlist->plen, new_hlist->nbuckets);
#endif

        hlist = new_hlist; /* replace current hlist with new_hlist */
    }

    /* create route6 entry and hash it into current hlist */
    rt6 = rte_zmalloc("rt6_entry", sizeof(struct route6), 0);
    if (unlikely(!rt6)) {
        RTE_LOG(ERR, RT6, "[%d] %s: fail to alloc rt6_entry!\n",
                rte_lcore_id(), __func__);
        if (hlist->nroutes == 0) {
            list_del(&hlist->node);
            rte_free(hlist);
        }
        return EDPVS_NOMEM;
    }

    rt6_fill_with_cfg(rt6, cf);
    rte_atomic32_set(&rt6->refcnt, 1);

    hashkey = rt6_hlist_hashkey(&cf->dst.addr.in6, cf->dst.plen, hlist->nbuckets);
    list_add_tail(&rt6->hnode, &hlist->hlist[hashkey]);
    hlist->nroutes++;
    this_rt6_nroutes++;

#ifdef DPVS_ROUTE6_DEBUG
    dump_rt6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
    RTE_LOG(DEBUG, RT6, "[%d] %s: new route6 node: %s->%s plen=%d, hashkey=%d/%d\n",
            rte_lcore_id(), __func__, buf, cf->ifname, hlist->plen,
            hashkey, hlist->nbuckets);
#endif

    return EDPVS_OK;
}

static int rt6_hlist_del_lcore(const struct dp_vs_route6_conf *cf)
{
    struct route6 *rt6;
    struct rt6_hlist *hlist = NULL;
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif

    rt6 = __rt6_hlist_get(cf, &hlist);
    if (!rt6)
        return EDPVS_NOTEXIST;

#ifdef DPVS_ROUTE6_DEBUG
    dump_rt6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
    RTE_LOG(DEBUG, RT6, "[%d] %s: del route6 node: %s->%s\n",
            rte_lcore_id(), __func__, buf, cf->ifname);
#endif
    list_del(&rt6->hnode);
    route6_free(rt6);

    assert(hlist != NULL);
    hlist->nroutes--;
    this_rt6_nroutes--;

    if (hlist->nroutes == 0) {
#ifdef DPVS_ROUTE6_DEBUG
        RTE_LOG(DEBUG, RT6, "[%d] %s: del rt6_hlist: plen=%d, nbuckets=%d\n",
                rte_lcore_id(), __func__, hlist->plen, hlist->nbuckets);
#endif
        list_del(&hlist->node);
        rte_free(hlist);
    }

    return EDPVS_OK;
}

static inline bool
rt6_hlist_flow_match(const struct route6 *rt6, const struct flow6 *fl6)
{
    if (rt6->rt6_dst.plen < 128) {
        if (!ipv6_prefix_equal(&fl6->fl6_daddr, &rt6->rt6_dst.addr.in6, rt6->rt6_dst.plen))
            return false;
    } else {
        if (!ipv6_addr_equal(&fl6->fl6_daddr, &rt6->rt6_dst.addr.in6))
            return false;
    }

    if (fl6->fl6_oif && rt6->rt6_dev && (fl6->fl6_oif->id != rt6->rt6_dev->id))
        return false;

    /* anything else to check ? */

    return true;
}

static struct route6 *rt6_hlist_lookup(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct rt6_hlist *hlist;
    struct route6 *rt6;
    int hashkey;

    list_for_each_entry(hlist, &this_rt6_htable, node) {
        hashkey = rt6_hlist_hashkey(&fl6->fl6_daddr, hlist->plen, hlist->nbuckets);
        list_for_each_entry(rt6, &hlist->hlist[hashkey], hnode) {
            if (rt6_hlist_flow_match(rt6, fl6)) {
                rte_atomic32_inc(&rt6->refcnt);
                return rt6;
            }
        }
    }

    return NULL;
}

static struct route6 *rt6_hlist_input(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_hlist_lookup(mbuf, fl6);
}

static struct route6 *rt6_hlist_output(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_hlist_lookup(mbuf, fl6);
}

static struct dp_vs_route6_conf_array*
        rt6_hlist_dump(const struct dp_vs_route6_conf *cf, size_t *nbytes)
{
    int i, off;
    struct rt6_hlist *hlist;
    struct route6 *entry;
    struct dp_vs_route6_conf_array *rt6_arr;
    struct netif_port *dev = NULL;

    if (cf && strlen(cf->ifname) > 0) {
        dev = netif_port_get_by_name(cf->ifname);
        if (!dev) {
            RTE_LOG(WARNING, RT6, "%s: route6 device %s not found!\n",
                    __func__, cf->ifname);
            return NULL;
        }
    }

    *nbytes = sizeof(struct dp_vs_route6_conf_array) +
            g_nroutes * sizeof(struct dp_vs_route6_conf);
    rt6_arr = rte_zmalloc("rt6_sockopt_get", *nbytes, 0);
    if (unlikely(!rt6_arr)) {
        RTE_LOG(WARNING, RT6, "%s: rte_zmalloc null.\n",
            __func__);
        return NULL;
    }

    off = 0;
    list_for_each_entry(hlist, &this_rt6_htable, node) {
        for (i = 0; i < hlist->nbuckets; i++) {
            list_for_each_entry(entry, &hlist->hlist[i], hnode) {
                if (off >= g_nroutes)
                    goto out;
                if (dev && dev->id != entry->rt6_dev->id)
                    continue;
                rt6_fill_cfg(&rt6_arr->routes[off++], entry);
            }
        }
    }

out:
    if (off < g_nroutes)
        *nbytes = sizeof(struct dp_vs_route6_conf_array) +
            off * sizeof(struct dp_vs_route6_conf);
    rt6_arr->nroute = off;

    return rt6_arr;
}

static struct route6_method rt6_hlist_method = {
    .name = "hlist",
    .rt6_setup_lcore = rt6_hlist_setup_lcore,
    .rt6_destroy_lcore = rt6_hlist_destroy_lcore,
    .rt6_count = rt6_hlist_count,
    .rt6_add_lcore = rt6_hlist_add_lcore,
    .rt6_del_lcore = rt6_hlist_del_lcore,
    .rt6_get = rt6_hlist_get,
    .rt6_input = rt6_hlist_input,
    .rt6_output = rt6_hlist_output,
    .rt6_dump = rt6_hlist_dump,
};

int route6_hlist_init(void)
{
    return route6_method_register(&rt6_hlist_method);
}

int route6_hlist_term(void)
{
    return route6_method_unregister(&rt6_hlist_method);
}
