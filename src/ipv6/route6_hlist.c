/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
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

/* Notice:
 *      The DPDK LPM6 API 'rte_lpm6_delete' is very slow because
 *      it memset a big memory(several millions of bytes) within
 *      its implementation. If dpvs is used under the environment
 *      that routes deletion is frequent, LPM6 is not recommended!
 */

#include "route6.h"
#include "route6_hlist.h"
#include "linux_ipv6.h"

#define RT6_LOCAL_TABLE_BITS        8
#define RT6_LOCAL_TABLE_SIZE        (1 << RT6_LOCAL_TABLE_BITS)
#define RT6_LOCAL_TABLE_MASK        (RT6_LOCAL_TABLE_SIZE - 1)

#define this_rt6_hlist              (RTE_PER_LCORE(rt6_hlist_lcore))
#define this_rt6_local              (this_rt6_hlist.rt6_local)
#define this_rt6_net                (this_rt6_hlist.rt6_net)
#define this_rt6_nroutes            (this_rt6_hlist.nroutes)

#define g_nroutes                   (this_rt6_hlist.nroutes)

struct route6_hlist {
    uint32_t nroutes;
    struct list_head rt6_local[RT6_LOCAL_TABLE_SIZE];
    struct list_head rt6_net;
};

static RTE_DEFINE_PER_LCORE(struct route6_hlist, rt6_hlist_lcore);

static int rt6_hlist_setup_lcore(void *arg)
{
    int i;

    for (i = 0; i < RT6_LOCAL_TABLE_SIZE; i++)
        INIT_LIST_HEAD(&this_rt6_local[i]);

    INIT_LIST_HEAD(&this_rt6_net);
    g_nroutes = 0;

    return EDPVS_OK;
}

static int rt6_hlist_destroy_lcore(void *arg)
{
    return EDPVS_OK;
}

static uint32_t rt6_hlist_count(void)
{
    return g_nroutes;
}

static inline bool rt6_match(const struct route6 *rt6, const struct dp_vs_route6_conf *cf)
{
    /* Note: Do not use `ipv6_masked_addr_cmp` here for performance consideration 
     *      here. We ensure the route6 entry is masked when added to route table. */
    if (ipv6_addr_cmp(&rt6->rt6_dst.addr, &cf->dst.addr) != 0)
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

static inline int rt6_local_hash_key(const struct in6_addr *addr)
{
    return rte_jhash_32b((const uint32_t *)addr, 4, 0) & RT6_LOCAL_TABLE_MASK;
}

static struct route6 *rt6_hlist_get(const struct dp_vs_route6_conf *cf)
{
    struct route6 *rt6;

    if (!cf)
        return NULL;

    if (cf->dst.plen == 128) {
        int hashkey = rt6_local_hash_key(&cf->dst.addr);
        list_for_each_entry(rt6, &this_rt6_local[hashkey], hnode) {
            if (rt6_match(rt6, cf))
                return rt6;
        }
    } else {
        list_for_each_entry(rt6, &this_rt6_net, hnode) {
            if (rt6_match(rt6, cf))
                return rt6;
        }
    }

    return NULL;
}

static int rt6_hlist_add_local(struct route6 *rt6_entry)
{
    int hashkey = rt6_local_hash_key(&rt6_entry->rt6_dst.addr);
    list_add_tail(&rt6_entry->hnode, &this_rt6_local[hashkey]);

    this_rt6_nroutes++;

    return EDPVS_OK;
}

static int rt6_hlist_add_net(struct route6 *rt6_entry)
{
    struct route6 *rt6 = NULL;
    bool insert = false;

    list_for_each_entry(rt6, &this_rt6_net, hnode) {
        if (rt6->rt6_dst.plen < rt6_entry->rt6_dst.plen) {
            insert = true;
            break;
        } else if (rt6->rt6_dst.plen == rt6_entry->rt6_dst.plen) {
            if (ipv6_addr_cmp(&rt6->rt6_dst.addr, &rt6_entry->rt6_dst.addr) > 0) {
                insert = true;
                break;
            }
        }
    }

    if (insert)
        __list_add(&rt6_entry->hnode, rt6->hnode.prev, &rt6->hnode);
    else
        list_add_tail(&rt6_entry->hnode, &this_rt6_net);

    this_rt6_nroutes++;

    return EDPVS_OK;
}

static int rt6_hlist_add_lcore(const struct dp_vs_route6_conf *cf)
{
    struct route6 *entry;

    if (rt6_hlist_get(cf))
        return EDPVS_EXIST;

    entry = rte_malloc_socket("rt6_entry", sizeof(struct route6), 0, rte_socket_id());
    if (unlikely(!entry))
        return EDPVS_NOMEM;

    rt6_fill_with_cfg(entry, cf);

    if (cf->dst.plen == 128)
        return rt6_hlist_add_local(entry);
    else
        return rt6_hlist_add_net(entry);
}

static int rt6_hlist_del_lcore(const struct dp_vs_route6_conf *cf)
{
    struct route6 *rt6_entry;

    rt6_entry = rt6_hlist_get(cf);
    if (!rt6_entry)
        return EDPVS_NOTEXIST;

    list_del(&rt6_entry->hnode);
    rte_free(rt6_entry);

    this_rt6_nroutes--;

    return EDPVS_OK;
}

static inline bool
    rt6_hlist_flow_match(const struct route6 *rt6, const struct flow6 *fl6)
{
    if (rt6->rt6_dst.plen < 128) {
        if (!ipv6_prefix_equal(&fl6->fl6_daddr, &rt6->rt6_dst.addr, rt6->rt6_dst.plen))
            return false;
    } else {
        if (!ipv6_addr_equal(&fl6->fl6_daddr, &rt6->rt6_dst.addr))
            return false;
    }

    if (fl6->fl6_oif && rt6->rt6_dev && (fl6->fl6_oif->id != rt6->rt6_dev->id))
        return false;

    if ((!ipv6_addr_any(&rt6->rt6_src.addr)) && (ipv6_addr_equal(&rt6->rt6_src.addr,
                    &fl6->fl6_saddr)) != true)
        return false;

    /* anything else to check ? */

    return true;
}

static struct route6 *rt6_hlist_lookup(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt6_entry;
    int hashkey;

    /* search local table */
    hashkey = rt6_local_hash_key(&fl6->fl6_daddr);
    list_for_each_entry(rt6_entry, &this_rt6_local[hashkey], hnode) {
        if (rt6_hlist_flow_match(rt6_entry, fl6))
            return rt6_entry;
    }

    /* search net list */
    list_for_each_entry(rt6_entry, &this_rt6_net, hnode) {
        if (rt6_hlist_flow_match(rt6_entry, fl6))
            return rt6_entry;
    }

    /* miss */
    return NULL;
}

static struct route6 *rt6_hlist_input(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_hlist_lookup(mbuf, fl6);
}

static struct route6 *rt6_hlist_output(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_hlist_lookup(mbuf, fl6);
}

static struct dp_vs_route6_conf_array*
        rt6_hlist_dump(const struct dp_vs_route6_conf *cf, size_t *nbytes)
{
    int i, off;
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
    rt6_arr = rte_zmalloc_socket("rt6_sockopt_get", *nbytes, 0, rte_socket_id());
    if (unlikely(!rt6_arr))
        return NULL;

    off = 0;
    for (i = 0; i < RT6_LOCAL_TABLE_SIZE; i++) {
        list_for_each_entry(entry, &this_rt6_local[i], hnode) {
            if (off > g_nroutes)
                break;
            if (dev && dev->id != entry->rt6_dev->id)
                continue;
            rt6_fill_cfg(&rt6_arr->routes[off++], entry);
        }
    }
    list_for_each_entry(entry, &this_rt6_net, hnode) {
        if (off > g_nroutes)
            break;
        if (dev && dev->id != entry->rt6_dev->id)
            continue;
        rt6_fill_cfg(&rt6_arr->routes[off++], entry);
    }

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
