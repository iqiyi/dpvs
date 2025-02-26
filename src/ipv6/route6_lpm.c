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

/* Notice:
 *      The DPDK LPM6 API 'rte_lpm6_delete' is very slow because
 *      it memset a big memory(several millions of bytes) within
 *      its implementation. If dpvs is used under the environment
 *      that routes deletion is frequent, LPM6 is not recommended!
 */

#include<assert.h>
#include <rte_lpm6.h>
#include "route6.h"
#include "linux_ipv6.h"
#include "route6_lpm.h"
#include "parser/parser.h"

#define LPM6_CONF_MAX_RULES_DEF         (1<<8)
#define LPM6_CONF_MAX_RULES_MIN         (1<<4)
#define LPM6_CONF_MAX_RULES_MAX         (1<<16)

#define LPM6_CONF_NUM_TBL8S_DEF         (LPM6_CONF_MAX_RULES_DEF<<4)
#define LPM6_CONF_NUM_TBL8S_MIN         (LPM6_CONF_MAX_RULES_MIN<<4)
#define LPM6_CONF_NUM_TBL8S_MAX         (LPM6_CONF_MAX_RULES_MAX<<4)

#define RT6_HASH_BUCKET_DEF             (1<<8)
#define RT6_HASH_BUCKET_MIN             (1<<4)
#define RT6_HASH_BUCKET_MAX             (1<<16)

#define this_lpm6_struct    (RTE_PER_LCORE(dpvs_lpm6_struct))
#define this_rt6_array      (RTE_PER_LCORE(dpvs_rt6_array))
#define this_rt6_hash       (RTE_PER_LCORE(dpvs_rt6_hash))
#define this_rt6_default    (RTE_PER_LCORE(dpvs_rt6_default))

/*
 *  Routes of IPv6 on different devices are likely to have the same prefix.
 *  For example, all devices often have link-local routes with prefix fe80::/64.
 *
 *  LPM6 only exposed an uint32_t next_hop for user to relate route entry to LPM6 rule.
 *  But each LPM6 prefix can be mapped to mutiple route6 entries, each with the same
 *  LPM6 prefix but different route attributes, such as netif ports. Thus, a LPM6
 *  next_hop should correspond to multiple route6 entries, which are chained with
 *  `struct lpm6_route` defined below.
 *
 *      lpm6[prefix] -> lpm6 nexthop: lpm6_route*
 *
 * */
// Get lpm6_route from its embeding route6 entry.
// Params:
//  route6_entry: pointer to route6 entry in the lpm6_route
#ifndef container_of
#define container_of(ptr, type, member) \
        (type *)((char *)(ptr) - (char *) &((type *)0)->member)
#endif

#define lpm6_route_of_entry(route6_entry) \
    container_of(route6_entry, struct lpm6_route, entry)

struct lpm6_route {
    struct route6 entry;    // Notes: always placed first to support route6_free
    uint32_t lpm_nexthop;
    struct lpm6_route *next;
};

/* DPDK LPM6 can store 4 bytes route information(i.e. an uint32_t integer) at most.
 * But DPVS route has more information needed to store: dest/source IP, gateway,
 * mtu, outgoing device...To solve the problem, an indexed route array is used.
 * */
struct rt6_array {
    uint32_t num;       /* total route6 entry number */
    uint32_t cursor;    /* positon of lastest insert, for fast search */
    void *entries[0];   /* route entry array, each elem is a pointer to lpm6_route */
};
#define g_nroutes   (this_rt6_array->num)

static uint8_t g_lcore_number = 0;
static uint64_t g_lcore_mask = 0;

static uint32_t g_lpm6_conf_max_rules = LPM6_CONF_MAX_RULES_DEF;
static uint32_t g_lpm6_conf_num_tbl8s = LPM6_CONF_NUM_TBL8S_DEF;
static uint32_t g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;

static RTE_DEFINE_PER_LCORE(struct rte_lpm6*, dpvs_lpm6_struct);
static RTE_DEFINE_PER_LCORE(struct rt6_array*, dpvs_rt6_array);
static RTE_DEFINE_PER_LCORE(struct route6*, dpvs_rt6_default);      /* lpm6 not support ::/0 */

/* Why need hash lists while using LPM6?
 * LPM6 can help find the best match route rule, but cannot find any route rule we want.
 * For example, assume there exists two rules with rt_addr
 *      FE80::0/16 --> rt6_array::entries[0]
 *      FE80::0/64 --> rt6_array::entries[1]
 * LPM6 lookup would never hit the first rule using 'rte_lpm6_lookup'. Though 'rte_lpm6_is_rule_present'
 * may solve the problem but it still cannot carry other route attributes such as netif_port.
 * So we cannot obtain the first rule when the control plane need to add/del/modify it.
 * Thus a hash list is needed for route6 control plane. Actually, hash list is not needed
 * for data plane. We use per-lcore struct just for convenience.
 */
static RTE_DEFINE_PER_LCORE(struct list_head*, dpvs_rt6_hash);

static inline bool rt6_default(const rt_addr_t *rt6_p)
{
    return ipv6_addr_any(&rt6_p->addr.in6) && (rt6_p->plen == 0);
}

static inline int rt6_find_free_array_idx(uint32_t *idx)
{
    uint32_t ii;
    if (unlikely(this_rt6_array == NULL))
        return EDPVS_NOTEXIST;
    if (this_rt6_array->num >= g_lpm6_conf_max_rules)
        return EDPVS_NOROOM;
    for (ii = (this_rt6_array->cursor+1) % g_lpm6_conf_max_rules;
            ii != this_rt6_array->cursor;
            ii = (ii+1) % g_lpm6_conf_max_rules) {
        if (this_rt6_array->entries[ii] == NULL) {
            *idx = ii;
            return EDPVS_OK;
        }
    }
    return EDPVS_INVAL;
}

static inline int rt6_hash_key(const rt_addr_t *rt6_p)
{
    return rte_jhash_32b((const uint32_t *)&rt6_p->addr, 4,
            rt6_p->plen) % g_rt6_hash_bucket;
}

static int rt6_lpm_setup_lcore(void *arg)
{
    char name[64];
    int i, ret;
    lcoreid_t cid = rte_lcore_id();
    int socketid = rte_socket_id();

    struct rte_lpm6_config config = {
        .max_rules = g_lpm6_conf_max_rules,
        .number_tbl8s = g_lpm6_conf_num_tbl8s,
        .flags = 0,
    };

    if ((!(g_lcore_mask & (1<<cid))) && (cid != rte_get_main_lcore())) {
        /* skip idle lcore for memory save */
        this_rt6_array = NULL;
        this_lpm6_struct = NULL;
        return EDPVS_OK;
    }

    this_rt6_default = NULL;

    this_rt6_array = rte_zmalloc("rt6_array",
            sizeof(struct rt6_array)+sizeof(void*)*g_lpm6_conf_max_rules, RTE_CACHE_LINE_SIZE);
    if (unlikely(this_rt6_array == NULL)) {
        RTE_LOG(ERR, RT6, "%s: no memory to create rt6_array!\n", __func__);
        return EDPVS_NOMEM;
    }

    this_rt6_hash = rte_zmalloc("rt6_hash",
            sizeof(struct list_head)*g_rt6_hash_bucket, RTE_CACHE_LINE_SIZE);
    if (unlikely(this_rt6_hash == NULL)) {
        ret = EDPVS_NOMEM;
        goto rt6_hash_fail;
    }
    for (i = 0; i < g_rt6_hash_bucket; i++)
        INIT_LIST_HEAD(&this_rt6_hash[i]);

    snprintf(name, sizeof(name), "lpm6_socket%d_lcore%d", socketid, cid);
    this_lpm6_struct = rte_lpm6_create(name, socketid, &config);
    if (unlikely(this_lpm6_struct == NULL)) {
        ret = EDPVS_DPDKAPIFAIL;
        goto rt6_lpm6_fail;
    }

    return EDPVS_OK;

rt6_lpm6_fail:
    rte_free(this_rt6_hash);
    this_rt6_hash = NULL;
rt6_hash_fail:
    rte_free(this_rt6_array);
    this_rt6_array = NULL;

    RTE_LOG(ERR, RT6, "%s: unable to create the lpm6 struct for lcore%d "
            "on socket%d -- %s\n", __func__, cid, socketid, dpvs_strerror(ret));
    return ret;
}

static int rt6_lpm_destroy_lcore(void *arg)
{
    int i;
    struct route6 *entry, *next;

    for (i = 0; i < g_rt6_hash_bucket; i++) {
        list_for_each_entry_safe(entry, next, &this_rt6_hash[i], hnode) {
            list_del(&entry->hnode);
            route6_free(entry);
        }
    }

    if (this_rt6_array) {
        rte_free(this_rt6_array);
        this_rt6_array = NULL;
    }

    if (this_rt6_hash) {
        rte_free(this_rt6_hash);
        this_rt6_hash = NULL;
    }

    if (this_lpm6_struct) {
        rte_lpm6_free(this_lpm6_struct);
        this_lpm6_struct = NULL;
    }

    return EDPVS_OK;
}

static struct route6 *rt6_lpm_lookup(const struct flow6 *fl6)
{
    bool found;
    uint32_t idx;
    struct lpm6_route *lpm6rt;
    struct route6 *rt6 = NULL;

    if (rte_lpm6_lookup(this_lpm6_struct,
                (const struct rte_ipv6_addr *)&fl6->fl6_daddr,
                &idx) != 0) {
        if (this_rt6_default)
            rte_atomic32_inc(&this_rt6_default->refcnt);
        return this_rt6_default;
    }

    assert(idx >= 0 && idx < g_lpm6_conf_max_rules);

    found = false;
    lpm6rt = this_rt6_array->entries[idx];
    while (lpm6rt != NULL) {
        rt6 = &lpm6rt->entry;
        if (!rt6->rt6_dev || !fl6->fl6_oif || rt6->rt6_dev->id == fl6->fl6_oif->id) {
            found = true;
            break;
        }
        lpm6rt = lpm6rt->next;
    }

    if (found) {
        rte_atomic32_inc(&rt6->refcnt);
        return rt6;
    }
    return NULL;
}

static struct route6 *rt6_lpm_input(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_lpm_lookup(fl6);
}

static struct route6 *rt6_lpm_output(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_lpm_lookup(fl6);
}

/* Note slaves have the same rt6_hash table with master. Call me on master only
 * if you just need to find the route entry specified by 'rt6_cfg' is configured.*/
static struct route6* rt6_lpm_get(const struct dp_vs_route6_conf *rt6_cfg)
{
    int hashkey;
    struct route6 *entry, *next;

    hashkey = rt6_hash_key(&rt6_cfg->dst);
    list_for_each_entry_safe(entry, next, &this_rt6_hash[hashkey], hnode) {
        if (entry->rt6_dst.plen == rt6_cfg->dst.plen &&
                ipv6_prefix_equal(&entry->rt6_dst.addr.in6, &rt6_cfg->dst.addr.in6,
                    rt6_cfg->dst.plen) && (entry->rt6_dev == NULL ||
                strcmp(rt6_cfg->ifname, entry->rt6_dev->name) == 0)) {
            return entry;
        }
    }

    if (rt6_cfg->dst.plen == 0 && ipv6_addr_any(&rt6_cfg->dst.addr.in6))
        return this_rt6_default;

    return NULL;
}

static int rt6_add_lcore_default(const struct dp_vs_route6_conf *rt6_cfg)
{
    struct route6 *entry;

    if (this_rt6_default)
        return EDPVS_EXIST;

    entry = rte_zmalloc("rt6_entry", sizeof(struct route6), 0);
    if (unlikely(entry == NULL))
        return EDPVS_NOMEM;

    /* 'rt6_cfg' has been verified by 'rt6_default' */
    rt6_fill_with_cfg(entry, rt6_cfg);
    INIT_LIST_HEAD(&entry->hnode);
    rte_atomic32_set(&entry->refcnt, 1);
    this_rt6_default = entry;

#ifdef DPVS_ROUTE6_DEBUG
    RTE_LOG(DEBUG, RT6, "[%d] %s(default via dev %s)->this_rt6_default OK!\n",
            rte_lcore_id(), __func__, rt6_cfg->ifname);
#endif

    return EDPVS_OK;
}

static int rt6_del_lcore_default(const struct dp_vs_route6_conf *rt6_cfg)
{

    if (!this_rt6_default)
        return EDPVS_NOTEXIST;

    /* 'rt6_cfg' has been verified by 'rt6_default' */
    route6_free(this_rt6_default);
    this_rt6_default = NULL;

#ifdef DPVS_ROUTE6_DEBUG
    RTE_LOG(DEBUG, RT6, "[%d] %s(default via dev %s)->this_rt6_default OK!\n",
            rte_lcore_id(), __func__, rt6_cfg->ifname);
#endif

    return EDPVS_OK;
}

static int rt6_lpm_add_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{
    uint32_t lpm_nexthop;
    int hashkey, ret;
    char buf[64];
    struct lpm6_route *entry, *head = NULL;

    assert(rt6_cfg != NULL);

    if (unlikely(g_nroutes >= g_lpm6_conf_max_rules))
        return EDPVS_NOROOM;

    if (rt6_default(&rt6_cfg->dst))
        return rt6_add_lcore_default(rt6_cfg);

    entry = rte_zmalloc("lpm6_route", sizeof(struct lpm6_route), 0);
    if (unlikely(entry == NULL)) {
        ret = EDPVS_NOMEM;
        goto rt6_add_fail;
    }
    entry->next = NULL;
    rt6_fill_with_cfg(&entry->entry, rt6_cfg);
    rte_atomic32_set(&entry->entry.refcnt, 1);

    if (rte_lpm6_is_rule_present(this_lpm6_struct,
                (const struct rte_ipv6_addr *)&rt6_cfg->dst.addr,
                (uint8_t)rt6_cfg->dst.plen, &lpm_nexthop)) {
        assert(lpm_nexthop < g_lpm6_conf_max_rules);
        head = this_rt6_array->entries[lpm_nexthop];
        assert(head && head->lpm_nexthop == lpm_nexthop);
    } else {
        ret = rt6_find_free_array_idx(&lpm_nexthop);
        if (unlikely(ret != EDPVS_OK))
            goto rt6_free;
        this_rt6_array->cursor = lpm_nexthop;
        ret = rte_lpm6_add(this_lpm6_struct,
                (const struct rte_ipv6_addr *)&entry->entry.rt6_dst.addr,
                (uint8_t)entry->entry.rt6_dst.plen, lpm_nexthop);
        if (unlikely(ret < 0)) {
            ret = EDPVS_DPDKAPIFAIL;
            goto rt6_free;
        }
#ifdef DPVS_ROUTE6_DEBUG
        RTE_LOG(DEBUG, RT6, "[%d] rte_lpm6_add succeed!\n", rte_lcore_id());
#endif
    }

    entry->lpm_nexthop = lpm_nexthop;
    entry->next = head;
    this_rt6_array->entries[lpm_nexthop] = entry;

    hashkey = rt6_hash_key(&entry->entry.rt6_dst);
    list_add_tail(&entry->entry.hnode, &this_rt6_hash[hashkey]);

    g_nroutes++;    // i.e., this_rt6_array->num++;

#ifdef DPVS_ROUTE6_DEBUG
    dump_rt6_prefix(&rt6_cfg->dst, buf, sizeof(buf));
    RTE_LOG(DEBUG, RT6, "[%d] %s(%s via dev %s)->rt6_hash[%d]:rt6_array[%d]:lpm6[%d] OK!"
            " %d routes exist.\n", rte_lcore_id(), __func__, buf, rt6_cfg->ifname, hashkey,
            lpm_nexthop, lpm_nexthop, this_rt6_array->num);
#endif
    return EDPVS_OK;

rt6_free:
    rte_free(entry);
rt6_add_fail:
    dump_rt6_prefix(&rt6_cfg->dst, buf, sizeof(buf));
    RTE_LOG(ERR, RT6, "%s[%d]: rt6_lpm_add_lcore %s failed -- %s!\n", __func__,
            rte_lcore_id(), buf, dpvs_strerror(ret));
    return ret;
}

static int rt6_lpm_del_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{
    uint32_t lpm_nexthop;
    int hashkey, ret;
    struct route6 *entry, *next;
    struct lpm6_route *lpm6rt, *head;
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif

    assert(rt6_cfg != NULL);

    if (rt6_default(&rt6_cfg->dst))
        return rt6_del_lcore_default(rt6_cfg);

    hashkey = rt6_hash_key(&rt6_cfg->dst);
    list_for_each_entry_safe(entry, next, &this_rt6_hash[hashkey], hnode) {
        if (entry->rt6_dst.plen == rt6_cfg->dst.plen && ipv6_prefix_equal(&entry->rt6_dst.addr.in6,
                    &rt6_cfg->dst.addr.in6, rt6_cfg->dst.plen) && (entry->rt6_dev == NULL ||
                        strcmp(rt6_cfg->ifname, entry->rt6_dev->name) == 0)) {
            /* hit! route source is not checked */
            lpm6rt = lpm6_route_of_entry(entry);
            lpm_nexthop = lpm6rt->lpm_nexthop;
            assert(lpm_nexthop < g_lpm6_conf_max_rules);
            head = this_rt6_array->entries[lpm6rt->lpm_nexthop];
            assert(head != NULL);
            if (lpm6rt != head) {
                head->next = lpm6rt->next;
            } else if (lpm6rt->next) {
                this_rt6_array->entries[lpm_nexthop] = lpm6rt->next;
            } else {
                ret = rte_lpm6_delete(this_lpm6_struct,
                        (const struct rte_ipv6_addr *)&entry->rt6_dst.addr,
                        (uint8_t)entry->rt6_dst.plen);
                if (unlikely(ret < 0)) {
                    /* rte_lpm6_delete return OK even if no satisfied route exists,
                     * but fail if duplicated routes exist */
                    char buf[256];
                    dump_rt6_prefix(&entry->rt6_dst, buf, sizeof(buf));
                    RTE_LOG(ERR, RT6, "[%d]%s: rte_lpm6_delete(%s) failed!\n",
                            rte_lcore_id(), __func__, buf);
                    return EDPVS_DPDKAPIFAIL;
                }
                this_rt6_array->entries[lpm_nexthop] = NULL;
#ifdef DPVS_ROUTE6_DEBUG
                RTE_LOG(DEBUG, RT6, "[%d] rte_lpm6_delete succeed!\n", rte_lcore_id());
#endif
            }
#ifdef DPVS_ROUTE6_DEBUG
            dump_rt6_prefix(&rt6_cfg->dst, buf, sizeof(buf));
            RTE_LOG(DEBUG, RT6, "[%d] %s(%s via dev %s)->rt6_hash[%d]:rt6_array[%d]:lpm6[%d] OK!"
                    " %d routes left.\n", rte_lcore_id(), __func__, buf, rt6_cfg->ifname,
                    hashkey, lpm_nexthop, lpm6rt->lpm_nexthop, this_rt6_array->num-1);
#endif
            list_del(&entry->hnode);
            route6_free((struct route6 *)lpm6rt);
            g_nroutes--;    // i.e., this_rt6_array->num--;
            /* no further search */
            break;
        }
    }
    return EDPVS_OK;
}

static int rt6_lpm_flush_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{

    bool flush_all;
    uint32_t lpm_nexthop;
    int i;
    struct route6 *entry, *next;
    struct lpm6_route *lpm6rt, *head;
    char buf[256];

    if (rt6_cfg && strlen(rt6_cfg->ifname) > 0) {
        flush_all = false;
    } else {
        rte_lpm6_delete_all(this_lpm6_struct);
#ifdef DPVS_ROUTE6_DEBUG
        RTE_LOG(DEBUG, RT6, "[%d] rte_lpm6_delete_all succeed!\n", rte_lcore_id());
#endif
        flush_all = true;
    }

    for (i = 0; i < g_rt6_hash_bucket; i++) {
        list_for_each_entry_safe(entry, next, &this_rt6_hash[i], hnode) {
            if (flush_all || (entry->rt6_dev && !strcmp(entry->rt6_dev->name, rt6_cfg->ifname))) {
                lpm6rt = lpm6_route_of_entry(entry);
                if (!flush_all)  {
                    lpm_nexthop = lpm6rt->lpm_nexthop;
                    assert(lpm_nexthop < g_lpm6_conf_max_rules);
                    head = this_rt6_array->entries[lpm6rt->lpm_nexthop];
                    assert(head != NULL);
                    if (lpm6rt != head) {
                        head->next = lpm6rt->next;
                    } else if (lpm6rt->next) {
                        this_rt6_array->entries[lpm_nexthop] = lpm6rt->next;
                    } else {
                        if (rte_lpm6_delete(this_lpm6_struct,
                                    (const struct rte_ipv6_addr *)&entry->rt6_dst.addr,
                                    (uint8_t)entry->rt6_dst.plen) < 0) {
                            dump_rt6_prefix(&entry->rt6_dst, buf, sizeof(buf));
                            RTE_LOG(WARNING, RT6, "[%d]%s: rt6_lpm_flush_lcore del %s dev %s failed!\n",
                                    rte_lcore_id(), __func__, buf, entry->rt6_dev->name ?: "none");
                        }
                        this_rt6_array->entries[lpm_nexthop] = NULL;
#ifdef DPVS_ROUTE6_DEBUG
                        RTE_LOG(DEBUG, RT6, "[%d] rte_lpm6_delete succeed!\n", rte_lcore_id());
#endif
                    }
                }
                list_del(&entry->hnode);
                g_nroutes--;    // i.e., this_rt6_array->num--;
                route6_free((struct route6 *)lpm6rt);
            }
        }
    }

    if (flush_all) {
        assert(g_nroutes == 0);
        this_rt6_array->cursor = 0;
        memset(this_rt6_array->entries, 0, sizeof(void *) * g_lpm6_conf_max_rules);
    }

    return EDPVS_OK;
}

static struct dp_vs_route6_conf_array *rt6_lpm_dump(
        const struct dp_vs_route6_conf *rt6_cfg, size_t *nbytes)
{
    int i, off;
    struct route6 *entry;
    struct dp_vs_route6_conf_array *rt6_arr;
    struct netif_port *dev = NULL;

    if (rt6_cfg && (strlen(rt6_cfg->ifname) > 0)) {
        dev = netif_port_get_by_name(rt6_cfg->ifname);
        if (!dev) {
            RTE_LOG(WARNING, RT6, "%s: route6 device %s not found!\n",
                    __func__, rt6_cfg->ifname);
            return NULL;
        }
    }

    if (this_rt6_default)
        *nbytes = sizeof(struct dp_vs_route6_conf_array) +\
                  (g_nroutes+1) * sizeof(struct dp_vs_route6_conf);
    else
        *nbytes = sizeof(struct dp_vs_route6_conf_array) +\
                  (g_nroutes) * sizeof(struct dp_vs_route6_conf);
    rt6_arr = rte_zmalloc("rt6_sockopt_get", *nbytes, 0);
    if (unlikely(!rt6_arr)) {
        RTE_LOG(WARNING, RT6, "%s: rte_zmalloc null!\n",
            __func__);
        return NULL;
    }

    off = 0;
    for (i = 0; i < g_rt6_hash_bucket; i++) {
        list_for_each_entry(entry, &this_rt6_hash[i], hnode) {
            if (off >= g_nroutes)
                break;
            if (dev && entry->rt6_dev && dev->id != entry->rt6_dev->id)
                continue;
            rt6_fill_cfg(&rt6_arr->routes[off++], entry);
        }
    }

    if (this_rt6_default && off <= g_nroutes+1)
        rt6_fill_cfg(&rt6_arr->routes[off++], this_rt6_default);

    if (off < g_nroutes)
        *nbytes = sizeof(struct dp_vs_route6_conf_array)+\
                  off * sizeof(struct dp_vs_route6_conf);
    rt6_arr->nroute = off;

    return rt6_arr;
}

static struct route6_method rt6_lpm_method = {
    .name = "lpm",
    .rt6_setup_lcore    = rt6_lpm_setup_lcore,
    .rt6_destroy_lcore  = rt6_lpm_destroy_lcore,
    .rt6_add_lcore      = rt6_lpm_add_lcore,
    .rt6_del_lcore      = rt6_lpm_del_lcore,
    .rt6_flush_lcore    = rt6_lpm_flush_lcore,
    .rt6_get            = rt6_lpm_get,
    .rt6_input          = rt6_lpm_input,
    .rt6_output         = rt6_lpm_output,
    .rt6_dump           = rt6_lpm_dump,
};

int route6_lpm_init(void)
{
    netif_get_slave_lcores(&g_lcore_number, &g_lcore_mask);
    return route6_method_register(&rt6_lpm_method);
}

int route6_lpm_term(void)
{
    return route6_method_unregister(&rt6_lpm_method);
}

/* config file */
static void rt6_lpm6_max_rules_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t lpm6_max_rules = atoi(str);

    if (lpm6_max_rules < LPM6_CONF_MAX_RULES_MIN || lpm6_max_rules > LPM6_CONF_MAX_RULES_MAX) {
        RTE_LOG(WARNING, RT6, "route6:lpm6_max_rules %s exceeds limits, "
                "using default %d\n", str, LPM6_CONF_MAX_RULES_DEF);
        g_lpm6_conf_max_rules = LPM6_CONF_MAX_RULES_DEF;
    } else {
        is_power2((int)lpm6_max_rules, 0, (int *)&lpm6_max_rules);
        RTE_LOG(INFO, RT6, "route6:lpm6_max_rules = %d\n", lpm6_max_rules);
        g_lpm6_conf_max_rules = lpm6_max_rules;
    }

    FREE_PTR(str);
}

static void rt6_lpm6_num_tbl8s_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t lpm6_num_tbl8s = atoi(str);

    if (lpm6_num_tbl8s < LPM6_CONF_NUM_TBL8S_MIN || lpm6_num_tbl8s > LPM6_CONF_NUM_TBL8S_MAX) {
        RTE_LOG(WARNING, RT6, "route6:lpm6_num_tbl8s %s exceeds limits, "
                "using default %d\n", str, LPM6_CONF_NUM_TBL8S_DEF);
        g_lpm6_conf_num_tbl8s = LPM6_CONF_NUM_TBL8S_DEF;
    } else {
        is_power2((int)lpm6_num_tbl8s, 0, (int *)&lpm6_num_tbl8s);
        RTE_LOG(INFO, RT6, "route6:lpm6_num_tbl8s = %d\n", lpm6_num_tbl8s);
        g_lpm6_conf_num_tbl8s = lpm6_num_tbl8s;
    }

    FREE_PTR(str);
}

static void rt6_hash_bucket_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t hash_buckets = atoi(str);

    if (hash_buckets < RT6_HASH_BUCKET_MIN || hash_buckets > RT6_HASH_BUCKET_MAX) {
        RTE_LOG(WARNING, RT6, "route6:hash_bucket %s exceeds limits, "
                "using default %d\n", str, RT6_HASH_BUCKET_DEF);
        g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;
    } else {
        is_power2((int)hash_buckets, 0, (int *)&hash_buckets);
        RTE_LOG(INFO, RT6, "route6:hash_bucket = %d\n", hash_buckets);
        g_rt6_hash_bucket = hash_buckets;
    }

    FREE_PTR(str);
}

void route6_lpm_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        g_lpm6_conf_max_rules = LPM6_CONF_MAX_RULES_DEF;
        g_lpm6_conf_num_tbl8s = LPM6_CONF_NUM_TBL8S_DEF;
        g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;
    }
}

void install_rt6_lpm_keywords(void)
{
    install_keyword("lpm", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("lpm6_max_rules", rt6_lpm6_max_rules_handler, KW_TYPE_INIT);
    install_keyword("lpm6_num_tbl8s", rt6_lpm6_num_tbl8s_handler, KW_TYPE_INIT);
    install_keyword("rt6_hash_bucket", rt6_hash_bucket_handler, KW_TYPE_INIT);
    install_sublevel_end();
}
