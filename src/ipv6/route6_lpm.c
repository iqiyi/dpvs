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

#define LPM6_CONF_MAX_RULES_DEF         1024
#define LPM6_CONF_NUM_TBL8S_DEF         (1<<16)

#define RT6_ARRAY_SIZE_DEF              (1<<16)
#define RT6_HASH_BUCKET_DEF             (1<<8)

#define this_lpm6_struct    (RTE_PER_LCORE(dpvs_lpm6_struct))
#define this_rt6_array      (RTE_PER_LCORE(dpvs_rt6_array))
#define this_rt6_hash       (RTE_PER_LCORE(dpvs_rt6_hash))
#define this_rt6_default    (RTE_PER_LCORE(dpvs_rt6_default))

/* DPDK LPM6 can store 4 bytes route information(i.e. an uint32_t integer) at most.
 * But DPVS route has more information needed to store: dest/source IP, gateway,
 * mtu, outgoing device...To solve the problem, an indexed route array is used.
 * */
struct rt6_array {
    uint32_t num;       /* total entry number */
    uint32_t cursor;    /* positon of lastest insert, for fast search */
    void *entries[0];   /* route entry array, each elem is a pointer to route6 */
};
#define g_nroutes   (this_rt6_array->num)

static uint8_t g_lcore_number = 0;
static uint64_t g_lcore_mask = 0;

static uint32_t g_lpm6_conf_max_rules = LPM6_CONF_MAX_RULES_DEF;
static uint32_t g_lpm6_conf_num_tbl8s = LPM6_CONF_NUM_TBL8S_DEF;
static uint32_t g_rt6_array_size = RT6_ARRAY_SIZE_DEF;
static uint32_t g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;

static RTE_DEFINE_PER_LCORE(struct rte_lpm6*, dpvs_lpm6_struct);
static RTE_DEFINE_PER_LCORE(struct rt6_array*, dpvs_rt6_array);
static RTE_DEFINE_PER_LCORE(struct route6*, dpvs_rt6_default); /*lpm6 not support ::/0 */

/* Why need hash lists while using LPM6?
 * LPM6 can help find the best match route rule, but cannot find any route rule we want.
 * For example, assume there exists two rules with rt_addr
 *      FE80::0/16 --> rt6_array::entries[0]
 *      FE80::0/64 --> rt6_array::entries[1]
 * LPM6 lookup would never hit the first rule using 'rte_lpm6_lookup'.
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
    if (this_rt6_array->num >= g_rt6_array_size)
        return EDPVS_NOROOM;
    for (ii = (this_rt6_array->cursor+1) % g_rt6_array_size;
            ii != this_rt6_array->cursor;
            ii = (ii+1) % g_rt6_array_size) {
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
            sizeof(struct rt6_array)+sizeof(void*)*g_rt6_array_size, 0);
    if (unlikely(this_rt6_array == NULL)) {
        RTE_LOG(ERR, RT6, "%s: no memory to create rt6_array!", __func__);
        return EDPVS_NOMEM;
    }

    this_rt6_hash = rte_zmalloc("rt6_hash",
            sizeof(struct list_head)*g_rt6_hash_bucket, 0);
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
    struct route6 *entry;

    for (i = 0; i < g_rt6_hash_bucket; i++) {
        list_for_each_entry(entry, &this_rt6_hash[i], hnode) {
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

static struct route6 *rt6_lpm_lookup(const struct in6_addr *addr)
{
    uint32_t idx;
    struct route6 *rt6;

    if (rte_lpm6_lookup(this_lpm6_struct, (uint8_t*)addr, &idx) != 0)
        return this_rt6_default;

    assert(idx >= 0 && idx < g_rt6_array_size);
    rt6 = this_rt6_array->entries[idx];

    return rt6;
}

static struct route6 *rt6_lpm_input(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt6;

    rt6 = rt6_lpm_lookup(&fl6->fl6_daddr);
    if (!rt6)
        return NULL;

    /* FIXME: search hash list for detailed match ? */
    if (rt6->rt6_dev && fl6->fl6_oif && rt6->rt6_dev->id != fl6->fl6_oif->id)
        goto miss;

    rte_atomic32_inc(&rt6->refcnt);
    return rt6;

miss:
    if (rt6)
        route6_put(rt6);
    return NULL;
}

static struct route6 *rt6_lpm_output(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt6;

    rt6 = rt6_lpm_lookup(&fl6->fl6_daddr);
    if (!rt6)
        return NULL;

    /* FIXME: search hash list for detailed match ? */
    if (rt6->rt6_dev && fl6->fl6_oif && rt6->rt6_dev->id != fl6->fl6_oif->id)
        goto miss;

    rte_atomic32_inc(&rt6->refcnt);
    return rt6;

miss:
    if (rt6)
        route6_put(rt6);
    return NULL;
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
                    rt6_cfg->dst.plen)) {
            /* Do not match rt6_cfg->ifname, because LPM6 does not support
             * the same rt_addr_t with different ifname */
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

#ifdef DPVS_RT6_DEBUG
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

#ifdef DPVS_RT6_DEBUG
    RTE_LOG(DEBUG, RT6, "[%d] %s(default via dev %s)->this_rt6_default OK!\n",
            rte_lcore_id(), __func__, rt6_cfg->ifname);
#endif

    return EDPVS_OK;
}

static int rt6_lpm_add_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{
    uint32_t idx;
    int hashkey, ret;
    char buf[64];
    struct route6 *entry;

    assert(rt6_cfg != NULL);

    if (rt6_default(&rt6_cfg->dst))
        return rt6_add_lcore_default(rt6_cfg);

    ret = rt6_find_free_array_idx(&idx);
    if (unlikely(ret != EDPVS_OK))
        goto rt6_add_fail;

    entry = rte_zmalloc("rt6_entry", sizeof(struct route6), 0);
    if (unlikely(entry == NULL)) {
        ret = EDPVS_NOMEM;
        goto rt6_add_fail;
    }
    rt6_fill_with_cfg(entry, rt6_cfg);
    rte_atomic32_set(&entry->refcnt, 1);

    ret = rte_lpm6_add(this_lpm6_struct, (uint8_t*)&entry->rt6_dst.addr,
            (uint8_t)entry->rt6_dst.plen, idx);
    if (unlikely(ret < 0)) {
        ret = EDPVS_DPDKAPIFAIL;
        goto rt6_lpm_fail;
    }

    entry->arr_idx = idx;
    this_rt6_array->num++;
    this_rt6_array->cursor = idx;
    this_rt6_array->entries[idx] = entry;
    hashkey = rt6_hash_key(&entry->rt6_dst);
    list_add_tail(&entry->hnode, &this_rt6_hash[hashkey]);

#ifdef DPVS_RT6_DEBUG
    dump_rt6_prefix(&rt6_cfg->dst, buf, sizeof(buf));
    RTE_LOG(DEBUG, RT6, "[%d] %s(%s via dev %s)->rt6_hash[%d]:rt6_array[%d] OK!"
            " %d routes exist.\n", rte_lcore_id(), __func__, buf,
            rt6_cfg->ifname, hashkey, idx, this_rt6_array->num);
#endif
    return EDPVS_OK;

rt6_lpm_fail:
    rte_free(entry);
rt6_add_fail:
    dump_rt6_prefix(&rt6_cfg->dst, buf, sizeof(buf));
    RTE_LOG(ERR, RT6, "%s[%d]: rte_lpm6_add %s failed -- %s!\n", __func__,
            rte_lcore_id(), buf, dpvs_strerror(ret));
    return ret;
}

static int rt6_lpm_del_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{
    int hashkey, ret;
    struct route6 *entry, *next;
#ifdef DPVS_RT6_DEBUG
    char buf[64];
#endif

    assert(rt6_cfg != NULL);

    if (rt6_default(&rt6_cfg->dst))
        return rt6_del_lcore_default(rt6_cfg);

    hashkey = rt6_hash_key(&rt6_cfg->dst);
    list_for_each_entry_safe(entry, next, &this_rt6_hash[hashkey], hnode) {
        if (entry->rt6_dst.plen == rt6_cfg->dst.plen &&
                strcmp(rt6_cfg->ifname, entry->rt6_dev->name) == 0 &&
                ipv6_prefix_equal(&entry->rt6_dst.addr.in6, &rt6_cfg->dst.addr.in6,
                    rt6_cfg->dst.plen)) {
            /* hit! route source is not checked */
            ret = rte_lpm6_delete(this_lpm6_struct, (uint8_t *)&entry->rt6_dst.addr,
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
#ifdef DPVS_RT6_DEBUG
            dump_rt6_prefix(&rt6_cfg->dst, buf, sizeof(buf));
            RTE_LOG(DEBUG, RT6, "[%d] %s(%s via dev %s)->rt6_hash[%d]:rt6_array[%d] OK!"
                    " %d routes left.\n", rte_lcore_id(), __func__, buf,
                    rt6_cfg->ifname, hashkey, entry->arr_idx, this_rt6_array->num-1);
#endif
            list_del(&entry->hnode);
            this_rt6_array->entries[entry->arr_idx] = NULL;
            this_rt6_array->num--;
            route6_free(entry);
            /* no further search */
            break;
        }
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
            if (dev && dev->id != entry->rt6_dev->id)
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

    if (lpm6_max_rules < 16 || lpm6_max_rules > 2147483647) {
        RTE_LOG(WARNING, RT6, "invalid route6:lpm6_max_rules %s, "
                "using default %d\n", str, LPM6_CONF_MAX_RULES_DEF);
        g_lpm6_conf_max_rules = LPM6_CONF_MAX_RULES_DEF;
    } else {
        RTE_LOG(INFO, RT6, "route6:lpm6_max_rules = %d\n", lpm6_max_rules);
        g_lpm6_conf_max_rules = lpm6_max_rules;
    }

    FREE_PTR(str);
}

static void rt6_lpm6_num_tbl8s_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t lpm6_num_tbl8s = atoi(str);

    if (lpm6_num_tbl8s < 16 || lpm6_num_tbl8s > 2147483647) {
        RTE_LOG(WARNING, RT6, "invalid route6:lpm6_num_tbl8s %s, "
                "using default %d\n", str, LPM6_CONF_NUM_TBL8S_DEF);
        g_lpm6_conf_num_tbl8s = LPM6_CONF_NUM_TBL8S_DEF;
    } else {
        RTE_LOG(INFO, RT6, "route6:lpm6_num_tbl8s = %d\n", lpm6_num_tbl8s);
        g_lpm6_conf_num_tbl8s = lpm6_num_tbl8s;
    }

    FREE_PTR(str);
}

static void rt6_array_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t array_size = atoi(str);

    if (array_size < 16 || array_size > 2147483647) {
        RTE_LOG(WARNING, RT6, "invalid route6:array_size %s, "
                "using default %d\n", str, RT6_ARRAY_SIZE_DEF);
        g_rt6_array_size = RT6_ARRAY_SIZE_DEF;
    } else {
        RTE_LOG(INFO, RT6, "route6:array_size = %d\n", array_size);
        g_rt6_array_size = array_size;
    }

    FREE_PTR(str);
}

static void rt6_hash_bucket_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t hash_buckets = atoi(str);

    if (hash_buckets < 16 || hash_buckets > 2147483647) {
        RTE_LOG(WARNING, RT6, "invalid route6:hash_bucket %s, "
                "using default %d\n", str, RT6_HASH_BUCKET_DEF);
        g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;
    } else {
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
        g_rt6_array_size = RT6_ARRAY_SIZE_DEF;
        g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;
    }
}

void install_rt6_lpm_keywords(void)
{
    install_keyword("lpm", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("lpm6_max_rules", rt6_lpm6_max_rules_handler, KW_TYPE_INIT);
    install_keyword("lpm6_num_tbl8s", rt6_lpm6_num_tbl8s_handler, KW_TYPE_INIT);
    install_keyword("rt6_array_size", rt6_array_size_handler, KW_TYPE_INIT);
    install_keyword("rt6_hash_bucket", rt6_hash_bucket_handler, KW_TYPE_INIT);
    install_sublevel_end();
}
