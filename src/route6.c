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
#include<assert.h>
#include <rte_lpm6.h>
#include "route6.h"
#include "linux_ipv6.h"
#include "ctrl.h"

#define RTE_LOGTYPE_RT6     RTE_LOGTYPE_USER1

#define LPM6_CONF_MAX_RULES_DEF         1024
#define LPM6_CONF_NUM_TBL8S_DEF         (1<<16)

#define RT6_ARRAY_SIZE_MAX_SUPPORTED    (1<<32)
#define RT6_ARRAY_SIZE_DEF              (1<<16)
#define RT6_HASH_BUCKET_DEF             (1<<8)

#define this_lpm6_struct    (RTE_PER_LCORE(dpvs_lpm6_struct))
#define this_rt6_array      (RTE_PER_LCORE(dpvs_rt6_array))
#define this_rt6_hash       (RTE_PER_LCORE(dpvs_rt6_hash))

/* DPDK LPM6 can store 4 bytes route information(i.e. an uint32_t integer) at most.
 * But DPVS route has more information needed to store: dest/source IP, gateway,
 * mtu, outgoing device...To solve the problem, an indexed route array is used.
 * */
struct rt6_array {
    uint32_t num;       /* total entry number */
    uint32_t cursor;    /* positon of lastest insert, for fast search */
    void *entries[0];   /* route entry array, each elem is a pointer to route6 */
};
    
static uint8_t g_lcore_number = 0;
static uint64_t g_lcore_mask = 0;

static uint32_t g_lpm6_conf_max_rules = LPM6_CONF_MAX_RULES_DEF;
static uint32_t g_lpm6_conf_num_tbl8s = LPM6_CONF_NUM_TBL8S_DEF;
static uint32_t g_rt6_array_size = RT6_ARRAY_SIZE_DEF;
static uint32_t g_rt6_hash_bucket = RT6_HASH_BUCKET_DEF;

static RTE_DEFINE_PER_LCORE(struct rte_lpm6*, dpvs_lpm6_struct);
static RTE_DEFINE_PER_LCORE(struct rt6_array*, dpvs_rt6_array);

/* Why need hash lists while using LPM6?
 * LPM6 can help find the best match route rule, but cannot find any route rule we want.
 * For example, assume there exists two rules with rt6_prefix
 *      FE80::0/16 --> rt6_array::entries[0]
 *      FE80::0/64 --> rt6_array::entries[1]
 * LPM6 lookup would never hit the first rule using 'rte_lpm6_lookup'.
 * So we cannot obtain the first rule when the control plane need to add/del/modify it.
 * Thus a hash list is needed for route6 control plane.
 */
static RTE_DEFINE_PER_LCORE(struct list_head*, dpvs_rt6_hash);

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

static inline int rt6_hash_key(const struct rt6_prefix *rt6_p)
{
    /* Debug the hash performance? */
    return rte_jhash_32b((const uint32_t *)&rt6_p->addr, 4,
            rt6_p->plen) % g_rt6_hash_bucket;
}

static int rt6_setup_lcore(void *arg)
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

    if (!(g_lcore_mask & (1<<cid))) {
        /* skip idle lcore for memory save */
        this_rt6_array = NULL;
        this_lpm6_struct = NULL;
        return EDPVS_OK;
    }

    this_rt6_array = rte_zmalloc_socket("rt6_array",
            sizeof(struct rt6_array)+sizeof(void*)*g_rt6_array_size, 0, socketid);
    if (unlikely(this_rt6_array == NULL)) {
        RTE_LOG(ERR, RT6, "%s: no memory to create rt6_array!", __func__);
        return EDPVS_NOMEM;
    }

    this_rt6_hash = rte_zmalloc_socket("rt6_hash",
            sizeof(struct list_head)*g_rt6_hash_bucket, 0, socketid);
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

static int rt6_destroy_lcore(void *arg)
{
    int i;
    struct route6 *hnode;

    /* free all route entries in spite of refcnt */
    for (i = 0; i < g_rt6_hash_bucket; i++) {
        list_for_each_entry(hnode, &this_rt6_hash[i], hnode)
            rte_free(hnode);
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

static struct route6 *rt6_lpm6_lookup(const struct in6_addr *addr)
{
    uint32_t idx;
    struct route6 *rt6;
    
    if (rte_lpm6_lookup(this_lpm6_struct, (uint8_t*)addr, &idx) != 0)
        return NULL;
    assert(idx >= 0 && idx < g_rt6_array_size);

    rt6 = this_rt6_array->entries[idx];
    rte_atomic32_inc(&rt6->refcnt);

    return rt6;
}

struct route6 *route6_input(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt6;

    rt6 = rt6_lpm6_lookup(&fl6->fl6_daddr);
    if (!rt6)
        return NULL;

    /* FIXME: search hash list for detailed match ? */
    if (rt6->rt6_dev->id != fl6->fl6_oif->id)
        goto miss;
    if (!ipv6_addr_equal(&rt6->rt6_src.addr, &fl6->fl6_saddr))
        goto miss;

    return rt6;

miss:
    if (rt6)
        route6_put(rt6);
    return NULL;
}

struct route6 *route6_output(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt6;
    
    rt6 = rt6_lpm6_lookup(&fl6->fl6_daddr);
    if (!rt6)
        return NULL;

    /* FIXME: search hash list for detailed match ? */
    if (rt6->rt6_dev->id != fl6->fl6_oif->id)
        goto miss;
    if (!ipv6_addr_equal(&rt6->rt6_src.addr, &fl6->fl6_saddr))
        goto miss;

    return rt6;

miss:
    if (rt6)
        route6_put(rt6);
    return NULL;
}

int route6_put(struct route6 *rt)
{
    rte_atomic32_dec(&rt->refcnt);
    return EDPVS_OK;
}

__rte_unused static int rt6_add_lcore(const struct route6 *rt6)
{
    uint32_t idx;
    int hashkey, ret;
    char buf[64];
    struct route6 *entry;

    ret = rt6_find_free_array_idx(&idx);
    if (unlikely(ret != EDPVS_OK))
        goto rt6_add_fail;

    entry = rte_zmalloc_socket("rt6_entry", sizeof(struct route6), 0, rte_socket_id());
    if (unlikely(entry == NULL)) {
        ret = EDPVS_NOMEM;
        goto rt6_add_fail;
    }

    ret = rte_lpm6_add(this_lpm6_struct, (uint8_t*)&rt6->rt6_dst.addr,
            (uint8_t)rt6->rt6_dst.plen, idx);
    if (unlikely(ret < 0)) {
        ret = EDPVS_DPDKAPIFAIL;
        goto rt6_lpm_fail;
    }

    memcpy(entry, rt6, sizeof(struct route6));
    rte_atomic32_set(&entry->refcnt, 1);
    entry->arr_idx = idx;
    hashkey = rt6_hash_key(&entry->rt6_dst);
    list_add_tail(&entry->hnode, &this_rt6_hash[hashkey]);

    return EDPVS_OK;

rt6_lpm_fail:
    rte_free(entry);
rt6_add_fail:
    dump_rt6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
    RTE_LOG(ERR, RT6, "%s[%d]: rte_lpm6_add %s failed -- %s!\n", __func__,
            rte_lcore_id(), buf, dpvs_strerror(ret));
    return ret;
}

int route6_add(const struct route6 *rt6)
{
    return EDPVS_OK;
}

int route6_del(const struct route6 *rt6)
{
    return EDPVS_OK;
}

static int rt6_msg_process_cb(struct dpvs_msg *msg)
{
    return EDPVS_OK;
}

int route6_init(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    netif_get_slave_lcores(&g_lcore_number, &g_lcore_mask);

    rte_eal_mp_remote_launch(rt6_setup_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(ERR, RT6, "%s: fail to setup rt6 on lcore%d -- %s\n",
                    __func__, cid, dpvs_strerror(err));
            return EDPVS_DPDKAPIFAIL;
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type           = MSG_TYPE_ROUTE6;
    msg_type.mode           = DPVS_MSG_MULTICAST;
    msg_type.cid            = rte_lcore_id();
    msg_type.unicast_msg_cb = rt6_msg_process_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, RT6, "%s: fail to register route6 msg!\n", __func__);
        return err;
    }

    return EDPVS_OK;
}

int route6_term(void)
{
    int err;
    lcoreid_t cid;

    rte_eal_mp_remote_launch(rt6_destroy_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, RT6, "%s: fail to destroy rt6 on lcore%d -- %s\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}
