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
#include <assert.h>
#include "common.h"
#include "netif.h"
#include "list.h"
#include "ctrl.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "ipvs/service.h"
#include "ipvs/stats.h"

#define this_dpvs_stats             (dpvs_stats[rte_lcore_id()])
#define this_dpvs_estats            (dpvs_estats[rte_lcore_id()])

static struct dp_vs_stats dpvs_stats[DPVS_MAX_LCORE];
static struct dp_vs_estats dpvs_estats[DPVS_MAX_LCORE];

static void __dp_vs_stats_clear(struct dp_vs_stats *stats)
{
    stats->conns    = 0;
    stats->inpkts   = 0;
    stats->inbytes  = 0;
    stats->outpkts  = 0;
    stats->outbytes = 0;
}

void dp_vs_stats_clear(void)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;

    /* get configured data-plane lcores */
    netif_get_slave_lcores(&nlcore, &lcore_mask);

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue; /* unused */

        __dp_vs_stats_clear(&dpvs_stats[i]);
    }

    return;
}

/*add this code for per core stats*/
void dp_svc_stats_clear(struct dp_vs_stats *stats)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;

    netif_get_slave_lcores(&nlcore, &lcore_mask);

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue;
        __dp_vs_stats_clear(&stats[i]);
    }
}


static struct dp_vs_stats* alloc_percpu_stats(void)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;
    struct dp_vs_stats* svc_stats;

    netif_get_slave_lcores(&nlcore, &lcore_mask);
    svc_stats = rte_malloc_socket(NULL, sizeof(struct dp_vs_stats) * DPVS_MAX_LCORE,
                                   RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!svc_stats)
        return NULL;

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue;
        __dp_vs_stats_clear(&svc_stats[i]);
    } 
    
    return svc_stats;
}

int dp_vs_new_stats(struct dp_vs_stats **p)
{
    *p = alloc_percpu_stats();
    if (NULL == *p) {
        RTE_LOG(WARNING, SERVICE, "%s: no memory!\n", __func__);
        return EDPVS_NOMEM;
    }
    return EDPVS_OK;
}

void dp_vs_del_stats(struct dp_vs_stats *p)
{
    if (p)
        rte_free(p);
}

void dp_vs_zero_stats(struct dp_vs_stats* stats)
{
    uint8_t nlcore, i;
    uint64_t lcore_mask;
    
    netif_get_slave_lcores(&nlcore,&lcore_mask);

    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        if (!(lcore_mask & (1L<<i)))
            continue;
        __dp_vs_stats_clear(&stats[i]);
    } 
    return;
}

static int get_stats_uc_cb(struct dpvs_msg *msg)
{
    struct dp_vs_stats **src;
    lcoreid_t cid;
    assert(msg);
    cid = rte_lcore_id();
    if (msg->len != sizeof(struct dp_vs_stats *)) {
        RTE_LOG(ERR, SERVICE, "%s: bad message.\n", __func__);
        return EDPVS_INVAL;
    }
    src = (struct dp_vs_stats **)msg->data;
    char *reply = rte_malloc(NULL, sizeof(struct dp_vs_stats), RTE_CACHE_LINE_SIZE);
    memcpy(reply, &((*src)[cid]), sizeof(struct dp_vs_stats));
    msg->reply.len = sizeof(struct dp_vs_stats);
    msg->reply.data = (void *)reply;
    return EDPVS_OK;
}

int dp_vs_copy_stats(struct dp_vs_stats* dst, struct dp_vs_stats* src)
{
    struct dpvs_msg *msg;
    struct dpvs_multicast_queue *reply=NULL;
    struct dpvs_msg *cur;
    struct dp_vs_stats *per_stats;
    int err;

    if (!src)
        return EDPVS_INVAL;

    msg = msg_make(MSG_TYPE_STATS_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
			sizeof(struct dp_vs_stats *), &src);
    if (!msg) {   
        return EDPVS_NOMEM;
    }
    err = multicast_msg_send(msg, 0, &reply);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
        return err;
    }
    list_for_each_entry(cur, &reply->mq, mq_node) {
        per_stats = (struct dp_vs_stats *)(cur->data);
        dst->conns += per_stats->conns;
        dst->inpkts += per_stats->inpkts;
        dst->inbytes += per_stats->inbytes;
        dst->outbytes += per_stats->outbytes;
        dst->outpkts += per_stats->outpkts;
    }
    msg_destroy(&msg);
    return EDPVS_OK;
}

static void register_stats_cb(void)
{
    struct dpvs_msg_type mt;
    memset(&mt, 0 ,sizeof(mt));
    mt.type = MSG_TYPE_STATS_GET;
    mt.unicast_msg_cb = get_stats_uc_cb;
    mt.multicast_msg_cb = NULL;
    assert(msg_type_mc_register(&mt) == 0);
}

static void unregister_stats_cb(void)
{
    struct dpvs_msg_type mt;
    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_STATS_GET;
    mt.unicast_msg_cb = get_stats_uc_cb;
    mt.multicast_msg_cb = NULL;
    assert(msg_type_mc_unregister(&mt) == 0);
}

int dp_vs_stats_in(struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    assert(conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;
    lcoreid_t cid;   
    cid = rte_lcore_id();

    if (dest && (dest->flags & DPVS_DEST_F_AVAILABLE)) {
        /*limit rate*/
        if ((dest->limit_proportion < 100) &&
            (dest->limit_proportion > 0)) {
            return (rand()%100) > dest->limit_proportion 
                        ? EDPVS_OVERLOAD : EDPVS_OK;
        }

        dest->stats[cid].inpkts++;
        dest->stats[cid].inbytes += mbuf->pkt_len;
    }

    this_dpvs_stats.inpkts++;
    this_dpvs_stats.inbytes += mbuf->pkt_len;
    return EDPVS_OK;
}

int dp_vs_stats_out(struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    assert(conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;
    lcoreid_t cid;
    cid = rte_lcore_id();

    if (dest && (dest->flags & DPVS_DEST_F_AVAILABLE)) {
        /*limit rate*/
        if ((dest->limit_proportion < 100) && 
            (dest->limit_proportion > 0)) {
            return (rand()%100) > dest->limit_proportion 
			? EDPVS_OVERLOAD : EDPVS_OK; 
        }

        dest->stats[cid].outpkts++;
        dest->stats[cid].outbytes += mbuf->pkt_len;
    }

    this_dpvs_stats.outpkts++;
    this_dpvs_stats.outbytes += mbuf->pkt_len;
    return EDPVS_OK;
}

void dp_vs_stats_conn(struct dp_vs_conn *conn)
{
    assert(conn && conn->dest);
    lcoreid_t cid;

    cid = rte_lcore_id();   
    conn->dest->stats[cid].conns++;
    this_dpvs_stats.conns++;
}

void dp_vs_estats_inc(enum dp_vs_estats_type field)
{
    this_dpvs_estats.mibs[field]++;
}

void dp_vs_estats_clear(void)
{
    memset(&dpvs_estats[0], 0, sizeof(dpvs_estats));
}

uint64_t dp_vs_estats_get(enum dp_vs_estats_type field)
{
    return this_dpvs_estats.mibs[field];
}

int dp_vs_stats_init(void)
{
    dp_vs_stats_clear();
    srand(rte_rdtsc());
    register_stats_cb();
    return EDPVS_OK;
}

int dp_vs_stats_term(void)
{
    unregister_stats_cb();
    return EDPVS_OK;
}
