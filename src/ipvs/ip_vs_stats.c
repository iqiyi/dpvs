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
#include "conf/common.h"
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

void dp_vs_stats_clear(struct dp_vs_stats *stats)
{
    stats->conns    = 0;
    stats->inpkts   = 0;
    stats->inbytes  = 0;
    stats->outpkts  = 0;
    stats->outbytes = 0;
}

int dp_vs_stats_add(struct dp_vs_stats *dst, struct dp_vs_stats *src)
{
    dst->conns    += src->conns;
    dst->inpkts   += src->inpkts;
    dst->inbytes  += src->inbytes;
    dst->outbytes += src->outbytes;
    dst->outpkts  += src->outpkts;
    return EDPVS_OK;
}

int dp_vs_stats_in(struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    assert(conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;

    if (dest && dp_vs_dest_is_avail(dest)) {
        /*limit rate*/
        if ((dest->limit_proportion < 100) &&
            (dest->limit_proportion > 0)) {
            return (rand()%100) > dest->limit_proportion
                        ? EDPVS_OVERLOAD : EDPVS_OK;
        }

        dest->stats.inpkts++;
        dest->stats.inbytes += mbuf->pkt_len;
    }

#ifdef CONFIG_DPVS_IPVS_STATS_DEBUG
    rte_atomic64_inc(&conn->stats.inpkts);
    rte_atomic64_add(&conn->stats.inbytes, mbuf->pkt_len);
#endif

    this_dpvs_stats.inpkts++;
    this_dpvs_stats.inbytes += mbuf->pkt_len;
    return EDPVS_OK;
}

int dp_vs_stats_out(struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    assert(conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;

    if (dest && dp_vs_dest_is_avail(dest)) {
        /*limit rate*/
        if ((dest->limit_proportion < 100) &&
            (dest->limit_proportion > 0)) {
            return (rand()%100) > dest->limit_proportion
            ? EDPVS_OVERLOAD : EDPVS_OK;
        }

        dest->stats.outpkts++;
        dest->stats.outbytes += mbuf->pkt_len;
    }

#ifdef CONFIG_DPVS_IPVS_STATS_DEBUG
    rte_atomic64_inc(&conn->stats.outpkts);
    rte_atomic64_add(&conn->stats.outbytes, mbuf->pkt_len);
#endif

    this_dpvs_stats.outpkts++;
    this_dpvs_stats.outbytes += mbuf->pkt_len;
    return EDPVS_OK;
}

void dp_vs_stats_conn(struct dp_vs_conn *conn)
{
    assert(conn && conn->dest);

    conn->dest->stats.conns++;
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
    dp_vs_estats_clear();
    srand(rte_rdtsc());
    return EDPVS_OK;
}

int dp_vs_stats_term(void)
{
    return EDPVS_OK;
}
