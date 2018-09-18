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
#include "common.h"
#include "ipv4.h"
#include "ipvs/ipvs.h"
#include "ipvs/pkt_fwd.h"

#define DPVS_PKT_FWD_RING_SIZE  4096

static struct rte_ring *dp_vs_pkt_fwd_ring[DPVS_MAX_LCORE][DPVS_MAX_LCORE];

void dp_vs_pkt_fwd_ring_proc(struct netif_queue_conf *qconf, lcoreid_t cid)
{
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    uint16_t nb_rb;
    lcoreid_t peer_cid;

    cid = rte_lcore_id();

    for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
        if (dp_vs_pkt_fwd_ring[cid][peer_cid]) {
            nb_rb = rte_ring_dequeue_burst(dp_vs_pkt_fwd_ring[cid][peer_cid],
                                           (void**)mbufs,
                                           NETIF_MAX_PKT_BURST, NULL);
            if (nb_rb > 0) {
                lcore_process_packets(qconf, mbufs, cid, nb_rb, 0);
            }
        }
    }
}

/**
 * Forward the packet to the found redirect owner core.
 */
int dp_vs_pkt_fwd(struct rte_mbuf *mbuf, lcoreid_t peer_cid)
{
    lcoreid_t cid = rte_lcore_id();
    int ret;

    ret = rte_ring_enqueue(dp_vs_pkt_fwd_ring[peer_cid][cid], mbuf);
    if (ret < 0) {
        RTE_LOG(WARNING, IPVS,
                "%s: [%d] failed to enqueue mbuf to pkt_fwd_ring[%d][%d]\n",
                __func__, cid, peer_cid, cid);
        return INET_DROP;
    }

    return INET_STOLEN;
}

/*
 * Each lcore allocates the packet forward rings with the other lcores
 * respectively.
 */
static int dp_vs_pkt_fwd_ring_init(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
    lcoreid_t cid, peer_cid;

    socket_id = rte_socket_id();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (cid == rte_get_master_lcore() || !rte_lcore_is_enabled(cid)) {
            continue;
        }

        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            if (!rte_lcore_is_enabled(peer_cid)
                || peer_cid == rte_get_master_lcore()
                || cid == peer_cid)
            {
                continue;
            }

            snprintf(name_buf, RTE_RING_NAMESIZE,
                     "dp_vs_pkt_fwd_ring[%d[%d]", cid, peer_cid);

            dp_vs_pkt_fwd_ring[cid][peer_cid] =
                rte_ring_create(name_buf, DPVS_PKT_FWD_RING_SIZE, socket_id,
                                RING_F_SP_ENQ | RING_F_SC_DEQ);

            if (!dp_vs_pkt_fwd_ring[cid][peer_cid]) {
                RTE_LOG(WARNING, IPVS,
                        "%s: failed to create pkt_fwd_ring[%d][%d]\n",
                        __func__, cid, peer_cid);
                return EDPVS_NOMEM;
            } else {
                RTE_LOG(WARNING, IPVS,
                        "%s: created pkt_fwd_ring[%d][%d]\n",
                        __func__, cid, peer_cid);
            }
        }
    }

    return EDPVS_OK;
}

static int dp_vs_pkt_fwd_ring_free(void)
{
    lcoreid_t cid, peer_cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        for (peer_cid = 0; peer_cid < DPVS_MAX_LCORE; peer_cid++) {
            rte_ring_free(dp_vs_pkt_fwd_ring[cid][peer_cid]);
        }
    }

    return EDPVS_OK;
}

int dp_vs_pkt_fwd_init(void)
{
    return dp_vs_pkt_fwd_ring_init();
}

int dp_vs_pkt_fwd_term(void)
{
    return dp_vs_pkt_fwd_ring_free();
}
