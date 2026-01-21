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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "conf/common.h"
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route6.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_ah_esp.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"
#include "ipvs/blklst.h"
#include "ipvs/redirect.h"

static int esp_timeouts[DPVS_AH_ESP_S_LAST + 1] = {
    [DPVS_AH_ESP_S_NORMAL] = 300,
    [DPVS_AH_ESP_S_LAST]   = 2,
};

static int esp_conn_sched(struct dp_vs_proto *proto,
                        const struct dp_vs_iphdr *iph,
                        struct rte_mbuf *mbuf,
                        struct dp_vs_conn **conn,
                        int *verdict)
{
/*
    struct dp_vs_service *svc;
    bool outwall = false;
    assert(proto && iph && mbuf && conn && verdict);

    svc = dp_vs_service_lookup(iph->af, iph->proto, &iph->daddr, 0, 0, mbuf, NULL, &outwall, rte_lcore_id());
    if (!svc) {
        *verdict = INET_ACCEPT;
        return EDPVS_NOSERV;
    }

    *conn = dp_vs_schedule(svc, iph, mbuf, false, outwall);
    if (!*conn) {
        *verdict = INET_DROP;
        return EDPVS_RESOURCE;
    }
    return EDPVS_OK;
*/

    // 在发送esp报文之前应该已经通过UDP协商报文建立会话，该流程理应永远不会走到。
    *verdict = INET_ACCEPT;
    return EDPVS_DROP;
}

static struct dp_vs_conn *
esp_conn_lookup(struct dp_vs_proto *proto,
                const struct dp_vs_iphdr *iph,
                struct rte_mbuf *mbuf, int *direct,
                bool reverse, bool *drop, lcoreid_t *peer_cid)
{
    struct dp_vs_conn *conn;
    assert(proto && iph && mbuf);

    conn = dp_vs_conn_get(iph->af, IPPROTO_UDP,
                          &iph->saddr, &iph->daddr,
                          htons(PORT_ISAKMP), htons(PORT_ISAKMP),
                          direct, reverse);

    return conn;
}

static int esp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                            struct rte_mbuf *mbuf, int dir)
{
    conn->state = DPVS_AH_ESP_S_NORMAL;
    conn->timeout.tv_sec = esp_timeouts[conn->state];
    return EDPVS_OK;
}


struct dp_vs_proto dp_vs_proto_ah = {
    .name               = "AH",
    .proto              = IPPROTO_AH,
    .conn_sched         = esp_conn_sched,
    .conn_lookup        = esp_conn_lookup,
    .state_trans        = esp_state_trans,
};

struct dp_vs_proto dp_vs_proto_esp = {
    .name               = "ESP",
    .proto              = IPPROTO_ESP,
    .conn_sched         = esp_conn_sched,
    .conn_lookup        = esp_conn_lookup,
    .state_trans        = esp_state_trans,
};


