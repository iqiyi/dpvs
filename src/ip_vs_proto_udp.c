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
#include "dpdk.h"
#include "ipv4.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_udp.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"
#include "parser/parser.h"

int g_defence_udp_drop = 0;

static int udp_timeouts[DPVS_UDP_S_LAST + 1] = {
    [DPVS_UDP_S_NORMAL] = 300,
    [DPVS_UDP_S_LAST]   = 2,
};

static int udp_conn_sched(struct dp_vs_proto *proto,
                        const struct dp_vs_iphdr *iph,
                        struct rte_mbuf *mbuf,
                        struct dp_vs_conn **conn,
                        int *verdict)
{
    struct udp_hdr *uh, _udph;
    struct dp_vs_service *svc;
    assert(proto && iph && mbuf && conn && verdict);

    uh = mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    if (unlikely(!uh)) {
        *verdict = INET_DROP;
        return EDPVS_INVPKT;
    }

    /* lookup service <vip:vport> */
    svc = dp_vs_service_lookup(iph->af, iph->proto,
                               &iph->daddr, uh->dst_port, 0, mbuf, NULL);
    if (!svc) {
        *verdict = INET_ACCEPT;
        return EDPVS_NOSERV;
    }

    /* schedule RS and create new connection */
    *conn = dp_vs_schedule(svc, iph, mbuf, false);
    if (!*conn) {
        dp_vs_service_put(svc);
        *verdict = INET_DROP;
        return EDPVS_RESOURCE;
    }

    dp_vs_service_put(svc);
    return EDPVS_OK;
}

static struct dp_vs_conn *
udp_conn_lookup(struct dp_vs_proto *proto,
                const struct dp_vs_iphdr *iph,
                struct rte_mbuf *mbuf, 
                int *direct, bool reverse)
{
    struct udp_hdr *uh, _udph;
    assert(proto && iph && mbuf);

    uh = mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    if (unlikely(!uh))
        return NULL;

    return dp_vs_conn_get(iph->af, iph->proto, 
                          &iph->saddr, &iph->daddr, 
                          uh->src_port, uh->dst_port, 
                          direct, reverse);
}

static int udp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                           struct rte_mbuf *mbuf, int dir)
{
    conn->state = DPVS_UDP_S_NORMAL;
    conn->timeout.tv_sec = udp_timeouts[conn->state];
    return EDPVS_OK;
}

static int udp_fnat_in_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->lport;
    uh->dst_port    = conn->dport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

    return EDPVS_OK;
}

static int udp_fnat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->vport;
    uh->dst_port    = conn->cport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

    return EDPVS_OK;
}

static int udp_snat_in_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->dst_port    = conn->dport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

    return EDPVS_OK;
}

static int udp_snat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->vport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

    return EDPVS_OK;
}

struct dp_vs_proto dp_vs_proto_udp = {
    .name               = "UDP",
    .proto              = IPPROTO_UDP,
    .conn_sched         = udp_conn_sched,
    .conn_lookup        = udp_conn_lookup,
    .state_trans        = udp_state_trans,
    .fnat_in_handler    = udp_fnat_in_handler,
    .fnat_out_handler   = udp_fnat_out_handler,
    .snat_in_handler    = udp_snat_in_handler,
    .snat_out_handler   = udp_snat_out_handler,
};

static void defence_udp_drop_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "defence_udp_drop ON\n");
    g_defence_udp_drop = 1;
}

static void timeout_normal_handler(vector_t tokens)
{
    int timeout;
    char *str = set_value(tokens);

    assert(str);
    timeout = atoi(str);
    if (timeout > IPVS_TIMEOUT_MIN && timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "udp_timeout_normal = %d\n", timeout);
        udp_timeouts[DPVS_UDP_S_NORMAL] = timeout;
    } else {
        RTE_LOG(INFO, IPVS, "invalid udp_timeout_normal %s, using default %d\n",
                str, 300);
        udp_timeouts[DPVS_UDP_S_NORMAL] = 300;
    }

    FREE_PTR(str);
}

static void timeout_last_handler(vector_t tokens)
{
    int timeout;
    char *str = set_value(tokens);

    assert(str);
    timeout = atoi(str);
    if (timeout > IPVS_TIMEOUT_MIN && timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "udp_timeout_last = %d\n", timeout);
        udp_timeouts[DPVS_UDP_S_LAST] = timeout;
    } else {
        RTE_LOG(INFO, IPVS, "invalid udp_timeout_last %s, using default %d\n",
                str, 2);
        udp_timeouts[DPVS_UDP_S_LAST] = 2;
    }

    FREE_PTR(str);
}

void udp_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
    }

    /* KW_TYPE_NORMAL keyword */
    g_defence_udp_drop = 0;
    udp_timeouts[DPVS_UDP_S_NORMAL] = 300;
    udp_timeouts[DPVS_UDP_S_LAST] = 2;
}

void install_proto_udp_keywords(void)
{
    install_keyword("defence_udp_drop", defence_udp_drop_handler, KW_TYPE_NORMAL);

    install_keyword("timeout", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("normal", timeout_normal_handler, KW_TYPE_NORMAL);
    install_keyword("last", timeout_last_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
}
