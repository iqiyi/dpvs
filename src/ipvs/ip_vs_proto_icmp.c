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
/**
 * icmp protocol for DPVS.
 *
 * raychen@qiyi.com, July 2017.
 */
#include <assert.h>
#include <linux/icmp.h>
#include "dpdk.h"
#include "common.h"
#include "inet.h"
#include "ipv4.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_icmp.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"

/*
 * o ICMP tuple
 *
 *   Unlike TCP/UDP/SCTP, ICMP has no port for demultiplexing.
 *   But we still need tuple to matching the packets for both directions.
 *
 *     <type-code, id>
 *
 *     1. save when create ip_vs_conn{}
 *     2. lookup for when conn_in_get/conn_out_get{}
 *
 *     For reply, id/code are not changed, type changes. When look up,
 *     tuple also should be inverted.
 *
 *   it seems not necessary to save icmp tuple to ip_vs_service{}.
 *
 * o NATing for payloads
 *
 *   + For ICMP non-error messages,
 *     ICMP header and payload are not changed when NATing.
 *
 *     ICMP SNAT/DNAT only mapping the L3 address, which can be done with
 *      - ip_vs_nat_xmit() or ip_vs_out_snat_xmit()
 *      - handle_response()
 *
 *   + For ICMP-Error, which includes original IP packet as payload:
 *     Those embedded IPs are not be handled here IPVS core.
 */

static int icmp_timeouts[DPVS_ICMP_S_LAST + 1] = {
    [DPVS_ICMP_S_NORMAL]    = 300,
    [DPVS_ICMP_S_LAST]      = 2,
};

static int icmp_conn_sched(struct dp_vs_proto *proto,
                           const struct dp_vs_iphdr *iph,
                           struct rte_mbuf *mbuf,
                           struct dp_vs_conn **conn,
                           int *verdict)
{
    struct icmphdr *ich, _icmph;
    struct dp_vs_service *svc;
    assert(proto && iph && mbuf && conn && verdict);

    ich = mbuf_header_pointer(mbuf, iph->len, sizeof(_icmph), &_icmph);
    if (unlikely(!ich)) {
        *verdict = INET_DROP;
        return EDPVS_INVPKT;
    }

    svc = dp_vs_service_lookup(iph->af, iph->proto,
                               &iph->daddr, 0, 0, mbuf, NULL);
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

static const uint8_t invmap[] = {
	[ICMP_ECHO] = ICMP_ECHOREPLY + 1,
	[ICMP_ECHOREPLY] = ICMP_ECHO + 1,
	[ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY + 1,
	[ICMP_TIMESTAMPREPLY] = ICMP_TIMESTAMP + 1,
	[ICMP_INFO_REQUEST] = ICMP_INFO_REPLY + 1,
	[ICMP_INFO_REPLY] = ICMP_INFO_REQUEST + 1,
	[ICMP_ADDRESS] = ICMP_ADDRESSREPLY + 1,
	[ICMP_ADDRESSREPLY] = ICMP_ADDRESS + 1
};

static bool icmp_invert_type(uint8_t *type, uint8_t orig)
{
	if (orig >= sizeof(invmap) || !invmap[orig])
		return false;

	*type = invmap[orig] - 1;
	return true;
}

static bool is_icmp_reply(uint8_t type)
{
	if (type == ICMP_ECHOREPLY
			|| type == ICMP_TIMESTAMPREPLY
			|| type == ICMP_INFO_REPLY
			|| type == ICMP_ADDRESSREPLY)
		return true;
	else
		return false;
}

static struct dp_vs_conn *icmp_conn_lookup(struct dp_vs_proto *proto,
                                           const struct dp_vs_iphdr *iph,
                                           struct rte_mbuf *mbuf, int *direct, 
                                           bool reverse, bool *drop)
{
    struct icmphdr *ich, _icmph;
    __be16 sport, dport; /* dummy ports */
    uint8_t type;
    assert(proto && iph && mbuf);

    ich = mbuf_header_pointer(mbuf, iph->len, sizeof(_icmph), &_icmph);
    if (unlikely(!ich))
        return NULL;

    if (!is_icmp_reply(ich->type)) {
        sport = ich->un.echo.id;
        dport = ich->type << 8 | ich->code;
    } else if (icmp_invert_type(&type, ich->type)) {
        sport = type << 8 | ich->code;
        dport = ich->un.echo.id;
    } else {
        return NULL;
    }

    return dp_vs_conn_get(iph->af, iph->proto, &iph->saddr, &iph->daddr,
                          sport, dport, direct, reverse);
}

static int icmp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                            struct rte_mbuf *mbuf, int dir)
{
    conn->state = DPVS_ICMP_S_NORMAL;
    conn->timeout.tv_sec = icmp_timeouts[conn->state];
    return EDPVS_OK;
}

struct dp_vs_proto dp_vs_proto_icmp = {
    .name           = "ICMP",
    .proto          = IPPROTO_ICMP,
    .conn_sched     = icmp_conn_sched,
    .conn_lookup    = icmp_conn_lookup,
    .state_trans    = icmp_state_trans,
};
