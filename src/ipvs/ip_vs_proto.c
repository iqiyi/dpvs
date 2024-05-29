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
#include "dpdk.h"
#include "ipv4.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"

#define DPVS_MAX_PROTOS         256     /* never change it */

static struct dp_vs_proto *dp_vs_protocols[DPVS_MAX_PROTOS];

static int proto_register(struct dp_vs_proto *proto)
{
    /* sanity check */
    if (!proto->name || proto->proto >= DPVS_MAX_PROTOS
            || !proto->conn_sched || !proto->conn_lookup)
        return EDPVS_INVAL;

    if (dp_vs_protocols[proto->proto])
        return EDPVS_EXIST;

    dp_vs_protocols[proto->proto] = proto;

    if (proto->init)
        proto->init(proto);

    return EDPVS_OK;
}

static int proto_unregister(struct dp_vs_proto *proto)
{
    assert(proto && proto->proto < DPVS_MAX_PROTOS);

    if (!dp_vs_protocols[proto->proto])
        return EDPVS_NOTEXIST;

    dp_vs_protocols[proto->proto] = NULL;

    if (proto->exit)
        proto->exit(proto);

    return EDPVS_OK;
}

struct dp_vs_proto *dp_vs_proto_lookup(uint8_t proto)
{
    assert(proto < DPVS_MAX_PROTOS);

    /* NULL if protocol is not registered */
    return dp_vs_protocols[proto];
}

extern struct dp_vs_proto dp_vs_proto_udp;
extern struct dp_vs_proto dp_vs_proto_tcp;
extern struct dp_vs_proto dp_vs_proto_sctp;
extern struct dp_vs_proto dp_vs_proto_icmp;
extern struct dp_vs_proto dp_vs_proto_icmp6;

int dp_vs_proto_init(void)
{
    int err;

    if ((err = proto_register(&dp_vs_proto_udp)) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register UDP\n", __func__);
        return err;
    }

    if ((err = proto_register(&dp_vs_proto_tcp)) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register TCP\n", __func__);
        goto tcp_error;
    }

    if ((err = proto_register(&dp_vs_proto_sctp)) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register SCTP\n", __func__);
        goto sctp_error;
    }

    if ((err = proto_register(&dp_vs_proto_icmp6)) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register ICMPV6\n", __func__);
        goto icmp6_error;
    }

    if ((err = proto_register(&dp_vs_proto_icmp)) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register ICMP\n", __func__);
        goto icmp_error;
    }

    return EDPVS_OK;

icmp_error:
    proto_unregister(&dp_vs_proto_icmp6);
icmp6_error:
    proto_unregister(&dp_vs_proto_sctp);
sctp_error:
    proto_unregister(&dp_vs_proto_tcp);
tcp_error:
    proto_unregister(&dp_vs_proto_udp);
    return err;
}

int dp_vs_proto_term(void)
{
    if (proto_unregister(&dp_vs_proto_icmp) != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "%s: fail to unregister ICMP\n", __func__);

    if (proto_unregister(&dp_vs_proto_icmp6) != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "%s: fail to unregister ICMPV6\n", __func__);

    if (proto_unregister(&dp_vs_proto_sctp) != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "%s: fail to unregister SCTP\n", __func__);

    if (proto_unregister(&dp_vs_proto_tcp) != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "%s: fail to unregister TCP\n", __func__);

    if (proto_unregister(&dp_vs_proto_udp) != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "%s: fail to unregister UDP\n", __func__);

    return EDPVS_OK;
}
