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
/**
 * IPv6 control plane.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#include <assert.h>
#include "conf/common.h"
#include "dpdk.h"
#include "inet.h"
#include "ipv6.h"
#include "conf/ipv6.h"
#include "ctrl.h"

static int ip6_msg_get_stats(struct dpvs_msg *msg)
{
    int err;
    struct inet_stats *stats;
    assert(msg);

    stats = msg_reply_alloc(sizeof(*stats));
    if (!stats)
        return EDPVS_NOMEM;

    err = ipv6_stats_cpu(stats);
    if (err != EDPVS_OK) {
        msg_reply_free(stats);
        return err;
    }

    msg->reply.len = sizeof(*stats);
    msg->reply.data = stats;

    return EDPVS_OK;
}

static int ip6_sockopt_set(sockoptid_t opt, const void *in, size_t inlen)
{
    return EDPVS_NOTSUPP;
}

static int ip6_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                           void **out, size_t *outsize)
{
    struct ip6_stats_param *param;
    struct dpvs_msg *req, *reply;
    struct dpvs_multicast_queue *replies = NULL;
    int err;

    if (opt != SOCKOPT_IP6_STATS)
        return EDPVS_NOTSUPP;

    if (!out || !outsize)
        return EDPVS_INVAL;

    /* ask each worker lcore for stats by msg */
    req = msg_make(MSG_TYPE_IPV6_STATS, 0, DPVS_MSG_MULTICAST,
                   rte_lcore_id(), 0, NULL);
    if (!req)
        return EDPVS_NOMEM;

    /* including per-lcore and total statistics. */
    param = rte_zmalloc(NULL, sizeof(struct ip6_stats_param), 0);
    if (!param) {
        msg_destroy(&req);
        return EDPVS_NOMEM;
    }

    err = multicast_msg_send(req, 0, &replies);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPV6, "%s: send msg: %s\n", __func__, dpvs_strerror(err));
        msg_destroy(&req);
        rte_free(param);
        return err;
    }

    /* handle each reply */
    list_for_each_entry(reply, &replies->mq, mq_node) {
        struct inet_stats *stats = (struct inet_stats *)reply->data;

        inet_stats_add(&param->stats, stats);
        param->stats_cpus[reply->cid] = *stats;
    }

    *out = param;
    *outsize = sizeof(*param);

    msg_destroy(&req);
    return EDPVS_OK;
}

static struct dpvs_msg_type ip6_stats_msg = {
    .type           = MSG_TYPE_IPV6_STATS,
    .prio           = MSG_PRIO_LOW,
    .unicast_msg_cb = ip6_msg_get_stats,
};

static struct dpvs_sockopts ip6_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_IP6_SET,
    .set_opt_max    = SOCKOPT_IP6_SET,
    .set            = ip6_sockopt_set,

    .get_opt_min    = SOCKOPT_IP6_STATS,
    .get_opt_max    = SOCKOPT_IP6_STATS,
    .get            = ip6_sockopt_get,
};

int ipv6_ctrl_init(void)
{
    int err;

    err = sockopt_register(&ip6_sockopts);
    if (err != EDPVS_OK)
        return err;

    err = msg_type_mc_register(&ip6_stats_msg);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPV6, "%s: fail to register msg\n", __func__);
        sockopt_unregister(&ip6_sockopts);
        return err;
    }

    return EDPVS_OK;
}

int ipv6_ctrl_term(void)
{
    int err;

    err = msg_type_mc_unregister(&ip6_stats_msg);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IPV6, "%s: fail to unregister msg\n", __func__);

    err = sockopt_unregister(&ip6_sockopts);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IPV6, "%s: fail to unregister sockopt\n", __func__);

    return EDPVS_OK;
}
