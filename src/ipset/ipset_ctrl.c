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
#include "ctrl.h"
#include "dpdk.h"
#include "conf/sockopts.h"
#include "ipset/ipset.h"

static uint32_t ipset_msg_seq(void)
{
    static uint32_t counter = 0;
    return counter++;
}

static int ipset_sockopt_check(const void *conf, size_t size, void **out, size_t *outsize)
{
    int *result;
    struct ipset_param *param = (struct ipset_param *)conf;

    if (!conf || size < sizeof(struct ipset_param))
        return EDPVS_INVAL;

    if (unlikely(param->opcode != IPSET_OP_TEST))
        return EDPVS_INVAL;

    result = rte_zmalloc(NULL, sizeof(int), 0);
    if (unlikely(result == NULL))
        return EDPVS_NOMEM;

    /* check on master lcore only */
    *result = ipset_local_action(param);

    *out = result;
    *outsize = sizeof(*result);
    return EDPVS_OK;
}

static int ipset_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    struct ipset_param *param = (struct ipset_param *)conf;
    struct dpvs_msg *msg;
    int err;

    if (!conf || size < sizeof(struct ipset_param))
        return EDPVS_INVAL;

    if (unlikely(param->opcode == IPSET_OP_TEST))
        return EDPVS_INVAL;

    /* set master lcore */
    err = ipset_local_action(param);
    if (err != EDPVS_OK)
        return err;

    /* set slave lcores */
    msg = msg_make(MSG_TYPE_IPSET_SET, ipset_msg_seq(), DPVS_MSG_MULTICAST,
                    rte_lcore_id(), sizeof(struct ipset_param), param);
    if (unlikely(!msg))
        return EDPVS_NOMEM;

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }

    msg_destroy(&msg);
    return EDPVS_OK;
}

static int ipset_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    switch(opt) {
        case SOCKOPT_GET_IPSET_LIST:
            return ipset_do_list(conf, out, outsize);
        case SOCKOPT_GET_IPSET_TEST:
            return ipset_sockopt_check(conf, size, out, outsize);
        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static struct dpvs_sockopts ipset_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_IPSET,
    .set_opt_max    = SOCKOPT_SET_IPSET,
    .set            = ipset_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_IPSET_TEST,
    .get_opt_max    = SOCKOPT_GET_IPSET_LIST,
    .get            = ipset_sockopt_get,
};

static int ipset_set_cb(struct dpvs_msg *msg)
{
    struct ipset_param *param;

    if (msg->len != sizeof(struct ipset_param))
        return EDPVS_INVAL;
    param = (struct ipset_param *)msg->data;

    return ipset_local_action(param);
}

struct dpvs_msg_type ipset_msg_types[] = {
    {
        .type           = MSG_TYPE_IPSET_SET,
        .prio           = MSG_PRIO_NORM,
        .mode           = DPVS_MSG_MULTICAST,
        .unicast_msg_cb = ipset_set_cb,
    },
};

int ipset_ctrl_init(void)
{
    int i, err;

    err = sockopt_register(&ipset_sockopts);
    if (err != EDPVS_OK)
        return err;

    for (i = 0; i < NELEMS(ipset_msg_types); i++) {
        err = msg_type_mc_register(&ipset_msg_types[i]);
        if (err != EDPVS_OK)
            break;
    }
    if (err != EDPVS_OK) {
        for (--i; i >= 0; i--)
            msg_type_mc_unregister(&ipset_msg_types[i]);
        sockopt_unregister(&ipset_sockopts);
        return err;
    }

    return EDPVS_OK;
}

int ipset_ctrl_term(void)
{
    int i, err;

    for (i = 0; i < NELEMS(ipset_msg_types); i++) {
        err = msg_type_mc_unregister(&ipset_msg_types[i]);
        if (err != EDPVS_OK)
            RTE_LOG(ERR, IPSET, "%s: fail to unregister ipset_msg_types[%d]\n", __func__, i);
    }

    err = sockopt_unregister(&ipset_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPSET, "%s: fail to unregister ipset_sockopts\n", __func__);
        return err;
    }

    return EDPVS_OK;
}
