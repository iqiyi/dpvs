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
#include <stdio.h>
#include "dpip.h"
#include "sockopt.h"
#include "conf/lldp.h"

static void lldp_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip lldp show TYPE dev NAME\n"
            "    TYPE := [ local | neigh ]\n"
            "    NAME := interface name\n"
            "Examples:\n"
            "    dpip lldp show local dev dpdk0\n"
            "    dpip lldp show dev dpdk1 neigh\n");
}

static int lldp_parse(struct dpip_obj *obj, struct dpip_conf *conf)
{
    struct lldp_param *param = obj->param;

    memset(param, 0, sizeof(*param));

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, conf->argv[0]);
            snprintf(param->ifname, sizeof(param->ifname), "%s", conf->argv[0]);
        } else {
            if (strcmp(conf->argv[0], "local") == 0) {
                param->node = DPVS_LLDP_NODE_LOCAL;
            } else if (strcmp(conf->argv[0], "neigh") == 0) {
                param->node = DPVS_LLDP_NODE_NEIGH;
            } else {
                fprintf(stderr, "too many arguments\n");
                return EDPVS_INVAL;
            }
        }
        NEXTARG(conf);
    }

    return EDPVS_OK;
}

static int lldp_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    const struct lldp_param *param = obj->param;

    /* sanity check */
    switch (cmd) {
        case DPIP_CMD_SHOW:
            if (strlen(param->ifname) == 0) {
                fprintf(stderr, "missing device name\n");
                return EDPVS_INVAL;
            }
            return EDPVS_OK;
        default:
            return EDPVS_NOTSUPP;
    }
    return EDPVS_OK;
}

static int lldp_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd, struct dpip_conf *conf)
{
    const struct lldp_param *param = obj->param;
    struct lldp_message *message;
    size_t size;
    int err;

    switch (cmd) {
        case DPIP_CMD_SHOW:
            err = dpvs_getsockopt(SOCKOPT_GET_LLDP_SHOW, param, sizeof(*param),
                    (void **)&message, &size);
            if (err != EDPVS_OK)
                return err;

            if (size < sizeof(*message)) {
                fprintf(stderr, "corrupted response\n");
                dpvs_sockopt_msg_free(message);
                return EDPVS_INVAL;
            }
            printf("-*-*-*- %s LLDP Message on Port %s -*-*-*-\n",
                    message->param.node == DPVS_LLDP_NODE_NEIGH ? "Neighbour" : "Local",
                    message->param.ifname);
            printf(message->message);
            dpvs_sockopt_msg_free(message);
            return EDPVS_OK;
        default:
            return EDPVS_NOTSUPP;
    }
}

static struct lldp_param lldp_param;

static struct dpip_obj dpip_lldp = {
    .name       = "lldp",
    .param      = &lldp_param,
    .help       = lldp_help,
    .parse      = lldp_parse,
    .check      = lldp_check,
    .do_cmd     = lldp_do_cmd,
};

static void __init lldp_init(void)
{
    dpip_register_obj(&dpip_lldp);
}

static void __exit lldp_exit(void)
{
    dpip_unregister_obj(&dpip_lldp);
}
