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
 * vlan.c - vlan module of dpip tool.
 *
 * raychen@qiyi.com, May 2017, initial.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include "conf/common.h"
#include "dpip.h"
#include "utils.h"
#include "conf/vlan.h"
#include "sockopt.h"

/*
 * XXX: why "vlan" is first level of dpip object ?
 * We can implement vlan in dpip/link.c (or dpip/link_vlan.c) alternately.
 * But the "link" (even dpvs/netif) module need refactor to be more
 * abstractive and easier for extension. So that less effort is needed to
 * support different sort of devices (rte_eth, kni, bonding, vlan, etc).
 */

static void vlan_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip vlan add [NAME] VLAN-PARAM\n"
            "    dpip vlan del { NAME | VLAN-PARAM }\n"
            "    dpip vlan show { NAME | link DEV [ proto VLAN-PROTO ] "
                                         "[ id VLAN-ID ] }\n"
            "Parameters:\n"
            "    NAME       := DEV\n"
            "    DEV        := STRING\n"
            "    VLAN-PARAM := link DEV [proto VLAN-PROTO] id VLAN-ID\n"
            "    VLAN-PROTO := { 802.1q | 802.1ad | vlan | QinQ }\n"
            "    VLAN-ID    := NUMBER\n"
            "\n"
            "    The default VLAN-PROTO is 802.1q (vlan).\n"
            "    802.1q equals to vlan, so does 802.1ad and QinQ.\n"
            "Examples:\n"
            "    dpip vlan add dpdk0.100 link dpdk0 id 100\n"
            "    dpip vlan add link dpdk1 proto 802.1q id 100\n"
            "    dpip vlan del dpdk0.100\n"
            "    dpip vlan del link dpdk1 id 100\n"
            "    dpip vlan show dpdk0.100\n"
            "    dpip vlan show link dpdk1\n"
            "    dpip vlan show link dpdk1 id 100\n");
}

static int vlan_parse(struct dpip_obj *obj, struct dpip_conf *conf)
{
    struct vlan_param *param = obj->param;

    memset(param, 0, sizeof(*param));
    param->vlan_proto = ETH_P_8021Q; /* by default */

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "link") == 0) {
            NEXTARG_CHECK(conf, conf->argv[0]);
            snprintf(param->real_dev, IFNAMSIZ, "%s", conf->argv[0]);
        } else if (strcmp(conf->argv[0], "proto") == 0) {
            NEXTARG_CHECK(conf, conf->argv[0]);
            if (strcmp(conf->argv[0], "802.1q") == 0 ||
                strcmp(conf->argv[0], "vlan") == 0) {
                param->vlan_proto = ETH_P_8021Q;
            } else if (strcmp(conf->argv[0], "802.1ad") == 0 ||
                       strcasecmp(conf->argv[0], "QinQ") == 0) {
                param->vlan_proto = ETH_P_8021AD;
            } else { /* if set, must be valid, or don't set. */
                return EDPVS_INVAL;
            }
        } else if (strcmp(conf->argv[0], "id") == 0) {
            NEXTARG_CHECK(conf, conf->argv[0]);
            param->vlan_id = atoi(conf->argv[0]);
        } else { /* have argument besides valid key-values */
            if (!strlen(param->ifname)) {
                snprintf(param->ifname, IFNAMSIZ, "%s", conf->argv[0]);
            } else {
                fprintf(stderr, "too many arguments\n");
                return EDPVS_INVAL;
            }
        }

        NEXTARG(conf);
    }

    return EDPVS_OK;
}

static int vlan_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    const struct vlan_param *param = obj->param;

    /* sanity check */
    switch (cmd) {
    case DPIP_CMD_DEL:
        if (strlen(param->ifname) >= 0)
            return EDPVS_OK;

        /* fallthrough */
    case DPIP_CMD_ADD:
        if (strlen(param->real_dev) == 0) {
            fprintf(stderr, "missing real device\n");
            return EDPVS_INVAL;
        }
        if (param->vlan_id == 0) {
            fprintf(stderr, "missing or invalid VLAN ID\n");
            return EDPVS_INVAL;
        }
        return EDPVS_OK;

    case DPIP_CMD_SHOW:
        /* either ifname or link device is set */
        if (strlen(param->ifname) == 0 && strlen(param->real_dev) == 0) {
            fprintf(stderr, "missing both vlan and real device\n");
            return EDPVS_INVAL;
        }
        return EDPVS_OK;

    default:
        return EDPVS_NOTSUPP;
    }
}

static inline const char *vlan_prot_itoa(uint16_t proto)
{
    switch (proto) {
    case ETH_P_8021Q:
        return "802.1q";
    case ETH_P_8021AD:
        return "802.1ad";
    default:
        return "<unknow>";
    }
}

static inline void vlan_param_dump(const struct vlan_param *param)
{
    fprintf(stderr, "%s link %s proto %s id %d\n",
            param->ifname, param->real_dev,
            vlan_prot_itoa(param->vlan_proto), param->vlan_id);
}

static int vlan_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    const struct vlan_param *param = obj->param;
    struct vlan_param_array *array;
    size_t size;
    int err, i;

    switch (cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_SET_VLAN_ADD, param, sizeof(*param));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_VLAN_DEL, param, sizeof(*param));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_VLAN_SHOW, param, sizeof(*param),
                              (void **)&array, &size);
        if (err != 0)
            return err;

        if (size < sizeof(*array)
                || size < sizeof(*array) + \
                           array->nparam * sizeof(struct vlan_param)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(array);
            return EDPVS_INVAL;
        }

        for (i = 0; i < array->nparam; i++)
            vlan_param_dump(&array->params[i]);

        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static struct vlan_param vlan_param;

static struct dpip_obj dpip_vlan = {
    .name       = "vlan",
    .param      = &vlan_param,

    .help       = vlan_help,
    .parse      = vlan_parse,
    .check      = vlan_check,
    .do_cmd     = vlan_do_cmd,
};

static void __init vlan_init(void)
{
    dpip_register_obj(&dpip_vlan);
}

static void __exit vlan_exit(void)
{
    dpip_unregister_obj(&dpip_vlan);
}
