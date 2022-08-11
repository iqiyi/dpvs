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
#include "dpip.h"
#include "sockopt.h"
#include "conf/kni.h"
#include "conf/sockopts.h"

enum dpip_flow_type {
    DPIP_FLOW_TYPE_KNI = 101,
};

struct dpip_flow_param {
    enum dpip_flow_type type;
    union {
        struct kni_conf_param kni;
    } flow;
};

static void flow_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip flow { add | del } type FLOWTYPE OPTS dev STRING\n"
            "    dpip flow { show | flush } type FLOWTYPE dev STRING\n"
            "Parameters:\n"
            "    FLOWTYPE   := { kni }\n"
            "    OPTS       := { KNI_IP_ADDRESS }\n"
            "Examples:\n"
            "    dpip flow add type kni dev dpdk0 192.168.88.12\n"
            "    dpip flow get type kni dev dpdk0\n"
           );
}

static int kni_flow_parse_args(struct dpip_conf *conf, struct dpip_flow_param *param)
{
    param->flow.kni.type = KNI_DTYPE_ADDR_FLOW;
    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(param->flow.kni.ifname, sizeof(param->flow.kni.ifname),
                    "%s", conf->argv[0]);
        } else {
            if (inet_pton_try(&param->flow.kni.data.flow.af, conf->argv[0],
                        &param->flow.kni.data.flow.addr) <= 0)
                return EDPVS_INVAL;
        }
        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static int flow_parse_args(struct dpip_conf *conf, struct dpip_flow_param *param)
{
    memset(param, 0, sizeof(struct dpip_flow_param));

    if ((conf->argc > 1) && (strcmp(conf->argv[0], "type") == 0)) {
        NEXTARG_CHECK(conf, "type");
        if (strcmp(conf->argv[0], "kni") == 0) {
            param->type = DPIP_FLOW_TYPE_KNI;
            NEXTARG(conf);
        }
    }

    if (!param->type) {
        fprintf(stderr, "missing flow type\n");
        return EDPVS_INVAL;
    }

    switch (param->type) {
        case DPIP_FLOW_TYPE_KNI:
            return kni_flow_parse_args(conf, param);
        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_NOTSUPP;
}

static int kni_flow_do_cmd(dpip_cmd_t cmd, struct dpip_conf *conf,
        struct kni_conf_param *param)
{
    int i, err = EDPVS_OK;
    struct kni_info *info;
    size_t outlen;
    char buf[64];

    switch (conf->cmd) {
        case DPIP_CMD_ADD:
            return dpvs_setsockopt(SOCKOPT_SET_KNI_ADD, param, sizeof(*param));
        case DPIP_CMD_DEL:
            return dpvs_setsockopt(SOCKOPT_SET_KNI_DEL, param, sizeof(*param));
        case DPIP_CMD_FLUSH:
            return dpvs_setsockopt(SOCKOPT_SET_KNI_FLUSH, param, sizeof(*param));
        case DPIP_CMD_SHOW:
            err = dpvs_getsockopt(SOCKOPT_GET_KNI_LIST, param, sizeof(*param),
                    (void **)&info, &outlen);
            break;
        default:
            return EDPVS_NOTSUPP;
    }

    // Only SOCKOPT_GET_KNI_LIST arrives here
    if (err != EDPVS_OK)
        return err;
    if (outlen < sizeof(*info) || outlen < sizeof(*info) +
            info->len * sizeof(struct kni_addr_flow_entry)) {
        fprintf(stderr, "corrupted response\n");
        dpvs_sockopt_msg_free(info);
        return EDPVS_INVAL;
    }

    for (i = 0; i < info->len; i++) {
        if (info->entries[i].type != KNI_DTYPE_ADDR_FLOW) {
            fprintf(stderr, "unexpectd kni data type %d\n", info->entries[i].type);
            continue;
        }
        printf("kni addr flow %s dev %s\n", inet_ntop(info->entries[i].data.flow.af,
                &info->entries[i].data.flow.addr, buf, sizeof(buf)), info->entries[i].ifname);
    }

    dpvs_sockopt_msg_free(info);
    return EDPVS_OK;
}

static int flow_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    struct dpip_flow_param param;

    if (flow_parse_args(conf, &param) != EDPVS_OK)
        return EDPVS_INVAL;

    switch (param.type) {
        case DPIP_FLOW_TYPE_KNI:
            return kni_flow_do_cmd(cmd, conf, &param.flow.kni);
        default:
            return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_flow = {
    .name   = "flow",
    .help   = flow_help,
    .do_cmd = flow_do_cmd,
};

static void __init addr_init(void)
{
    dpip_register_obj(&dpip_flow);
}

static void __exit addr_exit(void)
{
    dpip_unregister_obj(&dpip_flow);
}
