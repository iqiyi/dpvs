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
 * traffic control classifier of dpip tool.
 * see iproute2 "tc filter".
 *
 * raychen@qiyi.com, Aug. 2017, initial.
 */
#include <stdlib.h>
#include <string.h>
#include "conf/common.h"
#include "dpip.h"
#include "sockopt.h"
#include "conf/match.h"
#include "conf/tc.h"

static void cls_help(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    dpip cls { add | del | change | replace | show } dev STRING\n"
        "             [ handle HANDLE ] [ qsch HANDLE ]\n"
        "             [ pkttype PKTTYPE ] [ prio PRIO ]\n"
        "             [ CLS_TYPE [ COPTIONS ] ]\n"
        "\n"
        "Parameters:\n"
        "    PKTTYPE    := { ipv4 | ipv6 | vlan }\n"
        "    CLS_TYPE   := { match | ipset }\n"
        "    COPTIONS   := { MATCH_OPTS | SET_OPTS }\n"
        "    PRIO       := NUMBER\n"
        "\n"
        "Match options:\n"
        "    MATCH_OPTS := pattern PATTERN { target { CHILD_QSCH | drop } }\n"
        "    PATTERN    := comma seperated of tokens below,\n"
        "                  { PROTO | SRANGE | DRANGE | IIF | OIF }\n"
        "    CHILD_QSCH := child qsch handle of the qsch cls attached.\n"
        "    PROTO      := \"{ tcp | sctp | udp }\"\n"
        "    SRANGE     := \"from=RANGE\"\n"
        "    DRANGE     := \"to=RANGE\"\n"
        "    RANGE      := ADDR[-ADDR][:PORT[-PORT]]\n"
        "    IIF        := \"iif=IFNAME\"\n"
        "    OIF        := \"oif=IFNAME\"\n"
        "Set options:\n"
        "    SET_OPTS   := match IPSET { target { CHILD_QSCH | drop } }\n"
        "    IPSET      := SETNAME{,TARGET }\n"
        "    TARGET     := \"{ src | dst }\"\n"
        "\n"
        "Examples:\n"
        "    dpip cls show dev dpdk0 qsch 1:\n"
        "    dpip cls add dev dpdk0 qsch 1: \\\n"
        "         match pattern 'tcp,from=10.0.0.1' target drop\n"
        "    dpip cls add dev dpdk0 qsch 1: handle 1:10 \\\n"
        "         match pattern 'tcp,from=192.168.0.1:1-1024,oif=eth1'\\\n"
        "         target 1:1\n"
        "    dpip cls add dev dpdk0 qsch root ipset match denyset,src target drop\n"
        "    dpip cls del dev dpdk0 qsch 1: handle 1:10\n"
        );
}

static void cls_dump_param(const char *ifname, const union tc_param *param,
                           bool stats, bool verbose)
{
    const struct tc_cls_param *cls = &param->cls;
    char handle[16], sch_id[16];

    if (verbose)
        printf("[%02d] ", cls->cid);

    printf("cls %s %s dev %s qsch %s pkttype 0x%04x prio %d ",
           cls->kind, tc_handle_itoa(cls->handle, handle, sizeof(handle)),
           ifname, tc_handle_itoa(cls->sch_id, sch_id, sizeof(sch_id)),
           ntohs(cls->pkt_type), cls->priority);

    if (strcmp(cls->kind, "match") == 0) {
        char result[32], patt[256], target[16];
        const struct tc_cls_match_copt *m = &cls->copt.match;

        if (m->result.drop)
            snprintf(result, sizeof(result), "%s", "drop");
        else
            snprintf(result, sizeof(result), "%s",
                     tc_handle_itoa(m->result.sch_id, target, sizeof(target)));

        printf("%s target %s",
               dump_match(m->proto, &m->match, patt, sizeof(patt)), result);
    } else if (strcmp(cls->kind, "ipset") == 0) {
        char result[32], target[16];
        const struct tc_cls_ipset_copt *set = &cls->copt.set;

        if (set->result.drop)
            snprintf(result, sizeof(result), "%s", "drop");
        else
            snprintf(result, sizeof(result), "%s",
                    tc_handle_itoa(set->result.sch_id, target, sizeof(target)));
        printf("ipset match %s,%s target %s", set->setname,
                set->dst_match ? "dst" : "src", result);
    }

    printf("\n");
}

static inline int parse_cls_ipset(const char *args, char *setname, bool *dst_match)
{
    size_t len;
    char *dir;

    *dst_match = false;  // default false

    dir = strchr(args, ',');
    if (dir) {
        *dir++ = '\0';
        if (strncmp(dir, "src", 3) == 0)
            *dst_match = false;
        else if (strncmp(dir, "dst", 3) == 0)
            *dst_match = true;
        else
            return EDPVS_INVAL;
    }

    len = strlen(args);
    if (!len || len >= IPSET_MAXNAMELEN)
        return EDPVS_INVAL;
    strncpy(setname, args, len);

    return EDPVS_OK;
}

static int cls_parse(struct dpip_obj *obj, struct dpip_conf *cf)
{
    struct tc_conf *conf = obj->param;
    struct tc_cls_param *param = &conf->param.cls;

    memset(param, 0, sizeof(*param));

    /* default values */
    param->pkt_type = htons(ETH_P_IP);
    param->handle = TC_H_UNSPEC;
    param->sch_id = TC_H_ROOT;
    param->priority = 0;

    while (cf->argc > 0) {
        if (strcmp(CURRARG(cf), "dev") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            snprintf(conf->ifname, IFNAMSIZ, "%s", CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "handle") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->handle = tc_handle_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "qsch") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->sch_id = tc_handle_atoi(CURRARG(cf));
        } else if (strcmp(CURRARG(cf), "pkttype") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            if (strcasecmp(CURRARG(cf), "ipv4") == 0)
                param->pkt_type = htons(ETH_P_IP);
            else if (strcasecmp(CURRARG(cf), "ipv6") == 0)
                param->pkt_type = htons(ETH_P_IPV6);
            else if (strcasecmp(CURRARG(cf), "vlan") == 0)
                param->pkt_type = htons(ETH_P_8021Q);
            else {
                fprintf(stderr, "pkttype not support\n");
                return EDPVS_INVAL;
            }
        } else if (strcmp(CURRARG(cf), "prio") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));
            param->priority = atoi(CURRARG(cf));
        } else if ((strcmp(CURRARG(cf), "match") == 0) && (!param->kind[0])) {
            snprintf(param->kind, TCNAMESIZ, "%s", "match");
        } else if (strcmp(CURRARG(cf), "ipset") == 0) {
            snprintf(param->kind, TCNAMESIZ, "%s", "ipset");
        } else { /* kind must be set adead then COPTIONS */
            if (strcmp(param->kind, "match") == 0) {
                struct tc_cls_match_copt *m = &param->copt.match;

                if (strcmp(CURRARG(cf), "pattern") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    if (parse_match(CURRARG(cf), &m->proto,
                                    &m->match) != EDPVS_OK) {
                        fprintf(stderr, "invalid pattern: %s\n", CURRARG(cf));
                        return EDPVS_INVAL;
                    }
                } else if (strcmp(CURRARG(cf), "target") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    if (strcmp(CURRARG(cf), "drop") == 0)
                        m->result.drop = true;
                    else
                        m->result.sch_id = tc_handle_atoi(CURRARG(cf));
                }
            } else if (strcmp(param->kind, "ipset") == 0) {
                struct tc_cls_ipset_copt *set = &param->copt.set;
                if (strcmp(CURRARG(cf), "match") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    if (parse_cls_ipset(CURRARG(cf), set->setname, &set->dst_match) != EDPVS_OK) {
                        fprintf(stderr, "invalid ipset match: %s\n", CURRARG(cf));
                        return EDPVS_INVAL;
                    }
                } else if (strcmp(CURRARG(cf), "target") == 0) {
                    NEXTARG_CHECK(cf, CURRARG(cf));
                    if (strcmp(CURRARG(cf), "drop") == 0)
                        set->result.drop = true;
                    else
                        set->result.sch_id = tc_handle_atoi(CURRARG(cf));
                }
            } else {
                fprintf(stderr, "invalid/miss cls type: '%s'\n", param->kind);
                return EDPVS_INVAL;
            }
        }

        NEXTARG(cf);
    }

    return EDPVS_OK;
}

static int cls_check(const struct dpip_obj *obj, dpip_cmd_t cmd)
{
    const struct tc_conf *conf = obj->param;
    const struct tc_cls_param *param = &conf->param.cls;

    if (!strlen(conf->ifname)) {
        fprintf(stderr, "missing device.\n");
        return EDPVS_INVAL;
    }

    switch (cmd) {
    case DPIP_CMD_REPLACE:
        if (!param->handle)
            goto missing_handle;
        /* fall through */

    case DPIP_CMD_ADD:
        /* sch_id 0: is root qdisc for egress */

        if (strcmp(param->kind, "match") == 0) {
            if (is_empty_match(&param->copt.match.match)) {
                fprintf(stderr, "invalid match pattern.\n");
                return EDPVS_INVAL;
            }
        } else if (strcmp(param->kind, "ipset") == 0) {
            // TODO: check the existence of ipset?
        } else {
            fprintf(stderr, "invalid cls kind.\n");
            return EDPVS_INVAL;
        }
        break;

    case DPIP_CMD_DEL:
        if (!param->handle)
            goto missing_handle;
        break;

    case DPIP_CMD_SET:
        if (!param->handle)
            goto missing_handle;

        if (strcmp(param->kind, "match") == 0) {
            if (is_empty_match(&param->copt.match.match)) {
                fprintf(stderr, "invalid match pattern.\n");
                return EDPVS_INVAL;
            }
        } else if (strcmp(param->kind, "ipset") == 0) {
            // TODO: check the existence of ipset?
        } else {
            fprintf(stderr, "invalid cls kind.\n");
            return EDPVS_INVAL;
        }

        break;

    case DPIP_CMD_SHOW:
        break;

    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;

missing_handle:
    fprintf(stderr, "missing handle.\n");
    return EDPVS_INVAL;
}

static int cls_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                      struct dpip_conf *conf)
{
    struct tc_conf *tc_conf = obj->param;
    union tc_param *params;
    int err, i;
    size_t size;

    if (conf->stats)
        tc_conf->op_flags |= TC_F_OPS_STATS;

    if (conf->verbose)
        tc_conf->op_flags |= TC_F_OPS_VERBOSE;

    switch (cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_TC_ADD, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_TC_DEL, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_SET:
        return dpvs_setsockopt(SOCKOPT_TC_CHANGE, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_REPLACE:
        return dpvs_setsockopt(SOCKOPT_TC_REPLACE, tc_conf,
                               sizeof(struct tc_conf));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_TC_SHOW, tc_conf,
                              sizeof(struct tc_conf), (void **)&params, &size);
        if (err != 0)
            return EDPVS_INVAL;

        if (size < 0 || size % sizeof(*params) != 0) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(params);
            return EDPVS_INVAL;
        }

        for (i = 0; i < size / sizeof(*params); i++)
            cls_dump_param(tc_conf->ifname, &params[i], conf->stats, conf->verbose);

        dpvs_sockopt_msg_free(params);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

static struct tc_conf cls_conf = {
    .obj    = TC_OBJ_CLS,
};

static struct dpip_obj dpip_cls = {
    .name   = "cls",
    .param  = &cls_conf,
    .help   = cls_help,
    .parse  = cls_parse,
    .check  = cls_check,
    .do_cmd = cls_do_cmd,
};

static void __init cls_init(void)
{
    dpip_register_obj(&dpip_cls);
}

static void __exit cls_exit(void)
{
    dpip_unregister_obj(&dpip_cls);
}
