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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "conf/common.h"
#include "dpip.h"
#include "conf/inetaddr.h"
#include "sockopt.h"

static void addr_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip addr show [ dev STRING ]\n"
            "    dpip -6 addr show [ dev STRING ]\n"
            "    dpip addr { add | set } IFADDR dev STRING [LIFETIME] [ SCOPE ] [FLAGS]\n"
            "    dpip -6 addr { add | set } IFADDR dev STRING [LIFETIME] [ SCOPE ] [FLAGS]\n"
            "    dpip addr del IFADDR dev STRING\n"
            "    dpip -6 addr del IFADDR dev STRING\n"
            "    dpip addr flush dev STRING\n"
            "    dpip addr help\n"
            "Parameters:\n"
            "    IFADDR    := { PREFIX | ADDR } [ broadcast ADDR ]\n"
            "    PREFIX    := { ADDR/PLEN }\n"
            "    SCOPE     := [ scope { host | link | global | NUM } ]\n"
            "    LIFETIME  := [ valid_lft LFT ] [ preferred_lft LFT ]\n"
            "    LFT       := forever | SECONDS\n"
            "    FLAGS     := sapool\n"
           );
}

static const char *lft_itoa(uint32_t lft, char *buf, size_t size)
{
    if (!lft)
        snprintf(buf, size, "forever");
    else
        snprintf(buf, size, "%u", lft);

    return buf;
}

static const char *scope_itoa(uint8_t scope, char *buf, size_t size)
{
    struct {
        uint8_t iscope;
        const char *sscope;
    } scope_tab[] = {
        { IFA_SCOPE_HOST,    "host" },
        { IFA_SCOPE_LINK,    "link" },
        { IFA_SCOPE_SITE,    "site" },
        { IFA_SCOPE_GLOBAL,    "global" },
    };
    int i;

    for (i = 0; i < NELEMS(scope_tab); i++) {
        if (scope == scope_tab[i].iscope) {
            snprintf(buf, size, "%s", scope_tab[i].sscope);
            return buf;
        }
    }

    snprintf(buf, size, "%u", scope);
    return buf;
}

static void addr_dump(const struct inet_addr_data *data, uint32_t flags)
{
    char addr[64], bcast[64 + sizeof("broadcast ")];
    char scope[64], vld_lft[64], prf_lft[64];

    bcast[0] = '\0';
    if (!inet_is_addr_any(data->ifa_entry.af, &data->ifa_entry.bcast)) {
        snprintf(bcast, sizeof(bcast), "broadcast ");
        if (inet_ntop(data->ifa_entry.af, &data->ifa_entry.bcast, bcast + strlen(bcast),
                      sizeof(bcast) - strlen(bcast)) == NULL)
            bcast[0] = '\0';
    }

    if (flags & IFA_F_OPS_VERBOSE)
        printf("[%02d] ", data->ifa_entry.cid);
    printf("%s %s/%d scope %s %s\n    %s valid_lft %s preferred_lft %s",
           af_itoa(data->ifa_entry.af),
           inet_ntop(data->ifa_entry.af, &data->ifa_entry.addr, addr, sizeof(addr)) ? addr : "::",
           data->ifa_entry.plen, scope_itoa(data->ifa_entry.scope, scope, sizeof(scope)),
           data->ifa_entry.ifname, bcast,
           lft_itoa(data->ifa_entry.valid_lft, vld_lft, sizeof(vld_lft)),
           lft_itoa(data->ifa_entry.prefered_lft, prf_lft, sizeof(prf_lft)));

    if ((flags & (IFA_F_OPS_STATS | IFA_F_OPS_VERBOSE)) && (data->ifa_entry.flags & IFA_F_SAPOOL))
        printf(" sa_used %u sa_free %u sa_miss %u",
               data->ifa_stats.sa_used, data->ifa_stats.sa_free, data->ifa_stats.sa_miss);

    printf("\n");

    return;
}

static int addr_parse_args(struct dpip_conf *conf,
                           struct inet_addr_param *param)
{
    char *prefix = NULL;
    char *addr, *plen;

    memset(param, 0, sizeof(*param));

    if (conf->verbose)
        param->ifa_ops_flags |= IFA_F_OPS_VERBOSE;
    if (conf->stats)
        param->ifa_ops_flags |= IFA_F_OPS_STATS;

    param->ifa_entry.af = conf->af;
    param->ifa_entry.scope = IFA_SCOPE_GLOBAL;

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(param->ifa_entry.ifname, sizeof(param->ifa_entry.ifname), "%s", conf->argv[0]);
        } else if (strcmp(conf->argv[0], "scope") == 0) {
            NEXTARG_CHECK(conf, "scope");

            if (strcmp(conf->argv[0], "host") == 0)
                param->ifa_entry.scope = IFA_SCOPE_HOST;
            else if (strcmp(conf->argv[0], "link") == 0)
                param->ifa_entry.scope = IFA_SCOPE_LINK;
            else if (strcmp(conf->argv[0], "global") == 0)
                param->ifa_entry.scope = IFA_SCOPE_GLOBAL;
            else
                param->ifa_entry.scope = atoi(conf->argv[0]);
        } else if (strcmp(conf->argv[0], "broadcast") == 0) {
            NEXTARG_CHECK(conf, "broadcast");
            if (inet_pton_try(&param->ifa_entry.af, conf->argv[0], &param->ifa_entry.bcast) <= 0)
                return -1;
        } else if (strcmp(conf->argv[0], "valid_lft") == 0) {
            NEXTARG_CHECK(conf, "valid_lft");

            if (strcmp(conf->argv[0], "forever") == 0)
                param->ifa_entry.valid_lft = 0;
            else
                param->ifa_entry.valid_lft = atoi(conf->argv[0]);
        } else if (strcmp(conf->argv[0], "prefered_lft") == 0) {
            NEXTARG_CHECK(conf, "prefered_lft");

            if (strcmp(conf->argv[0], "forever") == 0)
                param->ifa_entry.prefered_lft = 0;
            else
                param->ifa_entry.prefered_lft = atoi(conf->argv[0]);
        } else if (strcmp(conf->argv[0], "sapool") == 0) {
            param->ifa_entry.flags |= IFA_F_SAPOOL;
        } else {
            prefix = conf->argv[0];
        }

        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    if (conf->cmd == DPIP_CMD_ADD || conf->cmd == DPIP_CMD_DEL
            || conf->cmd == DPIP_CMD_SET) {
        if (!prefix) {
            fprintf(stderr, "missing IFADDR\n");
            return -1;
        }
    }

    if (prefix) {
        addr = prefix;
        if ((plen = strchr(addr, '/')) != NULL)
            *plen++ = '\0';
        if (inet_pton_try(&param->ifa_entry.af, prefix, &param->ifa_entry.addr) <= 0)
            return -1;
        param->ifa_entry.plen = plen ? atoi(plen) : 0;
    }

    switch (param->ifa_entry.af) {
    case AF_INET:
        if (!param->ifa_entry.plen)
            param->ifa_entry.plen = 32;
        break;
    case AF_INET6:
        if (!param->ifa_entry.plen)
            param->ifa_entry.plen = 128;
        break;
    default:
        break;
    }

    if (conf->cmd != DPIP_CMD_SHOW && !strlen(param->ifa_entry.ifname)) {
        fprintf(stderr, "no device specified.\n");
        return -1;
    }

    return 0;
}

static int addr_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    struct inet_addr_param param;
    struct inet_addr_data_array *array;
    size_t size, i;
    int err;

    if (addr_parse_args(conf, &param) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
    case DPIP_CMD_ADD:
        param.ifa_ops = INET_ADDR_ADD;
        return dpvs_setsockopt(SOCKOPT_SET_IFADDR_ADD, &param, sizeof(param));
    case DPIP_CMD_DEL:
        param.ifa_ops = INET_ADDR_DEL;
        return dpvs_setsockopt(SOCKOPT_SET_IFADDR_DEL, &param, sizeof(param));
    case DPIP_CMD_SET:
        param.ifa_ops = INET_ADDR_MOD;
        return dpvs_setsockopt(SOCKOPT_SET_IFADDR_SET, &param, sizeof(param));
    case DPIP_CMD_FLUSH:
        param.ifa_ops = INET_ADDR_FLUSH;
        return dpvs_setsockopt(SOCKOPT_SET_IFADDR_FLUSH, &param, sizeof(param));
    case DPIP_CMD_SHOW:
        param.ifa_ops = INET_ADDR_GET;
        err = dpvs_getsockopt(SOCKOPT_GET_IFADDR_SHOW, &param, sizeof(param),
                              (void **)&array, &size);
        if (err != 0)
            return err;

        if (size < sizeof(*array)
                || size < sizeof(*array) + \
                           array->naddr * sizeof(struct inet_addr_data)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(array);
            return EDPVS_INVAL;
        }

        for (i = 0; i < array->naddr; i++)
            addr_dump(&array->addrs[i], array->ops_flags);

        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_addr = {
    .name   = "addr",
    .help   = addr_help,
    .do_cmd = addr_do_cmd,
};

static void __init addr_init(void)
{
    dpip_register_obj(&dpip_addr);
}

static void __exit addr_exit(void)
{
    dpip_unregister_obj(&dpip_addr);
}
