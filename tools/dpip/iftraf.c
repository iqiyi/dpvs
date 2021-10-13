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
#include "conf/iftraf.h"
#include "sockopt.h"


static void iftraf_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip iftraf [enable | disable]\n"
            "    dpip iftraf show\n"
           );
}

static void iftraf_dump(const struct iftraf_param *param)
{
    if (AF_INET == param->af) {
        printf("%s, [%s, %u -> ",
            param->ifname, inet_ntoa(param->saddr.in), ntohs(param->sport));
        printf("%s, %u | %u], [%u, %u]",
            inet_ntoa(param->daddr.in), ntohs(param->dport), param->proto, param->total_recv, param->total_sent);

    } else if (AF_INET6 == param->af) {
        char src_addr[INET6_ADDRSTRLEN];
        char dst_addr[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &param->saddr.in6, src_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &param->daddr.in6, dst_addr, INET6_ADDRSTRLEN);

        printf("%s, [%s, %u -> %s, %u | %u], [%u, %u]",
            param->ifname, src_addr, ntohs(param->sport), dst_addr, ntohs(param->dport), param->proto, param->total_recv, param->total_sent);

    } else {
        printf("unsupported");
    }

    printf("\n");
    return;
}

static int iftraf_parse_args(struct dpip_conf *conf,
                            struct dp_vs_iftraf_conf *iftraf_conf)
{
    memset(iftraf_conf, 0, sizeof(*iftraf_conf));

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(iftraf_conf->ifname, sizeof(iftraf_conf->ifname), "%s", conf->argv[0]);
        }
        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    return 0;
}

static int iftraf_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    size_t size;
    int err, i;
    struct dp_vs_iftraf_conf iftraf_conf;
    struct iftraf_param iftraf_param;
    struct iftraf_param_array *iftraf_array;

    if (iftraf_parse_args(conf, &iftraf_conf) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
    case DPIP_CMD_ENABLE:
        return dpvs_setsockopt(SOCKOPT_SET_IFTRAF_ADD, &iftraf_param, sizeof(iftraf_param));
    case DPIP_CMD_DISABLE:
        return dpvs_setsockopt(SOCKOPT_SET_IFTRAF_DEL, &iftraf_param, sizeof(iftraf_param));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_IFTRAF_SHOW, &iftraf_conf, sizeof(iftraf_conf),
                              (void **)&iftraf_array, &size);
        if (err != 0)
            return err;

        if (iftraf_array == NULL) {
            fprintf(stderr, "warnning: disabled.\n");
            return EDPVS_OK;

        }

        if (size <= sizeof(*iftraf_array)
                || size != sizeof(*iftraf_array) + \
                           iftraf_array->ntrafs * sizeof(struct iftraf_param)) {
            fprintf(stderr, "response nstats : %d.\n", iftraf_array->ntrafs);
            dpvs_sockopt_msg_free(iftraf_array);
            return EDPVS_NOTEXIST;
        }

        //printf("-------------top10 iftraf[in the last 20s]----------\n");
        if (strcmp(iftraf_conf.ifname, "all") == 0) {
            for (i = 0; i < iftraf_array->ntrafs; i++) {
                printf("top%d: ", i + 1);
                iftraf_dump(&iftraf_array->iftraf[i]);
            }
        } else {
            for (i = iftraf_array->ntrafs - 1; i >= 0; i--) {
                printf("top%d: ", iftraf_array->ntrafs - i);
                iftraf_dump(&iftraf_array->iftraf[i]);
            }
        }
        dpvs_sockopt_msg_free(iftraf_array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_iftraf = {
    .name   = "iftraf",
    .help   = iftraf_help,
    .do_cmd = iftraf_do_cmd,
};

static void __init iftraf_init(void)
{
    dpip_register_obj(&dpip_iftraf);
}

static void __exit iftraf_exit(void)
{
    dpip_unregister_obj(&dpip_iftraf);
}
