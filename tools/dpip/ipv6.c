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
 * Tool for IPv6 protocol.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "conf/common.h"
#include "conf/inet.h"
#include "dpip.h"
#include "sockopt.h"
#include "conf/ipv6.h"

enum {
    IPV6_STATS_CPU_ALL      = 0xFFFFFFFF,
    IPV6_STATS_CPU_TOTAL    = 0xFFFFFFFE,
};

struct ipv6_conf {
    int stats_cpu;
};

static struct ipv6_conf ipv6_conf;

static void ipv6_help(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    dpip ipv6 show [ cpu CPU | all | total ]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "    dpip ipv6 show\n");
    fprintf(stderr, "    dpip ipv6 show total\n");
    fprintf(stderr, "    dpip ipv6 show all\n");
    fprintf(stderr, "    dpip ipv6 show cpu 6\n");
}

static int ipv6_parse(struct dpip_obj *obj, struct dpip_conf *cf)
{
    struct ipv6_conf *conf = obj->param;

    memset(conf, 0, sizeof(*conf));
    conf->stats_cpu = IPV6_STATS_CPU_TOTAL;

    while (cf->argc > 0) {
        if (strcmp(CURRARG(cf), "cpu") == 0) {
            NEXTARG_CHECK(cf, CURRARG(cf));

            conf->stats_cpu = atoi(CURRARG(cf));
            if (conf->stats_cpu < 0 || conf->stats_cpu >= DPVS_MAX_LCORE) {
                fprintf(stderr, "bad cpu id `%s'\n", CURRARG(cf));
                return EDPVS_INVAL;
            }
        } else if (strcmp(CURRARG(cf), "all") == 0) {
            conf->stats_cpu = IPV6_STATS_CPU_ALL;
        } else if (strcmp(CURRARG(cf), "total") == 0) {
            conf->stats_cpu = IPV6_STATS_CPU_TOTAL;
        } else {
            fprintf(stderr, "unknow argument `%s'\n", CURRARG(cf));
            return EDPVS_INVAL;
        }

        NEXTARG(cf);
    }

    return EDPVS_OK;
}

static int ipv6_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    struct ip6_stats_param *stats;
    struct ipv6_conf *cf = obj->param;
    char cpu[16];
    size_t size;
    int err, i;

    if (cmd != DPIP_CMD_SHOW)
        return EDPVS_NOTSUPP;

    err = dpvs_getsockopt(SOCKOPT_IP6_STATS, NULL, 0, (void **)&stats, &size);
    if (err != EDPVS_OK)
        return EDPVS_INVAL;

    if (size != sizeof(*stats)) {
        fprintf(stderr, "corrupted response.\n");
        dpvs_sockopt_msg_free(stats);
        return EDPVS_INVAL;
    }

    switch (cf->stats_cpu) {
    case IPV6_STATS_CPU_TOTAL:
        inet_stats_dump(NULL, NULL, &stats->stats);
        break;
    case IPV6_STATS_CPU_ALL:
        inet_stats_dump("All", "    ", &stats->stats);

        for (i = 0; i < NELEMS(stats->stats_cpus); i++) {
            snprintf(cpu, sizeof(cpu), "cpu %d", i);
            inet_stats_dump(cpu, "    ", &stats->stats_cpus[i]);
        }
        break;
    default:
        if (cf->stats_cpu < 0 ||
            cf->stats_cpu >= NELEMS(stats->stats_cpus)) {
            fprintf(stderr, "bad cpu id %d.\n", cf->stats_cpu);
            break;
        }

        snprintf(cpu, sizeof(cpu), "cpu %d", cf->stats_cpu);
        inet_stats_dump(cpu, "    ", &stats->stats_cpus[cf->stats_cpu]);
        break;
    }

    dpvs_sockopt_msg_free(stats);

    return EDPVS_OK;
}

struct dpip_obj dpip_ipv6 = {
    .name   = "ipv6",
    .param  = &ipv6_conf,
    .help   = ipv6_help,
    .parse  = ipv6_parse,
    .do_cmd = ipv6_do_cmd,
};

static void __init ipv6_init(void)
{
    dpip_register_obj(&dpip_ipv6);
}

static void __exit ipv6_exit(void)
{
    dpip_unregister_obj(&dpip_ipv6);
}
