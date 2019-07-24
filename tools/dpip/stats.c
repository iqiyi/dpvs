/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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
#include "common.h"
#include "dpip.h"
#include "conf/inetaddr.h"
#include "conf/stats.h"
#include "sockopt.h"


static void stats_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip stats [enable | disable]\n"
            "    dpip stats show\n"
           );
}

static void stats_dump(const struct stats_param *param)
{
    if (AF_INET == param->af) {
           printf("lcore: %u, [%s, %u -> ",
               param->cid, inet_ntoa(param->saddr.in), ntohs(param->sport));
           printf("%s, %u | %u], [%.0Lf, %.0Lf]",            
               inet_ntoa(param->daddr.in), ntohs(param->dport), param->proto, param->total_recv, param->total_sent); 

	} else if (AF_INET6 == param->af) {
        char src_addr[INET6_ADDRSTRLEN];
        char dst_addr[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &param->saddr.in6, src_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &param->daddr.in6, dst_addr, INET6_ADDRSTRLEN);

        printf("lcore: %u, [%s, %u -> %s, %u | %u], [%.0Lf, %.0Lf]",
            param->cid, src_addr, ntohs(param->sport), dst_addr, ntohs(param->dport), param->proto, param->total_recv, param->total_sent);

	} else {
        printf("unsupported");
	}

    printf("\n");
    return;
}

static int stats_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                       struct dpip_conf *conf)
{
    size_t size;
    int err, i;
	struct stats_param stats_param;
	struct stats_param_array *stats_array;

    switch (conf->cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_SET_STATS_ADD, &stats_param, sizeof(stats_param));
    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_STATS_DEL, &stats_param, sizeof(stats_param));
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_STATS_SHOW, &stats_param, sizeof(stats_param),
                              (void **)&stats_array, &size);
        if (err != 0)
            return err;

        if (stats_array == NULL) {
            fprintf(stderr, "warnning: disabled.\n");
            return EDPVS_OK;

        }

        if (size <= sizeof(*stats_array)
                || size != sizeof(*stats_array) + \
                           stats_array->nstats * sizeof(struct stats_param)) {
            fprintf(stderr, "response nstats : %d.\n", stats_array->nstats);
            dpvs_sockopt_msg_free(stats_array);
            return EDPVS_NOTEXIST;
        }

	    //printf("-------------top10 stats[in the last 20s]----------\n");

        for (i = stats_array->nstats - 1; i >= 0; i--) {
            printf("top%d: ", stats_array->nstats - i);
            stats_dump(&stats_array->stats[i]);
        }

        dpvs_sockopt_msg_free(stats_array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_stats = {
    .name   = "stats",
    .help   = stats_help,
    .do_cmd = stats_do_cmd,
};

static void __init stats_init(void)
{
    dpip_register_obj(&dpip_stats);
}

static void __exit stats_exit(void)
{
    dpip_unregister_obj(&dpip_stats);
}
