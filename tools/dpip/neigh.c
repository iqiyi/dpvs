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
#include "net/ethernet.h"
#include "conf/common.h"
#include "dpip.h"
#include "conf/neigh.h"
#include "sockopt.h"

static void neigh_help(void)
{
    fprintf(stderr,
            "Usage:\n"
            "    dpip neigh show [ dev DEVICE ]\n"
            "    dpip neigh { add | del } ADDR lladdr LLADDR dev DEVICE\n"
            "    dpip neigh help\n"
           );
}

static int neigh_parse_args(struct dpip_conf *conf,
                            struct dp_vs_neigh_conf *neigh)
{
    char *addr = NULL;
    int iaddr[6], i;

    memset(neigh, 0, sizeof(*neigh));
    neigh->af = conf->af;

    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(neigh->ifname, sizeof(neigh->ifname), "%s", conf->argv[0]);
        } else if (strcmp(conf->argv[0], "lladdr") == 0) {
            NEXTARG_CHECK(conf, "lladdr");
            if (sscanf(conf->argv[0], "%02x:%02x:%02x:%02x:%02x:%02x",
                        &iaddr[0], &iaddr[1], &iaddr[2],
                        &iaddr[3], &iaddr[4], &iaddr[5]) != 6) {
                fprintf(stderr, "invalid link layer addr\n");
                return -1;
            }

            for (i = 0; i < 6; i++) {
                if ((iaddr[i] & ~0xFF)) {
                    fprintf(stderr, "invalid link layer addr\n");
                    return -1;
                }

                neigh->eth_addr.ether_addr_octet[i] = (uint8_t)iaddr[i];
            }
        } else {
            addr = conf->argv[0];
        }

        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    if (conf->cmd == DPIP_CMD_ADD || conf->cmd == DPIP_CMD_DEL) {
        if (!addr) {
            fprintf(stderr, "missing ip address\n");
            return -1;
        }
    }

    if (addr) {
        if (inet_pton_try(&neigh->af, addr, &neigh->ip_addr) <= 0) {
            fprintf(stderr, "invalid IP address\n");
            return -1;
        }
    }

    return 0;
}

static void neigh_dump(struct dp_vs_neigh_conf *neigh)
{
    char ipaddr[64];

    if (neigh->state >= DPVS_NUD_S_REACHABLE)
        printf("ip: %-48s mac: %02x:%02x:%02x:%02x:%02x:%02x   state: %-12s  dev: %s  core: %d  %s\n",
            inet_ntop(neigh->af, &neigh->ip_addr, ipaddr, sizeof(ipaddr)) ? ipaddr : "::",
            neigh->eth_addr.ether_addr_octet[0],
            neigh->eth_addr.ether_addr_octet[1],
            neigh->eth_addr.ether_addr_octet[2],
            neigh->eth_addr.ether_addr_octet[3],
            neigh->eth_addr.ether_addr_octet[4],
            neigh->eth_addr.ether_addr_octet[5],
            nud_state_names[neigh->state], neigh->ifname, neigh->cid,
            (neigh->flag & NEIGHBOUR_STATIC) ? "static" : "");
    else
        printf("ip: %-48s mac:incomplate                       state: %-12s   dev: %s  core: %d  %s\n",
            inet_ntop(neigh->af, &neigh->ip_addr, ipaddr, sizeof(ipaddr)) ? ipaddr : "::",
            nud_state_names[neigh->state], neigh->ifname, neigh->cid,
            (neigh->flag & NEIGHBOUR_STATIC) ? "static" : "");
    return;
}

static inline bool is_mac_valid(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] || ea->ether_addr_octet[1] ||
            ea->ether_addr_octet[2] || ea->ether_addr_octet[3] ||
            ea->ether_addr_octet[4] || ea->ether_addr_octet[5]);
}


static int neigh_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                        struct dpip_conf *conf)
{
    struct dp_vs_neigh_conf neigh;
    struct dp_vs_neigh_conf_array *array;
    size_t size, i;
    int err;

    if (neigh_parse_args(conf, &neigh) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd){
    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_NEIGH_SHOW, &neigh, sizeof(neigh),
                              (void **)&array, &size);
        if (err != 0)
            return err;
        if (size < sizeof(*array) ||
            size != sizeof(*array) + \
            array->neigh_nums * sizeof(struct dp_vs_neigh_conf)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(array);
            return EDPVS_INVAL;
        }
        for (i = 0; i < array->neigh_nums; i++)
            neigh_dump(&array->addrs[i]);
        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;

    case DPIP_CMD_ADD:
        if (!is_mac_valid(&neigh.eth_addr)) {
            fprintf(stderr, "invalid MAC address\n");
            return EDPVS_INVAL;
        }

        return dpvs_setsockopt(SOCKOPT_SET_NEIGH_ADD, &neigh, sizeof(neigh));

    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_NEIGH_DEL, &neigh, sizeof(neigh));

    default:
        return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_neigh = {
    .name = "neigh",
    .help = neigh_help,
    .do_cmd = neigh_do_cmd,
};

static void __init neigh_init(void)
{
    dpip_register_obj(&dpip_neigh);
}

static void __exit route_exit(void)
{
    dpip_unregister_obj(&dpip_neigh);
}
