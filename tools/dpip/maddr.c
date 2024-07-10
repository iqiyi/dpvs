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
#include "conf/sockopts.h"
#include "conf/common.h"
#include "conf/netif.h"
#include "conf/netif_addr.h"
#include "conf/inetaddr.h"
#include "sockopt.h"

static void maddr_help(void)
{
    fprintf(stderr, "Usage: dpip maddr show [dev STRING]\n");
}

static int maddr_parse_args(struct dpip_conf *conf, char *ifname, size_t len)
{
    while (conf->argc > 0) {
        if (strcmp(conf->argv[0], "dev") == 0) {
            NEXTARG_CHECK(conf, "dev");
            snprintf(ifname, len, "%s", conf->argv[0]);
        }
        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    return 0;
}

static int hwm_get_and_dump(const char *ifname, size_t len, bool verbose)
{
    int i, err;
    size_t outlen;
    struct netif_hw_addr_array *out;
    struct netif_hw_addr_entry *entry;

    err = dpvs_getsockopt(SOCKOPT_NETIF_GET_MADDR, ifname, len, (void **)&out, &outlen);
    if (err != EDPVS_OK || !out || !outlen)
        return err;

    for (i = 0; i < out->count; i++) {
        entry = &out->entries[i];
        if (verbose) {
            printf("\tlink  %s%s\t\trefcnt %u\t\tsync %d\n",
                    entry->addr, entry->flags & HW_ADDR_F_FROM_KNI ? " (+kni)" : "",
                    entry->refcnt, entry->sync_cnt);
        } else {
            printf("\tlink %s\n", entry->addr);
        }
    }

    dpvs_sockopt_msg_free(out);
    return EDPVS_OK;
}

static int ifm_get_and_dump(const char *ifname, size_t len, bool verbose)
{
    int i, err;
    size_t outlen;
    struct inet_maddr_array *out;
    struct inet_maddr_entry *entry;
    char ipbuf[64];

    err = dpvs_getsockopt(SOCKOPT_GET_IFMADDR_SHOW, ifname, len, (void **)&out, &outlen);
    if (err != EDPVS_OK || !out || !outlen)
        return err;

    for (i = 0; i < out->nmaddr; i++) {
        entry = &out->maddrs[i];
        if (verbose) {
            printf("\t%5s %s\t\tflags 0x%x\t\trefcnt %u\n", entry->af == AF_INET6 ? "inet6" : "inet",
                    inet_ntop(entry->af, &entry->maddr, ipbuf, sizeof(ipbuf)) ? ipbuf : "unknown",
                    entry->flags, entry->refcnt);
        } else {
            printf("\t%5s %s\n", entry->af == AF_INET6 ? "inet6" : "inet",
                    inet_ntop(entry->af, &entry->maddr, ipbuf, sizeof(ipbuf)) ? ipbuf : "unknown");
        }
    }

    dpvs_sockopt_msg_free(out);
    return EDPVS_OK;
}

static int maddr_get_and_dump(const char *ifname, size_t len, bool verbose)
{
    int err;

    err = hwm_get_and_dump(ifname, len, verbose);
    if (err != EDPVS_OK)
        return err;

    return ifm_get_and_dump(ifname, len, verbose);
}

static int maddr_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                        struct dpip_conf *conf)
{
    int i, err;
    size_t len;
    char ifname[IFNAMSIZ] = { 0 };
    netif_nic_list_get_t *ports;

    if (maddr_parse_args(conf, ifname, sizeof(ifname)) !=  0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
    case DPIP_CMD_SHOW:
        if (strlen(ifname) > 0) {
            printf("%s:\n", ifname);
            return maddr_get_and_dump(ifname, sizeof(ifname), conf->verbose);
        }

        /* list all devices */
        err = dpvs_getsockopt(SOCKOPT_NETIF_GET_PORT_LIST, NULL, 0, (void **)&ports, &len);
        if (err != EDPVS_OK || !ports || !len)
            return err;
        for (i = 0; i < ports->nic_num && i < NETIF_MAX_PORTS; i++) {
            printf("%d:\t%s\n", ports->idname[i].id + 1, ports->idname[i].name);
            err = maddr_get_and_dump(ports->idname[i].name,
                    sizeof(ports->idname[i].name), conf->verbose);
            if (err != EDPVS_OK) {
                dpvs_sockopt_msg_free(ports);
                return err;
            }
        }
        dpvs_sockopt_msg_free(ports);
        break;
    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

struct dpip_obj dpip_maddr = {
    .name   = "maddr",
    .help   = maddr_help,
    .do_cmd = maddr_do_cmd,
};

static void __init maddr_init(void)
{
    dpip_register_obj(&dpip_maddr);
}

static void __exit maddr_exit(void)
{
    dpip_unregister_obj(&dpip_maddr);
}
