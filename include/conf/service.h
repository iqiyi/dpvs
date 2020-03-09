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
#ifndef __DPVS_SVC_CONF_H__
#define __DPVS_SVC_CONF_H__

#include <stdint.h>
#include <net/if.h>
#include "inet.h"
#include "conf/match.h"
#include "conf/stats.h"
#include "conf/dest.h"

#define DP_VS_SCHEDNAME_MAXLEN      16

struct dp_vs_service_conf {
    /* virtual service addresses */
    uint16_t            af;
    uint16_t            protocol;
    union inet_addr     addr;       /* virtual ip address */
    uint16_t            port;
    uint32_t            fwmark;     /* firwall mark of service */
    struct dp_vs_match  match;

    /* virtual service options */
    char                *sched_name;
    unsigned            flags;     /* virtual service flags */
    unsigned            timeout;   /* persistent timeout in sec */
    unsigned            conn_timeout;
    uint32_t            netmask;        /* persistent netmask */
    unsigned            bps;
    unsigned            limit_proportion;
};

struct dp_vs_service_entry {
    int                 af;
    uint16_t            proto;
    union inet_addr     addr;
    uint16_t            port;
    uint32_t            fwmark;

    char                sched_name[DP_VS_SCHEDNAME_MAXLEN];
    unsigned            flags;
    unsigned            timeout;
    unsigned            conn_timeout;
    uint32_t            netmask;
    unsigned            bps;
    unsigned            limit_proportion;

    unsigned int        num_dests;
    unsigned int        num_laddrs;
    lcoreid_t           cid;

    struct dp_vs_stats  stats;

    char                srange[256];
    char                drange[256];
    char                iifname[IFNAMSIZ];
    char                oifname[IFNAMSIZ];
};

struct dp_vs_get_services {
    lcoreid_t     cid;
    unsigned int        num_services;
    struct dp_vs_service_entry entrytable[0];
};

struct dp_vs_service_user {
    int               af;
    uint16_t          proto;
    union inet_addr   addr;
    uint16_t          port;
    uint32_t          fwmark;

    char              sched_name[DP_VS_SCHEDNAME_MAXLEN];
    unsigned          flags;
    unsigned          timeout;
    unsigned          conn_timeout;
    uint32_t          netmask;
    unsigned          bps;
    unsigned          limit_proportion;

    char              srange[256];
    char              drange[256];
    char              iifname[IFNAMSIZ];
    char              oifname[IFNAMSIZ];
};

struct dp_vs_getinfo {
    unsigned int version;
    unsigned int size;
    unsigned int num_services;
    unsigned int num_lcores;
};

enum{
    DPVS_SO_SET_FLUSH = 200,
    DPVS_SO_SET_ZERO,
    DPVS_SO_SET_ADD,
    DPVS_SO_SET_EDIT,
    DPVS_SO_SET_DEL,
    DPVS_SO_SET_ADDDEST,
    DPVS_SO_SET_EDITDEST,
    DPVS_SO_SET_DELDEST,
    DPVS_SO_SET_GRATARP,
};

enum{
    DPVS_SO_GET_VERSION = 200,
    DPVS_SO_GET_INFO,
    DPVS_SO_GET_SERVICES,
    DPVS_SO_GET_SERVICE,
    DPVS_SO_GET_DESTS,
};


#define SOCKOPT_SVC_BASE         DPVS_SO_SET_FLUSH
#define SOCKOPT_SVC_SET_CMD_MAX  DPVS_SO_SET_GRATARP
#define SOCKOPT_SVC_GET_CMD_MAX  DPVS_SO_GET_DESTS
#define SOCKOPT_SVC_MAX          299

#define MAX_ARG_LEN    (sizeof(struct dp_vs_service_user) +    \
                         sizeof(struct dp_vs_dest_user))

#endif /* __DPVS_SVC_CONF_H__ */
