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
#ifndef __DPVS_SVC_CONF_H__
#define __DPVS_SVC_CONF_H__

#include <stdint.h>
#include <net/if.h>
#include "inet.h"
#include "conf/match.h"
#include "conf/stats.h"
#include "conf/dest.h"
#include "conf/sockopts.h"

#define DP_VS_SCHEDNAME_MAXLEN      16

/*
 * Virtual Service Flags derived from "linux/ip_vs.h"
 */
#define IP_VS_SVC_F_PERSISTENT          0x0001              /* persistent port */
#define IP_VS_SVC_F_HASHED              0x0002              /* hashed entry */
#define IP_VS_SVC_F_ONEPACKET           0x0004              /* one-packet scheduling */
#define IP_VS_SVC_F_SCHED1              0x0008              /* scheduler flag 1 */
#define IP_VS_SVC_F_SCHED2              0x0010              /* scheduler flag 2 */
#define IP_VS_SVC_F_SCHED3              0x0020              /* scheduler flag 3 */
#define IP_VS_SVC_F_SIP_HASH            0x0100              /* sip hash target */
#define IP_VS_SVC_F_QID_HASH            0x0200              /* quic cid hash target */
#define IP_VS_SVC_F_MATCH               0x0400              /* snat match */
#define IP_VS_SVC_F_SCHED_SH_FALLBACK   IP_VS_SVC_F_SCHED1  /* SH fallback */
#define IP_VS_SVC_F_SCHED_SH_PORT       IP_VS_SVC_F_SCHED2  /* SH use port */

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

#define MAX_ARG_LEN    (sizeof(struct dp_vs_service_user) +    \
                         sizeof(struct dp_vs_dest_user))

#endif /* __DPVS_SVC_CONF_H__ */
