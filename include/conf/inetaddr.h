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
#ifndef __DPVS_INETADDR_CONF_H__
#define __DPVS_INETADDR_CONF_H__

#include <stdint.h>
#include <linux/if_addr.h>
#include "inet.h"
#include "net/if.h"
#include "conf/sockopts.h"

enum {
    IFA_SCOPE_GLOBAL        = 0,
    IFA_SCOPE_SITE,         /* IPv6 only */
    IFA_SCOPE_LINK,         /* link local */
    IFA_SCOPE_HOST,         /* valid inside the host */
    IFA_SCOPE_NONE          = 255,
};

/* leverage IFA_F_XXX in linux/if_addr.h*/
#define IFA_F_SAPOOL        0x10000 /* if address with sockaddr pool */
#define IFA_F_LINKLOCAL     0x20000 /* ipv6 link-local address */

/* ifa command flags */
#define IFA_F_OPS_VERBOSE   0x0001
#define IFA_F_OPS_STATS     0x0002

typedef enum ifaddr_ops {
    INET_ADDR_GET       = 1,
    INET_ADDR_ADD,
    INET_ADDR_DEL,
    INET_ADDR_MOD,
    INET_ADDR_FLUSH,
    INET_ADDR_SYNC,
} ifaddr_ops_t;

struct inet_addr_entry {
    int                 af;
    uint32_t            valid_lft;
    uint32_t            prefered_lft;
    uint32_t            flags;
    char                ifname[IFNAMSIZ];
    union inet_addr     bcast;
    union inet_addr     addr;
    uint8_t             plen;
    uint8_t             scope;
    lcoreid_t           cid;
    uint8_t             nop;
} __attribute__((__packed__));

struct inet_addr_stats {
    uint32_t            sa_used;
    uint32_t            sa_free;
    uint32_t            sa_miss;
} __attribute__((__packed__));

struct inet_addr_param {
    ifaddr_ops_t            ifa_ops;
    uint32_t                ifa_ops_flags;
    struct inet_addr_entry  ifa_entry;
} __attribute__((__packed__));

struct inet_addr_data {
    struct inet_addr_entry  ifa_entry;
    struct inet_addr_stats  ifa_stats;
} __attribute__((__packed__));

struct inet_addr_data_array {
    ifaddr_ops_t            ops;
    uint32_t                ops_flags;
    int                     naddr;
    struct inet_addr_data   addrs[0];
} __attribute__((__packed__));

#ifdef CONFIG_DPVS_AGENT
struct inet_addr_stats_detail {
    union inet_addr     addr;
    uint32_t            sa_used;
    uint32_t            sa_free;
    uint32_t            sa_miss;
};

struct inet_addr_front {
    int count;
    int data[0];
};
#endif /* CONFIG_DPVS_AGENT */

struct inet_maddr_entry {
    char             ifname[IFNAMSIZ];
    union inet_addr  maddr;
    int              af;
    uint32_t         flags;
    uint32_t         refcnt;
} __attribute__((__packed__));

struct inet_maddr_array {
    int                      nmaddr;
    struct inet_maddr_entry  maddrs[0];
} __attribute__((__packed__));

#endif /* __DPVS_INETADDR_CONF_H__ */
