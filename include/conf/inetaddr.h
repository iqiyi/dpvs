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
#ifndef __DPVS_INETADDR_CONF_H__
#define __DPVS_INETADDR_CONF_H__
#include <stdint.h>
#include <linux/if_addr.h>
#include "inet.h"
#include "net/if.h"

enum {
    /* set */
    SOCKOPT_SET_IFADDR_ADD  = 400,
    SOCKOPT_SET_IFADDR_DEL,
    SOCKOPT_SET_IFADDR_SET,
    SOCKOPT_SET_IFADDR_FLUSH,

    /* get */
    SOCKOPT_GET_IFADDR_SHOW,
};

enum {
    IFA_SCOPE_GLOBAL        = 0,
    IFA_SCOPE_SITE,         /* IPv6 only */
    IFA_SCOPE_LINK,         /* link local */
    IFA_SCOPE_HOST,         /* valid inside the host */
    IFA_SCOPE_NONE          = 255,
};

/* leverage IFA_F_XXX in linux/if_addr.h*/
#define IFA_F_SAPOOL        0x10000 /* if address with sockaddr pool */

struct inet_addr_param {
    int                 af;
    char                ifname[IFNAMSIZ];
    union inet_addr     addr;
    uint8_t             plen;
    union inet_addr     bcast;
    uint32_t            valid_lft;
    uint32_t            prefered_lft;
    uint8_t             scope;
    uint32_t            flags;

    uint32_t            sa_used;
    uint32_t            sa_free;
    uint32_t            sa_miss;
} __attribute__((__packed__));

struct inet_addr_param_array {
    int                 naddr;
    struct inet_addr_param addrs[0];
};

#endif /* __DPVS_INETADDR_CONF_H__ */
