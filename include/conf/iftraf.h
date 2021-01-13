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
#ifndef __DPVS_IFTRAF_CONF_H__
#define __DPVS_IFTRAF_CONF_H__

#include <stdint.h>
#include <linux/if_addr.h>
#include "inet.h"
#include "conf/sockopts.h"

struct dp_vs_iftraf_conf {
    char ifname[IFNAMSIZ];
} __attribute__((__packed__));


struct iftraf_param {
    uint8_t af;
    uint8_t proto;
    uint8_t cid;
    uint16_t devid;
    char ifname[IFNAMSIZ];
    union inet_addr saddr;
    union inet_addr daddr;
    uint16_t sport;
    uint16_t dport;

    uint32_t total_recv;
    uint32_t total_sent;

} __attribute__((__packed__));

struct iftraf_param_array {
    int ntrafs;
    struct iftraf_param iftraf[0];
};

#endif /* __DPVS_INETADDR_CONF_H__ */
