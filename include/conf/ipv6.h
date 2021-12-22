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
 * IPv6 protocol control plane.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#ifndef __DPVS_IPV6_CONF_H__
#define __DPVS_IPV6_CONF_H__

#include "inet.h"
#include "conf/sockopts.h"

struct ip6_stats_param {
    struct inet_stats stats;
    struct inet_stats stats_cpus[DPVS_MAX_LCORE];
} __attribute__((__packed__));

#endif /* __DPVS_IPV6_CONF_H__ */
