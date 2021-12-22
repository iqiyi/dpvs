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
 * Note: control plane only
 * based on dpvs_sockopt.
 */
#ifndef __DPVS_IPSET_CONF_H__
#define __DPVS_IPSET_CONF_H__

#include "conf/sockopts.h"

struct dp_vs_ipset_conf {
	int af;
	union inet_addr    addr;
};

struct dp_vs_multi_ipset_conf {
    int num;
    struct dp_vs_ipset_conf ipset_conf[0];
};

struct dp_vs_ipset_conf_array {
    int                 nipset;
    struct dp_vs_ipset_conf   ips[0];
} __attribute__((__packed__));

#endif /* __DPVS_IPSET_CONF_H__ */
