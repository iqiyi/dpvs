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
#ifndef __DPVS_STATS_CONF_H__
#define __DPVS_STATS_CONF_H__
#include <stdint.h>
#include <linux/if_addr.h>
#include "inet.h"

enum {
    /* set */
    SOCKOPT_SET_STATS_ADD  = 6400,
    SOCKOPT_SET_STATS_DEL,

    /* get */
    SOCKOPT_GET_STATS_SHOW,
};

struct stats_param {
	uint8_t 			 af;
	uint8_t 			 proto;
	uint8_t			 cid;

	union inet_addr 	 saddr;
	union inet_addr 	 daddr;
	uint16_t			 sport;
	uint16_t			 dport;

    double long total_recv;
    double long total_sent;

} __attribute__((__packed__));

struct stats_param_array {
    int                 nstats;
    struct stats_param stats[0];
};

#endif /* __DPVS_INETADDR_CONF_H__ */
