/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
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

#ifndef __DPVS_ROUTE6_CONF_H__
#define __DPVS_ROUTE6_CONF_H__

enum {
    /* set */
    SOCKOPT_SET_ROUTE6_ADD   = 6300,
    SOCKOPT_SET_ROUTE6_DEL,

    /* get */
    SOCKOPT_GET_ROUTE6_SHOW,
};

struct dp_vs_route6_conf {

} __attribute__((__packed__));

struct dp_vs_route_conf_array {
    int                         nroute;
    struct dp_vs_route6_conf    routes[0];
} __attribute__((__packed__));

#endif /* __DPVS_ROUTE6_CONF_H__ */
