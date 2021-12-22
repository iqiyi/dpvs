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
#ifndef __IFTRAF_H__
#define __IFTRAF_H__

#include "conf/common.h"
#include "list.h"
#include "dpdk.h"
#include "timer.h"
#include "inet.h"
#include "ctrl.h"

int iftraf_sockopt_get(sockoptid_t opt, const void *conf, size_t size,  void **out, size_t *outsize);

int iftraf_pkt_in(int af, struct rte_mbuf *mbuf, struct netif_port *dev);
int iftraf_pkt_out(int af, struct rte_mbuf *mbuf, struct netif_port *dev);

int iftraf_init(void);
int iftraf_term(void); /* cleanup */

#endif
