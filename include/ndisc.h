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
#ifndef __DPVS_NDISC_H__
#define __DPVS_NDISC_H__

#include "neigh.h"

int ndisc_rcv(struct rte_mbuf *mbuf,
              struct netif_port *dev);

void ndisc_send_dad(struct netif_port *dev,
                    const struct in6_addr* solicit);

void ndisc_solicit(struct neighbour_entry *neigh,
                   const struct in6_addr *saddr);

#endif /* __DPVS_NDISC_H__ */
