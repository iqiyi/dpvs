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
#ifndef __DPVS_IPSET_H__
#define __DPVS_IPSET_H__

#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "list.h"
#include "netif.h"
#include "common.h"
#include "flow.h"

int ipset_add(int af, union inet_addr *dest);
int ipset_del(int af, union inet_addr *dest);
int ipset_list(void);
int ipset_init(void);

struct ipset_entry *ipset_dest_lookup(struct in_addr *dest);

struct ipset_entry *ipset_addr_lookup(int af, union inet_addr *dest);
int ipset_test(void);
#endif
