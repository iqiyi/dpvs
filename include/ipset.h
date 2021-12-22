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
#ifndef __DPVS_IPSET_H__
#define __DPVS_IPSET_H__

#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>

#include "list.h"
#include "netif.h"
#include "conf/common.h"
#include "flow.h"

#define RTE_LOGTYPE_IPSET       RTE_LOGTYPE_USER1

#define IPSET_CFG_FILE_NAME "/etc/gfwip.conf"
#define IPSET_CFG_MEMBERS   "members:"

struct ipset_addr {
    int af;
    union inet_addr    addr;
};

struct ipset_entry {
        struct list_head list;
        struct ipset_addr daddr;
};

int ipset_init(void);
int ipset_add(int af, union inet_addr *dest);
int ipset_del(int af, union inet_addr *dest);
int ipset_term(void);

struct ipset_entry *ipset_addr_lookup(int af, union inet_addr *dest);

#ifdef CONFIG_DPVS_IPSET_DEBUG
int ipset_list(void);
int ipset_test(void);
#endif


#endif
