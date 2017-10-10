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
#ifndef __DPVS_INET_H__
#define __DPVS_INET_H__
#include <stdbool.h>
#include <netinet/in.h>
#include "common.h"

union inet_addr {
    struct in_addr      in;
    struct in6_addr     in6;
};

struct inet_prefix {
    int                 plen;
    union inet_addr     addr;
};

struct inet_addr_range {
    union inet_addr     min_addr;
    union inet_addr     max_addr;
    __be16              min_port;
    __be16              max_port;
};

int inet_init(void);
int inet_term(void);

bool inet_addr_equal(int af, const union inet_addr *a1, 
                     const union inet_addr *a2);

const char *inet_proto_name(uint8_t proto);

bool inet_is_addr_any(int af, const union inet_addr *addr);

int inet_plen_to_mask(int af, uint8_t plen, union inet_addr *mask);

int inet_addr_net(int af, const union inet_addr *addr, 
                  const union inet_addr *mask,
                  union inet_addr *net);

bool inet_addr_same_net(int af, uint8_t plen,
                        const union inet_addr *addr1,
                        const union inet_addr *addr2);

int inet_addr_range_parse(int af, const char *param,
                          struct inet_addr_range *range);

void inet_addr_range_dump(int af, const struct inet_addr_range *range,
                          char *buf, size_t size);

#endif /* __DPVS_INET_H__ */
