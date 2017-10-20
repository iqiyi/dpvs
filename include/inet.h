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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

static inline const char *inet_proto_name(uint8_t proto)
{
    const static char *proto_names[256] = {
        [IPPROTO_TCP]   = "TCP",
        [IPPROTO_UDP]   = "UDP",
        [IPPROTO_ICMP]  = "ICMP",
    };

    return proto_names[proto] ? proto_names[proto] : "<unknow>";
}

/* ip1[-ip2][:port1[-port2]] */
static inline int inet_addr_range_parse(int af, const char *param,
                                        struct inet_addr_range *range)
{
    char _param[256], *ips, *ports;
    char *ip1, *ip2, *port1, *port2;

    if (af != AF_INET)
        return EDPVS_NOTSUPP;

    if (strlen(param) == 0)
        return EDPVS_OK; /* return asap */

    snprintf(_param, sizeof(_param), "%s", param);
    ports = strrchr(_param, ':');
    if (ports)
        *ports++ = '\0';
    ips = _param;

    ip1 = ips;
    ip2 = strrchr(ips, '-');
    if (ip2)
        *ip2++ = '\0';

    if (ports) {
        port1 = ports;
        port2 = strrchr(ports, '-');
        if (port2)
            *port2++ = '\0';
    } else {
        port1 = port2 = NULL;
    }

    memset(range, 0, sizeof(*range));

    if (strlen(ip1) && inet_pton(AF_INET, ip1, &range->min_addr.in) <= 0)
        return EDPVS_INVAL;

    if (ip2 && strlen(ip2)) {
       if  (inet_pton(AF_INET, ip2, &range->max_addr.in) <= 0)
           return EDPVS_INVAL;
    } else {
        range->max_addr = range->min_addr;
    }

    if (port1 && strlen(port1))
        range->min_port = htons(atoi(port1));

    if (port2 && strlen(port2))
        range->max_port = htons(atoi(port2));
    else
        range->max_port = range->min_port;

    return EDPVS_OK;
}

static inline int inet_addr_range_dump(int af,
                                       const struct inet_addr_range *range,
                                       char *buf, size_t size)
{
    char min_ip[64], max_ip[64];
    char min_port[16], max_port[16];

    inet_ntop(af, &range->min_addr, min_ip, sizeof(min_ip));
    inet_ntop(af, &range->max_addr, max_ip, sizeof(max_ip));
    snprintf(min_port, sizeof(min_port), "%u",  ntohs(range->min_port));
    snprintf(max_port, sizeof(max_port), "%u",  ntohs(range->max_port));

    return snprintf(buf, size, "%s-%s:%s-%s",
                    min_ip, max_ip, min_port, max_port);
}

#ifdef __DPVS__

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

int inet_addr_range_dump(int af, const struct inet_addr_range *range,
                         char *buf, size_t size);
#endif /* __DPVS__ */

#endif /* __DPVS_INET_H__ */
