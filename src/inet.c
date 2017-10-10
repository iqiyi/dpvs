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
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "ipv4.h"
#include "route.h"
#include "neigh.h"
#include "inet.h"
#include "icmp.h"
#include "inetaddr.h"

#define INET
#define RTE_LOGTYPE_INET RTE_LOGTYPE_USER1

int inet_init(void)
{
    int err;

    if ((err = neigh_init()) != 0)
        return err;
    if ((err = route_init()) != 0)
        return err;
    if ((err = ipv4_init()) != 0)
        return err;
    if ((err = icmp_init()) != 0)
        return err;
    if ((err = inet_addr_init()) != 0)
        return err;

    return EDPVS_OK;
}

int inet_term(void)
{
    int err;

    if ((err = inet_addr_term()) != 0)
        return err;
    if ((err = icmp_term()) != 0)
        return err;
    if ((err = ipv4_term()) != 0)
        return err;
    if ((err = route_term()) != 0)
        return err;
    if ((err = neigh_term()) != 0)
        return err;

    return EDPVS_OK;
}

bool inet_addr_equal(int af, const union inet_addr *a1, 
                     const union inet_addr *a2)
{
    switch (af) {
    case AF_INET:
        return a1->in.s_addr == a2->in.s_addr;
    case AF_INET6:
        return memcmp(a1->in6.s6_addr, a2->in6.s6_addr, 16) == 0;
    default:
        return memcmp(a1, a2, sizeof(union inet_addr)) == 0;
    }
}

const char *inet_proto_name(uint8_t proto)
{
    const static char *proto_names[256] = {
        [IPPROTO_TCP]   = "TCP",
        [IPPROTO_UDP]   = "UDP",
        [IPPROTO_ICMP]  = "ICMP",
    };

    return proto_names[proto] ? proto_names[proto] : "<unknow>";
}

bool inet_is_addr_any(int af, const union inet_addr *addr)
{
    switch (af) {
    case AF_INET:
        return addr->in.s_addr == htonl(INADDR_ANY);
    case AF_INET6:
        return IN6_ARE_ADDR_EQUAL(&addr->in6, &in6addr_any);
    default:
        return false; /* ? */
    }
}

int inet_plen_to_mask(int af, uint8_t plen, union inet_addr *mask)
{
    switch (af) {
    case AF_INET:
        if (plen == 0)
            return mask->in.s_addr = 0;
        return mask->in.s_addr = htonl(~((1U<<(32-plen))-1));
    case AF_INET6:
        return EDPVS_NOTSUPP;
    default:
        return EDPVS_INVAL;
    }
}

int inet_addr_net(int af, const union inet_addr *addr, 
                  const union inet_addr *mask,
                  union inet_addr *net)
{
    switch (af) {
    case AF_INET:
        net->in.s_addr = addr->in.s_addr & mask->in.s_addr;
        break;
    case AF_INET6:
        return EDPVS_NOTSUPP;
    default:
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

bool inet_addr_same_net(int af, uint8_t plen,
                        const union inet_addr *addr1,
                        const union inet_addr *addr2)
{
    uint32_t mask;

    switch (af) {
    case AF_INET:
        mask = ~((0x1<<(32-plen)) - 1);
        return !((addr1->in.s_addr^addr2->in.s_addr)&mask);
    default:
        return false;
    }
}

/* ip1[-ip2][:port1[-port2]] */
int inet_addr_range_parse(int af, const char *param,
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

void inet_addr_range_dump(int af, const struct inet_addr_range *range,
                          char *buf, size_t size)
{
    char min_ip[64], max_ip[64];
    char min_port[16], max_port[16];

    inet_ntop(af, &range->min_addr, min_ip, sizeof(min_ip));
    inet_ntop(af, &range->max_addr, max_ip, sizeof(max_ip));
    snprintf(min_port, sizeof(min_port), "%u",  ntohs(range->min_port));
    snprintf(max_port, sizeof(max_port), "%u",  ntohs(range->max_port));

    snprintf(buf, size, "%s-%s:%s-%s", min_ip, max_ip, min_port, max_port);
    return;
}
