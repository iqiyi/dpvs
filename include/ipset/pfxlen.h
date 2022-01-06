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
#ifndef __DPVS_IPSET_PFXLEN_H__
#define __DPVS_IPSET_PFXLEN_H__

#include <stdint.h>
#include <asm/byteorder.h>
#include <linux/netfilter.h>
#include "conf/inet.h"

/* Prefixlen maps, by Jan Engelhardt  */
extern const union nf_inet_addr ip_set_netmask_map[];
extern const union nf_inet_addr ip_set_hostmask_map[];

static inline __be32
ip_set_netmask(__u8 pfxlen)
{
    return ip_set_netmask_map[pfxlen].ip;
}

static inline const __be32 *
ip_set_netmask6(__u8 pfxlen)
{
    return &ip_set_netmask_map[pfxlen].ip6[0];
}

static inline __u32
ip_set_hostmask(__u8 pfxlen)
{
    return (__u32) ip_set_hostmask_map[pfxlen].ip;
}

static inline const __be32 *
ip_set_hostmask6(__u8 pfxlen)
{
    return &ip_set_hostmask_map[pfxlen].ip6[0];
}

extern __u32 ip_set_range_to_cidr(__u32 from, __u32 to, __u8 *cidr);

#define ip_set_mask_from_to(from, to, cidr)    \
do {                        \
    from &= ip_set_hostmask(cidr);        \
    to = from | ~ip_set_hostmask(cidr);    \
} while (0)

static inline void
ip6_netmask(union inet_addr *ip, __u8 prefix)
{
    __be32 *ip6 = ip->in6.__in6_u.__u6_addr32;

    ip6[0] &= ip_set_netmask6(prefix)[0];
    ip6[1] &= ip_set_netmask6(prefix)[1];
    ip6[2] &= ip_set_netmask6(prefix)[2];
    ip6[3] &= ip_set_netmask6(prefix)[3];
}

#endif
