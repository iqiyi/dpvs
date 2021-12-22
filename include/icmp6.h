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

#ifndef __DPVS_ICMPV6_H__
#define __DPVS_ICMPV6_H__

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#define icmp6h_id(icmp6h)        ((icmp6h)->icmp6_dataun.icmp6_un_data16[0])
void icmp6_send(struct rte_mbuf *imbuf, int type, int code, uint32_t info);
uint16_t icmp6_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich);
void icmp6_send_csum(struct ip6_hdr *shdr, struct icmp6_hdr *ich);

int icmpv6_init(void);
int icmpv6_term(void);

#endif /* __DPVS_ICMPV6_H__ */
