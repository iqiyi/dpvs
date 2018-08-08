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
/**
 * IPv6 protocol for "lite stack".
 * Linux Kernel net/ipv6/ is referred.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */

#ifndef __DPVS_IPV6_H__
#define __DPVS_IPV6_H__

#include <netinet/ip6.h>
#include "rte_mbuf.h"
#include "linux_ipv6.h"
#include "flow.h"

#define IPV6
#define RTE_LOGTYPE_IPV6    RTE_LOGTYPE_USER1

/*
 * helper functions
 */
static inline struct ip6_hdr *ip6_hdr(const struct rte_mbuf *mbuf)
{
    /* can only invoked at L3 */
    return rte_pktmbuf_mtod(mbuf, struct ip6_hdr *);
}

enum {
    INET6_PROTO_F_NONE      = 0x01,
    INET6_PROTO_F_FINAL     = 0x02,
};

/*
 * inet6_protocol:
 * to process IPv6 upper-layer protocol or ext-header.
 *
 * @handler
 * handler protocol, it consume pkt or return next-header.
 *
 * 1. if return > 0, it's always "nexthdr",
 *    no matter if proto is final or not.
 * 2. if return == 0, the pkt is consumed.
 * 3. should not return < 0, or it'll be ignored.
 * 4. mbuf->l3_len must be upadted by handler
 *    to the value as ext-header length.
 *
 * @flags: INET6_PROTO_F_XXX
 */
struct inet6_protocol {
    int             (*handler)(struct rte_mbuf *mbuf);
    unsigned int    flags;
};

int ipv6_init(void);
int ipv6_term(void);

int ipv6_xmit(struct rte_mbuf *mbuf, struct flow6 *fl6);

int ipv6_register_hooks(struct inet_hook_ops *ops, size_t n);
int ipv6_unregister_hooks(struct inet_hook_ops *ops, size_t n);

int ipv6_register_protocol(struct inet6_protocol *prot,
                           unsigned char protocol);
int ipv6_unregister_protocol(struct inet6_protocol *prot,
                             unsigned char protocol);

int ipv6_stats_cpu(struct inet_stats *stats);

void install_ipv6_keywords(void);
void ipv6_keyword_value_init(void);

/* control plane */
int ipv6_ctrl_init(void);
int ipv6_ctrl_term(void);

/* extension header and options. */
int ipv6_exthdrs_init(void);
void ipv6_exthdrs_term(void);
int ipv6_parse_hopopts(struct rte_mbuf *mbuf);

#endif /* __DPVS_IPV6_H__ */
