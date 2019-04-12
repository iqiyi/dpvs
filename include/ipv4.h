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
#ifndef __DPVS_IPV4_H__
#define __DPVS_IPV4_H__
#include <stdint.h>
#include "common.h"
#include "inet.h"
#include "netif.h"
#include "route.h"

#define IPPROTO_OSPF        89 /* OSPF protocol */

int ipv4_init(void);
int ipv4_term(void);

void ipv4_keyword_value_init(void);
void install_ipv4_keywords(void);

/*
 * Output
 */
/* 'flow4.daddr' & 'flow4.proto' is mandatory
 * while others are not. '0/NULL' for wildcard. */
int ipv4_xmit(struct rte_mbuf *mbuf, const struct flow4 *fl4);

/* call after fill IP headers and LOCAL_OUT hook */
int ipv4_output(struct rte_mbuf *mbuf);

/*
 * Transport Protocols
 */
struct inet_protocol {
    /* mbuf->userdata can be used to get IPv4 header,
     * save it if protocols need ->userdata for other purpose. */
    int (*handler)(struct rte_mbuf *mbuf);
};

int ipv4_register_protocol(struct inet_protocol *prot,
        unsigned char protocol);
int ipv4_unregister_protocol(struct inet_protocol *prot,
        unsigned char protocol);

enum {
    IP_DEFRAG_LOCAL_IN      = 0,
    IP_DEFRAG_PRE_ROUTING,
    IP_DEFRAG_VS_FWD,
};

int ipv4_register_hooks(struct inet_hook_ops *ops, size_t n);
int ipv4_unregister_hooks(struct inet_hook_ops *ops, size_t n);

/*
 * Statistics
 */
#ifdef CONFIG_DPVS_IPV4_STATS
extern struct ip4_stats ip4_statistics;
extern rte_spinlock_t ip4_stats_lock;

#define IP4_INC_STATS(field) \
    do { \
        rte_spinlock_lock(&ip4_stats_lock); \
        ip4_statistics.field++; \
        rte_spinlock_unlock(&ip4_stats_lock); \
    } while (0)

#define IP4_DEC_STATS(field) \
    do { \
        rte_spinlock_lock(&ip4_stats_lock); \
        ip4_statistics.field--; \
        rte_spinlock_unlock(&ip4_stats_lock); \
    } while (0)

#define __IP4_ADD_STATS(field, val) \
    do { \
        ip4_statistics.field += (val); \
    } while (0)

#define IP4_ADD_STATS(field, val) \
    do { \
        rte_spinlock_lock(&ip4_stats_lock); \
        __IP4_ADD_STATS(field, (val)); \
        rte_spinlock_unlock(&ip4_stats_lock); \
    } while (0)

#define IP4_UPD_PO_STATS(field, val) \
    do { \
        rte_spinlock_lock(&ip4_stats_lock); \
        __IP4_ADD_STATS(field##pkts, (val)); \
        __IP4_ADD_STATS(field##octets, (val)); \
        rte_spinlock_unlock(&ip4_stats_lock); \
    } while (0)
#else
#define IP4_INC_STATS(field)
#define IP4_DEC_STATS(field)
#define IP4_ADD_STATS(field, val)
#define IP4_UPD_PO_STATS(field, val)
#endif

typedef struct inet_stats ip4_stats;

struct ip4_stats;
int ipv4_get_stats(struct ip4_stats *stats);
int ip4_defrag(struct rte_mbuf *mbuf, int user);

uint32_t ip4_select_id(struct ipv4_hdr *iph);
int ipv4_local_out(struct rte_mbuf *mbuf);

/* helper functions */
static inline struct ipv4_hdr *ip4_hdr(const struct rte_mbuf *mbuf)
{
    /* can only invoked at L3 */
    return rte_pktmbuf_mtod(mbuf, struct ipv4_hdr *);
}

static inline int ip4_hdrlen(const struct rte_mbuf *mbuf)
{
    return (ip4_hdr(mbuf)->version_ihl & 0xf) << 2;
}

static inline void ip4_send_csum(struct ipv4_hdr *iph)
{
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
}

static inline bool ip4_is_frag(struct ipv4_hdr *iph)
{
    return (iph->fragment_offset
            & htons(IPV4_HDR_MF_FLAG | IPV4_HDR_OFFSET_MASK)) != 0;
}

/*
 * Process the pseudo-header checksum of an IPv4 header.
 *
 * Different from "rte_ipv4_phdr_cksum", "ip4_phdr_cksum" allows for ipv4 options.
 * The checksum field must be set to 0 by the caller.
 *
 * @param iph
 *   The pointer to the contiguous IPv4 header.
 * @param ol_flags
 *   The ol_flags of the associated mbuf.
 * @return
 *   The non-complemented pseudo checksum to set in the L4 header.
 */
static inline uint16_t ip4_phdr_cksum(struct ipv4_hdr *iph, uint64_t ol_flags)
{
    uint16_t csum;
    uint16_t total_length = iph->total_length;

    iph->total_length = htons(ntohs(total_length) -
            ((iph->version_ihl & 0xf) << 2) + sizeof(struct ipv4_hdr));
    csum = rte_ipv4_phdr_cksum(iph, ol_flags);

    iph->total_length = total_length;
    return csum;
}

/*
 * Process the IPv4 UDP or TCP checksum.
 *
 * Different from "rte_ipv4_udptcp_cksum", "ip4_udptcp_cksum" allows for ipv4 options.
 * The IP and layer 4 checksum must be set to 0 in the packet by the caller.
 *
 * @param iph
 *   The pointer to the contiguous IPv4 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the L4 header.
 */
static inline uint16_t ip4_udptcp_cksum(struct ipv4_hdr *iph, const void *l4_hdr)
{
    uint16_t csum;
    uint16_t total_length = iph->total_length;

    iph->total_length = htons(ntohs(total_length) -
            ((iph->version_ihl & 0xf) << 2) + sizeof(struct ipv4_hdr));
    csum = rte_ipv4_udptcp_cksum(iph, l4_hdr);

    iph->total_length = total_length;
    return csum;
}

#endif /* __DPVS_IPV4_H__ */
