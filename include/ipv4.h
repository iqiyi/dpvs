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
#include "netif.h"
#include "route.h"

#define IPPROTO_OSPF    89 /* OSPF protocol */
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

/* 
 * Inet Hooks
 */
enum {
    INET_HOOK_PRE_ROUTING,
    INET_HOOK_LOCAL_IN,
    INET_HOOK_FORWARD,
    INET_HOOK_LOCAL_OUT,
    INET_HOOK_POST_ROUTING,
    INET_HOOK_NUMHOOKS,
};

struct inet_hook_state {
    unsigned int        hook;
} __rte_cache_aligned;

enum {
    INET_DROP           = 0,
    INET_ACCEPT,
    INET_STOLEN,
    INET_REPEAT,
    INET_STOP,
    INET_VERDICT_NUM,
};

typedef int (*inet_hook_fn)(void *priv, struct rte_mbuf *mbuf, 
        const struct inet_hook_state *state);

struct inet_hook_ops {
    inet_hook_fn        hook;
    unsigned int        hooknum;
    void                *priv;
    int                 priority;

    struct list_head    list;
};

int ipv4_register_hooks(struct inet_hook_ops *ops, size_t n);
int ipv4_unregister_hooks(struct inet_hook_ops *ops, size_t n);

int INET_HOOK(unsigned int hook, struct rte_mbuf *mbuf, 
        struct netif_port *in, struct netif_port *out,
        int (*okfn)(struct rte_mbuf *mbuf));

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

struct ip4_stats {
    uint64_t inpkts;            /* InReceives */
    uint64_t inoctets;          /* InOctets */
    uint64_t indelivers;        /* InDelivers */
    uint64_t outforwdatagrams;  /* OutForwDatagrams */
    uint64_t outpkts;           /* OutRequests */
    uint64_t outoctets;         /* OutOctets */
    uint64_t inhdrerrors;       /* InHdrErrors */
    uint64_t intoobigerrors;    /* InTooBigErrors */
    uint64_t innoroutes;        /* InNoRoutes */
    uint64_t inaddrerrors;      /* InAddrErrors */
    uint64_t inunknownprotos;   /* InUnknownProtos */
    uint64_t intruncatedpkts;   /* InTruncatedPkts */
    uint64_t indiscards;        /* InDiscards */
    uint64_t outdiscards;       /* OutDiscards */
    uint64_t outnoroutes;       /* OutNoRoutes */
    uint64_t reasmtimeout;      /* ReasmTimeout */
    uint64_t reasmreqds;        /* ReasmReqds */
    uint64_t reasmoks;          /* ReasmOKs */
    uint64_t reasmfails;        /* ReasmFails */
    uint64_t fragoks;           /* FragOKs */
    uint64_t fragfails;         /* FragFails */
    uint64_t fragcreates;       /* FragCreates */
    uint64_t inmcastpkts;       /* InMcastPkts */
    uint64_t outmcastpkts;      /* OutMcastPkts */
    uint64_t inbcastpkts;       /* InBcastPkts */
    uint64_t outbcastpkts;      /* OutBcastPkts */
    uint64_t inmcastoctets;     /* InMcastOctets */
    uint64_t outmcastoctets;    /* OutMcastOctets */
    uint64_t inbcastoctets;     /* InBcastOctets */
    uint64_t outbcastoctets;    /* OutBcastOctets */
    uint64_t csumerrors;        /* InCsumErrors */
    uint64_t noectpkts;         /* InNoECTPkts */
    uint64_t ect1pkts;          /* InECT1Pkts */
    uint64_t ect0pkts;          /* InECT0Pkts */
    uint64_t cepkts;            /* InCEPkts */
} __rte_cache_aligned;

int ipv4_get_stats(struct ip4_stats *stats);
int ip4_defrag(struct rte_mbuf *mbuf, int user);

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

#endif /* __DPVS_IPV4_H__ */
