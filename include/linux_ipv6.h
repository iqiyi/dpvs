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
 *
 * modifyed from
 *   linux:include/net/ipv6.h
 *   linux:net/ipv6/addrconf_core.c
 *
 *    Authors:
 *    Pedro Roque        <roque@di.fc.ul.pt>
 */
#ifndef __LINUX_IPV6_H__
#define __LINUX_IPV6_H__
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/if_addr.h>
#include "conf/common.h"
#ifdef __DPVS__
#include "inetaddr.h"
#endif

#define IPV6_MAXPLEN        65535
#define IPV6_MIN_MTU        1280

/*
 *    NextHeader field of IPv6 header
 */
#define NEXTHDR_HOP         0    /* Hop-by-hop option header. */
#define NEXTHDR_TCP         6    /* TCP segment. */
#define NEXTHDR_UDP         17    /* UDP message. */
#define NEXTHDR_IPV6        41    /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING     43    /* Routing header. */
#define NEXTHDR_FRAGMENT    44    /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE         47    /* GRE header. */
#define NEXTHDR_ESP         50    /* Encapsulating security payload. */
#define NEXTHDR_AUTH        51    /* Authentication header. */
#define NEXTHDR_ICMP        58    /* ICMP for IPv6. */
#define NEXTHDR_NONE        59    /* No next header */
#define NEXTHDR_DEST        60    /* Destination options header. */
#define NEXTHDR_SCTP        132    /* SCTP message. */
#define NEXTHDR_MOBILITY    135    /* Mobility header. */

#define NEXTHDR_MAX         255

#define IPV6_DEFAULT_HOPLIMIT   64
#define IPV6_DEFAULT_MCASTHOPS  1

/*
 *    Addr type
 *
 *    type    -    unicast | multicast
 *    scope    -    local    | site        | global
 *    v4    -    compat
 *    v4mapped
 *    any
 *    loopback
 */

#define IPV6_ADDR_ANY           0x0000U

#define IPV6_ADDR_UNICAST       0x0001U
#define IPV6_ADDR_MULTICAST     0x0002U

#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U

#define IPV6_ADDR_COMPATv4      0x0080U

#define IPV6_ADDR_SCOPE_MASK    0x00f0U

#define IPV6_ADDR_MAPPED        0x1000U

#define IPV6_ADDR_RESERVED      0x2000U    /* reserved address space */

/*
 *    Addr scopes
 */
#define IPV6_ADDR_MC_SCOPE(a)    \
    ((a)->s6_addr[1] & 0x0f)    /* nonstandard */
#define __IPV6_ADDR_SCOPE_INVALID    -1
#define IPV6_ADDR_SCOPE_NODELOCAL    0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL    0x02
#define IPV6_ADDR_SCOPE_SITELOCAL    0x05
#define IPV6_ADDR_SCOPE_ORGLOCAL     0x08
#define IPV6_ADDR_SCOPE_GLOBAL       0x0e

/*
 *    Addr flags
 */
#define IPV6_ADDR_MC_FLAG_TRANSIENT(a)    \
    ((a)->s6_addr[1] & 0x10)
#define IPV6_ADDR_MC_FLAG_PREFIX(a)    \
    ((a)->s6_addr[1] & 0x20)
#define IPV6_ADDR_MC_FLAG_RENDEZVOUS(a)    \
    ((a)->s6_addr[1] & 0x40)

/*
 * choose an appropriate source address (RFC3484)
 */
enum {
    IPV6_SADDR_RULE_INIT = 0,
    IPV6_SADDR_RULE_LOCAL,
    IPV6_SADDR_RULE_SCOPE,
    IPV6_SADDR_RULE_PREFERRED,
#ifdef CONFIG_IPV6_MIP6
    IPV6_SADDR_RULE_HOA,
#endif
    IPV6_SADDR_RULE_OIF,
    IPV6_SADDR_RULE_LABEL,
#ifdef CONFIG_IPV6_PRIVACY
    IPV6_SADDR_RULE_PRIVACY,
#endif
    IPV6_SADDR_RULE_ORCHID,
    IPV6_SADDR_RULE_PREFIX,
    IPV6_SADDR_RULE_MAX
};

#ifdef __DPVS__
/* struct help for src select */
struct ipv6_saddr_score {
    int                rule;
    int                addr_type;
    struct inet_ifaddr *ifa;
    bool               scorebits[IPV6_SADDR_RULE_MAX];
    int                scopedist;
    int                matchlen;
};

struct ipv6_saddr_dst {
    const struct in6_addr  *addr;
    struct inet_device     *idev;
    int                    scope;
};
#endif

/**
 * from linux:net/ipv6/addrconf_core.c
 */
#define IPV6_ADDR_SCOPE_TYPE(scope)    ((scope) << 16)

#define IN6ADDR_LINKLOCAL_ALLNODES_INIT    \
        { { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
        { { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }

static const struct in6_addr in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
static const struct in6_addr in6addr_linklocal_allrouters = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;

static inline unsigned int ipv6_addr_scope2type(unsigned int scope)
{
    switch (scope) {
    case IPV6_ADDR_SCOPE_NODELOCAL:
        return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_NODELOCAL) |
            IPV6_ADDR_LOOPBACK);
    case IPV6_ADDR_SCOPE_LINKLOCAL:
        return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL) |
            IPV6_ADDR_LINKLOCAL);
    case IPV6_ADDR_SCOPE_SITELOCAL:
        return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL) |
            IPV6_ADDR_SITELOCAL);
    }
    return IPV6_ADDR_SCOPE_TYPE(scope);
}

static inline int __ipv6_addr_type(const struct in6_addr *addr)
{
    __be32 st;

    st = addr->s6_addr32[0];

    /* Consider all addresses with the first three bits different of
       000 and 111 as unicasts.
     */
    if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
        (st & htonl(0xE0000000)) != htonl(0xE0000000))
        return (IPV6_ADDR_UNICAST |
            IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));

    if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
        /* multicast */
        /* addr-select 3.1 */
        return (IPV6_ADDR_MULTICAST |
            ipv6_addr_scope2type(IPV6_ADDR_MC_SCOPE(addr)));
    }

    if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
        return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
            IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));        /* addr-select 3.1 */
    if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
        return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
            IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));        /* addr-select 3.1 */
    if ((st & htonl(0xFE000000)) == htonl(0xFC000000))
        return (IPV6_ADDR_UNICAST |
            IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));            /* RFC 4193 */

    if ((addr->s6_addr32[0] | addr->s6_addr32[1]) == 0) {
        if (addr->s6_addr32[2] == 0) {
            if (addr->s6_addr32[3] == 0)
                return IPV6_ADDR_ANY;

            if (addr->s6_addr32[3] == htonl(0x00000001))
                return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
                    IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));    /* addr-select 3.4 */

            return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST |
                IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));    /* addr-select 3.3 */
        }

        if (addr->s6_addr32[2] == htonl(0x0000ffff))
            return (IPV6_ADDR_MAPPED |
                IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));    /* addr-select 3.3 */
    }

    return (IPV6_ADDR_UNICAST |
        IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));    /* addr-select 3.4 */
}

static inline int ipv6_addr_type(const struct in6_addr *addr)
{
    return __ipv6_addr_type(addr) & 0xffff;
}

static inline int ipv6_addr_scope(const struct in6_addr *addr)
{
    return __ipv6_addr_type(addr) & IPV6_ADDR_SCOPE_MASK;
}

static inline int __ipv6_addr_src_scope(int type)
{
    return (type == IPV6_ADDR_ANY) ? __IPV6_ADDR_SCOPE_INVALID : (type >> 16);
}

static inline int ipv6_addr_src_scope(const struct in6_addr *addr)
{
    return __ipv6_addr_src_scope(__ipv6_addr_type(addr));
}

static inline bool __ipv6_addr_needs_scope_id(int type)
{
    return type & IPV6_ADDR_LINKLOCAL ||
           (type & IPV6_ADDR_MULTICAST &&
        (type & (IPV6_ADDR_LOOPBACK|IPV6_ADDR_LINKLOCAL)));
}

static inline __u32 ipv6_iface_scope_id(const struct in6_addr *addr, int iface)
{
    return __ipv6_addr_needs_scope_id(__ipv6_addr_type(addr)) ? iface : 0;
}

static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
    return memcmp(a1, a2, sizeof(struct in6_addr));
}

static inline bool
ipv6_masked_addr_cmp(const struct in6_addr *a1, const struct in6_addr *m,
             const struct in6_addr *a2)
{
    return !!(((a1->s6_addr32[0] ^ a2->s6_addr32[0]) & m->s6_addr32[0]) |
          ((a1->s6_addr32[1] ^ a2->s6_addr32[1]) & m->s6_addr32[1]) |
          ((a1->s6_addr32[2] ^ a2->s6_addr32[2]) & m->s6_addr32[2]) |
          ((a1->s6_addr32[3] ^ a2->s6_addr32[3]) & m->s6_addr32[3]));
}

static inline void ipv6_addr_prefix(struct in6_addr *pfx,
                    const struct in6_addr *addr,
                    int plen)
{
    /* caller must guarantee 0 <= plen <= 128 */
    int o = plen >> 3,
        b = plen & 0x7;

    memset(pfx->s6_addr, 0, sizeof(pfx->s6_addr));
    memcpy(pfx->s6_addr, addr, o);
    if (b != 0)
        pfx->s6_addr[o] = addr->s6_addr[o] & (0xff00 >> b);
}

static inline void ipv6_addr_prefix_copy(struct in6_addr *addr,
                     const struct in6_addr *pfx,
                     int plen)
{
    /* caller must guarantee 0 <= plen <= 128 */
    int o = plen >> 3,
        b = plen & 0x7;

    memcpy(addr->s6_addr, pfx, o);
    if (b != 0) {
        addr->s6_addr[o] &= ~(0xff00 >> b);
        addr->s6_addr[o] |= (pfx->s6_addr[o] & (0xff00 >> b));
    }
}

static inline bool ipv6_addr_equal(const struct in6_addr *a1,
                   const struct in6_addr *a2)
{
    return ((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
        (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
        (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
        (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;
}

static inline bool ipv6_prefix_equal(const struct in6_addr *addr1,
                     const struct in6_addr *addr2,
                     unsigned int prefixlen)
{
    const __be32 *a1 = addr1->s6_addr32;
    const __be32 *a2 = addr2->s6_addr32;
    unsigned int pdw, pbi;

    /* check complete u32 in prefix */
    pdw = prefixlen >> 5;
    if (pdw && memcmp(a1, a2, pdw << 2))
        return false;

    /* check incomplete u32 in prefix */
    pbi = prefixlen & 0x1f;
    if (pbi && ((a1[pdw] ^ a2[pdw]) & htonl((0xffffffff) << (32 - pbi))))
        return false;

    return true;
}

static inline bool ipv6_addr_any(const struct in6_addr *a)
{
    return (a->s6_addr32[0] | a->s6_addr32[1] |
            a->s6_addr32[2] | a->s6_addr32[3]) == 0;
}

static inline bool ipv6_addr_loopback(const struct in6_addr *a)
{
    return (a->s6_addr32[0] | a->s6_addr32[1] |
        a->s6_addr32[2] | (a->s6_addr32[3] ^ htonl(1))) == 0;
}

static inline bool ipv6_addr_v4mapped(const struct in6_addr *a)
{
    return (
        (unsigned long)(a->s6_addr32[0] | a->s6_addr32[1]) |
        (unsigned long)(a->s6_addr32[2] ^
                    htonl(0x0000ffff))) == 0UL;
}

static inline bool ipv6_addr_orchid(const struct in6_addr *a)
{
    return (a->s6_addr32[0] & htonl(0xfffffff0)) == htonl(0x20010010);
}

static inline bool ipv6_addr_is_multicast(const struct in6_addr *addr)
{
    return (addr->s6_addr32[0] & htonl(0xFF000000)) == htonl(0xFF000000);
}

static inline void ipv6_addr_set(struct in6_addr *addr,
                                 uint32_t w1, uint32_t w2,
                                 uint32_t w3, uint32_t w4)
{
        addr->s6_addr32[0] = w1;
        addr->s6_addr32[1] = w2;
        addr->s6_addr32[2] = w3;
        addr->s6_addr32[3] = w4;
}

static inline void ipv6_addr_copy(struct in6_addr *a1,
                                  const struct in6_addr *a2)
{
    memcpy(a1, a2, sizeof(struct in6_addr));
}

static inline void addrconf_addr_solict_mult(const struct in6_addr *addr,
                                             struct in6_addr *solicited)
{
        ipv6_addr_set(solicited,
                      htonl(0xFF020000), 0,
                      htonl(0x1),
                      htonl(0xFF000000) | addr->s6_addr32[3]);
}

/* net/addrconf.h */
static inline bool ipv6_addr_is_ll_all_nodes(const struct in6_addr *addr)
{
    return ((addr->s6_addr32[0] ^ htonl(0xff020000)) |
        addr->s6_addr32[1] | addr->s6_addr32[2] |
        (addr->s6_addr32[3] ^ htonl(0x00000001))) == 0;
}

static inline bool ipv6_addr_is_ll_all_routers(const struct in6_addr *addr)
{
    return ((addr->s6_addr32[0] ^ htonl(0xff020000)) |
        addr->s6_addr32[1] | addr->s6_addr32[2] |
        (addr->s6_addr32[3] ^ htonl(0x00000002))) == 0;
}

static inline bool ipv6_addr_is_isatap(const struct in6_addr *addr)
{
    return (addr->s6_addr32[2] | htonl(0x02000000)) == htonl(0x02005EFE);
}

static inline bool ipv6_addr_is_solict_mult(const struct in6_addr *addr)
{
    return ((addr->s6_addr32[0] ^ htonl(0xff020000)) |
        addr->s6_addr32[1] |
        (addr->s6_addr32[2] ^ htonl(0x00000001)) |
        (addr->s6_addr[12] ^ 0xff)) == 0;
}

static inline int fls(int x)
{
    int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}

static inline int __ipv6_addr_diff(const void *token1, const void *token2, int addrlen)
{
    const __be32 *a1 = token1, *a2 = token2;
    int i;

    addrlen >>= 2;

    for (i = 0; i < addrlen; i++) {
        __be32 xb = a1[i] ^ a2[i];
        if (xb)
            return i * 32 + 32 - fls(ntohl(xb));
    }

    /*
     *    we should *never* get to this point since that
     *    would mean the addrs are equal
     *
     *    However, we do get to it 8) And exacly, when
     *    addresses are equal 8)
     *
     *    ip route add 1111::/128 via ...
     *    ip route add 1111::/64 via ...
     *    and we are here.
     *
     *    Ideally, this function should stop comparison
     *    at prefix length. It does not, but it is still OK,
     *    if returned value is greater than prefix length.
     *                    --ANK (980803)
     */
    return (addrlen << 5);
}

static inline int ipv6_addr_diff(const struct in6_addr *a1, const struct in6_addr *a2)
{
    return __ipv6_addr_diff(a1, a2, sizeof(struct in6_addr));
}

static inline int ipv6_saddr_preferred(int type)
{
    if (type & (IPV6_ADDR_MAPPED|IPV6_ADDR_COMPATv4|
            IPV6_ADDR_LOOPBACK|IPV6_ADDR_RESERVED))
        return 1;
    return 0;
}

static inline bool ipv6_reserved_interfaceid(const struct in6_addr *addr)
{
    if ((addr->s6_addr32[2] | addr->s6_addr32[3]) == 0)
        return true;
    if (addr->s6_addr32[2] == htonl(0x02005eff) &&
                ((addr->s6_addr32[3] & htonl(0xfe000000)) == htonl(0xfe000000)))
        return true;
    if (addr->s6_addr32[2] == htonl(0xfdffffff) &&
            ((addr->s6_addr32[3] & htonl(0xffffff80)) == htonl(0xffffff80)))
        return true;
    return false;
}

#ifdef __DPVS__
/*functions below were edited from addrconf.c*/

/*
 * 1. Prefer same address. (i.e. destination is local machine)
 * 2. Prefer appropriate scope. (i.e. smallest scope shared with the destination)
 * 3. Avoid deprecated addresses.
 * 4. Prefer home addresses. (not support here!)
 * 5. Prefer outgoing interface. (i.e. prefer an address on the interface we’re sending out of)
 * 6. Prefer matching label. (not support here!)
 * 7. Prefer public addresses. (not support here)
 * 8. Use longest matching prefix.
 */
static inline int ipv6_get_saddr_eval(struct ipv6_saddr_score *score,
                                      struct ipv6_saddr_dst *dst,
                                      int i)
{
    int ret;

    if (i <= score->rule) {
        switch (i) {
            case IPV6_SADDR_RULE_SCOPE:
                ret = score->scopedist;
                break;
            case IPV6_SADDR_RULE_PREFIX:
                ret = score->matchlen;
                break;
            default:
                ret = score->scorebits[i];
        }
        goto out;
    }

    switch (i) {
    case IPV6_SADDR_RULE_INIT:
        /* Rule 0: remember if hiscore is not ready yet */
        ret = !!score->ifa;
        break;
    case IPV6_SADDR_RULE_LOCAL:
        /* Rule 1: Prefer same address */
        ret = ipv6_addr_equal(&score->ifa->addr.in6, dst->addr);
        break;
    case IPV6_SADDR_RULE_SCOPE:
        /* Rule 2: Prefer appropriate scope */
        ret = __ipv6_addr_src_scope(score->addr_type);
        if (ret >= dst->scope)
            ret = -ret;
        else
            ret -= 128;
        score->scopedist = ret;
        break;
    case IPV6_SADDR_RULE_PREFERRED:
        /* Rule 3: Avoid deprecated and optimistic addresses */
        ret = ipv6_saddr_preferred(score->addr_type) ||
              !(score->ifa->flags & (IFA_F_DEPRECATED|IFA_F_OPTIMISTIC));
        break;
    case IPV6_SADDR_RULE_OIF:
        /* Rule 5: Prefer outgoing interface */
        ret = (!dst->idev || dst->idev == score->ifa->idev);
        break;
    case IPV6_SADDR_RULE_ORCHID:
        /* Rule 8-: Prefer ORCHID vs ORCHID or
         * non-ORCHID vs non-ORCHID
         */
        ret = !(ipv6_addr_orchid(&score->ifa->addr.in6) ^
            ipv6_addr_orchid(dst->addr));
        break;
    case IPV6_SADDR_RULE_PREFIX:
        /* Rule 8: Use longest matching prefix */
        score->matchlen = ret = ipv6_addr_diff(&score->ifa->addr.in6,
                                dst->addr);
        break;
    default:
        ret = 0;
    }

    if (ret)
        score->scorebits[i] = 1;
    score->rule = i;

out:
    return ret;
}

/* call me by lock */
static inline int ipv6_addr_select(struct inet_device *idev,
                                   const union inet_addr *daddr,
                                   union inet_addr *saddr)
{
    struct ipv6_saddr_score scores[2];
    struct ipv6_saddr_score *score = &scores[0], *hiscore = &scores[1];
    struct ipv6_saddr_dst dst;
    int dst_type;
    struct inet_ifaddr *ifa;
    int i;
    lcoreid_t cid = rte_lcore_id();

    dst_type  = __ipv6_addr_type(&daddr->in6);
    dst.addr  = &daddr->in6;
    dst.idev  = idev;
    dst.scope = __ipv6_addr_src_scope(dst_type);

    hiscore->rule = -1;
    hiscore->ifa  = NULL;

    list_for_each_entry(ifa, &idev->ifa_list[cid], d_list) {
        if (ifa->af != AF_INET6)
            continue;

        if (ifa->flags & IFA_F_TENTATIVE)
            continue;

        score->ifa = ifa;
        score->addr_type = __ipv6_addr_type(&score->ifa->addr.in6);

        if (unlikely(score->addr_type == IPV6_ADDR_ANY ||
                     score->addr_type & IPV6_ADDR_MULTICAST))
            continue;

        score->rule = -1;
        memset(score->scorebits, 0, sizeof(bool) * IPV6_SADDR_RULE_MAX);

        for (i = 0; i < IPV6_SADDR_RULE_MAX; i++) {
            int minihiscore, miniscore;

            minihiscore = ipv6_get_saddr_eval(hiscore, &dst, i);
            miniscore = ipv6_get_saddr_eval(score, &dst, i);

            if (minihiscore > miniscore) {
                break;
            } else if (minihiscore < miniscore) {
                struct ipv6_saddr_score *temscore;
                temscore = score;
                score = hiscore;
                hiscore = temscore;
                break;
            }
        }
    }

    if (!hiscore->ifa)
        return EDPVS_NOTEXIST;

    *saddr = hiscore->ifa->addr;
    return EDPVS_OK;
}
#endif

#endif /* __LINUX_IPV6_H__ */
