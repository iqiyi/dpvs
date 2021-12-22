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

/*
 * Linux Kernel net/ipv6/ndisc.c is referred.
 * Wang Qing <jerrywang@qiyi.com>
 */
#include <rte_ether.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <linux/if_addr.h>

#include "conf/neigh.h"
#include "neigh.h"
#include "conf/common.h"
#include "ipv6.h"
#include "ndisc.h"
#include "icmp6.h"

#define NDISC_OPT_SPACE(len) (((len)+2+7)&~7)

struct nd_msg {
    struct icmp6_hdr    icmph;
    struct in6_addr    target;
    uint8_t            opt[0];
};

/*
 * netinet/icmp6.h define ND_OPT by '#define', ND_OPT_MAX is not defined.
 * kernel define ND_OPT_ARRAY_MAX by enum, just define 256 here.
 */
#define __ND_OPT_ARRAY_MAX 256

struct ndisc_options {
    struct nd_opt_hdr *nd_opt_array[__ND_OPT_ARRAY_MAX];
    struct nd_opt_hdr *nd_useropts;
    struct nd_opt_hdr *nd_useropts_end;
};

#define nd_opts_src_lladdr      nd_opt_array[ND_OPT_SOURCE_LINKADDR]
#define nd_opts_tgt_lladdr      nd_opt_array[ND_OPT_TARGET_LINKADDR]
#define nd_opts_pi              nd_opt_array[ND_OPT_PREFIX_INFORMATION]
#define nd_opts_pi_end          nd_opt_array[0]  //__ND_OPT_PREFIX_INFO_END
#define nd_opts_rh              nd_opt_array[ND_OPT_REDIRECTED_HEADER]
#define nd_opts_mtu             nd_opt_array[ND_OPT_MTU]

#ifdef CONFIG_NDISC_DEBUG
static inline void ndisc_show_addr(const char *func,
                                   const struct in6_addr *saddr,
                                   const struct in6_addr *daddr)
{
    char sbuf[64], dbuf[64];

    RTE_LOG(DEBUG, NEIGHBOUR, "%s: [%d] %s -> %s\n",
            func, rte_lcore_id(),
            saddr ? inet_ntop(AF_INET6, saddr, sbuf, sizeof(sbuf)) : "::",
            daddr ? inet_ntop(AF_INET6, daddr, dbuf, sizeof(dbuf)) : "::");
}

static inline void ndisc_show_target(const char *func,
                                     const struct in6_addr *addr,
                                     const uint8_t *lladdr,
                                     const struct netif_port *dev)
{
    char buf[64];

    if (!addr) {
        return;
    }

    inet_ntop(AF_INET6, addr, buf, sizeof(buf));

    if (lladdr) {
        RTE_LOG(DEBUG, NEIGHBOUR,
                "%s: [%d] address: %s, "
                "lladdr %02x:%02x:%02x:%02x:%02x:%02x, dev %s\n",
                __func__, rte_lcore_id(), buf,
                lladdr[0], lladdr[1], lladdr[2],
                lladdr[3], lladdr[4], lladdr[5], dev->name);
    } else {
        RTE_LOG(DEBUG, NEIGHBOUR,
                "%s: [%d] address: %s, dev %s\n",
                __func__, rte_lcore_id(), buf, dev->name);
    }
}
#endif

/* ipv6 neighbour */
static inline uint8_t *ndisc_opt_addr_data(struct nd_opt_hdr *p,
                                           struct netif_port *dev)
{
    uint8_t *lladdr = (uint8_t *)(p + 1);
    int lladdrlen = p->nd_opt_len << 3;

    /* support ether_addr only */
    if (lladdrlen != NDISC_OPT_SPACE(sizeof(dev->addr)))
        return NULL;

    return lladdr;
}

static uint8_t *ndisc_fill_addr_option(struct rte_mbuf *mbuf,
                                       uint8_t *opt, int type,
                                       void *data, int data_len)
{
    int space = NDISC_OPT_SPACE(data_len);

    opt[0] = type;
    opt[1] = space >> 3;

    opt = (uint8_t *)rte_pktmbuf_append(mbuf, data_len + 2);

    memcpy(opt + 2, data, data_len);
    data_len += 2;
    opt += data_len;

    /* clear space(after option) left */
    if ((space -= data_len) > 0)
        memset(opt, 0 ,space);

    return opt + space;
}

static struct ndisc_options *ndisc_parse_options(uint8_t *opt, int opt_len,
                                                struct ndisc_options *ndopts)
{
    struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)opt;

    if (!nd_opt || opt_len < 0 || !ndopts)
        return NULL;

    memset(ndopts, 0, sizeof(*ndopts));

    while (opt_len) {
        int l;

        if (opt_len < sizeof(struct nd_opt_hdr))
            return NULL;
        l = nd_opt->nd_opt_len << 3;

        if (opt_len < l || l == 0)
            return NULL;

        switch (nd_opt->nd_opt_type) {
        case ND_OPT_SOURCE_LINKADDR:
        case ND_OPT_TARGET_LINKADDR:
        case ND_OPT_MTU:
        case ND_OPT_REDIRECTED_HEADER:
            if (ndopts->nd_opt_array[nd_opt->nd_opt_type]) {
                RTE_LOG(ERR, NEIGHBOUR, "[%s] duplicated ND6 option found: \
                                 type=%d\n", __func__, nd_opt->nd_opt_type);
            } else {
                ndopts->nd_opt_array[nd_opt->nd_opt_type] = nd_opt;
            }
            break;

        case ND_OPT_PREFIX_INFORMATION:
            ndopts->nd_opts_pi_end = nd_opt;
            if (!ndopts->nd_opt_array[nd_opt->nd_opt_type])
                ndopts->nd_opt_array[nd_opt->nd_opt_type] = nd_opt;
            break;

        default:
            RTE_LOG(ERR, NEIGHBOUR, "[%s] unsupported option ignored: type=%d, \
                   len=%d\n", __func__, nd_opt->nd_opt_type, nd_opt->nd_opt_len);
        }

        opt_len -= l;
        nd_opt = ((void *)nd_opt) + l;
    }

    return ndopts;
}

static struct rte_mbuf *ndisc_build_mbuf(struct netif_port *dev,
                                         const struct in6_addr *daddr,
                                         const struct in6_addr *saddr,
                                         const struct icmp6_hdr *icmp6h,
                                         const struct in6_addr *target,
                                         int llinfo)
{
    struct rte_mbuf *mbuf;
    struct icmp6_hdr *icmp6hdr;
    struct rte_ipv6_hdr iph;
    int len;
    uint8_t *opt;

    len = sizeof(*icmp6h) + (target ? sizeof(*target) : 0);

    if (llinfo)
        len += NDISC_OPT_SPACE(sizeof(dev->addr));

    mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);
    if (!mbuf) {
        RTE_LOG(ERR, NEIGHBOUR, "mbuf_pool alloc failed\n");
        return NULL;
    }
    mbuf_userdata_reset(mbuf);

    icmp6hdr = (struct icmp6_hdr *)rte_pktmbuf_append(mbuf, sizeof(*icmp6h));
    rte_memcpy(icmp6hdr, icmp6h, sizeof(*icmp6h));

    opt = rte_pktmbuf_mtod_offset(mbuf, uint8_t *, sizeof(*icmp6h));

    if (target) {
        opt = (uint8_t *)rte_pktmbuf_append(mbuf, sizeof(*target));
        rte_memcpy((struct in6_addr *)opt, target, sizeof(*target));
        opt += sizeof(*target);
    }

    if (llinfo)
        ndisc_fill_addr_option(mbuf, opt, llinfo, &dev->addr, sizeof(dev->addr));

    /* checksum */
    iph.payload_len = htons(len);
    iph.proto       = IPPROTO_ICMPV6;
    rte_memcpy(&iph.src_addr, saddr, sizeof(*saddr));
    rte_memcpy(&iph.dst_addr, daddr, sizeof(*daddr));
    icmp6hdr->icmp6_cksum = 0;
    icmp6hdr->icmp6_cksum = rte_ipv6_udptcp_cksum(&iph, icmp6hdr);

    return mbuf;
}

static void ndisc_send_na(struct netif_port *dev,
                          const struct in6_addr *daddr,
                          const struct in6_addr *solicited_addr,
                          int solicited, int override, int inc_opt)
{
    struct inet_ifaddr *ifa;
    const struct in6_addr *src_addr;
    struct rte_mbuf *mbuf;
    struct icmp6_hdr icmp6h;
    struct flow6 fl6;

    /* solicited_addr is not always src_addr, just not support now */
    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)solicited_addr);
    if (ifa) {
        src_addr = solicited_addr;
        inet_addr_ifa_put(ifa);
    } else {
        RTE_LOG(ERR, NEIGHBOUR, "Find no src addr to send na\n");
        return;
    }

    memset(&icmp6h, 0, sizeof(icmp6h));
    icmp6h.icmp6_type = ND_NEIGHBOR_ADVERT;
    if (solicited)
        icmp6h.icmp6_pptr |= ND_NA_FLAG_SOLICITED;
    if (override)
        icmp6h.icmp6_pptr |= ND_NA_FLAG_OVERRIDE;

    /*ndisc*/
    mbuf = ndisc_build_mbuf(dev, daddr, src_addr, &icmp6h, solicited_addr,
                                     inc_opt ? ND_OPT_TARGET_LINKADDR : 0);
    if (!mbuf)
        return;

    memset(&fl6, 0, sizeof(fl6));
    fl6.fl6_oif   = dev;
    fl6.fl6_saddr = *src_addr;
    fl6.fl6_daddr = *daddr;
    fl6.fl6_proto = IPPROTO_ICMPV6;
    fl6.fl6_ttl   = 255;

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_addr(__func__, src_addr, daddr);
#endif

    ipv6_xmit(mbuf, &fl6);
}

/* saddr can be 0 in ns for dad in addrconf_dad_timer */
static void ndisc_send_ns(struct netif_port *dev,
                          const struct in6_addr *solicit,
                          const struct in6_addr *daddr,
                          const struct in6_addr *saddr)
{
    struct rte_mbuf *mbuf;
    struct icmp6_hdr icmp6h = {
        .icmp6_type = ND_NEIGHBOR_SOLICIT,
    };
    struct flow6 fl6;

    if (saddr == NULL) {
        /* in route module */
        RTE_LOG(ERR, NEIGHBOUR, "Find no src addr to send na,\
                                          not support yet\n");
        return;
    }

    memset(&icmp6h, 0, sizeof(icmp6h));
    icmp6h.icmp6_type = ND_NEIGHBOR_SOLICIT;

    mbuf = ndisc_build_mbuf(dev, daddr, saddr, &icmp6h, solicit,
              !ipv6_addr_any(saddr) ? ND_OPT_SOURCE_LINKADDR : 0);
    if (!mbuf)
        return;

    memset(&fl6, 0, sizeof(fl6));
    fl6.fl6_oif   = dev;
    fl6.fl6_saddr = *saddr;
    fl6.fl6_daddr = *daddr;
    fl6.fl6_proto = IPPROTO_ICMPV6;
    fl6.fl6_ttl   = 255;

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_addr(__func__, saddr, daddr);
#endif

    ipv6_xmit(mbuf, &fl6);
}

void ndisc_send_dad(struct netif_port *dev,
                    const struct in6_addr* solicit)
{
    struct in6_addr mcaddr;
    addrconf_addr_solict_mult(solicit, &mcaddr);
    ndisc_send_ns(dev, solicit, &mcaddr, &in6addr_any);
}

void ndisc_solicit(struct neighbour_entry *neigh,
                   const struct in6_addr *saddr)
{
    struct in6_addr mcaddr;
    struct netif_port *dev = neigh->port;
    struct in6_addr *target = &neigh->ip_addr.in6;

    addrconf_addr_solict_mult(target, &mcaddr);
    ndisc_send_ns(dev, target, &mcaddr, saddr);
}

static int ndisc_recv_ns(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    uint8_t *lladdr = NULL;
    struct ndisc_options ndopts;
    struct neighbour_entry *neigh;
    struct inet_ifaddr *ifa;
    int inc = 0;
    int hashkey = 0;
    uint32_t ndoptlen = 0;

    struct in6_addr *saddr = &MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO)->ip6_src;
    struct in6_addr *daddr = &MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO)->ip6_dst;

    struct nd_msg *msg = rte_pktmbuf_mtod(mbuf, struct nd_msg *);
    int dad = ipv6_addr_any(saddr);

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_addr(__func__, saddr, daddr);
#endif

    if (mbuf_may_pull(mbuf, sizeof(struct nd_msg)))
        return EDPVS_DROP;

    ndoptlen = mbuf->data_len - offsetof(struct nd_msg, opt);

    if (ipv6_addr_is_multicast(&msg->target)) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: muticast target address\n", __func__);
        return EDPVS_DROP;
    }

    if (dad && !ipv6_addr_is_solict_mult(daddr)) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: bad DAD packet\n", __func__);
        return EDPVS_DROP;
    }

    if (!ndisc_parse_options(msg->opt, ndoptlen, &ndopts)) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: invalid ND packet\n", __func__);
        return EDPVS_DROP;
    }

    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)&msg->target);
    if (!ifa) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] RECVNs: dpvs is not the target!\n", __func__);
        return EDPVS_KNICONTINUE;
    }

    if (ndopts.nd_opts_src_lladdr) {
        lladdr = ndisc_opt_addr_data(ndopts.nd_opts_src_lladdr, dev);
        if (!lladdr) {
            RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: invalid link-layer address\n", __func__);
            inet_addr_ifa_put(ifa);
            return EDPVS_DROP;
        }
        /*
         * RFC2461 7.1.1:
         * IP source address should not be unspecified address in NS
         * if ther is source link-layer address option in the message
         */
        if (dad) {
            RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: bad DAD packet (link-layer address option)\n", \
                                                                             __func__);
            inet_addr_ifa_put(ifa);
            return EDPVS_DROP;
        }
    } else {
        /* ingnore mbuf without opt */
        inet_addr_ifa_put(ifa);
        return EDPVS_KNICONTINUE;
    }

    inc = ipv6_addr_is_multicast(daddr);

    /*
     * dad response src_addr should be link local, daddr should be multi ff02::1
     * optimistic addr not support
     */
    if (dad) {
        if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC)) {
            RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NS: someone try to solicit our address.\n");
            inet_ifaddr_dad_failure(ifa);
            inet_addr_ifa_put(ifa);
            return EDPVS_KNICONTINUE;
        }
        ndisc_send_na(dev, &in6addr_linklocal_allnodes, &msg->target, 0, 1, 1);
        inet_addr_ifa_put(ifa);
        return EDPVS_KNICONTINUE;
    }

    inet_addr_ifa_put(ifa);

    /* update/create neighbour */
    hashkey = neigh_hashkey(AF_INET6, (union inet_addr *)saddr, dev);
    neigh = neigh_lookup_entry(AF_INET6, (union inet_addr *)saddr, dev, hashkey);
    if (neigh && !(neigh->flag & NEIGHBOUR_STATIC)) {
        neigh_edit(neigh, (struct rte_ether_addr *)lladdr);
        neigh_entry_state_trans(neigh, 1);
        neigh_sync_core(neigh, 1, NEIGH_ENTRY);
    } else {
        neigh = neigh_add_table(AF_INET6, (union inet_addr *)saddr,
                      (struct rte_ether_addr *)lladdr, dev, hashkey, 0);
        if (!neigh){
            RTE_LOG(ERR, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
            return EDPVS_NOMEM;
        }
        neigh_entry_state_trans(neigh, 1);
        neigh_sync_core(neigh, 1, NEIGH_ENTRY);
    }
    neigh_send_mbuf_cach(neigh);

    ndisc_send_na(dev, saddr, &msg->target,
                  1, inc, inc);

    return EDPVS_KNICONTINUE;
}

static int ndisc_recv_na(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    uint8_t *lladdr = NULL;
    struct ndisc_options ndopts;
    struct neighbour_entry *neigh;
    struct inet_ifaddr *ifa;
    int hashkey;
    struct in6_addr *daddr = &MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO)->ip6_dst;
    struct nd_msg *msg = rte_pktmbuf_mtod(mbuf, struct nd_msg *);
    uint32_t ndoptlen = mbuf->data_len - offsetof(struct nd_msg, opt);

#ifdef CONFIG_NDISC_DEBUG
    struct in6_addr *saddr = &MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO)->ip6_src;
    ndisc_show_addr(__func__, saddr, daddr);
#endif

    if (mbuf_may_pull(mbuf, sizeof(struct nd_msg))) {
        RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: packet too short.\n");
        return EDPVS_DROP;
    }

    if (ipv6_addr_is_multicast(&msg->target)) {
        RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: target address is multicast.\n");
        return EDPVS_DROP;
    }

    if (ipv6_addr_is_multicast(daddr) && (msg->icmph.icmp6_pptr & ND_NA_FLAG_SOLICITED)) {
        RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: solicited NA is multicast.\n");
        return EDPVS_DROP;
    }

    if (!ndisc_parse_options(msg->opt, ndoptlen, &ndopts)) {
        RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: invalid ND option.\n");
        return EDPVS_DROP;
    }

    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)&msg->target);
    if (ifa) {
        RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: someone advertises our address.\n");
        if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_OPTIMISTIC)) {
            inet_ifaddr_dad_failure(ifa);
        }
        inet_addr_ifa_put(ifa);
        return EDPVS_KNICONTINUE;
    }

    if (ndopts.nd_opts_tgt_lladdr) {
        lladdr = ndisc_opt_addr_data(ndopts.nd_opts_tgt_lladdr, dev);
        if (!lladdr) {
            RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: invalid link-layer address length.\n");
            return EDPVS_DROP;
        }
    } else {
        /* ingnore mbuf without opt */
        return EDPVS_KNICONTINUE;
    }

#ifdef CONFIG_NDISC_DEBUG
    ndisc_show_target(__func__, &msg->target, lladdr, dev);
#endif

    /* notice: override flag ignored */
    hashkey = neigh_hashkey(AF_INET6, (union inet_addr *)&msg->target, dev);
    neigh = neigh_lookup_entry(AF_INET6, (union inet_addr *)&msg->target, dev, hashkey);
    if (neigh && !(neigh->flag & NEIGHBOUR_STATIC)) {
        neigh_edit(neigh, (struct rte_ether_addr *)lladdr);
        neigh_entry_state_trans(neigh, 1);
        neigh_sync_core(neigh, 1, NEIGH_ENTRY);
    } else {
        neigh = neigh_add_table(AF_INET6, (union inet_addr *)&msg->target,
                       (struct rte_ether_addr *)lladdr, dev, hashkey, 0);
        if (!neigh) {
           RTE_LOG(ERR, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
           return EDPVS_NOMEM;
        }
        neigh_entry_state_trans(neigh, 1);
        neigh_sync_core(neigh, 1, NEIGH_ENTRY);
    }
    neigh_send_mbuf_cach(neigh);

    return EDPVS_KNICONTINUE;
}

int ndisc_rcv(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    struct nd_msg *msg;
    int ret;
    struct ip6_hdr *ipv6_hdr = MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO);

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0) {
        ret = EDPVS_NOMEM;
        goto free;
    }

    msg = (struct nd_msg *)rte_pktmbuf_mtod(mbuf, struct nd_msg *);

    if (ipv6_hdr->ip6_hlim != 255) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] invalid hop-limit\n", __func__);
        ret = EDPVS_INVAL;
        goto free;
    }

    if (msg->icmph.icmp6_code != 0) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] invalid ICMPv6_code:%d\n", __func__,
                msg->icmph.icmp6_code);
        ret = EDPVS_INVAL;
        goto free;
    }

    switch (msg->icmph.icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
        ret = ndisc_recv_ns(mbuf, dev);
        break;

    case ND_NEIGHBOR_ADVERT:
        ret = ndisc_recv_na(mbuf, dev);
        break;

    /* not support yet */
    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
    case ND_REDIRECT:
        ret = EDPVS_KNICONTINUE;
        break;
    default:
        ret = EDPVS_KNICONTINUE;
        break;
    }

    /* ipv6 handler should consume mbuf */
    if (ret != EDPVS_KNICONTINUE)
        goto free;

    return EDPVS_KNICONTINUE;

free:
    rte_pktmbuf_free(mbuf);
    return ret;
}
