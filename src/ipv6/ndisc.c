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

/*
 * Linux Kernel net/ipv6/ndisc.c is referred.
 * Wang Qing <jerrywang@qiyi.com>
 */
#include <rte_ether.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include "conf/neigh.h"
#include "neigh.h"
#include "common.h"
#include "ipv6.h"
#include "ndisc.h"
#include "icmp6.h"

#define NDISC_OPT_SPACE(len) (((len)+2+7)&~7)

#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
                { { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
const struct in6_addr in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;

/*ipv6 neighbour*/
static inline uint8_t *ndisc_opt_addr_data(struct nd_opt_hdr *p, 
                                           struct netif_port *dev)
{
    uint8_t *lladdr = (uint8_t *)(p + 1);
    int lladdrlen = p->nd_opt_len << 3;

    /*support ether_addr only*/
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

    /*clear space(after option) left*/
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
                                         struct icmp6_hdr *icmp6h,
                                         const struct in6_addr *target, 
                                         int llinfo)
{
    struct rte_mbuf *mbuf;
    struct icmp6_hdr *icmp6hdr;
    struct ipv6_hdr iph;
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

    /*checksum*/
    iph.payload_len = htons(len);
    iph.proto       = IPPROTO_ICMPV6;
    rte_memcpy(&iph.src_addr, saddr, sizeof(*saddr));
    rte_memcpy(&iph.dst_addr, daddr, sizeof(*daddr));
    
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

    /*solicited_addr is not always src_addr, just not support now*/
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

    ipv6_xmit(mbuf, &fl6);
}

/*saddr can be 0 in ns for dad in addrconf_dad_timer*/
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
        /*in route module*/
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

    if (neigh->state == DPVS_NUD_S_PROBE || 
        neigh->state == DPVS_NUD_S_DELAY) {
        ndisc_send_ns(dev, target, target, saddr);
    } else {
        addrconf_addr_solict_mult(target, &mcaddr);
        ndisc_send_ns(dev, target, &mcaddr, saddr);
    }
}

static int ndisc_recv_ns(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    uint8_t *lladdr = NULL;
    struct ndisc_options ndopts;
    struct neighbour_entry *neigh;
    struct inet_ifaddr *ifa;
    int inc = 0;
    int hashkey = 0;

    struct in6_addr *saddr = &((struct ip6_hdr *)mbuf->userdata)->ip6_src;
    struct in6_addr *daddr = &((struct ip6_hdr *)mbuf->userdata)->ip6_dst;

    struct nd_msg *msg = rte_pktmbuf_mtod(mbuf, struct nd_msg *);
    uint32_t ndoptlen = mbuf->data_len - offsetof(struct nd_msg, opt);

    int dad = ipv6_addr_any(saddr);

    if (ipv6_addr_is_multicast(&msg->target)) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: muticast target address\n", __func__);
        return EDPVS_DROP;
    }

    if (dad && !(daddr->s6_addr32[0] == htonl(0xff020000) &&
                 daddr->s6_addr32[1] == htonl(0x00000000) &&
                 daddr->s6_addr32[2] == htonl(0x00000001) &&
                 daddr->s6_addr[12] == 0xff)) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: bad DAD packet\n", __func__);
        return EDPVS_DROP;
    }

    if (!ndisc_parse_options(msg->opt, ndoptlen, &ndopts)) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: invalid ND packet\n", __func__);
        return EDPVS_DROP;
    }

    if (ndopts.nd_opts_src_lladdr) {
        lladdr = ndisc_opt_addr_data(ndopts.nd_opts_src_lladdr, dev);
        if (!lladdr) {
            RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: invalid link-layer address\n", __func__);
            return EDPVS_DROP;
        }
        /*
         * RFC2461 7.1.1:
         * IP source address should not be unspecified address in NS
         * if ther is source link-layer address option in the message
         * */
        if (dad) {
            RTE_LOG(ERR, NEIGHBOUR, "[%s] NS: bad DAD packet (link-layer address option)\n", \
                                                                             __func__);
            return EDPVS_DROP;
        }
    }

    inc = ipv6_addr_is_multicast(daddr);

    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)&msg->target);
    if (!ifa) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] RECVNs: dpvs is not the target!\n", __func__);
        return EDPVS_DROP;
    }
    inet_addr_ifa_put(ifa);

    /* dad response src_addr should be link local, daddr should be multi ff02::1
     * optimistic addr not support
     * */
    if (dad) {
        ndisc_send_na(dev, &in6addr_linklocal_allnodes, &msg->target, 0, 1, 1);
        return EDPVS_DROP;
    }

    /*update/create neighbour*/
    hashkey = neigh_hashkey(saddr, dev);
    neigh = neigh_lookup_entry(AF_INET6, saddr, dev, hashkey);
    if (neigh && !(neigh->flag & NEIGHBOUR_STATIC)) {
        neigh_edit(neigh, (struct ether_addr *)lladdr, hashkey);
        neigh_entry_state_trans(neigh, 1);
    } else {
        neigh = neigh_add_table(AF_INET6, (union inet_addr *)saddr, 
                      (struct ether_addr *)lladdr, dev, hashkey, 0);
        if (!neigh){
            RTE_LOG(ERR, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
            return EDPVS_NOMEM;
        }
        neigh_entry_state_trans(neigh, 1);
    }
    neigh_send_mbuf_cach(neigh);
    
    ndisc_send_na(dev, saddr, &msg->target,
                  1, inc, inc);

    return EDPVS_OK;
}

static int ndisc_recv_na(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    uint8_t *lladdr = NULL;
    struct ndisc_options ndopts;
    struct neighbour_entry *neigh;
    struct inet_ifaddr *ifa;
    int hashkey;

    struct in6_addr *saddr = &((struct ip6_hdr *)mbuf->userdata)->ip6_src;
    struct in6_addr *daddr = &((struct ip6_hdr *)mbuf->userdata)->ip6_dst;

    struct nd_msg *msg = rte_pktmbuf_mtod(mbuf, struct nd_msg *);
    uint32_t ndoptlen = mbuf->data_len - offsetof(struct nd_msg, opt);

    if (mbuf->data_len < sizeof(struct nd_msg)) {
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

    if (ndopts.nd_opts_tgt_lladdr) {
        lladdr = ndisc_opt_addr_data(ndopts.nd_opts_tgt_lladdr, dev);
        if (!lladdr) {
            RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: invalid link-layer address length.\n");
            return EDPVS_DROP;
        }
    }

    ifa = inet_addr_ifa_get(AF_INET6, dev, (union inet_addr *)&msg->target);
    if (ifa) {
        /*delete?*/
        RTE_LOG(ERR, NEIGHBOUR, "ICMPv6 NA: someone advertises our address.\n");
        inet_addr_ifa_put(ifa);
        return EDPVS_DROP;
    }

    /*notice: override flag ignored*/
    hashkey = neigh_hashkey(saddr, dev);
    neigh = neigh_lookup_entry(AF_INET6, &msg->target, dev, hashkey);
    if (neigh && !(neigh->flag & NEIGHBOUR_STATIC)) {
        neigh_edit(neigh, (struct ether_addr *)lladdr, hashkey);
        neigh_entry_state_trans(neigh, 1);
    } else {
        neigh = neigh_add_table(AF_INET6, (union inet_addr *)saddr,
                       (struct ether_addr *)lladdr, dev, hashkey, 0);
        if(!neigh){
           RTE_LOG(ERR, NEIGHBOUR, "[%s] add neighbour wrong\n", __func__);
           return EDPVS_NOMEM;
        }
        neigh_entry_state_trans(neigh, 1);
    }
    neigh_send_mbuf_cach(neigh);

    return EDPVS_OK;
}

int ndisc_rcv(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    struct nd_msg *msg;
    int ret;

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0)
        return EDPVS_NOMEM;

    /*ip module must have already move ipv6 header and save it!*/
    struct ip6_hdr *ipv6_hdr = mbuf->userdata;
    msg = (struct nd_msg *)rte_pktmbuf_mtod(mbuf, struct nd_msg *);

    if (ipv6_hdr->ip6_hlim != 255) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] invalid hop-limit\n", __func__);
        return EDPVS_INVAL;
    }

    if (msg->icmph.icmp6_code != 0) {
        RTE_LOG(ERR, NEIGHBOUR, "[%s] invalid ICMPv6_code:%d\n", __func__,
                msg->icmph.icmp6_code);
        return EDPVS_INVAL;
    }

    switch (msg->icmph.icmp6_type) {
    case ND_NEIGHBOR_SOLICIT:
        ret = ndisc_recv_ns(mbuf, dev);
        break;

    case ND_NEIGHBOR_ADVERT:
        ret = ndisc_recv_na(mbuf, dev);
        break;

    /*not support yet*/
    case ND_ROUTER_SOLICIT:
    case ND_ROUTER_ADVERT:
    case ND_REDIRECT:
        ret = EDPVS_DROP;
        break;
    default:
        ret = EDPVS_DROP;
        break;
    }

    return ret;
}

