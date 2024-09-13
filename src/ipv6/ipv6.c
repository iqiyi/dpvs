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
/**
 * IPv6 protocol for "lite stack".
 * Linux Kernel net/ipv6/ is referred.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/ip6.h>
#include "conf/common.h"
#include "mbuf.h"
#include "inet.h"
#include "ipv6.h"
#include "route6.h"
#include "parser/parser.h"
#include "neigh.h"
#include "icmp6.h"
#include "iftraf.h"

/*
 * IPv6 inet hooks
 */
static const struct inet6_protocol *inet6_prots[INET_MAX_PROTS];
static rte_rwlock_t inet6_prot_lock;

/*
 * IPv6 configures with default values.
 */
static struct ipv6_config ip6_configs;

const struct ipv6_config *ip6_config_get(void)
{
    return &ip6_configs;
};

/*
 * IPv6 statistics
 */
static RTE_DEFINE_PER_LCORE(struct inet_stats, ip6_stats);
#define this_ip6_stats  RTE_PER_LCORE(ip6_stats)

#define IP6_INC_STATS(__f__) \
    do { \
        this_ip6_stats.__f__++; \
    } while (0)

#define IP6_DEC_STATS(__f__) \
    do { \
        this_ip6_stats.__f__--; \
    } while (0)

#define IP6_ADD_STATS(__f__, val) \
    do { \
        this_ip6_stats.__f__ += (val); \
    } while (0)

#define IP6_UPD_PO_STATS(__f__, val) \
    do { \
        this_ip6_stats.__f__##pkts ++; \
        this_ip6_stats.__f__##octets += (val); \
    } while (0)

#ifdef CONFIG_DPVS_IP_HEADER_DEBUG
static inline void ip6_show_hdr(const char *func, struct rte_mbuf *mbuf)
{
    struct ip6_hdr *hdr;
    char sbuf[64], dbuf[64];

    hdr = ip6_hdr(mbuf);

    inet_ntop(AF_INET6, &hdr->ip6_src, sbuf, sizeof(sbuf));
    inet_ntop(AF_INET6, &hdr->ip6_dst, dbuf, sizeof(dbuf));

    RTE_LOG(DEBUG, IPV6, "%s: [%d] proto %d, %s -> %s\n",
            func, rte_lcore_id(), hdr->ip6_nxt, sbuf, dbuf);
}
#endif

/*
 * internal functions
 */
static void ip6_prot_init(void)
{
    int i;

    rte_rwlock_init(&inet6_prot_lock);
    rte_rwlock_write_lock(&inet6_prot_lock);

    for (i = 0; i < NELEMS(inet6_prots); i++)
        inet6_prots[i] = NULL;

    rte_rwlock_write_unlock(&inet6_prot_lock);
}

static void ip6_forwarding_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    assert(str);

    if (strcasecmp(str, "on") == 0)
        ip6_configs.forwarding = 1;
    else if (strcasecmp(str, "off") == 0)
        ip6_configs.forwarding = 0;
    else
        RTE_LOG(WARNING, IPV6, "invalid ipv6:forwarding %s\n", str);

    RTE_LOG(INFO, IPV6, "ipv6:forwarding = %s\n", ip6_configs.forwarding ? "on" : "off");

    FREE_PTR(str);
}

static void ip6_disable_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    assert(str);

    if (strcasecmp(str, "on") == 0)
        ip6_configs.disable = 1;
    else if (strcasecmp(str, "off") == 0)
        ip6_configs.disable = 0;
    else
        RTE_LOG(WARNING, IPV6, "invalid ipv6:disable %s\n", str);

    RTE_LOG(INFO, IPV6, "ipv6:disable=%s\n", ip6_configs.disable ? "disabled" : "enabled");

    FREE_PTR(str);
}

static void ip6_addr_gen_mode_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    assert(str);

    if (!strcasecmp(str, "eui64"))
        ip6_configs.addr_gen_mode = IP6_ADDR_GEN_MODE_EUI64;
    else if (!strcasecmp(str, "none"))
        ip6_configs.addr_gen_mode = IP6_ADDR_GEN_MODE_NONE;
    else if (!strcasecmp(str, "stable-privacy"))
        ip6_configs.addr_gen_mode = IP6_ADDR_GEN_MODE_STABLE_PRIVACY;
    else if (!strcasecmp(str, "random"))
        ip6_configs.addr_gen_mode = IP6_ADDR_GEN_MODE_RANDOM;
    else
        RTE_LOG(WARNING, IPV6, "invalid ipv6:addr_gen_mode:%s\n", str);

    RTE_LOG(INFO, IPV6, "ipv6:addr_gen_mode=%s\n", str);

    FREE_PTR(str);
}

static void ip6_stable_secret_handler(vector_t tokens)
{
    bool valid = true;
    size_t i, len;
    char *str = set_value(tokens);

    assert(str);
    len = strlen(str);
    if (len < 32) {
        valid = false;
    } else {
        for (i = 0; i < 32; i++) {
            if (!isxdigit(str[i])) {
                valid = false;
                break;
            }
        }
    }
    if (!valid) {
        RTE_LOG(WARNING, IPV6, "invalid ipv6:stable_secret %s, "
                "a 128-bit hexadecimal string required\n", str);
        FREE_PTR(str);
        return;
    }

    if (hexstr2binary(str, 32, (uint8_t *)(&ip6_configs.secret_stable.secret), 16) == 16)
        ip6_configs.secret_stable.initialized  = true;
    else
        RTE_LOG(WARNING, IPV6, "fail to tranlate ipv6:stable_secret %s into binary\n", str);
    RTE_LOG(INFO, IPV6, "ipv6:stable_secret configured");

    FREE_PTR(str);
}

static inline void ip6_gen_mode_random_init(void)
{
    const char hex_chars[] = "0123456789abcdef";
    char *buf = (char *)(&ip6_configs.secret_random.secret);
    int i;

    for (i = 0; i < 16; i++)
        buf[i] = hex_chars[random() % 16];
    ip6_configs.secret_random.initialized = true;
}

/* refer linux:ip6_input_finish() */
static int ip6_local_in_fin(struct rte_mbuf *mbuf)
{
    uint8_t nexthdr;
    int (*handler)(struct rte_mbuf *mbuf) = NULL;
    bool is_final, have_final = false;
    const struct inet6_protocol *prot;
    struct ip6_hdr *hdr = ip6_hdr(mbuf);
    int ret = EDPVS_INVAL;

    /*
     * release route info saved in @userdata
     * and set it to IPv6 fixed header for upper layer.
     */
    if (!ipv6_addr_is_multicast(&hdr->ip6_dst)) {
        struct route6 *rt = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
        if (rt) {
            route6_put(rt);
            MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = NULL;
        }
    }

    MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO) = hdr;
    nexthdr = hdr->ip6_nxt;

    /* parse extension headers */
resubmit:
    /*
     * l3_len is not the transport header length.
     * we just borrow it to save info for each step when processing
     * fixed header and extension header.
     *
     * l3_len is initially the fix header size (ipv6_rcv),
     * and being set to ext-header size by each non-final protocol.
     */
    if (rte_pktmbuf_adj(mbuf, mbuf->l3_len) == NULL)
        goto discard;

resubmit_final:
    rte_rwlock_read_lock(&inet6_prot_lock);

    prot = inet6_prots[nexthdr];
    if (unlikely(!prot)) {
        /* no proto, kni may like it.*/
        rte_rwlock_read_unlock(&inet6_prot_lock);
        IP6_INC_STATS(inunknownprotos);
        goto kni;
    }

    is_final = (prot->flags & INET6_PROTO_F_FINAL);

    if (have_final) {
        /* final proto don't allow encap non-final */
        if (!is_final) {
            rte_rwlock_read_unlock(&inet6_prot_lock);
            goto discard;
        }
    } else if (is_final) {
        have_final = true;

        /* check mcast, if failed, kni may like it. */
        if (ipv6_addr_is_multicast(&hdr->ip6_dst) &&
            !inet_chk_mcast_addr(AF_INET6, netif_port_get(mbuf->port),
                                 (union inet_addr *)&hdr->ip6_dst,
                                 (union inet_addr *)&hdr->ip6_src)) {
            rte_rwlock_read_unlock(&inet6_prot_lock);
            goto kni;
        }
    }

    handler = prot->handler;

    /* tunnel may try lock again, need release lock */
    rte_rwlock_read_unlock(&inet6_prot_lock);

    assert(handler);
    ret = handler(mbuf);

    /*
     * 1. if return > 0, it's always "nexthdr",
     *    no matter if proto is final or not.
     * 2. if return == 0, the pkt is consumed.
     * 3. should not return < 0, or it'll be ignored.
     * 4. mbuf->l3_len must be adjusted by handler.
     */
    if (ret > 0) {
        nexthdr = ret;

        if (is_final)
            goto resubmit_final;
        else
            goto resubmit;
    } else {
        IP6_INC_STATS(indelivers);
    }

    return ret;

kni:
    return EDPVS_KNICONTINUE;

discard:
    IP6_INC_STATS(indiscards);
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVAL;
}

static int ip6_local_in(struct rte_mbuf *mbuf)
{
    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_IN, mbuf,
                     netif_port_get(mbuf->port), NULL, ip6_local_in_fin);
}

static int ip6_mc_local_in(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *iph = ip6_hdr(mbuf);

    IP6_UPD_PO_STATS(inmcast, mbuf->pkt_len);

    if (inet_chk_mcast_addr(AF_INET6, netif_port_get(mbuf->port),
                            (union inet_addr *)&iph->ip6_dst, NULL))
        return ip6_local_in(mbuf);
    else
        return EDPVS_KNICONTINUE; /* not drop */
}

static inline struct in6_addr *ip6_rt_nexthop(struct route6 *rt,
                                              struct in6_addr *daddr)
{
    if (ipv6_addr_any(&rt->rt6_gateway))
        return daddr;
    else
        return &rt->rt6_gateway;
}

static inline unsigned int ip6_mtu_forward(struct route6 *rt)
{
    if (rt->rt6_mtu)
        return rt->rt6_mtu;
    else if (rt->rt6_dev && rt->rt6_dev->mtu)
        return rt->rt6_dev->mtu;
    else
        return IPV6_MIN_MTU;
}

static int ip6_fragment(struct rte_mbuf *mbuf, uint32_t mtu,
                        int (*out)(struct rte_mbuf *))
{
    struct route6 *rt = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);

    /* TODO: */

    IP6_INC_STATS(fragfails);
    route6_put(rt);
    rte_pktmbuf_free(mbuf);
    return EDPVS_FRAG;
}

static int ip6_output_fin2(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *hdr = ip6_hdr(mbuf);
    struct route6 *rt = NULL;
    struct in6_addr *nexthop;
    struct netif_port *dev;
    int err;

    if (ipv6_addr_is_multicast(&hdr->ip6_dst)) {
        IP6_UPD_PO_STATS(outmcast, mbuf->pkt_len);

        if (IPV6_ADDR_MC_SCOPE(&hdr->ip6_dst) <= IPV6_ADDR_SCOPE_NODELOCAL) {
            IP6_INC_STATS(outdiscards);
            rte_pktmbuf_free(mbuf);
            return EDPVS_INVAL;
        }

        dev = MBUF_USERDATA(mbuf, struct netif_port *, MBUF_FIELD_ROUTE);
        /* only support linklocal! */
        nexthop = &hdr->ip6_dst;

    } else {
        rt = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
        dev = rt->rt6_dev;
        nexthop = ip6_rt_nexthop(rt, &hdr->ip6_dst);
    }
    mbuf->packet_type = RTE_ETHER_TYPE_IPV6;

    err = neigh_output(AF_INET6, (union inet_addr *)nexthop, mbuf, dev);

    if (rt)
        route6_put(rt);

    return err;
}

static int ip6_output_fin(struct rte_mbuf *mbuf)
{
    uint16_t mtu;
    struct ip6_hdr *hdr = ip6_hdr(mbuf);

    if (ipv6_addr_is_multicast(&hdr->ip6_dst))
        mtu = MBUF_USERDATA(mbuf, struct netif_port *, MBUF_FIELD_ROUTE)->mtu;
    else
        mtu = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE)->rt6_mtu;

    if (mbuf->pkt_len > mtu)
        return ip6_fragment(mbuf, mtu, ip6_output_fin2);
    else
        return ip6_output_fin2(mbuf);
}

int ip6_output(struct rte_mbuf *mbuf)
{
    struct netif_port *dev;
    struct route6 *rt = NULL;
    struct ip6_hdr *hdr = ip6_hdr(mbuf);

    if (ipv6_addr_is_multicast(&hdr->ip6_dst)) {
        dev = MBUF_USERDATA(mbuf, struct netif_port *, MBUF_FIELD_ROUTE);
    } else {
        rt = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
        dev = rt->rt6_dev;
    }

    IP6_UPD_PO_STATS(out, mbuf->pkt_len);
    mbuf->port = dev->id;

    iftraf_pkt_out(AF_INET6, mbuf, dev);
    if (unlikely(ip6_configs.disable)) {
        IP6_INC_STATS(outdiscards);
        if (rt)
            route6_put(rt);
        rte_pktmbuf_free(mbuf);
        return EDPVS_OK;
    }

    return INET_HOOK(AF_INET6, INET_HOOK_POST_ROUTING, mbuf, NULL,
                     dev, ip6_output_fin);
}

int ip6_local_out(struct rte_mbuf *mbuf)
{
    struct netif_port *dev;
    struct ip6_hdr *hdr = ip6_hdr(mbuf);

    if (ipv6_addr_is_multicast(&hdr->ip6_dst))
        dev = MBUF_USERDATA(mbuf, struct netif_port *, MBUF_FIELD_ROUTE);
    else
        dev = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE)->rt6_dev;

    return INET_HOOK(AF_INET6, INET_HOOK_LOCAL_OUT, mbuf, NULL, dev, ip6_output);
}

static int ip6_forward_fin(struct rte_mbuf *mbuf)
{
    IP6_INC_STATS(outforwdatagrams);
    IP6_ADD_STATS(outoctets, mbuf->pkt_len);

    return ip6_output(mbuf);
}

static int ip6_forward(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *hdr = ip6_hdr(mbuf);
    struct route6 *rt = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
    int addrtype;
    uint32_t mtu;

    if (!ip6_configs.forwarding)
        goto error;

    if (mbuf->packet_type != ETH_PKT_HOST)
        goto drop;

    /* not support forward multicast */
    if (ipv6_addr_is_multicast(&hdr->ip6_dst))
        goto error;

    if (hdr->ip6_hlim <= 1) {
        mbuf->port = rt->rt6_dev->id;
        icmp6_send(mbuf, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
        IP6_INC_STATS(inhdrerrors);
        rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    /* security critical */
    addrtype = ipv6_addr_type(&hdr->ip6_src);

    if (addrtype == IPV6_ADDR_ANY ||
        addrtype & (IPV6_ADDR_MULTICAST | IPV6_ADDR_LOOPBACK))
        goto error;

    if (addrtype & IPV6_ADDR_LINKLOCAL) {
        icmp6_send(mbuf, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_BEYONDSCOPE, 0);
        goto error;
    }

    /* is packet too big ? */
    mtu = ip6_mtu_forward(rt);
    if (mtu < IPV6_MIN_MTU)
        mtu = IPV6_MIN_MTU;

    if (mbuf->pkt_len > mtu) {
        mbuf->port = rt->rt6_dev->id;
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, mtu);

        IP6_INC_STATS(intoobigerrors);
        IP6_INC_STATS(fragfails);
        goto drop;
    }

    /* decrease TTL */
    hdr->ip6_hlim--;

    return INET_HOOK(AF_INET6, INET_HOOK_FORWARD, mbuf,
                     netif_port_get(mbuf->port), rt->rt6_dev, ip6_forward_fin);

error:
    IP6_INC_STATS(inaddrerrors);
drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVAL;
}

static struct route6 *ip6_route_input(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *hdr = ip6_hdr(mbuf);
    struct flow6 fl6 = {
        .fl6_iif    = netif_port_get(mbuf->port),
        .fl6_daddr  = hdr->ip6_dst,
        .fl6_saddr  = hdr->ip6_src,
        .fl6_proto  = hdr->ip6_nxt,
    };

    return route6_input(mbuf, &fl6);
}

static int ip6_rcv_fin(struct rte_mbuf *mbuf)
{
    struct route6 *rt = NULL;
    eth_type_t etype = mbuf->packet_type;
    struct ip6_hdr *iph = ip6_hdr(mbuf);

    if (ipv6_addr_type(&iph->ip6_dst) & IPV6_ADDR_MULTICAST)
        return ip6_mc_local_in(mbuf);

    rt = ip6_route_input(mbuf);
    if (!rt) {
        IP6_INC_STATS(innoroutes);
        goto kni;
    }

    /*
     * @userdata is used for route info in L3.
     * someday, we may use extended mbuf if have more L3 info
     * then route need to be saved into mbuf.
     */
    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt;

    if (rt->rt6_flags & RTF_LOCALIN) {
        return ip6_local_in(mbuf);
    } else if (rt->rt6_flags & RTF_FORWARD) {
        /* pass multi-/broad-cast to kni */
        if (etype != ETH_PKT_HOST)
            goto kni;

        return ip6_forward(mbuf);
    }

    IP6_INC_STATS(innoroutes);

    /* to kni */

kni:
    if (rt) {
        route6_put(rt);
        MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = NULL;
    }
    return EDPVS_KNICONTINUE;
}

static int ip6_rcv(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    const struct ip6_hdr *hdr;
    uint32_t pkt_len, tot_len;
    eth_type_t etype = mbuf->packet_type;

    if (unlikely(etype == ETH_PKT_OTHERHOST || !dev)) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_DROP;
    }

    IP6_UPD_PO_STATS(in, mbuf->pkt_len);
    iftraf_pkt_in(AF_INET6, mbuf, dev);

    if (unlikely(ip6_configs.disable)) {
        IP6_INC_STATS(indiscards);
        goto drop;
    }

    if (unlikely(mbuf_may_pull(mbuf, sizeof(*hdr)) != 0))
        goto err;

    hdr = ip6_hdr(mbuf);

    if (unlikely(((hdr->ip6_vfc&0xf0)>>4) != 6))
        goto err;

    /*
     * we do not have loopback dev for DPVS at all,
     * as RFC4291, loopback must be send/recv from lo dev.
     * so let's drop all pkt with loopback address.
     */
    if (ipv6_addr_loopback(&hdr->ip6_src) ||
        ipv6_addr_loopback(&hdr->ip6_dst))
        goto err;

    /*
     * RFC4291 Errata ID: 3480
     * interface-local scope is useful only for loopback transmission of
     * multicast but we do not have loopback dev.
     */
    if (ipv6_addr_is_multicast(&hdr->ip6_dst) &&
        IPV6_ADDR_MC_SCOPE(&hdr->ip6_dst) == 1)
        goto err;

    /*
     * drop unicast encapsulated in link-layer multicast/broadcast.
     * kernel is configurable, so need we ?
     */
    if (!ipv6_addr_is_multicast(&hdr->ip6_dst) &&
        (etype == ETH_PKT_BROADCAST || etype == ETH_PKT_MULTICAST))
        goto err;

    /* RFC4291 2.7 */
    if (ipv6_addr_is_multicast(&hdr->ip6_dst) &&
        IPV6_ADDR_MC_SCOPE(&hdr->ip6_dst) == 0)
        goto err;

    /*
     * RFC4291 2.7
     * source address must not be multicast.
     */
    if (ipv6_addr_is_multicast(&hdr->ip6_src))
        goto err;

    pkt_len = ntohs(hdr->ip6_plen);
    tot_len = pkt_len + sizeof(*hdr);

    /* check pkt_len, note it's zero if jumbo payload option is present. */
    if (pkt_len || hdr->ip6_nxt != NEXTHDR_HOP) {
        if (tot_len > mbuf->pkt_len) {
            IP6_INC_STATS(intruncatedpkts);
            goto drop;
        }

        if (mbuf->pkt_len > tot_len) {
            if (rte_pktmbuf_trim(mbuf, mbuf->pkt_len - tot_len) != 0)
                goto err;
        }
    }

    /*
     * now @l3_len record fix header only,
     * it may change, when parsing extension headers.
     * @userdata is used to save route info in L3.
     */
    mbuf->l3_len = sizeof(*hdr);
    MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = NULL;

    /* hop-by-hop option header */
    if (hdr->ip6_nxt == NEXTHDR_HOP) {
        if (ipv6_parse_hopopts(mbuf) != EDPVS_OK)
            goto err;
    }

#ifdef CONFIG_DPVS_IP_HEADER_DEBUG
    ip6_show_hdr(__func__, mbuf);
#endif

    return INET_HOOK(AF_INET6, INET_HOOK_PRE_ROUTING, mbuf,
                     dev, NULL, ip6_rcv_fin);

err:
    IP6_INC_STATS(inhdrerrors);
drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

static struct pkt_type ip6_pkt_type = {
    /*.type    =  */
    .func   = ip6_rcv,
    .port   = NULL,
};

/*
 * IPv6 APIs
 */
int ipv6_init(void)
{
    int err;

    ip6_prot_init();

    err = ipv6_exthdrs_init();
    if (err)
        return err;

    /* htons, cpu_to_be16 not work when struct initialization :( */
    ip6_pkt_type.type = htons(RTE_ETHER_TYPE_IPV6);

    ip6_gen_mode_random_init();

    err = netif_register_pkt(&ip6_pkt_type);
    if (err)
        goto reg_pkt_err;

    err = ipv6_ctrl_init();
    if (err)
        goto ctrl_err;

    return EDPVS_OK;

reg_pkt_err:
    ipv6_exthdrs_term();
ctrl_err:
    netif_unregister_pkt(&ip6_pkt_type);

    return err;
}

int ipv6_term(void)
{
    int err;

    err = ipv6_ctrl_term();
    if (err)
        return err;

    err = netif_unregister_pkt(&ip6_pkt_type);
    if (err)
        return err;

    ipv6_exthdrs_term();

    return EDPVS_OK;
}

int ipv6_xmit(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    struct route6 *rt = NULL;
    struct ip6_hdr *hdr;
    struct netif_port *dev;

    if (unlikely(!mbuf || !fl6 || ipv6_addr_any(&fl6->fl6_daddr))) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    /* TODO: to support jumbo packet */
    if (mbuf->pkt_len > IPV6_MAXPLEN) {
        IP6_INC_STATS(outdiscards);
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROOM;
    }

    if (unlikely(ipv6_addr_is_multicast(&fl6->fl6_daddr))) {
        /* only support linklocal now */
        if (IPV6_ADDR_MC_SCOPE(&fl6->fl6_daddr)
            != IPV6_ADDR_SCOPE_LINKLOCAL) {
            IP6_INC_STATS(outnoroutes);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }
        assert(fl6->fl6_oif);
        /* use mbuf userdata type MBUF_FIELD_ROUTE for saving spaces */
        MBUF_USERDATA(mbuf, struct netif_port *, MBUF_FIELD_ROUTE) = fl6->fl6_oif;
        dev = fl6->fl6_oif;

    } else {
        /* route decision */
        rt = route6_output(mbuf, fl6);
        if (!rt) {
            IP6_INC_STATS(outnoroutes);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOROUTE;
        }
        MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt;
        dev = rt->rt6_dev;
    }

    hdr = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*hdr));
    if (unlikely(!hdr)) {
        if (rt)
            route6_put(rt);
        rte_pktmbuf_free(mbuf);
        IP6_INC_STATS(outdiscards);
        return EDPVS_NOROOM;
    }

    memset(hdr, 0, sizeof(*hdr));
    hdr->ip6_vfc    = 0x60;
    hdr->ip6_flow  |= htonl(((uint64_t)fl6->fl6_tos<<20) | \
                            (ntohl(fl6->fl6_flow)&0xfffffUL));
    hdr->ip6_plen   = htons(mbuf->pkt_len - sizeof(*hdr));
    hdr->ip6_nxt    = fl6->fl6_proto;
    hdr->ip6_hlim   = fl6->fl6_ttl ? : INET_DEF_TTL;
    hdr->ip6_src    = fl6->fl6_saddr;
    hdr->ip6_dst    = fl6->fl6_daddr;

    if (ipv6_addr_any(&hdr->ip6_src) &&
        hdr->ip6_nxt != IPPROTO_ICMPV6) {
        union inet_addr saddr;

        inet_addr_select(AF_INET6, dev, (void *)&fl6->fl6_daddr,
                         fl6->fl6_scope, &saddr);
        hdr->ip6_src = saddr.in6;
    }

    return ip6_local_out(mbuf);
}

int ipv6_register_protocol(struct inet6_protocol *prot,
                           unsigned char protocol)
{
    int err = EDPVS_OK;

    rte_rwlock_write_lock(&inet6_prot_lock);
    if (inet6_prots[protocol])
        err = EDPVS_EXIST;
    else
        inet6_prots[protocol] = prot;
    rte_rwlock_write_unlock(&inet6_prot_lock);

    return err;
}

int ipv6_unregister_protocol(struct inet6_protocol *prot,
                             unsigned char protocol)
{
    int err = EDPVS_OK;

    rte_rwlock_write_lock(&inet6_prot_lock);
    if (inet6_prots[protocol] != prot)
        err = EDPVS_NOTEXIST;
    else
        inet6_prots[protocol] = NULL;
    rte_rwlock_write_unlock(&inet6_prot_lock);

    return err;
}

int ipv6_stats_cpu(struct inet_stats *stats)
{
    if (!stats)
        return EDPVS_INVAL;

    memcpy(stats, &this_ip6_stats, sizeof(*stats));

    return EDPVS_OK;
}

/*
 * configure file
 */
void ipv6_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
    }
    /* KW_TYPE NORMAL keyword */
    ip6_configs.forwarding = 0;
    ip6_configs.disable = 0;
    ip6_configs.addr_gen_mode = IP6_ADDR_GEN_MODE_EUI64;
    ip6_configs.secret_stable.initialized = false;

    route6_keyword_value_init();
}

void install_ipv6_keywords(void)
{
    install_keyword_root("ipv6_defs", NULL);
    install_keyword("forwarding", ip6_forwarding_handler, KW_TYPE_NORMAL);
    install_keyword("disable", ip6_disable_handler, KW_TYPE_NORMAL);
    install_keyword("addr_gen_mode", ip6_addr_gen_mode_handler, KW_TYPE_NORMAL);
    install_keyword("stable_secret", ip6_stable_secret_handler, KW_TYPE_NORMAL);

    install_route6_keywords();
}

/*
 * ip6_hdrlen: get ip6 header length, including extension header length
 */
int ip6_hdrlen(const struct rte_mbuf *mbuf) {
    struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    uint8_t ip6nxt = ip6h->ip6_nxt;
    int ip6_hdrlen = ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);

    /* ip6_skip_exthdr may return -1 */
    return (ip6_hdrlen >= 0) ? ip6_hdrlen : sizeof(struct ip6_hdr);
}

/*
 * "ip6_phdr_cksum" is a upgraded version of DPDK routine "rte_ipv6_phdr_cksum"
 * to support IPv6 extension headers (RFC 2460).
 * */
uint16_t ip6_phdr_cksum(struct ip6_hdr *ip6h, uint64_t ol_flags,
        uint32_t exthdrlen, uint8_t l4_proto)
{
    uint16_t csum;
    uint8_t ip6nxt = ip6h->ip6_nxt;
    uint32_t ip6plen = ip6h->ip6_plen;
    struct in6_addr ip6dst = ip6h->ip6_dst;

    ip6h->ip6_nxt = l4_proto;

    /* length of L4 header plus L4 data */
    ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) +
            sizeof(struct ip6_hdr) - exthdrlen);

    /* ip6_dst translation for NEXTHDR_ROUTING exthdrs */
    if (unlikely(ip6nxt == NEXTHDR_ROUTING)) {
        struct ip6_rthdr0 *rh = (struct ip6_rthdr0 *)(ip6h + 1);
        if (likely(rh->ip6r0_segleft > 0))
            ip6h->ip6_dst = rh->ip6r0_addr[rh->ip6r0_segleft - 1];
    }
    /*FIXME: what if NEXTHDR_ROUTING is not the first exthdr? */

    csum = rte_ipv6_phdr_cksum((struct rte_ipv6_hdr *)ip6h, ol_flags);

    /* restore original ip6h header */
    ip6h->ip6_nxt = ip6nxt;
    ip6h->ip6_plen = ip6plen;
    if (unlikely(ip6nxt == NEXTHDR_ROUTING))
        ip6h->ip6_dst = ip6dst;

    return csum;
}

/*
 * "ip6_udptcp_cksum" is a upgraded version of DPDK routine "rte_ipv6_udptcp_cksum"
 * to support IPv6 extension headers (RFC 2460).
 * */
uint16_t ip6_udptcp_cksum(struct ip6_hdr *ip6h, const void *l4_hdr,
        uint32_t exthdrlen, uint8_t l4_proto)
{
    uint16_t csum;
    uint8_t ip6nxt = ip6h->ip6_nxt;
    uint32_t ip6plen = ip6h->ip6_plen;
    struct in6_addr ip6dst = ip6h->ip6_dst;

    ip6h->ip6_nxt = l4_proto;

    /* length of L4 header plus L4 data */
    ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) +
            sizeof(struct ip6_hdr) - exthdrlen);

    /* ip6_dst translation for NEXTHDR_ROUTING exthdrs */
    if (unlikely(ip6nxt == NEXTHDR_ROUTING)) {
        struct ip6_rthdr0 *rh = (struct ip6_rthdr0 *)(ip6h + 1);
        if (likely(rh->ip6r0_segleft > 0))
            ip6h->ip6_dst = rh->ip6r0_addr[rh->ip6r0_segleft - 1];
    }
    /*FIXME: what if NEXTHDR_ROUTING is not the first exthdr? */

    csum = rte_ipv6_udptcp_cksum((struct rte_ipv6_hdr *)ip6h, l4_hdr);

    /* restore original ip6h header */
    ip6h->ip6_nxt = ip6nxt;
    ip6h->ip6_plen = ip6plen;
    if (unlikely(ip6nxt == NEXTHDR_ROUTING))
        ip6h->ip6_dst = ip6dst;

    return csum;
}
