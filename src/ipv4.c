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
#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dpdk.h"
#include "netif.h"
#include "ipv4.h"
#include "ipv4_frag.h"
#include "neigh.h"
#include "icmp.h"
#include "parser/parser.h"
#include "iftraf.h"

#define IPV4
#define RTE_LOGTYPE_IPV4    RTE_LOGTYPE_USER1

#define IPV4_FORWARD_DEF  false
static bool ipv4_forward_switch = IPV4_FORWARD_DEF;

static uint32_t inet_def_ttl = INET_DEF_TTL;

static void ipv4_default_ttl_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int def_ttl;

    assert(str);
    def_ttl = atoi(str);
    if (def_ttl > 255 || def_ttl < 0) {
        RTE_LOG(WARNING, IPV4, "invalid inet_def_ttl %s, using default %d\n",
                str, INET_DEF_TTL);
        inet_def_ttl = INET_DEF_TTL;
    } else {
        RTE_LOG(INFO, IPV4, "inet_def_ttl = %d\n", def_ttl);
        inet_def_ttl = def_ttl;
    }

    FREE_PTR(str);
}

static void ipv4_forwarding_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (strcasecmp(str, "on") == 0)
        ipv4_forward_switch = true;
    else if (strcasecmp(str, "off") == 0)
        ipv4_forward_switch = false;
    else
        RTE_LOG(WARNING, IPV4, "invalid ipv4:forwarding %s\n", str);

    RTE_LOG(INFO, IPV4, "ipv4:forwarding = %s\n", ipv4_forward_switch ? "on" : "off");

    FREE_PTR(str);
}

void ipv4_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        inet_def_ttl = INET_DEF_TTL;
    }
    /* KW_TYPE_NORMAL keyword */
    ipv4_forward_switch = false;
}

void install_ipv4_keywords(void)
{
    install_keyword_root("ipv4_defs", NULL);
    install_keyword("default_ttl", ipv4_default_ttl_handler, KW_TYPE_INIT);
    install_keyword("forwarding", ipv4_forwarding_handler, KW_TYPE_NORMAL);
}

static const struct inet_protocol *inet_prots[INET_MAX_PROTS];
static rte_spinlock_t inet_prot_lock; /* to see if rwlock is better */

/* ip identification */
#define IP4_IDENTS_SZ       2048u

static rte_atomic32_t *ip4_idents;
static uint32_t ip4_id_hashrnd;

#ifdef CONFIG_DPVS_IPV4_STATS
struct ip4_stats ip4_statistics;
rte_spinlock_t ip4_stats_lock;
#endif

#ifdef CONFIG_DPVS_IP_HEADER_DEBUG
static void ip4_show_hdr(const char *func, const struct rte_mbuf *mbuf)
{
    portid_t port;
    lcoreid_t lcore;
    struct rte_ipv4_hdr *iph;
    char saddr[16], daddr[16];

    port = mbuf->port;
    iph = ip4_hdr(mbuf);
    lcore = rte_lcore_id();

    if (!inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr)))
        return;

    if (!inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr)))
        return;

    RTE_LOG(DEBUG, IPV4, "%s: [%d] port %u ipv4 hl %u tos %u tot %u "
            "id %u ttl %u prot %u src %s dst %s\n",
            func, lcore, port, RTE_IPV4_HDR_IHL_MASK & iph->version_ihl,
            iph->type_of_service, ntohs(iph->total_length),
            ntohs(iph->packet_id), iph->time_to_live,
            iph->next_proto_id, saddr, daddr);
}
#endif

int ip4_defrag(struct rte_mbuf *mbuf, int user)
{
    int err;

    IP4_INC_STATS(reasmreqds);

    err = ipv4_reassamble(mbuf);
    switch (err) {
    case EDPVS_INPROGRESS: /* collecting fragments */
        break;
    case EDPVS_OK:
        IP4_INC_STATS(reasmoks);
        break;
    default: /* error happened */
        rte_pktmbuf_free(mbuf);
        IP4_INC_STATS(reasmfails);
        break;
    }

    return err;
}

static int ipv4_local_in_fin(struct rte_mbuf *mbuf)
{
    int err, hlen;
    const struct inet_protocol *prot;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    int (*handler)(struct rte_mbuf *mbuf) = NULL;

    /* remove network header */
    hlen = ip4_hdrlen(mbuf);
    rte_pktmbuf_adj(mbuf, hlen);

    if (rt) {
        route4_put(rt);
        MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = NULL;
    }

    /*
     * give a change for upper layer to get IP header.
     * skb uses ->data, ->transport_header, ->network_header, etc.
     * but mbuf do not. Consider the length of header is variable
     * (e.g., IPv4 options), it's not make sence for every layer
     * to parse lower layer's headers.
     *
     * BTW, if netif_port_get() called too many times we can also
     * use 'extend' mbuf to save 'netif_port *dev'.
     */
    MBUF_USERDATA(mbuf, struct rte_ipv4_hdr *, MBUF_FIELD_PROTO) = iph;

    /* deliver to upper layer */
    rte_spinlock_lock(&inet_prot_lock);
    prot = inet_prots[iph->next_proto_id];
    if (prot)
        handler = prot->handler;
    rte_spinlock_unlock(&inet_prot_lock);

    if (handler) {
        err = handler(mbuf);
        IP4_INC_STATS(indelivers);
    } else {
        err = EDPVS_KNICONTINUE; /* KNI may like it, don't drop */
        IP4_INC_STATS(inunknownprotos);
    }

    return err;
}

static int ipv4_local_in(struct rte_mbuf *mbuf)
{
    int err;
    struct route_entry *rt;

    rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    if (ip4_is_frag(ip4_hdr(mbuf))) {
        if ((err = ip4_defrag(mbuf, IP_DEFRAG_LOCAL_IN)) != EDPVS_OK) {
            route4_put(rt);
            return err;
        }
    }

    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_IN, mbuf,
            netif_port_get(mbuf->port), NULL, ipv4_local_in_fin);
}

static int ipv4_output_fin2(struct rte_mbuf *mbuf)
{
    struct route_entry *rt;
    int err;
    struct in_addr nexthop;

    rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    if (rt->gw.s_addr == htonl(INADDR_ANY))
        nexthop.s_addr = ip4_hdr(mbuf)->dst_addr;
    else
        nexthop = rt->gw;

    /**
     * XXX:
     * because lacking of suitable fields in mbuf
     * (m.l3_type is only 4 bits, too short),
     * m.packet_type is used to save ether_type
     * e.g., 0x0800 for IPv4.
     * note it was used in RX path for eth_type_t.
     * really confusing.
     */
    mbuf->packet_type = RTE_ETHER_TYPE_IPV4;
    mbuf->l3_len = ip4_hdrlen(mbuf);

    err = neigh_output(AF_INET, (union inet_addr *)&nexthop, mbuf, rt->port);
    route4_put(rt);
    return err;
}

static int ipv4_output_fin(struct rte_mbuf *mbuf)
{
    struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);

    if (mbuf->pkt_len > rt->mtu)
        return ipv4_fragment(mbuf, rt->mtu, ipv4_output_fin2);

    return ipv4_output_fin2(mbuf);
}

int ipv4_output(struct rte_mbuf *mbuf)
{
    struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    assert(rt);

    IP4_UPD_PO_STATS(out, mbuf->pkt_len);
    mbuf->port = rt->port->id;
    iftraf_pkt_out(AF_INET, mbuf, rt->port);

    return INET_HOOK(AF_INET, INET_HOOK_POST_ROUTING, mbuf,
            NULL, rt->port, ipv4_output_fin);
}

static int ipv4_forward_fin(struct rte_mbuf *mbuf)
{
    IP4_INC_STATS(outforwdatagrams);
    IP4_ADD_STATS(outoctets, mbuf->pkt_len);

    return ipv4_output(mbuf);
}

static int ipv4_forward(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
    uint32_t mtu, csum;

    assert(rt && rt->port);

    if (iph->time_to_live <= 1) {
        icmp_send(mbuf, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
        IP4_INC_STATS(inhdrerrors);
        goto drop;
    }

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(RTE_IPV4_HDR_DF_FLAG))) {
        IP4_INC_STATS(fragfails);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        goto drop;
    }

    /* Drop packet if the switch is off */
    if (!ipv4_forward_switch) {
        goto drop;
    }

    /* decrease TTL and re-cal the checksum */
    csum = (uint32_t)iph->hdr_checksum;
    csum += (uint32_t)htons(0x0100);
    iph->hdr_checksum = (uint16_t)(csum + (csum >= 0xffff));
    iph->time_to_live--;

    return INET_HOOK(AF_INET, INET_HOOK_FORWARD, mbuf,
            netif_port_get(mbuf->port), rt->port, ipv4_forward_fin);

drop:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

static int ip4_rcv_options(struct rte_mbuf *mbuf)
{
    return EDPVS_OK;
}

int ipv4_rcv_fin(struct rte_mbuf *mbuf)
{
    int err;
    struct route_entry *rt = NULL;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    eth_type_t etype = mbuf->packet_type; /* FIXME: use other field ? */

    /* input route decision */
    rt = route4_input(mbuf, (struct in_addr *)&iph->dst_addr,
            (struct in_addr *)&iph->src_addr,
            iph->type_of_service, netif_port_get(mbuf->port));
    if (unlikely(!rt))
        return EDPVS_KNICONTINUE; /* KNI may like it, don't drop */

    /* input IPv4 options */
    if ((iph->version_ihl & 0xf) > 5) {
        if (ip4_rcv_options(mbuf) != EDPVS_OK) {
            err = EDPVS_INVPKT;
            goto drop;
        }
    }

    /* use extended mbuf if have more data then @rt */
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;

    if (rt->flag & RTF_LOCALIN) {
        return ipv4_local_in(mbuf);
    } else if (rt->flag & RTF_KNI) { /* destination is KNI dev's IP */
        route4_put(rt);
        return EDPVS_KNICONTINUE;
    } else if  (rt->flag & RTF_FORWARD) {
        if (etype != ETH_PKT_HOST) {
            /* multicast or broadcast */
            route4_put(rt);
            return EDPVS_KNICONTINUE; /* KNI may like it, don't drop */
        }
        return ipv4_forward(mbuf);
    } else {
        RTE_LOG(DEBUG, IPV4, "%s: input route has no dst\n", __func__);
        route4_put(rt);
        return EDPVS_KNICONTINUE; /* KNI may like it, don't drop */
    }

drop:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static int ipv4_rcv(struct rte_mbuf *mbuf, struct netif_port *port)
{
#ifdef CONFIG_ICMP_REDIRECT_CORE
        struct icmphdr *ich, _icmph;
#endif
    struct rte_ipv4_hdr *iph;
    uint16_t hlen, len;
    eth_type_t etype = mbuf->packet_type; /* FIXME: use other field ? */
    assert(mbuf);

    if (unlikely(etype == ETH_PKT_OTHERHOST || !port)) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_DROP;
    }

    IP4_UPD_PO_STATS(in, mbuf->pkt_len);
    iftraf_pkt_in(AF_INET, mbuf, port);
    if (mbuf_may_pull(mbuf, sizeof(struct rte_ipv4_hdr)) != 0)
        goto inhdr_error;

    iph = ip4_hdr(mbuf);

    hlen = ip4_hdrlen(mbuf);
    if (((iph->version_ihl) >> 4) != 4 || hlen < sizeof(struct rte_ipv4_hdr))
        goto inhdr_error;

    if (mbuf_may_pull(mbuf, hlen) != 0)
        goto inhdr_error;

    if (unlikely(!(port->flag & NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD))) {
        if (unlikely(rte_raw_cksum(iph, hlen) != 0xFFFF))
            goto csum_error;
    }

    len = ntohs(iph->total_length);
    if (mbuf->pkt_len < len) {
        IP4_INC_STATS(intruncatedpkts);
        goto drop;
    } else if (len < hlen)
        goto inhdr_error;

    /* trim padding if needed */
    if (mbuf->pkt_len > len) {
        if (rte_pktmbuf_trim(mbuf, mbuf->pkt_len - len) != 0) {
            IP4_INC_STATS(indiscards);
            goto drop;
        }
    }
    mbuf_userdata_reset(mbuf);
    mbuf->l3_len = hlen;

#ifdef CONFIG_DPVS_IP_HEADER_DEBUG
    ip4_show_hdr(__func__, mbuf);
#endif

    if (unlikely(iph->next_proto_id == IPPROTO_OSPF))
        return EDPVS_KNICONTINUE;
#ifdef CONFIG_ICMP_REDIRECT_CORE
    else if (unlikely(iph->next_proto_id == IPPROTO_ICMP)) {
        ich = mbuf_header_pointer(mbuf, hlen, sizeof(_icmph), &_icmph);
        if (unlikely(!ich))
            goto drop;
        if (ich->type == ICMP_ECHOREPLY || ich->type == ICMP_ECHO) {
            rte_pktmbuf_prepend(mbuf, (uint16_t)sizeof(struct rte_ether_hdr));
            icmp_recv_proc(mbuf);
            return EDPVS_OK;
        }
    }
#endif

    return INET_HOOK(AF_INET, INET_HOOK_PRE_ROUTING,
                     mbuf, port, NULL, ipv4_rcv_fin);

csum_error:
    IP4_INC_STATS(csumerrors);
inhdr_error:
    IP4_INC_STATS(inhdrerrors);
drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVPKT;
}

static struct pkt_type ip4_pkt_type = {
    //.type       = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4),
    .func       = ipv4_rcv,
    .port       = NULL,
};

int ipv4_init(void)
{
    int err, i;

    ip4_idents = rte_malloc(NULL, IP4_IDENTS_SZ * sizeof(*ip4_idents),
                            RTE_CACHE_LINE_SIZE);
    if (!ip4_idents)
        return EDPVS_NOMEM;
    ip4_id_hashrnd = (uint32_t)random();
    for (i = 0; i < IP4_IDENTS_SZ; i++)
        rte_atomic32_set(&ip4_idents[i], (uint32_t)random());

    rte_spinlock_init(&inet_prot_lock);
    rte_spinlock_lock(&inet_prot_lock);
    for (i = 0; i < NELEMS(inet_prots); i++)
        inet_prots[i] = NULL;
    rte_spinlock_unlock(&inet_prot_lock);

#ifdef CONFIG_DPVS_IPV4_STATS
    rte_spinlock_init(&ip4_stats_lock);
#endif

    if ((err = ipv4_frag_init()) != EDPVS_OK)
        return err;

    ip4_pkt_type.type = htons(RTE_ETHER_TYPE_IPV4);
    if ((err = netif_register_pkt(&ip4_pkt_type)) != EDPVS_OK) {
        ipv4_frag_term();
        return err;
    }

    return EDPVS_OK;
}

int ipv4_term(void)
{
    int err;

    if ((err = netif_unregister_pkt(&ip4_pkt_type)) != EDPVS_OK)
        return err;

    if ((err = ipv4_frag_term()) != EDPVS_OK)
        return err;

    rte_free(ip4_idents);
    return EDPVS_OK;
}

uint32_t ip4_select_id(struct rte_ipv4_hdr *iph)
{
    uint32_t hash, id;
    rte_atomic32_t *p_id;

    hash = rte_jhash_3words(iph->dst_addr, iph->src_addr,
            iph->next_proto_id, ip4_id_hashrnd);

    p_id = ip4_idents + hash % IP4_IDENTS_SZ;
    id = rte_atomic32_add_return(p_id, 1) - 1;
    id = htons(id);

    return id;
}

int ipv4_local_out(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt = MBUF_USERDATA(mbuf,
            struct route_entry *, MBUF_FIELD_ROUTE);

    iph->total_length = htons(mbuf->pkt_len);

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }
    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);
}

int ipv4_xmit(struct rte_mbuf *mbuf, const struct flow4 *fl4)
{
    struct route_entry *rt;
    struct rte_ipv4_hdr *iph;

    if (!mbuf || !fl4) {
        if (mbuf)
            rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    /* output route decision: out-dev, source address, ... */
    rt = route4_output(fl4);
    /* not support loopback */
    if (!rt || !(rt->flag & RTF_FORWARD)) {
        rte_pktmbuf_free(mbuf);
        IP4_INC_STATS(outnoroutes);
        return EDPVS_NOROUTE;
    }
    MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = (void *)rt;

    iph = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
    if (!iph) {
        rte_pktmbuf_free(mbuf);
        route4_put(rt);
        IP4_INC_STATS(outdiscards);
        return EDPVS_INVAL;
    }

    /* build the IP header */
    iph->version_ihl = ((4 << 4) | 5);
    iph->type_of_service = fl4->fl4_tos;
    iph->fragment_offset = 0;
    iph->time_to_live = fl4->fl4_ttl ? fl4->fl4_ttl : INET_DEF_TTL;
    iph->next_proto_id = fl4->fl4_proto;
    iph->src_addr = fl4->fl4_saddr.s_addr; /* route will not fill fl4.saddr */
    iph->dst_addr = fl4->fl4_daddr.s_addr;
    iph->packet_id = ip4_select_id(iph);

    if (iph->src_addr == htonl(INADDR_ANY)) {
        union inet_addr saddr;

        inet_addr_select(AF_INET, rt->port, (union inet_addr *)&fl4->fl4_daddr,
                         fl4->fl4_scope, &saddr);
        iph->src_addr = saddr.in.s_addr;
    }

    return ipv4_local_out(mbuf);
}

int ipv4_register_protocol(struct inet_protocol *prot,
        unsigned char protocol)
{
    int err = EDPVS_OK;

    rte_spinlock_lock(&inet_prot_lock);
    if (inet_prots[protocol])
        err = EDPVS_EXIST;
    else
        inet_prots[protocol] = prot;
    rte_spinlock_unlock(&inet_prot_lock);

    return err;
}

int ipv4_unregister_protocol(struct inet_protocol *prot,
        unsigned char protocol)
{
    int err = EDPVS_OK;

    rte_spinlock_lock(&inet_prot_lock);
    if (inet_prots[protocol] != prot)
        err = EDPVS_NOTEXIST;
    else
        inet_prots[protocol] = NULL;
    rte_spinlock_unlock(&inet_prot_lock);

    return err;
}
