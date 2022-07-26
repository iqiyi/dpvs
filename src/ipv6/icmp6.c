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

/* just for testing IPv6, not real ICMPv6 implementation. */
#include <assert.h>
#include "ipv6.h"
#include "conf/common.h"
#include "icmp6.h"
#include "ndisc.h"

#define ICMP6
#define RTE_LOGTYPE_ICMP6    RTE_LOGTYPE_USER1

#ifdef CONFIG_DPVS_ICMP_DEBUG
static void icmp6_dump_hdr(const struct rte_mbuf *mbuf)
{
    struct icmp6_hdr *ich = rte_pktmbuf_mtod(mbuf, struct icmp6_hdr *);
    lcoreid_t lcore = rte_lcore_id();

    fprintf(stderr, "lcore %d port %d icmp type %u code %u\n",
            lcore, mbuf->port, ich->icmp6_type, ich->icmp6_code);

    return;
}
#endif

uint16_t icmp6_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich)
{
    uint32_t csum, l4_len;
    struct ip6_hdr hdr;

    /* must be linear !! */
    l4_len = ntohs(iph->ip6_plen);
    if ((void *)ich != (void *)(iph + 1))
        l4_len -= (void *)ich - (void *)(iph+1);

    memset(&hdr, 0, sizeof(struct ip6_hdr));
    hdr.ip6_nxt     = IPPROTO_ICMPV6;
    hdr.ip6_plen    = htons(l4_len);
    hdr.ip6_src     = iph->ip6_src;
    hdr.ip6_dst     = iph->ip6_dst;

    csum = rte_raw_cksum(ich, l4_len);
    csum += rte_ipv6_phdr_cksum((struct rte_ipv6_hdr *)&hdr, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0)
        csum = 0xffff;

    return csum;
}

void icmp6_send_csum(struct ip6_hdr *shdr, struct icmp6_hdr *ich)
{
    uint32_t csum, l4_len;

    ich->icmp6_cksum = 0;

    l4_len = ntohs(shdr->ip6_plen);

    csum = rte_raw_cksum(ich, l4_len);
    csum += rte_ipv6_phdr_cksum((struct rte_ipv6_hdr *)shdr, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0)
        csum = 0xffff;

    ich->icmp6_cksum = csum;
}

/*
 *  copy from kernel
 *  an inline helper for the "simple" if statement below
 *  checks if parameter problem report is caused by an
 *  unrecognized IPv6 option that has the Option Type
 *  highest-order two bits set to 10
 */

static bool icmp6_opt_unrec(struct rte_mbuf *imbuf, uint32_t offset)
{
    uint8_t *op, optval;

    op = mbuf_header_pointer(imbuf, offset, sizeof(optval), &optval);
    if (!op)
        return true;
    return (*op & 0xC0) == 0x80;
}

/*
 * Figure out, may we reply to this packet with icmp error.
 *
 * We do not reply, if:
 *  - it was icmp error message.
 *  - it is truncated, so that it is known, that protocol is ICMPV6
 *    (i.e. in the middle of some exthdr)
 *
 *  --ANK (980726)
 */

static int icmp6_is_ineligible(struct rte_mbuf *imbuf)
{
    int ptr = sizeof(ip6_hdr);
    __u8 nexthdr = ip6_hdr(imbuf)->ip6_nxt;

    if (mbuf_may_pull(imbuf, ptr) != 0) {
        return 1;
    }

    ptr = ip6_skip_exthdr(imbuf, ptr, &nexthdr);
    if (ptr < 0)
        return 0;

    if (nexthdr == IPPROTO_ICMPV6) {
        __u8 _type, *tp;
        tp = mbuf_header_pointer(imbuf,
                ptr + offsetof(struct icmp6_hdr, icmp6_type),
                sizeof(_type), &_type);
        if (tp == NULL ||
            !(*tp & ICMP6_INFOMSG_MASK))
            return 1;
    }
    return 0;
}

/* @imbuf is input (original) IP packet to trigger ICMP. */
void icmp6_send(struct rte_mbuf *imbuf, int type, int code, uint32_t info)
{
    struct ip6_hdr *iph = ip6_hdr(imbuf);
    eth_type_t etype = imbuf->packet_type; /* FIXME: use other field ? */
    struct in6_addr *saddr = NULL;
    struct ip6_hdr shdr;                   /* IPv6 header for sending packet */
    struct rte_mbuf *mbuf;
    struct icmp6_hdr *ich;
    struct flow6 fl6;
    struct inet_ifaddr *ifa;
    int room, err;
    int addr_type = 0;

    ifa = inet_addr_ifa_get(AF_INET6, netif_port_get(imbuf->port),
                           (union inet_addr *)&iph->ip6_dst);
    if (ifa) {
        saddr = &iph->ip6_dst;
        inet_addr_ifa_put(ifa);
    }

    addr_type = ipv6_addr_type(&iph->ip6_dst);

    /*
     * when the original ipv6 dst is l2/l3 mcast, just deal ICMP6_PACKET_TOO_BIG and
     * ICMP6_PARAM_PROB's unrecognize IPv6 option.
     */
    if (addr_type & IPV6_ADDR_MULTICAST ||  etype != ETH_PKT_HOST) {
        if (type != ICMP6_PACKET_TOO_BIG &&
            !(type == ICMP6_PARAM_PROB &&
              code == ICMP6_PARAMPROB_OPTION &&
              (icmp6_opt_unrec(imbuf, info)))) {

                RTE_LOG(DEBUG, ICMP6,
                    "%s: l2 broadcast or l3 multicast don't support the error.\n",
                     __func__);
            return;
        }
        saddr = NULL;
    }

    addr_type = ipv6_addr_type(&iph->ip6_src);
    /*
     *  Must not send error if the source does not uniquely
     *  identify a single node (RFC2463 Section 2.4).
     *  We check unspecified / multicast addresses here,
     *  and anycast addresses will be checked later.
     */
    if ((addr_type == IPV6_ADDR_ANY) || (addr_type & IPV6_ADDR_MULTICAST)) {
        RTE_LOG(DEBUG, ICMP6, "icmpv6_send: addr_any/mcast source\n");
        return;
    }

    /*
     *  In icmp6_send, never answer to a ICMP packet except the type of ICMP6_INFOMSG_MASK.
     */
    if (icmp6_is_ineligible(imbuf)) {
        RTE_LOG(DEBUG, ICMP6, "icmpv6_send: no reply to icmp error\n");
        return;
    }

    memset(&shdr, 0, sizeof(struct ip6_hdr));
    memset(&fl6, 0, sizeof(fl6));
    shdr.ip6_nxt = IPPROTO_ICMPV6;
    shdr.ip6_dst = fl6.fl6_daddr = iph->ip6_src;

    fl6.fl6_proto = IPPROTO_ICMPV6;
    fl6.fl6_oif = netif_port_get(imbuf->port);
    if (saddr) {
        shdr.ip6_src = fl6.fl6_saddr = *saddr;
    } else {
        inet_addr_select(AF_INET6, fl6.fl6_oif,
                         (union inet_addr *)&fl6.fl6_daddr, fl6.fl6_scope,
                         (union inet_addr *)&fl6.fl6_saddr);
        shdr.ip6_src = fl6.fl6_saddr;
    }

    mbuf = rte_pktmbuf_alloc(fl6.fl6_oif->mbuf_pool);
    if (!mbuf) {
        RTE_LOG(DEBUG, ICMP6, "%s: no memory.\n", __func__);
        return;
    }
    mbuf_userdata_reset(mbuf);
    assert(rte_pktmbuf_headroom(mbuf) >= 128); /* for L2/L3 */
    ich = (struct icmp6_hdr*)rte_pktmbuf_append(mbuf, sizeof(struct icmp6_hdr));;
    if (!ich) {
        RTE_LOG(DEBUG, ICMP6, "%s: no room in mbuf.\n", __func__);
        rte_pktmbuf_free(mbuf);
        return;
    }
    ich->icmp6_type = type;
    ich->icmp6_code = code;
    ich->icmp6_pptr = htonl(info);  //use icmp6_pptr for store

    /* copy as much as we can without exceeding min-MTU */
    room = min_t(int, fl6.fl6_oif->mtu, IPV6_MIN_MTU);
    room -= sizeof(struct ip6_hdr);
    room -= sizeof(struct icmp6_hdr);
    room = min_t(int, imbuf->data_len, room);

    if (!rte_pktmbuf_append(mbuf, room)) {
        RTE_LOG(DEBUG, ICMP6, "%s: no room in mbuf.\n", __func__);
        rte_pktmbuf_free(mbuf);
        return;
    }

    mbuf_copy_bits(imbuf, 0, ich + 1, room);

    shdr.ip6_plen = htons(room + sizeof(struct icmp6_hdr));
    icmp6_send_csum(&shdr, ich);

    if ((err = ipv6_xmit(mbuf, &fl6)) != EDPVS_OK) {
        RTE_LOG(DEBUG, ICMP6, "%s: ipv6_xmit: %s.\n",
                __func__, dpvs_strerror(err));
    }
    return;
}

static int icmp6_echo_reply(struct rte_mbuf *mbuf, struct ip6_hdr *iph,
                            struct icmp6_hdr *ich)
{
    struct ip6_hdr shdr; /* IPv6 header for sending packet */
    uint32_t icmp_len;
    struct flow6 fl6;

    /* must be linear !! */
    icmp_len = ntohs(iph->ip6_plen);
    if ((void *)ich != (void *)(iph + 1))
        icmp_len -= (void *)ich - (void *)(iph+1);

    /* reply */
    ich->icmp6_type = ICMP6_ECHO_REPLY;

    memset(&shdr, 0, sizeof(struct ip6_hdr));
    memset(&fl6, 0, sizeof(struct flow6));

    shdr.ip6_nxt = IPPROTO_ICMPV6;
    shdr.ip6_plen = htons(icmp_len);
    shdr.ip6_dst = fl6.fl6_daddr = iph->ip6_src;

    fl6.fl6_proto = IPPROTO_ICMPV6;
    fl6.fl6_oif = netif_port_get(mbuf->port);

    if (!ipv6_addr_is_multicast(&iph->ip6_dst)) {
        shdr.ip6_src = fl6.fl6_saddr = iph->ip6_dst;
    } else {
        inet_addr_select(AF_INET6, fl6.fl6_oif,
                         (union inet_addr *)&fl6.fl6_daddr, fl6.fl6_scope,
                         (union inet_addr *)&fl6.fl6_saddr);
        shdr.ip6_src = fl6.fl6_saddr;
    }

    icmp6_send_csum(&shdr, ich);

    return ipv6_xmit(mbuf, &fl6);
}

static int icmp6_rcv(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *iph = MBUF_USERDATA(mbuf, struct ip6_hdr *, MBUF_FIELD_PROTO);
    struct icmp6_hdr *ich;

    assert(iph);

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0)
        goto drop;

    ich = rte_pktmbuf_mtod(mbuf, struct icmp6_hdr *);
    if (unlikely(!ich))
        goto drop;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
        goto drop;

    if (icmp6_csum(iph, ich) != 0xffff)
        goto drop;

#ifdef CONFIG_DPVS_ICMP_DEBUG
    icmp6_dump_hdr(mbuf);
#endif
    switch (ich->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
            return icmp6_echo_reply(mbuf, iph, ich);

        case ND_ROUTER_SOLICIT:
        case ND_ROUTER_ADVERT:
        case ND_NEIGHBOR_SOLICIT:
        case ND_NEIGHBOR_ADVERT:
        case ND_REDIRECT:
            return ndisc_rcv(mbuf, netif_port_get(mbuf->port));

        default :
            return EDPVS_KNICONTINUE;
    }

drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVPKT;
}

static struct inet6_protocol icmp6_proto = {
    .handler    = icmp6_rcv,
    .flags      = INET6_PROTO_F_FINAL,
};

int icmpv6_init(void)
{
    ipv6_register_protocol(&icmp6_proto, IPPROTO_ICMPV6);
    return 0;
}

int icmpv6_term(void)
{
    ipv6_unregister_protocol(&icmp6_proto, IPPROTO_ICMPV6);
    return 0;
}
