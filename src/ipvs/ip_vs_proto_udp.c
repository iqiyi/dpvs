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
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "conf/common.h"
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route6.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_udp.h"
#include "ipvs/quic.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"
#include "ipvs/blklst.h"
#include "ipvs/whtlst.h"
#include "ipvs/redirect.h"
#include "ipvs/proxy_proto.h"
#include "parser/parser.h"
#include "uoa.h"
#include "neigh.h"

#define UOA_DEF_MAX_TRAIL   3

enum uoa_state {
    UOA_S_SENDING,
    UOA_S_DONE,
};

enum uoa_mode {
    UOA_M_OPP,      /* priave "option-protocol" (IPPROTO_OPT) with UOA */
    UOA_M_IPO,      /* add UOA as IPv4 Option field */
};

struct conn_uoa {
    enum uoa_state  state;
    uint8_t         sent;
    uint8_t         acked;
};

static int g_uoa_max_trail = UOA_DEF_MAX_TRAIL; /* zero to disable UOA */
static int g_uoa_mode = UOA_M_OPP; /* by default */

int g_defence_udp_drop = 0;

static int udp_timeouts[DPVS_UDP_S_LAST + 1] = {
    [DPVS_UDP_S_NONE]   = 2,
    [DPVS_UDP_S_ONEWAY] = 300,
    [DPVS_UDP_S_NORMAL] = 300,
    [DPVS_UDP_S_LAST]   = 2,
};

inline void udp4_send_csum(struct rte_ipv4_hdr *iph, struct rte_udp_hdr *uh)
{
    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph, uh);
}

inline void udp6_send_csum(struct rte_ipv6_hdr *iph, struct rte_udp_hdr *uh)
{
    uh->dgram_cksum = 0;
    uh->dgram_cksum = ip6_udptcp_cksum((struct ip6_hdr *)iph, (struct udphdr *)uh,
            (void *)uh - (void *)iph, IPPROTO_UDP);
}

int udp_send_csum(int af, int iphdrlen, struct rte_udp_hdr *uh,
        const struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
        const struct opphdr *opp, struct netif_port *dev)
{
    /* leverage HW TX UDP csum offload if possible */
    struct netif_port *select_dev = NULL;

    if (AF_INET6 == af) {
        /* UDP checksum is mandatory for IPv6.[RFC 2460] */
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        if (unlikely(opp != NULL)) {
            udp6_send_csum((struct rte_ipv6_hdr*)ip6h, uh);
        } else {
            struct route6 *rt6 = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
            if (rt6 && rt6->rt6_dev)
                select_dev = rt6->rt6_dev;
            else if (dev)
                select_dev = dev;
            else if (conn->out_dev)
                select_dev = conn->out_dev;
            if (likely(select_dev && (select_dev->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD))) {
                mbuf->l3_len = iphdrlen;
                mbuf->l4_len = sizeof(struct rte_udp_hdr);
                mbuf->ol_flags |= (PKT_TX_UDP_CKSUM | PKT_TX_IPV6);
                uh->dgram_cksum = ip6_phdr_cksum(ip6h, mbuf->ol_flags,
                        iphdrlen, IPPROTO_UDP);
            } else {
                if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                    return EDPVS_INVPKT;
                udp6_send_csum((struct rte_ipv6_hdr*)ip6h, uh);
            }
        }
    } else { /* AF_INET */
        /* UDP checksum is not mandatory for IPv4. */
        struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
        if (unlikely(opp != NULL)) {
            /*
             * XXX: UDP pseudo header need UDP length, but the common helper function
             * rte_ipv4_udptcp_cksum() use (IP.tot_len - IP.header_len), it's not
             * correct if OPP header insterted between IP header and UDP header.
             * We can modify the function, or change IP.tot_len before use
             * rte_ipv4_udptcp_cksum() and restore it after.
             *
             * However, UDP checksum is not mandatory, to make things easier, when OPP
             * header exist, we just not calc UDP checksum.
             */
            uh->dgram_cksum = 0;
        } else {
            struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
            if (rt && rt->port)
                select_dev = rt->port;
            else if (dev)
                select_dev = dev;
            else if (conn->out_dev)
                select_dev = conn->out_dev;
            if (likely(select_dev && (select_dev->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD))) {
                mbuf->l3_len = iphdrlen;
                mbuf->l4_len = sizeof(struct rte_udp_hdr);
                mbuf->ol_flags |= (PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4);
                uh->dgram_cksum = rte_ipv4_phdr_cksum(iph, mbuf->ol_flags);
            } else {
                if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                    return EDPVS_INVPKT;
                udp4_send_csum(iph, uh);
            }
        }
    }
    return EDPVS_OK;
}

static int udp_conn_sched(struct dp_vs_proto *proto,
                        const struct dp_vs_iphdr *iph,
                        struct rte_mbuf *mbuf,
                        struct dp_vs_conn **conn,
                        int *verdict)
{
    struct rte_udp_hdr *uh, _udph;
    struct dp_vs_service *svc;
    assert(proto && iph && mbuf && conn && verdict);

    uh = mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    if (unlikely(!uh)) {
        *verdict = INET_DROP;
        return EDPVS_INVPKT;
    }

    /* lookup service <vip:vport> */
    svc = dp_vs_service_lookup(iph->af, iph->proto, &iph->daddr,
                     uh->dst_port, 0, mbuf, NULL, rte_lcore_id());
    if (!svc) {
        *verdict = INET_ACCEPT;
        return EDPVS_NOSERV;
    }

    /* schedule RS and create new connection */
    *conn = NULL;
    if (svc->flags & DP_VS_SVC_F_QUIC) { // deal with quic conn migration
        struct quic_server qsvr = { 0 };
        int err = quic_parse_server(mbuf, iph, &qsvr);
        if (likely(err == EDPVS_OK)) {
            if (qsvr.wildcard > 0) {
                *conn = quic_schedule(svc, &qsvr, iph, mbuf);
                if (*conn)
                    RTE_LOG(INFO, IPVS, "schedule new connection from quic cid\n");
                else {
                    // Do NOT emit warning log here!
                    // The DCID in Initial packets are generated randomly by client, which
                    // doesn't contain valid server address info for success schedule.
                }
            }
        } else {
            RTE_LOG(WARNING, IPVS, "fail to parse server info from quic mbuf: %s\n",
                    dpvs_strerror(err));
        }
    }
    if (!*conn) {
        *conn = dp_vs_schedule(svc, iph, mbuf, false);
        if (!*conn) {
            *verdict = INET_DROP;
            return EDPVS_RESOURCE;
        }
    }

    if ((*conn)->dest->fwdmode == DPVS_FWD_MODE_FNAT && g_uoa_max_trail > 0) {
        struct conn_uoa *uoa;

        (*conn)->prot_data = rte_zmalloc(NULL, sizeof(struct conn_uoa), 0);
        if (!(*conn)->prot_data) {
            RTE_LOG(WARNING, IPVS, "%s: no memory for UOA\n", __func__);
        } else {
            uoa = (struct conn_uoa *)(*conn)->prot_data;
            uoa->state = UOA_S_SENDING;

            /* not support fast-xmit during UOA_S_SENDING */
            (*conn)->flags |= DPVS_CONN_F_NOFASTXMIT;
        }
    }

    return EDPVS_OK;
}

static struct dp_vs_conn *
udp_conn_lookup(struct dp_vs_proto *proto,
                const struct dp_vs_iphdr *iph,
                struct rte_mbuf *mbuf, int *direct,
                bool reverse, bool *drop, lcoreid_t *peer_cid)
{
    struct rte_udp_hdr *uh, _udph;
    struct dp_vs_conn *conn;
    assert(proto && iph && mbuf);

    uh = mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    if (unlikely(!uh))
        return NULL;

    if (dp_vs_blklst_filtered(iph->af, iph->proto, &iph->daddr,
                uh->dst_port, &iph->saddr, mbuf)) {
        *drop = true;
        return NULL;
    }

    if (dp_vs_whtlst_filtered(iph->af, iph->proto, &iph->daddr,
                uh->dst_port, &iph->saddr, mbuf)) {
        *drop = true;
        return NULL;
    }

    conn = dp_vs_conn_get(iph->af, iph->proto,
                          &iph->saddr, &iph->daddr,
                          uh->src_port, uh->dst_port,
                          direct, reverse);

    /*
     * L2 confirm neighbour
     * UDP has no ack, we don't know pkt from client is response or not
     * UDP can only confirm neighbour to RS
     */
    if (conn != NULL) {
        if ((*direct == DPVS_CONN_DIR_OUTBOUND) && conn->in_dev
             && (!inet_is_addr_any(tuplehash_out(conn).af, &conn->in_nexthop))) {
            neigh_confirm(tuplehash_out(conn).af, &conn->in_nexthop, conn->in_dev);
        }
    } else {
        struct dp_vs_redirect *r;

        r = dp_vs_redirect_get(iph->af, iph->proto,
                               &iph->saddr, &iph->daddr,
                               uh->src_port, uh->dst_port);
        if (r) {
            *peer_cid = r->cid;
        }
    }

    return conn;
}

static int udp_conn_expire(struct dp_vs_proto *proto, struct dp_vs_conn *conn)
{
    // Note: udp dest-check works only when the udp is bidirectional, that is,
    //   the udp conns that forwarding inbound only or outbound only are always
    //   detcted dead. Thus "dest-check" should be never configured for the
    //   single directional udp flow. Besides, the a smaller conn timeout may be
    //   specified for the bidirectional flow service to detect dest fault quickly.
    if (conn->state == DPVS_UDP_S_ONEWAY)
        dp_vs_dest_detected_dead(conn->dest);

    if (conn->prot_data)
        rte_free(conn->prot_data);

    return EDPVS_OK;
}

static int udp_conn_expire_quiescent(struct dp_vs_conn *conn)
{
    dp_vs_conn_expire_now(conn);

    return EDPVS_OK;
}

static int udp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                           struct rte_mbuf *mbuf, int dir)
{
    int old_state = conn->state;

    if (conn->dest->fwdmode == DPVS_FWD_MODE_SNAT) {
        if (dir == DPVS_CONN_DIR_INBOUND)
            conn->state = DPVS_UDP_S_NORMAL;
        else if (conn->state == DPVS_UDP_S_NONE)
            conn->state = DPVS_UDP_S_ONEWAY;
    } else {
        if (dir == DPVS_CONN_DIR_OUTBOUND)
            conn->state = DPVS_UDP_S_NORMAL;
        else if (conn->state == DPVS_UDP_S_NONE)
            conn->state = DPVS_UDP_S_ONEWAY;
    }
    dp_vs_conn_set_timeout(conn, proto);

    if (old_state == DPVS_UDP_S_ONEWAY && conn->state == DPVS_UDP_S_NORMAL)
        dp_vs_dest_detected_alive(conn->dest);

    return EDPVS_OK;
}

static int send_standalone_uoa(const struct dp_vs_conn *conn,
                               const struct rte_mbuf *ombuf,
                               const void *oiph,
                               const struct udphdr *ouh,
                               enum uoa_mode mode)
{
    struct rte_mbuf *mbuf = NULL;
    void *iph;
    struct udphdr *uh;
    struct ipopt_uoa *uoa = NULL;
    struct opphdr *opp;
    int iaf = tuplehash_in(conn).af;
    int oaf = tuplehash_out(conn).af;

    assert(conn && ombuf && oiph && ouh &&
            MBUF_USERDATA_CONST(ombuf, void *, MBUF_FIELD_ROUTE));

    /* just in case */
    if (unlikely(conn->dest->fwdmode != DPVS_FWD_MODE_FNAT))
        return EDPVS_NOTSUPP;

    mbuf = rte_pktmbuf_alloc(ombuf->pool);
    if (unlikely(!mbuf))
        return EDPVS_NOMEM;
    MBUF_USERDATA(mbuf, void *, MBUF_FIELD_ROUTE) = NULL;

    int ipolen_uoa = (AF_INET6 == iaf) ? IPOLEN_UOA_IPV6 : IPOLEN_UOA_IPV4;

    /* don't copy any ip options from oiph, is it ok ? */
    if (AF_INET6 == oaf) {
        iph = (void *)rte_pktmbuf_append(mbuf, sizeof(struct ip6_hdr));
        if (unlikely(!iph))
            goto no_room;
        ((struct ip6_hdr *)iph)->ip6_ctlun
                                      = ((struct ip6_hdr *)oiph)->ip6_ctlun;
        memcpy(&((struct ip6_hdr *)iph)->ip6_src, &conn->laddr.in6,
                                                  sizeof(struct in6_addr));
        memcpy(&((struct ip6_hdr *)iph)->ip6_dst, &conn->daddr.in6,
                                                  sizeof(struct in6_addr));
    } else {
        iph = (void *)rte_pktmbuf_append(mbuf, sizeof(struct iphdr));
        if (unlikely(!iph))
            goto no_room;
        ((struct iphdr *)iph)->version = 4;
        ((struct iphdr *)iph)->tos     = ((struct iphdr *)oiph)->tos;
        ((struct iphdr *)iph)->id      = ip4_select_id((struct rte_ipv4_hdr *)iph);
        ((struct iphdr *)iph)->frag_off = 0;
        ((struct iphdr *)iph)->ttl     = ((struct iphdr *)oiph)->ttl;
        ((struct iphdr *)iph)->saddr   = conn->laddr.in.s_addr;
        ((struct iphdr *)iph)->daddr   = conn->daddr.in.s_addr;
    }

    if (mode == UOA_M_IPO) {
        /* only ipv4 support and use this ip option mode */
        if (iaf != AF_INET || oaf != AF_INET) {
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }
        ((struct iphdr *)iph)->ihl =
            (sizeof(struct iphdr) + IPOLEN_UOA_IPV4) / 4;
        ((struct iphdr *)iph)->tot_len  =
            htons(sizeof(*iph) + IPOLEN_UOA_IPV4 + sizeof(*uh));
        ((struct iphdr *)iph)->protocol = ((struct iphdr *)oiph)->protocol;

        uoa = (void *)rte_pktmbuf_append(mbuf, ipolen_uoa);
    } else {
        /* UOA_M_OPP */
        if (AF_INET6 == oaf) {
            ((struct ip6_hdr *)iph)->ip6_plen =
                                htons(sizeof(*opp) + ipolen_uoa + sizeof(*uh));
            ((struct ip6_hdr *)iph)->ip6_nxt = IPPROTO_OPT;
        } else {
            ((struct iphdr *)iph)->ihl = sizeof(struct iphdr) / 4;
            ((struct iphdr *)iph)->tot_len = htons(sizeof(struct iphdr) +
                                sizeof(*opp) + ipolen_uoa + sizeof(*uh));
            ((struct iphdr *)iph)->protocol = IPPROTO_OPT;
        }

        /* option-proto */
        opp = (void *)rte_pktmbuf_append(mbuf, sizeof(*opp));
        if (unlikely(!opp))
            goto no_room;

        memset(opp, 0, sizeof(*opp));
        opp->version = (AF_INET6 == iaf) ? OPPHDR_IPV6 : OPPHDR_IPV4;
        opp->protocol = IPPROTO_UDP; /* set to IPPROTO_UDP */
        opp->length = htons(sizeof(*opp) + ipolen_uoa);

        uoa = (void *)rte_pktmbuf_append(mbuf, ipolen_uoa);
    }

    /* UOA option */
    if (unlikely(!uoa))
        goto no_room;

    memset(uoa, 0, ipolen_uoa);
    uoa->op_code = IPOPT_UOA;
    uoa->op_len  = ipolen_uoa;
    uoa->op_port = ouh->source;
    /* fix uoa->op_addr */
    if (AF_INET6 == iaf) {
        memcpy(&uoa->op_addr, &((struct ip6_hdr *)oiph)->ip6_src,
                               IPV6_ADDR_LEN_IN_BYTES);
    } else {
        memcpy(&uoa->op_addr, &((struct iphdr *)oiph)->saddr,
                               IPV4_ADDR_LEN_IN_BYTES);
    }

    /* udp header */
    uh = (void *)rte_pktmbuf_append(mbuf, sizeof(struct udphdr));
    if (unlikely(!uh))
        goto no_room;

    memset(uh, 0, sizeof(struct udphdr));
    uh->source = conn->lport;
    uh->dest   = conn->dport;
    uh->len    = htons(sizeof(struct udphdr)); /* empty payload */

    /* ip checksum will calc later */

    if (AF_INET6 == oaf) {
        struct route6 *rt6;
        /*
         * IPv6 UDP checksum is a must, packets with OPP header also need checksum.
         * if udp checksum error here, may cause tcpdump & uoa moudule parse packets
         * correctly, however socket can not receive L4 data.
         */
        udp6_send_csum((struct rte_ipv6_hdr *)iph, (struct rte_udp_hdr*)uh);
        rt6 = MBUF_USERDATA_CONST(ombuf, struct route6 *, MBUF_FIELD_ROUTE);
        MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE) = rt6;
        route6_get(rt6);
        return ip6_local_out(mbuf);
    } else { /* IPv4 */
        struct route_entry *rt;
        uh->check  = 0; /* rte_ipv4_udptcp_cksum fails if opp inserted. */
        rt = MBUF_USERDATA_CONST(ombuf, struct route_entry *, MBUF_FIELD_ROUTE);
        MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE) = rt;
        route4_get(rt);
        return ipv4_local_out(mbuf);
    }

no_room:
    if (mbuf)
        rte_pktmbuf_free(mbuf);
    return EDPVS_NOROOM;
}

static int insert_ipopt_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                            struct iphdr *iph, struct udphdr *uh, int mtu)
{
    struct iphdr *niph = NULL;
    struct ipopt_uoa *optuoa;

    assert(AF_INET == tuplehash_in(conn).af && AF_INET == tuplehash_out(conn).af);
    if ((ip4_hdrlen(mbuf) + IPOLEN_UOA_IPV4 >
                sizeof(struct iphdr) + MAX_IPOPTLEN)
            || (mbuf->pkt_len + IPOLEN_UOA_IPV4 > mtu))
        goto standalone_uoa;

    /*
     * head-move or tail-move.
     *
     * move IP fixed header (not including options) if it's shorter,
     * otherwise move left parts (IP opts, UDP hdr and payloads).
     */
    if (likely(ntohs(iph->tot_len) >= (sizeof(struct iphdr) * 2))) {
        niph = (struct iphdr *)rte_pktmbuf_prepend(mbuf, IPOLEN_UOA_IPV4);
        if (unlikely(!niph))
            goto standalone_uoa;

        memmove(niph, iph, sizeof(struct iphdr));
    } else {
        unsigned char *ptr;

        niph = iph;

        /* pull all bits in segments to first segment */
        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto standalone_uoa;

        ptr = (void *)rte_pktmbuf_append(mbuf, IPOLEN_UOA_IPV4);
        if (unlikely(!ptr))
            goto standalone_uoa;

        memmove((void *)(iph + 1) + IPOLEN_UOA_IPV4, iph + 1,
                ntohs(iph->tot_len) - sizeof(struct iphdr));
        uh = (void *)uh + IPOLEN_UOA_IPV4;
    }

    optuoa = (struct ipopt_uoa *)(niph + 1);
    optuoa->op_code = IPOPT_UOA;
    optuoa->op_len  = IPOLEN_UOA_IPV4;
    optuoa->op_port = uh->source;
    memcpy(&optuoa->op_addr, &niph->saddr, IPV4_ADDR_LEN_IN_BYTES);

    niph->ihl += IPOLEN_UOA_IPV4 / 4;
    niph->tot_len = htons(ntohs(niph->tot_len) + IPOLEN_UOA_IPV4);
    /* UDP/IP checksum will recalc later*/

    return EDPVS_OK;

standalone_uoa:
    return send_standalone_uoa(conn, mbuf, iph, uh, UOA_M_IPO);
}

/*
 * insert_opp_uoa: insert IPPROTO_OPT with uoa
 *
 * @iph: pointer to ip header, type of void *
 *  will be cast to struct iphdr * or struct ip6_hdr * according to af
 * @uh: pointer to udp header
 * @return insertion status
 */
static int insert_opp_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          void *iph, struct udphdr *uh, int mtu)
{
    void *niph;
    struct opphdr *opph   = NULL;
    struct ipopt_uoa *uoa = NULL;
    int iphdrlen = 0, iptot_len = 0, ipolen_uoa = 0;

    /* the current af of mbuf before possible nat64,
     * i.e. the "tuplehash_in(conn).af" for FullNAT */
    int af = conn->af;

    if (AF_INET6 == af) {
        /*
         * iphdrlen:  ipv6 total header length =
         *   basic header length (40 B) + ext header length
         * iptot_len: ipv6 total length =
         *   basic header length (40 B) + payload length(including ext header)
         */
        iphdrlen   = ip6_hdrlen(mbuf);
        if (iphdrlen != sizeof(struct rte_ipv6_hdr))
            goto standalone_uoa;
        iptot_len  = sizeof(struct ip6_hdr) +
                     ntohs(((struct ip6_hdr *)iph)->ip6_plen);
        ipolen_uoa = IPOLEN_UOA_IPV6;
    } else {
        iphdrlen   = ip4_hdrlen(mbuf);
        iptot_len  = ntohs(((struct iphdr *)iph)->tot_len);
        ipolen_uoa = IPOLEN_UOA_IPV4;
    }

    if (mbuf->pkt_len + sizeof(*opph) + ipolen_uoa > mtu)
        goto standalone_uoa;

    /*
     * new protocol is inserted after IPv4/v6 header (including existing
     * options), and before UDP header. so unlike "ipo" mode, do not
     * need handle IPOPT_END coincide issue.
     */

    if (likely(iptot_len >= iphdrlen * 2)) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*opph) + ipolen_uoa);
        if (unlikely(!niph))
            goto standalone_uoa;

        memmove(niph, iph, iphdrlen);
    } else {
        unsigned char *ptr;

        niph = iph;

        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto standalone_uoa;

        ptr = (void *)rte_pktmbuf_append(mbuf, sizeof(*opph) + ipolen_uoa);
        if (unlikely(!ptr))
            goto standalone_uoa;

        memmove((void *)iph + iphdrlen + sizeof(*opph) + ipolen_uoa,
                (void *)iph + iphdrlen,
                iptot_len - iphdrlen);

        uh = (void *)uh + sizeof(*opph) + ipolen_uoa;
    }

    opph = (struct opphdr *)((void *)niph + iphdrlen);
    memset(opph, 0, sizeof(*opph));

    if (AF_INET6 == af) {
        /* version 2 for ipv6 address family */
        uint8_t nexthdr = ((struct ip6_hdr *)niph)->ip6_nxt;
        ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &nexthdr);
        opph->version  = OPPHDR_IPV6;
        opph->protocol = nexthdr;
    } else {
        /* version 1 for ipv4 address family */
        opph->version  = OPPHDR_IPV4;
        opph->protocol = ((struct iphdr *)niph)->protocol;
    }
    opph->length = htons(sizeof(*opph) + ipolen_uoa);

    uoa = (void *)opph->options;
    memset(uoa, 0, ipolen_uoa);
    uoa->op_code = IPOPT_UOA;
    uoa->op_len  = ipolen_uoa;
    uoa->op_port = uh->source;
    if (AF_INET6 == af) {
        memcpy(&uoa->op_addr, &((struct ip6_hdr *)niph)->ip6_src,
                                                    IPV6_ADDR_LEN_IN_BYTES);
        /*
         * we should set the 'nexthdr' of the last ext header to IPPROTO_OPT here
         * but seems no efficient method to set that one
         * ip6_skip_exthdr was only used to get the value
         * so we send_standalone_uoa when has ip ext headers
         */
        ((struct ip6_hdr *)niph)->ip6_nxt = IPPROTO_OPT;
        /* Update ipv6 payload length */
        ((struct ip6_hdr *)niph)->ip6_plen =
                    htons(ntohs(((struct ip6_hdr *)niph)->ip6_plen) +
                    sizeof(*opph) + ipolen_uoa);
    } else {
        memcpy(&uoa->op_addr, &((struct iphdr *)niph)->saddr,
                                                    IPV4_ADDR_LEN_IN_BYTES);
        ((struct iphdr *)niph)->protocol = IPPROTO_OPT;
        /* UDP/IP checksum will recalc later*/
        ((struct iphdr *)niph)->tot_len =
                               htons(iptot_len + sizeof(*opph) + ipolen_uoa);
    }

    return EDPVS_OK;

standalone_uoa:
    return send_standalone_uoa(conn, mbuf, iph, uh, UOA_M_OPP);
}

static int udp_insert_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          struct conn_uoa *uoa)
{
    void *rt = NULL;
    struct udphdr *uh = NULL;
    void *iph = NULL;
    int af = conn->af;
    int iphdrlen = 0;
    int err = EDPVS_OK;
    int mtu;

    /* already send enough UOA */
    if (uoa->state == UOA_S_DONE)
        return EDPVS_OK;

    /* stop sending if ACK received or max-trail reached */
    if (uoa->sent >= g_uoa_max_trail || uoa->acked) {
        uoa->state = UOA_S_DONE;
        conn->flags &= ~DPVS_CONN_F_NOFASTXMIT;
        return EDPVS_OK;
    }

    rt = MBUF_USERDATA(mbuf, void *, MBUF_FIELD_ROUTE);
    if (!rt) {
        RTE_LOG(ERR, IPVS, "%s: no route\n", __func__);
        return EDPVS_INVPKT;
    }

    if (AF_INET6 == tuplehash_out(conn).af) {
        mtu = ((struct route6*)rt)->rt6_mtu;
    } else {
        mtu = ((struct route_entry*) rt)->mtu;
    }

    if (AF_INET6 == conn->af) {
        iph = ip6_hdr(mbuf);
        iphdrlen = ip6_hdrlen(mbuf);
    } else {
        iph = (struct iphdr *)ip4_hdr(mbuf);
        iphdrlen = ip4_hdrlen(mbuf);
    }

    /* get udp header before any 'standalone_uoa' */
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udphdr *, iphdrlen);

    /*
     * send standalone (empty-payload) UDP/IP pkt with UOA if
     * no room in IP header or exceeding MTU.
     *
     * Note: don't worry about inserting IPOPT_END, since it's
     * not mandatory and Linux codes can handle absent of IPOPT_END.
     * actually just adding UOA will not cause "... end of option coincide
     * with the end of the internet header. - RFC791". if original packet
     * is coincide, the IPOPT_END should already exist.
     */
    switch (g_uoa_mode) {
        case UOA_M_IPO:
            /* only ipv4 support ipopt mode */
            if (AF_INET == af) {
                err = insert_ipopt_uoa(conn, mbuf, (struct iphdr *)iph, uh, mtu);
            } else {
                RTE_LOG(WARNING, IPVS, "fail to send UOA: %s\n", dpvs_strerror(err));
            }
            break;

        case UOA_M_OPP:
            err = insert_opp_uoa(conn, mbuf, iph, uh, mtu);
            break;

        default:
            return EDPVS_INVAL;
    }

    if (err == EDPVS_OK)
        uoa->sent++;
    else
        RTE_LOG(WARNING, IPVS, "fail to send UOA: %s\n", dpvs_strerror(err));

    return err;
}

static int udp_in_add_proxy_proto(struct dp_vs_conn *conn,
        struct rte_mbuf *mbuf, struct rte_udp_hdr *udph,
        int iphdrlen, int *hdr_shift)
{
    int offset;
    struct proxy_info ppinfo = { 0 };

    offset = iphdrlen + sizeof(struct rte_udp_hdr);
    if (unlikely(EDPVS_OK != proxy_proto_parse(mbuf, offset, &ppinfo)))
        return EDPVS_INVPKT;

    if (ppinfo.datalen > 0
            && ppinfo.version == PROXY_PROTOCOL_VERSION(conn->pp_version)
            && PROXY_PROTOCOL_IS_INSECURE(conn->pp_version))
        return EDPVS_OK;    // keep intact the original proxy protocol data

    if (!ppinfo.datalen || !PROXY_PROTOCOL_IS_INSECURE(conn->pp_version)) {
        ppinfo.af = tuplehash_in(conn).af;
        ppinfo.proto = IPPROTO_UDP;
        ppinfo.version = PROXY_PROTOCOL_VERSION(conn->pp_version);
        ppinfo.cmd = 1;
        if (AF_INET == ppinfo.af) {
            ppinfo.addr.ip4.src_addr = conn->caddr.in.s_addr;
            ppinfo.addr.ip4.dst_addr = conn->vaddr.in.s_addr;
            ppinfo.addr.ip4.src_port = conn->cport;
            ppinfo.addr.ip4.dst_port = conn->vport;
        } else if (AF_INET6 == ppinfo.af) {
            rte_memcpy(ppinfo.addr.ip6.src_addr, conn->caddr.in6.s6_addr, 16);
            rte_memcpy(ppinfo.addr.ip6.dst_addr, conn->vaddr.in6.s6_addr, 16);
            ppinfo.addr.ip6.src_port = conn->cport;
            ppinfo.addr.ip6.dst_port = conn->vport;
        } else {
            return EDPVS_NOTSUPP;
        }
    }

    return proxy_proto_insert(&ppinfo, conn, mbuf, udph, hdr_shift);
}

static int udp_fnat_in_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh = NULL;
    struct opphdr *opp = NULL;
    void *iph = NULL;
    /* af/mbuf may be changed for nat64 which in af is ipv6 and out is ipv4 */
    int af = tuplehash_out(conn).af;
    int err, iphdrlen = 0;
    int hdr_shift = 0;
    uint8_t nxt_proto;

    if (AF_INET6 == af) {
        iph = ip6_hdr(mbuf);
        iphdrlen = ip6_hdrlen(mbuf);
        /* need found the last ip6_nxt of the ext header */
        uint8_t nexthdr = ((struct ip6_hdr *)iph)->ip6_nxt;
        ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &nexthdr);
        nxt_proto = nexthdr;
    } else {
        iph = ip4_hdr(mbuf);
        iphdrlen = ip4_hdrlen(mbuf);
        nxt_proto = ((struct iphdr *)iph)->protocol;
    }

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct rte_udp_hdr)))
        return EDPVS_INVPKT;

    if (nxt_proto == IPPROTO_UDP) {
        uh = (struct rte_udp_hdr *)(iph + iphdrlen);
    } else if (nxt_proto == IPPROTO_OPT) {
        opp = (struct opphdr *)(iph + iphdrlen);
        uh  = (struct rte_udp_hdr *)((void *)opp + ntohs(opp->length));
    }

    if (unlikely(!uh))
        return EDPVS_INVPKT;

    if (!conn->pp_sent &&
            (PROXY_PROTOCOL_V2 == PROXY_PROTOCOL_VERSION(conn->pp_version))) {
        err = udp_in_add_proxy_proto(conn, mbuf, uh, iphdrlen, &hdr_shift);
        if (unlikely(EDPVS_OK != err))
            RTE_LOG(INFO, IPVS, "%s: insert proxy protocol fail -- %s\n",
                    __func__, dpvs_strerror(err));
        // Notes: Is there any approach to deal with the exceptional cases where
        //   - proxy protocol insertion failed
        //   - the first udp packet with proxy protocol data got lost in network
        conn->pp_sent = 1;
        uh = ((void *)uh) + hdr_shift;
    }
    uh->src_port = conn->lport;
    uh->dst_port = conn->dport;

    return udp_send_csum(af, iphdrlen, uh, conn, mbuf, opp, conn->in_dev);
}

static int udp_fnat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh;
    /* af/mbuf may be changed for nat64 which in af is ipv6 and out is ipv4 */
    int af = tuplehash_in(conn).af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct rte_udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port = conn->vport;
    uh->dst_port = conn->cport;

    return udp_send_csum(af, iphdrlen, uh, conn, mbuf, NULL, conn->out_dev);
}

static int udp_fnat_in_pre_handler(struct dp_vs_proto *proto,
                                   struct dp_vs_conn *conn,
                                   struct rte_mbuf *mbuf)
{
    struct conn_uoa *uoa = (struct conn_uoa *)conn->prot_data;

    if (PROXY_PROTOCOL_V2 == PROXY_PROTOCOL_VERSION(conn->pp_version))
        return EDPVS_OK;

    if (uoa && g_uoa_max_trail > 0)
        return udp_insert_uoa(conn, mbuf, uoa);

    return EDPVS_OK;
}

static int udp_snat_in_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh;
    int af = conn->af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct rte_udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->dst_port = conn->dport;

    return udp_send_csum(af, iphdrlen, uh, conn, mbuf, NULL, conn->in_dev);
}

static int udp_snat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct rte_udp_hdr *uh;
    int af = conn->af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct rte_udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, iphdrlen);
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port = conn->vport;

    return udp_send_csum(af, iphdrlen, uh, conn, mbuf, NULL, conn->out_dev);
}

struct dp_vs_proto dp_vs_proto_udp = {
    .name                  = "UDP",
    .proto                 = IPPROTO_UDP,
    .timeout_table         = udp_timeouts,
    .conn_sched            = udp_conn_sched,
    .conn_lookup           = udp_conn_lookup,
    .conn_expire           = udp_conn_expire,
    .conn_expire_quiescent = udp_conn_expire_quiescent,
    .state_trans           = udp_state_trans,
    .nat_in_handler        = udp_snat_in_handler,
    .nat_out_handler       = udp_snat_out_handler,
    .fnat_in_handler       = udp_fnat_in_handler,
    .fnat_out_handler      = udp_fnat_out_handler,
    .fnat_in_pre_handler   = udp_fnat_in_pre_handler,
    .snat_in_handler       = udp_snat_in_handler,
    .snat_out_handler      = udp_snat_out_handler,
};

static void defence_udp_drop_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "defence_udp_drop ON\n");
    g_defence_udp_drop = 1;
}

static void uoa_max_trail_handler(vector_t tokens)
{
    int max;
    char *str = set_value(tokens);

    assert(str);
    max = atoi(str);

    if (max >= 0) {
        RTE_LOG(INFO, IPVS, "uoa_max_trail = %d\n", max);
        g_uoa_max_trail = max;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid uoa_max_trail: %d\n", max);
    }

    FREE_PTR(str);
}

static void uoa_mode_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    assert(str);

    if (strcmp(str, "opp") == 0)
        g_uoa_mode = UOA_M_OPP;
    else if (strcmp(str, "ipo") == 0)
        g_uoa_mode = UOA_M_IPO;
    else
        RTE_LOG(WARNING, IPVS, "invalid uoa_mode: %s\n", str);

    FREE_PTR(str);
}

static void timeout_oneway_handler(vector_t tokens)
{
    int timeout;
    char *str = set_value(tokens);

    assert(str);
    timeout = atoi(str);
    if (timeout > IPVS_TIMEOUT_MIN && timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "udp_timeout_oneway = %d\n", timeout);
        udp_timeouts[DPVS_UDP_S_ONEWAY] = timeout;
    } else {
        RTE_LOG(INFO, IPVS, "invalid udp_timeout_oneway %s, using default %d\n",
                str, 300);
        udp_timeouts[DPVS_UDP_S_ONEWAY] = 300;
    }

    FREE_PTR(str);
}

static void timeout_normal_handler(vector_t tokens)
{
    int timeout;
    char *str = set_value(tokens);

    assert(str);
    timeout = atoi(str);
    if (timeout > IPVS_TIMEOUT_MIN && timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "udp_timeout_normal = %d\n", timeout);
        udp_timeouts[DPVS_UDP_S_NORMAL] = timeout;
    } else {
        RTE_LOG(INFO, IPVS, "invalid udp_timeout_normal %s, using default %d\n",
                str, 300);
        udp_timeouts[DPVS_UDP_S_NORMAL] = 300;
    }

    FREE_PTR(str);
}

static void timeout_last_handler(vector_t tokens)
{
    int timeout;
    char *str = set_value(tokens);

    assert(str);
    timeout = atoi(str);
    if (timeout > IPVS_TIMEOUT_MIN && timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "udp_timeout_last = %d\n", timeout);
        udp_timeouts[DPVS_UDP_S_LAST] = timeout;
    } else {
        RTE_LOG(INFO, IPVS, "invalid udp_timeout_last %s, using default %d\n",
                str, 2);
        udp_timeouts[DPVS_UDP_S_LAST] = 2;
    }

    FREE_PTR(str);
}

void udp_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
    }

    /* KW_TYPE_NORMAL keyword */
    g_defence_udp_drop = 0;
    g_uoa_max_trail = UOA_DEF_MAX_TRAIL;

    udp_timeouts[DPVS_UDP_S_ONEWAY] = 300;
    udp_timeouts[DPVS_UDP_S_NORMAL] = 300;
    udp_timeouts[DPVS_UDP_S_LAST] = 2;
}

void install_proto_udp_keywords(void)
{
    install_keyword("defence_udp_drop", defence_udp_drop_handler, KW_TYPE_NORMAL);
    install_keyword("uoa_max_trail", uoa_max_trail_handler, KW_TYPE_NORMAL);
    install_keyword("uoa_mode", uoa_mode_handler, KW_TYPE_NORMAL);

    install_keyword("timeout", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("normal", timeout_normal_handler, KW_TYPE_NORMAL);
    install_keyword("oneway", timeout_oneway_handler, KW_TYPE_NORMAL);
    install_keyword("last", timeout_last_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
}
