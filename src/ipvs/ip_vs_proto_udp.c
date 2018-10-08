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
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include "common.h"
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_udp.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"
#include "ipvs/blklst.h"
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
    [DPVS_UDP_S_NORMAL] = 300,
    [DPVS_UDP_S_LAST]   = 2,
};

static int udp_conn_sched(struct dp_vs_proto *proto,
                        const struct dp_vs_iphdr *iph,
                        struct rte_mbuf *mbuf,
                        struct dp_vs_conn **conn,
                        int *verdict)
{
    struct udp_hdr *uh, _udph;
    struct dp_vs_service *svc;
    assert(proto && iph && mbuf && conn && verdict);

    uh = mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    if (unlikely(!uh)) {
        *verdict = INET_DROP;
        return EDPVS_INVPKT;
    }

    /* lookup service <vip:vport> */
    svc = dp_vs_service_lookup(iph->af, iph->proto,
                               &iph->daddr, uh->dst_port, 0, mbuf, NULL);
    if (!svc) {
        *verdict = INET_ACCEPT;
        return EDPVS_NOSERV;
    }

    /* schedule RS and create new connection */
    *conn = dp_vs_schedule(svc, iph, mbuf, false);
    if (!*conn) {
        dp_vs_service_put(svc);
        *verdict = INET_DROP;
        return EDPVS_RESOURCE;
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

    dp_vs_service_put(svc);
    return EDPVS_OK;
}

static struct dp_vs_conn *
udp_conn_lookup(struct dp_vs_proto *proto,
                const struct dp_vs_iphdr *iph,
                struct rte_mbuf *mbuf, int *direct,
                bool reverse, bool *drop)
{
    struct udp_hdr *uh, _udph;
    struct dp_vs_conn *conn;
    assert(proto && iph && mbuf);

    uh = mbuf_header_pointer(mbuf, iph->len, sizeof(_udph), &_udph);
    if (unlikely(!uh))
        return NULL;

    if (dp_vs_blklst_lookup(iph->proto, &iph->daddr, uh->dst_port,
                            &iph->saddr)) {
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
             && (conn->in_nexthop.in.s_addr != htonl(INADDR_ANY))){
            neigh_confirm(AF_INET, &conn->in_nexthop, conn->in_dev);
        }
    }

    return conn;
}

static int udp_conn_expire(struct dp_vs_proto *proto, struct dp_vs_conn *conn)
{
    if (conn->prot_data)
        rte_free(conn->prot_data);

    return EDPVS_OK;
}

static int udp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                           struct rte_mbuf *mbuf, int dir)
{
    conn->state = DPVS_UDP_S_NORMAL;
    conn->timeout.tv_sec = udp_timeouts[conn->state];
    return EDPVS_OK;
}

static int send_standalone_uoa(const struct dp_vs_conn *conn,
                               const struct rte_mbuf *ombuf,
                               const void *oiph,
                               const struct udphdr *ouh,
                               enum uoa_mode mode)
{
    struct rte_mbuf *mbuf = NULL;
    struct route_entry *rt;
    void *iph;
    struct udphdr *uh;
    struct ipopt_uoa *uoa = NULL;
    struct opphdr *opp;
    int af = conn->af;

    assert(conn && ombuf && oiph && ouh && ombuf->userdata);

    /* just in case */
    if (unlikely(conn->dest->fwdmode != DPVS_FWD_MODE_FNAT))
        return EDPVS_NOTSUPP;

    mbuf = rte_pktmbuf_alloc(ombuf->pool);
    if (unlikely(!mbuf))
        return EDPVS_NOMEM;

    /* don't copy any ip options from oiph, is it ok ? */
    if (af == AF_INET6) {
        iph = (void *)rte_pktmbuf_append(mbuf, sizeof(struct ip6_hdr));
        if (unlikely(!iph))
            goto no_room;
        ((struct ip6_hdr *)iph)->ip6_ctlun
                                        = ((struct ip6_hdr *)oiph)->ip6_ctlun;
        memcpy(&((struct ip6_hdr *)iph)->ip6_src,
                                      &((struct ip6_hdr *)oiph)->ip6_src,
                                      IPV6_ADDR_LEN_IN_BYTES);
        memcpy(&((struct ip6_hdr *)iph)->ip6_dst,
                                      &((struct ip6_hdr *)oiph)->ip6_dst,
                                      IPV6_ADDR_LEN_IN_BYTES);
    } else {
        iph = (void *)rte_pktmbuf_append(mbuf, sizeof(struct iphdr));
        if (unlikely(!iph))
            goto no_room;
        ((struct iphdr *)iph)->version = 4;
        ((struct iphdr *)iph)->tos     = ((struct iphdr *)oiph)->tos;
        ((struct iphdr *)iph)->id      = ip4_select_id((struct ipv4_hdr *)iph);
        ((struct iphdr *)iph)->frag_off = 0;
        ((struct iphdr *)iph)->ttl     = ((struct iphdr *)oiph)->ttl;
        ((struct iphdr *)iph)->saddr   = conn->laddr.in.s_addr;
        ((struct iphdr *)iph)->daddr   = conn->daddr.in.s_addr;
    }

    if (mode == UOA_M_IPO) {
        /* only ipv4 support and use ip option mode, and thus get here */
        ((struct iphdr *)iph)->ihl =
            (sizeof(struct iphdr) + IPOLEN_UOA) / 4;
        ((struct iphdr *)iph)->tot_len  =
            htons(sizeof(*iph) + IPOLEN_UOA + sizeof(*uh));
        ((struct iphdr *)iph)->protocol = ((struct iphdr *)oiph)->protocol;

        uoa = (void *)rte_pktmbuf_append(mbuf, IPOLEN_UOA);
    } else { /* UOA_M_OPP */
        if (af == AF_INET6) {
            ((struct ip6_hdr *)iph)->ip6_plen =
                            htons(ntohs(((struct ip6_hdr *)oiph)->ip6_plen) +
                            sizeof(*opp) + sizeof(*uoa) + sizeof(*uh));
            ((struct ip6_hdr *)iph)->ip6_nxt = IPPROTO_OPT;
        } else {
            ((struct iphdr *)iph)->ihl = sizeof(struct iphdr) / 4;
            ((struct iphdr *)iph)->tot_len = htons(sizeof(struct iphdr) +
                                sizeof(*opp) + sizeof(*uoa) + sizeof(*uh));
            ((struct iphdr *)iph)->protocol = IPPROTO_OPT;
        }

        /* option-proto */
        opp = (void *)rte_pktmbuf_append(mbuf, sizeof(*opp));
        if (unlikely(!opp))
            goto no_room;

        memset(opp, 0, sizeof(*opp));
        if (af == AF_INET6) {
            opp->version  = 0x02;
            opp->protocol = ((struct ip6_hdr *)oiph)->ip6_nxt;
        } else {
            opp->version = 0x01;
            opp->protocol = ((struct iphdr *)oiph)->protocol;
        }
        opp->length = htons(sizeof(*opp) + sizeof(*uoa));

        uoa = (void *)rte_pktmbuf_append(mbuf, sizeof(*uoa));
    }

    /* UOA option */
    if (unlikely(!uoa))
        goto no_room;

    uoa->op_code = IPOPT_UOA;
    uoa->op_len  = IPOLEN_UOA;
    uoa->op_port = ouh->source;
    /* fix uoa->op_addr */
    if (af == AF_INET6) {
        memcpy(uoa->op_addr, &((struct ip6_hdr *)oiph)->ip6_src, 
                                                    IPV6_ADDR_LEN_IN_BYTES);
    } else {
        uoa->op_addr[0] = ((struct iphdr *)oiph)->saddr;
    }

    /* udp header */
    uh = (void *)rte_pktmbuf_append(mbuf, sizeof(struct udphdr));
    if (unlikely(!uh))
        goto no_room;
    uh->source      = conn->lport;
    uh->dest        = conn->dport;
    uh->len         = htons(sizeof(struct udphdr)); /* empty payload */

    /* udp checksum */
    uh->check       = 0; /* rte_ipv4_udptcp_cksum fails if opp inserted. */

    /* ip checksum will calc later */

    mbuf->userdata = rt = (struct route_entry *)ombuf->userdata;
    route4_get(rt);

    return ipv4_local_out(mbuf);

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

    if ((ip4_hdrlen(mbuf) + sizeof(struct ipopt_uoa) > MAX_IPOPTLEN) ||
            (mbuf->pkt_len + sizeof(struct ipopt_uoa) > mtu))
        goto standalone_uoa;

    /*
     * head-move or tail-move.
     *
     * move IP fixed header (not including options) if it's shorter,
     * otherwise move left parts (IP opts, UDP hdr and payloads).
     */
    if (likely(ntohs(iph->tot_len) >= (sizeof(struct iphdr) * 2))) {
        niph = (struct iphdr *)rte_pktmbuf_prepend(mbuf, IPOLEN_UOA);
        if (unlikely(!niph))
            goto standalone_uoa;

        memmove(niph, iph, sizeof(struct iphdr));
    } else {
        unsigned char *ptr;

        niph = iph;

        /* pull all bits in segments to first segment */
        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto standalone_uoa;

        ptr = (void *)rte_pktmbuf_append(mbuf, IPOLEN_UOA);
        if (unlikely(!ptr))
            goto standalone_uoa;

        memmove((void *)(iph + 1) + IPOLEN_UOA, iph + 1,
                ntohs(iph->tot_len) - sizeof(struct iphdr));
        uh = (void *)uh + IPOLEN_UOA;
    }

    optuoa = (struct ipopt_uoa *)(niph + 1);
    optuoa->op_code = IPOPT_UOA;
    optuoa->op_len  = IPOLEN_UOA;
    optuoa->op_port = uh->source;
    optuoa->op_addr[0] = niph->saddr;

    niph->ihl += IPOLEN_UOA / 4;
    niph->tot_len = htons(ntohs(niph->tot_len) + IPOLEN_UOA);
    /* UDP/IP checksum will recalc later*/

    return EDPVS_OK;

standalone_uoa:
    return send_standalone_uoa(conn, mbuf, iph, uh, UOA_M_IPO);
}

/*
 * insert_opp_uoa: insert IPPROTO_OPT with uoa
 * @iph: pointer to ip header, type void *,
 *       will be cast to struct iphdr * or struct ip6_hdr * according to af
 * @uh:  pointer to udp header
 * @return insertion status
 */
static int insert_opp_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          void *iph, struct udphdr *uh, int mtu)
{
    /* will be cast to struct iphdr * or struct ip6_hdr * according to af */
    void *niph;
    struct opphdr *opph = NULL;
    struct ipopt_uoa *uoa = NULL;
    int af = conn->af;
    int iphdrlen = 0;

    /* first of all, cast iph to its originally type */
    if (af == AF_INET6) {
        iphdrlen = ip6_hdrlen(mbuf);
    } else {
        iphdrlen = ip4_hdrlen(mbuf);
    }

    if (mbuf->pkt_len + sizeof(*opph) + IPOLEN_UOA > mtu)
        goto standalone_uoa;

    /*
     * new protocol is inserted after IPv4/v6 header (including existing
     * options), and before UDP header. so unlike "ipo" mode, do not
     * need handle IPOPT_END coincide issue.
     */

    int iptot_len = 0;
    if (af == AF_INET6) {
        iptot_len = iphdrlen + ntohs(((struct ip6_hdr *)iph)->ip6_plen);
    } else {
        iptot_len = ntohs(((struct iphdr *)iph)->tot_len);
    }

    if (likely(iptot_len >= iphdrlen * 2)) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*opph) + IPOLEN_UOA);
        if (unlikely(!niph))
            goto standalone_uoa;

        memmove(niph, iph, iphdrlen);
    } else {
        unsigned char *ptr;

        niph = iph;

        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto standalone_uoa;

        ptr = (void *)rte_pktmbuf_append(mbuf, sizeof(*opph) + IPOLEN_UOA);
        if (unlikely(!ptr))
            goto standalone_uoa;

        memmove((void *)iph + iphdrlen + sizeof(*opph) + IPOLEN_UOA,
                (void *)iph + iphdrlen,
                iptot_len - iphdrlen);

        uh = (void *)uh + sizeof(*opph) + IPOLEN_UOA;
    }

    opph = (struct opphdr *)((void *)niph + iphdrlen);
    memset(opph, 0, sizeof(*opph));
    if (af == AF_INET6) {
        /* version 2 for ipv6 address */
        opph->version  = 0x2;
        opph->protocol = ((struct ip6_hdr *)niph)->ip6_nxt;
    } else {
        /* version 1 for ipv4 address */
        opph->version  = 0x1;
        opph->protocol = ((struct iphdr *)niph)->protocol;
    }
    opph->length = htons(sizeof(*opph) + IPOLEN_UOA);

    memset(uoa, 0, sizeof(struct ipopt_uoa));
    uoa = (void *)opph->options;
    uoa->op_code    = IPOPT_UOA;
    uoa->op_len     = IPOLEN_UOA;
    uoa->op_port    = uh->source;
    if (af == AF_INET6) {
        memcpy(uoa->op_addr, &((struct ip6_hdr *)niph)->ip6_src, 
                                                    IPV6_ADDR_LEN_IN_BYTES);
        ((struct ip6_hdr *)niph)->ip6_nxt = IPPROTO_OPT;
        /*
         * UDP/IP checksum will recalc later
         *
         * Update ipv6 payload length, for short can be:
         * htons(iptot_len - iphdrlen + sizeof(*opph) + IPOLEN_UOA);
         */
        ((struct ip6_hdr *)niph)->ip6_plen =
                    htons(ntohs(((struct ip6_hdr *)niph)->ip6_plen) +
                    sizeof(*opph) + IPOLEN_UOA);
    } else {
        memcpy(uoa->op_addr, &((struct iphdr *)niph)->saddr, 4);
        ((struct iphdr *)niph)->protocol = IPPROTO_OPT;
        /* UDP/IP checksum will recalc later*/
        ((struct iphdr *)niph)->tot_len =
                               htons(iptot_len + sizeof(*opph) + IPOLEN_UOA);
    }

    return EDPVS_OK;

standalone_uoa:
    return send_standalone_uoa(conn, mbuf, iph, uh, UOA_M_OPP);
}

static int udp_insert_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          struct conn_uoa *uoa)
{
    struct route_entry *rt = NULL;
    struct udphdr *uh = NULL;
    int err = EDPVS_OK;

    int af = conn->af;
    int iphdrlen = 0;
    void *iph = NULL;

    if (af == AF_INET6) {
        /* ip6_hdr returns ipv6 header of linux version, not of dpdk */
        /* struct ip6_hdr */
        iph = ip6_hdr(mbuf);
        iphdrlen = ip6_hdrlen(mbuf);
    } else {
        iph = (struct iphdr *)ip4_hdr(mbuf);
        iphdrlen = ip4_hdrlen(mbuf);
    }

    /* already send enough UOA */
    if (uoa->state == UOA_S_DONE)
        return EDPVS_OK;

    /* stop sending if ACK received or max-trail reached */
    if (uoa->sent >= g_uoa_max_trail || uoa->acked) {
        uoa->state = UOA_S_DONE;
        conn->flags &= ~DPVS_CONN_F_NOFASTXMIT;
        return EDPVS_OK;
    }

    /* get udp header before any 'standalone_uoa' */
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udphdr *, iphdrlen);

    rt = mbuf->userdata;
    if (!rt) {
        RTE_LOG(ERR, IPVS, "%s: no route\n", __func__);
        return EDPVS_INVPKT;
    }

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
            if (af == AF_INET) {
                err = insert_ipopt_uoa(conn, mbuf, (struct iphdr *)iph, uh, rt->mtu);
            } else {
                RTE_LOG(WARNING, IPVS, "fail to send UOA: %s\n", dpvs_strerror(err));
            }
            break;

        case UOA_M_OPP:
            err = insert_opp_uoa(conn, mbuf, iph, uh, rt->mtu);
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

static int udp_fnat_in_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh = NULL;
    struct iphdr  *iph = NULL;
    struct opphdr *opp = NULL;

    int af = conn->af;
    if (af == AF_INET6) {
        iph = (void *)ip6_hdr(mbuf);
    } else {
        iph = (void *)ip4_hdr(mbuf);
    }
    int iphdrlen = ((af == AF_INET6) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;

    if (iph->protocol == IPPROTO_UDP) {
        uh = (void *)iph + iphdrlen;
    } else if (iph->protocol == IPPROTO_OPT) {
        opp = (void *)iph + iphdrlen;
        uh  = (void *)opp + ntohs(opp->length);
    }

    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->lport;
    uh->dst_port    = conn->dport;

    uh->dgram_cksum = 0;

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
    if (!opp) {
        if (af == AF_INET6) {
            uh->dgram_cksum =
                rte_ipv6_udptcp_cksum((struct ipv6_hdr *)ip6_hdr(mbuf), uh);
        } else {
            uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);
        }
    }

    return EDPVS_OK;
}

static int udp_fnat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;
    int af = conn->af;
    int iphdrlen = ((af == AF_INET6) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, iphdrlen);
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->vport;
    uh->dst_port    = conn->cport;

    uh->dgram_cksum = 0;
    if (af == AF_INET6) {
        uh->dgram_cksum =
            rte_ipv6_udptcp_cksum((struct ipv6_hdr *)ip6_hdr(mbuf), uh);
    } else {
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);
    }

    return EDPVS_OK;
}

static int udp_fnat_in_pre_handler(struct dp_vs_proto *proto,
                                   struct dp_vs_conn *conn,
                                   struct rte_mbuf *mbuf)
{
    struct conn_uoa *uoa = (struct conn_uoa *)conn->prot_data;

    if (uoa && g_uoa_max_trail > 0)
        return udp_insert_uoa(conn, mbuf, uoa);
    else
        return EDPVS_OK;
}

static int udp_snat_in_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;
    int af = conn->af;
    int iphdrlen = ((af == AF_INET6) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, iphdrlen);
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->dst_port    = conn->dport;

    uh->dgram_cksum = 0;
    if (af == AF_INET6) {
        uh->dgram_cksum =
            rte_ipv6_udptcp_cksum((struct ipv6_hdr *)ip6_hdr(mbuf), uh);
    } else {
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);
    }

    return EDPVS_OK;
}

static int udp_snat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;
    int af = conn->af;
    int iphdrlen = ((af == AF_INET6) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, iphdrlen);
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->vport;

    uh->dgram_cksum = 0;
    if (af == AF_INET6) {
        uh->dgram_cksum =
            rte_ipv6_udptcp_cksum((struct ipv6_hdr *)ip6_hdr(mbuf), uh);
    } else {
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);
    }

    return EDPVS_OK;
}

struct dp_vs_proto dp_vs_proto_udp = {
    .name               = "UDP",
    .proto              = IPPROTO_UDP,
    .conn_sched         = udp_conn_sched,
    .conn_lookup        = udp_conn_lookup,
    .conn_expire        = udp_conn_expire,
    .state_trans        = udp_state_trans,
    .nat_in_handler     = udp_snat_in_handler,
    .nat_out_handler    = udp_snat_out_handler,
    .fnat_in_handler    = udp_fnat_in_handler,
    .fnat_out_handler   = udp_fnat_out_handler,
    .fnat_in_pre_handler= udp_fnat_in_pre_handler,
    .snat_in_handler    = udp_snat_in_handler,
    .snat_out_handler   = udp_snat_out_handler,
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
    install_keyword("last", timeout_last_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
}
