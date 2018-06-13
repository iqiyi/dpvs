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
#include <netinet/udp.h>
#include "common.h"
#include "dpdk.h"
#include "ipv4.h"
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
            neigh_confirm(conn->in_nexthop.in, conn->in_dev);
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
                               const struct iphdr *oiph,
                               const struct udphdr *ouh,
                               enum uoa_mode mode)
{
    struct rte_mbuf *mbuf = NULL;
    struct route_entry *rt;
    struct iphdr *iph;
    struct udphdr *uh;
    struct ipopt_uoa *uoa = NULL;
    struct opphdr *opp;

    assert(conn && ombuf && oiph && ouh && ombuf->userdata);

    /* just in case */
    if (unlikely(conn->dest->fwdmode != DPVS_FWD_MODE_FNAT))
        return EDPVS_NOTSUPP;

    mbuf = rte_pktmbuf_alloc(ombuf->pool);
    if (unlikely(!mbuf))
        return EDPVS_NOMEM;

    /* don't copy any ip options from oiph, is it ok ? */
    iph = (void *)rte_pktmbuf_append(mbuf, sizeof(struct iphdr));
    if (unlikely(!iph))
        goto no_room;
    iph->version    = 4;
    iph->tos        = oiph->tos;
    iph->id         = ip4_select_id((struct ipv4_hdr *)iph);
    iph->frag_off   = 0;
    iph->ttl        = oiph->ttl;
    iph->saddr      = conn->laddr.in.s_addr;
    iph->daddr      = conn->daddr.in.s_addr;

    if (mode == UOA_M_IPO) {
        iph->ihl    = (sizeof(struct iphdr) + IPOLEN_UOA) / 4;
        iph->tot_len = htons(sizeof(*iph) + IPOLEN_UOA + sizeof(*uh));
        iph->protocol = oiph->protocol; /* should always UDP */

        uoa = (void *)rte_pktmbuf_append(mbuf, IPOLEN_UOA);
    } else { /* UOA_M_OPP */
        iph->ihl    = sizeof(struct iphdr) / 4;
        iph->tot_len = \
            htons(sizeof(*iph) + sizeof(*opp) + sizeof(*uoa) + sizeof(*uh));
        iph->protocol = IPPROTO_OPT;

        /* option-proto */
        opp = (void *)rte_pktmbuf_append(mbuf, sizeof(*opp));
        if (unlikely(!opp))
            goto no_room;

        memset(opp, 0, sizeof(*opp));
        opp->version = 0x01;
        opp->protocol = oiph->protocol;
        opp->length = htons(sizeof(*opp) + sizeof(*uoa));

        uoa = (void *)rte_pktmbuf_append(mbuf, sizeof(*uoa));
    }

    /* UOA option */
    if (unlikely(!uoa))
        goto no_room;

    uoa->op_code    = IPOPT_UOA;
    uoa->op_len     = IPOLEN_UOA;
    uoa->op_port    = ouh->source;
    uoa->op_addr    = oiph->saddr;

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
    optuoa->op_addr = niph->saddr;

    niph->ihl += IPOLEN_UOA / 4;
    niph->tot_len = htons(ntohs(niph->tot_len) + IPOLEN_UOA);
    /* UDP/IP checksum will recalc later*/

    return EDPVS_OK;

standalone_uoa:
    return send_standalone_uoa(conn, mbuf, iph, uh, UOA_M_IPO);
}

static int insert_opp_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          struct iphdr *iph, struct udphdr *uh, int mtu)
{
    struct iphdr *niph;
    struct opphdr *opph;
    struct ipopt_uoa *uoa;

    if (mbuf->pkt_len + sizeof(*opph) + IPOLEN_UOA > mtu)
        goto standalone_uoa;

    /*
     * new protocol in inserted after IPv4 header (including existing
     * options), and before UDP header. so unlike "ipo" mode, do not
     * need handle IPOPT_END coincide issue.
     */
    if (likely(ntohs(iph->tot_len) >= (iph->ihl<<2) * 2)) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, sizeof(*opph) + IPOLEN_UOA);
        if (unlikely(!niph))
            goto standalone_uoa;

        memmove(niph, iph, iph->ihl << 2);
    } else {
        unsigned char *ptr;

        niph = iph;

        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
            goto standalone_uoa;

        ptr = (void *)rte_pktmbuf_append(mbuf, sizeof(*opph) + IPOLEN_UOA);
        if (unlikely(!ptr))
            goto standalone_uoa;

        memmove((void *)iph + (iph->ihl << 2) + sizeof(*opph) + IPOLEN_UOA,
                (void *)iph + (iph->ihl << 2),
                ntohs(iph->tot_len) - (iph->ihl << 2));

        uh = (void *)uh + sizeof(*opph) + IPOLEN_UOA;
    }

    opph = (struct opphdr *)((void *)niph + (niph->ihl << 2));
    memset(opph, 0, sizeof(*opph));
    opph->version   = 0x1;
    opph->protocol  = niph->protocol;
    opph->length    = htons(sizeof(*opph) + IPOLEN_UOA);

    uoa = (void *)opph->options;
    uoa->op_code    = IPOPT_UOA;
    uoa->op_len     = IPOLEN_UOA;
    uoa->op_port    = uh->source;
    uoa->op_addr    = niph->saddr;

    niph->protocol = IPPROTO_OPT;
    niph->tot_len = htons(ntohs(niph->tot_len) + sizeof(*opph) + IPOLEN_UOA);
    /* UDP/IP checksum will recalc later*/

    return EDPVS_OK;

standalone_uoa:
    return send_standalone_uoa(conn, mbuf, iph, uh, UOA_M_OPP);
}

static int udp_insert_uoa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          struct conn_uoa *uoa)
{
    struct iphdr *iph = (struct iphdr *)ip4_hdr(mbuf);
    struct route_entry *rt = NULL;
    struct udphdr *uh = NULL;
    int err;

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
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udphdr *, ip4_hdrlen(mbuf));

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
        err = insert_ipopt_uoa(conn, mbuf, iph, uh, rt->mtu);
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
    struct iphdr *iph = (void *)ip4_hdr(mbuf);
    struct opphdr *opp = NULL;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;

    if (iph->protocol == IPPROTO_UDP) {
        uh = (void *)iph + ip4_hdrlen(mbuf);
    } else if (iph->protocol == IPPROTO_OPT) {
        opp = (void *)iph + ip4_hdrlen(mbuf);

        uh = (void *)opp + ntohs(opp->length);
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
    if (!opp)
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

    return EDPVS_OK;
}

static int udp_fnat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->vport;
    uh->dst_port    = conn->cport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

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

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->dst_port    = conn->dport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

    return EDPVS_OK;
}

static int udp_snat_out_handler(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct udp_hdr *uh;

    /* cannot use mbuf_header_pointer() */
    if (unlikely(mbuf->data_len < ip4_hdrlen(mbuf) + sizeof(struct udp_hdr)))
        return EDPVS_INVPKT;
    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, ip4_hdrlen(mbuf));
    if (unlikely(!uh))
        return EDPVS_INVPKT;

    uh->src_port    = conn->vport;

    uh->dgram_cksum = 0;
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ip4_hdr(mbuf), uh);

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
