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
#include <netinet/ip_icmp.h>
#include "common.h"
#include "ipv4.h"
#include "icmp.h"
#include "sa_pool.h"
#include "ipvs/ipvs.h"
#include "ipvs/conn.h"
#include "ipvs/proto.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/xmit.h"
#include "ipvs/synproxy.h"
#include "ipvs/blklst.h"
#include "ipvs/proto_udp.h"

#define icmp4_id(icmph)      (((icmph)->un).echo.id)

static inline int dp_vs_fill_iphdr(int af, const struct rte_mbuf *mbuf, 
                                   struct dp_vs_iphdr *iph)
{
    if (af == AF_INET) {
        const struct ipv4_hdr *ip4h = ip4_hdr(mbuf);
        iph->af     = AF_INET;
        iph->len    = ip4_hdrlen(mbuf);
        iph->proto  = ip4h->next_proto_id;
        iph->saddr.in.s_addr = ip4h->src_addr;
        iph->daddr.in.s_addr = ip4h->dst_addr;
    } else {
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

/*
 * IPVS persistent scheduling funciton.
 * It create a connection entry according to its template if exists,
 * or selects a server and creates a connection entry plus a template.
 */
static struct dp_vs_conn *dp_vs_sched_persist(struct dp_vs_service *svc,
        const struct dp_vs_iphdr *iph, struct rte_mbuf *mbuf, bool is_synproxy_on)
{
    uint32_t conn_flags;
    uint16_t _ports[2], *ports;
    uint16_t dport;
    struct dp_vs_dest *dest;
    struct dp_vs_conn *conn, *ct;
    struct dp_vs_conn_param param;
    union inet_addr snet;   /* source network of eth client after masking */
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], dbuf[64], maskbuf[64];
#endif

    assert(svc && iph && mbuf);

    conn_flags = (is_synproxy_on ? DPVS_CONN_F_SYNPROXY : 0);
    if (svc->af == AF_INET6) {
        RTE_LOG(ERR, IPVS, "%s: IPv6 is not supported!\n", __func__);
        return NULL;
    } else {
        snet.in.s_addr = iph->saddr.in.s_addr & svc->netmask;
    }

    ports = mbuf_header_pointer(mbuf, iph->len, sizeof(_ports), _ports);
    if (!ports)
        return NULL;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "%s: persist-schedule: src %s:%u dest %s:%u snet %s\n",
            __func__,
            inet_ntop(svc->af, &iph->saddr, sbuf, sizeof(sbuf)),
            ntohs(ports[0]),
            inet_ntop(svc->af, &iph->daddr, dbuf, sizeof(dbuf)),
            ntohs(ports[1]),
            inet_ntop(svc->af, &snet, maskbuf, sizeof(maskbuf)));
#endif

    if (ports[1] == svc->port) {
        /* regular persistent service: <proto, caddr, 0, vaddr, vport, daddr, dport> */
        ct = dp_vs_ct_in_get(svc->af, iph->proto, &snet, &iph->daddr, 0, ports[1]);
        if (!ct || !dp_vs_check_template(ct)) {
            /* no template found, or the dest of the conn template is not available */
            dest = svc->scheduler->schedule(svc, mbuf);
            if (unlikely(NULL == dest)) {
                RTE_LOG(WARNING, IPVS, "%s: persist-schedule: no dest found.\n", __func__);
                return NULL;
            }
            /* create a conn template */
            dp_vs_conn_fill_param(iph->af, iph->proto, &snet, &iph->daddr,
                    0, ports[1], 0, &param);

            ct = dp_vs_conn_new(mbuf, &param, dest, conn_flags | DPVS_CONN_F_TEMPLATE);
            if(unlikely(NULL == ct))
                return NULL;

            ct->timeout.tv_sec = svc->timeout;
        } else {
            /* set destination with the found template */
            dest = ct->dest;
        }
        dport = dest->port;
    } else {
        /* port zero service: <proto, caddr, 0, vaddr, 0, daddr, 0>
         * fw-mark based service: not support */
        ct = dp_vs_ct_in_get(svc->af, iph->proto, &snet, &iph->daddr, 0, 0);
        if (!ct || !dp_vs_check_template(ct)) {
            dest = svc->scheduler->schedule(svc, mbuf);
            if (unlikely(NULL == dest)) {
                RTE_LOG(WARNING, IPVS, "%s: persist-schedule: no dest found.\n", __func__);
                return NULL;
            }
            /* create a conn template */
            dp_vs_conn_fill_param(iph->af, iph->proto, &snet, &iph->daddr,
                    0, 0, 0, &param);

            ct = dp_vs_conn_new(mbuf, &param, dest, conn_flags | DPVS_CONN_F_TEMPLATE);
            if(unlikely(NULL == ct))
                return NULL;

            ct->timeout.tv_sec = svc->timeout;
        } else {
            /* set destination with the found template */
            dest = ct->dest;
        }
        dport = ports[1];
    }

    /* create a new connection according to the template */
    dp_vs_conn_fill_param(iph->af, iph->proto, &iph->saddr, &iph->daddr,
            ports[0], ports[1], dport, &param);

    conn = dp_vs_conn_new(mbuf, &param, dest, conn_flags);
    if (unlikely(NULL == conn)) {
        dp_vs_conn_put(ct);
        return NULL;
    }

    /* add control for the new connection */
    dp_vs_control_add(conn, ct);
    dp_vs_conn_put(ct);

    dp_vs_stats_conn(conn);

    return conn;
}

/* select an RS by service's scheduler and create a connection */
struct dp_vs_conn *dp_vs_schedule(struct dp_vs_service *svc, 
                                  const struct dp_vs_iphdr *iph,
                                  struct rte_mbuf *mbuf,
                                  bool is_synproxy_on)
{
    uint16_t _ports[2], *ports; /* sport, dport */
    struct dp_vs_dest *dest;
    struct dp_vs_conn *conn;
    struct dp_vs_conn_param param;
    struct sockaddr_in daddr, saddr;
    int err;

    assert(svc && iph && mbuf);

    ports = mbuf_header_pointer(mbuf, iph->len, sizeof(_ports), _ports);
    if (!ports)
        return NULL;
        
    /* persistent service */
    if (svc->flags & DP_VS_SVC_F_PERSISTENT)
        return dp_vs_sched_persist(svc, iph,  mbuf, is_synproxy_on);

    dest = svc->scheduler->schedule(svc, mbuf);
    if (!dest) {
        RTE_LOG(WARNING, IPVS, "%s: no dest found.\n", __func__);
        return NULL;
    }
        
    if (dest->fwdmode == DPVS_FWD_MODE_SNAT) {
        if (unlikely(iph->proto == IPPROTO_ICMP)) {
            struct icmphdr *ich, _icmph;
            ich = mbuf_header_pointer(mbuf, iph->len, sizeof(_icmph), &_icmph);
            if (!ich)
                return NULL;

            ports = _ports;
            _ports[0] = icmp4_id(ich);
            _ports[1] = ich->type << 8 | ich->code;

            /* ID may confict for diff host,
             * need we use ID pool ? */
            dp_vs_conn_fill_param(iph->af, iph->proto,
                                  &iph->daddr, &dest->addr,
                                  ports[1], ports[0],
                                  0, &param);
        } else {
            /* we cannot inherit dest (host's src port),
             * that may confict for diff hosts,
             * and using dest->port is worse choice. */
            memset(&daddr, 0, sizeof(daddr));
            daddr.sin_family = AF_INET;
            daddr.sin_addr = iph->daddr.in;
            daddr.sin_port = ports[1];
            memset(&saddr, 0, sizeof(saddr));
            saddr.sin_family = AF_INET;
            saddr.sin_addr = dest->addr.in;
            saddr.sin_port = 0;

            err = sa_fetch(NULL, &daddr, &saddr);
            if (err != 0)
                return NULL;

            dp_vs_conn_fill_param(iph->af, iph->proto,
                                  &iph->daddr, &dest->addr,
                                  ports[1], saddr.sin_port,
                                  0, &param);
        }
    } else {
        if (unlikely(iph->proto == IPPROTO_ICMP)) {
            struct icmphdr *ich, _icmph;
            ich = mbuf_header_pointer(mbuf, iph->len, sizeof(_icmph), &_icmph);
            if (!ich)
                return NULL;

            ports = _ports;
            _ports[0] = icmp4_id(ich);
            _ports[1] = ich->type << 8 | ich->code;

            dp_vs_conn_fill_param(iph->af, iph->proto,
                                  &iph->saddr, &iph->daddr,
                                  ports[0], ports[1], 0, &param);
        } else {
            dp_vs_conn_fill_param(iph->af, iph->proto,
                                  &iph->saddr, &iph->daddr,
                                  ports[0], ports[1], 0, &param);
        }
    }

    conn = dp_vs_conn_new(mbuf, &param, dest,
            is_synproxy_on ? DPVS_CONN_F_SYNPROXY : 0);
    if (!conn) {
        if (dest->fwdmode == DPVS_FWD_MODE_SNAT && iph->proto != IPPROTO_ICMP)
            sa_release(NULL, &daddr, &saddr);
        return NULL;
    }

    dp_vs_stats_conn(conn);
    return conn;
}

/* return verdict INET_XXX */
static int xmit_outbound(struct rte_mbuf *mbuf, 
                          struct dp_vs_proto *prot, 
                          struct dp_vs_conn *conn)
{
    int err;
    assert(mbuf && prot && conn);

    if (dp_vs_stats_out(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    } 
    if (!conn->packet_out_xmit) {
        RTE_LOG(WARNING, IPVS, "%s: missing out_xmit\n", __func__);
        dp_vs_conn_put(conn);
        return INET_ACCEPT;
    }

    err = conn->packet_out_xmit(prot, conn, mbuf);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to out xmit: %d\n", __func__, err);

    dp_vs_conn_put(conn);
    /* always stolen the packet */
    return INET_STOLEN;
}

/* return verdict INET_XXX */
static int xmit_inbound(struct rte_mbuf *mbuf,
                          struct dp_vs_proto *prot,
                          struct dp_vs_conn *conn)
{
    int err;
    assert(mbuf && prot && conn);

    if (dp_vs_stats_in(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    }
      
    /* is dest avaible to forward the packet ? */
    if (!conn->dest) {
        /* silently drop packet without reset connection timer.
         * wait for dest available or connection timeout. */
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    if (!conn->packet_xmit) {
        RTE_LOG(WARNING, IPVS, "%s: missing packet_xmit\n", __func__);
        dp_vs_conn_put(conn);
        return INET_ACCEPT;
    }

    /* forward to RS */
    err = conn->packet_xmit(prot, conn, mbuf);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to transmit: %d\n", __func__, err);

    dp_vs_conn_put(conn);
    /* always stolen the packet */
    return INET_STOLEN;
}

/* mbuf should be consumed here. */
static int xmit_outbound_icmp(struct rte_mbuf *mbuf, 
                              struct dp_vs_proto *prot, 
                              struct dp_vs_conn *conn)
{
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);

    /* no translation needed for DR/TUN. */
    if (conn->dest->fwdmode != DPVS_FWD_MODE_FNAT && 
        conn->dest->fwdmode != DPVS_FWD_MODE_NAT  &&
        conn->dest->fwdmode != DPVS_FWD_MODE_SNAT) {
        if (!conn->packet_out_xmit) {
            RTE_LOG(WARNING, IPVS, "%s: missing packet_out_xmit\n", __func__);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }

        return conn->packet_out_xmit(prot, conn, mbuf);
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.daddr = conn->caddr.in;
    fl4.saddr = conn->vaddr.in;
    fl4.tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROUTE;
    }

    if ((mbuf->pkt_len > rt->mtu) 
            && (ip4_hdr(mbuf)->fragment_offset & IPV4_HDR_DF_FLAG)) {
        route4_put(rt);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, 
                  htonl(rt->mtu));
        rte_pktmbuf_free(mbuf);
        return EDPVS_FRAG;
    }

    if (unlikely(mbuf->userdata != NULL))
        route4_put((struct route_entry *)mbuf->userdata);
    mbuf->userdata = rt;

    /* translation for outer L3, ICMP, and inner L3 and L4 */
    dp_vs_xmit_icmp(mbuf, prot, conn, DPVS_CONN_DIR_OUTBOUND);

    return INET_HOOK(INET_HOOK_LOCAL_OUT, mbuf, NULL, rt->port, ipv4_output);
}

/* mbuf should be consumed here. */
static int xmit_inbound_icmp(struct rte_mbuf *mbuf, 
                             struct dp_vs_proto *prot, 
                             struct dp_vs_conn *conn)
{
    struct flow4 fl4;
    struct route_entry *rt = NULL;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);

    /* no translation needed for DR/TUN. */
    if (conn->dest->fwdmode != DPVS_FWD_MODE_NAT  && 
	conn->dest->fwdmode != DPVS_FWD_MODE_FNAT &&
	conn->dest->fwdmode != DPVS_FWD_MODE_SNAT) {
        if (!conn->packet_xmit) {
            RTE_LOG(WARNING, IPVS, "%s: missing packet_xmit\n", __func__);
            rte_pktmbuf_free(mbuf);
            return EDPVS_NOTSUPP;
        }

        return conn->packet_xmit(prot, conn, mbuf);
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.daddr = conn->daddr.in;
    fl4.saddr = conn->laddr.in;
    fl4.tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROUTE;
    }

    if ((mbuf->pkt_len > rt->mtu) 
            && (ip4_hdr(mbuf)->fragment_offset & IPV4_HDR_DF_FLAG)) {
        route4_put(rt);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, 
                  htonl(rt->mtu));
        rte_pktmbuf_free(mbuf);
        return EDPVS_FRAG;
    }

    if (unlikely(mbuf->userdata != NULL))
        route4_put((struct route_entry *)mbuf->userdata);
    mbuf->userdata = rt;

    /* translation for outer L3, ICMP, and inner L3 and L4 */
    dp_vs_xmit_icmp(mbuf, prot, conn, DPVS_CONN_DIR_INBOUND);

    return INET_HOOK(INET_HOOK_LOCAL_OUT, mbuf, NULL, rt->port, ipv4_output);
}

/* return verdict INET_XXX */
static int dp_vs_in_icmp(struct rte_mbuf *mbuf, int *related)
{
    struct icmphdr *ich, _icmph;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct ipv4_hdr *ciph, _ciph;
    struct dp_vs_iphdr dciph;
    struct dp_vs_proto *prot;
    struct dp_vs_conn *conn;
    int off, dir, err;
    bool drop = false;

    *related = 0; /* not related until found matching conn */

    if (unlikely(ip4_is_frag(iph))) {
        if (ip4_defrag(mbuf, IP_DEFRAG_VS_FWD) != EDPVS_OK)
            return INET_STOLEN;
        iph = ip4_hdr(mbuf); /* reload with new mbuf */
        ip4_send_csum(iph);
    }

    off = ip4_hdrlen(mbuf);
    ich = mbuf_header_pointer(mbuf, off, sizeof(_icmph), &_icmph);
    if (unlikely(!ich))
        return INET_DROP;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "ICMP (%d,%d) %08X->%08X\n",
            ich->type, ntohs(icmp4_id(ich)), iph->src_addr, iph->dst_addr);
#endif

    /* support these related error types only,
     * others either not support or not related. */
    if (ich->type != ICMP_DEST_UNREACH
            && ich->type != ICMP_SOURCE_QUENCH
            && ich->type != ICMP_TIME_EXCEEDED)
        return INET_ACCEPT;

    /* inner (contained) IP header */
    off += sizeof(struct icmphdr);
    ciph = mbuf_header_pointer(mbuf, off, sizeof(_ciph), &_ciph);
    if (unlikely(!ciph))
        return INET_ACCEPT;

    prot = dp_vs_proto_lookup(ciph->next_proto_id);
    if (!prot)
        return INET_ACCEPT;

    if (unlikely((ciph->fragment_offset & htons(IPV4_HDR_OFFSET_MASK)))) {
        RTE_LOG(WARNING, IPVS, "%s: frag needed.\n", __func__);
        return INET_DROP;
    }

    /* 
     * lookup conn with inner IP pkt.
     * it need to move mbuf.data_off to inner IP pkt, 
     * and restore it later. although it looks strange.
     */
    rte_pktmbuf_adj(mbuf, off);
    if (mbuf_may_pull(mbuf, sizeof(struct ipv4_hdr)) != 0)
        return INET_DROP;
    dp_vs_fill_iphdr(AF_INET, mbuf, &dciph);

    conn = prot->conn_lookup(prot, &dciph, mbuf, &dir, true, &drop);
    if (!conn)
        return INET_ACCEPT;

    /* recover mbuf.data_off to outer IP header. */
    rte_pktmbuf_prepend(mbuf, off);

    /* so the ICMP is related to existing conn */
    *related = 1;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0) {
        RTE_LOG(WARNING, IPVS, "%s: may_pull icmp error\n", __func__);
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    if (rte_raw_cksum(ich, mbuf->pkt_len - ip4_hdrlen(mbuf)) != 0xffff) {
        RTE_LOG(DEBUG, IPVS, "%s: bad checksum\n", __func__);
        dp_vs_conn_put_no_reset(conn);
        return INET_DROP;
    }

    if (dp_vs_stats_in(conn, mbuf)) {
        dp_vs_conn_put(conn);
        return INET_DROP;
    }
    /* note 
     * 1. the direction of inner IP pkt is reversed with ICMP pkt.
     * 2. but we use (@reverse == true) for prot->conn_lookup()
     * as a result, @dir is same with icmp packet. */
    if (dir == DPVS_CONN_DIR_INBOUND)
        err = xmit_inbound_icmp(mbuf, prot, conn);
    else
        err = xmit_outbound_icmp(mbuf, prot, conn);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, IPVS, "%s: xmit icmp error: %s\n", 
                __func__, dpvs_strerror(err));

    dp_vs_conn_put_no_reset(conn);
    return INET_STOLEN;
}

/* return verdict INET_XXX */
static int dp_vs_in(void *priv, struct rte_mbuf *mbuf, 
                    const struct inet_hook_state *state)
{
    struct dp_vs_iphdr iph;
    struct dp_vs_proto *prot;
    struct dp_vs_conn *conn;
    int dir, af, verdict, err, related;
    bool drop = false;
    eth_type_t etype = mbuf->packet_type; /* FIXME: use other field ? */
    assert(mbuf && state);

    /* cannot use mbuf->l3_type which is conflict with m.packet_type
     * or using wrapper to avoid af check here */
    /* af = mbuf->l3_type == htons(ETHER_TYPE_IPv4) ? AF_INET : AF_INET6; */
    af = AF_INET;

    if (unlikely(etype != ETH_PKT_HOST))
        return INET_ACCEPT;

    if (dp_vs_fill_iphdr(af, mbuf, &iph) != EDPVS_OK)
        return INET_ACCEPT;

    if (unlikely(iph.proto == IPPROTO_ICMP)) {
        /* handle related ICMP error to existing conn */
        verdict = dp_vs_in_icmp(mbuf, &related);
        if (related || verdict != INET_ACCEPT)
            return verdict;
        /* let unrelated and valid ICMP goes down, 
         * may implement ICMP fwd in the futher. */
    }

    prot = dp_vs_proto_lookup(iph.proto);
    if (unlikely(!prot))
        return INET_ACCEPT;

    /*
     * Defrag ipvs-forwarding TCP/UDP is not supported for some reasons,
     *
     * - RSS/flow-director do not support TCP/UDP fragments, means it's
     *   not able to direct frags to same lcore as original TCP/UDP packets.
     * - per-lcore conn table will miss if frags reachs wrong lcore.
     *
     * If we redirect frags to "correct" lcore, it may cause performance
     * issue. Also it need to understand RSS algorithm. Moreover, for the
     * case frags in same flow are not occur in same lcore, a global lock is
     * needed, which is not a good idea.
     */
    if (ip4_is_frag(ip4_hdr(mbuf))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag not support.\n", __func__);
        return INET_DROP;
    }

    /* packet belongs to existing connection ? */
    conn = prot->conn_lookup(prot, &iph, mbuf, &dir, false, &drop);

    if (unlikely(drop)) {
        RTE_LOG(DEBUG, IPVS, "%s: deny ip try to visit.\n", __func__);
        return INET_DROP;
    }

    if (unlikely(!conn)) {
        /* try schedule RS and create new connection */
        if (prot->conn_sched(prot, &iph, mbuf, &conn, &verdict) != EDPVS_OK) {
            /* RTE_LOG(DEBUG, IPVS, "%s: fail to schedule.\n", __func__); */
            return verdict;
        }

        /* only SNAT triggers connection by inside-outside traffic. */
        if (conn->dest->fwdmode == DPVS_FWD_MODE_SNAT)
            dir = DPVS_CONN_DIR_OUTBOUND;
        else
            dir = DPVS_CONN_DIR_INBOUND;
    }

    if (conn->flags & DPVS_CONN_F_SYNPROXY) {
        if (dir == DPVS_CONN_DIR_INBOUND) {
            /* Filter out-in ack packet when cp is at SYN_SENT state.
             * Drop it if not a valid packet, store it otherwise */
            if (0 == dp_vs_synproxy_filter_ack(mbuf, conn, prot,
                                               &iph, &verdict)) {
                dp_vs_stats_in(conn, mbuf);
                dp_vs_conn_put(conn);
                return verdict;
            }

            /* "Reuse" synproxy sessions.
             * "Reuse" means update syn_proxy_seq struct
             * and clean ack_mbuf etc. */
            if (0 != dp_vs_synproxy_ctrl_conn_reuse) {
                if (0 == dp_vs_synproxy_reuse_conn(af, mbuf, conn, prot,
                                                   &iph, &verdict)) {
                    dp_vs_stats_in(conn, mbuf);
                    dp_vs_conn_put(conn);
                    return verdict;
                }
            }
        } else {
            /* Syn-proxy 3 logic: receive syn-ack from rs */
            if (dp_vs_synproxy_synack_rcv(mbuf, conn, prot,
                                          ip4_hdrlen(mbuf), &verdict) == 0) {
                dp_vs_stats_out(conn, mbuf);
                dp_vs_conn_put(conn);
                return verdict;
            }
        }
    }

    if (prot->state_trans) {
        err = prot->state_trans(prot, conn, mbuf, dir);
        if (err != EDPVS_OK)
            RTE_LOG(WARNING, IPVS, "%s: fail to trans state.", __func__);
    }
    conn->old_state = conn->state;

    /* holding the conn, need a "put" later. */
    if (dir == DPVS_CONN_DIR_INBOUND)
        return xmit_inbound(mbuf, prot, conn);
    else
        return xmit_outbound(mbuf, prot, conn);
}

static int dp_vs_pre_routing(void *priv, struct rte_mbuf *mbuf,
                    const struct inet_hook_state *state)
{
    struct dp_vs_iphdr iph;
    int af;
    struct dp_vs_service *svc;

    af = AF_INET;
    if (EDPVS_OK != dp_vs_fill_iphdr(af, mbuf, &iph))
        return INET_ACCEPT;

    /* Drop all ip fragment except ospf */
    if ((af == AF_INET) && ip4_is_frag(ip4_hdr(mbuf))
            && (iph.proto != IPPROTO_OSPF)) {
        dp_vs_estats_inc(DEFENCE_IP_FRAG_DROP);
        return INET_DROP;
    }

    /* Drop udp packet which send to tcp-vip */
    if (g_defence_udp_drop && IPPROTO_UDP == iph.proto) {
        if ((svc = dp_vs_lookup_vip(af, IPPROTO_UDP, &iph.daddr)) == NULL) {
            if ((svc = dp_vs_lookup_vip(af, IPPROTO_TCP, &iph.daddr)) != NULL) {
                dp_vs_estats_inc(DEFENCE_UDP_DROP);
                return INET_DROP;
            }
        }
    }

    /* Synproxy: defence synflood */
    if (IPPROTO_TCP == iph.proto) {
        int v = INET_ACCEPT;
        if (0 == dp_vs_synproxy_syn_rcv(af, mbuf, &iph, &v))
            return v;
    }

    return INET_ACCEPT;
}

static struct inet_hook_ops dp_vs_ops[] = {
    {
        .hook       = dp_vs_in,
        .hooknum    = INET_HOOK_PRE_ROUTING,
        .priority   = 100,
    },
    {
        .hook       = dp_vs_pre_routing,
        .hooknum    = INET_HOOK_PRE_ROUTING,
        .priority   = 99,
    },
};

int dp_vs_init(void)
{
    int err;

    err = dp_vs_proto_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init proto: %s\n", dpvs_strerror(err));
        return err;
    }

    err = dp_vs_laddr_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init laddr: %s\n", dpvs_strerror(err));
        goto err_laddr;
    }

    err = dp_vs_conn_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init conn: %s\n", dpvs_strerror(err));
        goto err_conn;
    }

    err = dp_vs_synproxy_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init synproxy: %s\n", dpvs_strerror(err));
        goto err_synproxy;
    }

    err = dp_vs_sched_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init sched: %s\n", dpvs_strerror(err));
        goto err_sched;
    }

    err = dp_vs_service_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init serv: %s\n", dpvs_strerror(err));
        goto err_serv;
    }
    err = dp_vs_blklst_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init blklst: %s\n", dpvs_strerror(err));
        goto err_blklst;
    }
    err = dp_vs_stats_init();
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to init stats: %s\n", dpvs_strerror(err));
        goto err_stats;
    }
    err = ipv4_register_hooks(dp_vs_ops, NELEMS(dp_vs_ops));
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to register hooks: %s\n", dpvs_strerror(err));
        goto err_hooks;
    }

    RTE_LOG(DEBUG, IPVS, "ipvs inialized.\n");
    return EDPVS_OK;

err_hooks:
    dp_vs_stats_term();
err_stats:
    dp_vs_service_term();
err_blklst:
    dp_vs_blklst_term();
err_serv:
    dp_vs_sched_term();
err_sched:
    dp_vs_synproxy_term();
err_synproxy:
    dp_vs_conn_term();
err_conn:
    dp_vs_laddr_term();
err_laddr:
    dp_vs_proto_term();

    return err;
}

int dp_vs_term(void)
{
    int err;

    err = ipv4_unregister_hooks(dp_vs_ops, NELEMS(dp_vs_ops));
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to unregister hooks: %s\n", dpvs_strerror(err));

    err = dp_vs_stats_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate term: %s\n", dpvs_strerror(err));

    err = dp_vs_blklst_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate blklst: %s\n", dpvs_strerror(err)); 

    err = dp_vs_service_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate serv: %s\n", dpvs_strerror(err));

    err = dp_vs_sched_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate sched: %s\n", dpvs_strerror(err));

    err = dp_vs_synproxy_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate synproxy: %s\n", dpvs_strerror(err));

    err = dp_vs_conn_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate conn: %s\n", dpvs_strerror(err));

    err = dp_vs_laddr_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate laddr: %s\n", dpvs_strerror(err));

    err = dp_vs_proto_term();
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPVS, "fail to terminate proto: %s\n", dpvs_strerror(err));

    RTE_LOG(ERR, IPVS, "ipvs terminated.\n");
    return err;
}
