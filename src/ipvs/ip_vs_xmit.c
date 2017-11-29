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
#include <netinet/ip_icmp.h>
#include <assert.h>
#include "dpdk.h"
#include "ipv4.h"
#include "route.h"
#include "icmp.h"
#include "neigh.h"
#include "ipvs/xmit.h"
#include "parser/parser.h"

static bool fast_xmit_close = false;

static int dp_vs_fast_xmit_fnat(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct ether_hdr *eth;
    int err;

    if(unlikely(conn->in_dev == NULL))
        return EDPVS_NOROUTE;

    iph->hdr_checksum = 0;
    iph->src_addr = conn->laddr.in.s_addr;
    iph->dst_addr = conn->daddr.in.s_addr;

    if(proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct ether_hdr));
    ether_addr_copy(&conn->in_dmac, &eth->d_addr);
    ether_addr_copy(&conn->in_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    mbuf->packet_type = ETHER_TYPE_IPv4;

    err = netif_xmit(mbuf, conn->in_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

static int dp_vs_fast_outxmit_fnat(struct dp_vs_proto *proto,
                          struct dp_vs_conn *conn,
                          struct rte_mbuf *mbuf)
{
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct ether_hdr *eth;
    int err;

    /*need to judge?*/
    if(unlikely(conn->out_dev == NULL))
        return EDPVS_NOROUTE;

    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;
    iph->dst_addr = conn->caddr.in.s_addr;

    if(proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if(err != EDPVS_OK)
            return err;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf,
                    (uint16_t)sizeof(struct ether_hdr));
    ether_addr_copy(&conn->out_dmac, &eth->d_addr);
    ether_addr_copy(&conn->out_smac, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    mbuf->packet_type = ETHER_TYPE_IPv4;
    
    err = netif_xmit(mbuf, conn->out_dev);
    if (err != EDPVS_OK)
        RTE_LOG(DEBUG, IPVS, "%s: fail to netif_xmit.\n", __func__);

    /* must return OK since netif_xmit alway consume mbuf */
    return EDPVS_OK;
}

/*ARP_HDR_ETHER SUPPORT ONLY
 *save source mac(client) for output in conn as dest mac
 *save port for output
 * */
static void dp_vs_save_xmit_info(struct rte_mbuf *mbuf, 
                          struct dp_vs_proto *proto,
                          struct dp_vs_conn *conn)
{
    struct ether_hdr *eth = NULL;
    struct netif_port *port = NULL;

    if (conn->out_dev)
        return;

    if (unlikely(mbuf->l2_len != sizeof(struct ether_hdr)))
        return;

    port = netif_port_get(mbuf->port);
    if (!port)
        return;

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, mbuf->l2_len);

    conn->out_dev = port;
    ether_addr_copy(&eth->s_addr, &conn->out_dmac);
    ether_addr_copy(&eth->d_addr, &conn->out_smac);
   
    rte_pktmbuf_adj(mbuf, sizeof(struct ether_hdr));
}

/*save source mac(rs) for input in conn as dest mac
 *save port for output
 */
static void dp_vs_save_outxmit_info(struct rte_mbuf *mbuf,
                             struct dp_vs_proto *proto,
                             struct dp_vs_conn *conn)
{
    struct ether_hdr *eth = NULL;
    struct netif_port *port = NULL;

    if (conn->in_dev)
        return;

    if (mbuf->l2_len != sizeof(struct ether_hdr))
        return;

    port = netif_port_get(mbuf->port);
    if (!port)
        return;

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, mbuf->l2_len);
    
    conn->in_dev = port;    
    ether_addr_copy(&eth->s_addr, &conn->in_dmac);
    ether_addr_copy(&eth->d_addr, &conn->in_smac);

    rte_pktmbuf_adj(mbuf, sizeof(struct ether_hdr));
}

int dp_vs_xmit_fnat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (!fast_xmit_close) {
        dp_vs_save_xmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_xmit_fnat(proto, conn, mbuf))
            return EDPVS_OK;
    }

    /* drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route. */
    if (unlikely(mbuf->userdata != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: FNAT have route %p ?\n", 
                __func__, mbuf->userdata);
        route4_put((struct route_entry *)mbuf->userdata);
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.daddr = conn->daddr.in;
    fl4.saddr = conn->laddr.in;
    fl4.tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    mbuf->userdata = rt;

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->laddr.in.s_addr;
    iph->dst_addr = conn->daddr.in.s_addr;

    /* L4 FNAT translation */
    if (proto->fnat_in_handler) {
        err = proto->fnat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }

    return INET_HOOK(INET_HOOK_LOCAL_OUT, mbuf, NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_out_xmit_fnat(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    if (!fast_xmit_close) {
        dp_vs_save_outxmit_info(mbuf, proto, conn);
        if (!dp_vs_fast_outxmit_fnat(proto, conn, mbuf))
            return EDPVS_OK;
    }

    /* drop old route. just for safe, because
     * FNAT is PRE_ROUTING, should not have route. */
    if (unlikely(mbuf->userdata != NULL))
        route4_put((struct route_entry *)mbuf->userdata);

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.daddr = conn->caddr.in;
    fl4.saddr = conn->vaddr.in;
    fl4.tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    mbuf->userdata = rt;

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;
    iph->dst_addr = conn->caddr.in.s_addr;

    /* L4 FNAT translation */
    if (proto->fnat_out_handler) {
        err = proto->fnat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM)) {
        iph->hdr_checksum = 0;
    } else {
        ip4_send_csum(iph);
    }


    return INET_HOOK(INET_HOOK_LOCAL_OUT, mbuf, NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

/* mbuf's data should pointer to outer IP packet. */
void dp_vs_xmit_icmp(struct rte_mbuf *mbuf, struct dp_vs_proto *prot,
                     struct dp_vs_conn *conn, int dir)
{
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct icmphdr *icmph = (struct icmphdr *)
                            ((unsigned char *)ip4_hdr(mbuf) + ip4_hdrlen(mbuf));
    struct ipv4_hdr *ciph = (struct ipv4_hdr *)(icmph + 1);
    int fullnat = (conn->dest->fwdmode == DPVS_FWD_MODE_FNAT);
    uint16_t csum;

    /* 
     * outer/inner L3 translation.
     */
    if (fullnat) {
        if (dir == DPVS_CONN_DIR_INBOUND) {
            iph->src_addr = conn->laddr.in.s_addr;
            ciph->dst_addr = conn->laddr.in.s_addr;
        } else {
            iph->dst_addr = conn->caddr.in.s_addr;
            ciph->src_addr = conn->caddr.in.s_addr;
        }
    }

    if (dir == DPVS_CONN_DIR_INBOUND) {
        iph->dst_addr = conn->daddr.in.s_addr;
        ip4_send_csum(iph);
        ciph->src_addr = conn->daddr.in.s_addr;
        ip4_send_csum(ciph);
    } else {
        iph->src_addr = conn->vaddr.in.s_addr;
        ip4_send_csum(iph);
        ciph->dst_addr = conn->vaddr.in.s_addr;
        ip4_send_csum(ciph);
    }

    /* 
     * inner L4 translation.
     *
     * note it's no way to recalc inner csum to lack of data,
     * actually it's not needed.
     */
    if (ciph->next_proto_id == IPPROTO_TCP
            || ciph->next_proto_id == IPPROTO_UDP) {
        uint16_t *ports = (void *)ciph + \
                          ((ciph->version_ihl & IPV4_HDR_IHL_MASK)<<2);

        if (fullnat) {
            if (dir == DPVS_CONN_DIR_INBOUND) {
                ports[1] = conn->lport;
            } else {
                ports[0] = conn->cport;
                /* seq adjustment (changed by FNAT) */
                if (ciph->next_proto_id == IPPROTO_TCP) {
                    uint32_t *seq = (uint32_t *)ports + 1;
                    *seq = htonl(ntohl(*seq) - conn->fnat_seq.delta);
                }
            }
        }

        if (dir == DPVS_CONN_DIR_INBOUND) {
            ports[0] = conn->dport;
            /* seq adjustment (changed by SynProxy) */
            if (ciph->next_proto_id == IPPROTO_TCP) {
                uint32_t *seq = (uint32_t *)ports + 1;
                *seq = htonl(ntohl(*seq) - conn->syn_proxy_seq.delta);
            }
        } else {
            ports[1] = conn->vport;
        }
    }

    /* 
     * ICMP recalc csum.
     */
    icmph->checksum = 0;
    csum = rte_raw_cksum(icmph, mbuf->pkt_len - ip4_hdrlen(mbuf));
    icmph->checksum = (csum == 0xffff) ? csum : ~csum;

    return;
}

int dp_vs_xmit_dr(struct dp_vs_proto *proto,
                   struct dp_vs_conn *conn,
                   struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;
    
    if (unlikely(mbuf->userdata != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: Already have route %p ?\n",
                __func__, mbuf->userdata);
        route4_put((struct route_entry *)mbuf->userdata);
    }

    memset(&fl4, 0, sizeof(struct flow4));
    fl4.daddr.s_addr = conn->daddr.in.s_addr;
    fl4.saddr.s_addr = iph->src_addr;
    fl4.tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    mbuf->packet_type = ETHER_TYPE_IPv4;
    err = neigh_resolve_output(&conn->daddr.in, mbuf, rt->port);
    if (rt)
        route4_put(rt);
    return err; 

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;        
}

int dp_vs_xmit_snat(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    struct flow4 fl4;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt;
    int err, mtu;

    /* drop old route. just for safe, because
     * inbound SNAT traffic is hooked at PRE_ROUTING,
     * should not have route. */
    if (unlikely(mbuf->userdata != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: SNAT have route %p ?\n",
                __func__, mbuf->userdata);
        route4_put((struct route_entry *)mbuf->userdata);
    }

    /* hosts inside SNAT may belongs to diff net,
     * let's route it. */
    memset(&fl4, 0, sizeof(struct flow4));
    fl4.daddr = conn->daddr.in;
    fl4.saddr = conn->caddr.in;
    fl4.tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }

    mtu = rt->mtu;
    if (mbuf->pkt_len > mtu
            && (iph->fragment_offset & htons(IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG, htonl(mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    mbuf->userdata = rt;

    /* L3 translation before l4 re-csum */
    iph->hdr_checksum = 0;
    iph->dst_addr = conn->daddr.in.s_addr;

    /* L4 translation */
    if (proto->snat_in_handler) {
        err = proto->snat_in_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    /* L3 re-checksum */
    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
        iph->hdr_checksum = 0;
    else
        ip4_send_csum(iph);

    return INET_HOOK(INET_HOOK_LOCAL_OUT, mbuf, NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

int dp_vs_out_xmit_snat(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf)
{
    int err;
    struct flow4 fl4;
    struct route_entry *rt = mbuf->userdata;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);

    if (!rt) {
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.daddr = conn->caddr.in;
        fl4.saddr = conn->vaddr.in;
        fl4.tos = iph->type_of_service;
        rt = route4_output(&fl4);
        if (!rt) {
            err = EDPVS_NOROUTE;
            goto errout;
        }

        mbuf->userdata = rt;
    }

    if (mbuf->pkt_len > rt->mtu &&
            (iph->fragment_offset & htons(IPV4_HDR_DF_FLAG))) {
        RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                  htonl(rt->mtu));
        err = EDPVS_FRAG;
        goto errout;
    }

    /* L3 translation before L4 re-csum */
    iph->hdr_checksum = 0;
    iph->src_addr = conn->vaddr.in.s_addr;

    /* L4 translation */
    if (proto->snat_out_handler) {
        err = proto->snat_out_handler(proto, conn, mbuf);
        if (err != EDPVS_OK)
            goto errout;
    }

    /* L3 re-checksum */
    if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
        iph->hdr_checksum = 0;
    else
        ip4_send_csum(iph);

    return INET_HOOK(INET_HOOK_LOCAL_OUT, mbuf, NULL, rt->port, ipv4_output);

errout:
    if (rt)
        route4_put(rt);
    rte_pktmbuf_free(mbuf);
    return err;
}

static void conn_fast_xmit_handler(vector_t tockens)
{
    RTE_LOG(INFO, IPVS, "fast xmit OFF\n");
    fast_xmit_close = true;
}

void install_xmit_keywords(void)
{
    install_keyword("fast_xmit_close", conn_fast_xmit_handler, 
            KW_TYPE_INIT);
}
