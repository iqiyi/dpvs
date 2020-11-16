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
#include "ipvs/ipvs.h"
#include "ipvs/proto_tcp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "parser/parser.h"
#include "ipvs/proxy_protocol.h"

static int dp_vs_fill_pphdr(int af, struct rte_mbuf *mbuf)
{
    int iphdrlen, thdrlen;
    int pphdrlen, iptot_len;
    int ploadlen;
    void *iph = NULL, *niph = NULL;
    struct tcphdr *th;
    struct proxy_hdr_v2 *pphdr_ptr;

    /* iphdr */
    switch(af) {
        case AF_INET6:
            iph       = ip6_hdr(mbuf);
            iphdrlen  = ip6_hdrlen(mbuf);
            pphdrlen  = PROXY_PROTO_HDR_LEN_V6;
            iptot_len = sizeof(struct ip6_hdr) +
                        ntohs(((struct ip6_hdr *)iph)->ip6_plen);
            break;
        case AF_INET:
            iph       = ip4_hdr(mbuf);
            iphdrlen  = ip4_hdrlen(mbuf);
            pphdrlen  = PROXY_PROTO_HDR_LEN_V4;
            iptot_len = ntohs(((struct ipv4_hdr *)iph)->total_length);
            break;
        default:
            return EDPVS_NOTSUPP;
    }

    /* thdr */
    th = tcp_hdr(mbuf);
    thdrlen = (th->doff) << 2;
    ploadlen = iptot_len - iphdrlen - thdrlen;

    /* reserve pphdr from headrom */
    if (iptot_len > (iphdrlen + thdrlen) * 2) {
        niph = (void *)rte_pktmbuf_prepend(mbuf, pphdrlen);
        if (unlikely(!niph)) {
            /* record log */
            return EDPVS_FRAG;
        }
        /* mv iph and th forward */
        memmove(niph, iph, iphdrlen + thdrlen);
        th = (struct tcphdr *)((void *)th - pphdrlen);
    } else {
        unsigned char *ptr;

        niph = iph;
        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)) {
            /* record log */
            return EDPVS_FRAG;
        }

        ptr = (void *)rte_pktmbuf_append(mbuf, pphdrlen);
        if (unlikely(!ptr)) {
            /* record log */
            return EDPVS_FRAG;
        }

        /* mv iph and th forward */
        memmove((void *)th + thdrlen + pphdrlen,
                (void *)th + thdrlen,
                ploadlen);
    }

    /* fill proxy protocol head v2 */
    pphdr_ptr = (struct proxy_hdr_v2 *)((void *)th + thdrlen);
    memcpy(pphdr_ptr->sig, PROXY_PROTO_V2_SIGNATURE , sizeof(PROXY_PROTO_V2_SIGNATURE ) - 1);
    pphdr_ptr->ver = 2;     /* 2:v2 */
    pphdr_ptr->cmd = 1;     /* 0:LOCAL, 1:PROXY */
    pphdr_ptr->af  = (af == AF_INET ? 1 : 2); /* 0:AF_UNIX, 1:AF_INET, 2:AF_INET6, 3:AF_UNIX */
    pphdr_ptr->proto = 1;   /* 0:UNSPEC, 1:STREAM, 2:DGRAM */ 
    
    if (af == AF_INET6) {
        struct proxy_addr_ipv6 *ppaddr = (struct proxy_addr_ipv6 *)(pphdr_ptr + 1);
        struct ip6_hdr *ip6h  = (struct ip6_hdr *)niph;

        pphdr_ptr->addrlen    = htons(sizeof(struct proxy_addr_ipv6));
        memcpy(ppaddr->src_addr, &ip6h->ip6_src, IPV6_ADDR_LEN_IN_BYTES);
        memcpy(ppaddr->dst_addr, &ip6h->ip6_dst, IPV6_ADDR_LEN_IN_BYTES);
        ppaddr->src_port      = th->th_sport;
        ppaddr->dst_port      = th->th_dport;
        /* update iph */
        ((struct ip6_hdr *)niph)->ip6_plen =
                    htons(ntohs(((struct ip6_hdr *)niph)->ip6_plen) + pphdrlen);
    } else {
        struct proxy_addr_ipv4 *ppaddr = (struct proxy_addr_ipv4 *)(pphdr_ptr + 1);
        struct ipv4_hdr *ip4h = (struct ipv4_hdr *)niph;

        pphdr_ptr->addrlen    = htons(sizeof(struct proxy_addr_ipv4));
        ppaddr->src_addr      = ip4h->src_addr;
        ppaddr->dst_addr      = ip4h->dst_addr;
        ppaddr->src_port      = th->th_sport;
        ppaddr->dst_port      = th->th_dport;
        /* update iph */
        ip4h->total_length = htons(ntohs(ip4h->total_length) + pphdrlen);
    }

    return EDPVS_OK;
}

int dp_vs_pphdr_inbound(struct rte_mbuf *mbuf,
                        struct dp_vs_conn *conn)
{
    int err;
    int af = conn->af;
    int iphdrlen, thdrlen;
    int pphdrlen, ploadlen, iptot_len;
    uint16_t oldmss = 0;
    void *iph = NULL;
    struct tcphdr *th;

    /* iphdr */
    if (AF_INET6 == af) {
        iph       = ip6_hdr(mbuf);
        iphdrlen  = ip6_hdrlen(mbuf);
        pphdrlen  = PROXY_PROTO_HDR_LEN_V6; 
        iptot_len = sizeof(struct ip6_hdr) +
                    ntohs(((struct ip6_hdr *)iph)->ip6_plen);
    } else if (AF_INET == af) {
        iph       = ip4_hdr(mbuf);
        iphdrlen  = ip4_hdrlen(mbuf);
        pphdrlen  = PROXY_PROTO_HDR_LEN_V4; 
        iptot_len = ntohs(((struct ipv4_hdr *)iph)->total_length);
    } else {
        /* record log */
        return EDPVS_NOTSUPP;
    }

    /* tcphdr */
    th = tcp_hdr(mbuf);
    thdrlen = (th->doff) << 2;
    ploadlen = iptot_len - iphdrlen - thdrlen;

    if (th->syn && !th->ack) {
        if (ploadlen) {
            /* drop syn packet with payload, eg:TFO */
            return EDPVS_FRAG;
        } else {
            tcpopt_get_mss(af, mbuf, &oldmss);
            /* update mss option, skip current packet */
            tcpopt_update_mss(af, mbuf, oldmss - pphdrlen);
            return EDPVS_OK;
        }
    }

    if (ntohl(th->ack_seq) == conn->fnat_seq.fdata_seq
            && !th->syn && !th->rst && !th->fin) {
        /* add pphdr to first data packet with payload */
        if (ploadlen) {
            err = dp_vs_fill_pphdr(af, mbuf);
            if (err != EDPVS_OK) {
                RTE_LOG(WARNING, IPVS, "[%s:%d] fill_pphdr failed!\n", __func__, __LINE__);
                return err;
            }
        }
        return EDPVS_OK;
    }

    /* update seq in tcp header, checksum will be recal by hardware */
    th->seq = htonl(ntohl(th->seq) + pphdrlen);
    return EDPVS_OK;
}

int dp_vs_pphdr_outbound(struct rte_mbuf *mbuf,
                         struct dp_vs_conn *conn)
{
    int af = conn->af;
    int pphdrlen;
    uint16_t oldmss;
    struct tcphdr *th = tcp_hdr(mbuf);

    switch(af) {
        case AF_INET6:
            pphdrlen = PROXY_PROTO_HDR_LEN_V6;
            break;
        case AF_INET:
            pphdrlen = PROXY_PROTO_HDR_LEN_V4;
            break;
        default:
            return EDPVS_NOTSUPP;
    }

    /* update mss option for syn packet */
    if (th->syn && th->ack) {
        tcpopt_get_mss(af, mbuf, &oldmss);
        /* update mss option */
        tcpopt_update_mss(af, mbuf, oldmss - pphdrlen);
        return EDPVS_OK;
    }

    /* update ack_seq in tcp header */
    th->ack_seq = htonl(ntohl(th->ack_seq) - pphdrlen);

    return EDPVS_OK;
}

