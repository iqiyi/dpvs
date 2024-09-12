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
#include <time.h>
#include "conf/common.h"
#include "dpdk.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route6.h"
#include "neigh.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_tcp.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/synproxy.h"
#include "ipvs/blklst.h"
#include "ipvs/whtlst.h"
#include "parser/parser.h"
/* we need more detailed fields than dpdk tcp_hdr{},
 * like tcphdr.syn, so use standard definition. */
#include <netinet/tcp.h>
#include <openssl/sha.h>
#include "ipvs/redirect.h"
#include "ipvs/proxy_proto.h"

static int g_defence_tcp_drop = 0;

static int tcp_timeouts[DPVS_TCP_S_LAST + 1] = {
    [DPVS_TCP_S_NONE]           = 2,    /* in seconds */
    [DPVS_TCP_S_ESTABLISHED]    = 90,
    [DPVS_TCP_S_SYN_SENT]       = 3,
    [DPVS_TCP_S_SYN_RECV]       = 30,
    [DPVS_TCP_S_FIN_WAIT]       = 7,
    [DPVS_TCP_S_TIME_WAIT]      = 7,
    [DPVS_TCP_S_CLOSE]          = 3,
    [DPVS_TCP_S_CLOSE_WAIT]     = 7,
    [DPVS_TCP_S_LAST_ACK]       = 7,
    [DPVS_TCP_S_LISTEN]         = 120,
    [DPVS_TCP_S_SYNACK]         = 30,
    [DPVS_TCP_S_LAST]           = 2
};

#ifdef CONFIG_DPVS_IPVS_DEBUG
static const char *tcp_state_names[] = {
    [DPVS_TCP_S_NONE]           = "NONE",
    [DPVS_TCP_S_ESTABLISHED]    = "ESTABLISHED",
    [DPVS_TCP_S_SYN_SENT]       = "SYN_SENT",
    [DPVS_TCP_S_SYN_RECV]       = "SYN_RECV",
    [DPVS_TCP_S_FIN_WAIT]       = "FIN_WAIT",
    [DPVS_TCP_S_TIME_WAIT]      = "TIME_WAIT",
    [DPVS_TCP_S_CLOSE]          = "CLOSE",
    [DPVS_TCP_S_CLOSE_WAIT]     = "CLOSE_WAIT",
    [DPVS_TCP_S_LAST_ACK]       = "LAST_ACK",
    [DPVS_TCP_S_LISTEN]         = "LISTEN",
    [DPVS_TCP_S_SYNACK]         = "SYNACK",
    [DPVS_TCP_S_LAST]           = "BUG!"
};
#endif

static struct tcp_state tcp_states[] = {
/*    INPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA    */
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sCW, sSS, sTW, sTW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sSR}},

/*    OUTPUT */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA    */
/*syn*/ {{sSS, sES, sSS, sSR, sSS, sSS, sSS, sSS, sSS, sLI, sSR}},
/*fin*/ {{sTW, sFW, sSS, sTW, sFW, sTW, sCL, sTW, sLA, sLI, sTW}},
/*ack*/ {{sES, sES, sSS, sES, sFW, sTW, sCL, sCW, sLA, sES, sES}},
/*rst*/ {{sCL, sCL, sSS, sCL, sCL, sTW, sCL, sCL, sCL, sCL, sCL}},

/*    INPUT-ONLY */
/*        sNO, sES, sSS, sSR, sFW, sTW, sCL, sCW, sLA, sLI, sSA    */
/*syn*/ {{sSR, sES, sES, sSR, sSR, sSR, sSR, sSR, sSR, sSR, sSR}},
/*fin*/ {{sCL, sFW, sSS, sTW, sFW, sTW, sCL, sCW, sLA, sLI, sTW}},
/*ack*/ {{sCL, sES, sSS, sES, sFW, sTW, sCL, sCW, sCL, sLI, sES}},
/*rst*/ {{sCL, sCL, sCL, sSR, sCL, sCL, sCL, sCL, sLA, sLI, sCL}},
};

static uint32_t tcp_secret;

/*
 * tcp_hdr: get the pointer to tcp header
 * @af: address family
 * @mbuf: message buffer from DPDK
 * @return pointer to the tcp header
 *
 * if tcp header will be modified mbuf_header_pointer() cannot be used
 */
inline struct tcphdr *tcp_hdr(const struct rte_mbuf *mbuf)
{
    int iphdrlen;
    unsigned char version, *verp;

    verp = rte_pktmbuf_mtod(mbuf, unsigned char*);
    version = (*verp >> 4) & 0xf;

    if (4 == version) {
        iphdrlen = ip4_hdrlen(mbuf);
    } else if (6 == version) {
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        uint8_t ip6nxt = ip6h->ip6_nxt;
        iphdrlen = ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);
        if (iphdrlen < 0)
            return NULL;
    } else {
        return NULL;
    }

    /* do not support frags */
    if (unlikely(mbuf->data_len < iphdrlen + sizeof(struct tcphdr)))
        return NULL;

    return rte_pktmbuf_mtod_offset(mbuf, struct tcphdr *, iphdrlen);
}

/*
 * tcp4_send_csum: compute checksum for tcp/udp ipv4
 * @iph: pointer to ipv4 header
 * @th:  pointer to the beginning of the L4 header
 * @return void
 */
inline void tcp4_send_csum(struct rte_ipv4_hdr *iph, struct tcphdr *th)
{
    th->check = 0;
    th->check = rte_ipv4_udptcp_cksum(iph, th);
}

/*
 * tcp6_send_csum: compute checksum for tcp ipv6
 * @iph: pointer to ipv6 header in dpdk ipv6_hdr format
 * @th:  pointer to the beginning of the L4 header
 * @return void
 */
inline void tcp6_send_csum(struct rte_ipv6_hdr *iph, struct tcphdr *th) {
    th->check = 0;
    th->check = ip6_udptcp_cksum((struct ip6_hdr *)iph, th,
            (void *)th - (void *)iph, IPPROTO_TCP);
}

int tcp_send_csum(int af, int iphdrlen, struct tcphdr *th,
        const struct dp_vs_conn *conn, struct rte_mbuf *mbuf, struct netif_port *dev)
{
    /* leverage HW TX TCP csum offload if possible */
    struct netif_port *select_dev = NULL;

    if (AF_INET6 == af) {
        struct route6 *rt6 = MBUF_USERDATA(mbuf, struct route6 *, MBUF_FIELD_ROUTE);
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        if (rt6 && rt6->rt6_dev)
            select_dev = rt6->rt6_dev;
        else if (dev)
            select_dev = dev;
        else if (conn->out_dev)
            select_dev = conn->out_dev;

        if (likely(select_dev && (select_dev->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD))) {
            mbuf->l3_len = iphdrlen;
            mbuf->l4_len = (th->doff << 2);
            mbuf->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IPV6);
            th->check = ip6_phdr_cksum(ip6h, mbuf->ol_flags, iphdrlen, IPPROTO_TCP);
        } else {
            if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                return EDPVS_INVPKT;
            tcp6_send_csum((struct rte_ipv6_hdr *)ip6h, th);
        }
    } else { /* AF_INET */
        struct route_entry *rt = MBUF_USERDATA(mbuf, struct route_entry *, MBUF_FIELD_ROUTE);
        struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
        if (rt && rt->port)
            select_dev = rt->port;
        else if (dev)
            select_dev = dev;
        else if (conn->out_dev)
            select_dev = conn->out_dev;
        if (likely(select_dev && (select_dev->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD))) {
            mbuf->l3_len = iphdrlen;
            mbuf->l4_len = (th->doff << 2);
            mbuf->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4);
            th->check = rte_ipv4_phdr_cksum(iph, mbuf->ol_flags);
        } else {
            if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                return EDPVS_INVPKT;
            tcp4_send_csum(iph, th);
        }
    }

    return EDPVS_OK;
}

static inline uint32_t seq_scale(uint32_t seq)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    /* 64 ns as kernel */
    return seq + ((now.tv_sec * 1000000000L + now.tv_nsec) >> 6);
}

static inline int seq_before(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1 - seq2) < 0;
}

static inline uint32_t tcp_secure_sequence_number(uint32_t saddr, uint32_t daddr,
                                 uint16_t sport, uint16_t dport)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    uint32_t data[4], hash0;

    data[0] = (uint32_t)saddr;
    data[1] = (uint32_t)daddr;
    data[2] = ((uint16_t)sport << 16) + (uint16_t)dport;
    data[3] = tcp_secret;

    SHA1((unsigned char *)data, sizeof(data), hash);
    hash0 = hash[0];
    return seq_scale(*(uint32_t *)&hash0);
}

static inline void tcp_in_init_seq(struct dp_vs_conn *conn,
                                   struct rte_mbuf *mbuf, struct tcphdr *th)
{
    struct dp_vs_seq *fseq = &conn->fnat_seq;
    uint32_t seq = ntohl(th->seq);

    if (fseq->isn != 0 && fseq->delta == fseq->isn - seq)
        return; /* retransmit */

    if (fseq->isn)
        return;

    fseq->isn = tcp_secure_sequence_number(conn->laddr.in.s_addr,
            conn->daddr.in.s_addr, conn->lport, conn->dport);

    fseq->delta = fseq->isn - seq;
    return;
}

void tcp_in_adjust_seq(struct dp_vs_conn *conn, struct tcphdr *th)
{
    th->seq = htonl(ntohl(th->seq) + conn->fnat_seq.delta);
    /* recalc checksum later */
    /* adjust ack_seq for synproxy,including tcp hdr and sack opt */
    dp_vs_synproxy_dnat_handler(th, &conn->syn_proxy_seq);
    return;
}

/* use NOP option to replace timestamp opt */
static void tcp_in_remove_ts(struct tcphdr *tcph)
{
    unsigned char *ptr;
    int len, i;

    ptr = (unsigned char *)(tcph + 1);
    len = (tcph->doff << 2) - sizeof(struct tcphdr);

    while (len > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCP_OPT_EOL:
            return;
        case TCP_OPT_NOP:
            len--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)    /* silly options */
                return;
            if (opsize > len)
                return;    /* partial options */
            if ((opcode == TCP_OPT_TIMESTAMP)
                    && (opsize == TCP_OLEN_TIMESTAMP)) {
                for (i = 0; i < TCP_OLEN_TIMESTAMP; i++)
                    *(ptr - 2 + i) = TCP_OPT_NOP;
                return;
            }

            ptr += opsize - 2;
            len -= opsize;
            break;
        }
    }
}

/*
 * Remove NOP and TOA options preset in the mbuf and compact option space.
 * If still no enough space, trim more options except for the protected ones.
 *
 * Return the trimmed length on success, otherwise dpvs error num on failure.
 * */
static int tcp_in_prune_options(int af, int reqlen, struct rte_mbuf *mbuf, struct tcphdr *tcph)
{
    unsigned char *ptr, *fast, *slow;
    const unsigned char *l3hdr, *payload;
    int i, optlen;
    unsigned int pruned;
    uint8_t opcode, opsize;
    uint64_t opts_protected;
    const uint8_t opts_maxlen[64] = {
        [2] = 4,  [3] = 3,   [4] = 2,
        [8] = 10, [30] = 40, [34] = 18
    };

    ptr = (unsigned char *)(tcph + 1);
    fast = slow = ptr;
    optlen = (tcph->doff << 2) - sizeof(struct tcphdr);
    payload = ptr + optlen;

    if (optlen < reqlen)    /* make no sense to do anything */
        return 0;

    while (optlen > 0) {
        opcode = *ptr++;
        switch (opcode) {
        case TCP_OPT_EOL:
            goto fini;
        case TCP_OPT_NOP:
            fast++;
            optlen--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)             /* silly options */
                goto fini;
            if (opsize > optlen)        /* partial options */
                goto fini;
            if (opcode == TCP_OPT_ADDR) {
                fast += opsize;
            } else {
                for (i = 0; i < opsize; i++) {
                    if (slow != fast)
                        *slow = *fast;
                    slow++;
                    fast++;
                }
            }

            ptr += opsize - 2;
            optlen -= opsize;
            break;
        }
    }

fini:
    pruned = payload - slow;
    if (pruned < reqlen) {
        /* further trim the options, the tcp functionality relies on unprotected
         * options may get hurt, refer to:
         *   https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
         *   #tcp-parameters-1
         * */
        ptr = slow;
        slow = fast = (unsigned char *)(tcph + 1);
        if (tcph->syn)
            opts_protected = (1ULL << 2) | (1ULL << 3) | (1ULL << 4)    /* MSS, WS, SACKP */
                | (1ULL << 8) | (1ULL << 30) | (1ULL << 34);            /* TS, MPTCP, TFO */
        else
            opts_protected = (1ULL << 8);    /* TS, drop SACK, MPTCP DSS/REMOVE_ADDR */
        while (fast < ptr) {
            opcode = *fast;
            opsize = *(fast + 1);
            if (opcode < 64 && ((1ULL << opcode) & opts_protected)
                    && (opsize <= opts_maxlen[opcode])) {
                for (i = 0; i < opsize; i++)
                    *slow++ = *fast++;
                opts_protected ^= (1ULL << opcode);
            } else {
                fast += opsize;
                pruned += opsize;
                if (pruned >= reqlen) {
                    while (fast < ptr)
                        *slow++ = *fast++;
                    break;
                }
            }
        }
        pruned = payload - slow;
    }
    if (pruned > 0) {
        while (pruned & 0x3) {  /* 4-bytes alignment for tcp options */
            *slow++ = 0;
            pruned--;
        }
        if (!pruned)
            return 0;
        /* trim the packet */
        l3hdr = rte_pktmbuf_mtod(mbuf, void *);
        if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)) {
            memset(slow, 0, pruned);
            return EDPVS_INVPKT;
        }
        if (unlikely(payload - l3hdr > mbuf->pkt_len)) {
            memset(slow, 0, pruned);
            return EDPVS_INVPKT;
        }
        memmove(slow, payload, mbuf->pkt_len - (payload - l3hdr));
        rte_pktmbuf_trim(mbuf, pruned);
        tcph->doff -= (pruned >> 2);
        if (af == AF_INET)
            ((struct rte_ipv4_hdr *)l3hdr)->total_length =
                htons(ntohs(((struct rte_ipv4_hdr *)l3hdr)->total_length) - pruned);
        else
            ((struct rte_ipv6_hdr *)l3hdr)->payload_len =
                htons(ntohs(((struct rte_ipv6_hdr *)l3hdr)->payload_len) - pruned);
        return pruned;
    }
    return 0;
}

static int tcp_in_add_proxy_proto(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
        struct tcphdr *tcph, int iphdrlen, int *hdr_shift)
{
    int offset;
    struct proxy_info ppinfo = { 0 };

    offset = iphdrlen + (tcph->doff << 2);
    if (offset == mbuf->pkt_len) {
        // Don't send proxy protocol data in pure ack packets that contains no
        // application data. Otherwise, the proxy protocol data is sent twice,
        // one in this ack packet, and another in the first tcp packet with payload
        // and same beginning seq number. Worse still, if the proxy protocol data
        // is sent in a standalone packet (despite of the rareness of the case), the
        // second proxy protocol data would be taken as application payload, causing
        // problem for the tcp connection (refer to a fix for the problem in #7561d1087).
        // Ths problem would get more complicated when taking into considertation of
        // tcp retransmission.
        return EDPVS_OK;
    }

    if (unlikely(EDPVS_OK != proxy_proto_parse(mbuf, offset, &ppinfo)))
        return EDPVS_INVPKT;

    if (ppinfo.datalen > 0
            && ppinfo.version == PROXY_PROTOCOL_VERSION(conn->pp_version)
            && PROXY_PROTOCOL_IS_INSECURE(conn->pp_version))
        return EDPVS_OK;    // keep intact the orginal proxy protocol data

    if (!ppinfo.datalen || !PROXY_PROTOCOL_IS_INSECURE(conn->pp_version)) {
        ppinfo.af = tuplehash_in(conn).af;
        ppinfo.proto = IPPROTO_TCP;
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

    return proxy_proto_insert(&ppinfo, conn, mbuf, tcph, hdr_shift);
}

static int tcp_in_add_toa(struct dp_vs_conn *conn, struct rte_mbuf *mbuf,
                          struct tcphdr *tcph)
{
    uint32_t mtu;
    struct tcpopt_addr *toa;
    uint32_t tcp_opt_len;
    uint8_t *p, *q, *tail;
    struct route_entry *rt;
    struct route6 *rt6;

    if (unlikely(conn->af != AF_INET && conn->af != AF_INET6))
        return EDPVS_NOTSUPP;

    tcp_opt_len = conn->af == AF_INET ? TCP_OLEN_IP4_ADDR : TCP_OLEN_IP6_ADDR;
    /*
     * check if we can add the new option
     */
    /* skb length and tcp option length checking */
    if (tuplehash_out(conn).af == AF_INET && (rt = MBUF_USERDATA(mbuf,
                    struct route_entry *, MBUF_FIELD_ROUTE)) != NULL) {
        mtu = rt->mtu;
    } else if (tuplehash_out(conn).af == AF_INET6 && (rt6 = MBUF_USERDATA(mbuf,
                    struct route6 *, MBUF_FIELD_ROUTE)) != NULL) {
        mtu = rt6->rt6_mtu;
    } else if (conn->in_dev) { /* no route for fast-xmit */
        mtu = conn->in_dev->mtu;
    } else {
        RTE_LOG(DEBUG, IPVS, "add toa: MTU unknown.\n");
        return EDPVS_NOROUTE;
    }

    if (unlikely(mbuf->pkt_len > (mtu - tcp_opt_len))) {
        RTE_LOG(DEBUG, IPVS, "add toa: need fragment, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_FRAG;
    }

    /* maximum TCP header is 60, and 40 for options */
    if (unlikely((60 - (tcph->doff << 2)) < tcp_opt_len)) {
        RTE_LOG(DEBUG, IPVS, "add toa: no TCP header room, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_NOROOM;
    }

    /* check tail room and expand mbuf.
     * have to pull all bits in segments for later operation. */
    if (unlikely(mbuf_may_pull(mbuf, mbuf->pkt_len) != 0))
        return EDPVS_INVPKT;
    tail = (uint8_t *)rte_pktmbuf_append(mbuf, tcp_opt_len);
    if (unlikely(!tail)) {
        RTE_LOG(DEBUG, IPVS, "add toa: no mbuf tail room, tcp opt len : %u.\n",
                tcp_opt_len);
        return EDPVS_NOROOM;
    }

    /*
     * now add address option
     */

    /* move data down, including existing tcp options
     * @p is last data byte,
     * @q is new position of last data byte */
    p = tail - 1;
    q = p + tcp_opt_len;
    while (p >= ((uint8_t *)tcph + sizeof(struct tcphdr))) {
        *q = *p;
        p--, q--;
    }

    /* insert toa right after TCP basic header */
    toa = (struct tcpopt_addr *)(tcph + 1);
    toa->opcode = TCP_OPT_ADDR;
    toa->opsize = tcp_opt_len;
    toa->port = conn->cport;

    if (conn->af == AF_INET) {
        struct tcpopt_ip4_addr *toa_ip4 = (struct tcpopt_ip4_addr *)(tcph + 1);
        toa_ip4->addr = conn->caddr.in;
    }
    else {
        struct tcpopt_ip6_addr *toa_ip6 = (struct tcpopt_ip6_addr *)(tcph + 1);
        toa_ip6->addr = conn->caddr.in6;
    }


    /* reset tcp header length */
    tcph->doff += tcp_opt_len >> 2;

    /*
     * reset ip header total length, notice nat64
     * toa is always for rs which is tuplehash_out conn
     */
    if (tuplehash_out(conn).af == AF_INET)
        ip4_hdr(mbuf)->total_length =
            htons(ntohs(ip4_hdr(mbuf)->total_length) + tcp_opt_len);
    else
        ip6_hdr(mbuf)->ip6_plen =
            htons(ntohs(ip6_hdr(mbuf)->ip6_plen) + tcp_opt_len);

    /* tcp csum will be recalc later,
     * so as IP hdr csum since iph.tot_len has been chagned. */
    return EDPVS_OK;
}

static void tcp_out_save_seq(struct rte_mbuf *mbuf,
                             struct dp_vs_conn *conn, struct tcphdr *th)
{
    if (th->rst)
        return;

    /* out of order ? */
    if (seq_before(ntohl(th->ack_seq), ntohl(conn->rs_end_ack))
            && conn->rs_end_ack != 0)
        return;

    if (th->syn && th->ack)
        conn->rs_end_seq = htonl(ntohl(th->seq) + 1);
    else
        conn->rs_end_seq = htonl(ntohl(th->seq) + mbuf->pkt_len
                - ip4_hdrlen(mbuf) - (th->doff << 2));

    conn->rs_end_ack = th->ack_seq;
}

static void tcp_out_adjust_window(struct dp_vs_conn *conn, struct tcphdr *th)
{
    uint32_t wnd_client;

    wnd_client = ntohs(th->window) * (1 << conn->wscale_rs) / (1 << conn->wscale_vs);
    if (unlikely(wnd_client > 0xffff))
        wnd_client = 0xffff;
    th->window = htons(wnd_client);
}

static void tcp_out_adjust_mss(int af, struct tcphdr *tcph)
{
    unsigned char *ptr;
    int length;

    if (unlikely(af != AF_INET && af != AF_INET6)) {
        RTE_LOG(DEBUG, IPVS, "adjust mss: unknow af, af : %d.\n",
                af);
        return ;
    }

    ptr = (unsigned char *)(tcph + 1);
    length = (tcph->doff << 2) - sizeof(struct tcphdr);

    while (length > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCP_OPT_EOL:
            return;
        case TCP_OPT_NOP:
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)    /* "silly options" */
                return;
            if (opsize > length)
                return;    /* partial options */
            if ((opcode == TCP_OPT_MSS) && (opsize == TCP_OLEN_MSS)) {
                uint16_t in_mss = ntohs(*(__be16 *) ptr);

                in_mss -= (af == AF_INET ? TCP_OLEN_IP4_ADDR : TCP_OLEN_IP6_ADDR);

                /* set mss, 16bit */
                *((uint16_t *) ptr) = htons(in_mss);
                /* re-calc csum later */
                return;
            }

            ptr += opsize - 2;
            length -= opsize;
            break;
        }
    }
}

static int tcp_out_adjust_seq(struct dp_vs_conn *conn, struct tcphdr *tcph)
{
    uint8_t i;
    uint8_t *ptr;
    int length;

    /* synproxy seq change, including tcp hdr and check ack storm */
    if (dp_vs_synproxy_snat_handler(tcph, conn) == 0) {
        return EDPVS_OK; // ACK storm found
    }

    /* adjust ack sequence */
    tcph->ack_seq = htonl(ntohl(tcph->ack_seq) - conn->fnat_seq.delta);

    /* adjust sack sequence */
    ptr = (uint8_t *)(tcph + 1);
    length = (tcph->doff << 2) - sizeof(struct tcphdr);

    /* Fast path for timestamp-only option */
    if (length == TCP_OLEN_TSTAMP_ALIGNED &&
            *(uint32_t *)ptr == htonl((TCP_OPT_NOP << 24) |
                (TCP_OPT_NOP << 16) |
                (TCP_OPT_TIMESTAMP << 8) |
                TCP_OLEN_TIMESTAMP))
        return EDPVS_OK;

    while (length > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCP_OPT_EOL:
            return EDPVS_OK;
        case TCP_OPT_NOP:
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2) /* silly options */
                return EDPVS_OK;
            if (opsize > length)
                return EDPVS_OK; /* partial options */
            if ((opcode == TCP_OPT_SACK) &&
                    (opsize >= (TCP_OLEN_SACK_BASE + TCP_OLEN_SACK_PERBLOCK))
                    && !((opsize - TCP_OLEN_SACK_BASE) %
                        TCP_OLEN_SACK_PERBLOCK)) {
                for (i = 0; i < opsize - TCP_OLEN_SACK_BASE;
                        i += TCP_OLEN_SACK_PERBLOCK) {
                    uint32_t *tmp = (uint32_t *) (ptr + i);
                    *tmp = htonl(ntohl(*tmp) -
                            conn->fnat_seq.delta);

                    tmp++;

                    *tmp = htonl(ntohl(*tmp) -
                            conn->fnat_seq.delta);
                }
                return EDPVS_OK;
            }

            ptr += opsize - 2;
            length -= opsize;
            break;
        }
    }

    return EDPVS_OK;
}

static void tcp_out_init_seq(struct dp_vs_conn *conn, struct tcphdr *th)
{
    conn->fnat_seq.fdata_seq = ntohl(th->seq) + 1;
}

/* set @verdict if failed to schedule */
static int tcp_conn_sched(struct dp_vs_proto *proto,
                          const struct dp_vs_iphdr *iph,
                          struct rte_mbuf *mbuf,
                          struct dp_vs_conn **conn,
                          int *verdict)
{
    struct tcphdr *th, _tcph;
    struct dp_vs_service *svc;

    assert(proto && iph && mbuf && conn && verdict);

    th = mbuf_header_pointer(mbuf, iph->len, sizeof(_tcph), &_tcph);
    if (unlikely(!th)) {
        *verdict = INET_DROP;
        return EDPVS_INVPKT;
    }

    /* Syn-proxy step 2 logic: receive client's 3-handshake ack packet */
    /* When synproxy disabled, only SYN packets can arrive here.
     * So don't judge SYNPROXY flag here! If SYNPROXY flag judged, and syn_proxy
     * got disbled and keepalived reloaded, SYN packets for RS may never be sent. */
    if (dp_vs_synproxy_ack_rcv(iph->af, mbuf, th, proto, conn, iph, verdict) == 0) {
        /* Attention: First ACK packet is also stored in conn->ack_mbuf */
        return EDPVS_PKTSTOLEN;
    }

    /* only TCP-SYN without other flag can be scheduled */
    if (!th->syn || th->ack || th->fin || th->rst) {
#ifdef CONFIG_DPVS_IPVS_DEBUG
        char dbuf[64], sbuf[64];
        const char *daddr, *saddr;

        daddr = inet_ntop(iph->af, &iph->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::";
        saddr = inet_ntop(iph->af, &iph->saddr, sbuf, sizeof(sbuf)) ? sbuf : "::";
        RTE_LOG(DEBUG, IPVS,
                "%s: [%d] try sched non-SYN packet: [%c%c%c%c] %s/%d->%s/%d\n",
                __func__, rte_lcore_id(),
                th->syn ? 'S' : '.', th->fin ? 'F' : '.',
                th->ack ? 'A' : '.', th->rst ? 'R' : '.',
                saddr, ntohs(th->source), daddr, ntohs(th->dest));
#endif

        /* Drop tcp packet which is send to vip and !vport */
        if (g_defence_tcp_drop &&
                (svc = dp_vs_vip_lookup(iph->af, iph->proto,
                                    &iph->daddr, rte_lcore_id()))) {
            dp_vs_estats_inc(DEFENCE_TCP_DROP);
            *verdict = INET_DROP;
            return EDPVS_INVPKT;
        }

        *verdict = INET_ACCEPT;
        return EDPVS_INVAL;
    }

    svc = dp_vs_service_lookup(iph->af, iph->proto, &iph->daddr, th->dest,
                               0, mbuf, NULL, rte_lcore_id());
    if (!svc) {
        /* Drop tcp packet which is send to vip and !vport */
        if (g_defence_tcp_drop &&
                (svc = dp_vs_vip_lookup(iph->af, iph->proto,
                                   &iph->daddr, rte_lcore_id()))) {
            dp_vs_estats_inc(DEFENCE_TCP_DROP);
            *verdict = INET_DROP;
            return EDPVS_INVPKT;
        }
        *verdict = INET_ACCEPT;
        return EDPVS_NOSERV;
    }

    *conn = dp_vs_schedule(svc, iph, mbuf, false);
    if (!*conn) {
        *verdict = INET_DROP;
        return EDPVS_RESOURCE;
    }

    return EDPVS_OK;
}

static struct dp_vs_conn *
tcp_conn_lookup(struct dp_vs_proto *proto, const struct dp_vs_iphdr *iph,
                struct rte_mbuf *mbuf, int *direct, bool reverse, bool *drop,
                lcoreid_t *peer_cid)
{
    struct tcphdr *th, _tcph;
    struct dp_vs_conn *conn;
    assert(proto && iph && mbuf);

    th = mbuf_header_pointer(mbuf, iph->len, sizeof(_tcph), &_tcph);
    if (unlikely(!th))
        return NULL;

    if (dp_vs_blklst_filtered(iph->af, iph->proto, &iph->daddr,
                th->dest, &iph->saddr, mbuf)) {
        *drop = true;
        return NULL;
    }

    if (dp_vs_whtlst_filtered(iph->af, iph->proto, &iph->daddr,
                th->dest, &iph->saddr, mbuf)) {
        *drop = true;
        return NULL;
    }

    conn = dp_vs_conn_get(iph->af, iph->proto,
            &iph->saddr, &iph->daddr, th->source, th->dest, direct, reverse);

    /*
     * L2 confirm neighbour
     * pkt in from client confirm neighbour to client
     * pkt out from rs confirm neighbour to rs
     */
    if (conn != NULL) {
        if (th->ack) {
            if ((*direct == DPVS_CONN_DIR_INBOUND) && conn->out_dev
                 && (!inet_is_addr_any(tuplehash_in(conn).af, &conn->out_nexthop))) {
                neigh_confirm(tuplehash_in(conn).af, &conn->out_nexthop,
                              conn->out_dev);
            } else if ((*direct == DPVS_CONN_DIR_OUTBOUND) && conn->in_dev
                        && (!inet_is_addr_any(tuplehash_out(conn).af, &conn->in_nexthop))) {
                neigh_confirm(tuplehash_out(conn).af, &conn->in_nexthop,
                              conn->in_dev);
            }
        }
    } else {
        struct dp_vs_redirect *r;

        r = dp_vs_redirect_get(iph->af, iph->proto,
                               &iph->saddr, &iph->daddr,
                               th->source, th->dest);
        if (r) {
            *peer_cid = r->cid;
        }
    }

    return conn;
}

static int tcp_fnat_in_handler(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct tcphdr *th;
    int af;             /* outbound af */
    int iphdrlen, toalen;
    int err, pp_hdr_shift = 0;

    af = tuplehash_out(conn).af;
    iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*th)) != 0)
        return EDPVS_INVPKT;

    th = tcp_hdr(mbuf);
    if (unlikely(!th))
        return EDPVS_INVPKT;

    if (mbuf_may_pull(mbuf, iphdrlen + (th->doff << 2)) != 0)
        return EDPVS_INVPKT;

    /*
     * for SYN packet
     * 1. remove tcp timestamp option,
     *    laddrs for different clients have diff timestamp.
     * 2. save original TCP sequence for seq-adjust later
     *    since TCP option will be changed.
     */
    if (th->syn && !th->ack) {
        tcp_in_remove_ts(th);
        tcp_in_init_seq(conn, mbuf, th);
    }

    /* Add toa/proxy_protocol to the first data packet */
    if (ntohl(th->ack_seq) == conn->fnat_seq.fdata_seq
            && !th->syn && !th->rst /*&& !th->fin*/) {
        if (PROXY_PROTOCOL_V2 == PROXY_PROTOCOL_VERSION(conn->pp_version)
                || PROXY_PROTOCOL_V1 == PROXY_PROTOCOL_VERSION(conn->pp_version)) {
            if (conn->fnat_seq.isn - conn->fnat_seq.delta + 1 == ntohl(th->seq)) {
                /* avoid inserting repetitive proxy protocol data
                 * when the first rs ack is delayed */
                err = tcp_in_add_proxy_proto(conn, mbuf, th, iphdrlen, &pp_hdr_shift);
                if (unlikely(EDPVS_OK != err))
                    RTE_LOG(INFO, IPVS, "%s: insert proxy protocol fail -- %s\n",
                            __func__, dpvs_strerror(err));
                th = ((void *)th) + pp_hdr_shift;
            }
        } else { /* use toa */
            err = tcp_in_add_toa(conn, mbuf, th);
            if (unlikely(EDPVS_OK != err)) {
                toalen = tuplehash_in(conn).af == AF_INET ? TCP_OLEN_IP4_ADDR : TCP_OLEN_IP6_ADDR;
                if (tcp_in_prune_options(af, toalen, mbuf, th) >= toalen
                        && (EDPVS_NOROOM == err || EDPVS_FRAG == err)) {
                    err = tcp_in_add_toa(conn, mbuf, th);
                }
                if (EDPVS_OK != err) {
                    char caddrbuf[64], vaddrbuf[64], laddrbuf[64], daddrbuf[64];
                    const char *caddr, *vaddr, *laddr, *daddr;
                    caddr = inet_ntop(conn->af, &conn->caddr, caddrbuf, sizeof(caddrbuf)) ? caddrbuf : "::";
                    vaddr = inet_ntop(conn->af, &conn->vaddr, vaddrbuf, sizeof(vaddrbuf)) ? vaddrbuf : "::";
                    laddr = inet_ntop(af, &conn->laddr, laddrbuf, sizeof(laddrbuf)) ? laddrbuf : "::";
                    daddr = inet_ntop(af, &conn->daddr, daddrbuf, sizeof(daddrbuf)) ? daddrbuf : "::";
                    RTE_LOG(WARNING, IPVS, "TOA add failed(%s): [%s]:%d -> [%s]:%d; [%s]:%d -> [%s]:%d\n",
                            dpvs_strerror(err), caddr, htons(conn->cport), vaddr, htons(conn->vport),
                            laddr, htons(conn->lport), daddr, htons(conn->dport));
                }
            }
        }
    }

    tcp_in_adjust_seq(conn, th);

    /* L4 translation */
    th->source  = conn->lport;
    th->dest    = conn->dport;

    return tcp_send_csum(af, iphdrlen, th, conn, mbuf, conn->in_dev);
}

static int tcp_fnat_out_handler(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct tcphdr *th;
    /* af/mbuf may be changed for nat64 which in af is ipv6 and out is ipv4*/
    int af = tuplehash_in(conn).af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*th)) != 0)
        return EDPVS_INVPKT;

    th = tcp_hdr(mbuf);
    if (unlikely(!th))
        return EDPVS_INVPKT;

    if (mbuf_may_pull(mbuf, iphdrlen + (th->doff<<2)) != 0)
        return EDPVS_INVPKT;

    /* save last seq/ack from RS for RST when conn expire */
    tcp_out_save_seq(mbuf, conn, th);

    /* L4 translation */
    th->source  = conn->vport;
    th->dest    = conn->cport;

    tcp_out_adjust_window(conn, th);

    if (th->syn && th->ack)
        tcp_out_adjust_mss(af, th);

    /* adjust ACK/SACK from RS since inbound SEQ is changed */
    if (tcp_out_adjust_seq(conn, th) != EDPVS_OK)
        return EDPVS_INVPKT;

    if (th->syn && th->ack)
        tcp_out_init_seq(conn, th);

    return tcp_send_csum(af, iphdrlen, th, conn, mbuf, conn->out_dev);
}

static int tcp_snat_in_handler(struct dp_vs_proto *proto,
                               struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct tcphdr *th;
    int af = conn->af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*th)) != 0)
        return EDPVS_INVPKT;

    th = tcp_hdr(mbuf);
    if (unlikely(!th))
        return EDPVS_INVPKT;

    if (mbuf_may_pull(mbuf, iphdrlen + (th->doff << 2)) != 0)
        return EDPVS_INVPKT;

    /* L4 translation */
    th->dest = conn->dport;

    /* L4 re-checksum */
    return tcp_send_csum(af, iphdrlen, th, conn, mbuf, conn->in_dev);
}

static int tcp_snat_out_handler(struct dp_vs_proto *proto,
                                struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct tcphdr *th;
    int af = conn->af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*th)) != 0)
        return EDPVS_INVPKT;

    th = tcp_hdr(mbuf);
    if (unlikely(!th))
        return EDPVS_INVPKT;

    if (mbuf_may_pull(mbuf, iphdrlen + (th->doff << 2)) != 0)
        return EDPVS_INVPKT;

    /* L4 translation */
    th->source = conn->vport;

    /* L4 re-checksum */
    return tcp_send_csum(af, iphdrlen, th, conn, mbuf, conn->out_dev);
}

static inline int tcp_state_idx(struct tcphdr *th)
{
    if (th->rst)
        return 3;
    if (th->syn)
        return 0;
    if (th->fin)
        return 1;
    if (th->ack)
        return 2;
    return -1;
}

#ifdef CONFIG_DPVS_IPVS_DEBUG
static const char *tcp_state_name(int state)
{
    if (state >= DPVS_TCP_S_LAST)
        return "ERR!";
    return tcp_state_names[state] ? tcp_state_names[state] : "<Unknown>";
}
#endif

static int tcp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                           struct rte_mbuf *mbuf, int dir)
{
    struct tcphdr *th, _tcph;
    int idx, off;
    int new_state = DPVS_TCP_S_CLOSE;
    assert(proto && conn && mbuf);
    struct dp_vs_dest *dest = conn->dest;
    int af = conn->af;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char dbuf[64], cbuf[64];
    const char *daddr, *caddr;
#endif

    if (dir == DPVS_CONN_DIR_INBOUND && dest->fwdmode == DPVS_FWD_MODE_FNAT)
        af = tuplehash_in(conn).af;
    else if (dir == DPVS_CONN_DIR_OUTBOUND && dest->fwdmode == DPVS_FWD_MODE_FNAT)
        af = tuplehash_out(conn).af;

    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf): ip4_hdrlen(mbuf));
    th = mbuf_header_pointer(mbuf, iphdrlen, sizeof(_tcph), &_tcph);
    if (unlikely(!th))
        return EDPVS_INVPKT;
    if (dest->fwdmode == DPVS_FWD_MODE_DR || dest->fwdmode == DPVS_FWD_MODE_TUNNEL)
        off = 8;
    else if (dir == DPVS_CONN_DIR_INBOUND)
        off = 0;
    else if (dir == DPVS_CONN_DIR_OUTBOUND)
        off = 4;
    else
        return EDPVS_NOTSUPP; /* do not support INPUT_ONLY now */

    if ((idx = tcp_state_idx(th)) < 0) {
        RTE_LOG(DEBUG, IPVS, "tcp_state_idx=%d !\n", idx);
        goto tcp_state_out;
    }

    new_state = tcp_states[off + idx].next_state[conn->state];

tcp_state_out:
    if (new_state == conn->state)
        return EDPVS_OK;

    /* state changed */

#ifdef CONFIG_DPVS_IPVS_DEBUG
    daddr = inet_ntop(tuplehash_out(conn).af, &conn->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::";
    caddr = inet_ntop(tuplehash_in(conn).af, &conn->caddr, cbuf, sizeof(cbuf)) ? cbuf : "::";

    RTE_LOG(DEBUG, IPVS, "state trans: %s %s [%c%c%c%c] %s:%u->%s:%u "
            " state %s->%s conn.refcnt %d\n",
            proto->name, dir == DPVS_CONN_DIR_OUTBOUND ? "out" : "in",
            th->syn ? 'S' : '.', th->fin ? 'F' : '.',
            th->ack ? 'A' : '.', th->rst ? 'R' : '.',
            caddr, ntohs(conn->cport),
            daddr, ntohs(conn->dport),
            tcp_state_name(conn->state),
            tcp_state_name(new_state),
            rte_atomic32_read(&conn->refcnt));
#endif

    conn->old_state = conn->state; // old_state called when connection reused
    conn->state = new_state;

    dp_vs_conn_set_timeout(conn, proto);

    if (new_state == DPVS_TCP_S_CLOSE && conn->old_state == DPVS_TCP_S_SYN_RECV)
        dp_vs_dest_detected_dead(conn->dest); // connection reset by dest
    else if (new_state == DPVS_TCP_S_ESTABLISHED)
        dp_vs_dest_detected_alive(conn->dest);

    if (dest) {
        if (!(conn->flags & DPVS_CONN_F_INACTIVE)
                && (new_state != DPVS_TCP_S_ESTABLISHED)) {
            rte_atomic32_dec(&dest->actconns);
            rte_atomic32_inc(&dest->inactconns);
            conn->flags |= DPVS_CONN_F_INACTIVE;
        } else if ((conn->flags & DPVS_CONN_F_INACTIVE)
                && (new_state == DPVS_TCP_S_ESTABLISHED)) {
            rte_atomic32_inc(&dest->actconns);
            rte_atomic32_dec(&dest->inactconns);
            conn->flags &= ~DPVS_CONN_F_INACTIVE;
        }
    }

    return EDPVS_OK;
}

struct rte_mempool *get_mbuf_pool(const struct dp_vs_conn *conn, int dir)
{
    struct netif_port *dev;
    int af;

    /* we need oif for correct rte_mempoll,
     * most likely oif is conn->in/out_dev (fast-xmit),
     * if not, determine output device by route. */
    dev = ((dir == DPVS_CONN_DIR_INBOUND) ? conn->in_dev : conn->out_dev);

    if (unlikely(!dev)) {
    /* dir is mbuf to revieve, route/af is mbuf to send
     * their in/out may be reversed */
        af = ((dir == DPVS_CONN_DIR_INBOUND) ? \
              tuplehash_out(conn).af : tuplehash_in(conn).af);
        if (AF_INET == af) {
            struct route_entry *rt = NULL;
            struct flow4 fl4;
            memset(&fl4, 0, sizeof(struct flow4));
            if (dir == DPVS_CONN_DIR_INBOUND) {
                fl4.fl4_saddr = conn->laddr.in;
                fl4.fl4_daddr = conn->daddr.in;
                fl4.fl4_sport = conn->lport;
                fl4.fl4_dport = conn->dport;
            } else {
                fl4.fl4_saddr = conn->vaddr.in;
                fl4.fl4_daddr = conn->caddr.in;
                fl4.fl4_sport = conn->vport;
                fl4.fl4_dport = conn->cport;
            }
            fl4.fl4_proto = IPPROTO_TCP;
            if ((rt = route4_output(&fl4)) == NULL)
                return NULL;
            dev = rt->port;
            route4_put(rt);
        } else { /* AF_INET6 */
            struct route6 *rt6 = NULL;
            struct flow6 fl6;
            memset(&fl6, 0, sizeof(struct flow6));
            if (dir == DPVS_CONN_DIR_INBOUND) {
                fl6.fl6_saddr = conn->laddr.in6;
                fl6.fl6_daddr = conn->daddr.in6;
                fl6.fl6_sport = conn->lport;
                fl6.fl6_dport = conn->dport;
            } else {
                fl6.fl6_saddr = conn->vaddr.in6;
                fl6.fl6_daddr = conn->caddr.in6;
                fl6.fl6_sport = conn->vport;
                fl6.fl6_dport = conn->cport;
            }
            fl6.fl6_proto = IPPROTO_TCP;
            if ((rt6 = route6_output(NULL, &fl6)) == NULL)
                return NULL;
            dev = rt6->rt6_dev;
            route6_put(rt6);
        }
    }

    return dev->mbuf_pool;
}

static int tcp_send_rst(struct dp_vs_proto *proto,
                        struct dp_vs_conn *conn, int dir)
{
    struct rte_mempool *pool;
    struct rte_mbuf *mbuf = NULL;
    struct tcphdr *th;
    struct rte_ipv4_hdr *ip4h;
    struct ip6_hdr *ip6h;

    if (conn->state != DPVS_TCP_S_ESTABLISHED) {
        /* RTE_LOG(WARNING, IPVS, "%s: only RST in ESTABLISHED.\n", __func__); */
        return EDPVS_OK;
    }

    pool = get_mbuf_pool(conn, dir);
    if (!pool)
        return EDPVS_NOROUTE;

    mbuf = rte_pktmbuf_alloc(pool);
    if (!mbuf)
        return EDPVS_NOMEM;
    mbuf_userdata_reset(mbuf); /* make sure "no route info" */

    /*
     * reserve head room ?
     * mbuf has alreay configured header room
     * RTE_PKTMBUF_HEADROOM for lower layer headers.
     */
    assert(rte_pktmbuf_headroom(mbuf) >= 128); /* how to reserve. >_< */

    /* rte_pktmbuf_mtod ? */
    th = (struct tcphdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct tcphdr));
    if (!th) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROOM;
    }

    memset(th, 0, sizeof(struct tcphdr));
    if (dir == DPVS_CONN_DIR_INBOUND) {
        th->source = conn->cport; /* will be translated */
        th->dest = conn->vport;
        th->seq = conn->rs_end_ack;
        if (conn->dest->fwdmode == DPVS_FWD_MODE_FNAT)
            th->seq = htonl(ntohl(th->seq) - conn->fnat_seq.delta);
    } else {
        th->source = conn->dport;
        th->dest = conn->lport;
        th->seq = conn->rs_end_seq;
    }

    th->ack_seq = 0;
    th->doff = sizeof(struct tcphdr) >> 2;
    th->rst = 1;

    /* IP header (before translation) */
    if (dir == DPVS_CONN_DIR_INBOUND) {
        if (tuplehash_in(conn).af == AF_INET) {
            ip4h = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct rte_ipv4_hdr));
            if (!ip4h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip4h->version_ihl     = 0x45;
            ip4h->total_length    = htons(mbuf->pkt_len);
            ip4h->packet_id       = 0;
            ip4h->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);
            ip4h->time_to_live    = 64;
            ip4h->next_proto_id   = IPPROTO_TCP;
            ip4h->src_addr        = conn->caddr.in.s_addr;
            ip4h->dst_addr        = conn->vaddr.in.s_addr;

            mbuf->l3_len = sizeof(*ip4h);

            ip4h->hdr_checksum = 0;
            tcp4_send_csum(ip4h, th);
            ip4_send_csum(ip4h);

        } else {
            int plen = mbuf->pkt_len;
            ip6h = (struct ip6_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct ip6_hdr));
            if (!ip6h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip6h->ip6_vfc   = 0x60;
            ip6h->ip6_plen  = htons(plen);
            ip6h->ip6_hlim  = 64;
            ip6h->ip6_nxt   = IPPROTO_TCP;
            ip6h->ip6_src   = conn->caddr.in6;
            ip6h->ip6_dst   = conn->vaddr.in6;

            mbuf->l3_len = sizeof(*ip6h);

            tcp6_send_csum((struct rte_ipv6_hdr *)ip6h, th);
        }

        conn->packet_xmit(proto, conn, mbuf);

    } else {
        if (tuplehash_out(conn).af == AF_INET) {
            ip4h = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct rte_ipv4_hdr));
            if (!ip4h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip4h->version_ihl     = 0x45;
            ip4h->total_length    = htons(mbuf->pkt_len);
            ip4h->packet_id       = 0;
            ip4h->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);
            ip4h->time_to_live    = 64;
            ip4h->next_proto_id   = IPPROTO_TCP;
            ip4h->src_addr        = conn->daddr.in.s_addr;
            ip4h->dst_addr        = conn->laddr.in.s_addr;

            mbuf->l3_len = sizeof(*ip4h);

            ip4h->hdr_checksum = 0;
            tcp4_send_csum(ip4h, th);
            ip4_send_csum(ip4h);

        } else {
            int plen = mbuf->pkt_len;
            ip6h = (struct ip6_hdr *)rte_pktmbuf_prepend(mbuf,
                                       sizeof(struct ip6_hdr));
            if (!ip6h) {
                rte_pktmbuf_free(mbuf);
                return EDPVS_NOROOM;
            }
            ip6h->ip6_vfc   = 0x60;
            ip6h->ip6_plen  = htons(plen);
            ip6h->ip6_hlim  = 64;
            ip6h->ip6_nxt   = IPPROTO_TCP;
            ip6h->ip6_src   = conn->daddr.in6;
            ip6h->ip6_dst   = conn->laddr.in6;

            mbuf->l3_len = sizeof(*ip6h);

            tcp6_send_csum((struct rte_ipv6_hdr *)ip6h, th);
        }

        conn->packet_out_xmit(proto, conn, mbuf);
    }

    return EDPVS_OK;
}

static int tcp_conn_expire(struct dp_vs_proto *proto,
                       struct dp_vs_conn *conn)
{
    int err;
    assert(proto && conn && conn->dest);

    if (conn->dest->fwdmode == DPVS_FWD_MODE_FNAT
            || conn->dest->fwdmode == DPVS_FWD_MODE_SNAT
            || conn->dest->fwdmode == DPVS_FWD_MODE_NAT) {
        /* send RST to RS and client */
        err = tcp_send_rst(proto, conn, DPVS_CONN_DIR_INBOUND);
        if (err != EDPVS_OK)
            RTE_LOG(WARNING, IPVS, "%s: fail RST RS.\n", __func__);
        err = tcp_send_rst(proto, conn, DPVS_CONN_DIR_OUTBOUND);
        if (err != EDPVS_OK)
            RTE_LOG(WARNING, IPVS, "%s: fail RST Client.\n", __func__);
    }

    /* the backend dest went down silently */
    if (DPVS_TCP_S_SYN_RECV == conn->state || DPVS_TCP_S_SYN_SENT == conn->state)
        dp_vs_dest_detected_dead(conn->dest);

    return EDPVS_OK;
}

static int tcp_conn_expire_quiescent(struct dp_vs_conn *conn)
{
    dp_vs_conn_expire_now(conn);

    return EDPVS_OK;
}

static void defence_tcp_drop_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "defence_tcp_drop ON\n");
    g_defence_tcp_drop = 1;
}

static inline void timeout_handler_template(vector_t tokens,
        const char *tcp_state, int idx, int default_timeout)
{
    char *str = set_value(tokens);
    int timeout;

    assert(str && idx >= DPVS_TCP_S_NONE && idx <= DPVS_TCP_S_LAST);

    timeout = atoi(str);
    if (timeout > IPVS_TIMEOUT_MIN && timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "tcp_timeout_%s = %d\n", tcp_state, timeout);
        tcp_timeouts[idx] = timeout;
    } else {
        RTE_LOG(INFO, IPVS, "invalid tcp_timeout_%s, using default %d\n",
                tcp_state, default_timeout);
        tcp_timeouts[idx] = default_timeout;
    }
    FREE_PTR(str);
}

static void timeout_none_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "none", DPVS_TCP_S_NONE, 2);
}

static void timeout_established_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "established", DPVS_TCP_S_ESTABLISHED, 90);
}

static void timeout_syn_sent_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "syn_sent", DPVS_TCP_S_SYN_SENT, 3);
}

static void timeout_syn_recv_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "syn_recv", DPVS_TCP_S_SYN_RECV, 30);
}

static void timeout_fin_wait_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "fin_wait", DPVS_TCP_S_FIN_WAIT, 7);
}

static void timeout_time_wait_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "time_wait", DPVS_TCP_S_TIME_WAIT, 7);
}

static void timeout_close_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "close", DPVS_TCP_S_CLOSE, 3);
}

static void timeout_close_wait_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "close_wait", DPVS_TCP_S_CLOSE_WAIT, 7);
}

static void timeout_last_ack_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "last_ack", DPVS_TCP_S_LAST_ACK, 7);
}

static void timeout_listen_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "listen", DPVS_TCP_S_LISTEN, 120);
}

static void timeout_synack_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "synack", DPVS_TCP_S_SYNACK, 30);
}

static void timeout_last_handler(vector_t tokens)
{
    timeout_handler_template(tokens, "last", DPVS_TCP_S_LAST, 2);
}

void tcp_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
    }
    /* KW_TYPE_NORMAL keyword */
    g_defence_tcp_drop = 0;
    tcp_timeouts[DPVS_TCP_S_NONE]           = 2;
    tcp_timeouts[DPVS_TCP_S_ESTABLISHED]    = 90;
    tcp_timeouts[DPVS_TCP_S_SYN_SENT]       = 3;
    tcp_timeouts[DPVS_TCP_S_SYN_RECV]       = 30;
    tcp_timeouts[DPVS_TCP_S_FIN_WAIT]       = 7;
    tcp_timeouts[DPVS_TCP_S_TIME_WAIT]      = 7;
    tcp_timeouts[DPVS_TCP_S_CLOSE]          = 3;
    tcp_timeouts[DPVS_TCP_S_CLOSE_WAIT]     = 7;
    tcp_timeouts[DPVS_TCP_S_LAST_ACK]       = 7;
    tcp_timeouts[DPVS_TCP_S_LISTEN]         = 120;
    tcp_timeouts[DPVS_TCP_S_SYNACK]         = 30;
    tcp_timeouts[DPVS_TCP_S_LAST]           = 2;
};

void install_proto_tcp_keywords(void)
{
    install_keyword("defence_tcp_drop", defence_tcp_drop_handler, KW_TYPE_NORMAL);
    install_keyword("timeout", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("none", timeout_none_handler, KW_TYPE_NORMAL);
    install_keyword("established", timeout_established_handler, KW_TYPE_NORMAL);
    install_keyword("syn_sent", timeout_syn_sent_handler, KW_TYPE_NORMAL);
    install_keyword("syn_recv", timeout_syn_recv_handler, KW_TYPE_NORMAL);
    install_keyword("fin_wait", timeout_fin_wait_handler, KW_TYPE_NORMAL);
    install_keyword("time_wait", timeout_time_wait_handler, KW_TYPE_NORMAL);
    install_keyword("close", timeout_close_handler, KW_TYPE_NORMAL);
    install_keyword("close_wait", timeout_close_wait_handler, KW_TYPE_NORMAL);
    install_keyword("last_ack", timeout_last_ack_handler, KW_TYPE_NORMAL);
    install_keyword("listen", timeout_listen_handler, KW_TYPE_NORMAL);
    install_keyword("synack", timeout_synack_handler, KW_TYPE_NORMAL);
    install_keyword("last", timeout_last_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
}

static int tcp_init(struct dp_vs_proto *proto)
{
    tcp_secret = (uint32_t)random();
    proto->timeout_table = tcp_timeouts;
    return EDPVS_OK;
}

static int tcp_exit(struct dp_vs_proto *proto)
{
    return EDPVS_OK;
}

struct dp_vs_proto dp_vs_proto_tcp = {
    .name                  = "TCP",
    .proto                 = IPPROTO_TCP,
    .init                  = tcp_init,
    .exit                  = tcp_exit,
    .conn_sched            = tcp_conn_sched,
    .conn_lookup           = tcp_conn_lookup,
    .conn_expire           = tcp_conn_expire,
    .conn_expire_quiescent = tcp_conn_expire_quiescent,
    .nat_in_handler        = tcp_snat_in_handler,
    .nat_out_handler       = tcp_snat_out_handler,
    .fnat_in_handler       = tcp_fnat_in_handler,
    .fnat_out_handler      = tcp_fnat_out_handler,
    .snat_in_handler       = tcp_snat_in_handler,
    .snat_out_handler      = tcp_snat_out_handler,
    .state_trans           = tcp_state_trans,
};
