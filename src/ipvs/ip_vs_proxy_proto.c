/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2023 iQIYI (www.iqiyi.com).
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
#include "ipvs/proxy_proto.h"
#include "ipvs/proto_tcp.h"
#include "ipvs/proto_udp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "route.h"
#include "route6.h"
#include "conf/common.h"
#include "conf/service.h"

int proxy_proto_parse(struct rte_mbuf *mbuf, int ppdoff, struct proxy_info *ppinfo)
{
    void *pphdr;
    char *token, *tmp, *end;
    int offset, ppdlen;
    char buf[PROXY_PROTO_V1_MAX_DATALEN+1];
    struct proxy_hdr_v2 *pphdrv2;
    struct proxy_addr_ipv4 *addr4;
    struct proxy_addr_ipv6 *addr6;
    struct proxy_addr_unix *addrunx;

    offset = ppdoff;
    if (mbuf_may_pull(mbuf, offset + 12))
        return EDPVS_OK; /* too small to reside pp data */

    pphdr = rte_pktmbuf_mtod_offset(mbuf, void *, offset);
    memset(ppinfo, 0, sizeof(struct proxy_info));
    offset += 12;

    if (!memcmp(pphdr, PROXY_PROTO_V2_SIGNATURE, 12)) {
        offset += 4;
        if (mbuf_may_pull(mbuf, offset))
            return EDPVS_INVPKT;
        pphdrv2 = (struct proxy_hdr_v2 *)pphdr;
        offset += ntohs(pphdrv2->addrlen);
        if (mbuf_may_pull(mbuf, offset))
            return EDPVS_INVPKT;
        ppinfo->version = pphdrv2->ver;
        if (unlikely(ppinfo->version != PROXY_PROTOCOL_V2 || ppinfo->cmd > 1))
            return EDPVS_INVAL;
        ppinfo->cmd = pphdrv2->cmd;
        if (!ppinfo->cmd)
            return EDPVS_OK; /* LOCAL command */
        ppinfo->af = ppv2_af_pp2host(pphdrv2->af);
        if (unlikely(AF_UNSPEC == ppinfo->af))
            return EDPVS_NOTSUPP;
        ppinfo->proto = ppv2_proto_pp2host(pphdrv2->proto);
        if (unlikely(!ppinfo->proto))
            return EDPVS_NOTSUPP;
        switch (ppinfo->af) {
            case AF_INET:
                addr4 = (struct proxy_addr_ipv4 *)(pphdrv2 + 1);
                ppinfo->addr.ip4.src_addr = addr4->src_addr;
                ppinfo->addr.ip4.dst_addr = addr4->dst_addr;
                ppinfo->addr.ip4.src_port = addr4->src_port;
                ppinfo->addr.ip4.dst_port = addr4->dst_port;
                ppinfo->datalen = PROXY_PROTO_HDR_LEN_V4;
                break;
            case AF_INET6:
                addr6 = (struct proxy_addr_ipv6 *)(pphdrv2 + 1);
                memcpy(ppinfo->addr.ip6.src_addr, addr6->src_addr, 16);
                memcpy(ppinfo->addr.ip6.dst_addr, addr6->dst_addr, 16);
                ppinfo->addr.ip6.src_port = addr6->src_port;
                ppinfo->addr.ip6.dst_port = addr6->dst_port;
                ppinfo->datalen = PROXY_PROTO_HDR_LEN_V6;
                break;
            case AF_UNIX:
                addrunx = (struct proxy_addr_unix *)(pphdrv2 + 1);
                memcpy(ppinfo->addr.unx.src_addr, addrunx->src_addr, 108);
                memcpy(ppinfo->addr.unx.dst_addr, addrunx->dst_addr, 108);
                ppinfo->datalen = PROXY_PROTO_HDR_LEN_UX;
                break;
            default:
                return EDPVS_NOTSUPP;
        }
        /* ignore all TLVs */
        return EDPVS_OK;
    } else if (!memcmp(pphdr, "PROXY ", 6)) {
        ppdlen = strcspn((const char *)pphdr, "\n");
        if (unlikely(ppdlen > PROXY_PROTO_V1_MAX_DATALEN || ppdlen <= 0))
            return EDPVS_INVPKT;
        ppdlen += 1;    // count in '\n'
        offset = ppdoff + ppdlen;
        if (mbuf_may_pull(mbuf, offset))
            return EDPVS_INVPKT;
        memcpy(buf, pphdr, ppdlen);
        buf[ppdlen-1] = '\0';
        if (ppdlen > 1 && buf[ppdlen-2] == '\r')
            buf[ppdlen-2] = '\0';
        if (NULL == (token = strtok_r(buf, " ", &tmp))) /* "PROXY" */
            return EDPVS_INVAL;
        ppinfo->version = PROXY_PROTOCOL_V1;
        if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* TCP4 | TCP6 */
            return EDPVS_INVAL;
        if (!memcmp(token, "TCP4", 4)) {
            ppinfo->af = AF_INET;
            ppinfo->proto = IPPROTO_TCP;
            ppinfo->cmd = 1;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* source IP */
                return EDPVS_INVAL;
            if (1 != inet_pton(AF_INET, token, &ppinfo->addr.ip4.src_addr))
                return EDPVS_INVAL;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* dest IP */
                return EDPVS_INVAL;
            if (1 != inet_pton(AF_INET, token, &ppinfo->addr.ip4.dst_addr))
                return EDPVS_INVAL;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* source port */
                return EDPVS_INVAL;
            ppinfo->addr.ip4.src_port = htons(strtol(token, &end, 10));
            if (*end != '\0')
                return EDPVS_INVAL;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* dest port */
                return EDPVS_INVAL;
            ppinfo->addr.ip4.dst_port = htons(strtol(token, &end, 10));
            if (*end != '\0')
                return EDPVS_INVAL;
            if (NULL != strtok_r(NULL, " ", &tmp))
                return EDPVS_INVAL;
            ppinfo->datalen = ppdlen;
            return EDPVS_OK;
        } else if (!memcmp(token, "TCP6", 4)) {
            ppinfo->af = AF_INET6;
            ppinfo->proto = IPPROTO_TCP;
            ppinfo->cmd = 1;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* source IP */
                return EDPVS_INVAL;
            if (1 != inet_pton(AF_INET6, token, ppinfo->addr.ip6.src_addr))
                return EDPVS_INVAL;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* dest IP */
                return EDPVS_INVAL;
            if (1 != inet_pton(AF_INET6, token, ppinfo->addr.ip6.dst_addr))
                return EDPVS_INVAL;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* source port */
                return EDPVS_INVAL;
            ppinfo->addr.ip6.src_port = htons(strtol(token, &end, 10));
            if (*end != '\0')
                return EDPVS_INVAL;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) /* dest port */
                return EDPVS_INVAL;
            ppinfo->addr.ip6.dst_port = htons(strtol(token, &end, 10));
            if (*end != '\0')
                return EDPVS_INVAL;
            if (NULL != strtok_r(NULL, " ", &tmp))
                return EDPVS_INVAL;
            ppinfo->datalen = ppdlen;
            return EDPVS_OK;
        } else if (!memcpy(token, "UNKNOWN", 7)) {
            ppinfo->datalen = ppdlen;
            ppinfo->cmd = 0;
            if (NULL != strtok_r(NULL, " ", &tmp))
                return EDPVS_INVAL;
            return EDPVS_OK;
        } else {
            return EDPVS_NOTSUPP;
        }
    }

    return EDPVS_OK;
}

static int proxy_proto_send_standalone(struct proxy_info *ppinfo,
        struct dp_vs_conn *conn, struct rte_mbuf *ombuf, void *ol4hdr,
        int *hdr_shift, int ppdlen, char *ppv1data)
{
    int err;
    int ppdoff;
    int oaf;
    void *iph, *oiph, *pph, *l4hdr;
    void *rt;
    struct netif_port *dev = NULL;
    struct tcphdr *th;
    struct rte_udp_hdr *uh;
    struct rte_mbuf *mbuf = NULL;
    struct proxy_hdr_v2 *pphv2;
    struct flow4 fl4;
    struct flow6 fl6;
    uint8_t pp_sent = 1;

    oiph = rte_pktmbuf_mtod(ombuf, void *);
    if (IPPROTO_TCP == conn->proto)
        ppdoff = ol4hdr + (((struct tcphdr *)ol4hdr)->doff << 2) - oiph;
    else
        ppdoff = ol4hdr + sizeof(struct rte_udp_hdr) - oiph;
    assert(ppdoff > 0);

    oaf = tuplehash_out(conn).af;
    rt = MBUF_USERDATA_CONST(ombuf, void *, MBUF_FIELD_ROUTE);
    if (!rt) {
        // fast-xmit only cached dev, not route,
        // so we have to look up route from route table
        if (AF_INET6 == oaf) {
            memset(&fl6, 0, sizeof(fl6));
            fl6.fl6_saddr = conn->laddr.in6;
            fl6.fl6_daddr = conn->daddr.in6;
            fl6.fl6_sport = conn->lport;
            fl6.fl6_dport = conn->dport;
            fl6.fl6_proto = conn->proto;
            rt = route6_output(NULL, &fl6);
            if (unlikely(!rt))
                return EDPVS_NOROUTE;
            dev = ((struct route6 *)rt)->rt6_dev;
            route6_put(rt);
        } else {
            memset(&fl4, 0, sizeof(fl4));
            fl4.fl4_saddr = conn->laddr.in;
            fl4.fl4_daddr = conn->daddr.in;
            fl4.fl4_sport = conn->lport;
            fl4.fl4_dport = conn->dport;
            fl4.fl4_proto = conn->proto;
            rt = route4_output(&fl4);
            if (unlikely(!rt))
                return EDPVS_NOROUTE;
            dev = ((struct route_entry *)rt)->port;
            route4_put(rt);
        }
    } else {
        if (AF_INET6 == oaf)
            dev =((struct route6 *)rt)->rt6_dev;
        else
            dev = ((struct route_entry *)rt)->port;
    }
    if (unlikely(!dev))
        return EDPVS_NOROUTE;

    mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);
    if (unlikely(!mbuf))
        return EDPVS_NOMEM;
    mbuf_userdata_reset(mbuf);

    // L3 header
    if (AF_INET6 == oaf) {
        iph = rte_pktmbuf_append(mbuf, sizeof(struct rte_ipv6_hdr));
        if (unlikely(!iph)) {
            err = EDPVS_NOMEM;
            goto errout;
        }
        ((struct ip6_hdr *)iph)->ip6_ctlun = ((struct ip6_hdr *)oiph)->ip6_ctlun;
        ((struct ip6_hdr *)iph)->ip6_plen = 0; // calc later
        rte_memcpy(&((struct ip6_hdr *)iph)->ip6_src, &conn->laddr.in6, 16);
        rte_memcpy(&((struct ip6_hdr *)iph)->ip6_dst, &conn->daddr.in6, 16);
    } else {
        iph = rte_pktmbuf_append(mbuf, sizeof(struct rte_ipv4_hdr));
        if (unlikely(!iph)) {
            err = EDPVS_NOMEM;
            goto errout;
        }
        ((struct iphdr *)iph)->version  = 4;
        ((struct iphdr *)iph)->ihl      = 5;
        ((struct iphdr *)iph)->tos      = ((struct iphdr *)oiph)->tos;
        ((struct iphdr *)iph)->tot_len  = 0; // calc later
        ((struct iphdr *)iph)->id       = ((struct iphdr *)oiph)->id;
        ((struct iphdr *)iph)->frag_off = 0;
        ((struct iphdr *)iph)->ttl      = ((struct iphdr *)oiph)->ttl;
        ((struct iphdr *)iph)->protocol = ((struct iphdr *)oiph)->protocol;
        ((struct iphdr *)iph)->check    = 0; // calc later
        ((struct iphdr *)iph)->saddr    = conn->laddr.in.s_addr;
        ((struct iphdr *)iph)->daddr    = conn->daddr.in.s_addr;
    }

    // L4 header
    if (IPPROTO_TCP == conn->proto) {
        th = (struct tcphdr *)rte_pktmbuf_append(mbuf, sizeof(struct rte_tcp_hdr));
        if (unlikely(!th)) {
            err = EDPVS_NOMEM;
            goto errout;
        }
        memset(th, 0, sizeof(struct rte_tcp_hdr));
        th->source      = conn->lport;
        th->dest        = conn->dport;
        th->seq         = ((struct tcphdr *)ol4hdr)->seq;
        th->ack_seq     = ((struct tcphdr *)ol4hdr)->ack_seq;
        th->doff        = 5;
        th->psh         = ((struct tcphdr *)ol4hdr)->psh;
        th->ack         = 1;
        th->window      = ((struct tcphdr *)ol4hdr)->window;
        th->check       = 0;
        tcp_in_adjust_seq(conn, th);
        l4hdr = th;
    } else { // IPPROTO_UDP
        uh = (struct rte_udp_hdr *)rte_pktmbuf_append(mbuf, sizeof(struct rte_udp_hdr));
        if (unlikely(!uh)) {
            err = EDPVS_NOMEM;
            goto errout;
        }
        uh->src_port    = conn->lport;
        uh->dst_port    = conn->dport;
        uh->dgram_len   = htons(sizeof(struct rte_udp_hdr) + ppdlen);
        uh->dgram_cksum = 0;
        l4hdr = uh;
    }

    // Proxy Protocol data
    pph = rte_pktmbuf_append(mbuf, ppdlen);
    if (unlikely(!pph)) {
        err = EDPVS_NOMEM;
        goto errout;
    }
    if (PROXY_PROTOCOL_V2 == PROXY_PROTOCOL_VERSION(conn->pp_version)) {
        pphv2 = (struct proxy_hdr_v2 *)pph;
        rte_memcpy(pphv2->sig, PROXY_PROTO_V2_SIGNATURE, sizeof(pphv2->sig));
        pphv2->cmd     = 1;
        pphv2->ver     = PROXY_PROTOCOL_V2;
        pphv2->proto   = ppv2_proto_host2pp(ppinfo->proto);
        pphv2->af      = ppv2_af_host2pp(ppinfo->af);
        pphv2->addrlen = ntohs(ppdlen - sizeof(struct proxy_hdr_v2));
        rte_memcpy(pphv2 + 1, &ppinfo->addr, ppdlen - sizeof(struct proxy_hdr_v2));
    } else if (PROXY_PROTOCOL_V1 == PROXY_PROTOCOL_VERSION(conn->pp_version)) {
        rte_memcpy(pph, ppv1data, ppdlen);
    } else {
        err = EDPVS_NOTSUPP;
        goto errout;
    }

    if (AF_INET6 == oaf) {
        MBUF_USERDATA(mbuf, void *, MBUF_FIELD_ROUTE) = rt;
        route6_get(rt);
        if (IPPROTO_TCP == conn->proto) {
            ((struct ip6_hdr *)iph)->ip6_plen = htons(sizeof(struct rte_tcp_hdr) + ppdlen);
            err = tcp_send_csum(AF_INET6, sizeof(struct rte_ipv6_hdr), l4hdr,
                    conn, mbuf, ((struct route6 *)rt)->rt6_dev);
            if (unlikely(EDPVS_OK != err)) {
                route6_put(rt);
                goto errout;
            }
        } else {
            ((struct ip6_hdr *)iph)->ip6_plen = htons(sizeof(struct rte_udp_hdr) + ppdlen);
            err = udp_send_csum(AF_INET6, sizeof(struct rte_ipv6_hdr), l4hdr,
                    conn, mbuf, NULL, ((struct route6 *)rt)->rt6_dev);
            if (unlikely(EDPVS_OK != err))
                goto errout;
        }
        err = ip6_local_out(mbuf);
        if (err != EDPVS_OK)
            goto errout;
        goto finish;
    } else { // AF_INET
        MBUF_USERDATA(mbuf, void *, MBUF_FIELD_ROUTE) = rt;
        route4_get(rt);
        if (IPPROTO_TCP == conn->proto) {
            ((struct iphdr *)iph)->tot_len  = htons(mbuf->pkt_len);
            err = tcp_send_csum(AF_INET, sizeof(struct rte_ipv4_hdr), l4hdr,
                    conn, mbuf, ((struct route_entry *)rt)->port);
            if (unlikely(EDPVS_OK != err)) {
                route4_put(rt);
                goto errout;
            }
        } else {
            ((struct iphdr *)iph)->tot_len  = htons(mbuf->pkt_len);
            // notes: ipv4 udp checksum is not mandatory
            err = udp_send_csum(AF_INET, sizeof(struct rte_ipv4_hdr), l4hdr,
                    conn, mbuf, NULL, ((struct route_entry *)rt)->port);
            if (unlikely(EDPVS_OK != err)) {
                route4_put(rt);
                goto errout;
            }
        }
        err = ipv4_local_out(mbuf);
        if (err != EDPVS_OK)
            goto errout;
        goto finish;
    }

errout:
    if (likely(NULL != mbuf))
        rte_pktmbuf_free(mbuf);
    return err;

finish:
    // adjust tcp seq number
    if (!conn->pp_sent && IPPROTO_TCP == conn->proto) {
        conn->pp_sent = pp_sent;
        conn->fnat_seq.delta += ppdlen - ppinfo->datalen;
    }

    // adjust protocol data in mbuf and
    // remove the existing proxy protocol data from original mbuf
    if (ppinfo->datalen > 0) {
        if (IPPROTO_UDP == conn->proto) {
            ((struct rte_udp_hdr *)ol4hdr)->dgram_len = htons(ntohs(
                    ((struct rte_udp_hdr *)ol4hdr)->dgram_len) - ppinfo->datalen);
        } else {
            // don't count original ppdatalen in tcp seq ajustment for ombuf
            ((struct tcphdr *)ol4hdr)->seq = htonl(ntohl(
                    ((struct tcphdr *)ol4hdr)->seq) + ppinfo->datalen);
        }
        if (AF_INET == oaf)
            ((struct iphdr *)oiph)->tot_len = htons(ntohs(((struct iphdr *)
                        oiph)->tot_len) - ppinfo->datalen);
        else
            ((struct rte_ipv6_hdr *)oiph)->payload_len = htons(ntohs(((struct rte_ipv6_hdr *)
                        oiph)->payload_len) - ppinfo->datalen);
        memmove(oiph + ppinfo->datalen, oiph, ppdoff);
        if (hdr_shift)
            *hdr_shift = ppinfo->datalen;
        rte_pktmbuf_adj(ombuf, ppinfo->datalen);
        ppinfo->datalen = 0;
    }

    return EDPVS_OK;
}

int proxy_proto_insert(struct proxy_info *ppinfo, struct dp_vs_conn *conn,
        struct rte_mbuf *mbuf, void *l4hdr, int *hdr_shift)
{
    void *iph, *pph, *niph;
    void *rt;
    int ppdoff, ppdatalen, room, mtu;
    int oaf;
    char ppv1buf[108], tbuf1[INET6_ADDRSTRLEN], tbuf2[INET6_ADDRSTRLEN];
    struct proxy_hdr_v2 *pphv2;

    assert(ppinfo && conn && mbuf && l4hdr);

    if (unlikely(conn->proto != ppinfo->proto))
        return EDPVS_INVAL;

    if (unlikely(conn->dest->fwdmode != DPVS_FWD_MODE_FNAT))
        return EDPVS_NOTSUPP;

    if (ppinfo->datalen > 0 && PROXY_PROTOCOL_IS_INSECURE(conn->pp_version)
            && ppinfo->version == PROXY_PROTOCOL_VERSION(conn->pp_version))
        return EDPVS_OK; // proxy the existing proxy protocol data directly to rs

    oaf = tuplehash_out(conn).af;
    rt = MBUF_USERDATA_CONST(mbuf, void *, MBUF_FIELD_ROUTE);
    if (rt) {
        if (AF_INET6 == oaf)
            mtu = ((struct route6 *)rt)->rt6_mtu;
        else
            mtu = ((struct route_entry *)rt)->mtu;
    } else if (conn->in_dev) {
        // fast-xmit
        mtu = conn->in_dev->mtu;
    } else {
        return EDPVS_NOROUTE;
    }

    // calculate required space size in mbuf
    ppdatalen = 0;
    if (PROXY_PROTOCOL_V2 == PROXY_PROTOCOL_VERSION(conn->pp_version)) {
        ppdatalen = sizeof(struct proxy_hdr_v2);
        if (ppinfo->cmd == 1) {
            switch (ppinfo->af) {
            case AF_INET:
                ppdatalen = PROXY_PROTO_HDR_LEN_V4;
                break;
            case AF_INET6:
                ppdatalen = PROXY_PROTO_HDR_LEN_V6;
                break;
            case AF_UNIX:
                ppdatalen += (strlen((const char *)ppinfo->addr.unx.src_addr)
                        + strlen((const char *)ppinfo->addr.unx.dst_addr));
                break;
            default:
                return EDPVS_NOTSUPP;
            }
        }
    } else if (PROXY_PROTOCOL_V1 == PROXY_PROTOCOL_VERSION(conn->pp_version)) {
        if (ppinfo->cmd == 1) {
            if (IPPROTO_TCP != ppinfo->proto)
                return EDPVS_NOTSUPP; // v1 only supports tcp
            switch (ppinfo->af) {
            case AF_INET:
                if (unlikely(NULL == inet_ntop(AF_INET, &ppinfo->addr.ip4.src_addr,
                                tbuf1, sizeof(tbuf1))))
                    return EDPVS_INVAL;
                if (unlikely(NULL == inet_ntop(AF_INET, &ppinfo->addr.ip4.dst_addr,
                                tbuf2, sizeof(tbuf2))))
                    return EDPVS_INVAL;
                if (unlikely(snprintf(ppv1buf, sizeof(ppv1buf), "PROXY TCP4 %s %s %d %d\r\n",
                            tbuf1, tbuf2, ntohs(ppinfo->addr.ip4.src_port),
                            ntohs(ppinfo->addr.ip4.dst_port)) > sizeof(ppv1buf)))
                    return EDPVS_INVAL;
                break;
            case AF_INET6:
                if (unlikely(NULL == inet_ntop(AF_INET6, ppinfo->addr.ip6.src_addr,
                                tbuf1, sizeof(tbuf1))))
                    return EDPVS_INVAL;
                if (unlikely(NULL == inet_ntop(AF_INET6, ppinfo->addr.ip6.dst_addr,
                                tbuf2, sizeof(tbuf2))))
                    return EDPVS_INVAL;
                if (unlikely(snprintf(ppv1buf, sizeof(ppv1buf), "PROXY TCP6 %s %s %d %d\r\n",
                                tbuf1, tbuf2, ntohs(ppinfo->addr.ip6.src_port),
                                ntohs(ppinfo->addr.ip6.dst_port)) > sizeof(ppv1buf)))
                    return EDPVS_INVAL;
                break;
            default:
                return EDPVS_NOTSUPP;
            }
        } else {
            rte_memcpy(ppv1buf, "PROXY UNKNOWN\r\n\0", 16);
        }
        ppdatalen = strlen(ppv1buf);
    } else {
        return EDPVS_NOTSUPP;
    }

    assert(ppdatalen > 0);
    iph = rte_pktmbuf_mtod(mbuf, void *);
    switch (conn->proto) {
        case IPPROTO_TCP:
            pph = l4hdr + (((struct tcphdr *)l4hdr)->doff << 2);
            ppdoff = pph - iph;
            break;
        case IPPROTO_UDP:
            pph = l4hdr + sizeof(struct rte_udp_hdr);
            ppdoff = pph - iph;
            break;
        default:
            return EDPVS_NOTSUPP;
    }

    // just a test for standalone sending
    // return proxy_proto_send_standalone(ppinfo, conn, mbuf, l4hdr, hdr_shift, ppdatalen, ppv1buf);

    assert(ppdoff > 0);
    room = ppdatalen - ppinfo->datalen;
    if (room > 0) {
        // allocate space from mbuf headroom
        if (mbuf->pkt_len + room > mtu)
            return proxy_proto_send_standalone(ppinfo, conn, mbuf, l4hdr, hdr_shift, ppdatalen, ppv1buf);
        niph = rte_pktmbuf_prepend(mbuf, room);
        if (unlikely(!niph))
            return proxy_proto_send_standalone(ppinfo, conn, mbuf, l4hdr, hdr_shift, ppdatalen, ppv1buf);
        memmove(niph, iph, ppdoff);
        if (hdr_shift)
            *hdr_shift = niph - iph;
        iph = niph;
        pph = iph + ppdoff;
    } else if (room < 0) {
        // strip extra space in mbuf
        room = -room;
        niph = iph + room;
        memmove(niph, iph, ppdoff);
        if (hdr_shift)
            *hdr_shift = niph - iph;
        niph = rte_pktmbuf_adj(mbuf, room);
        if (unlikely(!niph))
            return EDPVS_INVPKT;
        iph = niph;
        pph = iph + ppdoff;
    }

    // fill in proxy protocol data
    if (PROXY_PROTOCOL_V2 == PROXY_PROTOCOL_VERSION(conn->pp_version)) {
        pphv2 = (struct proxy_hdr_v2 *)pph;
        rte_memcpy(pphv2->sig, PROXY_PROTO_V2_SIGNATURE, sizeof(pphv2->sig));
        pphv2->cmd = 1;
        pphv2->ver = PROXY_PROTOCOL_V2;
        pphv2->af = ppv2_af_host2pp(ppinfo->af);
        pphv2->proto = ppv2_proto_host2pp(ppinfo->proto);
        pphv2->addrlen = ntohs(ppdatalen - sizeof(struct proxy_hdr_v2));
        rte_memcpy(pphv2 + 1, &ppinfo->addr, ppdatalen - sizeof(struct proxy_hdr_v2));
    } else { // PROXY_PROTOCOL_V1
        rte_memcpy(pph, ppv1buf, ppdatalen);
    }

    // updata ppinfo and mbuf headers
    l4hdr += *hdr_shift;
    if (IPPROTO_TCP == conn->proto) {
        // ajust inbound tcp sequence number except for the first segment
        ((struct tcphdr *)l4hdr)->seq = htonl(ntohl(((struct tcphdr *)l4hdr)->seq)
            - ppdatalen + ppinfo->datalen);
        if (!conn->pp_sent) {
            conn->pp_sent = 1;
            conn->fnat_seq.delta += ppdatalen - ppinfo->datalen;
        }
    } else if (IPPROTO_UDP == conn->proto) {
        ((struct rte_udp_hdr *)l4hdr)->dgram_len = htons(ntohs(
                ((struct rte_udp_hdr *)l4hdr)->dgram_len) + ppdatalen - ppinfo->datalen);
    }
    if (AF_INET == oaf)
        ((struct iphdr *)iph)->tot_len = htons(ntohs(((struct iphdr *)iph)->tot_len)
            + ppdatalen - ppinfo->datalen);
    else
        ((struct rte_ipv6_hdr *)iph)->payload_len = htons(ntohs(((struct rte_ipv6_hdr *)
                    iph)->payload_len) + ppdatalen - ppinfo->datalen);
    ppinfo->datalen = ppdatalen;

    return EDPVS_OK;
}
