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
/*
 * mbuf.c of dpvs.
 *
 * it includes some mbuf related functions beyond dpdk mbuf API.
 */
#include <assert.h>
#include "mbuf.h"
#include "inet.h"
#include "ipv4.h"
#include "sys_time.h"

#define EMBUF
#define RTE_LOGTYPE_EMBUF    RTE_LOGTYPE_USER1

/**
 * mbuf_may_pull - pull bits from segments to heading mbuf if needed.
 * see pskb_may_pull() && __pskb_pull_tail().
 *
 * it expands heading mbuf, moving it's tail forward and copying necessary
 * data from segments part.
 */
int mbuf_may_pull(struct rte_mbuf *mbuf, unsigned int len)
{
    int delta, eat;
    struct rte_mbuf *seg, *next;

    if (likely(len <= mbuf->data_len))
        return 0;

    if (unlikely(len > mbuf->pkt_len))
        return -1;

    delta = len - mbuf->data_len;

    /* different from skb, there's no way to expand mbuf's tail room,
     * because mbuf size is determined when init mbuf pool */
    if (rte_pktmbuf_tailroom(mbuf) < delta) {
        RTE_LOG(ERR, EMBUF, "%s: no tail room.", __func__);
        return -1;
    }

    /* pull bits needed from segments to tail room of heading mbuf */
    if (mbuf_copy_bits(mbuf, mbuf->data_len,
               mbuf_tail_point(mbuf), delta) != 0)
        return -1;

    /* free fully eaten segments and leave left segs attached,
     * points need be reload if partial bits was eaten for a seg. */
    eat = delta;
    mbuf_foreach_seg_safe(mbuf, next, seg) {
        if (eat <= 0)
            break;

        if (seg->data_len <= eat) {
            assert(mbuf->next == seg);
            eat -= seg->data_len;
            rte_pktmbuf_free_seg(seg);
            mbuf->next = next;
            mbuf->nb_segs--;
        } else {
            rte_pktmbuf_adj(seg, eat);
            eat = 0;
            break;
        }
    }

    assert(!eat &&
           mbuf->data_off + mbuf->data_len + delta <= mbuf->buf_len);

    /* mbuf points must be updated */
    mbuf->data_len += delta;

    return 0;
}

void mbuf_copy_metadata(struct rte_mbuf *mi, struct rte_mbuf *m)
{
    RTE_ASSERT(rte_mbuf_refcnt_read(mi) == 1);
    mi->priv_size = m->priv_size;
    mi->buf_len = m->buf_len;
    mi->data_off = m->data_off;
    mi->data_len = m->data_len;
    mi->port = m->port;
    mi->vlan_tci = m->vlan_tci;
    mi->vlan_tci_outer = m->vlan_tci_outer;
    mi->tx_offload = m->tx_offload;
    mi->hash = m->hash;
    mi->next = NULL;
    mi->pkt_len = mi->data_len;
    mi->nb_segs = 1;
    mi->ol_flags = m->ol_flags & (~IND_ATTACHED_MBUF);
    mi->packet_type = m->packet_type;
    mi->userdata = NULL;

    __rte_mbuf_sanity_check(mi, 1);
    __rte_mbuf_sanity_check(m, 0);
}

struct rte_mbuf *mbuf_copy(struct rte_mbuf *md, struct rte_mempool *mp)
{
    struct rte_mbuf *mc, *mi, **prev;
    uint32_t pktlen;
    uint8_t nseg;

    if (unlikely ((mc = rte_pktmbuf_alloc(mp)) == NULL))
        return NULL;

    mi = mc;
    pktlen = md->pkt_len;
    nseg = 0;
    prev = &mi->next;

    do {
        nseg++;
        mbuf_copy_metadata(mi, md);
        *prev = mi;
        prev = &mi->next;
        rte_memcpy(rte_pktmbuf_mtod(mi, void *), rte_pktmbuf_mtod(md, void *), md->data_len);
    } while ((md = md->next) != NULL && (mi = rte_pktmbuf_alloc(mp)) != NULL);

    *prev =  NULL;
    mc->nb_segs = nseg;
    mc->pkt_len = pktlen;

    if (unlikely (mi == NULL)) {
        rte_pktmbuf_free(mc);
        return NULL;
    }

    __rte_mbuf_sanity_check(mc, 1); //check packet header segment
    return mc;
}

#ifdef CONFIG_DPVS_MBUF_DEBUG
inline void dp_vs_mbuf_dump(const char *msg, int af, const struct rte_mbuf *mbuf)
{
    char stime[SYS_TIME_STR_LEN];
    char sbuf[64], dbuf[64];
    struct ipv4_hdr *iph;
    union inet_addr saddr, daddr;
    __be16 _ports[2], *ports;

    if (af != AF_INET)
        return;

    iph = ip4_hdr(mbuf);
    saddr.in.s_addr = iph->src_addr;
    daddr.in.s_addr = iph->dst_addr;
    ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
    if (!ports)
        return;

    RTE_LOG(DEBUG, MBUF, "[%s]%s: %s "
        "%s %s:%u to %s:%u\n", sys_localtime_str(stime, SYS_TIME_STR_LEN),
        __func__, msg ? msg : "", inet_proto_name(iph->next_proto_id),
        inet_ntop(af, &saddr, sbuf, sizeof(sbuf)),
        ntohs(ports[0]),
        inet_ntop(af, &daddr, dbuf, sizeof(dbuf)),
        ntohs(ports[1]));
}
#endif
