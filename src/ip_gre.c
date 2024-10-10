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
 * dpvs GRE/IP tunnel.
 * refer linux:net/ipv4/ip_gre.c, net/gre.h
 *
 * raychen@qiyi.com, Jan 2018, initial.
 */
#include <assert.h>
#include <endian.h>
#include "dpdk.h"
#include "netif.h"
#include "ipv4.h"
#include "icmp.h"
#include "ip_tunnel.h"

#define GRE
#define RTE_LOGTYPE_GRE     RTE_LOGTYPE_USER1

#define GRE_F_CSUM          htobe16(0x8000)
#define GRE_F_ROUTING       htobe16(0x4000)
#define GRE_F_KEY           htobe16(0x2000)
#define GRE_F_SEQ           htobe16(0x1000)
#define GRE_F_STRICT        htobe16(0x0800)
#define GRE_F_REC           htobe16(0x0700)
#define GRE_F_FLAGS         htobe16(0x00F8)
#define GRE_F_VERSION       htobe16(0x0007)

/* linux: net/gre.h */
struct gre_base_hdr {
    __be16  flags;
    __be16  protocol;
} __attribute__((__packed__));

static struct ip_tunnel_tab gre_tunnel_tab;

/* linux: gre_flags_to_tnl_flags */
static inline __be16 flags_gre2tnl(__be16 flags)
{
    __be16 tflags = 0;

    if (flags & GRE_F_CSUM)
        tflags |= TUNNEL_F_CSUM;
    if (flags & GRE_F_ROUTING)
        tflags |= TUNNEL_F_ROUTING;
    if (flags & GRE_F_KEY)
        tflags |= TUNNEL_F_KEY;
    if (flags & GRE_F_SEQ)
        tflags |= TUNNEL_F_SEQ;
    if (flags & GRE_F_STRICT)
        tflags |= TUNNEL_F_STRICT;
    if (flags & GRE_F_REC)
        tflags |= TUNNEL_F_REC;
    if (flags & GRE_F_VERSION)
        tflags |= TUNNEL_F_VERSION;

    return tflags;
}

/* linux: gre_tnl_flags_to_gre_flags */
static inline __be16 flags_tnl2gre(__be16 tflags)
{
    __be16 flags = 0;

    if (tflags & TUNNEL_F_CSUM)
        flags |= GRE_F_CSUM;
    if (tflags & TUNNEL_F_ROUTING)
        flags |= GRE_F_ROUTING;
    if (tflags & TUNNEL_F_KEY)
        flags |= GRE_F_KEY;
    if (tflags & TUNNEL_F_SEQ)
        flags |= GRE_F_SEQ;
    if (tflags & TUNNEL_F_STRICT)
        flags |= GRE_F_STRICT;
    if (tflags & TUNNEL_F_REC)
        flags |= GRE_F_REC;
    if (tflags & TUNNEL_F_VERSION)
        flags |= GRE_F_VERSION;

    return flags;
}

static inline __be16 gre_checksum(struct rte_mbuf *mbuf)
{
    __be16 csum;

    csum = rte_raw_cksum(rte_pktmbuf_mtod(mbuf, void *), mbuf->data_len);
    return csum == 0xffff ? csum : ~csum;
}

/* linux: gre_calc_hlen */
static inline int gre_calc_hlen(__be16 o_flags)
{
    int addend = 4;

    if (o_flags & TUNNEL_F_CSUM)
        addend += 4;
    if (o_flags & TUNNEL_F_KEY)
        addend += 4;
    if (o_flags & TUNNEL_F_SEQ)
        addend += 4;

    return addend;
}

/* linux: gre_build_header */
static int gre_build_header(struct rte_mbuf *mbuf, int hlen, __be16 flags,
                            __be16 proto, __be32 key, __be32 seq)
{
    struct gre_base_hdr *greh;

    assert(mbuf && hlen >= sizeof(*greh));

    greh = (struct gre_base_hdr *)rte_pktmbuf_prepend(mbuf, hlen);
    if (unlikely(!greh))
        return EDPVS_NOROOM;

    greh->flags = flags_tnl2gre(flags);
    greh->protocol = proto;

    if (flags & (TUNNEL_F_KEY | TUNNEL_F_CSUM | TUNNEL_F_SEQ)) {
        __be32 *ptr = (__be32 *)(((uint8_t *)greh) + hlen - 4);

        if (flags & TUNNEL_F_SEQ)
            *ptr-- = seq;

        if (flags & TUNNEL_F_KEY)
            *ptr-- = key;

        if (flags & TUNNEL_F_CSUM) {
            *ptr = 0;
            *(__be16 *)ptr = gre_checksum(mbuf);
        }
    }

    return EDPVS_OK;
}

/* linux: gre_parse_header.
 * return header length to be pulled and fill tpi if success. */
static int gre_parse_header(struct rte_mbuf *mbuf,
                            struct ip_tunnel_pktinfo *tpi,
                            bool *csum_err, __be16 proto)
{
    const struct gre_base_hdr *greh;
    __be32 *options;
    int hlen;

    if (unlikely(mbuf_may_pull(mbuf, sizeof(*greh)) != 0))
        return EDPVS_INVPKT;

    greh = rte_pktmbuf_mtod(mbuf, struct gre_base_hdr *);
    if (unlikely(greh->flags & (GRE_F_VERSION | GRE_F_ROUTING)))
        return EDPVS_INVPKT;

    tpi->flags = flags_gre2tnl(greh->flags);
    hlen = gre_calc_hlen(tpi->flags);

    if (unlikely(mbuf_may_pull(mbuf, hlen) != 0))
        return EDPVS_INVPKT;

    greh = rte_pktmbuf_mtod(mbuf, struct gre_base_hdr *);
    tpi->proto = greh->protocol;

    options = (__be32 *)(greh + 1);
    if (greh->flags & GRE_F_CSUM) {
        /* XXX: not support segments for csum */
        if (unlikely(mbuf->next != NULL))
            return EDPVS_INVPKT;

        if (unlikely(rte_raw_cksum(greh, mbuf->data_len) != 0xffff)) {
            *csum_err = true;
            return EDPVS_INVPKT;
        }

        options++;
    }

    if (greh->flags & GRE_F_KEY)
        tpi->key = *options++;
    else
        tpi->key = 0;

    if (greh->flags & GRE_F_SEQ)
        tpi->seq = *options++;
    else
        tpi->seq = 0;

    tpi->hdr_len = hlen;
    return hlen;
}

static int gre_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    const struct iphdr *tiph = &tnl->params.iph;
    int err;

    /* TODO: GRE offload */

    if (tnl->params.o_flags & TUNNEL_F_SEQ)
        tnl->o_seqno++;

    err = gre_build_header(mbuf, tnl->hlen, tnl->params.o_flags,
                           htons(mbuf->packet_type), tnl->params.o_key,
                           htonl(tnl->o_seqno));
    if (err != EDPVS_OK) {
        rte_pktmbuf_free(mbuf);
        return err;
    }

    return ip_tunnel_xmit(mbuf, dev, tiph, IPPROTO_GRE);
}

static int gre_dev_init(struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    tnl->hlen = gre_calc_hlen(tnl->params.o_flags);

    return ip_tunnel_dev_init(dev);
}

static struct netif_ops gre_dev_ops = {
    .op_init             = gre_dev_init,
    .op_xmit             = gre_xmit,
    .op_set_mc_list      = ip_tunnel_set_mc_list,
    .op_get_link         = ip_tunnel_get_link,
    .op_get_stats        = ip_tunnel_get_stats,
    .op_get_promisc      = ip_tunnel_get_promisc,
    .op_get_allmulticast = ip_tunnel_get_allmulticast,
};

static void gre_setup(struct netif_port *dev)
{
    dev->netif_ops = &gre_dev_ops;
}

static int gre_change(struct netif_port *dev,
                      const struct ip_tunnel_param *param)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    tnl->hlen = gre_calc_hlen(param->o_flags);

    return EDPVS_OK;
}

static int gre_rcv(struct rte_mbuf *mbuf)
{
    int hlen;
    struct iphdr *iph;
    struct ip_tunnel *tnl;
    struct ip_tunnel_pktinfo tpi;
    bool csum_err = false;

    hlen = gre_parse_header(mbuf, &tpi, &csum_err, htons(ETH_P_IP));
    if (hlen < 0)
        goto drop;

    iph = MBUF_USERDATA(mbuf, struct iphdr *, MBUF_FIELD_PROTO); /* see ipv4_local_in_fin */
    assert(iph->version == 4 && iph->protocol == IPPROTO_GRE);

    tnl = ip_tunnel_lookup(&gre_tunnel_tab, mbuf->port, tpi.flags,
                           iph->saddr, iph->daddr, tpi.key);
    if (!tnl) {
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
        goto drop;
    }

    if (ip_tunnel_pull_header(mbuf, hlen, tpi.proto) != 0)
        goto drop;

    return ip_tunnel_rcv(tnl, &tpi, mbuf);

drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

static struct ip_tunnel_ops gre_tnl_ops = {
    .kind       = "gre",
    .priv_size  = sizeof(struct ip_tunnel),
    .setup      = gre_setup,
    .change     = gre_change,
};

static struct inet_protocol gre_proto = {
    .handler    = gre_rcv,
};

int gre_init(void)
{
    int err;

    err = ip_tunnel_init_tab(&gre_tunnel_tab, &gre_tnl_ops, "gre0");
    if (err != EDPVS_OK)
        return err;

    err = ipv4_register_protocol(&gre_proto, IPPROTO_GRE);
    if (err != EDPVS_OK) {
        ip_tunnel_term_tab(&gre_tunnel_tab);
        return err;
    }

    return err;
}

int gre_term(void)
{
    int err;

    err = ipv4_unregister_protocol(&gre_proto, IPPROTO_GRE);
    if (err != EDPVS_OK)
        return err;

    err = ip_tunnel_term_tab(&gre_tunnel_tab);
    if (err != EDPVS_OK)
        return err;

    return err;
}
