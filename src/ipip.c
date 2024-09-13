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
 * dpvs IP-in-IP tunnel.
 * refer linux:net/ipv4/ipip.c
 *
 * raychen@qiyi.com, Dec 2017, initial.
 */
#include <assert.h>
#include "ipv4.h"
#include "ip_tunnel.h"

#define IPIP
#define RTE_LOGTYPE_IPIP    RTE_LOGTYPE_USER1

static struct ip_tunnel_tab ipip_tunnel_tab;

static int ipip_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    const struct iphdr *tiph = &tnl->params.iph;

    if (tiph->protocol != IPPROTO_IPIP && tiph->protocol != 0) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_DROP;
    }

    /* TODO: IPIP offload */

    return ip_tunnel_xmit(mbuf, dev, tiph, IPPROTO_IPIP);
}

static struct netif_ops ipip_dev_ops = {
    .op_init             = ip_tunnel_dev_init,
    .op_xmit             = ipip_xmit,
    .op_set_mc_list      = ip_tunnel_set_mc_list,
    .op_get_link         = ip_tunnel_get_link,
    .op_get_stats        = ip_tunnel_get_stats,
    .op_get_promisc      = ip_tunnel_get_promisc,
    .op_get_allmulticast = ip_tunnel_get_allmulticast,
};

/* dummy packet info for ipip tunnel. */
static struct ip_tunnel_pktinfo ipip_tpi = {
    /* .proto      = htons(ETH_P_IP), */
};

static void ipip_setup(struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);

    dev->netif_ops = &ipip_dev_ops;
    tnl->hlen = 0; /* no overhead for IP-in-IP tunnel */
}

static int ipip_rcv(struct rte_mbuf *mbuf)
{
    struct iphdr *iph;
    struct ip_tunnel *tnl;

    /* IPv4's upper layer can use @userdata for IP header,
     * see ipv4_local_in_fin() */
    iph = MBUF_USERDATA(mbuf, struct iphdr *, MBUF_FIELD_PROTO);
    assert(iph->version == 4 && iph->protocol == IPPROTO_IPIP);

    tnl = ip_tunnel_lookup(&ipip_tunnel_tab, mbuf->port, TUNNEL_F_NO_KEY,
                           iph->saddr, iph->daddr, 0);
    if (!tnl)
        goto drop;

    if (tnl->params.iph.protocol != IPPROTO_IPIP &&
        tnl->params.iph.protocol != 0)
        goto drop;

    if (ip_tunnel_pull_header(mbuf, 0, ipip_tpi.proto) != EDPVS_OK)
        goto drop;

    return ip_tunnel_rcv(tnl, &ipip_tpi, mbuf);

drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

static struct ip_tunnel_ops ipip_tunnel_ops = {
    .kind       = "ipip",
    .priv_size  = sizeof(struct ip_tunnel),
    .setup      = ipip_setup,
};

static struct inet_protocol ipip_proto = {
    .handler    = ipip_rcv,
};

int ipip_init(void)
{
    int err;

    ipip_tpi.proto = htons(ETH_P_IP);

    err = ip_tunnel_init_tab(&ipip_tunnel_tab, &ipip_tunnel_ops, "tunl0");
    if (err != EDPVS_OK)
        return err;

    err = ipv4_register_protocol(&ipip_proto, IPPROTO_IPIP);
    if (err != EDPVS_OK) {
        ip_tunnel_term_tab(&ipip_tunnel_tab);
        return err;
    }

    return err;
}

int ipip_term(void)
{
    int err;

    err = ipv4_unregister_protocol(&ipip_proto, IPPROTO_IPIP);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IPIP, "%s: fail to unregister proto\n", __func__);
        return err;
    }

    err = ip_tunnel_term_tab(&ipip_tunnel_tab);
    if (err != EDPVS_OK)
        RTE_LOG(ERR, IPIP, "%s: fail to term tab\n", __func__);

    return err;
}
