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
 * dpvs IPv4 tunnel common codes.
 * refer linux:include/net/ip_tunnels.h
 *       linux:include/uapi/linux/if_tunnel.h
 *
 * raychen@qiyi.com, Dec 2017, initial.
 */
#ifndef __DPVS_TUNNEL_H__
#define __DPVS_TUNNEL_H__
#include <net/if.h>
#include <netinet/ip.h>
#include <endian.h>
#include "conf/ip_tunnel.h"
#include "list.h"
#include "netif.h"
#include "route.h"

struct ip_tunnel_tab;

struct ip_tunnel_ops {
    const char              *kind;
    uint32_t                priv_size;
    struct list_head        list;
    struct ip_tunnel_tab    *tab;
    void                    (*setup)(struct netif_port *dev);
    int                     (*change)(struct netif_port *dev,
                                      const struct ip_tunnel_param *params);
};

#define IP_TNL_HASH_BITS    7
#define IP_TNL_HASH_SIZE    (1 << IP_TNL_HASH_BITS)

/* table of tunnels for each kind. */
struct ip_tunnel_tab {
    struct netif_port       *fb_tunnel_dev; /* fullback device */
    struct hlist_head       tunnels[IP_TNL_HASH_SIZE];
    int                     nb_tnl; /* total number of tunnel */
    struct ip_tunnel_ops    *ops;
};

struct ip_tunnel {
    struct hlist_node       hlist;
    struct netif_port       *dev;
    struct netif_port       *link;
    struct ip_tunnel_tab    *tab;
    struct ip_tunnel_param  params;
    int                     hlen;

    struct route_entry      *rt_cache;

    /* GRE only */
    uint32_t                i_seqno;
    uint32_t                o_seqno;
};

struct ip_tunnel_pktinfo {
    __be16  flags;
    __be16  proto;
    __be32  key;
    __be32  seq;
    int     hdr_len;
};

int ip_tunnel_init(void);
int ip_tunnel_term(void);

int ip_tunnel_init_tab(struct ip_tunnel_tab *tab, struct ip_tunnel_ops *ops,
                       const char *fbname);
int ip_tunnel_term_tab(struct ip_tunnel_tab *tab);

struct ip_tunnel *ip_tunnel_lookup(struct ip_tunnel_tab *tab,
                                   portid_t link, __be16 flags,
                                   __be32 remote, __be32 local,
                                   __be32 key);

int ip_tunnel_rcv(struct ip_tunnel *tnl, struct ip_tunnel_pktinfo *tpi,
                  struct rte_mbuf *mbuf);

int ip_tunnel_xmit(struct rte_mbuf *mbuf, struct netif_port *dev,
                   const struct iphdr *tiph, uint8_t proto);

int ip_tunnel_pull_header(struct rte_mbuf *mbuf, int hlen, __be16 in_proto);

int ip_tunnel_dev_init(struct netif_port *dev);
int ip_tunnel_set_mc_list(struct netif_port *dev);
int ip_tunnel_get_link(struct netif_port *dev, struct rte_eth_link *link);
int ip_tunnel_get_stats(struct netif_port *dev, struct rte_eth_stats *stats);
int ip_tunnel_get_promisc(struct netif_port *dev, bool *promisc);
int ip_tunnel_get_allmulticast(struct netif_port *dev, bool *allmulticast);

int ipip_init(void);
int ipip_term(void);

int gre_init(void);
int gre_term(void);

#endif /* __DPVS_TUNNEL_H__ */
