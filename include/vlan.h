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
 * dpvs VLAN (802.1q) implementation.
 *
 * raychen@qiyi.com, May 2017, initial.
 */
#ifndef __DPVS_VLAN_H__
#define __DPVS_VLAN_H__
#include <linux/if_ether.h>
#include "conf/common.h"
#include "list.h"
#include "netif.h"

#define VLAN_ID_MAX                 4096
#define VLAN_ID_MASK                0x0fff
#define VLAN_HLEN                   4
#define VLAN_ETH_DATA_LEN           1500

#define mbuf_vlan_tag_get_id(m)     htons(((m)->vlan_tci & VLAN_ID_MASK))

/* VLANs info for real device */
struct vlan_info {
    struct netif_port   *real_dev;
    struct hlist_head   *vlan_dev_hash;
    uint16_t            vlan_dev_num;
    rte_rwlock_t        vlan_lock;
    rte_atomic32_t      refcnt;
};

struct vlan_stats {
    uint64_t            rx_packets;
    uint64_t            rx_bytes;
    uint64_t            rx_multicast;
    uint64_t            tx_packets;
    uint64_t            tx_bytes;
    uint64_t            rx_errors;
    uint64_t            tx_dropped;
};

/**
 * struct vlan_dev_priv - vlan netif device specific info
 * NOTES:
 * 1. about priority mapping
 *    but mbuf has no fields to save priority and
 *    dpvs has no QoS module.
 * 2. refcnt for vlan_dev_priv ?
 *    it's a part of netif_port, if refcnt needed
 *    then add to netif_port.
 */
struct vlan_dev_priv {
    struct hlist_node   hlist;      /* node of real_dev.vlan_dev_hash */
    __be16              vlan_proto; /* now ETH_P_8021Q */
    __be16              vlan_id;
    uint16_t            flags;

    struct netif_port   *dev;
    struct netif_port   *real_dev;

    /* per-CPU statistics
     * RTE_DEFINE_PER_LCORE cannot be used inside struct */
    struct vlan_stats   lcore_stats[DPVS_MAX_LCORE];
};

/**
 *  from linux kernel.
 *
 *    struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *    @h_dest: destination ethernet address
 *    @h_source: source ethernet address
 *    @h_vlan_proto: ethernet protocol
 *    @h_vlan_TCI: priority and VLAN ID
 *    @h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_ethhdr {
    unsigned char    h_dest[ETH_ALEN];
    unsigned char    h_source[ETH_ALEN];
    __be16        h_vlan_proto;
    __be16        h_vlan_TCI;
    __be16        h_vlan_encapsulated_proto;
};

int vlan_add_dev(struct netif_port *real_dev, const char *ifname,
                 __be16 vlan_proto, __be16 vlan_id);

int vlan_del_dev(struct netif_port *real_dev, __be16 vlan_proto,
                 __be16 vlan_id);

struct netif_port *vlan_find_dev(const struct netif_port *real_dev,
                                __be16 vlan_proto, __be16 vlan_id);

int vlan_rcv(struct rte_mbuf *mbuf, struct netif_port *rdev);

int vlan_init(void);

static inline int vlan_insert_tag(struct rte_mbuf *mbuf,
                                  __be16 proto, __be16 id)
{
    struct vlan_ethhdr *veth;
    char *data;

    if (rte_pktmbuf_headroom(mbuf) < VLAN_HLEN)
        return EDPVS_NOROOM;

    veth = (struct vlan_ethhdr *)rte_pktmbuf_prepend(mbuf, VLAN_HLEN);
    data = rte_pktmbuf_mtod(mbuf, char *);
    memmove(data, data + VLAN_HLEN, 2 * ETH_ALEN);

    veth->h_vlan_proto = proto;
    veth->h_vlan_TCI = id;

    return EDPVS_OK;
}

#endif /* __DPVS_VLAN_H__ */
