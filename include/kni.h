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
/**
 * DPDK KNI device management.
 *
 * KNI device should be add/del by request. And any real devices,
 * can be attached on. Such as dpdk phy device, dpdk bonding
 * device and even virtual vlan device.
 *
 * raychen@qiyi.com, June 2017, initial.
 */
#ifndef __DPVS_KNI_H__
#define __DPVS_KNI_H__
#include <stdbool.h>
#include "netif.h"

/*
 * NOTE:
 * 1. local ip filter will make input set fixed on ixgbe/i40e.
 * 2. dip filter is not supported by ixgbe and i40e under the
 *    premise of local ip filter.
 * 3. use dip + dport + dst_port_mask filters to cover port range
 *    [0-65535] to replace dip filter on ixgbe/i40e.
 * 4. kni fdir filter support tcp and udp, icmp not supported.
 * 5. if (fdir_conf.mask.dst_port_mask & pkt.dport) equal to an
 *    element in the port_base_array, pkt will match kni fdir
 *    filter and redirected to kni rx queue.
 * 6. rss rte_flow to specfic rss queue region should with lower
 *    priority than lip and kni fdir filter.
 */
typedef struct kni_fdir {
    bool                    init_success;                    /* kni fdir init flag */
    uint16_t                filter_mask;                     /* kni filter's port mask */
    uint16_t                port_base_num;                   /* kni port_base num */
    __be16                  port_base_array[DPVS_MAX_LCORE]; /* kni port_base set */
    uint32_t                soft_id_array[DPVS_MAX_LCORE][MAX_FDIR_PROTO];
} dp_vs_kni_fdir;

/*
 * @dev     - real device kni attach to.
 * @kniname - optional, kni device name or auto generate.
 */
int kni_add_dev(struct netif_port *dev, const char *kniname);

int kni_del_dev(struct netif_port *dev);
int kni_init(void);

int kni_fdir_init(void);
int kni_fdir_filter_add(struct netif_port *dev,
                        const union inet_addr *kni_ip,
                        int af);

static inline bool kni_dev_exist(const struct netif_port *dev)
{
    return dev->kni.kni ? true : false;
}

static inline void kni_handle_request(const struct netif_port *dev)
{
    if (!kni_dev_exist(dev))
        return;

    rte_kni_handle_request(dev->kni.kni);
}

static inline bool kni_fwd_valid(const struct netif_port *dev,
                                 kni_fwd_mode_t fwd_mode)
{
    if (fwd_mode == KNI_FWD_MODE_DEFAULT) {
        return true;
    }

    if ((fwd_mode == KNI_FWD_MODE_ISOLATE_RX)
        && (dev->kni.fwd_mode == fwd_mode)
        && (dev->kni.rx_queue_id != NETIF_QUEUE_ID_INVALID))
    {
        return true;
    }

    return false;
}

#endif /* __DPVS_KNI_H__ */
