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
#include "netif_flow.h"
#include "linux_if.h"
#include "dpdk.h"

#define MAX_KNI_FLOW    2

#ifndef RTE_LOGTYPE_Kni
#define RTE_LOGTYPE_Kni     RTE_LOGTYPE_USER1
#endif

struct kni_addr_flow {
    struct list_head node;
    int af;
    int nflows;
    lcoreid_t kni_worker;
    struct netif_port *dev;
    union inet_addr addr;
    struct netif_flow_handler flows[MAX_KNI_FLOW];
};

/*
 * @dev     - real device kni attach to.
 * @kniname - optional, kni device name or auto generate.
 */
int kni_add_dev(struct netif_port *dev, const char *kniname);

int kni_del_dev(struct netif_port *dev);
int kni_init(void);
int kni_ctrl_init(void);
int kni_ctrl_term(void);

static inline bool kni_dev_exist(const struct netif_port *dev)
{
    return dev->kni.kni ? true : false;
}

static inline bool kni_dev_running(const struct netif_port *dev)
{
    return kni_dev_exist(dev) && !!(dev->kni.flags & NETIF_PORT_FLAG_RUNNING);
}

#ifdef CONFIG_KNI_VIRTIO_USER
static inline void disable_kni_tx_csum_offload(const char *ifname)
{
    // TODO: Support tx-csum offload on virtio-user kni device.
    struct {
        struct ethtool_gfeatures hdr;
        struct ethtool_get_features_block blocks[1];
    } gfeatures;

    if (linux_get_if_features(ifname, 1, (struct ethtool_gfeatures *)&gfeatures) < 0)
        RTE_LOG(WARNING, Kni, "linux_get_if_features(%s) failed\n", ifname);
    else if (gfeatures.blocks[0].requested & 0x1A
        /* NETIF_F_IP_CSUM_BIT|NETIF_F_HW_CSUM_BIT|NETIF_F_IPV6_CSUM_BIT */)
        RTE_LOG(INFO, Kni, "%s: tx-csum offload supported but to be disabled on %s!\n",
                __func__, ifname);

    // Disable tx-csum offload, and delegate the task to device driver.
    if (linux_set_tx_csum_offload(ifname, 0) < 0)
        RTE_LOG(WARNING, Kni, "failed to disable tx-csum offload on %s\n", ifname);
}

static inline void kni_tx_csum(struct rte_mbuf *mbuf)
{
    // TODO:
    // Support tx-csum offload on virtio-user kni device.
}
#else
// rte_kni doesn't support tx-csum offload feature
static inline void disable_kni_tx_csum_offload(const char *ifname) {}

static inline void kni_handle_request(const struct netif_port *dev)
{
    if (!kni_dev_exist(dev))
        return;

    rte_kni_handle_request(dev->kni.kni);
}
#endif

#endif /* __DPVS_KNI_H__ */
