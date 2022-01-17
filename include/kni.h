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

#define MAX_KNI_FLOW    2

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

static inline void kni_handle_request(const struct netif_port *dev)
{
    if (!kni_dev_exist(dev))
        return;

    rte_kni_handle_request(dev->kni.kni);
}

#endif /* __DPVS_KNI_H__ */
