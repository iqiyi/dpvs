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
#ifndef __DPVS_VLAN_CONF_H__
#define __DPVS_VLAN_CONF_H__
#include <stdint.h>
#include <net/if.h>
#include "conf/sockopts.h"
#include "vlan.h"

struct vlan_param {
    char        real_dev[IFNAMSIZ]; /* underlying device name */
    char        ifname[IFNAMSIZ];   /* vlan device name, e.g., dpdk0.100
                                       leave it empty auto-generate when add. */
    uint16_t    vlan_proto;         /* ETH_P_8021Q ... */
    uint16_t    vlan_id;            /* host byte order */
} __attribute__((__packed__));

struct vlan_param_array {
    int         nparam;
    struct vlan_param params[0];
};

#endif /* __DPVS_VLAN_CONF_H__ */
