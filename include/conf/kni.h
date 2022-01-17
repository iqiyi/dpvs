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
#ifndef __DPVS_KNI_CONF_H__
#define __DPVS_KNI_CONF_H__

#include <net/if.h>
#include "conf/inet.h"

enum kni_data_type {
    KNI_DTYPE_ADDR_FLOW = 1,
};

struct kni_addr_flow_entry {
    int                 af;
    union inet_addr     addr;
};

struct kni_addr_flow_info {
    int                         nentries;
    struct kni_addr_flow_entry  entries[0];
} __attribute__((__packed__));

struct kni_conf_param {
    enum kni_data_type  type;
    char                ifname[IFNAMSIZ];
    union {
        struct kni_addr_flow_entry flow;
    }                   data;
} __attribute__((__packed__));

struct kni_info {
    int len;
    struct kni_conf_param entries[0];
} __attribute__((__packed__));

#endif /* __DPVS_KNI_CONF_H__ */
