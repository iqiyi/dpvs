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
#ifndef __DPVS_LLDP_CONF_H__
#define __DPVS_LLDP_CONF_H__

#include <net/if.h>
#include "conf/sockopts.h"

#define LLDP_MESSAGE_LEN        4096

#define DPVS_LLDP_NODE_LOCAL    0
#define DPVS_LLDP_NODE_NEIGH    1
#define DPVS_LLDP_NODE_MAX      2


struct lldp_param {
    uint16_t node;              /* DPVS_LLDP_NODE_xxx */
    char ifname[IFNAMSIZ];
};

struct lldp_message {
    struct lldp_param param;
    char message[LLDP_MESSAGE_LEN];
};

#endif /* __DPVS_LLDP_CONF_H__ */
