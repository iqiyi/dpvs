/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2020 iQIYI (www.iqiyi.com).
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

#ifndef __NETIF_FLOW_H__
#define __NETIF_FLOW_H__

#include "netif.h"

struct netif_flow_handler {
    portid_t pid;
    void *handler;
};

typedef struct netif_flow_handler_param {
    int size;
    int flow_num;
    struct netif_flow_handler *handlers; // pointing to an netif_flow_handler array from outside
} netif_flow_handler_param_t;

/*
 *  Add sapool flow rules (for fullnat and snat).
 *
 *  @param dev [in]
 *      Target device for the flow rules, supporting bonding/physical ports.
 *  @param cid [in]
 *      Lcore id to which to route the target flow.
 *  @param af [in]
 *      IP address family.
 *  @param addr [in]
 *      IP address of the sapool.
 *  @param port_base [in]
 *      TCP/UDP base port of the sapool.
 *  @param port_mask [in]
 *      TCP/UDP mask mask of the sapool.
 *  @param flows [out]
 *      Containing netif flow handlers if success, undefined otherwise.
 *
 *  @return
 *      DPVS error code.
 */
int netif_sapool_flow_add(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            __be16 port_base, __be16 port_mask,
            netif_flow_handler_param_t *flows);

/*
 *  Delete saflow rules (for fullnat and snat).
 *  @param dev [in]
 *      Target device for the flow rules, supporting bonding/physical ports.
 *  @param cid [in]
 *      Lcore id to which to route the target flow.
 *  @param af [in]
 *      IP address family.
 *  @param addr [in]
 *      IP address of the sapool.
 *  @param port_base [in]
 *      TCP/UDP base port of the sapool.
 *  @param port_mask [in]
 *      TCP/UDP mask mask of the sapool.
 *  @param flows [in]
 *      Containing netif flow handlers to delete.
 *
 *  @return
 *      DPVS error code.
 */
int netif_sapool_flow_del(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            __be16 port_base, __be16 port_mask,
            netif_flow_handler_param_t *flows);

/*
 *  Add kni flow rules.
 *  @param dev [in]
 *      Target device for the flow rules, supporting bonding/physical ports.
 *  @param cid [in]
 *      Lcore id to which to route the target flow.
 *  @param af [in]
 *      IP address family.
 *  @param addr [in]
 *      Dedicated IP address of kni interface.
 *  @param flows [in]
 *      Containing netif flow handlers to delete.
 *
 *  @return
 *      DPVS error code.
 */
int netif_kni_flow_add(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            netif_flow_handler_param_t *flows);

/*
 *  Delete kni flow rules.
 *  @param dev [in]
 *      Target device for the flow rules, supporting bonding/physical ports.
 *  @param cid [in]
 *      Lcore id to which to route the target flow.
 *  @param af [in]
 *      IP address family.
 *  @param addr [in]
 *      Dedicated IP address of kni interface.
 *  @param flows [out]
 *      Containing netif flow handlers if success, undefined otherwise.
 *
 *  @return
 *      DPVS error code.
 */
int netif_kni_flow_del(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            netif_flow_handler_param_t *flows);
/*
 *  Flush all flow rules on a port.  *
 *  @param dev
 *      Target device, supporting bonding/physical ports.
 *
 *  @return
 *      DPVS error code.
 */
int netif_flow_flush(struct netif_port *dev);

#endif
