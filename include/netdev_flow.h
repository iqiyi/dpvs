/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2020 ByteDance (www.bytedance.com).
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
 * Copyright (C) 2020 ByteDance (www.bytedance.com).
 * All Rights Reserved.
 *
 * wanlebing@bytedance.com, 12/2020.
 */
#ifndef __NETDEV_FLOW_H__
#define __NETDEV_FLOW_H__

#include <assert.h>
#include <rte_flow.h>

#include "conf/common.h"
#include "netif.h"

#ifndef NETDEV
#define NETDEV
#define RTE_LOGTYPE_NETDEV RTE_LOGTYPE_USER1
#endif

#define DEFAULT_MAX_PATTERNS          6
#define DEFAULT_MAX_ACTIONS           6

#define NETDEV_FLOW_DEFAULT_MARK_ID   1
#define NETDEV_FLOW_DEFAULT_RSS_LEVEL 0

/* fuzzy match level with signature mode */
#define DEFAULT_FUZZY_SPEC            2
#define DEFAULT_FUZZY_LAST            0xfffffff0
#define DEFAULT_FUZZY_MASK            0xffffffff

#define NETDEV_IXGBE_DRIVER_NAME      "ixgbe"
#define NETDEV_I40E_DRIVER_NAME       "i40e"
#define NETDEV_MLNX_DRIVER_NAME       "net_mlx5"

/* flags for netdev flow */
#define NETDEV_FLOW_F_SIP_FIELD       (1 << 0)
#define NETDEV_FLOW_F_DIP_FIELD       (1 << 1)
#define NETDEV_FLOW_F_SPORT_FIELD     (1 << 2)
#define NETDEV_FLOW_F_DPORT_FIELD     (1 << 3)
#define NETDEV_FLOW_F_L3_PROTO_FIELD  (1 << 4)
#define NETDEV_FLOW_F_L4_PROTO_FIELD  (1 << 5)

/*
 * assign static priority on various flow
 * the smaller the priority higher on mellanox nic.
 */
enum netdev_flow_priority {
    NETDEV_FLOW_PRIORITY_NONE    = 0,
    NETDEV_FLOW_PRIORITY_FILTER,
    NETDEV_FLOW_PRIORITY_VXLAN,
    NETDEV_FLOW_PRIORITY_RSS,
};

/* move to next acts index, abort on failure */
#define get_next_acts_index(index) do { \
        assert((index) < DEFAULT_MAX_ACTIONS - 1); \
        (index)++; \
    } while(0)

/* move to next patts index, abort on failure */
#define get_next_patts_index(index) do { \
        assert((index) < DEFAULT_MAX_PATTERNS - 1); \
        (index)++; \
    } while(0)

/* netdev rss flow init */
#define NETDEV_RSS_FLOW_INIT(flow, port) do { \
        flow->type = NETDEV_FLOW_TYPE_RSS; \
        flow->port_id = port->id; \
        flow->flow_handle = NULL; \
        flow->hw_offloaded = false; \
        flow->flow_id = netdev_flow_hash(flow); \
    } while(0)

enum netdev_flow_type {
    NETDEV_FLOW_TYPE_RSS,
    NETDEV_FLOW_TYPE_FILTER,
    NETDEV_FLOW_TYPE_MAX
};

union netdev_flow_query {
    struct rte_flow_query_count  count;
    struct rte_flow_action_queue queue;
    struct rte_flow_action_rss   rss_conf;
};

struct netdev_flow_stats {
    uint64_t    n_pkts;
    uint64_t    n_bytes;
};

struct netdev_flow {
    enum netdev_flow_type      type;
    portid_t                   port_id;

    /* flow meta data */
    union {
        struct {
            queueid_t           rss_queues[NETIF_MAX_QUEUES];
            uint32_t            rss_queue_num;
        } rss_info;
        struct {
            queueid_t           queue_id;
            uint16_t            sport;
            uint16_t            dport;
            uint8_t             l3_proto;
            uint8_t             l4_proto;
            union inet_addr     saddr;
            union inet_addr     daddr;
        } filter_info;
    } data;

    uint32_t                    flags;
    /* unique flow id */
    uint32_t                    flow_id;

    /* pointer to rte flow in hardware */
    struct rte_flow             *flow_handle;
    bool                        hw_offloaded;
    struct list_head            list;
    struct netdev_flow_stats    stats;
};

/* l4_proto used by i40e only */
int netdev_flow_add_kni_filter(struct netif_port *port,
                               const union inet_addr *kni_ip,
                               queueid_t kni_queue_id,
                               uint8_t l3_proto,
                               uint8_t l4_proto);
/* called on dpvs initial */
int netdev_flow_add_rss_filter(struct netif_port *port);

/*
 * NOTE: netdev flow api, operate flow on initial or terminal,
 *       need to use lock on rte_flow_* in case of concurrent.
 */
int netdev_flow_init(struct netif_port *port);
int netdev_flow_add(struct netif_port *port,
                    struct netdev_flow *netdev_flow);
int netdev_flow_del(struct netif_port *port,
                    struct netdev_flow *netdev_flow);
int netdev_flow_query(struct netif_port *port,
                      struct netdev_flow *netdev_flow,
                      union netdev_flow_query *query);
int netdev_flow_flush(struct netif_port *port);

#endif /* __NETDEV_FLOW_H__ */
