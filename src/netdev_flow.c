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

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "netdev_flow.h"

/* init seed for unique flow id */
static uint32_t init_val = 0xdeadbeef;

/*
 * rte flow priority use for mellanox nic
 * filter priority should take over other
 * we will see something wrong if the priority swapped.
 */
static const uint32_t priority_map[NETDEV_FLOW_TYPE_MAX] = {
    [NETDEV_FLOW_TYPE_RSS]    = NETDEV_FLOW_PRIORITY_RSS,
    [NETDEV_FLOW_TYPE_FILTER] = NETDEV_FLOW_PRIORITY_FILTER,
};

/*
 * @brief print detailed err msg from rte_flow_* api
 */
static void
netdev_flow_print_err_msg(struct rte_flow_error *error)
{
    static const char *const errstrlist[] = {
        [RTE_FLOW_ERROR_TYPE_NONE] = "no error",
        [RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
        [RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
        [RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
        [RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
        [RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
        [RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
        [RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
        [RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
        [RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
        [RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
        [RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
        [RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
        [RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
        [RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
        [RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
        [RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
    };

    const char *errstr;
    char buf[32];
    int err = rte_errno;

    if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
        !errstrlist[error->type])
        errstr = "unknown type";
    else
        errstr = errstrlist[error->type];

    RTE_LOG(ERR, NETDEV,"Caught error type %d (%s): %s%s: %s\n",
            error->type, errstr,
            error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
            error->cause), buf) : "",
            error->message ? error->message : "(no stated reason)",
            rte_strerror(err));
}

/*
 * @brief generate a unique flow id
 *
 * @return crc hash on flow key
 */
static inline uint32_t
netdev_flow_hash(struct netdev_flow *flow)
{
    return rte_hash_crc((void *)flow,
                        offsetof(struct netdev_flow, flow_id),
                        init_val);
}

/*
 * @brief find netdev_flow with flow id
 *
 * @return netdev flow associated with flow id
 */
static struct netdev_flow *
netdev_flow_lookup_by_uuid(struct netif_port *port, uint32_t uuid)
{
    struct netdev_flow *flow;

    rte_rwlock_write_lock(&port->dev_lock);

    /* lookup with flow list on port */
    list_for_each_entry(flow, &port->hw_flow_info.flow_list, list) {
        if (flow->flow_id == uuid) {
            rte_rwlock_write_unlock(&port->dev_lock);
            return flow;
        }
    }

    rte_rwlock_write_unlock(&port->dev_lock);
    return NULL;
}

/*
 * @brief add ingress flow attr
 *
 * @return void
 */
static inline void
netdev_flow_add_ingress_attribute(struct netdev_flow *netdev_flow,
                                  struct rte_flow_attr *attr)
{
    struct netif_port *port = netif_port_get(netdev_flow->port_id);
    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return;
    }

    attr->ingress = 1;
    /* priority supported by mellanox only */
    if (strstr(port->dev_info.driver_name, NETDEV_MLNX_DRIVER_NAME) != NULL) {
        attr->priority = priority_map[netdev_flow->type];
    }
}

/*
 * @brief add fuzzy pattern
 *        refer to RTE_FLOW_ITEM_TYPE_FUZZY and signature_match(),
 *        Threshold 0 means perfect match (no fuzziness), while threshold
 *        0xffffffff means fuzziest match.
 *
 * @return void
 */
static inline void
netdev_flow_add_fuzzy_pattern(struct netif_port *port,
                              struct rte_flow_item patts[],
                              int *index)
{
    static struct rte_flow_item_fuzzy fuzzy_spec = { .thresh = DEFAULT_FUZZY_SPEC };
    static struct rte_flow_item_fuzzy fuzzy_last = { .thresh = DEFAULT_FUZZY_LAST };
    static struct rte_flow_item_fuzzy fuzzy_mask = { .thresh = DEFAULT_FUZZY_MASK };

    patts[*index].type = RTE_FLOW_ITEM_TYPE_FUZZY;
    patts[*index].spec = &fuzzy_spec;
    patts[*index].last = &fuzzy_last;
    patts[*index].mask = &fuzzy_mask;
}

/*
 * @brief add mark action
 *
 * @return void
 */
static inline void
netdev_flow_add_mark_action(struct netif_port *port,
                            struct rte_flow_action acts[],
                            int *index)
{
    static struct rte_flow_action_mark mark = { .id = NETDEV_FLOW_DEFAULT_MARK_ID};

    /* mark action not supported by ixgbe */
    if (strstr(port->dev_info.driver_name, NETDEV_IXGBE_DRIVER_NAME) == NULL) {
        get_next_acts_index(*index);
        acts[*index].type = RTE_FLOW_ACTION_TYPE_MARK;
        acts[*index].conf = &mark;
    }
}

/*
 * @brief add count action
 *
 * @return void
 */
static inline void
netdev_flow_add_count_action(struct netif_port *port,
                             struct rte_flow_action acts[],
                             int *index)
{
    static struct rte_flow_action_count count;

    /* count action supported by mellanox only */
    if (strstr(port->dev_info.driver_name, NETDEV_MLNX_DRIVER_NAME) != NULL) {
        get_next_acts_index(*index);
        acts[*index].type = RTE_FLOW_ACTION_TYPE_COUNT;
        acts[*index].conf = &count;
    }
}

/*
 * @brief add rss patterns
 *
 * @return void
 */
static inline void
netdev_flow_add_rss_patterns(struct netdev_flow *netdev_flow,
                             struct rte_flow_item patts[])
{
    int index = 0;
    struct netif_port *port = netif_port_get(netdev_flow->port_id);
    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return;
    }

    static struct rte_flow_item_eth eth_spec;
    static struct rte_flow_item_eth eth_mask;
    memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
    memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));

    /*
     * rss pattern not supported on i40e
     * TODO: without rss pattern maybe perf better
     */
    if (strstr(port->dev_info.driver_name, NETDEV_I40E_DRIVER_NAME) == NULL) {
        patts[index].type = RTE_FLOW_ITEM_TYPE_ETH;
        patts[index].spec = &eth_spec;
        patts[index].mask = &eth_mask;
    }

    get_next_patts_index(index);
    patts[index].type = RTE_FLOW_ITEM_TYPE_END;
}

/*
 * @brief add rss actions
 *
 * @return void
 */
static inline void
netdev_flow_add_rss_actions(portid_t port_id,
                            struct netdev_flow *netdev_flow,
                            struct rte_flow_action acts[])
{
    int i, index = 0;
    struct netif_port *port;
    static struct rte_flow_action_rss rss;
    static uint16_t queue[RTE_MAX_QUEUES_PER_PORT];

    port = netif_port_get(port_id);
    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return;
    }

    /* queue region exclude kni and ha queue */
    for (i = 0; i < port->rss_queue_num; i++) {
        queue[i] = port->rss_queues[i];
    }

    rss = (struct rte_flow_action_rss) {
        .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
        .types = port->dev_conf.rx_adv_conf.rss_conf.rss_hf,
        .key_len = port->dev_conf.rx_adv_conf.rss_conf.rss_key_len,
        .queue_num = port->rss_queue_num,
        .key = port->dev_conf.rx_adv_conf.rss_conf.rss_key,
        .queue = queue,
        .level = NETDEV_FLOW_DEFAULT_RSS_LEVEL,
    };

    acts[index].type = RTE_FLOW_ACTION_TYPE_RSS;
    acts[index].conf = &rss;

    /* TODO: remove count action if perf degraded */
    netdev_flow_add_count_action(port, acts, &index);

    get_next_acts_index(index);
    acts[index].type = RTE_FLOW_ACTION_TYPE_END;
}

/*
 * @brief add l3/l4 filter patterns
 *
 * @return void
 */
static inline void
netdev_flow_add_filter_patterns(struct netdev_flow *netdev_flow,
                                struct rte_flow_item patts[])
{
    int index = 0;
    struct netif_port *port;
    static struct rte_flow_item_eth eth_spec;
    static struct rte_flow_item_eth eth_mask;
    static struct rte_flow_item_ipv4 ip4_spec;
    static struct rte_flow_item_ipv4 ip4_mask;
    static struct rte_flow_item_ipv6 ip6_spec;
    static struct rte_flow_item_ipv6 ip6_mask;
    static struct rte_flow_item_tcp tcp_spec;
    static struct rte_flow_item_tcp tcp_mask;
    static struct rte_flow_item_udp udp_spec;
    static struct rte_flow_item_udp udp_mask;

    memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
    memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));

    port = netif_port_get(netdev_flow->port_id);
    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return;
    }

    /* fuzzy pattern is used by ipv6 flows on ixgbe */
    if (strstr(port->dev_info.driver_name, NETDEV_IXGBE_DRIVER_NAME) != NULL
        && netdev_flow->data.filter_info.l3_proto == AF_INET6) {
        netdev_flow_add_fuzzy_pattern(port, patts, &index);
    } else {
        /* mellanox and i40e fall into here */
        patts[index].type = RTE_FLOW_ITEM_TYPE_ETH;
        patts[index].spec = &eth_spec;
        patts[index].mask = &eth_mask;
    }

    /* Fill inner L3 item */
    switch (netdev_flow->data.filter_info.l3_proto) {
    case AF_INET:
        get_next_patts_index(index);
        memset(&ip4_spec, 0, sizeof(struct rte_flow_item_ipv4));
        memset(&ip4_mask, 0, sizeof(struct rte_flow_item_ipv4));

        /* set dst ipv4 */
        ip4_spec.hdr.dst_addr = netdev_flow->data.filter_info.daddr.in.s_addr;
        memset(&ip4_mask.hdr.dst_addr, 0xff, sizeof(ip4_mask.hdr.dst_addr));

        patts[index].type = RTE_FLOW_ITEM_TYPE_IPV4;
        patts[index].spec = &ip4_spec;
        patts[index].mask = &ip4_mask;
        break;
    case AF_INET6:
        get_next_patts_index(index);
        memset(&ip6_spec, 0, sizeof(struct rte_flow_item_ipv6));
        memset(&ip6_mask, 0, sizeof(struct rte_flow_item_ipv6));

        /* set src ipv6 */
        if (netdev_flow->flags & NETDEV_FLOW_F_SIP_FIELD) {
            rte_memcpy(ip6_spec.hdr.src_addr, netdev_flow->data.filter_info.saddr.in6.s6_addr,
                        sizeof(ip6_spec.hdr.src_addr));
            memset(ip6_mask.hdr.src_addr, 0xff, sizeof(ip6_mask.hdr.src_addr));
        }

        /* set dst ipv6 */
        rte_memcpy(ip6_spec.hdr.dst_addr, netdev_flow->data.filter_info.daddr.in6.s6_addr,
                   sizeof(ip6_spec.hdr.dst_addr));
        memset(ip6_mask.hdr.dst_addr, 0xff, sizeof(ip6_mask.hdr.dst_addr));

        patts[index].type = RTE_FLOW_ITEM_TYPE_IPV6;
        patts[index].spec = &ip6_spec;
        patts[index].mask = &ip6_mask;
        break;
    default:
        RTE_LOG(WARNING, NETDEV, "[%s]: unknown l3 proto\n", __func__);
        break;
    }

    /* Fill inner L4 item */
    switch (netdev_flow->data.filter_info.l4_proto) {
    case IPPROTO_TCP:
        get_next_patts_index(index);
        memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
        memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));

        /* set dst port */
        tcp_spec.hdr.dst_port = netdev_flow->data.filter_info.dport;
        tcp_mask.hdr.dst_port = tcp_spec.hdr.dst_port == 0 ? 0x0 : 0xffff;

        /* set src port */
        tcp_spec.hdr.src_port = netdev_flow->data.filter_info.sport;
        tcp_mask.hdr.src_port = tcp_spec.hdr.src_port == 0 ? 0x0 : 0xffff;

        patts[index].type = RTE_FLOW_ITEM_TYPE_TCP;
        patts[index].spec = &tcp_spec;
        patts[index].mask = &tcp_mask;
        break;
    case IPPROTO_UDP:
        get_next_patts_index(index);
        memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
        memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));

        /* set dst port */
        udp_spec.hdr.dst_port = netdev_flow->data.filter_info.dport;
        udp_mask.hdr.dst_port = udp_spec.hdr.dst_port == 0 ? 0x0 : 0xffff;

        patts[index].type = RTE_FLOW_ITEM_TYPE_UDP;
        patts[index].spec = &udp_spec;
        patts[index].mask = &udp_mask;
        break;
    default:
        RTE_LOG(WARNING, NETDEV, "[%s]: unknown l4 proto\n", __func__);
        break;
    }

    get_next_patts_index(index);
    patts[index].type = RTE_FLOW_ITEM_TYPE_END;
}

/*
 * @brief add l3/l4 filter actions
 *
 * @return void
 */
static inline void
netdev_flow_add_filter_actions(struct netdev_flow *netdev_flow,
                               struct rte_flow_action acts[])
{
    int index = 0;
    struct netif_port *port;
    static struct rte_flow_action_queue queue = { .index = 0 };

    port = netif_port_get(netdev_flow->port_id);
    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return;
    }

    queue = (struct rte_flow_action_queue) {
        .index = netdev_flow->data.filter_info.queue_id,
    };

    /* queue action is essential */
    acts[index].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    acts[index].conf = &queue;

    /*
     * attach an integer value to packets and
     * set PKT_RX_FDIR and PKT_RX_FDIR_ID mbuf flags
     */
    netdev_flow_add_mark_action(port, acts, &index);

    /* count action supported by mellanox only */
    netdev_flow_add_count_action(port, acts, &index);

    get_next_acts_index(index);
    acts[index].type = RTE_FLOW_ACTION_TYPE_END;
}

/*
 * @brief add egress flow attr
 *
 * @return void
 */
static inline void
netdev_flow_add_egress_attribute(struct rte_flow_attr *attr)
{
    attr->egress = 1;
}

/*
 * @brief add netdev flow on port
 *
 * @param port - dpdk or other type port
 * @param netdev_flow - flow store on netif_port
 *
 * @return EDPVS_OK on success, EDPVS_DPDKAPIFAIL on failure
 */
int netdev_flow_add(struct netif_port *port,
                    struct netdev_flow *netdev_flow)
{
    int err = EDPVS_OK;
    struct rte_flow_error error;
    struct rte_flow_attr attr;
    struct rte_flow_item patts[DEFAULT_MAX_PATTERNS];
    struct rte_flow_action acts[DEFAULT_MAX_ACTIONS];
    union netdev_flow_query query;
    struct rte_flow *flow = NULL;
    portid_t port_id;

    if (unlikely(netdev_flow == NULL || port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev flow info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    port_id = port->id;

    memset(&error, 0, sizeof(error));
    memset(&attr, 0, sizeof(attr));
    memset(patts, 0, sizeof(patts));
    memset(acts, 0, sizeof(acts));

    rte_rwlock_write_lock(&port->dev_lock);

    switch (netdev_flow->type) {
    case NETDEV_FLOW_TYPE_RSS:
        /* setup rss queues info */
        netdev_flow_add_ingress_attribute(netdev_flow, &attr);
        netdev_flow_add_rss_patterns(netdev_flow, patts);
        netdev_flow_add_rss_actions(port_id, netdev_flow, acts);
        break;
    case NETDEV_FLOW_TYPE_FILTER:
        /* setup filter flow */
        netdev_flow_add_ingress_attribute(netdev_flow, &attr);
        netdev_flow_add_filter_patterns(netdev_flow, patts);
        netdev_flow_add_filter_actions(netdev_flow, acts);
        break;
    default:
        RTE_LOG(WARNING, NETDEV,
                "[%s]: unsupported netdev flow type\n", __func__);
        rte_flow_error_set(&error, EINVAL,
                           RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
                           NULL, "unsupported netdev flow type.");
        goto err_out;
    };

    err = rte_flow_validate(port_id, &attr, patts, acts, &error);
    if (unlikely(err == -ENOTSUP || err == -ENOSYS)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: rte_flow not supported on port %d\n",
                __func__, port_id);
        goto err_out;
    } else if (err != EDPVS_OK) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to validate netdev flow on port %d\n",
                __func__, port_id);
        goto err_out;
    }

    flow = rte_flow_create(port_id, &attr, patts, acts, &error);
    if (unlikely(flow == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to add netdev flow on port %d\n",
                __func__, port_id);
        goto err_out;
    }

    netdev_flow->flow_handle = flow;
    netdev_flow->hw_offloaded = true;

    /* store to flow list */
    port->hw_flow_info.flow_cnt++;
    list_add_tail(&netdev_flow->list, &port->hw_flow_info.flow_list);

    rte_rwlock_write_unlock(&port->dev_lock);

    RTE_LOG(INFO, NETDEV,
            "[%s]: success to add netdev flow on port %d\n",
            __func__, port_id);

    /*
     * verify flow existed in hardware
     * supported only on mellanox.
     */
    if (strstr(port->dev_info.driver_name, NETDEV_MLNX_DRIVER_NAME) != NULL) {
        netdev_flow_query(port,
                          netdev_flow,
                          &query);
    }

    return EDPVS_OK;

err_out:
    port->hw_flow_info.flow_err++;
    rte_rwlock_write_unlock(&port->dev_lock);
    netdev_flow_print_err_msg(&error);
    return EDPVS_DPDKAPIFAIL;
}

/*
 * @brief destroy netdev flow on port
 *
 * @param port - dpdk or other type port
 * @param netdev_flow - flow store on netif_port
 *
 * @return EDPVS_OK on success, negative on failure
 */
int netdev_flow_del(struct netif_port *port,
                    struct netdev_flow *netdev_flow)
{
    int err = EDPVS_OK;
    struct rte_flow_error error;

    if (unlikely(NULL == netdev_flow || NULL == port)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev flow info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    memset(&error, 0, sizeof(error));

    rte_rwlock_write_lock(&port->dev_lock);

    err = rte_flow_destroy(port->id, netdev_flow->flow_handle, &error);
    if (unlikely(err != EDPVS_OK)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to remove netdev flow %#x on port %d\n",
                __func__, netdev_flow->flow_id, port->id);
        goto err_out;
    }

    /* remove from flow list */
    port->hw_flow_info.flow_cnt--;
    list_del(&netdev_flow->list);

    /* free flow on destroyed */
    rte_free(netdev_flow);

    rte_rwlock_write_unlock(&port->dev_lock);
    return EDPVS_OK;

err_out:
    port->hw_flow_info.flow_err++;
    rte_rwlock_write_unlock(&port->dev_lock);
    netdev_flow_print_err_msg(&error);
    return EDPVS_DPDKAPIFAIL;
}

/*
 * @brief print query info on port
 */
static void
print_query_info(const struct rte_flow_action *action,
                 union netdev_flow_query *query)
{
    if (unlikely(action == NULL))
        return;

    /* flow action query */
    switch (action->type) {
    case RTE_FLOW_ACTION_TYPE_QUEUE:
        RTE_LOG(INFO, NETDEV,
                "[%s]: flow queue query index: %d\n",
                __func__, query->queue.index);
        break;
    case RTE_FLOW_ACTION_TYPE_COUNT:
        RTE_LOG(INFO, NETDEV,
                "[%s]: flow count query:"
                " hits_set: %u bytes_set: %u"
                " hits: %"PRIu64" bytes: %"PRIu64"\n",
                __func__,
                query->count.hits_set, query->count.bytes_set,
                query->count.hits, query->count.bytes);
        break;
    case RTE_FLOW_ACTION_TYPE_RSS:
        break;
    default:
        break;
    }
}

/*
 * @brief query netdev flow on port
 *
 * @param port - dpdk or other type port
 * @param netdev_flow - flow store on netif_port
 * @param query - flow query result
 *
 * @return EDPVS_OK on success, EDPVS_DPDKAPIFAIL on failure
 */
int netdev_flow_query(struct netif_port *port,
                      struct netdev_flow *netdev_flow,
                      union netdev_flow_query *query)
{
    int err = EDPVS_OK;
    struct rte_flow_error error;

    /* default flow count query */
    struct rte_flow_action_count count = { .shared = 0, .id = 0 };
    const struct rte_flow_action action[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_COUNT,
            .conf = &count,
        },
        {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };

    memset(&error, 0, sizeof(error));

    rte_rwlock_write_lock(&port->dev_lock);

    err = rte_flow_query(port->id, netdev_flow->flow_handle, action, query, &error);
    if (unlikely(err != EDPVS_OK)) {
        RTE_LOG(ERR, NETDEV, "[%s]: failed to query flow %#x on"
                " port %d, err %d\n", __func__,
                netdev_flow->flow_id, port->id, err);
        goto err_out;
    }

    rte_rwlock_write_unlock(&port->dev_lock);

    print_query_info(action, query);

    return EDPVS_OK;

err_out:
    rte_rwlock_write_unlock(&port->dev_lock);
    netdev_flow_print_err_msg(&error);
    return EDPVS_DPDKAPIFAIL;
}

/*
 * @brief flush netdev flow on port
 *
 * @param port - dpdk or other type port
 *
 * @return EDPVS_OK on success, negative on failure
 */
int netdev_flow_flush(struct netif_port *port)
{
    int err = EDPVS_OK;
    struct netdev_flow *flow;
    struct rte_flow_error error;

    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    memset(&error, 0, sizeof(error));

    rte_rwlock_write_lock(&port->dev_lock);

    /* flush flows on port */
    err = rte_flow_flush(port->id, &error);
    if (unlikely(err != EDPVS_OK)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to flush flow on port %d, err %d\n",
                __func__, port->id, err);
        goto err_out;
    }

    /* empty flow list, need lock here */
    list_for_each_entry(flow, &port->hw_flow_info.flow_list, list) {
        port->hw_flow_info.flow_cnt--;
        list_del(&flow->list);
        rte_free(flow);
    }

    rte_rwlock_write_unlock(&port->dev_lock);
    return EDPVS_OK;

err_out:
    port->hw_flow_info.flow_err++;
    rte_rwlock_write_unlock(&port->dev_lock);
    netdev_flow_print_err_msg(&error);
    return EDPVS_DPDKAPIFAIL;
}

/*
 * @brief init kni flow, params validated
 *
 * @param flow - netdev flow
 * @param port - dpdk or other type port
 * @param kni_ip - ip addr of kni port
 * @param kni_queue_id - queue polled by kni core
 * @param l3_proto - AF_INET or AF_INET6
 * @param l4_proto - IPPROTO_UDP IPPROTO_TCP or IPPROTO_IP
 *
 * @return EDPVS_OK on success, EDPVS_INVAL on failure
 */
static inline
int netdev_flow_init_kni_filter(struct netdev_flow *flow,
                                 struct netif_port *port,
                                 const union inet_addr *kni_ip,
                                 queueid_t kni_queue_id,
                                 uint8_t l3_proto,
                                 uint8_t l4_proto)
{
    if (unlikely(flow == NULL || port == NULL
        || kni_ip == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid input info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    flow->type = NETDEV_FLOW_TYPE_FILTER;
    flow->port_id = port->id;
    flow->data.filter_info.l3_proto = l3_proto;
    flow->data.filter_info.l4_proto = l4_proto;
    flow->data.filter_info.queue_id = kni_queue_id;
    flow->flow_handle = NULL;
    flow->hw_offloaded = false;
    rte_memcpy(&(flow->data.filter_info.daddr), kni_ip,
                sizeof(union inet_addr));
    flow->flags |= NETDEV_FLOW_F_DIP_FIELD;
    flow->flags |= NETDEV_FLOW_F_L3_PROTO_FIELD;
    flow->flags |= NETDEV_FLOW_F_L4_PROTO_FIELD;
    flow->flow_id = netdev_flow_hash(flow);

    return EDPVS_OK;
}

/*
 * @brief log kni flow, params validated
 *
 * @param flow - netdev flow
 * @param port - dpdk or other type port
 * @param kni_ip - ip addr of kni port
 * @param kni_queue_id - queue polled by kni core
 * @param l3_proto - AF_INET or AF_INET6
 * @param l4_proto - IPPROTO_UDP IPPROTO_TCP or IPPROTO_IP
 *
 * @return EDPVS_OK on success, EDPVS_INVAL on failure
 */
static inline
int netdev_flow_log_kni_filter(struct netdev_flow *flow,
                                struct netif_port *port,
                                const union inet_addr *kni_ip,
                                queueid_t kni_queue_id,
                                uint8_t l3_proto,
                                uint8_t l4_proto)
{
    char dst[64];
    union inet_addr addr;

    if (unlikely(flow == NULL || port == NULL
        || kni_ip == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid input info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    if (l3_proto == AF_INET) {
        addr.in.s_addr = kni_ip->in.s_addr;
        RTE_LOG(INFO, NETDEV, "[%s] success to alloc kni ipv4 flow %#x "
                "on port %d kni_ip %s kni_queue_id %d\n",
                __func__, flow->flow_id, port->id,
                inet_ntop(AF_INET, &addr, dst, sizeof(dst)) ? dst: "",
                kni_queue_id);
    } else {
        inet_ntop(AF_INET6, kni_ip, dst, sizeof(dst));
        RTE_LOG(INFO, NETDEV, "[%s] success to alloc ha kni ipv6 flow %#x "
                "on port %d kni_ip %s kni_queue_id %d\n",
                __func__, flow->flow_id, port->id,
                dst, kni_queue_id);
    }

    return EDPVS_OK;
}

/*
 * @brief configure kni flow for kni port
 *
 * @param port - dpdk or other type port
 * @param kni_ip - ip addr of kni port
 * @param kni_queue_id - queue polled by kni core
 * @param l3_proto - AF_INET or AF_INET6
 * @param l4_proto - IPPROTO_UDP IPPROTO_TCP or IPPROTO_IP
 *
 * @return EDPVS_OK on success, negative on failure
 */
int netdev_flow_add_kni_filter(struct netif_port *port,
                               const union inet_addr *kni_ip,
                               queueid_t kni_queue_id,
                               uint8_t l3_proto,
                               uint8_t l4_proto)
{
    int err = EDPVS_OK;
    struct netdev_flow *flow;

    /* params assert */
    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    if (unlikely(kni_ip == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid kni ip info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    flow = rte_zmalloc("kni_flow",
                       sizeof(struct netdev_flow),
                       RTE_CACHE_LINE_SIZE);
    if (unlikely(flow == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to alloc kni flow on port %d\n",
                __func__, port->id);
        port->hw_flow_info.flow_err++;
        return EDPVS_NOMEM;
    }

    /* init kni flow */
    netdev_flow_init_kni_filter(flow, port,
                                kni_ip, kni_queue_id,
                                l3_proto, l4_proto);

    /* log kni flow */
    netdev_flow_log_kni_filter(flow, port,
                               kni_ip, kni_queue_id,
                               l3_proto, l4_proto);

    /* lookup netdev flow on port */
    if (netdev_flow_lookup_by_uuid(port, flow->flow_id)) {
        RTE_LOG(INFO, NETDEV,
                "[%s]: netdev flow %#x already exists on port %d\n",
                __func__, flow->flow_id, port->id);
        err = EDPVS_INVAL;
        goto done;
    }

    /* add netdev flow on port */
    err = netdev_flow_add(port, flow);
    if (unlikely(err == EDPVS_INVAL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to create kni flow %#x on port %d\n",
                __func__, flow->flow_id, port->id);
        goto done;
    }

    return EDPVS_OK;

done:
    rte_free(flow);
    return err;
}

/*
 * @brief configure rss queues region,
 *        exclude kni and ha queues,
 *        should called after rte_eth_rx_queue_setup().
 *
 * @param port - dpdk or other type port
 *
 * @return EDPVS_OK on success, negative on failure
 */
int netdev_flow_add_rss_filter(struct netif_port *port)
{
    int err = EDPVS_OK;
    struct netdev_flow *flow;

    if (unlikely(port == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: invalid netdev info on port\n",
                __func__);
        return EDPVS_INVAL;
    }

    flow = rte_zmalloc("rss_flow",
                       sizeof(struct netdev_flow),
                       RTE_CACHE_LINE_SIZE);
    if (unlikely(flow == NULL)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to alloc rss flow on port %d\n",
                __func__, port->id);
        port->hw_flow_info.flow_err++;
        return EDPVS_NOMEM;
    }

    /* init rss flow */
    NETDEV_RSS_FLOW_INIT(flow, port);

    RTE_LOG(INFO, NETDEV,
            "[%s]: success to alloc rss flow %#x on port %d\n",
            __func__, flow->flow_id, port->id);

    /* lookup netdev flow on port */
    if (netdev_flow_lookup_by_uuid(port, flow->flow_id)) {
        RTE_LOG(INFO, NETDEV,
                "[%s]: netdev flow %#x already exists on port %d\n",
                __func__, flow->flow_id, port->id);
        err = EDPVS_INVAL;
        goto done;
    }

    /* add netdev flow on port */
    err = netdev_flow_add(port, flow);
    if (unlikely(err != EDPVS_OK)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to create rss flow %#x on port %d err %d\n",
                __func__, flow->flow_id, port->id, err);
        goto done;
    }

    return EDPVS_OK;

done:
    rte_free(flow);
    return err;
}

int netdev_flow_init(struct netif_port *port)
{
    int err = EDPVS_OK;

    /* flush rte flows, exception occured on i40e driver */
    if (strstr(port->dev_info.driver_name, NETDEV_I40E_DRIVER_NAME) == NULL) {
        err = netdev_flow_flush(port);
        if (unlikely(err != EDPVS_OK)) {
            RTE_LOG(ERR, NETDEV,
                    "[%s]: failed to flush netdev flow on port %s\n",
                    __func__, port->name);
            return EDPVS_DPDKAPIFAIL;
        }

        RTE_LOG(INFO, NETDEV,
                "[%s]: success to flush netdev flow on port %s\n",
                __func__, port->name);
    }

    /* config rss rte flows on port init */
    err = netdev_flow_add_rss_filter(port);
    if (unlikely(err != EDPVS_OK)) {
        RTE_LOG(ERR, NETDEV,
                "[%s]: failed to config rss flow on port %s\n",
                __func__, port->name);
        return EDPVS_DPDKAPIFAIL;
    }

    RTE_LOG(INFO, NETDEV,
            "[%s]: success to config rss flow on port %s\n",
            __func__, port->name);

    return err;
}
