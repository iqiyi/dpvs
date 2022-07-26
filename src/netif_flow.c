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

#include <rte_flow.h>
#include "vlan.h"
#include "netif_flow.h"

#define RTE_LOGTYPE_FLOW RTE_LOGTYPE_USER1

/* uncomment the macro if rte_flow pmd driver is not thread-safe. */
// #define CONFIG_DEV_FLOW_LOCK

/* sapool pattern stack: ETH | IP | TCP/UDP | END */
#define SAPOOL_PATTERN_NUM  4
/* sapool action stack: QUEUE | END */
#define SAPOOL_ACTION_NUM   2
/* kni flow pattern stack: ETH | IP | END */
#define KNI_PATTERN_NUM  3
/* kni flow action stack: QUEUE | END */
#define KNI_ACTION_NUM   2

/* dpvs use only one flow group */
#define NETIF_FLOW_GROUP    0

/* DPVS flow type and priority.
 * The enum value matters. Lower value denotes higher priority. */
typedef enum {
    NETIF_FLOW_PRIO_SAPOOL = 1,     // sapool flow rules
    NETIF_FLOW_PRIO_KNI = 2,        // kni ip address flow rules
    NETIF_FLOW_PRIO_TUNNEL,         // TODO, gre tunnel flow rules
    // more ...
} netif_flow_type_prio_t;

static inline void netif_flow_lock(struct netif_port *dev)
{
#ifdef CONFIG_DEV_FLOW_LOCK
    rte_rwlock_write_lock(&dev->dev_lock);
#endif
}

static inline void netif_flow_unlock(struct netif_port *dev)
{
#ifdef CONFIG_DEV_FLOW_LOCK
    rte_rwlock_write_unlock(&dev->dev_lock);
#endif
}

/*
 * Create a rte_flow on a physical port.
 */
static inline int __netif_flow_create(struct netif_port *dev,
            const struct rte_flow_attr *attr,
            const struct rte_flow_item pattern[],
            const struct rte_flow_action actions[],
            struct netif_flow_handler *flow)
{
    struct rte_flow_error flow_error;

    if (unlikely(!flow || !dev || (dev->type != PORT_TYPE_GENERAL &&
                dev->type != PORT_TYPE_BOND_SLAVE)))
        return EDPVS_INVAL;

    netif_flow_lock(dev);
    if (rte_flow_validate(dev->id, attr, pattern, actions, &flow_error)) {
        netif_flow_unlock(dev);
        RTE_LOG(WARNING, FLOW, "rte_flow_validate on %s failed -- %d, %s\n",
                dev->name, flow_error.type, flow_error.message);
        return EDPVS_DPDKAPIFAIL;
    }

    flow->handler = rte_flow_create(dev->id, attr, pattern, actions, &flow_error);
    netif_flow_unlock(dev);
    if (!flow->handler) {
        flow->pid = 0;
        RTE_LOG(WARNING, FLOW, "rte_flow_create on %s failed -- %d, %s\n",
                dev->name, flow_error.type, flow_error.message);
        return EDPVS_DPDKAPIFAIL;
    }
    flow->pid = dev->id;

    return EDPVS_OK;
}

/*
 * Remove a specified rte_flow.
 */
static int __netif_flow_destroy(struct netif_flow_handler *flow)
{
    struct netif_port *dev;
    struct rte_flow_error flow_error;

    if (unlikely(!flow || !flow->handler))
        return EDPVS_INVAL;

    dev = netif_port_get(flow->pid);
    if (unlikely(!dev || (dev->type != PORT_TYPE_GENERAL &&
                    dev->type != PORT_TYPE_BOND_SLAVE)))
        return EDPVS_INVAL;

    netif_flow_lock(dev);
    if (rte_flow_destroy(flow->pid, (struct rte_flow *)flow->handler, &flow_error)) {
        RTE_LOG(WARNING, FLOW, "rte_flow_destroy on %s failed -- %d, %s\n",
                dev->name, flow_error.type, flow_error.message);
        netif_flow_unlock(dev);
        return EDPVS_DPDKAPIFAIL;
    }
    netif_flow_unlock(dev);

    return EDPVS_OK;
}

/*
 * Create rte_flow on specified device.
 */
static int netif_flow_create(struct netif_port *dev,
            const struct rte_flow_attr *attr,
            const struct rte_flow_item pattern[],
            const struct rte_flow_action actions[],
            netif_flow_handler_param_t *flows)
{
    int err;

    if (unlikely(!dev || !flows))
        return EDPVS_INVAL;

    if (dev->type == PORT_TYPE_VLAN) {
        struct vlan_dev_priv *vlan = netif_priv(dev);
        if (unlikely(!vlan || !vlan->real_dev))
            return EDPVS_INVAL;
        dev = vlan->real_dev;
    }

    if (dev->type == PORT_TYPE_GENERAL) {
        if (unlikely(flows->size < 1 || !flows->handlers))
            return EDPVS_INVAL;
        err = __netif_flow_create(dev, attr, pattern, actions, &flows->handlers[0]);
        flows->flow_num = (err == EDPVS_OK) ? 1 : 0;
        return err;
    }

    if (dev->type == PORT_TYPE_BOND_MASTER) {
        int i, slave_nb;
        slave_nb = dev->bond->master.slave_nb;

        if (unlikely(flows->size < slave_nb || !flows->handlers))
            return EDPVS_INVAL;
        for (i = 0; i < slave_nb; i++) {
            err = __netif_flow_create(dev->bond->master.slaves[i], attr, pattern, actions, &flows->handlers[i]);
            if (err != EDPVS_OK) {
                while (--i >= 0)
                    __netif_flow_destroy(&flows->handlers[i]);
                return err;
            }
        }
        flows->flow_num = slave_nb;
        return EDPVS_OK;
    }

    return EDPVS_INVAL;
}

/*
 * Destroy specified rte_flow.
 */
static int netif_flow_destroy(netif_flow_handler_param_t *flows)
{
    int i, err, ret = EDPVS_OK;

    if (unlikely(!flows || flows->flow_num > flows->size || !flows->handlers))
        return EDPVS_INVAL;

    for (i = 0; i < flows->flow_num; i++) {
        err = __netif_flow_destroy(&flows->handlers[i]);
        if (err != EDPVS_OK)
            ret = err;
    }

    return ret;
}

/*
 * Flush rte_flow of a physical port.
 */
static inline int __netif_flow_flush(struct netif_port *dev)
{
    struct rte_flow_error flow_error;

    if (unlikely(!dev || (dev->type != PORT_TYPE_GENERAL &&
                dev->type != PORT_TYPE_BOND_SLAVE)))
        return EDPVS_INVAL;

    if (rte_flow_flush(dev->id, &flow_error)) {
        RTE_LOG(WARNING, FLOW, "rte_flow_flush on %s failed -- %d, %p, %s\n",
                dev->name, flow_error.type, flow_error.cause, flow_error.message);
        return EDPVS_DPDKAPIFAIL;
    }

    return EDPVS_OK;
}

/*
 * Flush rte_flow on specified device.
 *
 * Note:
 * It invalidates all rte_flow handlers related to this device.
 * If the handlers are saved elsewhere previously, don't use any of them after being flushed.
 */
int netif_flow_flush(struct netif_port *dev)
{
    if (unlikely(!dev))
        return EDPVS_INVAL;

    if (dev->type == PORT_TYPE_BOND_SLAVE)
        return EDPVS_OK;

    if (dev->type == PORT_TYPE_VLAN) {
        struct vlan_dev_priv *vlan = netif_priv(dev);
        if (unlikely(!vlan || !vlan->real_dev))
            return EDPVS_INVAL;
        dev = vlan->real_dev;
    }

    if (dev->type == PORT_TYPE_GENERAL) {
        if (__netif_flow_flush(dev) != EDPVS_OK)
            return EDPVS_RESOURCE;
        return EDPVS_OK;
    }

    if (dev->type == PORT_TYPE_BOND_MASTER) {
        int i, slave_nb, err;
        err = EDPVS_OK;
        slave_nb = dev->bond->master.slave_nb;
        for (i = 0; i < slave_nb; i++) {
            if (__netif_flow_flush(dev->bond->master.slaves[i]) != EDPVS_OK)
                err = EDPVS_RESOURCE;
        }
        return err;
    }

    return EDPVS_NOTSUPP;
}

/*
 * Set sa_pool flow rules.
 *
 * Ether | IPv4/IPv6 | TCP/UDP
 */
int netif_sapool_flow_add(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            __be16 port_base, __be16 port_mask,
            netif_flow_handler_param_t *flows)
{
    int err, ret = EDPVS_OK, nflows = 0;
    char ipbuf[64];
    struct rte_flow_attr attr = {
        .group    = NETIF_FLOW_GROUP,
        .priority = NETIF_FLOW_PRIO_SAPOOL,
        .ingress  = 1,
        .egress   = 0,
        //.transfer = 0,
    };
    struct rte_flow_item pattern[SAPOOL_PATTERN_NUM];
    struct rte_flow_action action[SAPOOL_ACTION_NUM];
    netif_flow_handler_param_t resp;

    struct rte_flow_item_ipv4 ip_spec, ip_mask;
    struct rte_flow_item_ipv6 ip6_spec, ip6_mask;
    struct rte_flow_item_tcp tcp_spec, tcp_mask;
    struct rte_flow_item_udp udp_spec, udp_mask;

    queueid_t queue_id;
    struct rte_flow_action_queue queue;

    if (unlikely(!dev || !addr || !flows))
        return EDPVS_INVAL;
    if (unlikely(flows->size < 4 || !flows->handlers))
        return EDPVS_INVAL;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* create action stack */
    err = netif_get_queue(dev, cid, &queue_id);
    if (unlikely(err != EDPVS_OK))
        return err;
    queue.index = queue_id;
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /* create pattern stack */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    if (af == AF_INET) {
        memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
        memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
        ip_spec.hdr.dst_addr = addr->in.s_addr;
        ip_mask.hdr.dst_addr = htonl(0xffffffff);
        pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[1].spec = &ip_spec;
        pattern[1].mask = &ip_mask;
    } else if (af == AF_INET6) {
        memset(&ip6_spec, 0, sizeof(struct rte_flow_item_ipv6));
        memset(&ip6_mask, 0, sizeof(struct rte_flow_item_ipv6));
        memcpy(&ip6_spec.hdr.dst_addr, &addr->in6, sizeof(ip6_spec.hdr.dst_addr));
        memset(&ip6_mask.hdr.dst_addr, 0xff, sizeof(ip6_mask.hdr.dst_addr));
        pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
        pattern[1].spec = &ip6_spec;
        pattern[1].mask = &ip6_mask;
    } else {
        return EDPVS_INVAL;
    }
    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    tcp_spec.hdr.dst_port = port_base;
    tcp_mask.hdr.dst_port = port_mask;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    /* set tcp flow */
    resp.size = flows->size;
    resp.flow_num = 0;
    resp.handlers = &flows->handlers[0];
    err = netif_flow_create(dev, &attr, pattern, action, &resp);
    if (err) {
        ret = EDPVS_RESOURCE;
        RTE_LOG(ERR, FLOW, "%s: adding tcp sapool flow failed: %s ip %s port %d(0x%04X) mask 0x%04X,"
                " queue %d lcore %2d\n", __func__, dev->name,
                inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
                ntohs(port_base), ntohs(port_base), ntohs(port_mask), queue_id, cid);
    } else {
        nflows += resp.flow_num;
        RTE_LOG(INFO, FLOW, "%s: adding tcp sapool flow succeed: %s ip %s port %d(0x%04X) mask 0x%04X,"
                " queue %d lcore %2d\n", __func__, dev->name,
                inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
                ntohs(port_base), ntohs(port_base), ntohs(port_mask), queue_id, cid);
    }

    memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
    memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
    udp_spec.hdr.dst_port = port_base;
    udp_mask.hdr.dst_port = port_mask;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec = &udp_spec;
    pattern[2].mask = &udp_mask;
    /* set udp flow */
    resp.size = flows->size - nflows;
    resp.flow_num = 0;
    resp.handlers = &flows->handlers[nflows];
    err = netif_flow_create(dev, &attr, pattern, action, &resp);
    if (err) {
        ret = EDPVS_RESOURCE;
        RTE_LOG(ERR, FLOW, "%s: adding udp sapool flow failed: %s ip %s port %d(0x%04X) mask 0x%04X,"
                " queue %d lcore %2d\n", __func__, dev->name,
                inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
                ntohs(port_base), ntohs(port_base), ntohs(port_mask), queue_id, cid);
    } else {
        nflows += resp.flow_num;
        RTE_LOG(INFO, FLOW, "%s: adding udp sapool flow succeed: %s ip %s port %d(0x%04X) mask 0x%04X,"
                " queue %d lcore %2d\n", __func__, dev->name,
                inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
                ntohs(port_base), ntohs(port_base), ntohs(port_mask), queue_id, cid);
    }

    flows->flow_num = nflows;
    return ret;
}

/*
 * Delete sa_pool flow rules.
 *
 * Ether | IPv4/IPv6 | TCP/UDP
 */
int netif_sapool_flow_del(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            __be16 port_base, __be16 port_mask,
            netif_flow_handler_param_t *flows)
{
    int err, ret = EDPVS_OK;
    char ipbuf[64];

    err = netif_flow_destroy(flows);

    if (err) {
        err = EDPVS_RESOURCE;
        RTE_LOG(ERR, FLOW, "%s: deleting sapool flow failed: %s ip %s port %d(0x%04X) mask 0x%04X\n",
                __func__, dev->name, inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
                ntohs(port_base), ntohs(port_base), ntohs(port_mask));
    } else {
        flows->flow_num = 0;
        RTE_LOG(INFO, FLOW, "%s: deleting sapool flow succeed: %s ip %s port %d(0x%04X) mask 0x%04X\n",
                __func__, dev->name, inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
                ntohs(port_base), ntohs(port_base), ntohs(port_mask));
    }

    return ret;
}

/*
 * Set kni flow rules.
 *
 * Ether | IPv4/IPv6 | END
 */
int netif_kni_flow_add(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            netif_flow_handler_param_t *flows)
{
    int err;
    char ipbuf[64];
    struct rte_flow_attr attr = {
        .group    = NETIF_FLOW_GROUP,
        .priority = NETIF_FLOW_PRIO_KNI,
        .ingress  = 1,
        .egress   = 0,
        //.transfer = 0,
    };
    struct rte_flow_item pattern[KNI_PATTERN_NUM];
    struct rte_flow_action action[KNI_ACTION_NUM];
    netif_flow_handler_param_t resp;

    struct rte_flow_item_ipv4 ip_spec, ip_mask;
    struct rte_flow_item_ipv6 ip6_spec, ip6_mask;

    queueid_t queue_id;
    struct rte_flow_action_queue queue;

    if (unlikely(!dev || !addr || !flows))
        return EDPVS_INVAL;
    if (unlikely(flows->size < 2 || !flows->handlers))
        return EDPVS_INVAL;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* create action stack */
    err = netif_get_queue(dev, cid, &queue_id);
    if (unlikely(err != EDPVS_OK))
        return err;
    queue.index = queue_id;
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /* create pattern stack */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    if (af == AF_INET) {
        memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
        memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
        ip_spec.hdr.dst_addr = addr->in.s_addr;
        ip_mask.hdr.dst_addr = htonl(0xffffffff);
        pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[1].spec = &ip_spec;
        pattern[1].mask = &ip_mask;
    } else if (af == AF_INET6) {
        memset(&ip6_spec, 0, sizeof(struct rte_flow_item_ipv6));
        memset(&ip6_mask, 0, sizeof(struct rte_flow_item_ipv6));
        memcpy(&ip6_spec.hdr.dst_addr, &addr->in6, sizeof(ip6_spec.hdr.dst_addr));
        memset(&ip6_mask.hdr.dst_addr, 0xff, sizeof(ip6_mask.hdr.dst_addr));
        pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
        pattern[1].spec = &ip6_spec;
        pattern[1].mask = &ip6_mask;
    } else {
        return EDPVS_INVAL;
    }
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

    /* set kni flow */
    resp.size = flows->size;
    resp.flow_num = 0;
    resp.handlers = &flows->handlers[0];
    err = netif_flow_create(dev, &attr, pattern, action, &resp);
    if (err) {
        RTE_LOG(ERR, FLOW, "%s: adding kni flow failed: %s ip %s queue %d lcore %2d"
                " (cause: %s)\n", __func__, dev->name, inet_ntop(af, addr, ipbuf,
                sizeof(ipbuf)) ? : "::", queue_id, cid, dpvs_strerror(err));
        return EDPVS_RESOURCE;
    }

    flows->flow_num = resp.flow_num;
    RTE_LOG(INFO, FLOW, "%s: adding kni flow succeed: %s ip %s queue %d lcore %2d\n",
            __func__, dev->name, inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::",
            queue_id, cid);

    return EDPVS_OK;
}

/*
 * Delete kni flow rules.
 *
 * Ether | IPv4/IPv6 | END
 */
int netif_kni_flow_del(struct netif_port *dev, lcoreid_t cid,
            int af, const union inet_addr *addr,
            netif_flow_handler_param_t *flows)
{
    int err;
    char ipbuf[64];

    err = netif_flow_destroy(flows);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, FLOW, "%s: deleting kni flow failed: %s ip %s (cause: %s)\n",
                __func__, dev->name, inet_ntop(af, addr, ipbuf, sizeof(ipbuf))
                ? : "::", dpvs_strerror(err));
        return EDPVS_RESOURCE;
    }

    flows->flow_num = 0;
    RTE_LOG(INFO, FLOW, "%s: deleting kni flow succeed: %s ip %s\n", __func__,
            dev->name, inet_ntop(af, addr, ipbuf, sizeof(ipbuf)) ? : "::");
    return EDPVS_OK;
}
