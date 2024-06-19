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

#include <assert.h>
#include <netinet/ip6.h>
#include "ipv4.h"
#include "ipv6.h"
#include "libconhash/conhash.h"
#include "ipvs/conhash.h"

struct conhash_node {
    struct list_head    list;
    struct node_s       node;       /* node in libconhash */
};

struct conhash_sched_data {
    struct list_head    nodes;      /* node list */
    struct conhash_s   *conhash;    /* consistent hash meta data */
};

#define REPLICA 160
#define QUIC_PACKET_8BYTE_CONNECTION_ID  (1 << 3)

/*
 * QUIC CID hash target for quic*
 * QUIC CID(qid) should be configured in UDP service
 *
 * This is an early Google QUIC implementation, and has been obsoleted.
 * https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit?pli=1#heading=h.o9jvitkc5d2g
 *
 * Use IETF QUIC(officially published in 2021) instead.
 * Configure `--quic` option on DPVS service to enable it.
 * The quic application on RS  must conform with the CID format agreement
 * declared in `include/ipvs/quic.h`.
 */
static int get_quic_hash_target(int af, const struct rte_mbuf *mbuf,
                                uint64_t *quic_cid)
{
    uint8_t pub_flags;
    uint32_t udphoff;
    char *quic_data;
    uint32_t quic_len;

    if (af == AF_INET6) {
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);
        uint8_t ip6nxt = ip6h->ip6_nxt;
        udphoff = ip6_skip_exthdr(mbuf, sizeof(struct ip6_hdr), &ip6nxt);
    }
    else
        udphoff = ip4_hdrlen(mbuf);

    quic_len = udphoff + sizeof(struct rte_udp_hdr) +
               sizeof(pub_flags) + sizeof(*quic_cid);

    if (mbuf_may_pull((struct rte_mbuf *)mbuf, quic_len) != 0)
        return EDPVS_NOTEXIST;

    quic_data = rte_pktmbuf_mtod_offset(mbuf, char *,
                                        udphoff + sizeof(struct rte_udp_hdr));
    pub_flags = *((uint8_t *)quic_data);

    if ((pub_flags & QUIC_PACKET_8BYTE_CONNECTION_ID) == 0) {
        RTE_LOG(WARNING, IPVS, "packet without cid, pub_flag:%u\n", pub_flags);
        return EDPVS_NOTEXIST;
    }

    quic_data += sizeof(pub_flags);
    *quic_cid = *((uint64_t*)quic_data);

    return EDPVS_OK;
}

/*source ip hash target*/
static int get_sip_hash_target(int af, const struct rte_mbuf *mbuf,
                               uint32_t *addr_fold)
{
    if (af == AF_INET) {
        *addr_fold = ip4_hdr(mbuf)->src_addr;
    } else if (af == AF_INET6) {
        struct in6_addr *saddr = &ip6_hdr(mbuf)->ip6_src;
        *addr_fold = saddr->s6_addr32[0]^saddr->s6_addr32[1]^
                     saddr->s6_addr32[2]^saddr->s6_addr32[3];
    } else {
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static inline struct dp_vs_dest *
dp_vs_conhash_get(struct dp_vs_service *svc, struct conhash_s *conhash,
                  const struct rte_mbuf *mbuf)
{
    char str[40] = {0};
    uint64_t quic_cid;
    uint32_t addr_fold;
    const struct node_s *node;

    if (svc->flags & DP_VS_SVC_F_QID_HASH) {
        if (svc->proto != IPPROTO_UDP) {
            RTE_LOG(ERR, IPVS, "QUIC cid hash scheduler should only be set in UDP service.\n");
            return NULL;
        }
        /* try to get CID for hash target first, then source IP. */
        if (EDPVS_OK == get_quic_hash_target(svc->af, mbuf, &quic_cid)) {
            snprintf(str, sizeof(str), "%lu", quic_cid);
        } else if (EDPVS_OK == get_sip_hash_target(svc->af, mbuf, &addr_fold)) {
            snprintf(str, sizeof(str), "%u", addr_fold);
        } else {
            return NULL;
        }

    } else if (svc->flags & DP_VS_SVC_F_SIP_HASH) {
        if (EDPVS_OK == get_sip_hash_target(svc->af, mbuf, &addr_fold)) {
            snprintf(str, sizeof(str), "%u", addr_fold);
        } else {
            return NULL;
        }

    } else {
        RTE_LOG(ERR, IPVS, "%s: invalid hash target.\n", __func__);
        return NULL;
    }

    node = conhash_lookup(conhash, str);
    return node == NULL? NULL: node->data;
}

static void node_fini(struct node_s *node)
{
    struct conhash_node *p_conhash_node = NULL;

    if (!node)
        return;

    if (node->data) {
        dp_vs_dest_put((struct dp_vs_dest *)node->data, true);
        node->data = NULL;
    }

    p_conhash_node = container_of(node, struct conhash_node, node);
    list_del(&(p_conhash_node->list));
    rte_free(p_conhash_node);
}

static int conhash_update_node_replicas(struct conhash_node *p_conhash_node, struct conhash_sched_data *p_sched_data,
        struct dp_vs_dest *dest, int weight_gcd)
{
    int16_t weight;
    struct node_s *p_node;
    int ret;
    char iden[64];
    char addr[INET6_ADDRSTRLEN];

    // del from conhash
    p_node = &(p_conhash_node->node);
    ret = conhash_del_node(p_sched_data->conhash, p_node);
    if (ret < 0) {
        RTE_LOG(ERR, SERVICE, "%s: conhash_del_node failed\n", __func__);
        return EDPVS_INVAL;
    }

    // adjust weight
    weight = rte_atomic16_read(&dest->weight);
    inet_ntop(dest->af, &dest->addr, addr, sizeof(addr));
    snprintf(iden, sizeof(iden), "%s%d", addr, dest->port);
    conhash_set_node(p_node, iden, weight / weight_gcd * REPLICA);

    // add to conhash again
    ret = conhash_add_node(p_sched_data->conhash, p_node);
    if (ret < 0) {
        RTE_LOG(ERR, SERVICE, "%s: conhash_set_node failed\n", __func__);
        return EDPVS_INVAL;
    }

    return EDPVS_OK;
}

static int dp_vs_conhash_add_dest(struct dp_vs_service *svc,
        struct dp_vs_dest *dest)
{
    int ret;
    char iden[64];
    char addr[INET6_ADDRSTRLEN];
    int16_t weight = 0;
    struct node_s *p_node;
    struct conhash_node *p_conhash_node;
    struct conhash_sched_data *p_sched_data;
    int weight_gcd;
    struct dp_vs_dest *p_dest;

    p_sched_data = (struct conhash_sched_data *)(svc->sched_data);

    weight = rte_atomic16_read(&dest->weight);
    weight_gcd = dp_vs_gcd_weight(svc);
    if (weight < 0) {
        RTE_LOG(ERR, SERVICE, "%s: add dest with weight(%d) less than 0\n",
                __func__, weight);
        return EDPVS_INVAL;
    }

    p_conhash_node = rte_zmalloc(NULL, sizeof(struct conhash_node),
            RTE_CACHE_LINE_SIZE);
    if (!p_conhash_node) {
        RTE_LOG(ERR, SERVICE, "%s: alloc conhash node failed\n", __func__);
        return EDPVS_NOMEM;
    }

    INIT_LIST_HEAD(&(p_conhash_node->list));

    // add node to conhash
    p_node = &(p_conhash_node->node);
    inet_ntop(dest->af, &dest->addr, addr, sizeof(addr));
    snprintf(iden, sizeof(iden), "%s%d", addr, dest->port);
    conhash_set_node(p_node, iden, weight / weight_gcd * REPLICA);

    ret = conhash_add_node(p_sched_data->conhash, p_node);
    if (ret < 0) {
        RTE_LOG(ERR, SERVICE, "%s: conhash_add_node failed\n", __func__);
        rte_free(p_conhash_node);
        return EDPVS_INVAL;
    }

    // set node data
    rte_atomic32_inc(&dest->refcnt);
    p_node->data = dest;

    // add conhash node to list
    list_add(&(p_conhash_node->list), &(p_sched_data->nodes));

    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        p_dest = (struct dp_vs_dest *)p_conhash_node->node.data;
        weight = rte_atomic16_read(&p_dest->weight);
        if (p_conhash_node->node.replicas == weight / weight_gcd * REPLICA)
            continue;
        if (EDPVS_OK != conhash_update_node_replicas(p_conhash_node, p_sched_data, p_dest, weight_gcd)) {
            return EDPVS_INVAL;
        }
    }

    return EDPVS_OK;
}

static int dp_vs_conhash_del_dest(struct dp_vs_service *svc,
        struct dp_vs_dest *dest)
{
    int ret;
    struct node_s *p_node;
    struct conhash_node *p_conhash_node, *next;
    struct conhash_sched_data *p_sched_data;
    int weight_gcd;
    struct dp_vs_dest *p_dest;
    int16_t weight;

    p_sched_data = (struct conhash_sched_data *)(svc->sched_data);
    weight_gcd = dp_vs_gcd_weight(svc);

    list_for_each_entry_safe(p_conhash_node, next, &(p_sched_data->nodes), list) {
        p_dest = (struct dp_vs_dest *)p_conhash_node->node.data;
        if (p_dest == dest) {
            p_node = &(p_conhash_node->node);
            ret = conhash_del_node(p_sched_data->conhash, p_node);
            if (ret < 0) {
                RTE_LOG(ERR, SERVICE, "%s: conhash_del_node failed\n", __func__);
                return EDPVS_INVAL;
            }
            node_fini(p_node);
        } else {
            weight = rte_atomic16_read(&p_dest->weight);
            if (p_conhash_node->node.replicas == weight / weight_gcd * REPLICA)
                continue;
            if (EDPVS_OK != conhash_update_node_replicas(p_conhash_node, p_sched_data, p_dest, weight_gcd)) {
                return EDPVS_INVAL;
            }
        }
    }

    return EDPVS_OK;
}

static int dp_vs_conhash_edit_dest(struct dp_vs_service *svc,
        __rte_unused struct dp_vs_dest *dest)
{
    int16_t weight;
    struct conhash_node *p_conhash_node;
    struct conhash_sched_data *p_sched_data;
    int weight_gcd;
    struct dp_vs_dest *p_dest;

    weight_gcd = dp_vs_gcd_weight(svc);
    p_sched_data = (struct conhash_sched_data *)(svc->sched_data);

    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        p_dest = (struct dp_vs_dest *)p_conhash_node->node.data;
        weight = rte_atomic16_read(&p_dest->weight);
        if (p_conhash_node->node.replicas == weight / weight_gcd * REPLICA)
            continue;
        if (EDPVS_OK != conhash_update_node_replicas(p_conhash_node, p_sched_data, p_dest, weight_gcd)) {
            return EDPVS_INVAL;
        }
    }

    return EDPVS_OK;
}

/*
 *      Assign dest to conhash.
 */
static int
dp_vs_conhash_assign(struct dp_vs_service *svc)
{
    int err;
    struct dp_vs_dest *dest;

    list_for_each_entry(dest, &svc->dests, n_list) {
        err = dp_vs_conhash_add_dest(svc, dest);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, SERVICE, "%s: add dest to conhash failed\n", __func__);
            return err;
        }
    }

    return EDPVS_OK;
}

static int dp_vs_conhash_init_svc(struct dp_vs_service *svc)
{
    struct conhash_sched_data *sched_data = NULL;

    svc->sched_data = NULL;

    // alloc schedule data
    sched_data = rte_zmalloc(NULL, sizeof(struct conhash_sched_data),
            RTE_CACHE_LINE_SIZE);
    if (!sched_data) {
        RTE_LOG(ERR, SERVICE, "%s: alloc schedule data faild\n", __func__);
        return EDPVS_NOMEM;
    }

    // init conhash
    sched_data->conhash = conhash_init(NULL);
    if (!sched_data->conhash) {
        RTE_LOG(ERR, SERVICE, "%s: conhash init faild!\n", __func__);
        rte_free(sched_data);
        return EDPVS_NOMEM;
    }

    // init node list
    INIT_LIST_HEAD(&(sched_data->nodes));

    // assign node
    svc->sched_data = sched_data;
    return dp_vs_conhash_assign(svc);
}

static int dp_vs_conhash_done_svc(struct dp_vs_service *svc)
{
    struct conhash_sched_data *sched_data =
        (struct conhash_sched_data *)(svc->sched_data);
    struct conhash_node *p_conhash_node, *p_conhash_node_next;

    conhash_fini(sched_data->conhash, node_fini);

    // del nodes left in list when rs weight is 0
    list_for_each_entry_safe(p_conhash_node, p_conhash_node_next,
                             &(sched_data->nodes), list) {
       node_fini(&(p_conhash_node->node));
    }

    rte_free(svc->sched_data);
    svc->sched_data = NULL;

    return EDPVS_OK;
}

static int dp_vs_conhash_update_svc(struct dp_vs_service *svc,
        struct dp_vs_dest *dest, sockoptid_t opt)
{
    int ret;

    switch (opt) {
        case DPVS_SO_SET_ADDDEST:
            ret = dp_vs_conhash_add_dest(svc, dest);
            break;
        case DPVS_SO_SET_DELDEST:
            ret = dp_vs_conhash_del_dest(svc, dest);
            break;
        case DPVS_SO_SET_EDITDEST:
            ret = dp_vs_conhash_edit_dest(svc, dest);
            break;
        default:
            ret = EDPVS_INVAL;
            break;
    }

    if (ret != EDPVS_OK)
        RTE_LOG(ERR, SERVICE, "%s: update service faild!\n", __func__);

    return ret;
}

/*
 *      Consistent Hashing scheduling
 */
static struct dp_vs_dest *
dp_vs_conhash_schedule(struct dp_vs_service *svc, const struct rte_mbuf *mbuf,
            const struct dp_vs_iphdr *iph __rte_unused)
{
    struct dp_vs_dest *dest;
    struct conhash_sched_data *sched_data =
        (struct conhash_sched_data *)(svc->sched_data);

    dest = dp_vs_conhash_get(svc, sched_data->conhash, mbuf);

    return dp_vs_dest_is_valid(dest) ? dest : NULL;
}

/*
 *      IPVS CONHASH Scheduler structure
 */
static struct dp_vs_scheduler dp_vs_conhash_scheduler =
{
    .name = "conhash",
    .n_list =         LIST_HEAD_INIT(dp_vs_conhash_scheduler.n_list),
    .init_service =   dp_vs_conhash_init_svc,
    .exit_service =   dp_vs_conhash_done_svc,
    .update_service = dp_vs_conhash_update_svc,
    .schedule =       dp_vs_conhash_schedule,
};

int  dp_vs_conhash_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_conhash_scheduler);
}

int dp_vs_conhash_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_conhash_scheduler);
}
