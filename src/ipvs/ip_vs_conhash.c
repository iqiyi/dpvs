/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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

#include "ipv4.h"
#include "libconhash/conhash.h"
#include "ipvs/conhash.h"

#define REPLICA 160

#define QUIC_PACKET_8BYTE_CONNECTION_ID  (1 << 3)


/* QUIC CID hash target for quic*
 * QUIC CID(qid) should be configured in UDP service*/
static int get_quic_hash_target(const struct rte_mbuf *mbuf, uint64_t *quic_cid)
{
    uint8_t pub_flags;
    char *quic_data;
    uint32_t quic_len;

    quic_len = ip4_hdrlen(mbuf) + sizeof(struct udp_hdr) + \
                  sizeof(pub_flags) + sizeof(*quic_cid);

    if (mbuf_may_pull((struct rte_mbuf *)mbuf, quic_len) != 0)
        return EDPVS_NOTEXIST;

    quic_data = rte_pktmbuf_mtod_offset(mbuf, char *, ip4_hdrlen(mbuf) + sizeof(struct udp_hdr));
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
static int get_sip_hash_target(const struct rte_mbuf *mbuf, uint32_t *sip)
{
    *sip = ip4_hdr(mbuf)->src_addr;
    return EDPVS_OK;
}

static inline struct dp_vs_dest *
dp_vs_conhash_get(struct dp_vs_service *svc, struct conhash_s *conhash,
                  const struct rte_mbuf *mbuf)
{
    char str[40] = {0};
    uint64_t quic_cid;
    uint32_t sip;
    const struct node_s *node;

    if (svc->flags & DP_VS_SVC_F_QID_HASH) {
        if (svc->proto != IPPROTO_UDP) {
            RTE_LOG(ERR, IPVS, "QUIC cid hash scheduler should only be set in UDP service.\n");
            return NULL;
        }
        /* try to get CID for hash target first, then source IP. */
        if (EDPVS_OK == get_quic_hash_target(mbuf, &quic_cid)) {
            snprintf(str, sizeof(str), "%lu", quic_cid);
        } else if (EDPVS_OK == get_sip_hash_target(mbuf, &sip)) {
            snprintf(str, sizeof(str), "%u", sip);
        } else {
            return NULL;
        }

    } else if (svc->flags & DP_VS_SVC_F_SIP_HASH) {
        if (EDPVS_OK == get_sip_hash_target(mbuf, &sip)) {
            snprintf(str, sizeof(str), "%u", sip);
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

/*
 *      Assign dest to connhash.
 */
static int
dp_vs_conhash_assign(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;
    struct node_s *p_node;
    int weight = 0;
    char str[40];

    list_for_each_entry(dest, &svc->dests, n_list) {
       weight = rte_atomic16_read(&dest->weight);
       if (weight > 0) {

           p_node = rte_zmalloc("p_node", sizeof(struct node_s), RTE_CACHE_LINE_SIZE);
           if (p_node == NULL) {
                return EDPVS_NOMEM;
            }

           rte_atomic32_inc(&dest->refcnt);
           p_node->data = dest;

           snprintf(str, sizeof(str), "%u%d", dest->addr.in.s_addr, dest->port);

           conhash_set_node(p_node, str, weight*REPLICA);
           conhash_add_node(svc->sched_data, p_node);
        }
    }
    return EDPVS_OK;
}

static void node_fini(struct node_s *node)
{
    if (node)
        return;

    if (node->data) {
        rte_atomic32_dec(&(((struct dp_vs_dest *)(node->data))->refcnt));
        node->data = NULL;
    }

    rte_free(node);
}

static int dp_vs_conhash_init_svc(struct dp_vs_service *svc)
{
    svc->sched_data = conhash_init(NULL);

    if (!svc->sched_data) {
        RTE_LOG(ERR, SERVICE, "%s: conhash init faild!\n", __func__);
        return EDPVS_NOMEM;
    }

    dp_vs_conhash_assign(svc);

    return EDPVS_OK;
}

static int dp_vs_conhash_done_svc(struct dp_vs_service *svc)
{
    conhash_fini(svc->sched_data, node_fini);

    return EDPVS_OK;
}

static int dp_vs_conhash_update_svc(struct dp_vs_service *svc)
{
    conhash_fini(svc->sched_data, node_fini);

    svc->sched_data = conhash_init(NULL);

    dp_vs_conhash_assign(svc);

    return 0;
}

static inline int is_overloaded(struct dp_vs_dest *dest)
{
    return dest->flags & DPVS_DEST_F_OVERLOAD;
}

/*
 *      Consistent Hashing scheduling
 */
static struct dp_vs_dest *
dp_vs_conhash_schedule(struct dp_vs_service *svc, const struct rte_mbuf *mbuf)
{
    struct dp_vs_dest *dest;

    dest = dp_vs_conhash_get(svc, (struct conhash_s *)svc->sched_data, mbuf);

    if (!dest
        || !(dest->flags & DPVS_DEST_F_AVAILABLE)
        || rte_atomic16_read(&dest->weight) <= 0
        || is_overloaded(dest)) {

        return NULL;
    }
    else
        return dest;
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
