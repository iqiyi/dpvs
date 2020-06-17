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

#include <assert.h>
#include <netinet/ip6.h>
#include "ipv4.h"
#include "ipv6.h"
#include "libconhash/conhash.h"
#include "ipvs/conhash.h"

struct conhash_node {
    struct list_head    list;
    uint16_t            weight_ratio;
    int                 af;         /* address family */
    union inet_addr     addr;       /* IP address of the server */
    uint16_t            port;       /* port number of the server */
    int                 index;      /* rs index in dests list of svc */
    struct node_s       node;       /* node in libconhash */
};

struct conhash_sched_data {
    struct list_head    nodes;      /* node list */
    struct conhash_s   *conhash;    /* consistent hash meta data */
    rte_atomic32_t      refcnt;
};

struct conhash_svc_data {
    struct list_head    list;
    struct conhash_sched_data   *sched_data;
    int                 af;
    uint8_t             proto;      /* TCP/UDP/... */
    union inet_addr     addr;       /* virtual IP address */
    uint16_t            port;
};

struct conhash_rs_data {
    void   *rs_entry_tbl[DP_VS_MAX_RS_NUM_PER_SVC];     /* rs entry table */
};

#define REPLICA 160
#define QUIC_PACKET_8BYTE_CONNECTION_ID  (1 << 3)

static struct list_head s_conhash_svc_data_tbl[DP_VS_SVC_TAB_SIZE];
static int s_conhash_max_try_cnt = 200;

/*
 * QUIC CID hash target for quic*
 * QUIC CID(qid) should be configured in UDP service
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

    quic_len = udphoff + sizeof(struct udp_hdr) +
               sizeof(pub_flags) + sizeof(*quic_cid);

    if (mbuf_may_pull((struct rte_mbuf *)mbuf, quic_len) != 0)
        return EDPVS_NOTEXIST;

    quic_data = rte_pktmbuf_mtod_offset(mbuf, char *,
                                        udphoff + sizeof(struct udp_hdr));
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
    struct conhash_node *p_conhash_node = NULL;
    struct conhash_rs_data *rs_data = NULL;
    struct dp_vs_dest *dest = NULL;
    int index = 0;

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
    if (node) {
        rs_data = (struct conhash_rs_data *)svc->sched_data[1];
        p_conhash_node = container_of(node, struct conhash_node, node);
        index = p_conhash_node->index;
        if (rs_data && (-1 < index) && (index < DP_VS_MAX_RS_NUM_PER_SVC)) {
            dest = (struct dp_vs_dest *)rs_data->rs_entry_tbl[index];
        }
    }
    return dest;
}

static void node_fini(struct node_s *node)
{
    struct conhash_node *p_conhash_node = NULL;

    if (!node)
        return;

    p_conhash_node = container_of(node, struct conhash_node, node);
    list_del(&(p_conhash_node->list));
    rte_free(p_conhash_node);
}

static int dp_vs_conhash_add_dest(struct dp_vs_service *svc,
        struct dp_vs_dest *dest, struct conhash_sched_data *p_sched_data)
{
    int ret;
    char str[40];
    uint32_t addr_fold;
    int16_t weight = 0;
    struct node_s *p_node;
    struct conhash_node *p_conhash_node;
    int weight_gcd;

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
    p_conhash_node->af = dest->af;
    p_conhash_node->addr = dest->addr;
    p_conhash_node->port = dest->port;
    p_conhash_node->weight_ratio = weight / weight_gcd;
    p_conhash_node->index = -1;

    // add node to conhash
    p_node = &(p_conhash_node->node);
    addr_fold = inet_addr_fold(dest->af, &dest->addr);
    snprintf(str, sizeof(str), "%u%d", addr_fold, dest->port);

    conhash_set_node(p_node, str, p_conhash_node->weight_ratio * REPLICA);
    ret = conhash_add_node(p_sched_data->conhash, p_node);
    if (ret < 0) {
        RTE_LOG(ERR, SERVICE, "%s: conhash_add_node failed\n", __func__);
        rte_free(p_conhash_node);
        return EDPVS_INVAL;
    }

    // add conhash node to list
    list_add(&(p_conhash_node->list), &(p_sched_data->nodes));

    return EDPVS_OK;
}

static int dp_vs_conhash_dest_weight_changed(struct dp_vs_service *svc,
        struct dp_vs_dest *dest, struct conhash_svc_data * p_svc_data)
{
    int16_t weight;
    int weight_gcd;
    struct conhash_node *p_conhash_node;
    struct conhash_sched_data *p_sched_data;
    int change_flag = 1;

    p_sched_data = p_svc_data->sched_data;
    weight = rte_atomic16_read(&dest->weight);
    weight_gcd = dp_vs_gcd_weight(svc);

    // find node by addr and port
    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        if (p_conhash_node->af == dest->af &&
                inet_addr_equal(dest->af, &p_conhash_node->addr, &dest->addr) &&
                p_conhash_node->port == dest->port) {
            if (weight / weight_gcd == p_conhash_node->weight_ratio)
                change_flag = 0;
            break;
        }
    }

    return change_flag;
}

/*
 *      Assign dest to connhash.
 */
static int dp_vs_conhash_assign(struct dp_vs_service *svc,
            struct conhash_sched_data *p_sched_data)
{
    int err;
    struct dp_vs_dest *dest;

    list_for_each_entry(dest, &svc->dests, n_list) {
        err = dp_vs_conhash_add_dest(svc, dest, p_sched_data);
        if (err != EDPVS_OK) {
            RTE_LOG(ERR, SERVICE, "%s: add dest to conhash failed\n", __func__);
            return err;
        }
    }

    return EDPVS_OK;
}

static struct conhash_svc_data *dp_vs_conhash_get_svc_data(struct dp_vs_service *svc)
{
    int hash;
    struct conhash_svc_data *svc_data;

    hash = dp_vs_service_hashkey(svc->af, svc->proto, &svc->addr);
    if (unlikely(hash < 0)) {
        RTE_LOG(ERR, SERVICE, "%s: svc hash invalid.\n", __func__);
        return NULL;
    }

    list_for_each_entry(svc_data, &s_conhash_svc_data_tbl[hash], list) {
        if ((svc_data->af == svc->af)
            && inet_addr_equal(svc->af, &svc_data->addr, &svc->addr)
            && (svc_data->port == svc->port)
            && (svc_data->proto == svc->proto)) {
                return svc_data;
            }
    }

    return NULL;
}

static void dp_vs_conhash_update_node_index(struct conhash_sched_data *p_sched_data)
{
    struct conhash_node *p_conhash_node = NULL;
    int i = 0;

    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        p_conhash_node->index = i;
        i++;
    }
}

static void dp_vs_conhash_free_sched_data(struct conhash_sched_data *sched_data)
{
    struct conhash_node *p_conhash_node, *p_conhash_node_next;

    if (unlikely(!sched_data)) {
        return;
    }
    conhash_fini(sched_data->conhash, node_fini);
    // del nodes left in list when rs weight is 0
    list_for_each_entry_safe(p_conhash_node, p_conhash_node_next,
                             &(sched_data->nodes), list) {
       node_fini(&(p_conhash_node->node));
    }
    rte_free(sched_data);
}

static int dp_vs_conhash_create_sched_data(struct conhash_sched_data **sched_data)
{
    struct conhash_sched_data *tmp_sched_data = NULL;
    int ret = EDPVS_OK;

    tmp_sched_data = rte_zmalloc(NULL, sizeof(struct conhash_sched_data),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!tmp_sched_data)) {
        ret = EDPVS_NOMEM;
        RTE_LOG(ERR, SERVICE, "%s: alloc schedule data faild\n", __func__);
        return ret;
    }
    // init conhash
    tmp_sched_data->conhash = conhash_init(NULL);
    if (unlikely(!tmp_sched_data->conhash)) {
        ret = EDPVS_NOMEM;
        RTE_LOG(ERR, SERVICE, "%s: conhash init faild!\n", __func__);
        rte_free(tmp_sched_data);
        return ret;
    }
    // init node list
    INIT_LIST_HEAD(&(tmp_sched_data->nodes));
    rte_atomic32_set(&tmp_sched_data->refcnt, 0);
    *sched_data = tmp_sched_data;

    return ret;
}

static int dp_vs_conhash_create_svc_data(struct dp_vs_service *svc,
            struct conhash_svc_data **svc_data)
{
    struct conhash_sched_data *sched_data = NULL;
    struct conhash_svc_data *tmp_svc_data = NULL;
    int hash = 0;
    int ret = EDPVS_OK;

    hash = dp_vs_service_hashkey(svc->af, svc->proto, &svc->addr);
    if (unlikely(hash < 0)) {
        ret = EDPVS_INVAL;
        RTE_LOG(ERR, SERVICE, "%s: svc hash invalid.\n", __func__);
        return ret;
    }

    tmp_svc_data = rte_zmalloc(NULL, sizeof(struct conhash_svc_data),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(NULL == tmp_svc_data)) {
        ret = EDPVS_NOMEM;
        RTE_LOG(ERR, SERVICE, "%s: alloc svc data faild\n", __func__);
        return ret;
    }
    INIT_LIST_HEAD(&(tmp_svc_data->list));
    tmp_svc_data->af = svc->af;
    tmp_svc_data->proto = svc->proto;
    tmp_svc_data->addr = svc->addr;
    tmp_svc_data->port = svc->port;

    ret = dp_vs_conhash_create_sched_data(&sched_data);
    if (unlikely(EDPVS_OK != ret)) {
        rte_free(tmp_svc_data);
        return ret;
    }
    ret = dp_vs_conhash_assign(svc, sched_data);
    if (unlikely(EDPVS_OK != ret)) {
        dp_vs_conhash_free_sched_data(sched_data);
        rte_free(tmp_svc_data);
        return ret;
    }
    dp_vs_conhash_update_node_index(sched_data);

    tmp_svc_data->sched_data = sched_data;
    list_add(&tmp_svc_data->list, &s_conhash_svc_data_tbl[hash]);
    *svc_data = tmp_svc_data;

    return ret;
}

static int dp_vs_conhash_create_rs_data(struct conhash_rs_data **rs_data)
{
    struct conhash_rs_data *tmp_rs_data = NULL;

    tmp_rs_data = rte_zmalloc(NULL, sizeof(struct conhash_rs_data),
            RTE_CACHE_LINE_SIZE);
    if (unlikely(!tmp_rs_data)) {
        RTE_LOG(ERR, SERVICE, "%s: alloc rs data faild\n", __func__);
        return EDPVS_NOMEM;
    }
    *rs_data = tmp_rs_data;

    return EDPVS_OK;
}

static void dp_vs_conhash_update_rs_data(struct dp_vs_service *svc,
            struct conhash_sched_data *p_sched_data)
{
    struct conhash_rs_data *rs_data = NULL;
    struct conhash_node *p_conhash_node = NULL;
    int i = 0;

    rs_data = (struct conhash_rs_data *)svc->sched_data[1];
    memset(rs_data->rs_entry_tbl, 0, sizeof(rs_data->rs_entry_tbl));
    list_for_each_entry(p_conhash_node, &(p_sched_data->nodes), list) {
        rs_data->rs_entry_tbl[i] = dp_vs_dest_lookup(p_conhash_node->af, svc,
                        &p_conhash_node->addr, p_conhash_node->port);
        if (unlikely(!rs_data->rs_entry_tbl[i])) {
            RTE_LOG(INFO, SERVICE, "[%d]: %s: dest lookup none\n",
                rte_lcore_id(), __func__);
        }
        i++;
    }
}

static int dp_vs_conhash_init_svc(struct dp_vs_service *svc)
{
    struct conhash_svc_data *svc_data = NULL;
    struct conhash_rs_data *rs_data = NULL;
    int ret = EDPVS_OK;
    int cid = rte_lcore_id();
    int try_cnt = 0;

    // alloc rs data;
    ret = dp_vs_conhash_create_rs_data(&rs_data);
    if (EDPVS_OK != ret) {
        return ret;
    }

    svc_data = dp_vs_conhash_get_svc_data(svc);
    if (unlikely(svc_data && (rte_get_master_lcore() == cid))) {
        RTE_LOG(INFO, SERVICE, "[%d]: %s: master waits slave lcores to free svc data!\n",
                cid, __func__);
        while ((svc_data = dp_vs_conhash_get_svc_data(svc))) {
            rte_delay_ms(1);
            if (unlikely(++try_cnt >= s_conhash_max_try_cnt)) {
                RTE_LOG(ERR, SERVICE, "%s: master gets existed svc data !!\n",
                    __func__);
                break;
            }
        }
    }
    if (!svc_data) {
        if (rte_get_master_lcore() == cid) {
            // only master lcore comes here.
            RTE_LOG(DEBUG, SERVICE, "[%d] %s: conhash init svc get svc data failed, creating\n",
                        cid, __func__);
            ret = dp_vs_conhash_create_svc_data(svc, &svc_data);
            if (EDPVS_OK != ret) {
                rte_free(rs_data);
                return ret;
            }
        }
        else {
            RTE_LOG(ERR, SERVICE, "[%d]: %s: svc data lookup none !\n",
                cid, __func__);
            ret = EDPVS_NOTEXIST;
            rte_free(rs_data);
            return ret;
        }
    }

    svc->sched_data[0] = svc_data->sched_data;
    svc->sched_data[1] = rs_data;
    dp_vs_conhash_update_rs_data(svc, svc_data->sched_data);
    rte_atomic32_inc(&svc_data->sched_data->refcnt);

    return ret;
}

static int dp_vs_conhash_done_svc(struct dp_vs_service *svc)
{
    struct conhash_rs_data *rs_data = NULL;
    struct conhash_svc_data *svc_data = NULL;
    struct conhash_sched_data *sched_data = NULL;

    rs_data = (struct conhash_rs_data *)svc->sched_data[1];
    if (rs_data) {
        rte_free(rs_data);
        svc->sched_data[1] = NULL;
    }

    sched_data = (struct conhash_sched_data *)svc->sched_data[0];
    if (sched_data) {
        if (rte_atomic32_dec_and_test(&sched_data->refcnt)) {
            dp_vs_conhash_free_sched_data(sched_data);
            svc->sched_data[0] = NULL;
        }
        else {
            RTE_LOG(DEBUG, SERVICE, "[%d] %s: sched data refcnt dec!\n",
                    rte_lcore_id(), __func__);
            return EDPVS_OK;
        }
    }

    svc_data = dp_vs_conhash_get_svc_data(svc);
    if (unlikely(!svc_data)) {
        RTE_LOG(ERR, SERVICE, "%s: svc data not exist!\n", __func__);
        return EDPVS_NOTEXIST;
    }
    list_del(&(svc_data->list));
    rte_free(svc_data);

    return EDPVS_OK;
}

static int dp_vs_conhash_update_svc(struct dp_vs_service *svc,
        struct dp_vs_dest *dest, sockoptid_t opt)
{
    int ret = EDPVS_OK;
    int cid = rte_lcore_id();
    struct conhash_svc_data *svc_data = NULL;
    struct conhash_sched_data *old_sched_data = NULL;
    struct conhash_sched_data *new_sched_data = NULL;
    int update_flag = 0;
    int try_cnt = 0;

    svc_data = dp_vs_conhash_get_svc_data(svc);
    if (unlikely(!svc_data)) {
        ret = EDPVS_NOTEXIST;
        RTE_LOG(ERR, SERVICE, "%s: svc data not exist!\n", __func__);
        return ret;
    }
    old_sched_data = svc->sched_data[0];
    new_sched_data = svc_data->sched_data;

    if (rte_get_master_lcore() == cid) {
        // only master comes here.
        switch (opt) {
            case DPVS_SO_SET_ADDDEST:
            case DPVS_SO_SET_DELDEST:
                update_flag = 1;
                break;
            case DPVS_SO_SET_EDITDEST:
                update_flag = dp_vs_conhash_dest_weight_changed(svc, dest,
                                svc_data);
                break;
        }
        if (update_flag) {
            while (rte_atomic32_read(&old_sched_data->refcnt) < g_lcore_num) {
                /**
                *   Because the asynchronous message is transmitted between the slaves and the master,
                *   it may happen that the sche data is freed by the master in advance.
                *   (In theory, the sche data should always be freed by the slave lcore)
                *   For example, rs1 rs2 are added, rs3 is being added in master lcore,
                *   and the slaves have not received the asynchronous msg to add rs2,
                *   the old sched data will be freed by master lcore in the process of adding rs3.
                *   ps:
                *       If we use synchronization msg between slaves and master to config svc/rs,
                *       the timeout log may be printed.
                */
                rte_delay_ms(1);
                if (unlikely(++try_cnt >= s_conhash_max_try_cnt)) {
                    RTE_LOG(ERR, SERVICE, "%s: refcnt of sche data is %d, less than %d !!\n",
                        __func__, rte_atomic32_read(&old_sched_data->refcnt), g_lcore_num);
                    break;
                }
            }
            ret = dp_vs_conhash_create_sched_data(&new_sched_data);
            if (unlikely(EDPVS_OK != ret)) {
                RTE_LOG(ERR, SERVICE, "%s: create new sched data failed!\n", __func__);
                new_sched_data = old_sched_data;
                goto END;
            }
            ret = dp_vs_conhash_assign(svc, new_sched_data);
            if (unlikely(EDPVS_OK != ret)) {
                RTE_LOG(ERR, SERVICE, "%s: assign new sched data failed!\n", __func__);
                dp_vs_conhash_free_sched_data(new_sched_data);
                new_sched_data = old_sched_data;
                goto END;
            }
            dp_vs_conhash_update_node_index(new_sched_data);
        }
    }

END:
    svc_data->sched_data = new_sched_data;
    svc->sched_data[0] = new_sched_data;
    dp_vs_conhash_update_rs_data(svc, svc_data->sched_data);
    rte_atomic32_inc(&new_sched_data->refcnt);
    if (rte_atomic32_dec_and_test(&old_sched_data->refcnt)) {
        RTE_LOG(DEBUG, SERVICE, "[%d]: %s: free sched data!\n",
            cid, __func__);
        dp_vs_conhash_free_sched_data(old_sched_data);
    }

    return ret;
}

/*
 *      Consistent Hashing scheduling
 */
static struct dp_vs_dest *
dp_vs_conhash_schedule(struct dp_vs_service *svc, const struct rte_mbuf *mbuf)
{
    struct dp_vs_dest *dest = NULL;
    struct conhash_sched_data *sched_data = NULL;

    sched_data = (struct conhash_sched_data *)svc->sched_data[0];
    if (unlikely(!sched_data)) {
        return NULL;
    }
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
    int i;
    for (i = 0; i < DP_VS_SVC_TAB_SIZE; i++) {
        INIT_LIST_HEAD(&s_conhash_svc_data_tbl[i]);
    }
    return register_dp_vs_scheduler(&dp_vs_conhash_scheduler);
}

int dp_vs_conhash_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_conhash_scheduler);
}
