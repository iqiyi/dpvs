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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include "inet.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"
#include "ipvs/laddr.h"
#include "ipvs/conn.h"
#include "ctrl.h"

/*
 * Trash for destinations
 */

struct list_head dp_vs_dest_trash = LIST_HEAD_INIT(dp_vs_dest_trash);

struct dp_vs_dest *dp_vs_dest_lookup(int af,
                                     struct dp_vs_service *svc,
                                     const union inet_addr *daddr,
                                     uint16_t dport)
{
    struct dp_vs_dest *dest;

    list_for_each_entry(dest, &svc->dests, n_list){
        if ((dest->af == af)
            && inet_addr_equal(af, &dest->addr, daddr)
            && (dest->port == dport))
            return dest;
    }
    return NULL;
}

static void __dp_vs_dest_update(struct dp_vs_service *svc,
                                struct dp_vs_dest *dest,
                                struct dp_vs_dest_conf *udest)
{
    int conn_flags;
    uint8_t num_lcores;

    netif_get_slave_lcores(&num_lcores, NULL);
    rte_atomic16_set(&dest->weight, udest->weight);
    conn_flags = udest->conn_flags | DPVS_CONN_F_INACTIVE;
    rte_atomic16_set(&dest->conn_flags, conn_flags);

    dp_vs_dest_set_avail(dest);

    if (udest->max_conn == 0 || udest->max_conn > dest->max_conn)
        dest->flags &= ~DPVS_DEST_F_OVERLOAD;
    if (rte_lcore_id() != rte_get_main_lcore()) {
        dest->max_conn = udest->max_conn / num_lcores;
        dest->min_conn = udest->min_conn / num_lcores;
    } else {
        /*
            Ensure that the sum of rs's max_conn in all lcores is equal to the configured max_conn,
            to prevent the operation of modifying rs from keepalived when reloading.
        */
        dest->max_conn = udest->max_conn % num_lcores;
        dest->min_conn = udest->min_conn % num_lcores;
    }
}


int dp_vs_dest_new(struct dp_vs_service *svc,
                   struct dp_vs_dest_conf *udest,
                   struct dp_vs_dest **dest_p)
{
    int size;
    struct dp_vs_dest *dest;
    size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct dp_vs_dest));
    dest = rte_zmalloc("dpvs_new_dest", size, 0);
    if(dest == NULL){
        RTE_LOG(DEBUG, SERVICE, "%s: no memory.\n", __func__);
        return EDPVS_NOMEM;
    }
    assert(dest->svc == NULL);

    dest->af = udest->af;
    dest->proto = svc->proto;
    dest->vaddr = svc->addr;
    dest->vport = svc->port;
    dest->conn_timeout = svc->conn_timeout;
    dest->limit_proportion = svc->limit_proportion;
    dest->vfwmark = svc->fwmark;
    dest->addr = udest->addr;
    dest->port = udest->port;
    dest->fwdmode = udest->fwdmode;
    rte_atomic32_set(&dest->actconns, 0);
    rte_atomic32_set(&dest->inactconns, 0);
    rte_atomic32_set(&dest->persistconns, 0);
    rte_atomic32_set(&dest->refcnt, 1);
    dp_vs_service_bind(dest, svc);

    __dp_vs_dest_update(svc, dest, udest);

    *dest_p = dest;
    return EDPVS_OK;
}

int
dp_vs_dest_add(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    union inet_addr daddr;
    uint16_t dport = udest->port;
    int ret;

    if (udest->weight < 0) {
        RTE_LOG(DEBUG, SERVICE, "%s: server weight less than zero.\n", __func__);
        return EDPVS_NOTSUPP;
    }

    if (udest->min_conn > udest->max_conn) {
        RTE_LOG(DEBUG, SERVICE, "%s: lower threshold is higher than upper threshold\n",
               __func__);
        return EDPVS_NOTSUPP;
    }

    daddr = udest->addr;

    /*
     * Check if the dest already exists in the list
     */
    dest = dp_vs_dest_lookup(udest->af, svc, &daddr, dport);

    if (dest != NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s: dest already exists.\n", __func__);
        return EDPVS_EXIST;
    }

    /*
     * Allocate and initialize the dest structure
     */
    ret = dp_vs_dest_new(svc, udest, &dest);
    if (ret) {
        return ret;
    }

    list_add(&dest->n_list, &svc->dests);
    svc->weight += udest->weight;
    svc->num_dests++;

    /* call the update_service function of its scheduler */
    if (svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_ADDDEST);

    return EDPVS_OK;
}

int
dp_vs_dest_edit(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    union inet_addr daddr;
    uint16_t dport = udest->port;
    uint32_t old_weight;

    if (udest->weight < 0) {
        RTE_LOG(DEBUG, SERVICE,"%s(): server weight less than zero\n", __func__);
        return EDPVS_INVAL;
    }

    if (udest->min_conn > udest->max_conn) {
        RTE_LOG(DEBUG, SERVICE,"%s(): lower threshold is higher than upper threshold\n",
               __func__);
        return EDPVS_INVAL;
    }

    daddr = udest->addr;

    /*
     *  Lookup the destination list
     */
    dest = dp_vs_dest_lookup(udest->af, svc, &daddr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE,"%s(): dest doesn't exist\n", __func__);
        return EDPVS_NOTEXIST;
    }

    /* Save old weight */
    old_weight = rte_atomic16_read(&dest->weight);

    __dp_vs_dest_update(svc, dest, udest);

    /* Update service weight */
    svc->weight = svc->weight - old_weight + udest->weight;
    if (svc->weight < 0) {
        struct dp_vs_dest *tdest;
        svc->weight = 0;
        list_for_each_entry(tdest, &svc->dests, n_list) {
            svc->weight += rte_atomic16_read(&tdest->weight);
        }
        RTE_LOG(ERR, SERVICE, "%s(): vs weight < 0\n", __func__);
    }

    /* call the update_service, because server weight may be changed */
    if (svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_EDITDEST);

    return EDPVS_OK;
}

void dp_vs_dest_put(struct dp_vs_dest *dest)
{
    if (!dest)
        return;

    if (rte_atomic32_dec_and_test(&dest->refcnt)) {
        dp_vs_service_unbind(dest);
        rte_free(dest);
    }
}

/*
 *  Unlink a destination from the given service
 */
void dp_vs_dest_unlink(struct dp_vs_service *svc,
                struct dp_vs_dest *dest, int svcupd)
{
    dp_vs_dest_clear_avail(dest);

    /*
     *  Remove it from the d-linked destination list.
     */
    list_del(&dest->n_list);
    svc->num_dests--;

    svc->weight -= rte_atomic16_read(&dest->weight);
    if (svc->weight < 0) {
        struct dp_vs_dest *tdest;
        svc->weight = 0;
        list_for_each_entry(tdest, &svc->dests, n_list) {
            svc->weight += rte_atomic16_read(&tdest->weight);
        }
        RTE_LOG(ERR, SERVICE, "%s(): vs weight < 0\n", __func__);
    }

    /*
     *  Call the update_service function of its scheduler
     */
    if (svcupd && svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_DELDEST);
}

int
dp_vs_dest_del(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    uint16_t dport = udest->port;

    dest = dp_vs_dest_lookup(udest->af, svc, &udest->addr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE,"%s(): destination not found!\n", __func__);
        return EDPVS_NOTEXIST;
    }

    /*
     *      Unlink dest from the service
     */
    dp_vs_dest_unlink(svc, dest, 1);

    /*
     *      Delete the destination
     */
    dp_vs_dest_put(dest);

    return EDPVS_OK;
}

int dp_vs_dest_get_entries(const struct dp_vs_service *svc,
                           struct dp_vs_get_dests *uptr)
{
    int ret = 0;
    int count = 0;
    struct dp_vs_dest *dest;
    struct dp_vs_dest_entry entry;

    uptr->cid = rte_lcore_id();
    uptr->index = g_lcore_id2index[uptr->cid];
    uptr->num_dests = svc->num_dests;
    list_for_each_entry(dest, &svc->dests, n_list){
        if(count >= svc->num_dests)
            break;
        memset(&entry, 0, sizeof(entry));
        entry.af   = dest->af;
        entry.addr = dest->addr;
        entry.port = dest->port;
        entry.conn_flags = dest->fwdmode;
        entry.weight = rte_atomic16_read(&dest->weight);
        entry.max_conn = dest->max_conn;
        entry.min_conn = dest->min_conn;
        entry.actconns = rte_atomic32_read(&dest->actconns);
        entry.inactconns = rte_atomic32_read(&dest->inactconns);
        entry.persistconns = rte_atomic32_read(&dest->persistconns);
        ret = dp_vs_stats_add(&(entry.stats), &dest->stats);
        if (ret != EDPVS_OK)
            break;

        memcpy(&uptr->entrytable[count], &entry, sizeof(entry));
        count++;
    }

    return ret;
}

static int dp_vs_dest_get_details(const struct dp_vs_service *svc, 
                            struct dp_vs_dest_front *uptr)
{
    int ret = 0;
    int count = 0;
    struct dp_vs_dest *dest;
    struct dp_vs_dest_entry entry, *detail;

    uptr->cid = rte_lcore_id();
    uptr->index = g_lcore_id2index[uptr->cid];
    uptr->num_dests = svc->num_dests;
    detail = (struct dp_vs_dest_entry*)((char*)uptr + sizeof(*uptr));

    list_for_each_entry(dest, &svc->dests, n_list){
        if(count >= svc->num_dests)
            break;
        memset(&entry, 0, sizeof(entry));
        entry.af   = dest->af;
        entry.addr = dest->addr;
        entry.port = dest->port;
        entry.conn_flags = dest->fwdmode;
        entry.weight = rte_atomic16_read(&dest->weight);
        entry.max_conn = dest->max_conn;
        entry.min_conn = dest->min_conn;
        entry.actconns = rte_atomic32_read(&dest->actconns);
        entry.inactconns = rte_atomic32_read(&dest->inactconns);
        entry.persistconns = rte_atomic32_read(&dest->persistconns);
        ret = dp_vs_stats_add(&(entry.stats), &dest->stats);
        if (ret != EDPVS_OK)
            break;

        memcpy(detail, &entry, sizeof(entry));
        detail += 1;
        count++;
    }

    return ret;
}

static int dp_vs_dest_set(sockoptid_t opt, const void *user, size_t len);
static int dp_vs_dest_get(sockoptid_t opt, const void *user, size_t len, void **out, size_t *outlen);

struct dpvs_sockopts sockopts_dest = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = DPVSAGENT_VS_ADD_DESTS,
    .set_opt_max    = DPVSAGENT_VS_DEL_DESTS,
    .set            = dp_vs_dest_set,
    .get_opt_min    = DPVSAGENT_VS_GET_DESTS,
    .get_opt_max    = DPVSAGENT_VS_GET_DESTS,
    .get            = dp_vs_dest_get,
};

static int dest_msg_seq(void) {
    static uint32_t seq = 0;
    return seq++;
}

static int dp_vs_dest_set(sockoptid_t opt, const void *user, size_t len)
{
    struct dp_vs_dest_front *insvc;
    struct dp_vs_dest_detail *details;
    struct dp_vs_dest_conf udest;
    struct dpvs_msg *msg;
    struct dp_vs_service *getsvc;
    int i, ret = EDPVS_INVAL;
    lcoreid_t cid;

    insvc = (struct dp_vs_dest_front*)user;
    if (len != sizeof(*insvc) + insvc->num_dests*sizeof(struct dp_vs_dest_detail)) {
        return EDPVS_INVAL;
    }
    details = (struct dp_vs_dest_detail*)(user + sizeof(struct dp_vs_dest_front));

    cid = rte_lcore_id();
    if (cid < 0 || cid >= DPVS_MAX_LCORE) {
        return EDPVS_INVAL;
    }

    if (cid == rte_get_main_lcore()) {
        if (opt == DPVSAGENT_VS_ADD_DESTS) {
            msg = msg_make(MSG_TYPE_AGENT_ADD_DESTS, dest_msg_seq(), DPVS_MSG_MULTICAST, cid, len, user);
        } else if (opt == DPVSAGENT_VS_DEL_DESTS) {
            msg = msg_make(MSG_TYPE_AGENT_DEL_DESTS, dest_msg_seq(), DPVS_MSG_MULTICAST, cid, len, user);
        } else {
            return EDPVS_NOTSUPP;
        }
        if (!msg)
            return EDPVS_NOMEM;

        ret = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
        if (ret != EDPVS_OK) {
            RTE_LOG(ERR, SERVICE, "[%s] fail to send multicast message\n", __func__);
        }
        msg_destroy(&msg);
    }

    getsvc = dp_vs_service_lookup(insvc->af, insvc->proto, &insvc->addr, insvc->port, insvc->fwmark, NULL, &insvc->match, NULL, cid);
    if (!getsvc || getsvc->proto != insvc->proto) {
        return EDPVS_INVAL;
    }

    for (i = 0; i < insvc->num_dests; i++) {
        memset(&udest, 0, sizeof(struct dp_vs_dest_conf));
        dp_vs_copy_udest_compat(&udest, &details[i]);
        switch (opt) {
            case DPVSAGENT_VS_ADD_DESTS:
                ret = dp_vs_dest_add(getsvc, &udest);
                if (ret == EDPVS_EXIST)
                    ret = dp_vs_dest_edit(getsvc, &udest);
                break;
            case DPVSAGENT_VS_DEL_DESTS:
                ret = dp_vs_dest_del(getsvc, &udest);
                break;
            default:
                return EDPVS_NOTSUPP;
        }
    }
    return ret;
}

static int dp_vs_dest_get(sockoptid_t opt, const void *user, size_t len, void **out, size_t *outlen)
{
    struct dp_vs_dest_front *insvc, *outsvc, *front;
    struct dp_vs_dest_detail *outdest, *slave_dest;
    struct dp_vs_service *getsvc;
    struct dp_vs_dest *dest;
    int size, ret, i;
    struct dpvs_msg *msg, *cur;
    struct dpvs_multicast_queue *reply = NULL;
    lcoreid_t cid;

    switch (opt) {
        case DPVSAGENT_VS_GET_DESTS:
            insvc = (struct dp_vs_dest_front*)user;
            if (len != sizeof(*insvc)) {
                *outlen = 0;
                return EDPVS_INVAL;
            }

            cid = g_lcore_index2id[insvc->index];
            if (cid < 0 || cid >= DPVS_MAX_LCORE) {
                *outlen = 0;
                return EDPVS_INVAL;
            }

            size = sizeof(*insvc) + insvc->num_dests*sizeof(struct dp_vs_dest_detail);

            msg = msg_make(MSG_TYPE_AGENT_GET_DESTS, 0, DPVS_MSG_MULTICAST, rte_lcore_id(), len, user);
            if (!msg) {
                return EDPVS_NOMEM;
            }

            ret = multicast_msg_send(msg, 0, &reply);
            if (ret != EDPVS_OK) {
                RTE_LOG(ERR, SERVICE, "%s: send message fail.\n", __func__);
                msg_destroy(&msg);
                return EDPVS_MSG_FAIL;
            }

            if (cid == rte_get_main_lcore()) {
                // getsvc = dp_vs_service_get_lcore(&outsvc, cid);
                getsvc = dp_vs_service_lookup(insvc->af, insvc->proto, &insvc->addr, insvc->port, insvc->fwmark, NULL, &insvc->match, NULL, cid);
                if (!getsvc) {
                    msg_destroy(&msg);
                    return EDPVS_NOTEXIST;
                }

                size = sizeof(*insvc) + getsvc->num_dests*sizeof(struct dp_vs_dest_detail);
                *out = rte_zmalloc("get_dests", size, 0);
                if (!*out) {
                    msg_destroy(&msg);
                    return EDPVS_NOMEM;
                }

                rte_memcpy(*out, insvc, sizeof(insvc));
                outsvc = (struct dp_vs_dest_front*)*out;
                outsvc->cid = rte_lcore_id();
                outsvc->index = g_lcore_id2index[outsvc->cid];
                outsvc->num_dests = getsvc->num_dests;
                outdest = (struct dp_vs_dest_detail*)(*out + sizeof(outsvc));

                list_for_each_entry(dest, &getsvc->dests, n_list) {
                    outdest->af           = dest->af;
                    outdest->addr         = dest->addr;
                    outdest->port         = dest->port;
                    outdest->conn_flags   = dest->fwdmode;
                    outdest->max_conn     = dest->max_conn;
                    outdest->min_conn     = dest->min_conn;
                    outdest->weight       = rte_atomic16_read(&dest->weight);
                    outdest->actconns     = rte_atomic32_read(&dest->actconns);
                    outdest->inactconns   = rte_atomic32_read(&dest->inactconns);
                    outdest->persistconns = rte_atomic32_read(&dest->persistconns);

                    ret = dp_vs_stats_add(&outdest->stats, &dest->stats);
                    if (ret != EDPVS_OK)  {
                        msg_destroy(&msg);
                        rte_free(out);
                        return ret;
                    }
                    outdest += 1; 
                }

                list_for_each_entry(cur, &reply->mq, mq_node) {
                    slave_dest = (struct dp_vs_dest_detail*)(cur->data + sizeof(struct dp_vs_dest_front));
                    outdest = (struct dp_vs_dest_detail*)(*out + sizeof(outsvc));
                    for (i = 0; i < outsvc->num_dests; i++) {
                        outdest->max_conn += slave_dest->max_conn;
                        outdest->min_conn += slave_dest->min_conn;
                        outdest->actconns += slave_dest->actconns;
                        outdest->inactconns+= slave_dest->inactconns;
                        outdest->persistconns += slave_dest->persistconns;
                        dp_vs_stats_add(&outdest->stats, &slave_dest->stats);

                        outdest    += 1;
                        slave_dest += 1;
                    }
                }

                *outlen = size;
                msg_destroy(&msg);
                return EDPVS_OK;
            } else {
                *out = rte_zmalloc("get_dests", size, 0);
                if (!*out) {
                    msg_destroy(&msg);
                    return EDPVS_NOMEM;
                }

                list_for_each_entry(cur, &reply->mq, mq_node) {
                    front = (struct dp_vs_dest_front*)cur->data;
                    if (cid == front->cid) {
                        rte_memcpy(*out, cur->data, size);
                    }
                }
                *outlen = size;
                msg_destroy(&msg);
                return EDPVS_OK;
            }
            break;
        default:
            return EDPVS_NOTSUPP;
    }
    return EDPVS_INVAL;
}

static int adddest_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_dest_set(DPVSAGENT_VS_ADD_DESTS, msg->data, msg->len);
}

static int deldest_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_dest_set(DPVSAGENT_VS_DEL_DESTS, msg->data, msg->len);
}

static int dp_vs_dests_get_uc_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    int ret = EDPVS_INVAL;
    size_t size;
    struct dp_vs_dest_front *get, *output;
    struct dp_vs_service *svc;

    get = (struct dp_vs_dest_front*)msg->data;
    svc = dp_vs_service_lookup(get->af, get->proto, &get->addr, get->port, get->fwmark, NULL, &get->match, NULL, cid);
    if (!svc)
        return EDPVS_NOTEXIST;
    if (svc->num_dests != get->num_dests) {
        RTE_LOG(ERR, SERVICE, "%s: dests number not match in cid=%d.\n", __func__, cid);
        return EDPVS_INVAL;
    }

    size = sizeof(*get) + sizeof(struct dp_vs_dest_detail) * (svc->num_dests);
    output = msg_reply_alloc(size);
    if (output == NULL)
        return EDPVS_NOMEM;

    rte_memcpy(output, get, sizeof(*get));
    ret = dp_vs_dest_get_details(svc, output);

    if (ret != EDPVS_OK) {
        msg_reply_free(output);
        return ret;
    }

    msg->reply.len = size;
    msg->reply.data = (void *)output;
    return EDPVS_OK;
}

int dp_vs_dest_init(void)
{
    int err;
    struct dpvs_msg_type msg_type;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_ADD_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = adddest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_DEL_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = deldest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_GET_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dp_vs_dests_get_uc_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    return sockopt_register(&sockopts_dest);
}

int dp_vs_dest_term(void)
{
    return sockopt_unregister(&sockopts_dest);
}
