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

int dp_vs_dest_init(void)
{
    return EDPVS_OK;
}

int dp_vs_dest_term(void)
{
    return EDPVS_OK;
}
