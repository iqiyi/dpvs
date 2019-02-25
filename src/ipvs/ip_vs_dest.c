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
 * locks
 */

static rte_rwlock_t __dp_vs_rs_lock;


/*
 * hash table for rs
 */
#define DP_VS_RTAB_BITS 4
#define DP_VS_RTAB_SIZE (1 << DP_VS_RTAB_BITS)
#define DP_VS_RTAB_MASK (DP_VS_RTAB_SIZE - 1)

static struct list_head dp_vs_rtable[DP_VS_RTAB_SIZE];

/*
 * Trash for destinations
 */

struct list_head dp_vs_dest_trash = LIST_HEAD_INIT(dp_vs_dest_trash);

static inline unsigned dp_vs_rs_hashkey(int af,
                    const union inet_addr *addr,
                    uint32_t port)
{
    register unsigned porth = ntohs(port);
    uint32_t addr_fold;

    addr_fold = inet_addr_fold(af, addr);

    if (!addr_fold) {
        RTE_LOG(DEBUG, SERVICE, "%s: IP proto not support.\n", __func__);
        return 0;
    }

    return (ntohl(addr_fold) ^ (porth >> DP_VS_RTAB_BITS) ^ porth)
        & DP_VS_RTAB_MASK;
}

static int dp_vs_rs_hash(struct dp_vs_dest *dest)
{
    unsigned hash;
    if (!list_empty(&dest->d_list)){
        return EDPVS_EXIST;
    }
    hash = dp_vs_rs_hashkey(dest->af, &dest->addr, dest->port);
    list_add(&dest->d_list, &dp_vs_rtable[hash]);
    return EDPVS_OK;
}

static int dp_vs_rs_unhash(struct dp_vs_dest *dest)
{
    if(!list_empty(&dest->d_list)){
        list_del(&dest->d_list);
        INIT_LIST_HEAD(&dest->d_list);
    }
    return EDPVS_OK;
}


struct dp_vs_dest *dp_vs_lookup_dest(int af,
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

/*
 *  Lookup dest by {svc,addr,port} in the destination trash.
 *  The destination trash is used to hold the destinations that are removed
 *  from the service table but are still referenced by some conn entries.
 *  The reason to add the destination trash is when the dest is temporary
 *  down (either by administrator or by monitor program), the dest can be
 *  picked back from the trash, the remaining connections to the dest can
 *  continue, and the counting information of the dest is also useful for
 *  scheduling.
 */
struct dp_vs_dest *dp_vs_trash_get_dest(struct dp_vs_service *svc,
                                        const union inet_addr *daddr,
                                        uint16_t dport)
{
    struct dp_vs_dest *dest, *nxt;

    list_for_each_entry_safe(dest, nxt, &dp_vs_dest_trash, n_list) {
        RTE_LOG(DEBUG, SERVICE, "%s: Destination still in trash.\n", __func__);
        if (dest->af == svc->af &&
            inet_addr_equal(svc->af, &dest->addr, daddr) &&
            dest->port == dport &&
            dest->vfwmark == svc->fwmark &&
            dest->proto == svc->proto &&
            (svc->fwmark ||
             (inet_addr_equal(svc->af, &dest->vaddr, &svc->addr) &&
              dest->vport == svc->port))) {
             /*since svc may be edit, variables should be coverd*/
             dest->conn_timeout = svc->conn_timeout;
             dest->limit_proportion = svc->limit_proportion;
             return dest;
            }
        if (rte_atomic32_read(&dest->refcnt) == 1) {
            RTE_LOG(DEBUG, SERVICE, "%s: Removing destination from trash.\n", __func__);
            list_del(&dest->n_list);
            //dp_vs_dst_reset(dest);//to be finished
            __dp_vs_unbind_svc(dest);

            dp_vs_del_stats(dest->stats);
            rte_free(dest);
        }
    }
    return NULL;
}

void dp_vs_trash_cleanup(void)
{
    struct dp_vs_dest *dest, *nxt;

    list_for_each_entry_safe(dest, nxt, &dp_vs_dest_trash, n_list) {
        list_del(&dest->n_list);
        //dp_vs_dst_reset(dest);
        __dp_vs_unbind_svc(dest);

        dp_vs_del_stats(dest->stats);
        rte_free(dest);
    }
}

static void __dp_vs_update_dest(struct dp_vs_service *svc,
                                struct dp_vs_dest *dest,
                                struct dp_vs_dest_conf *udest)
{
    int conn_flags;

    rte_atomic16_set(&dest->weight, udest->weight);
    conn_flags = udest->conn_flags | DPVS_CONN_F_INACTIVE;

    rte_rwlock_write_lock(&__dp_vs_rs_lock);
    dp_vs_rs_hash(dest);
    rte_rwlock_write_unlock(&__dp_vs_rs_lock);
    rte_atomic16_set(&dest->conn_flags, conn_flags);

    /* bind the service */
    if (!dest->svc) {
        __dp_vs_bind_svc(dest, svc);
    } else {
        if (dest->svc != svc) {
            __dp_vs_unbind_svc(dest);

            dp_svc_stats_clear(dest->stats);

            __dp_vs_bind_svc(dest, svc);
        }
    }

    dest->flags |= DPVS_DEST_F_AVAILABLE;

    if (udest->max_conn == 0 || udest->max_conn > dest->max_conn)
        dest->flags &= ~DPVS_DEST_F_OVERLOAD;
    dest->max_conn = udest->max_conn;
    dest->min_conn = udest->min_conn;
}


int dp_vs_new_dest(struct dp_vs_service *svc,
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
    rte_atomic32_set(&dest->refcnt, 0);

    INIT_LIST_HEAD(&dest->d_list);

    if (dp_vs_new_stats(&(dest->stats)) != EDPVS_OK) {
        rte_free(dest);
        return EDPVS_NOMEM;
    }

    __dp_vs_update_dest(svc, dest, udest);

    *dest_p = dest;
    return EDPVS_OK;
}

int
dp_vs_add_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
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
    dest = dp_vs_lookup_dest(udest->af, svc, &daddr, dport);

    if (dest != NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s: dest already exists.\n", __func__);
        return EDPVS_EXIST;
    }

    /*
     * Check if the dest already exists in the trash and
     * is from the same service
     */
    dest = dp_vs_trash_get_dest(svc, &daddr, dport);

    if (dest != NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s: get dest from trash.\n", __func__);

        __dp_vs_update_dest(svc, dest, udest);

        /*
         * Get the destination from the trash
         */
        list_del(&dest->n_list);
        /* Reset the statistic value */
        dp_svc_stats_clear(dest->stats);

        rte_rwlock_write_lock(&__dp_vs_svc_lock);

        /*
         * Wait until all other svc users go away.
         */
        DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

        list_add(&dest->n_list, &svc->dests);
        svc->weight += udest->weight;
        svc->num_dests++;

        /* call the update_service function of its scheduler */
        if (svc->scheduler->update_service)
            svc->scheduler->update_service(svc, dest, DPVS_SO_SET_ADDDEST);

        rte_rwlock_write_unlock(&__dp_vs_svc_lock);
        return EDPVS_OK;
    }

    /*
     * Allocate and initialize the dest structure
     */
    ret = dp_vs_new_dest(svc, udest, &dest);
    if (ret) {
        return ret;
    }

    /*
     * Add the dest entry into the list
     */
    rte_atomic32_inc(&dest->refcnt);

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /*
     * Wait until all other svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    list_add(&dest->n_list, &svc->dests);
    svc->weight += udest->weight;
    svc->num_dests++;

    /* call the update_service function of its scheduler */
    if (svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_ADDDEST);

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    return EDPVS_OK;
}

int
dp_vs_edit_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
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
    dest = dp_vs_lookup_dest(udest->af, svc, &daddr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE,"%s(): dest doesn't exist\n", __func__);
        return EDPVS_NOTEXIST;
    }

    /* Save old weight */
    old_weight = rte_atomic16_read(&dest->weight);

    __dp_vs_update_dest(svc, dest, udest);

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /* Wait until all other svc users go away */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

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

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    return EDPVS_OK;
}

/*
 *  Delete a destination (must be already unlinked from the service)
 */
void __dp_vs_del_dest(struct dp_vs_dest *dest)
{
    /*
     *  Remove it from the d-linked list with the real services.
     */
    rte_rwlock_write_lock(&__dp_vs_rs_lock);
    dp_vs_rs_unhash(dest);
    rte_rwlock_write_unlock(&__dp_vs_rs_lock);

    /*
     *  Decrease the refcnt of the dest, and free the dest
     *  if nobody refers to it (refcnt=0). Otherwise, throw
     *  the destination into the trash.
     */
    if (rte_atomic32_dec_and_test(&dest->refcnt)) {
     //   dp_vs_dst_reset(dest);
        /* simply decrease svc->refcnt here, let the caller check
           and release the service if nobody refers to it.
           Only user context can release destination and service,
           and only one user context can update virtual service at a
           time, so the operation here is OK */
        rte_atomic32_dec(&dest->svc->refcnt);
        dest->svc = NULL;
        dp_vs_del_stats(dest->stats);
        rte_free(dest);
    } else {
        RTE_LOG(DEBUG, SERVICE,"%s moving dest into trash\n", __func__);
        list_add(&dest->n_list, &dp_vs_dest_trash);
        rte_atomic32_inc(&dest->refcnt);
    }
}

/*
 *  Unlink a destination from the given service
 */
void __dp_vs_unlink_dest(struct dp_vs_service *svc,
                struct dp_vs_dest *dest, int svcupd)
{
    dest->flags &= ~DPVS_DEST_F_AVAILABLE;

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
dp_vs_del_dest(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    uint16_t dport = udest->port;

    dest = dp_vs_lookup_dest(udest->af, svc, &udest->addr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE,"%s(): destination not found!\n", __func__);
        return EDPVS_NOTEXIST;
    }

    rte_rwlock_write_lock(&__dp_vs_svc_lock);

    /*
     *      Wait until all other svc users go away.
     */
    DPVS_WAIT_WHILE(rte_atomic32_read(&svc->usecnt) > 1);

    /*
     *      Unlink dest from the service
     */
    __dp_vs_unlink_dest(svc, dest, 1);

    rte_rwlock_write_unlock(&__dp_vs_svc_lock);

    /*
     *      Delete the destination
     */
    __dp_vs_del_dest(dest);

    return EDPVS_OK;
}

int dp_vs_get_dest_entries(const struct dp_vs_service *svc,
                           const struct dp_vs_get_dests *get,
                           struct dp_vs_get_dests *uptr)
{
    int ret = 0;
    int count = 0;
    struct dp_vs_dest *dest;
    struct dp_vs_dest_entry entry;

    list_for_each_entry(dest, &svc->dests, n_list){
        if(count >= get->num_dests)
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
        ret = dp_vs_copy_stats(&(entry.stats), dest->stats);
        if (ret != EDPVS_OK)
            break;

        memcpy(&uptr->entrytable[count], &entry, sizeof(entry));
        count++;
    }

    return ret;
}

int dp_vs_dest_init(void)
{
    int idx;
    for (idx = 0; idx < DP_VS_RTAB_SIZE; idx++) {
        INIT_LIST_HEAD(&dp_vs_rtable[idx]);
    }
    rte_rwlock_init(&__dp_vs_rs_lock);
    return EDPVS_OK;
}

int dp_vs_dest_term(void)
{
    dp_vs_trash_cleanup();
    return EDPVS_OK;
}
