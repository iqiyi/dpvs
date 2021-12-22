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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
#include "dpdk.h"
#include "list.h"
#include "conf/common.h"
#include "netif.h"
#include "inet.h"
#include "ctrl.h"
#include "ipvs/ipvs.h"
#include "ipvs/service.h"
#include "ipvs/blklst.h"
#include "conf/blklst.h"

/**
 *  * per-lcore config for blklst ip
 *   */


#define DPVS_BLKLST_TAB_BITS      16
#define DPVS_BLKLST_TAB_SIZE      (1 << DPVS_BLKLST_TAB_BITS)
#define DPVS_BLKLST_TAB_MASK      (DPVS_BLKLST_TAB_SIZE - 1)

#define this_blklst_tab           (RTE_PER_LCORE(dp_vs_blklst_tab))
#define this_num_blklsts         (RTE_PER_LCORE(num_blklsts))

static RTE_DEFINE_PER_LCORE(struct list_head *, dp_vs_blklst_tab);
static RTE_DEFINE_PER_LCORE(rte_atomic32_t, num_blklsts);

static uint32_t dp_vs_blklst_rnd;

static inline uint32_t blklst_hashkey(const union inet_addr *vaddr,
                                     const union inet_addr *blklst)
{
    /* jhash hurts performance, we do not use rte_jhash_2words here */
    return ((rte_be_to_cpu_32(vaddr->in.s_addr) * 31
                + rte_be_to_cpu_32(blklst->in.s_addr)) * 31
                + dp_vs_blklst_rnd) & DPVS_BLKLST_TAB_MASK;
}

struct blklst_entry *dp_vs_blklst_lookup(int af, uint8_t proto, const union inet_addr *vaddr,
                                         uint16_t vport, const union inet_addr *blklst)
{
    unsigned hashkey;
    struct blklst_entry *blklst_node;

    hashkey = blklst_hashkey(vaddr, blklst);
    list_for_each_entry(blklst_node, &this_blklst_tab[hashkey], list) {
        if (blklst_node->af == af && blklst_node->proto == proto &&
            blklst_node->vport == vport &&
            inet_addr_equal(af, &blklst_node->vaddr, vaddr) &&
            inet_addr_equal(af, &blklst_node->blklst, blklst))
            return blklst_node;
    }
    return NULL;
}

static int dp_vs_blklst_add_lcore(int af, uint8_t proto, const union inet_addr *vaddr,
                                  uint16_t vport, const union inet_addr *blklst)
{
    unsigned hashkey;
    struct blklst_entry *new, *blklst_node;

    blklst_node = dp_vs_blklst_lookup(af, proto, vaddr, vport, blklst);
    if (blklst_node) {
        return EDPVS_EXIST;
    }

    hashkey = blklst_hashkey(vaddr, blklst);

    new = rte_zmalloc("new_blklst_entry", sizeof(struct blklst_entry), 0);
    if (unlikely(new == NULL))
        return EDPVS_NOMEM;

    new->af    = af;
    new->proto = proto;
    new->vport = vport;
    memcpy(&new->vaddr, vaddr, sizeof(union inet_addr));
    memcpy(&new->blklst, blklst, sizeof(union inet_addr));
    list_add(&new->list, &this_blklst_tab[hashkey]);
    rte_atomic32_inc(&this_num_blklsts);

    return EDPVS_OK;
}

static int dp_vs_blklst_del_lcore(int af, uint8_t proto, const union inet_addr *vaddr,
                                  uint16_t vport, const union inet_addr *blklst)
{
    struct blklst_entry *blklst_node;

    blklst_node = dp_vs_blklst_lookup(af, proto, vaddr, vport, blklst);
    if (blklst_node != NULL) {
        list_del(&blklst_node->list);
        rte_free(blklst_node);
        rte_atomic32_dec(&this_num_blklsts);
        return EDPVS_OK;
    }

    return EDPVS_NOTEXIST;
}

static uint32_t blklst_msg_seq(void)
{
    static uint32_t counter = 0;
    return counter++;
}

static int dp_vs_blklst_add(int af, uint8_t proto, const union inet_addr *vaddr,
                            uint16_t vport, const union inet_addr *blklst)
{
    lcoreid_t cid = rte_lcore_id();
    int err;
    struct dpvs_msg *msg;
    struct dp_vs_blklst_conf cf;

    if (cid != rte_get_main_lcore()) {
        RTE_LOG(INFO, SERVICE, "%s must set from master lcore\n", __func__);
        return EDPVS_NOTSUPP;
    }

    memset(&cf, 0, sizeof(struct dp_vs_blklst_conf));
    memcpy(&(cf.vaddr), vaddr,sizeof(union inet_addr));
    memcpy(&(cf.blklst), blklst, sizeof(union inet_addr));
    cf.af    = af;
    cf.vport = vport;
    cf.proto = proto;

    /*set blklst ip on master lcore*/
    err = dp_vs_blklst_add_lcore(af, proto, vaddr, vport, blklst);
    if (err && err != EDPVS_EXIST) {
        RTE_LOG(ERR, SERVICE, "[%s] fail to set blklst ip -- %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    /*set blklst ip on all slave lcores*/
    msg = msg_make(MSG_TYPE_BLKLST_ADD, blklst_msg_seq(), DPVS_MSG_MULTICAST,
                   cid, sizeof(struct dp_vs_blklst_conf), &cf);
    if (unlikely(!msg))
        return EDPVS_NOMEM;
    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        RTE_LOG(INFO, SERVICE, "[%s] fail to send multicast message\n", __func__);
        return err;
    }
    msg_destroy(&msg);

    return EDPVS_OK;
}

static int dp_vs_blklst_del(int af, uint8_t proto, const union inet_addr *vaddr,
                            uint16_t vport, const union inet_addr *blklst)
{
    lcoreid_t cid = rte_lcore_id();
    int err;
    struct dpvs_msg *msg;
    struct dp_vs_blklst_conf cf;

    if (cid != rte_get_main_lcore()) {
        RTE_LOG(INFO, SERVICE, "%s must set from master lcore\n", __func__);
        return EDPVS_NOTSUPP;
    }

    memset(&cf, 0, sizeof(struct dp_vs_blklst_conf));
    memcpy(&(cf.vaddr), vaddr,sizeof(union inet_addr));
    memcpy(&(cf.blklst), blklst, sizeof(union inet_addr));
    cf.af    = af;
    cf.vport = vport;
    cf.proto = proto;

    /*del blklst ip on master lcores*/
    err = dp_vs_blklst_del_lcore(af, proto, vaddr, vport, blklst);
    if (err) {
        return err;
    }

    /*del blklst ip on all slave lcores*/
    msg = msg_make(MSG_TYPE_BLKLST_DEL, blklst_msg_seq(), DPVS_MSG_MULTICAST,
                   cid, sizeof(struct dp_vs_blklst_conf), &cf);
    if (!msg)
        return EDPVS_NOMEM;
    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        RTE_LOG(INFO, SERVICE, "%s: fail to send multicast message\n", __func__);
        return err;
    }
    msg_destroy(&msg);

    return EDPVS_OK;
}

void dp_vs_blklst_flush(struct dp_vs_service *svc)
{
    int hash;
    struct blklst_entry *entry, *next;

    for (hash = 0; hash < DPVS_BLKLST_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_blklst_tab[hash], list) {
            if (entry->af == svc->af
                && entry->vport == svc->port
                && entry->proto == svc->proto
                && inet_addr_equal(svc->af, &entry->vaddr, &svc->addr))
                dp_vs_blklst_del(svc->af, entry->proto, &entry->vaddr,
                                 entry->vport, &entry->blklst);
        }
    }
    return;
}

static void dp_vs_blklst_flush_all(void)
{
    struct blklst_entry *entry, *next;
    int hash;

    for (hash = 0; hash < DPVS_BLKLST_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_blklst_tab[hash], list) {
            dp_vs_blklst_del(entry->af, entry->proto, &entry->vaddr,
                             entry->vport, &entry->blklst);
        }
    }
    return;
}

/*
 * for control plane
 */
static int blklst_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct dp_vs_blklst_conf *blklst_conf = conf;
    int err;

    if (!conf && size < sizeof(*blklst_conf))
        return EDPVS_INVAL;

    switch (opt) {
    case SOCKOPT_SET_BLKLST_ADD:
        err = dp_vs_blklst_add(blklst_conf->af,
                               blklst_conf->proto, &blklst_conf->vaddr,
                               blklst_conf->vport, &blklst_conf->blklst);
        break;
    case SOCKOPT_SET_BLKLST_DEL:
        err = dp_vs_blklst_del(blklst_conf->af,
                               blklst_conf->proto, &blklst_conf->vaddr,
                               blklst_conf->vport, &blklst_conf->blklst);
        break;
    default:
        err = EDPVS_NOTSUPP;
        break;
    }

    return err;
}

static void blklst_fill_conf(struct dp_vs_blklst_conf *cf,
                            const struct blklst_entry *entry)
{
    memset(cf, 0 ,sizeof(*cf));
    cf->af = entry->af;
    cf->vaddr = entry->vaddr;
    cf->blklst = entry->blklst;
    cf->proto = entry->proto;
    cf->vport = entry->vport;
}

static int blklst_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    struct dp_vs_blklst_conf_array *array;
    struct blklst_entry *entry;
    size_t naddr, hash;
    int off = 0;

    naddr = rte_atomic32_read(&this_num_blklsts);
    *outsize = sizeof(struct dp_vs_blklst_conf_array) +
               naddr * sizeof(struct dp_vs_blklst_conf);
    *out = rte_calloc(NULL, 1, *outsize, 0);
    if (!(*out))
        return EDPVS_NOMEM;
    array = *out;
    array->naddr = naddr;

    for (hash = 0; hash < DPVS_BLKLST_TAB_SIZE; hash++) {
        list_for_each_entry(entry, &this_blklst_tab[hash], list) {
            if (off >= naddr)
                break;
            blklst_fill_conf(&array->blklsts[off++], entry);
        }
    }

    return EDPVS_OK;
}


static int blklst_msg_process(bool add, struct dpvs_msg *msg)
{
    struct dp_vs_blklst_conf *cf;
    int err;
    assert(msg);

    if (msg->len != sizeof(struct dp_vs_blklst_conf)){
        RTE_LOG(ERR, SERVICE, "%s: bad message.\n", __func__);
        return EDPVS_INVAL;
    }

    cf = (struct dp_vs_blklst_conf *)msg->data;
    if (add) {
        err = dp_vs_blklst_add_lcore(cf->af, cf->proto, &cf->vaddr, cf->vport, &cf->blklst);
	    if (err && err != EDPVS_EXIST) {
		    RTE_LOG(ERR, SERVICE, "%s: fail to add blklst: %s.\n", __func__, dpvs_strerror(err));
		}
	}
    else {
        err = dp_vs_blklst_del_lcore(cf->af, cf->proto, &cf->vaddr, cf->vport, &cf->blklst);
	}

    return err;
}

inline static int blklst_add_msg_cb(struct dpvs_msg *msg)
{
    return blklst_msg_process(true, msg);
}

inline static int blklst_del_msg_cb(struct dpvs_msg *msg)
{
    return blklst_msg_process(false, msg);
}

static struct dpvs_sockopts blklst_sockopts = {
    .version            = SOCKOPT_VERSION,
    .set_opt_min        = SOCKOPT_SET_BLKLST_ADD,
    .set_opt_max        = SOCKOPT_SET_BLKLST_FLUSH,
    .set                = blklst_sockopt_set,
    .get_opt_min        = SOCKOPT_GET_BLKLST_GETALL,
    .get_opt_max        = SOCKOPT_GET_BLKLST_GETALL,
    .get                = blklst_sockopt_get,
};

static int blklst_lcore_init(void *args)
{
    int i;
    if (!rte_lcore_is_enabled(rte_lcore_id()))
    return EDPVS_DISABLED;
    this_blklst_tab = rte_malloc(NULL,
                        sizeof(struct list_head) * DPVS_BLKLST_TAB_SIZE,
                        RTE_CACHE_LINE_SIZE);
    if (!this_blklst_tab)
        return EDPVS_NOMEM;

    for (i = 0; i < DPVS_BLKLST_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_blklst_tab[i]);

    return EDPVS_OK;
}

static int blklst_lcore_term(void *args)
{
    if (!rte_lcore_is_enabled(rte_lcore_id()))
       return EDPVS_DISABLED;

    dp_vs_blklst_flush_all();

    if (this_blklst_tab) {
       rte_free(this_blklst_tab);
       this_blklst_tab = NULL;
    }
    return EDPVS_OK;
}

int dp_vs_blklst_init(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    rte_atomic32_set(&this_num_blklsts, 0);

    rte_eal_mp_remote_launch(blklst_lcore_init, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, SERVICE, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
            return err;
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_BLKLST_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = blklst_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_BLKLST_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = blklst_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    if ((err = sockopt_register(&blklst_sockopts)) != EDPVS_OK)
        return err;
    dp_vs_blklst_rnd = (uint32_t)random();

    return EDPVS_OK;
}

int dp_vs_blklst_term(void)
{
    int err;
    lcoreid_t cid;

    if ((err = sockopt_unregister(&blklst_sockopts)) != EDPVS_OK)
        return err;

    rte_eal_mp_remote_launch(blklst_lcore_term, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, SERVICE, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}
