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
#include "ipvs/whtlst.h"
#include "conf/whtlst.h"

/**
 *  * per-lcore config for whtlst ip
 *   */


#define DPVS_WHTLST_TAB_BITS      16
#define DPVS_WHTLST_TAB_SIZE      (1 << DPVS_WHTLST_TAB_BITS)
#define DPVS_WHTLST_TAB_MASK      (DPVS_WHTLST_TAB_SIZE - 1)

#define this_whtlst_tab           (RTE_PER_LCORE(dp_vs_whtlst_tab))
#define this_num_whtlsts          (RTE_PER_LCORE(num_whtlsts))

static RTE_DEFINE_PER_LCORE(struct list_head *, dp_vs_whtlst_tab);
static RTE_DEFINE_PER_LCORE(rte_atomic32_t, num_whtlsts);

static uint32_t dp_vs_whtlst_rnd;

static inline uint32_t whtlst_hashkey(const uint8_t proto, const union inet_addr *vaddr, const uint16_t vport)
{
    /* jhash hurts performance, we do not use rte_jhash_2words here */
    return (((rte_be_to_cpu_16(proto) * 7
                + rte_be_to_cpu_32(vaddr->in.s_addr)) * 31
                + rte_be_to_cpu_16(vport)) * 15
                + dp_vs_whtlst_rnd) & DPVS_WHTLST_TAB_MASK;
}

struct whtlst_entry *dp_vs_whtlst_lookup(int af, uint8_t proto, const union inet_addr *vaddr,
                                         uint16_t vport, const union inet_addr *whtlst)
{
    unsigned hashkey;
    struct whtlst_entry *whtlst_node;

    hashkey = whtlst_hashkey(proto, vaddr, vport);
    list_for_each_entry(whtlst_node, &this_whtlst_tab[hashkey], list){
        if (whtlst_node->af == af && whtlst_node->proto == proto &&
            whtlst_node->vport == vport &&
			inet_addr_equal(af, &whtlst_node->vaddr, vaddr) &&
			inet_addr_equal(af, &whtlst_node->whtlst, whtlst))
            return whtlst_node;
    }
    return NULL;
}

bool dp_vs_whtlst_allow(int af, uint8_t proto, const union inet_addr *vaddr,
                        uint16_t vport, const union inet_addr *whtlst)
{
    unsigned hashkey;
    struct whtlst_entry *whtlst_node;

    hashkey = whtlst_hashkey(proto, vaddr, vport);

    if (&this_whtlst_tab[hashkey] == NULL || list_empty(&this_whtlst_tab[hashkey])) {
        return true;
    }
    list_for_each_entry(whtlst_node, &this_whtlst_tab[hashkey], list){
        if (whtlst_node->af == af && whtlst_node->proto == proto &&
            whtlst_node->vport == vport &&
			inet_addr_equal(af, &whtlst_node->vaddr, vaddr) &&
			inet_addr_equal(af, &whtlst_node->whtlst, whtlst))
            return true;
    }

    return false;
}

static int dp_vs_whtlst_add_lcore(int af, uint8_t proto, const union inet_addr *vaddr,
                                  uint16_t vport, const union inet_addr *whtlst)
{
    unsigned hashkey;
    struct whtlst_entry *new, *whtlst_node;
    whtlst_node = dp_vs_whtlst_lookup(af, proto, vaddr, vport, whtlst);
    if (whtlst_node) {
        return EDPVS_EXIST;
    }

    hashkey = whtlst_hashkey(proto, vaddr, vport);

    new = rte_zmalloc("new_whtlst_entry", sizeof(struct whtlst_entry), 0);
    if (unlikely(new == NULL))
        return EDPVS_NOMEM;

    new->af     = af;
    new->vport   = vport;
    new->proto  = proto;
    memcpy(&new->vaddr, vaddr, sizeof(union inet_addr));
    memcpy(&new->whtlst, whtlst, sizeof(union inet_addr));
    list_add(&new->list, &this_whtlst_tab[hashkey]);
    rte_atomic32_inc(&this_num_whtlsts);

    return EDPVS_OK;
}

static int dp_vs_whtlst_del_lcore(int af, uint8_t proto, const union inet_addr *vaddr,
                                  uint16_t vport, const union inet_addr *whtlst)
{
    struct whtlst_entry *whtlst_node;

    whtlst_node = dp_vs_whtlst_lookup(af, proto, vaddr, vport, whtlst);
    if (whtlst_node != NULL) {
        list_del(&whtlst_node->list);
        rte_free(whtlst_node);
        rte_atomic32_dec(&this_num_whtlsts);
        return EDPVS_OK;
    }
    return EDPVS_NOTEXIST;
}

static uint32_t whtlst_msg_seq(void)
{
    static uint32_t counter = 0;
	return counter++;
}

static int dp_vs_whtlst_add(int af, uint8_t proto, const union inet_addr *vaddr,
                            uint16_t vport, const union inet_addr *whtlst)
{
    lcoreid_t cid = rte_lcore_id();
    int err;
    struct dpvs_msg *msg;
    struct dp_vs_whtlst_conf cf;

    if (cid != rte_get_main_lcore()) {
        RTE_LOG(INFO, SERVICE, "[%s] must set from master lcore\n", __func__);
        return EDPVS_NOTSUPP;
    }

    memset(&cf, 0, sizeof(struct dp_vs_whtlst_conf));
    memcpy(&(cf.vaddr), vaddr, sizeof(union inet_addr));
    memcpy(&(cf.whtlst), whtlst, sizeof(union inet_addr));
    cf.af    = af;
    cf.vport = vport;
    cf.proto = proto;

    /*set whtlst ip on master lcore*/
    err = dp_vs_whtlst_add_lcore(af, proto, vaddr, vport, whtlst);
    if (err && err != EDPVS_EXIST) {
        RTE_LOG(ERR, SERVICE, "[%s] fail to set whtlst ip\n", __func__);
        return err;
    }

    /*set whtlst ip on all slave lcores*/
    msg = msg_make(MSG_TYPE_WHTLST_ADD, whtlst_msg_seq(), DPVS_MSG_MULTICAST,
                   cid, sizeof(struct dp_vs_whtlst_conf), &cf);
    if (!msg)
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

static int dp_vs_whtlst_del(int af, uint8_t proto, const union inet_addr *vaddr,
                            uint16_t vport, const union inet_addr *whtlst)
{
    lcoreid_t cid = rte_lcore_id();
    int err;
    struct dpvs_msg *msg;
    struct dp_vs_whtlst_conf cf;

    if (cid != rte_get_main_lcore()) {
        RTE_LOG(INFO, SERVICE, "[%s] must set from master lcore\n", __func__);
        return EDPVS_NOTSUPP;
    }

    memset(&cf, 0, sizeof(struct dp_vs_whtlst_conf));
    memcpy(&(cf.vaddr), vaddr, sizeof(union inet_addr));
    memcpy(&(cf.whtlst), whtlst, sizeof(union inet_addr));
    cf.af    = af;
    cf.vport = vport;
    cf.proto = proto;

    /*del whtlst ip on master lcores*/
    err = dp_vs_whtlst_del_lcore(af, proto, vaddr, vport, whtlst);
    if (err) {
        return err;
    }

    /*del whtlst ip on all slave lcores*/
    msg = msg_make(MSG_TYPE_WHTLST_DEL, 0, DPVS_MSG_MULTICAST,
                   cid, sizeof(struct dp_vs_whtlst_conf), &cf);
    if (!msg)
        return EDPVS_NOMEM;
    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        RTE_LOG(INFO, SERVICE, "[%s] fail to send multicast message\n", __func__);
        return err;
    }
    msg_destroy(&msg);

    return EDPVS_OK;
}

void  dp_vs_whtlst_flush(struct dp_vs_service *svc)
{
    struct whtlst_entry *entry, *next;
    int hash;

    for (hash = 0; hash < DPVS_WHTLST_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_whtlst_tab[hash], list) {
            if (entry->af == svc->af
                && entry->vport == svc->port
                && entry->proto == svc->proto
                && inet_addr_equal(svc->af, &entry->vaddr, &svc->addr))
                dp_vs_whtlst_del(svc->af, entry->proto, &entry->vaddr,
                                 entry->vport, &entry->whtlst);
        }
    }
    return;
}

static void dp_vs_whtlst_flush_all(void)
{
    struct whtlst_entry *entry, *next;
    int hash;

    for (hash = 0; hash < DPVS_WHTLST_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_whtlst_tab[hash], list) {
            dp_vs_whtlst_del(entry->af, entry->proto, &entry->vaddr,
                             entry->vport, &entry->whtlst);
        }
    }
    return;
}

/*
 * for control plane
 */
static int whtlst_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct dp_vs_whtlst_conf *whtlst_conf = conf;
    int err;

    if (!conf && size < sizeof(*whtlst_conf))
        return EDPVS_INVAL;

    switch (opt) {
    case SOCKOPT_SET_WHTLST_ADD:
        err = dp_vs_whtlst_add(whtlst_conf->af,
						       whtlst_conf->proto, &whtlst_conf->vaddr,
                               whtlst_conf->vport, &whtlst_conf->whtlst);
        break;
    case SOCKOPT_SET_WHTLST_DEL:
        err = dp_vs_whtlst_del(whtlst_conf->af,
						       whtlst_conf->proto, &whtlst_conf->vaddr,
                               whtlst_conf->vport, &whtlst_conf->whtlst);
        break;
    default:
        err = EDPVS_NOTSUPP;
        break;
    }

    return err;
}

static void whtlst_fill_conf(struct dp_vs_whtlst_conf *cf,
                            const struct whtlst_entry *entry)
{
    memset(cf, 0 ,sizeof(*cf));
    cf->af = entry->af;
    cf->vaddr = entry->vaddr;
    cf->whtlst = entry->whtlst;
    cf->proto = entry->proto;
    cf->vport = entry->vport;
}

static int whtlst_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    struct dp_vs_whtlst_conf_array *array;
    struct whtlst_entry *entry;
    size_t naddr, hash;
    int off = 0;

    naddr = rte_atomic32_read(&this_num_whtlsts);
    *outsize = sizeof(struct dp_vs_whtlst_conf_array) +
               naddr * sizeof(struct dp_vs_whtlst_conf);
    *out = rte_calloc(NULL, 1, *outsize, 0);
    if (!(*out))
        return EDPVS_NOMEM;
    array = *out;
    array->naddr = naddr;

    for (hash = 0; hash < DPVS_WHTLST_TAB_SIZE; hash++) {
        list_for_each_entry(entry, &this_whtlst_tab[hash], list) {
            if (off >= naddr)
                break;
            whtlst_fill_conf(&array->whtlsts[off++], entry);
        }
    }

    return EDPVS_OK;
}


static int whtlst_msg_process(bool add, struct dpvs_msg *msg)
{
    struct dp_vs_whtlst_conf *cf;
    int err;
    assert(msg);

    if (msg->len != sizeof(struct dp_vs_whtlst_conf)) {
        RTE_LOG(ERR, SERVICE, "%s: bad message.\n", __func__);
        return EDPVS_INVAL;
    }

    cf = (struct dp_vs_whtlst_conf *)msg->data;
    if (add) {
        err = dp_vs_whtlst_add_lcore(cf->af, cf->proto, &cf->vaddr, cf->vport, &cf->whtlst);
		if (err && err != EDPVS_EXIST) {
		    RTE_LOG(ERR, SERVICE, "%s: fail to add whtlst: %s.\n", __func__, dpvs_strerror(err));
		}
	}
    else {
        err = dp_vs_whtlst_del_lcore(cf->af, cf->proto, &cf->vaddr, cf->vport, &cf->whtlst);
	}

    return err;
}

inline static int whtlst_add_msg_cb(struct dpvs_msg *msg)
{
    return whtlst_msg_process(true, msg);
}

inline static int whtlst_del_msg_cb(struct dpvs_msg *msg)
{
    return whtlst_msg_process(false, msg);
}

static struct dpvs_sockopts whtlst_sockopts = {
    .version            = SOCKOPT_VERSION,
    .set_opt_min        = SOCKOPT_SET_WHTLST_ADD,
    .set_opt_max        = SOCKOPT_SET_WHTLST_FLUSH,
    .set                = whtlst_sockopt_set,
    .get_opt_min        = SOCKOPT_GET_WHTLST_GETALL,
    .get_opt_max        = SOCKOPT_GET_WHTLST_GETALL,
    .get                = whtlst_sockopt_get,
};

static int whtlst_lcore_init(void *args)
{
    int i;
    if (!rte_lcore_is_enabled(rte_lcore_id()))
        return EDPVS_DISABLED;
    this_whtlst_tab = rte_malloc(NULL,
                        sizeof(struct list_head) * DPVS_WHTLST_TAB_SIZE,
                        RTE_CACHE_LINE_SIZE);
    if (!this_whtlst_tab)
        return EDPVS_NOMEM;

    for (i = 0; i < DPVS_WHTLST_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_whtlst_tab[i]);

    return EDPVS_OK;
}

static int whtlst_lcore_term(void *args)
{
    if (!rte_lcore_is_enabled(rte_lcore_id()))
       return EDPVS_DISABLED;

    dp_vs_whtlst_flush_all();

    if (this_whtlst_tab) {
       rte_free(this_whtlst_tab);
       this_whtlst_tab = NULL;
    }
    return EDPVS_OK;
}

static int whtlst_unregister_msg_cb(void)
{
    struct dpvs_msg_type msg_type;
	int err;

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_WHTLST_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = whtlst_add_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to unregister msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_WHTLST_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = whtlst_del_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to unregister msg.\n", __func__);
        return err;
    }
	return EDPVS_OK;
}

int dp_vs_whtlst_init(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    rte_atomic32_set(&this_num_whtlsts, 0);

    rte_eal_mp_remote_launch(whtlst_lcore_init, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, SERVICE, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
            return err;
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_WHTLST_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = whtlst_add_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_WHTLST_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = whtlst_del_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
        return err;
    }

    if ((err = sockopt_register(&whtlst_sockopts)) != EDPVS_OK) {
		whtlst_unregister_msg_cb();
        return err;
	}
    dp_vs_whtlst_rnd = (uint32_t)random();

    return EDPVS_OK;
}

int dp_vs_whtlst_term(void)
{
    int err;
    lcoreid_t cid;

    if ((err = whtlst_unregister_msg_cb()) != EDPVS_OK)
		return err;

    if ((err = sockopt_unregister(&whtlst_sockopts)) != EDPVS_OK)
        return err;

    rte_eal_mp_remote_launch(whtlst_lcore_term, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, SERVICE, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}
