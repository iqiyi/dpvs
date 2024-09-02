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


#define DPVS_BLKLST_TAB_BITS    16
#define DPVS_BLKLST_TAB_SIZE    (1 << DPVS_BLKLST_TAB_BITS)
#define DPVS_BLKLST_TAB_MASK    (DPVS_BLKLST_TAB_SIZE - 1)
#define this_blklst_tab         (RTE_PER_LCORE(dp_vs_blklst_tab))
#define this_num_blklsts        (RTE_PER_LCORE(num_blklsts))

#define DPVS_BLKLST_IPSET_TAB_BITS      8
#define DPVS_BLKLST_IPSET_TAB_SIZE      (1 << DPVS_BLKLST_IPSET_TAB_BITS)
#define DPVS_BLKLST_IPSET_TAB_MASK      (DPVS_BLKLST_IPSET_TAB_SIZE - 1)
#define this_blklst_ipset_tab           (RTE_PER_LCORE(dp_vs_blklst_ipset_tab))
#define this_num_blklsts_ipset          (RTE_PER_LCORE(num_blklsts_ipset))

static RTE_DEFINE_PER_LCORE(struct list_head *, dp_vs_blklst_tab);
static RTE_DEFINE_PER_LCORE(uint32_t, num_blklsts);

static RTE_DEFINE_PER_LCORE(struct list_head *, dp_vs_blklst_ipset_tab);
static RTE_DEFINE_PER_LCORE(uint32_t, num_blklsts_ipset);

static uint32_t dp_vs_blklst_rnd;

static inline void blklst_fill_conf(const struct blklst_entry *entry,
        struct dp_vs_blklst_conf *conf)
{
    memset(conf, 0, sizeof(*conf));
    conf->vaddr = entry->vaddr;
    conf->vport = entry->vport;
    conf->proto = entry->proto;
    conf->af    = entry->af;
    conf->subject = entry->subject;
    if (entry->set)
        strncpy(conf->ipset, entry->set->name, sizeof(conf->ipset) - 1);
}

static inline uint32_t blklst_hashkey(const union inet_addr *vaddr,
        uint16_t vport, const union inet_addr *subject, bool ipset)
{
    /* jhash hurts performance, we do not use rte_jhash_2words here */
    if (ipset)
        return ((((vaddr->in.s_addr * 31) ^ vport) * 131)
                ^ dp_vs_blklst_rnd) & DPVS_BLKLST_IPSET_TAB_MASK;

    return ((((vaddr->in.s_addr * 31) ^ subject->in.s_addr) * 131)
            ^ (vport ^ dp_vs_blklst_rnd)) & DPVS_BLKLST_TAB_MASK;
}

static inline struct blklst_entry *dp_vs_blklst_ip_lookup(
        int af, uint8_t proto, const union inet_addr *vaddr,
        uint16_t vport, const union inet_addr *subject)
{
    unsigned hashkey;
    struct blklst_entry *entry;

    hashkey = blklst_hashkey(vaddr, vport, subject, false);
    list_for_each_entry(entry, &this_blklst_tab[hashkey], list) {
        if (entry->af == af && entry->proto == proto &&
            entry->vport == vport &&
            inet_addr_equal(af, &entry->vaddr, vaddr) &&
            inet_addr_equal(af, &entry->subject, subject))
            return entry;
    }

    return NULL;
}

static inline struct blklst_entry *dp_vs_blklst_ipset_lookup(
        int af, uint8_t proto, const union inet_addr *vaddr,
        uint16_t vport, const char *ipset)
{
    unsigned hashkey;
    struct blklst_entry *entry;

    hashkey = blklst_hashkey(vaddr, vport, NULL, true);
    list_for_each_entry(entry, &this_blklst_ipset_tab[hashkey], list) {
        if (entry->af == af && entry->proto == proto && entry->vport == vport &&
                inet_addr_equal(af, &entry->vaddr, vaddr) &&
                !strncmp(entry->set->name, ipset, sizeof(entry->set->name)))
            return entry;
    }

    return NULL;
}

static bool dp_vs_blklst_ip_match_set(int af, uint8_t proto,
        const union inet_addr *vaddr, uint16_t vport,
        struct rte_mbuf *mbuf)
{
    bool res = false;
    unsigned hashkey;
    struct blklst_entry *entry;

    hashkey = blklst_hashkey(vaddr, vport, NULL, true);
    list_for_each_entry(entry, &this_blklst_ipset_tab[hashkey], list) {
        if (entry->af == af && entry->proto == proto &&
                entry->vport == vport &&
                inet_addr_equal(af, &entry->vaddr, vaddr)) {
            rte_pktmbuf_prepend(mbuf, mbuf->l2_len);
            res = elem_in_set(entry->set, mbuf, entry->dst_match);
            rte_pktmbuf_adj(mbuf, mbuf->l2_len);
            if (res)
                break;
        }
    }
    return res;
}

static struct blklst_entry *dp_vs_blklst_lookup(const struct dp_vs_blklst_conf *conf)
{
    struct blklst_entry *entry;

    entry = dp_vs_blklst_ip_lookup(conf->af, conf->proto, &conf->vaddr, conf->vport,
            &conf->subject);
    if (entry)
        return entry;

    return dp_vs_blklst_ipset_lookup(conf->af, conf->proto, &conf->vaddr, conf->vport,
            conf->ipset);
}

bool dp_vs_blklst_filtered(int af, uint8_t proto, const union inet_addr *vaddr,
        uint16_t vport, const union inet_addr *subject, struct rte_mbuf *mbuf)
{
    if (dp_vs_blklst_ip_lookup(af, proto, vaddr, vport, subject))
        return true;

    return dp_vs_blklst_ip_match_set(af, proto, vaddr, vport, mbuf);
}

static int dp_vs_blklst_add_lcore(const struct dp_vs_blklst_conf *conf)
{
    unsigned hashkey;
    struct blklst_entry *new;
    bool is_ipset = conf->ipset[0] != '\0';

    if (dp_vs_blklst_lookup(conf))
        return EDPVS_EXIST;

    hashkey = blklst_hashkey(&conf->vaddr, conf->vport, &conf->subject, is_ipset);

    new = rte_zmalloc("new_blklst_entry", sizeof(struct blklst_entry), 0);
    if (unlikely(new == NULL))
        return EDPVS_NOMEM;

    new->vaddr = conf->vaddr;
    new->vport = conf->vport;
    new->proto = conf->proto;
    new->af    = conf->af;

    if (is_ipset) {
        new->set = ipset_get(conf->ipset);
        if (!new->set) {
            RTE_LOG(ERR, SERVICE, "[%2d] %s: ipset %s not found\n",
                    rte_lcore_id(), __func__, conf->ipset);
            rte_free(new);
            return EDPVS_INVAL;
        }
        // Notes: Reassess it when new ipset types added!
        if (!strcmp(new->set->type->name, "hash:ip,port,net") ||
                    !strcmp(new->set->type->name, "hash:ip,port,ip") ||
                    !strcmp(new->set->type->name, "hash:net,port,net"))
            new->dst_match = true;
        else
            new->dst_match = false;
        list_add(&new->list, &this_blklst_ipset_tab[hashkey]);
        ++this_num_blklsts_ipset;
    } else {
        new->subject = conf->subject;
        list_add(&new->list, &this_blklst_tab[hashkey]);
        ++this_num_blklsts;
    }

    return EDPVS_OK;
}

static int dp_vs_blklst_del_lcore(const struct dp_vs_blklst_conf *conf)
{
    struct blklst_entry *entry;

    entry = dp_vs_blklst_lookup(conf);
    if (!entry)
        return EDPVS_NOTEXIST;

    if (entry->set) {   /* ipset entry */
        list_del(&entry->list);
        ipset_put(entry->set);
        --this_num_blklsts_ipset;
    } else {            /* ip entry */
        list_del(&entry->list);
        --this_num_blklsts;
    }

    rte_free(entry);
    return EDPVS_OK;
}

static uint32_t blklst_msg_seq(void)
{
    static uint32_t counter = 0;
    return counter++;
}

static int dp_vs_blklst_add(const struct dp_vs_blklst_conf *conf)
{
    lcoreid_t cid = rte_lcore_id();
    int err;
    struct dpvs_msg *msg;

    if (cid != rte_get_main_lcore()) {
        RTE_LOG(INFO, SERVICE, "%s must set from master lcore\n", __func__);
        return EDPVS_NOTSUPP;
    }

    /* master lcore */
    err = dp_vs_blklst_add_lcore(conf);
    if (err && err != EDPVS_EXIST) {
        RTE_LOG(ERR, SERVICE, "%s: fail to add blklst entry -- %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    /* slave lcores */
    msg = msg_make(MSG_TYPE_BLKLST_ADD, blklst_msg_seq(), DPVS_MSG_MULTICAST,
                   cid, sizeof(struct dp_vs_blklst_conf), conf);
    if (unlikely(!msg))
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

static int dp_vs_blklst_del(const struct dp_vs_blklst_conf *conf)
{
    lcoreid_t cid = rte_lcore_id();
    int err;
    struct dpvs_msg *msg;

    if (cid != rte_get_main_lcore()) {
        RTE_LOG(INFO, SERVICE, "%s must set from master lcore\n", __func__);
        return EDPVS_NOTSUPP;
    }

    /* master lcore */
    err = dp_vs_blklst_del_lcore(conf);
    if (err) {
        RTE_LOG(ERR, SERVICE, "%s: fail to del blklst entry -- %s\n", __func__, dpvs_strerror(err));
        return err;
    }

    /* slave lcores */
    msg = msg_make(MSG_TYPE_BLKLST_DEL, blklst_msg_seq(), DPVS_MSG_MULTICAST,
                   cid, sizeof(struct dp_vs_blklst_conf), conf);
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
    struct dp_vs_blklst_conf conf;

    for (hash = 0; hash < DPVS_BLKLST_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_blklst_tab[hash], list) {
            if (entry->af == svc->af
                    && entry->vport == svc->port
                    && entry->proto == svc->proto
                    && inet_addr_equal(svc->af, &entry->vaddr, &svc->addr)) {
                blklst_fill_conf(entry, &conf);
                dp_vs_blklst_del(&conf);
            }
        }
    }

    for (hash = 0; hash < DPVS_BLKLST_IPSET_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_blklst_ipset_tab[hash], list) {
            if (entry->af == svc->af
                    && entry->vport == svc->port
                    && entry->proto == svc->proto
                    && inet_addr_equal(svc->af, &entry->vaddr, &svc->addr)) {
                blklst_fill_conf(entry, &conf);
                dp_vs_blklst_del(&conf);
            }
        }
    }
}

static void dp_vs_blklst_flush_all(void)
{
    int hash;
    struct blklst_entry *entry, *next;
    struct dp_vs_blklst_conf conf;

    for (hash = 0; hash < DPVS_BLKLST_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_blklst_tab[hash], list) {
            blklst_fill_conf(entry, &conf);
            dp_vs_blklst_del(&conf);
        }
    }

    for (hash = 0; hash < DPVS_BLKLST_IPSET_TAB_SIZE; hash++) {
        list_for_each_entry_safe(entry, next, &this_blklst_ipset_tab[hash], list) {
            blklst_fill_conf(entry, &conf);
            dp_vs_blklst_del(&conf);
        }
    }
}

/*
 * for control plane
 */
static int blklst_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    if (!conf && size < sizeof(struct dp_vs_blklst_conf))
        return EDPVS_INVAL;

    switch (opt) {
        case SOCKOPT_SET_BLKLST_ADD:
            return dp_vs_blklst_add(conf);
        case SOCKOPT_SET_BLKLST_DEL:
            return dp_vs_blklst_del(conf);
        default:
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int blklst_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    struct dp_vs_blklst_conf_array *array;
    struct blklst_entry *entry;
    size_t naddr, hash;
    int off = 0;

    naddr = this_num_blklsts + this_num_blklsts_ipset;
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
            blklst_fill_conf(entry, &array->blklsts[off++]);
        }
    }

    for (hash = 0; hash < DPVS_BLKLST_IPSET_TAB_SIZE; hash++) {
        list_for_each_entry(entry, &this_blklst_ipset_tab[hash], list) {
            if (off >= naddr)
                break;
            blklst_fill_conf(entry, &array->blklsts[off++]);
        }
    }

    return EDPVS_OK;
}

static int blklst_msg_process(bool add, struct dpvs_msg *msg)
{
    struct dp_vs_blklst_conf *conf;
    int err;
    assert(msg);

    if (msg->len != sizeof(struct dp_vs_blklst_conf)){
        RTE_LOG(ERR, SERVICE, "%s: bad message\n", __func__);
        return EDPVS_INVAL;
    }

    conf = (struct dp_vs_blklst_conf *)msg->data;
    if (add) {
        err = dp_vs_blklst_add_lcore(conf);
	    if (err && err != EDPVS_EXIST)
		    RTE_LOG(ERR, SERVICE, "%s: fail to add blklst: %s\n", __func__, dpvs_strerror(err));
	} else {
        err = dp_vs_blklst_del_lcore(conf);
        if (err && err != EDPVS_NOTEXIST)
            RTE_LOG(ERR, SERVICE, "%s: fail to del blklst: %s\n", __func__, dpvs_strerror(err));
	}

    return err;
}

static inline int blklst_add_msg_cb(struct dpvs_msg *msg)
{
    return blklst_msg_process(true, msg);
}

static inline int blklst_del_msg_cb(struct dpvs_msg *msg)
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
    lcoreid_t cid = rte_lcore_id();

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    this_num_blklsts = 0;
    this_num_blklsts_ipset = 0;

    this_blklst_tab = rte_malloc(NULL,
            sizeof(struct list_head) * DPVS_BLKLST_TAB_SIZE,
            RTE_CACHE_LINE_SIZE);
    if (!this_blklst_tab)
        return EDPVS_NOMEM;
    for (i = 0; i < DPVS_BLKLST_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_blklst_tab[i]);

    this_blklst_ipset_tab = rte_malloc(NULL, sizeof(struct list_head) *
            DPVS_BLKLST_IPSET_TAB_SIZE, RTE_CACHE_LINE_SIZE);
    if (!this_blklst_ipset_tab) {
        rte_free(this_blklst_tab);
        return EDPVS_NOMEM;
    }
    for (i = 0; i < DPVS_BLKLST_IPSET_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_blklst_ipset_tab[i]);

    return EDPVS_OK;
}

static int blklst_lcore_term(void *args)
{
    lcoreid_t cid = rte_lcore_id();

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    if (!rte_lcore_is_enabled(cid))
       return EDPVS_DISABLED;

    dp_vs_blklst_flush_all();

    if (this_blklst_tab) {
       rte_free(this_blklst_tab);
       this_blklst_tab = NULL;
    }

    if (this_blklst_ipset_tab) {
        rte_free(this_blklst_ipset_tab);
        this_blklst_ipset_tab = NULL;
    }

    return EDPVS_OK;
}

int dp_vs_blklst_init(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    rte_eal_mp_remote_launch(blklst_lcore_init, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, SERVICE, "[%02d] %s: blklst init failed -- %s\n",
                    cid, __func__, dpvs_strerror(err));
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
        RTE_LOG(ERR, SERVICE, "%s: register BLKLST_ADD msg failed -- %s\n",
                __func__, dpvs_strerror(err));
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
        RTE_LOG(ERR, SERVICE, "%s: register BLKLST_DEL msg failed -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    if ((err = sockopt_register(&blklst_sockopts)) != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: register sockopts failed -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    dp_vs_blklst_rnd = (uint32_t)random();

    return EDPVS_OK;
}

int dp_vs_blklst_term(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    if ((err = sockopt_unregister(&blklst_sockopts)) != EDPVS_OK) {
        RTE_LOG(WARNING, SERVICE, "%s: unregister sockopts failed -- %s\n",
                __func__, dpvs_strerror(err));
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_BLKLST_DEL;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = blklst_del_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: unregister BLKLST_DEL msg failed -- %s\n",
                __func__, dpvs_strerror(err));
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_BLKLST_ADD;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = blklst_add_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: unregister BLKLST_ADD msg failed -- %s\n",
                __func__, dpvs_strerror(err));
    }

    rte_eal_mp_remote_launch(blklst_lcore_term, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, SERVICE, "[%02d] %s: blklst termination failed -- %s\n",
                    cid, __func__, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}
