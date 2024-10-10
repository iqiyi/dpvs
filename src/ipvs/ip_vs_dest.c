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

enum {
    dest_notification_down = 1,
    dest_notification_up,
    dest_notification_close,
    dest_notification_open,
};

struct dest_notification {
    union inet_addr vaddr;
    union inet_addr daddr;
    uint16_t af;
    uint16_t svc_af;
    uint16_t proto;
    uint16_t vport;
    uint16_t dport;
    uint16_t weight;
    uint16_t notification;
};

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

    rte_atomic16_set(&dest->weight, udest->weight);
    if (udest->flags & DPVS_DEST_F_INHIBITED)
        dp_vs_dest_set_inhibited(dest);
    else
        dp_vs_dest_clear_inhibited(dest);
    conn_flags = udest->conn_flags | DPVS_CONN_F_INACTIVE;
    dest->fwdmode = udest->fwdmode;
    rte_atomic16_set(&dest->conn_flags, conn_flags);

    dp_vs_dest_set_avail(dest);

    if (udest->max_conn == 0 || udest->max_conn > dest->max_conn)
        dest->flags &= ~DPVS_DEST_F_OVERLOAD;
    if (rte_lcore_id() != g_master_lcore_id) {
        dest->max_conn = udest->max_conn / g_slave_lcore_num;
        dest->min_conn = udest->min_conn / g_slave_lcore_num;
    } else {
        /*
            Ensure that the sum of rs's max_conn in all lcores is equal to the configured max_conn,
            to prevent the operation of modifying rs from keepalived when reloading.
        */
        dest->max_conn = udest->max_conn % g_slave_lcore_num;
        dest->min_conn = udest->min_conn % g_slave_lcore_num;
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
    uint16_t dport;
    uint32_t old_weight;

    if (udest->min_conn > udest->max_conn) {
        RTE_LOG(DEBUG, SERVICE, "%s(): lower threshold is higher than upper threshold\n",
               __func__);
        return EDPVS_INVAL;
    }

    daddr = udest->addr;
    dport = udest->port;

    /*
     *  Lookup the destination list
     */
    dest = dp_vs_dest_lookup(udest->af, svc, &daddr, dport);

    if (dest == NULL) {
        RTE_LOG(DEBUG, SERVICE, "%s(): dest doesn't exist\n", __func__);
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

/* dp_vs_dest_edit_health only changes dest's weight and DPVS_DEST_F_INHIBITED flag */
int dp_vs_dest_edit_health(struct dp_vs_service *svc, struct dp_vs_dest_conf *udest)
{
    struct dp_vs_dest *dest;
    union inet_addr daddr;
    uint16_t dport;
    uint32_t old_weight;

    daddr = udest->addr;
    dport = udest->port;

    dest = dp_vs_dest_lookup(udest->af, svc, &daddr, dport);
    if (dest == NULL)
        return EDPVS_NOTEXIST;
    old_weight = rte_atomic16_read(&dest->weight);

    rte_atomic16_set(&dest->weight, udest->weight);
    if (udest->flags & DPVS_DEST_F_INHIBITED)
        dp_vs_dest_set_inhibited(dest);
    else
        dp_vs_dest_clear_inhibited(dest);

    svc->weight = svc->weight - old_weight + udest->weight;
    if (svc->weight < 0) {
        struct dp_vs_dest *tdest;
        svc->weight = 0;
        list_for_each_entry(tdest, &svc->dests, n_list)
            svc->weight += rte_atomic16_read(&tdest->weight);
        RTE_LOG(ERR, SERVICE, "%s(): vs weight < 0\n", __func__);
    }

    if (svc->scheduler->update_service)
        svc->scheduler->update_service(svc, dest, DPVS_SO_SET_EDITDEST);

    return EDPVS_OK;
}

void dp_vs_dest_put(struct dp_vs_dest *dest, bool timerlock)
{
    if (!dest)
        return;

    if (rte_atomic32_dec_and_test(&dest->refcnt)) {
        if (rte_lcore_id() == g_master_lcore_id) {
            if (timerlock)
                dpvs_timer_cancel(&dest->dfc.master.timer, true);
            else
                dpvs_timer_cancel_nolock(&dest->dfc.master.timer, true);
        }
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
    dp_vs_dest_put(dest, true);

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
        entry.fwdmode = dest->fwdmode;
        entry.flags = dest->flags;
        entry.conn_flags = rte_atomic16_read(&dest->conn_flags);
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

static int dest_msg_seq(void) {
    static uint32_t seq = 0;
    return seq++;
}

static void dest_inhibit_logging(const struct dp_vs_dest *dest, const char *msg)
{
    char str_vaddr[64], str_daddr[64];
    lcoreid_t cid = rte_lcore_id();

    if (cid == g_master_lcore_id) {
        RTE_LOG(INFO, SERVICE, "[cid %02d, %s, svc %s:%d, rs %s:%d, weight %d, inhibited %s,"
                " down_notice_recvd %d, inhibit_duration %ds, origin_weight %d] %s\n",
                cid,
                dest->proto == IPPROTO_TCP ? "tcp" : IPPROTO_UDP ? "udp" : "sctp",
                inet_ntop(dest->svc->af, &dest->svc->addr, str_vaddr, sizeof(str_vaddr)) ? str_vaddr : "::",
                ntohs(dest->svc->port),
                inet_ntop(dest->af, &dest->addr, str_daddr, sizeof(str_daddr)) ? str_daddr : "::",
                ntohs(dest->port),
                rte_atomic16_read(&dest->weight),
                dp_vs_dest_is_inhibited(dest) ? "yes" : "no",
                dest->dfc.master.down_notice_recvd,
                dest->dfc.master.inhibit_duration,
                dest->dfc.master.origin_weight,
                msg ?: ""
                );
    } else {
        RTE_LOG(DEBUG, SERVICE, "[cid %02d, %s, svc %s:%d, rs %s:%d, weight %d, inhibited %s, warm_up_count %d] %s\n",
                cid,
                dest->proto == IPPROTO_TCP ? "tcp" : IPPROTO_UDP ? "udp" : "sctp",
                inet_ntop(dest->svc->af, &dest->svc->addr, str_vaddr, sizeof(str_vaddr)) ? str_vaddr : "::",
                ntohs(dest->svc->port),
                inet_ntop(dest->af, &dest->addr, str_daddr, sizeof(str_daddr)) ? str_daddr : "::",
                ntohs(dest->port),
                rte_atomic16_read(&dest->weight),
                dp_vs_dest_is_inhibited(dest) ? "yes" : "no",
                dest->dfc.slave.warm_up_count,
                msg ?: ""
                );
    }
}

static inline void dest_notification_fill(const struct dp_vs_dest *dest, struct dest_notification *notice)
{
    notice->vaddr  = dest->svc->addr;
    notice->daddr  = dest->addr;
    notice->af     = dest->af;
    notice->svc_af = dest->svc->af;
    notice->proto  = dest->proto;
    notice->vport  = dest->svc->port;
    notice->dport  = dest->port;
    notice->weight = rte_atomic16_read(&dest->weight);
}

static struct dp_vs_dest *get_dest_from_notification(const struct dest_notification *notice)
{
    struct dp_vs_service *svc;

    svc = dp_vs_service_lookup(notice->svc_af, notice->proto, &notice->vaddr, notice->vport,
            0, NULL, NULL, rte_lcore_id());
    if (!svc)
        return NULL;
    return dp_vs_dest_lookup(notice->af, svc, &notice->daddr, notice->dport);
}

static int dest_down_wait_timeout(void *arg)
{
    struct dp_vs_dest *dest;

    dest = (struct dp_vs_dest *)arg;

    // This should never happen, just in case!
    dp_vs_dest_clear_inhibited(dest);
    if (dest->dfc.master.origin_weight > 0 && rte_atomic16_read(&dest->weight) == 0)
        rte_atomic16_set(&dest->weight, dest->dfc.master.origin_weight);
    dest->dfc.master.origin_weight = 0;

    dest->dfc.master.down_notice_recvd = 0;
    return EDPVS_OK;
}

static int dest_inhibit_timeout(void *arg)
{
    int err;
    struct dp_vs_dest *dest;
    struct dpvs_msg *msg;
    struct dest_notification *notice;

    dest = (struct dp_vs_dest *)arg;
    msg = msg_make(MSG_TYPE_DEST_CHECK_NOTIFY_SLAVES, dest_msg_seq(),
            DPVS_MSG_MULTICAST, rte_lcore_id(), sizeof(*notice), NULL);
    if (unlikely(msg == NULL))
        return EDPVS_NOMEM;
    notice = (struct dest_notification *)msg->data;
    dest_notification_fill(dest, notice);
    notice->weight = dest->dfc.master.origin_weight;
    notice->notification = dest_notification_open;
    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }
    msg_destroy(&msg);

    dest_inhibit_logging(dest, "notify slaves UP");
    dp_vs_dest_clear_inhibited(dest);
    rte_atomic16_set(&dest->weight, dest->dfc.master.origin_weight);
    dest->dfc.master.origin_weight = 0;
    dest->dfc.master.down_notice_recvd = 0;

    return EDPVS_OK;
}

static int msg_cb_notify_master(struct dpvs_msg *msg)
{
    int err;
    struct timeval delay;
    struct dp_vs_dest *dest;
    struct dest_notification *notice, *notice_sent;
    struct dest_check_configs *configs;
    struct dpvs_msg *msg_sent;
    bool has_up_notice;

    notice = (struct dest_notification *)msg->data;
    if (unlikely(notice->notification != dest_notification_down &&
                notice->notification != dest_notification_up)) {
        RTE_LOG(WARNING, SERVICE,"%s:invalid notification %d\n", __func__, notice->notification);
        return EDPVS_INVAL;
    }
    dest = get_dest_from_notification(notice);
    if (!dest)
        return EDPVS_NOTEXIST;
    configs = &dest->svc->check_conf;
    has_up_notice = !dest_check_down_only(configs);

    if (notice->notification == dest_notification_down) {
        if (dp_vs_dest_is_inhibited(dest) || rte_atomic16_read(&dest->weight) == 0) {
            return EDPVS_OK;
        }
        dest->dfc.master.down_notice_recvd++;

        // start down-wait-timer on the first DOWN notice
        if (dest->dfc.master.down_notice_recvd == 1 && configs->dest_down_notice_num > 1) {
            delay.tv_sec = configs->dest_down_wait - 1;
            delay.tv_usec = 500000;
            dpvs_time_rand_delay(&delay, 1000000);
            err = dpvs_timer_sched(&dest->dfc.master.timer, &delay, dest_down_wait_timeout, (void *)dest, true);
            if (err != EDPVS_OK) {
                // FIXME: reschedule time without changing dfc.master.down_notice_recvd
                dest->dfc.master.down_notice_recvd--;
                return err;
            }
            return EDPVS_OK;
        }
        if (dest->dfc.master.down_notice_recvd < configs->dest_down_notice_num)
            return EDPVS_OK;

        // send CLOSE notice to all slaves, remove the dest from service, start rs-inhibit-timer
        err = dpvs_timer_cancel(&dest->dfc.master.timer, true);
        if (unlikely(err != EDPVS_OK))
            return err;
        dp_vs_dest_set_inhibited(dest);
        if (dest->dfc.master.inhibit_duration > configs->dest_inhibit_max)
            dest->dfc.master.inhibit_duration = configs->dest_inhibit_max;
        if (dest->dfc.master.inhibit_duration < configs->dest_inhibit_min)
            dest->dfc.master.inhibit_duration = configs->dest_inhibit_min;
        if (has_up_notice) {
            delay.tv_sec = dest->dfc.master.inhibit_duration - 1;
            delay.tv_usec = 500000;
            dpvs_time_rand_delay(&delay, 1000000);
            err = dpvs_timer_sched(&dest->dfc.master.timer, &delay, dest_inhibit_timeout, (void *)dest, true);
            if (err != EDPVS_OK) {
                dp_vs_dest_clear_inhibited(dest);
                return err;
            }
        }
        msg_sent = msg_make(MSG_TYPE_DEST_CHECK_NOTIFY_SLAVES, dest_msg_seq(),
                DPVS_MSG_MULTICAST, rte_lcore_id(), sizeof(*notice), notice);
        if (unlikely(msg_sent == NULL)) {
            if (has_up_notice)
                dpvs_timer_cancel(&dest->dfc.master.timer, true);
            dp_vs_dest_clear_inhibited(dest);
            return EDPVS_NOMEM;
        }
        notice_sent = (struct dest_notification *)msg_sent->data;
        notice_sent->notification = dest_notification_close;
        err = multicast_msg_send(msg_sent, DPVS_MSG_F_ASYNC, NULL);
        if (unlikely(err != EDPVS_OK)) {
            if (has_up_notice)
                dpvs_timer_cancel(&dest->dfc.master.timer, true);
            dp_vs_dest_clear_inhibited(dest);
            msg_destroy(&msg_sent);
            return err;
        }
        msg_destroy(&msg_sent);

        dest_inhibit_logging(dest, "notify slaves DOWN");
        if (dest->dfc.master.inhibit_duration < DEST_INHIBIT_DURATION_MAX)
            dest->dfc.master.inhibit_duration <<= 1;
        dest->dfc.master.origin_weight = rte_atomic16_read(&dest->weight);
        rte_atomic16_clear(&dest->weight);
    } else { // dest_notification_up
        //assert(!dest_check_down_only(configs));
        dest->dfc.master.inhibit_duration >>= 1;
        if (dest->dfc.master.inhibit_duration < configs->dest_inhibit_min)
            dest->dfc.master.inhibit_duration = configs->dest_inhibit_min;
    }
    return EDPVS_OK;
}

static int msg_cb_notify_slaves(struct dpvs_msg *msg)
{
    struct dp_vs_dest *dest;
    struct dest_notification *notice;
    struct dest_check_configs *configs;

    notice = (struct dest_notification *)msg->data;
    if (unlikely(notice->notification != dest_notification_close &&
                notice->notification != dest_notification_open)) {
        RTE_LOG(WARNING, SERVICE,"%s:invalid notification %d\n", __func__, notice->notification);
        return EDPVS_INVAL;
    }
    dest = get_dest_from_notification(notice);
    if (!dest)
        return EDPVS_NOTEXIST;
    configs = &dest->svc->check_conf;

    if (notice->notification == dest_notification_close) {
        dest->dfc.slave.origin_weight = rte_atomic16_read(&dest->weight);
        rte_atomic16_clear(&dest->weight);
        dp_vs_dest_set_inhibited(dest);
    } else { // dest_notification_open
        //assert(!dest_check_down_only(configs));
        rte_atomic16_set(&dest->weight, dest->dfc.slave.origin_weight);
        dp_vs_dest_clear_inhibited(dest);
        dest->dfc.slave.warm_up_count = configs->dest_up_notice_num;
        dest->dfc.slave.origin_weight = 0;
    }
    return EDPVS_OK;
}

int dp_vs_dest_detected_alive(struct dp_vs_dest *dest)
{
    int err;
    struct dpvs_msg *msg;
    struct dest_notification *notice;

    if (!dest_check_passive(&dest->svc->check_conf))
        return EDPVS_DISABLED;

    if (likely(dest->dfc.slave.warm_up_count == 0))
        return EDPVS_OK;

    msg = msg_make(MSG_TYPE_DEST_CHECK_NOTIFY_MASTER, dest_msg_seq(),
            DPVS_MSG_UNICAST, rte_lcore_id(), sizeof(*notice), NULL);
    if (unlikely(msg == NULL))
        return EDPVS_NOMEM;
    notice = (struct dest_notification *)msg->data;
    dest_notification_fill(dest, notice);
    notice->notification = dest_notification_up;

    err = msg_send(msg, g_master_lcore_id, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }
    msg_destroy(&msg);

    dest_inhibit_logging(dest, "detect dest UP");
    dest->dfc.slave.warm_up_count--;
    return EDPVS_OK;
}

int dp_vs_dest_detected_dead(struct dp_vs_dest *dest)
{
    int err;
    struct dpvs_msg *msg;
    struct dest_notification *notice;

    if (!dest_check_passive(&dest->svc->check_conf))
        return EDPVS_DISABLED;

    if (dp_vs_dest_is_inhibited(dest) || rte_atomic16_read(&dest->weight) == 0)
        return EDPVS_OK;

    msg = msg_make(MSG_TYPE_DEST_CHECK_NOTIFY_MASTER, dest_msg_seq(),
            DPVS_MSG_UNICAST, rte_lcore_id(), sizeof(*notice), 0);
    if (unlikely(msg == NULL))
        return EDPVS_NOMEM;
    notice = (struct dest_notification *)msg->data;
    dest_notification_fill(dest, notice);
    notice->notification = dest_notification_down;

    err = msg_send(msg, g_master_lcore_id, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }
    msg_destroy(&msg);
    dest_inhibit_logging(dest, "detect dest DOWN");
    return EDPVS_OK;
}

#ifdef CONFIG_DPVS_AGENT
static int dp_vs_dest_get_details(const struct dp_vs_service *svc, 
                            struct dp_vs_dest_front *uptr)
{
    int ret = 0;
    int count = 0;
    struct dp_vs_dest *dest;
    struct dp_vs_dest_entry *detail;

    uptr->cid = rte_lcore_id();
    uptr->index = g_lcore_id2index[uptr->cid];
    uptr->num_dests = svc->num_dests;
    detail = (struct dp_vs_dest_entry*)((char*)uptr + sizeof(*uptr));

    list_for_each_entry(dest, &svc->dests, n_list){
        if(count >= svc->num_dests)
            break;
        memset(detail, 0, sizeof(*detail));
        detail->af   = dest->af;
        detail->addr = dest->addr;
        detail->port = dest->port;
        detail->fwdmode = dest->fwdmode;
        detail->flags = dest->flags;
        detail->conn_flags = rte_atomic16_read(&dest->conn_flags);
        detail->weight = rte_atomic16_read(&dest->weight);
        detail->max_conn = dest->max_conn;
        detail->min_conn = dest->min_conn;
        detail->actconns = rte_atomic32_read(&dest->actconns);
        detail->inactconns = rte_atomic32_read(&dest->inactconns);
        detail->persistconns = rte_atomic32_read(&dest->persistconns);
        ret = dp_vs_stats_add(&detail->stats, &dest->stats);
        if (unlikely(ret != EDPVS_OK))
            break;
        detail += 1;
        count++;
    }

    return ret;
}

static int dp_vs_dest_set(sockoptid_t opt, const void *user, size_t len)
{
    struct dp_vs_dest_front *insvc;
    struct dp_vs_dest_detail *details;
    struct dp_vs_dest_conf udest;
    struct dpvs_msg *msg;
    struct dp_vs_service *getsvc;
    int i, ret = EDPVS_INVAL;
    msgid_t msg_id = MSG_TYPE_IPVS_RANGE_START;
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
        switch (opt) {
            case DPVSAGENT_VS_ADD_DESTS:
                msg_id = MSG_TYPE_AGENT_ADD_DESTS;
                break;
            case DPVSAGENT_VS_DEL_DESTS:
                msg_id = MSG_TYPE_AGENT_DEL_DESTS;
                break;
            case DPVSAGENT_VS_EDIT_DESTS:
                msg_id = MSG_TYPE_AGENT_EDIT_DESTS;
                break;
            default:
                return EDPVS_NOTSUPP;
        }
        msg = msg_make(msg_id, dest_msg_seq(), DPVS_MSG_MULTICAST, cid, len, user);
        if (!msg)
            return EDPVS_NOMEM;

        ret = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
        if (ret != EDPVS_OK) {
            RTE_LOG(ERR, SERVICE, "[%s] fail to send multicast message\n", __func__);
        }
        msg_destroy(&msg);
    }

    getsvc = dp_vs_service_lookup(insvc->af, insvc->proto, &insvc->addr, insvc->port, insvc->fwmark, NULL, &insvc->match, cid);
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
            case DPVSAGENT_VS_EDIT_DESTS:
                ret = dp_vs_dest_edit_health(getsvc, &udest);
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

    *out = NULL;
    *outlen = 0;
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
                getsvc = dp_vs_service_lookup(insvc->af, insvc->proto, &insvc->addr, insvc->port, insvc->fwmark, NULL, &insvc->match, cid);
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

                rte_memcpy(*out, insvc, sizeof(*insvc));
                outsvc = (struct dp_vs_dest_front*)*out;
                outsvc->cid = rte_lcore_id();
                outsvc->index = g_lcore_id2index[outsvc->cid];
                outsvc->num_dests = getsvc->num_dests;
                outdest = (struct dp_vs_dest_detail*)(*out + sizeof(*outsvc));

                list_for_each_entry(dest, &getsvc->dests, n_list) {
                    outdest->af           = dest->af;
                    outdest->addr         = dest->addr;
                    outdest->port         = dest->port;
                    outdest->fwdmode      = dest->fwdmode;
                    outdest->flags        = dest->flags;
                    outdest->conn_flags   = rte_atomic16_read(&dest->conn_flags);
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
                    outdest = (struct dp_vs_dest_detail*)(*out + sizeof(*outsvc));
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
                        break;
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

static int editdest_msg_cb(struct dpvs_msg *msg)
{
    return dp_vs_dest_set(DPVSAGENT_VS_EDIT_DESTS, msg->data, msg->len);
}

static int dp_vs_dests_get_uc_cb(struct dpvs_msg *msg)
{
    lcoreid_t cid = rte_lcore_id();
    int ret = EDPVS_INVAL;
    size_t size;
    struct dp_vs_dest_front *get, *output;
    struct dp_vs_service *svc;

    get = (struct dp_vs_dest_front*)msg->data;
    svc = dp_vs_service_lookup(get->af, get->proto, &get->addr, get->port, get->fwmark, NULL, &get->match, cid);
    if (!svc)
        return EDPVS_NOTEXIST;

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

struct dpvs_sockopts sockopts_dest = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = DPVSAGENT_VS_ADD_DESTS,
    .set_opt_max    = DPVSAGENT_VS_DEL_DESTS,
    .set            = dp_vs_dest_set,
    .get_opt_min    = DPVSAGENT_VS_GET_DESTS,
    .get_opt_max    = DPVSAGENT_VS_GET_DESTS,
    .get            = dp_vs_dest_get,
};

#endif /* CONFIG_DPVS_AGENT */

static int dest_unregister_msg_cb(void)
{
	int err, rterr = EDPVS_OK;
    struct dpvs_msg_type msg_type;

    memset(&msg_type, 0, sizeof(msg_type));
    msg_type.type = MSG_TYPE_DEST_CHECK_NOTIFY_MASTER;
    msg_type.mode = DPVS_MSG_UNICAST;
    msg_type.prio = MSG_PRIO_NORM;
    msg_type.cid  = g_master_lcore_id;
    msg_type.unicast_msg_cb = msg_cb_notify_master;
    if ((err = msg_type_unregister(&msg_type)) != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to unregister MSG_TYPE_DEST_CHECK_NOTIFY_MASTER -- %s\n",
                __func__, dpvs_strerror(err));
    }

    memset(&msg_type, 0, sizeof(msg_type));
    msg_type.type = MSG_TYPE_DEST_CHECK_NOTIFY_SLAVES;
    msg_type.mode = DPVS_MSG_MULTICAST;
    msg_type.prio = MSG_PRIO_NORM;
    msg_type.unicast_msg_cb = msg_cb_notify_slaves;
    if ((err = msg_type_mc_unregister(&msg_type)) != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to unregister MSG_TYPE_DEST_CHECK_NOTIFY_SLAVES -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

#ifdef CONFIG_DPVS_AGENT
    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_ADD_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = adddest_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to unregister MSG_TYPE_AGENT_ADD_DESTS -- %s\n",
                __func__, dpvs_strerror(err));
        rterr = err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_DEL_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = deldest_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_AGENT_DEL_DESTS -- %s\n",
                 __func__, dpvs_strerror(err));
         if (rterr == EDPVS_OK)
             rterr = err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_EDIT_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = editdest_msg_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         if (rterr == EDPVS_OK)
             rterr = err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_GET_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dp_vs_dests_get_uc_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_AGENT_GET_DESTS -- %s\n",
                 __func__, dpvs_strerror(err));
         if (rterr == EDPVS_OK)
             rterr = err;
    }
#endif

    return rterr;
}

static int dest_register_msg_cb(void) {
    int err;
    struct dpvs_msg_type msg_type;

    memset(&msg_type, 0, sizeof(msg_type));
    msg_type.type = MSG_TYPE_DEST_CHECK_NOTIFY_MASTER;
    msg_type.mode = DPVS_MSG_UNICAST;
    msg_type.prio = MSG_PRIO_NORM;
    msg_type.cid  = g_master_lcore_id;
    msg_type.unicast_msg_cb = msg_cb_notify_master;
    if ((err = msg_type_register(&msg_type)) != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_DEST_CHECK_NOTIFY_MASTER -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    memset(&msg_type, 0, sizeof(msg_type));
    msg_type.type = MSG_TYPE_DEST_CHECK_NOTIFY_SLAVES;
    msg_type.mode = DPVS_MSG_MULTICAST;
    msg_type.prio = MSG_PRIO_NORM;
    msg_type.unicast_msg_cb = msg_cb_notify_slaves;
    if ((err = msg_type_mc_register(&msg_type)) != EDPVS_OK) {
        RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_DEST_CHECK_NOTIFY_SLAVES -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

#ifdef CONFIG_DPVS_AGENT
    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_ADD_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = adddest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_AGENT_ADD_DESTS -- %s\n",
                 __func__, dpvs_strerror(err));
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
         RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_AGENT_DEL_DESTS -- %s\n",
                 __func__, dpvs_strerror(err));
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_EDIT_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_NORM;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = editdest_msg_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register msg.\n", __func__);
         return err;
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type   = MSG_TYPE_AGENT_GET_DESTS;
    msg_type.mode   = DPVS_MSG_MULTICAST;
    msg_type.prio   = MSG_PRIO_LOW;
    msg_type.cid    = rte_lcore_id();
    msg_type.unicast_msg_cb = dp_vs_dests_get_uc_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
         RTE_LOG(ERR, SERVICE, "%s: fail to register MSG_TYPE_AGENT_GET_DESTS -- %s\n",
                 __func__, dpvs_strerror(err));
         return err;
    }

    if ((err = sockopt_register(&sockopts_dest)) != EDPVS_OK) {
        dest_unregister_msg_cb();
        return err;
    }
#endif /* CONFIG_DPVS_AGENT */
    return EDPVS_OK;
};

int dp_vs_dest_init(void)
{
    dest_register_msg_cb();
    return EDPVS_OK;
}

int dp_vs_dest_term(void)
{
    dest_unregister_msg_cb();
#ifdef CONFIG_DPVS_AGENT
    sockopt_unregister(&sockopts_dest);
#endif
    return EDPVS_OK;
}
