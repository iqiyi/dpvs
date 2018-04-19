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
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <assert.h>
#include "ctrl.h"
#include "netif.h"
#include "parser/parser.h"

/////////////////////////////////// lcore  msg ///////////////////////////////////////////

#define MSG_MAX_LCORE_SUPPORTED 64

uint64_t slave_lcore_mask;     /* bit-wise enabled lcores */
uint8_t slave_lcore_nb;        /* slave lcore number */
lcoreid_t master_lcore;        /* master lcore id */

struct netif_lcore_loop_job ctrl_lcore_job;

#define MSG_TIMEOUT_US 2000
static int msg_timeout = MSG_TIMEOUT_US;

#define DPVS_MSG_BITS 8
#define DPVS_MSG_LEN (1 << DPVS_MSG_BITS)
#define DPVS_MSG_MASK (DPVS_MSG_LEN - 1)

#define DPVS_MSG_RING_SIZE_DEF 4096
#define DPVS_MSG_RING_SIZE_MIN 256
#define DPVS_MSG_RING_SIZE_MAX 524288

static uint32_t msg_ring_size = DPVS_MSG_RING_SIZE_DEF;

/* maximum msg to send at a time */
#define DPVS_MULTICAST_LIST_LEN_DEF  256
#define DPVS_MSG_MC_QLEN_MIN 16
#define DPVS_MSG_MC_QLEN_MAX 32768
static uint32_t msg_mc_qlen = DPVS_MULTICAST_LIST_LEN_DEF;

/* per-lcore msg-type array */
typedef struct list_head msg_type_array_t[DPVS_MSG_LEN];
typedef rte_rwlock_t msg_type_lock_t[DPVS_MSG_LEN];

msg_type_array_t mt_array[DPVS_MAX_LCORE];
msg_type_lock_t mt_lock[DPVS_MAX_LCORE];

/* multicast_queue list (Master lcore only) */
struct multicast_wait_list {
    int32_t free_cnt;
    struct list_head list;
};
struct multicast_wait_list mc_wait_list;
rte_rwlock_t mc_wait_lock;

/* per-lcore msg queue */
struct rte_ring *msg_ring[DPVS_MAX_LCORE];

static inline int mt_hashkey(msgid_t type)
{
    return type & DPVS_MSG_MASK;
}

static struct dpvs_msg_type* msg_type_get(msgid_t type, /*DPVS_MSG_MODE mode, */lcoreid_t cid)
{
    int hashkey = mt_hashkey(type);
    struct dpvs_msg_type *mt;

    if (unlikely(cid >= DPVS_MAX_LCORE))
        return NULL;

    rte_rwlock_read_lock(&mt_lock[cid][hashkey]);
    list_for_each_entry(mt, &mt_array[cid][hashkey], list) {
        if (type == mt->type /*&& mode == mt->mode*/) {
            rte_atomic32_inc(&mt->refcnt);
            rte_rwlock_read_unlock(&mt_lock[cid][hashkey]);
            return mt;
        }
    }

    rte_rwlock_read_unlock(&mt_lock[cid][hashkey]);
    return NULL;
}

static inline void msg_type_put(struct dpvs_msg_type *mt)
{
    if (unlikely(NULL == mt))
        return;
    rte_atomic32_dec(&mt->refcnt);
}

/* only be called on Master, thus no lock needed */
static inline struct dpvs_multicast_queue* mc_queue_get(msgid_t type, uint32_t seq)
{
    assert(rte_lcore_id() == master_lcore);

    struct dpvs_multicast_queue *mcq;
    list_for_each_entry(mcq, &mc_wait_list.list, list)
        if (mcq->type == type && mcq->seq == seq) {
            return mcq;
        }
    return NULL;
}

int msg_type_register(const struct dpvs_msg_type *msg_type)
{
    int hashkey;
    struct dpvs_msg_type *mt;

    if (unlikely(NULL == msg_type  || msg_type->cid >= DPVS_MAX_LCORE)) {
        RTE_LOG(WARNING, MSGMGR, "%s: invalid args !\n", __func__);
        return EDPVS_INVAL;
    }

    hashkey = mt_hashkey(msg_type->type);
    mt = msg_type_get(msg_type->type, /*msg_type->mode, */msg_type->cid);
    if (NULL != mt) {
        RTE_LOG(WARNING, MSGMGR, "%s: msg type %d mode %s already registered\n",
                __func__, mt->type, mt->mode == DPVS_MSG_UNICAST ? "UNICAST" : "MULTICAST");
        msg_type_put(mt);
        rte_exit(EXIT_FAILURE, "inter-lcore msg type %d already exist!\n", mt->type);
        return EDPVS_EXIST;
    }

    mt = rte_zmalloc("msg_type", sizeof(struct dpvs_msg_type), RTE_CACHE_LINE_SIZE);
    if (unlikely(NULL == mt)) {
        RTE_LOG(ERR, MSGMGR, "%s: no memory !\n", __func__);
        return EDPVS_NOMEM;
    }

    memcpy(mt, msg_type, sizeof(struct dpvs_msg_type));
    rte_atomic32_set(&mt->refcnt, 0);
    rte_rwlock_write_lock(&mt_lock[msg_type->cid][hashkey]);
    list_add_tail(&mt->list, &mt_array[msg_type->cid][hashkey]);
    rte_rwlock_write_unlock(&mt_lock[msg_type->cid][hashkey]);

    return EDPVS_OK;
}

int msg_type_unregister(const struct dpvs_msg_type *msg_type)
{
    int hashkey;
    struct dpvs_msg_type *mt;

    if (unlikely(NULL == msg_type) || msg_type->cid >= DPVS_MAX_LCORE) {
        RTE_LOG(WARNING, MSGMGR, "%s: invalid args !\n", __func__);
        return EDPVS_INVAL;
    }

    hashkey = mt_hashkey(msg_type->type);
    mt = msg_type_get(msg_type->type, /*msg_type->mode, */msg_type->cid);
    if (NULL == mt) {
        RTE_LOG(WARNING, MSGMGR, "%s: msg type %d mode %s not yet registered\n",
                __func__, msg_type->type, msg_type->mode == DPVS_MSG_UNICAST ? "UNINCAST" : "MULTICAST");
        return EDPVS_NOTEXIST;
    }

    rte_rwlock_write_lock(&mt_lock[msg_type->cid][hashkey]);
    list_del_init(&mt->list);
    rte_rwlock_write_unlock(&mt_lock[msg_type->cid][hashkey]);

    msg_type_put(mt);
    DPVS_WAIT_WHILE(rte_atomic32_read(&mt->refcnt) > 0);
    rte_free(mt);

    return EDPVS_OK;
}

inline static int default_mc_msg_cb(__rte_unused struct dpvs_multicast_queue *mcq)
{
    return EDPVS_OK;
}

int msg_type_mc_register(const struct dpvs_msg_type *msg_type)
{
    lcoreid_t cid;
    struct dpvs_msg_type mt;
    int ret = EDPVS_OK;

    if (unlikely(NULL == msg_type))
        return EDPVS_INVAL;

    memset(&mt, 0, sizeof(mt));
    mt.type = msg_type->type;
    mt.mode = DPVS_MSG_MULTICAST;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (cid == master_lcore) {
            mt.cid = cid;
            mt.unicast_msg_cb = NULL;
            if (msg_type->multicast_msg_cb)
                mt.multicast_msg_cb = msg_type->multicast_msg_cb;
            else /* if no multicast callback given, then a default one is used, which do nothing now */
                mt.multicast_msg_cb = default_mc_msg_cb;
        } else if (slave_lcore_mask & (1L << cid)) {
            mt.cid = cid;
            mt.unicast_msg_cb = msg_type->unicast_msg_cb;
            mt.multicast_msg_cb = NULL;
        } else
            continue;

        ret = msg_type_register(&mt);
        if (unlikely(ret < 0)) {
            RTE_LOG(ERR, MSGMGR, "%s: fail to register multicast msg on lcore %d\n",
                    __func__, cid);
            return ret;
        }
    }

    return EDPVS_OK;
}

int msg_type_mc_unregister(const struct dpvs_msg_type *msg_type)
{
    lcoreid_t cid;
    struct dpvs_msg_type mt;
    int ret = EDPVS_OK;

    if (unlikely(NULL == msg_type))
        return EDPVS_INVAL;

    memset(&mt, 0, sizeof(mt));
    mt.type = msg_type->type;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (cid == master_lcore) {
            mt.cid = cid;
            mt.mode = DPVS_MSG_MULTICAST;
            mt.unicast_msg_cb = NULL;
            mt.multicast_msg_cb = msg_type->multicast_msg_cb;
        } else if (slave_lcore_mask & (1L << cid)) {
            mt.cid = cid;
            mt.mode = DPVS_MSG_UNICAST;
            mt.unicast_msg_cb = msg_type->unicast_msg_cb;
            mt.multicast_msg_cb = NULL;
        } else
            continue;

        ret = msg_type_unregister(&mt);
        if (unlikely(ret < 0)) {
            RTE_LOG(ERR, MSGMGR, "%s: fail to unregister mulitcast msg on lcore %d\n",
                    __func__, cid);
            return ret;
        }
    }

    return EDPVS_OK;
}

struct dpvs_msg* msg_make(msgid_t type, uint32_t seq,
        DPVS_MSG_MODE mode,
        lcoreid_t cid,
        uint32_t len, const void *data)
{
    struct dpvs_msg *msg;
    uint32_t flags;

    msg  = rte_zmalloc("msg", sizeof(struct dpvs_msg) + len, RTE_CACHE_LINE_SIZE);
    if (unlikely(NULL == msg))
        return NULL;

    rte_spinlock_init(&msg->lock);

    flags = get_msg_flags(msg);
    if (flags)
        RTE_LOG(WARNING, MSGMGR, "dirty msg flags: %d\n", flags);

    msg->type = type;
    msg->seq = seq;
    msg->mode = mode;
    msg->cid = cid;
    msg->len = len;
    if (len)
        memcpy(msg->data, data, len);
    assert(0 == flags);

    rte_atomic16_init(&msg->refcnt);
    rte_atomic16_inc(&msg->refcnt);

    return msg;
}

int msg_destroy(struct dpvs_msg **pmsg)
{
    struct dpvs_msg *msg;

    if (unlikely(!pmsg || !(*pmsg)))
        return EDPVS_INVAL;
    msg = *pmsg;

    assert(rte_atomic16_read(&msg->refcnt) != 0);
    if (!rte_atomic16_dec_and_test(&msg->refcnt)) {
        *pmsg = NULL;
        return EDPVS_OK;
    }

    /* i'm the only one hold the msg, free it now */
    if (msg->mode == DPVS_MSG_MULTICAST) {
        struct dpvs_msg *cur, *next;
        struct dpvs_multicast_queue *mcq;
        mcq = mc_queue_get(msg->type, msg->seq);
        if (likely(mcq != NULL)) {
            list_for_each_entry_safe(cur, next, &mcq->mq, mq_node) {
                list_del_init(&cur->mq_node);
                add_msg_flags(cur, DPVS_MSG_F_STATE_FIN); /* in case slaves reply with blockable msg */
                msg_destroy(&cur);
            }
            list_del_init(&mcq->list);
            mc_wait_list.free_cnt++;
            rte_free(mcq);
        } else {
            RTE_LOG(WARNING, MSGMGR, "%s: deleting multicast msg not found in queue:"
                    "type=%d, seq=%d\n", __func__, msg->type, msg->seq);
        }
    }

    if (msg->reply.data) {
        rte_free(msg->reply.data);
        msg->reply.len = 0;
    }
    rte_free(msg);
    *pmsg = NULL;

    return EDPVS_OK;
}

/* "msg" must be produced by "msg_make" */
int msg_send(struct dpvs_msg *msg, lcoreid_t cid, uint32_t flags, struct dpvs_msg_reply **reply)
{
    struct dpvs_msg_type *mt;
    int res;
    uint32_t tflags;
    uint64_t start, delay;

    add_msg_flags(msg, flags);

    if (unlikely(!msg || !((cid == master_lcore) || (slave_lcore_mask & (1L << cid))))) {
        RTE_LOG(WARNING, MSGMGR, "%s: invalid args\n", __func__);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_INVAL;
    }

    mt = msg_type_get(msg->type, cid);
    if (unlikely(!mt)) {
        RTE_LOG(WARNING, MSGMGR, "%s: msg type %d not registered\n", __func__, msg->type);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_NOTEXIST;
    }
    msg_type_put(mt);

    /* two lcores will be using the msg now, increase its refcnt */
    rte_atomic16_inc(&msg->refcnt);
    res = rte_ring_enqueue(msg_ring[cid], msg);
    if (unlikely(-EDQUOT == res)) {
        RTE_LOG(WARNING, MSGMGR, "%s: msg ring of lcore %d quota exceeded\n",
                __func__, cid);
    } else if (unlikely(-ENOBUFS == res)) {
        RTE_LOG(ERR, MSGMGR, "%s: msg ring of lcore %d is full\n", __func__, res);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        rte_atomic16_dec(&msg->refcnt); /* not enqueued, free manually */
        return EDPVS_DPDKAPIFAIL;
    } else if (res) {
        RTE_LOG(ERR, MSGMGR, "%s: unkown error %d for rte_ring_enqueue\n", __func__, res);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        rte_atomic16_dec(&msg->refcnt); /* not enqueued, free manually */
        return EDPVS_DPDKAPIFAIL;
    }

    if (flags & DPVS_MSG_F_ASYNC)
        return EDPVS_OK;

    /* blockable msg, wait here until done or timeout */
    add_msg_flags(msg, DPVS_MSG_F_STATE_SEND);
    start = rte_get_timer_cycles();
    while(!(test_msg_flags(msg, (DPVS_MSG_F_STATE_FIN | DPVS_MSG_F_STATE_DROP)))) {
        /* to avoid dead lock when one send a blockable msg to itself */
        if (rte_lcore_id() == master_lcore)
            msg_master_process();
        else
            msg_slave_process();
        delay = (uint64_t)msg_timeout * rte_get_timer_hz() / 1E6;
        if (start + delay < rte_get_timer_cycles()) {
            RTE_LOG(WARNING, MSGMGR, "%s: uc_msg(type:%d, cid:%d->%d, flags=%d) timeout"
                    "(%d us), drop...\n", __func__,
                    msg->type, msg->cid, cid, get_msg_flags(msg), msg_timeout);
            add_msg_flags(msg, DPVS_MSG_F_TIMEOUT);
            return EDPVS_MSG_DROP;
        }
    }
    if (reply)
        *reply = &msg->reply;

    tflags = get_msg_flags(msg);
    if (tflags & DPVS_MSG_F_CALLBACK_FAIL)
        return EDPVS_MSG_FAIL;
    else if (tflags & DPVS_MSG_F_STATE_FIN)
        return EDPVS_OK;
    else
        return EDPVS_MSG_DROP;
}

/* "msg" must be produced by "msg_make" */
int multicast_msg_send(struct dpvs_msg *msg, uint32_t flags, struct dpvs_multicast_queue **reply)
{
    struct dpvs_msg *new_msg;
    struct dpvs_multicast_queue *mc_msg;
    uint32_t tflags;
    uint64_t start, delay;
    int ii, ret;

    add_msg_flags(msg, flags);

    if (unlikely(!msg || DPVS_MSG_MULTICAST != msg->mode)
            || master_lcore != msg->cid) {
        RTE_LOG(WARNING, MSGMGR, "%s: invalid multicast msg\n", __func__);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_INVAL;
    }

    /* multicast msg of identical type and seq cannot coexist */
    if (unlikely(mc_queue_get(msg->type, msg->seq) != NULL)) {
        RTE_LOG(WARNING, MSGMGR, "%s: repeated sequence number for multicast msg: "
                "type %d, seq %d\n", __func__, msg->type, msg->seq);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        msg->mode = DPVS_MSG_UNICAST; /* do not free msg queue */
        return EDPVS_INVAL;
    }

    /* send unicast msgs from master to all alive slaves */
    rte_atomic16_inc(&msg->refcnt); /* refcnt increase by 1 for itself */
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (slave_lcore_mask & (1L << ii)) {
            new_msg = msg_make(msg->type, msg->seq, DPVS_MSG_UNICAST, msg->cid, msg->len, msg->data);
            if (unlikely(!new_msg)) {
                RTE_LOG(ERR, MSGMGR, "%s: msg make fail\n", __func__);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                rte_atomic16_dec(&msg->refcnt); /* decrease refcnt by 1 manually */
                return EDPVS_NOMEM;
            }

            /* must send F_ASYNC msg as mc_msg has not allocated */
            ret = msg_send(new_msg, ii, DPVS_MSG_F_ASYNC, NULL);
            if (ret < 0) { /* nonblock msg not equeued */
                RTE_LOG(ERR, MSGMGR, "%s: msg send fail\n", __func__);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                rte_atomic16_dec(&msg->refcnt); /* decrease refcnt by 1 manually */
                msg_destroy(&new_msg);
                return ret;
            }
            msg_destroy(&new_msg);
            rte_atomic16_inc(&msg->refcnt); /* refcnt increase by 1 for each slave */
        }
    }

    mc_msg = rte_zmalloc("mc_msg", sizeof(struct dpvs_multicast_queue), RTE_CACHE_LINE_SIZE);
    if (unlikely(!mc_msg)) {
        RTE_LOG(ERR, MSGMGR, "%s: no memory\n", __func__);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_NOMEM;
    }

    mc_msg->type = msg->type;
    mc_msg->seq = msg->seq;
    mc_msg->mask = slave_lcore_mask;
    mc_msg->org_msg = msg; /* save original msg */
    INIT_LIST_HEAD(&mc_msg->mq);

    rte_rwlock_write_lock(&mc_wait_lock);
    if (mc_wait_list.free_cnt <= 0) {
        RTE_LOG(WARNING, MSGMGR, "%s: multicast msg wait queue full, "
                "msg dropped and try later...\n", __func__);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_MSG_DROP;
    }
    list_add_tail(&mc_msg->list, &mc_wait_list.list);
    --mc_wait_list.free_cnt;
    rte_rwlock_write_unlock(&mc_wait_lock);

    if (flags & DPVS_MSG_F_ASYNC)
        return EDPVS_OK;

    /* blockable msg wait here until done or timeout */
    add_msg_flags(msg, DPVS_MSG_F_STATE_SEND);
    start = rte_get_timer_cycles();
    while(!(test_msg_flags(msg, (DPVS_MSG_F_STATE_FIN | DPVS_MSG_F_STATE_DROP)))) {
        msg_master_process(); /* to avoid dead lock if send msg to myself */
        delay = (uint64_t)msg_timeout * rte_get_timer_hz() / 1E6;
        if (start + delay < rte_get_timer_cycles()) {
            RTE_LOG(WARNING, MSGMGR, "%s: mc_msg(type:%d, cid:%d->slaves) timeout"
                    "(%d us), drop...\n", __func__,
                    msg->type, msg->cid, msg_timeout);
            add_msg_flags(msg, DPVS_MSG_F_TIMEOUT);
            return EDPVS_MSG_DROP;
        }
    }
    if (reply)
        *reply = mc_msg; /* here, mc_msg store all slave's response msg */

    tflags = get_msg_flags(msg);
    if (tflags & DPVS_MSG_F_CALLBACK_FAIL)
        return EDPVS_MSG_FAIL;
    else if (tflags & DPVS_MSG_F_STATE_FIN)
        return EDPVS_OK;
    else
        return EDPVS_MSG_DROP;
}

/* both unicast msg and multicast msg can be recieved on Master lcore */
int msg_master_process(void)
{
    struct dpvs_msg *msg;
    struct dpvs_msg_type *msg_type;
    struct dpvs_multicast_queue *mcq;

    /* dequeue msg from ring on the Master until drain */
    while (0 == rte_ring_dequeue(msg_ring[master_lcore], (void **)&msg)) {
        add_msg_flags(msg, DPVS_MSG_F_STATE_RECV);
        msg_type = msg_type_get(msg->type, master_lcore);
        if (!msg_type) {
            RTE_LOG(DEBUG, MSGMGR, "%s: unregistered msg type %d on master\n",
                    __func__, msg->type);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            msg_destroy(&msg);
            continue;
        }
        if (DPVS_MSG_UNICAST == msg_type->mode) { /* unicast msg */
            if (!msg_type->unicast_msg_cb) {
                RTE_LOG(DEBUG, MSGMGR, "%s: no callback registered for unicast msg %d\n",
                        __func__, msg->type);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                msg_destroy(&msg);
                msg_type_put(msg_type);
                continue;
            }
            if (msg_type->unicast_msg_cb(msg) < 0) {
                add_msg_flags(msg, DPVS_MSG_F_CALLBACK_FAIL);
                RTE_LOG(WARNING, MSGMGR, "%s: uc msg_type %d callback failed on master\n",
                        __func__, msg->type);
            }
            add_msg_flags(msg, DPVS_MSG_F_STATE_FIN);
            msg_destroy(&msg);
        } else { /* multicast msg */
            mcq = mc_queue_get(msg->type, msg->seq);
            if (!mcq) {
                RTE_LOG(WARNING, MSGMGR, "%s: miss multicast msg <type=%d, seq=%d> from"
                        " lcore %d\n", __func__, msg->type, msg->seq, msg->cid);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                msg_destroy(&msg);
                msg_type_put(msg_type);
                continue;
            }
            rte_atomic16_dec(&mcq->org_msg->refcnt); /* for each reply, decrease refcnt of org_msg */
            if (!msg_type->multicast_msg_cb) {
                RTE_LOG(DEBUG, MSGMGR, "%s: no callback registered for multicast msg %d\n",
                        __func__, msg->type);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                msg_destroy(&msg);
                msg_type_put(msg_type);
                continue;
            }
            if (mcq->mask & (1L << msg->cid)) { /* you are the msg i'm waiting */
                list_add_tail(&msg->mq_node, &mcq->mq);
                add_msg_flags(msg, DPVS_MSG_F_STATE_QUEUE);/* set QUEUE flag for slave's reply msg */
                mcq->mask &= ~(1L << msg->cid);
                if (test_msg_flags(msg, DPVS_MSG_F_CALLBACK_FAIL)) /* callback on slave failed */
                    add_msg_flags(mcq->org_msg, DPVS_MSG_F_CALLBACK_FAIL);

                if (unlikely(0 == mcq->mask)) { /* okay, all slave reply msg arrived */
                    if (msg_type->multicast_msg_cb(mcq) < 0) {
                        add_msg_flags(mcq->org_msg, DPVS_MSG_F_CALLBACK_FAIL);/* callback on master failed */
                        RTE_LOG(WARNING, MSGMGR, "%s: mc msg_type %d callback failed on master\n",
                                __func__, msg->type);
                    }
                    add_msg_flags(mcq->org_msg, DPVS_MSG_F_STATE_FIN);
                    msg_destroy(&mcq->org_msg);
                    msg_type_put(msg_type);
                    continue;
                }
                msg_type_put(msg_type);
                continue;
            }
            /* free repeated msg, but not free msg queue, so change msg mode to DPVS_MSG_UNICAST */
            msg->mode = DPVS_MSG_UNICAST;
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            msg_destroy(&msg); /* sorry, you are late */
            rte_atomic16_inc(&mcq->org_msg->refcnt); /* do not count refcnt for repeated msg */
        }
        msg_type_put(msg_type);
    }
    return EDPVS_OK;
}

/* only unicast msg can be recieved on slave lcore */
int msg_slave_process(void)
{
    struct dpvs_msg *msg, *xmsg;
    struct dpvs_msg_type *msg_type;
    lcoreid_t cid;
    int ret = EDPVS_OK;

    cid = rte_lcore_id();
    if (unlikely(cid == master_lcore)) {
        RTE_LOG(ERR, MSGMGR, "%s is called on master lcore!\n", __func__);
        return EDPVS_NONEALCORE;
    }

    /* dequeue msg from ring on the lcore until drain */
    while (0 == rte_ring_dequeue(msg_ring[cid], (void **)&msg)) {
        add_msg_flags(msg, DPVS_MSG_F_STATE_RECV);
        if (unlikely(DPVS_MSG_MULTICAST == msg->mode)) {
            RTE_LOG(ERR, MSGMGR, "%s: multicast msg recieved on slave lcore!\n", __func__);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            msg_destroy(&msg);
            continue;
        }

        msg_type = msg_type_get(msg->type, cid);
        if (!msg_type) {
            RTE_LOG(DEBUG, MSGMGR, "%s: unregistered msg type %d on lcore %d\n",
                    __func__, msg->type, cid);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            msg_destroy(&msg);
            continue;
        }

        if (msg_type->unicast_msg_cb) {
            if (msg_type->unicast_msg_cb(msg) < 0) {
                add_msg_flags(msg, DPVS_MSG_F_CALLBACK_FAIL);
                RTE_LOG(WARNING, MSGMGR, "%s: msg_type %d callback failed on lcore %d\n",
                     __func__, msg->type, cid);
            }
        }
        /* send response msg to Master for multicast msg */
        if (DPVS_MSG_MULTICAST == msg_type->mode) {
            xmsg = msg_make(msg->type, msg->seq, DPVS_MSG_UNICAST, cid, msg->reply.len,
                    msg->reply.data);
            if (unlikely(!xmsg)) {
                ret = EDPVS_NOMEM;
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                goto cont;
            }
            add_msg_flags(xmsg, DPVS_MSG_F_CALLBACK_FAIL & get_msg_flags(msg));
            if (msg_send(xmsg, master_lcore, DPVS_MSG_F_ASYNC, NULL)) {
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                msg_destroy(&xmsg);
                goto cont;
            }
            msg_destroy(&xmsg);
        }

        add_msg_flags(msg, DPVS_MSG_F_STATE_FIN);
cont:
        msg_destroy(&msg);
        msg_type_put(msg_type);
    }

    return ret;
}

static inline void slave_lcore_loop_func(__rte_unused void *dumpy)
{
    msg_slave_process();
}

/* for debug */
int msg_type_table_print(char *buf, int len)
{
    char line[256];
    int ii, jj, rem_len;
    struct dpvs_msg_type *mt;

    if (NULL == buf || !len)
        return EDPVS_INVAL;
    memset(buf, 0, len);

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (ii != master_lcore && !(slave_lcore_mask & (1L << ii)))
            continue;

        for (jj = 0; jj < DPVS_MSG_LEN; jj++) {
            rte_rwlock_read_lock(&mt_lock[ii][jj]);
            list_for_each_entry(mt, &mt_array[ii][jj], list) {
                memset(line, 0, sizeof(line));
                snprintf(line, sizeof(line), "lcore %-4d  hash %-8d  type %-8d  "
                        "mode %-12s  unicast_cb %p    multicast_cb %p\n", ii, jj, mt->type,
                        mt->mode == DPVS_MSG_UNICAST ? "UNICAST" : "MULITICAST",
                        mt->unicast_msg_cb, mt->multicast_msg_cb);

                rem_len = len - strlen(buf) - 1;
                if (strlen(line) > rem_len) {
                    RTE_LOG(WARNING, MSGMGR, "%s: buffer not enough\n", __func__);
                    return EDPVS_INVAL;
                }
                strncat(buf, line, rem_len);
            }
            rte_rwlock_read_unlock(&mt_lock[ii][jj]);

        }
    }
    return EDPVS_OK;
}

/**************************** built-in msg  *******************************/
static int msg_type_reg_cb(struct dpvs_msg *msg)
{
    int ret;
    struct dpvs_msg_type *mt;

    if (unlikely(NULL == msg || sizeof(struct dpvs_msg_type) != msg->len)) {
        RTE_LOG(WARNING, MSGMGR, "%s: bad msg data for MSG_TYPE_REG\n", __func__);
        return EDPVS_INVAL;
    }

    mt = (struct dpvs_msg_type *)msg->data;
    ret = msg_type_register(mt);
    if (ret < 0) {
        RTE_LOG(WARNING, MSGMGR, "%s: fail to request to register new msg type\n", __func__);
        return ret;
    }
    return EDPVS_OK;
}

static int msg_type_unreg_cb(struct dpvs_msg *msg)
{
    int ret;
    struct dpvs_msg_type *mt;

    if (unlikely(NULL == msg || sizeof(struct dpvs_msg_type) != msg->len)) {
        RTE_LOG(WARNING, MSGMGR, "%s: bad msg data for MSG_TYPE_UNREG\n", __func__);
        return EDPVS_INVAL;
    }

    mt = (struct dpvs_msg_type *)msg->data;
    ret = msg_type_unregister(mt);
    if (ret < 0) {
        RTE_LOG(WARNING, MSGMGR, "%s: fail to request to unregister new msg type\n", __func__);
        return ret;
    }
    return EDPVS_OK;
}

static int register_built_in_msg(void)
{
    int ii, tret, ret = EDPVS_OK;
    struct dpvs_msg_type mt;

    /* register msg-type on all enabled lcores */
    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_REG;
    mt.mode = DPVS_MSG_UNICAST;
    mt.unicast_msg_cb = msg_type_reg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (!rte_lcore_is_enabled(ii))
            continue;
        mt.cid = ii;
        if (unlikely((tret = msg_type_register(&mt)) < 0 )) {
            RTE_LOG(WARNING, MSGMGR, "%s: fail to register msg-register msg\n", __func__);
            ret = tret;
        }
    }

    /* unregister msg-type on all enabled lcores */
    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_UNREG;
    mt.mode = DPVS_MSG_UNICAST;
    mt.unicast_msg_cb = msg_type_unreg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (!rte_lcore_is_enabled(ii))
            continue;
        mt.cid = ii;
        if (unlikely((tret = msg_type_register(&mt)))) {
            RTE_LOG(WARNING, MSGMGR, "%s: fail to register msg-unregister mgs\n", __func__);
            ret = tret;
        }
    }

    /* master_xmit_msg msg-type on all slave lcores */
    if (unlikely(tret = netif_register_master_xmit_msg()))
        ret = tret;

    return ret;
}

static int unregister_built_in_msg(void)
{
    int ii, tret, ret = EDPVS_OK;
    struct dpvs_msg_type mt;

    /* msg register msg-type */
    mt.type = MSG_TYPE_REG;
    mt.mode = DPVS_MSG_UNICAST;
    mt.unicast_msg_cb = msg_type_reg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (!rte_lcore_is_enabled(ii))
            continue;
        mt.cid = ii;
        if (unlikely((tret = msg_type_unregister(&mt)) < 0)) {
            RTE_LOG(WARNING, MSGMGR, "%s: fail to unregister msg-register msg\n", __func__);
            ret = tret;
        }
    }

    /* msg unregister msg-type */
    memset(&mt, 0, sizeof(mt));
    mt.type = MSG_TYPE_UNREG;
    mt.mode = DPVS_MSG_UNICAST;
    mt.unicast_msg_cb = msg_type_unreg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (!rte_lcore_is_enabled(ii))
            continue;
        mt.cid = ii;
        if (unlikely((tret = msg_type_unregister(&mt)) < 0)) {
            RTE_LOG(WARNING, MSGMGR, "%s: fail to unregister msg-register msg\n", __func__);
            ret = tret;
        }
    }

    return ret;
}

/************************* built-in lcore msg ***************************/
static inline int msg_init(void)
{
    int ii, jj;
    int ret;
    char ring_name[16];
    char buf[4096];

    if (DPVS_MAX_LCORE > MSG_MAX_LCORE_SUPPORTED)
        return EDPVS_NOTSUPP;

    /* lcore mask init */
    slave_lcore_mask = 0;
    slave_lcore_nb = 0;
    master_lcore = rte_get_master_lcore();

    netif_get_slave_lcores(&slave_lcore_nb, &slave_lcore_mask);
    if (slave_lcore_nb > 64) {
        RTE_LOG(ERR, MSGMGR, "%s: only %d lcores supported for ctrl\n", __func__, 64);
        return EDPVS_INVAL;
    }

    /* per-lcore msg type array init */
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        for (jj = 0; jj < DPVS_MSG_LEN; jj++) {
            INIT_LIST_HEAD(&mt_array[ii][jj]);
            rte_rwlock_init(&mt_lock[ii][jj]);
        }
    }

    /* multicast queue init */
    mc_wait_list.free_cnt = msg_mc_qlen;
    INIT_LIST_HEAD(&mc_wait_list.list);

    /* per-lcore msg queue */
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        snprintf(ring_name, sizeof(ring_name), "msg_ring_%d", ii);
        msg_ring[ii] = rte_ring_create(ring_name, msg_ring_size,
                rte_socket_id(), 0/*RING_F_SC_DEQ*/);
        if (unlikely(NULL == msg_ring[ii])) {
            RTE_LOG(ERR, MSGMGR, "Fail to init ctrl !\n");
                    return EDPVS_DPDKAPIFAIL;
        }
    }

    /* register netif-lcore-loop-job for Slaves */
    snprintf(ctrl_lcore_job.name, sizeof(ctrl_lcore_job.name) - 1, "%s", "slave_ctrl_plane");
    ctrl_lcore_job.func = slave_lcore_loop_func;
    ctrl_lcore_job.data = NULL;
    ctrl_lcore_job.type = NETIF_LCORE_JOB_LOOP;
    if ((ret = netif_lcore_loop_job_register(&ctrl_lcore_job)) < 0) {
        RTE_LOG(ERR, MSGMGR, "%s: fail to register ctrl func on slave lcores\n", __func__);
        return ret;
    }

    /* register built-in msg type */
    register_built_in_msg();
    msg_type_table_print(buf, sizeof(buf));
    RTE_LOG(INFO, MSGMGR, "%s: built-in msg registered:\n%s\n", __func__, buf);

    return EDPVS_OK;
}

static inline int msg_term(void)
{
    int ii, ret;

    /* per-lcore msg queue */
    for (ii= 0; ii < DPVS_MAX_LCORE; ii++)
        rte_ring_free(msg_ring[ii]);

    /* unregister netif-lcore-loop-job for Slaves */
    if ((ret = netif_lcore_loop_job_unregister(&ctrl_lcore_job)) < 0) {
        RTE_LOG(ERR, MSGMGR, "%s: fail to unregister ctrl func on slave lcores\n", __func__);
        return ret;
    }

    /* unregister built-in msg type */
    unregister_built_in_msg();

    return EDPVS_OK;
}



/////////////////////////////// sockopt process msg ///////////////////////////////////////////

#define UNIX_DOMAIN_DEF "/var/run/dpvs_ctrl"
char ipc_unix_domain[256];

static struct list_head sockopt_list;

static int srv_fd;

static inline int judge_id_betw(sockoptid_t num, sockoptid_t min, sockoptid_t max)
{
    return ((num <= max) && (num >= min));
}

static struct dpvs_sockopts* sockopts_get(struct dpvs_sock_msg *msg)
{
    struct dpvs_sockopts *skopt;
    if (unlikely(NULL == msg))
        return NULL;

    switch (msg->type) {
        case SOCKOPT_GET:
            list_for_each_entry(skopt, &sockopt_list, list) {
                if (judge_id_betw(msg->id, skopt->get_opt_min, skopt->get_opt_max)) {
                    if (unlikely(skopt->version != msg->version)) {
                        RTE_LOG(WARNING, MSGMGR, "%s: socket msg version not match\n", __func__);
                        return NULL;
                    }
                    return skopt;
                }
            }
            return NULL;
            break;
        case SOCKOPT_SET:
            list_for_each_entry(skopt, &sockopt_list, list) {
                if (judge_id_betw(msg->id, skopt->set_opt_min, skopt->set_opt_max)) {
                    if (unlikely(skopt->version != msg->version)) {
                        RTE_LOG(WARNING, MSGMGR, "%s: socket msg version not match\n", __func__);
                        return NULL;
                    }
                    return skopt;
                }
            }
            return NULL;
            break;
        default:
            RTE_LOG(WARNING, MSGMGR, "%s: unkown sock msg type: %d\n", __func__, msg->type);
    }
    return NULL;
}

static inline int sockopts_exist(struct dpvs_sockopts *sockopts)
{
    struct dpvs_sockopts *skopt;
    if (unlikely(NULL == sockopts))
        return 0;

    list_for_each_entry(skopt, &sockopt_list, list) {
        if (judge_id_betw(sockopts->set_opt_min, skopt->set_opt_min, skopt->set_opt_max) ||
                judge_id_betw(sockopts->set_opt_max, skopt->set_opt_min, skopt->set_opt_max)) {
            return 1;
        }
        if (judge_id_betw(sockopts->get_opt_min, skopt->get_opt_min, skopt->get_opt_max) ||
                judge_id_betw(sockopts->get_opt_max, skopt->get_opt_min, skopt->get_opt_max)) {
            return 1;
        }
    }
    return 0;
}

int sockopt_register(struct dpvs_sockopts *sockopts)
{
    if (unlikely(NULL == sockopts)) {
        RTE_LOG(WARNING, MSGMGR, "%s: invalid socket msg type\n", __func__);
        return EDPVS_INVAL;
    }

    if (sockopts_exist(sockopts)) {
        RTE_LOG(WARNING, MSGMGR, "%s: socket msg type already exist\n", __func__);
        rte_exit(EXIT_FAILURE, "sockopt type already exist ->\n"
                "\t\tget: %d - %d\n\t\tset: %d - %d\n",
                sockopts->get_opt_min, sockopts->get_opt_max,
                sockopts->set_opt_min, sockopts->set_opt_max);

        return EDPVS_EXIST;
    }

    list_add_tail(&sockopts->list, &sockopt_list);

    return EDPVS_OK;
}

int sockopt_unregister(struct dpvs_sockopts *sockopts)
{
    struct dpvs_sockopts *skopt, *next;

    if (unlikely(NULL == sockopts)) {
        RTE_LOG(WARNING, MSGMGR, "%s: invalid socket msg type\n", __func__);
        return EDPVS_INVAL;
    }
    list_for_each_entry_safe(skopt, next, &sockopt_list, list) {
        if (sockopts == skopt) {
            list_del_init(&skopt->list);
            return EDPVS_OK;
        }
    }
    return EDPVS_NOTEXIST;
}

static inline int sockopt_msg_recv(int clt_fd, struct dpvs_sock_msg **pmsg)
{
    struct dpvs_sock_msg msg_hdr;
    struct dpvs_sock_msg *msg;
    int len, res;

    if (unlikely(!pmsg))
        return EDPVS_INVAL;
    *pmsg = NULL;

    len = sizeof(msg_hdr);
    memset(&msg_hdr, 0, len);
    res = readn(clt_fd, &msg_hdr, len);
    if (sizeof(msg_hdr) != res) {
        RTE_LOG(WARNING, MSGMGR, "%s: sockopt msg header recv fail -- %d/%d recieved\n",
                __func__, res, len);
        return EDPVS_IO;
    }

    *pmsg = rte_malloc("sockopt_msg",
            sizeof(struct dpvs_sock_msg) + msg_hdr.len, RTE_CACHE_LINE_SIZE);
    if (unlikely(NULL == *pmsg)) {
        RTE_LOG(ERR, MSGMGR, "%s: no memory\n", __func__);
        return EDPVS_NOMEM;
    }

    msg = *pmsg;
    msg->version = msg_hdr.version;
    msg->id = msg_hdr.id;
    msg->type = msg_hdr.type;
    msg->len = msg_hdr.len;

    if (msg_hdr.len > 0) {
        res = readn(clt_fd, msg->data, msg->len);
        if (res != msg->len) {
            RTE_LOG(WARNING, MSGMGR, "%s: sockopt msg body recv fail -- "
                    "%d/%d recieved\n", __func__, res, (int)msg->len);
            rte_free(msg);
            *pmsg = NULL;
            return EDPVS_IO;
        }
    }

    return EDPVS_OK;
}

/* free recieved msg */
static inline void sockopt_msg_free(struct dpvs_sock_msg *msg)
{
    rte_free(msg);
}

/* Note:
 * 1. data is created by user using rte_malloc, rte_zmalloc, etc.
 * 2. msg data not sent when errcode is set in reply header */
static int sockopt_msg_send(int clt_fd,
        const struct dpvs_sock_msg_reply *hdr,
        const char *data, int data_len)
{
    int len, res;

    len = sizeof(struct dpvs_sock_msg_reply);
    res = sendn(clt_fd, hdr, len, MSG_NOSIGNAL);
    if (len != res) {
        RTE_LOG(WARNING, MSGMGR, "[%s:msg#%d] sockopt reply msg header send error"
                " -- %d/%d sent\n", __func__, hdr->id, res, len);
        return EDPVS_IO;
    }

    if (hdr->errcode) {
        RTE_LOG(DEBUG, MSGMGR, "[%s:msg#%d] errcode set in sockopt msg reply: %s\n",
                __func__, hdr->id, dpvs_strerror(hdr->errcode));
        return hdr->errcode;
    }

    if (data_len) {
        res = sendn(clt_fd, data, data_len, MSG_NOSIGNAL);
        if (data_len != res) {
            RTE_LOG(WARNING, MSGMGR, "[%s:msg#%d] sockopt reply msg body send error"
                    " -- %d/%d sent\n", __func__, hdr->id, res, data_len);
            return EDPVS_IO;
        }
    }

    return EDPVS_OK;
}

int sockopt_ctl(__rte_unused void *arg)
{
    int clt_fd;
    int ret;
    socklen_t clt_len;
    struct sockaddr_un clt_addr;
    struct dpvs_sockopts *skopt;
    struct dpvs_sock_msg *msg;
    struct dpvs_sock_msg_reply reply_hdr;
    void *reply_data = NULL;
    size_t reply_data_len = 0;

    memset(&clt_addr, 0, sizeof(struct sockaddr_un));
    clt_len = sizeof(clt_addr);

    /* Note: srv_fd is nonblock */
    clt_fd = accept(srv_fd, (struct sockaddr*)&clt_addr, &clt_len);
    if (clt_fd < 0) {
        if (EWOULDBLOCK != errno) {
            RTE_LOG(WARNING, MSGMGR, "%s: Fail to accept client request\n", __func__);
        }
        return EDPVS_IO;
    }

    /* Note: clt_fd is block */
    ret = sockopt_msg_recv(clt_fd, &msg);
    if (unlikely(EDPVS_OK != ret)) {
        close(clt_fd);
        return ret;
    }

    skopt = sockopts_get(msg);
    if (skopt) {
        if (msg->type == SOCKOPT_GET)
            ret = skopt->get(msg->id, msg->data, msg->len, &reply_data, &reply_data_len);
        else if (msg->type == SOCKOPT_SET)
            ret = skopt->set(msg->id, msg->data, msg->len);
        if (ret < 0) {
            /* assume that reply_data is freed by user when callback fails */
            reply_data = NULL;
            reply_data_len = 0;
            RTE_LOG(INFO, MSGMGR, "%s: socket msg<type=%s, id=%d> callback failed\n",
                    __func__, msg->type == SOCKOPT_GET ? "GET" : "SET", msg->id);
        }

        memset(&reply_hdr, 0, sizeof(reply_hdr));
        reply_hdr.version = SOCKOPT_VERSION;
        reply_hdr.id = msg->id;
        reply_hdr.type = msg->type;
        reply_hdr.errcode = ret;
        strncpy(reply_hdr.errstr, dpvs_strerror(ret), SOCKOPT_ERRSTR_LEN - 1);
        reply_hdr.len = reply_data_len;

        /* send response */
        ret = sockopt_msg_send(clt_fd, &reply_hdr, reply_data, reply_data_len);

        if (reply_data)
            rte_free(reply_data);

        if (EDPVS_OK != ret) {
            sockopt_msg_free(msg);
            close(clt_fd);
            return ret;
        }
    }

    sockopt_msg_free(msg);
    close(clt_fd);

    return EDPVS_OK;
}

static inline int sockopt_init(void)
{
    struct sockaddr_un srv_addr;
    int srv_fd_flags = 0;

    INIT_LIST_HEAD(&sockopt_list);

    memset(ipc_unix_domain, 0, sizeof(ipc_unix_domain));
    strncpy(ipc_unix_domain, UNIX_DOMAIN_DEF, sizeof(ipc_unix_domain) - 1);

    srv_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        RTE_LOG(ERR, MSGMGR, "%s: Fail to create server socket\n", __func__);
        return EDPVS_IO;
    }

    srv_fd_flags = fcntl(srv_fd, F_GETFL, 0);
    srv_fd_flags |= O_NONBLOCK;
    if (-1 == fcntl(srv_fd, F_SETFL, srv_fd_flags)) {
        RTE_LOG(ERR, MSGMGR, "%s: Fail to set server socket NONBLOCK\n", __func__);
        return EDPVS_IO;
    }

    memset(&srv_addr, 0, sizeof(struct sockaddr_un));
    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, ipc_unix_domain, sizeof(srv_addr.sun_path) - 1);
    unlink(ipc_unix_domain);

    if (-1 == bind(srv_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr))) {
        RTE_LOG(ERR, MSGMGR, "%s: Fail to bind server socket\n", __func__);
        close(srv_fd);
        unlink(ipc_unix_domain);
        return EDPVS_IO;
    }

    if (-1 == listen(srv_fd, 1)) {
        RTE_LOG(ERR, MSGMGR, "%s: Server socket listen failed\n", __func__);
        close(srv_fd);
        unlink(ipc_unix_domain);
        return EDPVS_IO;
    }

    return EDPVS_OK;
}

static inline int sockopt_term(void)
{
    close(srv_fd);
    unlink(ipc_unix_domain);
    return EDPVS_OK;
}



/////////////////////////////// ctrl module API ////////////////////////////////////////////
int ctrl_init(void)
{
    int ret;

    rte_rwlock_init(&mc_wait_lock);

    ret = msg_init();
    if (unlikely(ret < 0)) {
        RTE_LOG(ERR, MSGMGR, "%s: msg module initialization failed!\n", __func__);
        return ret;
    }
    ret = sockopt_init();
    if (unlikely(ret < 0)) {
        RTE_LOG(ERR, MSGMGR, "%s: sockopt module initialization failed!\n", __func__);
        return ret;
    }
    return EDPVS_OK;
}

int ctrl_term(void)
{
    int ret;
    ret = msg_term();
    if (unlikely(ret < 0)) {
        RTE_LOG(ERR, MSGMGR, "%s: msg module initialization failed!\n", __func__);
        return ret;
    }
    ret = sockopt_term();
    if (unlikely(ret < 0)) {
        RTE_LOG(ERR, MSGMGR, "%s: sockopt module initialization failed!\n", __func__);
        return ret;
    }
    return EDPVS_OK;
}

static void msg_ring_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int ring_size;

    assert(str);
    ring_size = atoi(str);
    if (ring_size >= DPVS_MSG_RING_SIZE_MIN && ring_size <= DPVS_MSG_RING_SIZE_MAX) {
        is_power2(ring_size, 0, &ring_size);
        RTE_LOG(INFO, MSGMGR, "msg_ring_size = %d (round to 2^n)\n", ring_size);
        msg_ring_size = ring_size;
    } else {
        RTE_LOG(WARNING, MSGMGR, "invalid msg_ring_size %s, using default %d\n",
                str, DPVS_MSG_RING_SIZE_DEF);
        msg_ring_size = DPVS_MSG_RING_SIZE_DEF;
    }

    FREE_PTR(str);
}

static void msg_mc_qlen_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int mc_qlen;

    assert(str);
    mc_qlen = atoi(str);
    if (mc_qlen >= DPVS_MSG_MC_QLEN_MIN && mc_qlen <= DPVS_MSG_MC_QLEN_MAX) {
        is_power2(mc_qlen, 0, &mc_qlen);
        RTE_LOG(INFO, MSGMGR, "msg_mc_qlen = %d (round to 2^n)\n", mc_qlen);
        msg_mc_qlen = mc_qlen;
    } else {
        RTE_LOG(WARNING, MSGMGR, "invalid msg_mc_qlen %s, using default %d\n",
                str, DPVS_MULTICAST_LIST_LEN_DEF);
        msg_mc_qlen = DPVS_MULTICAST_LIST_LEN_DEF;
    }

    FREE_PTR(str);
}

static void msg_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int timeout;

    assert(str);
    timeout = atoi(str);
    if (timeout < 1) {
        RTE_LOG(WARNING, MSGMGR, "invalid sync_msg_timeout_us %s, using default %d\n",
                str, MSG_TIMEOUT_US);
        msg_timeout = MSG_TIMEOUT_US;
    } else {
        RTE_LOG(INFO, MSGMGR, "sync_msg_timeout_us = %d\n", timeout);
        msg_timeout = timeout;
    }

    FREE_PTR(str);
}

static void ipc_unix_domain_handler(vector_t tokens)
{
    char *str, *dup_str;
    size_t slen;

    str = set_value(tokens);
    slen = strlen(str);

    dup_str = strdup(str);
    dirname(dup_str);
    memset(ipc_unix_domain, 0, sizeof(ipc_unix_domain));

    if (slen > 0 && slen < sizeof(ipc_unix_domain) &&
            access(dup_str, F_OK) == 0) {
        RTE_LOG(INFO, MSGMGR, "ipc_unix_domain = %s\n", str);
        strncpy(ipc_unix_domain, str, sizeof(ipc_unix_domain) - 1);
    } else {
        RTE_LOG(WARNING, MSGMGR, "invalid ipc_unix_domain %s, using default %s\n",
                str, UNIX_DOMAIN_DEF);
        strncpy(ipc_unix_domain, UNIX_DOMAIN_DEF, sizeof(ipc_unix_domain) - 1);
    }

    free(dup_str);
    FREE_PTR(str);
}

void control_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        msg_ring_size = DPVS_MSG_RING_SIZE_DEF;
        msg_mc_qlen = DPVS_MULTICAST_LIST_LEN_DEF;
        strncpy(ipc_unix_domain, UNIX_DOMAIN_DEF, sizeof(ipc_unix_domain) - 1);
    }
    /* KW_TYPE_NORMAL keyword */
    msg_timeout = MSG_TIMEOUT_US;
}

void install_control_keywords(void)
{
    install_keyword_root("ctrl_defs", NULL);
    install_keyword("lcore_msg", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("ring_size", msg_ring_size_handler, KW_TYPE_INIT);
    install_keyword("multicast_queue_length", msg_mc_qlen_handler, KW_TYPE_INIT);
    install_keyword("sync_msg_timeout_us", msg_timeout_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_keyword("ipc_msg", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("unix_domain", ipc_unix_domain_handler, KW_TYPE_INIT);
    install_sublevel_end();
}
