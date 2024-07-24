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
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <assert.h>
#include "ctrl.h"
#include "netif.h"
#include "mempool.h"
#include "parser/parser.h"
#include "scheduler.h"

/////////////////////////////////// lcore  msg ///////////////////////////////////////////

#define MSG_MAX_LCORE_SUPPORTED 64

uint64_t slave_lcore_mask;     /* bit-wise enabled lcores */
uint8_t slave_lcore_nb;        /* slave lcore number */
lcoreid_t master_lcore;        /* master lcore id */
struct dpvs_mempool *msg_pool; /* memory pool for msg */

#define MSG_TIMEOUT_US 2000
static int g_msg_timeout = MSG_TIMEOUT_US;

static uint8_t g_msg_prio = MSG_PRIO_LOW;

const char* dpvs_sockopts_name[] = {
    DPVSMSG_SOCKOPT_ENUM(ENUM_STRING)
};

#define DPVS_MT_BITS 8
#define DPVS_MT_LEN (1 << DPVS_MT_BITS)
#define DPVS_MT_MASK (DPVS_MT_LEN - 1)

#define DPVS_MSG_RING_SIZE_DEF 4096
#define DPVS_MSG_RING_SIZE_MIN 256
#define DPVS_MSG_RING_SIZE_MAX 524288

static uint32_t msg_ring_size = DPVS_MSG_RING_SIZE_DEF;

/* per-lcore msg-type array */
typedef struct list_head msg_type_array_t[DPVS_MT_LEN];
typedef rte_rwlock_t msg_type_lock_t[DPVS_MT_LEN];

msg_type_array_t mt_array[DPVS_MAX_LCORE];
msg_type_lock_t mt_lock[DPVS_MAX_LCORE];

/* multicast msg hlist, to collect reply msg from slaves (used on master lcore only) */
#define DPVS_MC_HLIST_BITS 8
#define DPVS_MC_HLIST_LEN (1 << DPVS_MC_HLIST_BITS)
#define DPVS_MC_HLIST_MASK (DPVS_MC_HLIST_LEN - 1)
struct list_head mc_wait_hlist[DPVS_MC_HLIST_LEN];

/* per-lcore msg queue */
struct rte_ring *msg_ring[DPVS_MAX_LCORE];

#ifdef CONFIG_MSG_DEBUG
rte_atomic64_t n_msg_allc;
rte_atomic64_t n_msg_free;
rte_atomic32_t n_msg_using;

inline static void msg_debug_init(void)
{
    rte_atomic64_init(&n_msg_allc);
    rte_atomic64_init(&n_msg_free);
    rte_atomic32_init(&n_msg_using);
}

inline static void msg_debug_alloc(void)
{
    rte_atomic64_inc(&n_msg_allc);
    rte_atomic32_inc(&n_msg_using);
}

inline static void msg_debug_free(void)
{
    rte_atomic64_inc(&n_msg_free);
    rte_atomic32_dec(&n_msg_using);
}

inline static void msg_debug_dump(void)
{
    uint64_t allc;

    allc = rte_atomic64_read(&n_msg_allc);

    if (likely(allc % 100000))
        return;

    RTE_LOG(INFO, MSGMGR, "%s: allocated=%ld, freed=%ld, processing=%d\n",
            __func__, allc, rte_atomic64_read(&n_msg_free),
            rte_atomic32_read(&n_msg_using));
}

inline static int msg_memory_stats(char *buf, int len)
{
    snprintf(buf, len,
            "allocated:%ld, freed:%ld, processing:%d",
            rte_atomic64_read(&n_msg_allc),
            rte_atomic64_read(&n_msg_free),
            rte_atomic32_read(&n_msg_using));
    return strlen(buf);
}
#else
inline static void msg_debug_init(void) {}
inline static void msg_debug_alloc(void) {}
inline static void msg_debug_free(void) {}
inline static void msg_debug_dump(void) {}
inline static int msg_memory_stats(char *buf, int len) { return 0; }
#endif

static inline int mc_queue_hashkey(msgid_t type, uint32_t seq)
{
    return (((uint32_t)type) ^ seq) & DPVS_MC_HLIST_MASK;
}

/* only be called on master lcore, thus no lock needed */
static inline void mc_queue_hash(struct dpvs_multicast_queue *mcq)
{
    int hashkey;

    if (unlikely(!mcq))
        return;
    hashkey = mc_queue_hashkey(mcq->type, mcq->seq);
    list_add_tail(&mcq->list, &mc_wait_hlist[hashkey]);
}

static inline void mc_queue_unhash(struct dpvs_multicast_queue *mcq)
{
    if (unlikely(!mcq))
        return;
    list_del_init(&mcq->list);
}

static inline struct dpvs_multicast_queue* mc_queue_get(msgid_t type, uint32_t seq)
{
    int hashkey;
    struct dpvs_multicast_queue *mcq;

    assert(rte_lcore_id() == master_lcore);

    hashkey = mc_queue_hashkey(type, seq);
    list_for_each_entry(mcq, &mc_wait_hlist[hashkey], list) {
        if (mcq->type == type && mcq->seq == seq) {
            return mcq;
        }
    }
    return NULL;
}

static inline int mt_hashkey(msgid_t type)
{
    return type & DPVS_MT_MASK;
}

static struct dpvs_msg_type* msg_type_get(msgid_t type, lcoreid_t cid)
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
            mt.prio = msg_type->prio;
            mt.unicast_msg_cb = NULL;
            if (msg_type->multicast_msg_cb)
                mt.multicast_msg_cb = msg_type->multicast_msg_cb;
            else /* if no multicast callback given, then a default one is used, which do nothing now */
                mt.multicast_msg_cb = default_mc_msg_cb;
        } else if (slave_lcore_mask & (1L << cid)) {
            mt.cid = cid;
            mt.prio = MSG_PRIO_IGN; /* multi reply msg should always be sent */
            mt.unicast_msg_cb = msg_type->unicast_msg_cb;
            mt.multicast_msg_cb = NULL;
        } else
            continue;
        ret = msg_type_register(&mt);
        if (unlikely(ret < 0)) {
            RTE_LOG(ERR, MSGMGR, "%s: fail to register multicast msg on lcore %d\n", __func__, cid);
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
    mt.mode = DPVS_MSG_MULTICAST;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (cid == master_lcore) {
            mt.cid = cid;
            mt.prio = msg_type->prio;
            mt.unicast_msg_cb = NULL;
            if (msg_type->multicast_msg_cb)
                mt.multicast_msg_cb = msg_type->multicast_msg_cb;
            else
                mt.multicast_msg_cb = default_mc_msg_cb;
        } else if (slave_lcore_mask & (1L << cid)) {
            mt.cid = cid;
            mt.prio = MSG_PRIO_IGN;
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

void* msg_reply_alloc(int size)
{
    return dpvs_mempool_get(msg_pool, size);
}

void msg_reply_free(void *mptr)
{
    return dpvs_mempool_put(msg_pool, mptr);
}

struct dpvs_msg* msg_make(msgid_t type, uint32_t seq,
        msg_mode_t mode,
        lcoreid_t cid,
        uint32_t len, const void *data)
{
    int total_len;
    struct dpvs_msg *msg;

    total_len = sizeof(struct dpvs_msg) + len;
    msg = dpvs_mempool_get(msg_pool, total_len);
    if (unlikely(NULL == msg))
        return NULL;
    memset(msg, 0, total_len);

    rte_spinlock_init(&msg->lock);

    msg->type = type;
    msg->seq = seq;
    msg->mode = mode;
    msg->cid = cid;
    msg->len = len;
    if (len && data)
        rte_memcpy(msg->data, data, len);
    msg->reply.data = NULL;
    msg->reply.len = 0;

    rte_atomic16_init(&msg->refcnt);
    rte_atomic16_inc(&msg->refcnt);

    msg_debug_alloc();
    msg_debug_dump();

    return msg;
}

int msg_destroy(struct dpvs_msg **pmsg)
{
    struct dpvs_msg *msg;

    if (unlikely(!pmsg || !(*pmsg)))
        return EDPVS_INVAL;
    msg = *pmsg;

    if (unlikely(rte_atomic16_read(&msg->refcnt) == 0)) {
        char buf[1024];
        msg_dump(msg, buf, sizeof(buf));
        RTE_LOG(ERR, MSGMGR, "%s: bad msg refcnt at destroy:\n%s", __func__, buf);
        assert(0);
    }

    if (!rte_atomic16_dec_and_test(&msg->refcnt)) {
        *pmsg = NULL;
        return EDPVS_OK;
    }

    /* i'm the only one hold the msg, free it now */
    if (msg->mode == DPVS_MSG_MULTICAST) {
        struct dpvs_msg *cur, *next;
        struct dpvs_multicast_queue *mcq;
        assert(rte_lcore_id() == master_lcore);
        mcq = mc_queue_get(msg->type, msg->seq);
        if (likely(mcq != NULL)) {
            list_for_each_entry_safe(cur, next, &mcq->mq, mq_node) {
                list_del_init(&cur->mq_node);
                add_msg_flags(cur, DPVS_MSG_F_STATE_FIN); /* in case slaves reply with blockable msg */
                msg_destroy(&cur);
            }
            mc_queue_unhash(mcq);
            dpvs_mempool_put(msg_pool, mcq);
        } else {
            RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, deleting multicast msg not found in queue:"
                    "type=%d, seq=%d\n", __func__, msg, msg->type, msg->seq);
        }
    }

    if (msg->reply.data) {
        assert(msg->reply.len != 0);
        msg_reply_free(msg->reply.data);
        msg->reply.len = 0;
    }
    dpvs_mempool_put(msg_pool, msg);
    /*
    *   Be careful: 
    *       pmsg MUST NOT pointer to mcq->org_msg when seting *pmsg = NULL, bacause mcq is freed now.
    *       In that special case, if the space of freed mcq is newly allocted as a struct msg by other lcore, 
    *       set *pmsg = NULL here may cause step on the memory of the newly allocted msg.
    *   PS: the offset of member org_msg in struct dpvs_multicast_queue is 32, and it's size is 8B.
    *       the offset of member flags in struct dpvs_msg is 32, and it's size is 4.
    *       the offset of member refcnt in struct dpvs_msg is 36, and it's size is 2. 
    */
    *pmsg = NULL;

    msg_debug_free();

    return EDPVS_OK;
}

static int msg_master_process(int step);
/* "msg" must be produced by "msg_make" */
int msg_send(struct dpvs_msg *msg, lcoreid_t cid, uint32_t flags, struct dpvs_msg_reply **reply)
{
    struct dpvs_msg_type *mt;
    int res;
    int step = 1;
    uint32_t tflags;
    uint64_t start, delay;

    if (unlikely(msg == NULL))
        return EDPVS_INVAL;
    add_msg_flags(msg, flags);

    if (unlikely(!((cid == master_lcore) || (slave_lcore_mask & (1L << cid))))) {
        RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, invalid args\n", __func__, msg);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_INVAL;
    }

    mt = msg_type_get(msg->type, cid);
    if (unlikely(!mt)) {
        RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, msg type %d not registered\n",
                __func__, msg, msg->type);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        return EDPVS_NOTEXIST;
    }

    if (mt->prio > g_msg_prio) {
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        msg_type_put(mt);
        return EDPVS_DISABLED;
    }
    msg_type_put(mt);

    /* two lcores will be using the msg now, increase its refcnt */
    rte_atomic16_inc(&msg->refcnt);
    res = rte_ring_enqueue(msg_ring[cid], msg);
    if (unlikely(-EDQUOT == res)) {
        RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, msg ring of lcore %d quota exceeded\n",
                __func__, msg, cid);
    } else if (unlikely(-ENOBUFS == res)) {
        RTE_LOG(ERR, MSGMGR, "%s:msg@%p, msg ring of lcore %d is full\n", __func__, msg, cid);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        rte_atomic16_dec(&msg->refcnt); /* not enqueued, free manually */
        return EDPVS_DPDKAPIFAIL;
    } else if (res) {
        RTE_LOG(ERR, MSGMGR, "%s:msg@%p, unkown error %d for rte_ring_enqueue\n",
                __func__, msg, res);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        rte_atomic16_dec(&msg->refcnt); /* not enqueued, free manually */
        return EDPVS_DPDKAPIFAIL;
    }

    if (flags & DPVS_MSG_F_ASYNC)
        return EDPVS_OK;

    /* blockable msg, wait here until done or timeout */
    add_msg_flags(msg, DPVS_MSG_F_STATE_SEND);
    start = rte_get_timer_cycles();
    delay = (uint64_t)g_msg_timeout * g_cycles_per_sec / 1000000;
    while(!(test_msg_flags(msg, (DPVS_MSG_F_STATE_FIN | DPVS_MSG_F_STATE_DROP)))) {
        if (start + delay < rte_get_timer_cycles()) {
            RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, uc_msg(type:%d, cid:%d->%d, flags=%d) timeout"
                    "(%d us), drop...\n", __func__, msg, msg->type, msg->cid, cid,
                    get_msg_flags(msg), g_msg_timeout);
            add_msg_flags(msg, DPVS_MSG_F_TIMEOUT);
            return EDPVS_MSG_DROP;
        }
        /* to avoid dead lock when one send a blockable msg to itself */
        if (rte_lcore_id() == master_lcore)
            msg_master_process(step);
        else
            msg_slave_process(step);
        step *= 2;
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
    struct dpvs_multicast_queue *mcq;
    uint32_t tflags;
    uint64_t start, delay;
    int ii, ret;

    if (unlikely(msg == NULL))
        return EDPVS_INVAL;
    add_msg_flags(msg, flags);

    if (unlikely(DPVS_MSG_MULTICAST != msg->mode || master_lcore != msg->cid)) {
        RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, invalid multicast msg\n", __func__, msg);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        msg->mode = DPVS_MSG_UNICAST; /* do not free msg queue */
        return EDPVS_INVAL;
    }

    /* multicast msg of identical type and seq cannot coexist */
    if (unlikely(mc_queue_get(msg->type, msg->seq) != NULL)) {
        RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, repeated sequence number for multicast msg: "
                "type %d, seq %d\n", __func__, msg, msg->type, msg->seq);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        msg->mode = DPVS_MSG_UNICAST; /* do not free msg queue */
        return EDPVS_BUSY;
    }

    /* send unicast msgs from master to all alive slaves */
    rte_atomic16_inc(&msg->refcnt);
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (slave_lcore_mask & (1UL << ii)) {
            new_msg = msg_make(msg->type, msg->seq, DPVS_MSG_UNICAST, msg->cid, msg->len, msg->data);
            if (unlikely(!new_msg)) {
                RTE_LOG(ERR, MSGMGR, "%s:msg@%p, msg make fail\n", __func__, msg);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                rte_atomic16_dec(&msg->refcnt);
                return EDPVS_NOMEM;
            }

            /* must send F_ASYNC msg as mcq has not allocated */
            ret = msg_send(new_msg, ii, DPVS_MSG_F_ASYNC, NULL);
            if (ret < 0) { /* nonblock msg not equeued */
                if (ret != EDPVS_DISABLED)
                    RTE_LOG(ERR, MSGMGR, "%s:msg@%p, new_msg@%p, msg send fail\n",
                            __func__, msg, new_msg);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                rte_atomic16_dec(&msg->refcnt);
                msg_destroy(&new_msg);
                return ret;
            }
            msg_destroy(&new_msg);
        }
    }

    mcq = dpvs_mempool_get(msg_pool, sizeof(struct dpvs_multicast_queue));
    if (unlikely(!mcq)) {
        RTE_LOG(ERR, MSGMGR, "%s:msg@%p, no memory for mcq\n", __func__, msg);
        add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
        rte_atomic16_dec(&msg->refcnt);
        return EDPVS_NOMEM;
    }

    mcq->type = msg->type;
    mcq->seq = msg->seq;
    mcq->mask = slave_lcore_mask;
    mcq->org_msg = msg; /* save original msg */
    INIT_LIST_HEAD(&mcq->mq);

    /* hash mcq so that reply msg can be collected in msg_master_process */
    mc_queue_hash(mcq);

    if (flags & DPVS_MSG_F_ASYNC)
        return EDPVS_OK;

    /* blockable msg wait here until done or timeout */
    add_msg_flags(msg, DPVS_MSG_F_STATE_SEND);
    start = rte_get_timer_cycles();
    delay = (uint64_t)g_msg_timeout * g_cycles_per_sec / 1000000;
    while(!(test_msg_flags(msg, (DPVS_MSG_F_STATE_FIN | DPVS_MSG_F_STATE_DROP)))) {
        if (start + delay < rte_get_timer_cycles()) {
            RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, mcq(type:%d, cid:%d->slaves) timeout"
                    "(%d us), drop...\n", __func__, msg,
                    msg->type, msg->cid, g_msg_timeout);
            add_msg_flags(msg, DPVS_MSG_F_TIMEOUT);
            /* just in case slave send reply fail.
             * it's safe here, because msg is used on master lcore only. */
            msg_destroy(&msg);
            return EDPVS_MSG_DROP;
        }
        msg_master_process(slave_lcore_nb * 1.5); /* to avoid dead lock if send msg to myself */
    }
    if (reply)
        *reply = mcq; /* here, mcq store all slave's reply msg */

    tflags = get_msg_flags(msg);
    if (tflags & DPVS_MSG_F_CALLBACK_FAIL)
        return EDPVS_MSG_FAIL;
    else if (tflags & DPVS_MSG_F_STATE_FIN)
        return EDPVS_OK;
    else
        return EDPVS_MSG_DROP;
}

/* both unicast msg and multicast msg can be recieved on master lcore */
static int msg_master_process(int step)
{
    int n = 0;
    struct dpvs_msg *msg, *orig_msg;
    struct dpvs_msg_type *msg_type;
    struct dpvs_multicast_queue *mcq;

    /* dequeue msg from ring on the master lcore and process it */
    while (((step <= 0) || ((step > 0) && (++n <= step))) &&
            (0 == rte_ring_dequeue(msg_ring[master_lcore], (void **)&msg))) {
        add_msg_flags(msg, DPVS_MSG_F_STATE_RECV);
        msg_type = msg_type_get(msg->type, master_lcore);
        if (!msg_type) {
            RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, unregistered msg type %d on master\n",
                    __func__, msg, msg->type);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            msg_destroy(&msg);
            continue;
        }
        if (DPVS_MSG_UNICAST == msg_type->mode) { /* unicast msg */
            if (likely(msg_type->unicast_msg_cb != NULL)) {
                if (msg_type->unicast_msg_cb(msg) < 0) {
                    add_msg_flags(msg, DPVS_MSG_F_CALLBACK_FAIL);
#ifdef CONFIG_MSG_DEBUG
                    RTE_LOG(INFO, MSGMGR, "%s:msg@%p, uc msg_type %d callback failed on master\n",
                            __func__, msg, msg->type);
#endif
                }
            }
            add_msg_flags(msg, DPVS_MSG_F_STATE_FIN);
            msg_destroy(&msg);
        } else { /* multicast msg */
            mcq = mc_queue_get(msg->type, msg->seq);
            if (!mcq) {
                /* probably previous msg timeout */
                RTE_LOG(INFO, MSGMGR, "%s:msg@%p, multicast reply msg <type:%d, seq:%d> from"
                        " lcore %d missed\n", __func__, msg, msg->type, msg->seq, msg->cid);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                msg_destroy(&msg);
                msg_type_put(msg_type);
                continue;
            }
            assert(msg_type->multicast_msg_cb != NULL);
            if (mcq->mask & (1UL << msg->cid)) { /* you are the msg i'm waiting */
                list_add_tail(&msg->mq_node, &mcq->mq);
                add_msg_flags(msg, DPVS_MSG_F_STATE_QUEUE);/* set QUEUE flag for slave's reply msg */
                mcq->mask &= ~(1UL << msg->cid);
                if (test_msg_flags(msg, DPVS_MSG_F_CALLBACK_FAIL)) /* callback on slave failed */
                    add_msg_flags(mcq->org_msg, DPVS_MSG_F_CALLBACK_FAIL);

                if (unlikely(0 == mcq->mask)) { /* okay, all slave reply msg arrived */
                    if (msg_type->multicast_msg_cb(mcq) < 0) {
                        add_msg_flags(mcq->org_msg, DPVS_MSG_F_CALLBACK_FAIL);/* callback on master failed */
#ifdef CONFIG_MSG_DEBUG
                        RTE_LOG(INFO, MSGMGR, "%s:msg@%p, mc msg_type %d callback failed on master\n",
                                __func__, mcq->org_msg, msg->type);
#endif
                    }
                    add_msg_flags(mcq->org_msg, DPVS_MSG_F_STATE_FIN);
                    orig_msg = mcq->org_msg;
                    msg_destroy(&orig_msg);
                }
                msg_type_put(msg_type);
                continue;
            }
            /* probably previous msg timeout and new msg of this type sent */
            RTE_LOG(INFO, MSGMGR, "%s:msg@%p, multicast reply msg <type:%d, seq:%d> from"
                    " lcore %d repeated\n", __func__, msg, msg->type, msg->seq, msg->cid);
            assert(msg->mode == DPVS_MSG_UNICAST);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            msg_destroy(&msg); /* sorry, you are late */
        }
        msg_type_put(msg_type);
    }
    return EDPVS_OK;
}

/* only unicast msg can be recieved on slave lcore */
int msg_slave_process(int step)
{
    int n = 0;
    struct dpvs_msg *msg, *xmsg;
    struct dpvs_msg_type *msg_type;
    lcoreid_t cid;
    int ret = EDPVS_OK;

    cid = rte_lcore_id();
    if (unlikely(cid == master_lcore)) {
        RTE_LOG(ERR, MSGMGR, "%s is called on master lcore!\n", __func__);
        return EDPVS_NONEALCORE;
    }

    /* dequeue msg from ring on the lcore and process it */
    while (0 == rte_ring_dequeue(msg_ring[cid], (void **)&msg)) {
        add_msg_flags(msg, DPVS_MSG_F_STATE_RECV);
        msg_type = NULL;

        if (unlikely(DPVS_MSG_MULTICAST == msg->mode)) {
            RTE_LOG(ERR, MSGMGR, "%s:msg@%p, multicast msg recieved on slave lcore!\n",
                    __func__, msg);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            goto cont;
        }

        msg_type = msg_type_get(msg->type, cid);
        if (!msg_type) {
            RTE_LOG(WARNING, MSGMGR, "%s:msg@%p, unregistered msg type %d on lcore %d\n",
                    __func__, msg, msg->type, cid);
            add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
            goto cont;
        }

        if (likely(msg_type->unicast_msg_cb != NULL)) {
            if (msg_type->unicast_msg_cb(msg) < 0) {
                add_msg_flags(msg, DPVS_MSG_F_CALLBACK_FAIL);
#ifdef CONFIG_MSG_DEBUG
                RTE_LOG(INFO, MSGMGR, "%s:msg@%p, msg_type %d callback failed on lcore %d\n",
                     __func__, msg, msg->type, cid);
#endif
            }
        }
        /* send reply msg to master for multicast msg */
        if (DPVS_MSG_MULTICAST == msg_type->mode) {
            /* FIXME:
             * What if fail here? The result is master lcore would never get the reply msg from slaves.
             * - For blockable msg, no problem exists because the multicast_wait_hlist for it would be freed
             * when timeout, making all its repsonse slave msg freed or invalid.
             * - Nonblockable msg is difficult to end itself, and all this type msg sending afterwards would fail.
             * Fortunately, chances of error happending here is very slim, and nonblockable mulitcast msg is
             * rarely used. we just log an error and continue if fail here.
             * */
            xmsg = msg_make(msg->type, msg->seq, DPVS_MSG_UNICAST, cid, msg->reply.len,
                    msg->reply.data);
            if (unlikely(!xmsg)) {
                RTE_LOG(ERR, MSGMGR, "%s:msg@%p, no memory for msg_make\n", __func__, msg);
                ret = EDPVS_NOMEM;
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                goto cont;
            }
            add_msg_flags(xmsg, DPVS_MSG_F_CALLBACK_FAIL & get_msg_flags(msg));
            if (msg_send(xmsg, master_lcore, DPVS_MSG_F_ASYNC, NULL)) {
                RTE_LOG(ERR, MSGMGR, "%s:msg@%p,xmsg@%p, xmsg send failed!\n",
                        __func__, msg, xmsg);
                add_msg_flags(msg, DPVS_MSG_F_STATE_DROP);
                msg_destroy(&xmsg);
                goto cont;
            }
            msg_destroy(&xmsg);
        }

        add_msg_flags(msg, DPVS_MSG_F_STATE_FIN);

cont:
        if (likely(msg_type != NULL))
            msg_type_put(msg_type);

        msg_destroy(&msg);

        if (step > 0 && ++n >= step)
            break;
    }

    return ret;
}

/* for debug */
int msg_dump(const struct dpvs_msg *msg, char *buf, int len)
{
    int curlen;
    char mstats[256];
    if (!msg || !buf || !len)
        return 0;
    memset(buf, 0, len);

    snprintf(buf, len, " ptr:%p, type:%d, seq:%d, mode:%d, cid:%d, flags:0x%x, refcnt:%d\n ",
            msg, msg->type, msg->seq, msg->mode, msg->cid, msg->flags, rte_atomic16_read(&msg->refcnt));
    if (msg->len) {
        curlen = strlen(buf);
        if (len - curlen <= 0)
            return strlen(buf);
        snprintf(buf + curlen, len - curlen, "len:%d, data:0x%lx\n ", msg->len, (uint64_t)msg->data);
    }
    if (msg->reply.len) {
        curlen = strlen(buf);
        if (len - curlen <= 0)
            return strlen(buf);
        snprintf(buf + curlen, len - curlen, "reply.len:%d, reply.data:0x%lx\n ",
                msg->reply.len, (uint64_t)msg->reply.data);
    }

    if (msg_memory_stats(mstats, sizeof(mstats))) {
        curlen = strlen(buf);
        if (len - curlen <= 0)
            return strlen(buf);
        snprintf(buf + curlen, len - curlen, "%s\n ", mstats);
    }

    return strlen(buf);
}

int msg_type_table_print(char *buf, int len)
{
    char line[256];
    int ii, jj, rem_len;
    struct dpvs_msg_type *mt;

    if (!buf || !len)
        return EDPVS_INVAL;
    memset(buf, 0, len);

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (ii != master_lcore && !(slave_lcore_mask & (1L << ii)))
            continue;

        for (jj = 0; jj < DPVS_MT_LEN; jj++) {
            rte_rwlock_read_lock(&mt_lock[ii][jj]);
            list_for_each_entry(mt, &mt_array[ii][jj], list) {
                memset(line, 0, sizeof(line));
                snprintf(line, sizeof(line), "mt_array[%-2d][%-2d] type %-8d  mode %-12s"
                        "  unicast_cb %p    multicast_cb %p\n", ii, jj, mt->type,
                        mt->mode == DPVS_MSG_UNICAST ? "UNICAST" : "MULITICAST",
                        mt->unicast_msg_cb, mt->multicast_msg_cb);

                rem_len = len - strlen(buf) - 1;
                if (strlen(line) > rem_len) {
                    RTE_LOG(WARNING, MSGMGR, "%s: buffer not enough\n", __func__);
		      rte_rwlock_read_unlock(&mt_lock[ii][jj]);
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
    mt.prio = MSG_PRIO_HIGH;
    mt.unicast_msg_cb = msg_type_reg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii != master_lcore) && !(slave_lcore_mask & (1UL<<ii)))
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
    mt.prio = MSG_PRIO_HIGH;
    mt.unicast_msg_cb = msg_type_unreg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii != master_lcore) && !(slave_lcore_mask & (1UL<<ii)))
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
    mt.prio = MSG_PRIO_HIGH;
    mt.unicast_msg_cb = msg_type_reg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii != master_lcore) && !(slave_lcore_mask & (1UL<<ii)))
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
    mt.prio = MSG_PRIO_HIGH;
    mt.unicast_msg_cb = msg_type_unreg_cb;

    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if ((ii != master_lcore) && !(slave_lcore_mask & (1UL<<ii)))
            continue;
        mt.cid = ii;
        if (unlikely((tret = msg_type_unregister(&mt)) < 0)) {
            RTE_LOG(WARNING, MSGMGR, "%s: fail to unregister msg-register msg\n", __func__);
            ret = tret;
        }
    }

    return ret;
}

static inline void master_lcore_loop_func(__rte_unused void *dummy)
{
    msg_master_process(0);
}

static inline void slave_lcore_loop_func(__rte_unused void *dummy)
{
    msg_slave_process(0);
}

static struct dpvs_lcore_job msg_master_job = {
    .name = "msg_master_job",
    .type = LCORE_JOB_LOOP,
    .func = master_lcore_loop_func,
};

static struct dpvs_lcore_job msg_slave_job = {
    .name = "msg_slave_job",
    .type = LCORE_JOB_LOOP,
    .func = slave_lcore_loop_func,
};

static inline int msg_lcore_job_register(void)
{
    int ret;

    ret = dpvs_lcore_job_register(&msg_master_job, LCORE_ROLE_MASTER);
    if (ret < 0)
        return ret;

    ret = dpvs_lcore_job_register(&msg_slave_job, LCORE_ROLE_FWD_WORKER);
    if (ret < 0) {
        dpvs_lcore_job_unregister(&msg_master_job, LCORE_ROLE_MASTER);
        return ret;
    }

    return EDPVS_OK;
}

static inline void msg_lcore_job_unregister(void)
{
    dpvs_lcore_job_unregister(&msg_master_job, LCORE_ROLE_MASTER);
    dpvs_lcore_job_unregister(&msg_slave_job, LCORE_ROLE_FWD_WORKER);
}

static inline int msg_init(void)
{
    int ii, jj;
    int ret;
    char ring_name[16];
    char buf[8192];

    if (DPVS_MAX_LCORE > MSG_MAX_LCORE_SUPPORTED)
        return EDPVS_NOTSUPP;

    msg_debug_init();

    /* lcore mask init */
    slave_lcore_mask = 0;
    slave_lcore_nb = 0;
    master_lcore = rte_get_main_lcore();

    netif_get_slave_lcores(&slave_lcore_nb, &slave_lcore_mask);
    if (slave_lcore_nb > MSG_MAX_LCORE_SUPPORTED) {
        RTE_LOG(ERR, MSGMGR, "%s: lcore msg supports %d lcores at max\n",
                __func__, MSG_MAX_LCORE_SUPPORTED);
        return EDPVS_NOTSUPP;
    }

    /* msg_pool uses about 26MB memory */
    msg_pool = dpvs_mempool_create("mp_msg", 32, 131072, 2048);
    if (!msg_pool)
        return EDPVS_NOMEM;

    /* per-lcore msg type array init */
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        for (jj = 0; jj < DPVS_MT_LEN; jj++) {
            INIT_LIST_HEAD(&mt_array[ii][jj]);
            rte_rwlock_init(&mt_lock[ii][jj]);
        }
    }

    /* multicast queue init */
    for (ii = 0; ii < DPVS_MC_HLIST_LEN; ii++)
        INIT_LIST_HEAD(&mc_wait_hlist[ii]);

    /* per-lcore msg queue */
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        snprintf(ring_name, sizeof(ring_name), "msg_ring_%d", ii);
        msg_ring[ii] = rte_ring_create(ring_name, msg_ring_size,
                rte_socket_id(), RING_F_SC_DEQ);
        if (unlikely(NULL == msg_ring[ii])) {
            RTE_LOG(ERR, MSGMGR, "%s: fail to create msg ring\n", __func__);
            dpvs_mempool_destroy(msg_pool);
            for (--ii; ii >= 0; ii--)
                rte_ring_free(msg_ring[ii]);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    /* register netif-lcore-loop-job for Slaves */
    ret = msg_lcore_job_register();
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, MSGMGR, "%s: fail to register msg jobs\n", __func__);
        dpvs_mempool_destroy(msg_pool);
        for (ii = 0; ii < DPVS_MAX_LCORE; ii++)
            rte_ring_free(msg_ring[ii]);
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
    int ii;

    /* unregister built-in msg type */
    unregister_built_in_msg();

    /* unregister netif-lcore-loop-job for Slaves */
    msg_lcore_job_unregister();

    /* per-lcore msg queue */
    for (ii= 0; ii < DPVS_MAX_LCORE; ii++)
        rte_ring_free(msg_ring[ii]);
    dpvs_mempool_destroy(msg_pool);

    return EDPVS_OK;
}



/////////////////////////////// sockopt process msg ///////////////////////////////////////////

static char ipc_unix_domain[256];

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
        if (judge_id_betw(skopt->set_opt_min, sockopts->set_opt_min, sockopts->set_opt_max) ||
                judge_id_betw(skopt->set_opt_max, sockopts->set_opt_min, sockopts->set_opt_max)) {
            return 1;
        }
        if (judge_id_betw(sockopts->get_opt_min, skopt->get_opt_min, skopt->get_opt_max) ||
                judge_id_betw(sockopts->get_opt_max, skopt->get_opt_min, skopt->get_opt_max)) {
            return 1;
        }
        if (judge_id_betw(skopt->get_opt_min, sockopts->get_opt_min, sockopts->get_opt_max) ||
                judge_id_betw(skopt->get_opt_max, sockopts->get_opt_min, sockopts->get_opt_max)) {
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
                "\t\tget: %s - %s\n\t\tset: %s - %s\n",
                dpvs_sockopts_name[sockopts->get_opt_min], dpvs_sockopts_name[sockopts->get_opt_max],
                dpvs_sockopts_name[sockopts->set_opt_min], dpvs_sockopts_name[sockopts->set_opt_max]);

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
            RTE_LOG(WARNING, MSGMGR, "%s: sockopt[%s] msg body recv fail -- "
                    "%d/%d recieved\n", __func__, dpvs_sockopts_name[msg->id], res, (int)msg->len);
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
        RTE_LOG(WARNING, MSGMGR, "[%s:msg#%s] sockopt reply msg header send error"
                " -- %d/%d sent\n", __func__, dpvs_sockopts_name[hdr->id], res, len);
        return EDPVS_IO;
    }

    if (hdr->errcode) {
        RTE_LOG(DEBUG, MSGMGR, "[%s:msg#%s] errcode set in sockopt msg reply: %s\n",
                __func__, dpvs_sockopts_name[hdr->id], dpvs_strerror(hdr->errcode));
        return hdr->errcode;
    }

    if (data_len) {
        res = sendn(clt_fd, data, data_len, MSG_NOSIGNAL);
        if (data_len != res) {
            RTE_LOG(WARNING, MSGMGR, "[%s:msg#%s] sockopt reply msg body send error"
                    " -- %d/%d sent\n", __func__, dpvs_sockopts_name[hdr->id], res, data_len);
            return EDPVS_IO;
        }
    }

    return EDPVS_OK;
}

static int sockopt_ctl(__rte_unused void *arg)
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
#ifdef CONFIG_MSG_DEBUG
            RTE_LOG(INFO, MSGMGR, "%s: socket msg<type=%s, name=%s> callback failed\n",
                    __func__, msg->type == SOCKOPT_GET ? "GET" : "SET", dpvs_sockopts_name[msg->id]);
#endif
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

static inline void sockopt_job_func(void *dummy)
{
    sockopt_ctl(NULL);
}

static struct dpvs_lcore_job sockopt_job = {
    .name = "sockopt_job",
    .type = LCORE_JOB_LOOP,
    .func = sockopt_job_func,
};

static inline int sockopt_init(void)
{
    struct sockaddr_un srv_addr;
    int srv_fd_flags = 0;
    int err;

    INIT_LIST_HEAD(&sockopt_list);

    memset(ipc_unix_domain, 0, sizeof(ipc_unix_domain));
    strncpy(ipc_unix_domain, dpvs_ipc_file, sizeof(ipc_unix_domain) - 1);

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

    if ((err = dpvs_lcore_job_register(&sockopt_job, LCORE_ROLE_MASTER)) != EDPVS_OK) {
        RTE_LOG(ERR, MSGMGR, "%s: Fail to register sockopt_job into master\n", __func__);
        close(srv_fd);
        unlink(ipc_unix_domain);
        return err;
    }

    return EDPVS_OK;
}

static inline int sockopt_term(void)
{
    close(srv_fd);
    unlink(ipc_unix_domain);
    dpvs_lcore_job_unregister(&sockopt_job, LCORE_ROLE_MASTER);

    return EDPVS_OK;
}



/////////////////////////////// ctrl module API ////////////////////////////////////////////
int ctrl_init(void)
{
    int ret;

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

static void msg_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int timeout;

    assert(str);
    timeout = atoi(str);
    if (timeout < 1) {
        RTE_LOG(WARNING, MSGMGR, "invalid sync_msg_timeout_us %s, using default %d\n",
                str, MSG_TIMEOUT_US);
        g_msg_timeout = MSG_TIMEOUT_US;
    } else {
        RTE_LOG(INFO, MSGMGR, "sync_msg_timeout_us = %d\n", timeout);
        g_msg_timeout = timeout;
    }

    FREE_PTR(str);
}

static void msg_priority_level_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint8_t prio;

    assert(str);
    if (!strcasecmp(str, "low"))
        prio = MSG_PRIO_LOW;
    else if (!strcasecmp(str, "norm"))
        prio = MSG_PRIO_NORM;
    else if (!strcasecmp(str, "high"))
        prio = MSG_PRIO_HIGH;
    else if (!strcasecmp(str, "ign"))
        prio = MSG_PRIO_IGN;
    else {
        RTE_LOG(WARNING, MSGMGR, "invalid priority_level %s, using default level: %s\n",
                str, "low");
        prio = MSG_PRIO_LOW;
    }

    RTE_LOG(INFO, MSGMGR, "priority_level = %s\n", str);
    g_msg_prio = prio;

    FREE_PTR(str);
}

void control_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        msg_ring_size = DPVS_MSG_RING_SIZE_DEF;
    }
    /* KW_TYPE_NORMAL keyword */
    g_msg_timeout = MSG_TIMEOUT_US;
    g_msg_prio = MSG_PRIO_LOW;
}

void install_control_keywords(void)
{
    install_keyword_root("ctrl_defs", NULL);
    install_keyword("lcore_msg", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("ring_size", msg_ring_size_handler, KW_TYPE_INIT);
    install_keyword("sync_msg_timeout_us", msg_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("priority_level", msg_priority_level_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
}
