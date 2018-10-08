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
#ifndef __DPVS_MSGMGR_H__
#define __DPVS_MSGMGR_H__

#include "common.h"
#include "list.h"
#include "dpdk.h"

#define RTE_LOGTYPE_MSGMGR RTE_LOGTYPE_USER2

#define  DPVS_WAIT_WHILE(expr) while(expr){;}

typedef uint32_t msgid_t;

typedef enum msg_mode {
    DPVS_MSG_UNICAST   = 1,
    DPVS_MSG_MULTICAST
} DPVS_MSG_MODE;

/* nonblockable msg */
#define DPVS_MSG_F_ASYNC            1
/* msg has been sent from sender */
#define DPVS_MSG_F_STATE_SEND       2
/* for multicast msg only, msg arrived at Master and enqueued, waiting for all other Slaves reply */
#define DPVS_MSG_F_STATE_QUEUE      4
/* msg has dequeued from ring */
#define DPVS_MSG_F_STATE_RECV       8
/* msg finished, all Slaves replied if multicast msg */
#define DPVS_MSG_F_STATE_FIN        16
/* msg drop, callback not called, for reason such as unregister, timeout ... */
#define DPVS_MSG_F_STATE_DROP       32
/* msg callback failed */
#define DPVS_MSG_F_CALLBACK_FAIL    64
/* msg timeout */
#define DPVS_MSG_F_TIMEOUT          128

struct dpvs_msg_reply {
    uint32_t len;
    void *data;
};

/* inter-lcore msg structure */
struct dpvs_msg {
    struct list_head mq_node;
    msgid_t type;
    uint32_t seq;           /* msg sequence number */
    DPVS_MSG_MODE mode;     /* msg mode */
    lcoreid_t cid;          /* which lcore the msg from, for multicast always Master */
    uint32_t flags;         /* msg flags */
    rte_atomic16_t refcnt;  /* reference count */
    rte_spinlock_t lock;    /* msg lock */
    struct dpvs_msg_reply reply;
    /* response data, created with rte_malloc... and filled by callback */
    uint32_t len;           /* msg data length */
    char data[0];           /* msg data */
};

static inline uint32_t get_msg_flags(struct dpvs_msg *msg)
{
    uint32_t flags;
    rte_spinlock_lock(&msg->lock);
    flags = msg->flags;
    rte_spinlock_unlock(&msg->lock);
    return flags;
}

static inline bool test_msg_flags(struct dpvs_msg *msg, uint32_t flags)
{
    bool ret;
    rte_spinlock_lock(&msg->lock);
    ret = (msg->flags & flags) ? true : false;
    rte_spinlock_unlock(&msg->lock);
    return ret;
}

static inline void set_msg_flags(struct dpvs_msg *msg, uint32_t flags)
{
    rte_spinlock_lock(&msg->lock);
    msg->flags = flags;
    rte_spinlock_unlock(&msg->lock);
}

static inline void add_msg_flags(struct dpvs_msg *msg, uint32_t flags)
{
    rte_spinlock_lock(&msg->lock);
    msg->flags |= flags;
    rte_spinlock_unlock(&msg->lock);
}

static inline void del_msg_flags(struct dpvs_msg *msg, uint32_t flags)
{
    rte_spinlock_lock(&msg->lock);
    msg->flags &= (~flags);
    rte_spinlock_unlock(&msg->lock);
}

/* Master->Slave multicast msg queue */
struct dpvs_multicast_queue {
    msgid_t type;           /* msg type */
    uint32_t seq;           /* msg sequence number */
    //uint16_t ttl;           /* time to live */
    uint64_t mask;          /* bit-wise core mask */
    struct list_head mq;    /* recieved msg queue */
    struct dpvs_msg *org_msg; /* original msg from 'multicast_msg_send', sender should never visit me */
    struct list_head list;
};

/* All msg callbacks are called on the lcore which it registers */
typedef int (*UNICAST_MSG_CB)(struct dpvs_msg *);
typedef int (*MULTICAST_MSG_CB)(struct dpvs_multicast_queue *);

/* unicast only needs UNICAST_MSG_CB,
 * while multicast need both UNICAST_MSG_CB and MULTICAST_MSG_CB.
 * As for mulitcast msg, UNICAST_MSG_CB return a dpvs_msg to Master with the SAME
 * seq number as the msg recieved. */
struct dpvs_msg_type {
    msgid_t type;
    lcoreid_t cid;          /* on which lcore the callback func registers */
    DPVS_MSG_MODE mode;     /* distinguish unicast from multicast for the same msg type */
    UNICAST_MSG_CB unicast_msg_cb;     /* call this func if msg is unicast, i.e. 1:1 msg */
    MULTICAST_MSG_CB multicast_msg_cb; /* call this func if msg is multicast, i.e. 1:N msg */
    rte_atomic32_t refcnt;
    struct list_head list;
};

/* register|unregister msg-type on lcore 'msg_type->cid'  */
int msg_type_register(const struct dpvs_msg_type *msg_type);
int msg_type_unregister(const struct dpvs_msg_type *msg_type);

/* register|unregister multicast msg-type on each configured lcore */
int msg_type_mc_register(const struct dpvs_msg_type *msg_type);
int msg_type_mc_unregister(const struct dpvs_msg_type *msg_type);

/* make a msg for 'msg_send' or 'multicast_msg_send' */
struct dpvs_msg* msg_make(msgid_t type, uint32_t seq,
        DPVS_MSG_MODE mode,
        lcoreid_t cid,
        uint32_t len, const void *data);
int msg_destroy(struct dpvs_msg **pmsg);

/* send msg to lcore cid */
int msg_send(struct dpvs_msg *msg,
        lcoreid_t cid, /* target lcore for the msg */
        uint32_t flags, /* only  DPVS_MSG_F_ASYNC supported now */
        struct dpvs_msg_reply **reply); /* response, use it before msg_destroy */

/* send multicast msg to Master lcore */
int multicast_msg_send(struct dpvs_msg *msg,
        uint32_t flags, /* only DPVS_MSG_F_ASYNC supported now */
        struct dpvs_multicast_queue **reply); /* response, use it before msg_destroy */

/* Master lcore msg process loop */
int msg_master_process(void); /* Master lcore msg loop */

/* Slave lcore msg process loop */
int msg_slave_process(void);  /* Slave lcore msg loop */

/* print msg_type table on all configured lcores */
int msg_type_table_print(char *buf, int len); /* debug */

/***************************** built-in msg-type ******************************/
#define MSG_TYPE_REG                        1
#define MSG_TYPE_UNREG                      2
#define MSG_TYPE_HELLO                      3
#define MSG_TYPE_GET_ALL_SLAVE_ID           4
#define MSG_TYPE_MASTER_XMIT                5
#define MSG_TYPE_ROUTE_ADD                  6
#define MSG_TYPE_ROUTE_DEL                  7
#define MSG_TYPE_NETIF_LCORE_STATS          8
#define MSG_TYPE_BLKLST_ADD                 9
#define MSG_TYPE_BLKLST_DEL                 10
#define MSG_TYPE_STATS_GET                  11
#define MSG_TYPE_SAPOOL_STATS               12
#define MSG_TYPE_TC_STATS                   13
#define MSG_TYPE_CONN_GET                   14
#define MSG_TYPE_CONN_GET_ALL               15
#define MSG_TYPE_IPV6_STATS                 16
#define MSG_TYPE_ROUTE6                     17
#define MSG_TYPE_NEIGH_GET                  18

#define SOCKOPT_VERSION_MAJOR               1
#define SOCKOPT_VERSION_MINOR               0
#define SOCKOPT_VERSION_PATCH               0
#define SOCKOPT_VERSION     ((SOCKOPT_VERSION_MAJOR << 16) + \
        (SOCKOPT_VERSION_MINOR << 8) + SOCKOPT_VERSION_PATCH)

//#define SOCKOPT_MSG_BUFFER_SIZE             (1UL << 12)
#define SOCKOPT_ERRSTR_LEN                  64

typedef uint32_t sockoptid_t;

enum sockopt_type {
    SOCKOPT_GET = 0,
    SOCKOPT_SET,
    SOCKOPT_TYPE_MAX,
};

struct dpvs_sock_msg {
    uint32_t version;
    sockoptid_t id;
    enum sockopt_type type;
    size_t len;
    char data[0];
};

struct dpvs_sock_msg_reply {
    uint32_t version;
    sockoptid_t id;
    enum sockopt_type type;
    int errcode;
    char errstr[SOCKOPT_ERRSTR_LEN];
    size_t len;
    char data[0];
};

struct dpvs_sockopts {
    uint32_t version;
    struct list_head list;
    sockoptid_t set_opt_min;
    sockoptid_t set_opt_max;
    int (*set)(sockoptid_t opt, const void *in, size_t inlen);
    sockoptid_t get_opt_min;
    sockoptid_t get_opt_max;
    int (*get)(sockoptid_t opt, const void *in, size_t inlen, void **out, size_t *outlen);
};

int sockopt_ctl(void *arg);
int sockopt_register(struct dpvs_sockopts *sockopts);
int sockopt_unregister(struct dpvs_sockopts *sockopts);

void control_keyword_value_init(void);
void install_control_keywords(void);

int ctrl_init(void);
int ctrl_term(void);

#endif
