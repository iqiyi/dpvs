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
#include <fcntl.h>
#include "netif.h"
#include "netif.h"
#include "ipvs/sync_msg.h"
#include "ipvs/sync.h"
#include "ipvs/proto.h"
#include "ipvs/proto_tcp.h"
#include "parser/parser.h"

/* the sync_buff list head */
struct list_head dp_vs_sync_queue[DP_VS_SYNC_MAX];

/* current sync_buff for accepting new conn entries */
struct dp_vs_sync_buff *dp_vs_sync_curr_buff[DP_VS_SYNC_MAX];

struct dp_vs_sync_core g_dp_vs_sync_fwd_core;
struct dp_vs_sync_conf g_dp_vs_sync_conf;
static uint64_t cycles_per_sec = 0;

struct rte_ring *g_dp_vs_sync_tx_ring[DP_VS_SYNC_MAX];
struct rte_ring *g_dp_vs_sync_rx_ring[DPVS_MAX_LCORE];
int g_dp_vs_sync_send_fd[DP_VS_SYNC_MAX];

uint64_t g_start_cycles;
uint8_t g_req_timeout;
struct dpvs_timer g_req_timer;

struct dp_vs_sync_peer g_dp_vs_sync_fetch;
struct dp_vs_sync_peer g_dp_vs_sync_request;

static inline void dp_vs_sync_msg_dump(const char* info, int issend,
                                              struct dp_vs_sync_head* head)
{
    RTE_LOG(INFO, SYNC, "%s(syncid:%d %s %d) %s size %d\n",
            info ? info : "",
            g_dp_vs_sync_conf.syncid, issend ? "->" : "<-", head->syncid,
            head->type == DP_VS_SYNC_NEGO_INFO ? "nego info" : "conn sync",
            head->size);
}

static inline void dp_vs_sync_conn_dump(const char *msg, struct dp_vs_sync_conn *conn)
{
    char cbuf[64], vbuf[64], lbuf[64], dbuf[64];
    const char *caddr, *vaddr, *laddr, *daddr;

    caddr = inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)) ? cbuf : "::";
    vaddr = inet_ntop(conn->af, &conn->vaddr, vbuf, sizeof(vbuf)) ? vbuf : "::";
    laddr = inet_ntop(conn->af, &conn->laddr, lbuf, sizeof(lbuf)) ? lbuf : "::";
    daddr = inet_ntop(conn->af, &conn->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::";

    RTE_LOG(INFO, SYNC, "%s [%d] %s %s:%u %s:%u %s:%u %s:%u from lcore: %u\n",
            msg ? msg : "", rte_lcore_id(), inet_proto_name(conn->proto),
            caddr, ntohs(conn->cport), vaddr, ntohs(conn->vport),
            laddr, ntohs(conn->lport), daddr, ntohs(conn->dport), conn->lcore);
}

/*
 * Add an dp_vs_conn into the session sync tx ring.
 * */
void dp_vs_sync_conn_enqueue(struct dp_vs_conn *cp, dp_vs_sync_type type)
{
    struct dp_vs_sync_conn *s;
    int ret;

    if (!(s=rte_zmalloc(NULL,
                sizeof(struct dp_vs_sync_conn),
                RTE_CACHE_LINE_SIZE))) {
        RTE_LOG(WARNING, SYNC, "%s: no memory for a new dp_vs_sync_conn.\n", __func__);
        return;
    }

    /* copy members */
    s->af = cp->af;
    s->proto = cp->proto;
    s->cport = cp->cport;
    s->vport = cp->vport;
    s->lport = cp->lport;
    s->dport = cp->dport;

    s->caddr = cp->caddr;
    s->vaddr = cp->vaddr;
    s->laddr = cp->laddr;
    s->daddr = cp->daddr;
    s->qid   = cp->qid;
    s->lcore = cp->lcore;

    rte_memcpy(&s->fnat_seq, &cp->fnat_seq, sizeof(struct dp_vs_seq));
    s->rs_end_seq = cp->rs_end_seq;
    s->rs_end_ack = cp->rs_end_ack;

    s->flags = cp->flags & ~DPVS_CONN_F_HASHED;
    s->state = cp->state;

    ret = rte_ring_enqueue(g_dp_vs_sync_tx_ring[type], s);
    if (ret) {
        if (-ENOBUFS == ret)
            RTE_LOG(WARNING, SYNC, "%s: session %s sync tx ring quota exceeded.\n",
                   __func__, (DP_VS_SYNC_UNICAST== type) ? "unicat" : "mcast");
        else
            RTE_LOG(WARNING, SYNC, "%s: session %s sync tx ring enqueue failed. ret = %d\n",
                    __func__, (DP_VS_SYNC_UNICAST == type) ? "unicast" : "mcast", ret);
        rte_free(s);
    } else
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
        RTE_LOG(INFO, SYNC, "%s: session %s sync tx ring enqueue successed.\n",
                __func__, (DP_VS_SYNC_UNICAST == type) ? "unicat" : "mcast");
#endif
    return;
}

static void dp_vs_sync_buff_release(struct dp_vs_sync_buff *sb)
{
    rte_free(sb->mesg);
    rte_free(sb);
}

static inline struct dp_vs_sync_buff * dp_vs_sync_buff_create(void)
{
    struct dp_vs_sync_buff *sb;

    if (!(sb = rte_zmalloc(NULL,
            sizeof(struct dp_vs_sync_buff),
            RTE_CACHE_LINE_SIZE)))
        return NULL;

    if (!(sb->mesg = rte_zmalloc(NULL,
            g_dp_vs_sync_conf.send_mesg_maxlen,
            RTE_CACHE_LINE_SIZE))) {
        rte_free(sb);
        return NULL;
    }

    sb->mesg->head.syncid = g_dp_vs_sync_conf.syncid;
    sb->mesg->head.type = DP_VS_SYNC_CONN_INFO;
    sb->mesg->head.size = DP_VS_SYNC_MESG_HEADER_LEN;
    sb->mesg->nr_conns = 0;
    sb->head = (unsigned char *)sb->mesg + DP_VS_SYNC_MESG_HEADER_LEN;
    sb->end = (unsigned char *)sb->mesg + g_dp_vs_sync_conf.send_mesg_maxlen;
    sb->firstuse = rte_get_timer_cycles();

    return sb;
}

static inline void dp_vs_sync_buff_enqueue(struct dp_vs_sync_buff *sb,
                                                     dp_vs_sync_type type)
{
    list_add_tail(&sb->list, &dp_vs_sync_queue[type]);
}

static struct dp_vs_sync_buff * dp_vs_sync_buff_dequeue(dp_vs_sync_type type)
{
    struct dp_vs_sync_buff *sb;

    if (list_empty(&dp_vs_sync_queue[type])) {
        sb = NULL;
    } else {
        sb = list_entry(dp_vs_sync_queue[type].next, struct dp_vs_sync_buff, list);
        list_del(&sb->list);
    }

    return sb;
}

static void dp_vs_sync_conn_append_to_buff(struct dp_vs_sync_conn *sync_conn,
                                                        dp_vs_sync_type type)
{
    struct dp_vs_sync_mesg *m;
    int len = sizeof(struct dp_vs_sync_conn);

#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
    dp_vs_sync_conn_dump("sync conn append to buff", sync_conn);
#endif

    if (!dp_vs_sync_curr_buff[type]) {
        if (!(dp_vs_sync_curr_buff[type] = dp_vs_sync_buff_create())) {
            RTE_LOG(INFO, SYNC, "%s: create sync buffer failed.\n", __func__);
            return;
        }
    }

    m = dp_vs_sync_curr_buff[type]->mesg;
    rte_memcpy(dp_vs_sync_curr_buff[type]->head, sync_conn, len);
    m->nr_conns++;
    m->head.size += len;
    dp_vs_sync_curr_buff[type]->head += len;

    /**
    * if curr_sync_buff has no space for next one
    * then append it to dp_vs_sync_queue
    */
    if (dp_vs_sync_curr_buff[type]->head + len > dp_vs_sync_curr_buff[type]->end) {
        dp_vs_sync_buff_enqueue(dp_vs_sync_curr_buff[type], type);
        dp_vs_sync_curr_buff[type] = NULL;
    }

    return;
}

/**
 * get curr_sync_buff if it has been created for more
 * than g_sync_buff_delay seconds
 */
static struct dp_vs_sync_buff *
dp_vs_sync_expired_curr_sync_buff(dp_vs_sync_type type)
{
    struct dp_vs_sync_buff *sb = NULL;
    uint64_t time_diff = 0;

    if (NULL == dp_vs_sync_curr_buff[type])
        return NULL;

    time_diff = rte_get_timer_cycles() - dp_vs_sync_curr_buff[type]->firstuse;
    if(time_diff >= g_dp_vs_sync_conf.sync_buff_delay * cycles_per_sec) {
        sb = dp_vs_sync_curr_buff[type];
        dp_vs_sync_curr_buff[type] = NULL;
    }

    return sb;
}

static int dp_vs_sync_process_conn(const char *buffer, const int buflen)
{
    struct dp_vs_sync_mesg *m = (struct dp_vs_sync_mesg *)buffer;
    struct dp_vs_sync_conn *s = NULL;
    char *p = NULL;
    int i, res;

    p = (char *)(buffer + sizeof(struct dp_vs_sync_mesg));

    for (i = 0; i < m->nr_conns; i++) {
        if (!(s = rte_zmalloc(NULL, sizeof(struct dp_vs_sync_conn), RTE_CACHE_LINE_SIZE))) {
            RTE_LOG(ERR, SYNC, "%s: alloc sync conn node failed\n", __func__);
            return EDPVS_NOMEM;
        }

        rte_memcpy(s, p, sizeof(struct dp_vs_sync_conn));
        res = rte_ring_enqueue(g_dp_vs_sync_rx_ring[get_lcoreid(s->qid)], s);
        if (res) {
            if (unlikely(-EDQUOT == res)) {
                RTE_LOG(WARNING, SYNC, "%s: session sync rx ring of lcore %d quota exceeded\n",
                        __func__, get_lcoreid(s->qid));
            } else if (res < 0) {
                RTE_LOG(WARNING, SYNC, "%s: session sync rx ring of lcore %d enqueue failed\n",
                        __func__, get_lcoreid(s->qid));
            }
            rte_free(s);
        }

        p += sizeof(struct dp_vs_sync_conn);
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
        RTE_LOG(DEBUG, SYNC, "%s: current conn %d(total conn %d) from core %d queue %d enqueue rx rings[%d] %s\n",
            __func__, i + 1, m->nr_conns, s->lcore, s->qid, get_lcoreid(s->qid), 
            res ? "failed" : "succeed");
#endif
    }

    return EDPVS_OK;
}

static int dp_vs_sync_send_msg(int type, char* msg, int len,
                                        struct sockaddr_in* addr)
{
    if (DP_VS_SYNC_UNICAST== type) {
        return send_unicast_msg(g_dp_vs_sync_send_fd[type],
                                msg, len, addr);
    } else {
        return send_mcast_msg(g_dp_vs_sync_send_fd[type], msg, len);
    }
}

/**
 * Process received multicast message and create the corresponding
 * dp_vs_conn entries.
 */
static int dp_vs_sync_process_rx_msg(const char *buffer, const int buflen,
                                                struct sockaddr_in* remote_addr)
{
    struct dp_vs_sync_head *head = (struct dp_vs_sync_head *)buffer;

#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
    dp_vs_sync_msg_dump("recv", 0, head);
#endif

    if (buflen != head->size) {
        RTE_LOG(ERR, SYNC, "%s: recv conn sync message, buflen = %u, m->size = %d\n",
            __func__, buflen, head->size);
        return EDPVS_INVPKT;
    }

    /* syncid sanity check, ignore message sent from itself */
    if (head->syncid == g_dp_vs_sync_conf.syncid) {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
        RTE_LOG(DEBUG, SYNC,  "%s: ignoring incoming msg with syncid = %d\n",
            __func__, head->syncid);
#endif
        return EDPVS_OK;
    }

    if (DP_VS_SYNC_NEGO_INFO == head->type) {
        dp_vs_sync_recv_nego(buffer, buflen, remote_addr);
    } else {
        dp_vs_sync_process_conn(buffer, buflen);
    }

    return EDPVS_OK;
}

static int dp_vs_sync_tx_loop(dp_vs_sync_type type)
{
    uint16_t nb_rb = 0;
    uint16_t index = 0;
    struct dp_vs_sync_conn *conns[NETIF_MAX_PKT_BURST];
    struct dp_vs_sync_conn *conn;
    struct dp_vs_sync_buff *sb;

    nb_rb = rte_ring_dequeue_burst(g_dp_vs_sync_tx_ring[type], (void **)conns,
                                    NETIF_MAX_PKT_BURST, NULL);
    for (index = 0; index < nb_rb; index++) {
        conn = conns[index];
        dp_vs_sync_conn_append_to_buff(conn, type);
        rte_free(conn);
    }

    while ((sb = dp_vs_sync_buff_dequeue(type))) {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
        dp_vs_sync_msg_dump("send sync dequeue conn", 1, &(sb->mesg->head));
#endif
        dp_vs_sync_send_msg(type, (char *)sb->mesg, sb->mesg->head.size,
                           &g_dp_vs_sync_request.addr);
        dp_vs_sync_buff_release(sb);
    }

    if ((sb = dp_vs_sync_expired_curr_sync_buff(type))) {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
        dp_vs_sync_msg_dump("send curr sync buff conn", 1, &(sb->mesg->head));
#endif
        dp_vs_sync_send_msg(type, (char *)sb->mesg, sb->mesg->head.size,
                            &g_dp_vs_sync_request.addr);
        dp_vs_sync_buff_release(sb);
    }

    return EDPVS_OK;
}

static int dp_vs_session_sync_tx_loop(void)
{
    int index = 0;
    if (!g_dp_vs_sync_conf.sync_enable)
        return EDPVS_OK;

    if (!cycles_per_sec)
        cycles_per_sec = rte_get_timer_hz();

    g_dp_vs_sync_send_fd[DP_VS_SYNC_MCAST] = create_mcast_send_sock();
    if (g_dp_vs_sync_send_fd[DP_VS_SYNC_MCAST] == -1) {
        RTE_LOG(ERR, SYNC, "%s: failed to create mcast send sock.\n", __func__);
        return -1;
    }

    g_dp_vs_sync_send_fd[DP_VS_SYNC_UNICAST] = create_send_unicast_sock();
    if (g_dp_vs_sync_send_fd[DP_VS_SYNC_UNICAST] == -1) {
        RTE_LOG(ERR, SYNC, "%s: failed to create unicast send sock.\n", __func__);
        return -1;
    }

    for(;;) {
        for (index = 0; index < DP_VS_SYNC_MAX; index++) {
            dp_vs_sync_tx_loop(index);
        }
    }

    return 0;
}

static int dp_vs_sync_unicast_rx_loop(int sockfd, char *buffer, const size_t buflen)
{
    int len = 0;
    struct sockaddr_in remote_addr;
    memset(buffer, 0, buflen);

    len = receive_unicast_msg(sockfd, buffer, buflen, &remote_addr);
    if (len <= 0) {
        return EDPVS_OK;
    }
    dp_vs_sync_process_rx_msg(buffer, len, &remote_addr);

    return EDPVS_OK;
}

static int dp_vs_sync_mcast_rx_loop(int sockfd, char *buffer, const size_t buflen)
{
    int len = 0;
    struct sockaddr_in remote_addr;
    memset(buffer, 0, buflen);

    len = receive_mcast_msg(sockfd, buffer, buflen, &remote_addr);
    if (len <= 0) {
        return EDPVS_OK;
    }
    dp_vs_sync_process_rx_msg(buffer, len, &remote_addr);

    return EDPVS_OK;
}

static int dp_vs_session_sync_rx_loop(void)
{
    int res = 0;
    int unicast_fd = 0;
    int mcast_fd = 0;
    char* buff = NULL;
    fd_set fdsr;
    int maxsock;
    struct timeval tv;
    int ret = 0;

    if (!g_dp_vs_sync_conf.sync_enable)
        return EDPVS_OK;

    mcast_fd = create_mcast_receive_sock();
    if (mcast_fd == -1) {
        RTE_LOG(ERR, SYNC, "%s: failed to create receive sock.\n", __func__);
        return -1;
    }

    res = add_mcast_group(mcast_fd);
    if (res < 0) {
        RTE_LOG(ERR, SYNC, "%s: failed to add multicast group.\n", __func__);
        return -1;
    }

    unicast_fd = create_receive_unicast_sock();
    if (!(buff = rte_zmalloc(NULL,
            g_dp_vs_sync_conf.recv_mesg_maxlen,
            RTE_CACHE_LINE_SIZE))) {
        RTE_LOG(ERR, SYNC, "%s: alloc sync recv buffer failed\n", __func__);
        return EDPVS_NOMEM;
    }

    maxsock = MAX(unicast_fd, mcast_fd);
    for (;;) {
        FD_ZERO(&fdsr);
        FD_SET(mcast_fd,&fdsr);
        FD_SET(unicast_fd, &fdsr);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        ret = select(maxsock +1, &fdsr, NULL, NULL, &tv);
        if (ret < 0) {
            RTE_LOG(ERR, SYNC, "%s: select error ret %d\n", __func__, ret);
        } else if (ret == 0) {
            continue;
        }

        if (FD_ISSET(mcast_fd, & fdsr)) {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
            RTE_LOG(INFO, SYNC, "%s: mcastfd ready\n", __func__);
#endif
            dp_vs_sync_mcast_rx_loop(mcast_fd, buff, g_dp_vs_sync_conf.recv_mesg_maxlen);
        }

        if (FD_ISSET(unicast_fd, &fdsr)) {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
            RTE_LOG(INFO, SYNC, "%s: unicastfd ready\n", __func__);
#endif
            dp_vs_sync_unicast_rx_loop(unicast_fd, buff, g_dp_vs_sync_conf.recv_mesg_maxlen);
        }
    }

    rte_free(buff);
    return 0;
}

int dp_vs_sync_lcore_process_rx_msg(lcoreid_t cid)
{
    uint16_t idx = 0;
    uint16_t nb_rb = 0;
    struct dp_vs_sync_conn *conns[CONN_SYNC_MAX_PKT_BURST];
    struct dp_vs_sync_conn *conn = NULL;
    struct dp_vs_proto *pp = NULL;
    struct dp_vs_conn *cp = NULL;
    struct dp_vs_dest *dest = NULL;

#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
    char sbuf[64], dbuf[64];
#endif

    if (!g_dp_vs_sync_conf.sync_enable)
        return EDPVS_OK;

    nb_rb = rte_ring_dequeue_burst(g_dp_vs_sync_rx_ring[cid], (void **)conns,
                                        CONN_SYNC_MAX_PKT_BURST, NULL);
    for (idx = 0; idx < nb_rb; idx++) {
        conn = conns[idx];
        cp = dp_vs_conn_get(conn->af, 
                            conn->proto, 
                            &conn->caddr, 
                            &conn->vaddr,
                            conn->cport,
                            conn->vport,
                            NULL /*direct*/,
                            false);
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
            RTE_LOG(DEBUG, SYNC, "conn lookup: [%d] %s %s/%d -> %s/%d %s\n",
                    rte_lcore_id(), inet_proto_name(conn->proto),
                    inet_ntop(conn->af, &(conn->caddr), sbuf, sizeof(sbuf)) ? sbuf : "::", ntohs(conn->cport),
                    inet_ntop(conn->af, &(conn->vaddr), dbuf, sizeof(dbuf)) ? dbuf : "::", ntohs(conn->vport),
                    cp ? "already exits" : "does not exits");
#endif
        if (!cp) {
	        dest = dp_vs_find_dest(conn->af,
                        &conn->daddr,
                        conn->dport,
                        &conn->vaddr,
                        conn->vport,
                        conn->proto);
            if (!dest) {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
                RTE_LOG(DEBUG, SYNC, "dest lookup: [%d] %s %s/%d -> %s/%d %s\n",
                        rte_lcore_id(), inet_proto_name(conn->proto),
                        inet_ntop(conn->af, &(conn->vaddr), dbuf, sizeof(dbuf)) ? dbuf : "::", ntohs(conn->vport),
                        inet_ntop(conn->af, &(conn->daddr), sbuf, sizeof(sbuf)) ? sbuf : "::", ntohs(conn->dport),
                        "does not exits");
#endif
		        continue;
	        }
            cp = dp_vs_conn_copy_from_sync(conn, dest);
        } else { /* connection is already exists. change the state */
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
            RTE_LOG(DEBUG, SYNC, "conn lookup: [%d] %s %s/%d -> %s/%d state %d->%d\n",
                    rte_lcore_id(), inet_proto_name(conn->proto),
                    inet_ntop(conn->af, &(conn->caddr), sbuf, sizeof(sbuf)) ? sbuf : "::", ntohs(conn->cport),
                    inet_ntop(conn->af, &(conn->vaddr), dbuf, sizeof(dbuf)) ? dbuf : "::", ntohs(conn->vport),
                    cp->state, conn->state);
#endif
            cp->state = conn->state;
            pp = dp_vs_proto_lookup(cp->proto);
            if (pp && pp->timeout_table)
                cp->timeout.tv_sec = pp->timeout_table[cp->state];
            else
                cp->timeout.tv_sec = 60;

            cp->timeout.tv_usec = 0;
            if (cp->flags & DPVS_CONN_F_TEMPLATE)
                dpvs_timer_update(&cp->timer, &cp->timeout, true);
            else
                dpvs_timer_update(&cp->timer, &cp->timeout, false);
        }

        dp_vs_conn_put_no_reset(cp);
        rte_free(conn);
    }

    return EDPVS_OK;
}

static int dp_vs_sync_conn_expire(void *priv)
{
    struct dp_vs_conn *conn = priv;
    assert(conn);

#ifdef CONFIG_DPVS_SYNC_DEBUG
    char sbuf[64], dbuf[64];
    dp_vs_sync_conn_dump("sync conn expire", conn);
#endif

    if (conn->flags & DPVS_CONN_F_TEMPLATE) {
        dpvs_timer_cancel(&conn->conn_sync_timer, true);
    } else {
        dpvs_timer_cancel(&conn->conn_sync_timer, false);
    }

    dp_vs_sync_conn_enqueue(conn, DP_VS_SYNC_MCAST);
    return DTIMER_STOP;
}

int dp_vs_sync_conn_handler(struct dp_vs_conn *conn, int new_state)
{
    bool global = false;
    if (!g_dp_vs_sync_conf.sync_enable)
        return EDPVS_OK;

    if (conn->flags & DPVS_CONN_F_TEMPLATE) {
        global = true;
    }

    dpvs_timer_cancel(&conn->conn_sync_timer, global);

    if (new_state == DPVS_TCP_S_ESTABLISHED) {
        conn->conn_sync_timeout.tv_sec = g_dp_vs_sync_conf.sync_conn_elapse;
        conn->conn_sync_timeout.tv_usec = 0;
        dpvs_time_rand_delay(&conn->conn_sync_timeout, 1000000);
        if (conn->flags & DPVS_CONN_F_TEMPLATE) {
            dpvs_timer_sched(&conn->conn_sync_timer, &conn->conn_sync_timeout, 
                            dp_vs_sync_conn_expire, conn, true);
        } else {
            dpvs_timer_sched(&conn->conn_sync_timer, &conn->conn_sync_timeout, 
                            dp_vs_sync_conn_expire, conn, false);
        }
    } else if ( new_state == DPVS_TCP_S_FIN_WAIT ||
        new_state == DPVS_TCP_S_TIME_WAIT ||
        new_state == DPVS_TCP_S_CLOSE ||
        new_state == DPVS_TCP_S_CLOSE_WAIT ||
        new_state == DPVS_TCP_S_LAST_ACK) {
        dp_vs_sync_conn_enqueue(conn, DP_VS_SYNC_MCAST);
    }

    return EDPVS_OK;
}

int dp_vs_sync_set_rx_core(lcoreid_t cid)
{
    g_dp_vs_sync_conf.sync_rx_lcore = cid;
    RTE_LOG(INFO, SYNC, "%s: conn sync receive core id %d.\n",
            __func__, g_dp_vs_sync_conf.sync_rx_lcore);
    return EDPVS_OK;
}

int dp_vs_sync_set_tx_core(lcoreid_t cid)
{
    g_dp_vs_sync_conf.sync_tx_lcore = cid;
    RTE_LOG(INFO, SYNC, "%s: conn sync send core id %d.\n",
        __func__, g_dp_vs_sync_conf.sync_tx_lcore);
    return EDPVS_OK;
}

static int dp_vs_sync_head_init(struct dp_vs_sync_nego* info)
{
    int len = 0;
    len = sizeof(struct dp_vs_sync_nego);
    memset(info, 0, len);

    info->head.syncid = g_dp_vs_sync_conf.syncid;
    info->head.type = DP_VS_SYNC_NEGO_INFO;
    info->head.size = len;

    return EDPVS_OK;
}

static char* dp_vs_sync_code2str(int code)
{
    switch (code) {
        case DP_VS_SYNC_INFO_REPLY_CODE:
            return "reply";
        case DP_VS_SYNC_INFO_PROBE_CODE:
            return "probe";
        case DP_VS_SYNC_INFO_FETCH_CODE:
            return "fetch";
        case DP_VS_SYNC_INFO_DONE_CODE:
            return "done";
        default:
            return "unknown";
    }
}

static int dp_vs_sync_send_nego(uint8_t peer_syncid, int code,
                                        int type, struct sockaddr_in* remote_addr)
{
    struct dp_vs_sync_nego full_req;
    int len = 0;

    len = sizeof(struct dp_vs_sync_nego);
    dp_vs_sync_head_init(&full_req);
    full_req.code = code;
    full_req.peer_syncid = peer_syncid;
    full_req.uptime = rte_get_timer_cycles() - g_start_cycles;

    RTE_LOG(INFO, SYNC, "(syncid:%d -> %d)send sync %s"
            " uptime %ld remote addr %s\n",
            full_req.head.syncid, full_req.peer_syncid,
            dp_vs_sync_code2str(full_req.code),
            full_req.uptime,
            remote_addr ? inet_ntoa(remote_addr->sin_addr) : "null");

    dp_vs_sync_send_msg(type, (char *)&full_req, len, remote_addr);

    return EDPVS_OK;
}

static int dp_vs_sync_send_fetch_code(void* arg)
{
    dpvs_timer_cancel(&g_req_timer, true);
    g_req_timeout = 1;
    dp_vs_sync_send_nego(g_dp_vs_sync_fetch.syncid, 
        DP_VS_SYNC_INFO_FETCH_CODE, DP_VS_SYNC_UNICAST,
        &g_dp_vs_sync_fetch.addr);

    return DTIMER_STOP;
}

static void dp_vs_sync_full_is_all_end(void)
{
    int cid = 0;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if ((cid == rte_get_master_lcore()) || !is_lcore_id_valid(cid))
            continue;

        if (!DP_VS_SYNC_FULL_IS_END(cid))
            break;
    }

    if (cid >= DPVS_MAX_LCORE) {
#ifdef CONFIG_DPVS_SYNC_DEBUG
        RTE_LOG(INFO, SYNC, "(syncid:%d -> %d) full sync is complete.\n",
            g_dp_vs_sync_conf.syncid, g_dp_vs_sync_request.syncid);
#endif
        dp_vs_sync_send_nego(g_dp_vs_sync_request.syncid,
                            DP_VS_SYNC_INFO_DONE_CODE, DP_VS_SYNC_UNICAST,
                            &g_dp_vs_sync_request.addr);
    }

    return;
}

int dp_vs_sync_full_start(lcoreid_t cid)
{
    g_dp_vs_sync_fwd_core.fwd_core[cid].start = true;
    g_dp_vs_sync_fwd_core.fwd_core[cid].end = false;
    g_dp_vs_sync_fwd_core.fwd_core[cid].last_index = 0;
    return EDPVS_OK;
}

int dp_vs_sync_full_end(lcoreid_t cid)
{
    g_dp_vs_sync_fwd_core.fwd_core[cid].end = true;
    g_dp_vs_sync_fwd_core.fwd_core[cid].start = false;

    dp_vs_sync_full_is_all_end();
    return EDPVS_OK;
}

static int dp_vs_sync_recv_probe_code(struct dp_vs_sync_nego* req,
                                            struct sockaddr_in* remote_addr)
{
    return dp_vs_sync_send_nego(req->head.syncid, DP_VS_SYNC_INFO_REPLY_CODE,
                                DP_VS_SYNC_UNICAST, remote_addr);
}

static int dp_vs_sync_recv_reply_code(struct dp_vs_sync_nego* req,
                                            struct sockaddr_in* remote_addr)
{
    if (req->peer_syncid != g_dp_vs_sync_conf.syncid || g_req_timeout)
        return EDPVS_OK;

    if (req->uptime > g_dp_vs_sync_fetch.uptime) {
        g_dp_vs_sync_fetch.uptime = req->uptime;
        g_dp_vs_sync_fetch.syncid = req->head.syncid;
        memcpy(&g_dp_vs_sync_fetch.addr, remote_addr,
            sizeof(g_dp_vs_sync_fetch.addr));
    }

    return EDPVS_OK;
}

static int dp_vs_sync_recv_fetch_code(struct dp_vs_sync_nego* req,
                                        struct sockaddr_in* remote_addr)
{
    int cid = 0;

    if (req->peer_syncid != g_dp_vs_sync_conf.syncid)
        return EDPVS_OK;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if ((cid == rte_get_master_lcore()) || !is_lcore_id_valid(cid))
            continue;
        dp_vs_sync_full_start(cid);
    }

    g_dp_vs_sync_request.syncid = req->head.syncid;
    memcpy(&g_dp_vs_sync_request.addr.sin_addr,
        &remote_addr->sin_addr, sizeof(g_dp_vs_sync_request.addr.sin_addr));

    return EDPVS_OK;
}

static int dp_vs_sync_recv_done_code(struct dp_vs_sync_nego* req,
                                        struct sockaddr_in* remote_addr)
{
    if (req->peer_syncid != g_dp_vs_sync_conf.syncid)
        return EDPVS_OK;

    RTE_LOG(INFO, SYNC, "%s:(syncid %d <- %d) full sync is complete.\n",
        __func__, g_dp_vs_sync_conf.syncid, req->head.syncid);

    return EDPVS_OK;
}


int dp_vs_sync_recv_nego(const char * buf, int len,
                                struct sockaddr_in* remote_addr)
{
    struct dp_vs_sync_nego* req = (struct dp_vs_sync_nego*)buf;

    if (len != sizeof(struct dp_vs_sync_nego)) {
        RTE_LOG(ERR, SYNC, "%s: recv request sync message len error"
            "(actual length = %d, expected length = %d)\n",
            __func__, len, sizeof(struct dp_vs_sync_nego));
        return EDPVS_INVPKT;
    }

    RTE_LOG(INFO, SYNC, "(syncid:%d <- %d)recv sync %s"
        " uptime %ld remote addr %s\n",
        g_dp_vs_sync_conf.syncid, req->head.syncid,
        dp_vs_sync_code2str(req->code), req->uptime,
        inet_ntoa(remote_addr->sin_addr));

    switch (req->code) {
        case DP_VS_SYNC_INFO_REPLY_CODE:
            dp_vs_sync_recv_reply_code(req, remote_addr);
            break;
        case DP_VS_SYNC_INFO_PROBE_CODE:
            dp_vs_sync_recv_probe_code(req, remote_addr);
            break;
        case DP_VS_SYNC_INFO_FETCH_CODE:
            dp_vs_sync_recv_fetch_code(req, remote_addr);
            break;
        case DP_VS_SYNC_INFO_DONE_CODE:
            dp_vs_sync_recv_done_code(req, remote_addr);
            break;
        default:
            RTE_LOG(ERR, SYNC, "(syncid:%d <- %d)recv sync code %d"
                " uptime %ld remote addr %s\n",
                g_dp_vs_sync_conf.syncid, req->head.syncid,
                req->code, req->uptime,
                inet_ntoa(remote_addr->sin_addr));
            return EDPVS_INVPKT;
    }

    return EDPVS_OK;
}

int dp_vs_sync_conn_start(void)
{
    struct timeval tv;
    static int start_full_sync = 0;

    if (start_full_sync) {
        RTE_LOG(DEBUG, SYNC, "%s:(syncid:%d) already start conn sync.\n",
                __func__, g_dp_vs_sync_conf.syncid);
        return 0;
    }

    start_full_sync = 1;
    dp_vs_sync_send_nego(0, DP_VS_SYNC_INFO_PROBE_CODE,
                         DP_VS_SYNC_MCAST, NULL);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    dpvs_timer_sched(&g_req_timer, &tv, 
                    dp_vs_sync_send_fetch_code, NULL, true);

#ifdef CONFIG_DPVS_SYNC_DEBUG
    RTE_LOG(INFO, SYNC, "%s:(syncid:%d) start conn sync.\n",
            __func__, g_dp_vs_sync_conf.syncid);
#endif
    return EDPVS_OK;
}

void dp_vs_sync_run_loop(lcoreid_t cid)
{
    if (cid == g_dp_vs_sync_conf.sync_rx_lcore) {
        dp_vs_session_sync_rx_loop();
    } else if (cid == g_dp_vs_sync_conf.sync_tx_lcore) {
        dp_vs_session_sync_tx_loop();
    }
}

char* dp_vs_sync_laddr_ifname(void)
{
    return g_dp_vs_sync_conf.laddr_ifname;
}

static int dp_vs_set_sync_mesg_maxlen(void)
{
	int num = 0;
    int mtu = 0;

    mtu = get_sock_mtu();

    num = (mtu - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr) - 
           DP_VS_SYNC_MESG_HEADER_LEN - 20) / DP_VS_SYNC_CONN_SIZE;
    
	g_dp_vs_sync_conf.send_mesg_maxlen =
		DP_VS_SYNC_MESG_HEADER_LEN + DP_VS_SYNC_CONN_SIZE * num;
    RTE_LOG(INFO, SYNC, "%s: send_mesg_maxlen is %d.\n", __func__,
            g_dp_vs_sync_conf.send_mesg_maxlen);

    g_dp_vs_sync_conf.recv_mesg_maxlen = mtu - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr);
    RTE_LOG(INFO, SYNC, "%s: recv_mesg_maxlen is %d.\n", __func__,
            g_dp_vs_sync_conf.recv_mesg_maxlen);

	return 0;
}

static int dp_vs_sync_conf_init(void)
{
    if (!g_dp_vs_sync_conf.sync_buff_delay) {
        g_dp_vs_sync_conf.sync_buff_delay = DP_VS_SYNC_DELAY_SECONDS;

        RTE_LOG(INFO, SYNC, "%s: sync curr buffer delay time is %d.\n", __func__,
                g_dp_vs_sync_conf.sync_buff_delay);
    }

    if (!g_dp_vs_sync_conf.sync_conn_elapse) {
        g_dp_vs_sync_conf.sync_conn_elapse = DP_VS_SYNC_DELAY_SECONDS;

        RTE_LOG(INFO, SYNC, "%s: sync conn delay time is %d.\n", __func__,
                g_dp_vs_sync_conf.sync_conn_elapse);
    }

    dp_vs_set_sync_mesg_maxlen();
    return EDPVS_OK;
}

int dp_vs_sync_init(void)
{
    char ring_name[128];
    uint8_t cid;
    int index = 0;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        snprintf(ring_name, sizeof(ring_name), "session_sync_rx_ring_%d", cid);
        g_dp_vs_sync_rx_ring[cid] = rte_ring_create(ring_name, CONN_SYNC_RING_SIZE,
                                                        rte_socket_id(), RING_F_SP_ENQ);
        if (unlikely(!g_dp_vs_sync_rx_ring[cid])) {
            RTE_LOG(ERR, SYNC, "%s: Failed to create rx ring on lcore %d.\n",
                __func__, cid);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    for (index = 0; index < DP_VS_SYNC_MAX; index++) {
        INIT_LIST_HEAD(&dp_vs_sync_queue[index]);
        dp_vs_sync_curr_buff[index] = NULL;

        snprintf(ring_name, sizeof(ring_name), "session_sync_tx_ring_%d", index);
        g_dp_vs_sync_tx_ring[index] = rte_ring_create(ring_name, CONN_SYNC_RING_SIZE,
                                        rte_socket_id(), RING_F_SC_DEQ);
        if (unlikely(!g_dp_vs_sync_tx_ring[index])) {
            RTE_LOG(ERR, SYNC, "[%s] Failed to create tx ring.\n", __func__);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    g_start_cycles = rte_get_timer_cycles();

    dp_vs_sync_conf_init();

    return EDPVS_OK;
}

int dp_vs_sync_term(void)
{
    lcoreid_t cid = 0;
    int index = 0;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        rte_ring_free(g_dp_vs_sync_rx_ring[cid]);
    }

    for (index = 0; index < DP_VS_SYNC_MAX; index++) {
        rte_ring_free(g_dp_vs_sync_tx_ring[index]);
    }

    return EDPVS_OK;
}

static void dp_vs_sync_enable_handler(vector_t tokens)
{
    g_dp_vs_sync_conf.sync_enable = 1;
    RTE_LOG(INFO, SYNC, "%s: g_sync_sesion_enable ON.\n", __func__);
}

static void dp_vs_sync_elapse_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int delay = 0;
    assert(str);

    delay = atoi(str);
    if (delay > 30 || delay < 0) {
        RTE_LOG(WARNING, SYNC, "invalid sync_conn_elapse %s, using default %d\n",
                str, DP_VS_SYNC_DELAY_SECONDS);
        delay = DP_VS_SYNC_DELAY_SECONDS;
    } else {
        RTE_LOG(INFO, SYNC, "sync_conn_elapse = %d\n", delay);
    }

    g_dp_vs_sync_conf.sync_conn_elapse = delay;

    FREE_PTR(str);
}

static void dp_vs_sync_buff_delay_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int delay = 0;
    assert(str);

    delay = atoi(str);
    if (delay > 30 || delay < 0) {
        RTE_LOG(WARNING, SYNC, "invalid sync_buff_delay %s, using default %d\n",
                str, DP_VS_SYNC_DELAY_SECONDS);
        delay = DP_VS_SYNC_DELAY_SECONDS;
    } else {
        RTE_LOG(INFO, SYNC, "sync_buff_delay = %d\n", delay);
    }

    g_dp_vs_sync_conf.sync_buff_delay = delay;

    FREE_PTR(str);
}

static void dp_vs_sync_conn_count_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int count = 0;
    assert(str);

    count = atoi(str);
    if (count < 0) {
        RTE_LOG(WARNING, SYNC, "invalid count of sync per time %s, using default %d\n",
                str, DP_VS_SYNC_CONN_CNT_PER_TIME);
        count = DP_VS_SYNC_CONN_CNT_PER_TIME;
    } else {
        RTE_LOG(INFO, SYNC, "sync_per_time_cnt = %d\n", count);
    }

    g_dp_vs_sync_conf.sync_per_time_cnt = count;

    FREE_PTR(str);
}

static void dp_vs_sync_laddr_ifname_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);

    rte_memcpy(g_dp_vs_sync_conf.laddr_ifname, str, strlen(str));
    RTE_LOG(INFO, SYNC, "%s: laddr_ifname is %s\n",
        __func__, g_dp_vs_sync_conf.laddr_ifname);

    FREE_PTR(str);
}

static void dp_vs_sync_syncid_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int id = 0;
    assert(str);

    id = atoi(str);
    if (id > 65534 || id < 1) {
        RTE_LOG(WARNING, SYNC, "invalid dp_vs_syncid %s, using default %d\n",
                str, 1);
        g_dp_vs_sync_conf.syncid = 1;
    } else {
        RTE_LOG(INFO, SYNC, "dp_vs_syncid = %d\n", id);
        g_dp_vs_sync_conf.syncid = id;
    }

    FREE_PTR(str);
}

void install_session_sync_keywords(void)
{
    install_keyword_root("session_sync", NULL);
    install_keyword("sync_session_enable", dp_vs_sync_enable_handler, KW_TYPE_INIT);
    install_keyword("sync_session_elapse", dp_vs_sync_elapse_handler, KW_TYPE_INIT);
    install_keyword("sync_buff_delay", dp_vs_sync_buff_delay_handler, KW_TYPE_INIT);
    install_keyword("sync_conn_count", dp_vs_sync_conn_count_handler, KW_TYPE_INIT);
    install_keyword("laddr_ifname", dp_vs_sync_laddr_ifname_handler, KW_TYPE_INIT);
    install_keyword("sync_id", dp_vs_sync_syncid_handler, KW_TYPE_INIT);
    install_keyword("socket", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_session_sync_sock_keywords();
    install_sublevel_end();
}
