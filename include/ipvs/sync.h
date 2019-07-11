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
#ifndef __DPVS_SYNC_H__
#define __DPVS_SYNC_H__

#include "common.h"
#include "list.h"
#include "ipvs/conn.h"

#define RTE_LOGTYPE_SYNC RTE_LOGTYPE_USER1

#define CONN_SYNC_RING_SIZE     2048

/* maximum pkt number at a single burst */
#define CONN_SYNC_MAX_PKT_BURST         32

/*
 *  DPVS sync connection entry
 */
struct dp_vs_sync_conn {
    uint8_t            reserved;

    int                     af;
    uint8_t                 proto;
    union inet_addr         caddr;  /* Client address */
    union inet_addr         vaddr;  /* Virtual address */
    union inet_addr         laddr;  /* director Local address */
    union inet_addr         daddr;  /* Destination (RS) address */
    uint16_t                cport;
    uint16_t                vport;
    uint16_t                lport;
    uint16_t                dport;
    queueid_t               qid;
    lcoreid_t               lcore;

    /* Flags and state transition */
    uint16_t                flags;          /* status flags */
    uint16_t                state;          /* state info */

    /* The sequence options start here */
    struct dp_vs_seq        fnat_seq;
    uint32_t                rs_end_seq;
    uint32_t                rs_end_ack;
};

struct dp_vs_sync_head {
    uint8_t                    type;
    uint8_t                    syncid;
    uint16_t                   size;
};

struct dp_vs_sync_mesg {
    struct dp_vs_sync_head     head;
    uint8_t                    nr_conns;
};

struct dp_vs_sync_nego {
    struct dp_vs_sync_head head;
    uint32_t               code;
    uint8_t                peer_syncid;
    uint64_t               uptime;
};

struct dp_vs_sync_peer {
    uint8_t syncid;
    uint64_t uptime;
    struct sockaddr_in addr;
};

struct dp_vs_sync_buff {
    struct list_head        list;
    uint64_t           firstuse;

    /* pointers for the message data */
    struct dp_vs_sync_mesg  *mesg;
    unsigned char           *head;
    unsigned char           *end;
};

struct dp_vs_sync_fwd_core {
    int     cid;
    int     last_index;
    bool    start;
    bool    end;
};

struct dp_vs_sync_core {
    int core_cnt;
    struct dp_vs_sync_fwd_core fwd_core[DPVS_MAX_LCORE];
};

typedef enum {
    DP_VS_SYNC_MCAST = 0,
    DP_VS_SYNC_UNICAST = 1,
    DP_VS_SYNC_MAX  = 2,
} dp_vs_sync_type;

struct dp_vs_sync_conf {
    lcoreid_t sync_rx_lcore;
    lcoreid_t sync_tx_lcore;
    int syncid;
    int sync_enable;
    int sync_conn_elapse;
    int sync_buff_delay;
    int sync_per_time_cnt;
    int send_mesg_maxlen;
    int recv_mesg_maxlen;
    char laddr_ifname[IFNAMSIZ];
};

#define DP_VS_SYNC_CONN_SIZE            (sizeof(struct dp_vs_sync_conn))
#define DP_VS_SYNC_MESG_HEADER_LEN      (sizeof(struct dp_vs_sync_mesg))

#define DP_VS_SYNC_CONN_INFO         (0)
#define DP_VS_SYNC_NEGO_INFO         (1)

#define DP_VS_SYNC_INFO_PROBE_CODE       (0)
#define DP_VS_SYNC_INFO_REPLY_CODE       (1)
#define DP_VS_SYNC_INFO_FETCH_CODE       (2)
#define DP_VS_SYNC_INFO_DONE_CODE        (3)

#define DP_VS_SYNC_DELAY_SECONDS (2)
#define DP_VS_SYNC_CONN_CNT_PER_TIME (128)

#define MAX(x, y) ((x) > (y) ? (x) : (y))

extern struct dp_vs_sync_core g_dp_vs_sync_fwd_core;
#define DP_VS_SYNC_FULL_IS_START(cid) \
    (g_dp_vs_sync_fwd_core.fwd_core[cid].start == true)

#define DP_VS_SYNC_FULL_IS_END(cid) \
    (g_dp_vs_sync_fwd_core.fwd_core[cid].end == true)

#define DP_VS_SYNC_FULL_SET_LAST_INDEX(cid, index) \
    (g_dp_vs_sync_fwd_core.fwd_core[cid].last_index = index)

#define DP_VS_SYNC_FULL_GET_LAST_INDEX(cid) \
    (g_dp_vs_sync_fwd_core.fwd_core[cid].last_index)

extern struct dp_vs_sync_conf g_dp_vs_sync_conf;
#define DP_VS_SYNC_FULL_CNT_PER_TIME \
    g_dp_vs_sync_conf.sync_per_time_cnt

void dp_vs_sync_conn_enqueue(struct dp_vs_conn *cp, dp_vs_sync_type type);
int dp_vs_sync_conn_handler(struct dp_vs_conn *conn, int new_state);
int dp_vs_sync_lcore_process_rx_msg(lcoreid_t cid);
int dp_vs_sync_set_rx_core(lcoreid_t cid);
int dp_vs_sync_set_tx_core(lcoreid_t cid);
void dp_vs_sync_run_loop(lcoreid_t cid);
int dp_vs_sync_init(void);
int dp_vs_sync_term(void);

int dp_vs_sync_recv_nego(const char * buf, int len,
                                struct sockaddr_in* remote_addr);
int dp_vs_sync_full_end(lcoreid_t cid);
int dp_vs_sync_full_start(lcoreid_t cid);
int dp_vs_sync_conn_start(void);
char* dp_vs_sync_laddr_ifname(void);
void install_session_sync_keywords(void);

#endif /* __DPVS_SYNC_H__ */
