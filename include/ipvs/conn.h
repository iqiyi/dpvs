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
#ifndef __DPVS_CONN_H__
#define __DPVS_CONN_H__
#include <arpa/inet.h>
#include "conf/common.h"
#include "list.h"
#include "dpdk.h"
#include "timer.h"
#include "inet.h"
#include "ipv4.h"
#include "ipvs/conn.h"
#include "ipvs/proto.h"
#include "ipvs/service.h"
#include "ipvs/redirect.h"

enum {
    DPVS_CONN_DIR_INBOUND = 0,
    DPVS_CONN_DIR_OUTBOUND,
    DPVS_CONN_DIR_MAX,
};

/*
 * DPVS_CONN_F_XXX should always be the same with IP_VS_CONN_F_XXX.
 */
/* Conn flags used by both DPVS and Keepalived*/
#define DPVS_CONN_F_SYNPROXY                IP_VS_CONN_F_SYNPROXY
#define DPVS_CONN_F_EXPIRE_QUIESCENT        IP_VS_CONN_F_EXPIRE_QUIESCENT
/* Conn flags used by DPVS only */
#define DPVS_CONN_F_HASHED                  IP_VS_CONN_F_HASHED
#define DPVS_CONN_F_INACTIVE                IP_VS_CONN_F_INACTIVE
#define DPVS_CONN_F_TEMPLATE                IP_VS_CONN_F_TEMPLATE
#define DPVS_CONN_F_ONE_PACKET              IP_VS_CONN_F_ONE_PACKET
#define DPVS_CONN_F_IN_TIMER                IP_VS_CONN_F_IN_TIMER
#define DPVS_CONN_F_REDIRECT_HASHED         IP_VS_CONN_F_REDIRECT_HASHED
#define DPVS_CONN_F_NOFASTXMIT              IP_VS_CONN_F_NOFASTXMIT

struct dp_vs_conn_param {
    int                 af;
    uint8_t             proto;
    const union inet_addr *caddr;
    const union inet_addr *vaddr;
    uint16_t            cport;
    uint16_t            vport;
    uint16_t            ct_dport; /* RS port for template connection */
};

struct conn_tuple_hash {
    struct list_head    list;
    int                 direct; /* inbound/outbound */

    /* tuple info */
    int                 af;
    uint8_t             proto;
    union inet_addr     saddr;  /* pkt's source addr */
    union inet_addr     daddr;  /* pkt's dest addr */
    uint16_t            sport;
    uint16_t            dport;
} __rte_cache_aligned;

struct dp_vs_conn_stats {
    rte_atomic64_t      inpkts;
    rte_atomic64_t      inbytes;
    rte_atomic64_t      outpkts;
    rte_atomic64_t      outbytes;
} __rte_cache_aligned;

struct dp_vs_proto;

struct dp_vs_conn {
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

    struct rte_mempool      *connpool;
    struct conn_tuple_hash  tuplehash[DPVS_CONN_DIR_MAX];
    rte_atomic32_t          refcnt;
    struct dpvs_timer       timer;
    struct timeval          timeout;
    lcoreid_t               lcore;
    struct dp_vs_dest       *dest;  /* real server */
    void                    *prot_data;  /* protocol specific data */

    /* for FNAT */
    struct dp_vs_laddr      *local; /* local address */
    struct dp_vs_seq        fnat_seq;

    /* save last SEQ/ACK from RS for RST when conn expire*/
    uint32_t                rs_end_seq;
    uint32_t                rs_end_ack;

    int (*packet_xmit)(struct dp_vs_proto *prot,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);
    int (*packet_out_xmit)(struct dp_vs_proto *prot,
                        struct dp_vs_conn *conn,
                        struct rte_mbuf *mbuf);

    /* L2 fast xmit */
    struct rte_ether_addr   in_smac;
    struct rte_ether_addr   in_dmac;
    struct rte_ether_addr   out_smac;
    struct rte_ether_addr   out_dmac;

    /* route for neigbour */
    struct netif_port       *in_dev;    /* inside to rs*/
    struct netif_port       *out_dev;   /* outside to client*/
    union inet_addr         in_nexthop;  /* to rs*/
    union inet_addr         out_nexthop; /* to client*/

#ifdef CONFIG_DPVS_IPVS_STATS_DEBUG
    /* statistics */
    struct dp_vs_conn_stats stats;
#endif

    /* synproxy related members */
    struct dp_vs_seq syn_proxy_seq;     /* seq used in synproxy */
    struct list_head ack_mbuf;          /* ack mbuf saved in step2 */
    uint16_t ack_num;                   /* ack mbuf number stored */
    uint8_t wscale_vs;                  /* outbound wscale factor to client */
    uint8_t wscale_rs;                  /* outbound wscale factor from rs */
    struct rte_mbuf *syn_mbuf;          /* saved rs syn packet for retransmition */
    rte_atomic32_t syn_retry_max;       /* syn retransmition max packets */

    /* add for stopping ack storm */
    uint32_t last_seq;                  /* seq of the last ack packet */
    uint32_t last_ack_seq;              /* ack seq of the last ack packet */
    rte_atomic32_t dup_ack_cnt;         /* count of repeated ack packets */

    uint8_t pp_version;                 /* proxy protocol version */
    uint8_t pp_sent;                    /* proxy protocol data has sent */

    /* flags and state transition */
    volatile uint16_t       flags;
    volatile uint16_t       state;
    volatile uint16_t       old_state;  /* old state, to be used for state transition
                                           triggered synchronization */
    /* controll members */
    struct dp_vs_conn *control;         /* master who controlls me */
    rte_atomic32_t n_control;           /* number of connections controlled by me*/
#ifdef CONFIG_DPVS_IPVS_STATS_DEBUG
    uint64_t ctime;                     /* create time */
#endif

    /* connection redirect in fnat/snat/nat modes */
    struct dp_vs_redirect  *redirect;

} __rte_cache_aligned;

/* for syn-proxy to save all ack packet in conn before rs's syn-ack arrives */
struct dp_vs_synproxy_ack_pakcet {
    struct list_head list;
    struct rte_mbuf *mbuf;
} __rte_cache_aligned;

/* helpers */
#define tuplehash_in(c)         ((c)->tuplehash[DPVS_CONN_DIR_INBOUND])
#define tuplehash_out(c)        ((c)->tuplehash[DPVS_CONN_DIR_OUTBOUND])

int dp_vs_conn_init(void);
int dp_vs_conn_term(void);

struct dp_vs_conn *
dp_vs_conn_new(struct rte_mbuf *mbuf,
               const struct dp_vs_iphdr *iph,
               struct dp_vs_conn_param *param,
               struct dp_vs_dest *dest,
               uint32_t flags);
int dp_vs_conn_del(struct dp_vs_conn *conn);

struct dp_vs_conn *
dp_vs_conn_get(int af, uint16_t proto,
                const union inet_addr *saddr,
                const union inet_addr *daddr,
                uint16_t sport, uint16_t dport,
                int *dir, bool reverse);

struct dp_vs_conn *
dp_vs_ct_in_get(int af, uint16_t proto,
                const union inet_addr *saddr,
                const union inet_addr *daddr,
                uint16_t sport, uint16_t dport);

void dp_vs_conn_put(struct dp_vs_conn *conn);
/* put conn without reset the timer */
void dp_vs_conn_put_no_reset(struct dp_vs_conn *conn);

unsigned dp_vs_conn_get_timeout(struct dp_vs_conn *conn);
void dp_vs_conn_set_timeout(struct dp_vs_conn *conn, struct dp_vs_proto *pp);

void dp_vs_conn_expire_now(struct dp_vs_conn *conn);

void ipvs_conn_keyword_value_init(void);
void install_ipvs_conn_keywords(void);

static inline void dp_vs_conn_fill_param(int af, uint8_t proto,
        const union inet_addr *caddr, const union inet_addr *vaddr,
        uint16_t cport, uint16_t vport, uint16_t ct_dport,
        struct dp_vs_conn_param *param)
{
    param->af       = af;
    param->proto    = proto;
    param->caddr    = caddr;
    param->vaddr    = vaddr;
    param->cport    = cport;
    param->vport    = vport;
    param->ct_dport = ct_dport; /* only for template connection */
}


int dp_vs_check_template(struct dp_vs_conn *ct);

static inline void dp_vs_control_del(struct dp_vs_conn *conn)
{
    struct dp_vs_conn *ctl_conn = conn->control;
    char cbuf[64], vbuf[64];

    if (!ctl_conn) {
#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, IPVS, "%s: request control DEL for uncontrolled: "
                "%s:%u to %s:%u\n", __func__,
                inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)),
                ntohs(conn->cport),
                inet_ntop(conn->af, &conn->vaddr, vbuf, sizeof(vbuf)),
                ntohs(conn->vport));
#endif
        return;
    }

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "%s: deleting control for: conn.client=%s:%u "
            "ctrl_conn.client=%s:%u\n", __func__,
            inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)),
            ntohs(conn->cport),
            inet_ntop(conn->af, &ctl_conn->vaddr, cbuf, sizeof(cbuf)),
            ntohs(conn->vport));
#endif
    conn->control = NULL;
    if (rte_atomic32_read(&ctl_conn->n_control) == 0) {
        RTE_LOG(ERR, IPVS, "%s: BUG control DEL with zero n_control: "
                "%s:%u to %s:%u\n", __func__,
                inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)),
                ntohs(conn->cport),
                inet_ntop(conn->af, &conn->vaddr, vbuf, sizeof(vbuf)),
                ntohs(conn->vport));
        return;
    }
    rte_atomic32_dec(&ctl_conn->n_control);
}

static inline void dp_vs_control_add(struct dp_vs_conn *conn, struct dp_vs_conn *ctl_conn)
{
    char cbuf[64], vbuf[64];

    if (unlikely(conn->control != NULL)) {
        RTE_LOG(ERR, IPVS, "%s: request control ADD for already controlled conn: "
                "%s:%u to %s:%u\n", __func__,
                inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)) ? cbuf : "::",
                ntohs(conn->cport),
                inet_ntop(conn->af, &conn->vaddr, vbuf, sizeof(vbuf)) ? vbuf : "::",
                ntohs(conn->vport));
        dp_vs_control_del(conn);
    }
#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "%s: Adding control for: conn.client=%s:%u "
            "ctrl_conn.client=%s:%u\n", __func__,
            inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)) ? cbuf : "::",
            ntohs(conn->cport),
            inet_ntop(conn->af, &ctl_conn->caddr, vbuf, sizeof(cbuf)) ? cbuf : "::",
            ntohs(ctl_conn->cport));
#endif
    conn->control = ctl_conn;
    rte_atomic32_inc(&ctl_conn->n_control);
}

static inline bool
dp_vs_conn_is_template(struct dp_vs_conn *conn)
{
    return  (conn->flags & DPVS_CONN_F_TEMPLATE) ? true : false;
}

static inline void
dp_vs_conn_set_template(struct dp_vs_conn *conn)
{
    conn->flags |= DPVS_CONN_F_TEMPLATE;
}

static inline bool
dp_vs_conn_is_in_timer(struct dp_vs_conn *conn)
{
    return (conn->flags & DPVS_CONN_F_IN_TIMER) ? true : false;
}

static inline void
dp_vs_conn_set_in_timer(struct dp_vs_conn *conn)
{
    conn->flags |= DPVS_CONN_F_IN_TIMER;
}

static inline void
dp_vs_conn_clear_in_timer(struct dp_vs_conn *conn)
{
    conn->flags &= ~DPVS_CONN_F_IN_TIMER;
}

static inline bool
dp_vs_conn_is_redirect_hashed(struct dp_vs_conn *conn)
{
    return  (conn->flags & DPVS_CONN_F_REDIRECT_HASHED) ? true : false;
}

static inline void
dp_vs_conn_set_redirect_hashed(struct dp_vs_conn *conn)
{
    conn->flags |= DPVS_CONN_F_REDIRECT_HASHED;
}

static inline void
dp_vs_conn_clear_redirect_hashed(struct dp_vs_conn *conn)
{
    conn->flags &= ~DPVS_CONN_F_REDIRECT_HASHED;
}

uint32_t dp_vs_conn_hashkey(int af,
    const union inet_addr *saddr, uint16_t sport,
    const union inet_addr *daddr, uint16_t dport,
    uint32_t mask);
int dp_vs_conn_pool_size(void);
int dp_vs_conn_pool_cache_size(void);

extern bool dp_vs_redirect_disable;

#endif /* __DPVS_CONN_H__ */
