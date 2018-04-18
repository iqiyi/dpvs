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
#include <assert.h>
#include <netinet/tcp.h>
#include "common.h"
#include "inet.h"
#include "ipv4.h"
#include "sa_pool.h"
#include "ipvs/ipvs.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "ipvs/laddr.h"
#include "ipvs/xmit.h"
#include "ipvs/synproxy.h"
#include "ipvs/proto_tcp.h"
#include "ipvs/proto_udp.h"
#include "ipvs/proto_icmp.h"
#include "parser/parser.h"
#include "ctrl.h"
#include "conf/conn.h"

#define DPVS_CONN_TAB_BITS      20
#define DPVS_CONN_TAB_SIZE      (1 << DPVS_CONN_TAB_BITS)
#define DPVS_CONN_TAB_MASK      (DPVS_CONN_TAB_SIZE - 1)

/* too big ? adjust according to free mem ?*/
#define DPVS_CONN_POOL_SIZE_DEF     2097152
#define DPVS_CONN_POOL_SIZE_MIN     65536
static int conn_pool_size = DPVS_CONN_POOL_SIZE_DEF;
#define DPVS_CONN_CACHE_SIZE_DEF    256
static int conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;

#define DPVS_CONN_INIT_TIMEOUT_DEF  3   /* sec */
static int conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;

/* helpers */
#define this_conn_tab           (RTE_PER_LCORE(dp_vs_conn_tab))
#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
#define this_conn_lock          (RTE_PER_LCORE(dp_vs_conn_lock))
#endif
#define this_conn_count         (RTE_PER_LCORE(dp_vs_conn_count))
#define this_conn_cache         (dp_vs_conn_cache[rte_socket_id()])

/* dpvs control variables */
static bool conn_expire_quiescent_template = false;

/*
 * per-lcore dp_vs_conn{} hash table.
 */
static RTE_DEFINE_PER_LCORE(struct list_head *, dp_vs_conn_tab);
#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
static RTE_DEFINE_PER_LCORE(rte_spinlock_t, dp_vs_conn_lock);
#endif

/* global connection template table */
static struct list_head *dp_vs_ct_tab;
static rte_spinlock_t dp_vs_ct_lock;

static RTE_DEFINE_PER_LCORE(uint32_t, dp_vs_conn_count);

static uint32_t dp_vs_conn_rnd; /* hash random */

/*
 * memory pool for dp_vs_conn{}
 */
static struct rte_mempool *dp_vs_conn_cache[DPVS_MAX_SOCKET];

static inline struct dp_vs_conn *
tuplehash_to_conn(const struct conn_tuple_hash *thash)
{
    return container_of(thash, struct dp_vs_conn, tuplehash[thash->direct]);
}

static inline uint32_t conn_hashkey(int af,
                                const union inet_addr *saddr, uint16_t sport,
                                const union inet_addr *daddr, uint16_t dport)
{
    return rte_jhash_3words((uint32_t)saddr->in.s_addr,
            (uint32_t)daddr->in.s_addr,
            ((uint32_t)sport) << 16 | (uint32_t)dport,
            dp_vs_conn_rnd)
        & DPVS_CONN_TAB_MASK;
}

static inline int __conn_hash(struct dp_vs_conn *conn,
                              uint32_t ihash, uint32_t ohash)
{
    if (unlikely(conn->flags & DPVS_CONN_F_HASHED))
        return EDPVS_EXIST;

    if (conn->flags & DPVS_CONN_F_TEMPLATE) {
        /* lock is complusory for template */
        rte_spinlock_lock(&dp_vs_ct_lock);
        list_add(&tuplehash_in(conn).list, &dp_vs_ct_tab[ihash]);
        list_add(&tuplehash_out(conn).list, &dp_vs_ct_tab[ohash]);
        rte_spinlock_unlock(&dp_vs_ct_lock);
    } else {
        list_add(&tuplehash_in(conn).list, &this_conn_tab[ihash]);
        list_add(&tuplehash_out(conn).list, &this_conn_tab[ohash]);
    }

    conn->flags |= DPVS_CONN_F_HASHED;
    rte_atomic32_inc(&conn->refcnt);

    return EDPVS_OK;
}

static inline int conn_hash(struct dp_vs_conn *conn)
{
    uint32_t ihash, ohash;
    int err;

    ihash = conn_hashkey(conn->af,
                &tuplehash_in(conn).saddr, tuplehash_in(conn).sport,
                &tuplehash_in(conn).daddr, tuplehash_in(conn).dport);

    ohash = conn_hashkey(conn->af,
                &tuplehash_out(conn).saddr, tuplehash_out(conn).sport,
                &tuplehash_out(conn).daddr, tuplehash_out(conn).dport);

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_lock(&this_conn_lock);
#endif
    err = __conn_hash(conn, ihash, ohash);
#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_unlock(&this_conn_lock);
#endif

    return err;
}

static inline int conn_unhash(struct dp_vs_conn *conn)
{
    int err;

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_lock(&this_conn_lock);
#endif
    if (likely(conn->flags & DPVS_CONN_F_HASHED)) {
        if (rte_atomic32_read(&conn->refcnt) != 2) {
            err = EDPVS_BUSY;
        } else {
            if (conn->flags & DPVS_CONN_F_TEMPLATE) {
                rte_spinlock_lock(&dp_vs_ct_lock);
                list_del(&tuplehash_in(conn).list);
                list_del(&tuplehash_out(conn).list);
                rte_spinlock_unlock(&dp_vs_ct_lock);
            } else {
                list_del(&tuplehash_in(conn).list);
                list_del(&tuplehash_out(conn).list);
            }
            conn->flags &= ~DPVS_CONN_F_HASHED;
            rte_atomic32_dec(&conn->refcnt);
            err = EDPVS_OK;
        }
    } else {
        err = EDPVS_NOTEXIST;
    }
#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_unlock(&this_conn_lock);
#endif

#ifdef CONFIG_DPVS_IPVS_DEBUG
    if (unlikely(err == EDPVS_BUSY))
        RTE_LOG(DEBUG, IPVS, "%s: connection is busy: conn->refcnt = %d.\n",
                __func__, rte_atomic32_read(&conn->refcnt));
    else if (unlikely(err == EDPVS_NOTEXIST))
        RTE_LOG(DEBUG, IPVS, "%s: connection not hashed.\n", __func__);
#endif

    return err;
}

static int conn_bind_dest(struct dp_vs_conn *conn, struct dp_vs_dest *dest)
{
    /* ATTENTION:
     *   Initial state of conn should be INACTIVE, with conn->inactconns=1 and
     *   conn->actconns=0. We should not increase conn->actconns except in session
     *   sync.Generally, the INACTIVE and SYN_PROXY flags are passed down from
     *   the dest here. */
    conn->flags |= rte_atomic16_read(&dest->conn_flags);

    if (dest->max_conn &&
            (rte_atomic32_read(&dest->inactconns) + \
             rte_atomic32_read(&dest->actconns) >= dest->max_conn)) {
        dest->flags |= DPVS_DEST_F_OVERLOAD;
        return EDPVS_OVERLOAD;
    }

    rte_atomic32_inc(&dest->refcnt);

    if (conn->flags & DPVS_CONN_F_TEMPLATE)
        rte_atomic32_inc(&dest->persistconns);
    else
        rte_atomic32_inc(&dest->inactconns);

    switch (dest->fwdmode) {
    case DPVS_FWD_MODE_NAT:
        conn->packet_xmit = dp_vs_xmit_nat;
        conn->packet_out_xmit = dp_vs_out_xmit_nat;
        break;
    case DPVS_FWD_MODE_TUNNEL:
        conn->packet_xmit = dp_vs_xmit_tunnel;
        break;
    case DPVS_FWD_MODE_DR:
        conn->packet_xmit = dp_vs_xmit_dr;
        break;
    case DPVS_FWD_MODE_FNAT:
        conn->packet_xmit = dp_vs_xmit_fnat;
        conn->packet_out_xmit = dp_vs_out_xmit_fnat;
        break;
    case DPVS_FWD_MODE_SNAT:
        conn->packet_xmit = dp_vs_xmit_snat;
        conn->packet_out_xmit = dp_vs_out_xmit_snat;
        break;
    default:
        return EDPVS_NOTSUPP;
    }

    conn->dest = dest;
    return EDPVS_OK;
}

static int conn_unbind_dest(struct dp_vs_conn *conn)
{
    struct dp_vs_dest *dest = conn->dest;

    if (conn->flags & DPVS_CONN_F_TEMPLATE) {
        rte_atomic32_dec(&dest->persistconns);
    } else  {
        if (conn->flags & DPVS_CONN_F_INACTIVE)
            rte_atomic32_dec(&dest->inactconns);
        else
            rte_atomic32_dec(&dest->actconns);
    }

    if (dest->max_conn &&
            (rte_atomic32_read(&dest->inactconns) + \
             rte_atomic32_read(&dest->actconns) < dest->max_conn)) {
        dest->flags &= ~DPVS_DEST_F_OVERLOAD;
    }

    rte_atomic32_dec(&dest->refcnt);

    conn->dest = NULL;
    return EDPVS_OK;
}

#ifdef CONFIG_DPVS_IPVS_DEBUG
static inline void conn_dump(const char *msg, struct dp_vs_conn *conn)
{
    char cbuf[64], vbuf[64], lbuf[64], dbuf[64];
    const char *caddr, *vaddr, *laddr, *daddr;

    caddr = inet_ntop(conn->af, &conn->caddr, cbuf, sizeof(cbuf)) ? cbuf : "::";
    vaddr = inet_ntop(conn->af, &conn->vaddr, vbuf, sizeof(vbuf)) ? vbuf : "::";
    laddr = inet_ntop(conn->af, &conn->laddr, lbuf, sizeof(lbuf)) ? lbuf : "::";
    daddr = inet_ntop(conn->af, &conn->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::";

    RTE_LOG(DEBUG, IPVS, "%s [%d] %s %s:%u %s:%u %s:%u %s:%u refs %d\n",
            msg ? msg : "", rte_lcore_id(), inet_proto_name(conn->proto),
            caddr, ntohs(conn->cport), vaddr, ntohs(conn->vport),
            laddr, ntohs(conn->lport), daddr, ntohs(conn->dport),
            rte_atomic32_read(&conn->refcnt));
}

static inline void conn_tuplehash_dump(const char *msg,
                        struct conn_tuple_hash *t)
{
    char sbuf[64], dbuf[64];
    const char *saddr, *daddr;

    saddr = inet_ntop(t->af, &t->saddr, sbuf, sizeof(sbuf)) ? sbuf : "::";
    daddr = inet_ntop(t->af, &t->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::";

    RTE_LOG(DEBUG, IPVS, "%s%s %s %s:%u->%s:%u\n",
            msg ? msg : "",
            t->direct == DPVS_CONN_DIR_INBOUND ? "in " : "out",
            inet_proto_name(t->proto),
            saddr, ntohs(t->sport), daddr, ntohs(t->dport));
}

static inline void conn_tab_dump(void)
{
    int i;
    struct conn_tuple_hash *tuphash;

    RTE_LOG(DEBUG, IPVS, "Conn Table [%d]\n", rte_lcore_id());

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_lock(&this_conn_lock);
#endif

    for (i = 0; i < DPVS_CONN_TAB_SIZE; i++) {
        if (list_empty(&this_conn_tab[i]))
            continue;

        RTE_LOG(DEBUG, IPVS, "    hash %d\n", i);

        list_for_each_entry(tuphash, &this_conn_tab[i], list) {
            conn_tuplehash_dump("        ", tuphash);
        }
    }

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_unlock(&this_conn_lock);
#endif
}
#endif

/* timeout hanlder */
static void conn_expire(void *priv)
{
    struct dp_vs_conn *conn = priv;
    struct dp_vs_proto *pp;
    struct rte_mbuf *cloned_syn_mbuf;
    struct dp_vs_synproxy_ack_pakcet *ack_mbuf, *t_ack_mbuf;
    struct rte_mempool *pool;
    assert(conn);

    /* set proper timeout */
    unsigned conn_timeout = 0;

    pp = dp_vs_proto_lookup(conn->proto);
    if (((conn->proto == IPPROTO_TCP) &&
        (conn->state == DPVS_TCP_S_ESTABLISHED)) ||
        ((conn->proto == IPPROTO_UDP) &&
        (conn->state == DPVS_UDP_S_NORMAL))) {
        conn_timeout = dp_vs_get_conn_timeout(conn);
        if (unlikely(conn_timeout > 0))
            conn->timeout.tv_sec = conn_timeout;
        else if (pp && pp->timeout_table)
            conn->timeout.tv_sec = pp->timeout_table[conn->state];
        else
            conn->timeout.tv_sec = 60;
    }
    else if (pp && pp->timeout_table)
        conn->timeout.tv_sec = pp->timeout_table[conn->state];
    else
        conn->timeout.tv_sec = 60;

    dpvs_time_rand_delay(&conn->timeout, 1000000);

    rte_atomic32_inc(&conn->refcnt);

    /* retransmit syn packet to rs */
    if (conn->syn_mbuf && rte_atomic32_read(&conn->syn_retry_max) > 0) {
        if (likely(conn->packet_xmit != NULL)) {
            pool = get_mbuf_pool(conn, DPVS_CONN_DIR_INBOUND);
            if (unlikely(!pool)) {
                RTE_LOG(WARNING, IPVS, "%s: no route for syn_proxy rs's syn "
                        "retransmit\n", __func__);
            } else {
                cloned_syn_mbuf = rte_pktmbuf_clone(conn->syn_mbuf, pool);
                if (unlikely(!cloned_syn_mbuf)) {
                    RTE_LOG(WARNING, IPVS, "%s: no memory for syn_proxy rs's syn "
                            "retransmit\n", __func__);
                } else {
                    cloned_syn_mbuf->userdata = NULL;
                    conn->packet_xmit(pp, conn, cloned_syn_mbuf);
                }
            }
        }

        rte_atomic32_dec(&conn->syn_retry_max);
        dp_vs_estats_inc(SYNPROXY_RS_ERROR);

        /* expire later */
        dp_vs_conn_put(conn);
        return;
    }

    /* somebody is controlled by me, expire later */
    if (rte_atomic32_read(&conn->n_control)) {
        dp_vs_conn_put(conn);
        return;
    }

    /* unhash it then no further user can get it,
     * even we cannot del it now. */
    conn_unhash(conn);

    /* refcnt == 1 means we are the only referer.
     * no one is using the conn and it's timed out. */
    if (rte_atomic32_read(&conn->refcnt) == 1) {
        struct dp_vs_proto *proto = dp_vs_proto_lookup(conn->proto);

        if (conn->flags & DPVS_CONN_F_TEMPLATE)
            dpvs_timer_cancel(&conn->timer, true);
        else
            dpvs_timer_cancel(&conn->timer, false);

        /* I was controlled by someone */
        if (conn->control)
            dp_vs_control_del(conn);

        if (proto && proto->conn_expire)
            proto->conn_expire(proto, conn);

        if (conn->dest->fwdmode == DPVS_FWD_MODE_SNAT
                && conn->proto != IPPROTO_ICMP) {
            struct sockaddr_in daddr, saddr;

            memset(&daddr, 0, sizeof(daddr));
            daddr.sin_family = AF_INET;
            daddr.sin_addr = conn->caddr.in;
            daddr.sin_port = conn->cport;

            memset(&saddr, 0, sizeof(saddr));
            saddr.sin_family = AF_INET;
            saddr.sin_addr = conn->vaddr.in;
            saddr.sin_port = conn->vport;

            sa_release(conn->out_dev, &daddr, &saddr);
        }

        conn_unbind_dest(conn);
        dp_vs_laddr_unbind(conn);

        /* free stored ack packet */
        list_for_each_entry_safe(ack_mbuf, t_ack_mbuf, &conn->ack_mbuf, list) {
            list_del_init(&ack_mbuf->list);
            rte_pktmbuf_free(ack_mbuf->mbuf);
            sp_dbg_stats32_dec(sp_ack_saved);
            rte_mempool_put(this_ack_mbufpool, ack_mbuf);
        }
        conn->ack_num = 0;

        /* free stored syn mbuf */
        if (conn->syn_mbuf) {
            rte_pktmbuf_free(conn->syn_mbuf);
            sp_dbg_stats32_dec(sp_syn_saved);
        }

        rte_atomic32_dec(&conn->refcnt);

        rte_mempool_put(conn->connpool, conn);
        this_conn_count--;

#ifdef CONFIG_DPVS_IPVS_DEBUG
        conn_dump("del conn: ", conn);
#endif
        return;
    }

    conn_hash(conn);

    /* some one is using it when expire,
     * try del it again later */
    if (conn->flags & DPVS_CONN_F_TEMPLATE)
        dpvs_timer_update(&conn->timer, &conn->timeout, true);
    else
        dpvs_timer_update(&conn->timer, &conn->timeout, false);

    rte_atomic32_dec(&conn->refcnt);
    return;
}

static void conn_flush(void)
{
    struct conn_tuple_hash *tuphash, *next;
    struct dp_vs_conn *conn;
    int i;

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_lock(&this_conn_lock);
#endif
    for (i = 0; i < NELEMS(this_conn_tab); i++) {
        list_for_each_entry_safe(tuphash, next, &this_conn_tab[i], list) {
            conn = tuplehash_to_conn(tuphash);

            if (conn->flags & DPVS_CONN_F_TEMPLATE)
                dpvs_timer_cancel(&conn->timer, true);
            else
                dpvs_timer_cancel(&conn->timer, false);

            rte_atomic32_inc(&conn->refcnt);
            if (rte_atomic32_read(&conn->refcnt) == 2) {
                conn_unhash(conn);

                if (conn->dest->fwdmode == DPVS_FWD_MODE_SNAT &&
                        conn->proto != IPPROTO_ICMP) {
                    struct sockaddr_in daddr, saddr;

                    memset(&daddr, 0, sizeof(daddr));
                    daddr.sin_family = AF_INET;
                    daddr.sin_addr = conn->caddr.in;
                    daddr.sin_port = conn->cport;

                    memset(&saddr, 0, sizeof(saddr));
                    saddr.sin_family = AF_INET;
                    saddr.sin_addr = conn->vaddr.in;
                    saddr.sin_port = conn->vport;
                    sa_release(conn->out_dev, &daddr, &saddr);
                }

                conn_unbind_dest(conn);
                dp_vs_laddr_unbind(conn);
                rte_atomic32_dec(&conn->refcnt);

                rte_mempool_put(conn->connpool, conn);
                this_conn_count--;
                return;
            }
            rte_atomic32_dec(&conn->refcnt);
        }
    }
#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_unlock(&this_conn_lock);
#endif
}

struct dp_vs_conn * dp_vs_conn_new(struct rte_mbuf *mbuf,
                                   struct dp_vs_conn_param *param,
                                   struct dp_vs_dest *dest, uint32_t flags)
{
    struct dp_vs_conn *new;
    struct conn_tuple_hash *t;
    uint16_t rport;
    __be16 _ports[2], *ports;
    int err;

    assert(mbuf && param && dest);

    if (unlikely(rte_mempool_get(this_conn_cache, (void **)&new) != 0)) {
        RTE_LOG(WARNING, IPVS, "%s: no memory\n", __func__);
        return NULL;
    }
    memset(new, 0, sizeof(struct dp_vs_conn));
    new->connpool = this_conn_cache;

    /* set proper RS port */
    if ((flags & DPVS_CONN_F_TEMPLATE) || param->ct_dport != 0)
        rport = param->ct_dport;
    else if (dest->fwdmode == DPVS_FWD_MODE_SNAT) {
        if (unlikely(param->proto == IPPROTO_ICMP)) {
            rport = param->vport;
        } else {
            ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf),
                                        sizeof(_ports), _ports);
            if (unlikely(!ports)) {
                RTE_LOG(WARNING, IPVS, "%s: no memory\n", __func__);
                goto errout;
            }
            rport = ports[0];
        }
    } else
        rport = dest->port;

    /* init inbound conn tuple hash */
    t = &tuplehash_in(new);
    t->direct   = DPVS_CONN_DIR_INBOUND;
    t->af       = param->af;
    t->proto    = param->proto;
    t->saddr    = *param->caddr;
    t->sport    = param->cport;
    t->daddr    = *param->vaddr;
    t->dport    = param->vport;
    INIT_LIST_HEAD(&t->list);

    /* init outbound conn tuple hash */
    t = &tuplehash_out(new);
    t->direct   = DPVS_CONN_DIR_OUTBOUND;
    t->af       = param->af;
    t->proto    = param->proto;
    if (dest->fwdmode == DPVS_FWD_MODE_SNAT)
        t->saddr.in.s_addr    = ip4_hdr(mbuf)->src_addr;
    else
        t->saddr    = dest->addr;
    t->sport    = rport;
    t->daddr    = *param->caddr;    /* non-FNAT */
    t->dport    = param->cport;     /* non-FNAT */
    INIT_LIST_HEAD(&t->list);

    /* init connection */
    new->af     = param->af;
    new->proto  = param->proto;
    new->caddr  = *param->caddr;
    new->cport  = param->cport;
    new->vaddr  = *param->vaddr;
    new->vport  = param->vport;
    new->laddr  = *param->caddr;    /* non-FNAT */
    new->lport  = param->cport;     /* non-FNAT */
    if (dest->fwdmode == DPVS_FWD_MODE_SNAT)
        new->daddr.in.s_addr  = ip4_hdr(mbuf)->src_addr;
    else
        new->daddr  = dest->addr;
    new->dport  = rport;

    /* L2 fast xmit */
    new->in_dev = NULL;
    new->out_dev = NULL;

    /* Controll member */
    new->control = NULL;
    rte_atomic32_clear(&new->n_control);

    /* caller will use it right after created,
     * just like dp_vs_conn_get(). */
    rte_atomic32_set(&new->refcnt, 1);
    new->flags  = flags;
    new->state  = 0;

    /* bind destination and corresponding trasmitter */
    err = conn_bind_dest(new, dest);
    if (err != EDPVS_OK) {
        RTE_LOG(WARNING, IPVS, "%s: fail to bind dest: %s\n",
                __func__, dpvs_strerror(err));
        goto errout;
    }

    /* FNAT only: select and bind local address/port */
    if (dest->fwdmode == DPVS_FWD_MODE_FNAT) {
        if ((err = dp_vs_laddr_bind(new, dest->svc)) != EDPVS_OK)
            goto unbind_dest;
    }

    /* add to hash table (dual dir for each bucket) */
    if ((err = conn_hash(new)) != EDPVS_OK)
        goto unbind_laddr;

    /* timer */
    new->timeout.tv_sec = conn_init_timeout;
    new->timeout.tv_usec = 0;

    /* synproxy */
    INIT_LIST_HEAD(&new->ack_mbuf);
    rte_atomic32_set(&new->syn_retry_max, 0);
    rte_atomic32_set(&new->dup_ack_cnt, 0);
    if ((flags & DPVS_CONN_F_SYNPROXY) && !(flags & DPVS_CONN_F_TEMPLATE)) {
        struct tcphdr _tcph, *th;
        struct dp_vs_synproxy_ack_pakcet *ack_mbuf;
        struct dp_vs_proto *pp;

        th = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_tcph), &_tcph);
        if (!th) {
            RTE_LOG(ERR, IPVS, "%s: get tcphdr failed\n", __func__);
            goto unbind_laddr;
        }

        /* save ack packet */
        if (unlikely(rte_mempool_get(this_ack_mbufpool, (void **)&ack_mbuf) != 0)) {
            RTE_LOG(ERR, IPVS, "%s: no memory\n", __func__);
            goto unbind_laddr;
        }
        ack_mbuf->mbuf = mbuf;
        list_add_tail(&ack_mbuf->list, &new->ack_mbuf);
        new->ack_num++;
        sp_dbg_stats32_inc(sp_ack_saved);

        /* save ack_seq - 1 */
        new->syn_proxy_seq.isn =
            htonl((uint32_t) ((ntohl(th->ack_seq) - 1)));

        /* save ack_seq */
        new->fnat_seq.fdata_seq = htonl(th->ack_seq);

        /* FIXME: use DP_VS_TCP_S_SYN_SENT for syn */
        pp = dp_vs_proto_lookup(param->proto);
        new->timeout.tv_sec = pp->timeout_table[new->state = DPVS_TCP_S_SYN_SENT];
    }

    this_conn_count++;

    /* schedule conn timer */
    dpvs_time_rand_delay(&new->timeout, 1000000);
    if (new->flags & DPVS_CONN_F_TEMPLATE)
        dpvs_timer_sched(&new->timer, &new->timeout, conn_expire, new, true);
    else
        dpvs_timer_sched(&new->timer, &new->timeout, conn_expire, new, false);

#ifdef CONFIG_DPVS_IPVS_DEBUG
    conn_dump("new conn: ", new);
#endif
    return new;

unbind_laddr:
    dp_vs_laddr_unbind(new);
unbind_dest:
    conn_unbind_dest(new);
errout:
    rte_mempool_put(this_conn_cache, new);
    return NULL;
}

/**
 * try lookup and hold dp_vs_conn{} by packet tuple
 *
 *  <af, proto, saddr, sport, daddr, dport>.
 *
 * dp_vs_conn_tab[] for current lcore will be looked up.
 * return conn found and direction as well or NULL if not exist.
 */
struct dp_vs_conn *dp_vs_conn_get(int af, uint16_t proto,
            const union inet_addr *saddr, const union inet_addr *daddr,
            uint16_t sport, uint16_t dport, int *dir, bool reverse)
{
    uint32_t hash;
    struct conn_tuple_hash *tuphash;
    struct dp_vs_conn *conn = NULL;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], dbuf[64];
#endif

    if (unlikely(reverse))
        hash = conn_hashkey(af, daddr, dport, saddr, sport);
    else
        hash = conn_hashkey(af, saddr, sport, daddr, dport);

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_lock(&this_conn_lock);
#endif
    if (unlikely(reverse)) { /* swap source/dest for lookup */
        list_for_each_entry(tuphash, &this_conn_tab[hash], list) {
            if (tuphash->sport == dport
                    && tuphash->dport == sport
                    && inet_addr_equal(af, &tuphash->saddr, daddr)
                    && inet_addr_equal(af, &tuphash->daddr, saddr)
                    && tuphash->proto == proto
                    && tuphash->af == af) {
                /* hit */
                conn = tuplehash_to_conn(tuphash);
                rte_atomic32_inc(&conn->refcnt);
                if (dir)
                    *dir = tuphash->direct;
                break;
            }
        }
    } else {
        list_for_each_entry(tuphash, &this_conn_tab[hash], list) {
            if (tuphash->sport == sport
                    && tuphash->dport == dport
                    && inet_addr_equal(af, &tuphash->saddr, saddr)
                    && inet_addr_equal(af, &tuphash->daddr, daddr)
                    && tuphash->proto == proto
                    && tuphash->af == af) {
                /* hit */
                conn = tuplehash_to_conn(tuphash);
                rte_atomic32_inc(&conn->refcnt);
                if (dir)
                    *dir = tuphash->direct;
                break;
            }
        }
    }
#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_unlock(&this_conn_lock);
#endif

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "conn lookup: [%d] %s %s:%d -> %s:%d %s %s\n",
            rte_lcore_id(), inet_proto_name(proto),
            inet_ntop(af, saddr, sbuf, sizeof(sbuf)) ? sbuf : "::", ntohs(sport),
            inet_ntop(af, daddr, dbuf, sizeof(dbuf)) ? dbuf : "::", ntohs(dport),
            conn ? "hit" : "miss", reverse ? "reverse" : "");
#endif

    return conn;
}

/* get reference to connection template */
struct dp_vs_conn *dp_vs_ct_in_get(int af, uint16_t proto,
        const union inet_addr *saddr, const union inet_addr *daddr,
        uint16_t sport, uint16_t dport)
{
    uint32_t hash;
    struct conn_tuple_hash *tuphash;
    struct dp_vs_conn *conn = NULL;
    bool isHit = false;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], dbuf[64];
#endif

    hash = conn_hashkey(af, saddr, sport, daddr, dport);

    rte_spinlock_lock(&dp_vs_ct_lock);
    list_for_each_entry(tuphash, &dp_vs_ct_tab[hash], list) {
        conn = tuplehash_to_conn(tuphash);
        if (tuphash->sport == sport && tuphash->dport == dport
                && inet_addr_equal(af, &tuphash->saddr, saddr)
                && inet_addr_equal(proto == IPPROTO_IP ? AF_UNSPEC : af,
                    &tuphash->daddr, daddr)
                && conn->flags & DPVS_CONN_F_TEMPLATE
                && tuphash->proto == proto
                && tuphash->af == af) {
            /* hit */
            rte_atomic32_inc(&conn->refcnt);
            isHit = true;
            break;
        }
    }
    rte_spinlock_unlock(&dp_vs_ct_lock);

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "conn-template lookup: [%d] %s %s:%d -> %s:%d %s\n",
            rte_lcore_id(), inet_proto_name(proto),
            inet_ntop(af, saddr, sbuf, sizeof(sbuf)) ? sbuf : "::", ntohs(sport),
            inet_ntop(af, daddr, dbuf, sizeof(dbuf)) ? dbuf : "::", ntohs(dport),
            isHit ? "hit" : "miss");
#endif
    return isHit ? conn : NULL;
}

/* check if the destination of a connection template is avaliable
 *  *  * return 1 if available, otherwise return 0. */
int dp_vs_check_template(struct dp_vs_conn *ct)
{
    struct dp_vs_dest *dest = ct->dest;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[64], vbuf[64], lbuf[64], dbuf[64];
#endif

    /* check the dest server status */
    if ((NULL == dest) ||
            !(dest->flags & DPVS_DEST_F_AVAILABLE) ||
            (conn_expire_quiescent_template &&
             rte_atomic16_read(&dest->weight) == 0)) {
#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, IPVS, "%s: check_template: dest not available for "
                "protocol %s s:%s:%u v:%s:%u -> l:%s:%u d:%s:%u\n",
                __func__, inet_proto_name(ct->proto),
                inet_ntop(ct->af, &ct->caddr, sbuf, sizeof(sbuf)) ? sbuf : "::",
                ntohs(ct->cport),
                inet_ntop(ct->af, &ct->vaddr, vbuf, sizeof(vbuf)) ? vbuf : "::",
                ntohs(ct->vport),
                inet_ntop(ct->af, &ct->laddr, lbuf, sizeof(lbuf)) ? lbuf : "::",
                ntohs(ct->lport),
                inet_ntop(ct->af, &ct->daddr, dbuf, sizeof(dbuf)) ? dbuf : "::",
                ntohs(ct->dport));
#endif
        /* invalidate the connection */
        if (ct->vport != htons(0xffff)) {
            if (conn_unhash(ct)) {
                ct->dport = htonl(0xffff);
                ct->vport = htonl(0xffff);
                ct->lport = 0;
                ct->cport = 0;
                conn_hash(ct);
            }
        }
        /* simply decrease the refcnt of the template, do not restart its timer */
        rte_atomic32_dec(&ct->refcnt);
        return 0;
    }
    return 1;
}

void dp_vs_conn_put_no_reset(struct dp_vs_conn *conn)
{
    rte_atomic32_dec(&conn->refcnt);
}

/* put back the conn and reset it's timer */
void dp_vs_conn_put(struct dp_vs_conn *conn)
{
    if (conn->flags & DPVS_CONN_F_TEMPLATE)
        dpvs_timer_update(&conn->timer, &conn->timeout, true);
    else
        dpvs_timer_update(&conn->timer, &conn->timeout, false);

    rte_atomic32_dec(&conn->refcnt);
}

static int conn_init_lcore(void *arg)
{
    int i;

    if (!rte_lcore_is_enabled(rte_lcore_id()))
        return EDPVS_DISABLED;

    this_conn_tab = rte_malloc_socket(NULL,
                        sizeof(struct list_head) * DPVS_CONN_TAB_SIZE,
                        RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!this_conn_tab)
        return EDPVS_NOMEM;

    for (i = 0; i < DPVS_CONN_TAB_SIZE; i++)
        INIT_LIST_HEAD(&this_conn_tab[i]);

#ifdef CONFIG_DPVS_IPVS_CONN_LOCK
    rte_spinlock_init(&this_conn_lock);
#endif
    this_conn_count = 0;

    return EDPVS_OK;
}

static int conn_term_lcore(void *arg)
{
    if (!rte_lcore_is_enabled(rte_lcore_id()))
        return EDPVS_DISABLED;

    conn_flush();

    if (this_conn_tab) {
        rte_free(this_conn_tab);
        this_conn_tab = NULL;
    }

    return EDPVS_OK;
}


/*
 * ctrl plane support for commands:
 *     ipvsadm -ln -c
 *     ipvsadm -ln -c --sockpair af:proto:sip:sport:tip:tport
 *     ipvsadm -ln -c --persistent-conn
 */
struct ip_vs_conn_array_list {
    int head;
    int tail;
    struct list_head ca_list;
    ipvs_conn_entry_t array[0];
};

static uint8_t g_slave_lcore_nb;
static uint64_t g_slave_lcore_mask;
static struct list_head conn_to_dump;

static inline char* get_conn_state_name(uint16_t proto, uint16_t state)
{
    switch (proto) {
        case IPPROTO_TCP:
            switch (state) {
                case DPVS_TCP_S_NONE:
                    return "TCP_NONE";
                    break;
                case DPVS_TCP_S_ESTABLISHED:
                    return "TCP_EST";
                    break;
                case DPVS_TCP_S_SYN_SENT:
                    return "SYN_SENT";
                    break;
                case DPVS_TCP_S_SYN_RECV:
                    return "SYN_RECV";
                    break;
                case DPVS_TCP_S_FIN_WAIT:
                    return "FIN_WAIT";
                    break;
                case DPVS_TCP_S_TIME_WAIT:
                    return "TIME_WAIT";
                    break;
                case DPVS_TCP_S_CLOSE:
                    return "TCP_CLOSE";
                    break;
                case DPVS_TCP_S_CLOSE_WAIT:
                    return "CLOSE_WAIT";
                    break;
                case DPVS_TCP_S_LAST_ACK:
                    return "LAST_ACK";
                    break;
                case DPVS_TCP_S_LISTEN:
                    return "LISTEN";
                    break;
                case DPVS_TCP_S_SYNACK:
                    return "SYNACK";
                    break;
                default:
                    return "TCP_UNKOWN";
                    break;
            }
            break;
        case IPPROTO_UDP:
            switch (state) {
                case DPVS_UDP_S_NORMAL:
                    return "UDP_NORM";
                    break;
                case DPVS_UDP_S_LAST:
                    return "UDP_LAST";
                    break;
                default:
                    return "UDP_UNKOWN";
                    break;
            }
            break;
        case IPPROTO_ICMP:
            switch (state) {
                case DPVS_ICMP_S_NORMAL:
                    return "ICMP_NORMAL";
                    break;
                case DPVS_ICMP_S_LAST:
                    return "ICMP_LAST";
                    break;
                default:
                    return "ICMP_UNKOWN";
                    break;
            }
            break;
        default:
            return "UNKOWN";
    }
}

static inline void sockopt_fill_conn_entry(const struct dp_vs_conn *conn,
        ipvs_conn_entry_t *entry)
{
    entry->af = conn->af;
    entry->proto = conn->proto;
    entry->lcoreid = rte_lcore_id();
    snprintf(entry->state, sizeof(entry->state), "%s",
            get_conn_state_name(conn->proto, conn->state));
    entry->caddr = conn->caddr.in.s_addr;
    entry->vaddr = conn->vaddr.in.s_addr;
    entry->laddr = conn->laddr.in.s_addr;
    entry->daddr = conn->daddr.in.s_addr;
    entry->cport = conn->cport;
    entry->vport = conn->vport;
    entry->lport = conn->lport;
    entry->dport = conn->dport;
    entry->timeout = conn->timeout.tv_sec;
}

static int sockopt_conn_get_specified(const struct ip_vs_conn_req *conn_req,
        struct ip_vs_conn_array *conn_arr)
{
    union inet_addr sip, tip;
    struct dp_vs_conn *conn;
    struct dpvs_msg *msg, *rmsg;
    struct dpvs_multicast_queue *mcq;
    struct ip_vs_conn_array *resp_conn;
    int res;

    sip.in.s_addr = conn_req->sockpair.sip;
    tip.in.s_addr = conn_req->sockpair.tip;

    if (conn_req->flag & GET_IPVS_CONN_FLAG_TEMPLATE) {
        conn = dp_vs_ct_in_get(conn_req->sockpair.af, conn_req->sockpair.proto,
                &sip, &tip, conn_req->sockpair.sport, conn_req->sockpair.tport);
        if (unlikely(conn != NULL)) { /* hit persist conn */
            sockopt_fill_conn_entry(conn, &conn_arr->array[0]);
            conn_arr->nconns = 1;
            conn_arr->resl = GET_IPVS_CONN_RESL_OK;
            conn_arr->curcid = 0;
            dp_vs_conn_put(conn);
            return EDPVS_OK;
        }
    }

    /* per-lcore conns */
    msg = msg_make(MSG_TYPE_CONN_GET, 0, DPVS_MSG_MULTICAST, rte_lcore_id(),
            sizeof(struct ip_vs_conn_req), conn_req);
    if (unlikely(msg == NULL))
        return EDPVS_NOMEM;
    res = multicast_msg_send(msg, 0, &mcq);
    if (res == EDPVS_OK) {
        list_for_each_entry(rmsg, &mcq->mq, mq_node) {
            resp_conn = (struct ip_vs_conn_array *)rmsg->data;
            if (resp_conn->resl == GET_IPVS_CONN_RESL_OK &&
                    resp_conn->nconns == 1) {
                memcpy(conn_arr, resp_conn, sizeof(struct ip_vs_conn_array) +
                        sizeof(ipvs_conn_entry_t));
                msg_destroy(&msg);
                return EDPVS_OK;
            }
        }
    }
    msg_destroy(&msg);

    /* not found */
    conn_arr->nconns = 0;
    conn_arr->resl = GET_IPVS_CONN_RESL_FAIL;
    conn_arr->curcid = 0;

    return EDPVS_NOTEXIST;
}

/* call me on the same lcore as the conn table,
 * lock me if the conn table is global
 * */
static int __lcore_conn_table_dump(const struct list_head *cplist)
{
    int i;
    struct conn_tuple_hash *tuphash;
    struct dp_vs_conn *conn;
    struct ip_vs_conn_array_list *cparr = NULL;

    for (i = 0; i < DPVS_CONN_TAB_SIZE; i++) {
        list_for_each_entry(tuphash, &cplist[i], list) {
            if (tuphash->direct != DPVS_CONN_DIR_INBOUND)
                continue;
            conn = tuplehash_to_conn(tuphash);
            if (unlikely(cparr == NULL || cparr->tail >= MAX_CTRL_CONN_GET_ENTRIES)) {
                cparr = rte_zmalloc("conn_ctrl", sizeof(struct ip_vs_conn_array_list)
                        + MAX_CTRL_CONN_GET_ENTRIES * sizeof(ipvs_conn_entry_t), 0);
                if (unlikely(cparr == NULL))
                    return EDPVS_NOMEM;
                cparr->head = cparr->tail = 0;
            }
            sockopt_fill_conn_entry(conn, &cparr->array[cparr->tail++]);
            if (cparr->tail >= MAX_CTRL_CONN_GET_ENTRIES) {
                RTE_LOG(DEBUG, IPVS, "%s: adding %d elems to conn_to_dump list -- "
                        "%p:%d-%d\n", __func__, cparr->tail - cparr->head, cparr,
                        cparr->head, cparr->tail);
                list_add_tail(&cparr->ca_list, &conn_to_dump);
            }
        }
    }
    if (cparr && cparr->tail < MAX_CTRL_CONN_GET_ENTRIES) {
        RTE_LOG(DEBUG, IPVS, "%s: adding %d elems to conn_to_dump list -- "
                "%p:%d-%d\n", __func__, cparr->tail - cparr->head, cparr,
                cparr->head, cparr->tail);
        list_add_tail(&cparr->ca_list, &conn_to_dump);
    }
    return EDPVS_OK;
}

static int sockopt_conn_get_all(const struct ip_vs_conn_req *conn_req,
        struct ip_vs_conn_array *conn_arr)
{
    int n, res, got = 0;
    struct ip_vs_conn_array_list *larr, *next_larr;
    struct dpvs_msg *msg;
    lcoreid_t cid = conn_req->whence;

again:
    list_for_each_entry_safe(larr, next_larr, &conn_to_dump, ca_list) {
        RTE_LOG(DEBUG, IPVS, "%s: printing conn_to_dump list(len=%d) --"
                "%p:%d-%d\n", __func__, list_elems(&conn_to_dump), larr,
                larr->head, larr->tail);
        n = larr->tail - larr->head;
        assert(n > 0);
        if (n > MAX_CTRL_CONN_GET_ENTRIES - got) {
            memcpy(&conn_arr->array[got], &larr->array[larr->head],
                    (MAX_CTRL_CONN_GET_ENTRIES - got) * sizeof(ipvs_conn_entry_t));
            larr->head += MAX_CTRL_CONN_GET_ENTRIES - got;
            got += MAX_CTRL_CONN_GET_ENTRIES - got;

            assert(got == MAX_CTRL_CONN_GET_ENTRIES);
            conn_arr->nconns = got;
            /* low chance that all done here, we assign GET_IPVS_CONN_RESL_MORE
             * flag for simplicity here anyway */
            conn_arr->resl = GET_IPVS_CONN_RESL_OK | GET_IPVS_CONN_RESL_MORE;
            conn_arr->curcid = cid;
            return EDPVS_OK;
        } else {
            memcpy(&conn_arr->array[got], &larr->array[larr->head],
                    n * sizeof(ipvs_conn_entry_t));
            larr->head += n;
            assert(larr->head == larr->tail);
            list_del_init(&larr->ca_list);
            rte_free(larr);
            got += n;
            if (got == MAX_CTRL_CONN_GET_ENTRIES) {
                conn_arr->nconns = got;
                /* low chance that all done here, we assign GET_IPVS_CONN_RESL_MORE
                 * flag for simplicity here anyway */
                conn_arr->resl = GET_IPVS_CONN_RESL_OK | GET_IPVS_CONN_RESL_MORE;
                conn_arr->curcid = cid;
                return EDPVS_OK;
            }
        }
    }

    if ((conn_req->flag & GET_IPVS_CONN_FLAG_TEMPLATE)
            && (cid == rte_get_master_lcore())) { /* persist conns */
        rte_spinlock_lock(&dp_vs_ct_lock);
        res = __lcore_conn_table_dump(dp_vs_ct_tab);
        rte_spinlock_unlock(&dp_vs_ct_lock);
        if (res != EDPVS_OK) {
            conn_arr->nconns = got;
            conn_arr->resl = GET_IPVS_CONN_RESL_FAIL;
            conn_arr->curcid = cid;
            return res;
        }
        cid++;
        goto again;
    }

    if (conn_req->flag & GET_IPVS_CONN_FLAG_TEMPLATE) {
        conn_arr->nconns = got;
        conn_arr->resl = GET_IPVS_CONN_RESL_OK;
        conn_arr->curcid = 0;
        return EDPVS_OK;
    }

    for ( ; cid < DPVS_MAX_LCORE; cid++)
        if (g_slave_lcore_mask & (1UL << cid))
            break;
    if (cid >= DPVS_MAX_LCORE) {
        conn_arr->nconns = got;
        conn_arr->resl = GET_IPVS_CONN_RESL_OK;
        conn_arr->curcid = 0;
        return EDPVS_OK;
    }

    /* get conns table from cid and saved into dump list */
    msg = msg_make(MSG_TYPE_CONN_GET_ALL, 0, DPVS_MSG_UNICAST, rte_lcore_id(), 0, NULL);
    /* FIXME: When conns in session table are not many enough, blockable msg would get
     * timeout probably due to the traverse of the whole huge session table.  So non-
     * blockable msg is used. A more elegant solution is to use an upper time limit for
     * the session table access in this case, which is much more complicated. */
    res = msg_send(msg, cid, DPVS_MSG_F_ASYNC, NULL);
    while (!test_msg_flags(msg, DPVS_MSG_F_STATE_FIN|DPVS_MSG_F_STATE_DROP))
        ; /* wait until msg processed */

    if (res != EDPVS_OK || test_msg_flags(msg, DPVS_MSG_F_STATE_DROP|
                DPVS_MSG_F_CALLBACK_FAIL)) {
        RTE_LOG(WARNING, IPVS, "%s: fail to get lcore%d's connection table -- %s\n",
                __func__, (int)cid, dpvs_strerror(res));
        conn_arr->nconns = got;
        conn_arr->resl = GET_IPVS_CONN_RESL_FAIL;
        conn_arr->curcid = cid;
        return res;
    }
    cid++;
    goto again;
}

static int sockopt_conn_get(sockoptid_t opt, const void *in, size_t inlen,
        void **out, size_t *outlen)
{
    const struct ip_vs_conn_req *conn_req;
    struct ip_vs_conn_array *conn_arr;
    size_t arr_size;
    int res = EDPVS_OK;

    *out = NULL;
    *outlen = 0;

    if (in == NULL || inlen != sizeof(struct ip_vs_conn_req))
        return EDPVS_INVAL;

    conn_req = (struct ip_vs_conn_req *) in;

    switch (opt) {
        case SOCKOPT_GET_CONN_SPECIFIED:
        {
            if ((conn_req->flag & GET_IPVS_CONN_FLAG_SPECIFIED) == 0)
                return EDPVS_INVAL;
            arr_size = sizeof(struct ip_vs_conn_array) + sizeof(ipvs_conn_entry_t);
            conn_arr = rte_zmalloc("conn_ctrl", arr_size, 0);
            if (!conn_arr)
                return EDPVS_NOMEM;
            res = sockopt_conn_get_specified(conn_req, conn_arr);
        }
        break;
        case SOCKOPT_GET_CONN_ALL:
        {
            if (!(conn_req->flag & (GET_IPVS_CONN_FLAG_ALL|GET_IPVS_CONN_FLAG_MORE)))
                return EDPVS_INVAL;
            if (!(conn_req->flag & GET_IPVS_CONN_FLAG_MORE)) {
                struct ip_vs_conn_array_list *calst, *tcalst;
                list_for_each_entry_safe(calst, tcalst, &conn_to_dump, ca_list) {
                    list_del_init(&calst->ca_list);
                    rte_free(calst);
                }
            }

            arr_size = sizeof(struct ip_vs_conn_array) + MAX_CTRL_CONN_GET_ENTRIES *
                sizeof(ipvs_conn_entry_t);
            conn_arr = rte_zmalloc("conn_ctrl", arr_size, 0);
            if (!conn_arr)
                return EDPVS_NOMEM;
            res = sockopt_conn_get_all(conn_req, conn_arr);
        }
        break;
        default:
            return EDPVS_INVAL;
            break;
    }

    *out = conn_arr;
    *outlen = sizeof(struct ip_vs_conn_array) +
        conn_arr->nconns * sizeof(ipvs_conn_entry_t);

    return res;
}

static struct dpvs_sockopts conn_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = 0,
    .set_opt_max    = 0,
    .set            = NULL,
    .get_opt_min    = SOCKOPT_GET_CONN_ALL,
    .get_opt_max    = SOCKOPT_GET_CONN_SPECIFIED,
    .get            = sockopt_conn_get,
};

static int conn_get_msgcb_slave(struct dpvs_msg *msg)
{
    const struct ip_vs_conn_req *conn_req;
    union inet_addr sip, tip;
    struct dp_vs_conn *conn;
    int dir, reply_len;
    struct ip_vs_conn_array *reply_data;

    assert(msg->len == sizeof(struct ip_vs_conn_req));
    conn_req = (struct ip_vs_conn_req *)&msg->data[0];

    sip.in.s_addr = conn_req->sockpair.sip;
    tip.in.s_addr = conn_req->sockpair.tip;

    /* templates are global, it should never found here */
    if (conn_req->flag & GET_IPVS_CONN_FLAG_TEMPLATE)
        return EDPVS_INVAL;

    conn = dp_vs_conn_get(conn_req->sockpair.af, conn_req->sockpair.proto,
            &sip, &tip, conn_req->sockpair.sport, conn_req->sockpair.tport, &dir, 0);
    if (!conn) {
        conn = dp_vs_conn_get(conn_req->sockpair.af, conn_req->sockpair.proto,
                    &sip, &tip, conn_req->sockpair.sport,
                    conn_req->sockpair.tport, &dir, 1);
    }

    if (unlikely(conn != NULL))
        reply_len = sizeof(struct ip_vs_conn_array) + sizeof(ipvs_conn_entry_t);
    else
        reply_len = sizeof(struct ip_vs_conn_array);
    reply_data = rte_zmalloc("get_conns", reply_len, 0);
    if (unlikely(!reply_data)) {
        dp_vs_conn_put(conn);
        return EDPVS_NOMEM;
    }

    memset(reply_data, 0, reply_len);
    if (unlikely(conn != NULL)) {
        reply_data->nconns = 1;
        reply_data->resl = GET_IPVS_CONN_RESL_OK;
        reply_data->curcid = 0;
        sockopt_fill_conn_entry(conn, &reply_data->array[0]);
        dp_vs_conn_put(conn);
    }

    msg->reply.len = reply_len;
    msg->reply.data = reply_data;

    return EDPVS_OK;
}

static int conn_get_all_msgcb_slave(struct dpvs_msg *msg)
{
    return  __lcore_conn_table_dump(this_conn_tab);
}

static int register_conn_get_msg(void)
{
    int ret;
    unsigned ii;
    struct dpvs_msg_type conn_get, conn_get_all;

    memset(&conn_get, 0, sizeof(struct dpvs_msg_type));
    conn_get.type = MSG_TYPE_CONN_GET;
    conn_get.mode = DPVS_MSG_MULTICAST;
    conn_get.unicast_msg_cb = conn_get_msgcb_slave;
    conn_get.multicast_msg_cb = NULL;

    if ((ret = msg_type_mc_register(&conn_get)) < 0) {
        RTE_LOG(ERR, IPVS, "%s: fail to register conn-get multicast msg -- %s\n",
                __func__, dpvs_strerror(ret));
        return ret;
    }

    memset(&conn_get_all, 0, sizeof(struct dpvs_msg_type));
    conn_get_all.type = MSG_TYPE_CONN_GET_ALL;
    conn_get_all.mode = DPVS_MSG_UNICAST;
    conn_get_all.unicast_msg_cb = conn_get_all_msgcb_slave;
    conn_get_all.multicast_msg_cb = NULL;
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (!(g_slave_lcore_mask & (1UL << ii)))
            continue;
        conn_get_all.cid = ii;
        if ((ret = msg_type_register(&conn_get_all)) < 0) {
            RTE_LOG(ERR, IPVS, "%s: fail to register conn-get-all msg"
                    " on lcore%d -- %s\n", __func__, ii, dpvs_strerror(ret));
            return ret;
        }
    }

    return EDPVS_OK;
}

static int unregister_conn_get_msg(void)
{
    int ret = EDPVS_OK;
    unsigned ii;
    struct dpvs_msg_type conn_get, conn_get_all;

    memset(&conn_get, 0, sizeof(struct dpvs_msg_type));
    conn_get.type = MSG_TYPE_CONN_GET;
    conn_get.mode = DPVS_MSG_MULTICAST;
    conn_get.unicast_msg_cb = conn_get_msgcb_slave;
    conn_get.multicast_msg_cb = NULL;
    if ((ret = msg_type_mc_unregister(&conn_get)) < 0) {
        RTE_LOG(ERR, IPVS, "%s: fail to unregister conn-get msg -- %s\n",
                __func__, dpvs_strerror(ret));
    }

    memset(&conn_get_all, 0, sizeof(struct dpvs_msg_type));
    conn_get_all.type = MSG_TYPE_CONN_GET_ALL;
    conn_get_all.mode = DPVS_MSG_UNICAST;
    conn_get_all.unicast_msg_cb = conn_get_msgcb_slave;
    conn_get_all.multicast_msg_cb = NULL;
    for (ii = 0; ii < DPVS_MAX_LCORE; ii++) {
        if (!(g_slave_lcore_mask & (1UL << ii)))
            continue;
        conn_get_all.cid = ii;
        if ((ret = msg_type_unregister(&conn_get_all)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: fail to unregister conn-get-all msg "
                    "on lcore%d -- %s\n", __func__, ii, dpvs_strerror(ret));
        }
    }

    return ret;
}

static int conn_ctrl_init(void)
{
    int err;

    INIT_LIST_HEAD(&conn_to_dump);
    netif_get_slave_lcores(&g_slave_lcore_nb, &g_slave_lcore_mask);

    if ((err = register_conn_get_msg()) != EDPVS_OK)
        return err;

    if ((err = sockopt_register(&conn_sockopts)) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register conn_sockopts\n", __func__);
        unregister_conn_get_msg();
        return err;
    }

    return EDPVS_OK;
}

static void conn_ctrl_term(void)
{
    struct ip_vs_conn_array_list *calst, *tcalst;

    list_for_each_entry_safe(calst, tcalst, &conn_to_dump, ca_list) {
        list_del_init(&calst->ca_list);
        rte_free(calst);
    }

    sockopt_unregister(&conn_sockopts);
    unregister_conn_get_msg();
}

int dp_vs_conn_init(void)
{
    int i, err;
    lcoreid_t lcore;
    char poolname[32];

    /* init connection template table */
    dp_vs_ct_tab = rte_malloc_socket(NULL, sizeof(struct list_head) * DPVS_CONN_TAB_SIZE,
            RTE_CACHE_LINE_SIZE, rte_socket_id());
    for (i = 0; i < DPVS_CONN_TAB_SIZE; i++)
        INIT_LIST_HEAD(&dp_vs_ct_tab[i]);
    rte_spinlock_init(&dp_vs_ct_lock);

    /*
     * unlike linux per_cpu() which can assign CPU number,
     * RTE_PER_LCORE() can only access own instances.
     * it make codes looks strange.
     */
    rte_eal_mp_remote_launch(conn_init_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if ((err = rte_eal_wait_lcore(lcore)) < 0) {
            RTE_LOG(WARNING, IPVS, "%s: lcore %d: %s.\n",
                    __func__, lcore, dpvs_strerror(err));
        }
    }

    conn_ctrl_init();

    /* connection cache on each NUMA socket */
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(poolname, sizeof(poolname), "dp_vs_conn_%d", i);
        dp_vs_conn_cache[i] = rte_mempool_create(poolname,
                                    conn_pool_size,
                                    sizeof(struct dp_vs_conn),
                                    conn_pool_cache,
                                    0, NULL, NULL, NULL, NULL,
                                    i, 0);
        if (!dp_vs_conn_cache[i]) {
            err = EDPVS_NOMEM;
            goto cleanup;
        }
    }

    dp_vs_conn_rnd = (uint32_t)random();

    return EDPVS_OK;

cleanup:
    dp_vs_conn_term();
    return err;
}

int dp_vs_conn_term(void)
{
    lcoreid_t lcore;

    /* no API opposite to rte_mempool_create() */

    rte_eal_mp_remote_launch(conn_term_lcore, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        rte_eal_wait_lcore(lcore);
    }

    conn_ctrl_term();

    return EDPVS_OK;
}

static void conn_pool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pktpool_size;

    assert(str);
    pktpool_size = atoi(str);
    if (pktpool_size < DPVS_CONN_POOL_SIZE_MIN) {
        RTE_LOG(WARNING, IPVS, "invalid conn_pool_size %s, using default %d\n",
                str, DPVS_CONN_POOL_SIZE_DEF);
        conn_pool_size = DPVS_CONN_POOL_SIZE_DEF;
    } else {
        is_power2(pktpool_size, 0, &pktpool_size);
        RTE_LOG(INFO, IPVS, "conn_pool_size = %d (round to 2^n)\n", pktpool_size);
        conn_pool_size = pktpool_size;
    }

    FREE_PTR(str);
}

static void conn_pool_cache_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int pktpool_cache;

    assert(str);
    if ((pktpool_cache = atoi(str)) > 0) {
        is_power2(pktpool_cache, 0, &pktpool_cache);
        RTE_LOG(INFO, IPVS, "conn_pool_cache = %d (round to 2^n)\n", pktpool_cache);
        conn_pool_cache = pktpool_cache;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid conn_pool_cache %s, using default %d\n",
                str, DPVS_CONN_CACHE_SIZE_DEF);
        conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;
    }

    FREE_PTR(str);
}

static void conn_init_timeout_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int init_timeout;

    assert(str);
    init_timeout = atoi(str);
    if (init_timeout > IPVS_TIMEOUT_MIN && init_timeout < IPVS_TIMEOUT_MAX) {
        RTE_LOG(INFO, IPVS, "conn_init_timeout = %d\n", init_timeout);
        conn_init_timeout = init_timeout;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid conn_init_timeout %s, using default %d\n",
                str, DPVS_CONN_INIT_TIMEOUT_DEF);
        conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;
    }

    FREE_PTR(str);
}

static void conn_expire_quiscent_template_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "conn_expire_quiescent_template ON\n");
    conn_expire_quiescent_template = true;
}

void ipvs_conn_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        conn_pool_size = DPVS_CONN_POOL_SIZE_DEF;
        conn_pool_cache = DPVS_CONN_CACHE_SIZE_DEF;
    }
    /* KW_TYPE_NORMAL keyword */
    conn_init_timeout = DPVS_CONN_INIT_TIMEOUT_DEF;
    conn_expire_quiescent_template = false;
}

void install_ipvs_conn_keywords(void)
{
    install_sublevel();
    install_keyword("conn_pool_size", conn_pool_size_handler, KW_TYPE_INIT);
    install_keyword("conn_pool_cache", conn_pool_cache_handler, KW_TYPE_INIT);
    install_keyword("conn_init_timeout", conn_init_timeout_handler, KW_TYPE_NORMAL);
    install_keyword("expire_quiescent_template", conn_expire_quiscent_template_handler,
            KW_TYPE_NORMAL);
    install_xmit_keywords();
    install_sublevel_end();
}
