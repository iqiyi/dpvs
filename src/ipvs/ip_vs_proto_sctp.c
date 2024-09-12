// SPDX-License-Identifier: GPL-2.0
#include "conf/common.h"
#include "dpdk.h"
#include "mbuf.h"
#include "ipv6.h"
#include "route6.h"
#include "neigh.h"
#include "ipvs/ipvs.h"
#include "ipvs/proto.h"
#include "ipvs/proto_sctp.h"
#include "ipvs/conn.h"
#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/synproxy.h"
#include "ipvs/blklst.h"
#include "ipvs/whtlst.h"
#include "parser/parser.h"
#include "rte_hash_crc.h"

/*
 * Compute the SCTP checksum in network byte order for a given mbuf chain m
 * which contains an SCTP packet starting at offset.
 * Since this function is also called by ipfw, don't assume that
 * it is compiled on a kernel with SCTP support.
 */
static inline uint32_t sctp_calculate_cksum(struct rte_mbuf *mbuf,
                        int32_t offset)
{
    int len;
    uint32_t _old, _new;

    len = mbuf->data_len;

    struct sctphdr *sh =
        rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, offset);

    _old = sh->checksum;

    sh->checksum = 0;

    _new = ~rte_hash_crc(rte_pktmbuf_mtod_offset(mbuf, const void *,
                             offset),
                 len - offset, ~(uint32_t)0);

    sh->checksum = _old;

    return _new;
}

static int sctp_csum_check(struct dp_vs_proto *proto, int af,
               struct rte_mbuf *mbuf);

static struct dp_vs_conn *sctp_conn_lookup(struct dp_vs_proto *proto,
                       const struct dp_vs_iphdr *iph,
                       struct rte_mbuf *mbuf, int *direct,
                       bool reverse, bool *drop,
                       lcoreid_t *peer_cid)
{
    struct sctphdr *sh, _sctph;
    struct sctp_chunkhdr *sch, _schunkh;
    struct dp_vs_conn *conn;
    assert(proto && iph && mbuf);

    sh = mbuf_header_pointer(mbuf, iph->len, sizeof(_sctph), &_sctph);
    if (unlikely(!sh))
        return NULL;

    sch = mbuf_header_pointer(mbuf, iph->len + sizeof(_sctph),
                  sizeof(_schunkh), &_schunkh);
    if (unlikely(!sch))
        return NULL;

    if (dp_vs_blklst_filtered(iph->af, iph->proto, &iph->daddr, sh->dest_port,
                &iph->saddr, mbuf)) {
        *drop = true;
        return NULL;
    }

    if (dp_vs_whtlst_filtered(iph->af, iph->proto, &iph->daddr, sh->dest_port,
                &iph->saddr, mbuf)) {
        *drop = true;
        return NULL;
    }

    conn = dp_vs_conn_get(iph->af, iph->proto, &iph->saddr, &iph->daddr,
                  sh->src_port, sh->dest_port, direct, reverse);

    /*
     * L2 confirm neighbour
     * pkt in from client confirm neighbour to client
     * pkt out from rs confirm neighbour to rs
     */
    if (conn != NULL) {
        if ((*direct == DPVS_CONN_DIR_INBOUND) && conn->out_dev &&
            (!inet_is_addr_any(tuplehash_in(conn).af,
                       &conn->out_nexthop))) {
            neigh_confirm(tuplehash_in(conn).af, &conn->out_nexthop,
                      conn->out_dev);
        } else if ((*direct == DPVS_CONN_DIR_OUTBOUND) &&
               conn->in_dev &&
               (!inet_is_addr_any(tuplehash_out(conn).af,
                          &conn->in_nexthop))) {
            neigh_confirm(tuplehash_out(conn).af, &conn->in_nexthop,
                      conn->in_dev);
        }
    } else {
        struct dp_vs_redirect *r;

        r = dp_vs_redirect_get(iph->af, iph->proto, &iph->saddr,
                       &iph->daddr, sh->src_port,
                       sh->dest_port);
        if (r) {
            *peer_cid = r->cid;
        }
    }

    return conn;
}

static int sctp_conn_schedule(struct dp_vs_proto *proto,
                  const struct dp_vs_iphdr *iph,
                  struct rte_mbuf *mbuf, struct dp_vs_conn **conn,
                  int *verdict)
{
    struct sctphdr *sh, _sctph;
    struct dp_vs_service *svc;

    assert(proto && iph && mbuf && conn && verdict);

    sh = mbuf_header_pointer(mbuf, iph->len, sizeof(_sctph), &_sctph);
    if (unlikely(!sh)) {
        *verdict = INET_DROP;
        return EDPVS_INVPKT;
    }

    svc = dp_vs_service_lookup(iph->af, iph->proto, &iph->daddr,
                   sh->dest_port, 0, mbuf, NULL, rte_lcore_id());
    if (!svc) {
        *verdict = INET_ACCEPT;
        return EDPVS_NOSERV;
    }

    *conn = dp_vs_schedule(svc, iph, mbuf, false);
    if (!*conn) {
        *verdict = INET_DROP;
        return EDPVS_RESOURCE;
    }

    return EDPVS_OK;
}

static void sctp_nat_csum(struct rte_mbuf *mbuf, struct sctphdr *sctph,
              unsigned int offset)
{
    sctph->checksum = sctp_calculate_cksum(mbuf, offset);
}

static int sctp_fnat_in_handler(struct dp_vs_proto *proto,
                struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct sctphdr *sh;

    /* af/mbuf may be changed for nat64 which in af is ipv6 and out is ipv4 */
    int af = tuplehash_out(conn).af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf) : ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*sh)) != 0)
        return EDPVS_INVPKT;

    sh = rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, iphdrlen);

    /* Some checks before mangling */
    if (sctp_csum_check(proto, af, mbuf))
        return EDPVS_INVAL;

    /* L4 translation */
    sh->src_port = conn->lport;
    sh->dest_port = conn->dport;

    sctp_nat_csum(mbuf, sh, iphdrlen);

    return EDPVS_OK;
}

static int sctp_fnat_out_handler(struct dp_vs_proto *proto,
                 struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct sctphdr *sh;

    /* af/mbuf may be changed for nat64 which in af is ipv6 and out is ipv4 */
    int af = tuplehash_in(conn).af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf) : ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*sh)) != 0)
        return EDPVS_INVPKT;

    sh = rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, iphdrlen);

    /* Some checks before mangling */
    if (sctp_csum_check(proto, af, mbuf))
        return EDPVS_INVAL;

    /* L4 translation */
    sh->src_port = conn->vport;
    sh->dest_port = conn->cport;

    sctp_nat_csum(mbuf, sh, iphdrlen);

    return EDPVS_OK;
}

static int sctp_nat_in_handler(struct dp_vs_proto *proto,
                   struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct sctphdr *sh;
    int af = conn->af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf) : ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*sh)) != 0)
        return EDPVS_INVPKT;

    sh = rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, iphdrlen);

    /* Some checks before mangling */
    if (sctp_csum_check(proto, af, mbuf))
        return EDPVS_INVAL;

    /* Only update csum if we really have to */
    sh->dest_port = conn->dport;
    sctp_nat_csum(mbuf, sh, iphdrlen);

    return EDPVS_OK;
}

static int sctp_nat_out_handler(struct dp_vs_proto *proto,
                struct dp_vs_conn *conn, struct rte_mbuf *mbuf)
{
    struct sctphdr *sh;
    int af = conn->af;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf) : ip4_hdrlen(mbuf));

    if (mbuf_may_pull(mbuf, iphdrlen + sizeof(*sh)) != 0)
        return EDPVS_INVPKT;

    sh = rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, iphdrlen);

    /* Some checks before mangling */
    if (sctp_csum_check(proto, af, mbuf))
        return EDPVS_INVAL;

    /* Only update csum if we really have to */
    sh->src_port = conn->vport;
    sctp_nat_csum(mbuf, sh, iphdrlen);

    return EDPVS_OK;
}

static int sctp_csum_check(struct dp_vs_proto *proto, int af,
               struct rte_mbuf *mbuf)
{
    struct sctphdr *sh;
    uint32_t cmp, val;
    int iphdrlen = ((AF_INET6 == af) ? ip6_hdrlen(mbuf) : ip4_hdrlen(mbuf));

    sh = rte_pktmbuf_mtod_offset(mbuf, struct sctphdr *, iphdrlen);
    cmp = sh->checksum;
    val = sctp_calculate_cksum(mbuf, iphdrlen);

    if (val != cmp) {
        /* CRC failure, dump it. */
        RTE_LOG(WARNING, IPVS, "Failed checksum for %d %s %p!\n", af,
            proto->name, mbuf);
        return EDPVS_INVAL;
    }
    return EDPVS_OK;
}

/* RFC 2960, 3.2 Chunk Field Descriptions */
static __u8 sctp_events[] = {
    [SCTP_DATA] = DPVS_SCTP_DATA,
    [SCTP_INITIATION] = DPVS_SCTP_INIT,
    [SCTP_INITIATION_ACK] = DPVS_SCTP_INIT_ACK,
    [SCTP_SELECTIVE_ACK] = DPVS_SCTP_DATA,
    [SCTP_HEARTBEAT_REQUEST] = DPVS_SCTP_DATA,
    [SCTP_HEARTBEAT_ACK] = DPVS_SCTP_DATA,
    [SCTP_ABORT_ASSOCIATION] = DPVS_SCTP_ABORT,
    [SCTP_SHUTDOWN] = DPVS_SCTP_SHUTDOWN,
    [SCTP_SHUTDOWN_ACK] = DPVS_SCTP_SHUTDOWN_ACK,
    [SCTP_OPERATION_ERROR] = DPVS_SCTP_ERROR,
    [SCTP_COOKIE_ECHO] = DPVS_SCTP_COOKIE_ECHO,
    [SCTP_COOKIE_ACK] = DPVS_SCTP_COOKIE_ACK,
    [SCTP_ECN_ECHO] = DPVS_SCTP_DATA,
    [SCTP_ECN_CWR] = DPVS_SCTP_DATA,
    [SCTP_SHUTDOWN_COMPLETE] = DPVS_SCTP_SHUTDOWN_COMPLETE,
};

/* SCTP States:
 * See RFC 2960, 4. SCTP Association State Diagram
 *
 * New states (not in diagram):
 * - INIT1 state: use shorter timeout for dropped INIT packets
 * - REJECTED state: use shorter timeout if INIT is rejected with ABORT
 * - INIT, COOKIE_SENT, COOKIE_REPLIED, COOKIE states: for better debugging
 *
 * The states are as seen in real server. In the diagram, INIT1, INIT,
 * COOKIE_SENT and COOKIE_REPLIED processing happens in CLOSED state.
 *
 * States as per packets from client (C) and server (S):
 *
 * Setup of client connection:
 * DPVS_SCTP_S_INIT1: First C:INIT sent, wait for S:INIT-ACK
 * DPVS_SCTP_S_INIT: Next C:INIT sent, wait for S:INIT-ACK
 * DPVS_SCTP_S_COOKIE_SENT: S:INIT-ACK sent, wait for C:COOKIE-ECHO
 * DPVS_SCTP_S_COOKIE_REPLIED: C:COOKIE-ECHO sent, wait for S:COOKIE-ACK
 *
 * Setup of server connection:
 * DPVS_SCTP_S_COOKIE_WAIT: S:INIT sent, wait for C:INIT-ACK
 * DPVS_SCTP_S_COOKIE: C:INIT-ACK sent, wait for S:COOKIE-ECHO
 * DPVS_SCTP_S_COOKIE_ECHOED: S:COOKIE-ECHO sent, wait for C:COOKIE-ACK
 */

#define sNO DPVS_SCTP_S_NONE
#define sI1 DPVS_SCTP_S_INIT1
#define sIN DPVS_SCTP_S_INIT
#define sCS DPVS_SCTP_S_COOKIE_SENT
#define sCR DPVS_SCTP_S_COOKIE_REPLIED
#define sCW DPVS_SCTP_S_COOKIE_WAIT
#define sCO DPVS_SCTP_S_COOKIE
#define sCE DPVS_SCTP_S_COOKIE_ECHOED
#define sES DPVS_SCTP_S_ESTABLISHED
#define sSS DPVS_SCTP_S_SHUTDOWN_SENT
#define sSR DPVS_SCTP_S_SHUTDOWN_RECEIVED
#define sSA DPVS_SCTP_S_SHUTDOWN_ACK_SENT
#define sRJ DPVS_SCTP_S_REJECTED
#define sCL DPVS_SCTP_S_CLOSED

static const __u8 sctp_states[DPVS_DIR_LAST][DPVS_SCTP_EVENT_LAST][DPVS_SCTP_S_LAST] = {
    { /* INPUT */
/*          sNO, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL*/
/* d   */ { sES, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* i   */ { sI1, sIN, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sIN, sIN },
/* i_a */ { sCW, sCW, sCW, sCS, sCR, sCO, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* c_e */ { sCR, sIN, sIN, sCR, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* c_a */ { sES, sI1, sIN, sCS, sCR, sCW, sCO, sES, sES, sSS, sSR, sSA, sRJ, sCL },
/* s   */ { sSR, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sSR, sSS, sSR, sSA, sRJ, sCL },
/* s_a */ { sCL, sIN, sIN, sCS, sCR, sCW, sCO, sCE, sES, sCL, sSR, sCL, sRJ, sCL },
/* s_c */ { sCL, sCL, sCL, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sCL, sRJ, sCL },
/* err */ { sCL, sI1, sIN, sCS, sCR, sCW, sCO, sCL, sES, sSS, sSR, sSA, sRJ, sCL },
/* ab  */ { sCL, sCL, sCL, sCL, sCL, sRJ, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
    },
    { /* OUTPUT */
/*          sNO, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL*/
/* d   */ { sES, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* i   */ { sCW, sCW, sCW, sCW, sCW, sCW, sCW, sCW, sES, sCW, sCW, sCW, sCW, sCW },
/* i_a */ { sCS, sCS, sCS, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* c_e */ { sCE, sCE, sCE, sCE, sCE, sCE, sCE, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* c_a */ { sES, sES, sES, sES, sES, sES, sES, sES, sES, sSS, sSR, sSA, sRJ, sCL },
/* s   */ { sSS, sSS, sSS, sSS, sSS, sSS, sSS, sSS, sSS, sSS, sSR, sSA, sRJ, sCL },
/* s_a */ { sSA, sSA, sSA, sSA, sSA, sCW, sCO, sCE, sES, sSA, sSA, sSA, sRJ, sCL },
/* s_c */ { sCL, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* err */ { sCL, sCL, sCL, sCL, sCL, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* ab  */ { sCL, sRJ, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
    },
    { /* INPUT-ONLY */
/*          sNO, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL*/
/* d   */ { sES, sI1, sIN, sCS, sCR, sES, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* i   */ { sI1, sIN, sIN, sIN, sIN, sIN, sCO, sCE, sES, sSS, sSR, sSA, sIN, sIN },
/* i_a */ { sCE, sCE, sCE, sCE, sCE, sCE, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* c_e */ { sES, sES, sES, sES, sES, sES, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* c_a */ { sES, sI1, sIN, sES, sES, sCW, sES, sES, sES, sSS, sSR, sSA, sRJ, sCL },
/* s   */ { sSR, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sSR, sSS, sSR, sSA, sRJ, sCL },
/* s_a */ { sCL, sIN, sIN, sCS, sCR, sCW, sCO, sCE, sCL, sCL, sSR, sCL, sRJ, sCL },
/* s_c */ { sCL, sCL, sCL, sCL, sCL, sCW, sCO, sCE, sES, sSS, sCL, sCL, sRJ, sCL },
/* err */ { sCL, sI1, sIN, sCS, sCR, sCW, sCO, sCE, sES, sSS, sSR, sSA, sRJ, sCL },
/* ab  */ { sCL, sCL, sCL, sCL, sCL, sRJ, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
    },
};

#define DPVS_SCTP_MAX_RTO (60 + 1)

/* Timeout table[state] */
static int sctp_timeouts[DPVS_SCTP_S_LAST + 1] = {
    [DPVS_SCTP_S_NONE] = 2,
    [DPVS_SCTP_S_INIT1] = (0 + 3 + 1),
    [DPVS_SCTP_S_INIT] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_COOKIE_SENT] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_COOKIE_REPLIED] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_COOKIE_WAIT] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_COOKIE] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_COOKIE_ECHOED] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_ESTABLISHED] = 15 * 60,
    [DPVS_SCTP_S_SHUTDOWN_SENT] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_SHUTDOWN_RECEIVED] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_SHUTDOWN_ACK_SENT] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_REJECTED] = (0 + 3 + 1),
    [DPVS_SCTP_S_CLOSED] = DPVS_SCTP_MAX_RTO,
    [DPVS_SCTP_S_LAST] = 2,
};

static const char *sctp_state_name_table[DPVS_SCTP_S_LAST + 1] = {
    [DPVS_SCTP_S_NONE] = "NONE",
    [DPVS_SCTP_S_INIT1] = "INIT1",
    [DPVS_SCTP_S_INIT] = "INIT",
    [DPVS_SCTP_S_COOKIE_SENT] = "C-SENT",
    [DPVS_SCTP_S_COOKIE_REPLIED] = "C-REPLIED",
    [DPVS_SCTP_S_COOKIE_WAIT] = "C-WAIT",
    [DPVS_SCTP_S_COOKIE] = "COOKIE",
    [DPVS_SCTP_S_COOKIE_ECHOED] = "C-ECHOED",
    [DPVS_SCTP_S_ESTABLISHED] = "ESTABLISHED",
    [DPVS_SCTP_S_SHUTDOWN_SENT] = "S-SENT",
    [DPVS_SCTP_S_SHUTDOWN_RECEIVED] = "S-RECEIVED",
    [DPVS_SCTP_S_SHUTDOWN_ACK_SENT] = "S-ACK-SENT",
    [DPVS_SCTP_S_REJECTED] = "REJECTED",
    [DPVS_SCTP_S_CLOSED] = "CLOSED",
    [DPVS_SCTP_S_LAST] = "BUG!",
};

static const char *sctp_state_name(int state)
{
    if (state >= DPVS_SCTP_S_LAST)
        return "ERR!";
    if (sctp_state_name_table[state])
        return sctp_state_name_table[state];
    return "?";
}

static int sctp_state_trans(struct dp_vs_proto *proto, struct dp_vs_conn *conn,
                struct rte_mbuf *mbuf, int dir)
{
    struct sctp_chunkhdr _sctpch, *sch;
    unsigned char chunk_type;
    int event, next_state;
    int iphdrlen, cofs;
    assert(proto && conn && mbuf);

    iphdrlen =
        ((AF_INET6 == conn->af) ? ip6_hdrlen(mbuf) : ip4_hdrlen(mbuf));

    cofs = iphdrlen + sizeof(struct sctphdr);
    sch = mbuf_header_pointer(mbuf, cofs, sizeof(_sctpch), &_sctpch);
    if (!sch)
        return EDPVS_INVPKT;

    chunk_type = sch->chunk_type;
    /*
     * Section 3: Multiple chunks can be bundled into one SCTP packet
     * up to the MTU size, except for the INIT, INIT ACK, and
     * SHUTDOWN COMPLETE chunks. These chunks MUST NOT be bundled with
     * any other chunk in a packet.
     *
     * Section 3.3.7: DATA chunks MUST NOT be bundled with ABORT. Control
     * chunks (except for INIT, INIT ACK, and SHUTDOWN COMPLETE) MAY be
     * bundled with an ABORT, but they MUST be placed before the ABORT
     * in the SCTP packet or they will be ignored by the receiver.
     */
    if ((sch->chunk_type == SCTP_COOKIE_ECHO) ||
        (sch->chunk_type == SCTP_COOKIE_ACK)) {
        int clen = ntohs(sch->chunk_length);

        if (clen >= sizeof(_sctpch)) {
            sch = mbuf_header_pointer(mbuf,
                          cofs + RTE_ALIGN(clen, 4),
                          sizeof(_sctpch), &_sctpch);
            if (sch && sch->chunk_type == SCTP_ABORT_ASSOCIATION)
                chunk_type = sch->chunk_type;
        }
    }

    event = (chunk_type < sizeof(sctp_events)) ? sctp_events[chunk_type] :
                             DPVS_SCTP_DATA;

    next_state = sctp_states[dir][event][conn->state];

    if (next_state != conn->state) {
        struct dp_vs_dest *dest = conn->dest;

#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, IPVS,
            "%s %s  %X:%d->"
            "%X:%d state: %s->%s conn->refcnt:%d\n",
            proto->name,
            ((dir == DPVS_CONN_DIR_OUTBOUND) ? "output " :
                               "input "),
            inet_addr_fold(conn->af, &conn->caddr),
            ntohs(conn->dport),
            inet_addr_fold(conn->af, &conn->caddr),
            ntohs(conn->cport), sctp_state_name(conn->state),
            sctp_state_name(next_state),
            rte_atomic32_read(&conn->refcnt));
#endif
        if (dest) {
            if (!(conn->flags & DPVS_CONN_F_INACTIVE) &&
                (next_state != DPVS_SCTP_S_ESTABLISHED)) {
                rte_atomic32_dec(&dest->actconns);
                rte_atomic32_inc(&dest->inactconns);
                conn->flags |= DPVS_CONN_F_INACTIVE;
            } else if ((conn->flags & DPVS_CONN_F_INACTIVE) &&
                   (next_state == DPVS_SCTP_S_ESTABLISHED)) {
                rte_atomic32_inc(&dest->actconns);
                rte_atomic32_dec(&dest->inactconns);
                conn->flags &= ~DPVS_CONN_F_INACTIVE;
            }
        }
        conn->old_state = conn->state;
        conn->state = next_state;
    }
    dp_vs_conn_set_timeout(conn, proto);
    return EDPVS_OK;
}

static int sctp_conn_expire(struct dp_vs_proto *proto, struct dp_vs_conn *conn)
{
    if (conn && conn->prot_data)
        rte_free(conn->prot_data);

    return EDPVS_OK;
}

static int sctp_conn_expire_quiescent(struct dp_vs_conn *conn)
{
    dp_vs_conn_expire_now(conn);

    return EDPVS_OK;
}

static int sctp_init(struct dp_vs_proto *proto)
{
    if (!proto)
        return EDPVS_INVAL;        

    proto->timeout_table = sctp_timeouts;

    return EDPVS_OK;
}

static int sctp_exit(struct dp_vs_proto *proto)
{
    return EDPVS_OK;
}

struct dp_vs_proto dp_vs_proto_sctp = {
    .name = "SCTP",
    .proto = IPPROTO_SCTP,
    .init = sctp_init,
    .exit = sctp_exit,
    .conn_sched = sctp_conn_schedule,
    .conn_lookup = sctp_conn_lookup,
    .conn_expire = sctp_conn_expire,
    .conn_expire_quiescent = sctp_conn_expire_quiescent,
    .nat_in_handler = sctp_nat_in_handler,
    .nat_out_handler = sctp_nat_out_handler,
    .fnat_in_handler = sctp_fnat_in_handler,
    .fnat_out_handler = sctp_fnat_out_handler,
    .snat_in_handler = sctp_nat_in_handler,
    .snat_out_handler = sctp_nat_out_handler,
    .state_trans = sctp_state_trans,
    .state_name = sctp_state_name,
};
