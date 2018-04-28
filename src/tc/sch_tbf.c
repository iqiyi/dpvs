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
/**
 * the Token Bucket Filter scheduler of traffic control module.
 * see linux/net/sched/sch_tbf.c
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <assert.h>
#include "netif.h"
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"
#include "conf/tc.h"

extern struct Qsch_ops bfifo_sch_ops;
extern struct Qsch_ops tbf_sch_ops;

struct tbf_sch_priv {
    /* parameters */
    uint32_t                limit;      /* Maximal length of backlog: bytes */
    uint32_t                max_size;   /* max sigle packet size for enqueue.
                                           must be <= buffer or (peak-buf). */
    int64_t                 buffer;     /* Token bucket depth/rate: in time.
                                           MUST BE >= MTU/B. */
    int64_t                 mtu;        /* or "minburst", in time */
    struct qsch_rate        rate;       /* token fill speed */
    struct qsch_rate        peak;       /* max burst rate */

    /* internal variables */
    int64_t                 tokens;     /* current tokens, in time */
    int64_t                 ptokens;    /* current peak tokens, in time */
    int64_t                 t_c;        /* Time check-point */
    struct Qsch             *qsch;      /* backlog queue */
};

static inline bool tbf_peak_present(const struct tbf_sch_priv *priv)
{
    return priv->peak.rate_bytes_ps;
}

static int tbf_enqueue(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    int err;

    if (unlikely(mbuf->pkt_len > priv->max_size)) {
        RTE_LOG(WARNING, TC, "%s: packet too big.\n", __func__);
        return qsch_drop(sch, mbuf);
    }

    assert(priv->qsch);

    /*
     * enqueue is simple: just put into inner backlog queue,
     * if it's full then drop the packet (by inner queue).
     */
    err = priv->qsch->ops->enqueue(priv->qsch, mbuf);
    if (err != EDPVS_OK) {
        sch->this_qstats.drops++;
        return err;
    }

    sch->this_qstats.backlog += mbuf->pkt_len;
    sch->this_qstats.qlen++;
    sch->this_q.qlen++;
    return EDPVS_OK;
}

static struct rte_mbuf *tbf_dequeue(struct Qsch *sch)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    struct rte_mbuf *mbuf;
    int64_t now, toks, ptoks; /* need "signed" to compare with 0 */
    unsigned int pkt_len;

    assert(priv->qsch);

    mbuf = priv->qsch->ops->peek(priv->qsch);
    if (unlikely(!mbuf))
        return NULL;
    pkt_len = mbuf->pkt_len;

    now = tc_get_ns();
    /* "tokens" arrived since last check point, not exceed bucket depth.
     * note all of them are present in time manner. */
    toks = min_t(int64_t, now - priv->t_c, priv->buffer);
    ptoks = 0;

    if (tbf_peak_present(priv)) {
        /* calc peak-tokens with new arrived tokens plus remaining peak-tokens
         * should not exceed mtu ("minburst") */
        ptoks = toks + priv->ptokens;
        if (ptoks > priv->mtu)
            ptoks = priv->mtu;
        /* minus current pkt size to check if ptoks is enough later */
        ptoks -= (int64_t)qsch_l2t_ns(&priv->peak, pkt_len);
    }

    /* calc tokens with new arrived tokens plus remaining tokens
     * should not exceed bucket depth ("burst") */
    toks += priv->tokens;
    if (toks > priv->buffer)
        toks = priv->buffer;
    /* minus current pkt size to check if toks is enough later */
    toks -= (int64_t)qsch_l2t_ns(&priv->rate, pkt_len);

    /* dequeue if token or peak-tokens is enough.
     * current toks/ptoks was subtracted by pkt_len inadvance.
     * so < zero means not enough and >= 0 means enough. */
    if ((toks|ptoks) >= 0) {
        mbuf = qsch_dequeue_head(priv->qsch);
        if (unlikely(!mbuf))
            return NULL;

        /* update variables */
        priv->t_c = now; /* only need update time checkpoint when consumed */
        priv->tokens = toks;
        priv->ptokens = ptoks;

        sch->this_qstats.backlog -= pkt_len;
        sch->this_qstats.qlen--;
        sch->this_q.qlen--;
        sch->this_bstats.bytes += pkt_len;
        sch->this_bstats.packets++;

        return mbuf;
    }

    /* token not enough */
    sch->this_qstats.overlimits++;
    return NULL;
}

static int tbf_change(struct Qsch *sch, const void *arg)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    const struct tc_tbf_qopt *qopt = arg;
    int64_t buffer, mtu;
    uint64_t max_size;
    uint32_t limit;
    struct qsch_rate rate = {}, peak = {};
    struct Qsch *child = NULL;

    /* set new values or used original */
    if (qopt->rate.rate)
        rate.rate_bytes_ps = qopt->rate.rate / 8;
    else
        rate = priv->rate;

    if (qopt->limit)
        limit = qopt->limit;
    else
        limit = priv->limit;

    if (qopt->buffer)
        buffer = qsch_l2t_ns(&rate, qopt->buffer);
    else
        buffer = priv->buffer;

    if (qopt->peakrate.rate)
        peak.rate_bytes_ps = qopt->peakrate.rate / 8;
    else
        peak = priv->peak;

    if (qopt->mtu) /* minburst */
        mtu = qsch_l2t_ns(&peak, qopt->mtu);
    else if (peak.rate_bytes_ps)
        mtu = qsch_l2t_ns(&peak, qsch_t2l_ns(&peak, priv->mtu));
    else
        mtu = 0;

    /* max_size is min(burst, minburst) */
    max_size = ~0U;
    if (mtu)
        max_size = min_t(uint64_t, qsch_t2l_ns(&peak, mtu), ~0U);
    if (buffer)
        max_size = min_t(uint64_t, max_size, qsch_t2l_ns(&rate, buffer));

    /* sanity check */
    if (!max_size || !buffer || !rate.rate_bytes_ps)
        return EDPVS_INVAL;
    if (peak.rate_bytes_ps) {
        if (peak.rate_bytes_ps < rate.rate_bytes_ps)
            return EDPVS_INVAL;

        if (!mtu || qsch_t2l_ns(&peak, mtu) < qsch_dev(sch)->mtu)
            return EDPVS_INVAL;
    }

    /* set or create inner backlog queue */
    if (priv->qsch) {
        fifo_set_limit(priv->qsch, limit);
    } else {
        child = fifo_create_dflt(sch, &bfifo_sch_ops, limit);
        if (!child)
            return EDPVS_INVAL;

        priv->qsch = child;
        qsch_hash_add(child, true);
    }

    /* save values to sch */
    priv->limit = limit; /* could be zero (no backlog queue, drop if no token) */
    priv->max_size = max_size;
    priv->buffer = buffer;
    priv->mtu = mtu;
    priv->rate = rate;
    priv->peak = peak;
    priv->tokens = priv->buffer;
    priv->ptokens = priv->mtu;

    return EDPVS_OK;
}

static int tbf_init(struct Qsch *sch, const void *arg)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    const struct tc_tbf_qopt *qopt = arg;

    if (!qopt)
        return EDPVS_OK;

    priv->t_c = tc_get_ns();
    return tbf_change(sch, qopt);
}

static void tbf_destroy(struct Qsch *sch)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    if (priv->qsch)
        qsch_destroy(priv->qsch);
}

static void tbf_reset(struct Qsch *sch)
{
    lcoreid_t cid;
    struct tbf_sch_priv *priv = qsch_priv(sch);

    qsch_reset(priv->qsch);
    for (cid = 0; cid < NELEMS(sch->q); cid++) {
        sch->qstats[cid].backlog = 0;
        sch->qstats[cid].qlen = 0;
        sch->q[cid].qlen = 0;
    }

    priv->t_c = tc_get_ns();
    priv->tokens = priv->buffer;
    priv->ptokens = priv->mtu;
    return;
}

static int tbf_dump(struct Qsch *sch, void *arg)
{
    struct tbf_sch_priv *priv;
    struct tc_tbf_qopt *qopt = arg;

    if (!sch || sch->ops != &tbf_sch_ops)
        return EDPVS_INVAL;

    priv = qsch_priv(sch);

    memset(qopt, 0, sizeof(&qopt));
    qopt->rate.rate     = priv->rate.rate_bytes_ps * 8;
    qopt->peakrate.rate = priv->peak.rate_bytes_ps * 8;
    qopt->limit         = priv->limit;
    qopt->buffer        = qsch_t2l_ns(&priv->rate, priv->buffer);
    qopt->mtu           = qsch_t2l_ns(&priv->peak, priv->mtu);

    return EDPVS_OK;
}

struct Qsch_ops tbf_sch_ops = {
    .name       = "tbf",
    .priv_size  = sizeof(struct tbf_sch_priv),
    .enqueue    = tbf_enqueue,
    .dequeue    = tbf_dequeue,
    .peek       = qsch_peek_head,
    .init       = tbf_init,
    .reset      = tbf_reset,
    .destroy    = tbf_destroy,
    .change     = tbf_change,
    .dump       = tbf_dump,
};
