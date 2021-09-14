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

struct tbf_sch_shared {
    int64_t                 tokens;     /* current tokens, in time */
    int64_t                 ptokens;    /* current peak tokens, in time */
    int64_t                 t_c;        /* Time check-point */
    rte_spinlock_t          lock;
};

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
    struct tbf_sch_shared   *shm;
};

static inline bool tbf_peak_present(const struct tbf_sch_priv *priv)
{
    return priv->peak.rate_bytes_ps;
}

static int tbf_enqueue(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);

    if (unlikely(mbuf->pkt_len > priv->max_size)) {
        RTE_LOG(WARNING, TC, "%s: packet too big.\n", __func__);
        return qsch_drop(sch, mbuf);
    }

    /*
     * enqueue is simple: just put into inner backlog queue,
     * if it's full then drop the packet (by inner queue).
     */
    if (unlikely(sch->qstats.backlog + mbuf->pkt_len > priv->limit)) {
        return qsch_drop(sch, mbuf);
    }

    return qsch_enqueue_tail(sch, mbuf);
}

static struct rte_mbuf *tbf_dequeue(struct Qsch *sch)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    struct rte_mbuf *mbuf;
    int64_t now, toks, ptoks; /* need "signed" to compare with 0 */
    unsigned int pkt_len;

    mbuf = qsch_peek_head(sch);
    if (unlikely(!mbuf))
        return NULL;
    pkt_len = mbuf->pkt_len;

    if (!rte_spinlock_trylock(&priv->shm->lock))
        return NULL;  // Someone is doing what I want to, let it go.

    now = tc_get_ns();
    /* "tokens" arrived since last check point, not exceed bucket depth.
     * note all of them are present in time manner. */
    toks = min_t(int64_t, now - priv->shm->t_c, priv->buffer);
    ptoks = 0;

    if (unlikely(toks < 0)) {
        rte_spinlock_unlock(&priv->shm->lock);
        RTE_LOG(WARNING, TC, "[%d] %s：token producer bug?\n", rte_lcore_id(), __func__);
        return NULL;
    }

    if (tbf_peak_present(priv)) {
        /* calc peak-tokens with new arrived tokens plus remaining peak-tokens
         * should not exceed mtu ("minburst") */
        ptoks = toks + priv->shm->ptokens;
        if (ptoks > priv->mtu)
            ptoks = priv->mtu;
        /* minus current pkt size to check if ptoks is enough later */
        ptoks -= (int64_t)qsch_l2t_ns(&priv->peak, pkt_len);
    }

    /* calc tokens with new arrived tokens plus remaining tokens
     * should not exceed bucket depth ("burst") */
    toks += priv->shm->tokens;
    if (toks > priv->buffer)
        toks = priv->buffer;
    /* minus current pkt size to check if toks is enough later */
    toks -= (int64_t)qsch_l2t_ns(&priv->rate, pkt_len);

    /* dequeue if token or peak-tokens is enough.
     * current toks/ptoks was subtracted by pkt_len inadvance.
     * so < zero means not enough and >= 0 means enough. */
    if ((toks|ptoks) >= 0) {
        mbuf = qsch_dequeue_head(sch);
        if (unlikely(!mbuf))
            return NULL;

        /* update variables */
        priv->shm->t_c = now; /* only need to update time checkpoint when consumed */
        priv->shm->tokens = toks;
        priv->shm->ptokens = ptoks;
        rte_spinlock_unlock(&priv->shm->lock);
        return mbuf;
    }
    rte_spinlock_unlock(&priv->shm->lock);

    /* token not enough */
    sch->qstats.overlimits++;
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

    /* save values to sch */
    priv->limit = limit; /* could be zero (no backlog queue, drop if no token) */
    priv->max_size = max_size;
    priv->buffer = buffer;
    priv->mtu = mtu;
    priv->rate = rate;
    priv->peak = peak;

    if (rte_lcore_id() != g_master_lcore_id)
        return EDPVS_OK;

    assert(priv->shm);
    rte_spinlock_lock(&priv->shm->lock);
    priv->shm->t_c = tc_get_ns();
    priv->shm->tokens = priv->buffer;
    priv->shm->ptokens = priv->mtu;
    rte_spinlock_unlock(&priv->shm->lock);

    return EDPVS_OK;
}

static int tbf_init(struct Qsch *sch, const void *arg)
{
    struct tbf_sch_priv *priv = qsch_priv(sch);
    const struct tc_tbf_qopt *qopt = arg;

    if (!qopt)
        return EDPVS_OK;

    priv->shm = qsch_shm_get_or_create(sch, sizeof(struct tbf_sch_shared));
    if (!priv->shm)
        return EDPVS_NOMEM;

    return tbf_change(sch, qopt);
}

static void tbf_destroy(struct Qsch *sch)
{
    qsch_shm_put_or_destroy(sch);
}

static void tbf_reset(struct Qsch *sch)
{
    struct tbf_sch_priv *priv;

    qsch_reset_queue(sch);

    if (rte_lcore_id() != g_master_lcore_id)
        return;
    priv = qsch_priv(sch);

    rte_spinlock_lock(&priv->shm->lock);
    priv->shm->t_c = tc_get_ns();
    priv->shm->tokens = priv->buffer;
    priv->shm->ptokens = priv->mtu;
    rte_spinlock_unlock(&priv->shm->lock);
}

static int tbf_dump(struct Qsch *sch, void *arg)
{
    struct tbf_sch_priv *priv;
    struct tc_tbf_qopt *qopt = arg;

    if (!sch || sch->ops != &tbf_sch_ops)
        return EDPVS_INVAL;

    priv = qsch_priv(sch);

    memset(qopt, 0, sizeof(*qopt));
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
