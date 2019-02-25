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
 * the pfifo_fast scheduler of traffic control module.
 * see linux/net/sched/sch_generic.c
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "netif.h"
#include "tc/tc.h"
#include "conf/tc.h"

#define TC_PRIO_MAX             15

static const uint8_t prio2band[TC_PRIO_MAX + 1] = {
    1, 2, 2, 2, 1, 2, 0, 0 , 1, 1, 1, 1, 1, 1, 1, 1
};

#define PFIFO_FAST_BANDS        3

static const int bitmap2band[] = {-1, 0, 1, 0, 2, 0, 1, 0};

struct pfifo_fast_priv {
    uint32_t bitmap[RTE_MAX_LCORE];
    struct tc_mbuf_head q[RTE_MAX_LCORE][PFIFO_FAST_BANDS];

#define this_bitmap bitmap[rte_lcore_id()]
#define this_pff_q  q[rte_lcore_id()]
};

static inline struct tc_mbuf_head *band2list(struct pfifo_fast_priv *priv,
                                             int band)
{
    assert(band >= 0 && band < PFIFO_FAST_BANDS);

    return priv->this_pff_q + band;
}

static inline struct tc_mbuf_head *band2list_cpu(struct pfifo_fast_priv *priv,
                                                 int band, lcoreid_t cid)
{
    assert(band >= 0 && band < PFIFO_FAST_BANDS);

    return priv->q[cid] + band;
}

static int pfifo_fast_enqueue(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    int band, err;
    uint8_t prio = 0;
    struct pfifo_fast_priv *priv;
    struct tc_mbuf_head *qh;

    /* sch->limit is same as dev->txq_desc_nb */
    if (unlikely(sch->this_q.qlen >= sch->limit)) {
#if defined(CONFIG_TC_DEBUG)
        RTE_LOG(WARNING, TC, "%s: queue is full.\n", __func__);
#endif
        return qsch_drop(sch, mbuf);
    }

    if (unlikely(mbuf->udata64 > 0 && mbuf->udata64 <= TC_PRIO_MAX &&
                 mbuf->packet_type == ETH_P_IP))
        prio = (uint8_t)mbuf->udata64;

    band = prio2band[prio];
    priv = qsch_priv(sch);
    qh = band2list(priv, band);

    err = __qsch_enqueue_tail(sch, mbuf, qh);
    if (err == EDPVS_OK) {
        priv->this_bitmap |= (1 << band);
        sch->this_q.qlen++;
        sch->this_qstats.qlen++;
    }

    return err;
}

static struct rte_mbuf *pfifo_fast_dequeue(struct Qsch *sch)
{
    struct pfifo_fast_priv *priv = qsch_priv(sch);
    int band = bitmap2band[priv->this_bitmap];
    struct tc_mbuf_head *qh;
    struct rte_mbuf *mbuf;

    if (unlikely(band < 0))
        return NULL;

    qh = band2list(priv, band);
    mbuf = __qsch_dequeue_head(sch, qh);

    if (mbuf) {
        sch->this_q.qlen--;
        sch->this_qstats.qlen--;
    }

    if (likely(qh->qlen == 0))
        priv->this_bitmap &= ~(1 << band);

    return mbuf;
}

static struct rte_mbuf *pfifo_fast_peek(struct Qsch *sch)
{
    struct pfifo_fast_priv *priv = qsch_priv(sch);
    int band = bitmap2band[priv->this_bitmap];
    struct tc_mbuf_head *qh;
    struct tc_mbuf *tm;

    if (unlikely(band < 0))
        return NULL;

    qh = band2list(priv, band);
    tm = list_first_entry(&qh->mbufs, struct tc_mbuf, list);
    if (tm)
        return tm->mbuf;
    else
        return NULL;
}

static int pfifo_fast_init(struct Qsch *sch, const void *arg)
{
    int band;
    lcoreid_t cid;
    struct pfifo_fast_priv *priv = qsch_priv(sch);

    for (cid = 0; cid < NELEMS(priv->q); cid++) {
        for (band = 0; band < PFIFO_FAST_BANDS; band++) {
            tc_mbuf_head_init(band2list_cpu(priv, band, cid));
        }
    }

    /* FIXME: txq_desc_nb is not set when alloc device.
     * we can move tc_init_dev to dev start phase but not
     * all dev will be start now, netif need be modified. */
#if 0
    sch->limit = qsch_dev(sch)->txq_desc_nb;
#else
    sch->limit = 128;
#endif
    return EDPVS_OK;
}

static void pfifo_fast_reset(struct Qsch *sch)
{
    int band;
    lcoreid_t cid;
    struct pfifo_fast_priv *priv = qsch_priv(sch);

    for (cid = 0; cid < NELEMS(priv->q); cid++) {
        for (band = 0; band < PFIFO_FAST_BANDS; band++)
            __qsch_reset_queue(sch, band2list_cpu(priv, band, cid));

        priv->bitmap[cid] = 0;
        sch->q[cid].qlen = 0;
        sch->qstats[cid].qlen = 0;
    }
}

static int pfifo_fast_dump(struct Qsch *sch, void *arg)
{
    struct tc_prio_qopt *qopt = arg;

    qopt->bands = PFIFO_FAST_BANDS;
    memcpy(qopt->priomap, prio2band, sizeof(qopt->priomap));

    return EDPVS_OK;
}

struct Qsch_ops pfifo_fast_ops = {
    .name       = "pfifo_fast",
    .priv_size  = sizeof(struct pfifo_fast_priv),
    .enqueue    = pfifo_fast_enqueue,
    .dequeue    = pfifo_fast_dequeue,
    .peek       = pfifo_fast_peek,
    .init       = pfifo_fast_init,
    .reset      = pfifo_fast_reset,
    .dump       = pfifo_fast_dump,
};
