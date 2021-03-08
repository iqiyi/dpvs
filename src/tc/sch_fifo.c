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
 * the FIFO scheduler of traffic control module.
 * see linux/net/sched/sch_fifo.c
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <linux/pkt_sched.h>
#include "netif.h"
#include "tc/tc.h"
#include "conf/tc.h"

extern struct Qsch_ops bfifo_sch_ops;

static int pfifo_enqueue(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    if (likely(sch->q.qlen < sch->limit))
        return qsch_enqueue_tail(sch, mbuf);

#if defined(CONFIG_TC_DEBUG)
    RTE_LOG(WARNING, TC, "%s: queue is full.\n", __func__);
#endif
    return qsch_drop(sch, mbuf);
}

static int bfifo_enqueue(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    if (likely(sch->qstats.backlog + mbuf->pkt_len <= sch->limit))
        return qsch_enqueue_tail(sch, mbuf);

#if defined(CONFIG_TC_DEBUG)
    RTE_LOG(WARNING, TC, "%s: queue is full.\n", __func__);
#endif
    return qsch_drop(sch, mbuf);
}

static int fifo_init(struct Qsch *sch, const void *arg)
{
    const struct tc_fifo_qopt *opt = arg;
    bool is_bfifo = sch->ops == &bfifo_sch_ops;
    assert(sch);

    if (!opt) {
        uint32_t limit;
        struct netif_port *dev = qsch_dev(sch);
        uint32_t sch_mtu = dev->mtu + sizeof(struct ethhdr);
        assert(dev);

        /* FIXME: txq_desc_nb is not set when alloc device.
         * we can move tc_init_dev to dev start phase but not
         * all dev will be start now, netif need be modified. */
#if 0
        limit = dev->txq_desc_nb;
#else
        limit = 1024;
#endif

        if (is_bfifo)
            limit *= sch_mtu;

        sch->limit = limit;
    } else {
        sch->limit = opt->limit;
    }

    return EDPVS_OK;
}

static int fifo_dump(struct Qsch *sch, void *arg)
{
    struct tc_fifo_qopt *qopt = arg;

    qopt->limit = sch->limit;
    return EDPVS_OK;
}

struct Qsch_ops pfifo_sch_ops = {
    .name       = "pfifo",
    .priv_size  = 0,
    .enqueue    = pfifo_enqueue,
    .dequeue    = qsch_dequeue_head,
    .peek       = qsch_peek_head,
    .init       = fifo_init,
    .change     = fifo_init,
    .reset      = qsch_reset_queue,
    .dump       = fifo_dump,
};

struct Qsch_ops bfifo_sch_ops = {
    .name       = "bfifo",
    .priv_size  = 0,
    .enqueue    = bfifo_enqueue,
    .dequeue    = qsch_dequeue_head,
    .peek       = qsch_peek_head,
    .init       = fifo_init,
    .change     = fifo_init,
    .reset      = qsch_reset_queue,
    .dump       = fifo_dump,
};
