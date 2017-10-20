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

    return qsch_drop(sch, mbuf);
}

static int bfifo_enqueue(struct Qsch *sch, struct rte_mbuf *mbuf)
{
    if (likely(sch->qstats.backlog + mbuf->pkt_len <= sch->limit))
        return qsch_enqueue_tail(sch, mbuf);

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

        limit = dev->txq_desc_nb;

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

int fifo_set_limit(struct Qsch *sch, unsigned int limit)
{
    struct tc_fifo_qopt qopt = { .limit = limit };

    if (strncmp(sch->ops->name + 1, "fifo", 4) != 0)
        return EDPVS_INVAL;

    return sch->ops->change(sch, &qopt);
}

struct Qsch *fifo_create_dflt(struct Qsch *sch, struct Qsch_ops *ops,
                              unsigned int limit)
{
    struct Qsch *q;
    int err;

    q = qsch_create_dflt(qsch_dev(sch), ops, sch->handle);
    if (!q)
        return NULL;

    err = fifo_set_limit(q, limit);
    if (err != EDPVS_OK) {
        qsch_destroy(q);
        return NULL;
    }

    return q;
}
