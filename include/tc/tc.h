/**
 * traffic control module of DPVS.
 * see linux/net/sched/ for reference.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#ifndef __DPVS_TC_H__
#define __DPVS_TC_H__
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include "list.h"
#include "dpdk.h"

#define TCNAMESIZ           16

#define TC
#define RTE_LOGTYPE_TC      RTE_LOGTYPE_USER1

#define TC_ALIGNTO          64
#define TC_ALIGN(len)       (((len) + TC_ALIGNTO-1) & ~(TC_ALIGNTO-1))

typedef uint32_t            tc_handle_t;

/* need a wrapper to save mbuf list,
 * since there's no way to link mbuf by it's own elem.
 * (note mbuf.next if used for pkt segments. */
struct tc_mbuf_head {
    struct list_head        mbufs;
    uint16_t                qlen;
};

struct tc_mbuf {
    struct list_head        list;
    struct rte_mbuf         *mbuf;
};

struct netif_tc {
    struct netif_port       *dev;
    struct rte_mempool      *tc_mbuf_pool;
    rte_rwlock_t            lock;

    /*
     * Qsch section
     */
    int                     qsch_cnt;   /* total num of Qsch,
                                           including root and ingress */

    /* egress */
    struct Qsch             *qsch;      /* root Qsch */
    struct hlist_head       *qsch_hash; /* hash key is handle,
                                           root Qsch is not included */
    int                     qsch_hash_size;

    /* ingress */
    struct Qsch             *qsch_ingress;
};

struct Qsch_ops;
struct tc_cls_ops;

int tc_init(void);
int tc_ctrl_init(void);

int tc_init_dev(struct netif_port *dev);
int tc_destroy_dev(struct netif_port *dev);

int tc_register_qsch(struct Qsch_ops *ops);
int tc_unregister_qsch(struct Qsch_ops *ops);

struct Qsch_ops *tc_qsch_ops_lookup(const char *name);
void tc_qsch_ops_get(struct Qsch_ops *ops);
void tc_qsch_ops_put(struct Qsch_ops *ops);

int tc_register_cls(struct tc_cls_ops *ops);
int tc_unregister_cls(struct tc_cls_ops *ops);
struct tc_cls_ops *tc_cls_ops_get(const char *name);
void tc_cls_ops_put(struct tc_cls_ops *ops);

struct rte_mbuf *tc_handle_egress(struct netif_tc *tc,
                                  struct rte_mbuf *mbuf, int *ret);

static inline int64_t tc_get_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static inline void tc_mbuf_head_init(struct tc_mbuf_head *qh)
{
    INIT_LIST_HEAD(&qh->mbufs);
    qh->qlen = 0;
}

#endif /* __DPVS_TC_H__ */
