#include <rte_ethdev.h>
#include <rte_thash.h>
#include <rte_hash_crc.h>
#include "netif.h"
#include "rculist.h"
#include "srss.h"

#define SRSS_HASH_INITVAL 0x12345678
#define SRSS_FDIR_HASH_SIZE (1<<8)
struct dpvs_srss {
    struct rte_eth_rss_conf rss_conf;
    /* key is pointer in rss conf, and maybe NULL,
     * NIC will use default values */
    uint8_t rss_key[40];
    struct list_head fdir[SRSS_FDIR_HASH_SIZE];
    int reta_size;
    struct rte_eth_rss_reta_entry64 reta[8];
};

struct srss_fdir_entry {
    struct list_head node;
    struct srss_flow flow;
    uint32_t qid;
};

static uint32_t srss_flow_hash(const struct srss_flow* f)
{
    return rte_hash_crc(f, sizeof(*f), SRSS_HASH_INITVAL) % SRSS_FDIR_HASH_SIZE;
}

static int dpvs_maske_flow(struct netif_port* port,
        const struct srss_flow* f, struct srss_flow* mf)
{
#define MASK_FLOW(v, m) mf->v = f->v & mask->m
    struct rte_eth_fdir_masks *mask = &port->dev_conf.fdir_conf.mask;
    mf->af = f->af;
    MASK_FLOW(sport, src_port_mask);
    MASK_FLOW(dport, dst_port_mask);
    if (f->af == AF_INET) {
        MASK_FLOW(proto, ipv4_mask.proto);
        MASK_FLOW(saddr.in.s_addr, ipv4_mask.src_ip);
        MASK_FLOW(daddr.in.s_addr, ipv4_mask.dst_ip);
        mf->saddr.in6.s6_addr32[1] = 0;
        mf->saddr.in6.s6_addr32[2] = 0;
        mf->saddr.in6.s6_addr32[3] = 0;
        mf->daddr.in6.s6_addr32[1] = 0;
        mf->daddr.in6.s6_addr32[2] = 0;
        mf->daddr.in6.s6_addr32[3] = 0;
    } else {
        MASK_FLOW(proto, ipv4_mask.proto);
        MASK_FLOW(saddr.in6.s6_addr32[0], ipv6_mask.src_ip[0]);
        MASK_FLOW(saddr.in6.s6_addr32[1], ipv6_mask.src_ip[1]);
        MASK_FLOW(saddr.in6.s6_addr32[2], ipv6_mask.src_ip[2]);
        MASK_FLOW(saddr.in6.s6_addr32[3], ipv6_mask.src_ip[3]);
        MASK_FLOW(daddr.in6.s6_addr32[0], ipv6_mask.dst_ip[0]);
        MASK_FLOW(daddr.in6.s6_addr32[1], ipv6_mask.dst_ip[1]);
        MASK_FLOW(daddr.in6.s6_addr32[2], ipv6_mask.dst_ip[2]);
        MASK_FLOW(daddr.in6.s6_addr32[3], ipv6_mask.dst_ip[3]);
    }
    return 0;
}

static int srss_fdir_to_flow(struct rte_eth_fdir_filter* f, struct srss_flow* flow)
{
    memset(flow, 0, sizeof(*flow));
    switch (f->input.flow_type) {
    case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
        flow->af = AF_INET;
        flow->saddr.in.s_addr = f->input.flow.udp4_flow.ip.src_ip;
        flow->daddr.in.s_addr = f->input.flow.udp4_flow.ip.dst_ip;
        flow->sport = f->input.flow.udp4_flow.src_port;
        flow->dport = f->input.flow.udp4_flow.dst_port;
        flow->proto = IPPROTO_UDP;
        break;
    case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
        flow->af = AF_INET;
        flow->saddr.in.s_addr = f->input.flow.tcp4_flow.ip.src_ip;
        flow->daddr.in.s_addr = f->input.flow.tcp4_flow.ip.dst_ip;
        flow->sport = f->input.flow.tcp4_flow.src_port;
        flow->dport = f->input.flow.tcp4_flow.dst_port;
        flow->proto = IPPROTO_TCP;
        break;
    case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
        flow->af = AF_INET6;
        memcpy(&flow->saddr, f->input.flow.udp6_flow.ip.src_ip, 16);
        memcpy(&flow->daddr, f->input.flow.udp6_flow.ip.dst_ip, 16);
        flow->sport = f->input.flow.udp6_flow.src_port;
        flow->dport = f->input.flow.udp6_flow.dst_port;
        flow->proto = IPPROTO_UDP;
        break;
    case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
        flow->af = AF_INET6;
        memcpy(&flow->saddr, f->input.flow.tcp6_flow.ip.src_ip, 16);
        memcpy(&flow->daddr, f->input.flow.tcp6_flow.ip.dst_ip, 16);
        flow->sport = f->input.flow.tcp6_flow.src_port;
        flow->dport = f->input.flow.tcp6_flow.dst_port;
        flow->proto = IPPROTO_TCP;
        break;
    default:
        return EDPVS_NOTSUPP;
    }
    return EDPVS_OK;
}

/* do not check conflict */
static int srss_fdir_insert(struct netif_port* p, struct rte_eth_fdir_filter* f)
{
    uint32_t hash = 0;
    struct dpvs_srss* srss = p->sfilter;
    if (!srss) {
        return EDPVS_NOTEXIST;
    }
    struct srss_fdir_entry *e = rte_malloc("srss_fdir", sizeof(*e), RTE_CACHE_LINE_SIZE);
    if (!e) {
        return EDPVS_NOMEM;
    }
    srss_fdir_to_flow(f, &e->flow);
    dpvs_maske_flow(p, &e->flow, &e->flow);
    e->qid = f->action.rx_queue;
    hash = srss_flow_hash(&e->flow);
    list_add_tail_rcu(&e->node, &srss->fdir[hash]);
    return EDPVS_OK;
}

/* use weak symbol for compile, this function is define in another commit not merged in src/netif.c */
int __attribute__((weak))dpvs_wait_lcores(void);
int __attribute__((weak))dpvs_wait_lcores(void)
{
    return EDPVS_OK;
}

static int srss_fdir_del(struct netif_port* p, struct rte_eth_fdir_filter* f)
{
    uint32_t hash = 0;
    struct dpvs_srss* srss = p->sfilter;
    struct srss_fdir_entry *e = NULL;
    struct srss_flow flow;
    if (!srss) {
        return EDPVS_NOTEXIST;
    }

    srss_fdir_to_flow(f, &flow);
    dpvs_maske_flow(p, &flow, &flow);
    hash = srss_flow_hash(&flow);
    list_for_each_entry_rcu(e, &srss->fdir[hash], node) {
        if (!memcmp(&e->flow, f, sizeof(struct srss_flow)) &&
            e->qid == f->action.rx_queue) {
            list_del_rcu(&e->node);
            dpvs_wait_lcores();
            rte_free(e);
            return EDPVS_OK;
        }
    }
    return EDPVS_NOTEXIST;
}

static void __fdir_list_wait(void)
{
    dpvs_wait_lcores();
}
static int srss_fdir_flush(struct netif_port* p)
{
    uint32_t hash = 0;
    struct srss_fdir_entry *e = NULL;
    struct srss_fdir_entry *n = NULL;

    struct dpvs_srss* srss = p->sfilter;
    if (!srss) {
        return EDPVS_OK;
    }
    for (hash = 0; hash < SRSS_FDIR_HASH_SIZE; hash++) {
        struct list_head tmp = LIST_HEAD_INIT(tmp);
        list_splice_init_rcu(&srss->fdir[hash], &tmp, __fdir_list_wait);
        list_for_each_entry_safe(e, n, &tmp, node) {
            rte_free(e);
        }
    }
    return EDPVS_OK;
}

int dpvs_srss_fdir_get(struct netif_port* p, const struct srss_flow* f, uint32_t* qid)
{
    uint32_t hash;
    struct srss_fdir_entry *e = NULL;
    struct srss_flow mf;
    struct dpvs_srss* srss = p->sfilter;
    if (!srss) {
        return EDPVS_NOTEXIST;
    }

    memset(&mf, 0, sizeof(mf));
    dpvs_maske_flow(p, f, &mf);
    hash = srss_flow_hash(&mf);
    list_for_each_entry_rcu(e, &srss->fdir[hash], node) {
        if (!memcmp(&e->flow, &mf, sizeof(struct srss_flow))) {
            *qid = e->qid;
            return EDPVS_OK;
        }
    }
    return EDPVS_NOTEXIST;
}

int dpvs_dev_sfilter_ctrl(struct netif_port* port, enum rte_filter_type filter_type,
               enum rte_filter_op filter_op, void *arg)
{
    int ret = EDPVS_OK;
    if (filter_type != RTE_ETH_FILTER_FDIR) {
        return EDPVS_NOTSUPP;
    }
    switch (filter_op) {
    case RTE_ETH_FILTER_ADD:
        ret = srss_fdir_insert(port, (struct rte_eth_fdir_filter *)arg);
        break;
    case RTE_ETH_FILTER_DELETE:
        ret = srss_fdir_del(port, (struct rte_eth_fdir_filter *)arg);
        break;
    case RTE_ETH_FILTER_FLUSH:
        ret = srss_fdir_flush(port);
        break;
    default:
        RTE_LOG(ERR, NETIF, "srss filter_op %d not supported\n", filter_op);
        return EDPVS_NOTSUPP;
    }
    return ret;
}

static int dpvs_get_srss_qid(struct netif_port* port, uint32_t rss)
{
    struct dpvs_srss *srss = port->sfilter;
    if (!srss) {
        return 0;
    }
    uint32_t idx = rss % srss->reta_size;
    return srss->reta[idx / RTE_RETA_GROUP_SIZE].reta[idx % RTE_RETA_GROUP_SIZE];
}

static void dpvs_srss_load_v6_addrs(const struct in6_addr* in6, uint8_t *targ)
{
    int i;
    for (i = 0; i < 4; i++) {
        ((uint32_t *)targ)[i] = rte_be_to_cpu_32(in6->s6_addr32[i]);
    }
}

static int dpvs_dev_srss(struct netif_port* port, const struct srss_flow* f, uint32_t *rss)
{

    union rte_thash_tuple t;
    int len = 0;
    *rss = 0;
    struct dpvs_srss *srss = port->sfilter;
    if (!srss) {
        return EDPVS_OK;
    }
    if (f->af == AF_INET) {
        if (f->proto == IPPROTO_TCP &&
            srss->rss_conf.rss_hf & ETH_RSS_NONFRAG_IPV4_TCP) {
            len = 12;
        } else if (f->proto == IPPROTO_UDP &&
            srss->rss_conf.rss_hf & ETH_RSS_NONFRAG_IPV4_UDP) {
            len = 12;
        } else if (srss->rss_conf.rss_hf & ETH_RSS_IPV4) {
            len = 8;
        } else {
            return EDPVS_OK;
        }
        t.v4.src_addr = rte_be_to_cpu_32(f->saddr.in.s_addr);
        t.v4.dst_addr = rte_be_to_cpu_32(f->daddr.in.s_addr);
        t.v4.sport = f->sport;
        t.v4.dport = f->dport;
    } else {
        if (f->proto == IPPROTO_TCP &&
            srss->rss_conf.rss_hf & ETH_RSS_NONFRAG_IPV6_TCP) {
            len = 36;
        } else if (f->proto == IPPROTO_UDP &&
            srss->rss_conf.rss_hf & ETH_RSS_NONFRAG_IPV6_UDP) {
            len = 36;
        } else if (srss->rss_conf.rss_hf & ETH_RSS_IPV6) {
            len = 32;
        } else {
            return EDPVS_OK;
        }
        dpvs_srss_load_v6_addrs(&f->saddr.in6, t.v6.src_addr);
        dpvs_srss_load_v6_addrs(&f->daddr.in6, t.v6.dst_addr);
        t.v6.sport = f->sport;
        t.v6.dport = f->dport;
    }
    *rss = rte_softrss_be((void*)&t, len, srss->rss_key);
    return EDPVS_OK;
}

/* return value < 0 : lookup miss, >= 0 : return queue id */
int dpvs_dev_sfilter(struct netif_port* port, const struct srss_flow* f,
                     uint32_t* qid)
{
    int ret = EDPVS_OK;
    uint32_t rss = 0;
    struct dpvs_srss *srss = port->sfilter;
    if (!srss) {
        return EDPVS_NOTEXIST;
    }
    ret = dpvs_srss_fdir_get(port, f, qid);
    if (ret == EDPVS_OK) {
        return ret;
    }
    dpvs_dev_srss(port, f, &rss);
    *qid = dpvs_get_srss_qid(port, rss);
    return EDPVS_OK;
}

lcoreid_t qid2lcore[NETIF_MAX_RTE_PORTS][NETIF_MAX_QUEUES] = {};
int netif_get_lcore(struct netif_port *port, queueid_t qid, lcoreid_t *cid)
{
    if (!port || !cid || qid >= NETIF_MAX_QUEUES) {
        return EDPVS_INVAL;
    }
    *cid = qid2lcore[port->id][qid];
    return EDPVS_OK;
}
static int init_qid2lcore(struct netif_port* port)
{
    lcoreid_t cid = 0;
    queueid_t qid = 0;
    portid_t id = port->id;
    uint8_t num;
    uint64_t mask;
    netif_get_slave_lcores(&num, &mask);
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (mask & (1 << cid) &&
            netif_get_queue(port, cid, &qid) == EDPVS_OK) {
            qid2lcore[id][qid] = cid;
        }
    }
    return 0;
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
/* copyed from i40e driver */
static uint32_t default_rss_key[] = {0x6b793944,
    0x23504cb5, 0x5bea75b6, 0x309f4f12, 0x3dc0a2b8,
    0x024ddcdf, 0x339b8ca0, 0x4c4af64a, 0x34fac605,
    0x55d85839, 0x3a58997d, 0x2ec938e1, 0x66031581};
int dpvs_dev_srss_init(struct netif_port* port)
{
    int i = 0;
    struct dpvs_srss *srss = NULL;
    srss = rte_malloc("srss_filter", sizeof(struct dpvs_srss), 0);
    if (!srss) {
        RTE_LOG(ERR, NETIF, "%s: fail to alloc srss_filter\n", __func__);
        return EDPVS_NOMEM;
    }
    memset(srss, 0, sizeof(*srss));
    srss->rss_conf.rss_key = srss->rss_key;
    if (rte_eth_dev_rss_hash_conf_get(port->id, &srss->rss_conf)) {
        RTE_LOG(WARNING, NETIF, "%s: port %s rss get failed, use default\n", __func__, port->name);
        memcpy(srss->rss_key, default_rss_key, sizeof(srss->rss_key));
    }
    rte_convert_rss_key((void*)srss->rss_key, (void*)srss->rss_key, 40);
    for (i = 0; i < SRSS_FDIR_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&srss->fdir[i]);
    }
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port->id, &dev_info);
    srss->reta_size = dev_info.reta_size;
    for (i = 0; i < ARRAY_SIZE(srss->reta); i++) {
        srss->reta[i].mask = ~0ULL;
    }
    if (rte_eth_dev_rss_reta_query(port->id, srss->reta, srss->reta_size) < 0) {
        RTE_LOG(WARNING, NETIF, "%s: port %s reta get failed, use default\n", __func__, port->name);
        int j = 0;
        int idx = 0;
        for (i = 0; i < ARRAY_SIZE(srss->reta); i++) {
            for (j = 0; j < ARRAY_SIZE(srss->reta[i].reta); j++) {
                if (idx >= dev_info.nb_rx_queues) {
                    idx = 0;
                }
                srss->reta[i].reta[j] = idx;
                idx++;
            }
        }
    }
    port->sfilter = srss;
    init_qid2lcore(port);
    return EDPVS_OK;
}

