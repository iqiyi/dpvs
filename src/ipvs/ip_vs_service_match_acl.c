#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>
#include <assert.h>
#include <rte_acl.h>
#include <rte_hash_crc.h>
#include "linux_ipv6.h"
#include "ipvs/service.h"
#include "parser/parser.h"
#include "ipvs/service_match_acl.h"
#include "scheduler.h"
#include "rculist.h"

#define DEFAULT_MAX_CATEGORIES    1
#define DPVS_SVC_MAX 1000000
#define DPVS_SVC_HT_SIZE 0x10000
#define HASH_INIT_VAL 0x12345678

int dp_vs_match_acl_enable = 0;

/* DPDK ACL target is uint32_t, we should translate u32 to svc.
 * BASE+cache_line_size*u32 could index 256G memory,
 * maybe enough for most situations?
 */
static struct dp_vs_service **dpvs_svcs[DPVS_MAX_LCORE] = { NULL };
static struct rte_ring *dpvs_svc_idxq[DPVS_MAX_LCORE] = { NULL };
static uint64_t dpvs_match4_generation[DPVS_MAX_LCORE] = { 0 };
static uint64_t dpvs_match6_generation[DPVS_MAX_LCORE] = { 0 };
static struct rte_acl_ctx *dp_vs_svc_match_acl4[DPVS_MAX_LCORE] = { NULL };
static struct rte_acl_ctx *dp_vs_svc_match_acl6[DPVS_MAX_LCORE] = { NULL };
#define RULE_TAB_SIZE (1<<14)
static uint64_t dpvs_match4_cnt[DPVS_MAX_LCORE] = { 0 };
static struct hlist_head dp_vs_match4_list[DPVS_MAX_LCORE][RULE_TAB_SIZE];
static uint64_t dpvs_match6_cnt[DPVS_MAX_LCORE] = { 0 };
static struct hlist_head dp_vs_match6_list[DPVS_MAX_LCORE][RULE_TAB_SIZE];

struct rcu_list {
    struct rcu_list *n;
};
struct rcu_list rcu_free_list = {NULL};
static void rcu_list_add(struct rcu_list* rcu, struct rcu_list* head)
{
    int success = 1;
    struct rcu_list *old = NULL;
    do {
        old = head->n;
        rcu->n = old;
        rte_wmb();
        success = rte_atomic64_cmpset((void*)&head->n, (uint64_t)old, (uint64_t)rcu);
    } while (!success);
}
static void rcu_list_take(struct rcu_list* head, struct rcu_list* new_head)
{
    int success = 1;
    do {
        new_head->n = head->n;
        rte_rmb();
        success = rte_atomic64_cmpset((void*)&head->n, (uint64_t)new_head->n, 0);
    } while (!success);
}

struct dp_vs_match_list {
    struct hlist_node node;
    struct rcu_list rcu;
    struct dp_vs_match match;
    uint32_t idx;
    uint8_t proto;
};

static uint32_t dp_vs_match_hash(struct dp_vs_match *match)
{
    uint32_t hash = 0;
    hash = rte_hash_crc(match, sizeof(struct dp_vs_match), 0x12345678);
    return hash & RULE_TAB_SIZE;
}

struct dp_vs_match_ipv4 {
    uint8_t  proto;
    struct in_addr src;
    struct in_addr dst;
    __be16 sport;
    __be16 dport;
    portid_t iifid;
    portid_t oifid;
};

struct dp_vs_match_ipv6 {
    uint8_t  proto;
    struct in6_addr src;
    struct in6_addr dst;
    __be16 sport;
    __be16 dport;
    portid_t iifid;
    portid_t oifid;
};

enum {
    PROTO_FIELD_IPV4,
    SRC_FIELD_IPV4,
    DST_FIELD_IPV4,
    SRCP_FIELD_IPV4,
    DSTP_FIELD_IPV4,
    IIFID_FIELD_IPV4,
    OIFID_FIELD_IPV4,
    NUM_FIELDS_IPV4,
};

struct rte_acl_field_def dpvs_match_defs4[NUM_FIELDS_IPV4] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = PROTO_FIELD_IPV4,
        .input_index = PROTO_FIELD_IPV4,
        .offset = 0,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = SRC_FIELD_IPV4,
        .input_index = SRC_FIELD_IPV4,
        .offset = offsetof(struct dp_vs_match_ipv4, src),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = DST_FIELD_IPV4,
        .input_index = DST_FIELD_IPV4,
        .offset = offsetof(struct dp_vs_match_ipv4, dst),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = SRCP_FIELD_IPV4,
        .input_index = SRCP_FIELD_IPV4,
        .offset = offsetof(struct dp_vs_match_ipv4, sport),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = DSTP_FIELD_IPV4,
        .input_index = SRCP_FIELD_IPV4,
        .offset = offsetof(struct dp_vs_match_ipv4, dport),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = IIFID_FIELD_IPV4,
        .input_index = DSTP_FIELD_IPV4,
        .offset = offsetof(struct dp_vs_match_ipv4, iifid),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = OIFID_FIELD_IPV4,
        .input_index = DSTP_FIELD_IPV4,
        .offset = offsetof(struct dp_vs_match_ipv4, oifid),
    },
};

enum {
    PROTO_FIELD_IPV6,
    SRC1_FIELD_IPV6,
    SRC2_FIELD_IPV6,
    SRC3_FIELD_IPV6,
    SRC4_FIELD_IPV6,
    DST1_FIELD_IPV6,
    DST2_FIELD_IPV6,
    DST3_FIELD_IPV6,
    DST4_FIELD_IPV6,
    SRCP_FIELD_IPV6,
    DSTP_FIELD_IPV6,
    IIFID_FIELD_IPV6,
    OIFID_FIELD_IPV6,
    NUM_FIELDS_IPV6,
};

struct rte_acl_field_def dpvs_match_defs6[NUM_FIELDS_IPV6] = {
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof(uint8_t),
        .field_index = PROTO_FIELD_IPV6,
        .input_index = PROTO_FIELD_IPV6,
        .offset = 0,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = SRC1_FIELD_IPV6,
        .input_index = SRC1_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, src),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = SRC2_FIELD_IPV6,
        .input_index = SRC2_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, src) + sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = SRC3_FIELD_IPV6,
        .input_index = SRC3_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, src) + sizeof(uint32_t) * 2,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = SRC4_FIELD_IPV6,
        .input_index = SRC4_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, src) + sizeof(uint32_t) * 3,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = DST1_FIELD_IPV6,
        .input_index = DST1_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, dst),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = DST2_FIELD_IPV6,
        .input_index = DST2_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, dst) + sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = DST3_FIELD_IPV6,
        .input_index = DST3_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, dst) + sizeof(uint32_t) * 2,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint32_t),
        .field_index = DST4_FIELD_IPV6,
        .input_index = DST4_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, dst) + sizeof(uint32_t) * 3,
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = SRCP_FIELD_IPV6,
        .input_index = SRCP_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, sport),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = DSTP_FIELD_IPV6,
        .input_index = SRCP_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, dport),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = IIFID_FIELD_IPV6,
        .input_index = DSTP_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, iifid),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof(uint16_t),
        .field_index = OIFID_FIELD_IPV6,
        .input_index = DSTP_FIELD_IPV6,
        .offset = offsetof(struct dp_vs_match_ipv6, oifid),
    },
};

RTE_ACL_RULE_DEF(dpvs_match_rule4, RTE_DIM(dpvs_match_defs4));
RTE_ACL_RULE_DEF(dpvs_match_rule6, RTE_DIM(dpvs_match_defs6));

/* acl name MUST NOT be repeated with existing */
static rte_atomic32_t acl_build_idx;
static int svc_to_match_acl4(struct dp_vs_match_list *match, struct dpvs_match_rule4 *rule)
{
    uint32_t min = 0;
    uint32_t max = 0;
    struct netif_port* dev = NULL;
    rule->data.category_mask = -1;
    rule->data.priority = 1;
    rule->data.userdata = match->idx;;

    rule->field[PROTO_FIELD_IPV4].value.u8 = match->proto;
    rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0xff;
    /* for snat, 0 proto match any proto */
    if (!match->proto) {
        rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0x0;
    }

    min = ntohl(match->match.srange.min_addr.in.s_addr);
    max = ntohl(match->match.srange.max_addr.in.s_addr);
    if (min > max) {
        return 0;
    }
    /* zero means any ... */
    if (!max) {
        min = 0;
        max = 0xffffffff;
    }
    rule->field[SRC_FIELD_IPV4].value.u32 = min;
    rule->field[SRC_FIELD_IPV4].mask_range.u32 = max;

    min = ntohl(match->match.drange.min_addr.in.s_addr);
    max = ntohl(match->match.drange.max_addr.in.s_addr);
    if (min > max) {
        return 0;
    }
    /* zero means any ... */
    if (!max) {
        min = 0;
        max = 0xffffffff;
    }
    rule->field[DST_FIELD_IPV4].value.u32 = min;
    rule->field[DST_FIELD_IPV4].mask_range.u32 = max;

    min = ntohs(match->match.srange.min_port);
    max = ntohs(match->match.srange.max_port);
    if (min > max) {
        return 0;
    }
    /* zero means any ... */
    if (!max) {
        min = 0;
        max = 0xffff;
    }
    rule->field[SRCP_FIELD_IPV4].value.u16 = min;
    rule->field[SRCP_FIELD_IPV4].mask_range.u16 = max;

    min = ntohs(match->match.drange.min_port);
    max = ntohs(match->match.drange.max_port);
    if (min > max) {
        return 0;
    }
    /* zero means any ... */
    if (!max) {
        min = 0;
        max = 0xffff;
    }
    rule->field[DSTP_FIELD_IPV4].value.u16 = min;
    rule->field[DSTP_FIELD_IPV4].mask_range.u16 = max;

    dev = netif_port_get_by_name(match->match.iifname);
    if (dev) {
        rule->field[IIFID_FIELD_IPV4].value.u16 = ntohs(dev->id);
        rule->field[IIFID_FIELD_IPV4].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[IIFID_FIELD_IPV4].value.u16 = 0;
        rule->field[IIFID_FIELD_IPV4].mask_range.u16 = 0xffff;
    }

    dev = netif_port_get_by_name(match->match.oifname);
    if (dev) {
        rule->field[OIFID_FIELD_IPV4].value.u16 = ntohs(dev->id);
        rule->field[OIFID_FIELD_IPV4].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[OIFID_FIELD_IPV4].value.u16 = 0;
        rule->field[OIFID_FIELD_IPV4].mask_range.u16 = 0xffff;
    }
    return 1;
}


static int ip6_addr_fil(union inet_addr *d, union inet_addr *s, int len, uint32_t fill)
{
    int i = 0;
    for (i = 0; i < 4; i++) {
        if (i < len) {
            d->in6.s6_addr32[i] = s->in6.s6_addr32[i];
        } else {
            d->in6.s6_addr32[i] = fill;
        }
    }
    return 0;
}

static int network_order_add_u32(uint32_t *v, int i)
{
    uint32_t hv = ntohl(*v);
    hv += i;
    *v = htonl(hv);
    return 0;
}

static int ip6_range_split(struct inet_addr_range *s,
                           struct inet_addr_range d[8])
{
    int i = 0;
    int j = 0;
    int k = 0;
    uint32_t min = 0;
    uint32_t max = 0;
    struct inet_addr_range _d[8];
    if (!d) {
        d = _d;
    }
    if (ipv6_addr_cmp(&s->min_addr.in6, &s->max_addr.in6) > 0) {
        return 0;
    }
    if (inet_is_addr_any(AF_INET6, &s->max_addr)) {
        memset(&d[0].min_addr, 0, sizeof(d[0].min_addr));
        memset(&d[0].max_addr, 0xff, sizeof(d[0].max_addr));
        return 1;
    }
    d[k].min_addr = s->min_addr;
    /* skip same prefix */
    for (i = 0; i < 4; i++) {
        min = s->min_addr.in6.s6_addr32[i];
        max = s->max_addr.in6.s6_addr32[i];
        if (max != min) {
            break;
        }
    }
    /* skip min tail 0 */
    for (j = 3; j > i; j--) {
        min = s->min_addr.in6.s6_addr32[j];
        if (min) {
            break;
        }
    }
    for (; j > i; j--) {
        min = d[k].min_addr.in6.s6_addr32[j];
        if (min) {
            ip6_addr_fil(&d[k].max_addr, &d[k].min_addr, j, 0xffffffff);
            k++;
            ip6_addr_fil(&d[k].min_addr, &d[k - 1].min_addr, j, 0);
        }
        network_order_add_u32(&d[k].min_addr.in6.s6_addr32[j - 1], 1);
    }
    /* skip max tail 0xffffffff */
    for (j = 3; j > i; j--) {
        max = s->max_addr.in6.s6_addr32[j];
        if (max != 0xffffffff) {
            break;;
        }
    }
    for (; i < j; i++) {
        min = d[k].min_addr.in6.s6_addr32[i];
        max = s->max_addr.in6.s6_addr32[i];
        if (max != min) {
            ip6_addr_fil(&d[k].max_addr, &s->max_addr, i + 1, 0xffffffff);
            network_order_add_u32(&d[k].max_addr.in6.s6_addr32[i], -1);
            k++;
            ip6_addr_fil(&d[k].min_addr, &s->max_addr, i + 1, 0);
        }
    }
    d[k].max_addr =  s->max_addr;
    return k;
}

static int svc_to_match_acl6(struct dp_vs_match_list *match, struct dpvs_match_rule6 *rule)
{
    uint32_t min = 0;
    uint32_t max = 0;
    struct netif_port* dev = NULL;
    struct inet_addr_range srange[8];
    struct inet_addr_range drange[8];
    int src_cnt = 0;
    int dst_cnt = 0;
    int cnt = 0;
    int i = 0;
    int j = 0;
    int k = 0;

    rule->data.category_mask = -1;
    rule->data.priority = 1;
    rule->data.userdata = match->idx;;

    rule->field[PROTO_FIELD_IPV6].value.u8 = match->proto;
    rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0xff;
    /* for snat, 0 proto match any proto */
    if (!match->proto) {
        rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0x0;
    }

    min = ntohs(match->match.srange.min_port);
    max = ntohs(match->match.srange.max_port);
    if (min > max) {
        return 0;
    }
    /* zero means any ... */
    if (!max) {
        min = 0;
        max = 0xffff;
    }
    rule->field[SRCP_FIELD_IPV6].value.u16 = min;
    rule->field[SRCP_FIELD_IPV6].mask_range.u16 = max;

    min = ntohs(match->match.drange.min_port);
    max = ntohs(match->match.drange.max_port);
    if (min > max) {
        return 0;
    }
    /* zero means any ... */
    if (!max) {
        min = 0;
        max = 0xffff;
    }
    rule->field[DSTP_FIELD_IPV6].value.u16 = min;
    rule->field[DSTP_FIELD_IPV6].mask_range.u16 = max;

    dev = netif_port_get_by_name(match->match.iifname);
    if (dev) {
        rule->field[IIFID_FIELD_IPV6].value.u16 = ntohs(dev->id);
        rule->field[IIFID_FIELD_IPV6].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[IIFID_FIELD_IPV6].value.u16 = 0;
        rule->field[IIFID_FIELD_IPV6].mask_range.u16 = 0xffff;
    }

    dev = netif_port_get_by_name(match->match.oifname);
    if (dev) {
        rule->field[OIFID_FIELD_IPV6].value.u16 = ntohs(dev->id);
        rule->field[OIFID_FIELD_IPV6].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[OIFID_FIELD_IPV6].value.u16 = 0;
        rule->field[OIFID_FIELD_IPV6].mask_range.u16 = 0xffff;
    }

    src_cnt = ip6_range_split(&match->match.srange, srange);
    dst_cnt = ip6_range_split(&match->match.drange, drange);
    cnt = src_cnt * dst_cnt;
    if (cnt > 1) {
        memcpy(&rule[1], rule, sizeof(*rule) * (cnt - 1));
    }
    for (i = 0; i < src_cnt; i++) {
        for (j = 0; j < dst_cnt; j++) {
            for (k = 0; k < 4; k++) {
                min = srange[i].min_addr.in6.s6_addr32[k];
                max = srange[i].max_addr.in6.s6_addr32[k];
                rule->field[SRC1_FIELD_IPV6 + k].value.u32 = min;
                rule->field[SRC1_FIELD_IPV6 + k].mask_range.u32 = max;
            }
            for (k = 0; k < 4; k++) {
                min = drange[j].min_addr.in6.s6_addr32[k];
                max = drange[j].max_addr.in6.s6_addr32[k];
                rule->field[SRC1_FIELD_IPV6 + k].value.u32 = min;
                rule->field[SRC1_FIELD_IPV6 + k].mask_range.u32 = max;
            }
            rule++;
        }
    }

    return cnt;
}

static int build_acl(int af, lcoreid_t cid)
{
    char name[PATH_MAX];
    struct rte_acl_param acl_param;
    struct rte_acl_config acl_build_param;
    struct rte_acl_ctx *context = NULL;
    struct rte_acl_ctx **pctx = NULL;
    struct rte_acl_ctx *tmp = NULL;
    int dim = 0;
    struct hlist_head *list = NULL;

    memset(&acl_build_param, 0, sizeof(acl_build_param));
    acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
    if (af == AF_INET6) {
        dim = RTE_DIM(dpvs_match_defs6);
        memcpy(&acl_build_param.defs, dpvs_match_defs6,
                    sizeof(dpvs_match_defs6));
        pctx = &dp_vs_svc_match_acl6[cid];
        acl_param.max_rule_num = dpvs_match6_cnt[cid];
        list = dp_vs_match6_list[cid];
    } else {
        dim = RTE_DIM(dpvs_match_defs4);
        memcpy(&acl_build_param.defs, dpvs_match_defs4,
                    sizeof(dpvs_match_defs4));
        pctx = &dp_vs_svc_match_acl4[cid];
        acl_param.max_rule_num = dpvs_match4_cnt[cid];
        list = dp_vs_match4_list[cid];
    }
    if (!acl_param.max_rule_num) {
        goto end;
    }
    acl_build_param.num_fields = dim;
    snprintf(name, sizeof(name), "MatchAcl%d.%x", cid,
            rte_atomic32_add_return(&acl_build_idx, 1));
    acl_param.name = name;
    acl_param.socket_id = SOCKET_ID_ANY;
    acl_param.rule_size = RTE_ACL_RULE_SZ(dim);

    context = rte_acl_create(&acl_param);
    if (!context) {
        RTE_LOG(ERR, IPVS, "rte_acl_create failed\n");
        goto ctx_create_failed;
    }

    void *buf = malloc(64 * sizeof(struct dpvs_match_rule6));
    if (!buf) {
        goto nobuf;
    }
    struct dp_vs_match_list *m = NULL;
    int cnt = 0;
    int i = 0;
    for (i = 0; i < RULE_TAB_SIZE; i++) {
        hlist_for_each_entry_rcu(m, &list[i], node) {
            if (af == AF_INET) {
                cnt = svc_to_match_acl4(m, buf);
            } else {
                cnt = svc_to_match_acl6(m, buf);
            }
            if (!cnt) {
                continue;
            }
            if (rte_acl_add_rules(context, buf, cnt) < 0) {
                RTE_LOG(ERR, IPVS, "add rules failed\n");
                goto add_rule_fail;
            }
        }
    }
    if (rte_acl_build(context, &acl_build_param) != 0) {
        RTE_LOG(ERR, IPVS, "rte_acl_build failed\n");
        goto build_failed;
    }
    free(buf);
end:
    tmp = *pctx;
    *pctx = context;
    if (tmp) {
        rte_wmb();
        dpvs_wait_lcores();
        rte_acl_free(tmp);
    }
    return 0;
build_failed:
add_rule_fail:
    free(buf);
nobuf:
    rte_acl_free(context);
ctx_create_failed:
    return -1;
}

static struct dp_vs_service *dpvs_idx_svc(uint32_t idx, lcoreid_t cid)
{
    if (unlikely(idx >= DPVS_SVC_MAX)) {
        return NULL;
    }
    return dpvs_svcs[cid][idx];
}

int dp_vs_svc_match_acl_add(struct dp_vs_service *svc, lcoreid_t cid)
{
    void *p = NULL;
    uint32_t idx = 0;
    if (!svc) {
        return 0;
    }
    struct dp_vs_match_list *l = rte_zmalloc(NULL, sizeof(*l), 0);
    if (!l) {
        return EDPVS_NOMEM;
    }
    rte_ring_dequeue(dpvs_svc_idxq[cid], &p);
    idx = (unsigned long)p;
    svc->idx = idx;
    dpvs_svcs[cid][idx] = svc;
    l->match = *svc->match;
    l->idx = idx;
    l->proto = svc->proto;
    idx = dp_vs_match_hash(&l->match);
    if (svc->af == AF_INET) {
        hlist_add_head_rcu(&l->node, &dp_vs_match4_list[cid][idx]);
        dpvs_match4_cnt[cid]++;
        dpvs_match4_generation[cid]++;
    } else {
        hlist_add_head_rcu(&l->node, &dp_vs_match6_list[cid][idx]);
        dpvs_match6_cnt[cid]++;
        dpvs_match6_generation[cid]++;
    }
    return 0;
}

int dp_vs_svc_match_acl_del(struct dp_vs_service *svc, lcoreid_t cid)
{
    uint64_t idx = 0;
    if (!svc) {
        return 0;
    }
    if (svc->idx <= 0 || svc->idx >= DPVS_SVC_MAX) {
        return -1;
    }
    if (dpvs_svcs[cid][svc->idx] != svc) {
        return -1;
    }
    dpvs_svcs[cid][svc->idx] = NULL;
    idx = svc->idx;
    svc->idx = 0;
    rte_ring_enqueue(dpvs_svc_idxq[cid], (void*)idx);
    idx = dp_vs_match_hash(svc->match);
    struct dp_vs_match_list *l = NULL;
    struct hlist_head *h = NULL;
    if (svc->af == AF_INET) {
        h = &dp_vs_match4_list[cid][idx];
        dpvs_match4_cnt[cid]--;
        dpvs_match4_generation[cid]++;
    } else {
        h = &dp_vs_match6_list[cid][idx];
        dpvs_match6_cnt[cid]--;
        dpvs_match6_generation[cid]++;
    }
    hlist_for_each_entry(l, h, node) {
        if (!memcmp(&l->match, svc->match, sizeof(l->match))
            && l->proto == svc->proto) {
            hlist_del_rcu(&l->node);
            if (dp_vs_match_acl_enable) {
                rcu_list_add(&l->rcu, &rcu_free_list);
            } else {
                rte_free(l);
            }
            return 0;
        }
    }
    return 0;
}

struct dp_vs_service *dp_vs_get_match_svc_ip4(uint8_t proto, union inet_addr *saddr,
                     union inet_addr *daddr, __be16 sport, __be16 dport,
                     portid_t iif, portid_t oif, lcoreid_t cid)
{
    struct dp_vs_service *svc = NULL;
    struct rte_acl_ctx *ctx = NULL;
    ctx = dp_vs_svc_match_acl4[cid];
    if (ctx) {
        struct dp_vs_match_ipv4 entry;
        const uint8_t* pentry = (void*)&entry;
        uint32_t idx = 0;
        entry.proto = proto;
        entry.src = saddr->in;
        entry.dst = daddr->in;
        entry.sport = sport;
        entry.dport = dport;
        entry.iifid = iif;
        entry.oifid = oif;
        if (!rte_acl_classify(ctx, &pentry,
                     &idx, 1, DEFAULT_MAX_CATEGORIES) && idx) {
            svc = dpvs_idx_svc(idx, cid);
        }
    }
    return svc;
}

struct dp_vs_service *dp_vs_get_match_svc_ip6(uint8_t proto, union inet_addr *saddr,
                     union inet_addr *daddr, __be16 sport, __be16 dport,
                     portid_t iif, portid_t oif, lcoreid_t cid)
{
    struct dp_vs_service *svc = NULL;
    struct rte_acl_ctx *ctx = NULL;
    ctx = dp_vs_svc_match_acl6[cid];
    if (ctx) {
        struct dp_vs_match_ipv6 entry;
        const uint8_t* pentry = (void*)&entry;
        uint32_t idx = 0;
        entry.proto = proto;
        entry.src = saddr->in6;
        entry.dst = daddr->in6;
        entry.sport = sport;
        entry.dport = dport;
        entry.iifid = iif;
        entry.oifid = oif;
        if (!rte_acl_classify(ctx, &pentry,
                     &idx, 1, DEFAULT_MAX_CATEGORIES) && idx) {
            svc = dpvs_idx_svc(idx, cid);
        }
    }
    return svc;
}

static void dpvs_svc_match_build_job(void *data)
{
    static uint64_t pre4[DPVS_MAX_LCORE] = { 0 };
    static uint64_t pre6[DPVS_MAX_LCORE] = { 0 };
    struct timeval t1;
    struct timeval t2;
    struct timeval d;
    int cid = 0;
    int build = 0;
    gettimeofday(&t1, NULL);
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (pre4[cid] != dpvs_match4_generation[cid]) {
            pre4[cid] = dpvs_match4_generation[cid];
            build_acl(AF_INET, cid);
            build = 1;
        }
        if (pre6[cid] != dpvs_match6_generation[cid]) {
            pre6[cid] = dpvs_match6_generation[cid];
            build_acl(AF_INET6, cid);
            build = 1;
        }
    }
    if (build) {
        gettimeofday(&t2, NULL);
        if (t2.tv_usec < t1.tv_usec) {
            d.tv_usec = t2.tv_usec + 1000000 - t1.tv_usec;
            d.tv_sec = t2.tv_sec - t1.tv_sec - 1;
        } else {
            d.tv_usec = t2.tv_usec - t1.tv_usec;
            d.tv_sec = t2.tv_sec - t1.tv_sec;
        }
        RTE_LOG(DEBUG, IPVS, "build acl time used:%lu.%06lu,"
                " start at %lu.%06lu end at %lu.%06lu\n",
                d.tv_sec, d.tv_usec,
                t1.tv_sec, t1.tv_usec, t2.tv_sec, t2.tv_usec);
    }
    return;
}

static void dpvs_svc_match_rcu_free(void *data)
{
    struct rcu_list head;
    struct rcu_list *n;
    struct rcu_list *n2;
    rcu_list_take(&rcu_free_list, &head);
    for (n = head.n; n; n = n2) {
        n2 = n->n;
        rte_free(container_of(n, struct dp_vs_match_list, rcu));
    }
}

static void dpvs_svc_match_init(void *data)
{
    dp_vs_match_acl_enable = 1;
}

static struct dpvs_lcore_job idle_job[] = {
    {
        .name = "match_acl",
        .func = dpvs_svc_match_init,
        .data = NULL,
        .type = LCORE_JOB_INIT,
    },
    {
        .name = "match_acl",
        .func = dpvs_svc_match_build_job,
        .data = NULL,
        .type = LCORE_JOB_LOOP,
    },
    {
        .name = "rcu_free",
        .func = dpvs_svc_match_rcu_free,
        .data = NULL,
        .type = LCORE_JOB_LOOP,
    },
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
static int register_idle_job(void)
{
    int i = 0;
    int ret = EDPVS_OK;
    for (i = 0; i < ARRAY_SIZE(idle_job); i++) {
        ret = dpvs_lcore_job_register(&idle_job[i], LCORE_ROLE_IDLE);
        if (ret != EDPVS_OK) {
            RTE_LOG(ERR, CFG_FILE, "%s: fail to register cfgfile_reload job\n", __func__);
            return ret;
        }
    }
    return EDPVS_OK;
}

int dp_vs_svc_match_init(void)
{
    uint64_t i = 0;
    int size = 0;
    int cid = 0;
    char name[RTE_RING_NAMESIZE];
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        snprintf(name, RTE_RING_NAMESIZE, "dpvs_idx_q%d", cid);
        dpvs_svc_idxq[cid] = rte_ring_create(name, rte_align32pow2(DPVS_SVC_MAX),
                SOCKET_ID_ANY, 0);
        if (!dpvs_svc_idxq[cid]) {
            RTE_LOG(ERR, IPVS, "fail to create %s\n", name);
            dp_vs_svc_match_term();
            return EDPVS_NOMEM;
        }
        for (i = 1; i < DPVS_SVC_MAX; i++) {
            rte_ring_enqueue(dpvs_svc_idxq[cid], (void*)i);
        }
        size = sizeof(struct dp_vs_service*) * DPVS_SVC_MAX;
        dpvs_svcs[cid] = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);
        if (!dpvs_svcs[cid]) {
            RTE_LOG(ERR, IPVS, "fail to alloc dpvs_svcs\n");
            dp_vs_svc_match_term();
            return EDPVS_NOMEM;
        }
        memset(dpvs_svcs[cid], 0, size);
        dp_vs_svc_match_acl4[cid] = NULL;
        dp_vs_svc_match_acl6[cid] = NULL;
        for (i = 0; i < RULE_TAB_SIZE; i++) {
            INIT_HLIST_HEAD(&dp_vs_match4_list[cid][i]);
            INIT_HLIST_HEAD(&dp_vs_match6_list[cid][i]);
        }
    }
    if (register_idle_job() != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "fail to register_idle_job\n");
        dp_vs_svc_match_term();
        return EDPVS_INVAL;
    }
    return EDPVS_OK;
}

int dp_vs_svc_match_term(void)
{
    int cid = 0;
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (dp_vs_svc_match_acl4[cid]) {
            rte_acl_free(dp_vs_svc_match_acl4[cid]);
            dp_vs_svc_match_acl4[cid] = NULL;
        }
        if (dp_vs_svc_match_acl6[cid]) {
            rte_acl_free(dp_vs_svc_match_acl6[cid]);
            dp_vs_svc_match_acl6[cid] = NULL;
        }
        if (dpvs_svcs[cid]) {
            rte_free(dpvs_svcs[cid]);
        }
        if (dpvs_svc_idxq[cid]) {
            rte_ring_free(dpvs_svc_idxq[cid]);
        }
    }
    return EDPVS_OK;
}

