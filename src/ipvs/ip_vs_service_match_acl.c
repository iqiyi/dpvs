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

#define DEFAULT_MAX_CATEGORIES    1
#define DPVS_SVC_MAX 1000000
#define DPVS_SVC_HT_SIZE 0x10000
#define HASH_INIT_VAL 0x12345678

/* DPDK ACL target is uint32_t, we should translate u32 to svc.
 * BASE+cache_line_size*u32 could index 256G memory,
 * maybe enough for most situations?
 */
static struct dp_vs_service **dpvs_svcs = NULL;
static struct rte_ring *dpvs_svc_idxq = NULL;
static uint64_t dpvs_match4_generation = 0;
static uint64_t dpvs_match6_generation = 0;
static struct rte_acl_ctx *dp_vs_svc_match_acl4 = NULL;
static struct rte_acl_ctx *dp_vs_svc_match_acl6 = NULL;
static int stop_build = 0;

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
static int svc_to_match_acl4(struct dp_vs_service *svc, struct dpvs_match_rule4 *rule)
{
    uint32_t min = 0;
    uint32_t max = 0;
    struct netif_port* dev = NULL;
    rule->data.category_mask = -1;
    rule->data.priority = 1;
    rule->data.userdata = svc->idx;;

    rule->field[PROTO_FIELD_IPV4].value.u8 = svc->proto;
    rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0xff;
    /* for snat, 0 proto match any proto */
    if (!svc->proto) {
        rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0x0;
    }

    min = ntohl(svc->match->srange.min_addr.in.s_addr);
    max = ntohl(svc->match->srange.max_addr.in.s_addr);
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

    min = ntohl(svc->match->drange.min_addr.in.s_addr);
    max = ntohl(svc->match->drange.max_addr.in.s_addr);
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

    min = ntohs(svc->match->srange.min_port);
    max = ntohs(svc->match->srange.max_port);
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

    min = ntohs(svc->match->drange.min_port);
    max = ntohs(svc->match->drange.max_port);
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

    dev = netif_port_get_by_name(svc->match->iifname);
    if (dev) {
        rule->field[IIFID_FIELD_IPV4].value.u16 = ntohs(dev->id);
        rule->field[IIFID_FIELD_IPV4].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[IIFID_FIELD_IPV4].value.u16 = 0;
        rule->field[IIFID_FIELD_IPV4].mask_range.u16 = 0xffff;
    }

    dev = netif_port_get_by_name(svc->match->oifname);
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

static int svc_to_match_acl6(struct dp_vs_service *svc, struct dpvs_match_rule6 *rule)
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
    rule->data.userdata = svc->idx;;

    rule->field[PROTO_FIELD_IPV6].value.u8 = svc->proto;
    rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0xff;
    /* for snat, 0 proto match any proto */
    if (!svc->proto) {
        rule->field[PROTO_FIELD_IPV6].mask_range.u8 = 0x0;
    }

    min = ntohs(svc->match->srange.min_port);
    max = ntohs(svc->match->srange.max_port);
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

    min = ntohs(svc->match->drange.min_port);
    max = ntohs(svc->match->drange.max_port);
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

    dev = netif_port_get_by_name(svc->match->iifname);
    if (dev) {
        rule->field[IIFID_FIELD_IPV6].value.u16 = ntohs(dev->id);
        rule->field[IIFID_FIELD_IPV6].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[IIFID_FIELD_IPV6].value.u16 = 0;
        rule->field[IIFID_FIELD_IPV6].mask_range.u16 = 0xffff;
    }

    dev = netif_port_get_by_name(svc->match->oifname);
    if (dev) {
        rule->field[OIFID_FIELD_IPV6].value.u16 = ntohs(dev->id);
        rule->field[OIFID_FIELD_IPV6].mask_range.u16 = ntohs(dev->id);
    } else {
        rule->field[OIFID_FIELD_IPV6].value.u16 = 0;
        rule->field[OIFID_FIELD_IPV6].mask_range.u16 = 0xffff;
    }

    src_cnt = ip6_range_split(&svc->match->srange, srange);
    dst_cnt = ip6_range_split(&svc->match->drange, drange);
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

struct rules_block_node {
    struct list_head list;
    int cnt;
    struct rte_acl_rule rule[0];
};

struct rules_block_list {
    int cnt;
    int af;
    struct list_head head;
};
#define BLOCK_RULES_CNT 4096

static void* rules_block_list_get_rules(struct rules_block_list* bl, uint32_t cnt)
{
    struct rules_block_node *n = NULL;
    int size = 0;
    if (cnt > BLOCK_RULES_CNT) {
        return NULL;
    }
    if (bl->af == AF_INET) {
        size = sizeof(struct dpvs_match_rule4);
    } else {
        size = sizeof(struct dpvs_match_rule6);
    }
    if (!list_empty(&bl->head)) {
        n = list_last_entry(&bl->head, struct rules_block_node, list);
        if (n->cnt + cnt < BLOCK_RULES_CNT) {
            return ((void*)n->rule) + n->cnt * size;
        }
    }
    size = sizeof(struct rules_block_node) + size * BLOCK_RULES_CNT;
    n = malloc(size);
    if (!n) {
        return NULL;
    }
    memset(n, 0, size);
    list_add_tail(&n->list, &bl->head);
    return n->rule;
}

static int rules_block_list_add(struct rules_block_list* bl, uint32_t cnt)
{
    struct rules_block_node *n = NULL;
    n = list_last_entry(&bl->head, struct rules_block_node, list);
    assert(n->cnt + cnt < BLOCK_RULES_CNT);
    n->cnt += cnt;
    bl->cnt += cnt;
    return 0;
}

static int rules_block_list_clean(struct rules_block_list* bl)
{
    struct rules_block_node *p = NULL;
    struct rules_block_node *n = NULL;
    list_for_each_entry_safe(p, n, &bl->head, list) {
        free(p);
    }
    return EDPVS_OK;
}
static int dpvs_match_to_rules(struct dp_vs_service *svc, void *data)
{
    struct rules_block_list *bl = data;
    int rule_cnt = 0;
    void *rule = NULL;
    if (svc->af == AF_INET) {
        rule_cnt = 1;
        rule = rules_block_list_get_rules(bl, rule_cnt);
        if (!rule) {
            return EDPVS_NOMEM;
        }
        svc_to_match_acl4(svc, rule);
    } else {
        rule_cnt = ip6_range_split(&svc->match->srange, NULL) *
            ip6_range_split(&svc->match->drange, NULL);
        rule = rules_block_list_get_rules(bl, rule_cnt);
        if (!rule) {
            return EDPVS_NOMEM;
        }
        rule_cnt = svc_to_match_acl6(svc, rule);
    }
    rules_block_list_add(bl, rule_cnt);
    return EDPVS_OK;
}

static int build_acl(int af)
{
    char name[PATH_MAX];
    struct rte_acl_param acl_param;
    struct rte_acl_config acl_build_param;
    struct rte_acl_ctx *context = NULL;
    struct rte_acl_ctx **pctx = NULL;
    struct rte_acl_ctx *tmp = NULL;
    int dim = 0;
    struct rules_block_list bl;
    struct rules_block_node *n = NULL;

    memset(&acl_build_param, 0, sizeof(acl_build_param));
    acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
    if (af == AF_INET6) {
        dim = RTE_DIM(dpvs_match_defs6);
        memcpy(&acl_build_param.defs, dpvs_match_defs6,
                    sizeof(dpvs_match_defs6));
        pctx = &dp_vs_svc_match_acl6;
    } else {
        dim = RTE_DIM(dpvs_match_defs4);
        memcpy(&acl_build_param.defs, dpvs_match_defs4,
                    sizeof(dpvs_match_defs4));
        pctx = &dp_vs_svc_match_acl4;
    }
    bl.af = af;
    bl.cnt = 0;
    INIT_LIST_HEAD(&bl.head);
    if (dp_vs_services_match_iter(dpvs_match_to_rules, &bl,
                rte_get_master_lcore()) != EDPVS_OK) {
        rules_block_list_clean(&bl);
        return EDPVS_NOMEM;
    }
    if (!bl.cnt) {
        goto end;
    }
    acl_build_param.num_fields = dim;
    snprintf(name, sizeof(name), "dpvs_match_acl%x",
            rte_atomic32_add_return(&acl_build_idx, 1));
    acl_param.name = name;
    acl_param.socket_id = SOCKET_ID_ANY;
    acl_param.rule_size = RTE_ACL_RULE_SZ(dim);

    acl_param.max_rule_num = bl.cnt;
    context = rte_acl_create(&acl_param);
    if (!context) {
        RTE_LOG(ERR, IPVS, "rte_acl_create failed\n");
        goto ctx_create_failed;
    }

    list_for_each_entry_reverse(n, &bl.head, list) {
        if (!n->cnt) {
            continue;
        }
        if (rte_acl_add_rules(context, n->rule, n->cnt) < 0) {
            RTE_LOG(ERR, IPVS, "add rules failed\n");
            goto add_rule_fail;
        }
    }

    /* build acl needs lots of memory */
    rules_block_list_clean(&bl);

    if (rte_acl_build(context, &acl_build_param) != 0) {
        RTE_LOG(ERR, IPVS, "rte_acl_build failed\n");
        goto build_failed;
    }
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
    rte_acl_free(context);
ctx_create_failed:
    rules_block_list_clean(&bl);
    return -1;
}

static struct dp_vs_service *dpvs_idx_svc(uint32_t idx)
{
    if (unlikely(idx >= DPVS_SVC_MAX)) {
        return NULL;
    }
    return dpvs_svcs[idx];
}

int dp_vs_svc_match_acl_add(struct dp_vs_service *svc, lcoreid_t cid)
{
    void *p = NULL;
    uint32_t idx = 0;
    if (!svc || cid != rte_get_master_lcore()) {
        return 0;
    }
    rte_ring_dequeue(dpvs_svc_idxq, &p);
    idx = (unsigned long)p;
    svc->idx = idx;
    dpvs_svcs[idx] = svc;
    /* maybe we should put v4/v6 svc into diff list */
    if (svc->af == AF_INET) {
        dpvs_match4_generation++;
    } else {
        dpvs_match6_generation++;
    }
    return 0;
}

int dp_vs_svc_match_acl_del(struct dp_vs_service *svc)
{
    uint64_t idx = 0;
    if (!svc) {
        return 0;
    }
    if (svc->idx <= 0 || svc->idx >= DPVS_SVC_MAX) {
        return -1;
    }
    if (dpvs_svcs[svc->idx] != svc) {
        return -1;
    }
    dpvs_svcs[svc->idx] = NULL;
    idx = svc->idx;
    rte_ring_enqueue(dpvs_svc_idxq, (void*)idx);
    svc->idx = 0;
    if (svc->af == AF_INET) {
        dpvs_match4_generation++;
    } else {
        dpvs_match6_generation++;
    }
    return 0;
}

struct dp_vs_service *dp_vs_get_match_svc_ip4(uint8_t proto, union inet_addr *saddr,
                     union inet_addr *daddr, __be16 sport, __be16 dport,
                     portid_t iif, portid_t oif)
{
    struct dp_vs_service *svc = NULL;
    struct rte_acl_ctx *ctx = NULL;
    ctx = dp_vs_svc_match_acl4;
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
            svc = dpvs_idx_svc(idx);
        }
    }
    return svc;
}

struct dp_vs_service *dp_vs_get_match_svc_ip6(uint8_t proto, union inet_addr *saddr,
                     union inet_addr *daddr, __be16 sport, __be16 dport,
                     portid_t iif, portid_t oif)
{
    struct dp_vs_service *svc = NULL;
    struct rte_acl_ctx *ctx = NULL;
    ctx = dp_vs_svc_match_acl6;
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
            svc = dpvs_idx_svc(idx);
        }
    }
    return svc;
}

static char thread_name[16] = "match_acl";
static int bind_cpu = -1;
static int dpvs_svc_match_build_thread_init(void *data)
{
    int ret = 0;
    pthread_t tid;
    cpu_set_t cpuset;

    tid = pthread_self();
    ret = pthread_setname_np(tid, thread_name);
    if (ret != 0) {
        RTE_LOG(WARNING, EAL, "pthread_setname_np failed\n");
    }

    if (bind_cpu >= 0) {
        CPU_ZERO(&cpuset);
        CPU_SET(bind_cpu, &cpuset);
        ret = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
        if (ret != 0) {
            RTE_LOG(WARNING, EAL, "pthread_setaffinity_np failed, cpu %d\n", bind_cpu);
        }
    }
    return 0;
}

static void *dpvs_svc_match_build_loop(void *data)
{
    uint64_t pre4 = 0;
    uint64_t pre6 = 0;
    struct timeval t1;
    struct timeval t2;
    struct timeval d;
    dpvs_svc_match_build_thread_init(data);
    while (!stop_build) {
        if (pre4 == dpvs_match4_generation &&
            pre6 == dpvs_match6_generation) {
            usleep(100000);
            continue;
        }
        gettimeofday(&t1, NULL);
        if (pre4 != dpvs_match4_generation) {
            pre4 = dpvs_match4_generation;
            build_acl(AF_INET);
        }
        if (pre6 != dpvs_match6_generation) {
            pre6 = dpvs_match6_generation;
            build_acl(AF_INET6);
        }
        gettimeofday(&t2, NULL);
        if (t2.tv_usec < t1.tv_usec) {
            d.tv_usec = t2.tv_usec + 1000000 - t1.tv_usec;
            d.tv_sec = t2.tv_sec - t1.tv_sec - 1;
        } else {
            d.tv_usec = t2.tv_usec - t1.tv_usec;
            d.tv_sec = t2.tv_sec - t1.tv_sec;
        }
        RTE_LOG(DEBUG, IPVS, "build acl for generation4 %ld, generation6 %ld,"
                             " time used:%lu.%06lu, start at %lu.%06lu end at %lu.%06lu\n",
                            pre4, pre6, d.tv_sec, d.tv_usec,
                            t1.tv_sec, t1.tv_usec, t2.tv_sec, t2.tv_usec);
    }
    return NULL;
}

int dp_vs_svc_match_init(void)
{
    uint64_t i = 0;
    dpvs_svc_idxq = rte_ring_create("dpvs_idx_q", rte_align32pow2(DPVS_SVC_MAX),
                                         SOCKET_ID_ANY, 0);
    if (!dpvs_svc_idxq) {
        RTE_LOG(ERR, IPVS, "fail to create dpvs_idx_q\n");
        dp_vs_svc_match_term();
        return EDPVS_NOMEM;
    }
    for (i = 1; i < DPVS_SVC_MAX; i++) {
        rte_ring_enqueue(dpvs_svc_idxq, (void*)i);
    }
    dpvs_svcs = rte_malloc(NULL, sizeof(struct dp_vs_service*) * DPVS_SVC_MAX,
                            RTE_CACHE_LINE_SIZE);
    if (!dpvs_svcs) {
        RTE_LOG(ERR, IPVS, "fail to alloc dpvs_svcs\n");
        dp_vs_svc_match_term();
        return EDPVS_NOMEM;
    }
    memset(dpvs_svcs, 0, sizeof(struct dp_vs_service*) * DPVS_SVC_MAX);
    dp_vs_svc_match_acl4 = NULL;
    dp_vs_svc_match_acl6 = NULL;
    pthread_t tid;

    stop_build = 0;
    if (pthread_create(&tid, NULL, dpvs_svc_match_build_loop, NULL)) {
        RTE_LOG(ERR, IPVS, "fail to create dpvs_svc_match_build_loop thread\n");
        dp_vs_svc_match_term();
        return EDPVS_SYSCALL;
    }
    return EDPVS_OK;
}

int dp_vs_svc_match_term(void)
{
    stop_build = 1;
    if (dp_vs_svc_match_acl4) {
        rte_acl_free(dp_vs_svc_match_acl4);
        dp_vs_svc_match_acl4 = NULL;
    }
    if (dp_vs_svc_match_acl6) {
        rte_acl_free(dp_vs_svc_match_acl6);
        dp_vs_svc_match_acl6 = NULL;
    }
    if (dpvs_svcs) {
        rte_free(dpvs_svcs);
    }
    if (dpvs_svc_idxq) {
        rte_ring_free(dpvs_svc_idxq);
    }
    return EDPVS_OK;
}

static void bind_cpu_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    bind_cpu = atoi(str);
    FREE_PTR(str);
}

static void thread_name_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (str[0] ) {
        strncpy(thread_name, str, 15);
        thread_name[15] = 0;
    }
    FREE_PTR(str);
}

void install_service_match_keywords(void)
{
    install_keyword_root("service_match", NULL);
    install_keyword("bind_cpu", bind_cpu_handler, KW_TYPE_INIT);
    install_keyword("thead_name", thread_name_handler, KW_TYPE_NORMAL);
}

