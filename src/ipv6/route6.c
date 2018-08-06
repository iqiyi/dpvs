/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2018 iQIYI (www.iqiyi.com).
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
#include<assert.h>
#include "route6.h"
#include "linux_ipv6.h"
#include "ctrl.h"
#include "route6_lpm.h"
#include "route6_hlist.h"
#include "parser/parser.h"

#define this_rt6_dustbin        (RTE_PER_LCORE(rt6_dbin))
#define RT6_RECYCLE_TIME_DEF    10

static struct route6_method *g_rt6_method = NULL;
static char g_rt6_name[RT6_METHOD_NAME_SZ] = "hlist";
struct list_head g_rt6_list;

/* route6 recycle list */
struct rt6_dustbin {
    struct list_head routes;
    struct dpvs_timer tm;
};

static int g_rt6_recycle_time = RT6_RECYCLE_TIME_DEF;
static RTE_DEFINE_PER_LCORE(struct rt6_dustbin, rt6_dbin);

int route6_method_register(struct route6_method *rt6_mtd)
{
    struct route6_method *rnode;

    if (!rt6_mtd || strlen(rt6_mtd->name) == 0)
        return EDPVS_INVAL;

    list_for_each_entry(rnode, &g_rt6_list, lnode) {
        if (strncmp(rt6_mtd->name, rnode->name, sizeof(rnode->name)) == 0)
            return EDPVS_EXIST;
    }

    list_add_tail(&rt6_mtd->lnode, &g_rt6_list);
    return EDPVS_OK;
}

int route6_method_unregister(struct route6_method *rt6_mtd)
{
    if (!rt6_mtd)
        return EDPVS_INVAL;
    list_del(&rt6_mtd->lnode);
    return EDPVS_OK;
}

static struct route6_method *rt6_method_get(const char *name)
{
    struct route6_method *rnode;

    list_for_each_entry(rnode, &g_rt6_list, lnode)
        if (strcmp(rnode->name, name) == 0)
            return rnode;

    return NULL;
}

static int rt6_recycle(void *arg)
{
    struct route6 *rt6, *next;
#ifdef DPVS_ROUTE6_DEBUG
    char buf[64];
#endif
    list_for_each_entry_safe(rt6, next, &this_rt6_dustbin.routes, hnode) {
        if (rte_atomic32_read(&rt6->refcnt) <= 1) {
            list_del(&rt6->hnode);
#ifdef DPVS_ROUTE6_DEBUG
            dump_rt6_prefix(&rt6->rt6_dst, buf, sizeof(buf));
            RTE_LOG(DEBUG, RT6, "[%d] %s: delete dustbin route %s->%s\n", rte_lcore_id(),
                    __func__, buf, rt6->rt6_dev ? rt6->rt6_dev->name : "");
#endif
            rte_free(rt6);
        }
    }

    return EDPVS_OK;
}

void route6_free(struct route6 *rt6)
{
    if (unlikely(rte_atomic32_read(&rt6->refcnt) > 1))
        list_add_tail(&rt6->hnode, &this_rt6_dustbin.routes);
    else
        rte_free(rt6);
}

static int rt6_setup_lcore(void *arg)
{
    int err;
    bool global;
    struct timeval tv;

    tv.tv_sec = g_rt6_recycle_time,
    tv.tv_usec = 0,
    global = (rte_lcore_id() == rte_get_master_lcore());

    INIT_LIST_HEAD(&this_rt6_dustbin.routes);
    err = dpvs_timer_sched_period(&this_rt6_dustbin.tm, &tv, rt6_recycle, NULL, global);
    if (err != EDPVS_OK)
        return err;

    return g_rt6_method->rt6_setup_lcore(arg);
}

static int rt6_destroy_lcore(void *arg)
{
    struct route6 *rt6, *next;

    list_for_each_entry_safe(rt6, next, &this_rt6_dustbin.routes, hnode) {
        if (rte_atomic32_read(&rt6->refcnt) <= 1) { /* need judge refcnt here? */
            list_del(&rt6->hnode);
            rte_free(rt6);
        }
    }

    return g_rt6_method->rt6_destroy_lcore(arg);
}

struct route6 *route6_input(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return g_rt6_method->rt6_input(mbuf, fl6);
}

struct route6 *route6_output(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return g_rt6_method->rt6_output(mbuf, fl6);
}

int route6_put(struct route6 *rt)
{
    rte_atomic32_dec(&rt->refcnt);
    return EDPVS_OK;
}

static struct route6 *rt6_get(const struct dp_vs_route6_conf *rt6_cfg)
{
    return g_rt6_method->rt6_get(rt6_cfg);
}

static int rt6_add_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{
    return g_rt6_method->rt6_add_lcore(rt6_cfg);
}

static int rt6_del_lcore(const struct dp_vs_route6_conf *rt6_cfg)
{
    return g_rt6_method->rt6_del_lcore(rt6_cfg);
}

/* called on master */
static int rt6_add_del(const struct dp_vs_route6_conf *cf)
{
    int err;
    struct dpvs_msg *msg;
    lcoreid_t cid;

    cid = rte_lcore_id();
    assert(cid == rte_get_master_lcore());

    /* for master */
    switch (cf->ops) {
        case RT6_OPS_ADD:
            if (rt6_get(cf) != NULL)
                return EDPVS_EXIST;
            err = rt6_add_lcore(cf);
            break;
        case RT6_OPS_DEL:
            if (rt6_get(cf) == NULL)
                return EDPVS_NOTEXIST;
            err = rt6_del_lcore(cf);
            break;
        default:
            return EDPVS_INVAL;
    }
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, RT6, "%s: fail to add/del route on master -- %s!\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    /* for slaves */
    msg = msg_make(MSG_TYPE_ROUTE6, 0, DPVS_MSG_MULTICAST, cid,
            sizeof(struct dp_vs_route6_conf), cf);
    if (unlikely(msg == NULL)) {
        err = EDPVS_NOMEM;
        goto slave_fail;
    }

    err = multicast_msg_send(msg, 0, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        goto slave_fail;
    }
    msg_destroy(&msg);

    return EDPVS_OK;

slave_fail:
    RTE_LOG(ERR, RT6, "%s: fail to add/del route on slaves -- %s\n",
            __func__, dpvs_strerror(err));
    return err;
}

static int rt6_msg_process_cb(struct dpvs_msg *msg)
{
    struct dp_vs_route6_conf *cf;

    assert(msg && msg->data);
    if (msg->len != sizeof(struct dp_vs_route6_conf)) {
        RTE_LOG(WARNING, RT6, "%s: invalid route6 msg!\n", __func__);
        return EDPVS_INVAL;
    }

    cf = (struct dp_vs_route6_conf *)msg->data;
    switch (cf->ops) {
        case RT6_OPS_GET:
            /* to be supported */
            return EDPVS_NOTSUPP;
        case RT6_OPS_ADD:
            return rt6_add_lcore(cf);
        case RT6_OPS_DEL:
            return rt6_del_lcore(cf);
        default:
            RTE_LOG(WARNING, RT6, "%s: unsupported operation for route6 msg -- %d!\n",
                    __func__, cf->ops);
            return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static bool rt6_conf_check(const struct dp_vs_route6_conf *rt6_cfg)
{
    if (!rt6_cfg)
        return false;

    if (rt6_cfg->ops < RT6_OPS_GET || rt6_cfg->ops > RT6_OPS_FLUSH)
        return false;

    if (rt6_cfg->dst.plen > 128 || rt6_cfg->dst.plen < 0)
        return false;

    if (rt6_cfg->src.plen > 128 || rt6_cfg->src.plen < 0)
        return false;

    if (rt6_cfg->prefsrc.plen > 128 || rt6_cfg->prefsrc.plen < 0)
        return false;

    if (netif_port_get_by_name(rt6_cfg->ifname) == NULL)
        return false;

    return true;
}

#ifdef DPVS_ROUTE6_DEBUG
static void rt6_test(const struct dp_vs_route6_conf *rt6_cfg)
{
    struct route6 *rt6_input, *rt6_output;
    struct flow6 fl6;
    char dst[64], src[64];
    char rt6_input_prefix[64], rt6_output_prefix[64];

    memset(dst, 0, sizeof(dst));
    memset(src, 0, sizeof(src));
    memset(rt6_input_prefix, 0, sizeof(rt6_input_prefix));
    memset(rt6_output_prefix, 0, sizeof(rt6_output_prefix));

    memcpy(&fl6.fl6_daddr, &rt6_cfg->dst.addr, sizeof(struct in6_addr));
    memcpy(&fl6.fl6_saddr, &rt6_cfg->src.addr, sizeof(struct in6_addr));
    fl6.fl6_oif = netif_port_get_by_name(rt6_cfg->ifname);

    inet_ntop(AF_INET6, &fl6.fl6_daddr, dst, sizeof(dst));
    inet_ntop(AF_INET6, &fl6.fl6_saddr, src, sizeof(src));

    rt6_input = route6_input(NULL, &fl6);
    if (rt6_input)
        dump_rt6_prefix(&rt6_input->rt6_dst, rt6_input_prefix, sizeof(rt6_input_prefix));
    else
        snprintf(rt6_input_prefix, sizeof(rt6_input_prefix), "%s", "miss");

    rt6_output = route6_output(NULL, &fl6);
    if (rt6_output)
        dump_rt6_prefix(&rt6_output->rt6_dst, rt6_output_prefix, sizeof(rt6_output_prefix));
    else
        snprintf(rt6_output_prefix, sizeof(rt6_output_prefix), "%s", "miss");

    RTE_LOG(INFO, RT6, "[%d] fl6(daddr:%s, saddr: %s, oif=%s) -> "
            "in(%s dev %s), out(%s dev %s)\n",
            rte_lcore_id(), dst, src, fl6.fl6_oif->name,
            rt6_input_prefix, rt6_input ? rt6_input->rt6_dev->name : "xx",
            rt6_output_prefix, rt6_output ? rt6_output->rt6_dev->name : "xx");
}
#endif

static inline void rt6_zero_prefix_tail(struct rt6_prefix *rt6_p)
{
    struct in6_addr addr6;

    ipv6_addr_prefix(&addr6, &rt6_p->addr, rt6_p->plen);
    memcpy(&rt6_p->addr, &addr6, sizeof(addr6));
}

static void rt6_cfg_zero_prefix_tail(const struct dp_vs_route6_conf *src,
        struct dp_vs_route6_conf *dst)
{
    memcpy(dst, src, sizeof(*dst));

    rt6_zero_prefix_tail(&dst->dst);
    /* do not change dst->src, dst->prefsrc */
}

static int rt6_sockopt_set(sockoptid_t opt, const void *in, size_t inlen)
{
    const struct dp_vs_route6_conf *rt6_cfg_in = in;
    struct dp_vs_route6_conf rt6_cfg;

    if (!rt6_conf_check(rt6_cfg_in)) {
        RTE_LOG(INFO, RT6, "%s: invalid route6 sockopt!\n", __func__);
        return EDPVS_INVAL;
    }

    rt6_cfg_zero_prefix_tail(rt6_cfg_in, &rt6_cfg);

    switch (opt) {
        case SOCKOPT_SET_ROUTE6_ADD_DEL:
            return rt6_add_del(&rt6_cfg);
        case SOCKOPT_SET_ROUTE6_FLUSH:
#ifdef DPVS_ROUTE6_DEBUG
            RTE_LOG(INFO, RT6, "test route6 lookup using flush!\n");
            rt6_test(&rt6_cfg);
#endif
            return EDPVS_NOTSUPP;
        default:
            return EDPVS_NOTSUPP;
    }
}

static int rt6_sockopt_get(sockoptid_t opt, const void *in, size_t inlen,
        void **out, size_t *outlen)
{
    *out = g_rt6_method->rt6_dump(in, outlen);
    if (*out == NULL)
        *outlen = 0;
    return EDPVS_OK;
}

static struct dpvs_sockopts route6_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_ROUTE6_ADD_DEL,
    .set_opt_max    = SOCKOPT_SET_ROUTE6_FLUSH,
    .set            = rt6_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_ROUTE6_SHOW,
    .get_opt_max    = SOCKOPT_GET_ROUTE6_SHOW,
    .get            = rt6_sockopt_get,
};

static void rt6_method_init(void)
{
    /* register all route6 method here! */
    route6_lpm_init();
    route6_hlist_init();
}

static void rt6_method_term(void)
{
    /* clean up all route6 method here! */
    route6_lpm_term();
    route6_hlist_term();
}

int route6_init(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    INIT_LIST_HEAD(&g_rt6_list);

    rt6_method_init();
    g_rt6_method = rt6_method_get(g_rt6_name);
    if (!g_rt6_method) {
        RTE_LOG(ERR, RT6, "%s: rt6 method '%s' not found!\n",
                __func__, g_rt6_name);
        return EDPVS_NOTEXIST;
    }

    rte_eal_mp_remote_launch(rt6_setup_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(ERR, RT6, "%s: fail to setup rt6 on lcore%d -- %s\n",
                    __func__, cid, dpvs_strerror(err));
            return EDPVS_DPDKAPIFAIL;
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type           = MSG_TYPE_ROUTE6;
    msg_type.mode           = DPVS_MSG_MULTICAST;
    msg_type.cid            = rte_lcore_id();
    msg_type.unicast_msg_cb = rt6_msg_process_cb;
    err = msg_type_mc_register(&msg_type);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, RT6, "%s: fail to register route6 msg!\n", __func__);
        return err;
    }

    if ((err = sockopt_register(&route6_sockopts)) != EDPVS_OK) {
        RTE_LOG(ERR, RT6, "%s: fail to register route6 sockopt!\n", __func__);
        return err;
    }

    return EDPVS_OK;
}

int route6_term(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    rt6_method_term();

    if ((err = sockopt_unregister(&route6_sockopts)) != EDPVS_OK)
        RTE_LOG(WARNING, RT6, "%s: fail to unregister route6 sockopt!\n", __func__);

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type           = MSG_TYPE_ROUTE6;
    msg_type.mode           = DPVS_MSG_MULTICAST;
    msg_type.cid            = rte_lcore_id();
    msg_type.unicast_msg_cb = rt6_msg_process_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, RT6, "%s:fail to unregister route6 msg!\n", __func__);

    rte_eal_mp_remote_launch(rt6_destroy_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, RT6, "%s: fail to destroy rt6 on lcore%d -- %s\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}

/* config file */
static void rt6_method_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (!strcmp(str, "hlist") || !strcmp(str, "lpm")) {
        RTE_LOG(INFO, RT6, "route6:method = %s\n", str);
        snprintf(g_rt6_name, sizeof(g_rt6_name), "%s", str);
    } else {
        RTE_LOG(WARNING, RT6, "invalid route6:method %s, using default %s\n",
                str, "hlist");
        snprintf(g_rt6_name, sizeof(g_rt6_name), "%s", "hlist");
    }

    FREE_PTR(str);
}

void route6_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        snprintf(g_rt6_name, sizeof(g_rt6_name), "%s", "hlist");
    }

    route6_lpm_keyword_value_init();
}

void install_route6_keywords(void)
{
    install_keyword_root("route6", NULL);
    install_keyword("method", rt6_method_handler, KW_TYPE_INIT);
    install_rt6_lpm_keywords();
}
