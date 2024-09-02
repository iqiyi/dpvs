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
#include<assert.h>
#include "route6.h"
#include "conf/route.h"
#include "linux_ipv6.h"
#include "ctrl.h"
#include "route6_lpm.h"
#include "route6_hlist.h"
#include "parser/parser.h"

#define this_rt6_dustbin        (RTE_PER_LCORE(rt6_dbin))
#define RT6_RECYCLE_TIME_DEF    10
#define RT6_RECYCLE_TIME_MAX    36000
#define RT6_RECYCLE_TIME_MIN    1

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

static int rt6_msg_seq(void)
{
    static uint32_t seq = 0;

    return seq++;
}

static inline void rt6_zero_prefix_tail(rt_addr_t *rt6_p)
{
    struct in6_addr addr6;

    ipv6_addr_prefix(&addr6, &rt6_p->addr.in6, rt6_p->plen);
    memcpy(&rt6_p->addr.in6, &addr6, sizeof(addr6));
}

static void rt6_cfg_zero_prefix_tail(const struct dp_vs_route6_conf *src,
        struct dp_vs_route6_conf *dst)
{
    memcpy(dst, src, sizeof(*dst));

    rt6_zero_prefix_tail(&dst->dst);
    /* do not change dst->src, dst->prefsrc */
}

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
    lcoreid_t cid = rte_lcore_id();

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    tv.tv_sec = g_rt6_recycle_time,
    tv.tv_usec = 0,
    global = (cid == rte_get_main_lcore());

    INIT_LIST_HEAD(&this_rt6_dustbin.routes);
    err = dpvs_timer_sched_period(&this_rt6_dustbin.tm, &tv, rt6_recycle, NULL, global);
    if (err != EDPVS_OK)
        return err;

    return g_rt6_method->rt6_setup_lcore(arg);
}

static int rt6_destroy_lcore(void *arg)
{
    struct route6 *rt6, *next;

    if (rte_lcore_id() >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    list_for_each_entry_safe(rt6, next, &this_rt6_dustbin.routes, hnode) {
        if (rte_atomic32_read(&rt6->refcnt) <= 1) { /* need judge refcnt here? */
            list_del(&rt6->hnode);
            rte_free(rt6);
        }
    }

    return g_rt6_method->rt6_destroy_lcore(arg);
}

struct route6 *route6_input(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return g_rt6_method->rt6_input(mbuf, fl6);
}

struct route6 *route6_output(const struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return g_rt6_method->rt6_output(mbuf, fl6);
}

int route6_get(struct route6 *rt)
{
    if (!rt)
        return EDPVS_INVAL;
    rte_atomic32_inc(&rt->refcnt);
    return EDPVS_OK;
}

int route6_put(struct route6 *rt)
{
    if (!rt)
        return EDPVS_INVAL;
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
    assert(cid == rte_get_main_lcore());

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
    msg = msg_make(MSG_TYPE_ROUTE6, rt6_msg_seq(), DPVS_MSG_MULTICAST, cid,
            sizeof(struct dp_vs_route6_conf), cf);
    if (unlikely(msg == NULL)) {
        RTE_LOG(ERR, RT6, "%s: fail to add/del route on slaves -- %s\n",
                __func__, dpvs_strerror(err));
        return EDPVS_NOMEM;
    }

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, RT6, "%s: multicast_msg_send failed -- %s\n",
                __func__, dpvs_strerror(err));
    msg_destroy(&msg);

    return EDPVS_OK;
}

static int __route6_add_del(const struct in6_addr *dest, int plen, uint32_t flags,
                            const struct in6_addr *gw, struct netif_port *dev,
                            const struct in6_addr *src, uint32_t mtu, bool add)
{
    struct dp_vs_route6_conf cf;

    memset(&cf, 0, sizeof(cf));
    if (add)
        cf.ops  = RT6_OPS_ADD;
    else
        cf.ops  = RT6_OPS_DEL;
    cf.dst.addr.in6 = *dest;
    cf.dst.plen = plen;
    cf.flags    = flags;
    cf.gateway  = *gw;
    snprintf(cf.ifname, sizeof(cf.ifname), "%s", dev->name);
    cf.src.addr.in6 = *src;
    cf.src.plen = plen;
    cf.mtu      = mtu;

    rt6_zero_prefix_tail(&cf.dst);

    return rt6_add_del(&cf);
}

int route6_add(const struct in6_addr *dest, int plen, uint32_t flags,
               const struct in6_addr *gw, struct netif_port *dev,
               const struct in6_addr *src, uint32_t mtu)
{
    return __route6_add_del(dest, plen, flags, gw, dev, src, mtu, true);
}

int route6_del(const struct in6_addr *dest, int plen, uint32_t flags,
               const struct in6_addr *gw, struct netif_port *dev,
               const struct in6_addr *src, uint32_t mtu)
{
    return __route6_add_del(dest, plen, flags, gw, dev, src, mtu, false);
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

static int rt6_sockopt_set(sockoptid_t opt, const void *in, size_t inlen)
{
    const struct dp_vs_route6_conf  *rt6_cfg_in = in;
    struct dp_vs_route6_conf rt6_cfg;

#ifdef CONFIG_DPVS_AGENT
    const struct dp_vs_route_detail *detail = in;

    if (opt == DPVSAGENT_ROUTE6_ADD || opt == DPVSAGENT_ROUTE6_DEL) {
        memcpy(&rt6_cfg.dst, &detail->dst, sizeof(rt_addr_t));
        memcpy(&rt6_cfg.src, &detail->src, sizeof(rt_addr_t));
        memcpy(&rt6_cfg.prefsrc, &detail->prefsrc, sizeof(rt_addr_t));
        memcpy(&rt6_cfg.gateway, &detail->gateway.addr, sizeof(struct in6_addr));
        memcpy(rt6_cfg.ifname, detail->ifname, IFNAMSIZ);
        rt6_cfg.mtu = detail->mtu;
        rt6_cfg.flags = detail->flags;
        rt6_cfg.ops = opt == DPVSAGENT_ROUTE6_ADD ? RT6_OPS_ADD : RT6_OPS_DEL;

        rt6_zero_prefix_tail(&rt6_cfg.dst);
    } else {
#endif
        if (!rt6_conf_check(rt6_cfg_in)) {
            RTE_LOG(INFO, RT6, "%s: invalid route6 sockopt!\n", __func__);
            return EDPVS_INVAL;
        }

        rt6_cfg_zero_prefix_tail(rt6_cfg_in, &rt6_cfg);
#ifdef CONFIG_DPVS_AGENT
    }
#endif

    switch (opt) {
#ifdef CONFIG_DPVS_AGENT
        case DPVSAGENT_ROUTE6_ADD:
            /*fallthrough*/
        case DPVSAGENT_ROUTE6_DEL:
            /*fallthrough*/
#endif
        case SOCKOPT_SET_ROUTE6_ADD_DEL:
            return rt6_add_del(&rt6_cfg);
        case SOCKOPT_SET_ROUTE6_FLUSH:
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

#ifdef CONFIG_DPVS_AGENT
static struct dpvs_sockopts agent_route6_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = DPVSAGENT_ROUTE6_ADD,
    .set_opt_max    = DPVSAGENT_ROUTE6_DEL,
    .set            = rt6_sockopt_set,
    .get_opt_min    = DPVSAGENT_ROUTE6_GET,
    .get_opt_max    = DPVSAGENT_ROUTE6_GET,
    .get            = rt6_sockopt_get,
};
#endif

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

    rte_eal_mp_remote_launch(rt6_setup_lcore, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(ERR, RT6, "%s: fail to setup rt6 on lcore%d -- %s\n",
                    __func__, cid, dpvs_strerror(err));
            return EDPVS_DPDKAPIFAIL;
        }
    }

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type           = MSG_TYPE_ROUTE6;
    msg_type.mode           = DPVS_MSG_MULTICAST;
    msg_type.prio           = MSG_PRIO_NORM;
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

#ifdef CONFIG_DPVS_AGENT
    if ((err = sockopt_register(&agent_route6_sockopts)) != EDPVS_OK) {
        RTE_LOG(ERR, RT6, "%s: fail to register route6 sockopt!\n", __func__);
        return err;
    }
#endif

    return EDPVS_OK;
}

int route6_term(void)
{
    int err;
    lcoreid_t cid;
    struct dpvs_msg_type msg_type;

    rt6_method_term();

#ifdef CONFIG_DPVS_AGENT
    if ((err = sockopt_unregister(&agent_route6_sockopts)) != EDPVS_OK)
        RTE_LOG(WARNING, RT6, "%s: fail to unregister route6 sockopt!\n", __func__);
#endif

    if ((err = sockopt_unregister(&route6_sockopts)) != EDPVS_OK)
        RTE_LOG(WARNING, RT6, "%s: fail to unregister route6 sockopt!\n", __func__);

    memset(&msg_type, 0, sizeof(struct dpvs_msg_type));
    msg_type.type           = MSG_TYPE_ROUTE6;
    msg_type.mode           = DPVS_MSG_MULTICAST;
    msg_type.prio           = MSG_PRIO_NORM;
    msg_type.cid            = rte_lcore_id();
    msg_type.unicast_msg_cb = rt6_msg_process_cb;
    err = msg_type_mc_unregister(&msg_type);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, RT6, "%s:fail to unregister route6 msg!\n", __func__);

    rte_eal_mp_remote_launch(rt6_destroy_lcore, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
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

static void rt6_recycle_time_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int recycle_time;

    assert(str);
    recycle_time = atoi(str);
    if (recycle_time > RT6_RECYCLE_TIME_MAX || recycle_time < RT6_RECYCLE_TIME_MIN) {
        RTE_LOG(WARNING, RT6, "invalid ipv6:route:recycle_time %s, using default %d\n",
                str, RT6_RECYCLE_TIME_DEF);
        g_rt6_recycle_time = RT6_RECYCLE_TIME_DEF;
    } else {
        RTE_LOG(INFO, RT6, "ipv6:route:recycle_time = %d\n", recycle_time);
        g_rt6_recycle_time = recycle_time;
    }

    FREE_PTR(str);
}

void route6_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        snprintf(g_rt6_name, sizeof(g_rt6_name), "%s", "hlist");
    }
    /* KW_TYPE_NORMAL keyword */
    g_rt6_recycle_time = RT6_RECYCLE_TIME_DEF;

    route6_lpm_keyword_value_init();
}

void install_route6_keywords(void)
{
    install_keyword("route6", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("method", rt6_method_handler, KW_TYPE_INIT);
    install_keyword("recycle_time", rt6_recycle_time_handler, KW_TYPE_NORMAL);
    install_rt6_lpm_keywords();
    install_sublevel_end();
}
