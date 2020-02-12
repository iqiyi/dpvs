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
 * control plane for traffic control module of DPVS.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <linux/pkt_sched.h>
#include "ctrl.h"
#include "netif.h"
#include "tc/tc.h"
#include "tc/cls.h"
#include "tc/sch.h"
#include "conf/tc.h"

static int fill_qsch_param(struct Qsch *sch, struct tc_qsch_param *pr)
{
    int err;
    struct dpvs_msg *req, *reply;
    struct dpvs_multicast_queue *replies = NULL;
    struct tc_qsch_stats *st;

    memset(pr, 0, sizeof(*pr));

    pr->handle = sch->handle;
    pr->where = sch->parent;
    snprintf(pr->kind, sizeof(pr->kind), "%s", sch->ops->name);

    if (sch->ops->dump && (err = sch->ops->dump(sch, &pr->qopt)) != EDPVS_OK)
        return err;

    /* send msg to workers for per-cpu stats */
    req = msg_make(MSG_TYPE_TC_STATS, 0, DPVS_MSG_MULTICAST,
                   rte_lcore_id(), sizeof(struct Qsch *), &sch);
    if (!req)
        return EDPVS_NOMEM;

    err = multicast_msg_send(req, 0, &replies);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, TC, "%s: send msg: %s\n", __func__, dpvs_strerror(err));
        msg_destroy(&req);
        return err;
    }

    /* handle replies */
    list_for_each_entry(reply, &replies->mq, mq_node) {
        st = (struct tc_qsch_stats *)reply->data;
        assert(st && reply->cid < DPVS_MAX_LCORE);

        pr->qstats_cpus[reply->cid] = st->qstats;
        pr->bstats_cpus[reply->cid] = st->bstats;

        pr->qstats.qlen         += st->qstats.qlen;
        pr->qstats.backlog      += st->qstats.backlog;
        pr->qstats.drops        += st->qstats.drops;
        pr->qstats.requeues     += st->qstats.requeues;
        pr->qstats.overlimits   += st->qstats.overlimits;

        pr->bstats.bytes        += st->bstats.bytes;
        pr->bstats.packets      += st->bstats.packets;
    }

    msg_destroy(&req);
    return EDPVS_OK;
}

static int fill_cls_param(struct tc_cls *cls, struct tc_cls_param *pr)
{
    int err;

    memset(pr, 0, sizeof(*pr));

    pr->handle = cls->handle;
    pr->sch_id = cls->sch->handle;
    snprintf(pr->kind, sizeof(pr->kind), "%s", cls->ops->name);
    pr->pkt_type = cls->pkt_type;
    pr->priority = cls->prio;

    if (cls->ops->dump && (err = cls->ops->dump(cls, &pr->copt)) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

/* with tc->lock */
static int __tc_so_qsch_set(struct netif_tc *tc, tc_oper_t oper,
                            const struct tc_qsch_param *qpar)
{
    struct Qsch *sch = NULL;
    tc_handle_t where;
    int err;

    if (oper == SOCKOPT_TC_DEL ||
        oper == SOCKOPT_TC_CHANGE ||
        oper == SOCKOPT_TC_REPLACE) {
        sch = qsch_lookup_noref(tc, qpar->handle);
        if (!sch)
            return EDPVS_NOTEXIST;

        /* egress root is readonly */
        if (sch == tc->qsch)
            return EDPVS_NOTSUPP;
    }

    switch (oper) {
    case SOCKOPT_TC_ADD:
        qsch_create(tc->dev, qpar->kind, qpar->where, qpar->handle,
                    &qpar->qopt, &err);
        return err;
    case SOCKOPT_TC_DEL:
        qsch_destroy(sch);
        return EDPVS_OK;

    case SOCKOPT_TC_CHANGE:
        return qsch_change(sch, &qpar->qopt);

    case SOCKOPT_TC_REPLACE:
        /* keep parent unchanged if not indicated */
        if (qpar->where == TC_H_UNSPEC)
            where = sch->parent;
        else
            where = qpar->where;

        qsch_destroy(sch);
        qsch_create(tc->dev, qpar->kind, where, qpar->handle,
                    &qpar->qopt, &err);
        return err;

    default:
        return EDPVS_NOTSUPP;
    }
}

/* with tc->lock */
static int __tc_so_qsch_get(struct netif_tc *tc, tc_oper_t oper,
                            const struct tc_qsch_param *qpar,
                            union tc_param **arr, int *narr)
{
    int nparam, off, h, err;
    union tc_param *params = NULL;
    struct Qsch *sch = NULL;

    if (oper != SOCKOPT_TC_SHOW)
        return EDPVS_INVAL;

    if (qpar->handle != TC_H_UNSPEC) {
        sch = qsch_lookup_noref(tc, qpar->handle);
        if (!sch)
            return EDPVS_NOTEXIST;

        nparam = 1;
        params = rte_malloc(NULL, sizeof(*params), 0);
        if (!params)
            return EDPVS_NOMEM;

        err = fill_qsch_param(sch, &params[0].qsch);
        if (err != EDPVS_OK)
            goto errout;
    } else { /* get all Qsch */
        nparam = tc->qsch_cnt;

        params = rte_zmalloc(NULL, nparam * sizeof(*params), 0);
        if (!params) {
            err = EDPVS_NOMEM;
            goto errout;
        }

        off = 0;
        if (tc->qsch) {
            err = fill_qsch_param(tc->qsch, &params[off++].qsch);
            if (err != EDPVS_OK)
                goto errout;
        }

        if (tc->qsch_ingress) {
            err = fill_qsch_param(tc->qsch_ingress, &params[off++].qsch);
            if (err != EDPVS_OK)
                goto errout;
        }

        for (h = 0; h < tc->qsch_hash_size; h++) {
            hlist_for_each_entry(sch, &tc->qsch_hash[h], hlist) {
                if (sch->flags & QSCH_F_INVISIBLE) {
                    nparam--;
                    continue;
                }

                err = fill_qsch_param(sch, &params[off++].qsch);
                if (err != EDPVS_OK)
                    goto errout;
            }
        }
        assert(off == nparam);
    }

    *arr = params;
    *narr = nparam;

    return EDPVS_OK;

errout:
    if (params)
        rte_free(params);
    return err;
}

/* with tc->lock */
static int __tc_so_cls_set(struct netif_tc *tc, tc_oper_t oper,
                           const struct tc_cls_param *cpar)
{
    struct Qsch *sch;
    struct tc_cls *cls = NULL;
    int err;

    sch = qsch_lookup_noref(tc, cpar->sch_id);
    if (!sch)
        return EDPVS_NOTEXIST;

    if (oper == SOCKOPT_TC_DEL ||
        oper == SOCKOPT_TC_CHANGE ||
        oper == SOCKOPT_TC_REPLACE) {
        cls = tc_cls_lookup(sch, cpar->handle);
        if (!cls)
            return EDPVS_NOTEXIST;
    }

    switch (oper) {
    case SOCKOPT_TC_ADD:
        tc_cls_create(sch, cpar->kind, cpar->handle, cpar->pkt_type,
                      cpar->priority, &cpar->copt, &err);
        return err;

    case SOCKOPT_TC_DEL:
        tc_cls_destroy(cls);
        return EDPVS_OK;

    case SOCKOPT_TC_CHANGE:
        return tc_cls_change(cls, &cpar->copt);

    case SOCKOPT_TC_REPLACE:
        tc_cls_destroy(cls);
        tc_cls_create(sch, cpar->kind, cpar->handle, cpar->pkt_type,
                      cpar->priority, &cpar->copt, &err);
        return err;

    default:
        return EDPVS_NOTSUPP;
    }
}

/* with tc->lock */
static int __tc_so_cls_get(struct netif_tc *tc, tc_oper_t oper,
                           const struct tc_cls_param *cpar,
                           union tc_param **arr, int *narr)
{
    struct Qsch *sch;
    struct tc_cls *cls;
    int err, nparam, off;
    union tc_param *params;

    if (oper != SOCKOPT_TC_SHOW)
        return EDPVS_INVAL;

    sch = qsch_lookup_noref(tc, cpar->sch_id);
    if (!sch)
        return EDPVS_NOTEXIST;

    if (cpar->handle != TC_H_UNSPEC) {
        cls = tc_cls_lookup(sch, cpar->handle);
        if (!cls)
            return EDPVS_NOTEXIST;

        nparam = 1;
        params = rte_malloc(NULL, sizeof(*params), 0);
        if (!params)
            return EDPVS_NOMEM;

        err = fill_cls_param(cls, &params[0].cls);
        if (err != EDPVS_OK)
            goto errout;
    } else {
        nparam = sch->cls_cnt;

        params = rte_malloc(NULL, nparam * sizeof(*params), 0);
        if (!params) {
            err = EDPVS_NOMEM;
            goto errout;
        }

        off = 0;
        list_for_each_entry(cls, &sch->cls_list, list) {
            err = fill_cls_param(cls, &params[off++].cls);
            if (err != EDPVS_OK)
                goto errout;
        }
    }

    *arr = params;
    *narr = nparam;

    return EDPVS_OK;

errout:
    if (params)
        rte_free(params);
    return err;
}

static int tc_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct tc_conf *cf = conf;
    int err = EDPVS_INVAL;
    struct netif_tc *tc;
    struct netif_port *dev;

    if (!conf || size < sizeof(*cf))
        return EDPVS_INVAL;

    dev = netif_port_get_by_name(cf->ifname);
    if (!dev)
        return EDPVS_NODEV;
    tc = netif_tc(dev);

    rte_rwlock_write_lock(&tc->lock);
    switch (cf->obj) {
    case TC_OBJ_QSCH:
        err = __tc_so_qsch_set(tc, opt, &cf->param.qsch);
        break;
    case TC_OBJ_CLS:
        err = __tc_so_cls_set(tc, opt, &cf->param.cls);
        break;
    default:
        err = EDPVS_NOTSUPP;
        break;
    }
    rte_rwlock_write_unlock(&tc->lock);
    return err;
}

static int tc_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                          void **out, size_t *outsize)
{
    const struct tc_conf *cf = conf;
    struct netif_tc *tc;
    struct netif_port *dev;
    union tc_param *param_arr = NULL;
    int nparam = 0, err;

    if (!conf || size < sizeof(*cf) || !out || !outsize)
        return EDPVS_INVAL;

    dev = netif_port_get_by_name(cf->ifname);
    if (!dev)
        return EDPVS_NODEV;
    tc = netif_tc(dev);

    rte_rwlock_read_lock(&tc->lock);
    switch (cf->obj) {
        case TC_OBJ_QSCH:
            err = __tc_so_qsch_get(tc, opt, &cf->param.qsch,
                                   &param_arr, &nparam);
            break;
        case TC_OBJ_CLS:
            err = __tc_so_cls_get(tc, opt, &cf->param.cls,
                                  &param_arr, &nparam);
            break;
        default:
            err = EDPVS_NOTSUPP;
            break;
    }

    if (err == EDPVS_OK) {
        *out = param_arr;
        *outsize = nparam * sizeof(union tc_param);
    }

    rte_rwlock_read_unlock(&tc->lock);
    return err;
}

static struct dpvs_sockopts tc_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_TC_ADD,
    .set_opt_max    = SOCKOPT_TC_REPLACE,
    .set            = tc_sockopt_set,
    .get_opt_min    = SOCKOPT_TC_SHOW,
    .get_opt_max    = SOCKOPT_TC_SHOW,
    .get            = tc_sockopt_get,
};

static int tc_msg_get_stats(struct dpvs_msg *msg)
{
    void *ptr;
    struct Qsch *qsch;
    struct tc_qsch_stats *st;

    assert(msg && msg->len == sizeof(struct Qsch *));

    ptr = msg->data;
    qsch = *(struct Qsch **)ptr;

    st = msg_reply_alloc(sizeof(*st));
    if (!st)
        return EDPVS_NOMEM;

    st->qstats = qsch->this_qstats;
    st->bstats = qsch->this_bstats;

    msg->reply.len = sizeof(*st);
    msg->reply.data = st;

    return EDPVS_OK;
}

static struct dpvs_msg_type tc_stats_msg = {
    .type           = MSG_TYPE_TC_STATS,
    .prio           = MSG_PRIO_LOW,
    .unicast_msg_cb = tc_msg_get_stats,
};

int tc_ctrl_init(void)
{
    int err;

    err = sockopt_register(&tc_sockopts);
    if (err != EDPVS_OK)
        return err;

    err = msg_type_mc_register(&tc_stats_msg);
    if (err != EDPVS_OK) {
        sockopt_unregister(&tc_sockopts);
        return err;
    }

    return EDPVS_OK;
}
