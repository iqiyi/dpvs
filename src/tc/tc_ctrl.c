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

struct tc_msg_param {
    struct netif_port *dev;
    sockoptid_t operator;
    union tc_param param;
} __attribute__((__packed__));

static uint32_t tc_msg_seq(void)
{
    static uint32_t counter = 0;
    return counter++;
}

static int fill_qsch_param(struct Qsch *sch, struct tc_qsch_param *pr)
{
    int err;

    memset(pr, 0, sizeof(*pr));

    pr->cid    = rte_lcore_id();
    pr->handle = sch->handle;
    pr->where  = sch->parent;
    snprintf(pr->kind, sizeof(pr->kind), "%s", sch->ops->name);

    if (sch->ops->dump && (err = sch->ops->dump(sch, &pr->qopt)) != EDPVS_OK)
        return err;

    pr->cls_cnt = sch->cls_cnt;
    pr->flags   = sch->flags;
    pr->qstats  = sch->qstats;
    pr->bstats  = sch->bstats;

    return EDPVS_OK;
}

static int fill_cls_param(struct tc_cls *cls, struct tc_cls_param *pr)
{
    int err;

    memset(pr, 0, sizeof(*pr));

    pr->cid    = rte_lcore_id();
    pr->sch_id = cls->sch->handle;
    pr->handle = cls->handle;
    snprintf(pr->kind, sizeof(pr->kind), "%s", cls->ops->name);
    pr->pkt_type = cls->pkt_type;
    pr->priority = cls->prio;

    if (cls->ops->dump && (err = cls->ops->dump(cls, &pr->copt)) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}

static int tc_local_qsch_set(struct netif_port *dev, sockoptid_t oper,
                            const struct tc_qsch_param *qpar)
{
    struct netif_tc *tc;
    struct Qsch *sch = NULL;
    tc_handle_t where;
    int err;

    if (!netif_port_get(dev->id))
        return EDPVS_NODEV;
    tc = netif_tc(dev);

    if (oper == SOCKOPT_TC_DEL ||
        oper == SOCKOPT_TC_CHANGE ||
        oper == SOCKOPT_TC_REPLACE) {
        sch = qsch_lookup_noref(tc, qpar->handle);
        if (!sch)
            return EDPVS_NOTEXIST;
    }

    switch (oper) {
    case SOCKOPT_TC_ADD:
        assert(qpar->handle != 0);
        qsch_create(tc->dev, qpar->kind, qpar->where,
                    qpar->handle, &qpar->qopt, &err);
        return err;

    case SOCKOPT_TC_DEL:
        qsch_destroy(sch);
        return EDPVS_OK;

    case SOCKOPT_TC_CHANGE:
        return qsch_change(sch, &qpar->qopt);

    case SOCKOPT_TC_REPLACE:
        assert(qpar->handle != 0);
        /* keep parent unchanged if not indicated */
        if (qpar->where == TC_H_UNSPEC)
            where = sch->parent;
        else
            where = qpar->where;
        qsch_destroy(sch);
        qsch_create(tc->dev, qpar->kind, where,
                    qpar->handle, &qpar->qopt, &err);
        return err;

    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int tc_local_qsch_get(struct netif_port *dev, sockoptid_t oper,
                            const struct tc_qsch_param *qpar,
                            union tc_param **arr, uint32_t *narr)
{
    struct netif_tc *tc;
    struct Qsch *sch = NULL;
    union tc_param *params = NULL;
    int nparam, off, h, err;

    if (oper != SOCKOPT_TC_SHOW)
        return EDPVS_INVAL;

    if (!netif_port_get(dev->id))
        return EDPVS_NODEV;
    tc = netif_tc(dev);

    if (qpar->handle != TC_H_UNSPEC) {
        sch = qsch_lookup_noref(tc, qpar->handle);
        if (!sch)
            return EDPVS_NOTEXIST;

        nparam = 1;
        params = msg_reply_alloc(nparam * sizeof(*params)); /* msg may like it */
        if (!params)
            return EDPVS_NOMEM;

        err = fill_qsch_param(sch, &params[0].qsch);
        if (err != EDPVS_OK)
            goto errout;
    } else { /* get all Qsch */
        nparam = tc->qsch_cnt;
        if (!nparam) {
            err = EDPVS_OK;
            goto errout;
        }

        params = msg_reply_alloc(nparam * sizeof(*params)); /* msg may like it */
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
        msg_reply_free(params);
    *arr = NULL;
    *narr = 0;
    return err;
}

static int tc_local_cls_set(struct netif_port *dev, sockoptid_t oper,
                           const struct tc_cls_param *cpar)
{
    struct netif_tc *tc;
    struct Qsch *sch;
    struct tc_cls *cls = NULL;
    int err;

    if (!netif_port_get(dev->id))
        return EDPVS_NODEV;
    tc = netif_tc(dev);

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
        assert(cpar->handle != 0);
        tc_cls_create(sch, cpar->kind, cpar->handle, cpar->pkt_type,
                      cpar->priority, &cpar->copt, &err);
        return err;

    case SOCKOPT_TC_DEL:
        tc_cls_destroy(cls);
        return EDPVS_OK;

    case SOCKOPT_TC_CHANGE:
        return tc_cls_change(cls, &cpar->copt);

    case SOCKOPT_TC_REPLACE:
        assert(cpar->handle != 0);
        tc_cls_destroy(cls);
        tc_cls_create(sch, cpar->kind, cpar->handle, cpar->pkt_type,
                      cpar->priority, &cpar->copt, &err);
        return err;

    default:
        return EDPVS_NOTSUPP;
    }

    return EDPVS_OK;
}

static int tc_local_cls_get(struct netif_port *dev, sockoptid_t oper,
                           const struct tc_cls_param *cpar,
                           union tc_param **arr, uint32_t *narr)
{
    struct netif_tc *tc;
    struct Qsch *sch;
    struct tc_cls *cls;
    int err, nparam, off;
    union tc_param *params = NULL;

    if (oper != SOCKOPT_TC_SHOW)
        return EDPVS_INVAL;

    if (!netif_port_get(dev->id))
        return EDPVS_NODEV;
    tc = netif_tc(dev);

    sch = qsch_lookup_noref(tc, cpar->sch_id);
    if (!sch)
        return EDPVS_NOTEXIST;

    if (cpar->handle != TC_H_UNSPEC) {
        cls = tc_cls_lookup(sch, cpar->handle);
        if (!cls)
            return EDPVS_NOTEXIST;

        nparam = 1;
        params = msg_reply_alloc(nparam * sizeof(*params)); /* msg may like it */
        if (!params)
            return EDPVS_NOMEM;

        err = fill_cls_param(cls, &params[0].cls);
        if (err != EDPVS_OK)
            goto errout;
    } else {
        nparam = sch->cls_cnt;
        if (!nparam) {
            err = EDPVS_OK;
            goto errout;
        }

        params = msg_reply_alloc(nparam * sizeof(*params)); /* msg may like it */
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
        msg_reply_free(params);
    *arr = NULL;
    *narr = 0;
    return err;
}

static int tc_qsch_set_cb(struct dpvs_msg *msg)
{
    struct tc_msg_param *mpar;

    if (msg->len != sizeof(struct tc_msg_param))
        return EDPVS_INVAL;
    mpar = (struct tc_msg_param *)msg->data;

    return tc_local_qsch_set(mpar->dev, mpar->operator, &mpar->param.qsch);
}

static int tc_qsch_get_cb(struct dpvs_msg *msg)
{
    int err;
    uint32_t narr;
    union tc_param *arr;
    struct tc_msg_param *mpar;

    if (msg->len != sizeof(struct tc_msg_param))
        return EDPVS_INVAL;
    mpar = (struct tc_msg_param *)msg->data;

    err = tc_local_qsch_get(mpar->dev, mpar->operator, &mpar->param.qsch, &arr, &narr);
    if (err != EDPVS_OK)
        return err;

    msg->reply.data = arr;
    msg->reply.len= narr * sizeof(*arr);
    return EDPVS_OK;
}

static int tc_cls_set_cb(struct dpvs_msg *msg)
{
    struct tc_msg_param *mpar;

    if (msg->len != sizeof(struct tc_msg_param))
        return EDPVS_INVAL;
    mpar = (struct tc_msg_param *)msg->data;

    return tc_local_cls_set(mpar->dev, mpar->operator, &mpar->param.cls);
}

static int tc_cls_get_cb(struct dpvs_msg *msg)
{
    int err;
    uint32_t narr;
    union tc_param *arr;
    struct tc_msg_param *mpar;

    if (msg->len != sizeof(struct tc_msg_param))
        return EDPVS_INVAL;
    mpar = (struct tc_msg_param *)msg->data;

    err = tc_local_cls_get(mpar->dev, mpar->operator, &mpar->param.cls, &arr, &narr);
    if (err != EDPVS_OK)
        return err;

    msg->reply.data = arr;
    msg->reply.len = narr * sizeof(*arr);
    return EDPVS_OK;
}

static int tc_so_qsch_set(struct netif_port *dev, sockoptid_t oper,
                         const struct tc_qsch_param *qpar)
{
    int err;
    struct dpvs_msg *msg;
    struct tc_msg_param mpar;
    struct tc_qsch_param param = *qpar;

    if (oper == SOCKOPT_TC_ADD || oper == SOCKOPT_TC_REPLACE) {
        if (!param.handle) {
            param.handle = sch_alloc_handle(netif_tc(dev));
            if (unlikely(!param.handle))
                return EDPVS_RESOURCE;
        }
    }

    /* set master lcore */
    err = tc_local_qsch_set(dev, oper, &param);
    if (err != EDPVS_OK)
        return err;

    /* set slave lcores */
    mpar.dev = dev;
    mpar.operator = oper;
    mpar.param.qsch = param;

    msg = msg_make(MSG_TYPE_TC_QSCH_SET, tc_msg_seq(), DPVS_MSG_MULTICAST,
                    rte_lcore_id(), sizeof(mpar), &mpar);
    if (unlikely(!msg))
        return EDPVS_NOMEM;

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }

    msg_destroy(&msg);
    return EDPVS_OK;
}

static int tc_so_qsch_get(struct netif_port *dev,
                            sockoptid_t oper, uint32_t flags,
                            const struct tc_qsch_param *qpar,
                            union tc_param **arr, uint32_t *narr)
{
    int err, i, off = 0;
    struct dpvs_msg *msg, *_msg;
    struct dpvs_multicast_queue *reply;
    struct tc_msg_param mpar;

    union tc_param *entries, *_arr;
    uint32_t nentry, _narr, nqsch;

    err = tc_local_qsch_get(dev, oper, qpar, &_arr, &_narr);
    if (err != EDPVS_OK || !_narr)
        return err;

    nqsch = nentry = _narr;
    if (flags & TC_F_OPS_VERBOSE)
        nentry += g_slave_lcore_num * _narr;
    entries = rte_zmalloc("tc_qsch_get", nentry * sizeof(*entries), RTE_CACHE_LINE_SIZE);
    if (unlikely(!entries)) {
        msg_reply_free(_arr);
        err = EDPVS_NOMEM;
        goto errout;
    }

    for (i = 0; i < _narr; i++)
        entries[off++] = _arr[i];
    msg_reply_free(_arr);

    if (flags & (TC_F_OPS_STATS|TC_F_OPS_VERBOSE)) {
        mpar.dev = dev;
        mpar.operator = oper;
        mpar.param.qsch = *qpar;

        msg = msg_make(MSG_TYPE_TC_QSCH_GET, tc_msg_seq(), DPVS_MSG_MULTICAST,
                        rte_lcore_id(), sizeof(mpar), &mpar);
        if (unlikely(!msg))
            goto errout;
        err = multicast_msg_send(msg, 0, &reply);
        if (err != EDPVS_OK) {
            msg_destroy(&msg);
            goto errout;
        }
        list_for_each_entry(_msg, &reply->mq, mq_node) {
            _arr = (union tc_param *)_msg->data;
            _narr = _msg->len/sizeof(*_arr);
            if (unlikely(_narr != nqsch)) {
                RTE_LOG(WARNING, TC, "%s: tc qsch number does not match -- master=%d, slave[%d]=%d\n",
                        __func__, nqsch, _msg->cid, _narr);
                msg_destroy(&msg);
                err = EDPVS_INVAL;
                goto errout;
            }
            for (i = 0; i < _narr; i++) {
                if (flags & TC_F_OPS_VERBOSE)
                    entries[off++] = _arr[i];
                if (flags & TC_F_OPS_STATS) {
                    entries[i].qsch.qstats.qlen       += _arr[i].qsch.qstats.qlen;
                    entries[i].qsch.qstats.backlog    += _arr[i].qsch.qstats.backlog;
                    entries[i].qsch.qstats.drops      += _arr[i].qsch.qstats.drops;
                    entries[i].qsch.qstats.requeues   += _arr[i].qsch.qstats.requeues;
                    entries[i].qsch.qstats.overlimits += _arr[i].qsch.qstats.overlimits;
                    entries[i].qsch.bstats.bytes      += _arr[i].qsch.bstats.bytes;
                    entries[i].qsch.bstats.packets    += _arr[i].qsch.bstats.packets;
                }
            }
        }
        msg_destroy(&msg);
    }

    assert(off <= nentry);
    *narr = nentry;
    *arr = entries;
    return EDPVS_OK;

errout:
    if (entries)
        rte_free(entries);
    *narr = 0;
    *arr = NULL;
    return err;
}

static int tc_so_cls_set(struct netif_port  *dev, sockoptid_t oper,
                        const struct tc_cls_param *cpar)
{
    int err;
    struct dpvs_msg *msg;
    struct tc_msg_param mpar;
    struct tc_cls_param param = *cpar;

    if (oper == SOCKOPT_TC_ADD || oper == SOCKOPT_TC_REPLACE) {
        if (!param.handle) {
            struct Qsch *sch = qsch_lookup_noref(netif_tc(dev), cpar->sch_id);
            if (!sch)
                return EDPVS_NOTEXIST;
            param.handle = cls_alloc_handle(sch);
            if (unlikely(!param.handle))
                return EDPVS_RESOURCE;
        }
    }

    /* set master lcores */
    err = tc_local_cls_set(dev, oper, &param);
    if (err != EDPVS_OK)
        return err;

    /* set slave lcore */
    mpar.dev = dev;
    mpar.operator = oper;
    mpar.param.cls = param;

    msg = msg_make(MSG_TYPE_TC_CLS_SET, tc_msg_seq(), DPVS_MSG_MULTICAST,
                    rte_lcore_id(), sizeof(mpar), &mpar);
    if (unlikely(!msg))
        return EDPVS_NOMEM;

    err = multicast_msg_send(msg, DPVS_MSG_F_ASYNC, NULL);
    if (err != EDPVS_OK) {
        msg_destroy(&msg);
        return err;
    }

    msg_destroy(&msg);
    return EDPVS_OK;
}

static int tc_so_cls_get(struct netif_port *dev,
                           sockoptid_t oper, uint32_t flags,
                           const struct tc_cls_param *cpar,
                           union tc_param **arr, uint32_t *narr)
{
    int err, i, off = 0;
    struct dpvs_msg *msg, *_msg;
    struct dpvs_multicast_queue *reply;
    struct tc_msg_param mpar;

    union tc_param *entries, *_arr;
    uint32_t nentry, _narr, ncls;

    err = tc_local_cls_get(dev, oper, cpar, &_arr, &_narr);
    if (err != EDPVS_OK || !_narr)
        return err;

    ncls = nentry = _narr;
    if (flags & TC_F_OPS_VERBOSE)
        nentry += g_slave_lcore_num * _narr;
    entries = rte_zmalloc("tc_cls_get", nentry * sizeof(*entries), RTE_CACHE_LINE_SIZE);
    if (unlikely(!entries)) {
        msg_reply_free(_arr);
        err = EDPVS_NOMEM;
        goto errout;
    }

    for (i = 0; i < _narr; i++)
        entries[off++] = _arr[i];
    msg_reply_free(_arr);

    if (flags & TC_F_OPS_VERBOSE) {
        mpar.dev = dev;
        mpar.operator = oper;
        mpar.param.cls = *cpar;

        msg = msg_make(MSG_TYPE_TC_CLS_GET, tc_msg_seq(), DPVS_MSG_MULTICAST,
                        rte_lcore_id(), sizeof(mpar), &mpar);
        if (unlikely(!msg))
            goto errout;
        err = multicast_msg_send(msg, 0, &reply);
        if (err != EDPVS_OK) {
            msg_destroy(&msg);
            goto errout;
        }
        list_for_each_entry(_msg, &reply->mq, mq_node) {
            _arr = (union tc_param *)_msg->data;
            _narr = _msg->len/sizeof(*_arr);
            if (unlikely(_narr != ncls)) {
                RTE_LOG(WARNING, TC, "%s: tc cls number does not match -- master=%d, slave[%d]=%d\n",
                        __func__, ncls, _msg->cid, _narr);
                msg_destroy(&msg);
                err = EDPVS_INVAL;
                goto errout;
            }
            for (i = 0; i < _narr; i++) {
                entries[off++] = _arr[i];
            }
        }
        msg_destroy(&msg);
    }

    assert(off <= nentry);
    *narr = nentry;
    *arr = entries;
    return EDPVS_OK;

errout:
    if (entries)
        rte_free(entries);
    *narr = 0;
    *arr = NULL;
    return err;
}

static int tc_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    const struct tc_conf *cf = conf;
    int err = EDPVS_INVAL;
    struct netif_port *dev;

    if (!conf || size < sizeof(*cf))
        return EDPVS_INVAL;

    dev = netif_port_get_by_name(cf->ifname);
    if (!dev)
        return EDPVS_NODEV;

    switch (cf->obj) {
    case TC_OBJ_QSCH:
        err = tc_so_qsch_set(dev, opt, &cf->param.qsch);
        break;
    case TC_OBJ_CLS:
        err = tc_so_cls_set(dev, opt, &cf->param.cls);
        break;
    default:
        err = EDPVS_NOTSUPP;
        break;
    }
    return err;
}

static int tc_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                          void **out, size_t *outsize)
{
    const struct tc_conf *cf = conf;
    struct netif_port *dev;
    union tc_param *param_arr = NULL;
    uint32_t nparam = 0;
    int err;

    if (!conf || size < sizeof(*cf) || !out || !outsize)
        return EDPVS_INVAL;

    dev = netif_port_get_by_name(cf->ifname);
    if (!dev)
        return EDPVS_NODEV;

    switch (cf->obj) {
        case TC_OBJ_QSCH:
            err = tc_so_qsch_get(dev, opt, cf->op_flags, &cf->param.qsch,
                                   &param_arr, &nparam);
            break;
        case TC_OBJ_CLS:
            err = tc_so_cls_get(dev, opt, cf->op_flags, &cf->param.cls,
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

static struct dpvs_msg_type tc_msg_types[] = {
    {
        .type           = MSG_TYPE_TC_QSCH_GET,
        .prio           = MSG_PRIO_LOW,
        .mode           = DPVS_MSG_MULTICAST,
        .unicast_msg_cb = tc_qsch_get_cb,
    },
    {
        .type           = MSG_TYPE_TC_QSCH_SET,
        .prio           = MSG_PRIO_NORM,
        .mode           = DPVS_MSG_MULTICAST,
        .unicast_msg_cb = tc_qsch_set_cb,
    },
    {
        .type           = MSG_TYPE_TC_CLS_GET,
        .prio           = MSG_PRIO_LOW,
        .mode           = DPVS_MSG_MULTICAST,
        .unicast_msg_cb = tc_cls_get_cb,
    },
    {
        .type           = MSG_TYPE_TC_CLS_SET,
        .prio           = MSG_PRIO_LOW,
        .mode           = DPVS_MSG_MULTICAST,
        .unicast_msg_cb = tc_cls_set_cb,
    },
};

int tc_ctrl_init(void)
{
    int i, err;

    err = sockopt_register(&tc_sockopts);
    if (err != EDPVS_OK)
        return err;

    for (i = 0; i < NELEMS(tc_msg_types); i++) {
        err = msg_type_mc_register(&tc_msg_types[i]);
        if (err != EDPVS_OK)
            break;
    }
    if (err != EDPVS_OK) {
        for (--i; i >=0; i--)
            msg_type_mc_unregister(&tc_msg_types[i]);
        sockopt_unregister(&tc_sockopts);
        return err;
    }

    return EDPVS_OK;
}

int tc_ctrl_term(void)
{
    int i, err;

    for (i = 0; i < NELEMS(tc_msg_types); i++) {
        err = msg_type_mc_unregister(&tc_msg_types[i]);
        if (err != EDPVS_OK)
            RTE_LOG(ERR, TC, "%s: fail to unregister tc_msg_types[%d]\n", __func__, i);
    }

    err = sockopt_unregister(&tc_sockopts);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, TC, "%s: fail to unregister tc_sockopts\n", __func__);
        return err;
    }

    return EDPVS_OK;
}
