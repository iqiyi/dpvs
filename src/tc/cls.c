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
 * classifier for traffic control module.
 *
 * Lei Chen <raychen@qiyi.com>, Aug. 2017, initial.
 */
#include <assert.h>
#include <linux/if_ether.h>
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"

/* for master lcore only */
tc_handle_t cls_alloc_handle(struct Qsch *sch)
{
    int i = 0x8000;
    static uint32_t autohandle = TC_H_MAKE(0x80000000U, 0);

    do {
        autohandle += TC_H_MAKE(0x10000U, 0);
        if (autohandle == TC_H_MAKE(TC_H_ROOT, 0))
            autohandle = TC_H_MAKE(0x80000000U, 0);
        if (!tc_cls_lookup(sch, autohandle))
            return autohandle;
    } while (--i > 0);

    return 0;
}

static struct tc_cls *cls_alloc(struct Qsch *sch, struct tc_cls_ops *ops)
{
    struct tc_cls *cls;
    unsigned int size = TC_ALIGN(sizeof(*cls)) + ops->priv_size;

    cls = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);
    if (!cls)
        return NULL;

    INIT_LIST_HEAD(&cls->list);
    cls->sch = sch;
    cls->ops = ops;
    cls->pkt_type = ETH_P_ALL; /* default */
    cls->prio = 0;

    return cls;
}

static void cls_free(struct tc_cls *cls)
{
    rte_free(cls);
}

struct tc_cls *tc_cls_create(struct Qsch *sch, const char *kind,
                             tc_handle_t handle, __be16 pkt_type,
                             int prio, const void *arg, int *errp)
{
    struct tc_cls_ops *ops = NULL;
    struct tc_cls *cls = NULL;
    int err = EDPVS_INVAL;

    assert(sch && kind && errp);

    /* handle must be set */
    if (unlikely(!handle)) {
        err = EDPVS_INVAL;
        goto errout;
    }

    ops = tc_cls_ops_lookup(kind);
    if (!ops) {
        err = EDPVS_NOTSUPP;
        goto errout;
    }

    if (tc_cls_lookup(sch, handle)) {
        err = EDPVS_EXIST;
        goto errout;
    }

    cls = cls_alloc(sch, ops);
    if (!cls) {
        err = EDPVS_NOMEM;
        goto errout;
    }

    cls->handle = handle;
    cls->prio = prio;
    if (pkt_type)
        cls->pkt_type = pkt_type;

    if (ops->init && (err = ops->init(cls, arg)) != EDPVS_OK) {
        if (ops->destroy)
            ops->destroy(cls);
        goto errout;
    }

    /* insert according to priority */
    if (list_empty(&sch->cls_list)) {
        list_add(&cls->list, &sch->cls_list);
    } else {
        struct tc_cls *pos;

        list_for_each_entry(pos, &sch->cls_list, list) {
            if (pos->prio < prio)
                break;
        }

        list_add(&cls->list, pos->list.prev);
    }

    sch->cls_cnt++;
    *errp = EDPVS_OK;
    return cls;

errout:
    if (cls)
        cls_free(cls);
    *errp = err;
    return NULL;
}

void tc_cls_destroy(struct tc_cls *cls)
{
    struct tc_cls_ops *ops = cls->ops;
    struct Qsch *sch = cls->sch;

    list_del(&cls->list);
    sch->cls_cnt--;

    if (ops->destroy)
        ops->destroy(cls);

    cls_free(cls);
}

int tc_cls_change(struct tc_cls *cls, const void *arg)
{
    if (!cls->ops->change)
        return EDPVS_NOTSUPP;

    return cls->ops->change(cls, arg);
}

struct tc_cls *tc_cls_lookup(struct Qsch *sch, tc_handle_t handle)
{
    struct tc_cls *cls;

    list_for_each_entry(cls, &sch->cls_list, list) {
        if (cls->handle == handle)
            return cls;
    }

    return NULL;
}
