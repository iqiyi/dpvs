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
#ifndef __DPVS_TC_CLS_H__
#define __DPVS_TC_CLS_H__
#include "conf/common.h"
#include "conf/match.h"
#include "conf/ipset.h"
#ifdef __DPVS__
#include "dpdk.h"
#endif /* __DPVS__ */

struct tc_cls_result {
    bool                    drop;
    tc_handle_t             sch_id;
};

struct tc_cls_match_copt {
    uint8_t                 proto;      /* IPPROTO_XXX */
    struct dp_vs_match      match;
    struct tc_cls_result    result;
} __attribute__((__packed__));

struct tc_cls_ipset_copt {
    char                    setname[IPSET_MAXNAMELEN];
    bool                    dst_match;
    struct tc_cls_result    result;
} __attribute__((__packed__));

#ifdef __DPVS__

struct tc_cls;

struct tc_cls_ops {
    char                    name[TCNAMESIZ];
    uint32_t                priv_size;

    int                     (*classify)(struct tc_cls *cls,
                                        struct rte_mbuf *mbuf,
                                        struct tc_cls_result *result);

    int                     (*init)(struct tc_cls *cls, const void *arg);
    void                    (*destroy)(struct tc_cls *cls);
    int                     (*change)(struct tc_cls *cls, const void *arg);
    int                     (*dump)(struct tc_cls *cls, void *arg);

    struct list_head        list;
};

/* classifier */
struct tc_cls {
    tc_handle_t             handle;
    struct list_head        list;
    struct Qsch             *sch;

    struct tc_cls_ops       *ops;
    __be16                  pkt_type;   /* ETH_P_XXX */
    int                     prio;       /* priority */
};

static inline void *tc_cls_priv(struct tc_cls *cls)
{
    return (char *)cls + TC_ALIGN(sizeof(struct tc_cls));
}

struct tc_cls *tc_cls_create(struct Qsch *sch, const char *kind,
                             tc_handle_t handle, __be16 pkt_type,
                             int prio, const void *arg, int *errp);

void tc_cls_destroy(struct tc_cls *cls);

int tc_cls_change(struct tc_cls *cls, const void *arg);

struct tc_cls *tc_cls_lookup(struct Qsch *sch, tc_handle_t handle);

tc_handle_t cls_alloc_handle(struct Qsch *sch);

#endif /* __DPVS__ */

#endif /* __DPVS_TC_CLS_H__ */
