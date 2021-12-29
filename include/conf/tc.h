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
 * traffic control config.
 * see iproute2 tc modules.
 *
 * raychen@qiyi.com, Aug. 2017, initial.
 */
#ifndef __DPVS_TC_CONF_H__
#define __DPVS_TC_CONF_H__

#include <linux/pkt_sched.h>
#include "conf/sockopts.h"
#include "tc/tc.h"
#include "tc/sch.h"
#include "tc/cls.h"

#define TC_F_OPS_STATS    0x0001
#define TC_F_OPS_VERBOSE  0x0002

typedef enum {
    TC_OBJ_QSCH,
    TC_OBJ_CLS,
} tc_obj_t;

/**
 * scheduler section
 */
struct tc_qsch_param {
    lcoreid_t       cid;
    tc_handle_t     handle;
    tc_handle_t     where;              /* TC_H_ROOT | TC_H_INGRESS | parent */
    char            kind[TCNAMESIZ];    /* qsch type: bfifo, tbf, ... */

    union {
        struct tc_tbf_qopt tbf;
        struct tc_fifo_qopt fifo;
        struct tc_prio_qopt prio;       /* pfifo_fast ... */
    } qopt;

    /* get only */
    int cls_cnt;
    uint32_t flags;
    struct qsch_qstats qstats;
    struct qsch_bstats bstats;

} __attribute__((__packed__));

/**
 * classifier section
 */
struct tc_cls_param {
    lcoreid_t       cid;
    tc_handle_t     sch_id;             /* ID of Qsch attached to */
    tc_handle_t     handle;             /* or class-id */
    char            kind[TCNAMESIZ];    /* tc_cls type: "match", ... */
    __be16          pkt_type;           /* ETH_P_XXX */
    int             priority;

    union {
        struct tc_cls_match_copt match;
        struct tc_cls_ipset_copt set;
    } copt;
} __attribute__((__packed__));

/**
 * general section
 */
union tc_param {
    struct tc_qsch_param qsch;
    struct tc_cls_param cls;
} __attribute__((__packed__));

struct tc_conf {
    tc_obj_t        obj;                /* schedler, classifier, ... */
    uint32_t        op_flags;           /* TC_F_OPS_XXX */
    char            ifname[IFNAMSIZ];
    union tc_param  param;              /* object specific parameters */
} __attribute__((__packed__));

static inline tc_handle_t tc_handle_atoi(const char *handle)
{
    uint32_t maj, min;

    if (sscanf(handle, "%x:%x", &maj, &min) == 2)
        return (maj << 16) | min;

    if (sscanf(handle, "%x:", &maj) == 1)
        return (maj << 16);

    if (!strncmp(handle, "root", 4))
        return TC_H_ROOT;

    if (!strncmp(handle, "ingress", 7))
        return TC_H_INGRESS;

    return TC_H_UNSPEC;
}

static inline char *tc_handle_itoa(tc_handle_t handle, char *buf, size_t size)
{
    switch (handle) {
    case TC_H_ROOT:
        snprintf(buf, size, "%s", "root");
        break;
    case TC_H_INGRESS:
        snprintf(buf, size, "%s", "ingress");
        break;
    default:
        if (TC_H_MIN(handle))
            snprintf(buf, size, "%x:%x",
                     TC_H_MAJ(handle) >> 16, TC_H_MIN(handle));
        else
            snprintf(buf, size, "%x:", TC_H_MAJ(handle) >> 16);
        break;
    }

    return buf;
}

#endif /* __DPVS_TC_CONF_H__ */
