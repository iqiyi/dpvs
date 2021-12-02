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

/*
 * "ipset" classifier for traffic control module.
 */

#include "conf/tc.h"
#include "tc/cls.h"
#include "ipset/ipset.h"

struct ipset_cls_priv {
    struct tc_cls           *cls;
    struct ipset            *set;
    bool                    dst_match;

    struct tc_cls_result    result;
};

static inline int pkttype2family(uint16_t pkt_type)
{
    switch (pkt_type) {
        case ETH_P_IP:
            return AF_INET;
        case ETH_P_IPV6:
            return AF_INET6;
    }
    return AF_UNSPEC;
}

static int cls_ipset_classify(struct tc_cls *cls,
        struct rte_mbuf *mbuf, struct tc_cls_result *result)
{
    struct ipset_cls_priv *priv = tc_cls_priv(cls);

    if (pkttype2family(ntohs(cls->pkt_type)) != priv->set->family)
        return TC_ACT_RECLASSIFY;

    if (elem_in_set(priv->set, mbuf, priv->dst_match)) {
        // matched
        *result = priv->result;
        return TC_ACT_OK;
    }

    // missed
    return TC_ACT_RECLASSIFY;
}

static int cls_ipset_init(struct tc_cls *cls, const void *arg)
{
    struct ipset_cls_priv *priv = tc_cls_priv(cls);
    const struct tc_cls_ipset_copt *copt = arg;

    if (!arg)
        return EDPVS_INVAL;

    priv->cls = cls;
    priv->dst_match = copt->dst_match;
    priv->set = ipset_get(copt->setname);
    if (unlikely(!priv->set))
        return EDPVS_NOTEXIST;

    if (copt->result.drop) {
        priv->result.drop = copt->result.drop;
    } else {
        /* 0: (TC_H_UNSPEC) is not valid target */
        if (copt->result.sch_id != TC_H_UNSPEC) {
            priv->result.sch_id = copt->result.sch_id;
            priv->result.drop = false; /* exclusive with sch_id */
        }
    }

    return EDPVS_OK;
}

static void cls_ipset_destroy(struct tc_cls *cls)
{
    struct ipset_cls_priv *priv = tc_cls_priv(cls);

    if (likely(priv->set != NULL))
        ipset_put(priv->set);
}

static int cls_ipset_dump(struct tc_cls *cls, void *arg)
{
    struct ipset_cls_priv *priv = tc_cls_priv(cls);
    struct tc_cls_ipset_copt *copt = arg;

    strncpy(copt->setname, priv->set->name, sizeof(copt->setname));
    copt->dst_match = priv->dst_match;
    copt->result = priv->result;

    return EDPVS_OK;
}

struct tc_cls_ops ipset_cls_ops = {
    .name       = "ipset",
    .priv_size  = sizeof(struct ipset_cls_priv),
    .classify   = cls_ipset_classify,
    .init       = cls_ipset_init,
    .change     = cls_ipset_init,
    .destroy    = cls_ipset_destroy,
    .dump       = cls_ipset_dump,
};
