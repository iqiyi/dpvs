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
/**
 * IPv6 protocol for "lite stack".
 * Linux Kernel net/ipv6/exthdrs.c is referred.
 *
 * Lei Chen <raychen@qiyi.com>, initial, Jul 2018.
 */
#include <netinet/ip6.h>
#include "ipv6.h"

/*
 * it's a dummy ext-header handler to parse next header
 * and ext-hdr-length only.
 */
static int ip6_dummy_hdr_rcv(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *hdr = mbuf->userdata;
    struct ip6_ext *exthdr;

    if (mbuf_may_pull(mbuf, 8) != 0)
        goto drop;

    exthdr = rte_pktmbuf_mtod(mbuf, struct ip6_ext *);

    if (mbuf_may_pull(mbuf, 8 + (exthdr->ip6e_len<<3)) != 0)
        goto drop;

    if (ipv6_addr_is_multicast(&hdr->ip6_dst) ||
        mbuf->packet_type != ETH_PKT_HOST)
        goto drop;

    /* handle nothing */

    /* set current ext-header length and return next header.
     * note l3_len record current header length only. */
    mbuf->l3_len = 8 + (exthdr->ip6e_len<<3);
    return exthdr->ip6e_nxt;

drop:
    rte_pktmbuf_free(mbuf);
    return -1;
}

static int ip6_rthdr_rcv(struct rte_mbuf *mbuf)
{
    /* TODO: handle route header */
    return ip6_dummy_hdr_rcv(mbuf);
}

static int ip6_destopt_rcv(struct rte_mbuf *mbuf)
{
    /* TODO: handle dest option header */
    return ip6_dummy_hdr_rcv(mbuf);
}

static int ip6_nodata_rcv(struct rte_mbuf *mbuf)
{
    /* no payload ? just consume it. */
    rte_pktmbuf_free(mbuf);
    return 0;
}

static struct inet6_protocol rthdr_proto = {
    .handler    = ip6_rthdr_rcv,
};

static struct inet6_protocol destopt_proto = {
    .handler    = ip6_destopt_rcv,
};

static struct inet6_protocol nodata_proto = {
    .handler    = ip6_nodata_rcv,
};

int ipv6_exthdrs_init(void)
{
    int err;

    err = ipv6_register_protocol(&rthdr_proto, IPPROTO_ROUTING);
    if (err)
        goto out;

    err = ipv6_register_protocol(&destopt_proto, IPPROTO_DSTOPTS);
    if (err)
        goto dstopt_fail;

    err = ipv6_register_protocol(&nodata_proto, IPPROTO_NONE);
    if (err)
        goto nodata_fail;

    return EDPVS_OK;

nodata_fail:
    ipv6_unregister_protocol(&destopt_proto, IPPROTO_DSTOPTS);
dstopt_fail:
    ipv6_unregister_protocol(&rthdr_proto, IPPROTO_ROUTING);
out:
    return err;
}

void ipv6_exthdrs_term(void)
{
    ipv6_unregister_protocol(&nodata_proto, IPPROTO_NONE);
    ipv6_unregister_protocol(&destopt_proto, IPPROTO_DSTOPTS);
    ipv6_unregister_protocol(&rthdr_proto, IPPROTO_ROUTING);
}

int ipv6_parse_hopopts(struct rte_mbuf *mbuf)
{
    /* TODO */
    return EDPVS_OK;
}

/*
 * The helper function return upper proto offset of mbuf, including ip6_hdr
 * and exthdrs.
 * */
int ip6_skip_exthdr(const struct rte_mbuf *mbuf, int start, uint8_t *nexthdrp)
{
    /* TODO */
    return sizeof(struct ip6_hdr);
}
