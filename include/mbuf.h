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
 * mbuf.c of dpvs.
 *
 * it includes some mbuf related function beyond dpdk librte_mbuf.
 */
#ifndef __DP_VS_MBUF_H__
#define __DP_VS_MBUF_H__
#include <stdlib.h>
#include <string.h>
#include "rte_mbuf.h"

/* for each mbuf including heading mbuf and segments */
#define mbuf_foreach(m, pos)    \
    for (pos = m; pos != NULL; pos = pos->next)

/* for each segments of mbuf */
#define mbuf_foreach_seg(m, s)    \
    for (s = m->next; s != NULL; s = s->next)

#define mbuf_foreach_seg_safe(m, n, s)    \
    for (s = m->next, n = s ? s->next : NULL; \
        s != NULL; \
        s = n, n = s ? s->next : NULL)

/**
 * mbuf_copy_bits - copy bits from mbuf to buffer.
 * see skb_copy_bits().
 */
static inline int mbuf_copy_bits(const struct rte_mbuf *mbuf,
                 int offset, void *to, int len)
{
    const struct rte_mbuf *seg;
    int start, copy, end;

    if (offset + len > (int)mbuf->pkt_len)
        return -1;

    start = 0;
    mbuf_foreach(mbuf, seg) {
        end = start + seg->data_len;

        if ((copy = end - offset) > 0) {
            if (copy > len)
                copy = len;

            memcpy(to, rte_pktmbuf_mtod_offset(
                        seg, void *, offset - start),
                   copy);

            if ((len -= copy) == 0)
                return 0;
            offset += copy;
            to += copy;
        }

        start = end;
    }

    if (!len)
        return 0;

    return -1;
}

static inline void *mbuf_tail_point(const struct rte_mbuf *mbuf)
{
    return rte_pktmbuf_mtod_offset(mbuf, void *, mbuf->data_len);
}

static inline void *mbuf_header_pointer(const struct rte_mbuf *mbuf,
                    int offset, int len, void *buffer)
{
    if (unlikely(mbuf->data_len < offset + len)) {
        if (unlikely(mbuf->pkt_len < offset + len))
            return NULL;

        if (mbuf_copy_bits(mbuf, offset, buffer, len) != 0)
            return NULL;

        return buffer;
    }

    return rte_pktmbuf_mtod_offset(mbuf, void *, offset);
}

/**
 * mbuf_may_pull - pull bits from segments to heading mbuf if needed.
 * see pskb_may_pull() && __pskb_pull_tail().
 *
 * it expands heading mbuf, moving it's tail forward and copying necessary
 * data from segments part.
 *
 * return 0 if success and -1 on error.
 */
int mbuf_may_pull(struct rte_mbuf *mbuf, unsigned int len);

/**
* Copy a rte_mbuf including the data area.
*
* return a new rte_mbuf if success and NULL on error.
*/
struct rte_mbuf *mbuf_copy(struct rte_mbuf *md, struct rte_mempool *mp);
void mbuf_copy_metadata(struct rte_mbuf *mi, struct rte_mbuf *m);

#ifdef CONFIG_DPVS_MBUF_DEBUG
inline void dp_vs_mbuf_dump(const char *msg, int af, const struct rte_mbuf *mbuf);
#endif

#endif /* __DP_VS_MBUF_H__ */
