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
/*
 * mbuf.c of dpvs.
 *
 * it includes some mbuf related functions beyond dpdk mbuf API.
 */
#include <assert.h>
#include "mbuf.h"

#define EMBUF
#define RTE_LOGTYPE_EMBUF    RTE_LOGTYPE_USER1

/**
 * mbuf_may_pull - pull bits from segments to heading mbuf if needed.
 * see pskb_may_pull() && __pskb_pull_tail().
 *
 * it expands heading mbuf, moving it's tail forward and copying necessary
 * data from segments part.
 */
int mbuf_may_pull(struct rte_mbuf *mbuf, unsigned int len)
{
	int delta, eat;
	struct rte_mbuf *seg, *next;

	if (likely(len <= mbuf->data_len))
		return 0;

	if (unlikely(len > mbuf->pkt_len))
		return -1;

	delta = len - mbuf->data_len;

	/* different from skb, there's no way to expand mbuf's tail room,
	 * because mbuf size is determined when init mbuf pool */
	if (rte_pktmbuf_tailroom(mbuf) < delta) {
		RTE_LOG(ERR, EMBUF, "%s: no tail room.", __func__);
		return -1;
	}

	/* pull bits needed from segments to tail room of heading mbuf */
	if (mbuf_copy_bits(mbuf, mbuf->data_len, 
			   mbuf_tail_point(mbuf), delta) != 0)
		return -1;

	/* free fully eaten segments and leave left segs attached,
	 * points need be reload if partial bits was eaten for a seg. */
	eat = delta;
	mbuf_foreach_seg_safe(mbuf, next, seg) {
		if (eat <= 0)
			break;

		if (seg->data_len <= eat) {
			assert(mbuf->next == seg);
			eat -= seg->data_len;
			rte_pktmbuf_free_seg(seg);
			mbuf->next = next;
			mbuf->nb_segs--;
		} else {
			rte_pktmbuf_adj(seg, eat);
			eat = 0;
			break;
		}
	}

	assert(!eat &&
	       mbuf->data_off + mbuf->data_len + delta <= mbuf->buf_len);

	/* mbuf points must be updated */
	mbuf->data_len += delta;

	return 0;
}
