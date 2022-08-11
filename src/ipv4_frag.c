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
 * fragment and reassemble of IPv4 packet.
 */
#include <assert.h>
#include "dpdk.h"
#include "netif.h"
#include "ipv4.h"
#include "ipv4_frag.h"
#include "icmp.h"
#include "parser/parser.h"
#include "scheduler.h"

#define IP4FRAG
#define RTE_LOGTYPE_IP4FRAG RTE_LOGTYPE_USER1

#define IP4FRAG_PREFETCH_OFFSET        3

struct ipv4_frag {
    struct rte_ip_frag_tbl        *reasm_tbl;
    struct rte_ip_frag_death_row    death_tbl; /* frags to be free */
};

/* parameters */
#define IP4_FRAG_BUCKETS_DEF        4096
#define IP4_FRAG_BUCKETS_MIN        32
#define IP4_FRAG_BUCKETS_MAX        65536

#define IP4_FRAG_BUCKET_ENTRIES_DEF 16
#define IP4_FRAG_BUCKET_ENTRIES_MIN 1
#define IP4_FRAG_BUCKET_ENTRIES_MAX 256

#define IP4_FRAG_TTL_DEF            1

static uint32_t ip4_frag_buckets = IP4_FRAG_BUCKETS_DEF;
static uint32_t ip4_frag_bucket_entries = IP4_FRAG_BUCKET_ENTRIES_DEF;
static uint32_t ip4_frag_max_entries = IP4_FRAG_BUCKETS_DEF;
static uint32_t ip4_frag_ttl = IP4_FRAG_TTL_DEF; /* seconds */

static void frag_bucket_number_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t frag_buckets;

    assert(str);
    frag_buckets = atoi(str);
    if (frag_buckets >= IP4_FRAG_BUCKETS_MIN && frag_buckets <= IP4_FRAG_BUCKETS_MAX) {
        RTE_LOG(INFO, IP4FRAG, "ip4_frag_buckets = %d\n", frag_buckets);
        ip4_frag_buckets = frag_buckets;
    } else {
        RTE_LOG(WARNING, IP4FRAG, "invalid ip4_frag_buckets config %s, using default "
                "%d\n", str, IP4_FRAG_BUCKETS_DEF);
        ip4_frag_buckets = IP4_FRAG_BUCKETS_DEF;
    }

    FREE_PTR(str);
}

static void frag_bucket_entries_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int bucket_entries;

    assert(str);
    bucket_entries = atoi(str);
    if (bucket_entries >= IP4_FRAG_BUCKET_ENTRIES_MIN &&
            bucket_entries <= IP4_FRAG_BUCKET_ENTRIES_MAX) {
        is_power2(bucket_entries, 0, &bucket_entries);
        RTE_LOG(INFO, IP4FRAG, "ip4_frag_bucket_entries = %d (round to 2^n)\n",
                bucket_entries);
        ip4_frag_bucket_entries = bucket_entries;
    } else {
        RTE_LOG(WARNING, IP4FRAG, "invalid ip4_frag_bucket_entries config %s, using "
                "default %d\n", str, IP4_FRAG_BUCKET_ENTRIES_DEF);
        ip4_frag_bucket_entries = IP4_FRAG_BUCKET_ENTRIES_DEF;
    }

    FREE_PTR(str);
}

static void frag_max_entries_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t max_entries;

    assert(str);
    if ((max_entries = atoi(str)) > 0) {
        RTE_LOG(INFO, IP4FRAG, "ip4_frag_max_entries = %d\n", max_entries);
        ip4_frag_max_entries = max_entries;
    } else {
        RTE_LOG(WARNING, IP4FRAG, "invalid ip4_frag_max_entries config %s, using "
                "default %d\n", str, IP4_FRAG_BUCKETS_DEF);
        ip4_frag_max_entries = IP4_FRAG_BUCKETS_DEF;
    }

    FREE_PTR(str);
}

static void frag_ttl_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t ttl;

    assert(str);
    ttl = atoi(str);
    if (ttl > 0 && ttl < 256) {
        RTE_LOG(INFO, IP4FRAG, "ip4_frag_ttl = %d\n", ttl);
        ip4_frag_ttl = ttl;
    } else {
        RTE_LOG(WARNING, IP4FRAG, "invalid ip4_frag_ttl %s, using default %d\n",
                str, IP4_FRAG_TTL_DEF);
        ip4_frag_ttl = IP4_FRAG_TTL_DEF;
    }

    FREE_PTR(str);
}

void ip4_frag_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
        ip4_frag_buckets = IP4_FRAG_BUCKETS_DEF;
        ip4_frag_bucket_entries = IP4_FRAG_BUCKET_ENTRIES_DEF;
        ip4_frag_max_entries = IP4_FRAG_BUCKETS_DEF;
        ip4_frag_ttl = IP4_FRAG_TTL_DEF;
    }
    /* KW_TYPE_NORMAL keyword */
}

void install_ip4_frag_keywords(void)
{
    install_keyword("fragment", NULL, KW_TYPE_INIT);
    install_sublevel();
    install_keyword("bucket_number", frag_bucket_number_handler, KW_TYPE_INIT);
    install_keyword("bucket_entries", frag_bucket_entries_handler, KW_TYPE_INIT);
    install_keyword("max_entries", frag_max_entries_handler, KW_TYPE_INIT);
    install_keyword("ttl", frag_ttl_handler, KW_TYPE_INIT);
    install_sublevel_end();
}

/*
 * per-lcore reassamble table.
 *
 * RTE_DEFINE_PER_LCORE has no way to traverse the table
 * it need to use rte_eal_mp_remote_launch with additional func.
 * that's not straightforward, so let's use array.
 */
static struct ipv4_frag ip4_frags[DPVS_MAX_LCORE];
#define this_ip4_frag    (ip4_frags[rte_lcore_id()])

/*
 * change mbuf in-place or have to change proto-type
 * for all fun in calling chain to use **mbuf if any func uses
 * mbuf after reasm. just modify ip4_defrag() is not enough.
 */
int ipv4_reassamble(struct rte_mbuf *mbuf)
{
    struct rte_mbuf *asm_mbuf, *next, *seg, *prev;
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);

    assert(mbuf->l3_len > 0);

    /* dpdk frag lib need mbuf->data_off of fragments
     * start with l2 header if exist. */
    rte_pktmbuf_prepend(mbuf, mbuf->l2_len);

    asm_mbuf = rte_ipv4_frag_reassemble_packet(
            this_ip4_frag.reasm_tbl,
            &this_ip4_frag.death_tbl,
            mbuf, rte_rdtsc(), iph);

    if (!asm_mbuf) /* no way to distinguish error and in-progress */
        return EDPVS_INPROGRESS;

    rte_pktmbuf_adj(asm_mbuf, mbuf->l2_len);

    /* as kernel, make this frag as heading mbuf.
     * the latest fragment (mbuf) should be linear. */

    /* now mbuf is a seg of asm_mbuf, replace it with a new seg. */
    if ((seg = rte_pktmbuf_alloc(mbuf->pool)) == NULL) {
        RTE_LOG(ERR, IP4FRAG, "%s: no memory.", __func__);
        rte_pktmbuf_free(asm_mbuf);
        return EDPVS_NOMEM;
    }
    mbuf_userdata_reset(seg);
    for (prev = asm_mbuf; prev; prev = prev->next)
        if (prev->next == mbuf)
            break;
    if (!prev) {
        RTE_LOG(ERR, IP4FRAG, "%s: mbuf is not a seg.", __func__);
        rte_pktmbuf_free(asm_mbuf);
        rte_pktmbuf_free(seg);
        return EDPVS_NOMEM;
    }
    memcpy(rte_pktmbuf_mtod(seg, void *),
           rte_pktmbuf_mtod(mbuf, void *), mbuf->data_len);
    seg->data_len = mbuf->data_len;
    seg->pkt_len = mbuf->pkt_len;
    prev->next = seg;
    seg->next = mbuf->next;
    mbuf->next = NULL;

    /* make mbuf as heading frag. */
    if (!rte_pktmbuf_is_contiguous(mbuf)) {
        RTE_LOG(ERR, IP4FRAG, "%s: mbuf is not linear.", __func__);
        rte_pktmbuf_free(asm_mbuf);
        return EDPVS_NOROOM;
    }

    if (mbuf->data_off + asm_mbuf->data_len > mbuf->buf_len) {
        RTE_LOG(ERR, IP4FRAG, "%s: no room.", __func__);
        rte_pktmbuf_free(asm_mbuf);
        return EDPVS_NOROOM;
    }

    memcpy(rte_pktmbuf_mtod(mbuf, void *),
           rte_pktmbuf_mtod(asm_mbuf, void *), asm_mbuf->data_len);
    mbuf->data_len = asm_mbuf->data_len;
    mbuf->pkt_len = mbuf->data_len;

    /* move segs to new heading mbuf. */
    prev = mbuf;
    mbuf_foreach_seg_safe(asm_mbuf, next, seg) {
        assert(asm_mbuf->next == seg);

        asm_mbuf->next = next;
        asm_mbuf->nb_segs--;
        asm_mbuf->pkt_len -= seg->data_len;

        prev->next = seg;
        prev = seg;
        mbuf->nb_segs++;
        mbuf->pkt_len += seg->data_len;
    }

    /* now asm_mbuf has no segs  */
    rte_pktmbuf_free(asm_mbuf);
    return EDPVS_OK;
}

/* this function consumes mbuf also free route. */
int ipv4_fragment(struct rte_mbuf *mbuf, unsigned int mtu,
          int (*output)(struct rte_mbuf *))
{
    struct rte_ipv4_hdr *iph = ip4_hdr(mbuf);
    struct route_entry *rt = MBUF_USERDATA(mbuf,
            struct route_entry *, MBUF_FIELD_ROUTE);
    struct rte_mbuf *frag;
    unsigned int left, len, hlen;
    int offset, err, from;
    void *to;
    assert(rt);

    if (iph->fragment_offset & RTE_IPV4_HDR_DF_FLAG) {
        icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
              htonl(mtu));
        err = EDPVS_FRAG;
        goto out;
    }

    hlen = ip4_hdrlen(mbuf);
    mtu -= hlen; /* IP payload space */
    left = mbuf->pkt_len - hlen;
    from = hlen;
    offset = 0;

    while (left > 0) {
        len = left < mtu ? left : mtu; /* min(left, mtu) */

        /* if we are not last frag,
         * ensure next start on eight byte boundary */
        if (len < left)
            len &= ~7;

        /* mbuf should have enough headroom,
         * but no way to extend tail room. */
        frag = rte_pktmbuf_alloc(mbuf->pool);
        if (!frag) {
            err = EDPVS_NOMEM;
            goto out;
        }
        mbuf_userdata_reset(frag);

        /* copy metadata from orig pkt */
        route4_get(rt);
        /* no need to hold before consume mbuf */
        MBUF_USERDATA(frag, struct route_entry *, MBUF_FIELD_ROUTE) = rt;
        frag->port = mbuf->port;
        frag->ol_flags = 0; /* do not offload csum for frag */
        frag->l2_len = mbuf->l2_len;
        frag->l3_len = mbuf->l3_len;

        /* copy IP header */
        if (unlikely((to = rte_pktmbuf_append(frag, hlen)) == NULL)
                || mbuf_copy_bits(mbuf, 0, to, hlen) != 0) {
            err = EDPVS_NOROOM;
            route4_put(rt);
            rte_pktmbuf_free(frag);
            goto out;
        }

        /* copy data block */
        if (unlikely((to = rte_pktmbuf_append(frag, len)) == NULL)
                || mbuf_copy_bits(mbuf, from, to, len) != 0) {
            err = EDPVS_NOROOM;
            route4_put(rt);
            rte_pktmbuf_free(frag);
            goto out;
        }
        left -= len;

        /* adjust new IP header fields */
        iph = ip4_hdr(frag);
        iph->fragment_offset = htons(offset >> 3);
        /* TODO: if (offset == 0) ip_fragment_options(frag); */

        if (left > 0)
            iph->fragment_offset |= htons(RTE_IPV4_HDR_MF_FLAG);
        offset += len;
        from += len;

        iph->total_length = htons(len + hlen);
        ip4_send_csum(iph);

        /* consumes frag and it's route */
        err = output(frag);
        if (err != EDPVS_OK)
            goto out;

        IP4_INC_STATS(fragcreates);
    }

    err = EDPVS_OK;

out:
    route4_put(rt);
    rte_pktmbuf_free(mbuf);
    if (err == EDPVS_OK)
        IP4_INC_STATS(fragoks);
    else
        IP4_INC_STATS(fragfails);
    return err;
}

static void ipv4_frag_job(void *arg)
{
    struct ipv4_frag *f = &ip4_frags[rte_lcore_id()];

    rte_ip_frag_free_death_row(&f->death_tbl, IP4FRAG_PREFETCH_OFFSET);
    return;
}

static struct dpvs_lcore_job frag_job = {
    .name = "ipv4_frag",
    .type = LCORE_JOB_SLOW,
    .func = ipv4_frag_job,
    .skip_loops = IP4_FRAG_FREE_DEATH_ROW_INTERVAL,
};

int ipv4_frag_init(void)
{
    lcoreid_t cid;
    int socket_id; /* NUMA-socket ID */
    uint64_t max_cycles;
    int err;
    struct ipv4_frag *f4;

    if (ip4_frag_bucket_entries <=0 ||
            ip4_frag_max_entries > ip4_frag_buckets * ip4_frag_bucket_entries) {
        RTE_LOG(WARNING, IP4FRAG, "invalid ip4_frag_max_entries %d (should be no "
                "bigger than ip4_frag_buckets(%d) * ip4_frag_bucket_entries(%d), using "
                "%d instead\n", ip4_frag_max_entries,
                ip4_frag_buckets, ip4_frag_bucket_entries,
                ip4_frag_buckets * ip4_frag_bucket_entries / 2);
        ip4_frag_max_entries = ip4_frag_buckets * ip4_frag_bucket_entries / 2;
    }

    /* this magic expression comes from DPDK ip_reassembly example */
    max_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
             (ip4_frag_ttl * MS_PER_S);

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid))
            continue;

        f4 = &ip4_frags[cid];
        memset(f4, 0, sizeof(struct ipv4_frag));
        socket_id = rte_lcore_to_socket_id(cid);

        f4->reasm_tbl = rte_ip_frag_table_create(
                    ip4_frag_buckets,
                    ip4_frag_bucket_entries,
                    ip4_frag_max_entries,
                    max_cycles,
                    socket_id);
        if (!f4->reasm_tbl) {
            RTE_LOG(ERR, IP4FRAG,
                "[%d] fail to create frag table.\n", cid);
            return EDPVS_DPDKAPIFAIL;
        }
    }

    err = dpvs_lcore_job_register(&frag_job, LCORE_ROLE_FWD_WORKER);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IP4FRAG, "fail to register loop job.\n");
        return err;
    }

    return EDPVS_OK;
}

int ipv4_frag_term(void)
{
    int err;

    err = dpvs_lcore_job_unregister(&frag_job, LCORE_ROLE_FWD_WORKER);
    if (err != EDPVS_OK) {
        RTE_LOG(ERR, IP4FRAG, "fail to unregister loop job.\n");
        return err;
    }

    return EDPVS_OK;
}
