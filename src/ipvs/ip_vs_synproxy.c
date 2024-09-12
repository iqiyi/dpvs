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
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/md5.h>
#include "conf/common.h"
#include "dpdk.h"
#include "ipvs/ipvs.h"
#include "ipvs/synproxy.h"
#include "timer.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipvs/proto.h"
#include "ipvs/proto_tcp.h"
#include "ipvs/blklst.h"
#include "ipvs/whtlst.h"
#include "parser/parser.h"

/* synproxy controll variables */
/* syn-proxy ctrl variables */
#define DP_VS_SYNPROXY_INIT_MSS_DEFAULT         1452
#define DP_VS_SYNPROXY_TTL_DEFAULT              63
#define DP_VS_SYNPROXY_SACK_DEFAULT             1
#define DP_VS_SYNPROXY_WSCALE_DEFAULT           0
#define DP_VS_SYNPROXY_TIMESTAMP_DEFAULT        0
#define DP_VS_SYNPROXY_CLWND_DEFAULT            0
#define DP_VS_SYNPROXY_DEFER_DEFAULT            0
#define DP_VS_SYNPROXY_DUP_ACK_DEFAULT          10
#define DP_VS_SYNPROXY_MAX_ACK_SAVED_DEFAULT    3
#define DP_VS_SYNPROXY_CONN_REUSE_DEFAULT       1
#define DP_VS_SYNPROXY_CONN_REUSE_CL_DEFAULT    1
#define DP_VS_SYNPROXY_CONN_REUSE_TW_DEFAULT    1
#define DP_VS_SYNPROXY_CONN_REUSE_FW_DEFAULT    0
#define DP_VS_SYNPROXY_CONN_REUSE_CW_DEFAULT    0
#define DP_VS_SYNPROXY_CONN_REUSE_LA_DEFAULT    0
#define DP_VS_SYNPROXY_SYN_RETRY_DEFAULT        3
int dp_vs_synproxy_ctrl_init_mss = DP_VS_SYNPROXY_INIT_MSS_DEFAULT;
int dp_vs_synproxy_ctrl_sack = DP_VS_SYNPROXY_SACK_DEFAULT;
int dp_vs_synproxy_ctrl_wscale = DP_VS_SYNPROXY_WSCALE_DEFAULT;
int dp_vs_synproxy_ctrl_timestamp = DP_VS_SYNPROXY_TIMESTAMP_DEFAULT;
int dp_vs_synproxy_ctrl_synack_ttl = DP_VS_SYNPROXY_TTL_DEFAULT;
int dp_vs_synproxy_ctrl_clwnd = DP_VS_SYNPROXY_CLWND_DEFAULT;
int dp_vs_synproxy_ctrl_defer = DP_VS_SYNPROXY_DEFER_DEFAULT;
int dp_vs_synproxy_ctrl_conn_reuse = DP_VS_SYNPROXY_CONN_REUSE_DEFAULT;
int dp_vs_synproxy_ctrl_conn_reuse_cl = DP_VS_SYNPROXY_CONN_REUSE_CL_DEFAULT;
int dp_vs_synproxy_ctrl_conn_reuse_tw = DP_VS_SYNPROXY_CONN_REUSE_TW_DEFAULT;
int dp_vs_synproxy_ctrl_conn_reuse_fw = DP_VS_SYNPROXY_CONN_REUSE_FW_DEFAULT;
int dp_vs_synproxy_ctrl_conn_reuse_cw = DP_VS_SYNPROXY_CONN_REUSE_CW_DEFAULT;
int dp_vs_synproxy_ctrl_conn_reuse_la = DP_VS_SYNPROXY_CONN_REUSE_LA_DEFAULT;
int dp_vs_synproxy_ctrl_dup_ack_thresh = DP_VS_SYNPROXY_DUP_ACK_DEFAULT;
int dp_vs_synproxy_ctrl_max_ack_saved = DP_VS_SYNPROXY_MAX_ACK_SAVED_DEFAULT;
int dp_vs_synproxy_ctrl_syn_retry = DP_VS_SYNPROXY_SYN_RETRY_DEFAULT;

#define DP_VS_SYNPROXY_ACK_MBUFPOOL_SIZE        1048575  // 2^20 - 1
#define DP_VS_SYNPROXY_ACK_CACHE_SIZE           256
struct rte_mempool *dp_vs_synproxy_ack_mbufpool[DPVS_MAX_SOCKET];

#ifdef CONFIG_SYNPROXY_DEBUG
rte_atomic32_t sp_syn_saved;
rte_atomic32_t sp_ack_saved;
rte_atomic64_t sp_ack_refused;
static struct dpvs_timer g_second_timer;
#endif

/*
 * syncookies using digest function from openssl libray,
 * a little difference from kernel, which uses md5_transform
 * */
static uint32_t g_net_secret[2][MD5_LBLOCK];
static struct dpvs_timer g_minute_timer;
static rte_atomic32_t g_minute_count;

static int minute_timer_expire( void *priv)
{
    struct timeval tv;

    rte_atomic32_inc(&g_minute_count);

    tv.tv_sec = 60; /* one minute timer */
    tv.tv_usec = 0;
    dpvs_timer_update_nolock(&g_minute_timer, &tv, true);

    return DTIMER_OK;
}

#ifdef CONFIG_SYNPROXY_DEBUG
static int second_timer_expire(void *priv)
{
    struct timeval tv;

    RTE_LOG(INFO, IPVS, "dpvs_mbuf: syn_saved|ack_saved|ack_refused=%d|%d|%ld\n",
            rte_atomic32_read(&sp_syn_saved),
            rte_atomic32_read(&sp_ack_saved),
            rte_atomic64_read(&sp_ack_refused));

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    dpvs_timer_sched_nolock(&g_second_timer, &tv, second_timer_expire, NULL, true);

    return DTIMER_OK;
}
#endif

static int generate_random_key(void *key, unsigned length)
{
    int fd;
    int ret;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ret = read(fd, key, length);
    close(fd);

    if (ret != (signed)length) {
        return -1;
    }
    return 0;
}

int dp_vs_synproxy_init(void)
{
    int i;
    char ack_mbufpool_name[32];
    struct timeval tv;

    if (generate_random_key(g_net_secret, sizeof(g_net_secret))) {
        for (i = 0; i < MD5_LBLOCK; i++) {
            g_net_secret[0][i] = (uint32_t)random();
            g_net_secret[1][i] = (uint32_t)random();
        }
    }

    rte_atomic32_set(&g_minute_count, (uint32_t)random());
    tv.tv_sec = 60; /* one minute timer */
    tv.tv_usec = 0;
    dpvs_timer_sched(&g_minute_timer, &tv, minute_timer_expire, NULL, true);

    /* allocate NUMA-aware ACK list cache */
    for (i = 0; i < get_numa_nodes(); i++) {
        snprintf(ack_mbufpool_name, sizeof(ack_mbufpool_name), "ack_mbufpool_%d", i);
        dp_vs_synproxy_ack_mbufpool[i] = rte_mempool_create(ack_mbufpool_name,
                DP_VS_SYNPROXY_ACK_MBUFPOOL_SIZE,
                sizeof(struct dp_vs_synproxy_ack_pakcet),
                DP_VS_SYNPROXY_ACK_CACHE_SIZE,
                0, NULL, NULL, NULL, NULL,
                i, 0);
        if (!dp_vs_synproxy_ack_mbufpool[i]) {
            for (i = i - 1; i >= 0; i--)
                rte_mempool_free(dp_vs_synproxy_ack_mbufpool[i]);
            return EDPVS_NOMEM;
        }
    }

#ifdef CONFIG_SYNPROXY_DEBUG
    rte_atomic32_init(&sp_syn_saved);
    rte_atomic32_init(&sp_ack_saved);
    rte_atomic64_init(&sp_ack_refused);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    dpvs_timer_sched(&g_second_timer, &tv, second_timer_expire, NULL, true);
#endif

    return EDPVS_OK;
}

int dp_vs_synproxy_term(void)
{
    int i;
    dpvs_timer_cancel(&g_minute_timer, true);

    for (i = 0; i < get_numa_nodes(); i++)
        rte_mempool_free(dp_vs_synproxy_ack_mbufpool[i]);

    return EDPVS_OK;
}

#define COOKIEBITS 24 /* Upper bits store count */
#define COOKIEMASK (((uint32_t)1 << COOKIEBITS) - 1)

static uint32_t
cookie_hash(uint32_t saddr, uint32_t daddr,
            uint16_t sport, uint16_t dport,
            uint32_t count, int c)
{
    unsigned char hash[MD5_DIGEST_LENGTH];
    uint32_t data[5];
    uint32_t hvalue;

    data[0] = saddr;
    data[1] = daddr;
    data[2] = (sport << 16) + dport;
    data[3] = count;
    data[4] = g_net_secret[c][0];

    MD5((unsigned char *)data, sizeof(data), hash);
    memcpy(&hvalue, hash, sizeof(hvalue));

    return hvalue;
}

static uint32_t
secure_tcp_syn_cookie(uint32_t saddr, uint32_t daddr,
                      uint16_t sport, uint16_t dport,
                      uint32_t sseq, uint32_t count,
                      uint32_t data)
{
    /*
     * Compute the secure sequence number.
     * The output should be:
     * HASH(sec1, saddr, sport, daddr, dport, sec1) + sseq + (count * 2^24)
     *      + (HASH(sec2, saddr, sport, daddr, dport, count, sec2) % 2^24).
     * Where sseq is their sequence number and count increases every minute by 1.
     * As an extra hack, we add a small "data" value that encodes the MSS into
     * the second hash value.
     */
    return (cookie_hash(saddr, daddr, sport, dport, 0, 0) +
        sseq + (count << COOKIEBITS) +
        ((cookie_hash(saddr, daddr, sport, dport, count, 1) + data) & COOKIEMASK));
}

static uint32_t
check_tcp_syn_cookie(uint32_t cookie,
                     uint32_t saddr, uint32_t daddr,
                     uint16_t sport, uint16_t dport,
                     uint32_t sseq, uint32_t count,
                     uint32_t maxdiff)
{
    /*
     * This retrieves the small "data" value from the syncookie.
     * If the syncookie is bad, the data returned will be out of range.
     * This must be checked by the caller.
     *
     * The count value used to generate the cookie must be within "maxdiff"
     * if the current (passed-in) "count". The return value is (uint32_t) -1
     * if this test fails.
     */
    uint32_t diff;

    /* Strip away the layers from the cookie */
    cookie -= cookie_hash(saddr, daddr, sport, dport, 0, 0) + sseq;

    /* Cookie is now reduced to (count * 2^24) ^ (hash % 2^24) */
    diff = (count - (cookie >> COOKIEBITS)) & ((uint32_t) -1 >> COOKIEBITS);
    if (diff >= maxdiff)
        return (uint32_t) -1;

    return (cookie - cookie_hash(saddr, daddr, sport, dport, count - diff, 1))
        & COOKIEMASK; /* Leaving the data behind */
}

static uint32_t
cookie_hash_v6(const struct in6_addr *saddr,
               const struct in6_addr *daddr,
               uint16_t sport, uint16_t dport,
               uint32_t count, int c)
{
    int i;
    uint32_t hvalue, data[MD5_LBLOCK];
    unsigned char hash[MD5_DIGEST_LENGTH];

    for (i = 0; i < 4; i++)
        data[i] = g_net_secret[c][i] + ((uint32_t *)saddr)[i];
    for (i = 4; i < 8; i++)
        data[i] = g_net_secret[c][i] + ((uint32_t *)daddr)[i-4];

    data[8] = g_net_secret[c][8] + ((sport << 16) + dport);
    data[9] = g_net_secret[c][9] + count;

    for (i = 10; i < MD5_LBLOCK; i++)
        data[i] = g_net_secret[c][i];

    MD5((unsigned char*)data, sizeof(data), hash);
    memcpy(&hvalue, hash, sizeof(hvalue));

    return hvalue;
}

static uint32_t
secure_tcp_syn_cookie_v6(const struct in6_addr *saddr,
                      const struct in6_addr *daddr,
                      uint16_t sport, uint16_t dport,
                      uint32_t sseq, uint32_t count,
                      uint32_t data)
{
    return (cookie_hash_v6(saddr, daddr, sport, dport, 0, 0)
            + sseq + (count << COOKIEBITS)
            + ((cookie_hash_v6(saddr, daddr, sport, dport, count, 1)
                    + data) & COOKIEMASK));
}

static uint32_t
check_tcp_syn_cookie_v6(uint32_t cookie,
                        const struct in6_addr *saddr,
                        const struct in6_addr *daddr,
                        uint16_t sport, uint16_t dport,
                        uint32_t sseq, uint32_t count,
                        uint32_t maxdiff)
{
    uint32_t diff;

    cookie -= cookie_hash_v6(saddr, daddr, sport, dport, 0, 0) + sseq;

    diff = (count - (cookie >> COOKIEBITS)) & ((uint32_t) -1 >> COOKIEBITS);
    if (diff >= maxdiff)
        return (uint32_t) -1;

    return (cookie - cookie_hash_v6(saddr, daddr, sport, dport,
                count - diff, 1)) & COOKIEMASK;
}

/* This table has to be sorted and terminated with (uint16_t)-1.
 * XXX generate a better table.
 * Unresolved Issues: HIPPI with a 64K MSS is not well supported.
 */
static uint16_t const msstab[] = {
    64 - 1,
    256 - 1,
    512 - 1,
    536 - 1,
    1024 - 1,
    1280 - 1,
    1440 - 1,
    1452 - 1,
    1460 - 1,
    4312 - 1,
    (uint16_t)-1
};

/* The number doesn't include the -1 terminator */
#define NUM_MSS (NELEMS(msstab) - 1)

/*
 * This (misnamed) value is the age of syncookie which is permitted.
 * Its ideal value should be dependent on TCP_TIMEOUT_INIT and
 * sysctl_tcp_retries. It's a rather complicated formula (exponetional
 * backoff) to compute at runtime so it's currently hardcoded here.
 */
#define DP_VS_SYNPROXY_COUNTER_TRIES 4

/*
 * Generate a syncookie for dp_vs module.
 * Besides mss, we store additional tcp options in cookie "data".
 *
 * Cookie "data" format:
 * |[21][20][19-16][15-0]|
 * [21] SACKOK
 * [20] TimeStampOK
 * [19-16] snd_wscale
 * [15-12] MSSIND
 */
static uint32_t
syn_proxy_cookie_v4_init_sequence(struct rte_mbuf *mbuf,
                                  const struct tcphdr *th,
                                  struct dp_vs_synproxy_opt *opts)
{
    const struct iphdr *iph = (struct iphdr*)ip4_hdr(mbuf);
    int mssind;
    const uint16_t mss = opts->mss_clamp;
    uint32_t data;

    /* XXX sort msstab[] by probability? Binary serarch? */
    for (mssind = 0; mss > msstab[mssind + 1]; mssind++)
        ;
    opts->mss_clamp = msstab[mssind] + 1;

    data = ((mssind & 0x0f) << DP_VS_SYNPROXY_MSS_BITS);
    data |= opts->sack_ok << DP_VS_SYNPROXY_SACKOK_BIT;
    data |= opts->tstamp_ok << DP_VS_SYNPROXY_TSOK_BIT;
    data |= ((opts->snd_wscale & 0xf) << DP_VS_SYNPROXY_SND_WSCALE_BITS);

    return secure_tcp_syn_cookie(iph->saddr, iph->daddr,
            th->source, th->dest, ntohl(th->seq),
            rte_atomic32_read(&g_minute_count), data);
}

static uint32_t
syn_proxy_cookie_v6_init_sequence(struct rte_mbuf *mbuf,
                                  const struct tcphdr *th,
                                  struct dp_vs_synproxy_opt *opts)
{
    const struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    int mssind;
    const uint16_t mss = opts->mss_clamp;
    uint32_t data;

    /* XXX sort msstab[] by probability? Binary serarch? */
    for (mssind = 0; mss > msstab[mssind + 1]; mssind++)
        ;
    opts->mss_clamp = msstab[mssind] + 1;

    data = ((mssind & 0x0f) << DP_VS_SYNPROXY_MSS_BITS);
    data |= opts->sack_ok << DP_VS_SYNPROXY_SACKOK_BIT;
    data |= opts->tstamp_ok << DP_VS_SYNPROXY_TSOK_BIT;
    data |= ((opts->snd_wscale & 0xf) << DP_VS_SYNPROXY_SND_WSCALE_BITS);

    return secure_tcp_syn_cookie_v6(&ip6h->ip6_src, &ip6h->ip6_dst,
            th->source, th->dest, ntohl(th->seq),
            rte_atomic32_read(&g_minute_count), data);
}

/*
 * When syn_proxy_cookie_v4_init_sequence is used, we check cookie as follow:
 *  1. mssind check.
 *  2. get sack/timestamp/wscale options
 */
static int
syn_proxy_v4_cookie_check(struct rte_mbuf *mbuf, uint32_t cookie,
                          struct dp_vs_synproxy_opt *opt)
{
    const struct iphdr *iph = (struct iphdr*)ip4_hdr(mbuf);
    const struct tcphdr *th = tcp_hdr(mbuf);

    uint32_t seq = ntohl(th->seq) - 1;
    uint32_t mssind;
    uint32_t res = check_tcp_syn_cookie(cookie, iph->saddr, iph->daddr,
            th->source, th->dest, seq, rte_atomic32_read(&g_minute_count),
            DP_VS_SYNPROXY_COUNTER_TRIES);

    memset(opt, 0, sizeof(struct dp_vs_synproxy_opt));
    if ((uint32_t) -1 == res) /* count is invalid, g_minute_count' >> g_minute_count */
        return 0;

    mssind = (res & DP_VS_SYNPROXY_MSS_MASK) >> DP_VS_SYNPROXY_MSS_BITS;
    if ((mssind < NUM_MSS) && ((res & DP_VS_SYNPROXY_OTHER_MASK) == 0)) {
        opt->mss_clamp = msstab[mssind] + 1;
        opt->sack_ok = (res & DP_VS_SYNPROXY_SACKOK_MASK) >> DP_VS_SYNPROXY_SACKOK_BIT;
        opt->tstamp_ok = (res & DP_VS_SYNPROXY_TSOK_MASK) >> DP_VS_SYNPROXY_TSOK_BIT;
        opt->snd_wscale = (res & DP_VS_SYNPROXY_SND_WSCALE_MASK)
                            >> DP_VS_SYNPROXY_SND_WSCALE_BITS;
        if (opt->snd_wscale > 0 && opt->snd_wscale <= DP_VS_SYNPROXY_WSCALE_MAX)
            opt->wscale_ok = 1;
        else if (opt->snd_wscale == 0)
            opt->wscale_ok = 0;
        else
            return 0;

        return 1;
    }
    return 0;
}

static int
syn_proxy_v6_cookie_check(struct rte_mbuf *mbuf, uint32_t cookie,
                          struct dp_vs_synproxy_opt *opt)
{
    const struct ip6_hdr *ip6h = ip6_hdr(mbuf);
    const struct tcphdr *th = tcp_hdr(mbuf);

    uint32_t seq = ntohl(th->seq) - 1;
    uint32_t mssind;
    uint32_t res = check_tcp_syn_cookie_v6(cookie, &ip6h->ip6_src, &ip6h->ip6_dst,
                   th->source, th->dest, seq, rte_atomic32_read(&g_minute_count),
                   DP_VS_SYNPROXY_COUNTER_TRIES);

    memset(opt, 0, sizeof(struct dp_vs_synproxy_opt));
    if ((uint32_t) -1 == res) /* count is invalid, g_minute_count' >> g_minute_count */
        return 0;

    mssind = (res & DP_VS_SYNPROXY_MSS_MASK) >> DP_VS_SYNPROXY_MSS_BITS;
    if ((mssind < NUM_MSS) && ((res & DP_VS_SYNPROXY_OTHER_MASK) == 0)) {
        opt->mss_clamp = msstab[mssind] + 1;
        opt->sack_ok = (res & DP_VS_SYNPROXY_SACKOK_MASK) >> DP_VS_SYNPROXY_SACKOK_BIT;
        opt->tstamp_ok = (res & DP_VS_SYNPROXY_TSOK_MASK) >> DP_VS_SYNPROXY_TSOK_BIT;
        opt->snd_wscale = (res & DP_VS_SYNPROXY_SND_WSCALE_MASK)
                            >> DP_VS_SYNPROXY_SND_WSCALE_BITS;
        if (opt->snd_wscale > 0 && opt->snd_wscale <= DP_VS_SYNPROXY_WSCALE_MAX)
            opt->wscale_ok = 1;
        else if (opt->snd_wscale == 0)
            opt->wscale_ok = 0;
        else
            return 0;

        return 1;
    }
    return 0;
}

/*
 *  Synproxy implementation
 */

static unsigned char syn_proxy_parse_wscale_opt(struct rte_mbuf *mbuf, struct tcphdr *th)
{
    int length;
    unsigned char opcode, opsize;
    unsigned char *ptr;

    length = (th->doff * 4) - sizeof(struct tcphdr);
    ptr = (unsigned char *)(th + 1);
    while (length > 0) {
        opcode = *ptr++;
        switch (opcode) {
            case TCPOPT_EOL:
                return 0;
            case TCPOPT_NOP:
                length--;
                continue;
            default:
                opsize = *ptr++;
                if (opsize < 2) /* silly options */
                    return 0;
                if (opsize > length) /* partial options */
                    return 0;
                if (opcode == TCPOPT_WINDOW) {
                    if (*ptr > DP_VS_SYNPROXY_WSCALE_MAX) /* invalid wscale opt */
                        return 0;
                    return *ptr;
                }
                ptr += opsize -2;
                length -= opsize;
        }
    }
    return 0; /* should never reach here */
}

/* Replace tcp options in tcp header, called by syn_proxy_reuse_mbuf() */
static void syn_proxy_parse_set_opts(struct rte_mbuf *mbuf, struct tcphdr *th,
        struct dp_vs_synproxy_opt *opt)
{
    /* mss in received packet */
    uint16_t in_mss;
    uint32_t *tmp;
    unsigned char *ptr;
    int length = (th->doff * 4) - sizeof(struct tcphdr);
    uint16_t user_mss = dp_vs_synproxy_ctrl_init_mss;
    struct timespec tsp_now;

    memset(opt, '\0', sizeof(struct dp_vs_synproxy_opt));
    opt->mss_clamp = 536;
    ptr = (unsigned char *)(th + 1);

    while (length > 0) {
        unsigned char *tmp_opcode = ptr;
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCPOPT_EOL:
            return;
        case TCPOPT_NOP:
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2 ) /* silly options */
                return;
            if (opsize > length)
                return; /* don't parse partial options */
            switch(opcode) {
            case TCPOPT_MAXSEG:
                if (opsize == TCPOLEN_MAXSEG) {
                    in_mss = ntohs(*(uint16_t *) ptr);
                    if (in_mss) {
                        if (user_mss < in_mss) {
                            in_mss = user_mss;
                        }
                        opt->mss_clamp = in_mss;
                    }
                    *(uint16_t *) ptr = htons(opt->mss_clamp);
                }
                break;
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW) {
                    if (dp_vs_synproxy_ctrl_wscale) {
                        opt->wscale_ok = 1;
                        opt->snd_wscale = *(uint8_t *)ptr;
                        if (opt->snd_wscale > DP_VS_SYNPROXY_WSCALE_MAX) {
                            RTE_LOG(INFO, IPVS, "tcp_parse_options: Illegal window "
                                    "scaling value %d > %d received.",
                                    opt->snd_wscale, DP_VS_SYNPROXY_WSCALE_MAX);
                            opt->snd_wscale = DP_VS_SYNPROXY_WSCALE_MAX;
                        }
                        *(uint8_t *) ptr = (uint8_t) dp_vs_synproxy_ctrl_wscale;
                    } else {
                        memset(tmp_opcode, TCPOPT_NOP, TCPOLEN_WINDOW);
                    }
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {
                    if (dp_vs_synproxy_ctrl_timestamp) {
                        memset(&tsp_now, 0, sizeof(tsp_now));
                        clock_gettime(CLOCK_REALTIME, &tsp_now);
                        opt->tstamp_ok = 1;
                        tmp = (uint32_t *) ptr;
                        *(tmp + 1) = *tmp;
                        *tmp = htonl((uint32_t)(TCP_OPT_TIMESTAMP(tsp_now)));
                    } else {
                        memset(tmp_opcode, TCPOPT_NOP, TCPOLEN_TIMESTAMP);
                    }
                }
                break;
            case TCPOPT_SACK_PERMITTED:
                if (opsize == TCPOLEN_SACK_PERMITTED) {
                    if (dp_vs_synproxy_ctrl_sack) {
                        opt->sack_ok = 1;
                    } else {
                        memset(tmp_opcode, TCPOPT_NOP, TCPOLEN_SACK_PERMITTED);
                    }
                }
                break;
            }
            ptr += opsize -2;
            length -= opsize;
        }
    }
}

/* Reuse mbuf for syn proxy, called by syn_proxy_syn_rcv().
 * do following things:
 * 1) set tcp options,
 * 2) compute seq with cookie func,
 * 3) set tcp seq and ack_seq,
 * 4) exchange ip addr and tcp port,
 * 5) compute iphdr and tcp check (HW xmit checksum offload not support for syn).
 */
static void syn_proxy_reuse_mbuf(int af, struct rte_mbuf *mbuf,
                                 struct tcphdr *th,
                                 struct dp_vs_synproxy_opt *opt)
{
    uint32_t isn;
    uint16_t tmpport;
    int iphlen;

    if (AF_INET6 == af)
        iphlen = sizeof(struct ip6_hdr);
    else
        iphlen = ip4_hdrlen(mbuf);

    if (mbuf_may_pull(mbuf, iphlen + (th->doff << 2)) != 0)
        return;

    /* deal with tcp options */
    syn_proxy_parse_set_opts(mbuf, th, opt);

    /* get cookie */
    if (AF_INET6 == af)
        isn = syn_proxy_cookie_v6_init_sequence(mbuf, th, opt);
    else
        isn = syn_proxy_cookie_v4_init_sequence(mbuf, th, opt);

    /* set syn-ack flag */
    ((uint8_t *)th)[13] = 0x12;

    /* exchage ports */
    tmpport = th->dest;
    th->dest = th->source;
    th->source = tmpport;
    /* set window size to zero if enabled */
    if (dp_vs_synproxy_ctrl_clwnd && !dp_vs_synproxy_ctrl_defer)
        th->window = 0;
    /* set seq(cookie) and ack_seq */
    th->ack_seq = htonl(ntohl(th->seq) + 1);
    th->seq = htonl(isn);

    /* exchage addresses */
    if (AF_INET6 == af) {
        struct in6_addr tmpaddr;
        struct ip6_hdr *ip6h = ip6_hdr(mbuf);

        tmpaddr = ip6h->ip6_src;
        ip6h->ip6_src = ip6h->ip6_dst;
        ip6h->ip6_dst = tmpaddr;
        ip6h->ip6_hlim = dp_vs_synproxy_ctrl_synack_ttl;

        if (likely(mbuf->ol_flags & PKT_TX_TCP_CKSUM)) {
            mbuf->l3_len = (void *)th - (void *)ip6h;
            mbuf->l4_len = (th->doff << 2);
            th->check = ip6_phdr_cksum(ip6h, mbuf->ol_flags, mbuf->l3_len, IPPROTO_TCP);
        } else {
            if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                return;
            tcp6_send_csum((struct rte_ipv6_hdr*)ip6h, th);
        }
    } else {
        uint32_t tmpaddr;
        struct iphdr *iph = (struct iphdr*)ip4_hdr(mbuf);

        tmpaddr = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = tmpaddr;
        iph->ttl = dp_vs_synproxy_ctrl_synack_ttl;
        iph->tos = 0;

        /* compute checksum */
        if (likely(mbuf->ol_flags & PKT_TX_TCP_CKSUM)) {
            mbuf->l3_len = iphlen;
            mbuf->l4_len = (th->doff << 2);
            th->check = rte_ipv4_phdr_cksum((struct rte_ipv4_hdr*)iph, mbuf->ol_flags);
        } else {
            if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                return;
            tcp4_send_csum((struct rte_ipv4_hdr*)iph, th);
        }

        if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
            iph->check = 0;
        else
            ip4_send_csum((struct rte_ipv4_hdr*)iph);
    }
}

/* Syn-proxy step 1 logic: receive client's Syn.
 * Check if synproxy is enabled for this skb, and send syn/ack back
 *
 * Synproxy is enabled when:
 * 1) mbuf is a syn packet,
 * 2) and the service is synproxy-enable,
 * 3) and ip_vs_todrop return fasle (not supported now)
 *
 * @return 0 means the caller should return at once and use
 * verdict as return value, return 1 for nothing.
 */
int dp_vs_synproxy_syn_rcv(int af, struct rte_mbuf *mbuf,
        const struct dp_vs_iphdr *iph, int *verdict)
{
    int ret;
    struct dp_vs_service *svc = NULL;
    struct tcphdr *th, _tcph;
    struct dp_vs_synproxy_opt tcp_opt;
    struct netif_port *dev;
    struct rte_ether_hdr *eth;
    struct rte_ether_addr ethaddr;

    th = mbuf_header_pointer(mbuf, iph->len, sizeof(_tcph), &_tcph);
    if (unlikely(NULL == th))
        goto syn_rcv_out;

    if (th->syn && !th->ack && !th->rst && !th->fin &&
            (svc = dp_vs_service_lookup(af, iph->proto, &iph->daddr, th->dest, 0,
                NULL, NULL, rte_lcore_id())) && (svc->flags & DP_VS_SVC_F_SYNPROXY)) {
        /* if service's weight is zero (non-active realserver),
         * do noting and drop the packet */
        if (svc->weight == 0) {
            dp_vs_estats_inc(SYNPROXY_NO_DEST);
            goto syn_rcv_out;
        }

        /* drop packet from blacklist */
        if (dp_vs_blklst_filtered(iph->af, iph->proto, &iph->daddr,
                    th->dest, &iph->saddr, mbuf)) {
            goto syn_rcv_out;
        }

        /* drop packet if not in whitelist */
        if (dp_vs_whtlst_filtered(iph->af, iph->proto, &iph->daddr,
                    th->dest, &iph->saddr, mbuf)) {
            goto syn_rcv_out;
        }
    } else {
        return 1;
    }

    /* mbuf will be reused and ether header will be set.
     * FIXME: to support non-ether packets. */
    if (mbuf->l2_len != sizeof(struct rte_ether_hdr))
        goto syn_rcv_out;

    /* update statistics */
    dp_vs_estats_inc(SYNPROXY_SYN_CNT);

    /* set tx offload flags */
    assert(mbuf->port <= NETIF_MAX_PORTS);
    dev = netif_port_get(mbuf->port);
    if (unlikely(!dev)) {
        RTE_LOG(ERR, IPVS, "%s: device eth%d not found\n",
                __func__, mbuf->port);
        goto syn_rcv_out;
    }
    if (likely(dev && (dev->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD))) {
        if (af == AF_INET)
            mbuf->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4);
        else
            mbuf->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IPV6);
    }

    /* reuse mbuf */
    syn_proxy_reuse_mbuf(af, mbuf, th, &tcp_opt);

    /* set L2 header and send the packet out
     * It is noted that "ipv4_xmit" should not used here,
     * because mbuf is reused. */
    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, mbuf->l2_len);
    if (unlikely(!eth)) {
        RTE_LOG(ERR, IPVS, "%s: no memory\n", __func__);
        goto syn_rcv_out;
    }
    memcpy(&ethaddr, &eth->s_addr, sizeof(struct rte_ether_addr));
    memcpy(&eth->s_addr, &eth->d_addr, sizeof(struct rte_ether_addr));
    memcpy(&eth->d_addr, &ethaddr, sizeof(struct rte_ether_addr));

    if (unlikely(EDPVS_OK != (ret = netif_xmit(mbuf, dev)))) {
        RTE_LOG(ERR, IPVS, "%s: netif_xmit failed -- %s\n",
                __func__, dpvs_strerror(ret));
    /* should not set verdict to INET_DROP since netif_xmit
     * always consume the mbuf while INET_DROP means mbuf'll
     * be free in INET_HOOK.*/
    }

    *verdict = INET_STOLEN;
    return 0;

syn_rcv_out:
    /* drop and destroy the packet */
    *verdict = INET_DROP;
    return 0;
}

/* Check if mbuf has user data */
static inline int syn_proxy_ack_has_data(struct rte_mbuf *mbuf,
        const struct dp_vs_iphdr *iph, struct tcphdr *th)
{
    RTE_LOG(DEBUG, IPVS, "%s: tot_len = %u, iph_len = %u, tcph_len = %u\n",
            __func__, mbuf->pkt_len, iph->len, th->doff * 4);
    return (mbuf->pkt_len - iph->len - th->doff * 4) != 0;
}

/* Build TCP options for SYN packet sent to RS */
static inline void syn_proxy_syn_build_options(uint32_t *ptr,
                                               struct dp_vs_synproxy_opt *opt)
{
    struct timespec tsp_now;

    *ptr++ = htonl((TCPOPT_MAXSEG << 24) | (TCPOLEN_MAXSEG << 16) | opt->mss_clamp);
    if (opt->tstamp_ok) {
        if (opt->sack_ok)
            *ptr++ = htonl((TCPOPT_SACK_PERMITTED << 24) |
                    (TCPOLEN_SACK_PERMITTED << 16) |
                    (TCPOPT_TIMESTAMP << 8) |
                    TCPOLEN_TIMESTAMP);
        else
            *ptr++ = htonl((TCPOPT_NOP << 24) |
                    (TCPOPT_NOP << 16) |
                    (TCPOPT_TIMESTAMP << 8) |
                    TCPOLEN_TIMESTAMP);
        memset(&tsp_now, 0, sizeof(tsp_now));
        clock_gettime(CLOCK_REALTIME, &tsp_now);
        *ptr++ = htonl(TCP_OPT_TIMESTAMP(tsp_now)); /* TSVAL */
        *ptr++ = 0; /* TSECR */
    } else if (opt->sack_ok) {
        *ptr++ = htonl((TCPOPT_NOP << 24) |
                (TCPOPT_NOP << 16) |
                (TCPOPT_SACK_PERMITTED << 8) |
                TCPOLEN_SACK_PERMITTED);
    }
    if (opt->wscale_ok) {
        *ptr++ = htonl((TCPOPT_NOP << 24) |
                (TCPOPT_WINDOW << 16) |
                (TCPOLEN_WINDOW << 8) |
                opt->snd_wscale);
    }
}

/* Create syn packet and send it to rs.
 * We also store syn mbuf in cp if syn retransmition is turned on. */
static int syn_proxy_send_rs_syn(int af, const struct tcphdr *th,
        struct dp_vs_conn *cp, struct rte_mbuf *mbuf,
        struct dp_vs_proto *pp, struct dp_vs_synproxy_opt *opt)
{
    int tcp_hdr_size;
    struct rte_mbuf *syn_mbuf, *syn_mbuf_cloned;
    struct rte_mempool *pool;
    struct tcphdr *syn_th;

    if (!cp->packet_xmit) {
        RTE_LOG(WARNING, IPVS, "%s: packet_xmit is null\n", __func__);
        return EDPVS_INVAL;
    }

    /* Allocate mbuf from device mempool */
    pool = get_mbuf_pool(cp, DPVS_CONN_DIR_INBOUND);
    if (unlikely(!pool)) {
        //RTE_LOG(WARNING, IPVS, "%s: %s\n", __func__, dpvs_strerror(EDPVS_NOROUTE));
        return EDPVS_NOROUTE;
    }

    syn_mbuf = rte_pktmbuf_alloc(pool);
    if (unlikely(!syn_mbuf)) {
        //RTE_LOG(WARNING, IPVS, "%s: %s\n", __func__, dpvs_strerror(EDPVS_NOMEM));
        return EDPVS_NOMEM;
    }
    mbuf_userdata_reset(syn_mbuf);  /* make sure "no route info" */

    /* Reserve space for tcp header */
    tcp_hdr_size = (sizeof(struct tcphdr) + TCPOLEN_MAXSEG
            + (opt->tstamp_ok ? TCPOLEN_TSTAMP_APPA : 0)
            + (opt->wscale_ok ? TCP_OLEN_WSCALE_ALIGNED : 0)
            /* SACK_PERM is in the palce of NOP NOP of TS */
            + ((opt->sack_ok && !opt->tstamp_ok) ? TCP_OLEN_SACKPERMITTED_ALIGNED : 0));
    syn_th = (struct tcphdr *)rte_pktmbuf_prepend(syn_mbuf, tcp_hdr_size);
    if (!syn_th) {
        rte_pktmbuf_free(syn_mbuf);
        //RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOROOM));
        return EDPVS_NOROOM;
    }

    /* Set up tcp header */
    memset(syn_th, 0, tcp_hdr_size);
    syn_th->source = th->source;
    syn_th->dest = th->dest;
    syn_th->seq = htonl(ntohl(th->seq) - 1);
    syn_th->ack_seq = 0;
    *(((uint16_t *) syn_th) + 6) = htons(((tcp_hdr_size >> 2) << 12) | /*TH_SYN*/ 0x02);
    /* FIXME: what window should we use */
    syn_th->window = htons(5000);
    syn_th->check = 0;
    syn_th->urg_ptr = 0;
    syn_th->urg = 0;
    syn_proxy_syn_build_options((uint32_t *)(syn_th + 1), opt);

    if (AF_INET6 == af) {
        struct ip6_hdr *ack_ip6h;
        struct ip6_hdr *syn_ip6h;

        /* Reserve space for ipv6 header */
        syn_ip6h = (struct ip6_hdr *)rte_pktmbuf_prepend(syn_mbuf,
                sizeof(struct ip6_hdr));
        if (!syn_ip6h) {
            rte_pktmbuf_free(syn_mbuf);
            //RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOROOM));
            return EDPVS_NOROOM;
        }

        ack_ip6h = (struct ip6_hdr *)ip6_hdr(mbuf);

        syn_ip6h->ip6_vfc = 0x60;  /* IPv6 */
        syn_ip6h->ip6_src = ack_ip6h->ip6_src;
        syn_ip6h->ip6_dst = ack_ip6h->ip6_dst;
        syn_ip6h->ip6_plen = htons(tcp_hdr_size);
        syn_ip6h->ip6_nxt = NEXTHDR_TCP;
        syn_ip6h->ip6_hlim = IPV6_DEFAULT_HOPLIMIT;

        syn_mbuf->l3_len = sizeof(*syn_ip6h);
    } else {
        struct iphdr *ack_iph;
        struct iphdr *syn_iph;

        /* Reserve space for ipv4 header */
        syn_iph = (struct iphdr *)rte_pktmbuf_prepend(syn_mbuf, sizeof(struct rte_ipv4_hdr));
        if (!syn_iph) {
            rte_pktmbuf_free(syn_mbuf);
            //RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOROOM));
            return EDPVS_NOROOM;
        }

        ack_iph = (struct iphdr *)ip4_hdr(mbuf);
        *((uint16_t *) syn_iph) = htons((4 << 12) | (5 << 8) | (ack_iph->tos & 0x1E));
        syn_iph->tot_len = htons(syn_mbuf->pkt_len);
        syn_iph->frag_off = htons(RTE_IPV4_HDR_DF_FLAG);
        syn_iph->ttl = 64;
        syn_iph->protocol = IPPROTO_TCP;
        syn_iph->saddr = ack_iph->saddr;
        syn_iph->daddr = ack_iph->daddr;

        syn_mbuf->l3_len = sizeof(*syn_iph);

        /* checksum is done by fnat_in_handler */
        syn_iph->check = 0;
    }

    /* Save syn_mbuf if syn retransmission is on */
    if (dp_vs_synproxy_ctrl_syn_retry > 0) {
        syn_mbuf_cloned = mbuf_copy(syn_mbuf, pool);
        if (unlikely(!syn_mbuf_cloned)) {
            rte_pktmbuf_free(syn_mbuf);
            //RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOMEM));
            return EDPVS_NOMEM;
        }

        mbuf_userdata_reset(syn_mbuf_cloned);
        cp->syn_mbuf = syn_mbuf_cloned;
        sp_dbg_stats32_inc(sp_syn_saved);
        rte_atomic32_set(&cp->syn_retry_max, dp_vs_synproxy_ctrl_syn_retry);
    }

    /* TODO: Save info for fast_response_xmit */

    /* Count in the syn packet */
    dp_vs_stats_in(cp, mbuf);

    /* If xmit failed, syn_mbuf will be freed correctly */
    cp->packet_xmit(pp, cp, syn_mbuf);

    return EDPVS_OK;
}

/* Reuse mbuf and construct TCP RST packet */
static int syn_proxy_build_tcp_rst(int af, struct rte_mbuf *mbuf,
                                   void *iph, struct tcphdr *th,
                                   uint32_t l3_len, uint32_t l4_len)
{
    struct netif_port *dev;
    uint16_t tmpport;
    uint16_t tcph_len, payload_len;
    struct iphdr *ip4h;
    struct ip6_hdr *ip6h;
    uint32_t seq;

    if (unlikely(l4_len < sizeof(struct tcphdr)))
        return EDPVS_INVPKT;

    tcph_len = th->doff * 4;

    if (unlikely(l4_len < tcph_len))
        return EDPVS_INVPKT;

    payload_len = l4_len - tcph_len;

    /* set tx offload flags */
    dev = netif_port_get(mbuf->port);
    if (unlikely(!dev)) {
        RTE_LOG(ERR, IPVS, "%s: device port %d not found\n",
                __func__, mbuf->port);
        return EDPVS_NOTEXIST;
    }
    if (likely(dev && (dev->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD))) {
        if (af == AF_INET6)
            mbuf->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IPV6);
        else
            mbuf->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4);
    }

    /* exchange ports */
    tmpport = th->dest;
    th->dest = th->source;
    th->source = tmpport;
    /* set window size to zero */
    th->window = 0;
    /* set seq and ack_seq */
    seq = th->ack_seq;
    if (th->syn)
        th->ack_seq = htonl(ntohl(th->seq) + 1);
    else
        th->ack_seq = htonl(ntohl(th->seq) + payload_len);
    th->seq = seq;
    /* set TCP flags */
    th->fin = 0;
    th->syn = 0;
    th->rst = 1;
    th->psh = 0;
    th->ack = 1;

    /* truncate packet if TCP payload presents */
    if (payload_len > 0) {
        if (rte_pktmbuf_trim(mbuf, payload_len) != 0) {
            return EDPVS_INVPKT;
        }
        l4_len -= payload_len;
    }

    if (AF_INET6 == af) {
        struct in6_addr tmpaddr;
        ip6h = iph;

        tmpaddr = ip6h->ip6_src;
        ip6h->ip6_src = ip6h->ip6_dst;
        ip6h->ip6_dst = tmpaddr;
        ip6h->ip6_hlim = 63;
        ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) - payload_len);

        /* compute checksum */
        if (likely(mbuf->ol_flags & PKT_TX_TCP_CKSUM)) {
            mbuf->l3_len = l3_len;
            mbuf->l4_len = l4_len;
            th->check = ip6_phdr_cksum(ip6h, mbuf->ol_flags, mbuf->l3_len, IPPROTO_TCP);
        } else {
            if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                return EDPVS_INVPKT;
            tcp6_send_csum((struct rte_ipv6_hdr*)ip6h, th);
        }
    } else {
        uint32_t tmpaddr;
        ip4h = iph;

        tmpaddr = ip4h->saddr;
        ip4h->saddr = ip4h->daddr;
        ip4h->daddr = tmpaddr;
        ip4h->ttl = 63;
        ip4h->tot_len = htons(ntohs(ip4h->tot_len) - payload_len);
        ip4h->tos = 0;

        /* compute checksum */
        if (likely(mbuf->ol_flags & PKT_TX_TCP_CKSUM)) {
            mbuf->l3_len = l3_len;
            mbuf->l4_len = l4_len;
            th->check = rte_ipv4_phdr_cksum((struct rte_ipv4_hdr*)ip4h, mbuf->ol_flags);
        } else {
            if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
                return EDPVS_INVPKT;
            tcp4_send_csum((struct rte_ipv4_hdr*)ip4h, th);
        }

        if (likely(mbuf->ol_flags & PKT_TX_IP_CKSUM))
            ip4h->check = 0;
        else
            ip4_send_csum((struct rte_ipv4_hdr*)ip4h);
    }

    return EDPVS_OK;
}

/* Send TCP RST to client before conn is established.
 * mbuf is consumed if EDPVS_OK is returned. */
static int syn_proxy_send_tcp_rst(int af, struct rte_mbuf *mbuf)
{
    struct tcphdr *th;
    struct netif_port *dev;
    struct rte_ether_hdr *eth;
    struct rte_ether_addr ethaddr;
    uint32_t l3_len, l4_len;
    void *l3_hdr;

    th = tcp_hdr(mbuf);
    if (unlikely(!th))
        return EDPVS_INVPKT;

    if (AF_INET6 == af) {
        l3_hdr = ip6_hdr(mbuf);
    } else {
        l3_hdr = ip4_hdr(mbuf);
    }

    l3_len = (void *) th - l3_hdr;

    l4_len = mbuf->pkt_len - l3_len;

    if (unlikely(l4_len < sizeof(struct tcphdr)
                 || mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)) {
        return EDPVS_INVPKT;
    }

    if (EDPVS_OK != syn_proxy_build_tcp_rst(af, mbuf, l3_hdr,
                                            th, l3_len, l4_len))
        return EDPVS_INVPKT;

    if (mbuf->l2_len < sizeof(struct rte_ether_hdr))
        return EDPVS_INVPKT;
    /* set L2 header and send the packet out
     * It is noted that "ipv4_xmit" should not used here,
     * because mbuf is reused. */
    eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, mbuf->l2_len);
    if (unlikely(!eth)) {
        RTE_LOG(ERR, IPVS, "%s: no memory\n", __func__);
        return EDPVS_NOMEM;
    }
    memcpy(&ethaddr, &eth->s_addr, sizeof(struct rte_ether_addr));
    memcpy(&eth->s_addr, &eth->d_addr, sizeof(struct rte_ether_addr));
    memcpy(&eth->d_addr, &ethaddr, sizeof(struct rte_ether_addr));

    dev = netif_port_get(mbuf->port);
    if (unlikely(!dev)) {
        RTE_LOG(ERR, IPVS, "%s: device port %d not found\n",
                __func__, mbuf->port);
        return EDPVS_NOTEXIST;
    }
    if (unlikely(EDPVS_OK != netif_xmit(mbuf, dev))) {
        RTE_LOG(ERR, IPVS, "%s: netif_xmit failed\n",
                __func__);
        /* should not set verdict to INET_DROP since netif_xmit
         * always consume the mbuf while INET_DROP means mbuf'll
         * be free in INET_HOOK.*/
    }

    return EDPVS_OK;
}

/* Syn-proxy step 2 logic: receive client's Ack
 * Receive client's 3-handshakes ack packet, do cookie check and then
 * send syn to rs after creating a session */
int dp_vs_synproxy_ack_rcv(int af, struct rte_mbuf *mbuf,
        struct tcphdr *th, struct dp_vs_proto *pp,
        struct dp_vs_conn **cpp,
        const struct dp_vs_iphdr *iph, int *verdict)
{
    int res;
    struct dp_vs_synproxy_opt opt;
    struct dp_vs_service *svc;
    int res_cookie_check;

    /* Do not check svc syn-proxy flag, as it may be changed after syn-proxy step 1. */
    if (!th->syn && th->ack && !th->rst && !th->fin &&
            (svc = dp_vs_service_lookup(af, iph->proto, &iph->daddr,
                           th->dest, 0, NULL, NULL, rte_lcore_id()))) {
        if (dp_vs_synproxy_ctrl_defer &&
                !syn_proxy_ack_has_data(mbuf, iph, th)) {
            /* Update statistics */
            dp_vs_estats_inc(SYNPROXY_NULL_ACK);
            /* We get a pure ack when expecting ack packet with payload, so
             * have to drop it */
            *verdict = INET_DROP;
            return 0;
        }

        if (AF_INET6 == af)
            res_cookie_check = syn_proxy_v6_cookie_check(mbuf,
                    ntohl(th->ack_seq) - 1, &opt);
        else
            res_cookie_check = syn_proxy_v4_cookie_check(mbuf,
                    ntohl(th->ack_seq) - 1, &opt);
        if (!res_cookie_check) {
            /* Update statistics */
            dp_vs_estats_inc(SYNPROXY_BAD_ACK);
            /* Cookie check failed, drop the packet */
            RTE_LOG(DEBUG, IPVS, "%s: syn_cookie check failed seq=%u\n", __func__,
                    ntohl(th->ack_seq) - 1);
            if (EDPVS_OK == syn_proxy_send_tcp_rst(af, mbuf)) {
                *verdict = INET_STOLEN;
            } else {
                *verdict = INET_DROP;
            }
            return 0;
        }

        /* Update statistics */
        dp_vs_estats_inc(SYNPROXY_OK_ACK);

        /* Let the virtual server select a real server for the incoming connetion,
         * and create a connection entry */
        *cpp = dp_vs_schedule(svc, iph, mbuf, 1);
        if (unlikely(!*cpp)) {
            RTE_LOG(WARNING, IPVS, "%s: ip_vs_schedule failed\n", __func__);
            /* FIXME: What to do when virtual service is available but no destination
             * available for a new connetion: send an icmp UNREACHABLE ? */
            *verdict = INET_DROP;
            return 0;
        }

        if (opt.wscale_ok)
            (*cpp)->wscale_vs = dp_vs_synproxy_ctrl_wscale;

        /* Do nothing but print a error msg when fail, because session will be
         * correctly freed in dp_vs_conn_expire */
        if (EDPVS_OK != (res = syn_proxy_send_rs_syn(af, th, *cpp, mbuf, pp, &opt))) {
            RTE_LOG(ERR, IPVS, "%s: syn_proxy_send_rs_syn failed -- %s\n",
                    __func__, dpvs_strerror(res));
        }

        /* Count in the ack packet (STOLEN by synproxy) */
        dp_vs_stats_in(*cpp, mbuf);

        /* Active session timer, and dec refcnt.
         * Also steal the mbuf, and let caller return immediately */
        dp_vs_conn_put(*cpp);
        *verdict = INET_STOLEN;
        return 0;
    }

    return 1;
}

/* Update out2in sack seqs */
static inline void
syn_proxy_filter_opt_outin(struct tcphdr *th, struct dp_vs_seq *sp_seq)
{
    unsigned char *ptr;
    int length = (th->doff * 4) - sizeof(struct tcphdr);
    uint32_t *tmp;
    uint32_t old_ack_seq;

    if (!length)
        return;

    ptr = (unsigned char *)(th + 1);

    /* Fast path for timestamp-only option */
    if (TCPOLEN_TSTAMP_APPA == length &&
        *(uint32_t *)ptr == htonl((TCPOPT_NOP << 24)
                                | (TCPOPT_NOP << 16)
                                | (TCPOPT_TIMESTAMP << 8)
                                | TCPOLEN_TIMESTAMP))
        return;

    while (length > 0) {
        int opcode = *ptr++;
        int opsize, i;

        switch (opcode) {
        case TCPOPT_EOL:
            return;
        case TCPOPT_NOP: /* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2) /* "silly options */
                return;
            if (opsize > length)
                break; /* don't parse partial options */

            if (TCPOPT_SACK == opcode &&
                    opsize >= (TCP_OLEN_SACK_BASE + TCP_OLEN_SACK_PERBLOCK) &&
                    !((opsize - TCP_OLEN_SACK_BASE) % TCP_OLEN_SACK_PERBLOCK)) {
                for (i = 0; i < (opsize - TCP_OLEN_SACK_BASE);
                        i += TCP_OLEN_SACK_PERBLOCK) {
                    tmp = (uint32_t *)(ptr + i);
                    old_ack_seq = ntohl(*tmp);
                    *tmp = htonl((uint32_t) (old_ack_seq - sp_seq->delta));
                    //syn_proxy_seq_csum_update
#ifdef CONFIG_DPVS_IPVS_DEBUG
                    RTE_LOG(DEBUG, IPVS, "%s: sack_left_seq %u => %u, delta = %u\n",
                            __func__, old_ack_seq, ntohl(*tmp), sp_seq->delta);
#endif
                    tmp++;
                    old_ack_seq = ntohl(*tmp);
                    *tmp = htonl((uint32_t)(old_ack_seq - sp_seq->delta));
                    //syn_proxy_seq_csum_update
#ifdef CONFIG_DPVS_IPVS_DEBUG
                    RTE_LOG(DEBUG, IPVS, "%s: sack_right_seq %u => %u, delta = %u\n",
                            __func__, old_ack_seq, ntohl(*tmp), sp_seq->delta);
#endif
                }
                return;
            }
            ptr += opsize - 2;
            length -= opsize;
        }
    }
}

/* Transfer ack seq and sack opt for Out-In packet */
void dp_vs_synproxy_dnat_handler(struct tcphdr *tcph, struct dp_vs_seq *sp_seq)
{
    uint32_t old_ack_seq;

    if (sp_seq->delta != 0) {
        old_ack_seq = ntohl(tcph->ack_seq);
        tcph->ack_seq = htonl((uint32_t)(old_ack_seq - sp_seq->delta));
        // syn_proxy_seq_csum_update
        syn_proxy_filter_opt_outin(tcph, sp_seq);
#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, IPVS, "%s: tcp->ack_seq %u => %u, delta = %u\n",
                __func__, old_ack_seq, ntohl(tcph->ack_seq), sp_seq->delta);
#endif
    }
}

static int syn_proxy_send_window_update(int af, struct rte_mbuf *mbuf, struct dp_vs_conn *conn,
                                        struct dp_vs_proto *pp, struct tcphdr *th)
{
    struct rte_mbuf *ack_mbuf;
    struct rte_mempool *pool;
    struct tcphdr *ack_th;

    if (!conn->packet_out_xmit) {
        return EDPVS_INVAL;
    }

    pool = get_mbuf_pool(conn, DPVS_CONN_DIR_OUTBOUND);
    if (unlikely(!pool)) {
        RTE_LOG(WARNING, IPVS, "%s: %s\n", __func__, dpvs_strerror(EDPVS_NOROUTE));
        return EDPVS_NOROUTE;
    }

    ack_mbuf = rte_pktmbuf_alloc(pool);
    if (unlikely(!ack_mbuf)) {
        RTE_LOG(WARNING, IPVS, "%s: %s\n", __func__, dpvs_strerror(EDPVS_NOMEM));
        return EDPVS_NOMEM;
    }
    mbuf_userdata_reset(ack_mbuf);

    ack_th = (struct tcphdr *)rte_pktmbuf_prepend(ack_mbuf, sizeof(struct tcphdr));
    if (!ack_th) {
        rte_pktmbuf_free(ack_mbuf);
        RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOROOM));
        return EDPVS_NOROOM;
    }

    /* Set up tcp header */
    memcpy(ack_th, th, sizeof(struct tcphdr));
    /* clear SYN flag */
    ack_th->syn = 0;
    /* add one to seq and seq will be adjust later */
    ack_th->seq = htonl(ntohl(ack_th->seq)+1);
    ack_th->doff = sizeof(struct tcphdr) >> 2;

    if (AF_INET6 == af) {
        struct ip6_hdr *ack_ip6h;
        struct ip6_hdr *reuse_ip6h = (struct ip6_hdr *)ip6_hdr(mbuf);
        /* Reserve space for ipv6 header */
        ack_ip6h = (struct ip6_hdr *)rte_pktmbuf_prepend(ack_mbuf,
                                         sizeof(struct ip6_hdr));
        if (!ack_ip6h) {
            rte_pktmbuf_free(ack_mbuf);
            RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOROOM));
            return EDPVS_NOROOM;
        }

        memcpy(ack_ip6h, reuse_ip6h, sizeof(struct ip6_hdr));
        ack_ip6h->ip6_vfc = 0x60;  /* IPv6 */
        ack_ip6h->ip6_plen = htons(sizeof(struct tcphdr));
        ack_ip6h->ip6_nxt = NEXTHDR_TCP;
        ack_mbuf->l3_len = sizeof(*ack_ip6h);
    } else {
        struct rte_ipv4_hdr *ack_iph;
        struct rte_ipv4_hdr *reuse_iph = ip4_hdr(mbuf);
        int pkt_ack_len = sizeof(struct tcphdr) + sizeof(struct iphdr);
        /* Reserve space for ipv4 header */
        ack_iph = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(ack_mbuf, sizeof(struct rte_ipv4_hdr));
        if (!ack_iph) {
            rte_pktmbuf_free(ack_mbuf);
            RTE_LOG(WARNING, IPVS, "%s:%s\n", __func__, dpvs_strerror(EDPVS_NOROOM));
            return EDPVS_NOROOM;
        }

        memcpy(ack_iph, reuse_iph, sizeof(struct rte_ipv4_hdr));
        /* version and ip header length */
        ack_iph->version_ihl = 0x45;
        ack_iph->type_of_service = 0;
        ack_iph->fragment_offset = htons(RTE_IPV4_HDR_DF_FLAG);
        ack_iph->total_length = htons(pkt_ack_len);
        ack_mbuf->l3_len = sizeof(*ack_iph);
    }

    conn->packet_out_xmit(pp, conn, ack_mbuf);

    return EDPVS_OK;
}

/* Syn-proxy step 3 logic: receive rs's Syn/Ack.
 * Update syn_proxy_seq.delta and send stored ack mbufs to rs. */
int dp_vs_synproxy_synack_rcv(struct rte_mbuf *mbuf, struct dp_vs_conn *cp,
        struct dp_vs_proto *pp, int th_offset, int *verdict)
{
    struct tcphdr _tcph, *th;
    struct dp_vs_synproxy_ack_pakcet *tmbuf, *tmbuf2;
    struct list_head save_mbuf;
    struct dp_vs_dest *dest = cp->dest;

    th = mbuf_header_pointer(mbuf, th_offset, sizeof(_tcph), &_tcph);
    if (unlikely(!th)) {
        *verdict = INET_DROP;
        return 0;
    }

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, IPVS, "%s: seq = %u ack_seq = %u %c%c%c cp->is_synproxy = %u "
            "cp->state = %u\n", __func__, ntohl(th->seq), ntohl(th->ack_seq),
            (th->syn) ? 'S' : '-',
            (th->ack) ? 'A' : '-',
            (th->rst) ? 'R' : '-',
            cp->flags & DPVS_CONN_F_SYNPROXY, cp->state);
#endif

    INIT_LIST_HEAD(&save_mbuf);

    if ((th->syn) && (th->ack) && (!th->rst) &&
            (cp->flags & DPVS_CONN_F_SYNPROXY) &&
            (cp->state == DPVS_TCP_S_SYN_SENT)) {
        cp->wscale_rs = syn_proxy_parse_wscale_opt(mbuf, th);
        cp->syn_proxy_seq.delta = ntohl(cp->syn_proxy_seq.isn) - ntohl(th->seq);
        cp->state = DPVS_TCP_S_ESTABLISHED;
        dp_vs_conn_set_timeout(cp, pp);
        dpvs_time_rand_delay(&cp->timeout, 1000000);
        if (dest) {
            rte_atomic32_inc(&dest->actconns);
            rte_atomic32_dec(&dest->inactconns);
            cp->flags &= ~DPVS_CONN_F_INACTIVE;
            dp_vs_dest_detected_alive(dest);
        }

        /* Save tcp sequence for fullnat/nat, inside to outside */
        if (DPVS_FWD_MODE_NAT == cp->dest->fwdmode ||
                DPVS_FWD_MODE_FNAT == cp->dest->fwdmode) {
            cp->rs_end_seq = htonl(ntohl(th->seq) + 1);
            cp->rs_end_ack = th->ack_seq;
#ifdef CONFIG_DPVS_IPVS_DEBUG
            RTE_LOG(DEBUG, IPVS, "%s: packet from rs, seq = %u, ack_seq = %u, port %u => %u\n",
                    __func__, ntohl(th->seq), ntohl(th->ack_seq),
                    ntohs(th->source), ntohs(th->dest));
#endif
        }

        /* TODO: ip_vs_synproxy_save_fast_xmit_info ? */

        /* Free stored syn mbuf, no need for retransmition any more */
        if (cp->syn_mbuf) {
            rte_pktmbuf_free(cp->syn_mbuf);
            cp->syn_mbuf = NULL;
            sp_dbg_stats32_dec(sp_syn_saved);
        }

        if (list_empty(&cp->ack_mbuf)) {
            /*
             * FIXME: Maybe a bug here, print err msg and go.
             * Attention: cp->state has been changed and we
             * should still DROP the syn/ack mbuf.
             */
            RTE_LOG(ERR, IPVS, "%s: got ack_mbuf NULL pointer: ack-saved = %u\n",
                    __func__, cp->ack_num);
            *verdict = INET_DROP;
            return 0;
        }

        /* Window size has been set to zero in the syn-ack packet to Client.
         * If get more than one ack packet here,
         * it means client has sent a window probe after one RTO.
         * The probe will be forward to RS and RS will respond a window update.
         * So DPVS has no need to send a window update.
         */
        if (dp_vs_synproxy_ctrl_clwnd && !dp_vs_synproxy_ctrl_defer && cp->ack_num <= 1)
            syn_proxy_send_window_update(tuplehash_out(cp).af, mbuf, cp, pp, th);

        list_for_each_entry_safe(tmbuf, tmbuf2, &cp->ack_mbuf, list) {
            list_del_init(&tmbuf->list);
            cp->ack_num--;
            list_add_tail(&tmbuf->list, &save_mbuf);
        }
        assert(cp->ack_num == 0);

        list_for_each_entry_safe(tmbuf, tmbuf2, &save_mbuf, list) {
            list_del_init(&tmbuf->list);
            /* syn_mbuf will be freed correctly if xmit failed */
            cp->packet_xmit(pp, cp, tmbuf->mbuf);
            /* free dp_vs_synproxy_ack_pakcet */
            rte_mempool_put(this_ack_mbufpool, tmbuf);
            sp_dbg_stats32_dec(sp_ack_saved);
        }

        *verdict = INET_DROP;
        return 0;
    } else if ((th->rst) &&
            (cp->flags & DPVS_CONN_F_SYNPROXY) &&
            (cp->state == DPVS_TCP_S_SYN_SENT)) {
        RTE_LOG(DEBUG, IPVS, "%s: get rst from rs, seq = %u ack_seq = %u\n",
                __func__, ntohl(th->seq), ntohl(th->ack_seq));
        dp_vs_dest_detected_dead(dest);

        /* Count the delta of seq */
        cp->syn_proxy_seq.delta = ntohl(cp->syn_proxy_seq.isn) - ntohl(th->seq);
        cp->state = DPVS_TCP_S_CLOSE;
        cp->timeout.tv_sec = pp->timeout_table[cp->state];
        dpvs_time_rand_delay(&cp->timeout, 1000000);
        th->seq = htonl(ntohl(th->seq) + 1);
        //syn_proxy_seq_csum_update ?

        return 1;
    }
    return 1;
}

static inline int __syn_proxy_reuse_conn(struct dp_vs_conn *cp,
        struct rte_mbuf *ack_mbuf,
        struct tcphdr *th, struct dp_vs_proto *pp)
{
    struct dp_vs_synproxy_ack_pakcet *tmbuf, *tmbuf2;

    /* Free stored ack packet */
    list_for_each_entry_safe(tmbuf, tmbuf2, &cp->ack_mbuf, list) {
        list_del_init(&tmbuf->list);
        cp->ack_num--;
        rte_pktmbuf_free(tmbuf->mbuf);
        sp_dbg_stats32_dec(sp_ack_saved);
        rte_mempool_put(this_ack_mbufpool, tmbuf) ;
    }
    assert(cp->ack_num == 0);

    /* Free stored syn mbuf */
    if (cp->syn_mbuf) {
        rte_pktmbuf_free(cp->syn_mbuf);
        sp_dbg_stats32_dec(sp_syn_saved);
        cp->syn_mbuf = NULL;
    }

    /* Store new ack_mbuf */
    assert(list_empty(&cp->ack_mbuf));
    INIT_LIST_HEAD(&cp->ack_mbuf);

    if (unlikely(rte_mempool_get(this_ack_mbufpool, (void **)&tmbuf) != 0))
        return EDPVS_NOMEM;
    tmbuf->mbuf = ack_mbuf;
    list_add_tail(&tmbuf->list, &cp->ack_mbuf);
    sp_dbg_stats32_inc(sp_ack_saved);
    cp->ack_num++;

    /* Save ack_seq - 1 */
    cp->syn_proxy_seq.isn = htonl((uint32_t)((ntohl(th->ack_seq) - 1)));
    /* Do not change delta here, so original flow can still be valid */

    /* Save ack_seq */
    cp->fnat_seq.fdata_seq = ntohl(th->ack_seq);

    cp->fnat_seq.isn = 0;

    /* Clean duplicated ack count */
    rte_atomic32_set(&cp->dup_ack_cnt, 0);

    /* Set timeout value */
    cp->state = DPVS_TCP_S_SYN_SENT;
    cp->timeout.tv_sec = pp->timeout_table[cp->state];
    dpvs_time_rand_delay(&cp->timeout, 1000000);

    return EDPVS_OK;
}

/* Syn-proxy conn reuse logic: receive client's Ack.
 * Update syn_proxy_seq struct and clean syn-proxy related members. */
int dp_vs_synproxy_reuse_conn(int af, struct rte_mbuf *mbuf,
        struct dp_vs_conn *cp,
        struct dp_vs_proto *pp,
        const struct dp_vs_iphdr *iph, int *verdict)
{
    struct tcphdr _tcph, *th = NULL;
    struct dp_vs_synproxy_opt opt;
    int res_cookie_check;
    uint32_t tcp_conn_reuse_states = 0;
    int ret;

    th = mbuf_header_pointer(mbuf, iph->len, sizeof(_tcph), &_tcph);
    if (unlikely(!th)) {
        RTE_LOG(ERR, IPVS, "%s: mbuf has a invalid tcp header\n", __func__);
        *verdict = INET_DROP;
        return 0;
    }

    tcp_conn_reuse_states =
        (dp_vs_synproxy_ctrl_conn_reuse_cl << DPVS_TCP_S_CLOSE) |
        (dp_vs_synproxy_ctrl_conn_reuse_tw << DPVS_TCP_S_TIME_WAIT) |
        (dp_vs_synproxy_ctrl_conn_reuse_fw << DPVS_TCP_S_FIN_WAIT) |
        (dp_vs_synproxy_ctrl_conn_reuse_cw << DPVS_TCP_S_CLOSE_WAIT) |
        (dp_vs_synproxy_ctrl_conn_reuse_la << DPVS_TCP_S_LAST_ACK);
    if (((1 << (cp->state)) & tcp_conn_reuse_states) &&
            (cp->flags & DPVS_CONN_F_SYNPROXY) &&
            (!th->syn && th->ack && !th->rst && !th->fin) &&
            (cp->syn_proxy_seq.isn != htonl((uint32_t)(ntohl(th->ack_seq) - 1)))) {
        if (AF_INET6 == af)
            res_cookie_check = syn_proxy_v6_cookie_check(mbuf,
                    ntohl(th->ack_seq) - 1, &opt);
        else
            res_cookie_check = syn_proxy_v4_cookie_check(mbuf,
                    ntohl(th->ack_seq) - 1, &opt);
        if (!res_cookie_check) {
            /* Update statistics */
            dp_vs_estats_inc(SYNPROXY_BAD_ACK);
            /* Cookie check fail, let it go.
             * Attention: Do not drop the packet here! Do not print any log here.
             *            Because the session's last ACK may arrive here.*/
            return 1;
        }

        /* Update statistics */
        dp_vs_estats_inc(SYNPROXY_OK_ACK);
        dp_vs_estats_inc(SYNPROXY_CONN_REUSED);

        switch (cp->old_state) {
        case DPVS_TCP_S_CLOSE:
            dp_vs_estats_inc(SYNPROXY_CONN_REUSED_CLOSE);
            break;
        case DPVS_TCP_S_TIME_WAIT:
            dp_vs_estats_inc(SYNPROXY_CONN_REUSED_TIMEWAIT);
            break;
        case DPVS_TCP_S_FIN_WAIT:
            dp_vs_estats_inc(SYNPROXY_CONN_REUSED_FINWAIT);
            break;
        case DPVS_TCP_S_CLOSE_WAIT:
            dp_vs_estats_inc(SYNPROXY_CONN_REUSED_CLOSEWAIT);
            break;
        case DPVS_TCP_S_LAST_ACK:
            dp_vs_estats_inc(SYNPROXY_CONN_REUSED_LASTACK);
            break;
        }

        if (unlikely(EDPVS_OK != __syn_proxy_reuse_conn(cp, mbuf, th, pp))) {
            /* Release conn immediately */
            cp->timeout.tv_sec = 0;
        }

        if (unlikely(EDPVS_OK != (ret = syn_proxy_send_rs_syn(af, th, cp,
                            mbuf, pp, &opt)))) {
            RTE_LOG(ERR, IPVS, "%s: syn_proxy_send_rs_syn failed when reuse conn"
                    " -- %s\n", __func__, dpvs_strerror(ret));
            /* Release conn immediately */
            cp->timeout.tv_sec = 0;
        }

        *verdict = INET_STOLEN;
        return 0;
    }

    return 1;
}

/* Check and stop ack storm.
 * Return 0 if ack storm is found */
static int syn_proxy_is_ack_storm(struct tcphdr *tcph, struct dp_vs_conn *cp)
{
    /* Only for syn-proxy sessions */
    if (!(cp->flags & DPVS_CONN_F_SYNPROXY) || !tcph->ack)
        return 1;

    if (unlikely(dp_vs_synproxy_ctrl_dup_ack_thresh == 0))
        return 1;

    if(unlikely(tcph->seq == cp->last_seq &&
                tcph->ack_seq == cp->last_ack_seq)) {
        rte_atomic32_inc(&cp->dup_ack_cnt);
        if (rte_atomic32_read(&cp->dup_ack_cnt) >= dp_vs_synproxy_ctrl_dup_ack_thresh) {
            rte_atomic32_set(&cp->dup_ack_cnt, dp_vs_synproxy_ctrl_dup_ack_thresh);
            /* Update statisitcs */
            dp_vs_estats_inc(SYNPROXY_ACK_STORM);
            return 0;
        }

        return 1;
    }

    cp->last_seq = tcph->seq;
    cp->last_ack_seq = tcph->ack_seq;
    rte_atomic32_set(&cp->dup_ack_cnt, 0);

    return 1;
}

/* Transer seq for In-Out packet.
 * 1) Check and stop ack storm
 * 2) Update in-out seqs
 * Return 0 if ack storm is found and stopped. */
int dp_vs_synproxy_snat_handler(struct tcphdr *tcph, struct dp_vs_conn *cp)
{
    uint32_t old_seq;

    if (syn_proxy_is_ack_storm(tcph, cp) == 0)
        return 0;

    if (cp->syn_proxy_seq.delta) {
        old_seq = ntohl(tcph->seq);
        tcph->seq = htonl((uint32_t)(old_seq + cp->syn_proxy_seq.delta));
        //syn_proxy_seq_csum_update(tcph, htonl(old_seq), tch->seq);
#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, IPVS, "%s: tcph->seq %u => %u, delta = %u\n",
                __func__, old_seq, ntohl(tcph->seq), cp->syn_proxy_seq.delta);
#endif
    }

    return 1;
}

/* Store or drop client's ack packet, when dpvs is waiting for rs's Syn/Ack packet */
int dp_vs_synproxy_filter_ack(struct rte_mbuf *mbuf, struct dp_vs_conn *cp,
        struct dp_vs_proto *pp,
        const struct dp_vs_iphdr *iph, int *verdict)
{
    struct tcphdr _tcph, *th;
    struct dp_vs_synproxy_ack_pakcet *ack_mbuf;

    th = mbuf_header_pointer(mbuf, iph->len, sizeof(_tcph), &_tcph);
    if (unlikely(!th)) {
        RTE_LOG(ERR, IPVS, "%s: mbuf has an invalid tcp header\n", __func__);
        *verdict = INET_DROP;
        return 0;
    }

    if ((cp->flags & DPVS_CONN_F_SYNPROXY) &&
            (cp->state == DPVS_TCP_S_SYN_SENT)) {
        /* Not an ack packet, drop it */
        if (!th->ack) {
            *verdict = INET_DROP;
            return 0;
        }

        /* the length of ack list should be limited to avoid pktpool resource drained
         * when we does not recieve rs's reply to our syn in no time */
        if (dp_vs_synproxy_ctrl_max_ack_saved < cp->ack_num) {
            dp_vs_estats_inc(SYNPROXY_SYNSEND_QLEN);
            sp_dbg_stats64_inc(sp_ack_refused);
            *verdict = INET_DROP;
            return 0;
        }

        /* Store ack mbuf */
        if (unlikely(rte_mempool_get(this_ack_mbufpool, (void **)&ack_mbuf) != 0)) {
            RTE_LOG(ERR, IPVS, "%s: no memory\n", __func__);
            *verdict = INET_DROP;
            return 0;
        }

        ack_mbuf->mbuf = mbuf;
        list_add_tail(&ack_mbuf->list, &cp->ack_mbuf);
        cp->ack_num++;
        sp_dbg_stats32_inc(sp_ack_saved);

        *verdict = INET_STOLEN;
        return 0;
    }

    return 1;
}

static void synack_mss_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int mss;

    assert(str);
    mss = atoi(str);
    if (mss > 0 && mss < 65536) {
        RTE_LOG(INFO, IPVS, "synack_mss = %d\n", mss);
        dp_vs_synproxy_ctrl_init_mss = mss;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid synack_mss %s, using default %d\n",
                str, DP_VS_SYNPROXY_INIT_MSS_DEFAULT);
        dp_vs_synproxy_ctrl_init_mss = DP_VS_SYNPROXY_INIT_MSS_DEFAULT;
    }

    FREE_PTR(str);
}

static void synack_ttl_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int ttl;

    assert(str);
    ttl = atoi(str);
    if (ttl > 0 && ttl < 256) {
        RTE_LOG(INFO, IPVS, "synack_ttl = %d\n", ttl);
        dp_vs_synproxy_ctrl_synack_ttl = ttl;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid synack_ttl %s, using default %d\n",
                str, DP_VS_SYNPROXY_TTL_DEFAULT);
        dp_vs_synproxy_ctrl_synack_ttl = DP_VS_SYNPROXY_TTL_DEFAULT;
    }

    FREE_PTR(str);
}

static void synack_sack_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_synack_options_sack ON\n");
    dp_vs_synproxy_ctrl_sack = 1;
}

static void synack_wscale_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int wscale;

    assert(str);
    wscale = atoi(str);
    if (wscale >= 0 && wscale <= DP_VS_SYNPROXY_WSCALE_MAX) {
        RTE_LOG(INFO, IPVS, "synproxy_synack_options_wscale = %d\n", wscale);
        dp_vs_synproxy_ctrl_wscale = wscale;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid synproxy_synack_options_wscale %s, using default %d\n",
                str, DP_VS_SYNPROXY_WSCALE_DEFAULT);
        dp_vs_synproxy_ctrl_init_mss = DP_VS_SYNPROXY_WSCALE_DEFAULT;
    }

    FREE_PTR(str);
}

static void synack_timestamp_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_synack_options_timestamp ON\n");
    dp_vs_synproxy_ctrl_timestamp = 1;
}

static void close_client_window_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "close_client_window ON\n");
    dp_vs_synproxy_ctrl_clwnd = 1;
}

static void defer_rs_syn_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_defer_rs_syn ON\n");
    dp_vs_synproxy_ctrl_defer = 1;
}

static void rs_syn_max_retry_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int max_retry;

    assert(str);
    max_retry = atoi(str);
    if (max_retry > 0 && max_retry < 100) {
        RTE_LOG(INFO, IPVS, "rs_syn_max_retry = %d\n", max_retry);
        dp_vs_synproxy_ctrl_syn_retry = max_retry;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid rs_syn_max_retry %s, using default %d\n",
                str, DP_VS_SYNPROXY_SYN_RETRY_DEFAULT);
        dp_vs_synproxy_ctrl_syn_retry = DP_VS_SYNPROXY_SYN_RETRY_DEFAULT;
    }

    FREE_PTR(str);
}

static void ack_storm_thresh_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int ack_thresh;
    assert(str);

    ack_thresh = atoi(str);
    if (ack_thresh > 0 && ack_thresh < 1000) {
        RTE_LOG(INFO, IPVS, "ack_storm_thresh = %d\n", ack_thresh);
        dp_vs_synproxy_ctrl_dup_ack_thresh = ack_thresh;
    } else {
        RTE_LOG(WARNING, IPVS, "invalid ack_storm_thresh %s, using default %d\n",
                str, DP_VS_SYNPROXY_DUP_ACK_DEFAULT);
        dp_vs_synproxy_ctrl_dup_ack_thresh = DP_VS_SYNPROXY_DUP_ACK_DEFAULT;
    }

    FREE_PTR(str);
}

static void max_ack_saved_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int max_ack;
    assert(str);

    max_ack = atoi(str);
    if (max_ack > 0 && max_ack < 64) {
        RTE_LOG(INFO, IPVS, "max_ack_saved = %d\n", max_ack);
        dp_vs_synproxy_ctrl_max_ack_saved = max_ack;
    } else {
        RTE_LOG(INFO, IPVS, "invalid max_ack_saved %s, using default %d\n",
                str, DP_VS_SYNPROXY_MAX_ACK_SAVED_DEFAULT);
        dp_vs_synproxy_ctrl_max_ack_saved = DP_VS_SYNPROXY_MAX_ACK_SAVED_DEFAULT;
    }

    FREE_PTR(str);
}

static void conn_reuse_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_conn_reuse ON\n");
    dp_vs_synproxy_ctrl_conn_reuse = 1;
}

static void conn_reuse_close_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_conn_reuse: CLOSE\n");
    dp_vs_synproxy_ctrl_conn_reuse_cl = 1;
}
static void conn_reuse_timewait_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_conn_reuse: TIMEWAIT\n");
    dp_vs_synproxy_ctrl_conn_reuse_tw = 1;
}

static void conn_reuse_finwait_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_conn_reuse: FINWAIT\n");
    dp_vs_synproxy_ctrl_conn_reuse_fw = 1;
}

static void conn_reuse_closewait_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_conn_reuse: CLOSEWAIT\n");
    dp_vs_synproxy_ctrl_conn_reuse_cw = 1;
}

static void conn_reuse_lastack_handler(vector_t tokens)
{
    RTE_LOG(INFO, IPVS, "synproxy_conn_reuse: LASTACK\n");
    dp_vs_synproxy_ctrl_conn_reuse_la = 1;
}

void synproxy_keyword_value_init(void)
{
    if (dpvs_state_get() == DPVS_STATE_INIT) {
        /* KW_TYPE_INIT keyword */
    }
    /* KW_TYPE_NORMAL keyword */
    dp_vs_synproxy_ctrl_init_mss = DP_VS_SYNPROXY_INIT_MSS_DEFAULT;
    dp_vs_synproxy_ctrl_sack = DP_VS_SYNPROXY_SACK_DEFAULT;
    dp_vs_synproxy_ctrl_wscale = DP_VS_SYNPROXY_WSCALE_DEFAULT;
    dp_vs_synproxy_ctrl_timestamp = DP_VS_SYNPROXY_TIMESTAMP_DEFAULT;
    dp_vs_synproxy_ctrl_synack_ttl = DP_VS_SYNPROXY_TTL_DEFAULT;
    dp_vs_synproxy_ctrl_clwnd = DP_VS_SYNPROXY_CLWND_DEFAULT;
    dp_vs_synproxy_ctrl_defer = DP_VS_SYNPROXY_DEFER_DEFAULT;
    dp_vs_synproxy_ctrl_conn_reuse = DP_VS_SYNPROXY_CONN_REUSE_DEFAULT;
    dp_vs_synproxy_ctrl_conn_reuse_cl = DP_VS_SYNPROXY_CONN_REUSE_CL_DEFAULT;
    dp_vs_synproxy_ctrl_conn_reuse_tw = DP_VS_SYNPROXY_CONN_REUSE_TW_DEFAULT;
    dp_vs_synproxy_ctrl_conn_reuse_fw = DP_VS_SYNPROXY_CONN_REUSE_FW_DEFAULT;
    dp_vs_synproxy_ctrl_conn_reuse_cw = DP_VS_SYNPROXY_CONN_REUSE_CW_DEFAULT;
    dp_vs_synproxy_ctrl_conn_reuse_la = DP_VS_SYNPROXY_CONN_REUSE_LA_DEFAULT;
    dp_vs_synproxy_ctrl_dup_ack_thresh = DP_VS_SYNPROXY_DUP_ACK_DEFAULT;
    dp_vs_synproxy_ctrl_max_ack_saved = DP_VS_SYNPROXY_MAX_ACK_SAVED_DEFAULT;
    dp_vs_synproxy_ctrl_syn_retry = DP_VS_SYNPROXY_SYN_RETRY_DEFAULT;
}

void install_synproxy_keywords(void)
{
    install_keyword("synproxy", NULL, KW_TYPE_NORMAL);

    install_sublevel();
    install_keyword("synack_options", NULL, KW_TYPE_NORMAL);

    install_sublevel();
    install_keyword("mss", synack_mss_handler, KW_TYPE_NORMAL);
    install_keyword("ttl", synack_ttl_handler, KW_TYPE_NORMAL);
    install_keyword("sack", synack_sack_handler, KW_TYPE_NORMAL);
    install_keyword("wscale", synack_wscale_handler, KW_TYPE_NORMAL);
    install_keyword("timestamp", synack_timestamp_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("close_client_window", close_client_window_handler, KW_TYPE_NORMAL);
    install_keyword("defer_rs_syn", defer_rs_syn_handler, KW_TYPE_NORMAL);
    install_keyword("rs_syn_max_retry", rs_syn_max_retry_handler, KW_TYPE_NORMAL);
    install_keyword("ack_storm_thresh", ack_storm_thresh_handler, KW_TYPE_NORMAL);
    install_keyword("max_ack_saved", max_ack_saved_handler, KW_TYPE_NORMAL);

    install_keyword("conn_reuse_state", conn_reuse_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("close", conn_reuse_close_handler, KW_TYPE_NORMAL);
    install_keyword("time_wait", conn_reuse_timewait_handler, KW_TYPE_NORMAL);
    install_keyword("fin_wait", conn_reuse_finwait_handler, KW_TYPE_NORMAL);
    install_keyword("close_wait", conn_reuse_closewait_handler, KW_TYPE_NORMAL);
    install_keyword("last_ack", conn_reuse_lastack_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_sublevel_end();
}
