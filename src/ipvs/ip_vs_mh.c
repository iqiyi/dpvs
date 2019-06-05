/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * The mh algorithm is to assign a preference list of all the lookup
 * table positions to each destination and populate the table with
 * the most-preferred position of destinations. Then it is to select
 * destination with the hash key of source IP address through looking
 * up a the lookup table.
 *
 * The algorithm is detailed in:
 * [3.4 Consistent Hasing]
 * https://www.usenix.org/system/files/conference/nsdi16/nsdi16-paper-eisenbud.pdf
 *
 * see net/netfilter/ipvs/ip_vs_mh.c for reference
 *
 * yangxingwu <xingwu.yang@gmail.com>, May 2019, initial.
 *
 */

#include "ipvs/siphash.h"
#include "ipvs/gcd.h"
#include "ipvs/mh.h"
#include "ipvs/kcompat.h"

#define DP_VS_SVC_F_SCHED_MH_FALLBACK   DP_VS_SVC_F_SCHED1 /* MH fallback */
#define DP_VS_SVC_F_SCHED_MH_PORT       DP_VS_SVC_F_SCHED2 /* MH use port */

struct dp_vs_mh_lookup {
    struct dp_vs_dest *dest; /* real server (cache) */
};

struct dp_vs_mh_dest_setup {
    unsigned int offset; /* starting offset */
    unsigned int skip; /* skip */
    unsigned int perm; /* next_offset */
    int turns; /* weight / gcd() and rshift */
};

/* Available prime numbers for MH table */
static int primes[] = {251, 509, 1021, 2039, 4093,
    8191, 16381, 32749, 65521, 131071};

/* For DPVS MH entry hash table */
#define CONFIG_DPVS_MH_TAB_INDEX   12
#define DPVS_MH_TAB_BITS           (CONFIG_DPVS_MH_TAB_INDEX / 2)
#define DPVS_MH_TAB_INDEX          (CONFIG_DPVS_MH_TAB_INDEX - 8)
#define DPVS_MH_TAB_SIZE           primes[DPVS_MH_TAB_INDEX]

struct dp_vs_mh_state {
    rte_rwlock_t lock;
    struct dp_vs_mh_lookup *lookup;
    struct dp_vs_mh_dest_setup *dest_setup;
    hsiphash_key_t hash1, hash2;
    int gcd;
    int rshift;
};

static inline void generate_hash_secret(hsiphash_key_t *hash1,
        hsiphash_key_t *hash2)
{
    hash1->key[0] = 2654435761UL;
    hash1->key[1] = 2654435761UL;

    hash2->key[0] = 2654446892UL;
    hash2->key[1] = 2654446892UL;
}

/* Helper function to determine if server is unavailable */
static inline bool is_unavailable(struct dp_vs_dest *dest)
{
    return rte_atomic16_read(&dest->weight) <= 0 ||
        dest->flags & DPVS_DEST_F_OVERLOAD;
}

/* Returns hash value for IPVS MH entry */
static inline unsigned int dp_vs_mh_hashkey(int af, const union inet_addr *addr,
        __be16 port, hsiphash_key_t *key, unsigned int offset)
{
    unsigned int v;
    __be32 addr_fold = inet_addr_fold(af, addr);

    v = (offset + ntohs(port) + ntohl(addr_fold));
    return hsiphash(&v, sizeof(v), key);
}

/* Reset all the hash buckets of the specified table. */
static void dp_vs_mh_reset(struct dp_vs_mh_state *s)
{
    int i;
    struct dp_vs_mh_lookup *l;

    rte_rwlock_write_lock(&s->lock);

    l = &s->lookup[0];
    for (i = 0; i < DPVS_MH_TAB_SIZE; i++) {
        if (l->dest)
            l->dest = NULL;
        l++;
    }

    rte_rwlock_write_unlock(&s->lock);
}

static int dp_vs_mh_permutate(struct dp_vs_mh_state *s,
        struct dp_vs_service *svc)
{
    struct list_head *p;
    struct dp_vs_mh_dest_setup *ds;
    struct dp_vs_dest *dest;
    int lw;

    /* If gcd is smaller then 1, number of dests or
     * all last_weight of dests are zero. So, skip
     * permutation for the dests.
     */
    if (s->gcd < 1)
        return 0;

    /* Set dest_setup for the dests permutation */
    p = &svc->dests;
    ds = &s->dest_setup[0];
    while ((p = p->next) != &svc->dests) {
        dest = list_entry(p, struct dp_vs_dest, n_list);

        ds->offset = dp_vs_mh_hashkey(svc->af, &dest->addr,
                dest->port, &s->hash1, 0) %
            DPVS_MH_TAB_SIZE;
        ds->skip = dp_vs_mh_hashkey(svc->af, &dest->addr,
                dest->port, &s->hash2, 0) %
            (DPVS_MH_TAB_SIZE - 1) + 1;
        ds->perm = ds->offset;

        lw = rte_atomic16_read(&dest->weight);
        ds->turns = ((lw / s->gcd) >> s->rshift) ? : (lw != 0);
        ds++;
    }

    return 0;
}

static int dp_vs_mh_populate(struct dp_vs_mh_state *s,
        struct dp_vs_service *svc)
{
    int n, c, dt_count;
    unsigned long *table;
    struct list_head *p;
    struct dp_vs_mh_dest_setup *ds;
    struct dp_vs_dest *dest, *new_dest;

    /* If gcd is smaller then 1, number of dests or
     * all last_weight of dests are zero. So, skip
     * the population for the dests and reset lookup table.
     */
    if (s->gcd < 1) {
        dp_vs_mh_reset(s);
        return 0;
    }

    table =  rte_calloc(NULL, BITS_TO_LONGS(DPVS_MH_TAB_SIZE),
            sizeof(unsigned long), RTE_CACHE_LINE_SIZE);
    if (!table)
        return EDPVS_NOMEM;

    p = &svc->dests;
    n = 0;
    dt_count = 0;
    while (n < DPVS_MH_TAB_SIZE) {
        if (p == &svc->dests)
            p = p->next;

        ds = &s->dest_setup[0];
        while (p != &svc->dests) {
            /* Ignore added server with zero weight */
            if (ds->turns < 1) {
                p = p->next;
                ds++;
                continue;
            }

            c = ds->perm;
#if 0
            while (test_bit(c, table)) {
                /* Add skip, mod DPVS_MH_TAB_SIZE */
                ds->perm += ds->skip;
                if (ds->perm >= DPVS_MH_TAB_SIZE)
                    ds->perm -= DPVS_MH_TAB_SIZE;
                c = ds->perm;
            }

            __set_bit(c, table);
#endif

            rte_rwlock_write_lock(&s->lock);
            new_dest = list_entry(p, struct dp_vs_dest, n_list);
            dest = s->lookup[c].dest;
            if (dest != new_dest)
                s->lookup[c].dest = new_dest;
            rte_rwlock_write_unlock(&s->lock);

            if (++n == DPVS_MH_TAB_SIZE)
                goto out;

            if (++dt_count >= ds->turns) {
                dt_count = 0;
                p = p->next;
                ds++;
            }
        }
    }

out:
    rte_free(table);
    return 0;
}

/* Get ip_vs_dest associated with supplied parameters. */
static inline struct dp_vs_dest *dp_vs_mh_get(struct dp_vs_service *svc,
        struct dp_vs_mh_state *s, const union inet_addr *addr, __be16 port)
{
    unsigned int hash = dp_vs_mh_hashkey(svc->af, addr, port, &s->hash1, 0)
        % DPVS_MH_TAB_SIZE;
    struct dp_vs_dest *dest = NULL;

    rte_rwlock_read_lock(&s->lock);
    dest = s->lookup[hash].dest;
    rte_rwlock_read_unlock(&s->lock);

    return (!dest || is_unavailable(dest)) ? NULL : dest;
}

/* As ip_vs_mh_get, but with fallback if selected server is unavailable */
static inline struct dp_vs_dest *dp_vs_mh_get_fallback(struct dp_vs_service *svc,
        struct dp_vs_mh_state *s, const union inet_addr *addr, __be16 port)
{
    unsigned int offset, roffset;
    unsigned int hash, ihash;
    struct dp_vs_dest *dest;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char buf[INET6_ADDRSTRLEN];
#endif

    /* First try the dest it's supposed to go to */
    ihash = dp_vs_mh_hashkey(svc->af, addr, port, &s->hash1, 0)
        % DPVS_MH_TAB_SIZE;
    rte_rwlock_read_lock(&s->lock);
    dest = s->lookup[ihash].dest;
    rte_rwlock_read_unlock(&s->lock);
    if (!dest)
        return NULL;
    if (!is_unavailable(dest))
        return dest;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, SERVICE,
            "MH: selected unavailable server %s:%u, reselecting",
            inet_ntop(dest->af, &dest->addr, buf, sizeof(buf)),
            ntohs(dest->port));
#endif

    /* If the original dest is unavailable, loop around the table
     * starting from ihash to find a new dest
     */
    for (offset = 0; offset < DPVS_MH_TAB_SIZE; offset++) {
        roffset = (offset + ihash) % DPVS_MH_TAB_SIZE;
        hash = dp_vs_mh_hashkey(svc->af, addr, port, &s->hash1,
                roffset) % DPVS_MH_TAB_SIZE;
        rte_rwlock_read_lock(&s->lock);
        dest = s->lookup[hash].dest;
        rte_rwlock_read_unlock(&s->lock);
        if (!dest)
            break;
        if (!is_unavailable(dest))
            return dest;

#ifdef CONFIG_DPVS_IPVS_DEBUG
        RTE_LOG(DEBUG, SERVICE,
                "MH: selected unavailable server %s:%u (offset %u), reselecting",
                inet_ntop(dest->af, &dest->addr, buf, sizeof(buf)),
                ntohs(dest->port), roffset);
#endif
    }

    return NULL;
}

/* Assign all the hash buckets of the specified table with the service. */
static int dp_vs_mh_reassign(struct dp_vs_mh_state *s,
        struct dp_vs_service *svc)
{
    int ret;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char buf[INET6_ADDRSTRLEN];
#endif

    if (svc->num_dests > DPVS_MH_TAB_SIZE)
        return EDPVS_INVAL;

    if (svc->num_dests >= 1) {
        s->dest_setup = rte_calloc(NULL, svc->num_dests,
                sizeof(struct dp_vs_mh_dest_setup), RTE_CACHE_LINE_SIZE);
        if (!s->dest_setup)
            return EDPVS_NOMEM;
    }

    dp_vs_mh_permutate(s, svc);

    ret = dp_vs_mh_populate(s, svc);
    if (ret < 0)
        goto out;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, SERVICE, "MH: reassign lookup table of %s:%u\n",
            inet_ntop(svc->af, &svc->addr, buf, sizeof(buf)),
            ntohs(svc->port));
#endif

out:
    if (svc->num_dests >= 1) {
        rte_free(s->dest_setup);
        s->dest_setup = NULL;
    }
    return ret;
}

static int dp_vs_mh_gcd_weight(struct dp_vs_service *svc)
{
    struct dp_vs_dest *dest;
    int weight;
    int g = 0;

    list_for_each_entry(dest, &svc->dests, n_list) {
        weight = rte_atomic16_read(&dest->weight);
        if (weight > 0) {
            if (g > 0)
                g = gcd(weight, g);
            else
                g = weight;
        }
    }
    return g;
}

/* To avoid assigning huge weight for the MH table,
 * calculate shift value with gcd.
 */
static int dp_vs_mh_shift_weight(struct dp_vs_service *svc, int gcd)
{
    struct dp_vs_dest *dest;
    int new_weight, weight = 0;
    int mw, shift;

    /* If gcd is smaller then 1, number of dests or
     * all last_weight of dests are zero. So, return
     * shift value as zero.
     */
    if (gcd < 1)
        return 0;

    list_for_each_entry(dest, &svc->dests, n_list) {
        new_weight = rte_atomic16_read(&dest->weight);
        if (new_weight > weight)
            weight = new_weight;
    }

    /* Because gcd is greater than zero,
     * the maximum weight and gcd are always greater than zero
     */
    mw = weight / gcd;

    /* shift = occupied bits of weight/gcd - MH highest bits */
    shift = fls(mw) - DPVS_MH_TAB_BITS;
    return (shift >= 0) ? shift : 0;
}

static void dp_vs_mh_state_free(rte_rwlock_t *lock)
{
    struct dp_vs_mh_state *s;

    s = container_of(lock, struct dp_vs_mh_state, lock);
    rte_free(s->lookup);
    rte_free(s);
}

static int dp_vs_mh_init_svc(struct dp_vs_service *svc)
{
    int ret;
    struct dp_vs_mh_state *s;

    /* Allocate the MH table for this service */
    s = rte_zmalloc(NULL, sizeof(*s), RTE_CACHE_LINE_SIZE);
    if (!s)
        return EDPVS_NOMEM;

    s->lookup = rte_calloc(NULL, DPVS_MH_TAB_SIZE,
            sizeof(struct dp_vs_mh_lookup), RTE_CACHE_LINE_SIZE);
    if (!s->lookup) {
        rte_free(s);
        return EDPVS_NOMEM;
    }

    generate_hash_secret(&s->hash1, &s->hash2);
    s->gcd = dp_vs_mh_gcd_weight(svc);
    s->rshift = dp_vs_mh_shift_weight(svc, s->gcd);

    RTE_LOG(INFO, SERVICE,
            "MH lookup table (memory=%zdbytes) allocated for current service\n",
            sizeof(struct dp_vs_mh_lookup) * DPVS_MH_TAB_SIZE);

    /* Assign the lookup table with current dests */
    ret = dp_vs_mh_reassign(s, svc);
    if (ret < 0) {
        dp_vs_mh_reset(s);
        dp_vs_mh_state_free(&s->lock);
        return ret;
    }

    /* No more failures, attach state */
    svc->sched_data = s;
    return 0;
}

static int dp_vs_mh_done_svc(struct dp_vs_service *svc)
{
    struct dp_vs_mh_state *s = svc->sched_data;

    /* Got to clean up lookup entry here */
    dp_vs_mh_reset(s);

    dp_vs_mh_state_free(&s->lock);
    RTE_LOG(DEBUG, SERVICE, "MH lookup table (memory=%zdbytes) released\n",
            sizeof(struct dp_vs_mh_lookup) * DPVS_MH_TAB_SIZE);

    return EDPVS_OK;
}

static int dp_vs_mh_dest_changed(struct dp_vs_service *svc,
        struct dp_vs_dest *dest, sockoptid_t opt __rte_unused)
{
    struct dp_vs_mh_state *s = svc->sched_data;

    s->gcd = dp_vs_mh_gcd_weight(svc);
    s->rshift = dp_vs_mh_shift_weight(svc, s->gcd);

    /* Assign the lookup table with the updated service */
    return dp_vs_mh_reassign(s, svc);
}

/* Helper function to get port number */
static inline __be16 dp_vs_mh_get_port(const struct rte_mbuf *mbuf,
        const struct dp_vs_iphdr *iph)
{
    __be16 _ports[2], *ports;

    /* At this point we know that we have a valid packet of some kind.
     * Because ICMP packets are only guaranteed to have the first 8
     * bytes, let's just grab the ports.  Fortunately they're in the
     * same position for all three of the protocols we care about.
     */
    switch (iph->proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            ports = mbuf_header_pointer(mbuf, iph->len, sizeof(_ports), _ports);
            if (unlikely(!ports))
                return 0;
            // always use source port
            return ports[0];
        default:
            return 0;
    }
}

/* Maglev Hashing scheduling */
static struct dp_vs_dest *dp_vs_mh_schedule(struct dp_vs_service *svc,
        const struct rte_mbuf *mbuf, const struct dp_vs_iphdr *iph)
{
    struct dp_vs_dest *dest;
    struct dp_vs_mh_state *s;
    __be16 port = 0;
    const union inet_addr *hash_addr;
#ifdef CONFIG_DPVS_IPVS_DEBUG
    char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
#endif

    // always use source address
    hash_addr = &iph->saddr;

#ifdef CONFIG_DPVS_IPVS_DEBUG
    RTE_LOG(DEBUG, SERVICE, "%s : Scheduling...\n", __func__);
#endif

    if (svc->flags & DP_VS_SVC_F_SCHED_MH_PORT)
        port = dp_vs_mh_get_port(mbuf, iph);

    s = (struct dp_vs_mh_state *)svc->sched_data;

    if (svc->flags & DP_VS_SVC_F_SCHED_MH_FALLBACK)
        dest = dp_vs_mh_get_fallback(svc, s, hash_addr, port);
    else
        dest = dp_vs_mh_get(svc, s, hash_addr, port);

#ifdef CONFIG_DPVS_IPVS_DEBUG
    if (dest)
        RTE_LOG(DEBUG, SERVICE, "MH: source IP address %s:%u -> server %s:%u\n",
                inet_ntop(svc->af, &iph->saddr, sbuf, sizeof(sbuf)),
                ntohs(port),
                inet_ntop(svc->af, &iph->daddr, dbuf, sizeof(dbuf)),
                ntohs(dest->port));
#endif

    return dest;
}

/* DPVS MH Scheduler structure */
static struct dp_vs_scheduler dp_vs_mh_scheduler = {
    .name           = "mh",
    .n_list         = LIST_HEAD_INIT(dp_vs_mh_scheduler.n_list),
    .schedule       = dp_vs_mh_schedule,
    .init_service   = dp_vs_mh_init_svc,
    .exit_service   = dp_vs_mh_done_svc,
    .update_service = dp_vs_mh_dest_changed,
};

int dp_vs_mh_init(void)
{
    return register_dp_vs_scheduler(&dp_vs_mh_scheduler);
}

int dp_vs_mh_term(void)
{
    return unregister_dp_vs_scheduler(&dp_vs_mh_scheduler);
}
