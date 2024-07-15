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
 *
 * UDP Option of Address (UOA) Kernel Module for Real Server.
 * it refers TOA of LVS and ip_vs kernel module.
 *
 * raychen@qiyi.com, Feb 2018, initial.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <asm/pgtable_types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#include <net/ipv6.h> /* ipv6_skip_exthdr */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define HAVE_PROC_OPS
#endif

#define UOA_NEED_EXTRA
#include "uoa_extra.h"
#include "uoa.h"

struct kr_ipopt_uoa {
    __u8                    op_code;
    __u8                    op_len;
    __be16                  op_port;
    union inet_addr         op_addr;
} __attribute__((__packed__));

/* uoa mapping hash table */
struct uoa_map {
    struct hlist_node       hlist;
    atomic_t                refcnt;
    struct timer_list       timer;

    /* tuples as hash key */
    __be16                  af;
    union inet_addr         saddr;
    union inet_addr         daddr;
    __be16                  sport;
    __be16                  dport;

    struct kr_ipopt_uoa     optuoa;
};

static int uoa_debug = 0;
module_param_named(uoa_debug, uoa_debug, int, 0444);
MODULE_PARM_DESC(uoa_debug, "enable UOA debug by setting it to 1");

static int uoa_map_timeout = 360;
module_param_named(uoa_map_timeout, uoa_map_timeout, int, 0444);
MODULE_PARM_DESC(uoa_map_timeout, "UOA mapping timeout in second");

static int uoa_map_tab_bits = 12;
module_param_named(uoa_map_tab_bits, uoa_map_tab_bits, int, 0444);
MODULE_PARM_DESC(uoa_map_tab_bits, "UOA mapping table hash size");

static int uoa_hook_forward = 0;
module_param_named(uoa_hook_forward, uoa_hook_forward, int, 0444);
MODULE_PARM_DESC(uoa_hook_forward, "also parse UOA data in netfilter FORWARD chain (INPUT chain only by default)");

static int uoa_map_tab_size __read_mostly;
static int uoa_map_tab_mask __read_mostly;

static struct hlist_head *uoa_map_tab __read_mostly; /* mapping table */
static struct kmem_cache *uoa_map_cache __read_mostly;
static unsigned int uoa_map_rnd __read_mostly;

static atomic_t uoa_map_count = ATOMIC_INIT(0);
static int ipv6_hdrlen(const struct sk_buff *skb);

/* uoa mapping table lock array */
#define UOA_MAP_LOCKARR_BITS    5
#define UOA_MAP_LOCKARR_SIZE    (1<<UOA_MAP_LOCKARR_BITS)
#define UOA_MAP_LOCKARR_MASK    (UOA_MAP_LOCKARR_SIZE-1)

struct uoa_map_lock {
    spinlock_t        lock;
} __attribute__((__aligned__(SMP_CACHE_BYTES)));

static struct uoa_map_lock
__uoa_map_tab_lock_array[UOA_MAP_LOCKARR_SIZE] __cacheline_aligned;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void uoa_map_expire(struct timer_list *timer);
#else
static void uoa_map_expire(unsigned long data);
#endif

static inline void um_lock_bh(unsigned int hash)
{
    int i = hash & UOA_MAP_LOCKARR_MASK;

    spin_lock_bh(&__uoa_map_tab_lock_array[i].lock);
}

static inline void um_unlock_bh(unsigned int hash)
{
    int i = hash & UOA_MAP_LOCKARR_MASK;

    spin_unlock_bh(&__uoa_map_tab_lock_array[i].lock);
}

/* per-cpu and global statistics */
struct uoa_stats {
    struct uoa_kstats kstats;
    spinlock_t lock;
    struct uoa_cpu_stats __percpu *cpustats;
};

static struct uoa_stats uoa_stats;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#define UOA_STATS_INC(_f_) do { \
    struct uoa_cpu_stats *s = this_cpu_ptr(uoa_stats.cpustats); \
    u64_stats_update_begin(&s->syncp); \
    s->_f_++; \
    u64_stats_update_end(&s->syncp); \
    uoa_stats.kstats._f_++; \
} while (0)
#else
#define UOA_STATS_INC(_f_) do { \
    struct uoa_cpu_stats *s = this_cpu_ptr(uoa_stats.cpustats); \
    s->_f_++; \
    uoa_stats.kstats._f_++; \
} while (0)
#endif

static int uoa_stats_show(struct seq_file *seq, void *arg)
{
    struct uoa_kstats ks;

    spin_lock_bh(&uoa_stats.lock);
    ks = uoa_stats.kstats;
    spin_unlock_bh(&uoa_stats.lock);

    seq_puts(seq, " Success     Miss  Invalid|UOA  Got     None    Saved Ack-Fail\n");

    seq_printf(seq, "%8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
               ks.success, ks.miss, ks.invalid,
               ks.uoa_got, ks.uoa_none, ks.uoa_saved, ks.uoa_ack_fail);

    return 0;
}

static int uoa_stats_percpu_show(struct seq_file *seq, void *arg)
{
    int i;

    seq_puts(seq, "CPU  Success     Miss  Invalid|UOA  Got     None    Saved Ack-Fail\n");

    for_each_possible_cpu(i) {
        struct uoa_cpu_stats *s = per_cpu_ptr(uoa_stats.cpustats, i);
        __u64 success, miss, invalid, got, none, saved, ack_fail;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
        unsigned int start;

        do {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0) || \
    ( defined(RHEL_MAJOR) && ((RHEL_MAJOR == 9 && RHEL_MINOR > 3) || RHEL_MAJOR > 9))
            start = u64_stats_fetch_begin(&s->syncp);
#else
            start = u64_stats_fetch_begin_irq(&s->syncp);
#endif
#endif
            success  = s->success;
            miss     = s->miss;
            invalid  = s->invalid;
            got      = s->uoa_got;
            none     = s->uoa_none;
            saved    = s->uoa_saved;
            ack_fail = s->uoa_ack_fail;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0) || \
    ( defined(RHEL_MAJOR) && ((RHEL_MAJOR == 9 && RHEL_MINOR > 3) || RHEL_MAJOR > 9))
        } while (u64_stats_fetch_retry(&s->syncp, start));
#else
        } while (u64_stats_fetch_retry_irq(&s->syncp, start));
#endif
#endif

        seq_printf(seq,
                   "%3X  %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
                   i, success, miss, invalid, got, none, saved, ack_fail);
    }

    return 0;
}

static int uoa_stats_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, uoa_stats_show, NULL);
}

static int uoa_stats_percpu_seq_open(struct inode *inode, struct file *file)
{
    return single_open(file, uoa_stats_percpu_show, NULL);
}

#ifdef HAVE_PROC_OPS
static const struct proc_ops uoa_stats_fops = {
    .proc_open = uoa_stats_seq_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops uoa_stats_percpu_fops = {
    .proc_open = uoa_stats_percpu_seq_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations uoa_stats_fops = {
    .owner      = THIS_MODULE,
    .open       = uoa_stats_seq_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static const struct file_operations uoa_stats_percpu_fops = {
    .owner      = THIS_MODULE,
    .open       = uoa_stats_percpu_seq_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};
#endif

static int uoa_stats_init(void)
{
    int i;

    spin_lock_init(&uoa_stats.lock);
    memset(&uoa_stats.kstats, 0, sizeof(struct uoa_kstats));

    uoa_stats.cpustats = alloc_percpu(struct uoa_cpu_stats);
    if (!uoa_stats.cpustats) {
        pr_err("fail to alloc percpu stats\n");
        return -ENOMEM;
    }

    for_each_possible_cpu(i) {
        struct uoa_cpu_stats *cs;

        cs = per_cpu_ptr(uoa_stats.cpustats, i);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
        u64_stats_init(&cs->syncp);
#endif
    }

    proc_create("uoa_stats", 0, init_net.proc_net, &uoa_stats_fops);
    proc_create("uoa_stats_percpu", 0, init_net.proc_net,
                &uoa_stats_percpu_fops);

    return 0;
}

static void uoa_stats_exit(void)
{
    remove_proc_entry("uoa_stats", init_net.proc_net);
    remove_proc_entry("uoa_stats_percpu", init_net.proc_net);
    free_percpu(uoa_stats.cpustats);
}

static inline void uoa_map_dump(const struct uoa_map *um, const char *pref)
{
    int real_af;

    if (likely(!uoa_debug))
      return;

    if (um->optuoa.op_len == IPOLEN_UOA_IPV6)
        real_af = AF_INET6;
    else
        real_af = AF_INET;

    if (AF_INET == um->af) {
        if (real_af == AF_INET) {
            pr_info("%s %pI4:%d->%pI4:%d real %pI4:%d, refcnt %d\n", pref ? : "",
                    &um->saddr.in, ntohs(um->sport), &um->daddr.in, ntohs(um->dport),
                    &um->optuoa.op_addr.in, ntohs(um->optuoa.op_port),
                    atomic_read(&um->refcnt));
        } else {
            pr_info("%s %pI4:%d->%pI4:%d real [%pI6]:%d, refcnt %d\n", pref ? : "",
                    &um->saddr.in, ntohs(um->sport), &um->daddr.in, ntohs(um->dport),
                    &um->optuoa.op_addr.in6, ntohs(um->optuoa.op_port),
                    atomic_read(&um->refcnt));
        }
    } else {
        if (real_af == AF_INET) {
            pr_info("%s [%pI6]:%d->[%pI6]:%d real %pI4:%d, refcnt %d\n", pref ? : "",
                    &um->saddr.in6, ntohs(um->sport), &um->daddr.in6, ntohs(um->dport),
                    &um->optuoa.op_addr.in, ntohs(um->optuoa.op_port),
                    atomic_read(&um->refcnt));
        } else {
            pr_info("%s [%pI6]:%d->[%pI6]:%d real [%pI6]:%d, refcnt %d\n", pref ? : "",
                    &um->saddr.in6, ntohs(um->sport), &um->daddr.in6, ntohs(um->dport),
                    &um->optuoa.op_addr.in6, ntohs(um->optuoa.op_port),
                    atomic_read(&um->refcnt));
        }
    }
}

static inline unsigned int __uoa_map_hash_key(__be16 af,
                                              const union inet_addr *saddr,
                                              const union inet_addr *daddr,
                                              __be16 sport, __be16 dport)
{
    /* do not cal daddr, it could be zero for wildcard lookup */
    uint32_t saddr_fold;
    saddr_fold = inet_addr_fold(af, saddr);
    return jhash_3words(saddr_fold, sport, dport, uoa_map_rnd) &
        uoa_map_tab_mask;
}

static inline unsigned int uoa_map_hash_key(const struct uoa_map *um)
{
    return __uoa_map_hash_key(um->af, &um->saddr, &um->daddr,
                              um->sport, um->dport);
}

static inline void uoa_map_hash(struct uoa_map *um)
{
    unsigned int hash = uoa_map_hash_key(um);
    struct hlist_head *head = &uoa_map_tab[hash];
    struct uoa_map *cur;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
    struct hlist_node *node;
#endif

    um_lock_bh(hash);

    /* overwrite existing mapping */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
    hlist_for_each_entry_rcu(cur, head, hlist) {
#else
    hlist_for_each_entry_rcu(cur, node, head, hlist) {
#endif
        if (um->af == cur->af &&
            inet_addr_equal(um->af, &um->saddr, &cur->saddr) &&
            inet_addr_equal(um->af, &um->daddr, &cur->daddr) &&
            um->sport == cur->sport &&
            um->dport == cur->dport) {
            /* update */
            memmove(&cur->optuoa, &um->optuoa, sizeof(cur->optuoa));
            mod_timer(&cur->timer, jiffies + uoa_map_timeout * HZ);

            kmem_cache_free(uoa_map_cache, um);

            uoa_map_dump(cur, "update:");
            goto hashed;
        }
    }

    /* not exist */
    hlist_add_head_rcu(&um->hlist, head);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    timer_setup(&um->timer, uoa_map_expire, 0);
#else
    setup_timer(&um->timer, uoa_map_expire, (unsigned long)um);
#endif
    mod_timer(&um->timer, jiffies + uoa_map_timeout * HZ);

    atomic_inc(&uoa_map_count);
    uoa_map_dump(um, "new:");

hashed:
    um_unlock_bh(hash);
}

static inline int uoa_map_unhash(struct uoa_map *um)
{
    unsigned int hash = uoa_map_hash_key(um);
    int err = -1;

    um_lock_bh(hash);
    if (atomic_read(&um->refcnt) == 0) {
        hlist_del_rcu(&um->hlist);
        atomic_dec(&uoa_map_count);
        err = 0;
    }
    um_unlock_bh(hash);

    return err;
}

static inline struct uoa_map *uoa_map_get(__be16 af,
                                          union inet_addr *saddr,
                                          union inet_addr *daddr,
                                          __be16 sport, __be16 dport)
{
    unsigned int hash = __uoa_map_hash_key(af, saddr, daddr, sport, dport);
    struct hlist_head *head = &uoa_map_tab[hash];
    struct uoa_map *um = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
    struct hlist_node *node;
#endif

    um_lock_bh(hash);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
    hlist_for_each_entry_rcu(um, head, hlist) {
#else
    hlist_for_each_entry_rcu(um, node, head, hlist) {
#endif
        /* we allow daddr being set to wildcard (zero),
        * since UDP server may bind INADDR_ANY */
        if (um->af == af &&
            inet_addr_equal(af, &um->saddr, saddr) &&
                (inet_is_addr_any(af, daddr) ||
                 inet_addr_equal(af, &um->daddr, daddr)) &&
            um->sport == sport &&
            um->dport == dport) {
            mod_timer(&um->timer, jiffies + uoa_map_timeout * HZ);
            atomic_inc(&um->refcnt);

            um_unlock_bh(hash);
            return um;
        }
    }

    um_unlock_bh(hash);

    return NULL;
}

static inline void uoa_map_put(struct uoa_map *um)
{
    atomic_dec(&um->refcnt);
}

static inline void __uoa_map_expire(struct uoa_map *um, struct timer_list *timer)
{
    if (uoa_map_unhash(um) != 0) {
        /* try again if some one is using it */
        mod_timer(timer, jiffies + uoa_map_timeout * HZ);

        uoa_map_dump(um, "expire delayed:");
        return;
    }

    uoa_map_dump(um, "del:");
    del_timer(&um->timer);
    kmem_cache_free(uoa_map_cache, um);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void uoa_map_expire(struct timer_list *timer)
{
    struct uoa_map *um = from_timer(um, timer, timer);

    __uoa_map_expire(um, timer);
}
#else
static void uoa_map_expire(unsigned long data)
{
    struct uoa_map *um = (struct uoa_map *)data;

    __uoa_map_expire(um, &um->timer);
}
#endif

static void uoa_map_flush(void)
{
    int i;

flush_again:
    for (i = 0; i < uoa_map_tab_size; i++) {
        struct uoa_map *um;
        struct hlist_node *n;
        struct hlist_head *head = &uoa_map_tab[i];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
        struct hlist_node *node;
#endif

        um_lock_bh(i);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
        hlist_for_each_entry_safe(um, n, head, hlist) {
#else
        hlist_for_each_entry_safe(um, node, n, head, hlist) {
#endif
            if (timer_pending(&um->timer))
                del_timer(&um->timer);

            if (atomic_read(&um->refcnt) != 0)
                continue;

            uoa_map_dump(um, "flu:");

            hlist_del_rcu(&um->hlist);
            atomic_dec(&uoa_map_count);
            kmem_cache_free(uoa_map_cache, um);
        }

        um_unlock_bh(i);
    }

    if (atomic_read(&uoa_map_count) > 0) {
        pr_debug("%s: again\n", __func__);
        schedule();
        goto flush_again;
    }
}

static int uoa_so_set(struct sock *sk, int cmd,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
            void __user *user,
#else
            sockptr_t arg,
#endif
            unsigned int len)
{
    return 0;
}

static int uoa_so_get(struct sock *sk, int cmd, void __user *user, int *len)
{
    struct uoa_param_map map;
    struct uoa_map *um;
    int err;

    if (cmd != UOA_SO_GET_LOOKUP) {
        pr_warn("%s: bad cmd\n", __func__);
        return -EINVAL;
    }

    if (*len < sizeof(struct uoa_param_map)) {
        pr_warn("%s: bad param len\n", __func__);
        return -EINVAL;
    }

    if (copy_from_user(&map, user, sizeof(struct uoa_param_map)) != 0)
        return -EFAULT;

    /* lookup uap mapping table */
    um = uoa_map_get(map.af, &map.saddr, &map.daddr, map.sport, map.dport);

    if (!um) {
        if (uoa_debug) {
            if (AF_INET == map.af) {
                pr_warn("%s: not found: %pI4:%d->%pI4:%d\n", __func__,
                        &map.saddr.in, ntohs(map.sport),
                        &map.daddr.in, ntohs(map.dport));
            } else {
                pr_warn("%s: not found: [%pI6]:%d->[%pI6]:%d\n", __func__,
                        &map.saddr.in6, ntohs(map.sport),
                        &map.daddr.in6, ntohs(map.dport));
            }
        }
        UOA_STATS_INC(miss);
        return -ENOENT;
    }

    uoa_map_dump(um, "hit:");

    if (likely(um->optuoa.op_code == IPOPT_UOA)) {
        if (um->optuoa.op_len == IPOLEN_UOA_IPV4) {
            map.real_af = AF_INET;
            memmove(&map.real_saddr.in, &um->optuoa.op_addr.in,
                        sizeof(map.real_saddr.in));
            map.real_sport = um->optuoa.op_port;
            UOA_STATS_INC(success);
            err = 0;
        } else {
            if (um->optuoa.op_len == IPOLEN_UOA_IPV6) {
                map.real_af = AF_INET6;
                memmove(&map.real_saddr.in6, &um->optuoa.op_addr.in6,
                            sizeof(map.real_saddr.in6));
                map.real_sport = um->optuoa.op_port;
                UOA_STATS_INC(success);
                err = 0;
            } else {
                UOA_STATS_INC(invalid);
                err = -EFAULT;
            }
        }
    } else {
        UOA_STATS_INC(invalid);
        err = -EFAULT;
    }

    if (copy_to_user(user, &map, sizeof(struct uoa_param_map)) != 0)
        err = -EFAULT;
    *len = sizeof(struct uoa_param_map);

    uoa_map_put(um);

    return err;
}

static struct nf_sockopt_ops uoa_sockopts = {
    .pf          = PF_INET,
    .owner        = THIS_MODULE,
    /* set */
    .set_optmin    = UOA_BASE_CTL,
    .set_optmax    = UOA_SO_SET_MAX + 1,
    .set        = uoa_so_set,
    /* get */
    .get_optmin    = UOA_BASE_CTL,
    .get_optmax    = UOA_SO_GET_MAX + 1,
    .get        = uoa_so_get,
};

static int uoa_map_init(void)
{
    int i, err;

    /* mapping table */
    uoa_map_tab_size = 1 << uoa_map_tab_bits;
    uoa_map_tab_mask = uoa_map_tab_size - 1;

    uoa_map_tab = vmalloc(uoa_map_tab_size * sizeof(*uoa_map_tab));
    if (!uoa_map_tab) {
        pr_err("no memory for uoa mapping table\n");
        return -ENOMEM;
    }

    atomic_set(&uoa_map_count, 0);
    get_random_bytes(&uoa_map_rnd, sizeof(uoa_map_rnd));

    for (i = 0; i < uoa_map_tab_size; i++)
        INIT_HLIST_HEAD(&uoa_map_tab[i]);

    for (i = 0; i < UOA_MAP_LOCKARR_SIZE; i++)
        spin_lock_init(&__uoa_map_tab_lock_array[i].lock);

    /* mapping cache */
    uoa_map_cache = kmem_cache_create("uoa_map",
                                      sizeof(struct uoa_map), 0,
                                      SLAB_HWCACHE_ALIGN, NULL);
    if (!uoa_map_cache) {
        pr_err("fail to create uoa_map cache\n");
        vfree(uoa_map_tab);
        return -ENOMEM;
    }

    /* socket option */
    err = nf_register_sockopt(&uoa_sockopts);
    if (err != 0) {
        pr_err("fail to register sockopt\n");
        kmem_cache_destroy(uoa_map_cache);
        vfree(uoa_map_tab);
        return -ENOMEM;
    }

    pr_debug("mapping hash initialed, size %d\n", uoa_map_tab_size);
    return 0;
}

static void uoa_map_exit(void)
{
    nf_unregister_sockopt(&uoa_sockopts);
    kmem_cache_destroy(uoa_map_cache);
    vfree(uoa_map_tab);
}

/*
 * "ACK" is an empty payload UDP/IP packet.
 * UOA sender (LB) will handle the "ACK" and eat it,
 * it should not be forwarded by LB to original UDP sender.
 */
static int uoa_send_ack(const struct sk_buff *oskb)
{
    /* TODO: */
    return 0;
}

static struct uoa_map *uoa_parse_ipopt(__be16 af, unsigned char *optptr,
                                       int optlen, void *iph,
                                       __be16 sport, __be16 dport)
{
    int l;
    struct uoa_map *um = NULL;

    for (l = optlen; l > 0; ) {
        switch (*optptr) {
            case IPOPT_END:
                break;
            case IPOPT_NOOP:
                l--;
                optptr++;
                continue;
        }

        if (unlikely(l < 2))
            goto out; /* invalid */

        optlen = optptr[1];
        if (unlikely(optlen < 2 || optlen > l))
            goto out; /* invalid */

        if (*optptr == IPOPT_UOA) {
            UOA_STATS_INC(uoa_got);
            um = kmem_cache_alloc(uoa_map_cache, GFP_ATOMIC);
            if (!um) {
                UOA_STATS_INC(uoa_miss);
                goto out;
            }

            atomic_set(&um->refcnt, 0);
            um->af = af;
            if (AF_INET == af) {
                memmove(&um->saddr.in, &((struct iphdr *)iph)->saddr,
                            sizeof(struct in_addr));
                memmove(&um->daddr.in, &((struct iphdr *)iph)->daddr,
                            sizeof(struct in_addr));
            } else {
                /* ipv6 */
                memmove(&um->saddr.in6, &((struct ipv6hdr *)iph)->saddr,
                            sizeof(struct in6_addr));
                memmove(&um->daddr.in6, &((struct ipv6hdr *)iph)->daddr,
                            sizeof(struct in6_addr));
            }
            um->sport = sport;
            um->dport = dport;
            memcpy(&um->optuoa, optptr, optlen);

            UOA_STATS_INC(uoa_saved);
            return um;
        }

        l -= optlen;
        optptr += optlen;
        continue;
    }

    /* no UOA option */
    UOA_STATS_INC(uoa_none);

out:
    return NULL;
}

/* get uoa info from uoa-option in IP header. */
static struct uoa_map *uoa_iph_rcv(const struct iphdr *iph, struct sk_buff *skb)
{
    struct udphdr *uh;
    int optlen;
    unsigned char *optptr;
    struct uoa_map *um = NULL;

    if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))
        return NULL;

    uh = (void *)iph + ip_hdrlen(skb);

    optlen = ip_hdrlen(skb) - sizeof(struct iphdr);
    optptr = (unsigned char *)(iph + 1);

    um = uoa_parse_ipopt(AF_INET, optptr, optlen,
                         (void *)iph, uh->source, uh->dest);

    if (um && uoa_send_ack(skb) != 0) {
        UOA_STATS_INC(uoa_ack_fail);
        pr_warn("fail to send UOA ACK\n");
    }

    return um;
}

/* get uoa info from private option protocol. */
static struct uoa_map *uoa_opp_rcv(__be16 af, void *iph, struct sk_buff *skb)
{
    struct opphdr *opph;
    struct udphdr *uh;
    int optlen, opplen;
    unsigned char *optptr;
    struct uoa_map *um = NULL;
    int iphdrlen = ((AF_INET6 == af) ? ipv6_hdrlen(skb) : ip_hdrlen(skb));

    if (!pskb_may_pull(skb, iphdrlen + sizeof(struct opphdr)))
      return NULL;

    opph = iph + iphdrlen;
    opplen = ntohs(opph->length);

    if (unlikely(opph->protocol != IPPROTO_UDP)) {
        pr_warn("bad opp header\n");
        return NULL;
    }

    if (!pskb_may_pull(skb, iphdrlen + opplen + sizeof(*uh)))
      return NULL;

    uh = iph + iphdrlen + opplen;
    optlen = opplen - sizeof(*opph);
    optptr = (unsigned char *)(opph + 1);

    /* try parse UOA option from ip-options */
    um = uoa_parse_ipopt(af, optptr, optlen, iph, uh->source, uh->dest);

    if (um && uoa_send_ack(skb) != 0) {
        UOA_STATS_INC(uoa_ack_fail);
        pr_warn("fail to send UOA ACK\n");
    }

    /*
     * "remove" private option protocol, then adjust IP header
     * protocol, tot_len and checksum. these could be slow ?
     */

    skb_set_transport_header(skb, iphdrlen + opplen);

    /* Old kernel like 2.6.32 use "iph->ihl" rather "skb->transport_header"
     * to get UDP header offset. The UOA private protocol data should be
     * erased here, but this should move skb data and harm perfomance. As a
     * compromise, we convert the private protocol data into NOP IP option
     * data if possible.*/
    if (AF_INET == af) {
        if (((struct iphdr *)iph)->ihl + (opplen >> 2) < 16) {
            ((struct iphdr *)iph)->ihl += (opplen >> 2);
            /* need change it to parse transport layer */
            ((struct iphdr *)iph)->protocol = opph->protocol;
            memset(opph, IPOPT_NOOP, opplen);
        } else {
            pr_warn("IP header has no room to convert uoa data into option.\n");
        }
        /* re-calc checksum */
        ip_send_check(iph);
    } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
        /* do as upper ipv4, handle for old kernel version */
        int payload_len = ntohs(((struct ipv6hdr *)iph)->payload_len);
        ((struct ipv6hdr *)iph)->payload_len = htons(payload_len - opplen);
        ((struct ipv6hdr *)iph)->nexthdr = opph->protocol;
        memmove(iph + iphdrlen, uh, ntohs(uh->len));
        skb_set_transport_header(skb, iphdrlen);
#else
        ((struct ipv6hdr *)iph)->nexthdr = opph->protocol;
#endif
    }

    return um;
}

static struct uoa_map *uoa_skb_rcv_opt(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    __be16 af = ((6 == iph->version) ? AF_INET6 : AF_INET);

    if (AF_INET6 == af) {
        struct ipv6hdr *ip6h = ipv6_hdr(skb);
        if (ipv6_hdrlen(skb) != sizeof(struct ipv6hdr)) {
            if (uoa_debug) {
                pr_info("we not support uoa with ipv6 ext header now.");
            }
        }
        if (unlikely(ip6h->nexthdr == IPPROTO_OPT)) {
            return uoa_opp_rcv(af, (void *)ip6h, skb);
        }
    } else {
        if (unlikely(iph->ihl > 5) && iph->protocol == IPPROTO_UDP)
            return uoa_iph_rcv(iph, skb);
        else if (unlikely(iph->protocol == IPPROTO_OPT))
            return uoa_opp_rcv(af, (void *)iph, skb);
    }

    UOA_STATS_INC(uoa_none);
    return NULL;
}

/*
 * the definition of nf_hookfn changes a lot.
 * may need modify according to the Kernel version.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static unsigned int uoa_ip_local_in(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state)
#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)
static unsigned int uoa_ip_local_in(const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    const struct nf_hook_state *state)
#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,4)
static unsigned int uoa_ip_local_in(unsigned int hooknum,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
#else
#error "Pls modify the definition according to kernel version."
#endif
{
    struct uoa_map *um;

    um = uoa_skb_rcv_opt(skb);
    if (um)
        uoa_map_hash(um);

    return NF_ACCEPT;
}

/*
 * use nf LOCAL_IN hook to get UOA option.
 */
static struct nf_hook_ops uoa_nf_hook_ops[] __read_mostly = {
    {
        .hook        = uoa_ip_local_in,
        .pf          = NFPROTO_IPV4,
        .hooknum     = NF_INET_LOCAL_IN,
        .priority    = NF_IP_PRI_NAT_SRC + 1,
    },
    {
        // do NOT register unless module param `uoa_hook_forward` is enabled
        .hook        = uoa_ip_local_in,
        .pf          = NFPROTO_IPV4,
        .hooknum     = NF_INET_FORWARD,
        .priority    = NF_IP_PRI_LAST - 1,
    },
};

static struct nf_hook_ops uoa_nf_hook_ops6[] __read_mostly = {
    {
        .hook        = uoa_ip_local_in,
        .pf          = NFPROTO_IPV6,
        .hooknum     = NF_INET_LOCAL_IN,
        .priority    = NF_IP_PRI_NAT_SRC + 1,
    },
    {
        // do NOT register unless module param `uoa_hook_forward` is enabled
        .hook        = uoa_ip_local_in,
        .pf          = NFPROTO_IPV6,
        .hooknum     = NF_INET_FORWARD,
        .priority    = NF_IP_PRI_LAST - 1,
    },
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static int __net_init __uoa_init(struct net *net)
{
    int ret = -ENOMEM;

    ret = nf_register_net_hooks(net, uoa_nf_hook_ops, ARRAY_SIZE(uoa_nf_hook_ops));
    if (ret < 0)
        goto ops_hook_fail;

    ret = nf_register_net_hooks(&init_net, uoa_nf_hook_ops6,
                           ARRAY_SIZE(uoa_nf_hook_ops6));
    if (ret < 0)
        goto ops6_hook_fail;

    return 0;

/*
 * Error handling
 */
ops6_hook_fail:
    nf_unregister_net_hooks(net, uoa_nf_hook_ops,
                           ARRAY_SIZE(uoa_nf_hook_ops));
ops_hook_fail:
    return ret;
}

static void __net_exit __uoa_cleanup(struct net *net)
{
    nf_unregister_net_hooks(net, uoa_nf_hook_ops,
                            ARRAY_SIZE(uoa_nf_hook_ops));
    nf_unregister_net_hooks(&init_net, uoa_nf_hook_ops6,
                            ARRAY_SIZE(uoa_nf_hook_ops6));
}

static struct pernet_operations uoa_ops = {
    .init = __uoa_init,
    .exit = __uoa_cleanup,
};
#endif

static __init int uoa_init(void)
{
    int err = -ENOMEM;

    /* uoa mapping hash table. */
    err = uoa_map_init();
    if (err != 0)
        return err;

    /* statistics */
    err = uoa_stats_init();
    if (err != 0)
        goto stats_failed;

    /*
     * no way to hook udp_rcv() and udp_recvmsg() is difficult
     * to be overwirten since it handles multiple skbs.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
    err = register_pernet_device(&uoa_ops);
#else
    err = nf_register_hooks(uoa_nf_hook_ops,
            uoa_hook_forward ? ARRAY_SIZE(uoa_nf_hook_ops) : ARRAY_SIZE(uoa_nf_hook_ops) - 1);
    if (err < 0) {
        pr_err("fail to register netfilter hooks.\n");
        goto hook_failed;
    }
    err = nf_register_hooks(uoa_nf_hook_ops6,
            uoa_hook_forward ? ARRAY_SIZE(uoa_nf_hook_ops6) : ARRAY_SIZE(uoa_nf_hook_ops6) - 1);
#endif
    if (err < 0) {
        pr_err("fail to register netfilter hooks.\n");
        goto hook_failed;
    }

    pr_info("UOA module installed %s\n", uoa_debug ? "with debug" : "");
    return 0;

hook_failed:
    uoa_stats_exit();
stats_failed:
    uoa_map_exit();
    return err;
}

static __exit void uoa_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
    unregister_pernet_device(&uoa_ops);
#else
    nf_unregister_hooks(uoa_nf_hook_ops,
            uoa_hook_forward ? ARRAY_SIZE(uoa_nf_hook_ops) : ARRAY_SIZE(uoa_nf_hook_ops) - 1);
    nf_unregister_hooks(uoa_nf_hook_ops6,
            uoa_hook_forward ? ARRAY_SIZE(uoa_nf_hook_ops6) : ARRAY_SIZE(uoa_nf_hook_ops6) - 1);
#endif
    synchronize_net();

    uoa_stats_exit();

    uoa_map_flush();
    uoa_map_exit();

    pr_info("UOA module removed\n");
}

static int ipv6_hdrlen(const struct sk_buff *skb)
{
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    uint8_t ip6nxt = ip6h->nexthdr;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
    int ip6_hdrlen = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &ip6nxt);
#else
    __be16 frag_off;
    int ip6_hdrlen = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr),
            &ip6nxt, &frag_off);
#endif

    return (ip6_hdrlen >= 0) ? ip6_hdrlen : sizeof(struct ipv6hdr);
}

module_init(uoa_init);
module_exit(uoa_exit);
MODULE_LICENSE("GPL");
