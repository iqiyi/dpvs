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
/*
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
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <asm/pgtable_types.h>

#include "uoa.h"

/* uoa mapping hash table */
struct uoa_map {
	struct hlist_node	hlist;
	atomic_t		refcnt;
	struct timer_list	timer;

	/* tuples as hash key */
	__be32			saddr;
	__be32			daddr;
	__be16			sport;
	__be16			dport;

	struct ipopt_uoa	optuoa;
};

static int uoa_debug = 0;
module_param_named(uoa_debug, uoa_debug, int, 0444);
MODULE_PARM_DESC(uoa_debug, "enable UOA debug by setting it to 1");

static int uoa_map_timeout = 60;
module_param_named(uoa_map_timeout, uoa_map_timeout, int, 0444);
MODULE_PARM_DESC(uoa_map_timeout, "UOA mapping timeout in second");

static int uoa_map_tab_bits = 12;
module_param_named(uoa_map_tab_bits, uoa_map_tab_bits, int, 0444);
MODULE_PARM_DESC(uoa_map_tab_bits, "UOA mapping table hash size");

static int uoa_map_tab_size __read_mostly;
static int uoa_map_tab_mask __read_mostly;

static struct hlist_head *uoa_map_tab __read_mostly; /* mapping table */
static struct kmem_cache *uoa_map_cache __read_mostly;
static unsigned int uoa_map_rnd __read_mostly;

static atomic_t uoa_map_count = ATOMIC_INIT(0);

/* uoa mapping table lock array */
#define UOA_MAP_LOCKARR_BITS	5
#define UOA_MAP_LOCKARR_SIZE	(1<<UOA_MAP_LOCKARR_BITS)
#define UOA_MAP_LOCKARR_MASK	(UOA_MAP_LOCKARR_SIZE-1)

struct uoa_map_lock {
	spinlock_t		lock;
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

#define UOA_STATS_INC(_f_) do { \
	struct uoa_cpu_stats *s = this_cpu_ptr(uoa_stats.cpustats); \
	u64_stats_update_begin(&s->syncp); \
	s->_f_++; \
	u64_stats_update_end(&s->syncp); \
	uoa_stats.kstats._f_++; \
} while (0)

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
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&s->syncp);

			success	= s->success;
			miss	= s->miss;
			invalid = s->invalid;
			got	= s->uoa_got;
			none	= s->uoa_none;
			saved   = s->uoa_saved;
			ack_fail = s->uoa_ack_fail;
		} while (u64_stats_fetch_retry_irq(&s->syncp, start));

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

static const struct file_operations uoa_stats_fops = {
	.owner		= THIS_MODULE,
	.open		= uoa_stats_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations uoa_stats_percpu_fops = {
	.owner		= THIS_MODULE,
	.open		= uoa_stats_percpu_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

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
		u64_stats_init(&cs->syncp);
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
	if (likely(!uoa_debug))
		return;

	pr_info("%s %pI4:%d->%pI4:%d real %pI4:%d\n", pref ? : "",
		&um->saddr, ntohs(um->sport), &um->daddr, ntohs(um->dport),
		&um->optuoa.op_addr, ntohs(um->optuoa.op_port));
}

static inline unsigned int __uoa_map_hash_key(__be32 saddr, __be32 daddr,
					      __be16 sport, __be16 dport)
{
	/* do not cal daddr, it could be zero for wildcard lookup */
	return jhash_3words(saddr, sport, dport, uoa_map_rnd) &
		uoa_map_tab_mask;
}

static inline unsigned int uoa_map_hash_key(const struct uoa_map *um)
{
	return __uoa_map_hash_key(um->saddr, um->daddr, um->sport, um->dport);
}

static inline void uoa_map_hash(struct uoa_map *um)
{
	unsigned int hash = uoa_map_hash_key(um);
	struct hlist_head *head = &uoa_map_tab[hash];
	struct uoa_map *cur;

	um_lock_bh(hash);

	/* overwrite existing mapping */
	hlist_for_each_entry_rcu(cur, head, hlist) {
		if (um->saddr == cur->saddr &&
		    um->daddr == cur->daddr &&
		    um->sport == cur->sport &&
		    um->dport == cur->dport) {
			/* update */
			memcpy(&cur->optuoa, &um->optuoa, IPOLEN_UOA);

			mod_timer(&cur->timer, jiffies + uoa_map_timeout * HZ);

			kmem_cache_free(uoa_map_cache, um);
		}

		uoa_map_dump(cur, "update:");
		goto hashed;
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

static inline struct uoa_map *uoa_map_get(__be32 saddr, __be32 daddr,
					  __be16 sport, __be16 dport)
{
	unsigned int hash = __uoa_map_hash_key(saddr, daddr, sport, dport);
	struct hlist_head *head = &uoa_map_tab[hash];
	struct uoa_map *um = NULL;

	um_lock_bh(hash);

	hlist_for_each_entry_rcu(um, head, hlist) {
		/* we allow daddr being set to wildcard (zero),
		 * since UDP server may bind INADDR_ANY */
		if (um->saddr == saddr && (daddr == 0 || um->daddr == daddr) &&
		    um->sport == sport && um->dport == dport) {
			mod_timer(&um->timer, jiffies + uoa_map_timeout * HZ);
			atomic_inc(&um->refcnt);
			break;
		}
	}

	um_unlock_bh(hash);

	return um;
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

		pr_warn("expire delaye: refcnt: %d\n",
			 atomic_read(&um->refcnt));
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

		hlist_for_each_entry_safe(um, n, head, hlist) {
			if (timer_pending(&um->timer))
				del_timer(&um->timer);

			if (atomic_read(&um->refcnt) != 0)
				continue;

			hlist_del(&um->hlist);
			atomic_dec(&uoa_map_count);
			kmem_cache_free(uoa_map_cache, um);
		}
	}

	if (atomic_read(&uoa_map_count) > 0) {
		schedule();
		goto flush_again;
	}
}

static int uoa_so_set(struct sock *sk, int cmd, void __user *user,
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
	um = uoa_map_get(map.saddr, map.daddr, map.sport, map.dport);
	if (!um) {
		if (uoa_debug) {
			pr_warn("%s: not found: %pI4:%d->%pI4:%d\n", __func__,
				&map.saddr, ntohs(map.sport),
				&map.daddr, ntohs(map.dport));
		}
		UOA_STATS_INC(miss);
		return -ENOENT;
	}

	uoa_map_dump(um, "lookup:");

	if (likely(um->optuoa.op_code == IPOPT_UOA &&
		   um->optuoa.op_len == IPOLEN_UOA)) {
		map.real_saddr = um->optuoa.op_addr;
		map.real_sport = um->optuoa.op_port;
		UOA_STATS_INC(success);
		err = 0;
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
	.pf		= PF_INET,
	.owner		= THIS_MODULE,
	/* set */
	.set_optmin	= UOA_BASE_CTL,
	.set_optmax	= UOA_SO_SET_MAX+1,
	.set		= uoa_so_set,
	/* get */
	.get_optmin	= UOA_BASE_CTL,
	.get_optmax	= UOA_SO_GET_MAX+1,
	.get		= uoa_so_get,
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

static struct uoa_map *uoa_skb_rcv_opt(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *uh;
	int optlen, l;
	unsigned char *optptr;
	struct uoa_map *um = NULL;

	/* try get UOA from IP header */
	iph = ip_hdr(skb);
	if (likely(iph->ihl <= 5))
		goto uoa_none;

	if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))
		goto out;
	uh = (void *)iph + ip_hdrlen(skb);

	optlen = ip_hdrlen(skb) - sizeof(struct iphdr);
	optptr = (unsigned char *)(iph + 1);

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

		if (*optptr == IPOPT_UOA && optlen == IPOLEN_UOA) {
			UOA_STATS_INC(uoa_got);

			um = kmem_cache_alloc(uoa_map_cache, GFP_ATOMIC);
			if (!um) {
				UOA_STATS_INC(uoa_miss);
				goto out;
			}

			atomic_set(&um->refcnt, 0);
			um->saddr = iph->saddr;
			um->daddr = iph->daddr;
			um->sport = uh->source;
			um->dport = uh->dest;

			memcpy(&um->optuoa, optptr, IPOLEN_UOA);

			UOA_STATS_INC(uoa_saved);

			if (uoa_send_ack(skb) != 0) {
				UOA_STATS_INC(uoa_ack_fail);
				pr_warn("fail to send UOA ACK\n");
			}

			return um;
		}

		l -= optlen;
		optptr += optlen;
		continue;
	}

uoa_none:
	/* no UOA option */
	UOA_STATS_INC(uoa_none);

out:
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
#else
#error "Pls modify the definition according to kernel version."
#endif
{
	int protocol;
	struct uoa_map *um;

	protocol = ip_hdr(skb)->protocol;
	if (protocol != IPPROTO_UDP)
		return NF_ACCEPT;

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
		.hook		= uoa_ip_local_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_NAT_SRC + 1,
	},
};

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
	err = nf_register_net_hooks(&init_net, uoa_nf_hook_ops,
				    ARRAY_SIZE(uoa_nf_hook_ops));
#else
	err = nf_register_hooks(uoa_nf_hook_ops, ARRAY_SIZE(uoa_nf_hook_ops));
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
	nf_unregister_net_hooks(&init_net, uoa_nf_hook_ops,
				ARRAY_SIZE(uoa_nf_hook_ops));
#else
	nf_unregister_hooks(uoa_nf_hook_ops, ARRAY_SIZE(uoa_nf_hook_ops));
#endif
	synchronize_net();

	uoa_stats_exit();

	uoa_map_flush();
	uoa_map_exit();

	pr_info("UOA module removed\n");
}

module_init(uoa_init);
module_exit(uoa_exit);
MODULE_LICENSE("GPL");
