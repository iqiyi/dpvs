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
 * it refers TOA of LVS.
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
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/udp.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <linux/ip.h>
#include <asm/pgtable_types.h>

#include "uoa.h"

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

	seq_puts(seq, " Success     Miss  Invalid    Empty|UOA  Got     None    Saved Ack-Fail\n");

	seq_printf(seq, "%8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
		   ks.success, ks.miss, ks.invalid, ks.empty,
		   ks.uoa_got, ks.uoa_none, ks.uoa_saved, ks.uoa_ack_fail);

	return 0;
}

static int uoa_stats_percpu_show(struct seq_file *seq, void *arg)
{
	int i;

	seq_puts(seq, "CPU  Success     Miss  Invalid    Empty|UOA  Got     None    Saved Ack-Fail\n");

	for_each_possible_cpu(i) {
		struct uoa_cpu_stats *s = per_cpu_ptr(uoa_stats.cpustats, i);
		__u64 success, miss, invalid, empty, got, none, saved, ack_fail;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin_irq(&s->syncp);

			success	= s->success;
			miss	= s->miss;
			invalid = s->invalid;
			empty   = s->empty;
			got	= s->uoa_got;
			none	= s->uoa_none;
			saved   = s->uoa_saved;
			ack_fail = s->uoa_ack_fail;
		} while (u64_stats_fetch_retry_irq(&s->syncp, start));

		seq_printf(seq,
		   "%3X  %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
		   i, success, miss, invalid, empty,
		   got, none, saved, ack_fail);
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

/*
 * we borrow sk->sk_user_data to save UOA option,
 * so need check if it's used by other module. the method
 * comes from TOA, checking if sk->sk_data_ready overrided.
 * some module like rpc/tux uses both.
 *
 * it may not the ideal way, if someone uses sk_user_data but
 * not sk_data_ready, we may get wrong info, although
 * op_code/op_len are double checked. on the other hand, if
 * someone uses sk_data_ready but not sk_user_data, we will
 * miss UOA info. anyway, those're really conner cases, and
 * not hurt the system.
 */
static unsigned long sk_data_ready_p;

static int (*udp_rcv_p)(struct sk_buff *skb);

static unsigned int addr_is_ro(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte & ~_PAGE_RW)
		return 1;
	else
		return 0;
}

static void addr_set_rw(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte & ~_PAGE_RW)
		pte->pte |= _PAGE_RW;
}

static void addr_set_ro(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte & ~_PAGE_RW;
}

static int inet_getname_uoa(struct socket *sock, struct sockaddr *uaddr,
			    int *uaddr_len, int peer)
{
	int err;
	struct sock *sk = sock->sk;
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	struct ipopt_uoa opt;

	err = inet_getname(sock, uaddr, uaddr_len, peer);
	if (err != 0 || !peer) {
		UOA_STATS_INC(empty);
		return err;
	}

	/* sk_user_data is used by other modules ? */
	if (sk_data_ready_p != (unsigned long)sk->sk_data_ready) {
		UOA_STATS_INC(miss);
		return err;
	}

	memcpy(&opt, &sk->sk_user_data, sizeof(struct ipopt_uoa));

	if (IPOPT_UOA != opt.op_code || IPOLEN_UOA != opt.op_len) {
		UOA_STATS_INC(invalid);
		return err;
	}

	sin->sin_port = opt.op_port;
	sin->sin_addr.s_addr = opt.op_addr;

	UOA_STATS_INC(success);
	return err;
}

/*
 * "ACK" is an empty payload UDP/IP packet.
 * UOA sender (LB) will handle the "ACK" and eat it,
 * it should not be forwarded by LB to original UDP sender.
 */
static int uoa_send_ack(const struct sk_buff *oskb)
{
	// TODO:
	return 0;
}

static int udp_rcv_uoa(struct sk_buff *skb)
{
	struct sock *sk;
	struct iphdr *iph;
	int err, optlen, l;
	unsigned char *optptr;

	/*
	 * udp_rcv will always consume skb, it's either
	 * get freed in udp_rcv or udp_recvmsg later.
	 * let's hold skb first to prevent it being freed
	 * and try free it later. by using refcnt, it's ok
	 * even we call kfree_skb before udp_recvmsg.
	 */
	skb_get(skb);

	/* invoke original function first. */
	err = udp_rcv_p(skb);
	if (err != 0)
		goto out; /* bad UDP packet or unreachable ? */

	/* now skb should have sock info (if not dropped) */
	sk = skb->sk;
	if (!sk)
		goto out;

	/* try get UOA from IP header */
	iph = ip_hdr(skb);
	if (likely(iph->ihl <= 5))
		goto uoa_none;

	optlen = iph->ihl * 4 - sizeof(struct iphdr);
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

			/* may already saved UOA or used by other module */
			if (unlikely(sk->sk_user_data != NULL))
				goto out; /* should not count as error */

			/* XXX: alloc if NULL and free when destroy sock ? */
			memcpy(&sk->sk_user_data, optptr, sizeof(IPOLEN_UOA));
			UOA_STATS_INC(uoa_saved);

			if (uoa_send_ack(skb) != 0) {
				UOA_STATS_INC(uoa_ack_fail);
				pr_warn("fail to send UOA ACK\n");
			}

			goto out;
		}

		l -= optlen;
		optptr += optlen;
		continue;
	}

uoa_none:
	/* no UOA option */
	UOA_STATS_INC(uoa_none);

out:
	kfree_skb(skb);
	return 0;
}

static unsigned int uoa_ip_local_in(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	int err, protocol;

	__skb_pull(skb, skb_network_header_len(skb));

	protocol = ip_hdr(skb)->protocol;
	if (protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	/* compare to ip_local_deliver_finish, we do not handle
	 * raw socket and xfrm */

resubmit:
	err = udp_rcv_uoa(skb);
	if (err < 0) {
		protocol = -err; /* xxx over UDP ? */
		goto resubmit;
	}

	__IP_INC_STATS(state->net, IPSTATS_MIB_INDELIVERS);

	return NF_STOLEN;
}

/*
 * there's no way to access unexported symbol udp_protocol{}
 * to override udp_rcv(). while in order to get sock{}, we have to
 * invoke udp_rcv(), so just use nf LOCAL_IN hook.
 */
static const struct nf_hook_ops uoa_nf_ops[] = {
	{
		.hook		= uoa_ip_local_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_NAT_SRC + 1,
	},
};

static int uoa_hook_func(void)
{
	struct proto_ops *inet_dgram_ops_p;
	int is_ro = 0, err;

	/*
	 * no way to hook udp_rcv() and udp_recvmsg() is difficult
	 * to be overwirten since it handles multiple skbs.
	 */
	err = nf_register_net_hooks(&init_net, uoa_nf_ops,
				    ARRAY_SIZE(uoa_nf_ops));
	if (err < 0) {
		pr_err("fail to register netfilter hooks.\n");
		return err;
	}

	/* it's "const" */
	inet_dgram_ops_p = (struct proto_ops *)&inet_dgram_ops;

	/* hook inet_getname() */
	if (addr_is_ro((unsigned long)&inet_dgram_ops.getname)) {
		is_ro = 1;
		addr_set_rw((unsigned long)&inet_dgram_ops.getname);
	}

	inet_dgram_ops_p->getname = inet_getname_uoa;

	if (is_ro)
		addr_set_ro((unsigned long)&inet_dgram_ops.getname);

	return 0;
}

static int uoa_unhook_func(void)
{
	struct proto_ops *inet_dgram_ops_p;
	int is_ro = 0;

	nf_unregister_net_hooks(&init_net, uoa_nf_ops, ARRAY_SIZE(uoa_nf_ops));

	inet_dgram_ops_p = (struct proto_ops *)&inet_dgram_ops;

	if (addr_is_ro((unsigned long)&inet_dgram_ops.getname)) {
		is_ro = 1;
		addr_set_rw((unsigned long)&inet_dgram_ops.getname);
	}

	inet_dgram_ops_p->getname = inet_getname;

	if (is_ro)
		addr_set_ro((unsigned long)&inet_dgram_ops.getname);

	return 0;
}

static __init int uoa_init(void)
{
	int i;

	/* statistics */
	spin_lock_init(&uoa_stats.lock);
	memset(&uoa_stats.kstats, 0, sizeof(struct uoa_kstats));

	uoa_stats.cpustats = alloc_percpu(struct uoa_cpu_stats);
	if (!uoa_stats.cpustats)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		struct uoa_cpu_stats *cs;

		cs = per_cpu_ptr(uoa_stats.cpustats, i);
		u64_stats_init(&cs->syncp);
	}

	proc_create("uoa_stats", 0, init_net.proc_net, &uoa_stats_fops);
	proc_create("uoa_stats_percpu", 0, init_net.proc_net,
		    &uoa_stats_percpu_fops);

	/* the addr is used to check if sk->sk_user_data is using by others */
	sk_data_ready_p = kallsyms_lookup_name("sock_def_readable");
	if (!sk_data_ready_p) {
		pr_err("Cannot get symbol sock_def_readable\n");
		goto errout;
	}

	udp_rcv_p = (void *)kallsyms_lookup_name("udp_rcv");
	if (!udp_rcv_p) {
		pr_err("Cannot get symbol udp_rcv\n");
		goto errout;
	}

	if (uoa_hook_func() != 0) {
		pr_err("Fail to hook uoa functions\n");
		goto errout;
	}

	pr_info("UOA module installed\n");
	return 0;

errout:
	remove_proc_entry("uoa_stats", init_net.proc_net);
	remove_proc_entry("uoa_stats_percpu", init_net.proc_net);
	free_percpu(uoa_stats.cpustats);

	return -EINVAL;
}

static __exit void uoa_exit(void)
{
	if (uoa_unhook_func() != 0)
		pr_warn("Fail to unhook uoa functions\n");
	synchronize_net();

	remove_proc_entry("uoa_stats", init_net.proc_net);
	remove_proc_entry("uoa_stats_percpu", init_net.proc_net);

	free_percpu(uoa_stats.cpustats);

	pr_info("UOA module removed\n");
}

module_init(uoa_init);
module_exit(uoa_exit);
MODULE_LICENSE("GPL");
