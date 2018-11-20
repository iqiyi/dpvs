#include "toa.h"

/*
 *	TOA: Address is a new TCP Option
 *	Address include ip+port, Now support IPV4 and IPV6
 */

unsigned long sk_data_ready_addr = 0;

#define TOA_NIPQUAD_FMT "%u.%u.%u.%u"

#define TOA_NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]

#define TOA_NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

#define TOA_NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])

#ifdef TOA_IPV6_ENABLE
static struct proto_ops *inet6_stream_ops_p = NULL;
static struct inet_connection_sock_af_ops *ipv6_specific_p = NULL;

typedef struct sock *(*syn_recv_sock_func_pt)(
		struct sock *sk, struct sk_buff *skb,
		struct request_sock *req,
		struct dst_entry *dst);
static syn_recv_sock_func_pt tcp_v6_syn_recv_sock_org_pt = NULL;
#endif

/*
 * Statistics of toa in proc /proc/net/toa_stats
 */

struct toa_stats_entry toa_stats[] = {
	TOA_STAT_ITEM("syn_recv_sock_toa", SYN_RECV_SOCK_TOA_CNT),
	TOA_STAT_ITEM("syn_recv_sock_no_toa", SYN_RECV_SOCK_NO_TOA_CNT),
	TOA_STAT_ITEM("getname_toa_ok", GETNAME_TOA_OK_CNT),
	TOA_STAT_ITEM("getname_toa_mismatch", GETNAME_TOA_MISMATCH_CNT),
	TOA_STAT_ITEM("getname_toa_bypass", GETNAME_TOA_BYPASS_CNT),
	TOA_STAT_ITEM("getname_toa_empty", GETNAME_TOA_EMPTY_CNT),
	TOA_STAT_ITEM("ip6_address_alloc", IP6_ADDR_ALLOC_CNT),
	TOA_STAT_ITEM("ip6_address_free", IP6_ADDR_FREE_CNT),
	TOA_STAT_END
};

DEFINE_TOA_STAT(struct toa_stat_mib, ext_stats);

/*
 * Funcs for toa hooks
 */

/* Parse TCP options in skb, try to get client ip, port
 * @param skb [in] received skb, it should be a ack/get-ack packet.
 * @return NULL if we don't get client ip/port;
 *         value of toa_data in ret_ptr if we get client ip/port.
 */
static void *get_toa_data(int af, struct sk_buff *skb, int *nat64)
{
	struct tcphdr *th;
	int length;
	unsigned char *ptr;

	TOA_DBG("get_toa_data called\n");

	*nat64 = 0;
	if (NULL != skb) {
		th = tcp_hdr(skb);
		length = (th->doff * 4) - sizeof(struct tcphdr);
		ptr = (unsigned char *) (th + 1);

		while (length > 0) {
			int opcode = *ptr++;
			int opsize;
			switch (opcode) {
			case TCPOPT_EOL:
				return NULL;
			case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
				length--;
				continue;
			default:
				opsize = *ptr++;
				if (opsize < 2)	/* "silly options" */
					return NULL;
				if (opsize > length)
					/* don't parse partial options */
					return NULL;
				if (TCPOPT_TOA == opcode &&
					TCPOLEN_IP4_TOA == opsize) {

					struct toa_ip4_data tdata;
					void *ret_ptr = NULL;

					memcpy(&tdata, ptr - 2, sizeof(tdata));
					TOA_DBG("af = %d, find toa data: ip = "
						TOA_NIPQUAD_FMT", port = %u\n",
						af,
						TOA_NIPQUAD(tdata.ip),
						ntohs(tdata.port));
					if (af == AF_INET) {
						memcpy(&ret_ptr, &tdata,
							sizeof(ret_ptr));
						TOA_DBG("coded ip4 toa data: %p\n",
							ret_ptr);
						return ret_ptr;
					}
#ifdef TOA_IPV6_ENABLE
					else if (af == AF_INET6) {
						struct toa_ip6_data *ptr_toa_ip6 =
							kmalloc(sizeof(struct toa_ip6_data), GFP_ATOMIC);
						if (!ptr_toa_ip6) {
							return NULL;
						}
						ptr_toa_ip6->opcode = opcode;
						ptr_toa_ip6->opsize = TCPOLEN_IP6_TOA;
						ipv6_addr_set(&ptr_toa_ip6->in6_addr, 0, 0,
							htonl(0x0000FFFF), tdata.ip);
						TOA_DBG("coded ip6 toa data: %p\n",
							ptr_toa_ip6);
						TOA_INC_STATS(ext_stats, IP6_ADDR_ALLOC_CNT);
						return ptr_toa_ip6;
					}
#endif
				}

				if (TCPOPT_TOA == opcode &&
				    TCPOLEN_IP6_TOA == opsize) {
					struct toa_ip6_data *ptr_toa_ip6 =
						kmalloc(sizeof(struct toa_ip6_data), GFP_ATOMIC);
					if (!ptr_toa_ip6) {
							return NULL;
					}
					memcpy(ptr_toa_ip6, ptr - 2, sizeof(struct toa_ip6_data));

					TOA_DBG("find toa_v6 data : ip = "
						TOA_NIP6_FMT", port = %u,"
						" coded ip6 toa data: %p\n",
						TOA_NIP6(ptr_toa_ip6->in6_addr),
						ptr_toa_ip6->port,
						ptr_toa_ip6);
					TOA_INC_STATS(ext_stats, IP6_ADDR_ALLOC_CNT);
#ifdef TOA_IPV6_ENABLE
					if (af == AF_INET6)
						*nat64 = 0;
					else
#endif
						*nat64 = 1;
					return ptr_toa_ip6;
				}

				ptr += opsize - 2;
				length -= opsize;
			}
		}
	}
	return NULL;
}

/* get client ip from socket
 * @param sock [in] the socket to getpeername() or getsockname()
 * @param uaddr [out] the place to put client ip, port
 * @param uaddr_len [out] lenth of @uaddr
 * @peer [in] if(peer), try to get remote address; if(!peer),
 *  try to get local address
 * @return return what the original inet_getname() returns.
 */
static int
inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
		int *uaddr_len, int peer)
{
	int retval = 0;
	struct sock *sk = sock->sk;
	struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
	struct toa_ip4_data tdata;

	TOA_DBG("inet_getname_toa called, sk->sk_user_data is %p\n",
		sk->sk_user_data);

	/* call orginal one */
	retval = inet_getname(sock, uaddr, uaddr_len, peer);

	/* set our value if need */
	if (retval == 0 && NULL != sk->sk_user_data && peer) {
		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
			memcpy(&tdata, &sk->sk_user_data, sizeof(tdata));
			if (TCPOPT_TOA == tdata.opcode &&
			    TCPOLEN_IP4_TOA == tdata.opsize) {
				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
				TOA_DBG("inet_getname_toa: set new sockaddr, ip "
					TOA_NIPQUAD_FMT" -> "TOA_NIPQUAD_FMT
					", port %u -> %u\n",
					TOA_NIPQUAD(sin->sin_addr.s_addr),
					TOA_NIPQUAD(tdata.ip), ntohs(sin->sin_port),
					ntohs(tdata.port));
				sin->sin_port = tdata.port;
				sin->sin_addr.s_addr = tdata.ip;
			} else { /* sk_user_data doesn't belong to us */
				TOA_INC_STATS(ext_stats,
						GETNAME_TOA_MISMATCH_CNT);
				TOA_DBG("inet_getname_toa: invalid toa data, "
					"ip "TOA_NIPQUAD_FMT" port %u opcode %u "
					"opsize %u\n",
					TOA_NIPQUAD(tdata.ip), ntohs(tdata.port),
					tdata.opcode, tdata.opsize);
			}
		} else {
			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
		}
	} else { /* no need to get client ip */
		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
	}

	return retval;
}

/* NAT64 get client ip from socket
 * Client ip is v6 and socket is v4
 * Find toa and copy_to_user
 * This function will not return inet_getname,
 * so users can get distinctions from normal v4
 *
 * Notice:
 * In fact, we can just use original api inet_getname_toa by uaddr_len judge.
 * We didn't do this because RS developers may be confused about this api.
 */
static int
inet64_getname_toa(struct sock *sk, int cmd, void __user *user, int *len)
{
	struct inet_sock *inet;
	struct toa_ip6_data *t_ip6_data_ptr;
	struct toa_nat64_peer uaddr;

	if (cmd != TOA_SO_GET_LOOKUP || !sk) {
		TOA_INFO("%s: bad cmd\n", __func__);
		return -EINVAL;
	}

	if (*len < sizeof(struct toa_nat64_peer) ||
	    NULL == user) {
		TOA_INFO("%s: bad param len\n", __func__);
		return -EINVAL;
	}

	inet = inet_sk(sk);
	/* refered to inet_getname */
#if LINUX_VERSION_CODE >=KERNEL_VERSION(2,6,33)
	if (!inet->inet_dport || 
#else
	if (!inet->dport ||
#endif
		((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)))
		return -ENOTCONN;

	if (NULL != sk->sk_user_data) {
		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
			t_ip6_data_ptr = sk->sk_user_data;
			if (TCPOPT_TOA == t_ip6_data_ptr->opcode &&
			    TCPOLEN_IP6_TOA == t_ip6_data_ptr->opsize) {
				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
				TOA_DBG("inet64_getname_toa: set new sockaddr, ip "
					 TOA_NIPQUAD_FMT" -> "TOA_NIP6_FMT
					", port %u -> %u\n",
					TOA_NIPQUAD(inet->saddr),
					TOA_NIP6(t_ip6_data_ptr->in6_addr),
					ntohs(inet->port),
					ntohs(t_ip6_data_ptr->port));
				uaddr.saddr = t_ip6_data_ptr->in6_addr;
				uaddr.port  = t_ip6_data_ptr->port;
				if (copy_to_user(user, &uaddr, 
					sizeof(struct toa_nat64_peer)) != 0)
					return -EFAULT;
				*len = sizeof(struct toa_nat64_peer);
				return 0;
			} else {
				TOA_INC_STATS(ext_stats,
						GETNAME_TOA_MISMATCH_CNT);
			}
		} else {
			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
		}
	} else {
		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
	}

	return -EINVAL;
}

#ifdef TOA_IPV6_ENABLE
static int
inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
		  int *uaddr_len, int peer)
{
	int retval = 0;
	struct sock *sk = sock->sk;
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *) uaddr;
	struct toa_ip6_data* t_ip6_data_ptr;

	TOA_DBG("inet6_getname_toa called, sk->sk_user_data is %p\n",
		sk->sk_user_data);

	/* call orginal one */
	retval = inet6_getname(sock, uaddr, uaddr_len, peer);

	/* set our value if need */
	if (retval == 0 && NULL != sk->sk_user_data && peer) {
		if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
			t_ip6_data_ptr = sk->sk_user_data;
			if (TCPOPT_TOA == t_ip6_data_ptr->opcode &&
			    TCPOLEN_IP6_TOA == t_ip6_data_ptr->opsize) {
				TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
				TOA_DBG("inet6_getname_toa: set new sockaddr, ip " 
					TOA_NIP6_FMT" -> "TOA_NIP6_FMT
					", port %u -> %u\n",
					TOA_NIP6(sin->sin6_addr),
					TOA_NIP6(t_ip6_data_ptr->in6_addr),
					ntohs(sin->sin6_port),
					ntohs(t_ip6_data_ptr->port));
				sin->sin6_port = t_ip6_data_ptr->port;
				sin->sin6_addr = t_ip6_data_ptr->in6_addr;
			} else { /* sk_user_data doesn't belong to us */
				TOA_INC_STATS(ext_stats,
					      GETNAME_TOA_MISMATCH_CNT);
			}
		} else {
			TOA_INC_STATS(ext_stats, GETNAME_TOA_BYPASS_CNT);
		}
	} else { /* no need to get client ip */
		TOA_INC_STATS(ext_stats, GETNAME_TOA_EMPTY_CNT);
	}

	return retval;
}

static inline int 
get_kernel_ipv6_symbol(void)
{
        inet6_stream_ops_p =
                (struct proto_ops *)kallsyms_lookup_name("inet6_stream_ops");
        if (inet6_stream_ops_p == NULL) {
                TOA_INFO("CPU [%u] kallsyms_lookup_name cannot find symbol inet6_stream_ops\n",
                        smp_processor_id());
    
                return -1;    
        }   
        ipv6_specific_p =
                (struct inet_connection_sock_af_ops *)kallsyms_lookup_name("ipv6_specific");
        if (ipv6_specific_p == NULL) {
                TOA_INFO("CPU [%u] kallsyms_lookup_name cannot find symbol ipv6_specific\n",
                        smp_processor_id());
                return -1; 
        }   
        tcp_v6_syn_recv_sock_org_pt =
                (syn_recv_sock_func_pt)kallsyms_lookup_name("tcp_v6_syn_recv_sock");
        if (tcp_v6_syn_recv_sock_org_pt == NULL) {
                TOA_INFO("CPU [%u] kallsyms_lookup_name cannot find symbol tcp_v6_syn_recv_sock\n",
                        smp_processor_id());
        	return -1;
	}   
        return 0;    
}
#endif

static void 
tcp_v6_sk_destruct_toa(struct sock *sk) {
        if (sk->sk_user_data) {
                kfree(sk->sk_user_data);
                sk->sk_user_data = NULL;
                TOA_INC_STATS(ext_stats, IP6_ADDR_FREE_CNT);
        }   
        inet_sock_destruct(sk);
}

/* The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 * We need to save toa data into the new socket.
 * @param sk [out]  the socket
 * @param skb [in] the ack/ack-get packet
 * @param req [in] the open request for this connection
 * @param dst [out] route cache entry
 * @return NULL if fail new socket if succeed.
 */
static struct sock *
tcp_v4_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
			struct request_sock *req, struct dst_entry *dst)
{
	struct sock *newsock = NULL;
	int nat64 = 0;

	TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

	/* call orginal one */
	newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);

	/* set our value if need */
	if (NULL != newsock && NULL == newsock->sk_user_data) {
		newsock->sk_user_data = get_toa_data(AF_INET, skb, &nat64);
		if (NULL != newsock->sk_user_data) {
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
			if (nat64) {
				newsock->sk_destruct = tcp_v6_sk_destruct_toa;
			}
		}
		else
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);

		TOA_DBG("tcp_v4_syn_recv_sock_toa: set "
			"sk->sk_user_data to %p\n",
			newsock->sk_user_data);
	}
	return newsock;
}

#ifdef TOA_IPV6_ENABLE
static struct sock *
tcp_v6_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
			 struct request_sock *req, struct dst_entry *dst)
{
	struct sock *newsock = NULL;
	int nat64 = 0;

	TOA_DBG("tcp_v6_syn_recv_sock_toa called\n");

	/* call orginal one */
	newsock = tcp_v6_syn_recv_sock_org_pt(sk, skb, req, dst);

	/* set our value if need */
	if (NULL != newsock && NULL == newsock->sk_user_data) {
		newsock->sk_user_data = get_toa_data(AF_INET6, skb, &nat64);
		if (NULL != newsock->sk_user_data) {
			newsock->sk_destruct = tcp_v6_sk_destruct_toa;
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
		} else {
			TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_NO_TOA_CNT);
		}

		TOA_DBG("tcp_v6_syn_recv_sock_toa: set "
			"sk->sk_user_data to %p\n",
			newsock->sk_user_data);
	}
	return newsock;
}
#endif

/*
 * HOOK FUNCS
 */

/* replace the functions with our functions */
static inline int
hook_toa_functions(void)
{
	/* hook inet_getname for ipv4 */
	struct proto_ops *inet_stream_ops_p =
			(struct proto_ops *)&inet_stream_ops;
	/* hook tcp_v4_syn_recv_sock for ipv4 */
	struct inet_connection_sock_af_ops *ipv4_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv4_specific;

	inet_stream_ops_p->getname = inet_getname_toa;
	TOA_INFO("CPU [%u] hooked inet_getname <%p> --> <%p>\n",
		smp_processor_id(), inet_getname, inet_stream_ops_p->getname);

	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock_toa;
	TOA_INFO("CPU [%u] hooked tcp_v4_syn_recv_sock <%p> --> <%p>\n",
		smp_processor_id(), tcp_v4_syn_recv_sock,
		ipv4_specific_p->syn_recv_sock);

#ifdef TOA_IPV6_ENABLE
	inet6_stream_ops_p->getname = inet6_getname_toa;
	TOA_INFO("CPU [%u] hooked inet6_getname <%p> --> <%p>\n",
		smp_processor_id(), inet6_getname, inet6_stream_ops_p->getname);

	ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_toa;
	TOA_INFO("CPU [%u] hooked tcp_v6_syn_recv_sock <%p> --> <%p>\n",
		smp_processor_id(), tcp_v6_syn_recv_sock_org_pt,
		ipv6_specific_p->syn_recv_sock);
#endif

	return 0;
}

/* replace the functions to original ones */
static int
unhook_toa_functions(void)
{
	/* unhook inet_getname for ipv4 */
	struct proto_ops *inet_stream_ops_p =
			(struct proto_ops *)&inet_stream_ops;
	/* unhook tcp_v4_syn_recv_sock for ipv4 */
	struct inet_connection_sock_af_ops *ipv4_specific_p =
			(struct inet_connection_sock_af_ops *)&ipv4_specific;

	inet_stream_ops_p->getname = inet_getname;
	TOA_INFO("CPU [%u] unhooked inet_getname\n",
		smp_processor_id());

	ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock;
	TOA_INFO("CPU [%u] unhooked tcp_v4_syn_recv_sock\n",
		smp_processor_id());

#ifdef TOA_IPV6_ENABLE
	if (inet6_stream_ops_p) {
		inet6_stream_ops_p->getname = inet6_getname;
		TOA_INFO("CPU [%u] unhooked inet6_getname\n",
			smp_processor_id());
	}
	if (ipv6_specific_p) {
		ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_org_pt;
		TOA_INFO("CPU [%u] unhooked tcp_v6_syn_recv_sock\n",
			smp_processor_id());
	}
#endif

	return 0;
}

/*
 * Statistics of toa in proc /proc/net/toa_stats
 */
static int toa_stats_show(struct seq_file *seq, void *v)
{
	int i, j, cpu_nr;

	/* print CPU first */
	seq_printf(seq, "                                  ");
	cpu_nr = num_possible_cpus();
	for (i = 0; i < cpu_nr; i++)
		if (cpu_online(i))
			seq_printf(seq, "CPU%d       ", i);
	seq_putc(seq, '\n');

	i = 0;
	while (NULL != toa_stats[i].name) {
		seq_printf(seq, "%-25s:", toa_stats[i].name);
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				seq_printf(seq, "%10lu ", *(
					((unsigned long *) per_cpu_ptr(
					ext_stats, j)) + toa_stats[i].entry
					));
			}
		}
		seq_putc(seq, '\n');
		i++;
	}
	return 0;
}

static int toa_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, toa_stats_show, NULL);
}

static const struct file_operations toa_stats_fops = {
	.owner = THIS_MODULE,
	.open = toa_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct nf_sockopt_ops toa_sockopts = {
	.pf	= PF_INET,
	.owner	= THIS_MODULE,
	/* Nothing to do in set */
	/* get */
	.get_optmin = TOA_BASE_CTL,
	.get_optmax = TOA_SO_GET_MAX+1,
	.get        = inet64_getname_toa,
};

/*
 * TOA module init and destory
 */
#if LINUX_VERSION_CODE >=KERNEL_VERSION(3,9,0)
static struct proc_dir_entry *proc_net_fops_create(struct net *net,
	const char *name, mode_t mode, const struct file_operations *fops)
{
	return proc_create(name, mode, net->proc_net, fops);
}

static void proc_net_remove(struct net *net, const char *name)
{
	remove_proc_entry(name, net->proc_net);
}
#endif

/* module init */
static int __init
toa_init(void)
{

	TOA_INFO("TOA " TOA_VERSION " by pukong.wjm\n");

	/* alloc statistics array for toa */
	ext_stats = alloc_percpu(struct toa_stat_mib);
	if (NULL == ext_stats)
		return 1;
	proc_net_fops_create(&init_net, "toa_stats", 0, &toa_stats_fops);

	/* get the address of function sock_def_readable
	 * so later we can know whether the sock is for rpc, tux or others
	 */
	sk_data_ready_addr = kallsyms_lookup_name("sock_def_readable");
	TOA_INFO("CPU [%u] sk_data_ready_addr = "
		"kallsyms_lookup_name(sock_def_readable) = %lu\n",
		 smp_processor_id(), sk_data_ready_addr);
	if (0 == sk_data_ready_addr) {
		TOA_INFO("cannot find sock_def_readable.\n");
		goto err;
	}

#ifdef TOA_IPV6_ENABLE
	if (0 != get_kernel_ipv6_symbol()) {
		TOA_INFO("get ipv6 struct from kernel fail.\n");
		goto err;
	}
#endif
	if (0 != nf_register_sockopt(&toa_sockopts)) {
		TOA_INFO("fail to register sockopt\n");
		goto err;
	}

	/* hook funcs for parse and get toa */
	hook_toa_functions();

	TOA_INFO("toa loaded\n");
	return 0;

err:
	proc_net_remove(&init_net, "toa_stats");
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}

	return 1;
}

/* module cleanup*/
static void __exit
toa_exit(void)
{
	unhook_toa_functions();
	nf_unregister_sockopt(&toa_sockopts);
	synchronize_net();

	proc_net_remove(&init_net, "toa_stats");
	if (NULL != ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}
	TOA_INFO("toa unloaded\n");
}

module_init(toa_init);
module_exit(toa_exit);
MODULE_LICENSE("GPL");
