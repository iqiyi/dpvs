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
#include "toa.h"
/*
 *    TOA: Address is a new TCP Option
 *    Address include ip+port, Now support IPV4 and IPV6
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
#endif

unsigned long sk_data_ready_addr = 0;

#define TOA_NIPQUAD_FMT "%u.%u.%u.%u"

#define TOA_NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
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

/* ipv6's toa list table array */
#define TOA_IP6_TAB_BITS    12
#define TOA_IP6_TAB_SIZE    (1 << TOA_IP6_TAB_BITS)
#define TOA_IP6_TAB_MASK    (TOA_IP6_TAB_SIZE - 1)

struct toa_ip6_entry {
    struct toa_ip6_data toa_data;
    struct sock *sk;

    struct list_head list;
};

struct toa_ip6_list_head {
    struct list_head toa_ip6_head;
    spinlock_t lock;
} __attribute__((__aligned__(SMP_CACHE_BYTES)));

static struct toa_ip6_list_head
__toa_ip6_list_tab[TOA_IP6_TAB_SIZE] __cacheline_aligned;

/* per-cpu lock for toa of ipv6  */
struct toa_ip6_sk_lock {
    /* lock for sk of ip6 toa */
    spinlock_t __percpu *lock;
};

static struct toa_ip6_sk_lock toa_ip6_sk_lock;
#endif

#ifdef TOA_IPV6_ENABLE
static struct proto_ops *inet6_stream_ops_p = NULL;
static struct inet_connection_sock_af_ops *ipv6_specific_p = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,1)
typedef struct sock *(*syn_recv_sock_func_pt)(
        const struct sock *sk, struct sk_buff *skb,
        struct request_sock *req,
        struct dst_entry *dst,
        struct request_sock *req_unhash,
        bool *own_req);
#else
typedef struct sock *(*syn_recv_sock_func_pt)(
        struct sock *sk, struct sk_buff *skb,
        struct request_sock *req,
        struct dst_entry *dst);
#endif
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
#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
    TOA_STAT_ITEM("ip6_address_alloc", IP6_ADDR_ALLOC_CNT),
    TOA_STAT_ITEM("ip6_address_free", IP6_ADDR_FREE_CNT),
#endif
    TOA_STAT_END
};

unsigned int is_ro_addr(unsigned long addr)
{
    unsigned int level;
    unsigned int ro_enable = 1;
    pte_t *pte = lookup_address(addr, &level);
    if (pte->pte & _PAGE_RW)
    {
            ro_enable = 0;
    }
    
    return ro_enable;
}

void set_addr_rw(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte |= _PAGE_RW;
    smp_wmb();
}

void set_addr_ro(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte &= ~_PAGE_RW;
}

DEFINE_TOA_STAT(struct toa_stat_mib, ext_stats);

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,103)
/* more secured version of ipv6_addr_hash() */
static inline u32
__ipv6_addr_jhash(const struct in6_addr *a, const u32 initval)
{
    u32 v = (__force u32)a->s6_addr32[0] ^ (__force u32)a->s6_addr32[1];

    return jhash_3words(v,
                (__force u32)a->s6_addr32[2],
                (__force u32)a->s6_addr32[3],
                initval);
}
#endif

static void
toa_ip6_hash(struct toa_ip6_entry *ptr_ip6_entry)
{
    struct toa_ip6_data *ptr_toa_data = &ptr_ip6_entry->toa_data;
    __u32 hash_key =
        __ipv6_addr_jhash(&ptr_toa_data->in6_addr, ptr_toa_data->port) & TOA_IP6_TAB_MASK;

    spin_lock_bh(&__toa_ip6_list_tab[hash_key].lock);

    list_add(&ptr_ip6_entry->list, &__toa_ip6_list_tab[hash_key].toa_ip6_head);

    spin_unlock_bh(&__toa_ip6_list_tab[hash_key].lock);

    return;
}

static void
toa_ip6_unhash(struct toa_ip6_entry *ptr_ip6_entry)
{
    struct toa_ip6_data *ptr_toa_data = &ptr_ip6_entry->toa_data;
    __u32 hash_key =
        __ipv6_addr_jhash(&ptr_toa_data->in6_addr, ptr_toa_data->port) & TOA_IP6_TAB_MASK;

    spin_lock_bh(&__toa_ip6_list_tab[hash_key].lock);

    list_del(&ptr_ip6_entry->list);

    spin_unlock_bh(&__toa_ip6_list_tab[hash_key].lock);
}

static void
lock_all_toa_ip6_sk(void)
{
    int i;
    for_each_possible_cpu(i) {
        spinlock_t *lock;

        lock = per_cpu_ptr(toa_ip6_sk_lock.lock, i);
        spin_lock_bh(lock);
    }
}

static void
unlock_all_toa_ip6_sk(void)
{
    int i;
    for_each_possible_cpu(i) {
        spinlock_t *lock;

        lock = per_cpu_ptr(toa_ip6_sk_lock.lock, i);
        spin_unlock_bh(lock);
    }
}

static void
lock_cpu_toa_ip6_sk(void)
{
    spinlock_t *lock = this_cpu_ptr(toa_ip6_sk_lock.lock);
    spin_lock_bh(lock);
}

static void
unlock_cpu_toa_ip6_sk(void)
{
    spinlock_t *lock = this_cpu_ptr(toa_ip6_sk_lock.lock);
    spin_unlock_bh(lock);
}

static int
init_toa_ip6(void)
{
    int i;

    for_each_possible_cpu(i) {
        spinlock_t *lock;

        lock = per_cpu_ptr(toa_ip6_sk_lock.lock, i);
        spin_lock_init(lock);
    }

    for (i = 0; i < TOA_IP6_TAB_SIZE; ++i) {
        INIT_LIST_HEAD(&__toa_ip6_list_tab[i].toa_ip6_head);
        spin_lock_init(&__toa_ip6_list_tab[i].lock);
    }

    toa_ip6_sk_lock.lock = alloc_percpu(spinlock_t);
    if (toa_ip6_sk_lock.lock == NULL) {
        TOA_INFO("fail to alloc per cpu ip6's destruct lock\n");
        return -ENOMEM;
    }

    return 0;
}

static void 
tcp_v6_sk_destruct_toa(struct sock *sk) {

        lock_cpu_toa_ip6_sk();

        if (sk->sk_user_data) {
                struct toa_ip6_entry* ptr_ip6_entry = sk->sk_user_data;
                toa_ip6_unhash(ptr_ip6_entry);
                sk->sk_destruct = inet_sock_destruct;
                sk->sk_user_data = NULL;
                kfree(ptr_ip6_entry);
                TOA_INC_STATS(ext_stats, IP6_ADDR_FREE_CNT);
        }

        inet_sock_destruct(sk);

        unlock_cpu_toa_ip6_sk();
}

static int
exit_toa_ip6(void)
{
    int i;
    struct list_head *head;
    struct toa_ip6_entry *ptr_ip6_entry;
    struct sock *sk;

    lock_all_toa_ip6_sk();

    for (i = 0; i < TOA_IP6_TAB_SIZE; ++i) {

        spin_lock_bh(&__toa_ip6_list_tab[i].lock);

        head = &__toa_ip6_list_tab[i].toa_ip6_head;
        while (!list_empty(head)) {
            ptr_ip6_entry = list_first_entry(head, struct toa_ip6_entry, list);
            sk = ptr_ip6_entry->sk;

            if (sk && sk->sk_user_data &&
                (sk->sk_destruct == tcp_v6_sk_destruct_toa)) {

                sk->sk_destruct = inet_sock_destruct;
                sk->sk_user_data = NULL;

                TOA_DBG("free ip6_entry in __toa_ip6_list_tab succ. "
                        "ptr_ip6_entry : %p, toa_ip6 : "TOA_NIP6_FMT", toa_port : %u\n",
                        ptr_ip6_entry,
                        TOA_NIP6(ptr_ip6_entry->toa_data.in6_addr),
                        ptr_ip6_entry->toa_data.port);
            } else {
                TOA_DBG("update sk of ip6_entry fail. "
                        "ptr_ip6_entry : %p\n",
                        ptr_ip6_entry);
            }

            TOA_INC_STATS(ext_stats, IP6_ADDR_FREE_CNT);

            list_del(&ptr_ip6_entry->list);
            kfree(ptr_ip6_entry);
        }

        spin_unlock_bh(&__toa_ip6_list_tab[i].lock);

    }

    unlock_all_toa_ip6_sk();

    synchronize_net();

    free_percpu(toa_ip6_sk_lock.lock);
    return 0;
}

#endif


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
            case TCPOPT_NOP:    /* Ref: RFC 793 section 3.1 */
                length--;
                continue;
            default:
                opsize = *ptr++;
                if (opsize < 2)    /* "silly options" */
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
                        struct toa_ip6_data *ptr_toa_ip6;
                        struct toa_ip6_entry *ptr_toa_entry =
                            kzalloc(sizeof(struct toa_ip6_entry), GFP_ATOMIC);
                        if (!ptr_toa_entry) {
                            return NULL;
                        }

                        ptr_toa_ip6 = &ptr_toa_entry->toa_data;
                        ptr_toa_ip6->opcode = opcode;
                        ptr_toa_ip6->opsize = TCPOLEN_IP6_TOA;
                        ipv6_addr_set(&ptr_toa_ip6->in6_addr, 0, 0,
                            htonl(0x0000FFFF), tdata.ip);
                        ptr_toa_ip6->port = tdata.port;
                        TOA_DBG("coded ip6 toa data: %p\n",
                            ptr_toa_ip6);
                        TOA_INC_STATS(ext_stats, IP6_ADDR_ALLOC_CNT);
                        return ptr_toa_entry;
                    }
#endif
                }

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
                if (TCPOPT_TOA == opcode &&
                    TCPOLEN_IP6_TOA == opsize) {
                    struct toa_ip6_data *ptr_toa_ip6;
                    struct toa_ip6_entry *ptr_toa_entry =
                        kzalloc(sizeof(struct toa_ip6_entry), GFP_ATOMIC);
                    if (!ptr_toa_entry) {
                            return NULL;
                    }

                    ptr_toa_ip6 = &ptr_toa_entry->toa_data;
                    memcpy(ptr_toa_ip6, ptr - 2, sizeof(struct toa_ip6_data));

                    TOA_DBG("find toa_v6 data : ip = "
                        TOA_NIP6_FMT", port = %u,"
                        " coded ip6 toa data: %p\n",
                        TOA_NIP6(ptr_toa_ip6->in6_addr),
                        ptr_toa_ip6->port,
                        ptr_toa_ip6);
                    TOA_INC_STATS(ext_stats, IP6_ADDR_ALLOC_CNT);
                    if (af == AF_INET6)
                        *nat64 = 0;
                    else
                        *nat64 = 1;

                    return ptr_toa_entry;
                }
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,1)
static int
inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
        int peer)
#else
static int
inet_getname_toa(struct socket *sock, struct sockaddr *uaddr,
        int *uaddr_len, int peer)
#endif
{
    int retval = 0;
    struct sock *sk = sock->sk;
    struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
    struct toa_ip4_data tdata;

    TOA_DBG("inet_getname_toa called, sk->sk_user_data is %p\n",
        sk->sk_user_data);

    /* call orginal one */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,1)
    retval = inet_getname(sock, uaddr, peer);
#else
    retval = inet_getname(sock, uaddr, uaddr_len, peer);
#endif

    /* set our value if need */
    if (retval >= 0 && NULL != sk->sk_user_data && peer) {
        if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready &&
            !sock_flag(sk, SOCK_NAT64)) {
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
#ifdef TOA_NAT64_ENABLE
static int
inet64_getname_toa(struct sock *sk, int cmd, void __user *user, int *len)
{
    struct inet_sock *inet;
    struct toa_nat64_peer uaddr;
    int ret;

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
    if (!inet->inet_dport ||
#else
    if (!inet->dport ||
#endif
        ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)))
        return -ENOTCONN;

    ret = -EINVAL;

    lock_cpu_toa_ip6_sk();

    if (NULL != sk->sk_user_data) {
        struct toa_ip6_entry *ptr_ip6_entry;
        struct toa_ip6_data *ptr_ip6_data;

        if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {

            if (!sock_flag(sk, SOCK_NAT64)) {
                ret = -EFAULT;
                goto out;
            }

            ptr_ip6_entry = sk->sk_user_data;
            ptr_ip6_data = &ptr_ip6_entry->toa_data;

            if (TCPOPT_TOA == ptr_ip6_data->opcode &&
                TCPOLEN_IP6_TOA == ptr_ip6_data->opsize) {
                TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
                TOA_DBG("inet64_getname_toa: set new sockaddr, ip "
                     TOA_NIPQUAD_FMT" -> "TOA_NIP6_FMT
                    ", port %u -> %u\n",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
                    TOA_NIPQUAD(inet->inet_saddr),
#else
                    TOA_NIPQUAD(inet->saddr),
#endif
                    TOA_NIP6(ptr_ip6_data->in6_addr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
                    ntohs(inet->inet_sport),
#else
                    ntohs(inet->sport),
#endif
                    ntohs(ptr_ip6_data->port));
                uaddr.saddr = ptr_ip6_data->in6_addr;
                uaddr.port  = ptr_ip6_data->port;

                if (copy_to_user(user, &uaddr,
                    sizeof(struct toa_nat64_peer)) != 0) {
                    ret = -EFAULT;
                    goto out;
                }

                *len = sizeof(struct toa_nat64_peer);
                ret = 0;
                goto out;
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

out:
    unlock_cpu_toa_ip6_sk();
    return ret;
}
#endif

#ifdef TOA_IPV6_ENABLE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,1)
static int
inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
          int peer)
#else
static int
inet6_getname_toa(struct socket *sock, struct sockaddr *uaddr,
          int *uaddr_len, int peer)
#endif
{
    int retval = 0;
    struct sock *sk = sock->sk;
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *) uaddr;

    TOA_DBG("inet6_getname_toa called, sk->sk_user_data is %p\n",
        sk->sk_user_data);

    /* call orginal one */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,1)
    retval = inet6_getname(sock, uaddr, peer);
#else
    retval = inet6_getname(sock, uaddr, uaddr_len, peer);
#endif

    /* set our value if need */
    lock_cpu_toa_ip6_sk();

    if (retval >= 0 && NULL != sk->sk_user_data && peer) {
        if (sk_data_ready_addr == (unsigned long) sk->sk_data_ready) {
            struct toa_ip6_entry* ptr_ip6_entry  = sk->sk_user_data;
            struct toa_ip6_data* ptr_ip6_data = &ptr_ip6_entry->toa_data;

            if (sk == ptr_ip6_entry->sk &&
                TCPOPT_TOA == ptr_ip6_data->opcode &&
                TCPOLEN_IP6_TOA == ptr_ip6_data->opsize) {
                TOA_INC_STATS(ext_stats, GETNAME_TOA_OK_CNT);
                TOA_DBG("inet6_getname_toa: set new sockaddr, ip "
                    TOA_NIP6_FMT" -> "TOA_NIP6_FMT
                    ", port %u -> %u\n",
                    TOA_NIP6(sin->sin6_addr),
                    TOA_NIP6(ptr_ip6_data->in6_addr),
                    ntohs(sin->sin6_port),
                    ntohs(ptr_ip6_data->port));
                sin->sin6_port = ptr_ip6_data->port;
                sin->sin6_addr = ptr_ip6_data->in6_addr;
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

    unlock_cpu_toa_ip6_sk();

    return retval;
}

static inline int
get_kernel_ipv6_symbol(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    kallsyms_lookup_name_t kallsyms_lookup_name;
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
#endif

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

/* The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 * We need to save toa data into the new socket.
 * @param sk [out]  the socket
 * @param skb [in] the ack/ack-get packet
 * @param req [in] the open request for this connection
 * @param dst [out] route cache entry
 * @return NULL if fail new socket if succeed.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,1)
static struct sock *
tcp_v4_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
            struct request_sock *req,
            struct dst_entry *dst,
            struct request_sock *req_unhash,
            bool *own_req)
#else
static struct sock *
tcp_v4_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
            struct request_sock *req, struct dst_entry *dst)
#endif
{
    struct sock *newsock = NULL;
    int nat64 = 0;

    TOA_DBG("tcp_v4_syn_recv_sock_toa called\n");

    /* call orginal one */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,1)
    newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
#else
    newsock = tcp_v4_syn_recv_sock(sk, skb, req, dst);
#endif

    /* set our value if need */
    if (NULL != newsock && NULL == newsock->sk_user_data) {
        newsock->sk_user_data = get_toa_data(AF_INET, skb, &nat64);
        sock_reset_flag(newsock, SOCK_NAT64);
        if (NULL != newsock->sk_user_data) {
            TOA_INC_STATS(ext_stats, SYN_RECV_SOCK_TOA_CNT);
#ifdef TOA_NAT64_ENABLE
            if (nat64) {
                struct toa_ip6_entry *ptr_ip6_entry = newsock->sk_user_data;
                ptr_ip6_entry->sk = newsock;
                toa_ip6_hash(ptr_ip6_entry);

                newsock->sk_destruct = tcp_v6_sk_destruct_toa;

                sock_set_flag(newsock, SOCK_NAT64);
            }
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,1)
static struct sock *
tcp_v6_syn_recv_sock_toa(const struct sock *sk, struct sk_buff *skb,
             struct request_sock *req,
             struct dst_entry *dst,
             struct request_sock *req_unhash,
             bool *own_req)
#else
static struct sock *
tcp_v6_syn_recv_sock_toa(struct sock *sk, struct sk_buff *skb,
             struct request_sock *req, struct dst_entry *dst)
#endif
{
    struct sock *newsock = NULL;
    int nat64 = 0;

    TOA_DBG("tcp_v6_syn_recv_sock_toa called\n");

    /* call orginal one */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,1)
    newsock = tcp_v6_syn_recv_sock_org_pt(sk, skb, req, dst, req_unhash,
            own_req);
#else
    newsock = tcp_v6_syn_recv_sock_org_pt(sk, skb, req, dst);
#endif

    /* set our value if need */
    if (NULL != newsock && NULL == newsock->sk_user_data) {
        newsock->sk_user_data = get_toa_data(AF_INET6, skb, &nat64);
        sock_reset_flag(newsock, SOCK_NAT64);
        if (NULL != newsock->sk_user_data) {
            struct toa_ip6_entry *ptr_ip6_entry = newsock->sk_user_data;
            ptr_ip6_entry->sk = newsock;
            toa_ip6_hash(ptr_ip6_entry);

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

    struct proto_ops *inet_stream_ops_p;
    struct inet_connection_sock_af_ops *ipv4_specific_p;
    int rw_enable = 0;
    
    /* hook inet_getname for ipv4 */
    inet_stream_ops_p = (struct proto_ops *)&inet_stream_ops;
    
    if (is_ro_addr((unsigned long)(&inet_stream_ops.getname))) {
            set_addr_rw((unsigned long)(&inet_stream_ops.getname));
            rw_enable = 1;
    }
    inet_stream_ops_p->getname = inet_getname_toa;
    if (rw_enable == 1) {
            set_addr_ro((unsigned long)(&inet_stream_ops.getname));
            rw_enable = 0;
    }
    TOA_INFO("CPU [%u] hooked inet_getname <%p> --> <%p>\n",
            smp_processor_id(), inet_getname, inet_stream_ops_p->getname);
    
    ipv4_specific_p = (struct inet_connection_sock_af_ops *)&ipv4_specific;
    
    if (is_ro_addr((unsigned long)(&ipv4_specific.syn_recv_sock))) {
            set_addr_rw((unsigned long)(&ipv4_specific.syn_recv_sock));
            rw_enable = 1;
    }
    ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock_toa;
    if (rw_enable == 1) {
            set_addr_ro((unsigned long)(&ipv4_specific.syn_recv_sock));
            rw_enable = 0;
    }
    TOA_INFO("CPU [%u] hooked tcp_v4_syn_recv_sock <%p> --> <%p>\n",
            smp_processor_id(), tcp_v4_syn_recv_sock,
            ipv4_specific_p->syn_recv_sock);
#ifdef TOA_IPV6_ENABLE
    if (is_ro_addr((unsigned long)(&inet6_stream_ops_p->getname))) {
            set_addr_rw((unsigned long)(&inet6_stream_ops_p->getname));
            rw_enable = 1;
    }
    inet6_stream_ops_p->getname = inet6_getname_toa;
    if (rw_enable == 1) {
            set_addr_ro((unsigned long)(&inet6_stream_ops_p->getname));
            rw_enable = 0;
    }
    TOA_INFO("CPU [%u] hooked inet6_getname <%p> --> <%p>\n",
            smp_processor_id(), inet6_getname, inet6_stream_ops_p->getname);

    if (is_ro_addr((unsigned long)(&ipv6_specific_p->syn_recv_sock))) {
            set_addr_rw((unsigned long)(&ipv6_specific_p->syn_recv_sock));
            rw_enable = 1;
    }
    ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_toa;
    if (rw_enable == 1) {
            set_addr_ro((unsigned long)(&ipv6_specific_p->syn_recv_sock));
            rw_enable = 0;
    }
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

    struct proto_ops *inet_stream_ops_p;
    struct inet_connection_sock_af_ops *ipv4_specific_p;
    int rw_enable = 0;
    
    /* unhook inet_getname for ipv4 */
    inet_stream_ops_p = (struct proto_ops *)&inet_stream_ops;
    
    if (is_ro_addr((unsigned long)(&inet_stream_ops.getname))) {
            set_addr_rw((unsigned long)(&inet_stream_ops.getname));
            rw_enable = 1;
    }
    inet_stream_ops_p->getname = inet_getname;
    if (rw_enable == 1) {
            set_addr_ro((unsigned long)(&inet_stream_ops.getname));
            rw_enable = 0;
    }
    TOA_INFO("CPU [%u] unhooked inet_getname\n", smp_processor_id());
    
    /* unhook tcp_v4_syn_recv_sock for ipv4 */
    ipv4_specific_p = (struct inet_connection_sock_af_ops *)&ipv4_specific;
    if (is_ro_addr((unsigned long)(&ipv4_specific.syn_recv_sock))) {
            set_addr_rw((unsigned long)(&ipv4_specific.syn_recv_sock));
            rw_enable = 1;
    }
    set_addr_rw((unsigned long)(&ipv4_specific.syn_recv_sock));
    ipv4_specific_p->syn_recv_sock = tcp_v4_syn_recv_sock;
    if (rw_enable == 1) {
            set_addr_ro((unsigned long)(&ipv4_specific.syn_recv_sock));
            rw_enable = 0;
    }

    TOA_INFO("CPU [%u] unhooked tcp_v4_syn_recv_sock\n", smp_processor_id());

#ifdef TOA_IPV6_ENABLE
    if (inet6_stream_ops_p) {
            if (is_ro_addr((unsigned long)(&inet6_stream_ops_p->getname))) {
                    set_addr_rw((unsigned long)(&inet6_stream_ops_p->getname));
                    rw_enable = 1;
            }
            inet6_stream_ops_p->getname = inet6_getname;
            if (rw_enable == 1) {
                    set_addr_ro((unsigned long)(&inet6_stream_ops_p->getname));
                    rw_enable = 0;
            }
            TOA_INFO("CPU [%u] unhooked inet6_getname\n", smp_processor_id());
    }
    if (ipv6_specific_p) {
            if (is_ro_addr((unsigned long)(&ipv6_specific_p->syn_recv_sock))) {
                    set_addr_rw((unsigned long)(&ipv6_specific_p->syn_recv_sock));
                    rw_enable = 1;
            }
            ipv6_specific_p->syn_recv_sock = tcp_v6_syn_recv_sock_org_pt;
            if (rw_enable == 1) {
                    set_addr_ro((unsigned long)(&ipv6_specific_p->syn_recv_sock));
                    rw_enable = 0;
            }
            TOA_INFO("CPU [%u] unhooked tcp_v6_syn_recv_sock\n", smp_processor_id());
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops toa_stats_fops = {
    .proc_open = toa_stats_seq_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations toa_stats_fops = {
    .owner = THIS_MODULE,
    .open = toa_stats_seq_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

#ifdef TOA_NAT64_ENABLE
static struct nf_sockopt_ops toa_sockopts = {
    .pf    = PF_INET,
    .owner    = THIS_MODULE,
    /* Nothing to do in set */
    /* get */
    .get_optmin = TOA_BASE_CTL,
    .get_optmax = TOA_SO_GET_MAX+1,
    .get        = inet64_getname_toa,
};
#endif

/*
 * TOA module init and destory
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static struct proc_dir_entry *proc_net_fops_create(struct net *net,
    const char *name, mode_t mode, const struct proc_ops *proc_ops)
{
    return proc_create(name, mode, net->proc_net, proc_ops);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
static struct proc_dir_entry *proc_net_fops_create(struct net *net,
    const char *name, mode_t mode, const struct file_operations *fops)
{
    return proc_create(name, mode, net->proc_net, fops);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
static void proc_net_remove(struct net *net, const char *name)
{
    remove_proc_entry(name, net->proc_net);
}
#endif

/* module init */
static int __init
toa_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int ret = register_kprobe(&kp);
    if (ret < 0) {
        TOA_INFO("register_kprobe failed, returned %d\n", ret);
        return 1;
    }
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
#endif

    TOA_INFO("TOA " TOA_VERSION " by qlb of iqiyi.\n");

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

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
    if (0 != init_toa_ip6()) {
        TOA_INFO("init toa ip6 fail.\n");
        goto err;
    }
#endif

#ifdef TOA_IPV6_ENABLE
    if (0 != get_kernel_ipv6_symbol()) {
        TOA_INFO("get ipv6 struct from kernel fail.\n");
        goto err;
    }
#endif

#ifdef TOA_NAT64_ENABLE
    if (0 != nf_register_sockopt(&toa_sockopts)) {
        TOA_INFO("fail to register sockopt\n");
        goto err;
    }
#endif

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
#ifdef TOA_NAT64_ENABLE
    nf_unregister_sockopt(&toa_sockopts);
#endif
    synchronize_net();

#if (defined(TOA_IPV6_ENABLE) || defined(TOA_NAT64_ENABLE))
    if (0 != exit_toa_ip6()) {
        TOA_INFO("exit toa ip6 fail.\n");
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    unregister_kprobe(&kp);
#endif

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
