#include <assert.h>
#include <endian.h>
#include <rte_hash_crc.h>
#include <rte_arp.h>
#include "dpdk.h"
#include "netif.h"
#include "ipv4.h"
#include "icmp.h"
#include "icmp6.h"
#include "flow.h"
#include "list.h"
#include "rculist.h"
#include "ip_tunnel.h"
#include "ipvs/conn.h"
#include "ipvs/dest.h"
#include "scheduler.h"
#include "conf/ip_tunnel.h"
#include "ipv4_frag.h"
#include "parser/parser.h"
#include "vxlan.h"
#include "srss.h"

struct vxlan_tun_node {
    struct hlist_node node;
    struct list_head arp_list;
    uint32_t ip;
    struct vxlan_tunnel *vxlan;
};

static struct ip_tunnel_tab vxlan_tunnel_tab;
static struct ip_tunnel *vxlan_tnl = NULL;
static uint16_t vxlan_port = 0; // network order
int vxlan_srss = 1;
static const int vxlan_ht_size = (1<<10);
static struct hlist_head *vxlan_tunnels = NULL;
uint8_t bind_vni_prefix = 244;

/* arp list is only used in master, no lock needed */
static LIST_HEAD(arp_list_head);
static int arp_list_push(struct vxlan_tun_node *node)
{
    list_add_tail(&node->arp_list, &arp_list_head);
    return EDPVS_OK;
}

static int arp_list_push_head(struct vxlan_tun_node *node)
{
    list_add(&node->arp_list, &arp_list_head);
    return EDPVS_OK;
}

static struct vxlan_tun_node *arp_list_pop(void)
{
    struct vxlan_tun_node *tmp = NULL;
    tmp = list_first_entry_or_null(&arp_list_head,
                 struct vxlan_tun_node, arp_list);
    if (tmp) {
        list_del_init(&tmp->arp_list);
    }
    return tmp;
}

static int vxlan_resolve_arp(struct vxlan_tun_node* node)
{
    return arp_list_push(node);
}

static int vxlan_resolve_arp_stop(struct vxlan_tun_node *node)
{
    if (!list_empty(&node->arp_list)) {
        list_del_init(&node->arp_list);
    }
    return EDPVS_OK;
}

static int is_ip_bind_vni(uint32_t ip)
{
    return *(uint8_t*)&ip == bind_vni_prefix;
}

static uint32_t get_ip_bind_vni(uint32_t ip)
{
    uint32_t vni = ip;
    *(uint8_t*)&vni = 0;
    return vni;
}

static uint32_t get_vni_bind_ip(uint32_t vni)
{
    uint32_t ip = vni;
    *(uint8_t*)&ip = bind_vni_prefix;
    return ip;
}

static uint32_t __vxlan_dest_hash(uint32_t ip)
{
    uint32_t hash = 0;
    hash = rte_hash_crc_4byte(ip, hash);
    return hash % vxlan_ht_size;
}

static uint32_t vxlan_dest_hash(struct vxlan_tun_node *node)
{
    return __vxlan_dest_hash(node->ip);
}

static int dp_vs_vxlan_src_select(struct vxlan_tunnel *vxlan)
{
    if (vxlan_tunnel_auto_local(vxlan)) {
        struct route_entry *rt = NULL;
        struct flow4 fl4;
        memset(&fl4, 0, sizeof(struct flow4));
        fl4.fl4_daddr.s_addr = vxlan->remote;
        rt = route4_output(&fl4);
        if (rt && rt->port) {
            union inet_addr addr;
            union inet_addr daddr;
            daddr.in.s_addr = vxlan->remote;
            inet_addr_select(AF_INET, rt->port, &daddr, 0, &addr);
            vxlan->local = addr.in.s_addr;
        }
        if (rt) {
            route4_put(rt);
        }
    }
    return EDPVS_OK;
}

int vxlan_add_dest(struct dp_vs_service *svc, struct dp_vs_dest *dest)
{
    if (!svc || !dest) {
        return EDPVS_INVAL;
    }
    struct vxlan_tunnel *vxlan = &dest->vxlan;
    if (!vxlan_tunnel_enabled(vxlan)) {
        return EDPVS_OK;
    }
    dp_vs_vxlan_src_select(vxlan);
    if (rte_lcore_id() != rte_get_master_lcore()) {
        return EDPVS_OK;
    }
    struct vxlan_tun_node *node = rte_malloc("vxlan_hash_node", sizeof(*node), 0);
    if (!node) {
        return EDPVS_NOMEM;
    }
    INIT_LIST_HEAD(&node->arp_list);
    node->vxlan = vxlan;
    node->ip = dest->addr.in.s_addr;
    uint32_t hash = vxlan_dest_hash(node);
    hlist_add_head_rcu(&node->node, &vxlan_tunnels[hash]);
    if (vxlan_tunnel_arp_resolve(vxlan)) {
        vxlan_resolve_arp(node);
    }
    return EDPVS_OK;
}

int vxlan_del_dest(struct dp_vs_service *svc, struct dp_vs_dest *dest)
{
    if (rte_lcore_id() != rte_get_master_lcore()) {
        return EDPVS_OK;
    }
    if (!svc || !dest) {
        return EDPVS_INVAL;
    }
    struct vxlan_tunnel *vxlan = &dest->vxlan;
    if (!vxlan_tunnel_enabled(vxlan)) {
        return EDPVS_OK;
    }
    uint32_t ip = dest->addr.in.s_addr;
    uint32_t hash = __vxlan_dest_hash(ip);
    struct vxlan_tun_node *node = NULL;
    hlist_for_each_entry_rcu(node, &vxlan_tunnels[hash], node) {
        if (node->vxlan == &dest->vxlan) {
            vxlan_resolve_arp_stop(node);
            hlist_del_rcu(&node->node);
            dpvs_wait_lcores();
            rte_free(node);
            return EDPVS_OK;
        }
    }
    return EDPVS_NOTEXIST;
}

int vxlan_update_dest(struct dp_vs_service *svc, struct dp_vs_dest *dest, struct dp_vs_dest_conf *udest)
{
    if (!svc || !dest || !udest) {
        return EDPVS_INVAL;
    }
    vxlan_del_dest(svc, dest);
    dest->vxlan = udest->vxlan;
    vxlan_add_dest(svc, dest);
    return EDPVS_OK;
}

static struct vxlan_tun_node* get_vxlan_node(uint32_t vni, uint32_t ip)
{
    uint32_t hash = __vxlan_dest_hash(ip);
    struct vxlan_tun_node *node = NULL;
    hlist_for_each_entry_rcu(node, &vxlan_tunnels[hash], node) {
        if (node->ip == ip && 
           (!vxlan_tunnel_bind_vni(node->vxlan) || node->vxlan->vni == vni)) {
            return node;
        }
    }
    return NULL;
}

static struct vxlan_tunnel* get_vxlan_tunnel(uint32_t vni, uint32_t ip)
{
    struct vxlan_tun_node *node = get_vxlan_node(vni, ip);
    if (node) {
        return node->vxlan;
    }
    return NULL;
}

static uint32_t vxlan_get_vni_from_mac(uint8_t *mac)
{
    uint32_t vni = 0;
    if (mac[0] == 0xee && mac[1] == 0xff) {
        memcpy(&vni, &mac[2], sizeof(uint32_t));
    }
    return vni;
}

static int vxlan_set_vni_into_mac(uint32_t vni, uint8_t *mac)
{
    mac[0] = 0xee;
    mac[1] = 0xff;
    memcpy(&mac[2], &vni, sizeof(uint32_t));
    return EDPVS_OK;
}

static void csum_replace4(uint16_t *sum, uint32_t from, uint32_t to)
{
    uint32_t diff[] = { ~from, to };
    uint16_t old_sum = *sum;
    old_sum = ~old_sum;
    *sum = ~__rte_raw_cksum_reduce(__rte_raw_cksum(diff, sizeof(diff), old_sum));
}

int dpvs_health_check_vni_bind(struct rte_mbuf *mbuf)
{
    if (mbuf->port != vxlan_tnl->dev->id) {
        return EDPVS_OK;
    }

    if (!rte_pktmbuf_adj(mbuf, mbuf->userdata - rte_pktmbuf_mtod(mbuf, void*))) {
        return EDPVS_OK;
    }
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
    if (eth->ether_type != htons(ETH_P_IP)) {
        return EDPVS_OK;
    }
    uint32_t vni = 0;
    vni = vxlan_get_vni_from_mac(eth->s_addr.addr_bytes);
    struct iphdr *iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr*, sizeof(struct ether_hdr));
    struct vxlan_tunnel *vxlan = get_vxlan_tunnel(vni, iph->saddr);
    if (!vxlan) {
        return EDPVS_OK;
    }
    if (vxlan_tunnel_bind_vni(vxlan)) {
        uint32_t ip = get_vni_bind_ip(vxlan->vni);
        csum_replace4(&iph->check, iph->daddr, ip);
        if (iph->protocol == IPPROTO_UDP) {
            struct udp_hdr *uh = (struct udp_hdr *)((void*)iph + (iph->ihl << 2));
            csum_replace4(&uh->dgram_cksum, iph->daddr, ip);
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcp_hdr *th = (struct tcp_hdr *)((void*)iph + (iph->ihl << 2));
            csum_replace4(&th->cksum, iph->daddr, ip);
        }
        iph->daddr = ip;
    }
    return EDPVS_OK;
}

#define DPVS_VXLAN_DFT_SRC_PORT 4789
#define DPVS_VXLAN_TTL 64
#define DPVS_VXLAN_MIN_PORT 10000
static inline uint16_t udp_flow_src_port(struct rte_mbuf *mbuf,
                                         struct dp_vs_conn *conn)
{
    if (!conn) {
        return DPVS_VXLAN_DFT_SRC_PORT;
    }
    uint32_t hash = conn->lport << 16 | conn->dport;
    hash = rte_hash_crc(&conn->laddr, sizeof(conn->laddr), hash);
    hash = rte_hash_crc(&conn->daddr, sizeof(conn->daddr), hash);
    hash = (hash ^ (hash >> 16)) & 0xffff;
    if (hash < DPVS_VXLAN_MIN_PORT) {
        hash += DPVS_VXLAN_MIN_PORT;
    }
    return hash;
}

static int dp_vs_vxlan_encap(uint16_t eth_type, struct rte_mbuf *mbuf, struct dp_vs_conn *conn,
                             struct vxlan_tunnel* vxlan)
{
    struct ether_hdr *eth = NULL;
    struct vxlan_hdr *vh = NULL;
    struct udp_hdr *uh = NULL;
    struct ipv4_hdr *iph = NULL;
    if (rte_pktmbuf_headroom(mbuf) < (sizeof(struct ether_hdr) * 2
                                    + sizeof(struct vxlan_hdr) 
                                    + sizeof(struct udp_hdr)
                                    + sizeof(struct ipv4_hdr))) {
        return EDPVS_NOROOM;
    }
    eth = (struct ether_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));
    memcpy(eth->d_addr.addr_bytes, vxlan->dmac, ETHER_ADDR_LEN);
    eth->ether_type = eth_type;
    vh = (struct vxlan_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct vxlan_hdr));
    vh->vx_flags = htonl(1<<27);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    vh->vx_vni = vxlan->vni << 8;
#else
    vh->vx_vni = vxlan->vni >> 8;
#endif

    /* clean ol flags to make pkt type & offload flags right */
    mbuf->ol_flags = 0;
    uh = (struct udp_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct udp_hdr));
    uh->src_port = udp_flow_src_port(mbuf, conn);
    uh->dst_port = vxlan->rport;
    uh->dgram_len = htons(rte_pktmbuf_pkt_len(mbuf));
    uh->dgram_cksum = 0;

    iph = (struct ipv4_hdr*)rte_pktmbuf_prepend(mbuf, sizeof(struct ipv4_hdr));
    memset(iph, 0, sizeof(struct ipv4_hdr));
    iph->version_ihl = 0x45;
    iph->total_length = htons(mbuf->pkt_len);
    iph->time_to_live = DPVS_VXLAN_TTL;
    iph->next_proto_id = IPPROTO_UDP;
    iph->dst_addr = vxlan->remote;
    iph->src_addr = vxlan->local;
    iph->packet_id = ip4_select_id(iph);
    mbuf->l3_len = sizeof(struct ipv4_hdr);
    mbuf->l4_len = ntohs(iph->total_length) - sizeof(struct ipv4_hdr);
    mbuf->ol_flags |= PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4;
    iph->hdr_checksum = 0;
    uh->dgram_cksum = rte_ipv4_phdr_cksum(iph, mbuf->ol_flags);
    return EDPVS_OK;
}

static int dpvs_vxlan_fix_csum(struct rte_mbuf *mbuf, struct netif_port *port)
{
    if (!mbuf || !port) {
        return EDPVS_OK;
    }
    if ((mbuf->ol_flags & PKT_TX_IP_CKSUM) &&
        !(port->flag &  NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)) {
        struct ipv4_hdr *iph = rte_pktmbuf_mtod(mbuf, struct ipv4_hdr*);
        iph->hdr_checksum = 0;
        iph->hdr_checksum = rte_ipv4_cksum(iph);
        struct udp_hdr *uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr*, sizeof(struct ipv4_hdr));
        /* disable udp checksum */
        uh->dgram_cksum = 0;
        mbuf->ol_flags &= ~(PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_IPV4);
    } else if ((mbuf->ol_flags & PKT_TX_UDP_CKSUM) &&
        !(port->flag &  NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)) {
        struct udp_hdr *uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr*, sizeof(struct ipv4_hdr));
        uh->dgram_cksum = 0;
        mbuf->ol_flags &= ~(PKT_TX_UDP_CKSUM);
    }
    return EDPVS_OK;
}

int dpvs_health_check_vxlan_encap(struct rte_mbuf *mbuf, struct netif_port *port)
{
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
    if (eth->ether_type != htons(ETH_P_IP)) {
        return EDPVS_OK;
    }
    struct iphdr *iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, sizeof(struct ether_hdr));
    uint32_t vni = 0;
    /* source address 127.0.0.0/8 is bind vni  */
    if (is_ip_bind_vni(iph->saddr))  {
        vni = get_ip_bind_vni(iph->saddr);
        union inet_addr addr;
        union inet_addr daddr;
        daddr.in.s_addr = iph->daddr;
        inet_addr_select(AF_INET, port, &daddr, 0, &addr);
        csum_replace4(&iph->check, iph->saddr, addr.in.s_addr);
        if (iph->protocol == IPPROTO_UDP) {
            struct udp_hdr *uh = (struct udp_hdr *)((void*)iph + (iph->ihl << 2));
            csum_replace4(&uh->dgram_cksum, iph->saddr, addr.in.s_addr);
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcp_hdr *th = (struct tcp_hdr *)((void*)iph + (iph->ihl << 2));
            csum_replace4(&th->cksum, iph->saddr, addr.in.s_addr);
        }
        iph->saddr = addr.in.s_addr;
    }
    struct vxlan_tunnel *vxlan = get_vxlan_tunnel(vni, iph->daddr);
    if (!vxlan) {
        return EDPVS_OK;
    }
    struct ether_hdr _eth;
    memcpy(&_eth, eth, sizeof(_eth));
    rte_pktmbuf_adj(mbuf, sizeof(struct ether_hdr));
    if (dp_vs_vxlan_encap(htons(ETHER_TYPE_IPv4), mbuf, NULL, vxlan) != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to encap vxlan for health check packet\n", __func__);
        rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));
        return EDPVS_OK;
    }
    dpvs_vxlan_fix_csum(mbuf, port);
    rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));
    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
    /* use the origin mac header */
    memcpy(eth, &_eth, sizeof(_eth));
    return EDPVS_OK;
}

static int dp_vs_vxlan_fnat4(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    int ret = EDPVS_OK;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    /* pre-handler before translation */
    if (proto->fnat_in_pre_handler) {
        ret = proto->fnat_in_pre_handler(proto, conn, mbuf);
        if (ret != EDPVS_OK) {
            return ret;
        }
        iph = ip4_hdr(mbuf);
    }

    /* L3 translation before l4 re-csum */
    iph->src_addr = conn->laddr.in.s_addr;
    iph->dst_addr = conn->daddr.in.s_addr;
    iph->hdr_checksum = 0;

    /* L4 FNAT translation */
    if (proto->fnat_in_handler) {
        ret = proto->fnat_in_handler(proto, conn, mbuf);
        if (ret != EDPVS_OK) {
            return ret;
        }
    }
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    mbuf->ol_flags &=~ PKT_TX_IP_CKSUM;
    return ret;
}

static int dp_vs_vxlan_nat(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    switch (conn->dest->fwdmode) {
    case DPVS_FWD_MODE_TUNNEL:
    case DPVS_FWD_MODE_DR:
        /* maybe packet was modified, or self generated, and set csum hw offload */
        return EDPVS_OK;
    case DPVS_FWD_MODE_FNAT:
        if (tuplehash_in(conn).af == AF_INET &&
                tuplehash_out(conn).af == AF_INET) {
            return dp_vs_vxlan_fnat4(proto, conn, mbuf);
        } else {
            return EDPVS_NOTSUPP;
        }
        break;
    default:
        return EDPVS_NOTSUPP;
    }
    return EDPVS_OK;
}
static int dp_vs_vxlan_out_route(struct rte_mbuf *mbuf)
{
    struct route_entry *rt = NULL;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct flow4 fl4;
    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr.s_addr = iph->dst_addr;
    fl4.fl4_tos = iph->type_of_service;
    rt = route4_output(&fl4);
    if (!rt) {
        return EDPVS_NOROUTE;
    }
    if (!rt->port) {
        route4_put(rt);
        return EDPVS_NOROUTE;
    }

    mbuf->userdata = rt;
    return EDPVS_OK;
}

struct vxlan_route {
    struct route_entry rt;
    struct vxlan_tunnel* vxlan;
} __rte_cache_aligned;
struct vxlan_route *vxlan_rt;
static int __vxlan_xmit(struct rte_mbuf *mbuf)
{
    int ret = EDPVS_OK;
    lcoreid_t cid = rte_lcore_id();
    uint16_t eth_type = htons(ETHER_TYPE_IPv4);
    if (rte_pktmbuf_mtod(mbuf, struct iphdr *)->version == 6) {
        eth_type = htons(ETHER_TYPE_IPv6);
    }
    ret = dp_vs_vxlan_encap(eth_type, mbuf, NULL, vxlan_rt[cid].vxlan);
    if (ret != EDPVS_OK) {
        goto errout;
    }

    ret = dp_vs_vxlan_out_route(mbuf);
    if (ret != EDPVS_OK) {
        goto errout;
    }
    struct route_entry *rt = mbuf->userdata;
    dpvs_vxlan_fix_csum(mbuf, rt->port);
    return INET_HOOK(AF_INET, INET_HOOK_LOCAL_OUT, mbuf,
                     NULL, rt->port, ipv4_output);
errout:
    rte_pktmbuf_free(mbuf);
    return ret;
}

static int vxlan_frag_out(struct rte_mbuf *mbuf, uint32_t mtu, int (*xmit)(struct rte_mbuf *))
{
    struct iphdr *iph = rte_pktmbuf_mtod(mbuf, struct iphdr *);
    if (iph->version == 4) {
        if (iph->frag_off & htons(IP_DF)) {
            icmp_send(mbuf, ICMP_DEST_UNREACH, ICMP_UNREACH_NEEDFRAG,
                    htonl(mtu));
            goto errout;
        }
        return ipv4_fragment(mbuf, mtu, xmit);
    } else if (iph->version == 6) {
        icmp6_send(mbuf, ICMP6_PACKET_TOO_BIG, 0, htonl(mtu));
        goto errout;
    } else {
        goto errout;
    }
    return EDPVS_OK;
errout:
    RTE_LOG(DEBUG, IPVS, "%s: frag needed.\n", __func__);
    rte_pktmbuf_free(mbuf);
    return EDPVS_FRAG;
}

int dp_vs_xmit_vxlan(struct dp_vs_proto *proto,
                    struct dp_vs_conn *conn,
                    struct rte_mbuf *mbuf)
{
    lcoreid_t cid = rte_lcore_id();
    //assert(conn->dest);
    struct vxlan_tunnel* vxlan = &conn->dest->vxlan;
    int ret = EDPVS_OK;

    if (unlikely(mbuf->userdata != NULL)) {
        RTE_LOG(WARNING, IPVS, "%s: VXLAN TUNNEL have route %p ?\n",
                __func__, mbuf->userdata);
        route4_put((struct route_entry*)mbuf->userdata);
        mbuf->userdata = NULL;
    }

#ifdef DPVS_VXLAN_ARP_RESOLVE
    if (!vxlan_tunnel_arp_resolved(vxlan)) {
        /* arp is only handled in master lcore */
        struct vxlan_tunnel* m_vxlan = get_vxlan_tunnel(vxlan->vni, conn->dest->addr.in.s_addr);
        if (m_vxlan && vxlan_tunnel_arp_resolved(m_vxlan)) {
            memcpy(vxlan->dmac, m_vxlan->dmac, ETHER_ADDR_LEN);
            vxlan_tunnel_set_arp_resolved(vxlan, 1);
        }
    }
#endif
    vxlan_rt[cid].vxlan = vxlan;
    mbuf->userdata = &vxlan_rt[cid].rt;

    ret = dp_vs_vxlan_nat(proto, conn, mbuf);
    if (ret != EDPVS_OK) {
        goto errout;
    }
    if (mbuf->pkt_len > vxlan_rt[cid].rt.mtu) {
        return vxlan_frag_out(mbuf, vxlan_rt[cid].rt.mtu, __vxlan_xmit);
    }
    return __vxlan_xmit(mbuf);
errout:
    rte_pktmbuf_free(mbuf);
    return ret;
}

static int vxlan_update_mac(struct vxlan_tunnel *vxlan, uint32_t ipaddr)
{
    struct vxlan_tunnel *v = get_vxlan_tunnel(vxlan->vni, ipaddr);
    if (v) {
        memcpy(v->dmac, vxlan->dmac, ETHER_ADDR_LEN);
        vxlan_tunnel_set_arp_resolved(v, 1);
    }
    return EDPVS_OK;
}

static int vxlan_process_arp(struct rte_mbuf *mbuf, struct vxlan_tunnel* vxlan)
{
    struct ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr*);
    rte_pktmbuf_adj(mbuf, sizeof(struct ether_hdr));
    struct arp_hdr *arp = rte_pktmbuf_mtod(mbuf, struct arp_hdr *);
    struct netif_port *port = netif_port_get(mbuf->port);
    uint32_t ipaddr = 0;
    int ret = EDPVS_OK;

    switch (rte_be_to_cpu_16(arp->arp_op)) {
    case ARP_OP_REQUEST:
        ether_addr_copy(&eth->s_addr, &eth->d_addr);
        rte_memcpy(&eth->s_addr, &port->addr, 6);
        arp->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

        ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
        ether_addr_copy(&eth->s_addr, &arp->arp_data.arp_sha);

        ipaddr = arp->arp_data.arp_sip;
        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
        arp->arp_data.arp_tip = ipaddr;
        mbuf->l2_len = sizeof(struct ether_hdr);
        mbuf->l3_len = sizeof(struct arp_hdr);
        ret = dp_vs_vxlan_encap(htons(ETHER_TYPE_ARP), mbuf, NULL, vxlan);
        if (ret != EDPVS_OK) {
            goto err;
        }
        ret = dp_vs_vxlan_out_route(mbuf);
        if (ret != EDPVS_OK) {
            goto err;
        }
        dpvs_vxlan_fix_csum(mbuf, port);
        return ipv4_output(mbuf);
        break;
     case ARP_OP_REPLY:
        ipaddr = arp->arp_data.arp_sip;
        memcpy(vxlan->dmac, arp->arp_data.arp_sha.addr_bytes, ETHER_ADDR_LEN);
        vxlan_update_mac(vxlan, ipaddr);
        rte_pktmbuf_free(mbuf);
        return EDPVS_OK;
    default:
        goto err;
    }
    return EDPVS_OK;
err:
    rte_pktmbuf_free(mbuf);
    return EDPVS_DROP;
}

static int vxlan_srss_redirect(portid_t port_id,struct rte_mbuf *mbuf)
{
    uint32_t pktlen = sizeof(struct ether_hdr);
    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    if (eth_hdr->ether_type != htons(ETH_P_IP)) {
        return EDPVS_NOTEXIST;
    }
    struct iphdr *iph = rte_pktmbuf_mtod_offset(mbuf, struct iphdr *, pktlen);
    uint16_t hlen = iph->ihl << 2;
    pktlen += hlen;
    /* only src_port & dst_port are needed, and they are at same position */
    struct udp_hdr *uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, pktlen);
    if (iph->protocol == IPPROTO_TCP) {
        pktlen += sizeof(struct tcp_hdr);
    } else if (iph->protocol == IPPROTO_UDP) {
        pktlen += sizeof(struct udp_hdr);
    } else {
        return EDPVS_NOTEXIST;
    }
    if (mbuf_may_pull(mbuf, pktlen) != 0) {
        return EDPVS_NOTEXIST;
    }

    struct netif_port* port = netif_port_get(port_id);
    if (unlikely(!port))
        return EDPVS_NOTEXIST;
    /* should swap src & dst */
    struct srss_flow flow = {
        .af = AF_INET,
        .proto = iph->protocol,
        .saddr.in.s_addr = iph->saddr,
        .daddr.in.s_addr = iph->daddr,
        .sport = uh->src_port,
        .dport = uh->dst_port,
    };
    uint32_t qid = 0;
    lcoreid_t peer_cid = 0;
    if (dpvs_srss_fdir_get(port, &flow, &qid) == EDPVS_OK) {
        lcoreid_t cid = rte_lcore_id();
        if (netif_get_lcore(port, qid, &peer_cid) == EDPVS_OK && cid != peer_cid) {
            if (dp_vs_redirect_pkt(mbuf, peer_cid) == INET_STOLEN) {
                return EDPVS_OK;
            }
            // else fallthrough
        }
    }
    return EDPVS_NOTEXIST;
}
/* vxlan->local & vxlan->remote MUST be set by caller */
static int vxlan_rcv(struct rte_mbuf *mbuf, struct vxlan_tunnel* vxlan)
{
    struct ether_hdr *eth_hdr = NULL;
    struct vxlan_hdr *vh = NULL;
    portid_t orig_port = mbuf->port;
    if (mbuf_may_pull(mbuf, vxlan_tnl->hlen) != 0) {
        return EDPVS_KNICONTINUE;
    }

    vh = rte_pktmbuf_mtod(mbuf, struct vxlan_hdr *);
    eth_hdr = (void*)rte_pktmbuf_adj(mbuf, sizeof(struct vxlan_hdr));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    vxlan->vni = vh->vx_vni >> 8;
#else
    vxlan->vni = vh->vx_vni << 8;
#endif
    memcpy(vxlan->dmac, eth_hdr->s_addr.addr_bytes, ETHER_ADDR_LEN);

    if (eth_hdr->ether_type == htons(ETH_P_ARP)) {
        return vxlan_process_arp(mbuf, vxlan);
    }

    /* local route lookup MUST match in port */
    //mbuf->port = vxlan_tnl->dev->id;

    if (vxlan_srss && vxlan_srss_redirect(orig_port, mbuf) == EDPVS_OK) {
        return EDPVS_OK;
    }
    rte_pktmbuf_adj(mbuf, sizeof(struct ether_hdr));
    int ret = netif_rcv(vxlan_tnl->dev, eth_hdr->ether_type, mbuf);
    if (ret == EDPVS_KNICONTINUE) {
        mbuf->userdata = eth_hdr;
        /* to kni do not use this port*/
        mbuf->port = vxlan_tnl->dev->id;
        /* set vni into smac, for health check packet vni bind revert */
        vxlan_set_vni_into_mac(vxlan->vni, eth_hdr->s_addr.addr_bytes);
    }
    return ret;
}
static int udp_rcv(struct rte_mbuf *mbuf)
{
    struct iphdr *iph;
    struct udp_hdr *uh;

    /* IPv4's upper layer can use @userdata for IP header,
     * see ipv4_local_in_fin() */
    iph = mbuf->userdata;
    assert(iph->version == 4 && iph->protocol == IPPROTO_UDP);

    uh = rte_pktmbuf_mtod(mbuf, struct udp_hdr*);
    if (vxlan_port && uh->dst_port != vxlan_port) {
        return EDPVS_KNICONTINUE;
    }
    rte_pktmbuf_adj(mbuf, sizeof(struct udp_hdr));
    /* for arp response encap */
    struct vxlan_tunnel vxlan = {
        .local = iph->daddr,
        .remote = iph->saddr,
        .rport = uh->dst_port,
    };
    return vxlan_rcv(mbuf, &vxlan);
}

static struct inet_protocol udp_proto = {
    .handler    = udp_rcv,
};

static int vxlan_xmit(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    return __vxlan_xmit(mbuf);
}

static int vxlan_dev_init(struct netif_port *dev)
{
    struct ip_tunnel *tnl = netif_priv(dev);
    tnl->hlen = sizeof(struct vxlan_hdr) + sizeof(struct ether_hdr);
    return EDPVS_OK;
}

static struct netif_ops vxlan_dev_ops = {
    .op_init        = vxlan_dev_init,
    .op_xmit        = vxlan_xmit,
    .op_get_link    = ip_tunnel_get_link,
    .op_get_stats   = ip_tunnel_get_stats,
    .op_get_promisc = ip_tunnel_get_promisc,
};

static void vxlan_setup(struct netif_port *dev)
{
    dev->netif_ops = &vxlan_dev_ops;
}

static struct ip_tunnel_ops vxlan_tnl_ops = {
    .kind       = "vxlan",
    .priv_size  = sizeof(struct ip_tunnel),
    .setup      = vxlan_setup,
};

static int send_arp_request(uint32_t ip, struct vxlan_tunnel *vxlan)
{
    struct rte_mbuf *m = NULL;
    struct ether_hdr *eth = NULL;
    struct arp_hdr *arp = NULL;
    int ret = EDPVS_OK;
    struct netif_port *port = NULL;
    struct flow4 fl4 = {};
    struct route_entry *rt = NULL;
    fl4.fl4_proto           = IPPROTO_UDP;
    fl4.fl4_daddr.s_addr    = ip;

    rt = route4_output(&fl4);
    if (!rt) {
        ret = EDPVS_NOROUTE;
        goto errout;
    }
    port = rt->port;
    route4_put(rt);
    if (!port) {
        ret = EDPVS_NOROUTE;
        goto errout;
    }
    union inet_addr saddr = {};
    union inet_addr daddr = {
        .in.s_addr = ip,
    };
    inet_addr_select(AF_INET, port, &daddr, 0, &saddr);
    if (!saddr.in.s_addr) {
        ret = EDPVS_NOROUTE;
        goto errout;
    }
    m = rte_pktmbuf_alloc(port->mbuf_pool);
    if (unlikely(m == NULL)) {
        ret = EDPVS_NOMEM;
        goto errout;
    }
    m->userdata = NULL;

    eth = (void*)rte_pktmbuf_append(m, sizeof(struct ether_hdr));
    arp = (void*)rte_pktmbuf_append(m, sizeof(struct arp_hdr));
    if (!eth || !arp) {
        ret = EDPVS_NOMEM;
        rte_pktmbuf_free(m);
        goto errout;
    }

    memset(arp, 0, sizeof(struct arp_hdr));
    rte_memcpy(&arp->arp_data.arp_sha, &port->addr, 6);
    arp->arp_data.arp_sip = saddr.in.s_addr;
    memset(&arp->arp_data.arp_tha, 0, 6);
    arp->arp_data.arp_tip = ip;

    arp->arp_hrd = htons(ARP_HRD_ETHER);
    arp->arp_pro = htons(ETHER_TYPE_IPv4);
    arp->arp_hln = 6;
    arp->arp_pln = 4;
    arp->arp_op  = htons(ARP_OP_REQUEST);
    m->l2_len    = sizeof(struct ether_hdr);
    m->l3_len    = sizeof(struct arp_hdr);

    rte_pktmbuf_adj(m, sizeof(struct ether_hdr));
    ret = dp_vs_vxlan_encap(htons(ETHER_TYPE_ARP), m, NULL, vxlan);
    if (ret != EDPVS_OK) {
        rte_pktmbuf_free(m);
        goto errout;
    }
    memset(&eth->d_addr, 0xFF, 6);
    ether_addr_copy(&port->addr, &eth->s_addr);
    eth->ether_type = htons(ETHER_TYPE_ARP);
    dpvs_vxlan_fix_csum(m, port);

    /* ipv4_xmit will rewrite every thing... */
    struct ipv4_hdr *iph = ip4_hdr(m);
    memset(&fl4, 0, sizeof(struct flow4));
    fl4.fl4_daddr.s_addr = iph->dst_addr;
    fl4.fl4_saddr.s_addr = iph->src_addr;
    fl4.fl4_proto = IPPROTO_UDP;
    /* mbuf header should at l4 header */
    rte_pktmbuf_adj(m, sizeof(struct ipv4_hdr));
    return netif_master_local_out4(m, &fl4);
errout:
    return ret;
}

#define DPVS_VXLAN_ARP_RESOLVE_BATCH 10
#define DPVS_VXLAN_ARP_RESOLVE_INTERVAL 5
static void resolve_arp(void *arg)
{
    static uint64_t next_t = 0;
    uint64_t t = rte_get_timer_cycles() / g_cycles_per_sec;
    if (t < next_t) {
        return;
    }
    int cnt = 0;
    struct vxlan_tun_node *node = NULL;
    struct vxlan_tun_node *first = NULL;
    while ((node = arp_list_pop())) {
        if (first == node) {
            arp_list_push_head(node);
            break;
        }
        struct vxlan_tunnel* o_vxlan = get_vxlan_tunnel(node->vxlan->vni, node->ip);
        if (o_vxlan != node->vxlan && o_vxlan && vxlan_tunnel_arp_resolved(o_vxlan)) {
            memcpy(node->vxlan->dmac, o_vxlan->dmac, ETHER_ADDR_LEN);
            vxlan_tunnel_set_arp_resolved(node->vxlan, 1);
        }
        if (!vxlan_tunnel_arp_resolved(node->vxlan)) {
            if (!first) {
                first = node;
            }
            send_arp_request(node->ip, node->vxlan);
            arp_list_push(node);
        }
        if (cnt++ >= DPVS_VXLAN_ARP_RESOLVE_BATCH) {
            return;
        }
    }
    next_t = t + DPVS_VXLAN_ARP_RESOLVE_INTERVAL;
    return;
}

static struct dpvs_lcore_job vxlan_arp_job = {
    .name = "vxlan_arp",
    .func = resolve_arp,
    .data = NULL,
    .type = LCORE_JOB_SLOW,
    .skip_loops = 10000,
};

int vxlan_init(void)
{
    int ret = EDPVS_OK;
    int i = 0;
    struct netif_port *dev = NULL;
    struct ip_tunnel_param params = {
        .ifname = "vxlan0",
        .kind = "vlxan",
    };
    vxlan_tunnels = rte_malloc("vxlan", sizeof(struct hlist_head) * vxlan_ht_size, 0);
    if (!vxlan_tunnels) {
        ret = EDPVS_NOMEM;
        goto alloc_vxlan_ht;
    }
    for (i = 0; i < vxlan_ht_size; i++) {
        INIT_HLIST_HEAD(&vxlan_tunnels[i]);
    }
    ret = ip_tunnel_init_tab(&vxlan_tunnel_tab, &vxlan_tnl_ops, "vxlan");
    if (ret != EDPVS_OK) {
        goto init_tab_failed;
    }
    dev = tunnel_create(vxlan_tnl_ops.tab, &vxlan_tnl_ops, &params);
    if (!dev) {
        ret = EDPVS_INVAL;
        goto vxlan0_create_failed;
    }
    vxlan_tnl = netif_priv(dev);
    ret = ipv4_register_protocol(&udp_proto, IPPROTO_UDP);
    if (ret != EDPVS_OK) {
        goto register_proto_failed;;
    }
    ret = dpvs_lcore_job_register(&vxlan_arp_job, LCORE_ROLE_MASTER);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to register vxlan_arp job\n", __func__);
        goto job_register_failed;
    }
    vxlan_rt = rte_malloc("vxlan", sizeof(struct vxlan_route) * DPVS_MAX_LCORE, RTE_CACHE_LINE_SIZE);
    if (!vxlan_rt) {
        goto rt_alloc_failed;
    }
    memset(vxlan_rt, 0, sizeof(struct vxlan_route) * DPVS_MAX_LCORE);
    for (i = 0; i < DPVS_MAX_LCORE; i++) {
        vxlan_rt[i].rt.port = dev;
        vxlan_rt[i].rt.mtu = dev->mtu;
        rte_atomic32_inc(&vxlan_rt[i].rt.refcnt);
    }
    return ret;
rt_alloc_failed:
    dpvs_lcore_job_unregister(&vxlan_arp_job, LCORE_ROLE_MASTER);
job_register_failed:
    ipv4_unregister_protocol(&udp_proto, IPPROTO_UDP);
register_proto_failed:
    tunnel_destroy(vxlan_tnl_ops.tab, vxlan_tnl->dev);
    vxlan_tnl = NULL;
vxlan0_create_failed:
    ip_tunnel_term_tab(&vxlan_tunnel_tab);
init_tab_failed:
    rte_free(vxlan_tunnels);
alloc_vxlan_ht:
    return ret;
}

int vxlan_term(void)
{
    int ret;
    if (vxlan_rt) {
        rte_free(vxlan_rt);
    }
    dpvs_lcore_job_unregister(&vxlan_arp_job, LCORE_ROLE_MASTER);
    ret = ipv4_unregister_protocol(&udp_proto, IPPROTO_UDP);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, IPVS, "%s: fail to unregister proto\n", __func__);
        return ret;
    }
    if (vxlan_tnl) {
        tunnel_destroy(vxlan_tnl_ops.tab, vxlan_tnl->dev);
        vxlan_tnl = NULL;
    }
    ret = ip_tunnel_term_tab(&vxlan_tunnel_tab);
    if (ret != EDPVS_OK)
        return ret;
    if (vxlan_tunnels) {
        rte_free(vxlan_tunnels);
    }
    return ret;
}

static void bind_vni_prefix_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t n = 0;

    assert(str);
    n = atoi(str);
    if (n > 0xff) {
        RTE_LOG(WARNING, NETIF, "invalid bind_vni_prefix %s, should in 0~255, using  %d\n", str, bind_vni_prefix);
    } else {
        bind_vni_prefix = n;
    }

    FREE_PTR(str);
}

static void vxlan_srss_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    vxlan_srss = !!atoi(str);
    FREE_PTR(str);
}

static void vxlan_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t n = 0;

    assert(str);
    n = atoi(str);
    if (n > 0xffff) {
        RTE_LOG(WARNING, NETIF, "invalid vxlan_port %s, should in 0~65535, 0 means any, using  %u\n", str, vxlan_port);
    } else {
        vxlan_port = n;
    }
    FREE_PTR(str);
}

void install_vxlan_keywords(void)
{
    install_keyword_root("vxlan", NULL);
    install_keyword("bind_vni_prefix", bind_vni_prefix_handler, KW_TYPE_INIT);
    install_keyword("vxlan_srss", vxlan_srss_handler, KW_TYPE_INIT);
    install_keyword("vxlan_port", vxlan_port_handler, KW_TYPE_INIT);
}

