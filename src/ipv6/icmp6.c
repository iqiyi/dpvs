/* just for testing IPv6, not real ICMPv6 implementation. */
#include <assert.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include "ipv6.h"
#include "icmp6.h"
#include "ndisc.h"

static inline uint16_t icmp6_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich)
{
    uint32_t csum, l4_len;
    struct ip6_hdr hdr;

    /* must be linear !! */
    l4_len = ntohs(iph->ip6_plen);
    if ((void *)ich != (void *)(iph + 1))
        l4_len -= (void *)ich - (void *)(iph+1);

    memset(&hdr, 0, sizeof(struct ip6_hdr));
    hdr.ip6_nxt     = IPPROTO_ICMPV6;
    hdr.ip6_plen    = htons(l4_len);
    hdr.ip6_src     = iph->ip6_src;
    hdr.ip6_dst     = iph->ip6_dst;

    csum = rte_raw_cksum(ich, l4_len);
    csum += rte_ipv6_phdr_cksum((struct ipv6_hdr *)&hdr, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0)
        csum = 0xffff;

    return csum;
}

static inline void icmp6_send_csum(struct ip6_hdr *shdr, struct icmp6_hdr *ich)
{
    uint32_t csum, l4_len;

    ich->icmp6_cksum = 0;

    l4_len = ntohs(shdr->ip6_plen);

    csum = rte_raw_cksum(ich, l4_len);
    csum += rte_ipv6_phdr_cksum((struct ipv6_hdr *)shdr, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0)
        csum = 0xffff;

    ich->icmp6_cksum = csum;
}

static int icmp6_rcv(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *iph = mbuf->userdata;
    struct icmp6_hdr *ich;
    struct flow6 fl6;
    struct ip6_hdr shdr; /* IPv6 header for sending packet */
    uint32_t icmp_len;

    assert(iph);

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0)
        goto drop;

    ich = rte_pktmbuf_mtod(mbuf, struct icmp6_hdr *);
    if (unlikely(!ich))
        goto drop;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
        goto drop;

    /* ndisc test*/
    if ((ich->icmp6_type == ND_NEIGHBOR_SOLICIT) ||
       (ich->icmp6_type == ND_NEIGHBOR_ADVERT)) {
        return ndisc_rcv(mbuf, netif_port_get(mbuf->port));
    }

    if (ich->icmp6_type != ICMP6_ECHO_REQUEST)
        goto drop;

    if (icmp6_csum(iph, ich) != 0xffff)
        goto drop;

    /* must be linear !! */
    icmp_len = ntohs(iph->ip6_plen);
    if ((void *)ich != (void *)(iph + 1))
        icmp_len -= (void *)ich - (void *)(iph+1);

    /* reply */
    ich->icmp6_type = ICMP6_ECHO_REPLY;

    memset(&shdr, 0, sizeof(struct ip6_hdr));
    shdr.ip6_nxt = IPPROTO_ICMPV6;
    shdr.ip6_plen = htons(icmp_len);
    if (!ipv6_addr_is_multicast(&iph->ip6_dst))
        shdr.ip6_src = iph->ip6_dst; /**/
    else
        inet_pton(AF_INET6, "fe80::1234:56ff:feaa:bbcc", &shdr.ip6_src);
    shdr.ip6_dst = iph->ip6_src;
    icmp6_send_csum(&shdr, ich);

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_oif = netif_port_get(mbuf->port);

    if (!ipv6_addr_is_multicast(&iph->ip6_dst))
        fl6.fl6_saddr = iph->ip6_dst;
    else
        inet_pton(AF_INET6, "fe80::1234:56ff:feaa:bbcc", &fl6.fl6_saddr);
    fl6.fl6_daddr = iph->ip6_src;
    fl6.fl6_proto = IPPROTO_ICMPV6;

    return ipv6_xmit(mbuf, &fl6);

drop:
    rte_pktmbuf_free(mbuf);
    return EDPVS_INVPKT;
}

static struct inet6_protocol icmp6_proto = {
    .handler    = icmp6_rcv,
    .flags      = INET6_PROTO_F_FINAL,
};

int icmpv6_init(void)
{
    ipv6_register_protocol(&icmp6_proto, IPPROTO_ICMPV6);
    return 0;
}

int icmpv6_term(void)
{
    ipv6_unregister_protocol(&icmp6_proto, IPPROTO_ICMPV6);
    return 0;
}
