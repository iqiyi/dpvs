/* just for testing IPv6, not real ICMPv6 implementation. */
#include <assert.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include "ipv6.h"
#include "icmp6.h"

static inline uint16_t icmp6_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich)
{
    uint32_t csum, l4_len;

    /* must be linear !! */
    l4_len = ntohs(iph->ip6_plen);
    if ((void *)ich != (void *)(iph + 1))
        l4_len -= (void *)ich - (void *)iph;

    csum = rte_raw_cksum(ich, l4_len);
    csum += rte_ipv6_phdr_cksum((struct ipv6_hdr *)iph, 0);

    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = (~csum) & 0xffff;
    if (csum == 0)
        csum = 0xffff;

    return csum;
}

static inline void icmp6_send_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich)
{
    ich->icmp6_cksum = 0;
    ich->icmp6_cksum = icmp6_csum(iph, ich);
}

static int icmp6_rcv(struct rte_mbuf *mbuf)
{
    struct ip6_hdr *iph = mbuf->userdata;
    struct icmp6_hdr *ich;
    struct flow6 fl6;

    assert(iph);

    if (mbuf_may_pull(mbuf, sizeof(struct icmp6_hdr)) != 0)
        goto drop;

    ich = rte_pktmbuf_mtod(mbuf, struct icmp6_hdr *);
    if (unlikely(!ich))
        goto drop;

    if (mbuf_may_pull(mbuf, mbuf->pkt_len) != 0)
        goto drop;

    if (ich->icmp6_type != ICMP6_ECHO_REQUEST)
        goto drop;

    if (icmp6_csum(iph, ich) != 0xffff)
        goto drop;

    /* reply */
    ich->icmp6_type = ICMP6_ECHO_REPLY;
    icmp6_send_csum(iph, ich);

    memset(&fl6, 0, sizeof(struct flow6));
    fl6.fl6_oif = netif_port_get(mbuf->port);
    fl6.fl6_saddr = iph->ip6_dst;
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
