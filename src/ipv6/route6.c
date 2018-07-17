/*
 * XXX:
 * this file is for test only, it's composed with stub functions
 * and dummy data! and the implementation is NOT correct!
 */
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "common.h"
#include "netif.h"
#include "ipv6.h"
#include "route6.h"

static struct route6 routes[4] = {};

static struct route6 *rt6_lookup(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    int i;
    struct route6 *rt;

    for (i = 0; i < NELEMS(routes); i++) {
        rt = &routes[i];

        if (ipv6_prefix_equal(&fl6->fl6_daddr, &rt->rt6_dst.addr,
                              rt->rt6_dst.plen))
            return rt;

        if (ipv6_prefix_equal(&ip6_hdr(mbuf)->ip6_dst, &rt->rt6_dst.addr,
                              rt->rt6_dst.plen))
            return rt;
    }

    return NULL;
}

struct route6 *route6_input(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_lookup(mbuf, fl6);
}

struct route6 *route6_output(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    return rt6_lookup(mbuf, fl6);
}

int route6_put(struct route6 *rt)
{
    return 0;
}

int route6_init(void)
{
    struct route6 *rt;

    rt = &routes[0];
    inet_pton(AF_INET6, "2001:db8::1", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 128;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_LOCALIN | RTF_HOST;

    rt = &routes[1];
    inet_pton(AF_INET6, "2001:db8::", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 64;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_FORWARD;

    rt = &routes[2];
    inet_pton(AF_INET6, "2001:db8:1::", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 64;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    inet_pton(AF_INET6, "2001:db8:1::1", &rt->rt6_gateway);
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_FORWARD;

    rt = &routes[3];
    inet_pton(AF_INET6, "2001:db8:2::", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 64;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    inet_pton(AF_INET6, "2001:db8:2::1", &rt->rt6_gateway);
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_FORWARD | RTF_DEFAULT;

    return EDPVS_OK;
}

int route6_term(void)
{
    return EDPVS_OK;
}

int neigh6_output(struct in6_addr *daddr, struct rte_mbuf *mbuf,
                  struct netif_port *dev)
{
    struct ether_addr temp, *ea1, *ea2;

    /* assume eth header is exist and just need swap src/dst */
    ea1 = (void *)rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));
    ea2 = ea1 + 1;

    ether_addr_copy(ea1, &temp);
    ether_addr_copy(ea2, ea1);
    ether_addr_copy(&temp, ea2);

    return netif_xmit(mbuf, dev);
}
