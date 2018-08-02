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
#include "inetaddr.h"

static struct route6 routes[6] = {};

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
    struct neigh *neigh;

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
    inet_pton(AF_INET6, "2001:db8:1::1", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 128;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_LOCALIN | RTF_HOST;

    rt = &routes[3];
    inet_pton(AF_INET6, "2001:db8:1::", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 64;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    inet_pton(AF_INET6, "2001:db8:1::1", &rt->rt6_gateway);
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_FORWARD;

    rt = &routes[4];
    inet_pton(AF_INET6, "ff00::", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 8;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    rt->rt6_mtu = 1500;

    rt = &routes[5];
    inet_pton(AF_INET6, "fe80::", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 64;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    rt->rt6_mtu = 1500;

    neigh = &neigh_tab[0];
    neigh->af = AF_INET6;
    inet_pton(AF_INET6, "2001:db8::1", &neigh->ia);
    ether_addr_pton("00:00:00:00:00:00", &neigh->ea);

    neigh = &neigh_tab[1];
    neigh->af = AF_INET6;
    inet_pton(AF_INET6, "2001:db8:1::1", &neigh->ia);
    ether_addr_pton("00:00:00:00:00:00", &neigh->ea);

    neigh = &neigh_tab[2];
    neigh->af = AF_INET6;
    inet_pton(AF_INET6, "2001:db8::2", &neigh->ia);
    ether_addr_pton("00:00:00:00:00:00", &neigh->ea);

    neigh = &neigh_tab[3];
    neigh->af = AF_INET6;
    inet_pton(AF_INET6, "2001:db8:1::2", &neigh->ia);
    ether_addr_pton("00:00:00:00:00:00", &neigh->ea);

    return EDPVS_OK;
}

/*test, remember delete me!!*/
int ipv6_addr_init(void)
{
      /*addr hardcode*/
    union inet_addr addr;
    inet_pton(AF_INET6, "2001:db8:1::1", &addr);
    
    inet_addr_add(AF_INET6, routes[0].rt6_dev, &addr, 64, NULL,
                  0, 0 ,0, 0);
    return EDPVS_OK;	
}

int route6_term(void)
{
    struct ether_hdr *eh;
    struct neigh *neigh = NULL;
    int i;

    eh = (void *)rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));
    if (!eh) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOROOM;
    }

    for (i = 0; i < NELEMS(neigh_tab); i++) {
        if (inet_addr_equal(AF_INET6, nexthop, &neigh_tab[i].ia)) {
            neigh = &neigh_tab[i];
            break;
        }
    }
    if (!neigh) {
        fprintf(stderr, "%s: no neigh info\n", __func__);
        rte_pktmbuf_free(mbuf);
        return EDPVS_INVAL;
    }

    eh->d_addr = neigh->ea;
    eh->s_addr = dev->addr;
    eh->ether_type = htons(ETH_P_IPV6);

    return netif_xmit(mbuf, dev);
}

