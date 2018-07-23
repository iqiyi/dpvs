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

struct neigh {
    int                 af;
    union inet_addr     ia;
    struct ether_addr   ea;
};

struct neigh neigh_tab[4] = {};

static int ether_addr_pton(const char *ea, struct ether_addr *buf)
{
    unsigned int ea_buf[6];

    if (sscanf(ea, "%02x:%02x:%02x:%02x:%02x:%02x",
           &ea_buf[0], &ea_buf[1], &ea_buf[2],
           &ea_buf[3], &ea_buf[4], &ea_buf[5]) != 6)
        return -1;

    buf->addr_bytes[0] = ea_buf[0];
    buf->addr_bytes[1] = ea_buf[1];
    buf->addr_bytes[2] = ea_buf[2];
    buf->addr_bytes[3] = ea_buf[3];
    buf->addr_bytes[4] = ea_buf[4];
    buf->addr_bytes[5] = ea_buf[5];

    return 0;
}

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

int route6_term(void)
{
    return EDPVS_OK;
}

/* neighbour codes should not be here ! test only, remove it later. */
int neigh_output(int af, union inet_addr *nexthop, struct rte_mbuf *mbuf,
                 struct netif_port *dev)
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
