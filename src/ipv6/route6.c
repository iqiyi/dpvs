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

#if 0
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
#endif

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
    if (ipv6_addr_is_multicast(&fl6->fl6_daddr))//recv NS 
        return &routes[0];
    return rt6_lookup(mbuf, fl6);
}

struct route6 *route6_output(struct rte_mbuf *mbuf, struct flow6 *fl6)
{
    if (ipv6_addr_is_multicast(&fl6->fl6_daddr))//send NS
        return &routes[1];
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
    inet_pton(AF_INET6, "2001:db8:0:f101::2", &rt->rt6_dst.addr);
    rt->rt6_dst.plen = 128;
    rt->rt6_dev = netif_port_get_by_name("dpdk0");
    rt->rt6_mtu = 1500;
    rt->rt6_flags = RTF_LOCALIN | RTF_HOST;

    rt = &routes[1];
    inet_pton(AF_INET6, "2001:db8:0:f101::", &rt->rt6_dst.addr);
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

    return EDPVS_OK;
}

/*test, remember delete me!!*/
int ipv6_addr_init(void)
{
      /*addr hardcode*/
    union inet_addr addr;
    inet_pton(AF_INET6, "2001:db8:0:f101::2", &addr);
    
    inet_addr_add(AF_INET6, routes[0].rt6_dev, &addr, 64, NULL,
                  0, 0 ,0, 0);
    return EDPVS_OK;	
}

int route6_term(void)
{
    return EDPVS_OK;
}

