#ifndef __DPVS_ICMPV6_H__
#define __DPVS_ICMPV6_H__

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#define icmp6h_id(icmp6h)        ((icmp6h)->icmp6_dataun.icmp6_un_data16[0])
void icmp6_send(struct rte_mbuf *imbuf, int type, int code, uint32_t info);
uint16_t icmp6_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich);

int icmpv6_init(void);
int icmpv6_term(void);

#endif /* __DPVS_ICMPV6_H__ */
