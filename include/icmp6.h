#ifndef __DPVS_ICMPV6_H__
#define __DPVS_ICMPV6_H__

void icmp6_send_csum(struct ip6_hdr *iph, struct icmp6_hdr *ich);

int icmpv6_init(void);
int icmpv6_term(void);

#endif /* __DPVS_ICMPV6_H__ */
