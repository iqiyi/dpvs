#ifndef __DPVS_SVC_MATCH_ACL_H__
#define __DPVS_SVC_MATCH_ACL_H__

struct dp_vs_service *dp_vs_svc_match_acl_lookup(int af, uint8_t proto, const struct dp_vs_match *match);
int dp_vs_svc_match_acl_add(struct dp_vs_service *svc, lcoreid_t cid);
int dp_vs_svc_match_acl_del(struct dp_vs_service *svc, lcoreid_t cid);
struct dp_vs_service *dp_vs_get_match_svc_ip4(uint8_t proto, union inet_addr *saddr,
                     union inet_addr *daddr, __be16 sport, __be16 dport,
                     portid_t iif, portid_t oif, lcoreid_t cid);
struct dp_vs_service *dp_vs_get_match_svc_ip6(uint8_t proto, union inet_addr *saddr,
                     union inet_addr *daddr, __be16 sport, __be16 dport,
                     portid_t iif, portid_t oif, lcoreid_t cid);
int dp_vs_svc_match_init(void);
int dp_vs_svc_match_term(void);
void install_service_match_keywords(void);

#endif /* __DPVS_SVC_MATCH_ACL_H__ */

