#ifndef __DPVS_VXLAN_H__
#define __DPVS_VXLAN_H__
#include "conf/vxlan.h"

int dp_vs_xmit_vxlan(struct dp_vs_proto *proto, struct dp_vs_conn *conn, struct rte_mbuf *mbuf);
int vxlan_add_dest(struct dp_vs_service *svc, struct dp_vs_dest *dest);
int vxlan_del_dest(struct dp_vs_service *svc, struct dp_vs_dest *dest);
int vxlan_update_dest(struct dp_vs_service *svc, struct dp_vs_dest *dest, struct dp_vs_dest_conf *udest);
int dpvs_health_check_vni_bind(struct rte_mbuf *mbuf);
int dpvs_health_check_vxlan_encap(struct rte_mbuf *mbuf, struct netif_port *port);
void install_vxlan_keywords(void);

#endif /* __DPVS_VXLAN_H__ */

