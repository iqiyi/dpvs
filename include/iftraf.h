#ifndef __IFTRAF_H__
#define __IFTRAF_H__

#include "common.h"
#include "list.h"
#include "dpdk.h"
#include "timer.h"
#include "inet.h"
#include "ctrl.h"

int iftraf_sockopt_get(sockoptid_t opt, const void *conf, size_t size,  void **out, size_t *outsize);

int iftraf_pkt_in(int af, struct rte_mbuf *mbuf, struct netif_port *dev);
int iftraf_pkt_out(int af, struct rte_mbuf *mbuf, struct netif_port *dev);

int iftraf_init(void);
int iftraf_term(void); /* cleanup */

#endif

