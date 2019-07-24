#ifndef __STATS_H__
#define __STATS_H__

#include "common.h"
#include "list.h"
#include "dpdk.h"
#include "timer.h"
#include "inet.h"
#include "ctrl.h"

int stats_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize);

int stats_pkt_in(int af, struct rte_mbuf *mbuf);
int stats_pkt_out(int af, struct rte_mbuf *mbuf);
void stats_process_ring(void);

int stats_enable_func(void);
int stats_disable_func(void);

int stats_init(void);

#endif

