#ifndef __DPVS_SRSS_H__
#define __DPVS_SRSS_H__
#include "inetaddr.h"

struct srss_flow {
    int                 af;
    uint8_t             proto;
    union inet_addr     saddr;  /* pkt's source addr, network order */
    union inet_addr     daddr;  /* pkt's dest addr, network order */
    uint16_t            sport;
    uint16_t            dport;
};

int netif_get_lcore(struct netif_port *port, queueid_t qid, lcoreid_t *cid);
int dpvs_srss_fdir_get(struct netif_port* p, const struct srss_flow* f, uint32_t* qid);
int dpvs_dev_sfilter_ctrl(struct netif_port* port, enum rte_filter_type filter_type,
               enum rte_filter_op filter_op, void *arg);
int dpvs_dev_sfilter(struct netif_port* port, const struct srss_flow* f,
                     uint32_t* qid);
int dpvs_dev_srss_init(struct netif_port* port);

#endif /* __DPVS_SRSS_H__ */

