/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __DPVS_CONN_CONF_H__
#define __DPVS_CONN_CONF_H__

#include "list.h"
#include "inet.h"
#include "conf/sockopts.h"

/*
 * IPVS Conn flags derived from "linux/ip_vs.h".
 *
 * Note: We just keep the macros used by dpvs/keepalived, and the value for some macros
 *       are changed. Besides, some new macros are added for dpvs.
 */
/* Conn flags used by DPVS and Keepalived */
#define IP_VS_CONN_F_MASQ               0x0000        /* masquerading/NAT */
#define IP_VS_CONN_F_LOCALNODE          0x0001        /* local node */
#define IP_VS_CONN_F_TUNNEL             0x0002        /* tunneling */
#define IP_VS_CONN_F_DROUTE             0x0003        /* direct routing */
#define IP_VS_CONN_F_BYPASS             0x0004        /* cache bypass */
#define IP_VS_CONN_F_FULLNAT            0x0005        /* full nat mode */
#define IP_VS_CONN_F_SNAT               0x0006        /* snat mode */
#define IP_VS_CONN_F_FWD_MASK           0x0007        /* mask for the fwd methods */

#define IP_VS_CONN_F_SYNPROXY           0x0010        /* synproxy switch flag*/
#define IP_VS_CONN_F_EXPIRE_QUIESCENT   0x0020        /* expire quiescent conns */

/* Conn flags used by DPVS only */
#define IP_VS_CONN_F_HASHED             0x0100        /* hashed entry */
#define IP_VS_CONN_F_INACTIVE           0x0200        /* not established */
#define IP_VS_CONN_F_TEMPLATE           0x0400        /* template, not connection */
#define IP_VS_CONN_F_ONE_PACKET         0x0800        /* forward only one packet */

#define IP_VS_CONN_F_IN_TIMER           0x1000        /* timer attached */
#define IP_VS_CONN_F_REDIRECT_HASHED    0x2000        /* hashed in redirect table */
#define IP_VS_CONN_F_NOFASTXMIT         0x4000        /* do not fastxmit */

/* How many connections returned at most for one sockopt ctrl msg.
 * Decrease it for saving memory, increase it for better performace.
 */
#define MAX_CTRL_CONN_GET_ENTRIES       1024

enum conn_get_flags {
    GET_IPVS_CONN_FLAG_ALL          = 1,
    GET_IPVS_CONN_FLAG_MORE         = 2,
    GET_IPVS_CONN_FLAG_SPECIFIED    = 4,
    GET_IPVS_CONN_FLAG_TEMPLATE     = 8,
};

enum conn_get_result {
    GET_IPVS_CONN_RESL_OK           = 1,
    GET_IPVS_CONN_RESL_MORE         = 2,
    GET_IPVS_CONN_RESL_FAIL         = 4,
    GET_IPVS_CONN_RESL_NOTEXIST     = 8,
};

struct ip_vs_sockpair {
    uint16_t af;
    uint16_t proto;
    __be16 sport;
    __be16 tport;
    union inet_addr sip;
    union inet_addr tip;
};

typedef struct ip_vs_sockpair ipvs_sockpair_t;

struct ip_vs_conn_entry {
    uint16_t            in_af;
    uint16_t            out_af;
    uint16_t            proto;
    union inet_addr     caddr;
    union inet_addr     vaddr;
    union inet_addr     laddr;
    union inet_addr     daddr;
    uint16_t            cport;
    uint16_t            vport;
    uint16_t            lport;
    uint16_t            dport;
    uint32_t            timeout;
    uint8_t             lcoreid;
    char                state[16];
};
typedef struct ip_vs_conn_entry ipvs_conn_entry_t;

struct ip_vs_conn_req {
    uint32_t flag;
    uint32_t whence;
    ipvs_sockpair_t sockpair;
};

struct ip_vs_conn_array {
    uint32_t nconns;
    uint32_t resl;
    uint8_t curcid;
    ipvs_conn_entry_t array[0];
} __attribute__((__packed__));

#endif /* __DPVS_CONN_CONF_H__ */
