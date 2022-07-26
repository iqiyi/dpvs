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
#ifndef __DPVS_ROUTE_CONF_H__
#define __DPVS_ROUTE_CONF_H__

#include <arpa/inet.h>
#include <net/if.h>
#include "inet.h"
#include "conf/sockopts.h"

enum {
    DPVS_NUD_S_NONE        = 0,
    DPVS_NUD_S_SEND,
    DPVS_NUD_S_REACHABLE,
    DPVS_NUD_S_PROBE,
    DPVS_NUD_S_DELAY,
    DPVS_NUD_S_MAX /*Reserved*/
};

struct dp_vs_neigh_conf {
    int                     af;
    uint32_t                state;
    union inet_addr         ip_addr;
#ifdef __DPVS__
    struct rte_ether_addr   eth_addr;
#else
    struct ether_addr       eth_addr;
#endif
    uint32_t                que_num;
    char                    ifname[IFNAMSIZ];
    uint8_t                 flag;
    uint8_t                 cid;
}__attribute__((__packed__, aligned(2)));

struct dp_vs_neigh_conf_array {
    int  neigh_nums;
    struct dp_vs_neigh_conf addrs[0];
}__attribute__((__packed__));

#define sNNO DPVS_NUD_S_NONE
#define sNSD DPVS_NUD_S_SEND
#define sNRE DPVS_NUD_S_REACHABLE
#define sNPR DPVS_NUD_S_PROBE
#define sNDE DPVS_NUD_S_DELAY

#define DPVS_NUD_S_KEEP DPVS_NUD_S_MAX
#define sNKP DPVS_NUD_S_KEEP /*Keep state and do not reset timer*/

static const char *nud_state_names[] = {
    [DPVS_NUD_S_NONE]      = "NONE",
    [DPVS_NUD_S_SEND]      = "SEND",
    [DPVS_NUD_S_REACHABLE] = "REACHABLE",
    [DPVS_NUD_S_PROBE]     = "PROBE",
    [DPVS_NUD_S_DELAY]     = "DELAY",
};

static inline const char *nud_state_name(int state)
{
    if (state >= DPVS_NUD_S_KEEP)
         return "ERR!";
    return nud_state_names[state] ? nud_state_names[state] :"<Unknown>";
}

#define NEIGHBOUR_HASHED     0x01
#define NEIGHBOUR_STATIC     0x02

#endif
