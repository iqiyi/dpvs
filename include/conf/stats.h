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
#ifndef __DPVS_STATS_CONF_H__
#define __DPVS_STATS_CONF_H__

struct dp_vs_stats {
    uint64_t            conns;
    uint64_t            inpkts;
    uint64_t            inbytes;
    uint64_t            outpkts;
    uint64_t            outbytes;

    uint32_t cps;
    uint32_t inpps;
    uint32_t inbps;
    uint32_t outpps;
    uint32_t outbps;
};

#endif /* __DPVS_STATS_CONF_H__ */
