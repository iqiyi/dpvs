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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <execinfo.h>
#include <rte_cycles.h>
#include <rte_per_lcore.h>
#include "global_data.h"
#include "debug.h"

RTE_DEFINE_PER_LCORE(uint64_t, cycles_start);
RTE_DEFINE_PER_LCORE(uint64_t, cycles_stop);

#define timing_cycle_var1 RTE_PER_LCORE(cycles_start)
#define timing_cycle_var2 RTE_PER_LCORE(cycles_stop)

int dpvs_backtrace(char *buf, int len)
{
    int ii, depth, slen;
    char **trace;
    void *btbuf[TRACE_STACK_DEPTH_MAX] = { NULL };

    if (len <= 0)
        return 0;
    buf[0] = '\0';

    depth = backtrace(btbuf, TRACE_STACK_DEPTH_MAX);
    trace = backtrace_symbols(btbuf, depth);
    if (!trace)
        return 0;

    for (ii = 0; ii < depth; ++ii) {
        slen = strlen(buf);
        if (slen + 1 >= len)
            break;
        snprintf(buf+slen, len-slen-1, "[%02d] %s\n", ii, trace[ii]);
    }
    free(trace);

    return strlen(buf);
}

void dpvs_timing_start(void)
{
    timing_cycle_var1 = rte_get_timer_cycles();
}

void dpvs_timing_stop(void)
{
    timing_cycle_var2 = rte_get_timer_cycles();
}

int dpvs_timing_get(void)
{
    if (timing_cycle_var2 < timing_cycle_var1)
        return 0;

    return (timing_cycle_var2 - timing_cycle_var1) * 1000000 / g_cycles_per_sec;
}
