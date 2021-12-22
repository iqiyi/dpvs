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
 */

#include <stdio.h>
#include <string.h>
#include "sys_time.h"
#include "dpdk.h"
#include "global_data.h"

/*Notice:
 * the time zone is the value compared with the server's;
 * default is 57(beijing),supposed the server is 0(Greenwich time)
 */
static time_t g_dpvs_timer = 0;
static uint64_t g_start_cycles = 0;

static void sys_time_to_str(time_t* ts, char* time_str, int str_len)
{
    struct tm tm_time;

    localtime_r(ts, &tm_time);
    snprintf(time_str, str_len, "%04d-%02d-%02d %02d:%02d:%02d",
            tm_time.tm_year+1900, tm_time.tm_mon+1, tm_time.tm_mday,
            tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
}

char* cycles_to_stime(uint64_t cycles, char* stime, int len)
{
    time_t ts;

    if (stime == NULL)
        return NULL;

    memset(stime, 0, len);
    ts = (cycles - g_start_cycles) / g_cycles_per_sec;
    ts += g_dpvs_timer;
    sys_time_to_str(&ts, stime, len);

    return stime;
}

char* sys_localtime_str(char* stime, int len)
{
    time_t now;

    if (stime == NULL)
        return NULL;

    memset(stime, 0, len);
    now = sys_current_time();
    sys_time_to_str(&now, stime, len);

    return stime;
}

time_t sys_current_time(void)
{
    time_t now;

    now = (rte_rdtsc() - g_start_cycles) / g_cycles_per_sec;
    return now + g_dpvs_timer;
}

void sys_start_time(void)
{
    struct timeval tv;
    struct timezone tz;

    time(&g_dpvs_timer);
    gettimeofday(&tv, &tz);
    g_dpvs_timer -= tz.tz_minuteswest*60;

    g_start_cycles = rte_rdtsc();

    return;
}
