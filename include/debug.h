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

#ifndef __DPVS_DEBUG_H__
#define __DPVS_DEBUG_H__

#define TRACE_STACK_DEPTH_MAX       128

/* get backtrace for the calling program */
int dpvs_backtrace(char *buf, int len);

void dpvs_timing_start(void);
void dpvs_timing_stop(void);
/*  return elapsed time of the most recent call between
 * "dpvs_timing_start" and "dpvs_timing_stop" in microsecond */
int dpvs_timing_get(void);

#endif
