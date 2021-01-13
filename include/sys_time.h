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
#ifndef _SYS_DPVS_TIME_H_
#define _SYS_DPVS_TIME_H_
#include <sys/time.h>
#include <time.h>
#include "dpdk.h"

#define SYS_TIME_STR_LEN (64)

char* sys_localtime_str(char* stime, int len);
char* cycles_to_stime(uint64_t cycles, char* stime, int len);
time_t sys_current_time(void);
void sys_start_time(void);

#endif /* _SYS_DPVS_TIME_H_ */
