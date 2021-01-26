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
 * yangxingwu <xingwu.yang@gmail.com>, Feb 2019, initial.
 *
 */

#ifndef __DPVS_FO_H__
#define __DPVS_FO_H__

#include "ipvs/service.h"
#include "ipvs/dest.h"
#include "ipvs/sched.h"

int dp_vs_fo_init(void);
int dp_vs_fo_term(void);

#endif
