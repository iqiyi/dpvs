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
#ifndef __DPVS_ROUTE6_LPM_H__
#define __DPVS_ROUTE6_LPM_H__

int route6_lpm_init(void);
int route6_lpm_term(void);

void route6_lpm_keyword_value_init(void);
void install_rt6_lpm_keywords(void);

#endif /* __DPVS_ROUTE6_LPM_H__ */
