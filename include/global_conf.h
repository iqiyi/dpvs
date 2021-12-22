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
#ifndef __GLOBAL_CONF_H__
#define __GLOBAL_CONF_H__

#include <unistd.h>
#include "conf/common.h"
#include "parser/parser.h"
#include "dpdk.h"

#define DEF_LOG_LEVEL RTE_LOG_DEBUG

void install_global_keywords(void);

int global_conf_init(void);
int global_conf_term(void);

#endif
