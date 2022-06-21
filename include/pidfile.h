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
#ifndef __PIDFILE_H__
#define __PIDFILE_H__

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <stdbool.h>

/* lock file */
#define RTE_LOGTYPE_PIDFILE RTE_LOGTYPE_USER1

int pidfile_write(const char *pid_file, int pid);

void pidfile_rm(const char *pid_file);

bool dpvs_running(const char *pid_file);

#endif
