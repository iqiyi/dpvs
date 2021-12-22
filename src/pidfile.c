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
#include <assert.h>
#include <stdio.h>
#include "pidfile.h"

/* Create the running pidfile */
int pidfile_write(const char *pid_file, int pid)
{
    assert(pid_file && pid > 0);

    FILE *pidfile = fopen(pid_file, "w");

    if (!pidfile) {
        syslog(LOG_INFO, "%s: Cannot open %s pid file\n", __func__, pid_file);
        return 0;
    }

    fprintf(pidfile, "%d\n", pid);
    fclose(pidfile);
    return 1;
}

/* Remove the running pidfile */
void pidfile_rm(const char *pid_file)
{
    if (pid_file)
        unlink(pid_file);
}

/* Return the running state */
bool dpvs_running(const char *pid_file)
{
    FILE *pidfile = fopen(pid_file, "r");
    pid_t pid;

    /* pidfile not exist */
    if (!pidfile)
        return false;

    if (fscanf(pidfile, "%d", &pid) != 1) {
        fclose(pidfile);
        return false;
    }
    fclose(pidfile);

    /* remove pidfile if no process attached to it */
    if (kill(pid, 0)) {
        syslog(LOG_INFO, "%s: Remove a zombie pid file %s\n", __func__, pid_file);
        pidfile_rm(pid_file);
        return false;
    }

    return true;
}

