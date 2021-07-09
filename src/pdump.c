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

#ifdef CONFIG_DPVS_PDUMP
#include <rte_pdump.h>
#endif

#include "conf/common.h"
#include "global_data.h"
#include "pdump.h"

extern bool g_dpvs_pdump;

int pdump_init(void)
{
    int err = EDPVS_OK;

#ifdef CONFIG_DPVS_PDUMP
    if (g_dpvs_pdump) {
        /* initialize packet capture framework */
        err = rte_pdump_init();
    }
#endif

    return err;
}

int pdump_term(void)
{
    int err = EDPVS_OK;

#ifdef CONFIG_DPVS_PDUMP
    if (g_dpvs_pdump) {
        err = rte_pdump_uninit();
    }
#endif

    return err;
}
