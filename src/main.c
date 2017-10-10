/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
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
#include "pidfile.h"
#include "dpdk.h"
#include "common.h"
#include "netif.h"
#include "vlan.h"
#include "inet.h"
#include "timer.h"
#include "ctrl.h"
#include "ipv4.h"
#include "neigh.h"
#include "sa_pool.h"
#include "ipvs/ipvs.h"
#include "cfgfile.h"

#define DPVS    "dpvs"
#define RTE_LOGTYPE_DPVS RTE_LOGTYPE_USER1

#define LCORE_CONF_BUFFER_LEN 1024

int main(int argc, char *argv[])
{
    int err, nports;
    portid_t pid;
    struct netif_port *dev;
    struct timeval tv;
    char pql_conf_buf[LCORE_CONF_BUFFER_LEN];
    int pql_conf_buf_len = LCORE_CONF_BUFFER_LEN;
    uint32_t loop_cnt = 0;
    int timer_sched_loop_interval;

    /* check if dpvs is running and remove zombie pidfile */
    if (dpvs_running(DPVS_PIDFILE)) {
        fprintf(stderr, "dpvs is already running\n");
        exit(EXIT_FAILURE);
    }

    dpvs_state_set(DPVS_STATE_INIT);

    gettimeofday(&tv, NULL);
    srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

    err = rte_eal_init(argc, argv);
    if (err < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= err, argv += err;

    rte_timer_subsystem_init();

    if ((err = cfgfile_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail init configuration file: %s\n",
                 dpvs_strerror(err));

    if ((err = netif_virtual_devices_add()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail add virtual devices:%s\n",
                 dpvs_strerror(err));

    if ((err = dpvs_timer_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail init timer on %s\n", dpvs_strerror(err));

    if ((err = netif_init(NULL)) != 0)
        rte_exit(EXIT_FAILURE, "Fail to init netif: %s\n", dpvs_strerror(err));
    /* Default lcore conf and port conf are used and may be changed here 
     * with "netif_port_conf_update" and "netif_lcore_conf_set" */

    if ((err = ctrl_init()) != 0 )
        rte_exit(EXIT_FAILURE, "Fail to init ctrl plane: %s\n",
                 dpvs_strerror(err));

    if ((err = vlan_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init vlan: %s\n", dpvs_strerror(err));

    if ((err = inet_init()) != 0)
        rte_exit(EXIT_FAILURE, "Fail to init inet: %s\n", dpvs_strerror(err));

    if ((err = sa_pool_init()) != 0)
        rte_exit(EXIT_FAILURE, "Fail to init sa_pool: %s\n", dpvs_strerror(err));

    if ((err = dp_vs_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init ipvs: %s\n", dpvs_strerror(err));

    if ((err = netif_ctrl_init()) !=0 )
        rte_exit(EXIT_FAILURE, "Fail to init netif_ctrl: %s\n",
                 dpvs_strerror(err));

    /* config and start all available dpdk ports */
    nports = rte_eth_dev_count();
    for (pid = 0; pid < nports; pid++) {
        dev = netif_port_get(pid);
        if (!dev) {
            RTE_LOG(WARNING, DPVS, "port %d not found\n", pid);
            continue;
        }

        err = netif_port_start(dev);
        if (err != EDPVS_OK)
            RTE_LOG(WARNING, DPVS, "Start %s failed, skipping ...\n",
                    dev->name);
    }

    /* print port-queue-lcore relation */
    netif_print_lcore_conf(pql_conf_buf, &pql_conf_buf_len, true, 0);
    RTE_LOG(INFO, DPVS, "\nport-queue-lcore relation array: \n%s\n",
            pql_conf_buf);

    /* start data plane threads */
    netif_lcore_start();

    /* write pid file */
    if (!pidfile_write(DPVS_PIDFILE, getpid()))
        goto end;

    timer_sched_loop_interval = dpvs_timer_sched_interval_get();
    assert(timer_sched_loop_interval > 0);

    dpvs_state_set(DPVS_STATE_NORMAL);

    /* start control plane thread */
    while (1) {
        /* reload configuations if reload flag is set */
        try_reload();
        /* IPC loop */
        sockopt_ctl(NULL);
        /* msg loop */
        msg_master_process();
        /* timer */
        loop_cnt++;
        if (loop_cnt % timer_sched_loop_interval == 0)
            rte_timer_manage();
        /* kni */
        kni_process_on_master();
 
        /* increase loop counts */
        netif_update_master_loop_cnt();
    }

end:
    dpvs_state_set(DPVS_STATE_FINISH);
    if ((err = netif_ctrl_term()) !=0 )
        rte_exit(EXIT_FAILURE, "Fail to term netif_ctrl: %s\n",
                 dpvs_strerror(err));
    if ((err = dp_vs_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term ipvs: %s\n", dpvs_strerror(err));
    if ((err = sa_pool_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term sa_pool: %s\n", dpvs_strerror(err));
    if ((err = inet_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term inet: %s\n", dpvs_strerror(err));
    if ((err = dpvs_timer_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term timer: %s\n", dpvs_strerror(err));
    if ((err = ctrl_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term ctrl plane\n");
    if ((err = netif_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term route\n");
    if ((err = cfgfile_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term configuration file: %s\n",
                dpvs_strerror(err));
    pidfile_rm(DPVS_PIDFILE);

    exit(0);
}
