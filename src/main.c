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
#define _GNU_SOURCE
#include <pthread.h>
#include <assert.h>
#include <getopt.h>
#include <sys/resource.h>
#include "pidfile.h"
#include "dpdk.h"
#include "conf/common.h"
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
#include "ip_tunnel.h"
#include "sys_time.h"
#include "route6.h"
#include "iftraf.h"
#include "scheduler.h"

#define DPVS    "dpvs"
#define RTE_LOGTYPE_DPVS RTE_LOGTYPE_USER1

#define LCORE_CONF_BUFFER_LEN 4096

extern int log_slave_init(void);

static int set_all_thread_affinity(void)
{
    int s;
    lcoreid_t cid;
    pthread_t tid;
    cpu_set_t cpuset;
    unsigned long long cpumask=0;

    tid = pthread_self();
    CPU_ZERO(&cpuset);
    for (cid = 0; cid < RTE_MAX_LCORE; cid++)
        CPU_SET(cid, &cpuset);

    s = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        errno = s;
        perror("fail to set thread affinty");
        return -1;
    }

    CPU_ZERO(&cpuset);
    s = pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        errno = s;
        perror("fail to get thread affinity");
        return -2;
    }

    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        if (CPU_ISSET(cid, &cpuset))
            cpumask |= (1LL << cid);
    }
    printf("current thread affinity is set to %llX\n", cpumask);

    return 0;
}

static void dpvs_usage(const char *prgname)
{
    printf("\nUsage: %s ", prgname);
    printf("DPVS application options:\n"
            "   -v  version     display DPVS version info\n"
            "   -h  help        display DPVS help info\n"
    );
}

static int parse_app_args(int argc, char **argv)
{
    const char *short_options = "vh";
    char *prgname = argv[0];
    int c, ret = -1;

    const int old_optind = optind;
    const int old_optopt = optopt;
    char * const old_optarg = optarg;

    struct option long_options[] = {
        {"version", 0, NULL, 'v'},
        {"help", 0, NULL, 'h'},
        {NULL, 0, 0, 0}
    };

    optind = 1;

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                fprintf(stderr, "dpvs version: %s, build on %s\n",
                        DPVS_VERSION,
                        DPVS_BUILD_DATE);
                exit(EXIT_SUCCESS);
            case 'h':
                dpvs_usage(prgname);
                exit(EXIT_SUCCESS);
            case '?':
            default:
                dpvs_usage(prgname);
                exit(EXIT_FAILURE);
        }
    }

    if (optind > 0)
        argv[optind-1] = prgname;

    ret = optind - 1;

    /* restore getopt lib */
    optind = old_optind;
    optopt = old_optopt;
    optarg = old_optarg;

    return ret;
}

static void enable_coredump(void)
{
    struct rlimit core_limits;

    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);
}

int main(int argc, char *argv[])
{
    int err, nports;
    portid_t pid;
    struct netif_port *dev;
    struct timeval tv;
    char pql_conf_buf[LCORE_CONF_BUFFER_LEN];
    int pql_conf_buf_len = LCORE_CONF_BUFFER_LEN;

    enable_coredump();

    /**
     * add application agruments parse before EAL ones.
     * use it like the following:
     * ./dpvs -v
     * OR
     * ./dpvs -- -n 4 -l 0-11 (if you want to use eal arguments)
     */
    err = parse_app_args(argc, argv);
    if (err < 0) {
        fprintf(stderr, "fail to parse application options\n");
        exit(EXIT_FAILURE);
    }
    argc -= err, argv += err;

    /* check if dpvs is running and remove zombie pidfile */
    if (dpvs_running(DPVS_PIDFILE)) {
        fprintf(stderr, "dpvs is already running\n");
        exit(EXIT_FAILURE);
    }

    dpvs_state_set(DPVS_STATE_INIT);

    gettimeofday(&tv, NULL);
    srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());
    sys_start_time();

    if (get_numa_nodes() > DPVS_MAX_SOCKET) {
        fprintf(stderr, "DPVS_MAX_SOCKET is smaller than system numa nodes!\n");
        return -1;
    }

    if (set_all_thread_affinity() != 0) {
        fprintf(stderr, "set_all_thread_affinity failed\n");
        exit(EXIT_FAILURE);
    }

    err = rte_eal_init(argc, argv);
    if (err < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

    RTE_LOG(INFO, DPVS, "dpvs version: %s, build on %s\n", DPVS_VERSION, DPVS_BUILD_DATE);

    rte_timer_subsystem_init();

#ifdef CONFIG_DPVS_PDUMP
    /* initialize packet capture framework */
    err = rte_pdump_init(NULL);
    if (err < 0) {
        rte_exit(EXIT_FAILURE, "Fail to init dpdk pdump framework\n");
    }
#endif
    if ((err = dpvs_scheduler_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init dpvs scheduler\n");

    if ((err = global_data_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init global data\n");

    if ((err = cfgfile_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init configuration file: %s\n",
                 dpvs_strerror(err));

    if ((err = netif_virtual_devices_add()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to add virtual devices:%s\n",
                 dpvs_strerror(err));

    if ((err = dpvs_timer_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init timer on %s\n", dpvs_strerror(err));

    if ((err = tc_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init traffic control: %s\n",
                 dpvs_strerror(err));

    if ((err = netif_init(NULL)) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init netif: %s\n", dpvs_strerror(err));
    /* Default lcore conf and port conf are used and may be changed here
     * with "netif_port_conf_update" and "netif_lcore_conf_set" */

    if ((err = ctrl_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init ctrl plane: %s\n",
                 dpvs_strerror(err));

    if ((err = tc_ctrl_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init tc control plane: %s\n",
                 dpvs_strerror(err));

    if ((err = vlan_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init vlan: %s\n", dpvs_strerror(err));

    if ((err = inet_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init inet: %s\n", dpvs_strerror(err));

    if ((err = sa_pool_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init sa_pool: %s\n", dpvs_strerror(err));

    if ((err = ip_tunnel_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init tunnel: %s\n", dpvs_strerror(err));

    if ((err = dp_vs_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init ipvs: %s\n", dpvs_strerror(err));

    if ((err = netif_ctrl_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init netif_ctrl: %s\n",
                 dpvs_strerror(err));

    if ((err = iftraf_init()) != EDPVS_OK)
        rte_exit(EXIT_FAILURE, "Fail to init stats: %s\n", dpvs_strerror(err));
    
    /* config and start all available dpdk ports */
    nports = dpvs_rte_eth_dev_count();
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

    log_slave_init();

    /* start slave worker threads */
    dpvs_lcore_start(0);

    /* write pid file */
    if (!pidfile_write(DPVS_PIDFILE, getpid()))
        goto end;

    dpvs_state_set(DPVS_STATE_NORMAL);

    /* start control plane thread loop */
    dpvs_lcore_start(1);

end:
    dpvs_state_set(DPVS_STATE_FINISH);
    if ((err = iftraf_term()) !=0 )
        rte_exit(EXIT_FAILURE, "Fail to term iftraf: %s\n",
                dpvs_strerror(err));

    if ((err = netif_ctrl_term()) !=0 )
        rte_exit(EXIT_FAILURE, "Fail to term netif_ctrl: %s\n",
                 dpvs_strerror(err));
    if ((err = dp_vs_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term ipvs: %s\n", dpvs_strerror(err));
    if ((err = ip_tunnel_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term tunnel: %s\n", dpvs_strerror(err));
    if ((err = sa_pool_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term sa_pool: %s\n", dpvs_strerror(err));
    if ((err = inet_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term inet: %s\n", dpvs_strerror(err));
    if ((err = dpvs_timer_term()) != EDPVS_OK)
        RTE_LOG(ERR, DPVS, "Fail to term timer: %s\n", dpvs_strerror(err));
    if ((err = ctrl_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term ctrl plane\n");
    if ((err = netif_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term netif\n");
    if ((err = cfgfile_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term configuration file: %s\n",
                dpvs_strerror(err));
    if ((err = global_data_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to clean global data\n");
    if ((err = dpvs_scheduler_term()) != 0)
        RTE_LOG(ERR, DPVS, "Fail to term dpvs scheduler\n");

#ifdef CONFIG_DPVS_PDUMP
    if ((err = rte_pdump_uninit()) != 0) {
        RTE_LOG(ERR, DPVS, "Fail to uninitialize dpdk pdump framework.\n");
    }
#endif
    pidfile_rm(DPVS_PIDFILE);

    exit(0);
}
