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

/*
 * '_GNU_SOURCE' has been defined in newer DPDK's makefile
 * (e.g., 18.11) but not in order DPDK (e.g., 17.11).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <assert.h>
#include <getopt.h>
#include "pidfile.h"
#include "dpdk.h"
#include "conf/common.h"
#include "log.h"
#include "netif.h"
#include "vlan.h"
#include "inet.h"
#include "timer.h"
#include "ctrl.h"
#include "ipv4.h"
#include "neigh.h"
#include "sa_pool.h"
#include "ipset/ipset.h"
#include "ipvs/ipvs.h"
#include "cfgfile.h"
#include "ip_tunnel.h"
#include "sys_time.h"
#include "route6.h"
#include "iftraf.h"
#include "eal_mem.h"
#include "scheduler.h"
#include "pdump.h"

#define DPVS    "dpvs"
#define RTE_LOGTYPE_DPVS RTE_LOGTYPE_USER1

#define LCORE_CONF_BUFFER_LEN 4096

static void inline dpdk_version_check(void)
{
#if RTE_VERSION < RTE_VERSION_NUM(20, 11, 1, 0)
    rte_panic("The current DPVS needs dpdk-stable-20.11.1 or higher. "
            "Try old releases if you are using earlier dpdk versions.");
#endif
}

/*
 * the initialization order of all the modules
 */
#define DPVS_MODULES {                                          \
        DPVS_MODULE(MODULE_FIRST,       "scheduler",            \
                    dpvs_scheduler_init, dpvs_scheduler_term),  \
        DPVS_MODULE(MODULE_GLOBAL_DATA, "global data",          \
                    global_data_init,    global_data_term),     \
        DPVS_MODULE(MODULE_MBUF,        "mbuf",                 \
                    mbuf_init,           NULL),                 \
        DPVS_MODULE(MODULE_CFG,         "config file",          \
                    cfgfile_init,        cfgfile_term),         \
        DPVS_MODULE(MODULE_PDUMP,        "pdump",               \
                    pdump_init,          pdump_term),           \
        DPVS_MODULE(MODULE_NETIF_VDEV,  "vdevs",                \
                    netif_vdevs_add,     NULL),                 \
        DPVS_MODULE(MODULE_TIMER,       "timer",                \
                    dpvs_timer_init,     dpvs_timer_term),      \
        DPVS_MODULE(MODULE_TC,          "tc",                   \
                    tc_init,             tc_term),              \
        DPVS_MODULE(MODULE_NETIF,       "netif",                \
                    netif_init,          netif_term),           \
        DPVS_MODULE(MODULE_CTRL,        "ctrl",                 \
                    ctrl_init,           ctrl_term),            \
        DPVS_MODULE(MODULE_TC_CTRL,     "tc_ctrl",              \
                    tc_ctrl_init,        tc_ctrl_term),         \
        DPVS_MODULE(MODULE_VLAN,        "vlan",                 \
                    vlan_init,           NULL),                 \
        DPVS_MODULE(MODULE_INET,        "inet",                 \
                    inet_init,           inet_term),            \
        DPVS_MODULE(MODULE_SA_POOL,     "sa_pool",              \
                    sa_pool_init,        sa_pool_term),         \
        DPVS_MODULE(MODULE_IP_TUNNEL,   "tunnel",               \
                    ip_tunnel_init,      ip_tunnel_term),       \
        DPVS_MODULE(MODULE_IPSET,       "ipset",                \
                    ipset_init,          ipset_term),           \
        DPVS_MODULE(MODULE_VS,          "ipvs",                 \
                    dp_vs_init,          dp_vs_term),           \
        DPVS_MODULE(MODULE_NETIF_CTRL,  "netif ctrl",           \
                    netif_ctrl_init,     netif_ctrl_term),      \
        DPVS_MODULE(MODULE_IFTRAF,      "iftraf",               \
                    iftraf_init,         iftraf_term),          \
        DPVS_MODULE(MODULE_EAL_MEM,     "eal_mem",              \
                    eal_mem_init,        eal_mem_term),         \
        DPVS_MODULE(MODULE_LAST,        "last",                 \
                    NULL,                NULL)                  \
    }

#define DPVS_MODULE(a, b, c, d)  a
enum dpvs_modules DPVS_MODULES;
#undef DPVS_MODULE

#define DPVS_MODULE(a, b, c, d)  b
static const char *dpvs_modules[] = DPVS_MODULES;
#undef DPVS_MODULE

typedef int (*dpvs_module_init_pt)(void);
typedef int (*dpvs_module_term_pt)(void);

#define DPVS_MODULE(a, b, c, d)  c
dpvs_module_init_pt dpvs_module_inits[] = DPVS_MODULES;
#undef DPVS_MODULE

#define DPVS_MODULE(a, b, c, d)  d
dpvs_module_term_pt dpvs_module_terms[] = DPVS_MODULES;

static void modules_init(void)
{
    int m, err;

    for (m = MODULE_FIRST; m <= MODULE_LAST; m++) {
        if (dpvs_module_inits[m]) {
            if ((err = dpvs_module_inits[m]()) != EDPVS_OK) {
                rte_exit(EXIT_FAILURE, "failed to init %s: %s\n",
                         dpvs_modules[m], dpvs_strerror(err));
            }
        }
    }
}

static void modules_term(void)
{
    int m, err;

    for (m = MODULE_LAST ; m >= MODULE_FIRST; m--) {
        if (dpvs_module_terms[m]) {
            if ((err = dpvs_module_terms[m]()) != EDPVS_OK) {
                rte_exit(EXIT_FAILURE, "failed to term %s: %s\n",
                         dpvs_modules[m], dpvs_strerror(err));
            }
        }
    }
}

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
            "   -v, --version           display DPVS version info\n"
            "   -c, --conf FILE         specify config file for DPVS\n"
            "   -p, --pid-file FILE     specify pid file of DPVS process\n"
            "   -x, --ipc-file FILE     specify unix socket file for ipc communication between DPVS and Tools\n"
            "   -h, --help              display DPVS help info\n"
    );
}

static int parse_app_args(int argc, char **argv)
{
    const char *short_options = "vhc:p:x:";
    char *prgname = argv[0];
    int c, ret = -1;

    const int old_optind = optind;
    const int old_optopt = optopt;
    char * const old_optarg = optarg;

    struct option long_options[] = {
        {"version", 0, NULL, 'v'},
        {"conf", required_argument, NULL, 'c'},
        {"pid-file", required_argument, NULL, 'p'},
        {"ipc-file", required_argument, NULL, 'x'},
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
            case 'c':
                dpvs_conf_file=optarg;
                break;
            case 'p':
                dpvs_pid_file=optarg;
                break;
            case 'x':
                dpvs_ipc_file=optarg;
                break;
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

    /* check */
    if (!dpvs_conf_file)
        dpvs_conf_file="/etc/dpvs.conf";
    if (!dpvs_pid_file)
        dpvs_pid_file="/var/run/dpvs.pid";
    if (!dpvs_ipc_file)
        dpvs_ipc_file="/var/run/dpvs.ipc";

    g_version = version_parse(DPVS_VERSION);

    return ret;
}

int main(int argc, char *argv[])
{
    int err, nports;
    portid_t pid;
    struct netif_port *dev;
    struct timeval tv;
    char pql_conf_buf[LCORE_CONF_BUFFER_LEN];
    int pql_conf_buf_len = LCORE_CONF_BUFFER_LEN;

    dpdk_version_check();

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
    if (dpvs_running(dpvs_pid_file)) {
        fprintf(stderr, "dpvs is already running\n");
        exit(EXIT_FAILURE);
    }

    dpvs_state_set(DPVS_STATE_INIT);

    gettimeofday(&tv, NULL);
    srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());
    srand48(tv.tv_sec ^ tv.tv_usec ^ getpid());
    rte_srand((uint64_t)(tv.tv_sec ^ tv.tv_usec ^ getpid()));
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
    RTE_LOG(INFO, DPVS, "dpvs-conf-file: %s\n", dpvs_conf_file);
    RTE_LOG(INFO, DPVS, "dpvs-pid-file: %s\n", dpvs_pid_file);
    RTE_LOG(INFO, DPVS, "dpvs-ipc-file: %s\n", dpvs_ipc_file);

    rte_timer_subsystem_init();

    modules_init();

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
    RTE_LOG(INFO, DPVS, "port-queue-lcore relation array: \n%s\n",
            pql_conf_buf);

    /* start slave worker threads */
    dpvs_lcore_start(0);

    /* start async logging worker thread */
    log_slave_init();

    /* write pid file */
    if (!pidfile_write(dpvs_pid_file, getpid()))
        goto end;

    dpvs_state_set(DPVS_STATE_NORMAL);

    /* start control plane thread loop */
    dpvs_lcore_start(1);

end:
    dpvs_state_set(DPVS_STATE_FINISH);
    modules_term();

    pidfile_rm(dpvs_pid_file);

    exit(0);
}
