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
#include <unistd.h>
#include <signal.h>
#include "dpdk.h"
#include "conf/common.h"
#include "parser/parser.h"
#include "cfgfile.h"
#include "global_conf.h"
#include "timer.h"
#include "neigh.h"
#include "ipv4.h"
#include "ipv4_frag.h"
#include "ipv6.h"
#include "ctrl.h"
#include "sa_pool.h"
#include "ipvs/conn.h"
#include "ipvs/proto_tcp.h"
#include "ipvs/proto_udp.h"
#include "ipvs/synproxy.h"
#include "ipset/ipset_hash.h"
#include "scheduler.h"

typedef void (*sighandler_t)(int);

static void keyword_value_init(void)
{
    /* init keywords value here */

    netif_keyword_value_init();
    timer_keyword_value_init();
    neigh_keyword_value_init();

    ipv4_keyword_value_init();
    ip4_frag_keyword_value_init();

    control_keyword_value_init();
    ipvs_conn_keyword_value_init();
    udp_keyword_value_init();
    tcp_keyword_value_init();
    synproxy_keyword_value_init();

    ipv6_keyword_value_init();
}

static vector_t install_keywords(void)
{
    /* install configuration keywords here */

    install_global_keywords();

    install_netif_keywords();
    install_timer_keywords();
    install_neighbor_keywords();
    install_sa_pool_keywords();

    install_ipv4_keywords();
    install_ip4_frag_keywords();

    install_ipset_hash_keywords();

    install_control_keywords();

    install_keyword_root("ipvs_defs", NULL);
    install_keyword("conn", NULL, KW_TYPE_NORMAL);
    install_ipvs_conn_keywords();

    install_keyword("tcp", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_proto_tcp_keywords();
    install_synproxy_keywords();
    install_sublevel_end();

    install_keyword("udp", NULL, KW_TYPE_NORMAL);
    install_sublevel();
    install_proto_udp_keywords();
    install_sublevel_end();

    install_ipv6_keywords();

    return g_keywords;
}

static inline void load_conf_file(char *cfg_file)
{
    keyword_value_init();
    init_data(cfg_file, install_keywords);
}

static inline void sighup(void)
{
    SET_RELOAD;
}

static void try_reload(void *dump)
{
    if (unlikely(RELOAD_STATUS)) {
        UNSET_RELOAD;
        /* using default configuration file */
        load_conf_file(NULL);
    }
}

static void sig_callback(int sig)
{
    switch(sig) {
        case SIGHUP:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGHUP.\n");
            sighup();
            break;
        case SIGINT:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGINT.\n");
            break;
        case SIGQUIT:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGQUIT.\n");
            break;
        case SIGTERM:
            RTE_LOG(INFO, CFG_FILE, "Got signal SIGTERM.\n");
            break;
        default:
            RTE_LOG(INFO, CFG_FILE, "Unkown signal type %d.\n", sig);
            break;
    }
}

static struct dpvs_lcore_job reload_job = {
    .name = "cfgfile_reload",
    .type = LCORE_JOB_LOOP,
    .func = try_reload,
};

int cfgfile_init(void)
{
    int ret;
    struct sigaction sig;

    netif_cfgfile_init();

    /* register SIGHUP signal handler */
    memset(&sig, 0, sizeof(struct sigaction));
    sig.sa_handler = sig_callback;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    ret = sigaction(SIGHUP, &sig, NULL);
    if (ret < 0) {
        RTE_LOG(ERR, CFG_FILE, "%s: signal handler register failed\n", __func__);
        return EDPVS_SYSCALL;
    }

    /* module initialization */
    if ((ret = global_conf_init()) != EDPVS_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: global configuration initialization failed\n",
                __func__);
        return ret;
    }

    /* load configuration file on start */
    SET_RELOAD;
    try_reload(NULL);

    ret = dpvs_lcore_job_register(&reload_job, LCORE_ROLE_MASTER);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: fail to register cfgfile_reload job\n", __func__);
        return ret;
    }

    return EDPVS_OK;
}

int cfgfile_term(void)
{
    int ret;
    /* module termination */
    if ((ret = global_conf_term()) != EDPVS_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: global configuration termination failed\n",
                __func__);
        return ret;
    }

    ret = dpvs_lcore_job_unregister(&reload_job, LCORE_ROLE_MASTER);
    if (ret != EDPVS_OK) {
        RTE_LOG(ERR, CFG_FILE, "%s: fail to unregister cfgfile_reload job\n", __func__);
        return ret;
    }

    return EDPVS_OK;
}
