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
#include <fcntl.h>
#include <sys/stat.h>
#include "global_conf.h"
#include "global_data.h"
#include "log.h"
#include "lldp.h"

bool g_dpvs_pdump = false;

static void log_current_time(void)
{
    time_t t = time(0);
    char buf[256];
    strftime(buf, sizeof(buf), "%Y/%m/%d %X %A",localtime(&t));
    RTE_LOG(INFO, CFG_FILE, "load dpvs configuation file at %s\n", buf);
}

static inline void set_log_level_dynamic_types(const char *regex, uint32_t level)
{
#if RTE_VERSION >= RTE_VERSION_NUM(17, 5, 0, 0)
    rte_log_set_level_regexp(regex, level);
#endif
}

static int set_log_level(char *log_level)
{
    if (!log_level) {
        rte_log_set_global_level(RTE_LOG_DEBUG);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_DEBUG);
    } else if (!strncmp(log_level, "EMERG", strlen("EMERG"))) {
        rte_log_set_global_level(RTE_LOG_EMERG);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_EMERG);
    } else if (!strncmp(log_level, "ALERT", strlen("ALERT"))) {
        rte_log_set_global_level(RTE_LOG_ALERT);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_ALERT);
    } else if (!strncmp(log_level, "CRIT", strlen("CRIT"))) {
        rte_log_set_global_level(RTE_LOG_CRIT);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_CRIT);
    } else if (!strncmp(log_level, "ERR", strlen("ERR"))) {
        rte_log_set_global_level(RTE_LOG_ERR);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_ERR);
    } else if (!strncmp(log_level, "WARNING", strlen("WARNING"))) {
        rte_log_set_global_level(RTE_LOG_WARNING);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_WARNING);
    } else if (!strncmp(log_level, "NOTICE", strlen("NOTICE"))) {
        rte_log_set_global_level(RTE_LOG_NOTICE);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_NOTICE);
    } else if (!strncmp(log_level, "INFO", strlen("INFO"))) {
        rte_log_set_global_level(RTE_LOG_INFO);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_INFO);
    } else if (!strncmp(log_level, "DEBUG", strlen("DEBUG"))) {
        rte_log_set_global_level(RTE_LOG_DEBUG);
        set_log_level_dynamic_types("user[0-9]", RTE_LOG_DEBUG);
    } else {
        RTE_LOG(WARNING, CFG_FILE, "%s: illegal log level: %s\n",
                __func__, log_level);
        return EDPVS_INVAL;
    }
    return EDPVS_OK;
}

static FILE *g_log_stream;
static int set_log_file(const char *log_file)
{
    if (log_file == NULL)
        return EDPVS_NOTEXIST;

    if (g_log_stream) {
        fclose(g_log_stream);
        g_log_stream = NULL;
    }

    g_log_stream = fopen(log_file, "a+");
    if (g_log_stream == NULL) {
        RTE_LOG(WARNING, CFG_FILE, "%s: illegal log file: %s -- %s\n",
                __func__, log_file, strerror(errno));
        return EDPVS_INVAL;
    }

    if (rte_openlog_stream(g_log_stream)) {
        RTE_LOG(WARNING, CFG_FILE, "%s: fail to set log stream to %s\n",
                __func__, log_file);
        return EDPVS_DPDKAPIFAIL;
    }

    log_current_time();
    return EDPVS_OK;
}

static void global_defs_handler(vector_t tokens)
{
    // initilize config to default value
    g_dpvs_log_tslen = 0;
    dpvs_lldp_disable();
}

static void log_level_handler(vector_t tokens)
{
    char *log_level = set_value(tokens);
    assert(log_level);
    RTE_LOG(INFO, CFG_FILE, "log_level = %s\n", log_level);
    set_log_level(log_level);
    FREE_PTR(log_level);
}

static void log_file_handler(vector_t tokens)
{
    char *log_file = set_value(tokens);
    assert(log_file);
    RTE_LOG(INFO, CFG_FILE, "log_file = %s\n", log_file);
    set_log_file(log_file);
    FREE_PTR(log_file);
}

static void log_async_mode_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (strcasecmp(str, "on") == 0)
        g_dpvs_log_async_mode = true;
    else if (strcasecmp(str, "off") == 0)
        g_dpvs_log_async_mode = false;
    else
        RTE_LOG(WARNING, CFG_FILE, "invalid log async mode %s\n", str);

    RTE_LOG(INFO, CFG_FILE, "log async mode = %s\n", g_dpvs_log_async_mode ? "on" : "off");

    FREE_PTR(str);
}

static void log_with_timestamp_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (strcasecmp(str, "on") == 0)
        g_dpvs_log_tslen = LOG_SYS_TIME_LEN;
    else if (strcasecmp(str, "off") == 0)
        g_dpvs_log_tslen = 0;
    else
        RTE_LOG(WARNING, CFG_FILE, "invalid log_with_timestamp %s\n", str);

    RTE_LOG(INFO, CFG_FILE, "log_with_timestamp = %s\n", g_dpvs_log_tslen > 0 ? "on" : "off");

    FREE_PTR(str);
}

static void log_async_pool_size_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int poolsize;

    assert(str);
    poolsize = atoi(str);
    if (poolsize < DPVS_LOG_POOL_SIZE_MIN) {
        RTE_LOG(WARNING, CFG_FILE, "invalid log_async_pool_size %s, using default %d\n",
                str, DPVS_LOG_POOL_SIZE_DEF);
        dpvs_set_log_pool_size(DPVS_LOG_POOL_SIZE_DEF);
    } else {
        is_power2(poolsize, 1, &poolsize);
        RTE_LOG(INFO, CFG_FILE, "log_async_pool_size = %d (round to 2^n-1)\n", poolsize);
        dpvs_set_log_pool_size(poolsize - 1);
    }

    FREE_PTR(str);
}

static void kni_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (strcasecmp(str, "on") == 0)
        g_kni_enabled = true;
    else if (strcasecmp(str, "off") == 0)
        g_kni_enabled = false;
    else
        RTE_LOG(WARNING, CFG_FILE, "invalid kni switch: %s\n", str);

    RTE_LOG(INFO, CFG_FILE, "kni = %s\n", g_kni_enabled ? "on" : "off");

    FREE_PTR(str);
}

static void lldp_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (strcasecmp(str, "on") == 0)
        dpvs_lldp_enable();
    else if (strcasecmp(str, "off") == 0)
        dpvs_lldp_disable();
    else
        RTE_LOG(WARNING, CFG_FILE, "invalid lldp config: %s\n", str);

    RTE_LOG(INFO, CFG_FILE, "lldp = %s\n", dpvs_lldp_is_enabled() ? "on" : "off");

    FREE_PTR(str);
}

#ifdef CONFIG_DPVS_PDUMP
static void pdump_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);
    if (strcasecmp(str, "on") == 0)
        g_dpvs_pdump = true;
    else if (strcasecmp(str, "off") == 0)
        g_dpvs_pdump = false;
    else
        RTE_LOG(WARNING, CFG_FILE, "invalid pdump switch: %s\n", str);

    RTE_LOG(INFO, CFG_FILE, "pdump = %s\n", g_dpvs_pdump ? "on" : "off");

    FREE_PTR(str);
}
#endif

void install_global_keywords(void)
{
    install_keyword_root("global_defs", global_defs_handler);
    install_keyword("log_level", log_level_handler, KW_TYPE_NORMAL);
    install_keyword("log_file", log_file_handler, KW_TYPE_NORMAL);
    install_keyword("log_async_mode", log_async_mode_handler, KW_TYPE_INIT);
    install_keyword("log_with_timestamp", log_with_timestamp_handler, KW_TYPE_NORMAL);
    install_keyword("log_async_pool_size", log_async_pool_size_handler, KW_TYPE_INIT);
    install_keyword("kni", kni_handler, KW_TYPE_INIT);
    install_keyword("lldp", lldp_handler, KW_TYPE_NORMAL);
#ifdef CONFIG_DPVS_PDUMP
    install_keyword("pdump", pdump_handler, KW_TYPE_INIT);
#endif
}

int global_conf_init(void)
{
    return EDPVS_OK;
}

int global_conf_term(void)
{
    if (g_log_stream) {
        fclose(g_log_stream);
        g_log_stream = NULL;
    }
    return EDPVS_OK;
}
