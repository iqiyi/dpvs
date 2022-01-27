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
#ifndef _DPVS_LOG_H_
#define _DPVS_LOG_H_

#define LOG_SYS_TIME_LEN 20
#define DPVS_LOG_MAX_LINE_LEN 1024
#define LOG_BUF_MAX_LEN 4096

#define DPVS_LOG_POOL_SIZE_DEF     16383
#define DPVS_LOG_POOL_SIZE_MIN     1023
#define DPVS_LOG_CACHE_SIZE_DEF    64


extern bool g_dpvs_log_async_mode;
extern uint8_t g_dpvs_log_tslen;

struct dpvs_log {
    lcoreid_t cid;          
    int log_level;
    int log_type;	
    int log_len;
    char data[0];           
};

typedef struct log_buf {
    char buf[LOG_BUF_MAX_LEN];
    int pos;
    int level;
    uint64_t time;
} log_buf_t;

typedef struct log_stats{
    unsigned int log_hash;
    uint64_t log_begin;
    int slow;
    uint64_t slow_begin;
    uint32_t missed;
} log_stats_t;

int dpvs_log(uint32_t level, uint32_t logtype, const char *func, int line,
        const char *format, ...) __rte_format_printf(5, 6);
int log_slave_init(void);    
void dpvs_set_log_pool_size(int size);

#endif
