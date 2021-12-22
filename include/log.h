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

#define DPVS_LOG_RING_SIZE_DEF 4096
#define DPVS_LOG_RING_SIZE_MIN 256
#define DPVS_LOG_RING_SIZE_MAX 524288


#define TIMEZONE   0
#define DAY        (60*60*24) 
#define YEARFIRST  2001 
#define YEARSTART  (365*(YEARFIRST-1970) + 8) 
#define YEAR400    (365*4*100 + (4*(100/4 - 1) + 1)) 
#define YEAR100    (365*100 + (100/4 - 1)) 
#define YEAR004    (365*4 + 1) 
#define YEAR001    365

#define LOG_SYS_TIME_LEN 20

#define LOG_INTERNAL_TIME 5

#define LOG_SLOW_INTERNAL_TIME (60*10)

#define DPVS_LOG_MAX_LINE_LEN 1024

#define LOG_BUF_MAX_LEN 4096

#define DPVS_LOG_POOL_SIZE_DEF     2097151
#define DPVS_LOG_POOL_SIZE_MIN     65536
#define DPVS_LOG_CACHE_SIZE_DEF    256


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
    int log_hash;
    uint64_t log_begin;
    int slow;
    uint64_t slow_begin;
    uint32_t missed;
} log_stats_t;

int dpvs_log(uint32_t level, uint32_t logtype, const char *func, int line, const char *format, ...);
int log_slave_init(void);    

#endif
