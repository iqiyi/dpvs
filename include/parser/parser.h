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
#ifndef __PARSER_H__
#define __PARSER_H__

#include <stdbool.h>
#include "vector.h"

#define RTE_LOGTYPE_CFG_FILE RTE_LOGTYPE_USER1
typedef enum {
    KW_TYPE_INIT = 1, /* keyword used in init stage only */
    KW_TYPE_NORMAL = 2, /* keyword used in both init and normal stage */
} keyword_type_t;

typedef void (*keyword_callback_t)(vector_t);

/* global definitions */
#define CFG_FILE_EOB "}"
#define CFG_FILE_MAX_BUF_SZ 1024

/* exported global vars */
extern vector_t g_keywords;
extern FILE *g_current_stream;
extern bool g_reload;

/* keyword definition */
struct keyword {
    char *str;
    keyword_callback_t handler;
    vector_t sub;
};

/* reloading helpers */
#define SET_RELOAD (g_reload = true)
#define UNSET_RELOAD (g_reload = false)
#define RELOAD_STATUS (g_reload)
#define RELOAD_DELAY 5

/* interfaces */
void keyword_alloc(vector_t keywords_vec, char *str, keyword_callback_t handler);
void keyword_alloc_sub(vector_t keywords_vec, char *str, keyword_callback_t handler);
void free_keywords(vector_t keywords);
#ifdef DPVS_CFG_PARSER_DEBUG
void dump_keywords(vector_t keywords, int level);
#endif

void install_sublevel(void);
void install_sublevel_end(void);
void install_keyword_root(char *str, keyword_callback_t handler);
void install_keyword(char *str, keyword_callback_t handler, keyword_type_t type);

void process_stream(vector_t keywords_vec);
void read_conf_file(char *conf_file);
int check_include(char *buf);

int read_line(char *buf, int size);
vector_t read_value_block(void);
void alloc_value_block(void (*alloc_func)(vector_t));

void *set_value(vector_t tokens);
void init_data(char *conf_file, vector_t (*init_keywords)(void));

#endif
