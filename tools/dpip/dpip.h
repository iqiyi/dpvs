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
#ifndef __DPIP_H__
#define __DPIP_H__
#include "list.h"
#include "utils.h"

#define DPIP_NAME           "dpip"
#ifndef DPIP_VERSION
#define DPIP_VERSION        "v1.0.0"
#endif

typedef enum dpip_cmd_e {
    DPIP_CMD_ENABLE,
    DPIP_CMD_DISABLE,
    DPIP_CMD_CREATE,
    DPIP_CMD_DESTROY,
    DPIP_CMD_ADD,
    DPIP_CMD_DEL,
    DPIP_CMD_SET,
    DPIP_CMD_SHOW,
    DPIP_CMD_REPLACE,
    DPIP_CMD_FLUSH,
    DPIP_CMD_HELP,
    DPIP_CMD_TEST,
} dpip_cmd_t;

struct dpip_conf {
    int         af;
    int         verbose;
    int         stats;
    int         interval;
    int         count;
    bool        color;
    bool        force;
    char        *obj;
    dpip_cmd_t  cmd;
    int         argc;
    char        **argv;
};

struct dpip_obj {
    struct list_head list;
    char *name;
    void *param;

    void (*help)(void);
    /* @conf is used to passing general config like af, verbose, ...
     * we have obj.parse() to handle obj specific parameters. */
    int (*do_cmd)(struct dpip_obj *obj, dpip_cmd_t cmd,
                  struct dpip_conf *conf);
    /* the parser can be used to parse @conf into @param */
    int (*parse)(struct dpip_obj *obj, struct dpip_conf *conf);
    int (*check)(const struct dpip_obj *obj, dpip_cmd_t cmd);
};

void dpip_register_obj(struct dpip_obj *obj);
void dpip_unregister_obj(struct dpip_obj *obj);

#endif
