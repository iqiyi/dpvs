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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <linux/socket.h>
#include <arpa/inet.h>
#include "dpip.h"
#include "list.h"
#include "sockopt.h"
#include "conf/common.h"

static struct list_head dpip_objs = LIST_HEAD_INIT(dpip_objs);

static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "    "DPIP_NAME" [OPTIONS] OBJECT { COMMAND | help }\n"
        "Parameters:\n"
        "    OBJECT  := { link | addr | route | neigh | vlan | tunnel | qsch | cls |\n"
        "                 ipv6 | iftraf | eal-mem | ipset | flow | maddr | lldp }\n"
        "    COMMAND := { create | destroy | add | del | show (list) | set (change) |\n"
        "                 replace | flush | test | enable | disable }\n"
        "Options:\n"
        "    -v, --verbose\n"
        "    -h, --help\n"
        "    -V, --version\n"
        "    -4, --family=inet\n"
        "    -6, --family=inet6\n"
        "    -s, --stats, statistics\n"
        "    -C, --color\n"
        "    -F, --force\n"
        );
}

static struct dpip_obj *dpip_obj_get(const char *name)
{
    struct dpip_obj *obj;

    list_for_each_entry(obj, &dpip_objs, list) {
        if (strcmp(obj->name, name) == 0)
            return obj;
    }

    return NULL;
}

static int parse_args(int argc, char *argv[], struct dpip_conf *conf)
{
    int opt;
    bool show_usage = false;
    struct dpip_obj *obj;
    struct option opts[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"help",    no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {"family",  required_argument, NULL, 'f'},
        {"stats", no_argument, NULL, 's'},
        {"statistics", no_argument, NULL, 's'},
        {"color",  no_argument, NULL, 'C'},
        {"interval", required_argument, NULL, 'i'},
        {"count", required_argument, NULL, 'c'},
        {"force", no_argument, NULL, 'F'},
        {NULL, 0, NULL, 0},
    };

    memset(conf, 0, sizeof(*conf));
    conf->af = AF_UNSPEC;

    if (argc <= 1) {
        usage();
        exit(0);
    }

    while ((opt = getopt_long(argc, argv, "vhV46f:si:c:CDF", opts, NULL)) != -1) {
        switch (opt) {
        case 'v':
            conf->verbose = 1;
            break;
        case 'h':
            show_usage = true;
            break;
        case 'V':
            printf(DPIP_NAME"-"DPIP_VERSION"\n");
            exit(0);
        case '4':
            conf->af = AF_INET;
            break;
        case '6':
            conf->af = AF_INET6;
            break;
        case 'f':
            if (strcmp(optarg, "inet") == 0)
                conf->af = AF_INET;
            else if (strcmp(optarg, "inet6") == 0)
                conf->af = AF_INET6;
            else {
                fprintf(stderr, "invalid family\n");
                return -1;
            }
            break;
        case 's':
            conf->stats = 1;
            break;
        case 'i':
            conf->interval = atoi(optarg);
            break;
        case 'c':
            conf->count = atoi(optarg);
            break;
        case 'C':
            conf->color = true;
            break;
        case 'F':
            conf->force = true;
            break;
        case '?':
        default:
            fprintf(stderr, "Invalid option: %s\n", argv[optind]);
            return -1;
        }
    }

    /* at least two args for: obj and cmd */
    if (optind >= argc) {
        usage();
        exit(1);
    }

    if (conf->count && !conf->interval)
        fprintf(stderr, "missing option '-i'\n");

    argc -= optind;
    argv += optind;

    conf->obj = argv[0];
    if (argc < 2 || show_usage) {
        obj = dpip_obj_get(conf->obj);
        if (obj && obj->help)
            obj->help();
        else
            usage();
        exit(1);
    }

    if (strcmp(argv[1], "create") == 0)
        conf->cmd = DPIP_CMD_CREATE;
    else if (strcmp(argv[1], "destroy") == 0)
        conf->cmd = DPIP_CMD_DESTROY;
    else if (strcmp(argv[1], "enable") == 0)
        conf->cmd = DPIP_CMD_ENABLE;
    else if (strcmp(argv[1], "disable") == 0)
        conf->cmd = DPIP_CMD_DISABLE;
    else if (strcmp(argv[1], "add") == 0)
        conf->cmd = DPIP_CMD_ADD;
    else if (strcmp(argv[1], "del") == 0)
        conf->cmd = DPIP_CMD_DEL;
    else if (strcmp(argv[1], "set") == 0 ||
             strcmp(argv[1], "change") == 0)
        conf->cmd = DPIP_CMD_SET;
    else if (strcmp(argv[1], "show") == 0 ||
             strcmp(argv[1], "list") == 0)
        conf->cmd = DPIP_CMD_SHOW;
    else if (strcmp(argv[1], "replace") == 0)
        conf->cmd = DPIP_CMD_REPLACE;
    else if (strcmp(argv[1], "flush") == 0)
        conf->cmd = DPIP_CMD_FLUSH;
    else if (strcmp(argv[1], "test") == 0)
        conf->cmd = DPIP_CMD_TEST;
    else if (strcmp(argv[1], "help") == 0)
        conf->cmd = DPIP_CMD_HELP;
    else {
        fprintf(stderr, "invalid command %s\n", argv[1]);
        exit(1);
    }

    conf->argc = argc - 2;
    conf->argv = argv + 2;
    return 0;
}

void dpip_register_obj(struct dpip_obj *obj)
{
    list_add(&obj->list, &dpip_objs);
}

void dpip_unregister_obj(struct dpip_obj *obj)
{
    if (obj->list.prev != LIST_POISON2
            && obj->list.prev != NULL
            && obj->list.prev != &obj->list)
        list_del(&obj->list);
}

int main(int argc, char *argv[])
{
    char *prog;
    struct dpip_conf conf;
    struct dpip_obj *obj;
    int err;

    if ((prog = strchr(argv[0], '/')) != NULL)
        *prog++ = '\0';
    else
        prog = argv[0];

    if (parse_args(argc, argv, &conf) != 0)
        exit(1);

    if ((obj = dpip_obj_get(conf.obj)) == NULL) {
        fprintf(stderr, "%s: invalid object, use `-h' for help.\n", prog);
        exit(1);
    }

    if (conf.cmd == DPIP_CMD_HELP) {
        if (obj->help) {
            obj->help();
            return EDPVS_OK;
        }
    }

    dpvs_sockopt_init();

    if (obj->parse && (err = obj->parse(obj, &conf)) != EDPVS_OK) {
        fprintf(stderr, "%s: parse: %s\n", prog, dpvs_strerror(err));
        exit(1);
    }

    if (obj->check && (err = obj->check(obj, conf.cmd)) != EDPVS_OK) {
        fprintf(stderr, "%s: check: %s\n", prog, dpvs_strerror(err));
        exit(1);
    }

    if ((err = obj->do_cmd(obj, conf.cmd, &conf)) != EDPVS_OK) {
        fprintf(stderr, "%s: %s\n", prog, dpvs_strerror(err));
        exit(1);
    }

    exit(0);
}
