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
#include <stdlib.h>
#include <string.h>
#include "conf/common.h"
#include "dpip.h"
#include "conf/ipset.h"
#include "linux_ipv6.h"
#include "sockopt.h"

static void ipset_help(void)
{
	fprintf(stderr, 
                    "Usage:\n"
                    "    dpip gfwip { add | del } IPs\n"
                    "    dpip gfwip show\n"
                    "    dpip gfwip flush\n"
    );
}

static int ipset_parse_args(struct dpip_conf *conf, struct dp_vs_multi_ipset_conf **ips_conf, int *ips_size)
{
    char *ipaddr = NULL;
    int ipset_size;
    int index = 0;
    struct dp_vs_multi_ipset_conf *ips;

    if (conf->cmd == DPIP_CMD_FLUSH || conf->cmd == DPIP_CMD_SHOW) {
        if (conf->argc != 0) 
            return -1;
        else 
            return 0;
    }
	
    if (conf->argc <= 0) {
        fprintf(stderr, "no arguments\n");
        return -1;
    }

    ipset_size = sizeof(struct dp_vs_multi_ipset_conf) + conf->argc*sizeof(struct dp_vs_ipset_conf);
    *ips_conf = malloc(ipset_size);
    if (*ips_conf == NULL) {
        fprintf(stderr, "no memory\n");
        return -1;
    }		
    memset(*ips_conf, 0, ipset_size);
    ips = *ips_conf;
	
    ips->num = conf->argc;
    while (conf->argc > 0) {
        ipaddr = conf->argv[0];
        ips->ipset_conf[index].af = AF_INET;
        if (inet_pton_try(&conf->af, ipaddr, &ips->ipset_conf[index].addr) <= 0)
        {
            fprintf(stderr, "bad IP\n");
            free(ips);
            return -1;
        }
        index++;
        NEXTARG(conf);
    }

    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        free(ips);
        return -1;
    }
    *ips_size = ipset_size;
    return 0;
}

static int ipset_dump(const struct dp_vs_ipset_conf *ipconf)
{
    char ip[64];
    printf("%s\n", inet_ntop(ipconf->af, &ipconf->addr, ip, sizeof(ip))? ip: "");
    return 0;
}

static int ipset_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                        struct dpip_conf *conf)
{
    struct dp_vs_multi_ipset_conf *ips_conf;
    struct dp_vs_ipset_conf_array *array;
    size_t size, i;
    int ips_size, err;

    if ((ipset_parse_args(conf, &ips_conf, &ips_size)) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
    case DPIP_CMD_ADD:
        err = dpvs_setsockopt(SOCKOPT_SET_IPSET_ADD, ips_conf, ips_size);
        free(ips_conf);
        return err;

    case DPIP_CMD_DEL:
        err = dpvs_setsockopt(SOCKOPT_SET_IPSET_DEL, ips_conf, ips_size);
        free(ips_conf);
        return err;

    case DPIP_CMD_FLUSH:
        return dpvs_setsockopt(SOCKOPT_SET_IPSET_FLUSH, NULL, 0);

    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_IPSET_SHOW, NULL, 0, (void **)&array, &size);
        if (err != 0)
            return err;

        if (size < sizeof(*array) 
                || size != sizeof(*array) + \
                           array->nipset * sizeof(struct dp_vs_ipset_conf)) {
            fprintf(stderr, "corrupted response.\n");
            dpvs_sockopt_msg_free(array);
            return EDPVS_INVAL;
        }
        

        if (array->nipset)
            printf("IPset gfwip has %d members:\n", array->nipset);
        else
            printf("IPset gfwip has no members.\n");
            
        for (i = 0; i < array->nipset; i++)
            ipset_dump(&array->ips[i]);

        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_ipset = {
    .name   = "gfwip",
    .help   = ipset_help,
    .do_cmd = ipset_do_cmd,
};

static void __init ipset_init(void)
{
    dpip_register_obj(&dpip_ipset);
} 

static void __exit ipset_exit(void)
{
    dpip_unregister_obj(&dpip_ipset);
}

