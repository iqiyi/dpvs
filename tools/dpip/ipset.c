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
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "dpip.h"
#include "conf/ipset.h"
#include "linux_ipv6.h"
#include "sockopt.h"

static void ipset_help(void)
{
	fprintf(stderr, 
	                "Usage:\n"
                        "    dpip ipset show\n"
			"    dpip ipset { add | del } IP\n"
		);
}



static int ipset_parse_args(struct dpip_conf *conf, struct dp_vs_ipset_conf *ip_conf)
{
    char *ipaddr = NULL;
	
    memset(ip_conf, 0, sizeof(struct dp_vs_ipset_conf));
    ip_conf->af = conf->af;

    while (conf->argc > 0) {
	ipaddr = conf->argv[0];
        NEXTARG(conf);
    }
	
    if (conf->argc > 0) {
        fprintf(stderr, "too many arguments\n");
        return -1;
    }

    if (ipaddr) {
	if (inet_pton_try(&ip_conf->af, ipaddr, &ip_conf->addr) <= 0)
	{
	     fprintf(stderr, "bad IP\n");
             return -1;
	}
    }
    return 0;
}

static int ipset4_dump(const struct dp_vs_ipset_conf *ipconf)
{
    char ip[64];
    printf("%s\n", inet_ntop(ipconf->af, &ipconf->addr, ip, sizeof(ip))? ip: "");
    return 0;
}

static int ipset_do_cmd(struct dpip_obj *obj, dpip_cmd_t cmd,
                        struct dpip_conf *conf)
{
    struct dp_vs_ipset_conf ip_conf;
    struct dp_vs_ipset_conf_array *array;
    size_t size, i;
    int err;

    if (ipset_parse_args(conf, &ip_conf) != 0)
        return EDPVS_INVAL;

    switch (conf->cmd) {
    case DPIP_CMD_ADD:
        return dpvs_setsockopt(SOCKOPT_SET_IPSET_ADD, &ip_conf, sizeof(ip_conf));

    case DPIP_CMD_DEL:
        return dpvs_setsockopt(SOCKOPT_SET_IPSET_DEL, &ip_conf, sizeof(ip_conf));

    case DPIP_CMD_FLUSH:
        return dpvs_setsockopt(SOCKOPT_SET_IPSET_FLUSH, NULL, 0);

    case DPIP_CMD_SHOW:
        err = dpvs_getsockopt(SOCKOPT_GET_IPSET_SHOW, &ip_conf, sizeof(ip_conf),
                              (void **)&array, &size);
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
            printf("IPset has %d members:\n", array->nipset);
        else
            printf("IPset has no members.\n");
            
        for (i = 0; i < array->nipset; i++)
            ipset4_dump(&array->ips[i]);

        dpvs_sockopt_msg_free(array);
        return EDPVS_OK;
    default:
        return EDPVS_NOTSUPP;
    }
}

struct dpip_obj dpip_ipset = {
    .name   = "ipset",
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

