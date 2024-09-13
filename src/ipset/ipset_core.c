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
#include <string.h>
#include <errno.h>
#include <netinet/ip6.h>
#include "ctrl.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipset/ipset.h"
#include "conf/common.h"

#define this_ipsets_tbl         (RTE_PER_LCORE(ip_sets))

#define IPSETS_TBL_BITS         7
#define IPSETS_TBL_SIZE         (1 << IPSETS_TBL_BITS)
#define IPSETS_TBL_MASK         (IPSETS_TBL_SIZE - 1)

/* Registered ipset types list */
static struct list_head ipset_types;
/* Ip sets hash table */
static RTE_DEFINE_PER_LCORE(struct list_head *, ip_sets);

static struct ipset *
ipset_lookup(const char *name)
{
    struct ipset *set;
    uint32_t hash;

    hash = rte_jhash(name, strlen(name), 0) & IPSETS_TBL_MASK;

    list_for_each_entry(set, &this_ipsets_tbl[hash], list) {
        if (!strcmp(set->name, name))
            return set;
    }
    return NULL;
}

struct ipset *
ipset_get(const char *name)
{
    struct ipset *set = ipset_lookup(name);

    if (set == NULL)
        return NULL;

    set->references++;
    return set;
}

static struct ipset_type *
ipset_type_lookup(char *name)
{
    struct ipset_type *type;

    list_for_each_entry(type, &ipset_types, l) {
        if (!strcmp(type->name, name))
            return type;
    }
    return NULL;
}

static int
ipset_local_create(struct ipset_param *param)
{
    struct ipset *set;
    struct ipset_type *type;
    uint32_t hash;
    int ret = 0;
    struct ipset_option *opt = &param->option;

    if ((type = ipset_type_lookup(param->type)) == NULL) {
        RTE_LOG(ERR, IPSET, "IP set type %s not supported.\n", param->type);
        return EDPVS_NOTSUPP;
    }

    if ((set = ipset_lookup(param->name)) != NULL) {
        RTE_LOG(ERR, IPSET, "IP set %s already exists.\n", param->name);
        return EDPVS_EXIST;
    }

    set = rte_zmalloc("ip set", sizeof(struct ipset), RTE_CACHE_LINE_SIZE);

    rte_strlcpy(set->name, param->name, IPSET_MAXNAMELEN);
    set->type = type;

    if (opt->family)
        set->family = opt->family;
    else
        set->family = AF_INET;

    if (opt->create.comment)
        set->comment = true;

    ret = set->type->create(set, param);
    if (ret)
        goto out;

    hash = rte_jhash(set->name, strlen(set->name), 0) & IPSETS_TBL_MASK;
    list_add_tail(&set->list, &this_ipsets_tbl[hash]);

    return EDPVS_OK;

    out:
        rte_free(set);
        return ret;
}

int ipset_local_action(struct ipset_param *param)
{
    struct ipset *set;
    int opcode = param->opcode;

    if (opcode == IPSET_OP_CREATE)
        return ipset_local_create(param);

    if ((set = ipset_lookup(param->name)) == NULL) {
        return EDPVS_NOTEXIST;
    }

    switch (opcode) {
        case IPSET_OP_ADD:
        case IPSET_OP_DEL:
        case IPSET_OP_TEST:
            return set->variant->adt(opcode, set, param);
        case IPSET_OP_FLUSH:
            set->type->flush(set);
            return EDPVS_OK;
        case IPSET_OP_DESTROY:
            if (set->references != 0)
                return EDPVS_BUSY;
            set->type->destroy(set);
            list_del(&set->list);
            rte_free(set);
            return EDPVS_OK;
        default:
            return EDPVS_NOTSUPP;
    }
}

int ipset_do_list(const void *conf, void **out, size_t *outsize)
{
    void *data, *ptr;
    struct ipset *set;
    struct ipset_param *param = (struct ipset_param *)conf;
    struct ipset_info_array *array;
    struct ipset_info *info;
    int nipset = 0, nelem = 0, i = 0, j;

    /* list the specific set */
    if (strlen(param->name) != 0) {
        if ((set = ipset_lookup(param->name)) == NULL)
            return EDPVS_NOTEXIST;

        *outsize = sizeof(*array) + sizeof(struct ipset_info)
                 + set->elements * sizeof(struct ipset_member);
        data = rte_zmalloc(NULL, *outsize, RTE_CACHE_LINE_SIZE);
        if (data == NULL)
            return EDPVS_NOMEM;

        array = (struct ipset_info_array *)data;
        array->nipset = 1;
        info = &array->infos[0];
        info->members = info + 1;
        info->references = set->references;

        set->type->list(set, info);

        *out = data;
        return EDPVS_OK;
    }

    /* list all sets */
    /* obtain the total size */
    for (j = 0; j < IPSETS_TBL_SIZE; j++) {
        list_for_each_entry(set, &this_ipsets_tbl[j], list) {
            nipset++;
            nelem += set->elements;
        }
    }

    /* allocate memory */
    *outsize = sizeof(*array) + nipset * sizeof(struct ipset_info)
            + nelem * sizeof(struct ipset_member);
    data = rte_zmalloc(NULL, *outsize, RTE_CACHE_LINE_SIZE);
    if (data == NULL)
        return EDPVS_NOMEM;

    array = (struct ipset_info_array *)data;
    array->nipset = nipset;
    /* Let the set do the actual listing job
       Memory layout :
       | array | info[0] | info[1] | ... | members[0] | members[1] | ... |
    */
    ptr = data + sizeof(*array) + nipset * sizeof(*info);
    for (j = 0; j < IPSETS_TBL_SIZE; j++) {
        list_for_each_entry(set, &this_ipsets_tbl[j], list) {
            info = &array->infos[i++];
            info->members = ptr;
            info->references = set->references;
            ptr += set->elements * sizeof(struct ipset_member);
            set->type->list(set, info);
        }
    }
    *out = data;

    return EDPVS_OK;
}

static int
ipset_flush_lcore(void *arg)
{
    int i;
    struct ipset *set;

    if (rte_lcore_id() >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    for (i = 0; i < IPSETS_TBL_SIZE; i++) {
        list_for_each_entry(set, &this_ipsets_tbl[i], list)
            set->type->destroy(set);
    }

    if (this_ipsets_tbl) {
        rte_free(this_ipsets_tbl);
        this_ipsets_tbl = NULL;
    }

    return EDPVS_OK;
}

static int
ipset_lcore_init(void *arg)
{
    int i;
    lcoreid_t cid = rte_lcore_id();

    if (cid >= DPVS_MAX_LCORE)
        return EDPVS_OK;

    if (!rte_lcore_is_enabled(cid))
        return EDPVS_DISABLED;

    this_ipsets_tbl = rte_zmalloc(NULL, 
            sizeof(struct list_head) * IPSETS_TBL_SIZE,
            RTE_CACHE_LINE_SIZE);
    
    if (!this_ipsets_tbl)
        return EDPVS_NOMEM;
    
    for (i = 0; i < IPSETS_TBL_SIZE; i++)
        INIT_LIST_HEAD(&this_ipsets_tbl[i]);

    return EDPVS_OK;
}

static void
ipset_type_register(struct ipset_type *type)
{
    list_add_tail(&type->l, &ipset_types);
}

/* IPset types */
extern struct ipset_type bitmap_ip_type, bitmap_ipmac_type, bitmap_port_type,
       hash_ip_type, hash_net_type, hash_ipport_type, hash_netport_type,
       hash_netportiface_type, hash_ipportip_type, hash_netportnet_type,
       hash_ipportnet_type, hash_netportnetport_type;

int ipset_init(void)
{
    int err;
    lcoreid_t cid;

    INIT_LIST_HEAD(&ipset_types);

    ipset_type_register(&bitmap_ip_type);
    ipset_type_register(&bitmap_ipmac_type);
    ipset_type_register(&bitmap_port_type);
    ipset_type_register(&hash_ip_type);
    ipset_type_register(&hash_net_type);
    ipset_type_register(&hash_ipport_type);
    ipset_type_register(&hash_netport_type);
    ipset_type_register(&hash_netportiface_type);
    ipset_type_register(&hash_ipportip_type);
    ipset_type_register(&hash_netportnet_type);
    ipset_type_register(&hash_ipportnet_type);
    ipset_type_register(&hash_netportnetport_type);

    if ((err = ipset_ctrl_init()) < 0) {
        RTE_LOG(ERR, IPSET, "ipset ctrl init: %s.\n", dpvs_strerror(err));
        return err;
    };

    if ((err = ipset_hash_init()) < 0) {
        RTE_LOG(ERR, IPSET, "ipset hash init: %s.\n", dpvs_strerror(err));
        return err;
    }

    rte_eal_mp_remote_launch(ipset_lcore_init, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, IPSET, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}

int ipset_term(void)
{
    int err;
    lcoreid_t cid;

    if ((err = ipset_ctrl_term()) < 0) {
        RTE_LOG(ERR, IPSET, "ipset ctrl term: %s.\n", dpvs_strerror(err));
    };

    rte_eal_mp_remote_launch(ipset_flush_lcore, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        if ((err = rte_eal_wait_lcore(cid)) < 0) {
            RTE_LOG(WARNING, IPSET, "%s: lcore %d: %s.\n",
                    __func__, cid, dpvs_strerror(err));
        }
    }

    return EDPVS_OK;
}
