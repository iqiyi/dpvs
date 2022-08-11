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
/**
 * Note: control plane only
 * based on dpvs_sockopt.
 */
#ifndef __DPVS_IPSET_CONF_H__
#define __DPVS_IPSET_CONF_H__

#include <net/if.h>
#include "conf/inet.h"
#include "conf/sockopts.h"

#define IPSET_MAXNAMELEN    32
#define IPSET_MAXCOMLEN     32

#define IPSET_F_FORCE   0x0001

enum ipset_op {
    IPSET_OP_ADD,
    IPSET_OP_DEL,
    IPSET_OP_TEST,
    IPSET_OP_CREATE,
    IPSET_OP_DESTROY,
    IPSET_OP_FLUSH,
    IPSET_OP_LIST,
    IPSET_OP_MAX
};

struct ipset_option {
    int family;
    union {
        struct {
            bool comment;
            int hashsize;
            int maxelem;
        } create;
        struct {
            bool nomatch;
        } add;
    };
};

struct ipset_param {
    char                        type[IPSET_MAXNAMELEN];
    char                        name[IPSET_MAXNAMELEN];
    char                        comment[IPSET_MAXCOMLEN];
    int                         opcode;
    struct ipset_option         option;
    uint16_t                    flag;

    uint8_t                     proto;
    uint8_t                     cidr;
    struct inet_addr_range      range;   /* port in host byteorder */
    uint8_t                     mac[6];
    char                        iface[IFNAMSIZ];

    /* for type with 2 nets */
    uint8_t                     cidr2;
    struct inet_addr_range      range2;
    //uint8_t                     mac[2];
};

struct ipset_member {
    char                        comment[IPSET_MAXCOMLEN];

    union inet_addr             addr;
    uint8_t                     cidr;
    uint8_t                     proto;
    uint16_t                    port;
    uint8_t                     mac[6];
    char                        iface[IFNAMSIZ];
    bool                        nomatch;
    
    /* second net */
    union inet_addr             addr2;
    uint8_t                     cidr2;
    uint16_t                    port2;
};

struct ipset_info {
    char name[IPSET_MAXNAMELEN];
    char type[IPSET_MAXNAMELEN];
    bool comment;

    union {
        struct ipset_bitmap_header {
            struct inet_addr_range range;
            uint8_t cidr;
        } bitmap;
        struct ipset_hash_header {
            int hashsize;
            int maxelem;
        } hash;
    };

    int af;
    size_t size;
    int entries;
    int references;

    void *members;
};

struct ipset_info_array {
    int                   nipset;
    struct ipset_info     infos[0];
} __attribute__((__packed__));

#endif /* __DPVS_IPSET_CONF_H__ */
