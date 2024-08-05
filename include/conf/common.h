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
#ifndef __DPVS_COMMON_H__
#define __DPVS_COMMON_H__
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

typedef uint32_t sockoptid_t;

#ifndef NELEMS
#define NELEMS(a)       (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef min
#define min(x,y) ({ \
    typeof(x) _x = (x);    \
    typeof(y) _y = (y);    \
    (void) (&_x == &_y);    \
    _x < _y ? _x : _y; })
#endif

#ifndef max
#define max(x,y) ({ \
    typeof(x) _x = (x);    \
    typeof(y) _y = (y);    \
    (void) (&_x == &_y);    \
    _x > _y ? _x : _y; })
#endif

#ifndef min_t
#define min_t(type, a, b) min(((type) a), ((type) b))
#endif
#ifndef max_t
#define max_t(type, a, b) max(((type) a), ((type) b))
#endif

#ifndef __be32
typedef uint32_t    __be32;
#endif

#ifndef __be16
typedef uint16_t    __be16;
#endif

#ifndef __u8
typedef uint8_t     __u8;
#endif

#ifndef __u16
typedef uint16_t    __u16;
#endif

#ifndef __u32
typedef uint32_t    __u32;
#endif

#ifndef lcoreid_t
typedef uint8_t lcoreid_t;
#endif

#ifndef portid_t
typedef uint16_t portid_t;
#endif

#ifndef queueid_t
typedef uint16_t queueid_t;
#endif

#define DPVS_WAIT_WHILE(expr) while(expr){;}

typedef enum {
    DPVS_STATE_STOP = 1,
    DPVS_STATE_INIT,
    DPVS_STATE_NORMAL,
    DPVS_STATE_FINISH,
} dpvs_state_t;

void dpvs_state_set(dpvs_state_t stat);
dpvs_state_t dpvs_state_get(void);

bool is_power2(int num, int offset, int *lower);

enum {
    EDPVS_OK            = 0,
    EDPVS_INVAL         = -1,       /* invalid parameter */
    EDPVS_NOMEM         = -2,       /* no memory */
    EDPVS_EXIST         = -3,       /* already exist */
    EDPVS_NOTEXIST      = -4,       /* not exist */
    EDPVS_INVPKT        = -5,       /* invalid packet */
    EDPVS_DROP          = -6,       /* packet dropped */
    EDPVS_NOPROT        = -7,       /* no protocol */
    EDPVS_NOROUTE       = -8,       /* no route */
    EDPVS_DEFRAG        = -9,       /* defragment error */
    EDPVS_FRAG          = -10,      /* fragment error */
    EDPVS_DPDKAPIFAIL   = -11,      /* DPDK error */
    EDPVS_IDLE          = -12,      /* nothing to do */
    EDPVS_BUSY          = -13,      /* resource busy */
    EDPVS_NOTSUPP       = -14,      /* not support */
    EDPVS_RESOURCE      = -15,      /* no resource */
    EDPVS_OVERLOAD      = -16,      /* overloaded */
    EDPVS_NOSERV        = -17,      /* no service */
    EDPVS_DISABLED      = -18,      /* disabled */
    EDPVS_NOROOM        = -19,      /* no room */
    EDPVS_NONEALCORE    = -20,      /* non-eal thread lcore */
    EDPVS_CALLBACKFAIL  = -21,      /* callbacks fail */
    EDPVS_IO            = -22,      /* I/O error */
    EDPVS_MSG_FAIL      = -23,      /* msg callback failed */
    EDPVS_MSG_DROP      = -24,      /* msg callback dropped */
    EDPVS_PKTSTOLEN     = -25,      /* stolen packet */
    EDPVS_SYSCALL       = -26,      /* system call failed */
    EDPVS_NODEV         = -27,      /* no such device */

    /* positive code for non-error */
    EDPVS_KNICONTINUE   = 1,        /* KNI to continue */
    EDPVS_INPROGRESS    = 2,        /* in progress */
};

extern const char *dpvs_strerror(int err);

int get_numa_nodes(void);

int linux_get_link_status(const char *ifname, int *if_flags, char *if_flags_str, size_t len);
int linux_set_if_mac(const char *ifname, const unsigned char mac[ETH_ALEN]);
int linux_hw_mc_add(const char *ifname, const uint8_t hwma[ETH_ALEN]);
int linux_hw_mc_del(const char *ifname, const uint8_t hwma[ETH_ALEN]);
int linux_ifname2index(const char *ifname);

/* read "n" bytes from a descriptor */
ssize_t readn(int fd, void *vptr, size_t n);

/* write "n" bytes to a descriptor */
ssize_t writen(int fd, const void *vptr, size_t n);

/* send "n" bytes to a descriptor */
ssize_t sendn(int fd, const void *vptr, size_t n, int flags);

static inline char *strupr(char *str) {
    char *s;
    for (s = str; *s != '\0'; s++)
        *s = toupper(*s);
    return str;
}

static inline char *strlwr(char *str) {
    char *s;
    for (s = str; *s != '\0'; s++)
        *s = tolower(*s);
    return str;
}

/* convert hexadecimal string to binary sequence, return the converted binary length
 * note: buflen should be half in size of len at least */
int hexstr2binary(const char *hexstr, size_t len, uint8_t *buf, size_t buflen);

/* convert binary sequence to hexadecimal string, return the converted string length
 * note: buflen should be twice in size of len at least */
int binary2hexstr(const uint8_t *hex, size_t len, char *buf, size_t buflen);

/* convert binary sequence to printable or hexadecimal string, return the converted string length
 * note: buflen should be triple in size of len in the worst case */
int binary2print(const uint8_t *hex, size_t len, char *buf, size_t buflen);

/* get prefix from network mask */
int mask2prefix(const struct sockaddr *addr);

/* get host addresses and corresponding interfaces
 *
 * Loopback addresses, ipv6 link local addresses, and addresses on linked-down
 * or not-running interface are ignored. If multiple addresses matched, return
 * the address of the least prefix length.
 *
 * Params:
 *   @ifname: preferred interface where to get host address, can be NULL
 *   @result4: store ipv4 address found, can be NULL
 *   @result6: store ipv6 address found, can be NULL
 *   @ifname4: interface name of ipv4 address, can be NULL
 *   @ifname6: interface name of ipv6 address, can be NULL
 * Return:
 *   1: only ipv4 address found
 *   2: only ipv6 address found
 *   3: both ipv4 and ipv6 address found
 *   dpvs error code: error occurred
 * */
int get_host_addr(const char *ifname, struct sockaddr_storage *result4,
        struct sockaddr_storage *result6, char *ifname4, char *ifname6);

#endif /* __DPVS_COMMON_H__ */
