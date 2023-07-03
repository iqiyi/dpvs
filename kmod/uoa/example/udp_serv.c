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
 *
 * Example UDP server to get real client IP/port by UOA.
 *
 * raychen@qiyi.com, Mar 2018, initial.
 * yuwenchao@qiyi.com, Sep 2019, add ipv6 support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
/* for __u8, __be16, __be32, __u64 only */
#include "common.h"

/* for union inet_addr only */
#include "uoa_extra.h"
#include "uoa.h"

#define MAX_SUPP_AF         2
#define MAX_EPOLL_EVENTS    2
#define SA                  struct sockaddr

static __u16 SERV_PORT = 6000;

void handle_reply(int efd, int fd)
{
    struct sockaddr_storage peer;
    struct sockaddr_in *sin = NULL;
#ifdef WITH_IPV6_ENABLE
    struct sockaddr_in6 *sin6 = NULL;
#endif
    char buff[4096], from[64];
    struct uoa_param_map map;
    socklen_t len, mlen;
    int n;
    uint8_t af = AF_INET;

    len = sizeof(peer);
    n = recvfrom(fd, buff, sizeof(buff), 0, (SA *)&peer, &len);
    if (n < 0) {
        perror("recvfrom failed\n");
        exit(1);
    }
    buff[n]='\0';
    af = ((SA *)&peer)->sa_family;

    if (AF_INET == af) {
        sin = (struct sockaddr_in *)&peer;
        inet_ntop(AF_INET, &sin->sin_addr.s_addr, from, sizeof(from));
        printf("Receive %d bytes from %s:%d -- %s\n",
                n, from, ntohs(sin->sin_port), buff);
        /*
         * get real client address:
         *
         * note: src/dst is for original pkt, so peer is
         * "orginal" source, instead of local. wildcard
         * lookup for daddr (or local IP) is supported.
         * */
        memset(&map, 0, sizeof(map));
        map.af    = af;
        map.sport = sin->sin_port;
        map.dport = htons(SERV_PORT);
        memmove(&map.saddr, &sin->sin_addr.s_addr, sizeof(struct in_addr));
        mlen = sizeof(map);
        if (getsockopt(fd, IPPROTO_IP, UOA_SO_GET_LOOKUP, &map, &mlen) == 0) {
            inet_ntop(map.real_af, &map.real_saddr.in, from, sizeof(from));
            printf("  real client %s:%d\n", from, ntohs(map.real_sport));
        }

        len = sizeof(peer);
        sendto(fd, buff, n, 0, (SA *)&peer, len);
    }
#ifdef WITH_IPV6_ENABLE
    else {  /* AF_INET6 */
        sin6 = (struct sockaddr_in6 *)&peer;
        inet_ntop(AF_INET6, &sin6->sin6_addr, from, sizeof(from));
        printf("Receive %d bytes from %s:%d -- %s\n",
                n, from, ntohs(sin6->sin6_port), buff);
        /* get real client address */
        memset(&map, 0, sizeof(map));
        map.af    = af;
        map.sport = sin6->sin6_port;
        map.dport = htons(SERV_PORT);
        memmove(&map.saddr, &sin6->sin6_addr, sizeof(struct in6_addr));
        mlen = sizeof(map);

        if (getsockopt(fd, IPPROTO_IP, UOA_SO_GET_LOOKUP, &map, &mlen) == 0) {
            inet_ntop(map.real_af, &map.real_saddr.in6, from, sizeof(from));
            printf("  real client %s:%d\n", from, ntohs(map.real_sport));
        }

        len = sizeof(peer);
        sendto(fd, buff, n, 0, (SA *)&peer, len);
    }
#endif
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    int i, sockfd[MAX_SUPP_AF], nsock = 0;
    int epfd, nfds;
    int enable = 1;
    struct epoll_event events[MAX_EPOLL_EVENTS];
    struct sockaddr_in local;
#ifdef WITH_IPV6_ENABLE
    struct sockaddr_in6 local6;
#endif

    if (argc > 1)
        SERV_PORT = atoi(argv[1]);
    printf("start udp echo server on 0.0.0.0:%u\n", SERV_PORT);

    if ((sockfd[0] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Fail to create INET socket!\n");
        exit(1);
    }
    nsock++;

#ifdef WITH_IPV6_ENABLE
    if ((sockfd[1] = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        perror("Fail to create INET6 socket!");
        exit(1);
    }
    nsock++;
#endif

    if ((epfd = epoll_create1(0)) < 0) {
        perror("Fail to create epoll fd!\n");
        exit(1);
    }

    for (i = 0; i < nsock; i++) {
        setsockopt(sockfd[i], SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        setsockopt(sockfd[i], SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
    }

    memset(&local, 0, sizeof(struct sockaddr_in));
    local.sin_family = AF_INET;
    local.sin_port = htons(SERV_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd[0], (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("Fail to bind INET socket!\n");
        exit(1);
    }

#ifdef WITH_IPV6_ENABLE
    memset(&local6, 0, sizeof(struct sockaddr_in6));
    local6.sin6_family = AF_INET6;
    local6.sin6_port = htons(SERV_PORT);
    local6.sin6_addr = in6addr_any;

    if (bind(sockfd[1], (struct sockaddr *)&local6, sizeof(local6)) != 0) {
        perror("Fail to bind INET6 socket!\n");
        exit(1);
    }
#endif

    for (i = 0; i < nsock; i++) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLERR;
        ev.data.fd = sockfd[i];
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd[i], &ev) != 0) {
            fprintf(stderr, "epoll_ctl add failed for sockfd[%d]\n", i);
            exit(1);
        }
    }

    while (1) {
        nfds = epoll_wait(epfd, events, 2, -1);
        if (nfds == -1) {
            perror("epoll_wait failed\n");
            exit(1);
        }

        for (i = 0; i < nfds; i++) {
            handle_reply(epfd, events[i].data.fd);
        }
    }

    for (i = 0; i < nsock; i++)
        close(sockfd[i]);

    exit(0);
}
