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
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "common.h"

/* for union inet_addr only */
#include "uoa_extra.h"
#include "uoa.h"

/**
 * checksum codes from Linux Kernel.
 */
static inline __u16 csum_fold(__u32 csum)
{
    __u32 sum = (__u32)csum;
    sum += (sum >> 16) | (sum << 16);
    return ~(__u16)(sum >> 16);
}

static inline __u16 ip_fast_csum(const void *iph, unsigned int ihl)
{
    __uint128_t tmp;
    uint64_t sum;

    tmp = *(const __uint128_t *)iph;
    iph += 16;
    ihl -= 4;
    tmp += ((tmp >> 64) | (tmp << 64));
    sum = tmp >> 64;
    do {
        sum += *(const __u32 *)iph;
        iph += 4;
    } while (--ihl);

    sum += ((sum >> 32) | (sum << 32));
    return csum_fold((__u32)(sum >> 32));
}

/* Generate a checksum for an outgoing IP datagram. */
static void ip_send_check(struct iphdr *iph)
{
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct iphdr *iph;
    struct opphdr *opph;
    struct ipopt_uoa *uoa;
    struct udphdr *uh;
    __u8 pkt[4096] = {0};
    __u8 payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    int v = 1;
    struct sockaddr_in sin;

    if (argc != 5) {
        fprintf(stderr, "usage: a.out SRC-IP DST-IP CLI-IP CLI-PORT\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &v, sizeof(v)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    /* build IP header */
    iph = (void *)pkt;
    iph->version    = 0x4;
    iph->ihl    = sizeof(struct iphdr) / 4;
    iph->tos    = 0x0;
    iph->tot_len    = htons(sizeof(*iph) + sizeof(*opph) + \
                sizeof(*uoa) + sizeof(*uh) + sizeof(payload));
    iph->id        = htons(1234); // just for test.
    iph->frag_off    = 0x0;
    iph->ttl    = 64;
    iph->protocol    = IPPROTO_OPT;

    if (inet_pton(AF_INET, argv[1], &iph->saddr) <= 0) {
        fprintf(stderr, "bad src-ip\n");
        exit(1);
    }

    if (inet_pton(AF_INET, argv[2], &iph->daddr) <= 0) {
        fprintf(stderr, "bad dst-ip\n");
        exit(1);
    }

    /* build Option Protocol fixed header */
    opph = (void *)iph + (iph->ihl << 2);
    opph->version    = 0x1;
    opph->protocol    = IPPROTO_UDP;
    opph->length    = htons(sizeof(*opph) + sizeof(*uoa));

    /* uoa option */
    uoa = (void *)opph->options;
    uoa->op_code    = IPOPT_UOA;
    uoa->op_len    = IPOLEN_UOA_IPV4;
    uoa->op_port    = htons(atoi(argv[4]));

    if (inet_pton(AF_INET, argv[3], &uoa->op_addr) <= 0) {
        fprintf(stderr, "bad cli-ip\n");
        exit(1);
    }

    ip_send_check(iph);

    /* udp header */
    uh = (void *)opph + ntohs(opph->length);
    uh->source    = htons(1122);
    uh->dest    = htons(3344);
    uh->len        = htons(sizeof(*uh) + sizeof(payload));
    uh->check    = 0; /* ok for UDP */

    /* payload */
    memcpy(uh + 1, payload, sizeof(payload));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family    = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;

    if (sendto(sockfd, pkt, ntohs(iph->tot_len), 0,
           (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        exit(1);
    }

    close(sockfd);
    exit(0);
}
