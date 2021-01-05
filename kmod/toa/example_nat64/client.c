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
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAXLINE 1024
#define ADDR "127.0.0.1"
#define PORT 10004
static char *sendbuf = "test";

int main(int argc,char **argv)
{
    char *servInetAddr = ADDR;//TODO
    int socketfd;
    struct sockaddr_in sockaddr;
    int n;
    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(PORT);
    inet_pton(AF_INET, servInetAddr, &sockaddr.sin_addr);
    if((connect(socketfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr))) < 0 ) {
        printf("connect error %s errno: %d\n", strerror(errno), errno);
        exit(0);
    }
    printf("send message to server\n");
    if((send(socketfd, sendbuf, strlen(sendbuf), 0)) < 0) {
        printf("send mes error: %s errno : %d", strerror(errno), errno);
        exit(0);
    }
    close(socketfd);
    printf("exit\n");
    exit(0);
}
