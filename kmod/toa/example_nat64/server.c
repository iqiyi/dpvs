#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "toa.h"
#define MAXLINE 1024
#define PORT 10004

int main(int argc,char **argv)
{
    int listenfd,connfd;
    struct sockaddr_in sockaddr, caddr;
    char buff[MAXLINE];
    int n;
    struct toa_nat64_peer uaddr;
    int len = sizeof(struct toa_nat64_peer);
    char from[40];
    int err;

    memset(&sockaddr,0,sizeof(sockaddr));
    memset(&caddr,0,sizeof(caddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    sockaddr.sin_port = htons(PORT);
    listenfd = socket(AF_INET,SOCK_STREAM,0);
    if (err = bind(listenfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
        printf("bind error, code = %d\n", err);
        exit(0);
    }
    if (listen(listenfd,1024) != 0) {
        printf("listen error\n");
        exit(0);
    }
    printf("Please wait for the client information\n");

    for(;;) {
        socklen_t length = sizeof(caddr);
        if((connfd = accept(listenfd, (struct sockaddr*)&caddr, &length))==-1) {
            printf("accpet socket error: %s errno :%d\n", strerror(errno), errno);
            continue;
        }
        if (err = recv(connfd, buff, MAXLINE, 0) == -1) {
            printf("recv error\n");
            continue;
        }

        if (getsockopt(connfd, IPPROTO_IP, TOA_SO_GET_LOOKUP, &uaddr, &len) == 0) {
               inet_ntop(AF_INET6, &uaddr.saddr, from, sizeof(from));
            printf("  real client [%s]:%d\n", from, ntohs(uaddr.sport));
        } else {
            printf("client is %s\n", inet_ntoa(caddr.sin_addr));
        }

        close(connfd);
    }

    close(listenfd);
}
