// 
// This is a simple UDP echo server supports Proxy Protocol.
// Client address encoded in Proxy Protocol is parsed and output to stdout.
// Note that only proxy protocol v2 supports UDP.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include "proxy_protocol.h"
#include <errno.h>

#define DEFAULT_SERV_PORT   8082
#define AFS                 2
#define EPOLL_EVENTS        2

static int sockfd[AFS] = { 0 };

static int handle_reply(int epfd, int fd) {
    struct sockaddr_storage peer;
    char *buf, addrbuf[64];
    int len, addrlen;
    uint16_t port;

    buf = (char *)calloc(1, 2048);
    if (!buf)
        return -1;

    while (1) {
        addrlen = sizeof(peer);
        len = recvfrom(fd, buf, 2047, 0, (struct sockaddr *)&peer, &addrlen);
        if (len < 0) {
            if (EAGAIN == errno || EWOULDBLOCK == errno)
                break;
            perror("recvfrom failed\n");
            exit(1);
        }
        if (0 == len)
            break;
        buf[len] = '\0';

        if (AF_INET == peer.ss_family) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, addrbuf, sizeof(addrbuf));
            port = ntohs(((struct sockaddr_in *)&peer)->sin_port);
        } else {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, addrbuf, sizeof(addrbuf));
            port = ntohs(((struct sockaddr_in6 *)&peer)->sin6_port);
        }
#ifdef LOG_VERBOSE
        printf("%d bytes received from %s:%d\n", len, addrbuf, port);
#endif
        len = parse_proxy_protocol(buf, len);
        if (len > 0 && sendto(fd, buf, len, 0,
                    (const struct sockaddr*)&peer, addrlen) < 0) {
            perror("sendto failed\n");
            exit(1);
        }
#ifdef LOG_VERBOSE
        printf("%d bytes written back to %s:%d: %s\n", len, addrbuf, port, buf);
#endif
    }

    free(buf);
    return 0;
}

int main(int argc, char *argv[]) {
    int epfd;
    int i, nfds;
    int enable = 1;
    int serv_port;
    struct epoll_event ev;
    struct epoll_event events[EPOLL_EVENTS];
    struct sockaddr_in serv_addr;
#ifdef WITH_IPV6_ENABLE
    struct sockaddr_in6 serv_addr6;
#endif
    char addrbuf[64];

    if (argc > 1)
        serv_port = atoi(argv[1]);
    if (serv_port <= 0 || serv_port > 65535)
        serv_port = DEFAULT_SERV_PORT;

    if ((epfd = epoll_create1(0)) < 0) {
        perror("Fail to create epoll fd!\n");
        exit(1);
    }

    if ((sockfd[0] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) < 0) {
        perror("Fail to create INET socket!\n");
        exit(1);
    }
    setsockopt(sockfd[0], SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(sockfd[0], SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(serv_port);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd[0], (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        perror("Fail to bind INET socket!\n");
        exit(1);
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = sockfd[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd[0], &ev) != 0) {
        perror("EPOLL_CTL_ADD failed for INET fd!\n");
        exit(1);
    }

#ifdef WITH_IPV6_ENABLE
    if ((sockfd[1] = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0)) < 0) {
        perror("Fail to create INET6 socket!\n");
        exit(1);
    }
    setsockopt(sockfd[1], SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(sockfd[1], SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));

    memset(&serv_addr6, 0, sizeof(serv_addr6));
    serv_addr6.sin6_family = AF_INET6;
    serv_addr6.sin6_port = htons(serv_port);
    serv_addr6.sin6_addr = in6addr_any;
    if (bind(sockfd[1], (struct sockaddr *)&serv_addr6, sizeof(serv_addr6)) != 0) {
        perror("Fail to bind INET6 socket!\n");
        exit(1);
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = sockfd[1];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd[1], &ev) != 0) {
        perror("EPOLL_CTL_ADD failed for INET6 fd!\n");
        exit(1);
    }
#endif

    while (1) {
        nfds = epoll_wait(epfd, events, EPOLL_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait failed!\n");
            exit(1);
        }

        for (i = 0; i < nfds; i++) {
            handle_reply(epfd, events[i].data.fd);
        }
    }

    return 0;
}
