// 
// This is a simple TCP echo server supports Proxy Protocol.
// Client address encoded in Proxy Protocol is parsed and output to stdout.
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
#define LISTEN_BACKLOG      16
#define EPOLL_EVENTS        32

static int listen_fds[AFS] = { 0 };

struct evdata {
    int fd;
    int af;
    uint16_t firstseg;
    uint16_t port;
    union {
        struct in_addr in;
        struct in6_addr in6;
    } addr;
};

static int handle_accept(int af, int epfd, int listen_fd) {
    int fd;
    socklen_t caddrlen;
    struct sockaddr_storage caddr;
    char addrbuf[64] = { 0 };
    struct sockaddr_in *caddr4;
#ifdef WITH_IPV6_ENABLE
    struct sockaddr_in6 *caddr6;
#endif
    struct epoll_event ev;
    struct evdata *pdata;

    caddrlen = sizeof(caddr);
    fd = accept(listen_fd, (struct sockaddr *)&caddr, &caddrlen);
    if (fd == -1) {
        fprintf(stderr, "accept connection failed: %d, %s\n", af, strerror(errno));
        return -1;
    }

    pdata = calloc(1, sizeof(struct evdata));
    if (!pdata)
        return -1;
    pdata->af = af;
    pdata->fd = fd;
    pdata->firstseg = 1;

    if (af == AF_INET) {
        caddr4 = (struct sockaddr_in *)&caddr;
        pdata->addr.in.s_addr = caddr4->sin_addr.s_addr;
        pdata->port = htons(caddr4->sin_port);
        inet_ntop(AF_INET, &caddr4->sin_addr, addrbuf, sizeof(addrbuf));
        printf("accept connection %d from %s:%d\n", fd, addrbuf, htons(caddr4->sin_port));
    }
#ifdef WITH_IPV6_ENABLE
    else {
        caddr6 = (struct sockaddr_in6 *)&caddr;
        memcpy(&pdata->addr.in6, &caddr6->sin6_addr, sizeof(struct in6_addr));
        pdata->port = htons(caddr6->sin6_port);
        inet_ntop(AF_INET6, &caddr6->sin6_addr, addrbuf, sizeof(addrbuf));
        printf("accept connection %d from [%s]:%d\n", fd, addrbuf, htons(caddr6->sin6_port));
    }
#endif

    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = pdata;
    ev.events = EPOLLIN | EPOLLERR;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        fprintf(stderr, "add accepted connection to epoll failed");
        free(pdata);
        return -1;
    }

    return 0;
}

static int handle_reply(int epfd, struct evdata *pdata) {
    char *buf, addrbuf[64];
    int len;

    buf = (char *)calloc(1, 2048);
    if (!buf)
        return -1;
    len = read(pdata->fd, buf, 2047);
    if (len == 0) { // received EOF
        inet_ntop(pdata->af, &pdata->addr, addrbuf, sizeof(addrbuf));
        printf("close connection %s:%d\n", addrbuf, pdata->port);
        epoll_ctl(epfd, EPOLL_CTL_DEL, pdata->fd, NULL);
        close(pdata->fd);
        free(pdata);
        return 0;
    }
    buf[len] = '\0';

#ifdef LOG_VERBOSE
    printf("%d bytes received: %s\n", len, buf);
#endif

    if (pdata->firstseg) {
        len = parse_proxy_protocol(buf, len);
        if (len > 0)
            write(pdata->fd, buf, len);
        pdata->firstseg = 0;
        buf[len] = '\0';
    }
#ifdef LOG_VERBOSE
    printf("%d bytes written back: %s\n", len, buf);
#endif

    free(buf);
    return 0;
}

int main(int argc, char *argv[]) {
    int epfd;
    int i, nfds;
    int enable = 1;
    int serv_port;
    struct evdata *pdata, evdata[2] = { 0 };
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

    if ((listen_fds[0] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Fail to create INET socket!\n");
        exit(1);
    }
    setsockopt(listen_fds[0], SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(listen_fds[0], SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(serv_port);
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listen_fds[0], (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        perror("Fail to bind INET socket!\n");
        exit(1);
    }

    if (listen(listen_fds[0], LISTEN_BACKLOG) < 0) {
        perror("Fail to listen INET socket!\n");
        exit(1);
    }

    evdata[0].af = AF_INET;
    evdata[0].fd = listen_fds[0];
    evdata[0].port = serv_port;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.ptr = &evdata[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fds[0], &ev) != 0) {
        perror("EPOLL_CTL_ADD failed for INET fd!\n");
        exit(1);
    }

#ifdef WITH_IPV6_ENABLE
    if ((listen_fds[1] = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        perror("Fail to create INET6 socket!\n");
        exit(1);
    }
    setsockopt(listen_fds[1], SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(listen_fds[1], SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));

    memset(&serv_addr6, 0, sizeof(serv_addr6));
    serv_addr6.sin6_family = AF_INET6;
    serv_addr6.sin6_port = htons(serv_port);
    serv_addr6.sin6_addr = in6addr_any;
    if (bind(listen_fds[1], (struct sockaddr *)&serv_addr6, sizeof(serv_addr6)) != 0) {
        perror("Fail to bind INET6 socket!\n");
        exit(1);
    }

    if (listen(listen_fds[1], LISTEN_BACKLOG) < 0) {
        perror("Fail to listen INET6 socket!\n");
        exit(1);
    }

    evdata[1].af = AF_INET6;
    evdata[1].fd = listen_fds[1];
    evdata[1].port = serv_port;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.ptr = &evdata[1];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fds[1], &ev) != 0) {
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
            pdata = (struct evdata *)events[i].data.ptr;
            if (pdata->fd == listen_fds[0]) {
                handle_accept(AF_INET, epfd, pdata->fd);
            }
#ifdef WITH_IPV6_ENABLE
            else if (((struct evdata *)events[i].data.ptr)->fd == listen_fds[1]) {
                handle_accept(AF_INET6, epfd, pdata->fd);
            }
#endif
            else {
                if (events[i].events & EPOLLERR) {
                    inet_ntop(pdata->af, &pdata->addr, addrbuf, sizeof(addrbuf));
                    fprintf(stderr, "error occurred, close connection %s:%d\n", addrbuf, pdata->port);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, pdata->fd, NULL);
                    close(pdata->fd);
                    free(pdata);
                    continue;
                }
                handle_reply(epfd, pdata);
            }
        }
    }

    return 0;
}
