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
 * UDP client for performance (high concurrency) test.
 *
 * raychen@qiyi.com, Mar 2018, initial.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>
#include <signal.h>
#include <sched.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define SA                  struct sockaddr

#define DEF_SERV_PORT       6000
#define DEF_MAX_CONN        2000    /* per worker */
#define DEF_DURATION        10      /* seconds */
#define DEF_PKT_SIZE        1000    /* bytes */
#define DEF_DUMP_INTV       1       /* seconds */

struct config {
    int             max_conn;    /* max conn per worker */
    int             duration;    /* test duration in seconds */
    int             pkt_size;    /* packet size in bytes */
    int             interval;    /* dump interval seconds */
    int             af;
    struct sockaddr_storage servaddr;    /* server address */
};

struct stats {
    uint64_t        tot_conns;
    uint64_t        conns;
    uint64_t        pkts_sent;
    uint64_t        pkts_recv;
    uint64_t        bytes_sent;
    uint64_t        bytes_recv;
    uint64_t        errors;
};

struct worker {
    int             cpu;
    pid_t           pid;
    struct config   conf;
    struct stats    stats;
    char            *sndbuf;
    char            *rcvbuf;
};

static cpu_set_t        cpuset;             /* cpu for workers */
static sig_atomic_t     quit_test = 0;      /* for master */
static sig_atomic_t     quit_client = 0;    /* for worker */

static struct worker    workers[CPU_SETSIZE] = {};

static void usage(const char *prog)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [OPTIONS] host[:port]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    -c CPUMASK    workers' CPU mask in hex format.\n");
    fprintf(stderr, "    -m MAXCONN    connection per worker (CPU).\n");
    fprintf(stderr, "    -t DRUATION   test duration in second.\n");
    fprintf(stderr, "    -s SIZE       packet size (payload) in byte.\n");
    fprintf(stderr, "    -i INTERVAL   print interval in second.\n");
    fprintf(stderr, "    -h            show this help info.\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "    %s 127.0.0.1\n", prog);
    fprintf(stderr, "    %s [2001::1]\n", prog);
    fprintf(stderr, "    %s -c 1f 1.1.1.1:1234\n", prog);
    fprintf(stderr, "    %s -c 3 [2002::12:1]:5320\n", prog);
    fprintf(stderr, "    %s -c f -m 1000 -t 10 -s 10 2.2.2.2:5000\n", prog);
}

static void sig_quit(int signo)
{
    quit_test = 1;
}

static void sig_quit_client(int signo)
{
    quit_client = 1;
}

static int hexstr_to_cpuset(const char *hex, cpu_set_t *set)
{
    const char *c;
    unsigned long long mask;
    int cpu;

    if (!hex || !set)
        return -1;

    for (c = hex; *c != '\0'; c++) {
        if (!isxdigit(*c))
            return -1;
    }

    CPU_ZERO(set);
    mask = strtoull(hex, NULL, 16);

    for (cpu = 0; cpu < sizeof(mask) * 8; cpu++) {
        if (mask & (0x1LL<<cpu))
            CPU_SET(cpu, set);
    }

    return 0;
}

static void timespec_sub(const struct timespec *a, const struct timespec *b,
             struct timespec *res)
{
    /* we do not need nano-second precision,
     * so use timeval API for make it easier. */
    struct timeval tv1, tv2, tv_diff;

    TIMESPEC_TO_TIMEVAL(&tv1, a);
    TIMESPEC_TO_TIMEVAL(&tv2, b);

    timersub(&tv1, &tv2, &tv_diff);

    TIMEVAL_TO_TIMESPEC(&tv_diff, res);
}

static int parse_args(int argc, char *argv[], struct config *conf)
{
    int opt;
    char *prog, *host, *port;
    struct option opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"cpu", required_argument, NULL, 'c'},
        {"max-conn", required_argument, NULL, 'm'},
        {"time", required_argument, NULL, 't'},
        {"size", required_argument, NULL, 's'},
        {"interval", required_argument, NULL, 'i'},
        {NULL, 0, NULL, 0},
    };
    struct sockaddr_in *sin = (struct sockaddr_in *)&conf->servaddr;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&conf->servaddr;

    prog = strrchr(argv[0], '/');
    if (prog)
        *prog++ = '\0';
    else
        prog = argv[0];

    CPU_ZERO(&cpuset);
    memset(conf, 0, sizeof(*conf));
    conf->max_conn = DEF_MAX_CONN;
    conf->duration = DEF_DURATION;
    conf->pkt_size = DEF_PKT_SIZE;
    conf->interval = DEF_DUMP_INTV;

    if (argc <= 1) {
        usage(prog);
        exit(0);
    }

    while ((opt = getopt_long(argc, argv, "hc:m:t:s:i:",
                  opts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(prog);
            exit(0);
        case 'c':
            if (hexstr_to_cpuset(optarg, &cpuset) != 0) {
                fprintf(stderr, "Bad CPU mask: %s\n", optarg);
                exit(1);
            }
            break;
        case 'm':
            conf->max_conn = atoi(optarg);
            break;
        case 't':
            conf->duration = atoi(optarg);
            if (conf->duration <= 0) {
                fprintf(stderr, "Invalid duration.\n");
                exit(1);
            }
            break;
        case 's':
            conf->pkt_size = atoi(optarg);
            break;
        case 'i':
            conf->interval = atoi(optarg);
            if (conf->interval <= 0) {
                fprintf(stderr, "Invalid interval.\n");
                exit(1);
            }
            break;
        case '?':
        default:
            fprintf(stderr, "Invalid option: %s\n", argv[optind]);
            return -1;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        fprintf(stderr, "Missing server IP address.\n");
        exit(1);
    }

    host = argv[0];
    port = argv[0];

    if (index(host, '[') && index(host, ']')) {
        host = strchr(host, '[');
        port = strchr(host, ']');
        host++;
        *port++ = '\0';
    }

    port = strrchr(port, ':');
    if (port)
        *port++ = '\0';

    if (port) {
        if (atoi(port) <= 0 || atoi(port) >= 65535) {
            fprintf(stderr, "Invalid port: %s\n", port);
            exit(1);
        }
    }

    if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = conf->af = AF_INET6;
        if (port)
            sin6->sin6_port = htons(atoi(port));
        else
            sin6->sin6_port = htons(DEF_SERV_PORT);
    } else if (inet_pton(AF_INET, host, &sin->sin_addr.s_addr) == 1) {
        sin->sin_family = conf->af = AF_INET;
        if (port)
            sin->sin_port = htons(atoi(port));
        else
            sin->sin_port = htons(DEF_SERV_PORT);
    } else {
        fprintf(stderr, "Invalid host IP: %s\n", host);
        exit(1);
    }

    return 0;
}

static inline void dump_stats(int cpu, const struct stats *st)
{
    printf("[% 2d] %5"PRIu64" %8"PRIu64" %8"PRIu64" %12"PRIu64" %12"PRIu64" %8"PRIu64" %8"PRIu64"\n",
        cpu, st->conns, st->pkts_recv, st->pkts_sent,
        st->bytes_recv, st->bytes_sent, st->errors, st->tot_conns);
}

static int udp_new_conn(int epfd, struct worker *wk)
{
    int sockfd;
    struct epoll_event ev;
    socklen_t salen;

    if (wk->conf.af == AF_INET6)
        salen = sizeof(struct sockaddr_in6);
    else
        salen = sizeof(struct sockaddr_in);

    sockfd = socket(wk->conf.af, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    /* use connect to receive ICMP port unreachable. */
    if (connect(sockfd, (SA *)&wk->conf.servaddr, salen) != 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    if (send(sockfd, wk->sndbuf, wk->conf.pkt_size, 0) != wk->conf.pkt_size) {
        perror("send");
        close(sockfd);
        return -1;
    }

    wk->stats.pkts_sent++;
    wk->stats.bytes_sent += wk->conf.pkt_size;

    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = sockfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) != 0) {
        perror("epoll_ctl");
        close(sockfd);
        return -1;
    }

    wk->stats.conns++;
    wk->stats.tot_conns++;

    return 0;
}

static void udp_handle_reply(int epfd, int fd, struct worker *wk)
{
    int n;

    n = recv(fd, wk->rcvbuf, wk->conf.pkt_size, 0);

    if (n < 0) {
        /* we're nonblock recv */
        if (errno == EINTR && errno == EAGAIN)
            return;

        wk->stats.errors++;
    }

    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);

    wk->stats.conns--;
    if (n >= 0) {
        wk->stats.pkts_recv++;
        wk->stats.bytes_recv += n;
    }
}

static void udp_client(struct worker *wk)
{
    int epfd, nfds, timeo, i;
    struct epoll_event *events;
    struct config *conf = &wk->conf;
    struct stats *stats = &wk->stats;
    struct timespec ts_start, ts_now, ts_elapse, ts_dump;

    events = malloc(conf->max_conn * sizeof(struct epoll_event));
    if (!events) {
        fprintf(stderr, "%s: no memory\n", __func__);
        exit(1);
    }

    wk->sndbuf = malloc(conf->pkt_size);
    wk->rcvbuf = malloc(conf->pkt_size);
    if (!wk->sndbuf || !wk->rcvbuf) {
        fprintf(stderr, "%s: no memory\n", __func__);
        exit(1);
    }

    /* generate random alpha string for UDP payload. */
    for (i = 0; i < conf->pkt_size; i++)
        wk->sndbuf[i] = 'A' + (random() % 26);

    /*
     * each socket send one packet and receive a reply,
     * try to create "connections" until max_conn reached.
     *
     * use epoll to avoid block on recv reply.
     */
    epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        exit(1);
    }

    signal(SIGQUIT, sig_quit_client);

    memset(stats, 0, sizeof(*stats));
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts_start);
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts_dump);

    /*      0123 01234 01234567 01234567 012345678901 012345678901 01234567 01234567 */
    printf("CPU%d conns ipackets opackets       ibytes       obytes   errors tot-conn\n", wk->cpu);

    /* main loop */
    while (1) {
        if (quit_test || quit_client)
            break;

        /* try create conn as much as possible */
        while (stats->conns < conf->max_conn)
            udp_new_conn(epfd, wk);

        clock_gettime(CLOCK_MONOTONIC_COARSE, &ts_now);
        timespec_sub(&ts_now, &ts_start, &ts_elapse);

        /* stop test if duration reached. */
        if (ts_elapse.tv_sec >= conf->duration)
            break;

        /* decide wait timeout for MIN(interval, duration_remain).
         * calculate in ms */
        timeo = (conf->duration - ts_elapse.tv_sec) * 1000 \
            - ts_elapse.tv_nsec / 1000000;
        timeo = (timeo <= conf->interval * 1000) ? timeo :
            conf->interval * 1000;

        /* dump stats with interval */
        timespec_sub(&ts_now, &ts_dump, &ts_elapse);
        if (ts_elapse.tv_sec >= conf->interval) {
            dump_stats(wk->cpu, stats);
            ts_dump = ts_now;
        }

        nfds = epoll_wait(epfd, events, conf->max_conn, timeo);
        if (nfds == -1) {
            perror("epoll_wait");
            exit(1);
        }

        for (i = 0; i < nfds; i++) {
            udp_handle_reply(epfd, events[i].data.fd, wk);
        }
    }

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts_now);
    timespec_sub(&ts_now, &ts_start, &ts_elapse);

    dump_stats(wk->cpu, stats);

    printf("[%2d] --------\n", wk->cpu);
    printf("[%2d] Summary: total connection %"PRIu64", errors %"PRIu64" duration %lu.%03lu\n",
           wk->cpu, stats->tot_conns, stats->errors, ts_elapse.tv_sec, ts_elapse.tv_nsec / 1000000);
    printf("[%2d] RX %lu pps %lu B/s, TX %lu pps %lu B/s\n", wk->cpu,
           stats->pkts_recv * 1000 / (ts_elapse.tv_sec * 1000 + ts_elapse.tv_nsec / 1000000),
           stats->bytes_recv * 1000 / (ts_elapse.tv_sec * 1000 + ts_elapse.tv_nsec / 1000000),
           stats->pkts_sent * 1000 / (ts_elapse.tv_sec * 1000 + ts_elapse.tv_nsec / 1000000),
           stats->bytes_sent * 1000 / (ts_elapse.tv_sec * 1000 + ts_elapse.tv_nsec / 1000000));

    /* exiting, nothing need to release. */
    return;
}

static int new_worker(const int cpu, const struct config *conf)
{
    pid_t pid;

    workers[cpu].cpu = cpu;
    workers[cpu].conf = *conf;

    pid = fork();

    if (pid > 0) { /* master */
        workers[cpu].pid = pid;
    } else if (pid == 0) { /* worker */
        cpu_set_t set;

        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(getpid(), CPU_SETSIZE, &set) != 0)
            perror("sched_setaffinity");

        udp_client(&workers[cpu]);

        exit(1); /* never return */
    } else {
        fprintf(stderr, "%s: fail to fork worker\n", __func__);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int cpu;
    int num_workers = 0;
    struct config conf;
    struct rlimit limit;

    if (parse_args(argc, argv, &conf) != 0)
        exit(1);

    /* example only, pls use sigaction */
    signal(SIGINT, sig_quit);

    /* extend open-file limit as needed. */
    if (getrlimit(RLIMIT_OFILE, &limit) == 0) {
        limit.rlim_cur = limit.rlim_max;
        if (setrlimit(RLIMIT_OFILE, &limit) != 0)
            perror("setrlimit(OFILE)");
    }

    /* standalone mode ? */
    if (CPU_COUNT(&cpuset) == 0) {
        struct worker *wk = &workers[0];

        /* master itself is worker (client) */
        memset(wk, 0, sizeof(*wk));
        wk->cpu = 0;
        wk->pid = getpid();
        wk->conf = conf;

        udp_client(wk);
        exit(0);
    }

    /*
     * master/worker mode.
     * let worker to performe test.
     */
    for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &cpuset))
            continue;

        if (new_worker(cpu, &conf) == 0)
            num_workers++;
    }

    /* abort test if no worker created ! */
    if (!num_workers)
        exit(1);

    /* wait all workers exit or user stop the test */
    while (num_workers) {
        while (waitpid(-1, NULL, WNOHANG) > 0)
            num_workers--;

        /* kill all workers if user stop test */
        if (quit_test) {
            for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
                if (workers[cpu].pid == 0)
                    continue;

                kill(workers[cpu].pid, SIGQUIT);
            }

            quit_test = 0;
        }

        sleep(1);
    }

    printf("Test stopped!\n");
    exit(0);
}
