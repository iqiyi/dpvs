#ifndef __DPVS_SEND_MSG__
#define __DPVS_SEND_MSG__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "common.h"
#include "dpdk.h"

#define RTE_LOGTYPE_MCAST   RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_UNICAST RTE_LOGTYPE_USER1

int create_mcast_receive_sock(void);
int create_mcast_send_sock(void);
int add_mcast_group(int sockfd);
int drop_mcast_group(int sockfd);
int send_mcast_msg(int sockfd, char *buffer, int len);
int receive_mcast_msg(int sockfd, char *buffer, const size_t buflen,
                                struct sockaddr_in* remote_addr);

int create_receive_unicast_sock(void);

int create_send_unicast_sock(void);

int send_unicast_msg(int sockfd, char *buffer, int len,
                                        struct sockaddr_in* remote_addr);

int receive_unicast_msg(int sockfd, char *buffer, const size_t buflen,
                                struct sockaddr_in* remote_addr);
int get_sock_mtu(void);
void install_session_sync_sock_keywords(void);

#endif /* __DPVS_SEND_MSG__ */
