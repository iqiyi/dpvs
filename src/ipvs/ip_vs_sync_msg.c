#include "ipvs/sync_msg.h"
#include "parser/parser.h"

#define DEFAULT_MCAST_ADDR "224.0.1.100"
#define DEFAULT_MCAST_PORT 8088
#define DEFAULT_MCAST_TTL 20
#define DEFAULT_SOCK_MTU 1500

static uint32_t sock_mtu = DEFAULT_SOCK_MTU;
static uint32_t mcast_ttl = DEFAULT_MCAST_TTL;
static uint16_t mcast_port = DEFAULT_MCAST_PORT;
char mcast_addr_str[16];
static struct sockaddr_in mcast_addr;

#define DEFAULT_UNICAST_PORT 8089
static uint16_t unicast_port = DEFAULT_UNICAST_PORT;

/* Set up sending multicast socket over UDP */
int create_mcast_send_sock(void)
{
    /* Create a socket */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        RTE_LOG(ERR, MCAST, "%s: failed to create socket.\n", __func__);
        return fd;
    }
    /* Add mcast info */
    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_addr.s_addr = inet_addr(mcast_addr_str);
    mcast_addr.sin_port = htons(mcast_port);

    /* Set multicast ttl */
    u_char ttl = mcast_ttl;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&ttl, sizeof(ttl));

    return fd;
}

int create_mcast_receive_sock(void)
{
    struct sockaddr_in local_addr;

    /* Create a socket */
    int yes = 1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        RTE_LOG(ERR, MCAST, "%s: failed to create socket.\n", __func__);
        return fd;
    }

    /* Set reused*/
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        RTE_LOG(ERR, MCAST, "%s: failed to set SO_REUSEADDR.\n", __func__);
        goto error;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(DEFAULT_MCAST_PORT);

    /* Set loop */
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &yes, sizeof(yes)) < 0) {
        RTE_LOG(ERR, MCAST, "%s: failed to set IP_MULTICAST_LOOP.\n", __func__);
        goto error;
    }

    /* Bind local addr */
    if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        RTE_LOG(ERR, MCAST, "%s: failed to bind local_addr.\n", __func__);
        goto error;
    }

    return fd;

error:
    close(fd);
    return -1;
}

static void fill_in_mreq(struct ip_mreq *mreq)
{
    //memset(mreq, 0, sizeof(struct ip_mreq));
    mreq->imr_multiaddr.s_addr = inet_addr(mcast_addr_str);
    mreq->imr_interface.s_addr = htonl(INADDR_ANY);
}

int add_mcast_group(int sockfd)
{
    struct ip_mreq mreq;
    int err;
    fill_in_mreq(&mreq);
    err = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (err < 0) {
        RTE_LOG(ERR, MCAST, "%s: failed to add multicast group.\n", __func__);
        close(sockfd);
    }
    return err;
}

int drop_mcast_group(int sockfd)
{
    struct ip_mreq mreq;
    int err;
    fill_in_mreq(&mreq);
    err = setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    if (err < 0) {
        RTE_LOG(ERR, MCAST, "%s: failed to drop mcast group.\n", __func__);
    }
    close(sockfd);
    return err;
}

int send_mcast_msg(int sockfd, char *buffer, int len)
{
    int res = sendto(sockfd, buffer, len, 0,
                (struct sockaddr*)&mcast_addr,
                sizeof(mcast_addr));
    if (res < 0 )
        RTE_LOG(ERR, MCAST, "%s: mcast send to %s failed.\n",
                __func__, inet_ntoa(mcast_addr.sin_addr));
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
    else
        RTE_LOG(DEBUG, MCAST, "%s: send %d bytes msg to %s success.\n",
                __func__, res, inet_ntoa(mcast_addr.sin_addr));
#endif
    return res;
}

int receive_mcast_msg(int sockfd, char *buffer, const size_t buflen,
                                struct sockaddr_in* remote_addr)
{
    /* receive a multicast packet */
    struct sockaddr_in addr;
    socklen_t l = sizeof(addr);
    int len = recvfrom(sockfd, buffer, buflen, 0, (struct sockaddr *)&addr, &l);
    if (len == -1) {
        RTE_LOG(ERR, MCAST, "%s: failed to recv msg.\n", __func__);
    } else {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
        RTE_LOG(DEBUG, MCAST, "%s: recv %d msg from %s .\n", __func__,
                len, inet_ntoa(addr.sin_addr));
#endif
        if (remote_addr != NULL)
            memcpy(remote_addr, &addr, l);
    }
    return len;
}

static void mcast_addr_str_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    assert(str);

    rte_memcpy(mcast_addr_str, str, strlen(str));
    RTE_LOG(INFO, MCAST, "%s: mcast_addr = %s\n", __func__,
            mcast_addr_str);

    FREE_PTR(str);
}

static void mcast_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint16_t port;

    assert(str);
    port = atoi(str);

    if (port > 65535 || port < 1024) {
        RTE_LOG(WARNING, MCAST, "invalid mcast_port %s, using default %d\n",
                str, DEFAULT_MCAST_PORT);
    } else {
        RTE_LOG(INFO, MCAST, "%s: mcast_port = %d\n", __func__, port);
        mcast_port = port;
    }

    FREE_PTR(str);
}

static void mcast_ttl_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t ttl;

    assert(str);
    ttl = atoi(str);

    if (ttl > 255 || ttl < 0) {
        RTE_LOG(WARNING, MCAST, "invalid mcast_ttl %s, using default %d\n",
                str, DEFAULT_MCAST_TTL);
        mcast_ttl = DEFAULT_MCAST_TTL;
    } else {
        RTE_LOG(INFO, MCAST, "%s: mcast_ttl = %d\n", __func__, ttl);
        mcast_ttl = ttl;
    }

    FREE_PTR(str);
}

static void install_session_sync_mcast_keywords(void)
{
    install_keyword("mcast_addr", mcast_addr_str_handler, KW_TYPE_NORMAL);
    install_keyword("mcast_port", mcast_port_handler, KW_TYPE_NORMAL);
    install_keyword("mcast_ttl", mcast_ttl_handler, KW_TYPE_NORMAL);
    //install_keyword("mcast_mtu", mcast_mtu_handler, KW_TYPE_NORMAL);
}

int create_receive_unicast_sock(void)
{
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(unicast_port);
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
        goto eexit;
    return fd;

eexit:
    close(fd);
    return -1;
}

int create_send_unicast_sock(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        return -1;
    }

    return fd;
}

int send_unicast_msg(int sockfd, char *buffer, int len,
                                        struct sockaddr_in* remote_addr)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(unicast_port);
    memcpy(&addr.sin_addr, &remote_addr->sin_addr, sizeof(addr.sin_addr));
    
    int res = sendto(sockfd, buffer, len, 0,
                (struct sockaddr*)&addr,
                sizeof(addr));
    if (res < 0 )
        RTE_LOG(ERR, UNICAST, "%s: unicast send to %s failed.\n",
                __func__, inet_ntoa(remote_addr->sin_addr));
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
    else
        RTE_LOG(DEBUG, UNICAST, "%s: unicast send %d bytes msg to %s success.\n", 
                __func__, res, inet_ntoa(remote_addr->sin_addr));
#endif
    return res;
}

int receive_unicast_msg(int sockfd, char *buffer, const size_t buflen,
                                struct sockaddr_in* remote_addr)
{
    struct sockaddr_in addr;
    socklen_t l = sizeof(addr);
    int len = recvfrom(sockfd, buffer, buflen, 0, (struct sockaddr *)&addr, &l);
    if (len == -1) {
        RTE_LOG(ERR, UNICAST, "%s: unicast failed to recv msg.\n", __func__);
    } else {
#ifdef CONFIG_DPVS_CONN_SYNC_DEBUG
	    RTE_LOG(INFO, UNICAST, "%s: unicast recv %d msg from %s .\n", __func__,
                len, inet_ntoa(addr.sin_addr));
#endif
        if (remote_addr != NULL)
            memcpy(remote_addr, &addr, l);
    }
    return len;
}

static void unicast_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint16_t port;

    assert(str);
    port = atoi(str);

    if (port > 65535 || port < 1024) {
        RTE_LOG(WARNING, UNICAST, "invalid mcast_port %s, using default %d\n",
                str, DEFAULT_UNICAST_PORT);
    } else {
        RTE_LOG(INFO, UNICAST, "%s: mcast_port = %d\n", __func__, port);
        unicast_port = port;
    }

    FREE_PTR(str);
}

static void install_session_sync_unicast_keywords(void)
{
    install_keyword("unicast_port", unicast_port_handler, KW_TYPE_NORMAL);
}

int get_sock_mtu(void)
{
    return sock_mtu;
}

static void sock_mtu_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t mtu;

    assert(str);
    mtu = atoi(str);

    if (mtu > 0 && mtu < 65536) {
        RTE_LOG(INFO, MCAST, "sock_mtu = %d\n", mtu);
        sock_mtu = mtu;
    } else {
        RTE_LOG(WARNING, MCAST, "invalid sock_mtu %s, using default %d\n",
                str, DEFAULT_SOCK_MTU);
        sock_mtu = DEFAULT_SOCK_MTU;
    }
    
    FREE_PTR(str);
}

void install_session_sync_sock_keywords(void)
{
    install_keyword("mtu", sock_mtu_handler, KW_TYPE_NORMAL);
    install_session_sync_mcast_keywords();
    install_session_sync_unicast_keywords();
}
