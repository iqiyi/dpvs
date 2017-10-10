#include "sockopt.h"
#include <stdio.h>

#define SOCKOPT_MSG_BASE            23

#define SOCKOPT_MSG_SET_CMD_1       SOCKOPT_MSG_BASE + 1
#define SOCKOPT_MSG_SET_CMD_2       SOCKOPT_MSG_BASE + 2
#define SOCKOPT_MSG_SET_CMD_3       SOCKOPT_MSG_BASE + 3
#define SOCKOPT_MSG_SET_CMD_MAX     SOCKOPT_MSG_SET_CMD_3 + 1

#define SOCKOPT_MSG_GET_CMD_1       SOCKOPT_MSG_BASE + 1
#define SOCKOPT_MSG_GET_CMD_2       SOCKOPT_MSG_BASE + 2
#define SOCKOPT_MSG_GET_CMD_3       SOCKOPT_MSG_BASE + 3
#define SOCKOPT_MSG_GET_CMD_MAX     SOCKOPT_MSG_GET_CMD_3 + 1

static void send_set_msg(sockoptid_t cmd, char *in, size_t in_len)
{
    printf("[%s] send set msg #%u (len=%u): %s\n", __func__, cmd, in_len, in);
    dpvs_setsockopt(cmd, in, in_len);
}

static void send_get_msg(sockoptid_t cmd, char *in, size_t in_len)
{
    void *out;
    size_t out_len;

    printf("[%s] send get msg #%u (len=%u): %s\n", __func__, cmd, in_len, in);
    dpvs_getsockopt(cmd, in, in_len, &out, &out_len);
    if (out) {
        printf("[%s] get msg #%u reply:%s\n", __func__, cmd, (char *)out);
        dpvs_sockopt_msg_free(out);
    } else
        printf("[%s] fail to recieve get msg#%u reply\n", __func__, cmd);
}


int main(void)
{
    char buf[SOCKOPT_MSG_BUFFER_SIZE];
    size_t out_len = SOCKOPT_MSG_BUFFER_SIZE;

    printf("Start ...\n");
    sprintf(buf, "Hello, I'm set#%u", SOCKOPT_MSG_SET_CMD_1);
    send_set_msg(SOCKOPT_MSG_SET_CMD_1, buf, strlen(buf) + 1);
    sprintf(buf, "Hello, I'm set#%u", SOCKOPT_MSG_SET_CMD_2);
    send_set_msg(SOCKOPT_MSG_SET_CMD_2, buf, strlen(buf) + 1);
    sprintf(buf, "Hello, I'm set#%u", SOCKOPT_MSG_SET_CMD_3);
    send_set_msg(SOCKOPT_MSG_SET_CMD_3, buf, strlen(buf) + 1);

    sprintf(buf, "Hello, I'm get#%u", SOCKOPT_MSG_GET_CMD_1);
    send_get_msg(SOCKOPT_MSG_SET_CMD_1, buf, strlen(buf) + 1);
    sprintf(buf, "Hello, I'm get#%u", SOCKOPT_MSG_GET_CMD_2);
    send_get_msg(SOCKOPT_MSG_SET_CMD_2, buf, strlen(buf) + 1);
    sprintf(buf, "Hello, I'm get#%u", SOCKOPT_MSG_GET_CMD_3);
    send_get_msg(SOCKOPT_MSG_SET_CMD_3, buf, strlen(buf) + 1);
    printf("End ...\n");

    return 0;
}
