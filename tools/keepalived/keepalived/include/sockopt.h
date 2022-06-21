#ifndef __DPVS_SOCK_OPT_H__
#define __DPVS_SOCK_OPT_H__

#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKOPT_VERSION_MAJOR           1
#define SOCKOPT_VERSION_MINOR           0
#define SOCKOPT_VERSION_PATCH           0
#define SOCKOPT_VERSION     ((SOCKOPT_VERSION_MAJOR << 16) + \
        (SOCKOPT_VERSION_MINOR << 8) + SOCKOPT_VERSION_PATCH)

#define SOCKOPT_MSG_BUFFER_SIZE         (1UL << 12)
#define SOCKOPT_ERRSTR_LEN              64

#define ENV_DPVS_IPC_FILE               "DPVS_IPC_FILE"

enum {
    ESOCKOPT_INVAL = -16385,
    ESOCKOPT_IO,
    ESOCKOPT_NOMEM,
    ESOCKOPT_VERSION,
    ESOCKOPT_UNKOWN = 65535,
    ESOCKOPT_OK = 0,
};

typedef uint32_t sockoptid_t;

enum sockopt_type {
    SOCKOPT_GET = 0,
    SOCKOPT_SET,
    SOCKOPT_TYPE_MAX,
};

struct dpvs_sock_msg {
    uint32_t version;
    sockoptid_t id;
    enum sockopt_type type;
    size_t len;
    char data[0];
};

struct dpvs_sock_msg_reply {
    uint32_t version;
    sockoptid_t id;
    enum sockopt_type type;
    int errcode;
    char errstr[SOCKOPT_ERRSTR_LEN];
    size_t len;
    char data[0];
};

extern int dpvs_setsockopt(sockoptid_t cmd, const void *in, size_t in_len);
extern int dpvs_getsockopt(sockoptid_t cmd, const void *in, size_t in_len,
        void **out, size_t *out_len);
extern int dpvs_sockopt_init(void);

static inline void dpvs_sockopt_msg_free(void *msg)
{
    free(msg);
    msg = NULL;
}

#endif
