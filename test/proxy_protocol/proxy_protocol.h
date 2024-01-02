#include <stdint.h>

#define PPV2SIG "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

typedef union {
    struct {
        char line[108];
    } v1;
    struct {
        uint8_t sig[12];
        uint8_t ver_cmd;
        uint8_t fam;
        uint16_t len;
        union {
            struct {  /* for TCP/UDP over IPv4, len = 12 */
                uint32_t src_addr;
                uint32_t dst_addr;
                uint16_t src_port;
                uint16_t dst_port;
            } ip4;
            struct {  /* for TCP/UDP over IPv6, len = 36 */
                uint8_t  src_addr[16];
                uint8_t  dst_addr[16];
                uint16_t src_port;
                uint16_t dst_port;
            } ip6;
            struct {  /* for AF_UNIX sockets, len = 216 */
                uint8_t src_addr[108];
                uint8_t dst_addr[108];
            } unx;
        } addr;
    } v2;
} pphdr_t;

int parse_proxy_protocol(char *buf, int len);
