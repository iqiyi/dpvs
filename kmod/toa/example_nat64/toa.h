#include <netinet/in.h>
 /* toa socket options, now only for nat64 */
enum {
    TOA_BASE_CTL            = 4096,
    /* set */
    TOA_SO_SET_MAX          = TOA_BASE_CTL,
    /* get */
    TOA_SO_GET_LOOKUP       = TOA_BASE_CTL,
    TOA_SO_GET_MAX          = TOA_SO_GET_LOOKUP,
};

struct toa_nat64_peer {
    struct in6_addr saddr;
    uint16_t sport;
};
