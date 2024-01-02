//
// The proxy protocol implementation (server reception side)
// https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
//
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include "proxy_protocol.h"

const char ppv2sig[] = PPV2SIG;

int parse_proxy_protocol(char *buf, int len) {
    struct sockaddr_storage from = { 0 }, to = { 0 };
    size_t pplen;
    pphdr_t *phdr;
    char ppv1data[108], *token, *tmp, *end;
    char frombuf[64], tobuf[64];

    phdr = (pphdr_t *)buf;
    if (len >= 16 && memcmp(&phdr->v2, ppv2sig, 12) == 0 &&
            (phdr->v2.ver_cmd & 0xF0) == 0x20) { // PPv2
        pplen = 16 + ntohs(phdr->v2.len);
        if (pplen > len) // invalid PPv2
            return len;
        switch (phdr->v2.ver_cmd & 0xF) {
            case 0x01: // PROXY command
                switch (phdr->v2.fam) {
                    case 0x11: // TCPv4
                    case 0x12: // UDPv4
                        ((struct sockaddr_in *)&from)->sin_family      = AF_INET;
                        ((struct sockaddr_in *)&from)->sin_addr.s_addr = phdr->v2.addr.ip4.src_addr;
                        ((struct sockaddr_in *)&from)->sin_port        = phdr->v2.addr.ip4.src_port;
                        ((struct sockaddr_in *)&to)->sin_family        = AF_INET;
                        ((struct sockaddr_in *)&to)->sin_addr.s_addr   = phdr->v2.addr.ip4.dst_addr;
                        ((struct sockaddr_in *)&to)->sin_port          = phdr->v2.addr.ip4.dst_port;
                        goto done;
                    case 0x21: // TCPv6
                    case 0x22: // UDPv6
                        ((struct sockaddr_in6 *)&from)->sin6_family     = AF_INET6;
                        memcpy(&((struct sockaddr_in6 *)&from)->sin6_addr, &phdr->v2.addr.ip6.src_addr, 16);
                        ((struct sockaddr_in6 *)&from)->sin6_port       = phdr->v2.addr.ip6.src_port;
                        ((struct sockaddr_in6 *)&to)->sin6_family       = AF_INET6;
                        memcpy(&((struct sockaddr_in6 *)&to)->sin6_addr, &phdr->v2.addr.ip6.dst_addr, 16);
                        ((struct sockaddr_in6 *)&to)->sin6_port         = phdr->v2.addr.ip6.dst_port;
                        goto done;
                    default: // unsupported protocol
                        break;
                break;
                }
            case 0x00: // LOCAL command
                goto done;
            default: // unsupported command
                break;
        }
    } else if (len >= 8 && memcmp(phdr->v1.line, "PROXY", 5) == 0) { // PPv1
        end = index((char *)phdr, '\n');
        if (NULL == end || end + 1 - (char *)phdr > 107) // invalid PPv1
            return len;
        pplen = end + 1 - (char *)phdr;

        memcpy(ppv1data, phdr, pplen);
        if (ppv1data[pplen-1] != '\n')
            return len;
        ppv1data[pplen-1] = '\0';
        if (pplen > 1 && ppv1data[pplen-2] == '\r')
            ppv1data[pplen-2] = '\0';

        if (NULL == (token = strtok_r((char *)ppv1data, " ", &tmp))) // "PROXY"
            return len;
        if (NULL == (token = strtok_r(NULL, " ", &tmp))) // "TCP4|TCP6|UNKNOWN"
            return len;
        if (memcmp(token, "TCP4", 4) == 0) {
            ((struct sockaddr_in *)&from)->sin_family = AF_INET;
            ((struct sockaddr_in *)&to)->sin_family = AF_INET;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // source IP
                return len;
            if (1 != inet_pton(AF_INET, token, &(((struct sockaddr_in *)&from)->sin_addr)))
                return len;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // dest IP
                return len;
            if (1 != inet_pton(AF_INET, token, &(((struct sockaddr_in *)&to)->sin_addr)))
                return len;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // source port
                return len;
            ((struct sockaddr_in *)&from)->sin_port = htons(strtol(token, &end, 10));
            if (*end != '\0')
                return len;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // dest port
                return len;
            ((struct sockaddr_in *)&to)->sin_port = htons(strtol(token, &end, 10));
            if (*end != '\0')
                return len;
            if (NULL != strtok_r(NULL, " ", &tmp))
                return len;
            goto done;
        } else if (memcmp(token, "TCP6", 4) == 0) {
            ((struct sockaddr_in6 *)&from)->sin6_family = AF_INET6;
            ((struct sockaddr_in6 *)&to)->sin6_family = AF_INET6;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // source IP
                return len;
            if (1 != inet_pton(AF_INET6, token, &(((struct sockaddr_in6 *)&from)->sin6_addr)))
                return len;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // dest IP
                return len;
            if (1 != inet_pton(AF_INET6, token, &(((struct sockaddr_in6 *)&to)->sin6_addr)))
                return len;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // source port
                return len;
            ((struct sockaddr_in6 *)&from)->sin6_port = ntohs(strtol(token, &end, 10));
            if (*end != '\0')
                return len;
            if (NULL == (token = strtok_r(NULL, " ", &tmp))) // dest port
                return len;
            ((struct sockaddr_in6 *)&to)->sin6_port = ntohs(strtol(token, &end, 10));
            if (*end != '\0')
                return len;
            if (NULL != strtok_r(NULL, " ", &tmp))
                return len;
            goto done;
        } else if (memcmp(token, "UNKNOWN", 7) == 0) { // LOCAL command
            if (NULL != strtok_r(NULL, " ", &tmp))
                return len;
            goto done;
        } else { // unsupported protocol
                 // UDP4, UDP6 are not supported in v1
            return len;
        }
    } else { // no or invalid proxy protocol
    }
    return len;
done:
    if (from.ss_family == AF_INET) {
        inet_ntop(from.ss_family, &((struct sockaddr_in *)&from)->sin_addr, frombuf, sizeof(frombuf));
        inet_ntop(from.ss_family, &((struct sockaddr_in *)&to)->sin_addr, tobuf, sizeof(tobuf));
        printf("original connection from proxy protocol: %s:%d -> %s:%d\n",
                frombuf, ntohs(((struct sockaddr_in *)&from)->sin_port),
                tobuf, ntohs(((struct sockaddr_in *)&to)->sin_port));
    } else if (from.ss_family == AF_INET6) {
        inet_ntop(from.ss_family, &((struct sockaddr_in6 *)&from)->sin6_addr, frombuf, sizeof(frombuf));
        inet_ntop(from.ss_family, &((struct sockaddr_in6 *)&to)->sin6_addr, tobuf, sizeof(tobuf));
        printf("original connection from proxy protocol: [%s]:%d -> [%s]:%d\n",
                frombuf, ntohs(((struct sockaddr_in6 *)&from)->sin6_port),
                tobuf, ntohs(((struct sockaddr_in6 *)&to)->sin6_port));
    }
    // strip the proxy protocol data
    if (pplen < len) {
        memmove(buf, buf + pplen, len - pplen);
        memset(buf + len - pplen, 0, len - pplen);
    } else {
        memset(buf, 0, len);
    }
    // return the left data length
    return len - pplen;
}
