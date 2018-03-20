#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h" /* for __u8, __be16, __be32, __u64 only,
		       just define them if not want common.h */
#include "uoa.h"

#define SA		struct sockaddr
#define SERV_PORT	6000

int main(int argc, char *argv[])
{
	int sockfd, n, enable = 1;
	char buff[4096], from[64];
	struct sockaddr_in local, peer;
	struct uoa_param_map map;
	socklen_t len, mlen;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("fail to create socket");
		exit(1);
	}

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

	memset(&local, 0, sizeof(struct sockaddr_in));
	local.sin_family	= AF_INET;
	local.sin_port		= htons(SERV_PORT);
	local.sin_addr.s_addr	= htonl(INADDR_ANY);

	if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
		perror("bind");
		exit(1);
	}

	while (1) {
		len = sizeof(peer);
		n = recvfrom(sockfd, buff, sizeof(buff), 0, (SA *)&peer, &len);
		if (n < 0) {
			perror("recvfrom");
			break;
		}

		inet_ntop(AF_INET, &peer.sin_addr, from, sizeof(from));
		printf("Receive %d bytes from %s:%d\n",
		       n, from, ntohs(peer.sin_port));

		/*
		 * get real client address:
		 *
		 * note: src/dst is for original pkt, so peer is
		 * "orginal" source, instead of local. wildcard
		 * lookup for daddr (or local IP) is supported.
		 */
		memset(&map, 0, sizeof(map));
		map.saddr = peer.sin_addr.s_addr;
		map.sport = peer.sin_port;
		map.daddr = htonl(INADDR_ANY);
		map.dport = htons(SERV_PORT);
		mlen = sizeof(map);

		if (getsockopt(sockfd, IPPROTO_IP, UOA_SO_GET_LOOKUP,
			       &map, &mlen) != 0) {
			perror("getsockopt: UOA_SO_GET_LOOKUP");
			goto do_echo;
		}

		inet_ntop(AF_INET, &map.real_saddr, from, sizeof(from));
		printf("  real client %s:%d\n", from, ntohs(map.real_sport));

do_echo:
		len = sizeof(peer);
		sendto(sockfd, buff, n, 0, (SA *)&peer, len);
	}

	close(sockfd);
	exit(0);
}
