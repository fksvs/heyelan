#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "utils.h"
#include "types.h"

/* for prng */
static unsigned int x;

int init_socket(int protocol)
{
	int sockfd;
	int enable = 1;

	if ((sockfd = socket(AF_INET, SOCK_RAW, protocol)) == -1) {
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == -1) {
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

void init_signal(void (*signal_exit))
{
	struct sigaction act;

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = signal_exit;

	if (sigaction(SIGINT, &act, NULL) == -1) {
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &act, NULL) == -1) {
		exit(EXIT_FAILURE);
	}
}

uint16_t checksum_generic(uint16_t *ptr, size_t nbytes)
{
	unsigned short oddbyte = 0;
	register long sum = 0;
	register short answer = 0;

	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	} 
	if (nbytes == 1) {
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = (unsigned short)~sum;

	return answer;
}

uint16_t checksum_tcp(struct ip_hdr *iph, struct tcp_hdr *tcph,
			char *payload, size_t payload_size)
{
	struct psd_hdr psh;
	char *psd;
	size_t psd_size;
	uint16_t check;

	memcpy(&psh.src_addr, &iph->src_addr, 4);
	memcpy(&psh.dst_addr, &iph->dst_addr, 4);

	psh.reserve = 0;
	psh.protocol = IPPROTO_TCP;
	psh.length = htons(sizeof(struct tcp_hdr) + payload_size);

	psd_size = sizeof(struct psd_hdr) + sizeof(struct tcp_hdr) + payload_size;

	psd = malloc(psd_size);
	memset(psd, 0, psd_size);

	memcpy(psd, (char *)&psh, sizeof(struct psd_hdr));
	memcpy(psd + sizeof(struct psd_hdr), tcph, sizeof(struct tcp_hdr));
	memcpy(psd + sizeof(struct psd_hdr) + sizeof(struct tcp_hdr), payload, payload_size);

	if (payload) {
		memcpy(psd + sizeof(struct psd_hdr) + sizeof(struct tcp_hdr), payload, payload_size);
	}

	check = checksum_generic((uint16_t *)psd, psd_size);
	free(psd);

	return check;
}

uint16_t checksum_udp(struct ip_hdr *iph, struct udp_hdr *udph,
			char *payload, size_t payload_size)
{
	struct psd_hdr psh;
	char *psd;
	size_t psd_size;
	uint16_t check;

	memcpy(&psh.src_addr, &iph->src_addr, 4);
	memcpy(&psh.dst_addr, &iph->dst_addr, 4);

	psh.reserve = 0;
	psh.protocol = IPPROTO_UDP;
	psh.length = htons(sizeof(struct udp_hdr) + payload_size);

	psd_size = sizeof(struct psd_hdr) + sizeof(struct udp_hdr) + payload_size;

	psd = malloc(psd_size);
	memset(psd, 0, psd_size);

	memcpy(psd, (char *)&psh, sizeof(struct psd_hdr));
	memcpy(psd + sizeof(struct psd_hdr), udph, sizeof(struct udp_hdr));
	memcpy(psd + sizeof(struct psd_hdr) + sizeof(struct udp_hdr), payload, payload_size);

	check = checksum_generic((uint16_t *)psd, psd_size);
	free(psd);

        return check;
}

void seed_rand(unsigned int seed)
{
	x = seed;
}

int random_num()
{
	unsigned int number = 0;

	number = (1103515245 * x + 12345) % (1 << 31);
	x = number;

	return number;
}
