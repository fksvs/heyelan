#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

void parse_args(int argc, char *argv[], struct target_data *target);

int init_socket(int protocol);
void init_signal(void (*signal_exit)());
void init_attack_info(struct target_data *target, struct attack_info *info);

void print_attack_header(struct attack_info *info);
void print_attack_info(struct attack_info *info);

uint16_t checksum_generic(uint16_t *ptr, size_t nbytes);
uint16_t checksum_tcp(struct ip_hdr *iph, struct tcp_hdr *tcph,
			char *payload, size_t payload_size);
uint16_t checksum_udp(struct ip_hdr *iph, struct udp_hdr *udph,
			char *payload, size_t payload_size);

void seed_rand(unsigned int seed);
int random_num();

#endif
