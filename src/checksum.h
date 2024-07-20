#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

uint16_t checksum_generic(uint16_t *ptr, size_t nbytes);
uint16_t checksum_tcp(struct ip_hdr *iph, struct tcp_hdr *tcph,
			char *payload, size_t payload_size);
uint16_t checksum_udp(struct ip_hdr *iph, struct udp_hdr *udph,
			char *payload, size_t payload_size);
#endif