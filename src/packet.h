#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include "types.h"

void build_ip(struct ip_hdr *iph, uint16_t length, uint8_t protocol, uint32_t dst_addr);
void build_tcp(struct ip_hdr *iph, struct tcp_hdr *tcph, uint8_t flag, uint16_t dst_port);
void build_udp(struct ip_hdr *iph, struct udp_hdr *udph, uint16_t dst_port);
void build_icmp(struct icmp_hdr *icmph);

#endif
