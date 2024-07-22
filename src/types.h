#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <sys/socket.h>

#define ATTACK_TCP_SYN 0
#define ATTACK_TCP_ACK 1
#define ATTACK_TCP_SYNACK 2
#define ATTACK_TCP_PSHACK 3
#define ATTACK_TCP_ACKFIN 4
#define ATTACK_TCP_RST 5
#define ATTACK_TCP_ALL 6
#define ATTACK_TCP_NULL 7
#define ATTACK_UDP 8
#define ATTACK_HTTP_GET 9
#define ATTACK_HTTP_POST 10
#define ATTACK_ICMP_PING 11

#define BUFFER_SIZE 4096

struct target_data {
	int sockfd;
	int attack_type;
	uint32_t target_addr;
	uint16_t target_port;
	struct sockaddr_in addr;
};

struct ip_hdr {
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t ihl:4;
	uint8_t version:4;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version:4;
	uint8_t ihl:4;
#endif
	uint8_t tos;
	uint16_t length;
	uint16_t ident;
	uint16_t frag;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
};

#define TCP_NULL 0x00
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t reserved:4;
	uint8_t offset:4;
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
	uint8_t offset:4;
	uint8_t reserved:4;
#endif
	uint8_t flag;
	uint16_t win_size;
	uint16_t checksum;
	uint16_t urg_ptr;
};

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
};

struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		uint32_t data32[1];
		uint16_t data16[2];
		uint8_t data8[4];
	} data;
};

struct psd_hdr {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t reserve;
	uint8_t protocol;
	uint16_t length;
};

#endif
