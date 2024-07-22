#include <stdlib.h>
#include <arpa/inet.h>
#include "packet.h"
#include "utils.h"
#include "types.h"

void build_ip(struct ip_hdr *iph, uint16_t length, uint8_t protocol, uint32_t dst_addr)
{
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->length = length;
	iph->ident = random_num() & 0xfff;
	iph->frag = 0;
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->checksum = 0;
	iph->src_addr = random_num();
	iph->dst_addr = dst_addr;
	iph->checksum = checksum_generic((uint16_t *)iph, iph->length);
}

void build_tcp(struct ip_hdr *iph, struct tcp_hdr *tcph, uint8_t flag)
{
	tcph->src_port = random_num() & 0xffff;
	tcph->dst_port = random_num() & 0xffff;
	tcph->seq_num = random_num();
	tcph->ack_num = 0;
	tcph->offset = 5;
	tcph->reserved = 0;
	tcph->flag = flag;
	tcph->win_size = random_num() & 0xffff;
	tcph->checksum = 0;
	tcph->urg_ptr = 0;
	tcph->checksum = checksum_tcp(iph, tcph, NULL, 0);
}

void build_udp(struct ip_hdr *iph, struct udp_hdr *udph)
{
	udph->src_port = random_num() & 0xffff;
        udph->dst_port = random_num() & 0xffff;
        udph->length = htons(sizeof(struct udp_hdr));
        udph->checksum = 0;
	udph->checksum = checksum_udp(iph, udph, NULL, 0);
}

void build_icmp(struct icmp_hdr *icmph)
{
	icmph->type = 8;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->data.data16[0] = random_num() & 0xffff;
	icmph->data.data16[1] = random_num() & 0xffff;
	icmph->checksum = checksum_generic((uint16_t *)icmph, sizeof(struct icmp_hdr));
}
