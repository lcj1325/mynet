




#ifndef __MYNET_H__
#define __MYNET_H__


#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_timer.h>


#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define SEND_UDP 1
#define SEND_ARP 1
#define SEND_ICMP 1

#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6


struct ethhdr_info{
    uint8_t *dst_addr;
    uint16_t ether_type;
};


struct arphdr_info{
    uint8_t *arp_tha;
    uint32_t arp_tip;
    uint16_t arp_opcode;
};

struct ip4hdr_info {

    uint16_t total_length;
    uint8_t next_proto_id;
    uint32_t dst_addr;
};


struct icmphdr_info {

	uint8_t  icmp_type;
	uint16_t icmp_ident;
	uint16_t icmp_seq_nb;
    uint8_t *data;
    uint16_t data_len;
    uint16_t icmp_len;
};

struct udphdr_info {

    uint16_t src_port;
    uint16_t dst_port;
    uint16_t dgram_len;
    uint8_t *data;
    uint16_t data_len;
};


struct tcphdr_info {

    uint16_t src_port;
    uint16_t dst_port;
    uint8_t *data;
    uint16_t data_len;
};




#endif  //  __MYNET_H__




