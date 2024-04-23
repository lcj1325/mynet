




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

#define mynet_debug(format, ...) printf("[ Core %u %s:%d ==> " format " ]\n", rte_lcore_id(), __FUNCTION__, __LINE__, ##__VA_ARGS__)



#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))


#define LL_ADD(item, list) do {		            \
	item->prev = NULL;				            \
	item->next = list;				            \
	if (list != NULL) list->prev = item;        \
	list = item;					            \
} while(0)


#define LL_REMOVE(item, list) do {		                    \
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	                \
	item->prev = item->next = NULL;			                \
} while(0)


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RING_SIZE	1024
#define TIMER_RESOLUTION_CYCLES 1200000000000ULL // 10ms * 1000 = 10s * 6
#define TCP_MAX_SEQ		4294967295
#define TCP_INITIAL_WINDOW  14600


extern struct rte_mempool *g_mbuf_pool;
extern uint32_t g_local_addr;
extern struct rte_ether_addr g_local_mac;


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
    uint16_t icmp_len;
    uint8_t *icmp;
};


struct udphdr_info {

    uint16_t src_port;
    uint16_t dst_port;
    uint8_t *data;
    uint16_t data_len;
};


struct tcphdr_info {

    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sent_seq;
    uint32_t recv_ack;
    uint8_t tcp_flags;
    uint8_t *data;
    uint16_t data_len;
};

void format_ipv4_tcp_pkt(struct rte_mbuf *buf, const char *msg);

void format_ipv4_udp_pkt(struct rte_mbuf *buf, const char *msg);

void  format_ipv4_icmp_pkt(struct rte_mbuf *buf, const char *msg);

void format_arp_pkt(struct rte_mbuf *buf, const char *msg);

int encap_pkt_ethhdr(struct rte_mbuf *new_buf, struct ethhdr_info *ethinfo);


int encap_pkt_arphdr(struct rte_mbuf *new_buf, struct arphdr_info *arpinfo);


int encap_pkt_ip4hdr(struct rte_mbuf *new_buf, struct ip4hdr_info *ip4info);


int encap_pkt_udphdr(struct rte_mbuf *new_buf, struct udphdr_info *udpinfo);


int encap_pkt_tcphdr(struct rte_mbuf *new_buf, struct tcphdr_info *tcpinfo);


int encap_pkt_icmphdr(struct rte_mbuf *new_buf, struct icmphdr_info *icmpinfo);


struct rte_mbuf *encap_arp_request_pkt(uint32_t dstip);


struct rte_mbuf *encap_arp_reply_pkt(struct rte_mbuf *buf);


struct rte_mbuf *encap_icmp_reply_pkt(struct rte_mbuf *buf);


struct rte_mbuf *encap_tcp_synack_pkt(struct tcp_stream *new_stream);


struct rte_mbuf *encap_tcp_ack_pkt(struct tcp_stream *stream);


#endif  //  __MYNET_H__




