/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */



#include "mynet_arp.h"
#include "mynet_ring.h"
#include "mynet_socket.h"
#include "mynet.h"

struct rte_mempool *g_mbuf_pool;
uint32_t g_local_addr = MAKE_IPV4_ADDR(10, 66, 24, 22);
struct rte_ether_addr g_local_mac;
uint8_t g_default_mac_0[RTE_ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t g_default_mac_1[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


/* mynet.c */

// 计算校验和的函数
static inline uint16_t mynet_icmp_checksum(void *addr, int len) {
    uint16_t *buf = (uint16_t *)addr;
    uint32_t sum = 0;

    // 按照16位字节对进行求和
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    // 如果长度为奇数，将最后一个字节单独处理
    if (len == 1) {
        sum += *((uint8_t *)buf);
    }

    // 将32位的累加和转换为16位，注意将高16位和低16位相加
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum; // 取反得到校验和

}


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, &g_local_mac);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&g_local_mac));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

static inline void format_eth_hdr(struct rte_ether_hdr *ethhdr) {

	printf("[ "
            "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			" -> "
			"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			" ]\n",
			RTE_ETHER_ADDR_BYTES(&ethhdr->src_addr),
			RTE_ETHER_ADDR_BYTES(&ethhdr->dst_addr));

}

static inline void format_arp_hdr(struct rte_arp_hdr *arphdr) {

    struct in_addr addr;
	addr.s_addr = arphdr->arp_data.arp_sip;
	printf("[ %s -> ", inet_ntoa(addr));

	addr.s_addr = arphdr->arp_data.arp_tip;
	printf("%s ]\n", inet_ntoa(addr));

	printf("[ "
            "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
    		" -> "
    		"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
    		" ]\n",
    		RTE_ETHER_ADDR_BYTES(&arphdr->arp_data.arp_sha),
    		RTE_ETHER_ADDR_BYTES(&arphdr->arp_data.arp_tha));
}

static inline void format_ip4_hdr(struct rte_ipv4_hdr *ip4hdr) {

	struct in_addr addr;
	addr.s_addr = ip4hdr->src_addr;
	printf("[ %s -> ", inet_ntoa(addr));

	addr.s_addr = ip4hdr->dst_addr;
	printf("%s ]\n", inet_ntoa(addr));

}

static inline void format_udp_hdr(struct rte_udp_hdr *udphdr) {

    uint16_t length = ntohs(udphdr->dgram_len);
    *((char*)udphdr + length) = '\0';

	printf("[ %u -> %u ]\n", rte_be_to_cpu_16(udphdr->src_port), rte_be_to_cpu_16(udphdr->dst_port));
	printf("[ length = %u, %s ]\n", rte_be_to_cpu_16(udphdr->dgram_len), (char *)(udphdr + 1));

}
struct rte_tcp_hdr {
	rte_be16_t src_port; /**< TCP source port. */
	rte_be16_t dst_port; /**< TCP destination port. */
	rte_be32_t sent_seq; /**< TX data sequence number. */
	rte_be32_t recv_ack; /**< RX data acknowledgment sequence number. */
	uint8_t  data_off;   /**< Data offset. */
	uint8_t  tcp_flags;  /**< TCP flags */
	rte_be16_t rx_win;   /**< RX flow control window. */
	rte_be16_t cksum;    /**< TCP checksum. */
	rte_be16_t tcp_urp;  /**< TCP urgent pointer, if any. */
} __rte_packed;

static inline void format_tcp_hdr(struct rte_tcp_hdr *tcphdr) {

    uint16_t length = ntohs(udphdr->dgram_len);
    *((char*)udphdr + length) = '\0';

	printf("[ %u -> %u, sent_seq=%u, recv_ack=%u ]\n",
            rte_be_to_cpu_16(tcphdr->src_port),
            rte_be_to_cpu_16(tcphdr->dst_port),
            rte_be_to_cpu_32(tcphdr->sent_seq),
            rte_be_to_cpu_32(tcphdr->recv_ack));

}


static inline void format_icmp_hdr(struct rte_icmp_hdr *icmphdr) {

    printf("[ ident:%u, seq_nb:%u ]\n",
            rte_be_to_cpu_16(icmphdr->icmp_ident),
            rte_be_to_cpu_16(icmphdr->icmp_seq_nb));
}

static inline void format_ipv4_tcp_pkt(struct rte_mbuf *buf, const char *msg) {

    if (MYNET_DEBUG) {

        struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
        struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
        struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ip4hdr + 1);

        printf("\n  %s:\n", msg);
        format_eth_hdr(ethhdr);
        format_ip4_hdr(ip4hdr);
        format_tcp_hdr(tcphdr);

        printf("[ length = %u, %s ]\n",
                rte_be_to_cpu_16(ip4hdr->total_length) - sizeof(struct rte_ipv4_hdr)- sizeof(struct rte_tcp_hdr),
                (char *)(tcphdr + 1));
    }

}


static inline void format_ipv4_udp_pkt(struct rte_mbuf *buf, const char *msg) {

    if (MYNET_DEBUG) {

        struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
        struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
        struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(ip4hdr + 1);

        printf("\n  %s:\n", msg);
        format_eth_hdr(ethhdr);
        format_ip4_hdr(ip4hdr);
        format_udp_hdr(udphdr);

    }

}

static inline void  format_ipv4_icmp_pkt(struct rte_mbuf *buf, const char *msg){

    if (MYNET_DEBUG) {

        printf("\n  %s:\n", msg);
        struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
        struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
        struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(ip4hdr + 1);

        format_eth_hdr(ethhdr);
        format_ip4_hdr(ip4hdr);
        format_icmp_hdr(icmphdr);

    }
}


static inline void format_ipv4_arp_pkt(struct rte_mbuf *buf, const char *msg) {

    if (MYNET_DEBUG) {

        struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
        struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethhdr + 1);

        printf("\n  %s:\n", msg);
        format_eth_hdr(ethhdr);
        format_arp_hdr(arphdr);

    }
}


int encap_pkt_ethhdr(struct rte_mbuf *new_buf, struct ethhdr_info *ethinfo) {

	struct rte_ether_hdr *new_eth =  rte_pktmbuf_mtod(new_buf, struct rte_ether_hdr*);

	rte_memcpy(&new_eth->src_addr, &g_local_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(new_eth->dst_addr.addr_bytes, ethinfo->dst_addr, RTE_ETHER_ADDR_LEN);
	new_eth->ether_type = ethinfo->ether_type;

	return 0;
}


int encap_pkt_arphdr(struct rte_mbuf *new_buf, struct arphdr_info *arpinfo) {

    struct rte_arp_hdr *new_arp =  rte_pktmbuf_mtod_offset(new_buf, struct rte_arp_hdr*,
                                                            sizeof(struct rte_ether_hdr));
    new_arp->arp_hardware = rte_cpu_to_be_16(1);
    new_arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    new_arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    new_arp->arp_plen = sizeof(uint32_t);
    new_arp->arp_opcode = arpinfo->arp_opcode;

	rte_memcpy(new_arp->arp_data.arp_sha.addr_bytes, g_local_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(new_arp->arp_data.arp_tha.addr_bytes, arpinfo->arp_tha, RTE_ETHER_ADDR_LEN);

	new_arp->arp_data.arp_sip = g_local_addr;
    new_arp->arp_data.arp_tip = arpinfo->arp_tip;

    return 0;
}


int encap_pkt_ip4hdr(struct rte_mbuf *new_buf, struct ip4hdr_info *ip4info) {

	struct rte_ipv4_hdr *new_ip = rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));
	new_ip->version_ihl = 0x45;
	new_ip->type_of_service = 0;
	new_ip->total_length = ip4info->total_length;
	new_ip->packet_id = 0;
	new_ip->fragment_offset = 0;
	new_ip->time_to_live = 64; // ttl = 64
	new_ip->next_proto_id = ip4info->next_proto_id;
	new_ip->hdr_checksum = 0;
	new_ip->src_addr = g_local_addr;
	new_ip->dst_addr = ip4info->dst_addr;

	new_ip->hdr_checksum = rte_ipv4_cksum(new_ip);

	return 0;

}


int encap_pkt_udphdr(struct rte_mbuf *new_buf, struct udphdr_info *udpinfo) {

    struct rte_ipv4_hdr *new_ip = rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *new_udp = (struct rte_udp_hdr *)(new_ip + 1);

	new_udp->src_port = udpinfo->src_port;
    new_udp->dst_port = udpinfo->dst_port;
	new_udp->dgram_len = rte_cpu_to_be_16(udpinfo->data_len + sizeof(struct rte_udp_hdr));
	new_udp->dgram_cksum = 0;
	rte_memcpy((uint8_t*)(new_udp + 1), udpinfo->data, udpinfo->data_len);

	new_udp->dgram_cksum = rte_ipv4_udptcp_cksum(new_ip, new_udp);

	return 0;

}


int encap_pkt_tcphdr(struct rte_mbuf *new_buf, struct tcphdr_info *tcpinfo) {

    struct rte_ipv4_hdr *new_ip = rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *new_tcp = (struct rte_tcp_hdr *)(new_ip + 1);

    new_tcp->src_port = tcpinfo->src_port;
	new_tcp->dst_port = tcpinfo->dst_port;
	new_tcp->sent_seq = tcpinfo->sent_seq;
	new_tcp->recv_ack = tcpinfo->recv_ack;

	new_tcp->data_off = 0x50; // 20 字节长 tcp 头部
	new_tcp->tcp_flags = tcpinfo->tcp_flags;
	new_tcp->rx_win = rte_cpu_to_be_16(TCP_INITIAL_WINDOW);
	new_tcp->tcp_urp = 0;

    rte_memcpy((uint8_t *)(new_tcp + 1), tcpinfo.data, tcpinfo.data_len);

	return 0;
}


int encap_pkt_icmphdr(struct rte_mbuf *new_buf, struct icmphdr_info *icmpinfo) {

    struct rte_icmp_hdr *new_icmp = rte_pktmbuf_mtod_offset(new_buf, struct rte_icmp_hdr *,
                                            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    new_icmp->icmp_type = icmpinfo->icmp_type;
    new_icmp->icmp_code = 0;
    new_icmp->icmp_cksum = 0;
    new_icmp->icmp_ident = icmpinfo->icmp_ident;
    new_icmp->icmp_seq_nb = icmpinfo->icmp_seq_nb;
    rte_memcpy((uint8_t *)(new_icmp + 1), icmpinfo->data, icmpinfo->data_len);

    new_icmp->icmp_cksum = mynet_icmp_checksum(new_icmp, icmpinfo->icmp_len);
	return 0;
}


static inline struct rte_mbuf *encap_arp_request_pkt(uint32_t dstip) {

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc arp buf error.\n");
    }

    //eth
    struct ethhdr_info ethinfo;
    memset(&ethinfo, 0, sizeof(ethinfo));

    ethinfo.dst_addr = g_default_mac_1;
    ethinfo.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    encap_pkt_ethhdr(new_buf, &ethinfo);

    //arp
    struct arphdr_info arpinfo;
    memset(&arpinfo, 0, sizeof(arpinfo));

    arpinfo.arp_tha = g_default_mac_0;
    arpinfo.arp_tip = dstip;
    arpinfo.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    encap_pkt_arphdr(new_buf, &arpinfo);

    format_ipv4_arp_pkt(new_buf, "send arp request");

    return new_buf;
}


static inline struct rte_mbuf *encap_arp_reply_pkt(struct rte_mbuf *buf) {

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc arp reply buf error.\n");
    }

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethhdr + 1);

    uint16_t eth_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    new_buf->pkt_len = eth_len;
	new_buf->data_len = eth_len;

    //eth
    struct ethhdr_info ethinfo;
    memset(&ethinfo, 0, sizeof(ethinfo));

    ethinfo.dst_addr = arphdr->arp_data.arp_sha.addr_bytes;
    ethinfo.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    encap_pkt_ethhdr(new_buf, &ethinfo);

    //arp
    struct arphdr_info arpinfo;
    memset(&arpinfo, 0, sizeof(arpinfo));

    arpinfo.arp_tha = arphdr->arp_data.arp_sha.addr_bytes;
    arpinfo.arp_tip = arphdr->arp_data.arp_sip;
    arpinfo.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    encap_pkt_arphdr(new_buf, &arpinfo);

    format_ipv4_arp_pkt(new_buf, "send arp reply");

    return new_buf;
}

static inline struct rte_mbuf *encap_udp_pkt(struct rte_mbuf *new_buf) {

    struct rte_ipv4_hdr *ip4 =  rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr*,
                                                        sizeof(struct rte_ether_hdr));

    uint8_t *dstmac = mynet_get_dstmac(ip4->dst_addr);

    if (dstmac == NULL) {

        return encap_arp_request_pkt(ip4->dst_addr);
    }
    else {
        struct ethhdr_info ethinfo;
        memset(&ethinfo, 0, sizeof(ethinfo));

        ethinfo.dst_addr = dstmac;
        ethinfo.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        encap_pkt_ethhdr(new_buf, &ethinfo);
    }

    return NULL;

}

static inline struct rte_mbuf *encap_tcp_synack_pkt(struct tcpstream *stream) {

    uint8_t *dstmac = mynet_get_dstmac(stream->sip);
    if (dstmac == NULL) {
        printf("[ %s ==> dst mac nil. ]\n", __FUNCTION__);
        return encap_arp_request_pkt(stream->dip);
    }

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc tcp buf error.\n");
    }

    uint16_t eth_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
    uint16_t ip4_len = sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);

    new_buf->pkt_len = eth_len;
	new_buf->data_len = eth_len;

    // eth
    struct ethhdr_info ethinfo;
    memset(&ethinfo, 0, sizeof(ethinfo));

    ethinfo.dst_addr = dstmac;
    ethinfo.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    encap_pkt_ethhdr(new_buf, &ethinfo);

    // ip4
    struct ip4hdr_info ip4info;
    memset(&ip4info, 0, sizeof(ip4info));

    ip4info.dst_addr = stream->sip;
    ip4info.next_proto_id = IPPROTO_TCP;
    ip4info.total_length = rte_cpu_to_be_16(ip4_len);

    encap_pkt_ip4hdr(new_buf, &ip4info);

    // tcp
    struct tcphdr_info tcpinfo;
    memset(&tcpinfo, 0, sizeof(tcpinfo));

    tcpinfo.src_port = stream->dport;
    tcpinfo.dst_port = stream->sport;
    tcpinfo.sent_seq = rte_cpu_to_be_32(stream->sent_seq);
    tcpinfo.recv_ack = rte_cpu_to_be_32(stream->recv_ack);
    tcpinfo.tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);

    encap_pkt_tcphdr(new_buf, &tcpinfo);

}

static inline struct rte_mbuf *encap_icmp_reply_pkt(struct rte_mbuf *buf) {

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc icmp buf error.\n");
    }

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(ip4hdr + 1);

    uint16_t ip4_len = rte_be_to_cpu_16(ip4hdr->total_length);
    uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);
    uint16_t data_len = ip4_len - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_icmp_hdr);
    uint16_t icmp_len = ip4_len - sizeof(struct rte_ipv4_hdr);

    new_buf->pkt_len = eth_len;
	new_buf->data_len = eth_len;

    // eth
    struct ethhdr_info ethinfo;
    memset(&ethinfo, 0, sizeof(ethinfo));

    ethinfo.dst_addr = ethhdr->src_addr.addr_bytes;
    ethinfo.ether_type = ethhdr->ether_type;

    encap_pkt_ethhdr(new_buf, &ethinfo);

    // ip4
    struct ip4hdr_info ip4info;
    memset(&ip4info, 0, sizeof(ip4info));

    ip4info.dst_addr = ip4hdr->src_addr;
    ip4info.next_proto_id = ip4hdr->next_proto_id;
    ip4info.total_length = rte_cpu_to_be_16(ip4_len);

    encap_pkt_ip4hdr(new_buf, &ip4info);

    // icmp
    struct icmphdr_info icmpinfo;
    memset(&icmpinfo, 0, sizeof(icmpinfo));

    icmpinfo.icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmpinfo.icmp_ident = icmphdr->icmp_ident;
    icmpinfo.icmp_seq_nb = icmphdr->icmp_seq_nb;
    icmpinfo.data = (uint8_t *)(icmphdr + 1);
    icmpinfo.data_len = data_len;
    icmpinfo.icmp_len = icmp_len;

    encap_pkt_icmphdr(new_buf, &icmpinfo);

    format_ipv4_icmp_pkt(new_buf, "send icmp echo reply");

    return new_buf;
}



static inline int encap_socketbuf_ethhdr(struct rte_mbuf *new_buf, struct inout_ring *ring) {

    struct rte_ipv4_hdr *new_ip4 =  rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr*,
                                                        sizeof(struct rte_ether_hdr));

    uint8_t *dstmac = mynet_get_dstmac(new_ip4->dst_addr);

    if (dstmac == NULL) {

        struct rte_mbuf *arp_buf = encap_arp_request_pkt(new_ip4->dst_addr);
        rte_pktmbuf_free(new_buf);
        rte_ring_sp_enqueue_burst(ring->out, (void**)&arp_buf, 1, NULL);

    }
    else {

        // encap eth hdr
        struct ethhdr_info ethinfo;
        memset(&ethinfo, 0, sizeof(ethinfo));

        ethinfo.dst_addr = dstmac;
        ethinfo.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        encap_pkt_ethhdr(new_buf, &ethinfo);

        rte_ring_sp_enqueue_burst(ring->out, (void**)&new_buf, 1, NULL);
    }

    return 0;

}


int tcp_handle_listen(struct tcpstream *stream, struct rte_mbuf *buf) {

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ip4hdr + 1);

    if (!(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG))  {
        printf("[ %s ==> pkt not syn.] \n", __FUNCTION__);
        return -1;
    }

    if (stream->status != TCP_STATUS_LISTEN) {
        printf("[ %s ==> stream not listen.] \n", __FUNCTION__);
        return -1;
    }

    struct tcpstream *new_stream = stream_create(-1);
    if (new_stream == NULL){
        printf("[ %s ==> create stream error.] \n", __FUNCTION__);
        return -1;
    }

    new_stream->sip = ip4hdr->src_addr;
    new_stream->dip = ip4hdr->dst_addr;
    new_stream->sport = tcphdr->src_port;
    new_stream->dport = tcphdr->dst_port;

    uint32_t next_seed = time(NULL);
    new_stream->sent_seq = rand_r(&next_seed) % TCP_MAX_SEQ;

    new_stream->recv_ack = rte_be_to_cpu_32(tcphdr->recv_ack) + 1;

    new_stream->status = TCP_STATUS_SYN_RCVD;

    LL_ADD(new_stream, g_streams);

    struct rte_mbuf *new_buf = encap_tcp_synack_pkt(new_stream);

    if (new_buf != NULL) {

        rte_ring_mp_enqueue(new_stream->sendbuf, new_buf);
    }

    return 0;

}


int tcp_handle_syn_rcvd(struct tcpstream *stream, struct rte_mbuf *buf) {

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ip4hdr + 1);

    if (!(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG)) {

        printf("[ %s ==> pkt not ack.] \n", __FUNCTION__);
        return -1;

    }

    if (stream->status != TCP_STATUS_SYN_RCVD) {

        printf("[ %s ==> stream not syn rcvd.] \n", __FUNCTION__);
        return -1;
    }

    uint32_t acknum = rte_be_to_cpu_32(tcphdr->recv_ack);
    if (acknum != stream->sent_seq + 1) {
        printf("[ %s ==> sent_seq not match acknum, acknum=%d stream->sent_seq=%d.] \n",
                __FUNCTION__, acknum, stream->sent_seq);
    }

    stream->status = TCP_STATUS_ESTABLISHED;

    // accept
    struct tcpstream *listener = mynet_getstream_from_ipport(0, stream->dip, 0, stream->dport);

    if (listener == NULL) {
        rte_exit(EXIT_FAILURE, "find listener failed\n");
    }

    pthread_mutex_lock(&listener->mutex);
    pthread_cond_signal(&listener->cond);
    pthread_mutex_unlock(&listener->mutex);

    return 0;

}

int tcp_handle_established(struct tcpstream *stream, struct rte_mbuf *buf) {

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ip4hdr + 1);

    uint16_t ip4_len = rte_be_to_cpu_16(ip4hdr->total_length);
    uint16_t tcp_len = ip4_len - sizeof(struct rte_ipv4_hdr);
    uint8_t tcphdr_len = tcphdr->data_off >> 4;
    uint16_t data_len = tcp_len - tcphdr_len;

    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		//
	}

    if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {

        // recv ring
        rte_ring_mp_enqueue(stream->recvbuf, buf);
        pthread_mutex_lock(&stream->mutex);
        pthread_cond_signal(&stream->cond);
        pthread_mutex_unlock(&stream->mutex);

		stream->recv_ack = stream->recv_ack + data_len;
		stream->sent_seq = rte_be_to_cpu_32(tcphdr->recv_ack);

        tcp_send_ackpkt(stream, tcphdr);
    }

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

        tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);
        tcp_send_ackpkt(stream, tcphdr);

	}

}

static inline struct rte_mbuf *pkt_udp_proc(struct rte_mbuf *buf) {

	format_ipv4_udp_pkt(buf, "recv udp pkt");

    struct rte_ether_hdr *eth =  rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 =  (struct rte_ipv4_hdr *)(eth + 1);
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip4 + 1);

    struct localhost *host = mynet_gethost_from_app(ip4->dst_addr, udp->dst_port, ip4->next_proto_id);
    if (host == NULL) {

        if (MYNET_DEBUG) {
            printf("[ test ==> pkt_udp_proc find host error. ]\n");
        }

        return NULL;
    }

    rte_ring_mp_enqueue(host->recvbuf, buf);

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

    return NULL;
}

static inline struct rte_mbuf *pkt_tcp_proc(struct rte_mbuf *buf) {

    format_ipv4_tcp_pkt(buf, "recv tcp pkt");

    struct rte_ipv4_hdr *ip4hdr =  rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
				                                            sizeof(struct rte_ether_hdr));

	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(ip4hdr + 1);

    struct tcpstream *stream = mynet_getstream_from_ipport(ip4hdr->src_addr, ip4hdr->dst_addr,
                                                           tcphdr->src_port, tcphdr->dst_port);

	if (stream == NULL) {
		return NULL;
	}

	switch (stream->status) {

		case TCP_STATUS_CLOSED: //client
			break;

		case TCP_STATUS_LISTEN: // server
			tcp_handle_listen(stream, buf);
			break;

		case TCP_STATUS_SYN_RCVD: // server
			tcp_handle_syn_rcvd(stream, buf);
			break;

		case TCP_STATUS_SYN_SENT: // client
			break;

		case TCP_STATUS_ESTABLISHED: { // server | client

			int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);

			tcp_handle_established(stream, tcphdr, tcplen);

			break;
		}
		case TCP_STATUS_FIN_WAIT_1: //  ~client
			break;

		case TCP_STATUS_FIN_WAIT_2: // ~client
			break;

		case TCP_STATUS_CLOSING: // ~client
			break;

		case TCP_STATUS_TIME_WAIT: // ~client
			break;

		case TCP_STATUS_CLOSE_WAIT: // ~server
			tcp_handle_close_wait(stream, tcphdr);
			break;

		case TCP_STATUS_LAST_ACK:  // ~server
			tcp_handle_last_ack(stream, tcphdr);
			break;

	}

    return NULL;
}

static inline struct rte_mbuf *pkt_icmp_proc(struct rte_mbuf *buf) {

    struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(buf, struct rte_icmp_hdr *,
                                        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

        format_ipv4_icmp_pkt(buf, "recv icmp echo request");

        return encap_icmp_reply_pkt(buf);
    }
    else {

        if (MYNET_DEBUG) {
            printf("[ test ==> pkt_icmp_proc invalid type, icmp->icmp_type=%u.] \n", icmp->icmp_type);
        }
    }

    return NULL;
}


static inline struct rte_mbuf *pkt_ip4_proc(struct rte_mbuf *buf) {

	struct rte_ipv4_hdr *ip4hdr =  rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
				                                            sizeof(struct rte_ether_hdr));

    if (ip4hdr->dst_addr != g_local_addr) {
        /*
        if (MYNET_DEBUG) {
            struct in_addr addr;
            addr.s_addr = ip4hdr->dst_addr;
            printf("[ test ==> ip4 dst addr('%s')", inet_ntoa(addr));

            addr.s_addr = g_local_addr;
            printf(" not equal local addr('%s'). ]\n", inet_ntoa(addr));
        }
        */
        return NULL;
    }

	if (ip4hdr->next_proto_id == IPPROTO_UDP) {
		return pkt_udp_proc(buf);
	}
	else if (ip4hdr->next_proto_id == IPPROTO_TCP) {
		return pkt_tcp_proc(buf);
	}
    else if (ip4hdr->next_proto_id == IPPROTO_ICMP) {
        return pkt_icmp_proc(buf);
    }
	else {

        if (MYNET_DEBUG) {
    		printf("test ==> pkt_ip4_proc invalid proto, ip4hdr->next_proto_id=%u.\n",
    				rte_be_to_cpu_16(ip4hdr->next_proto_id));
        }
	}

    return NULL;
}


static inline struct rte_mbuf *pkt_ip6_proc(struct rte_mbuf *buf) {

    if (MYNET_DEBUG) {
	    printf("[ test ==> pkt_ip6_proc to do ... ]\n");
    }

    return NULL;
}



static struct rte_mbuf *pkt_arp_proc(struct rte_mbuf *buf) {

    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr*,
                                                            sizeof(struct rte_ether_hdr));
    if (arphdr->arp_data.arp_tip != g_local_addr) {
        /*
        if (MYNET_DEBUG) {
            struct in_addr addr;
            addr.s_addr = arphdr->arp_data.arp_tip;
            printf("[ test ==> arp dst addr('%s')", inet_ntoa(addr));

            addr.s_addr = g_local_addr;
            printf(" not equal local addr('%s').\n ]", inet_ntoa(addr));
        }
        */
        return NULL;
    }

    /**/

    struct arp_table *table = arp_table_instance();
    uint8_t *mac = mynet_get_dstmac(arphdr->arp_data.arp_sip);

    if (mac == NULL) {

        struct arp_entry *entry = rte_malloc("ARP_ENTRY",sizeof(struct arp_entry), 0);
        if (entry == NULL) {
            rte_exit(EXIT_FAILURE, "rte_malloc arp_entry error.\n");
        }

        memset(entry, 0, sizeof(struct arp_entry));

        entry->ip = arphdr->arp_data.arp_sip;
        rte_memcpy(entry->mac, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
        entry->type = ARP_DYNAMIC;

        LL_ADD(entry, table->entries);
        (table->count)++;

    }
    else {

        rte_memcpy(mac, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
    }


    /**/


    if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {

        format_ipv4_arp_pkt(buf, "recv arp request");

        return encap_arp_reply_pkt(buf);
    }
    else if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {

        format_ipv4_arp_pkt(buf, "recv arp reply");
    }
    else {

        if (MYNET_DEBUG) {
            printf("[ test ==> pkt_arp_proc invalid opcode, arphdr->arp_opcode=%u.\n ]",
    				rte_be_to_cpu_16(arphdr->arp_opcode));
        }
    }

    return NULL;

}


static inline struct rte_mbuf *pkt_eth_proc(struct rte_mbuf *buf) {

	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);

	if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		return pkt_ip4_proc(buf);
	}
	else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		return pkt_ip6_proc(buf);
	}
	else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		return pkt_arp_proc(buf);
	}
	else {
        /*
        if (MYNET_DEBUG) {
    		printf("[ test ==> pkt_eth_proc invalid type, ehdr->ether_type=%x.] \n",
    				rte_be_to_cpu_16(ehdr->ether_type));
        }
        */
	}

    return NULL;

}

static void arp_request_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {
#if 0
    uint16_t port;
    int i = 0;
	for (i = 1;i <= 254;i ++) {

		uint32_t dstip = (g_local_addr & 0x00FFFFFF) | (0xFF000000 & (i << 24));

		struct rte_mbuf *arp_req = NULL;
		uint8_t *dstmac = mynet_get_dstmac(dstip);
		if (dstmac == NULL) {
			arp_req = encap_arp_request_pkt(g_default_mac_0, dstip);

		} else {

			arp_req = encap_arp_request_pkt(dstmac, dstip);
		}

        RTE_ETH_FOREACH_DEV(port) {
            rte_eth_tx_burst(port, 0, &arp_req, 1);
        }

        rte_pktmbuf_free(arp_req);

	}
#endif
}



// 处理数据包, in_ring 收包，发送到 socket；从 socket 收包，发送到 out_ring
static int mynet_main(void *arg) {

    struct inout_ring *ring = inout_ring_instance();

    while(1) {

        struct rte_mbuf *rx_bufs[BURST_SIZE];
    	const uint16_t nb_de = rte_ring_sc_dequeue_burst(ring->in, (void**)rx_bufs, BURST_SIZE, NULL);

        uint16_t i = 0;
    	for (i = 0; i < nb_de; i++) {

            struct rte_mbuf *buf = rx_bufs[i];

    		struct rte_mbuf *new_buf = pkt_eth_proc(buf);

            if (new_buf != NULL) {
                rte_ring_sp_enqueue_burst(ring->out, (void**)&new_buf, 1, NULL);
            }
    	}

        struct localhost *host;
        for (host = g_hosts; host != NULL; host = host->next) {

            struct rte_mbuf *new_buf;
            int nb_de = rte_ring_mc_dequeue(host->sendbuf, (void **)&new_buf);
            if (nb_de < 0) continue;

            if (new_buf == NULL) {
                continue;
            }

            encap_socketbuf_ethhdr(new_buf, ring);

        }

        struct tcpstream *stream;
        for (stream = g_streams; stream != NULL; stream = stream->next) {

            struct rte_mbuf *new_buf;
            int nb_de = rte_ring_mc_dequeue(stream->sendbuf, (void **)&new_buf);
            if (nb_de < 0) continue;

            if (new_buf == NULL) {
                continue;
            }

            encap_socketbuf_ethhdr(new_buf, ring);
        }

    }

    return 0;
}

// 从 port 收包入队到 in_ring ，从 out_ring 出队由 port 发包
static int work_main(void) {
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port) {
		if (rte_eth_dev_socket_id(port) >= 0 &&
			rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {

			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);
		}

	}

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

	/* Main work of application loop. 8< */
    struct inout_ring *ring = inout_ring_instance();
	for (;;) {
		/*
		 * Receive packets on a port and reply from the same port
		 */
		RTE_ETH_FOREACH_DEV(port) {

            // rx
			struct rte_mbuf *rx_bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, rx_bufs, BURST_SIZE);
            if (nb_rx > 0) {
    			const uint16_t nb_en = rte_ring_sp_enqueue_burst(ring->in, (void **)rx_bufs, nb_rx, NULL);

                if (unlikely(nb_en < nb_rx)) {
                    uint16_t q;
                    for (q = nb_en; q < nb_rx; q++) {
                        rte_pktmbuf_free(rx_bufs[q]);
                    }
                }
            }

            // tx
            struct rte_mbuf *tx_bufs[BURST_SIZE];
    		const uint16_t nb_de = rte_ring_sc_dequeue_burst(ring->out, (void**)tx_bufs, BURST_SIZE, NULL);
    		if (nb_de > 0) {
    			rte_eth_tx_burst(port, 0, tx_bufs, nb_de);

    			uint16_t i = 0;
    			for (i = 0;i < nb_de;i ++) {
    				rte_pktmbuf_free(tx_bufs[i]);
    			}
    		}
		}

        // 定时触发，查询 arp table
        static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
	/* >8 End of loop. */
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
	unsigned nb_ports;
	uint16_t portid;
    uint16_t lcore_id;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 1) {
		rte_exit(EXIT_FAILURE, "Error: number of ports invalid, nb_ports=%d\n", nb_ports);
    }

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	g_mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (g_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, g_mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
        }
    }
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() < 4) {
		rte_exit(EXIT_FAILURE, "\nWARNING: lack lcores, at least 4 needed.\n");
    }

    /* arp table start */
    rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_cb, NULL);
    /* arp table end */

    /*ring init*/
    struct inout_ring *ring = inout_ring_instance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
    /* end of init ring*/

    /* get pkt from port */
    lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
    rte_eal_remote_launch(mynet_main, NULL, lcore_id);
    /* end  */

    /* udp server*/
    lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
    rte_eal_remote_launch(udp_server_main, NULL, lcore_id);
    /* */

    /* tcp server*/
    lcore_id = rte_get_next_lcore(lcore_id, 1, 1);
    rte_eal_remote_launch(tcp_server_main, NULL, lcore_id);
    /* */

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	work_main();
	/* >8 End of called on single lcore. */

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
