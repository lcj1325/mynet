/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */



#include "arp.h"
#include "ring.h"
#include "mynet.h"



static struct rte_mempool *g_mbuf_pool;
static uint32_t g_local_addr = MAKE_IPV4_ADDR(10, 66, 24, 22);
static struct rte_ether_addr g_local_mac;
uint8_t g_default_mac_0[RTE_ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t g_default_mac_1[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


/* basicfwd.c: Basic DPDK skeleton forwarding example. */

// 计算校验和的函数
static uint16_t mynet_icmp_checksum(void *addr, int len) {
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
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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

static void format_eth_hdr(struct rte_ether_hdr *ethhdr) {

	printf("[ "
            "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			" -> "
			"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			" ]\n",
			RTE_ETHER_ADDR_BYTES(&ethhdr->src_addr),
			RTE_ETHER_ADDR_BYTES(&ethhdr->dst_addr));

}

static void format_arp_hdr(struct rte_arp_hdr *arphdr) {

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

static void format_ip4_hdr(struct rte_ipv4_hdr *ip4hdr) {

	struct in_addr addr;
	addr.s_addr = ip4hdr->src_addr;
	printf("[ %s -> ", inet_ntoa(addr));

	addr.s_addr = ip4hdr->dst_addr;
	printf("%s ]\n", inet_ntoa(addr));

}

static void format_udp_hdr(struct rte_udp_hdr *udphdr) {

    uint16_t length = ntohs(udphdr->dgram_len);
    *((char*)udphdr + length) = '\0';

	printf("[ %u -> %u ]\n", rte_be_to_cpu_16(udphdr->src_port), rte_be_to_cpu_16(udphdr->dst_port));
	printf("[ length = %u, %s ]\n", rte_be_to_cpu_16(udphdr->dgram_len), (char *)(udphdr + 1));

}

static void format_icmp_hdr(struct rte_icmp_hdr *icmphdr) {

    printf("[ ident:%u, seq_nb:%u ]\n",
            rte_be_to_cpu_16(icmphdr->icmp_ident),
            rte_be_to_cpu_16(icmphdr->icmp_seq_nb));
}


static void format_ipv4_udp_pkt(struct rte_mbuf *buf, const char *msg) {

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(ip4hdr + 1);

    printf("\n  %s:\n", msg);
    format_eth_hdr(ethhdr);
    format_ip4_hdr(ip4hdr);
    format_udp_hdr(udphdr);

}

static void  format_ipv4_icmp_pkt(struct rte_mbuf *buf, const char *msg){

    printf("\n  %s:\n", msg);
    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(ip4hdr + 1);

    format_eth_hdr(ethhdr);
    format_ip4_hdr(ip4hdr);
    format_icmp_hdr(icmphdr);
}


static void format_ipv4_arp_pkt(struct rte_mbuf *buf, const char *msg) {

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethhdr + 1);

    printf("\n  %s:\n", msg);
    format_eth_hdr(ethhdr);
    format_arp_hdr(arphdr);
}


static int encap_pkt_ethhdr(struct rte_mbuf *new_buf, struct ethhdr_info *ethinfo) {

	struct rte_ether_hdr *new_eth =  rte_pktmbuf_mtod(new_buf, struct rte_ether_hdr*);

	rte_memcpy(&new_eth->src_addr, &g_local_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(new_eth->dst_addr.addr_bytes, ethinfo->dst_addr, RTE_ETHER_ADDR_LEN);
	new_eth->ether_type = ethinfo->ether_type;

	return 0;
}


static int encap_pkt_arphdr(struct rte_mbuf *new_buf, struct arphdr_info *arpinfo) {

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



static int encap_pkt_ip4hdr(struct rte_mbuf *new_buf, struct ip4hdr_info *ip4info) {

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

static int encap_pkt_udphdr(struct rte_mbuf *new_buf, struct udphdr_info *udpinfo) {

	struct rte_udp_hdr *new_udp = rte_pktmbuf_mtod_offset(new_buf, struct rte_udp_hdr *,
                                        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    struct rte_ipv4_hdr *new_ip = rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));

	new_udp->src_port = udpinfo->src_port;
    new_udp->dst_port = udpinfo->dst_port;
	new_udp->dgram_len = udpinfo->dgram_len;
	new_udp->dgram_cksum = 0;
	rte_memcpy((uint8_t*)(new_udp + 1), udpinfo->data, udpinfo->data_len);

	new_udp->dgram_cksum = rte_ipv4_udptcp_cksum(new_ip, new_udp);

	return 0;

}

static int encap_pkt_tcpphdr(struct rte_mbuf *new_buf, struct tcphdr_info *tcpinfo) {

    printf("test ==> encap_pkt_tcpphdr to do ...\n");

	return 0;
}

static int encap_pkt_icmphdr(struct rte_mbuf *new_buf, struct icmphdr_info *icmpinfo) {

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

static struct rte_mbuf *encap_arp_request_pkt(uint8_t *dstmac, uint32_t dstip) {

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc arp buf error.\n");
    }

    //eth
    struct ethhdr_info ethinfo;
    memset(&ethinfo, 0, sizeof(ethinfo));

    if (memcmp(dstmac, g_default_mac_0, RTE_ETHER_ADDR_LEN)) {
        ethinfo.dst_addr = dstmac;
    }
    else {
        ethinfo.dst_addr = g_default_mac_1;
    }
    ethinfo.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    encap_pkt_ethhdr(new_buf, &ethinfo);

    //arp
    struct arphdr_info arpinfo;
    memset(&arpinfo, 0, sizeof(arpinfo));

    arpinfo.arp_tha = dstmac;
    arpinfo.arp_tip = dstip;
    arpinfo.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    encap_pkt_arphdr(new_buf, &arpinfo);

    format_ipv4_arp_pkt(new_buf, "send arp request");

    return new_buf;
}


static struct rte_mbuf *encap_arp_reply_pkt(struct rte_mbuf *buf) {

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc arp buf error.\n");
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

static struct rte_mbuf *encap_udp_reply_pkt(struct rte_mbuf *buf) {


    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
	if (new_buf == NULL) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc udp buf error.\n");
	}

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(ip4hdr + 1);

    uint16_t udp_len = rte_be_to_cpu_16(udphdr->dgram_len);
    uint16_t ip4_len = udp_len + sizeof(struct rte_ipv4_hdr);
    uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);

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

    // udp
    struct udphdr_info udpinfo;
    memset(&udpinfo, 0, sizeof(udpinfo));

    udpinfo.src_port = udphdr->dst_port;
    udpinfo.dst_port = udphdr->src_port;
    udpinfo.dgram_len = udphdr->dgram_len;
    udpinfo.data = (uint8_t *)(udphdr + 1);
    udpinfo.data_len = udp_len - sizeof(struct rte_udp_hdr);

    encap_pkt_udphdr(new_buf, &udpinfo);

    format_ipv4_udp_pkt(new_buf, "reply udp pkt");

    return new_buf;

}

static struct rte_mbuf *encap_icmp_reply_pkt(struct rte_mbuf *buf) {

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

    format_ipv4_icmp_pkt(new_buf, "reply icmp");

    return new_buf;
}


static struct rte_mbuf *pkt_udp_proc(struct rte_mbuf *buf) {

	format_ipv4_udp_pkt(buf, "recv udp pkt");

    if (SEND_UDP) {
        return encap_udp_reply_pkt(buf);
    }

    return NULL;
}

static struct rte_mbuf *pkt_tcp_proc(struct rte_mbuf *buf) {

	printf("test ==> pkt_tcp_proc to do ...\n");

    return NULL;
}

static struct rte_mbuf *pkt_icmp_proc(struct rte_mbuf *buf) {

    struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(buf, struct rte_icmp_hdr *,
                                        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
        printf("test ==> pkt_icmp_proc invalid type, icmp->icmp_type=%u.\n", icmp->icmp_type);
        return NULL;
    }

	format_ipv4_icmp_pkt(buf, "recv icmp request");

    if(SEND_ICMP) {
        return encap_icmp_reply_pkt(buf);
    }

    return NULL;
}


static struct rte_mbuf *pkt_ip4_proc(struct rte_mbuf *buf) {

	struct rte_ipv4_hdr *ip4hdr =  rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
    if (ip4hdr->dst_addr != g_local_addr) {
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
		printf("test ==> pkt_ip4_proc invalid proto, ip4hdr->next_proto_id=%u.\n",
				rte_be_to_cpu_16(ip4hdr->next_proto_id));
	}

    return NULL;
}

static struct rte_mbuf *pkt_ip6_proc(struct rte_mbuf *buf) {

	printf("test ==> pkt_ip6_proc to do ...\n");
    return NULL;
}



static struct rte_mbuf *pkt_arp_proc(struct rte_mbuf *buf) {

    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr*,
                                                            sizeof(struct rte_ether_hdr));

    if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {

        if (arphdr->arp_data.arp_tip != g_local_addr) {
            return NULL;
        }

        format_ipv4_arp_pkt(buf, "recv arp request");

        if (SEND_ARP) {
            return encap_arp_reply_pkt(buf);
        }
    }
    else if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {

        format_ipv4_arp_pkt(buf, "recv arp reply");

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



    }

    return NULL;

}


static struct rte_mbuf *pkt_eth_proc(struct rte_mbuf *buf) {

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
		printf("test ==> pkt_eth_proc invalid type, ehdr->ether_type=%x.\n",
				rte_be_to_cpu_16(ehdr->ether_type));
	}

    return NULL;

}

static inline void pkts_proc(const uint16_t nb_rx, struct rte_mbuf *bufs[]) {

    struct inout_ring *ring = inout_ring_instance();

	uint16_t i = 0;
	for (i = 0; i < nb_rx; i++) {

		struct rte_mbuf *new_buf = pkt_eth_proc(bufs[i]);

        if (new_buf != NULL) {
            rte_ring_mp_enqueue_burst(ring->out, (void**)&new_buf, 1, NULL);
        }

        rte_pktmbuf_free(bufs[i]);
	}

}

static void arp_request_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {

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
            // rte_eth_tx_burst(port, 0, &arp_req, 1);
        }

        rte_pktmbuf_free(arp_req);

	}



}


 static int mynet_main(void) {

    struct inout_ring *ring = inout_ring_instance();

    while(1) {

        struct rte_mbuf *rx_bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void**)rx_bufs, BURST_SIZE, NULL);

        pkts_proc(nb_rx, rx_bufs);

    }

    return 0;
 }



 /* mynet application lcore. 8< */

static int work_main(void *arg) {
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
    struct inout_ring *ring = inout_ring_instance();

	/* Main work of application loop. 8< */
	for (;;) {
		/*
		 * Receive packets on a port and reply from the same port
		 */
		RTE_ETH_FOREACH_DEV(port) {

            // rx
			struct rte_mbuf *rx_bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, rx_bufs, BURST_SIZE);
			rte_ring_sp_enqueue_burst(ring->in, (void **)rx_bufs, nb_rx, NULL);


            // tx
            struct rte_mbuf *tx_bufs[BURST_SIZE];
    		const uint16_t nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx_bufs, BURST_SIZE, NULL);
    		if (nb_tx > 0) {
    			rte_eth_tx_burst(port, 0, tx_bufs, nb_tx);

    			uint16_t i = 0;
    			for (i = 0;i < nb_tx;i ++) {
    				rte_pktmbuf_free(tx_bufs[i]);
    			}

    		}

		}

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
/* >8 End mynet application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
	unsigned nb_ports;
	uint16_t portid;

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

	if (rte_lcore_count() < 2) {
		rte_exit(EXIT_FAILURE, "\nWARNING: lack lcores, at least 2 needed.\n");
    }

    /* arp table start */
    rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
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

    rte_eal_remote_launch(work_main, NULL, rte_get_next_lcore(lcore_id, 1, 0));

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	mynet_main();
	/* >8 End of called on single lcore. */

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
