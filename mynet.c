/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

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

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define SEND_UDP 1

struct rte_mempool *g_mbuf_pool;


/* basicfwd.c: Basic DPDK skeleton forwarding example. */

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
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

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

static void format_ip4_hdr(struct rte_ipv4_hdr *ip4hdr) {

	struct in_addr addr;
	addr.s_addr = ip4hdr->src_addr;
	printf("[ %s -> ", inet_ntoa(addr));

	addr.s_addr = ip4hdr->dst_addr;
	printf("%s ]\n", inet_ntoa(addr));

}

static void format_udp_hdr(struct rte_udp_hdr *udphdr) {

	printf("[ %u -> %u ]\n", rte_be_to_cpu_16(udphdr->src_port), rte_be_to_cpu_16(udphdr->dst_port));
	printf("[ length = %u, %s ]\n", rte_be_to_cpu_16(udphdr->dgram_len), (char *)(udphdr + 1));

}

static void format_ipv4_udp_pkt(struct rte_mbuf *buf) {

    struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
    struct rte_ipv4_hdr *ip4hdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(ip4hdr + 1);

    format_eth_hdr(ethhdr);
    format_ip4_hdr(ip4hdr);
    format_udp_hdr(udphdr);

}

static int encap_pkt_ethhdr(struct rte_mbuf *buf, struct rte_mbuf *new_buf) {

	struct rte_ether_hdr *eth =  rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);
	struct rte_ether_hdr *new_eth =  rte_pktmbuf_mtod(new_buf, struct rte_ether_hdr*);
	rte_memcpy(&new_eth->src_addr, &eth->dst_addr, sizeof(new_eth->src_addr));
	rte_memcpy(&new_eth->dst_addr, &eth->src_addr, sizeof(new_eth->dst_addr));
	rte_memcpy(&new_eth->ether_type, &eth->ether_type, sizeof(new_eth->ether_type));

	return 0;
}


static int encap_pkt_ip4hdr(struct rte_mbuf *buf, struct rte_mbuf *new_buf, uint16_t len) {

	struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));
	struct rte_ipv4_hdr *new_ip = rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));
	new_ip->version_ihl = 0x45;
	new_ip->type_of_service = 0;
	new_ip->total_length = htons(len + sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr));
	new_ip->packet_id = 0;
	new_ip->fragment_offset = 0;
	new_ip->time_to_live = 64; // ttl = 64
	new_ip->next_proto_id = IPPROTO_UDP;
	new_ip->hdr_checksum = 0;
	rte_memcpy(&new_ip->src_addr, &ip->dst_addr, sizeof(new_ip->src_addr));
	rte_memcpy(&new_ip->dst_addr, &ip->src_addr, sizeof(new_ip->src_addr));

	new_ip->hdr_checksum = rte_ipv4_cksum(new_ip);

	return 0;

}

static int encap_pkt_udphdr(struct rte_mbuf *buf, struct rte_mbuf *new_buf,
                                    uint8_t *data, uint16_t len) {

	struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(buf, struct rte_udp_hdr *,
                                        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	struct rte_udp_hdr *new_udp = rte_pktmbuf_mtod_offset(new_buf, struct rte_udp_hdr *,
                                        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    struct rte_ipv4_hdr *new_ip = rte_pktmbuf_mtod_offset(new_buf, struct rte_ipv4_hdr *,
                                                        sizeof(struct rte_ether_hdr));
	rte_memcpy(&new_udp->src_port, &udp->dst_port, sizeof(new_udp->src_port));
	rte_memcpy(&new_udp->dst_port, &udp->src_port, sizeof(new_udp->dst_port));
	new_udp->dgram_len = htons(len + sizeof(struct rte_udp_hdr));
	new_udp->dgram_cksum = 0;

	rte_memcpy((uint8_t*)(new_udp + 1), data, len);

	new_udp->dgram_cksum = rte_ipv4_udptcp_cksum(new_ip, new_udp);

	return 0;

}

static int encap_pkt_tcpphdr() {

    printf("test ==> encap_pkt_tcpphdr to do ...\n");
	return 0;
}

static struct rte_mbuf *encap_udp_reply_pkt(struct rte_mbuf *buf) {

    uint8_t *data;
    uint16_t length;
    uint16_t total_len;
    struct rte_udp_hdr *udphdr = rte_pktmbuf_mtod_offset(buf, struct rte_udp_hdr *,
                                        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

	struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
	if (new_buf == NULL) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc udp buf error.\n");
	}


    data = (uint8_t *)(udphdr + 1);
    length = rte_be_to_cpu_16(udphdr->dgram_len) - sizeof(struct rte_udp_hdr);
	total_len = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
	                        + sizeof(struct rte_udp_hdr);

	new_buf->pkt_len = total_len;
	new_buf->data_len = total_len;

	encap_pkt_ethhdr(buf, new_buf);
    encap_pkt_ip4hdr(buf, new_buf, length);
    encap_pkt_udphdr(buf, new_buf, data, length);

    format_ipv4_udp_pkt(new_buf);

    return new_buf;

}

static struct rte_mbuf *pkt_udp_proc(struct rte_mbuf *buf) {

	format_ipv4_udp_pkt(buf);

    if (SEND_UDP) {
        return encap_udp_reply_pkt(buf);
    }

    return NULL;
}

static struct rte_mbuf *pkt_tcp_proc(struct rte_mbuf *buf) {

	printf("test ==> pkt_tcp_proc to do ...\n");

    return NULL;
}

static struct rte_mbuf *pkt_ip4_proc(struct rte_mbuf *buf) {

	struct rte_ipv4_hdr *ip4hdr =  rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
    if (ip4hdr->dst_addr != MAKE_IPV4_ADDR(10, 66, 24, 22)) {
        return NULL;
    }

	if (ip4hdr->next_proto_id == IPPROTO_UDP) {
		return pkt_udp_proc(buf);
	}
	else if (ip4hdr->next_proto_id == IPPROTO_TCP) {
		return pkt_tcp_proc(buf);
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

static struct rte_mbuf *pkt_eth_proc(struct rte_mbuf *buf) {

	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr*);

	if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		return pkt_ip4_proc(buf);
	}
	else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		return pkt_ip6_proc(buf);
	}
	else {
		printf("test ==> pkt_eth_proc invalid type, ehdr->ether_type=%x.\n",
				rte_be_to_cpu_16(ehdr->ether_type));
	}

    return NULL;

}

static void pkts_proc(uint16_t nb_rx, struct rte_mbuf *bufs[], uint16_t port) {

	unsigned i = 0;
	for (i = 0; i < nb_rx; i++) {

		struct rte_mbuf *new_buf = pkt_eth_proc(bufs[i]);

        if (new_buf != NULL) {
            rte_eth_tx_burst(port, 0, &new_buf, 1);
            rte_pktmbuf_free(new_buf);
        }
	}

}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* mynet application lcore. 8< */
static __rte_noreturn void
mynet_main(void)
{
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
	for (;;) {
		/*
		 * Receive packets on a port and reply from the same port
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			pkts_proc(nb_rx, bufs, port);

			uint16_t i;
			for (i = 0; i < nb_rx; i++) {
				rte_pktmbuf_free(bufs[i]);
			}

		}
	}
	/* >8 End of loop. */
}
/* >8 End mynet application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
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

	if (rte_lcore_count() > 1) {
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    }

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	mynet_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
