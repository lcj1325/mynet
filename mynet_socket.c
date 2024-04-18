





#include "mynet_socket.h"
#include "mynet.h"


int g_socket_fd = 3;
struct localhost *g_hosts = NULL;

static inline int mynet_getfd() {

    int fd = g_socket_fd;
    if (fd > MAX_FD_NUM) {
        return -1;
    }
    g_socket_fd++;
    return fd;
}

struct localhost *mynet_gethost_from_fd(int sockfd) {

    struct localhost *host;
    for (host = g_hosts; host != NULL; host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}

	}

    return NULL;
}

struct localhost *mynet_gethost_from_app(uint32_t addr, uint16_t port, uint8_t proto) {

    struct localhost *host;
    for (host = g_hosts; host != NULL; host = host->next) {

        if (host->localip == addr && host->localport == port && host->protocol == proto) {
            return host;
        }

    }

    return NULL;

}


int mynet_socket(__attribute__((unused)) int domain, int type, int protocol) {

    int fd = mynet_getfd();
    if (fd < 0) {
        return -1;
    }

    struct localhost *host = rte_malloc("HOST", sizeof(struct localhost), 0);
    if (host == NULL) {
        return -1;
    }

    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    if (type == SOCK_DGRAM) {
        host->protocol = IPPROTO_UDP;
    }

    host->recvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (host->recvbuf == NULL) {

		rte_free(host);
		return -1;
	}


	host->sendbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (host->sendbuf == NULL) {

		rte_ring_free(host->recvbuf);

		rte_free(host);
		return -1;
	}

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    LL_ADD(host, g_hosts);

    return fd;

}

int mynet_bind(int sockfd, const struct sockaddr *addr , __attribute__((unused)) socklen_t addrlen) {

	struct localhost *host =  mynet_gethost_from_fd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
	host->localport = laddr->sin_port;
	rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));

	return 0;

}

ssize_t mynet_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))int flags,
        struct sockaddr *src_addr, __attribute__((unused))socklen_t *addrlen) {

    struct localhost *host =  mynet_gethost_from_fd(sockfd);
    if (host == NULL) return -1;

    struct rte_mbuf *rx_buf = NULL;

    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;

    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->recvbuf, (void **)&rx_buf)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    if (rx_buf == NULL) {
        return -1;
    }


    struct rte_ether_hdr *eth =  rte_pktmbuf_mtod(rx_buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 =  (struct rte_ipv4_hdr *)(eth + 1);
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip4 + 1);
    uint16_t udp_len = rte_be_to_cpu_16(udp->dgram_len);
    uint8_t *data = (uint8_t *)(udp + 1);
    uint16_t data_len = udp_len - sizeof(struct rte_udp_hdr);

    saddr->sin_port = udp->src_port;
    rte_memcpy(&saddr->sin_addr.s_addr, &ip4->src_addr, sizeof(uint32_t));

    if (len < data_len) {

        rte_memcpy(buf, data, len);

        // rte_memcpy(data, data + len, data_len - len);
        int i;
        for (int i = 0; i < data_len - len; i++) {
            data[i] = data[i + len];
        }

        udp->dgram_len = rte_cpu_to_be_16(data_len - len + sizeof(struct rte_udp_hdr));

        rte_ring_mp_enqueue(host->recvbuf, rx_buf);

        return len;

    } else {

        rte_memcpy(buf, data, data_len);

        rte_pktmbuf_free(rx_buf);

        return data_len;
    }

}

ssize_t mynet_sendto(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) {

    struct localhost *host =  mynet_gethost_from_fd(sockfd);
    if (host == NULL) return -1;

    const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {

        if (MYNET_DEBUG) {
            printf("[ test ==> rte_pktmbuf_alloc udp send buf error. ]\n");
        }
        return -1;
    }

    uint16_t udp_len = len + sizeof(struct rte_udp_hdr);
    uint16_t ip4_len = udp_len + sizeof(struct rte_ipv4_hdr);
    uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);

	new_buf->pkt_len = eth_len;
	new_buf->data_len = eth_len;

    // eth
    // sokcet do it

    // ip4
    struct ip4hdr_info ip4info;
    memset(&ip4info, 0, sizeof(ip4info));

    rte_memcpy(&ip4info.dst_addr, &daddr->sin_addr.s_addr, sizeof(uint32_t));
    ip4info.next_proto_id = IPPROTO_UDP;
    ip4info.total_length = rte_cpu_to_be_16(ip4_len);

    encap_pkt_ip4hdr(new_buf, &ip4info);

    // udp
    struct udphdr_info udpinfo;
    memset(&udpinfo, 0, sizeof(udpinfo));

    udpinfo.src_port = host->localport;
    udpinfo.dst_port = daddr->sin_port;
    udpinfo.data = (uint8_t *)(buf);
    udpinfo.data_len = len;

    encap_pkt_udphdr(new_buf, &udpinfo);


    rte_ring_mp_enqueue(host->sendbuf, new_buf);

    return len;

}

int mynet_close(int fd) {

    struct localhost *host =  mynet_gethost_from_fd(fd);
    if (host == NULL) return -1;

    LL_REMOVE(host, g_hosts);

    if (host->recvbuf) {
        rte_ring_free(host->recvbuf);
        host->recvbuf = NULL;
    }

    if (host->sendbuf) {
        rte_ring_free(host->sendbuf);
        host->sendbuf = NULL;
    }

    rte_free(host);

    LL_REMOVE(host, g_hosts);

    return 0;
}


int udp_server_main(__attribute__((unused))  void *arg) {

    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    char buffer[BUFFER_SIZE];
    socklen_t len;

    // 创建UDP套接字
    if ((sockfd = mynet_socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        rte_exit(EXIT_FAILURE, "socket creation failed.\n");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // 设置服务器地址
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(BIND_ADDR);
    servaddr.sin_port = htons(BIND_PORT);

    // 将套接字绑定到服务器地址
    if (mynet_bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        rte_exit(EXIT_FAILURE, "bind failed.\n");
    }

    while (1) {
        // 接收数据
        int n = mynet_recvfrom(sockfd, (char *)buffer, BUFFER_SIZE, MSG_WAITALL,
                                (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';

        printf("[ Client : %s ]\n", buffer);

        // 发送回应给客户端
        mynet_sendto(sockfd, (const char *)buffer, strlen(buffer), MSG_CONFIRM,
                        (const struct sockaddr *)&cliaddr, len);
        printf("[ Message sent. ]\n");
    }

    mynet_close(sockfd);

    return 0;
}


int tcp_server_main(__attribute__((unused))  void *arg) {



}








