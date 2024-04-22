





#include "mynet_socket.h"
#include "mynet.h"


static int g_socket_fd = DEFAULT_FD_NUM;

struct udp_dgram *g_dgrams = NULL;
struct tcp_stream *g_streams = NULL;


static inline int mynet_getfd() {

    int fd = g_socket_fd;
    if (fd > MAX_FD_NUM) {
        return -1;
    }
    g_socket_fd++;
    return fd;
}

struct udp_dgram *mynet_getdgram_from_fd(int sockfd) {

    struct udp_dgram *dgram;
    for (dgram = g_udptable; dgram != NULL; dgram = dgram->next) {

		if (sockfd == dgram->fd) {
			return dgram;
		}

	}

    mynet_debug("get dgram nil");
    return NULL;
}

struct udp_dgram *mynet_getdgram_from_ipport(uint32_t ip, uint16_t port) {

    struct udp_dgram *dgram;
    for (dgram = g_udptable; dgram != NULL; dgram = dgram->next) {

		if (ip == dgram->localip && port == dgram->localport) {
			return dgram;
		}

	}

    mynet_debug("get dgram nil");
    return NULL;
}


struct tcp_stream *mynet_getstream_from_fd(int sockfd) {

    struct tcp_stream *stream;
    for (stream = g_tcptable; stream != NULL; stream = stream->next) {

		if (sockfd == stream->fd) {
			return stream;
		}

	}

    mynet_debug("get stream nil");
    return NULL;

}


struct tcp_stream *mynet_getstream_from_ipport(uint32_t sip, uint32_t dip,
                                                           uint16_t sport, uint16_t dport) {

	struct tcp_stream *stream;
	for (stream = g_tcptable; stream != NULL; stream = stream->next) { // client

		if (stream->sip == sip && stream->dip == dip &&
			stream->sport == sport && stream->dport == dport) {
			return stream;
		}

	}

	for (stream = g_tcptable; stream != NULL; stream = stream->next) {

		if (stream->status == TCP_STATUS_LISTEN && stream->dip == dip && stream->dport == dport) { // server
			return stream;
		}

	}

    mynet_debug("get stream nil");
	return NULL;

}

static inline struct udp_dgram *dgram_create(int fd) {

    struct udp_dgram *dgram = rte_malloc("DGRAM", sizeof(struct udp_dgram), 0);
    if (dgram == NULL) {
        mynet_debug("rte_malloc dgram error.");
        return NULL;
    }

    memset(dgram, 0, sizeof(struct udp_dgram));

    dgram->fd = fd;

    dgram->recvbuf = rte_ring_create("RECV_BUF", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (dgram->recvbuf == NULL) {
        mynet_debug("rte_ring_create dgram recv ring error.");
        rte_free(dgram);
        return NULL;
    }

    dgram->sendbuf = rte_ring_create("SEND_BUF", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (dgram->sendbuf == NULL) {
        mynet_debug("rte_ring_create dgram send ring error.");
        rte_ring_free(dgram->recvbuf);
        rte_free(dgram);
        return NULL;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&dgram->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&dgram->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    return dgram;
}

static struct tcp_stream *stream_create(int fd){

    struct tcp_stream *stream = rte_malloc("STREAM", sizeof(struct tcp_stream), 0);
    if (stream == NULL) {
        mynet_debug("rte_malloc stream error.");
        return NULL;
    }

    memset(stream, 0, sizeof(struct tcp_stream));

    stream->fd = fd;

    stream->recvbuf = rte_ring_create("RECV_BUF", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stream->recvbuf == NULL) {
        mynet_debug("rte_ring_create stream recv ring error.");
        rte_free(stream);
        return NULL;
    }

    stream->sendbuf = rte_ring_create("SEND_BUF", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stream->sendbuf == NULL) {
        mynet_debug("rte_ring_create stream send ring error.");
        rte_ring_free(stream->recvbuf);
        rte_free(stream);
        return NULL;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    return stream;

}

int mynet_socket(__attribute__((unused))int domain, int type, int protocol) {

    int fd = mynet_getfd();
    if (fd < 0) {
        return -1;
    }

    if (type == SOCK_DGRAM) {

        struct udp_dgram *dgram = dgram_create(fd);
        if (dgram == NULL) {
            return -1;
        }
        LL_ADD(dgram, g_dgrams);
    }
    else if (type == SOCK_STREAM) {

        struct tcp_stream *stream = stream_create(fd);
        if (stream == NULL) {
            return -1;
        }
        LL_ADD(stream, g_streams);
    }
    else {

        return -1;
    }

    return fd;

}

int mynet_bind(int sockfd, const struct sockaddr *addr , __attribute__((unused))socklen_t addrlen) {

	struct udp_dgram *dgram =  mynet_getdgram_from_fd(sockfd);
    struct tcp_stream *stream =  mynet_getstream_from_fd(sockfd);
    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;

	if (dgram != NULL) {
        dgram->localport = laddr->sin_port;
	    rte_memcpy(&dgram->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    }
    else if (stream != NULL) {
        stream->dport = laddr->sin_port;
	    rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        stream->status = TCP_STATUS_CLOSED
    }
    else {
        return -1;
    }

	return 0;

}

int mynet_listen(int sockfd, __attribute__((unused))int backlog) {

	struct tcp_stream *stream =  mynet_getstream_from_fd(sockfd);
	if (stream == NULL) {
        return -1;
    }

    stream->status = TCP_STATUS_LISTEN;

    return 0;

}

static inline struct tcp_stream *accept_get_new_stream(uint32_t dip, uint16_t dport){

    struct tcp_stream *stream;
    for (stream = g_streams; stream != NULL; stream = stream->next) {
        if (stream->fd == -1 && stream->dip == dip && stream->dport == dport) {
            return stream;
        }
    }

    return NULL;
}

int mynet_accept(int sockfd, struct sockaddr *addr, __attribute__((unused))socklen_t *addrlen) {

	struct tcp_stream *stream =  mynet_getstream_from_fd(sockfd);
	if (stream == NULL) {
        return -1;
    }

	struct tcp_stream *new_stream;

	pthread_mutex_lock(&stream->mutex);
	while((new_stream = accept_get_new_stream(stream->dip, stream->dport)) == NULL) {
		pthread_cond_wait(&stream->cond, &stream->mutex);
	}
	pthread_mutex_unlock(&stream->mutex);

    int fd = mynet_getfd();
    if (fd < 0) {
        return -1;
    }

	new_stream->fd = fd;

    // 填充客户端 ip 和 port
	struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
	saddr->sin_port = new_stream->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &new_stream->sip, sizeof(uint32_t));

	return new_stream->fd;

}


ssize_t mynet_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))int flags,
                            struct sockaddr *src_addr, __attribute__((unused))socklen_t *addrlen) {

    struct udp_dgram *dgram =  mynet_getdgram_from_fd(sockfd);
    if (dgram == NULL) {
        return -1;
    }

    struct rte_mbuf *rx_buf = NULL;
    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;

    int nb = -1;
    pthread_mutex_lock(&dgram->mutex);
    while ((nb = rte_ring_mc_dequeue(dgram->recvbuf, (void **)&rx_buf)) < 0) {
        pthread_cond_wait(&dgram->cond, &dgram->mutex);
    }
    pthread_mutex_unlock(&dgram->mutex);

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

        rte_ring_mp_enqueue(dgram->recvbuf, rx_buf);

        return len;

    } else {

        rte_memcpy(buf, data, data_len);

        rte_pktmbuf_free(rx_buf);

        return data_len;
    }

}


ssize_t mynet_recv(int sockfd, void *buf, size_t len, __attribute__((unused))int flags) {

    struct tcp_stream *stream =  mynet_getstream_from_fd(sockfd);
    if (stream == NULL) {
        return -1;
    }

    struct rte_mbuf *rx_buf = NULL;

    int nb = -1;
    pthread_mutex_lock(&stream->mutex);
    while ((nb = rte_ring_mc_dequeue(stream->recvbuf, (void **)&rx_buf)) < 0) {
        pthread_cond_wait(&stream->cond, &stream->mutex);
    }
    pthread_mutex_unlock(&stream->mutex);

    if (rx_buf == NULL) {
        return -1;
    }

    struct rte_ether_hdr *eth =  rte_pktmbuf_mtod(rx_buf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip4 =  (struct rte_ipv4_hdr *)(eth + 1);
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip4 + 1);
    uint16_t ip4_len = rte_be_to_cpu_16(ip4->total_length);
    uint16_t tcp_len = ip4_len - sizeof(struct rte_ipv4_hdr);
    uint8_t *data = (uint8_t *)(tcp + 1);
    uint8_t tcphdr_len = tcp->data_off >> 4;
    uint16_t data_len = tcp_len - tcphdr_len * 4;

    saddr->sin_port = tcp->src_port;
    rte_memcpy(&saddr->sin_addr.s_addr, &ip4->src_addr, sizeof(uint32_t));

    if (len < data_len) {

        rte_memcpy(buf, data, len);

        // rte_memcpy(data, data + len, data_len - len);
        int i;
        for (int i = 0; i < data_len - len; i++) {
            data[i] = data[i + len];
        }

        ip4->total_length = rte_cpu_to_be_16(data_len - len + tcphdr_len * 4
                                                + sizeof(struct rte_ipv4_hdr));

        rte_ring_mp_enqueue(stream->recvbuf, rx_buf);

        return len;

    } else {

        rte_memcpy(buf, data, data_len);

        rte_pktmbuf_free(rx_buf);

        return data_len;
    }

}


ssize_t mynet_sendto(int sockfd, const void *buf, size_t len, int flags,
                     const struct sockaddr *dest_addr, __attribute__((unused))socklen_t addrlen) {

    struct udp_dgram *dgram =  mynet_getdgram_from_fd(sockfd);
    if (dgram == NULL) {
        return -1;
    }

    const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

    struct rte_mbuf *udpbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (udpbuf == NULL) {
        mynet_debug("rte_pktmbuf_alloc udp send buf error.");
        return -1;
    }

    uint16_t udp_len = len + sizeof(struct rte_udp_hdr);
    uint16_t ip4_len = udp_len + sizeof(struct rte_ipv4_hdr);
    uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);

	udpbuf->pkt_len = eth_len;
	udpbuf->data_len = eth_len;

    // encap eth
    // mynet_main do it

    // encap ip4
    struct ip4hdr_info ip4info;

    rte_memcpy(&ip4info.dst_addr, &daddr->sin_addr.s_addr, sizeof(uint32_t));
    ip4info.next_proto_id = IPPROTO_UDP;
    ip4info.total_length = rte_cpu_to_be_16(ip4_len);

    encap_pkt_ip4hdr(udpbuf, &ip4info);

    // udp
    struct udphdr_info udpinfo;
    memset(&udpinfo, 0, sizeof(udpinfo));

    udpinfo.src_port = dgram->localport;
    udpinfo.dst_port = daddr->sin_port;
    udpinfo.data = (uint8_t *)(buf);
    udpinfo.data_len = len;

    encap_pkt_udphdr(udpbuf, &udpinfo);

    // enqueue
    rte_ring_mp_enqueue(dgram->sendbuf, udpbuf);

    return len;

}

ssize_t mynet_send(int sockfd, const void *buf, size_t len, __attribute__((unused))int flags) {

    struct tcp_stream *stream =  mynet_getstream_from_fd(sockfd);
    if (stream == NULL) {
        return -1;
    }

    struct rte_mbuf *tcpbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {
        mynet_debug("rte_pktmbuf_alloc tcp send buf error.");
        return -1;
    }

    uint16_t tcp_len = len + sizeof(struct rte_tcp_hdr);
    uint16_t ip4_len = tcp_len + sizeof(struct rte_ipv4_hdr);
    uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);

    tcpbuf->pkt_len = eth_len;
    tcpbuf->data_len = eth_len;

    // eth
    // mynet_main do it

    // ip4
    struct ip4hdr_info ip4info;

    ip4info.dst_addr = stream->sip;
    ip4info.next_proto_id = IPPROTO_TCP;
    ip4info.total_length = rte_cpu_to_be_16(ip4_len);

    encap_pkt_ip4hdr(tcpbuf, &ip4info);

    // tcp
    struct tcphdr_info tcpinfo;
    memset(&tcpinfo, 0, sizeof(tcpinfo));

    tcpinfo.src_port = stream->dport;
    tcpinfo.dst_port = stream->sport;
    tcpinfo.sent_seq = rte_cpu_to_be_32(stream->sent_seq);
	tcpinfo.recv_ack = rte_cpu_to_be_32(stream->recv_ack);
	tcpinfo.tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    tcpinfo.data = (uint8_t *)(buf);
    tcpinfo.data_len = len;

    encap_pkt_tcphdr(tcpbuf, &tcpinfo);

    rte_ring_mp_enqueue(stream->sendbuf, tcpbuf);

    return len;

}

int mynet_close(int fd) {

    struct udp_dgram *dgram =  mynet_getdgram_from_fd(fd);
    if (dgram != NULL) {

        LL_REMOVE(dgram, g_dgrams);

        if (dgram->recvbuf) {
            rte_ring_free(dgram->recvbuf);
            dgram->recvbuf = NULL;
        }

        if (dgram->sendbuf) {
            rte_ring_free(dgram->sendbuf);
            dgram->sendbuf = NULL;
        }

        rte_free(dgram);
    }


    struct tcp_stream *stream =  mynet_getstream_from_fd(fd);
    if (stream != NULL) {

        struct rte_mbuf *finbuf = rte_pktmbuf_alloc(g_mbuf_pool);
        if (finbuf == NULL) {
            mynet_debug("rte_pktmbuf_alloc tcp fin buf error.");
            return -1;
        }

        uint16_t tcp_len = sizeof(struct rte_tcp_hdr);
        uint16_t ip4_len = tcp_len + sizeof(struct rte_ipv4_hdr);
        uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);

        finbuf->pkt_len = eth_len;
        finbuf->data_len = eth_len;

        // eth
        // mynet_main do it

        // ip4
        struct ip4hdr_info ip4info;
        ip4info.dst_addr = stream->sip;
        ip4info.next_proto_id = IPPROTO_TCP;
        ip4info.total_length = rte_cpu_to_be_16(ip4_len);

        encap_pkt_ip4hdr(finbuf, &ip4info);

        // tcp
        struct tcphdr_info tcpinfo;
        tcpinfo.src_port = stream->dport;
        tcpinfo.dst_port = stream->sport;
        tcpinfo.sent_seq = rte_cpu_to_be_32(stream->sent_seq);
        tcpinfo.recv_ack = rte_cpu_to_be_32(stream->recv_ack);
        tcpinfo.tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
        tcpinfo.data = NULL;
        tcpinfo.data_len = 0;

        encap_pkt_tcphdr(finbuf, &tcpinfo);

        rte_ring_mp_enqueue(stream->sendbuf, finbuf);

        stream->status = TCP_STATUS_LAST_ACK;
    }


    return 0;
}


int udp_server_main(__attribute__((unused))  void *arg) {

    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    char buffer[BUFFER_SIZE];
    socklen_t len;

    // 创建UDP套接字
    if ((sockfd = mynet_socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        rte_exit(EXIT_FAILURE, "udp socket create failed.\n");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // 设置服务器地址
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(BIND_ADDR);
    servaddr.sin_port = htons(BIND_PORT);

    // 将套接字绑定到服务器地址
    if (mynet_bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        rte_exit(EXIT_FAILURE, "udp socket bind failed.\n");
    }

    while (1) {
        // 接收数据
        int n = mynet_recvfrom(sockfd, (char *)buffer, BUFFER_SIZE - 1, MSG_WAITALL,
                                (struct sockaddr *)&cliaddr, &len);
        if(n < 0) {
            continue;
        }

        buffer[n] = '\0';

        mynet_debug("UDP Client(%d) : %s", n, buffer);

        // 发送回应给客户端
        n = mynet_sendto(sockfd, (const char *)buffer, strlen(buffer), MSG_CONFIRM,
                        (const struct sockaddr *)&cliaddr, len);

        mynet_debug("UDP Server(%d)", n);
    }

    mynet_debug("UDP close(%d)", sockfd);
    mynet_close(sockfd);

    return 0;
}


int tcp_server_main(__attribute__((unused))  void *arg) {

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    int addrlen = sizeof(server_addr);
    char buffer[BUFFER_SIZE];

    // 创建socket
    if ((server_fd = mynet_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        rte_exit(EXIT_FAILURE, "tcp socket create failed.\n");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(BIND_ADDR);
    server_addr.sin_port = htons(BIND_PORT);


    // 绑定地址和端口
    if (mynet_bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        rte_exit(EXIT_FAILURE, "tcp socket bind failed.\n");
    }

    // 监听
    if (mynet_listen(server_fd, 3) < 0) {
        rte_exit(EXIT_FAILURE, "tcp socket listen failed.\n");
    }

    while (1) {

        // 接受连接请求
        client_fd = mynet_accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t*)&addrlen);
        if (client_fd < 0) {
            rte_exit(EXIT_FAILURE, "tcp socket accept failed.\n");
        }

        // 从客户端接收数据
        int n;
        while ((n = mynet_recv(client_fd, buffer, BUFFER_SIZE - 1, 0)) > 0) {

            buffer[n] = '\0';

            mynet_debug("TCP Client(%d) : %s", n, buffer);

            // 回复客户端
            mynet_send(client_fd, buffer, strlen(buffer), 0);

            mynet_debug("TCP Server(%d)", n);
        }

        if (n == 0) {
            mynet_send("TCP Client disconnected.");
        } else {
            mynet_send("TCP Receive failed.");
        }

        mynet_debug("TCP close(%d)", client_fd);
        mynet_close(client_fd);
    }

    mynet_debug("TCP close(%d)", server_fd);
    mynet_close(server_fd);

    return 0;
}







