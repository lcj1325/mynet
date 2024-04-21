





#include "mynet_socket.h"
#include "mynet.h"


int g_socket_fd = 3;
struct localhost *g_hosts = NULL;
struct tcp_stream *g_streams = NULL;


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

struct tcpstream *mynet_getstream_from_fd(int sockfd) {

    struct tcpstream *stream;
    for (stream = g_streams; stream != NULL; stream = stream->next) {

		if (sockfd == stream->fd) {
			return stream;
		}

	}

    return NULL;

}


struct tcpstream *mynet_getstream_from_ipport(uint32_t sip, uint32_t dip,
                                                           uint16_t sport, uint16_t dport) {

	struct tcpstream *iter;
	for (iter = g_streams; iter != NULL; iter = iter->next) { // established

		if (iter->sip == sip && iter->dip == dip &&
			iter->sport == sport && iter->dport == dport) {
			return iter;
		}

	}

	for (iter = g_streams; iter != NULL; iter = iter->next) {

		if (iter->status == TCP_STATUS_LISTEN && iter->dip == dip && iter->dport == dport) { // listen
			return iter;
		}

	}

	return NULL;

}

static inline struct localhost *host_create(int fd) {

    struct localhost *host = rte_malloc("HOST", sizeof(struct localhost), 0);
    if (host == NULL) {
        return NULL;
    }

    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    host->recvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->recvbuf == NULL) {

        rte_free(host);
        return NULL;
    }

    host->sendbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->sendbuf == NULL) {

        rte_ring_free(host->recvbuf);

        rte_free(host);
        return NULL;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    return host;
}

static struct tcpstream *stream_create(int fd){

    struct tcpstream *stream = rte_malloc("STREAM", sizeof(struct tcpstream), 0);
    if (stream == NULL) {
        return NULL;
    }

    memset(stream, 0, sizeof(struct tcpstream));

    stream->fd = fd;

    stream->recvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->recvbuf == NULL) {

        rte_free(stream);
        return NULL;
    }

    stream->sendbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->sendbuf == NULL) {

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


int mynet_socket(__attribute__((unused)) int domain, int type, int protocol) {

    int fd = mynet_getfd();
    if (fd < 0) {
        return -1;
    }

    if (type == SOCK_DGRAM) {

        struct localhost *host = host_create(fd);
        if (host == NULL) {
            return -1;
        }
        LL_ADD(host, g_hosts);
    }
    else if (type == SOCK_STREAM) {

        struct tcpstream *stream = stream_create(fd);
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

	struct localhost *host =  mynet_gethost_from_fd(sockfd);
    struct tcpstream *stream =  mynet_getstream_from_fd(sockfd);
    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;

	if (host != NULL) {
        host->localport = laddr->sin_port;
	    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    }
    else if (stream != NULL) {
        stream->dport = laddr->sin_port;
	    rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        stream->status = TCP_STATUS_CLOSED
    }
    else {
        printf("[ %s ==> bind addr error. ]", __FUNCTION__);
        return -1;
    }

	return 0;

}

int mynet_listen(int sockfd, __attribute__((unused))int backlog) {

	struct tcpstream *stream =  mynet_getstream_from_fd(sockfd);

	if (stream == NULL) return -1;

    stream->status = TCP_STATUS_LISTEN;

    return 0;

}

static struct tcpstream *accept_get_new_stream(uint32_t dip, uint16_t dport){

    struct tcpstream *stream;
    for (stream = g_streams; stream != NULL; stream = apt->next) {
        if (stream->fd == -1 && stream->dip == dip && stream->dport == dport) {
            return stream;
        }
    }

    return NULL;

}

int mynet_accept(int sockfd, struct sockaddr *addr, __attribute__((unused))socklen_t *addrlen) {

	struct tcpstream *stream =  mynet_getstream_from_fd(sockfd);

	if (stream == NULL) return -1;

	struct tcpstream *new_stream = NULL;

	pthread_mutex_lock(&stream->mutex);
	while((new_stream = accept_get_new_stream(stream->dip, stream->dport)) == NULL) {
		pthread_cond_wait(&stream->cond, &stream->mutex);
	}
	pthread_mutex_unlock(&stream->mutex);

	new_stream->fd = mynet_getfd();

    // 填充 客户端 ip 和 port
	struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
	saddr->sin_port = new_stream->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &new_stream->sip, sizeof(uint32_t));

	return new_stream->fd;

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


ssize_t mynet_recv(int sockfd, void *buf, size_t len, __attribute__((unused))int flags) {

    struct tcpstream *stream =  mynet_getstream_from_fd(sockfd);
    if (stream == NULL) {
        printf("[ %s ==> stream nil]", __FUNCTION__);
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
    uint8_t *data = (uint8_t *)(tcp + 1);
    uint16_t data_len = ip4_len - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr);

    saddr->sin_port = tcp->src_port;
    rte_memcpy(&saddr->sin_addr.s_addr, &ip4->src_addr, sizeof(uint32_t));

    if (len < data_len) {

        rte_memcpy(buf, data, len);

        // rte_memcpy(data, data + len, data_len - len);
        int i;
        for (int i = 0; i < data_len - len; i++) {
            data[i] = data[i + len];
        }

        ip4->total_length = rte_cpu_to_be_16(data_len - len + sizeof(struct rte_tcp_hdr)
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

ssize_t mynet_send(int sockfd, const void *buf, size_t len, __attribute__((unused))int flags) {

    struct tcpstream *stream =  mynet_getstream_from_fd(sockfd);
    if (stream == NULL) return -1;

    struct rte_mbuf *new_buf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (new_buf == NULL) {

        if (MYNET_DEBUG) {
            printf("[ %s ==> rte_pktmbuf_alloc tcp send buf error. ]\n", __FUNCTION__);
        }
        return -1;
    }

    uint16_t ip4_len = len + sizeof(struct rte_tcp_hdr) + sizeof(struct rte_ipv4_hdr);
    uint16_t eth_len = ip4_len + sizeof(struct rte_ether_hdr);

    new_buf->pkt_len = eth_len;
    new_buf->data_len = eth_len;

    // eth
    // sokcet do it

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
	tcpinfo.tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    tcpinfo.data = (uint8_t *)(buf);
    tcpinfo.data_len = len;

    encap_pkt_tcphdr(new_buf, &tcpinfo);

    rte_ring_mp_enqueue(stream->sendbuf, new_buf);

    return len;

}

int mynet_close(int fd) {

    struct localhost *host =  mynet_gethost_from_fd(fd);
    if (host != NULL) {

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
    }


    struct tcpstream *stream =  mynet_getstream_from_fd(fd);
    if (stream != NULL) {

        LL_REMOVE(stream, g_streams);

        if (stream->recvbuf) {
            rte_ring_free(stream->recvbuf);
            stream->recvbuf = NULL;
        }

        if (stream->sendbuf) {
            rte_ring_free(stream->sendbuf);
            stream->sendbuf = NULL;
        }

        rte_free(stream);
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
        int n = mynet_recvfrom(sockfd, (char *)buffer, BUFFER_SIZE-1, MSG_WAITALL,
                                (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';

        printf("[ UDP Client : %s ]\n", buffer);

        // 发送回应给客户端
        mynet_sendto(sockfd, (const char *)buffer, strlen(buffer), MSG_CONFIRM,
                        (const struct sockaddr *)&cliaddr, len);
        printf("[ UDP Message sent. ]\n");
    }

    mynet_close(sockfd);

    return 0;
}


int tcp_server_main(__attribute__((unused))  void *arg) {

    int server_fd, new_socket;
    struct sockaddr_in server_addr, client_addr;
    int addrlen = sizeof(server_addr);
    char buffer[BUFFER_SIZE] = {0};

    // 创建socket
    if ((server_fd = mynet_socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(BIND_ADDR);
    server_addr.sin_port = htons(BIND_PORT);


    // 绑定地址和端口
    if (mynet_bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 监听
    if (mynet_listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", BIND_PORT);

    while (1) {

        // 接受连接请求
        if ((new_socket = mynet_accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        // 从客户端接收数据
        int valread;
        while ((valread = mynet_recv(new_socket, buffer, BUFFER_SIZE-1, 0)) > 0) {

            buffer[n] = '\0';

            printf("[ TCP Client : %s ]\n", buffer);

            // 回复客户端
            mynet_send(new_socket, buffer, strlen(buffer), 0);
            printf("[ TCP Message sent. ]\n");
        }

        if (valread == 0) {
            printf("[ TCP Client disconnected. ]\n");
        } else {
            perror("[ TCP Receive failed. ]\n");
        }

        mynet_close(new_socket);
    }

    mynet_close(server_fd);

    return 0;
}







