


#ifndef __MYNET_SOCKET_H__
#define __MYNET_SOCKET_H__

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>


#define BUFFER_SIZE 1024
#define DEFAULT_FD_NUM 3
#define MAX_FD_NUM 103
#define BIND_ADDR "192.168.1.120"
#define BIND_PORT 8888

#include <pthread.h>


#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>


typedef enum TCP_STATUS {

	TCP_STATUS_CLOSED = 0,
	TCP_STATUS_LISTEN,
	TCP_STATUS_SYN_RCVD,
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,

	TCP_STATUS_FIN_WAIT_1,
	TCP_STATUS_FIN_WAIT_2,
	TCP_STATUS_CLOSING,
	TCP_STATUS_TIME_WAIT,

	TCP_STATUS_CLOSE_WAIT,
	TCP_STATUS_LAST_ACK

} TCP_STATUS;


struct udp_dgram { //

	int fd;

	uint32_t localip;
    uint16_t localport;

	struct rte_ring *sendbuf;
	struct rte_ring *recvbuf;

	struct udp_dgram *prev; //
	struct udp_dgram *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};


struct tcp_stream { // tcb control block

	int fd;

    uint32_t dip;
	uint32_t sip;

	uint16_t sport;
    uint16_t dport;

	uint32_t sent_seq; // seqnum
	uint32_t recv_ack; // acknum

	TCP_STATUS status;

	struct rte_ring *sendbuf;
	struct rte_ring *recvbuf;

	struct tcp_stream *prev;
	struct tcp_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};


extern struct udp_dgram *g_dgrams;
extern struct tcp_stream *g_streams;


struct udp_dgram *mynet_getdgram_from_fd(int sockfd);

struct udp_dgram *mynet_getdgram_from_ipport(uint32_t ip, uint16_t port);

struct tcp_stream *mynet_getstream_from_fd(int sockfd);

struct tcp_stream *mynet_getstream_from_ipport(uint32_t sip, uint32_t dip,
                                                           uint16_t sport, uint16_t dport);

struct udp_dgram *mynet_create_dgram(int fd, const char *recvbuf, const char *sendbuf);

struct tcp_stream *mynet_create_stream(int fd, const char *recvbuf, const char *sendbuf);


int mynet_socket(__attribute__((unused))int domain, int type, int protocol);

int mynet_listen(int sockfd, __attribute__((unused))int backlog);

int mynet_accept(int sockfd, struct sockaddr *addr, __attribute__((unused))socklen_t *addrlen);


int mynet_bind(int sockfd, const struct sockaddr *addr , __attribute__((unused))socklen_t addrlen);

ssize_t mynet_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))int flags,
                            struct sockaddr *src_addr, __attribute__((unused))socklen_t *addrlen);

ssize_t mynet_recv(int sockfd, void *buf, size_t len, __attribute__((unused))int flags);

ssize_t mynet_sendto(int sockfd, const void *buf, size_t len, int flags,
                            const struct sockaddr *dest_addr, __attribute__((unused))socklen_t addrlen);

ssize_t mynet_send(int sockfd, const void *buf, size_t len, __attribute__((unused))int flags);

int mynet_close(int fd);

int udp_server_main(__attribute__((unused))  void *arg);

int tcp_server_main(__attribute__((unused))  void *arg);



#endif  //  __MYNET_UDP_H__



