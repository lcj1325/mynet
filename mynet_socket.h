


#ifndef __MYNET_SOCKET_H__
#define __MYNET_SOCKET_H__

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>


#define BUFFER_SIZE 1024
#define MAX_FD_NUM 103
#define BIND_ADDR "10.66.24.22"
#define BIND_PORT 8888

#include <pthread.h>


#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>


struct localhost { //

	int fd;

	uint32_t localip;
	uint16_t localport;
	uint8_t protocol;

	struct rte_ring *sendbuf;
	struct rte_ring *recvbuf;

	struct localhost *prev; //
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

extern struct localhost *g_hosts;


struct localhost *mynet_gethost_from_fd(int sockfd);

struct localhost *mynet_gethost_from_app(uint32_t addr, uint16_t port, uint8_t proto);


int mynet_socket(__attribute__((unused))int domain, int type, int protocol);

int mynet_bind(int sockfd, const struct sockaddr *addr , __attribute__((unused))socklen_t addrlen);

ssize_t mynet_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))int flags,
                            struct sockaddr *src_addr, __attribute__((unused))socklen_t *addrlen);

ssize_t mynet_sendto(int sockfd, const void *buf, size_t len, int flags,
                            const struct sockaddr *dest_addr, socklen_t addrlen);

int mynet_close(int fd);

int udp_server_main(__attribute__((unused))  void *arg);

int tcp_server_main(__attribute__((unused))  void *arg);



#endif  //  __MYNET_UDP_H__



