



#ifndef __MYNET_RING_H__
#define __MYNET_RING_H__

#include <rte_mbuf.h>
#include <rte_malloc.h>



struct inout_ring {

	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *io_ring = NULL;

static struct inout_ring *inout_ring_instance(void) {

	if (io_ring == NULL) {

		io_ring = rte_malloc("IN_OUT_RING", sizeof(struct inout_ring), 0);
		memset(io_ring, 0, sizeof(struct inout_ring));
	}

	return io_ring;
}




#endif  //  __MYNET_RING_H__





