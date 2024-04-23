


#ifndef __MYNET_ARP_H__
#define __MYNET_ARP_H__

#include <rte_ether.h>
#include <rte_malloc.h>



#define ARP_DYNAMIC 0
#define ARP_STATIC 1

struct arp_entry {

	uint32_t ip;
	uint8_t mac[RTE_ETHER_ADDR_LEN];
	uint8_t type;

	struct arp_entry *next;
	struct arp_entry *prev;

};

struct arp_table {

	struct arp_entry *entries;
	int count;

};

static struct arp_table *arpt = NULL;

static struct arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = (struct arp_table *)rte_malloc("ARP_TABLE", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp_table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}

	return arpt;

}


static uint8_t* mynet_get_dstmac(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries; iter != NULL; iter = iter->next) {
		if (dip == iter->ip) {
			return iter->mac;
		}
	}

	return NULL;
}


#endif  //  __MYNET_ARP_H__














