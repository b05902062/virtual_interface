#ifndef VIRTUAL_INTERFACE_H
#define VIRTUAL_INTERFACE_H

#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>

#define ARPHRD_ETHER 1


struct dhcp_lease_info{
	int aq_ipaddr;
	int ro_ipaddr;
	int dh_ipaddr;
	int lease;


};
struct mac_address{
	unsigned char hwmac[6];

};
static void send_fd(char *s);
struct dhcp_lease_info *dhcp_protocol(int sd,unsigned int xid, unsigned char*hwmac,unsigned char *dstmac, unsigned int *scrip, unsigned int *dstip, struct ifreq itface,unsigned char* fixed_mac, unsigned int type);
int strncmp_with_null(unsigned char* s1,unsigned char *s2,int number);
void *initiate_interface(void*arg);
void *recv_worker(void *arg);
void process_msg(unsigned char *packet_in, int recv_msg_len, Packet *p);


#endif
