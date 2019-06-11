#ifndef DHCP_PROTOCOL_H
#define DHCP_PROTOCOL_H

#include <linux/if_ether.h>
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
	int activation;
	int aq_ipaddr;
	int ro_ipaddr;
	int dh_ipaddr;
	char destmac[6];
	int lease;
	int renew;
	int rebind;

};
struct mac_address{
	unsigned char hwmac[6];

};

//run dhcp protocol
int dhcp_protocol(char command[128],int hwmac_increment);
//use this function to aquire dhcp_info.
//the info returned is in network byte order.
int get_lease_info(struct dhcp_lease_info*ret);



//functions below are for internal use.
static int dhcp_protocol_init(char hwmac[6]);
static void send_fd(char *s);
int send_dhcp_packet(unsigned int xid, unsigned char*hwmac,unsigned char *dstmac, unsigned int *scrip, unsigned int *dstip,unsigned int*server_ip,unsigned int *req_ip,unsigned int type);


#endif
