#include "dhcp.h"

struct dhcp_info dhcp_protocol2(int hwmac_increment){

	//Initializing file descriptor.
	//get a file descriptor from at layer two.
	int sd;
	if((sd=socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW))<0){
		perror("socket()");
		exit(-1);
	}


	// get mac address
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,interface,strlen(interface));
	if(ioctl(sd,SIOCGIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCGIFHWADDR)");	
		exit(-1);
	}

	//check whether it is ethernet interface
	if(itface.ifr_hwaddr.sa_family!=ARPHRD_ETHER){
		fprintf(stderr,"interface provided is not a ethernet interface\n");
		exit(-1);

	}

#ifdef debugoriginal_mac
	fprintf(stdout,"mac_addr");
	for(int iii=0;iii<6;iii++){
		fprintf(stdout,":%02x",(unsigned char)(itface.ifr_hwaddr.sa_data[iii]));

	}
	fprintf(stdout,"\n");
	
#endif

	//Because we do not create new interface, it is necessary to send packet using the original mac address of the computer this program is running on. 
	unsigned char original_mac[6];
	memcpy(original_mac, itface.ifr_hwaddr.sa_data, 6);


	//Get index of the provided interface.
	if(ioctl(sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		exit(-1);

	}
	
	//Bind our file descriptor to this index.
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);
	if(bind(sd,(struct sockaddr*)&ifaddr,sizeof(struct sockaddr_ll))<0){
		perror("bind()");
		exit(-1);
	}
	
	//Finish initializing file descriptor.
	//Ready to run dhcp protocol.

	// set mac and xid
	unsigned char hwmac[6]={0x80,0xa5,0x89,0xa2,0xc5,0xff};
	int last = 5;
	for(int i = 0; i < hwmac_increment ; i++)
	{
		while(hwmac[last] == 0xff)
		{
			hwmac[last]=0x00;
			last -=1 ;
			assert(last>=0);
		}
		hwmac[last] += 0x01;
	}
	srand(time(NULL));

	int timeout = 0;
	while(1){
		if(timeout) send_fd("timeout");
		timeout = 0;

		// send DHCP_DISCOVER
		unsigned int xid = rand();
		dhcp_protocol(sd,xid, hwmac,"\xff\xff\xff\xff\xff\xff", (unsigned int *)"\x00\x00\x00\x00", (unsigned int *)"\xff\xff\xff\xff",itface, fixed_mac, DHCP_DISCOVER);	
		send_fd("[DHCP_DISCOVER]");
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
		struct dhcp_header *dhcp;
		int router_ipaddress=0;	
	
	
		// get dhcp offer
		time_t pre;
		pre = time(NULL);

		while(1){
			time_t seconds = time(NULL);
			if(seconds - pre > 5)
			{
				timeout = 1;
				break;
			}
			

			memset(packet_in,0,PACKETMAXSIZE);
			recv_msg_len=recvfrom(recv_sd,packet_in,PACKETMAXSIZE,0,(struct sockaddr*)&dhcp_server,&recv_addr_len);
			
			//filter out packets we don't want.
			Packet*p = (Packet *)packet_in;
			if(memcmp(p -> udp.srcPort, dhcp_port, 2) != 0){
				continue;
			}
			dhcp = (struct dhcp_header*)&(p -> data);
			if(memcmp(dhcp -> hw_addr,hwmac,6)!=0) continue;
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
							send_fd("[DHCP OFFER]");
							send_fd(inet_ntoa(*(struct in_addr *)&(dhcp -> your_ip)));
							// fprintf(stdout,"get ip: %s\n", inet_ntoa(*(struct in_addr *)&(dhcp -> your_ip)));
						}else{
							send_fd("sth wrong!");
							exit(1);
						}
						break;
					case 54:
						dhcp_server_ip = (struct in_addr *)&(dhcp -> exten[offset]);
						// fprintf(stdout,"server ip : %s\n", inet_ntoa(*dhcp_server_ip));
						break;
					default:
						break;
				}
				offset += len;
			
			}
			break;
		}
		if(timeout) continue;
		// send dhcp_request
		dhcp_protocol(sd,xid, hwmac,p -> l2.srcMAC, &(dhcp -> your_ip), (unsigned int*)dhcp_server_ip, itface, fixed_mac, DHCP_REQUEST);	
		send_fd("[DHCP REQUEST]");

		// wait dhcp_ack
		pre = time(NULL);
		while(1){

			time_t seconds = time(NULL);
			if(seconds - pre > 5)
			{
				timeout = 1;
				break;
			}

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
							send_fd("[DHCP ACK] success!");
						}else{
							send_fd("something wrong!");
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
		if(timeout) continue;
		dhcp_protocol(sd,xid,hwmac, "\x9c\x5c\xf9\x2a\x9f\x00",&aquired_ipaddress, (unsigned int *)"\x08\x08\x08\x08",itface ,fixed_mac, DHCP_DISCOVER);	
		break;
	}
	
	//sleep(5);
	send_fd("[FINISH]");
	while(1);
	close(sd);
	exit(0);
	
	
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
static void send_fd(char *s){
	write(STDOUT_FILENO, s, strlen(s));
}
