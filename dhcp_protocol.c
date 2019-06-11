#include "dhcp_protocol.h"
#include "construct_dhcp_packet.h"
#include "virtual_interface.h"

static struct dhcp_lease_info dlf={0};

//the info returned is in network byte order.
int get_lease_info(struct dhcp_lease_info* ret){
	memcpy(ret,&dlf,sizeof(struct dhcp_lease_info));
	return 1;

}

int dhcp_protocol(char command[128],int hwmac_increment){

	// set mac address
	// mac address in dhcp payload. mac address would be hwmac plus hwmac_increment.
	// mac address in layer two would be aquired below automatically.
	unsigned char hwmac[6]={0x80,0xa5,0x89,0xa2,0xc5,0xff};//
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
	
	char * pch;
	pch = strtok(command," ");
	int count=0;
	while (pch != NULL){
		if(count==0){
			if(strcmp(pch,"DHCP")!=0){
				fprintf(stderr,"dhcp_protocol_virtual_interface_error\n");
				return -1;//parameter error.
			}
			
		}
		else if(count==1){
			if(strcmp(pch,"init")==0){
				if(dlf.activation==1){
					send_fd("already have a ip address.please release first.\n");
					return 0;
				}
				if(dhcp_protocol_init(hwmac)<0){
					return -1;

				}
				else return 0;
			}
			else if(strcmp(pch,"release")==0){
				
				if(dlf.activation==0){
					send_fd("do not have a lease to release\n");
					return 0;
	
				}
				srand(time(NULL));
				unsigned int xid=rand();

				if(send_dhcp_packet(xid, hwmac, dlf.destmac, &(dlf.aq_ipaddr), &(dlf.ro_ipaddr),&(dlf.ro_ipaddr),&(dlf.aq_ipaddr)/*of no use*/, DHCP_RELEASE)<0){
					send_fd("release dhcp error\n");
					return -1;
					//release dhcp error.
				}
				else{
					memset(&dlf,0,sizeof(struct dhcp_lease_info));
					return 0;
				}
			}
			else{
				fprintf(stderr,"dhcp_command_error\n");
				return -1;

			}
		
		}
		count++;
		if(count==2){
			return -1;//it shall never reach here.
		}
		pch = strtok (NULL, " ");
	}
	return -1;//parameters error.

}

static int dhcp_protocol_init(char hwmac[6]){

	srand(time(NULL));
	dlf.activation=1;
	int recv_sd=0;
	if((recv_sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0){
		perror("recv socket()");
		return -1;
	}

	int timeout = 0;
	int max_try=0;
	while(1){

		if(max_try>=5){
			
			memset(&dlf,0,sizeof(struct dhcp_lease_info));
			return -1;

		}
		max_try++;

		memset(&dlf,0,sizeof(struct dhcp_lease_info));
		if(timeout) send_fd("timeout");
		timeout = 0;

		// send DHCP_DISCOVER
		unsigned int xid = rand();
		if(send_dhcp_packet(xid, hwmac,"\xff\xff\xff\xff\xff\xff", (unsigned int *)"\x00\x00\x00\x00", (unsigned int *)"\xff\xff\xff\xff",(unsigned int *)"\xff\xff\xff\xff"/*of no use*/,(unsigned int *)"\xff\xff\xff\xff"/*of no use*/, DHCP_DISCOVER)<0){
			continue;
			//error on sending dhcp packet. restart dhcp protocol.

		};	
		send_fd("[DHCP_DISCOVER]\n");
		//variables needed for recvfrom.
		unsigned char packet_in[PACKETMAXSIZE]={0};
		int recv_msg_len=0;

		unsigned char dhcp_port[2] = {0x00, 0x43};
	
		// get dhcp offer
		time_t pre;
		pre = time(NULL);

		while(1){
			time_t seconds = time(NULL);
			if(seconds - pre > 5){
			
				timeout = 1;
				break;
				//break with timeout set to 1.
			}
			
			memset(packet_in,0,PACKETMAXSIZE);
			//recv_msg_len=recvfrom(recv_sd,packet_in,PACKETMAXSIZE,0,(struct sockaddr*)&dhcp_server,&recv_addr_len);
			recv_msg_len=recv(recv_sd,packet_in,PACKETMAXSIZE,0);
			
			//filter out packets we don't want.
			Packet*p = (Packet *)packet_in;
			if(memcmp(p -> udp.srcPort, dhcp_port, 2) != 0){
				continue;
			}
			struct dhcp_header *dhcp;
			dhcp = (struct dhcp_header*)&(p -> data);
			if(dhcp -> xid != xid) continue;
			if(dhcp -> op != 2) continue;
			memcpy(dlf.destmac,p->l2.srcMAC,6);
			dlf.aq_ipaddr = dhcp->your_ip;
			dlf.ro_ipaddr= dhcp->server_ip;
			dlf.activation=1;
			int flag=0;	
		
			//process each option
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
							send_fd("\n");
							// fprintf(stdout,"get ip: %s\n", inet_ntoa(*(struct in_addr *)&(dhcp -> your_ip)));
						}else{
							//not the packet we want.
							flag=1;		
						}
						break;
					case 54:
						dlf.dh_ipaddr = *(int*)((dhcp -> exten)+offset);
						// fprintf(stdout,"server ip : %s\n", inet_ntoa(*dhcp_server_ip));
						break;
					case 51:
						dlf.lease=*(int*)( (dhcp->exten) + offset );
						break;
					case 58:
						dlf.renew=*(int*)((dhcp->exten)+offset);
						break;
					case 59:
						dlf.rebind=*(int*)((dhcp->exten)+offset);
						break;
					default:
						break;
				}
				offset += len;
			}
			if(flag==1) continue; 	
			break;//succesfully received dhcp offer. break with timeout=0
		}
		if(timeout) continue;
			
		//receive dhcp offer without timeout
		//send dhcp_request
		if(send_dhcp_packet(xid, hwmac, (unsigned char*)"\xff\xff\xff\xff\xff\xff", (unsigned int*)"\x00\x00\x00\x00",(unsigned int*)"\xff\xff\xff\xff",&(dlf.ro_ipaddr),&(dlf.aq_ipaddr), DHCP_REQUEST)<0){
			continue;
			//restart dhcp protocol.
		};
		send_fd("[DHCP REQUEST]\n");

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
			recv_msg_len=recv(recv_sd,packet_in,PACKETMAXSIZE,0);
			Packet*p = (Packet *)packet_in;
			/*for(int iii=0;iii<recv_msg_len;iii++){

				printf("/x%02x",packet_in[iii]);

			}
			printf("\n");*/
			if(memcmp(p -> udp.srcPort, dhcp_port, 2) != 0){
				continue;
			}
			struct dhcp_header *dhcp;
			dhcp = (struct dhcp_header*)&(p -> data);
			if(dhcp -> xid != xid) continue;
			if(dhcp -> op != 2) continue;
			int flag=0;	
			for(int offset = 4/* skip magic cookie*/;;){
				unsigned char option = dhcp -> exten[offset];
				if(option == 0xff) break;
				offset ++;
				int len = dhcp -> exten[offset];
				offset ++;
				switch(option){
					case 53: //message type
						if(dhcp -> exten[offset] == DHCP_ACK){
							send_fd("[DHCP ACK] success!\n");
						}else{
							//not the packet we want.
							flag=1;
						}
						break;
					default:
						break;
				}
				offset += len;
			
			}
			if(flag==1) continue;
			break;


		}
		if(timeout) continue;//restart dhcp protocol completely.
		break;//successfully received dhcp ack without timeout. break dhcp_protocol.

	}
	
	//sleep(5);
	send_fd("[FINISH]\n");
	close(recv_sd);
	return 0;	
}


int send_dhcp_packet(unsigned int xid, unsigned char*hwmac,unsigned char *dstmac, unsigned int *srcip, unsigned int *dstip,unsigned int*server_ip,unsigned int*req_ip, unsigned int type){

	//Initializing file descriptor.
	//get a file descriptor from at layer two.
	int sd;
	if((sd=socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW))<0){
		perror("socket()");
		return -1;
	}


	// get mac address
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,interface,strlen(interface));
	if(ioctl(sd,SIOCGIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCGIFHWADDR)");	
		return -1;
	}

	//check whether it is ethernet interface
	if(itface.ifr_hwaddr.sa_family!=ARPHRD_ETHER){
		fprintf(stderr,"interface provided is not a ethernet interface\n");
		return -1;

	}

#ifdef debugfixed_mac
	fprintf(stdout,"mac_addr");
	for(int iii=0;iii<6;iii++){
		fprintf(stdout,":%02x",(unsigned char)(itface.ifr_hwaddr.sa_data[iii]));

	}
	fprintf(stdout,"\n");
	
#endif

	//Because we do not create new interface, it is necessary to send packet using the original mac address of the computer this program is running on. 
	unsigned char fixed_mac[6];
	memcpy(fixed_mac, itface.ifr_hwaddr.sa_data, 6);


	//Get index of the provided interface.
	if(ioctl(sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		return -1;

	}
	
	//Bind our file descriptor to this index.
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);
	if(bind(sd,(struct sockaddr*)&ifaddr,sizeof(struct sockaddr_ll))<0){
		perror("bind()");
		return -1;
	}
	
	//Finish initializing file descriptor.
	//Ready to run dhcp protocol.


	//start to construct dhcp datagram
	unsigned char packet[PACKETMAXSIZE];
	if(construct_dhcp_packet(xid,type,hwmac,dstmac, srcip, dstip, packet, fixed_mac,server_ip,req_ip)<0){
		fprintf(stderr,"error construct dhcp_packet\n");
		return -1;
	};


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
		return -1;
	}

	close(sd);
	return 0;
}
static void send_fd(char *s){
	write(STDOUT_FILENO, s, strlen(s));
}
