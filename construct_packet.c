#include "construct_packet.h"

void construct_udp(unsigned int proto,unsigned char hwmac[6],unsigned char dstmac[6],unsigned int *hip,unsigned int *dip,unsigned char *packet){


	memset(packet,0,PACKETMAXSIZE);
	struct ethhdr *ether=(struct ethhdr*)packet;
	struct iphdr *ip=(struct iphdr*)(packet+sizeof(struct ethhdr));
	int packet_len=PACKETMAXSIZE;//sizeof(struct ethhdr)+64;
	
	//ethernet frame header
	copy_macaddr(ether->h_dest,dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
	copy_macaddr(ether->h_source,hwmac[0],hwmac[1],hwmac[2],hwmac[3],hwmac[4],hwmac[5]);
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
	ip->saddr=*hip;
	ip->daddr=*dip;
	ip->check=checksum(ip,20);


	//Create a pseudo udp header for udp checksum.
	struct pseudo_udp_hdr p_udp;
	memset(&p_udp,0,sizeof(struct pseudo_udp_hdr));	

	p_udp.source=*hip;
	p_udp.dest=*dip;
	p_udp.pad=0;
	p_udp.proto=IPPROTO_UDP;
	p_udp.length=htons(PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));
	p_udp.udp_hdr.source=htons(0);
	p_udp.udp_hdr.dest=htons(0);
	p_udp.udp_hdr.len=htons(PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));
	p_udp.udp_hdr.check=0;
	

	//Construct application layer packet.
	
	construct_application_packet(proto,&p_udp);

	//Compute checksum over the entire pseudo header, including application data.
	p_udp.udp_hdr.check=checksum(&p_udp,sizeof(struct pseudo_udp_hdr));

	//Copy the pseudo udp header and data to real our udp header.
	//Real udp header
	struct udphdr *udp=(struct udphdr*)(packet+sizeof(struct iphdr)+sizeof(struct ethhdr));
	memcpy(udp,&(p_udp.udp_hdr),PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));
	
	return;
}

void construct_application_packet(unsigned int proto,struct pseudo_udp_hdr* p_udp){

	if(proto == 67/*dhcp*/){
		p_udp->udp_hdr.source=htons(67);
		p_udp->udp_hdr.dest=htons(68);

	}
	else{
		fprintf(stderr,"Doesn't support this protocol.");
		//Do nothing.
	}


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

