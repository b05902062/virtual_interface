#include "construct_dhcp_packet.h"

int construct_dhcp_packet(unsigned int xid,unsigned int type,unsigned char hwmac[6],unsigned char dstmac[6],unsigned int *hip,unsigned int *dip,unsigned char *packet, unsigned char* fixed_mac,unsigned int*server_ip,unsigned int *req_ip){



	memset(packet,0,PACKETMAXSIZE);
	struct ethhdr *ether=(struct ethhdr*)packet;
	struct iphdr *ip=(struct iphdr*)(packet+sizeof(struct ethhdr));
	int packet_len=PACKETMAXSIZE;//sizeof(struct ethhdr)+64;
	
	//ethernet frame header
	copy_macaddr(ether->h_dest,dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
	//we do not create new interfaces,so we use the mac address of the computer this program is running on at layer two.
	memcpy(ether->h_source, fixed_mac, 6);
	ether->h_proto=htons(ETH_P_IP);

	//ip header
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(PACKETMAXSIZE-sizeof(struct ethhdr));
	ip->frag_off = 0;
	ip->id = 88; // need to be random
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
	p_udp.udp_hdr.source=htons(68);
	p_udp.udp_hdr.dest=htons(67);
	p_udp.udp_hdr.len=htons(PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));
	p_udp.udp_hdr.check=0;
	


	if(construct_dhcp_payload(xid, type,&p_udp,hwmac,dstmac,hip, dip,server_ip,req_ip)<0){
		return -1;
	};

	//Compute checksum over the entire pseudo header, including application data.
	p_udp.udp_hdr.check=checksum(&p_udp,sizeof(struct pseudo_udp_hdr));

	//Copy the pseudo udp header and data to real our udp header.
	//Real udp header
	struct udphdr *udp=(struct udphdr*)(packet+sizeof(struct iphdr)+sizeof(struct ethhdr));
	memcpy(udp,&(p_udp.udp_hdr),PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr));
	
	return 0;
}

static int construct_dhcp_payload(unsigned int xid, unsigned int type,struct pseudo_udp_hdr* p_udp,unsigned char *hwmac,unsigned char*dstmac,unsigned int*hip,unsigned int*dip, unsigned int *server_ip,unsigned int *req_ip){

	if(type == DHCP_DISCOVER/*dhcp*/){
		struct dhcp_header* dhcp_hdr=(struct dhcp_header*)p_udp->data;
		dhcp_hdr->op=1;
		dhcp_hdr->htype=1;
		dhcp_hdr->hlen=6;
		dhcp_hdr->hops=0;
		dhcp_hdr->xid=xid;
		dhcp_hdr->secs=0;//for lease renewal.
		dhcp_hdr->broadcast=1;
		dhcp_hdr->client_ip=0;
		memset(&(dhcp_hdr -> your_ip), '\0', sizeof(dhcp_hdr -> your_ip));
		// dhcp_hdr->your_ip=0;
		dhcp_hdr->server_ip=0;
		dhcp_hdr->relay_ip=0;
		memcpy(dhcp_hdr->hw_addr,hwmac,6);
		//memcpy(dhcp_hdr->hw_addr,"\x80\xa5\x89\x52\xdf\x5d",6);



		//dhcp_hdr->serv_name;
		//dhcp_hdr->boot_file;
		unsigned char*cursor=dhcp_hdr->exten;
		unsigned char magic_cookie[5]="\x63\x82\x53\x63";
		memcpy(cursor,magic_cookie,4);
		cursor+=4;

		cursor=dhcp_add_exten(cursor,53,1,"\x01");//dhcp discover
		cursor=dhcp_add_exten(cursor,55,10,"\x01\x79\x03\x06\x0f\x77\xfc\x5f\x2c\x2e");//subnet mask,classless static route,router,dns server,domain name,domain search,pirvate/proxy autodiscovery,LDAP,netbios over name server,netbios over node type.
		//cursor=dhcp_add_exten(cursor,55,4,"\x01\x03\x06\x0f");
		// cursor=dhcp_add_exten(cursor,57,2,"\x04\x00");//max dhcp size
		// unsigned char temp[8]="\x01";
		// memcpy(temp+1,hwmac,6);
		// cursor=dhcp_add_exten(cursor,61,7,temp);//ethernet ,macaddress
		// cursor=dhcp_add_exten(cursor,51,4,"\x00\x76\xa7\x00");//lease time
		cursor=dhcp_add_exten(cursor,12,4,"\x61\x61\x61\x61");//host name
		cursor=dhcp_add_exten(cursor,255,0,"\x00");//end

	}
	else if(type == DHCP_REQUEST){
		struct dhcp_header* dhcp_hdr=(struct dhcp_header*)p_udp->data;
		dhcp_hdr->op=1;
		dhcp_hdr->htype=1;
		dhcp_hdr->hlen=6;

		dhcp_hdr->hops=0;
		dhcp_hdr->xid=xid;
		dhcp_hdr->secs=0;//for lease renewal.
		dhcp_hdr->broadcast=1;
		dhcp_hdr->client_ip=0;
		memset(&(dhcp_hdr -> your_ip), '\0', sizeof(dhcp_hdr -> your_ip));
		// dhcp_hdr->your_ip=0;
		// dhcp_hdr->server_ip=0;
		memcpy(&(dhcp_hdr -> server_ip), server_ip, sizeof(int));
		dhcp_hdr->relay_ip=0;
		memcpy(dhcp_hdr->hw_addr,hwmac,6);
		//dhcp_hdr->serv_name;
		//dhcp_hdr->boot_file;
		unsigned char*cursor=dhcp_hdr->exten;
		unsigned char magic_cookie[5]="\x63\x82\x53\x63";
		memcpy(cursor,magic_cookie,4);
		cursor+=4;

		cursor=dhcp_add_exten(cursor,53,1,"\x03");//dhcp request
		//cursor=dhcp_add_exten(cursor,55,10,"\x01\x79\x03\x06\x0f\x77\xfc\x5f\x2c\x2e");//subnet mask,classless static route,router,dns server,domain name,domain search,pirvate/proxy autodiscovery,LDAP,netbios over name server,netbios over node type.

		//cursor=dhcp_add_exten(cursor,57,2,"\x04\x00");//max dhcp size
		unsigned char temp[8]="\x01";
		memcpy(temp+1,hwmac,6);
		// cursor=dhcp_add_exten(cursor,61,7,hwmac);//ethernet ,macaddress
		//cursor=dhcp_add_exten(cursor,51,4,"\x00\x76\xa7\x00");//lease time
		// cursor=dhcp_add_exten(cursor,12,4,"\x00\x00\x00\x00");//host name
		cursor=dhcp_add_exten(cursor, 54, 4, (unsigned char*)server_ip);
		cursor=dhcp_add_exten(cursor,50,4,(unsigned char*)req_ip);//request ip address
		// cursor=dhcp_add_exten(cursor, 57, 2, "\x05\xdc");//MAX message size
		// cursor=dhcp_add_exten(cursor, 55, 10, "\x01\x03\x06\x0f\x1a\x1c\x33\x3a\x3b\x2b");
		cursor=dhcp_add_exten(cursor,255,0,"\x00");//end

	}else if(type==DHCP_RELEASE){
		struct dhcp_header* dhcp_hdr=(struct dhcp_header*)p_udp->data;
		dhcp_hdr->op=1;
		dhcp_hdr->htype=1;
		dhcp_hdr->hlen=6;

		dhcp_hdr->hops=0;
		dhcp_hdr->xid=xid;
		dhcp_hdr->secs=0;//for lease renewal.
		dhcp_hdr->broadcast=0;
		dhcp_hdr->client_ip=0;
		memcpy(&(dhcp_hdr -> client_ip),hip, sizeof(int));
		memset(&(dhcp_hdr -> your_ip), '\0', sizeof(int));
		// dhcp_hdr->your_ip=0;
		// dhcp_hdr->server_ip=0;
		memcpy(&(dhcp_hdr -> server_ip), server_ip, sizeof(int));
		dhcp_hdr->relay_ip=0;
		memcpy(dhcp_hdr->hw_addr,hwmac,6);
		//dhcp_hdr->serv_name;
		//dhcp_hdr->boot_file;
		unsigned char*cursor=dhcp_hdr->exten;
		unsigned char magic_cookie[5]="\x63\x82\x53\x63";
		memcpy(cursor,magic_cookie,4);
		cursor+=4;

		cursor=dhcp_add_exten(cursor,53,1,"\x07");//dhcp release

		unsigned char temp[8]="\x01";
		memcpy(temp+1,hwmac,6);
		cursor=dhcp_add_exten(cursor,61,7,hwmac);//ethernet ,macaddress
		cursor=dhcp_add_exten(cursor, 54, 4, (unsigned char*)server_ip);//server ip
		cursor=dhcp_add_exten(cursor,255,0,"\x00");//end



	}
	else{
		fprintf(stderr,"Doesn't support this type.");
		return -1;
		//Do nothing.
	}
	return 0;

}
unsigned char*dhcp_add_exten(unsigned char*cursor,unsigned char code,unsigned char length,unsigned char* value){

	memcpy(cursor++,&code,1);
	memcpy(cursor++,&length,1);
	memcpy(cursor,value,length);
	cursor+=length;
	return cursor;

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

