#include <linux/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdlib.h>                 
#include <string.h>   
#include <stdio.h>

#define PACKETMAXSIZE 1024
#define IP_LAYER 3
#define TRANSPORT_LAYER 4
#define APP_LAYER 5
#define LINK_LAYER 2

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_BROADCAST_FLAT 128
struct dhcp_header {		/* BOOTP packet format */
	unsigned char op;			/* 1=request, 2=reply */
	unsigned char htype;		/* HW address type */
	unsigned char hlen;		/* HW address length */
	unsigned char hops;		/* Used only by gateways */
	unsigned int xid;		/* Transaction ID */
	unsigned short secs;		/* Seconds since we started */
	unsigned short flag;		/* Just what it says */
	unsigned int client_ip;		/* Client's IP address if known */
	unsigned int your_ip;		/* Assigned IP address */
	unsigned int server_ip;		/* (Next, e.g. NFS) Server's IP address */
	unsigned int relay_ip;		/* IP address of BOOTP relay */
	unsigned char hw_addr[16];		/* Client's HW address */
	unsigned char serv_name[64];	/* Server host name */
	unsigned char boot_file[128];	/* Name of boot file */
	unsigned char exten[312];		/* DHCP options / BOOTP vendor extensions */
};

struct ip_h {
	unsigned char type;
	unsigned char type_of_service;
	unsigned char total_len[2];
	unsigned char id[2];
	unsigned char flags[2];
	unsigned char ttl;
	unsigned char proto;
	unsigned char checksum[2];
	unsigned char srcIP[4];
	unsigned char desIP[4];
};
struct l2_h {
	unsigned char desMAC[6];
	unsigned char srcMAC[6];
	unsigned char type[2];
};
struct udp_h {
	unsigned char srcPort[2];
	unsigned char desPort[2];
	unsigned char len[2];
	unsigned char checksum[2];
};

typedef struct packet {
	struct l2_h l2;
	struct ip_h ip;
	struct udp_h udp;
	unsigned char data[PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr)-sizeof(struct udphdr)];
} Packet;
//pseudo hdr for computing udp checksum
struct pseudo_udp_hdr{  
                             
        unsigned int source;                    
        unsigned int dest;
        unsigned char pad;
        unsigned char proto;
        unsigned short length;
        struct udphdr udp_hdr;
        unsigned char data[PACKETMAXSIZE-sizeof(struct ethhdr)-sizeof(struct iphdr)-sizeof(struct udphdr)];
};

//Construct packet from Layer 2 to udp.
//The port numbers in udp header will be modified in construct_application_packet().
void construct_udp(unsigned int proto,unsigned char hwmac[6],unsigned char dstmac[6],unsigned int *hip,unsigned int *dip,unsigned char *packet);

//Supported prototol should be defined in this function call.
void construct_application_packet(unsigned int proto,struct pseudo_udp_hdr* p_udp);

unsigned short checksum(void* addr,int count);

void copy_macaddr(unsigned char *sll_addr,unsigned char first,unsigned char second,unsigned char third,unsigned char fourth,unsigned char fifth,unsigned char sixth);

void construct_dhcp(unsigned int xid,unsigned int type,unsigned char hwmac[6],unsigned char dstmac[6],unsigned int *hip,unsigned int *dip,unsigned char *packet,unsigned int *server_ip);

void construct_dhcp_payload(unsigned int xid, unsigned int type,struct pseudo_udp_hdr* p_udp,unsigned char *hwmac,unsigned int*hip,unsigned int *server_ip);

unsigned char*dhcp_add_exten(unsigned char*cursor,unsigned char code,unsigned char length,unsigned char* value);
