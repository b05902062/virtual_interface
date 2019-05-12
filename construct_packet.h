#include <linux/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdlib.h>                 
#include <string.h>   
#include <stdio.h>
#define PACKETMAXSIZE 512

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

