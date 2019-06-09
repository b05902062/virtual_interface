/*
dcmp denial_of_service program.
march 2019
by wang zih_min

*/
#include "virtual_interface.h"


int main(int argc,char **argv){

	if(argc!=3){
		fprintf(stderr,"usage: ./virtual_interface <name of a connected interface> <i (hwmac + i)>\n");
		exit(-1);
	}

	if(strlen(argv[1])>=IFNAMSIZ){
		fprintf(stderr,"interface name too long\n");
		exit(-1);
	}

	//Copy interface name to a global variable.
	memcpy(interface,argv[1],IFNAMSIZ);
	int hwmac_increment=atoi(argv[2]);

	
	while(1){
		char command[128]={0};
		int len=0;//len is the total length of command in the end,excluding of terminator.
		char byte=0;
		while(read(STDIN_FILENO,&byte,1)>0){
			if(byte=='\n') break;
			assert(len<127);//the last byte of command is always null.
			command[len]=byte;
			len+=1;
		}

		int kill_flag=0;
		char * pch;
		pch = strtok(command," ");
		while (pch != NULL)
		{
			//pch is the first command
			if(strcmp(pch,"kill")==0){
				kill_flag=1;//terminate this virtual interface.

			}
			else if(strcmp(pch,"DHCP")==0){
				dhcp_protocol(hwmac_increment);
			}
			else if(0){
				//put supported protocol at here.

			}	
			else{
				send_fd("doesn't support this protocol\n");


			}
			
			break;//only read the first command



		}


		if(kill_flag==1){
			send_fd("terminating\n");
			break;
		}

	}


	return 0;
}

static void send_fd(char *s){
	write(STDOUT_FILENO, s, strlen(s));
}
