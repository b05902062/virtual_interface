#include <stdio.h>
#include <stdlib.h>
#include<sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#define MAX_CHILD 1000
void showState(int i, int* childrenState){
	printf("child %d\n", i);
	if(childrenState[i] == 0)
	{
		puts("state: start");
	}
	else if(childrenState[i] == 1)
	{
		puts("state: DHCP_DISCOVER");
	}
	else if(childrenState[i] == 2)
	{
		puts("state: DHCP_OFFER");
	}
	else if(childrenState[i] == 3)
	{
		puts("state: sth wrong!");
	}
	else if(childrenState[i] == 4)
	{
		puts("state: DHCP REQUEST");
	}
	else if(childrenState[i] == 5)
	{
		puts("state success!");
	}
	else if(childrenState[i] == 6)
	{
		puts("something wrong!");
	}
	else if(childrenState[i] == 7)
	{
		puts("FINISH");
	}
	else{
		puts("execlp not successful");
	}
}

int valid(int nm)
{
	return  (nm == 0) ||  (nm == 1) || (nm == 2) || (nm == 4) || (nm == 5) || (nm == 7) ;
}

int main(int argc, char **argv)
{	
	int children_nm;
	pid_t pid[MAX_CHILD];
	if(argc!=4){
		fprintf(stderr,"usage: ./personas <process_nm> <name of a connected interface>  <xid>\n");
		exit(-1);
	}
	sscanf(argv[1],"%d", &children_nm);
	if(children_nm > MAX_CHILD){
		fprintf(stderr, "too many children\n, MAX is %d\n", MAX_CHILD);
		exit(-1);
	}
	int p2c_pfd[MAX_CHILD][2];
	int c2p_pfd[MAX_CHILD][2];
	int childrenState[MAX_CHILD];
	int childrenIP[MAX_CHILD] = {0};

	for(int i = 0; i < children_nm; i++)
	{
		if(pipe(p2c_pfd[i]) == -1 || pipe(c2p_pfd[i]) == -1){
			perror("pipe");
			exit(-1);
		}
		pid[i] = fork();
		if(pid[i] == 0)
		{
			// need to handle parent's instruction to children
			// close(STDOUT_FILENO);
			
			if(dup2(p2c_pfd[i][0], STDIN_FILENO) == -1){
				fprintf(stderr, "dup failed");
				exit(1);
			}
			//close(p2c_pfd[i][0]);
			close(p2c_pfd[i][1]);
			close(c2p_pfd[i][0]);

			char buf[1000];
			sprintf(buf,"%d",i);
			char str1[1000], str2[1000];
			memset(str1, '\0', sizeof(str1));
			memset(str2, '\0', sizeof(str2));
			memcpy(str1, argv[2], strlen(argv[2]));
			memcpy(str2, argv[3], strlen(argv[3]));

			childrenState[i] = 0;

			if(execlp("./virtual_interface","./virtual_interface", str1, buf, (char*) 0)<0){
				perror("execlp()");
				printf("child:%d\n",i);
				exit(-1);
			}
		}
		else
		{	
			close(c2p_pfd[i][1]);
			close(p2c_pfd[i][0]);
			puts("I am parent");
		}
	}
	int maxfd = 0;
	for(int i = 0; i < children_nm; i++){
		if(c2p_pfd[i][0] > maxfd) maxfd = c2p_pfd[i][0];
	}

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	fd_set readfds;

	int target_child;

	while(1){
		FD_ZERO(&readfds);
		// should need to add STDIN to get user input
		FD_SET(STDIN_FILENO, &readfds);
		for(int i = 0; i < children_nm; i++){
			FD_SET(c2p_pfd[i][0], &readfds);
		}
		

		//printf("select\n");
		if(select(maxfd+1, &readfds, NULL, NULL, &tv)<0){
			perror("select()");
			exit(-1);
		};



		if(FD_ISSET(STDIN_FILENO, &readfds)){
			//puts("inside");
			char buf[128] = {0};

			char byte;
			int len = 0;

			while(read(STDIN_FILENO, &byte, 1)>0){
				if(byte=='\n') break;
				assert(len < 127);//the last byte of command is always null.
				buf[len]=byte;
				len+=1;
			}
			buf[len] = 0;
			const char del[2] = " ";
			char *token = strtok(buf, del);
			if(token != NULL && strcmp(token, "DHCP") == 0)
			{
				token = strtok(NULL, del);
				if(token != NULL && strcmp(token, "init") == 0)
				{
					token = strtok(NULL, del);
					if(token != NULL)
					{
						
						sscanf(token,"%d", &target_child);
						char sendmsg[100] ={0};
						sprintf(sendmsg,"DHCP init\n");
						showState(target_child, childrenState);
						if(valid(childrenState[target_child]))
							write(p2c_pfd[target_child][1], sendmsg, strlen(sendmsg));
						
					}

				}
				else if(token != NULL && strcmp(token, "kill") == 0)
				{
					sscanf(token,"%d", &target_child);
					char sendmsg[100] = {0};
					sprintf(sendmsg, "DHCP kill\n");
					showState(target_child, childrenState);
					write(p2c_pfd[target_child][1], sendmsg, strlen(sendmsg));
				}
				else if(token != NULL && strcmp(token, "release") == 0)
				{
					sscanf(token,"%d", &target_child);
					char sendmsg[100] = {0};
					sprintf(sendmsg, "DHCP release\n");
					showState(target_child, childrenState);
					write(p2c_pfd[target_child][1], sendmsg, strlen(sendmsg));
				}
			}
			else if(token == "STATE")
			{
				token = strtok(NULL, del);	
				if(token != NULL)
				{
					sscanf(token,"%d", &target_child);
					if(valid(childrenState[target_child]))
						write(p2c_pfd[target_child][1], sendmsg, strlen(sendmsg));					
				}
			}
		}

		for(int i = 0; i < children_nm; i++){
			if(FD_ISSET(c2p_pfd[i][0], &readfds)){
				char buf[1000] = {};
				int n = read(c2p_pfd[i][0], buf, sizeof(buf)-1);
					// processing child input
				//printf("parent get from %d %d bytes:[start]%s[end]\n",i,n, buf);
				if(strcmp(buf,"[DHCP_DISCOVER]") == 0)
				{
					childrenState[i] = 1;
				}
				else if(strcmp(buf, "[DHCP OFFER]") == 0)
				{
					childrenState[i] = 2;
				}
				else if(strcmp(buf, "sth wrong!") == 0)
				{
					childrenState[i] = 3;
				}
				else if(strcmp(buf, "[DHCP REQUEST]") == 0)
				{
					childrenState[i] = 4;
				}
				else if(strcmp(buf, "[DHCP ACK] success!") == 0)
				{
					childrenState[i] = 5;
				}
				else if(strcmp(buf, "something wrong!") == 0)
				{
					childrenState[i] = 6;
				}
				else if(strcmp(buf, "[FINISH]") == 0)
				{
					childrenState[i] = 7;
				}
				else{
					childrenState[i] = 8;
				}
				memset(buf,0,1000);	
				
			}
		}
		
		
		// fgets (buf, 128, stdin);
		// printf("buf:%s\n",buf);
		// //select does not work as expect.

		//puts("hois");
	}
	printf("wait\n");
	while(wait(NULL)>0){};

	puts("children are all dead");
	for(int i = 0; i < children_nm; i++){
		close(c2p_pfd[i][0]);
		// close(pfd[i][1]);
	}
}
