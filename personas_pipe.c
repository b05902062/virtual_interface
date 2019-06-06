#include <stdio.h>
#include <stdlib.h>
#include<sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#define MAX_CHILD 1000
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
	int pfd[MAX_CHILD][2];
	for(int i = 0; i < children_nm; i++)
	{
		if(pipe(pfd[i]) == -1){
			perror("pipe");
			exit(-1);
		}
		pid[i] = fork();
		if(pid[i] == 0)
		{
			// need to handle parent's instruction to children
			// close(STDOUT_FILENO);
			dup2(pfd[i][1], STDOUT_FILENO);
			close(pfd[i][0]);
			close(pfd[i][1]);
			char buf[10];
			sprintf(buf,"%d",i);
			char str1[100], str2[100];
			memset(str1, '\0', sizeof(str1));
			memset(str2, '\0', sizeof(str2));
			memcpy(str1, argv[2], strlen(argv[2]));
			memcpy(str2, argv[3], strlen(argv[3]));
			if(execlp("./getip","./getip", str1, buf, str2, (char*) 0)<0){
				perror("execlp()");
				printf("child:%d\n",i);
				exit(-1);
			};
		}
		else
		{	
			close(pfd[i][1]);
			puts("I am parent");
		}
	}
	int maxfd = 0;
	for(int i = 0; i < children_nm; i++){
		if(pfd[i][0] > maxfd) maxfd = pfd[i][0];
	}
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	fd_set readfds;
	while(1){
		FD_ZERO(&readfds);
		// should need to add STDIN to get user input
		for(int i = 0; i < children_nm; i++){
			FD_SET(pfd[i][0], &readfds);
		}
		// printf("select\n");
		if(select(maxfd+1, &readfds, NULL, NULL, &tv)<0){
			perror("select()");
			exit(-1);
		};

		for(int i = 0; i < children_nm; i++){
			if(FD_ISSET(pfd[i][0], &readfds)){
				char buf[1000] = {};
				int n = read(pfd[i][0], buf, sizeof(buf)-1);
				//n = read(pfd[i][0], buf, sizeof(buf)-1);
					// processing child input
				printf("parent get from %d %d bytes:[start]%s[end]\n",i,n, buf);
				memset(buf,0,1000);	
				
			}
		}
	}
	printf("wait\n");
	while(wait(NULL)>0){};

	puts("children are all dead");
	for(int i = 0; i < children_nm; i++){
		close(pfd[i][0]);
		// close(pfd[i][1]);
	}
}
