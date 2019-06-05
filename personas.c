#include <stdio.h>
#include <stdlib.h>
#include<sys/wait.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char **argv)
{	
	int children_nm;
	pid_t pid[100];
	if(argc!=4){
		fprintf(stderr,"usage: ./Personas <process_nm> <name of a connected interface>  <xid>\n");
		exit(-1);
	}
	sscanf(argv[1],"%d", &children_nm);
	for(int i = 0; i < children_nm; i++)
	{
		pid[i] = fork();
		if(pid[i] == 0)
		{
			//printf("child:%d is ready to go\n",i);
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
			puts("I am parent");
		}
	}

	while(wait(NULL)>0);

	puts("children are all dead");
}
