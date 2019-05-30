#include <stdio.h>
#include <stdlib.h>
#include<sys/wait.h>
#include <unistd.h>
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
			printf("child:%d is ready to go\n",i);
			char buf[10];
			sprintf(buf,"%d",i);
			execlp("getip","getip", argv[2], buf, argv[3], NULL);
		}
		else
		{
			puts("I am parent");
		}
	}

	while(wait(NULL));

	puts("childrne are all die");
}
