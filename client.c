#include<stdio.h> 
#include<stdlib.h> 
#include<string.h>    
#include<sys/socket.h> 
#include<arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include "color.h" // color red for fail, green for authenticated message.

char pass[10];

int main(int argc, char *argv[])
{
	struct timeval tv1, tv2;
	int malicious = 0;
	struct timeval tv = { 2, 0};

	if(argc != 2) {
		printf("Usage error: ./client.out [password]!\n");
		return (-1);
	}

	strcpy(pass, argv[1]);

	if(strcmp("666",pass) == 0)
		malicious++;

	int sock;
	struct sockaddr_in server;
	char message[1000], server_reply[2000];

	//Create socket
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock == -1)
	{
		printf("Could not create socket");
	}
	puts("Socket created");

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8888 );

	//Connect to remote server
	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("connect failed. Error");
		return 1;
	}

	puts("\tConnected\n");
	
	printf("Enter your password to authenticate\n");
	printf("against the authentication server.:\n");
//	scanf("%s", message);
	strcpy(message, pass);
	
	// malicious node just keeps the connection
	if(malicious) {
		printf("I will loop forever!\n");
		sleep(6000);	
	}	
	
	if( send(sock, message, strlen(message), 0) < 0) {
		puts("Send failed");
		return 1;
	}

	gettimeofday(&tv1, NULL);

	printf("Sended message\n");
	
	//Receive a reply from the server
	int nbytes = 0;

	// Forcing receive to fail after 2 seconds without getting a reply
	setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval)); 

	nbytes = recv(sock, server_reply, 2000, 0);

	if(nbytes < 0) {
		printf("%sRecv failed: pid:%d\n", KRED, getpid());	
		printf("Invalid credential provided most possible\n");
		printf("%s\n",KWHT);
		exit(-1);
	}

	if(nbytes){
		gettimeofday(&tv2, NULL);
		double time = (double) (tv2.tv_usec - tv1.tv_usec) + (double) (tv2.tv_sec - tv1.tv_sec)*1000000;
		printf("microseconds: %f\n",time);
	
		if(strcmp("invalid", server_reply) == 0) {
			printf("%s Failed to get key%s\n",KRED, KWHT);
			close(sock);
			return (0);	
		}	
		printf("%sAuthenticated.\n",KGRN);
		printf("pid: %d received key: %s\n",getpid(), server_reply);
		printf("%s Auth complete.\n",KWHT);
	} else if(nbytes == 0) {
		printf("%sFailed to access key..\n",KRED);
		printf("%sInvalid password\n",KWHT);
	}
	close(sock);
	printf("\t\t\t\t\tclose socket__CLIENT\n");
	
	return 0;
}
