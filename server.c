#include <stdio.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <libexplain/select.h>  // Details when select fails. Link with -lexplain
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h> // To get tid, through syscall.

#define AUTH	0
#define MAX_CL	2000
#define MAXMSG	512
#define MAX_THREADS 2000

int test = 0;
fd_set active_fd_set, read_fd_set;
int validReq, invalidReq, maliciousReq;
int bnt, nt;
int connections;

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

int make_socket(uint16_t port)
{
	int sock;
	struct sockaddr_in name;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if(sock < 0) {
		printf("error creating socket\n");
		exit(EXIT_FAILURE);
	}

	printf("Created socket\n");
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	name.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind(sock,  (struct sockaddr *) &name, sizeof(name) ) < 0) {
		printf("/bind() error\n");
		exit(EXIT_FAILURE);
	}
	printf("Bind socket\n");

	return sock;
}

void clear_buffer(char *b)
{
	for (int i = 0; i < MAXMSG; i++)
		b[i] = '\0';
}

int read_from_client(int fd)
{
	char buffer[MAXMSG];
	int nbytes;
	clear_buffer(buffer);	

	nbytes = read(fd, buffer, MAXMSG);
	printf("Read count: %d\n", nbytes);

	if(nbytes < 0) {
		printf("/error read() fd: %d\n", fd);
		exit(EXIT_FAILURE);
	} else if(nbytes == 0) {
		return -1;
	} else {
		printf("Server, got: %s\n", buffer);
		
		if( strcmp("123", buffer) == 0) {
			clear_buffer(buffer);

			if( send(fd, "abb3cfe", strlen("abb3cfe"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}
			printf("Access granted.\n");
			validReq++;	
			return AUTH;
		} else if( strcmp("111", buffer) == 0) {

			clear_buffer(buffer);

			if( send(fd, "22833f4", strlen("22833f4"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}
			printf("Access granted.\n");
			validReq++;	
			return AUTH;
		} else if(strcmp("check", buffer) == 0) {
		
			clear_buffer(buffer);
			
			if( send(fd, "ok", strlen("ok"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}
			printf("Server periodic proccess connection.\nSuccess\n");
			validReq++;	
			return AUTH;		
		}else {
			printf("Invalid password given\nConnection closing\n");
			invalidReq++;	
			clear_buffer(buffer);
			
			if( send(fd, "invalid", strlen("invalid"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}
			return AUTH;
		}
	}
}

void close_con(int fd)
{
	close(fd);
	FD_CLR(fd, &active_fd_set);
	read_fd_set = active_fd_set;
}

void * serveReq(void * arg)
{
	int i = * (int *) arg;
	struct pollfd pfd;
	int pret;
	
	pfd.fd = i;
	pfd.events = POLLIN;
	pid_t tt = syscall(SYS_gettid);
	printf("\t\t %d Handling FD: %d\n",tt, i);	

	pret = poll(&pfd, 1, 2000);

	if(pret == 0) {

		printf("TIME_OUT in FD: %d  %d occured.\n", i, tt);
		
		pthread_mutex_lock(&mtx);
		
		maliciousReq++;	
		close_con(i);
		pthread_mutex_unlock(&mtx);
		
		printf("reducing connections after a TIMEOUT\n");
		pthread_exit(NULL);

	} else 	if( read_from_client(i) <= 0) {

		printf(" \t\t\t\tCLOSING: %d\n", i);
		
		pthread_mutex_lock(&mtx);
		close_con(i);		
		pthread_mutex_unlock(&mtx);

		printf("Reducing connections\n");
	}
}

int main(int argc, char *argv[])
{
	pthread_t thread[MAX_THREADS];

	int fd_differents[MAX_THREADS];
	int new;
	int sock, sockf;
	int i;
	struct sockaddr_in client_name;
	size_t size;
	int retv, retv2;
	int fret;

	sock = make_socket(8888);

	printf("INITIAL SOCKET FD: %d\n", sock);
	printf("Server...\n");
	
	if( listen(sock, MAX_CL)!= 0 ) {
		printf("/error listen()\n");
		exit(EXIT_FAILURE);
	}

	printf("Awaiting connections\n");

	fret = fork();

	if(fret == 0) {
		/*	child process connects periodically */
		struct sockaddr_in fserv;	
		char testm[10];
		char testreply[12];
		int cc = 0;	

		while(1) {

			sockf = socket(AF_INET, SOCK_STREAM, 0);
		
			if(sockf == -1) {
				perror("Error in helper socket.\n");
				exit(EXIT_FAILURE);
			}
		
			fserv.sin_addr.s_addr = inet_addr("127.0.0.1");
			fserv.sin_family = AF_INET;
			fserv.sin_port = htons( 8888 );
			
			cc++;
			printf("CC: %d\n", cc);
			sleep(2);
	
			if(connect(sockf, (struct sockaddr *) &fserv, sizeof(fserv)) < 0) {
				perror("connect failed\n");
				return 1;
			}

			printf("Helper connected\n");
				
			strcpy(testm, "check");
		
			if( send(sockf, testm, strlen(testm), 0) < 0) {
				printf("send failed\n");
				return (-1);
			}
			
			int reb;
			reb = recv(sockf, testreply, 2000, 0);

			if(reb < 0) {
				printf("recv failed.\n");
				exit(-1);
			}
	
			if(reb) {
				printf("GOT REPLY\n");
			}
			close(sockf);
		}
	}

	FD_ZERO(&active_fd_set);
	FD_SET(sock,&active_fd_set);

	while(1) {
		while( pthread_mutex_trylock(&mtx) != 0 ) { 
			;
		}
		read_fd_set = active_fd_set;
		
		if( (select ( FD_SETSIZE, &read_fd_set,NULL, NULL, NULL)) < 0) {
			fprintf(stderr,"error in select: %s\n", explain_select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL));
			exit(EXIT_FAILURE);
		} 
		pthread_mutex_unlock(&mtx);

		for( i = 0; i < FD_SETSIZE; i++) {

			if(FD_ISSET(i, &read_fd_set)) {

				if( i == sock) {
					pthread_mutex_lock(&mtx);				
					
					size = sizeof(client_name);
					new = accept(sock, (struct sockaddr *) &client_name,(socklen_t *) &size);

					if(new < 0) {
						printf("/error accept()\n");
						exit(EXIT_FAILURE);
					}
					fd_differents[nt] = new;	
					printf("Server: con fr. %s, port: %d\n", inet_ntoa(client_name.sin_addr), ntohs(client_name.sin_port));
					connections++;
					FD_SET(new, &active_fd_set);
					printf("Connections: %d SIKOSA to %d\n",connections, new);
					pthread_create(&thread[nt], NULL, (void *) serveReq, (void *) &fd_differents[nt]);
					nt++;

					pthread_mutex_unlock(&mtx);	

				} else {
					;
				}	
			}
		}
	}
	pthread_join(thread[nt-1],NULL);
	
	return (0);
}
