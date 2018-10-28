#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
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
#include "color.h"
#include <errno.h>

#define AUTH	0
#define MAX_CL 10000
#define MAXMSG	512
#define MAX_THREADS 10000

int test = 0;
fd_set active_fd_set, read_fd_set;
int validReq, invalidReq, maliciousReq;
int bnt, nt;
int connections;
int topen, tclosed, times_over;

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
	
	int enable = 1;	
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		printf("/error setsockopt\n");
		exit(-1);
	}


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

	pid_t vt = syscall(SYS_gettid);

	if(nbytes < 0) {

		printf("/error read() fd: %d %d\n", fd, vt);
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

		} else if ( strcmp("111", buffer) == 0) {

			clear_buffer(buffer);

			if( send(fd, "22833f4", strlen("22833f4"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}

			printf("Access granted.\n");
			validReq++;

			return AUTH;

		} else if (strcmp("check", buffer) == 0) {

			clear_buffer(buffer);

			if( send(fd, "ok", strlen("ok"), 0) < 0) {
				printf("/error send()\n");
				exit(EXIT_FAILURE);
			}

			printf("Server periodic proccess connection.\nSuccess\n");
			validReq++;

			return AUTH;

		} else {

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
	if( close(fd) != 0) {
		printf("%s close error : %d\n", KRED, errno);
		exit(-1);
	}
	FD_CLR(fd, &active_fd_set);
	read_fd_set = active_fd_set;
}

void * serveReq(void * arg)
{
	int i = * (int *) arg;
	struct pollfd pfd;
	int pret;
	
	/* guarantees that thread resources are deallocated upon return */
	if( pthread_detach( pthread_self()) != 0) {
		printf("/error detatching thread.\n");
		exit(EXIT_FAILURE);
	}

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	int s = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, PTHREAD_CANCEL_DEFERRED);

	if(s != 0) {
		printf("Error on setting asynchronous type cancelation\n");

	}

	pfd.fd = i;
	pfd.events = POLLIN;
	pid_t tt = syscall(SYS_gettid);
	printf("\t\t %d Handling FD: %d\n",tt, i);

	pret = poll(&pfd, 1, 2000);

	if(pret == 0) {

		printf("TIME_OUT in FD: %d  %d occured.\n", i, tt);

		pthread_mutex_lock(&mtx);
		tclosed++;
		maliciousReq++;
		close_con(i);
		pthread_mutex_unlock(&mtx);

		printf("reducing connections after a TIMEOUT\n");
		pthread_exit(NULL);

	} else 	if( read_from_client(i) <= 0) {

		printf(" \t\t\t\tCLOSING: %d\n", i);
		pthread_mutex_lock(&mtx);
		tclosed++;
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
	int fret, child_proc;


	sock = make_socket(8888);

	printf("INITIAL SOCKET FD: %d\n", sock);
	printf("Server with PID: %d...\n", getpid());

	if( listen(sock, MAX_CL)!= 0 ) {
		printf("/error listen()\n");
		exit(EXIT_FAILURE);
	}

	printf("Awaiting connections\n");

	fret = fork();
	child_proc = fret;
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

			if( close(sockf) != 0) {
				printf("Error closing socket: %d\n", errno);
				exit(EXIT_FAILURE);
			}
		}
	}

	FD_ZERO(&active_fd_set);
	FD_SET(sock,&active_fd_set);

	while(1) {

		int tmp;
		printf("times_overflow: %d open: %d close: %d DIFF: %d\n",times_over, topen, tclosed, topen - tclosed);

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

					printf("NT: %d\n", nt);

					pthread_mutex_lock(&mtx);
					size = sizeof(client_name);

					new = accept(sock, (struct sockaddr *) &client_name,(socklen_t *) &size);

					if(new < 0) {

						printf("%s/error accept()--: %d\n",KRED, errno);

						/* Too many open files.(maximun open file-descriptors used */
						//TO-DO:  Solution 1: clean all threads, restart Server.

						if(errno == EMFILE) {

							printf("%sMissing connection.%s\n",KRED,KWHT);

							for(int k = 4; k < 1024; k++ ) {

								if( close(k) < 0) {
									printf("Error closing socket: %d.\n", errno);
									exit(-1);
								}

								printf("%sClosed socket: %d %s\n",KRED, k, KWHT);

								// attempt to cancel threads.. always returns error.. ? WHY?
								if( pthread_cancel(thread[k]) != 0) {
									printf("Error %d canceling thread: %d\n", errno, k);
								} else {
									printf("Thread: %d killed\n", k);

								}

								FD_CLR(k, &active_fd_set);
							}
							FD_ZERO(&active_fd_set);
							FD_SET(sock,&active_fd_set);

							pthread_mutex_unlock(&mtx);
							sleep(1);

						}
					}

					fd_differents[nt] = new;

					printf("Server: con fr. %s, port: %d\n", inet_ntoa(client_name.sin_addr), ntohs(client_name.sin_port));
					connections++;
					FD_SET(new, &active_fd_set);
					printf("Connections: %d SIKOSA to %d\n",connections, new);

					if(nt > MAX_THREADS) {
						tmp = new;

						printf("%s Rollback variable to prevent out of bound allocation.%s\n", KRED, KWHT);

						for( int r = 4; r < FD_SETSIZE; r++) {

							if(!FD_ISSET(r, &read_fd_set)) {

								nt = r;
								printf("\t\tSetting %d as nevalue!\n", r);
								fd_differents[nt] = new;
								break;
							}
						}

					}

					topen++;
					pthread_create( &thread[nt], NULL, (void *) serveReq, (void *) &fd_differents[nt]);
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
