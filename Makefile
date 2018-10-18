all:
	gcc -o client.out client.c
	gcc -o server.out -g server.c -lpthread -lexplain
clean:
	rm client.out
	rm server.out
