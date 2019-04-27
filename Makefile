all:
	gcc -pthread -w -g main.c -o send
	sudo ./send
