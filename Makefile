CC=gcc
#CC=arm-hisiv300-linux-gcc
all:
	$(CC) server.c -Og -o server
clean:
	rm -f server
