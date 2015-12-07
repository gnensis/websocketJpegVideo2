CC=gcc
#CC=arm-hisiv300-linux-gcc
all:
	$(CC) server.c -lcrypto -Og -o server
clean:
	rm -f server
