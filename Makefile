all:
	arm-hisiv300-linux-gcc server.c -o server
clean:
	rm -f server
