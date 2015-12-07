#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write

int isAsciiArgs(char *p, int len)
{
	for (; len > 0; len--, p++) {
		if (*p == ':') 
			return 1;
	}
	return 0;
}
int argLength(char *p, int last)
{
    	int i;
	for (i = 0; *(p+i) != '\r' && i <= last; i++) ;
	return i;
}
#define HEX 0
#define ASCII 1
void printArgs(char *p, int n, int type)
{
	for (; n > 0; n--, p++) {
	    if (type == HEX)
		printf("0x%x ", *p);
	    else
	    	putchar(*p);
	}
	printf("\n");
}
int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c , read_size;
    struct sockaddr_in server , client;
    char msg[1024] = {0};
    char reply[1024] = {0};
     
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1) {
        perror("socket() err\n");
	return 0;
    }
    printf("socket created\n");
     
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(9999);
     
    if (bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
        perror("bind() err\n");
        return 0;
    }
    printf("bind done\n");
     
    listen(socket_desc , 1);
    printf("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
     
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0) {
        perror("accept() err\n");
        return 0;
    }
    printf("Connection accepted\n");
     
    strcpy(reply, "HTTP/1.1 101 Switching Protocols\r\n");

    while((read_size = recv(client_sock, msg, 1024, 0)) > 0 ) {
        //Send the message back to client
        //write(client_sock , client_message , strlen(client_message));
	printf("client:\n%s\n", msg);
	int i = 0, n = 0;
	while (i < read_size) {
	    n = argLength(msg+i, read_size-i);
	    if (strncmp(msg+i, "Upgrade:", 8) == 0 ||
	    	strncmp(msg+i, "Connection:", 11) == 0 ||
	    	strncmp(msg+i, "Sec-WebSocket-Protocol:", 23) == 0) {
//		strncat(reply, msg+i, j);
		printArgs(msg+i, n, ASCII);
	    }
	    else if (strncmp(msg+i, "Sec-WebSocket-Key:", 18) == 0) {
		printf("**");
		printArgs(msg+i, n, ASCII);
	    }
	    else if (isAsciiArgs(msg+i, n)) {
		printf("--");
		printArgs(msg+i, n, ASCII);
	    }
	    else {
		printf("--");
		printArgs(msg+i, n, HEX);
	    }
	    fflush(stdout);
	    i += (n+2);
	}
    }
     
    if(read_size == 0) {
        perror("Client disconnected\n");
    }
    else if(read_size == -1) {
        perror("recv failed\n");
    }
     
    return 0;
}
