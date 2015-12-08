#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<sys/stat.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write, access
#include <openssl/sha.h>	//sha1

#include <openssl/hmac.h>	//base64
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define perror printf
unsigned int fsize(const char *filename) 
{
    struct stat st; 

    if (stat(filename, &st) == 0) {
	printf("%s %zu bytes\n", filename, st.st_size);
	return st.st_size;
    }
    else {
	perror("fsize(%s) error\n", filename);
    	return -1; 
    }
}

/* setFinBit = 1, if the FINAL packet for this message
 * setFinBit = 0, if need other packet for this message
 * opcode = 0, if not first packet
 * opcode = 1, if first packet of text message
 * opcode = 2, if first packet of blob message
 */
unsigned int setPacketHeader(unsigned char *pkt, unsigned long size, int setFinBit, unsigned char opcode)
{
    printf("%s(%lx, %d, %d)\n", __func__, size, setFinBit, opcode);
    unsigned int i;

    if (setFinBit)
	pkt[0] |= 0x80;
    else
	pkt[0] |= 0x00;
    pkt[0] |= opcode;

    if (size > 0xffff) {
	pkt[1] = 0x7f;
	for (i = 0; i < 8; i++)
		pkt[9-i] = *((unsigned char *)(&size)+i);
    }
    else if (size > 0x7d) {
	pkt[1] = 0x7e;
	for (i = 0; i < 2; i++)
		pkt[3-i] = *((unsigned char *)(&size)+i);
    }
    else {
	i = 0;
	pkt[1] = *(unsigned char *)&size;
    }
    i += 2;

    int j;
    printf("%d packet header:\n", i);
    for (j = 0; j < i; j++) {
	if (!(j+1 & 0xf)) printf("%02x\n", pkt[j]);
	else if (!(j+1 & 0x3)) printf("%02x  ", pkt[j]);
	else printf("%02x ", pkt[j]);
    }
    printf("\n");
    return i;
}

void b64Encode(const unsigned char *input, char *buf)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, SHA_DIGEST_LENGTH);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    memcpy(buf, bptr->data, bptr->length-1);	// ignore newLine char

    BIO_free_all(b64);
}
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

    int i = 0, n = 0;
    if ((read_size = recv(client_sock, msg, 1024, 0)) > 0 ) {
        //Send the message back to client
        //write(client_sock , client_message , strlen(client_message));
	printf("client:\n%s\n", msg);
	while (i < read_size) {
	    n = argLength(msg+i, read_size-i);
	    if (strncmp(msg+i, "Upgrade:", 8) == 0 ||
	    	strncmp(msg+i, "Connection:", 11) == 0 ||
	    	strncmp(msg+i, "Sec-WebSocket-Protocol:", 23) == 0) {
		strncat(reply, msg+i, n+2);	// include \r\n
		printArgs(msg+i, n, ASCII);
	    }
	    else if (strncmp(msg+i, "Sec-WebSocket-Key:", 18) == 0) {
		unsigned char hashString[128] = {0};
		unsigned char hashDigest[SHA_DIGEST_LENGTH] = {0};
		char buf[256] = {0};
		int j;
		printf("**");
		printArgs(msg+i, n, ASCII);
		strncpy(hashString, msg+i+19, n-19);
		strcat(hashString, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
		SHA1(hashString, strlen(hashString), hashDigest);
		for (j = 0; j < SHA_DIGEST_LENGTH; j++) {
		    sprintf((char*)&(buf[j*2]), "%02x", hashDigest[j]);
		}
		printf("\thashString: %s\n", hashString);
		printf("\thashDigest: %s\n", buf);
		memset(buf, 0, 256);
		b64Encode(hashDigest, buf);
		printf("\tb64: %s\n", buf);
		strcat(reply, "Sec-WebSocket-Accept:");
		strcat(reply, buf);
		strcat(reply, "\r\n");
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
	strcat(reply, "\r\n");
    }

    printf("server:\n%s\n", reply);
    send(client_sock, reply, strlen(reply), 0);

    char fileName[128] = {0};
    unsigned char *tmp;
    for (i = 1; i < 10000; i++) {
	FILE *fd;
	unsigned int fileLen, headerLen, ret;
	unsigned char header[20] = {0};
        sprintf(fileName, "%s%08d.jpg", argv[1], i);
	if (access(fileName, R_OK) == -1) {
	    perror("Wrong fileName: %s\n", fileName);
	    break;
	}
	if ((fd = fopen(fileName, "rb")) == NULL) {
	    perror("Wrong fileName: %s\n", fileName);
	    break;
	}
	fileLen = fsize(fileName);
	headerLen = setPacketHeader(header, fileLen, 1, 2);
	if ((tmp = malloc(headerLen + fileLen)) == NULL) {
	    perror("malloc failed\n");
	    break;
	}
	memset(tmp, 0, headerLen + fileLen);
	memcpy(tmp, header, headerLen);
	if ((ret = fread(tmp + headerLen, 1, fileLen, fd)) != fileLen) {
	    perror("fread size error: %d/%d bytes\n", fileLen, ret);
	    break;
	}
	send(client_sock, tmp, headerLen + fileLen, 0);
        free(tmp);
	fclose(fd);
	usleep(33300);
    }
#if 0
    char test[20] = {0};
    char tmp[] = "helloWorld";
    unsigned int pktLen;
    pktLen = setPacket(test, tmp, strlen(tmp), 0, 1);
    send(client_sock, test, pktLen, 0);
    memset(test, 0, 20);
    pktLen = setPacket(test, tmp, strlen(tmp), 1, 0);
    send(client_sock, test, pktLen, 0);
#endif
    getchar();
     
    if(read_size == 0) {
        perror("Client disconnected\n");
    }
    else if(read_size == -1) {
        perror("recv failed\n");
    }
     
    return 0;
}
