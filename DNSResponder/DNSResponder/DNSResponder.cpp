// DNSResponder.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "dns_classes.h"

extern bool recv_buf(SOCKET sock, char *out_buf, struct sockaddr_in *remote);
extern bool respond(char *in_buf, char *out_buf, char *b_ip, int *len);
extern bool send_buf(SOCKET sock, char *buf, int len, struct sockaddr_in remote);

void print_usage()
{
	printf("Usage: DNSResponder [B_IP]\n");
}

int main(int argc, char **argv)
{
	/*argc = 2;
	argv[1] = "1.0.0.0";*/

	WSADATA wsaData;

	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		_return(1);
	}

	if (argc != 2) {
		printf("hw1: error: incorrect number of arguments\n");
		print_usage();
		_return(1);
	}

	// more descriptive names
	char *b_ip = argv[1];
	if (inet_addr(b_ip) == INADDR_NONE) {
		printf("DNSResponder: error: invalid IP address for server(s)\n");
		print_usage();
		_return(1);
	}

	//printf("Ready to receive DNS queries...\n");

	while (true) {
		char in_buf[MAX_DNS_SIZE], out_buf[MAX_DNS_SIZE];
		int len;
		struct sockaddr_in remote;

		SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == INVALID_SOCKET) {
			printf("socket() error %d", WSAGetLastError());
			_return(1);
		}

		recv_buf(sock, in_buf, &remote);
		respond(in_buf, out_buf, b_ip, &len);
		send_buf(sock, out_buf, len, remote);
	}

    return 0;
}

