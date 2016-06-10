// main.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "dns_classes.h"

extern int startup_server(LPVOID params);
int startup_client(LPVOID params);

void print_usage()
{
	printf("Usage: DNSResponder [A_IP] [B_IP]\n");
}

int main(int argc, char **argv)
{
	/*argc = 3;
	argv[1] = "128.194.135.82";
	argv[2] = "1.0.0.0";*/

	srand(time(NULL));

	WSADATA wsaData;

	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		_return(1);
	}

	if (argc != 3) {
		printf("hw1: error: incorrect number of arguments\n");
		print_usage();
		_return(1);
	}

	// more descriptive names
	char *a_ip = argv[1], *b_ip = argv[2];
	if (inet_addr(a_ip) == INADDR_NONE || inet_addr(b_ip) == INADDR_NONE) {
		printf("DNSResponder: error: invalid IP address for server(s)\n");
		print_usage();
		_return(1);
	}

	ThreadParams tp;
	tp.a_ip = a_ip;
	tp.b_ip = b_ip;
	tp.cf = &(ClientFunctions());
	//tp.eventQuit = CreateEvent(NULL, true, false, NULL);

	HANDLE client = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startup_client, &tp, 0, NULL);
	if (client == NULL) {
		printf("CreateThread() error %d\n", WSAGetLastError());
		_return(1);
	}

	HANDLE server = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startup_server, &tp, 0, NULL);
	if (server == NULL) {
		printf("CreateThread() error %d\n", WSAGetLastError());
		_return(1);
	}

	if (WaitForSingleObject(client, INFINITE) == WAIT_FAILED) {
		printf("WaitForSingleObject() error %d\n", WSAGetLastError());
		_return(1);
	}
	CloseHandle(client);

	if (WaitForSingleObject(server, INFINITE) == WAIT_FAILED) {
		printf("WaitForSingleObject() error %d\n", WSAGetLastError());
		_return(1);
	}
	CloseHandle(server);

	//printf("Ready to receive DNS queries...\n");

    return 0;
}

