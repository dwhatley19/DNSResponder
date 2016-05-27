#include "stdafx.h"
#include "dns_classes.h"
using namespace std;

extern bool recv_buf(SOCKET sock, char *out_buf, struct sockaddr_in *remote);
extern bool respond(char *in_buf, char *out_buf, char *b_ip, int *len);
extern bool send_buf(SOCKET sock, char *buf, int len, struct sockaddr_in remote);

int startup_server(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;

	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		printf("[server] socket() error %d", WSAGetLastError());
		_return(1);
	}

	// Connect socket
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));

	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(53);

	// Bind socket
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		printf("Socket error %d\n", WSAGetLastError());
		_return(1);
	}

	while (true) {
		WSADATA wsaData;

		//Initialize WinSock; once per program run
		WORD wVersionRequested = MAKEWORD(2, 2);
		if (WSAStartup(wVersionRequested, &wsaData) != 0) {
			printf("WSAStartup error %d\n", WSAGetLastError());
			_return(1);
		}

		char in_buf[MAX_DNS_SIZE], out_buf[MAX_DNS_SIZE];
		int len;
		struct sockaddr_in remote;

		bool res = recv_buf(sock, in_buf, &remote);
		if (res) {
			res = respond(in_buf, out_buf, tp->b_ip, &len);
			if (res) send_buf(sock, out_buf, len, remote);
		}
	}

	closesocket(sock);
}

int startup_client(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;
	ClientFunctions *cf = tp->cf;

	char lookup[MAX_DNS_SIZE];

	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		printf("socket() error %d", WSAGetLastError());
		_return(1);
	}

	// Connect socket
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));

	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);

	// Bind socket
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		printf("Socket error %d\n", WSAGetLastError());
		_return(1);
	}

	while (true) {
		printf("Enter a lookup to process, in the form <6-digit hash>.iresearch.us. ");
		printf("Or press Ctrl + C to quit.\n");
		scanf("%s", lookup);

		if (strlen(lookup) != 19) {
			printf("Invalid lookup: Not 19 characters long.\n\n");
			continue;
		}
		printf("\n");

		// Check if valid IP
		DWORD IP = inet_addr(lookup);
		int qtype;
		if (IP == INADDR_NONE) qtype = DNS_A;
		else qtype = DNS_PTR;

		// Make buffer to send
		char buf[MAX_DNS_SIZE];
		int len;
		int id = cf->make_buf(sock, buf, lookup, qtype, &len);

		// Send & receive buffer
		// NEED SEMAPHORE
		char out_buf[MAX_DNS_SIZE + 1];
		bool res = cf->send_buf(sock, buf, out_buf, tp->a_ip, len);
		unsigned char *uout_buf = (unsigned char *)out_buf;

		if (res == false) {
			printf("Read operation failed.\n");
			_return(1);
		}

		cf->parse_buf(uout_buf, id);

		printf("\n\nSuccess!\n\n");
	}

	closesocket(sock);
}