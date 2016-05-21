#include "stdafx.h"
#include "dns_classes.h"
using namespace std;

extern bool recv_buf(SOCKET sock, char *out_buf, struct sockaddr_in *remote);
extern bool respond(char *in_buf, char *out_buf, char *b_ip, int *len);
extern bool send_buf(SOCKET sock, char *buf, int len, struct sockaddr_in remote);

int startup_server(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;

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
		respond(in_buf, out_buf, tp->b_ip, &len);
		send_buf(sock, out_buf, len, remote);
	}
}

int startup_client(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;
	ClientFunctions *cf = tp->cf;

	char lookup[MAX_DNS_SIZE];

	while (true) {
		printf("Enter a lookup to process. Or press Ctrl+C to quit.\n");
		scanf("%s", lookup);
		printf("\n");

		// Check if valid IP
		DWORD IP = inet_addr(lookup);
		int qtype;
		if (IP == INADDR_NONE) qtype = DNS_A;
		else qtype = DNS_PTR;

		SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == INVALID_SOCKET) {
			printf("socket() error %d", WSAGetLastError());
			_return(1);
		}

		// Make buffer to send
		char buf[MAX_DNS_SIZE];
		int len;
		int id = cf->make_buf(sock, buf, lookup, qtype, &len);

		// Send & receive buffer
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
}