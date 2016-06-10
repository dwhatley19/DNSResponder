#include "stdafx.h"
#include "dns_classes.h"
using namespace std;

extern bool recv_buf(SOCKET sock, char *out_buf, struct sockaddr_in *remote);
extern bool respond(char *in_buf, char *out_buf, char *b_ip, int *len);
extern bool send_buf(SOCKET sock, char *buf, int len, struct sockaddr_in remote);
extern bool parse_name(char *buf, char *out);

int startup_recv(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;

	while (WaitForSingleObject(tp->eventQuit, 0) != WAIT_OBJECT_0) {
		char in_buf[MAX_DNS_SIZE], out_buf[MAX_DNS_SIZE];
		int len;

		bool res = recv_buf(tp->serverSock, in_buf, &tp->remote);
		if (res) {
			char name[MAX_DNS_SIZE];
			parse_name(in_buf + sizeof(FixedDNSHeader), name);
			QueryHeader *qh = (QueryHeader *)(in_buf + strlen(name) + 2 + sizeof(FixedDNSHeader));

			res = respond(in_buf, out_buf, tp->b_ip, &len);

			if (res) {
				if (ntohs(qh->qtype) == DNS_AAAA) {
					send_buf(tp->serverSock, out_buf, len, tp->remote);
				}
				else {
					// send to other thread to send
					EnterCriticalSection(&tp->cs);
					tp->serverQ.push(Packet(out_buf, len, tp->remote));
					ReleaseSemaphore(tp->qSize, 1, NULL);
					LeaveCriticalSection(&tp->cs);
				}
			}
		}
	}

	return true;
}

int startup_send(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;
	
	while (true) {
		HANDLE stuff[2] = { tp->eventQuit, tp->qSize };

		// check if finished or semaphore waiting
		// if neither of these two conditions happens,
		// then result == WAIT_OBJECT_0 + 1
		int result = WaitForMultipleObjects(2, stuff, FALSE, INFINITE);

		if (result == WAIT_FAILED) {
			printf("WaitForMultipleObjects() error %d\n", WSAGetLastError());
			_return(1);
		}
		else if (result == WAIT_OBJECT_0) {
			if (SetEvent(tp->eventQuit) == FALSE) {
				printf("SetEvent() error %d\n", WSAGetLastError());
				_return(1);
			}
			break;
		}

		// wait for a while
		Sleep(0);

		// we know there's something to do
		EnterCriticalSection(&tp->cs);

		// send to server X
		Packet out_buf = tp->serverQ.front();

		send_buf(tp->serverSock, out_buf.buf, out_buf.len, out_buf.dest);
		tp->serverQ.pop();

		LeaveCriticalSection(&tp->cs);
	}
}

int startup_server(LPVOID params)
{
	ThreadParams *tp = (ThreadParams *)params;

	tp->serverSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (tp->serverSock == INVALID_SOCKET) {
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
	if (bind(tp->serverSock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
		printf("Socket error %d\n", WSAGetLastError());
		_return(1);
	}

	InitializeCriticalSection(&tp->cs);
	tp->qSize = CreateSemaphore(NULL, 0, 0x3FFFFFFF, NULL);
	tp->eventQuit = CreateEvent(NULL, true, false, NULL);

	HANDLE recvThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startup_recv, tp, 0, NULL);
	HANDLE sendThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startup_send, tp, 0, NULL);

	if (recvThread == NULL || sendThread == NULL) {
		printf("CreateThread() error %d\n", WSAGetLastError());
		_return(1);
	}

	int res = WaitForSingleObject(tp->eventQuit, INFINITE);
	if (res == WAIT_FAILED) {
		printf("WaitForSingleObject() error %d\n");
		_return(1);
	}

	closesocket(tp->serverSock);
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
		printf("Or type EXIT! to quit.\n");
		scanf("%s", lookup);

		// not needed.
		/*if (strlen(lookup) != 19) {
			printf("Invalid lookup: Not 19 characters long.\n\n");
			continue;
		}*/
		printf("\n");

		if (strcmp(lookup, "EXIT!") == 0) {
			if (SetEvent(tp->eventQuit) == FALSE) {
				printf("SetEvent() error %d\n");
				_return(1);
			}
			break;
		}

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