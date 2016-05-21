#include "stdafx.h"
#include "dns_classes.h"

using namespace std;

extern string typetoa(int type);

// Takes pointer to buffer, host.
// Type A
void make_questionA(char *buf, char *host)
{
	int cur_pos = 0, buf_pos = 0;
	int n = strlen(host);

	// while not at end of string...
	while (cur_pos < n) {
		// look for next dot, determine length
		char *next = strchr(host + cur_pos, '.');
		if (next == NULL) next = host + n;
		int len = next - (host + cur_pos);

		// copy to buf
		buf[buf_pos] = len;
		buf_pos++;
		memcpy(buf + buf_pos, host + cur_pos, len);

		cur_pos += (len + 1);
		buf_pos += len;
	}
	buf[buf_pos] = 0;
}

// Takes pointer to buffer, host.
// Type PTR
void make_questionPTR(char *buf, char *host)
{
	int cur_pos = 0, buf_pos = 0;
	int n = strlen(host);
	char reverse[20];

	// reverse entire IP
	for (int i = n - 1; i >= 0; --i) {
		reverse[i] = host[n - 1 - i];
	}
	reverse[n] = '\0';

	// now reverse segments
	while (cur_pos < n) {
		// look for next dot, determine length
		char *next = strchr(reverse + cur_pos, '.');
		if (next == NULL) next = reverse + n;
		int len = next - (reverse + cur_pos);

		// swap if necessary
		if (len == 2) {
			char t = reverse[cur_pos];
			reverse[cur_pos] = reverse[cur_pos + 1];
			reverse[cur_pos + 1] = t;
		}
		else if (len == 3) {
			char t = reverse[cur_pos];
			reverse[cur_pos] = reverse[cur_pos + 2];
			reverse[cur_pos + 2] = t;
		}

		// copy to buf
		buf[buf_pos] = len;
		buf_pos++;
		memcpy(buf + buf_pos, reverse + cur_pos, len);

		cur_pos += (len + 1);
		buf_pos += len;
	}

	// add in_addr & arpa
	buf[buf_pos] = 7;
	++buf_pos;
	memcpy(buf + buf_pos, "in-addr", 7);
	buf_pos += 7;

	buf[buf_pos] = 4;
	++buf_pos;
	memcpy(buf + buf_pos, "arpa", 4);
	buf_pos += 4;

	buf[buf_pos] = 0;
}

// Makes buffer to send to server.
USHORT ClientFunctions::make_buf(SOCKET sock, char *buf, char *host, int qtype, int *len)
{
	FixedDNSHeader *fd = (FixedDNSHeader *)buf;

	// TXID is the socket thingy
	int flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	fd->ID = htons(rand() + rand());
	fd->flags = flags;
	fd->questions = htons(1);
	fd->answers = htons(0), fd->authority = htons(0), fd->additional = htons(0);

	// Make the question
	if (qtype == DNS_A) make_questionA(buf + sizeof(FixedDNSHeader), host);
	else make_questionPTR(buf + sizeof(FixedDNSHeader), host);

	printf("Query : ");
	for (int i = 0; i < strlen(buf + sizeof(FixedDNSHeader) + 1); ++i) {
		if (buf[i + sizeof(FixedDNSHeader) + 1] < 32) printf(".");
		else printf("%c", buf[i + sizeof(FixedDNSHeader) + 1]);
	}

	printf(", type %d, TXID 0x%x\n", qtype, ntohs(fd->ID));

	// insert the query header
	int query_start = strlen(host) + 2 + sizeof(FixedDNSHeader);
	// take .in-addr.arpa into account
	if (qtype == DNS_PTR) query_start += 13;

	QueryHeader *qh = (QueryHeader *)(buf + query_start);

	qh->qtype = htons(qtype);
	qh->qclass = htons(DNS_INET);

	// null-terminate buffer
	buf[query_start + sizeof(QueryHeader)] = '\0';

	*len = query_start + sizeof(QueryHeader);

	return fd->ID;
}

// Sends in_buf to server and receives out_buf.
bool ClientFunctions::send_buf(SOCKET sock, char *in_buf, char *out_buf, char *server, int len)
{
	printf("Server: %s\n", server);
	printf("********************************\n");

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

	// Send buffer
	struct sockaddr_in remote;
	memset(&local, 0, sizeof(local));

	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(server); // server’s IP
	remote.sin_port = htons(53); // DNS port on server

	int sender_size = sizeof(remote);

	// Receive buffer
	int count = 0;
	while (count++ < MAX_ATTEMPTS) {
		printf("[client] Attempt %d with %d bytes...\n", count, len);

		if (sendto(sock, in_buf, len, 0, (struct sockaddr*)&remote, sender_size) == SOCKET_ERROR) {
			printf("Socket error %d\n", WSAGetLastError());
			_return(1);
		}

		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);

		struct timeval timeout;
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		// Check how many bytes available from socket
		clock_t c1 = clock();
		int res = select(0, &fd, NULL, NULL, &timeout);

		// Error check
		if (res == 0) {
			printf("[client] Timeout in %d ms\n", clock() - c1);
			continue;
		}
		else if (res == SOCKET_ERROR) {
			printf("[client] select() socket error %d\n", WSAGetLastError());
			_return(1);
		}

		// Receive
		if (res > 0) {
			// No receive loop necessary: each call to recvfrom is 1 packet
			int bytes = recvfrom(sock, out_buf, MAX_DNS_SIZE, NULL, (struct sockaddr*)&remote, &sender_size);
			if (bytes == SOCKET_ERROR) {
				// also catches too many bytes, so we're ok
				printf("[client] recv() socket error %d\n", WSAGetLastError());
				_return(1);
			}

			if (bytes <= sizeof(FixedDNSHeader)) {
				printf("\n  ++ invalid reply: smaller than fixed header\n");
				_return(1);
			}

			printf("[client] Response in %d ms with %d bytes\n", clock() - c1, bytes);
			buf_len = bytes;

			closesocket(sock);
			return true;
		}
	}

	closesocket(sock);
	return false;
}

// Parses binary buffer.
bool ClientFunctions::parse_buf(unsigned char *buf, USHORT id)
{
	// get first 32 bytes
	USHORT *head = (USHORT *)buf;

	printf("  TXID 0x%x flags 0x%x ", ntohs(head[0]), ntohs(head[1]));
	printf("questions %d answers %d authority %d additional %d\n",
		ntohs(head[2]), ntohs(head[3]), ntohs(head[4]), ntohs(head[5]));

	if (head[0] != id) {
		printf("  ++ invalid reply: TXID mismatch, sent 0x%x, received 0x%x\n",
			ntohs(id), ntohs(head[0]));
		_return(1);
	}

	// Rcode != 0
	if ((ntohs(head[1]) & 0xF) != 0) {
		printf("  failed with Rcode = %d\n", ntohs(head[1]) & 0xF);
		_return(1);
	}

	unsigned char *lstart = (unsigned char *)(head);
	int cur_pos = 12;

	// initialize cache
	for (int i = 0; i < MAX_DNS_SIZE; ++i) {
		cache[i] = "";
	}

	// 4 fields
	char *st[4] = { "questions", "answers", "authority", "additional" };
	for (int x = 0; x < 4; ++x) {
		printf(" ------------ [%s] ----------\n", st[x]);

		for (int i = 0; i < ntohs(head[2 + x]); ++i) {
			check_jump(cur_pos + 1, NUMRR_CHECK);

			if (x == 0) {
				// parsing questions field -> query header
				int final_pos = cur_pos;
				printf("\t%s", print_name(lstart, cur_pos, 1, &final_pos).c_str());

				cur_pos = final_pos;
				QueryHeader *qr = (QueryHeader *)(lstart + cur_pos);
				printf(" type %d class %d\n", ntohs(qr->qtype), ntohs(qr->qclass));

				cur_pos += sizeof(QueryHeader);
			}
			else {
				// otherwise, response record
				int final_pos = cur_pos;
				string s = print_name(lstart, cur_pos, 1, &final_pos).c_str();
				printf("\t%s", s.c_str());
				cur_pos = final_pos;

				check_jump((unsigned int)(cur_pos + sizeof(FixedRR) - 1), RR_CHECK);

				FixedRR *rr = (FixedRR *)(lstart + cur_pos);
				// flip qType
				int fQType = ntohs(rr->qType), fTTL = ntohl(rr->TTL);

				cur_pos += sizeof(FixedRR);
				// only process these 4
				if (fQType == DNS_A) {
					// name + IP address
					check_jump(cur_pos + 3, VALUE_CHECK);
					printf(" A %d.%d.%d.%d ",
						lstart[cur_pos], lstart[cur_pos + 1], lstart[cur_pos + 2], lstart[cur_pos + 3]);
					printf(" TTL = %d\n", ntohl(rr->TTL));

					cur_pos += ntohs(rr->len);
				}
				else if (fQType == DNS_CNAME || fQType == DNS_NS || fQType == DNS_PTR) {
					// name + name
					check_jump(cur_pos + ntohs(rr->len) - 1, VALUE_CHECK);
					printf(" %s ", typetoa(fQType).c_str());

					// make new buffer, then parse that
					unsigned char newbuf[MAX_DNS_SIZE];
					memcpy(newbuf, lstart, buf_len);
					newbuf[cur_pos + ntohs(rr->len)] = '\0';

					limit = cur_pos + ntohs(rr->len);
					printf(" %s ", print_name(newbuf, cur_pos, 1, &final_pos).c_str());
					cur_pos += ntohs(rr->len);
					limit = 1e9;

					printf(" TTL = %d\n", ntohl(rr->TTL));
				}
				else {
					printf(" [unrecognized type]\n");
					cur_pos += ntohs(rr->len);
				}
			}
		}
	}

	return true;
}