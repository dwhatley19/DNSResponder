// dns_funcs.cpp :
// Defines functions for use in main DNS routine.

#include "stdafx.h"
#include "dns_classes.h"

// receives out_buf.
bool recv_buf(SOCKET sock, char *out_buf, char *server)
{
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

	fd_set fd;
	FD_ZERO(&fd);
	FD_SET(sock, &fd);

	// Receive
	// No receive loop necessary: each call to recvfrom is 1 packet
	// Blocking: goes to sleep when no packet immediately available
	clock_t c1 = clock();

	int bytes = recvfrom(sock, out_buf, MAX_DNS_SIZE, NULL, (struct sockaddr*)&remote, &sender_size);
	if (bytes == SOCKET_ERROR) {
		// also catches too many bytes, so we're ok
		printf("recv() socket error %d\n", WSAGetLastError());
		_return(1);
	}
	
	if (bytes <= sizeof(FixedDNSHeader)) {
		printf("\n  ++ invalid reply: smaller than fixed header\n");
		_return(1);
	}

	printf("response in %d ms with %d bytes\n", clock() - c1, bytes);

	//closesocket(sock); // this is only done in below function
	return true;
}

// get the name in regular format from DNS format
bool parse_name(char *buf, char *out)
{
	int cur_pos = 0, out_pos = 0;
	int sz = buf[cur_pos++];

	while (sz != 0) {
		for (int i = 0; i < sz; ++i) {
			out[out_pos++] = buf[cur_pos++];
		}

		sz = buf[cur_pos++];
		out[out_pos++] = '.';
	}

	out[out_pos++] = 0;
	return true;
}

// get the name from regular format to DNS format
bool change_name(char *buf, char *out)
{
	int cur_pos = 0, out_pos = 0;
	int sz = strlen(buf);

	while (cur_pos < sz) {
		int prev_pos = cur_pos;

		while (cur_pos < sz && buf[cur_pos] != '.') {
			++cur_pos;
		}

		int seglen = cur_pos - prev_pos;
		out[out_pos++] = seglen;
		memcpy(out + out_pos, buf + prev_pos, seglen);
		out_pos += seglen;
		++cur_pos;
	}

	out[out_pos] = 0;
}

// returns a buffer to respond with
// consider different cases
// b_ip = server B's IP (the referral)
bool respond(char *in_buf, char *out_buf, char *b_ip, int *len)
{
	FixedDNSHeader *fd = (FixedDNSHeader *)in_buf;

	char name[MAX_DNS_SIZE];
	parse_name(in_buf + sizeof(FixedDNSHeader), name);

	int txid = ntohs(fd->ID);
	
	// flags = 0x8500 if available, 0x8500 if unavailable
	// 850 = response packet, authoritative, recursion unavailable
	// 0 = no error, 3 = name error

	// FOR REFERENCE ONLY
	//FixedRR typeA(DNS_A, DNS_INET, 0, 4);
	//FixedRR typeNS(DNS_NS, DNS_INET, 0, depends_on_name);

	QueryHeader *qh = (QueryHeader *)(in_buf + strlen(name) + 2); // used for repeating question

	// the X and Y need to be changed, but not now
	if (strcmp(name, "X-Y.irl-dns.info") == 0) {
		USHORT *head = (USHORT *)out_buf;
		out_buf[0] = htons(txid);
		out_buf[1] = htons(0x8500);
		out_buf[2] = htons(1); // 1 question
		out_buf[3] = htons(0); // 0 answer
		out_buf[4] = htons(1); // 1 authoritative
		out_buf[5] = htons(1); // 1 additional (to prevent re-query)

		// QUESTION
		QueryHeader *out_qh = (QueryHeader *)(out_buf + sizeof(FixedDNSHeader));
		out_qh->qclass = qh->qclass;
		out_qh->qtype = qh->qtype;
		
		char *ns = "ns.X-Y.irl-dns.info";
		int cur_pos = sizeof(FixedDNSHeader) + sizeof(QueryHeader);

		// AUTHORITY
		change_name(name, out_buf + cur_pos);
		cur_pos += (strlen(name) + 2);

		FixedRR *rr = (FixedRR *)(out_buf + cur_pos);
		*rr = FixedRR(htons(DNS_NS), htons(DNS_INET), htons(0), htons(strlen(ns) + 2));
		cur_pos += sizeof(FixedRR);

		change_name(ns, out_buf + cur_pos);
		cur_pos += (strlen(ns) + 2);

		// ADDITIONAL
		change_name(ns, out_buf + cur_pos);
		cur_pos += (strlen(ns) + 2);

		FixedRR *rr = (FixedRR *)(out_buf + cur_pos);
		*rr = FixedRR(htons(DNS_A), htons(DNS_INET), htons(0), htons(4));
		cur_pos += sizeof(FixedRR);

		int *ip = (int *)(out_buf + cur_pos);
		*ip = htonl(inet_addr(b_ip));
		cur_pos += 4;

		*len = cur_pos;
	}
	else if (strcmp(name, "ns.X-Y.irl-dns.info") == 0) {
		// this is the query where X doesn't "trust" us

		USHORT *head = (USHORT *)out_buf;
		out_buf[0] = htons(txid);
		out_buf[1] = htons(0x8500);
		out_buf[2] = htons(1); // 1 question
		out_buf[3] = htons(1); // 1 answer
		out_buf[4] = htons(0); // already gave authoritative
		out_buf[5] = htons(0); // no additional req'd

		// QUESTION
		QueryHeader *out_qh = (QueryHeader *)(out_buf + sizeof(FixedDNSHeader));
		out_qh->qclass = qh->qclass;
		out_qh->qtype = qh->qtype;

		char *ns = "ns.X-Y.irl-dns.info";
		int cur_pos = sizeof(FixedDNSHeader) + sizeof(QueryHeader);

		// ANSWER
		change_name(ns, out_buf + cur_pos);
		cur_pos += (strlen(ns) + 2);

		FixedRR *rr = (FixedRR *)(out_buf + cur_pos);
		*rr = FixedRR(htons(DNS_A), htons(DNS_INET), htons(0), htons(4));
		cur_pos += sizeof(FixedRR);

		int *ip = (int *)(out_buf + cur_pos);
		*ip = htonl(inet_addr(b_ip));
		cur_pos += 4;

		*len = cur_pos;
	}
	else {
		// invalid query -- reject

		USHORT *head = (USHORT *)out_buf;
		out_buf[0] = htons(txid);
		out_buf[1] = htons(0x8503); // Rcode = 3 -- error
		out_buf[2] = htons(1); // 1 question
		out_buf[3] = htons(0); // no answer
		out_buf[4] = htons(0); // already gave authoritative
		out_buf[5] = htons(0); // no additional req'd

		// QUESTION
		QueryHeader *out_qh = (QueryHeader *)(out_buf + sizeof(FixedDNSHeader));
		out_qh->qclass = qh->qclass;
		out_qh->qtype = qh->qtype;

		*len = sizeof(FixedDNSHeader) + sizeof(QueryHeader);
	}

	return true;
}

bool send_buf(SOCKET sock, char *buf, char *server, int len)
{
	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));

	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(server); // server’s IP
	remote.sin_port = htons(53); // DNS port on server

	int sender_size = sizeof(remote);

	if (sendto(sock, buf, len, 0, (struct sockaddr*)&remote, sender_size) == SOCKET_ERROR) {
		printf("Socket error %d\n", WSAGetLastError());
		_return(1);
	}

	closesocket(sock);
	return true;
}