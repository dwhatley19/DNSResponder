// dns_funcs.cpp :
// Defines functions for use in main DNS routine.

#include "stdafx.h"
#include "dns_classes.h"

// receives out_buf.
bool recv_buf(SOCKET sock, char *out_buf, struct sockaddr_in *remote)
{
	memset(remote, 0, sizeof(struct sockaddr_in));
	int sender_size = sizeof(struct sockaddr_in);

	// Receive buffer

	// Receive
	// No receive loop necessary: each call to recvfrom is 1 packet
	// Blocking: goes to sleep when no packet immediately available
	while (true) {
		clock_t c1 = clock();

		fd_set fd;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);

		struct timeval tv;
		tv.tv_sec = 9;
		tv.tv_usec = 0;
		int res = select(0, &fd, NULL, NULL, &tv);

		if (res == 0) continue;
		else if (res == SOCKET_ERROR) {
			printf("[server] select() socket error %d\n", WSAGetLastError());
			_return(1);
		}

		int bytes = recvfrom(sock, out_buf, MAX_DNS_SIZE, NULL, (struct sockaddr*)remote, &sender_size);

		if (bytes == SOCKET_ERROR) {
			// also catches too many bytes, so we're ok
			printf("[server] recv() socket error %d\n", WSAGetLastError());
			_return(1);
		}

		if (bytes <= sizeof(FixedDNSHeader)) {
			printf("\n  ++ invalid reply: smaller than fixed header\n");
			return false;
		}

		return true;
	}
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
		if(sz > 0) out[out_pos++] = '.';
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
	return true;
}

// returns a buffer to respond with
// consider different cases
// b_ip = server B's IP (the referral)
bool respond(char *in_buf, char *out_buf, char *b_ip, int *len)
{
	FixedDNSHeader *fd = (FixedDNSHeader *)in_buf;

	char name[MAX_DNS_SIZE];
	parse_name(in_buf + sizeof(FixedDNSHeader), name);
	printf("[server] Query: %s, ", name);

	USHORT txid = ntohs(fd->ID);
	
	// flags = 0x8500 if available, 0x8500 if unavailable
	// 850 = response packet, authoritative, recursion unavailable
	// 0 = no error, 3 = name error

	// FOR REFERENCE ONLY
	//FixedRR typeA(DNS_A, DNS_INET, 0, 4);
	//FixedRR typeNS(DNS_NS, DNS_INET, 0, depends_on_name);

	QueryHeader *qh = (QueryHeader *)(in_buf + strlen(name) + 2 + sizeof(FixedDNSHeader));
	printf("Type: %d\n", ntohs(qh->qtype));

	int sz = strlen(name);

	// the X and Y need to be changed, but not now
	if ((strncmp(name + sz - 12, "iresearch.us", 12) == 0
		|| strncmp(name + sz - 12, "IRESEARCH.us", 12) == 0) && sz != 22) {
		USHORT *head = (USHORT *)out_buf;
		head[0] = htons(txid);
		head[1] = htons(0x8500);
		head[2] = htons(1); // 1 question
		head[3] = htons(0); // 0 answer
		head[4] = htons(1); // 1 authoritative
		head[5] = htons(1); // 1 additional (to prevent re-query)

		// QUESTION
		change_name(name, out_buf + sizeof(FixedDNSHeader));

		int cur_pos = strlen(name) + 2 + sizeof(FixedDNSHeader);
		QueryHeader *out_qh = (QueryHeader *)(out_buf + cur_pos);
		out_qh->qclass = htons(ntohs(qh->qclass));
		out_qh->qtype = htons(ntohs(qh->qtype));
		
		cur_pos += sizeof(QueryHeader);

		if (ntohs(qh->qtype) == DNS_AAAA) {
			head[1] = htons(0x8502);
			return true;
		}

		char ns[MAX_DNS_SIZE];
		ns[0] = 0;

		strcat(ns, "ns.");
		strcat(ns, name);

		// AUTHORITY
		change_name(name, out_buf + cur_pos);
		cur_pos += (strlen(name) + 2);

		FixedRR *rr = (FixedRR *)(out_buf + cur_pos);
		*rr = FixedRR(htons(DNS_NS), htons(DNS_INET), htons(0), htons(USHORT(strlen(ns)) + 2));
		cur_pos += sizeof(FixedRR);

		change_name(ns, out_buf + cur_pos);
		cur_pos += (strlen(ns) + 2);

		// ADDITIONAL
		change_name(ns, out_buf + cur_pos);
		cur_pos += (strlen(ns) + 2);

		FixedRR *rrA = (FixedRR *)(out_buf + cur_pos);
		*rrA = FixedRR(htons(DNS_A), htons(DNS_INET), htons(0), htons(4));
		cur_pos += sizeof(FixedRR);

		int *ip = (int *)(out_buf + cur_pos);
		*ip = inet_addr(b_ip);
		cur_pos += 4;

		*len = cur_pos;
	}
	else if (strlen(name) == 22 && strncmp(name + 10, "iresearch.us", 12) == 0) {
		// this is the query where X doesn't "trust" us

		USHORT *head = (USHORT *)out_buf;
		head[0] = htons(txid);
		head[1] = htons(0x8500);
		head[2] = htons(1); // 1 question
		head[3] = htons(1); // 1 answer
		head[4] = htons(0); // already gave authoritative
		head[5] = htons(0); // no additional req'd

		// QUESTION
		change_name(name, out_buf + sizeof(FixedDNSHeader));

		int cur_pos = strlen(name) + 2 + sizeof(FixedDNSHeader);
		QueryHeader *out_qh = (QueryHeader *)(out_buf + cur_pos);
		out_qh->qclass = htons(ntohs(qh->qclass));
		out_qh->qtype = htons(ntohs(qh->qtype));

		cur_pos += sizeof(QueryHeader);

		if (ntohs(qh->qtype) == DNS_AAAA) {
			head[1] = htons(0x8502);
			return true;
		}

		char *ns = name;

		// ANSWER
		change_name(ns, out_buf + cur_pos);
		cur_pos += (strlen(ns) + 2);

		FixedRR *rr = (FixedRR *)(out_buf + cur_pos);
		*rr = FixedRR(htons(DNS_A), htons(DNS_INET), htons(0), htons(4));
		cur_pos += sizeof(FixedRR);

		int *ip = (int *)(out_buf + cur_pos);
		*ip = inet_addr(b_ip);
		cur_pos += 4;

		*len = cur_pos;
	}
	else {
		// invalid query -- reject

		USHORT *head = (USHORT *)out_buf;
		head[0] = htons(txid);
		head[1] = htons(0x8503); // Rcode = 3 -- error
		head[2] = htons(1); // 1 question
		head[3] = htons(0); // no answer
		head[4] = htons(0); // already gave authoritative
		head[5] = htons(0); // no additional req'd

		// QUESTION
		change_name(name, out_buf + sizeof(FixedDNSHeader));

		int cur_pos = strlen(name) + 2 + sizeof(FixedDNSHeader);
		QueryHeader *out_qh = (QueryHeader *)(out_buf + cur_pos);
		out_qh->qclass = htons(ntohs(qh->qclass));
		out_qh->qtype = htons(ntohs(qh->qtype));

		cur_pos += sizeof(QueryHeader);

		*len = cur_pos;
	}

	return true;
}

bool send_buf(SOCKET sock, char *buf, int len, struct sockaddr_in remote)
{
	int sender_size = sizeof(struct sockaddr_in);

	if (sendto(sock, buf, len, 0, (struct sockaddr*)&remote, sender_size) == SOCKET_ERROR) {
		printf("[server] sendto() error %d\n", WSAGetLastError());
		_return(1);
	}

	return true;
}