///Daniel Whatley
///CSCE 463-500 Spring 2016

#pragma once

#include "stdafx.h"

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AAAA 28 /* IPv6 */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */

/* query classes */
#define DNS_INET 1 

/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */ 

#define MAX_DNS_SIZE 512

#define MAX_ATTEMPTS 3

#define JUMP_CHECK 1
#define NAME_CHECK 2
#define RR_CHECK 3
#define OFFSET_CHECK 4
#define VALUE_CHECK 5
#define NUMRR_CHECK 6

typedef std::pair<int, int> pii;
#define A first
#define B second

#pragma pack(push,1) // sets struct padding/alignment to 1 byte
class QueryHeader {
public:
	USHORT qtype;
	USHORT qclass;
};

class FixedDNSHeader {
public:
	USHORT ID, flags, questions, answers, authority, additional;
};

class FixedRR {
public:
	USHORT qType, qClass;
	int TTL;
	USHORT len;

	FixedRR(USHORT q, USHORT c, int t, USHORT l) : qType(q), qClass(c), TTL(t), len(l) {}
};

class ClientFunctions {
public:
	int buf_len;
	std::string cache[MAX_DNS_SIZE];
	int limit;

	USHORT make_buf(SOCKET sock, char *buf, char *host, int qtype, int *len);
	bool send_buf(SOCKET sock, char *in_buf, char *out_buf, char *server, int len);
	bool check_jump(unsigned int jump, int fl);
	std::string print_name(unsigned char *buf, int cur_pos, int first, int *final_pos);
	bool parse_buf(unsigned char *buf, USHORT id);

	ClientFunctions() : limit(1e9)
	{
		for (int i = 0; i < MAX_DNS_SIZE; ++i) cache[i] = "";
	}
};

class ThreadParams {
public:
	char *a_ip, *b_ip;
	ClientFunctions *cf;
	HANDLE eventQuit; // set when client receives error
};
#pragma pack(pop) // restores old packing 