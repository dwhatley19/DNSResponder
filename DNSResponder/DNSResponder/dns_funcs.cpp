#include "stdafx.h"
#include "dns_classes.h"

using namespace std;

// range check
// fl = 1 if jump, 0 if normal range check
bool ClientFunctions::check_jump(unsigned int jump, int fl)
{
	if (jump < sizeof(FixedDNSHeader) && fl == JUMP_CHECK) {
		printf("  ++ invalid record: jump into fixed header\n");
		return false;
	}
	else if (jump >= buf_len && fl == JUMP_CHECK) {
		printf("  ++ invalid record: jump beyond packet boundary\n");
		return false;
	}
	else if (jump >= buf_len && fl == NAME_CHECK) {
		printf("  ++ invalid record: truncated name\n");
		return false;
	}
	else if (jump >= buf_len && fl == RR_CHECK) {
		printf("  ++ invalid record: truncated fixed RR header\n");
		return false;
	}
	else if (jump >= buf_len && fl == OFFSET_CHECK) {
		printf("  ++ invalid record: truncated jump offset\n");
		return false;
	}
	else if (jump >= buf_len && fl == VALUE_CHECK) {
		printf("  ++ invalid record: value length beyond packet\n");
		return false;
	}
	else if (jump >= buf_len && fl == NUMRR_CHECK) {
		printf("  ++ invalid section: not enough records\n");
		return false;
	}
}

string typetoa(int type)
{
	if (type == DNS_NS) return "NS";
	else if (type == DNS_CNAME) return "CNAME";
	else if (type == DNS_PTR) return "PTR";
}

// Prints name recursively.
string ClientFunctions::print_name(unsigned char *buf, int cur_pos, int first, int *final_pos)
{
	std::set<pii> vis;
	string res2 = "";

	int prev_pos = cur_pos;

	int seglen = buf[cur_pos];
	if (seglen >= 0xc0) --cur_pos;

	while (seglen != 0 && cur_pos < limit) {
		// if we need to jump
		if (seglen >= 0xc0) {
			cur_pos += 2;
			if (cur_pos >= limit) break;

			if (!check_jump(cur_pos, OFFSET_CHECK)) return false;

			// get jump length
			unsigned short jump = (buf[cur_pos - 1] * 256 + buf[cur_pos]) & 0x3FFF;

			if (!check_jump(jump, JUMP_CHECK)) return false;

			// check if this position is visited from the same location
			if (vis.find(pii(jump, cur_pos - 1)) == vis.end()) {
				vis.insert(pii(jump, cur_pos - 1));
				//				if (first) (*final_pos) += 2;

				// use the cache
				if (cache[jump] != "") res2 += cache[jump];
				else res2 += print_name(buf, jump, 0, final_pos);

				break;
			}
			else {
				printf("  ++ invalid record: jump loop\n");
				_return(1);
			}
		}

		++cur_pos;
		// add stuff to the string
		for (int j = 0; j < seglen; ++j) {
			if (!check_jump(cur_pos, NAME_CHECK)) return false;
			res2 += buf[cur_pos++];
		}

		if (!check_jump(cur_pos, NAME_CHECK)) return false;
		seglen = buf[cur_pos];

		if (seglen >= 0xc0) --cur_pos;
		if (seglen) res2 += '.';
	}

	if (first) {
		*final_pos = cur_pos + 1;
		if (!vis.empty()) vis.clear();
	}

	cache[prev_pos] = res2;
	return res2;
}
