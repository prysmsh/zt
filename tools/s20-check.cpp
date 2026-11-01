// Scratch tool: compare ZeroTier's Salsa20 output against a reference
// implementation, to determine which state layout it uses.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

#include "node/Salsa20.hpp"

using namespace ZeroTier;

int main()
{
	unsigned char key[32];
	unsigned char iv[8];
	char line[256];
	if (!fgets(line, sizeof(line), stdin)) return 1;
	for (int i = 0; i < 32; ++i) {
		char b[3] = { line[i * 2], line[i * 2 + 1], 0 };
		key[i] = (unsigned char)strtoul(b, 0, 16);
	}
	if (!fgets(line, sizeof(line), stdin)) return 1;
	for (int i = 0; i < 8; ++i) {
		char b[3] = { line[i * 2], line[i * 2 + 1], 0 };
		iv[i] = (unsigned char)strtoul(b, 0, 16);
	}

	Salsa20 s20(key, iv);
	unsigned char out[64];
	memset(out, 0, sizeof(out));
	s20.crypt12(out, out, sizeof(out));
	for (int i = 0; i < 64; ++i) printf("%02x", out[i]);
	printf("\n");
	return 0;
}
