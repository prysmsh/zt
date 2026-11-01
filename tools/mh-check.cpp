// Scratch tool: compute ZeroTier's memory-hard identity hash for a public
// key set, to cross-check the Rust implementation.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

#include "node/ECC.hpp"
#include "node/Identity.hpp"
#include "node/SHA512.hpp"
#include "node/Salsa20.hpp"
#include "node/Utils.hpp"

using namespace ZeroTier;

#define ZT_IDENTITY_GEN_MEMORY 2097152

static inline void mh(const void *pk, unsigned int n, void *digest, void *genmem)
{
	SHA512(digest, pk, n);

	memset(genmem, 0, ZT_IDENTITY_GEN_MEMORY);
	Salsa20 s20(digest, (char *)digest + 32);
	s20.crypt20((char *)genmem, (char *)genmem, 64);
	for (unsigned long i = 64; i < ZT_IDENTITY_GEN_MEMORY; i += 64) {
		unsigned long k = i - 64;
		for (int j = 0; j < 64; j += 8) {
			*((uint64_t *)((char *)genmem + i + j)) = *((uint64_t *)((char *)genmem + k + j));
		}
		s20.crypt20((char *)genmem + i, (char *)genmem + i, 64);
	}
	for (unsigned long i = 0; i < (ZT_IDENTITY_GEN_MEMORY / sizeof(uint64_t));) {
		unsigned long idx1 = (unsigned long)(Utils::ntoh(((uint64_t *)genmem)[i++]) % (64 / sizeof(uint64_t)));
		unsigned long idx2 = (unsigned long)(Utils::ntoh(((uint64_t *)genmem)[i++]) % (ZT_IDENTITY_GEN_MEMORY / sizeof(uint64_t)));
		uint64_t tmp = ((uint64_t *)genmem)[idx2];
		((uint64_t *)genmem)[idx2] = ((uint64_t *)digest)[idx1];
		((uint64_t *)digest)[idx1] = tmp;
		s20.crypt20(digest, digest, 64);
	}
}

int main()
{
	unsigned char pk[64];
	char line[256];
	if (!fgets(line, sizeof(line), stdin)) return 1;
	for (int i = 0; i < 64; ++i) {
		char b[3] = { line[i * 2], line[i * 2 + 1], 0 };
		pk[i] = (unsigned char)strtoul(b, 0, 16);
	}
	unsigned char digest[64];
	char *mem = (char *)malloc(ZT_IDENTITY_GEN_MEMORY);
	mh(pk, 64, digest, mem);
	printf("digest: ");
	for (int i = 0; i < 64; ++i) printf("%02x", digest[i]);
	printf("\naddress: ");
	for (int i = 59; i < 64; ++i) printf("%02x", digest[i]);
	printf("\n");
	return 0;
}
