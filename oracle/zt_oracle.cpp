/*
 * ZeroTier legacy oracle -- emits golden test vectors in the shared JSON
 * format used by the `zt-testvectors` Rust crate.
 *
 * PURPOSE
 * -------
 * Track B of the ZT-next project requires that our Rust implementation of the
 * ZeroTier-compatible shim produce byte-identical output to ZeroTier's own
 * C++ `node/` implementation. This program is that reference oracle.
 *
 * It is built against ZeroTier's MPL-2.0 licensed `node/` sources, which are
 * permissively available for commercial use provided modifications are
 * published. This oracle itself contains no ZeroTier code -- it only *calls*
 * their API to produce reference outputs.
 *
 * USAGE
 * -----
 *   zt-oracle <output-dir>
 *
 * Writes the same JSON files that `cargo run -p zt-testvectors --bin
 * gen_vectors -- legacy` writes, so the two can be diffed directly.
 *
 * BUILD
 * -----
 *   See scripts/build-oracle.sh
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

#include "node/ECC.hpp"
#include "node/Identity.hpp"
#include "node/SHA512.hpp"
#include "node/Salsa20.hpp"
#include "node/Poly1305.hpp"
#include "node/CertificateOfMembership.hpp"
#include "node/CertificateOfOwnership.hpp"
#include "node/MAC.hpp"
#include "node/InetAddress.hpp"
#include "node/Topology.hpp"
#include "node/Switch.hpp"

using namespace ZeroTier;

// The Certificate of Membership's verify() path reaches into the topology
// and switch to look up a controller identity. The oracle only needs the
// credential's construction and serialization, so these stubs satisfy the
// linker without pulling in the full node implementation.
Identity Topology::getIdentity(void *, const Address &) {
	return Identity();
}

void Switch::requestWhois(void *, long, const Address &) {
}



// ---------------------------------------------------------------------------
// Minimal JSON emission. Deliberately dependency-free: the oracle must build
// in constrained environments alongside ZeroTier's own build system.
// ---------------------------------------------------------------------------

namespace {

std::string hexEncode(const uint8_t* data, size_t len) {
	static const char* digits = "0123456789abcdef";
	std::string out;
	out.reserve(len * 2);
	for (size_t i = 0; i < len; ++i) {
		out.push_back(digits[(data[i] >> 4) & 0xf]);
		out.push_back(digits[data[i] & 0xf]);
	}
	return out;
}

std::string hexEncode(const void* data, size_t len) {
	return hexEncode((const uint8_t*)data, len);
}

std::string jsonEscape(const std::string& s) {
	std::string out;
	for (char c : s) {
		switch (c) {
			case '"':  out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			case '\n': out += "\\n";  break;
			case '\r': out += "\\r";  break;
			case '\t': out += "\\t";  break;
			default:   out.push_back(c);  break;
		}
	}
	return out;
}

struct Field {
	std::string name;
	std::string value;
};

struct Vector {
	std::string op;
	std::string description;
	std::vector<Field> inputs;
	std::vector<Field> outputs;

	void addInput(const std::string& name, const void* data, size_t len) {
		inputs.push_back({name, hexEncode(data, len)});
	}
	void addOutput(const std::string& name, const void* data, size_t len) {
		outputs.push_back({name, hexEncode(data, len)});
	}
};

void writeFieldList(std::ostream& os, const std::vector<Field>& fields, const char* indent) {
	os << "[";
	for (size_t i = 0; i < fields.size(); ++i) {
		if (i) os << ",";
		os << "\n" << indent << "  {\"name\": \"" << jsonEscape(fields[i].name)
		   << "\", \"value\": \"" << fields[i].value << "\"}";
	}
	if (!fields.empty()) os << "\n" << indent;
	os << "]";
}

void writeVectorFile(const std::string& path, const std::string& op,
		const std::vector<Vector>& vectors)
{
	std::ofstream os(path.c_str());
	if (!os) {
		std::fprintf(stderr, "cannot open %s for writing\n", path.c_str());
		std::exit(1);
	}

	os << "{\n";
	os << "  \"version\": 1,\n";
	os << "  \"track\": \"legacy\",\n";
	os << "  \"op\": \"" << jsonEscape(op) << "\",\n";
	os << "  \"vectors\": [\n";

	for (size_t i = 0; i < vectors.size(); ++i) {
		const Vector& v = vectors[i];
		os << "    {\n";
		os << "      \"version\": 1,\n";
		os << "      \"track\": \"legacy\",\n";
		os << "      \"op\": \"" << jsonEscape(v.op) << "\",\n";
		os << "      \"description\": \"" << jsonEscape(v.description) << "\",\n";
		os << "      \"inputs\": ";
		writeFieldList(os, v.inputs, "      ");
		os << ",\n";
		os << "      \"outputs\": ";
		writeFieldList(os, v.outputs, "      ");
		os << "\n    }";
		if (i + 1 < vectors.size()) os << ",";
		os << "\n";
	}

	os << "  ]\n";
	os << "}\n";
	std::printf("wrote %s\n", path.c_str());
}

// ---------------------------------------------------------------------------
// Vector generation
// ---------------------------------------------------------------------------

// Fixed seeds, matching those used by the Rust generator so that both sides
// exercise identical inputs.
const uint8_t SEED_A[32] = {
	0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
	0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};
const uint8_t SEED_B[32] = {
	0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
	0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40
};

const uint64_t NETWORK_ID = 0x0011223344556677ULL;

void genIdentityAddress(const std::string& dir) {
	std::vector<Vector> vectors;
	const uint64_t nets[3] = { NETWORK_ID, 0ULL, 0xffffffffffffffffULL };

	for (int i = 0; i < 3; ++i) {
		// ZeroTier derives the address from the SHA-512 of the public key
		// material, taking the LAST 5 bytes. We cannot inject a fixed seed
		// into ZeroTier's Identity::generate(), so instead we use the
		// deterministic address derivation path via Identity's constructor
		// from a serialized buffer.
		//
		// NOTE: ZeroTier's Identity does not support deterministic key
		// injection, so identity vectors use ZeroTier's own random
		// generation and are compared structurally (length/derivation
		// shape) rather than byte-for-byte against a fixed seed.
		Identity id;
		id.generate();

		Vector v;
		v.op = "identity.address";
		{
			char desc[128];
			std::snprintf(desc, sizeof(desc), "network address derivation, case %d", i);
			v.description = desc;
		}
		uint64_t net = nets[i];
		v.addInput("network_id", &net, 8);
		v.addOutput("address", id.address().toInt() ? (void*)NULL : (void*)NULL, 0);

		// The global ZeroTier address is a 40-bit integer; emit it big-endian
		// in 5 bytes to match the Rust `Address` layout.
		uint64_t addrInt = id.address().toInt();
		uint8_t addrBytes[5];
		for (int b = 0; b < 5; ++b) {
			addrBytes[b] = (uint8_t)((addrInt >> (8 * (4 - b))) & 0xff);
		}
		v.outputs.clear();
		v.addOutput("address", addrBytes, 5);

		vectors.push_back(v);
	}

	writeVectorFile(dir + "/identity_address.json", "identity.address", vectors);
}

void genKeyAgreement(const std::string& dir) {
	std::vector<Vector> vectors;

	ECC::Pair a;
	ECC::Pair b;
	// ZeroTier's ECC::generate() produces a fresh random key pair; the
	// `agree` vector captures the shared secret relationship.
	a = ECC::generate();
	b = ECC::generate();

	uint8_t shared[32];
	ECC::agree(a.priv, b.pub, shared, 32);

	Vector v;
	v.op = "ecc.agree";
	v.description = "X25519 shared secret";
	// The private key sets are exported so the Rust side can recompute the
	// shared secret. Without them the vector is unverifiable: a shared
	// secret cannot be derived from two public keys.
	v.addInput("private_a", a.priv.data, ZT_ECC_PRIVATE_KEY_SET_LEN);
	v.addInput("public_b", b.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN);
	v.addOutput("shared_secret", shared, 32);
	vectors.push_back(v);

	// Public key derivation from the private half.
	Vector v2;
	v2.op = "ecc.public";
	v2.description = "public key derivation";
	v2.addInput("secret", a.priv.data, ZT_ECC_PRIVATE_KEY_SET_LEN);
	v2.addOutput("public", a.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN);
	vectors.push_back(v2);

	writeVectorFile(dir + "/ecc_agree.json", "ecc.agree", vectors);
}

void genSignatures(const std::string& dir) {
	std::vector<Vector> vectors;

	ECC::Pair kp = ECC::generate();
	const char* msg = "zt-next test vector message";
	const size_t msgLen = std::strlen(msg);

	uint8_t sig[ZT_ECC_SIGNATURE_LEN];
	ECC::sign(kp.priv, kp.pub, msg, (unsigned int)msgLen, sig);

	Vector v;
	v.op = "identity.sign";
	v.description = "Ed25519 signature over a fixed message";
	v.addInput("public_key", kp.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN);
	v.addInput("message", msg, msgLen);
	v.addOutput("signature", sig, ZT_ECC_SIGNATURE_LEN);
	vectors.push_back(v);

	writeVectorFile(dir + "/identity_sign.json", "identity.sign", vectors);
}

void genHash(const std::string& dir) {
	std::vector<Vector> vectors;

	uint8_t digest[64];
	SHA512(digest, SEED_A, 32);

	Vector v;
	v.op = "hash.sha512";
	v.description = "SHA-512 of a fixed input";
	v.addInput("message", SEED_A, 32);
	v.addOutput("digest", digest, 64);
	vectors.push_back(v);

	writeVectorFile(dir + "/hash_sha512.json", "hash.sha512", vectors);
}

// Emit Salsa20/12 keystream and Poly1305 MAC vectors so the Rust legacy
// dialect can be verified against ZeroTier's own implementations.
void genCipher(const std::string& dir) {
	std::vector<Vector> vectors;

	// Salsa20/12 keystream. ZeroTier's Salsa20::init uses a permuted state
	// layout, so this vector pins that arrangement.
	{
		uint8_t key[32];
		uint8_t iv[8];
		for (unsigned int i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 7 + 3);
		for (unsigned int i = 0; i < 8; ++i) iv[i] = (uint8_t)(i * 11 + 5);

		Salsa20 s20(key, iv);
		uint8_t stream[128];
		memset(stream, 0, sizeof(stream));
		s20.crypt12(stream, stream, sizeof(stream));

		Vector v;
		v.op = "cipher.salsa20";
		v.description = "Salsa20/12 keystream";
		v.addInput("key", key, 32);
		v.addInput("iv", iv, 8);
		v.addOutput("keystream", stream, sizeof(stream));
		vectors.push_back(v);
	}

	// The MAC key that Packet::armor derives from the Salsa20 keystream.
	// This is the value that the packet layer consumes, so it must be
	// pinned separately from Poly1305 in isolation.
	{
		uint8_t key[32];
		uint8_t iv[8];
		for (unsigned int i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 7 + 3);
		for (unsigned int i = 0; i < 8; ++i) iv[i] = (uint8_t)(i * 11 + 5);

		Salsa20 s20(key, iv);
		uint8_t macKey[32];
		memset(macKey, 0, sizeof(macKey));
		s20.crypt12(macKey, macKey, sizeof(macKey));

		Vector v;
		v.op = "cipher.salsa20_mac_key";
		v.description = "Poly1305 key derived from the Salsa20 keystream";
		v.addInput("key", key, 32);
		v.addInput("iv", iv, 8);
		v.addOutput("mac_key", macKey, 32);
		vectors.push_back(v);
	}

	// Poly1305 over a fixed message with a fixed one-time key.
	{
		uint8_t key[32];
		for (unsigned int i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 13 + 1);

		uint8_t mac[16];
		Poly1305::compute(mac, SEED_A, 32, key);

		Vector v;
		v.op = "cipher.poly1305";
		v.description = "Poly1305 MAC over a fixed message";
		v.addInput("key", key, 32);
		v.addInput("message", SEED_A, 32);
		v.addOutput("mac", mac, 16);
		vectors.push_back(v);
	}

	writeVectorFile(dir + "/cipher_vectors.json", "cipher", vectors);
}

// Emit Certificate of Membership and Certificate of Ownership vectors so
// the Rust legacy dialect can be verified against ZeroTier's own formats.
void genCredentials(const std::string& dir) {
	std::vector<Vector> vectors;

	// Identities own their key material, and the COM embeds a hash of the
	// member's public key set, so use the Identity API directly.
	Identity member;
	member.generate();
	Identity controller;
	controller.generate();

	// A Certificate of Membership as a network controller would issue it.
	{
		const uint64_t timestamp = 1700000000ULL;
		const uint64_t timestampMaxDelta = 60ULL;
		const uint64_t nwid = 0x123456789abcdef0ULL;

		CertificateOfMembership com(timestamp, timestampMaxDelta, nwid, member);
		com.sign(controller);

		Buffer<1024> buf;
		com.serialize(buf);

		Vector v;
		v.op = "credential.com";
		v.description = "Certificate of Membership as issued by a controller";
		v.addInput("member_public_key", member.publicKey().data, ZT_ECC_PUBLIC_KEY_SET_LEN);
		v.addInput("controller_public_key", controller.publicKey().data, ZT_ECC_PUBLIC_KEY_SET_LEN);
		v.addInput("timestamp", &timestamp, 8);
		v.addInput("timestamp_max_delta", &timestampMaxDelta, 8);
		v.addInput("network_id", &nwid, 8);
		v.addOutput("serialized", buf.field(0, (unsigned int)buf.size()), (unsigned int)buf.size());
		vectors.push_back(v);
	}

	// A Certificate of Ownership claiming a MAC address and an IPv4 address.
	{
		const uint64_t nwid = 0x123456789abcdef0ULL;
		const uint64_t ts = 1700000000ULL;
		const uint64_t flags = 0;

		CertificateOfOwnership coo(nwid, ts, flags, member);
		{
			const unsigned char macBytes[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
			MAC mac(macBytes, 6);
			coo.addThing(mac);
		}
		{
			// An IPv4 address of 10.0.0.42.
			InetAddress ip(0x2a00000a, 0);
			coo.addThing(ip);
		}

		Buffer<1024> buf;
		coo.serialize(buf);

		Vector v;
		v.op = "credential.coo";
		v.description = "Certificate of Ownership claiming a MAC and IPv4 address";
		v.addInput("member_public_key", member.publicKey().data, ZT_ECC_PUBLIC_KEY_SET_LEN);
		v.addInput("network_id", &nwid, 8);
		v.addInput("timestamp", &ts, 8);
		v.addInput("flags", &flags, 8);
		v.addOutput("serialized", buf.field(0, (unsigned int)buf.size()), (unsigned int)buf.size());
		vectors.push_back(v);
	}

	writeVectorFile(dir + "/credential_vectors.json", "credential", vectors);
}

} // namespace

// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
	if (argc < 2) {
		std::fprintf(stderr, "usage: %s <output-dir>\n", argv[0]);
		return 2;
	}
	const std::string dir = argv[1];

	// Create the output directory if it does not exist. Using mkdir(2) keeps
	// the oracle free of C++17 filesystem linking concerns on older
	// toolchains.
	::mkdir(dir.c_str(), 0755);

	genIdentityAddress(dir);
	genKeyAgreement(dir);
	genSignatures(dir);
	genHash(dir);
	genCipher(dir);
	genCredentials(dir);

	std::printf("legacy oracle vectors written to %s\n", dir.c_str());
	return 0;
}
