# Legacy protocol facts (ZeroTier `node/`)

Verified empirically against ZeroTier's own C++ implementation via the
`oracle/` harness. These are the facts that drive the Track B design.

## Identity / key material

| Item | ZeroTier | ZT-next | Notes |
|---|---|---|---|
| Public key set | **64 bytes** | 32 bytes | ZT: `C25519 (32) ‖ Ed25519 (32)` |
| Private key set | **64 bytes** | 32 bytes | ZT: `C25519 scalar ‖ Ed25519 seed` |
| Signature | **96 bytes** | 64 bytes | ZT: `R(32) ‖ S(32) ‖ SHA512-prefix(32)` |
| Address | 5 bytes (40 bits) | 10 bytes | ZT: global, one per node |
| Address derivation | `SHA512(digest)[59..64]` | `SHA256(domain‖nwid‖pk)[0..10]` | ZT rejects "reserved" addresses by regenerating |

**Critical:** ZeroTier's 96-byte signature is *not* standard Ed25519.

From `node/ECC.cpp` (Ed25519 branch):

```cpp
SHA512(digest, msg, len);        // 64-byte digest
...
SHA512(extsk, myPrivate.data + 32, 32);
// sig[32..64]  = extsk[32..64]
// sig[64..96]  = digest[0..32]
SHA512(hmg, sig + 32, 64);
// then Ed25519-signs the 32-byte hmg, storing R(32) ‖ S(32) in sig[0..64]
```

So the signature is Ed25519 over `SHA512(msg)`, with the raw first 32 bytes of
`SHA512(msg)` appended. **RustCrypto's `ed25519-dalek` cannot produce this**
— it signs a full 64-byte message, not a pre-hashed 32-byte value. A custom
implementation is required.

## Key agreement

From `node/ECC.cpp`:

```cpp
void ECC::agree(const ECC::Private& mine, const ECC::Public& their, void* keybuf, unsigned int keylen)
{
    unsigned char rawkey[32];
    unsigned char digest[64];
    crypto_scalarmult(rawkey, mine.data, their.data);   // raw X25519, no hashing
    SHA512(digest, rawkey, 32);                          // 64-byte digest
    for (unsigned int i = 0, k = 0; i < keylen;) {
        if (k == 64) { k = 0; SHA512(digest, digest, 64); }  // counter-mode KDF
        ((unsigned char*)keybuf)[i++] = digest[k++];
    }
}
```

**Critical:** this is a *hand-rolled* KDF — SHA-512 in counter mode, re-hashing
the digest in 64-byte blocks. Not HKDF. ZT-next uses HKDF-SHA256.

Note `crypto_scalarmult(rawkey, mine.data, their.data)` — raw X25519 with **no**
all-zero output check. ZT-next rejects low-order points.

## Cipher suites

From `node/Packet.hpp`:

| ID | Name |
|---|---|
| 0 | `C25519_POLY1305_NONE` |
| 1 | `C25519_POLY1305_SALSA2012` |
| 2 | `NO_CRYPTO_TRUSTED_PATH` |
| 3 | `AES_GMAC_SIV` |

The 3-bit cipher selector sits in the flags/cipher/hops byte: `FFCCCHHH`.

## Packet framing

From `node/Packet.hpp`:

```text
<[8] 64-bit packet ID / crypto IV / counter>
<[5] destination ZT address>
<[5] source ZT address>
<[1] flags/cipher/hops   -- FFCCCHHH>
<[8] 64-bit MAC (or trusted path ID)>
<[1] encrypted flags (MS 3 bits) + verb (LS 5 bits)>
<[...] verb-specific payload>
```

- Minimum valid packet: **28 bytes**
- The **3-bit hop count is the only mutable field** in transit; intermediate
  nodes may increment it up to 7 without invalidating the MAC.
- The 64-bit packet ID doubles as the crypto IV; its low 3 bits are a
  monotonically increasing counter.

## Packet verbs

20 verbs, 5-bit field (`node/Packet.hpp`):

| Ver | Name | Ver | Name |
|---|---|---|---|
| 0x00 | `NOP` | 0x0a | `NETWORK_CREDENTIALS` |
| 0x01 | `HELLO` | 0x0b | `NETWORK_CONFIG_REQUEST` |
| 0x02 | `ERROR` | 0x0c | `NETWORK_CONFIG` |
| 0x03 | `OK` | 0x0d | `MULTICAST_GATHER` |
| 0x04 | `WHOIS` | 0x0e | `MULTICAST_FRAME` |
| 0x05 | `RENDEZVOUS` | 0x10 | `PUSH_DIRECT_PATHS` |
| 0x06 | `FRAME` | 0x12 | `ACK` |
| 0x07 | `EXT_FRAME` | 0x13 | `QOS_MEASUREMENT` |
| 0x08 | `ECHO` | 0x14 | `USER_MESSAGE` |
| 0x09 | `MULTICAST_LIKE` | 0x15 | `REMOTE_TRACE` |
| | | 0x16 | `PATH_NEGOTIATION_REQUEST` |

Note the gaps: `0x0f` and `0x11` are unused.

## Protocol versioning

- `ZT_PROTO_VERSION 13` (current), `ZT_PROTO_VERSION_MIN 4`
- The version is sent in the `HELLO` packet (`node/Peer.cpp`).
- Peers negotiate down to the minimum of the two versions.

## Credentials

`CertificateOfMembership` (COM) is the node's network membership credential.
It is a **bearer capability**: long-lived, no expiry, not bound to the node's
key material. Revocation is push-based via `Revocation` records.

ZT-next replaces this with short-lived, key-bound `NodeCredential`s.

## Track B implications

To interoperate, the Rust legacy shim must reproduce:

1. ✅ 64-byte public/private key set layout (`C25519 ‖ Ed25519`)
2. ✅ 96-byte signature format (custom Ed25519 over truncated SHA-512)
3. ✅ SHA-512 counter-mode KDF for `agree()`
4. ✅ Salsa20/12 + Poly1305 AEAD
5. ✅ Packet framing with the mutable hop counter
6. ✅ All 20 verbs
7. ✅ `CertificateOfMembership` binary format, byte-identical
8. ✅ `CertificateOfOwnership` (proof-of-possession over MAC/IP)

Items 2 and 3 are the hard ones — both require custom implementations that
cannot use standard RustCrypto APIs directly.

## Verification workflow

```bash
# 1. Build the oracle against ZeroTier's sources
./scripts/build-oracle.sh ~/compose/zerotierone

# 2. Emit reference vectors
./target/oracle/zt-oracle vectors/legacy

# 3. Generate ours
cargo run -p zt-testvectors --bin gen_vectors -- legacy

# 4. Diff
diff <(jq -S . vectors/legacy/ecc_agree.json) \
     <(jq -S . vectors/legacy/ecc_agree.json)
```

For fixed-seed comparisons, the oracle must support deterministic key
injection. ZeroTier's `Identity`/`ECC` API has no such facility, so the
oracle either (a) needs a small patch to ZeroTier's source, or (b) compares
by *relationship* rather than by absolute bytes (e.g. verify that
`agree(secret_a, public_b) == agree(secret_b, public_a)`).

Option (b) is sufficient for correctness testing and avoids modifying
ZeroTier's code.
