# Post-quantum cryptography design

## Threat model

An adversary with a cryptographically relevant quantum computer (CRQC) can
break X25519 and Ed25519 using Shor's algorithm. If they have recorded
traffic today, they can decrypt it retroactively — the "harvest now, decrypt
later" problem.

ZT-next therefore defaults to **hybrid** constructions: a classical primitive
combined with a NIST-standard post-quantum primitive. A hybrid is secure as
long as *either* component holds.

## Algorithms

| Purpose | Classical | Post-quantum | Standard |
|---|---|---|---|
| Key agreement | X25519 | ML-KEM-768 | RFC 7748 / FIPS 203 |
| Signatures | Ed25519 | ML-DSA-65 | RFC 8032 / FIPS 204 |
| AEAD | ChaCha20-Poly1305 | — | RFC 8439 |
| KDF | HKDF-SHA256 | — | RFC 5869 |

## Sizes

Measured empirically against the RustCrypto implementations:

| Item | Bytes |
|---|---|
| ML-KEM-768 encapsulation key | 1184 |
| ML-KEM-768 ciphertext | 1088 |
| ML-KEM-768 shared secret | 32 |
| ML-KEM-768 decapsulation key (seed) | 64 |
| ML-DSA-65 public key | 1952 |
| ML-DSA-65 signature | 3309 |
| ML-DSA-65 seed | 32 |
| Ed25519 public key | 32 |
| Ed25519 signature | 64 |
| **Hybrid signature** | **3373** |
| **Hybrid shared secret** | **64 → 32 after HKDF** |

## Handshake cost

```
Initiator                              Responder
   ├── kem_suite (1 B) ─────────────────▶│
   ├── x25519_pub (32 B) ──────────────▶│
   ├── mlkem_ek (1184 B) ──────────────▶│
   │                                     │
   │◀── x25519_pub (32 B) ───────────────┤
   │◀── mlkem_ct (1088 B) ───────────────┤
```

| Suite | Initiator → Responder | Responder → Initiator | Total |
|---|---|---|---|
| `X25519` | 32 B | 32 B | 64 B |
| `MlKem768` | 1184 B | 1088 B | 2272 B |
| `HybridX25519MlKem768` | 1216 B | 1120 B | **2336 B** |

**This is a per-session cost, not a per-packet cost.** The data path after the
handshake is unchanged: ChaCha20-Poly1305 with a 32-byte key. Throughput is
unaffected.

## Combination

### Key agreement

Following the structure of `draft-ietf-tls-hybrid-design` (as used by Chrome
and Cloudflare):

```
ikm        = x25519_shared ‖ mlkem_shared        (64 bytes)
shared     = HKDF-SHA256(ikm, salt="zt-next/hybrid-kem/v1", info=context)
```

Breaking either component still leaves the other intact.

### Signatures

The hybrid signature is `Ed25519 ‖ ML-DSA-65` (3373 bytes). Verification
requires **both** to be valid.

This is deliberately stricter than a combiner where "either is sufficient".
Requiring both means a fault or attack against one implementation cannot
masquerade as a valid signature, and a corrupted signature is always
detected regardless of which half was damaged.

## Negotiation

Peers exchange their supported suites before the handshake. The chosen suite
is the first entry in the initiator's preference list that the responder also
supports.

Preference order:

1. `HybridX25519MlKem768` — secure if either component holds
2. `MlKem768` — pure PQ, for when the classical half is undesirable
3. `X25519` — classical only; a fallback, **never a default**

The negotiation is authenticated as part of the handshake transcript, so a
downgrade attack is detected.

### Why negotiate at all?

Three reasons:

1. **Deployability.** Not every peer will have PQ support immediately.
2. **Contingency.** If ML-KEM or ML-DSA turns out to be broken, operators can
   disable the affected suite without a protocol change.
3. **Future-proofing.** When pure-PQ becomes the only acceptable option, the
   negotiation mechanism already exists.

The downside is complexity, and the risk that a downgrade is used as an
attack. The mitigation is that the negotiated suite is included in the
authenticated transcript — the handshake fails if a peer claims one suite and
proves another.

## Consequences for the protocol

### Packet format

The per-packet header does **not** grow. The session is established once, and
subsequent packets use the negotiated traffic keys.

### Identity

The node's long-term identity uses Ed25519 (32-byte public key) rather than
ML-DSA-65 (1952 bytes). This is a deliberate trade-off:

- A node's public key appears in peer directories, controller databases, and
  handshake messages.
- At 1952 bytes per node, a 1000-node network directory is ~2 MB.
- The node's identity key is only used to authenticate the *handshake*, and
  the handshake already carries ML-KEM material.

The **controller-signed credential** does use ML-DSA-65, because that is the
long-lived, high-value artifact whose forgery would grant persistent network
access.

### Credentials

Controller-signed credentials carry a hybrid signature. This is the right
place to spend the 3373 bytes: credentials are issued rarely, are not on the
data path, and a forged credential is a serious compromise.

The credential layout is:

```text
[ header                                             ]
[ public_key (32) | controller_id (16) | nonce (16)  ]
[ ml_dsa_65_pub (1952)                               ]
[ ed25519_sig (64) | ml_dsa_65_sig (3309)            ]
```

The ML-DSA public key sits **before** the signatures so that it is part of
the signed body. Both signatures cover the same body, so the key cannot be
swapped for an attacker-controlled one. The controller's Ed25519 key is the
trust anchor that pins the ML-DSA key, so a node needs only one trusted
controller key.

The credential is therefore ~5.4 KB. That is acceptable because credentials
are exchanged rarely, over a control channel, and are cached.

### Node identity

The node's long-term identity uses Ed25519 (32-byte public key) rather than
ML-DSA-65 (1952 bytes). This is a deliberate trade-off:

- A node's public key appears in peer directories, controller databases, and
  handshake messages.
- At 1952 bytes per node, a 1000-node network directory is ~2 MB.
- The node's identity key is only used to authenticate the *handshake*, and
  the handshake already carries ML-KEM material.

The **controller-signed credential** does use ML-DSA-65, because that is the
long-lived, high-value artifact whose forgery would grant persistent network
access.

### The legacy shim (Track B)

The ZeroTier compatibility shim **cannot** be quantum-resistant. ZeroTier's
protocol uses X25519 and a custom Ed25519 variant, and the wire format has no
room for injected PQ material without breaking compatibility.

This is acceptable: the legacy shim is a migration path for existing ZeroTier
deployments, not the recommended long-term posture. Nodes that need PQ
protection use the ZT-next protocol.

## Implementation notes

### Two RNG worlds

`ml-kem` and `ml-dsa` use `rand_core` 0.10; the classical code uses `rand`
0.8. These have incompatible `CryptoRng` traits, so the workspace carries
both (`rand_pq` and `rand_core_pq` aliases). The two are kept strictly
separate to avoid accidentally passing a weak RNG to a PQ primitive.

### ML-KEM direction

In an ML-KEM exchange the **responder** encapsulates to the **initiator's**
encapsulation key. The responder's message therefore carries the ciphertext,
while the initiator's carries the encapsulation key. The
[`KemRole`](../../crates/zt-crypto/src/handshake.rs) field records which
side sent a message so the two are never confused — a mistake here produces
a handshake that silently fails to agree rather than an obvious error.

### Implicit rejection

FIPS 203 specifies that ML-KEM decapsulation never fails loudly: on a
malformed ciphertext it returns a pseudorandom shared secret. This is a
deliberate anti-oracle design. The consequence is that a corrupted
ciphertext is detected by the AEAD layer failing to authenticate, not by the
KEM itself.

## What is *not* done here

- **Hash-based signatures (SLH-DSA).** Not used. ML-DSA-65 is smaller and
  faster for the security levels we need.
- **Quantum-safe hashing.** SHA-256 and SHA-512 are considered
  quantum-resistant for collision and preimage resistance at the levels we
  use. Grover's algorithm gives a square-root speedup on preimage search,
  which is accounted for by using 256-bit hashes.
- **FN-DSA (FIPS 206).** Too new and too slow for general use.
- **Stateful hash-based signatures.** Rejected: they require a large
  one-time-key store and complicate multi-device deployment.

## References

- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard
- `draft-ietf-tls-hybrid-design` — Hybrid key exchange in TLS 1.3
- `draft-ietf-tls-ecdhe-mlkem` — the ECDHE-MLKEM construction in use by
  Chrome, Cloudflare, and Apple
- RFC 8439 — ChaCha20 and Poly1305
- RFC 7748 — X25519 and X448
- RFC 5869 — HKDF
- RFC 8032 — Ed25519
