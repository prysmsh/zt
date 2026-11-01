# The ZT-next protocol

## Layers

```
┌─────────────────────────────────────────────────────┐
│ Application  (IP / Ethernet frames, DNS, etc.)      │
├─────────────────────────────────────────────────────┤
│ Session     (replay window, directional keys)       │
├─────────────────────────────────────────────────────┤
│ Packet      (encrypted header + ciphertext)         │
├─────────────────────────────────────────────────────┤
│ Handshake   (Noise-style, hybrid PQ)                │
├─────────────────────────────────────────────────────┤
│ Transport   (UDP)                                   │
└─────────────────────────────────────────────────────┘
```

## Handshake

Noise-**IK**-style: the initiator knows the responder's static key
in advance, so the responder is authenticated in the first message and the
handshake completes in one round trip.

```
Initiator                                Responder
   │                                         │
   ├── msg1 ────────────────────────────────▶│
   │    e, s, mlkem_ek, payload              │
   │                                         │
   │◀── msg2 ────────────────────────────────┤
   │    e, mlkem_ct, payload                 │
   │                                         │
   ├── traffic keys derived ───────────────┤
```

### Message framing

Messages are a sequence of length-prefixed fields:

```
<[1] message type>
<[1] tag> <[2] length> <[..] value> ...
```

Self-describing fields mean an unrecognised field can be skipped rather
than breaking the parse — this is how the protocol extends without
breaking older peers.

| Tag | Field |
|---|---|
| 0x01 | Ephemeral X25519 public key (32 B) |
| 0x02 | Static Ed25519 public key (32 B) |
| 0x03 | ML-KEM-768 encapsulation key (1184 B) or ciphertext (1088 B) |
| 0x04 | Encrypted payload |

### Key agreement

| Suite | Init → Resp | Resp → Init |
|---|---|---|
| `X25519` | 32 B | 32 B |
| `MlKem768` | 1184 B | 1088 B |
| `HybridX25519MlKem768` | 1216 B | 1120 B |

In an ML-KEM exchange the **responder** encapsulates to the **initiator's**
encapsulation key, so the initiator's message carries the encapsulation key
and the responder's carries the ciphertext.

### Transcript

The transcript is a Noise `SymmetricState` using BLAKE3 as the hash:

```
MixHash(data):  h = BLAKE3(h ‖ data)
MixKey(input):  (ck, k) = HKDF-SHA256(ck, input, 2)
EncryptAndHash: ct = ENCRYPT(k, n++, pt); h = BLAKE3(h ‖ ct)
Split():         (k1, k2) = HKDF-SHA256(ck, "zt-next/split/v1", 2)
```

The negotiated **suite id is mixed into the initial hash**, before any key
material. A peer that negotiates one suite but performs another produces a
different transcript and the signature check fails — this is the
downgrade protection.

### Authentication

After the DH chain, each party signs the transcript hash with its hybrid
key (Ed25519 ‖ ML-DSA-65). The signed bytes are:

```
hash (32) ‖ sig_suite (1) ‖ initiator_ml_dsa_key ‖ responder_ml_dsa_key
```

The canonical ordering (initiator's key first) is used by **both** sides so
they sign over identical bytes.

### Why the static keys are not used for DH

Standard Noise IK mixes `es` and `se` — DH between an ephemeral and the
peer's *static* key. ZT-next's static key is Ed25519, which cannot perform
DH. The responder's static contribution instead comes from its *ephemeral*
plus the ML-KEM exchange.

This does not weaken the construction:

- **Forward secrecy** comes from the ephemeral exchange.
- **Authentication** comes from the signature over the transcript, not from
  a static DH contribution.

## Data plane

```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ session_id   │ seq          │ reserved     │ payload_len  │
│ [u8;4]       │ u64          │ u8           │ u16          │
├──────────────┴──────────────┴──────────────┴──────────────┤
│ ciphertext + Poly1305 tag                                  │
└────────────────────────────────────────────────────────────┘
```

**15-byte header.** The inner packet type is *inside* the ciphertext, so an
observer cannot tell what kind of traffic is flowing. The reserved byte is
always zero.

### Replay protection

Each direction has a sliding 64-packet window backed by a bitmap. A
sequence number outside the window resets it (counter desynchronisation);
one already seen is rejected. The check happens **before** decryption so a
replay costs no AEAD work, and the sequence number is only recorded
**after** successful decryption so a forged packet cannot consume a slot.

### Packet types

| Type | Name |
|---|---|
| 0x01 | `FRAME` |
| 0x02 | `PING` |
| 0x03 | `PONG` |
| 0x04 | `PATH_HINT` |
| 0x05 | `RELAY` |

## Session identifiers

Both peers derive the session id from the same inputs — the initiator's
address, the responder's public key, and the transcript hash as a session
nonce — so they always agree. The transcript hash is used because it is the
one value both parties independently computed.

## What is not implemented yet

- **Topology layer**: peer discovery, path selection, NAT traversal,
  relaying. The current implementation is a point-to-point session manager.
- **Data plane**: the forwarding path exists — `zt-node`'s data plane reads
  IP packets from the virtual interface, routes them to the peer that owns
  the destination, and writes the frames the peers send back — but nothing
  feeds it yet. The controller does not assign the overlay addresses the
  routing depends on, and the node agent does not open the interface. See
  [`docs/saas-readiness.md`](saas-readiness.md).
- **ZeroTier compatibility (Track B)**: the oracle harness is in place but
  the legacy shim is not started.

The control plane — the controller, its multi-tenant service layer, and the
node agent that talks to it — is implemented and deployed. See
[`docs/deployment.md`](deployment.md) and
[`docs/saas-readiness.md`](saas-readiness.md).

## Verifying it

```bash
cargo test                                    # the whole workspace
cargo run -p zt-node --bin demo               # live two-node demo
```

The demo starts two nodes on the loopback interface, performs a hybrid
post-quantum handshake, exchanges an encrypted frame, and demonstrates that
a replayed datagram is rejected.
