# ZT-next interoperability

## Can ZT-next be Tailscale- and ZeroTier-compatible at the same time?

Short answer: **yes for real client interop, but not by reimplementing both
protocols in one wire format.** It works because both ecosystems are
*transport-compatible* in a specific, narrow sense: a ZT-next node can speak
each foreign protocol as an alternative dialect over the same UDP transport and
the same process, while ZT-next-to-ZT-next traffic keeps using the native
protocol.

This document explains the architecture, what it costs, and what it does not
give you.

## The three dialects

```
                    ┌──────────────────────────────────────────┐
                    │              zt-node process             │
                    │                                          │
   UDP :41641 ────▶│  dispatcher ──┬──▶ zt-next handshake     │
   (Tailscale)      │               │    + zt-next data plane  │
                    │               │                          │
   UDP :9994  ────▶│               ├──▶ WireGuard/Noise engine  │
   (ZeroTier)       │               │    (Tailscale dialect)    │
                    │               │                          │
   UDP :9994  ────▶│               └──▶ ZeroTier legacy shim   │
   (ZT-next)        │                    (ZeroTier dialect)      │
                    └──────────────────────────────────────────┘
```

| Dialect | Transport | Purpose |
|---|---|---|
| **ZT-next** | UDP, native handshake | ZT-next peers, controller-issued short-lived credentials |
| **Tailscale** | UDP, WireGuard (Noise IK / WG handshake) | Join Tailscale tailnets and interop with `tailscaled` |
| **ZeroTier** | UDP, legacy `HELLO`/`OK`/`FRAME` verbs | Join ZeroTier networks and interop with `zerotier-one` |

The same UDP socket handles all three. Dispatch is by datagram inspection:

- **ZT-next** — data packets carry the `00 5a 54 00` magic; handshake
  messages carry the `00 5a 54` prefix with a type byte of `0x01` or `0x02`.
- **Tailscale** — WireGuard messages have a 4-byte header whose first byte is
  a type (`1`–`4`) and whose remaining three bytes are a zero reserved field.
- **ZeroTier** — the legacy framing is at least 28 bytes and the verb byte at
  offset 27 must be one of the 20 defined verbs.

### The prefix collision that forced a wire-format change

WireGuard uses message types `1` and `2`, which are the same values ZT-next
originally used for its handshake types. The first byte alone was therefore
ambiguous.

The native handshake now carries an explicit magic prefix
(`00 5a 54 ‖ type`), matching the data-plane magic. This costs four bytes
per handshake — negligible, since handshakes are rare — and removes the
ambiguity permanently. The dispatcher is now exact rather than heuristic.

The implementation lives in `crates/zt-node/src/dialect.rs`.

## Why "same transport" works

The key insight is that the three protocols differ in their **session
semantics**, not in their **transport requirements**:

- All three are UDP.
- All three are peer-to-peer with an optional relay fallback.
- All three carry IP/Ethernet frames once the session is up.
- All three need a discovery/relay mechanism to traverse NAT.

That means one node can:

1. Run three independent session managers.
2. Share one relay infrastructure (each dialect's relay protocol differs, but
   the relay *deployment* can be shared operationally).
3. Expose one virtual interface carrying frames from all three.
4. Run one controller UI that shows all peers regardless of dialect.

## What "real client interop" requires

Interoperating with official clients is not a matter of framing. Each dialect
requires reproducing its own cryptographic and protocol conventions exactly.

### Tailscale dialect

Tailscale's data plane is WireGuard. To interop:

- **WireGuard handshake** — Curve25519 key exchange, Noise IK construction,
  `Noise_IK_25519_ChaChaPoly_BLAKE2s` label set.
- **ChaCha20-Poly1305 transport** — the same AEAD ZT-next already uses, with
  WireGuard's message counters and nonce scheme.
- **Noise IK** — static-key authentication, so the responder is authenticated
  in the first message. This maps cleanly onto ZT-next's existing Noise-style
  handshake.
- **Data key / data salt** — WireGuard derives separate data-plane keys for
  each direction plus a salt for the initiator.
- **Rekeying** — WireGuard rekeys at `REKEY_AFTER_MESSAGES` (2³⁶) and
  `REKEY_AFTER_TIME` (120 s). These must be honored exactly or peers
  desynchronize.

Good news: ZT-next already uses X25519, ChaCha20-Poly1305, HKDF-SHA256, and
BLAKE3. The Tailscale dialect is a *rearrangement* of primitives ZT-next
already has, plus a faithful implementation of the Noise IK label set.

**One deviation remains.** Upstream WireGuard hashes the handshake transcript
with BLAKE2s. ZT-next uses BLAKE3, and the current implementation keeps
BLAKE3. A `tailscaled` peer will reject the handshake. Switching to BLAKE2s
means adding the `blake2` crate, which is the only new dependency this dialect
requires.

This is recorded in `zt_legacy::wireguard::HASH_NOTE` rather than hidden,
because claiming interoperability that does not work is worse than shipping a
partial implementation.

### ZeroTier dialect

This is the harder one, and the repository already documents the obstacles in
[`docs/legacy-protocol-facts.md`](legacy-protocol-facts.md):

| Requirement | Difficulty | Notes |
|---|---|---|
| 64-byte key set (`C25519 ‖ Ed25519`) | Straightforward | Layout only |
| 96-byte signature format | **Hard** | Not standard Ed25519 — Ed25519 over `SHA512(msg)` with the raw digest prefix appended. `ed25519-dalek` cannot produce it. |
| SHA-512 counter-mode KDF | **Hard** | ZeroTier's `agree()` is a hand-rolled KDF, not HKDF |
| Salsa20/12 + Poly1305 | Moderate | Different AEAD from ZT-next's |
| Packet framing with mutable hop count | Moderate | The 3-bit hop count may be changed in transit without invalidating the MAC |
| 20 packet verbs | Mechanical | `NOP` … `PATH_NEGOTIATION_REQUEST` |
| `CertificateOfMembership` | Moderate | Must be byte-identical; long-lived bearer capability |
| `CertificateOfOwnership` | Moderate | Proof-of-possession over the node's MAC/IP |

The oracle harness in `oracle/zt_oracle.cpp` and the golden vectors in
`vectors/legacy/` exist precisely so these byte-level details can be verified
against ZeroTier's own C++ implementation rather than guessed.

## The architecture

### 1. A transport dispatcher

```rust
pub enum Dialect {
    ZtNext,
    Tailscale,
    ZeroTier,
}

pub fn classify(datagram: &[u8]) -> Option<Dialect> {
    if zt_crypto::packet::is_data_packet(datagram) { return Some(Dialect::ZtNext) }
    if zt_crypto::packet::is_handshake_packet(datagram) { return Some(Dialect::ZtNext) }
    if zt_legacy::wireguard::is_wireguard(datagram) { return Some(Dialect::Tailscale) }
    if zt_legacy::zerotier::is_legacy(datagram) { return Some(Dialect::ZeroTier) }
    None
}
```

Classification must be infallible in the sense that it never misroutes: an
unrecognized datagram is dropped, not guessed at.

### 2. Separate session managers

Each dialect owns its own peer table, key schedule, and replay protection.
They must not share state, because their replay windows, counters, and
rekeying rules differ.

```rust
pub struct Node {
    zt_next: ZtNextSessions,     // native
    tailscale: WireGuardSessions, // Tailscale dialect
    zerotier: LegacySessions,     // ZeroTier dialect
}
```

Each session manager presents the same interface to the upper layer:

```rust
trait SessionManager {
    fn handle(&mut self, datagram: &[u8], from: SocketAddr) -> Result<SessionEvent>;
    fn open(&mut self, peer: PeerId, payload: &[u8]) -> Result<Vec<u8>>;
}
```

### 3. A unified frame layer

Above the session managers sits one frame dispatcher. All three dialects
produce the same thing: an IP or Ethernet frame destined for the local TUN
device, or a control message for the topology layer.

```rust
enum SessionEvent {
    Frame(Vec<u8>),        // deliver to TUN
    PathLearned(PathInfo),
    PeerLost(PeerId),
    Control(ControlMessage),
}
```

### 4. One controller, three membership models

This is the part that needs careful design, because the three ecosystems have
fundamentally different trust models.

|  | ZT-next | Tailscale | ZeroTier |
|---|---|---|---|
| Membership credential | Short-lived, key-bound, hybrid-signed | WireGuard keypair + node key in control plane | `CertificateOfMembership`, long-lived bearer |
| Who issues it | ZT-next controller | Tailscale control server | ZeroTier controller |
| Revocation | Pull-based; cannot renew | Control plane push | Revocation list push |
| Address | Per-network, 10 bytes | Per-tailnet, 10 bytes | Global, 5 bytes |
| Address derivation | `SHA256(domain‖nwid‖pk)` | WireGuard key + tailnet | `SHA512(digest)[59..64]` |

**Consequence:** a single ZT-next controller cannot issue Tailscale or
ZeroTier credentials. Those credentials come from their own control planes.

So the controller gains a **federated membership** concept:

```rust
enum Membership {
    /// Issued by our own controller. Short-lived and key-bound.
    Native { credential: NodeCredential },
    /// Issued by a Tailscale control server for a joined tailnet.
    Tailscale { tailnet: String, node_key: String },
    /// Issued by a ZeroTier controller for a joined network.
    ZeroTier { network_id: u64, com: Vec<u8> },
}
```

A ZT-next node enrolled in a tailnet or ZeroTier network holds that
credential alongside its native one. The operator sees all of them in one
console.

### 5. One relay fleet, three relay protocols

Relay *deployment* is shared — the same machines, the same monitoring, the
same drain procedures — but the relay *protocols* differ:

- ZT-next relays speak the native `RELAY` packet type.
- Tailscale relays speak the DERP protocol.
- ZeroTier relays speak the legacy `RENDEZVOUS`/relay verbs.

The controller can therefore show one relay list, but each entry carries a
capability set:

```rust
struct Relay {
    id: EntityId,
    endpoint: String,
    capabilities: RelayCapabilities,
}

struct RelayCapabilities {
    zt_next: bool,
    tailscale_derp: bool,
    zerotier: bool,
}
```

## Honest trade-offs

### What this does not give you

- **No transparent cross-network routing.** A Tailscale node and a ZeroTier
  node on the same ZT-next node cannot talk to each other unless something
  explicitly bridges them. WireGuard and ZeroTier frames are not the same
  protocol, and no common header exists.
- **No unified addressing.** A node has a ZT-next address, a Tailscale IP, and
  a ZeroTier address. They are unrelated identifiers, not aliases.
- **No single credential.** Each dialect requires its own membership
  credential from its own authority.
- **Different security properties.** ZeroTier's COM remains a long-lived
  bearer capability even inside a ZT-next node. ZT-next's key-bound,
  short-lived design applies only to native ZT-next membership.
- **More attack surface.** Three protocol implementations means three sets of
  parsing bugs to find. The legacy dialects are the risky part — they cannot
  use standard RustCrypto APIs for signature or KDF, so they are custom code
  and must be held to a higher verification bar.

### The honest recommendation

Build the **ZT-next native protocol and controller first**, with the
transport dispatcher designed in from the start. Then add dialects in order of
increasing difficulty:

1. **Tailscale dialect** — moderate. Reuses primitives ZT-next already has.
   The main work is a faithful Noise IK implementation and WireGuard's
   rekeying rules.
2. **ZeroTier dialect** — hard. Custom signature format, custom KDF, custom
   AEAD, 20 verbs, byte-identical credentials. This is Track B, already
   scoped in the project plan as M7.

The dispatcher and unified frame layer are the parts that must be right early.
The dialects themselves can land later without rework.

## Testing strategy

Interoperability cannot be tested against the spec; it must be tested against
the other implementation.

### ZeroTier

```bash
# Build the oracle against ZeroTier's own sources
./scripts/build-oracle.sh ~/compose/zerotierone

# Emit reference vectors from ZeroTier's C++ code
./target/oracle/zt-oracle vectors/legacy

# The Rust shim is checked against them
cargo test -p zt-legacy
```

The golden vectors cover identity derivation, signing, and key agreement.
The packet-level and credential-level vectors still need to be generated.

### Tailscale

Tailscale's protocol is open source, so the equivalent approach is:

- Build against `tailscale` sources and diff observable behavior.
- Test against a real `tailscaled` in a container.
- Use `tailscale ping` and `tailscale netcheck` as external assertions.
- Cross-check key schedules against independent WireGuard implementations.

### Shared requirements

- Fuzz every datagram parser. Three parsers means three fuzz targets.
- Golden-vector tests must cover every byte-level convention, not just the
  ones that are convenient.
- The dispatcher itself needs tests proving no datagram is ever misrouted.

## Status

| Component | State |
|---|---|
| ZT-next native handshake and data plane | ✅ complete |
| Transport dispatcher with exact prefix matching | ✅ implemented (`zt-node/src/dialect.rs`) |
| Native handshake magic prefix | ✅ implemented, resolves the WireGuard type collision |
| Tailscale dialect: WireGuard key schedule and transport | ✅ implemented, **not yet wire-compatible** (BLAKE3 vs BLAKE2s) |
| Tailscale dialect: Noise IK handshake messages | not started |
| ZeroTier dialect: 64-byte key set | ✅ implemented |
| ZeroTier dialect: 96-byte custom signature | ✅ implemented, verified against the oracle |
| ZeroTier dialect: SHA-512 counter-mode KDF | ✅ implemented, verified against the oracle |
| ZeroTier dialect: Ed25519 seed expansion | ✅ implemented (ZeroTier hashes the seed) |
| ZeroTier dialect: packet framing and 20 verbs | not started |
| ZeroTier dialect: COM and COO credentials | not started |
| Unified frame layer | designed, not implemented |
| Federated membership in the controller | designed, not implemented |
| Shared relay fleet | relay infrastructure planned; capability model not implemented |

## References

- ZeroTier protocol facts — [`legacy-protocol-facts.md`](legacy-protocol-facts.md)
- ZT-next wire format — [`protocol.md`](protocol.md)
- Tailscale / WireGuard — `tailscale/wgengine`, `wireguard-go`
- Noise IK specification — <https://noiseprotocol.org/noise.html>
