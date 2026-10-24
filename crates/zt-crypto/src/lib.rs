//! # `zt-crypto`
//!
//! Cryptographic primitives for the ZT-next overlay network protocol.
//!
//! This crate is the cryptographic foundation of the new protocol. It
//! deliberately contains **only** standardized primitives with well-known
//! implementations — there is no hand-rolled cipher, hash, or signature
//! scheme anywhere in this crate.
//!
//! ## Design principles
//!
//! 1. **No bespoke cryptography.** Every primitive comes from RustCrypto.
//!    Where ZT-next deliberately diverges from ZeroTier (e.g. standard
//!    Ed25519 instead of Ed25519-over-a-truncated-SHA-512), the divergence is
//!    a choice to *use* the standard form, not to invent a variant.
//! 2. **Per-network addressing.** See [`identity`].
//! 3. **Short-lived credentials.** See the `zt-next` protocol crate (M1).
//! 4. **Forward secrecy by construction.** Ephemeral X25519 keys are rotated
//!    per session; see [`key_agreement`].
//!
//! ## Primitive inventory
//!
//! | Purpose | Primitive | Standard |
//! |---|---|---|
//! | Symmetric encryption | ChaCha20-Poly1305 | RFC 8439 |
//! | Key agreement | X25519 | RFC 7748 |
//! | Key derivation | HKDF-SHA256 | RFC 5869 |
//! | Signatures | Ed25519 | RFC 8032 |
//! | Hashing | SHA-256, BLAKE3 | FIPS 180-4 / BLAKE3 spec |
//!
//! ## ZeroTier comparison
//!
//! For reference, ZeroTier's `node/` implementation uses:
//!
//! | ZeroTier | ZT-next | Rationale |
//! |---|---|---|
//! | Salsa20/12 + Poly1305 | ChaCha20-Poly1305 | Standard, widely implemented |
//! | X25519 + hand-rolled SHA-512 counter KDF | X25519 + HKDF-SHA256 | Removes custom KDF |
//! | Ed25519 over truncated SHA-512, 96-byte sig | Standard Ed25519, 64-byte sig | Removes custom signature scheme |
//! | Global address, `SHA512(digest)[59..64]` | Per-network address, `SHA256(domain‖nwid‖pk)[0..10]` | Per-network ACLs; no rejection loop |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod credential;
pub mod error;
pub mod identity;
pub mod key_agreement;
pub mod symmetric;

pub use credential::{ControllerIdentity, NodeCredential};
pub use error::{Error, Result};
pub use identity::{Address, Identity};
pub use key_agreement::StaticKeyPair;
pub use symmetric::{NonceValue, SymmetricKey};

/// The domain separator used for all ZT-next protocol purposes.
pub const PROTOCOL_DOMAIN: &[u8] = b"zt-next/v1";
