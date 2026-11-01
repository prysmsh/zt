//! Foreign-protocol dialects for ZT-next.
//!
//! This crate holds the implementations that let a ZT-next node interoperate
//! with other overlay networks over the same UDP transport:
//!
//! - [`wireguard`] — the Tailscale dialect, which is WireGuard.
//! - [`zerotier`] — the legacy ZeroTier dialect.
//!
//! See `docs/interoperability.md` for the architecture and trade-offs.
//!
//! # Status
//!
//! The Tailscale dialect is structurally complete but uses BLAKE3 for the
//! transcript hash where upstream WireGuard uses BLAKE2s. It is therefore
//! **not** yet wire-compatible with `tailscaled`. The deviation is recorded
//! in [`wireguard::HASH_NOTE`].
//!
//! The ZeroTier dialect reproduces the key set layout, the custom 96-byte
//! signature format, and the SHA-512 counter-mode KDF. The packet framing and
//! credential formats remain to be implemented.

pub mod credential;
pub mod hashcash;
pub mod packet;
pub mod salsa20;
pub mod wireguard;
pub mod zerotier;

pub use credential::{CertificateOfMembership, CertificateOfOwnership, OwnedThing, Qualifier};
pub use hashcash::{address_from_public_key, memory_hard_hash};
pub use packet::{Cipher, LegacyPacket, Verb};
pub use salsa20::{Poly1305, Salsa20};
pub use wireguard::{
    derive_session_keys, transport_decrypt, transport_encrypt, transport_nonce, KeySchedule,
    SessionKeys, StaticKey, TransportSession, AEAD_KEY_LEN, KEY_LEN, REKEY_AFTER_MESSAGES,
    REKEY_AFTER_TIME, TAG_LEN,
};
pub use zerotier::{
    agree, is_reserved_address, LegacyAddress, LegacyIdentity, LegacySignature, ADDRESS_LEN,
    ED25519_LEN, KEY_SET_LEN, SIG_LEN,
};
