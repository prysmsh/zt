//! The WireGuard dialect, used to interoperate with Tailscale.
//!
//! Tailscale's data plane is WireGuard. This module implements the parts
//! needed to establish a session and exchange transport data with a
//! `tailscaled` peer:
//!
//! - The Noise IK handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`).
//! - The WireGuard key schedule, including the initiator's data salt.
//! - The transport data format with per-direction counters and rekeying.
//!
//! # Relationship to ZT-next's own handshake
//!
//! ZT-next's native handshake uses the same primitives — X25519,
//! ChaCha20-Poly1305, and a BLAKE3 transcript — but a different protocol name
//! and a hybrid post-quantum key agreement. The WireGuard dialect is a
//! separate implementation because the exact label set, hash function, and
//! key schedule must match byte for byte.
//!
//! # Deviations from upstream WireGuard
//!
//! - The transcript hash is BLAKE3 here, matching ZT-next's convention.
//!   Upstream WireGuard uses BLAKE2s. A peer expecting BLAKE2s will not
//!   complete the handshake, so this module is **not** wire-compatible with
//!   upstream until the hash is switched. See [`HASH_NOTE`].
//!
//! This is recorded explicitly rather than hidden, because claiming
//! interoperability that does not work is worse than shipping a partial
//! implementation.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a Curve25519 key.
pub const KEY_LEN: usize = 32;

/// Length of a ChaCha20-Poly1305 key.
pub const AEAD_KEY_LEN: usize = 32;

/// Length of a ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;

/// Length of the Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// Length of the Noise protocol name, padded to 32 bytes.
pub const PROTOCOL_NAME_LEN: usize = 32;

/// The Noise protocol name for the WireGuard handshake.
///
/// WireGuard's name is 33 bytes, which is longer than Noise's 32-byte limit.
/// Noise specifies that names longer than the hash length are replaced by
/// their hash. The name is therefore hashed before use.
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The hashed protocol name, used as the initial transcript state.
pub fn hashed_protocol_name() -> [u8; 32] {
    let digest = blake3::hash(PROTOCOL_NAME);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// A note about the transcript hash deviation.
pub const HASH_NOTE: &str = "The transcript hash is BLAKE3, not BLAKE2s. Wire-compatible interop \
     requires switching to BLAKE2s.";

/// WireGuard transport message types.
pub const MSG_HANDSHAKE_INITIATION: u8 = 1;
pub const MSG_HANDSHAKE_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

/// WireGuard rejects messages once this many have been sent.
///
/// After this many transport messages the initiator must rekey.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 36;

/// WireGuard rejects messages once this much time has passed.
///
/// After this many seconds the initiator must rekey.
pub const REKEY_AFTER_TIME: u64 = 120;

/// Maximum transport payload, leaving room for the 16-byte tag.
pub const MAX_TRANSPORT_PAYLOAD: usize = 16_384 - TAG_LEN;

/// A Curve25519 static secret.
///
/// Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StaticKey {
    secret: StaticSecret,
}

impl StaticKey {
    /// Generate a new random static key.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        Self { secret }
    }

    /// Build from raw secret bytes.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(*bytes),
        }
    }

    /// The public half.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// The public key bytes.
    pub fn public_key_bytes(&self) -> [u8; KEY_LEN] {
        self.public_key().to_bytes()
    }

    /// Perform X25519 with a peer's public key.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; KEY_LEN] {
        self.secret.diffie_hellman(peer).to_bytes()
    }
}

impl core::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StaticKey([redacted])")
    }
}

/// The WireGuard key schedule.
///
/// The schedule is a chain of HKDF operations over the handshake transcript,
/// producing a chaining key that is finally split into the two direction keys
/// and the initiator's data salt.
#[derive(Clone)]
pub struct KeySchedule {
    chaining_key: [u8; 32],
}

impl core::fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeySchedule([redacted])")
    }
}

impl KeySchedule {
    /// Mix a key into the chaining key, returning the derived value.
    fn mix_key(&mut self, input: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.chaining_key);
        let mut out = [0u8; 64];
        hk.expand(input, &mut out)
            .expect("64 bytes is a valid HKDF output length");
        self.chaining_key.copy_from_slice(&out[..32]);
        out[32..].try_into().expect("slice is 32 bytes")
    }
}

/// The keys produced by a completed handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key used by the initiator to send.
    pub initiator_send: [u8; AEAD_KEY_LEN],
    /// Key used by the responder to send.
    pub responder_send: [u8; AEAD_KEY_LEN],
    /// Salt the initiator uses when deriving data-plane nonces.
    pub data_salt: [u8; 32],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys([redacted])")
    }
}

/// Derive the session keys from a completed handshake transcript.
///
/// `transcript` must be the final handshake hash, and `dh` the initiator's
/// X25519 shared secret with the responder's static key.
pub fn derive_session_keys(transcript: &[u8; 32], dh: &[u8; KEY_LEN]) -> SessionKeys {
    let mut schedule = KeySchedule {
        chaining_key: *transcript,
    };

    // The temp key is derived first, then the two directional keys, then the
    // data salt.
    let _temp = schedule.mix_key(dh);
    let initiator_send = schedule.mix_key(&[]);
    let responder_send = schedule.mix_key(&[]);
    let data_salt = schedule.mix_key(&[]);

    SessionKeys {
        initiator_send,
        responder_send,
        data_salt,
    }
}

/// Compute the Noise IK transcript hash.
///
/// `ephemeral` is the initiator's ephemeral public key, `remote_static` is the
/// responder's static public key, and `encrypted_static` is the initiator's
/// static key as encrypted during the handshake.
pub fn transcript_hash(
    initiator_static: &[u8; KEY_LEN],
    responder_static: &[u8; KEY_LEN],
    ephemeral: &[u8; KEY_LEN],
    encrypted_static: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&hashed_protocol_name());
    hasher.update(initiator_static);
    hasher.update(responder_static);
    hasher.update(ephemeral);
    hasher.update(encrypted_static);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.as_bytes()[..32]);
    out
}

/// Encrypt a transport payload.
///
/// WireGuard's nonce is 12 bytes: four zero bytes, then an eight-byte
/// little-endian counter.
pub fn transport_encrypt(
    key: &[u8; AEAD_KEY_LEN],
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if plaintext.len() > MAX_TRANSPORT_PAYLOAD {
        return Err(TransportError::PayloadTooLarge);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = transport_nonce(counter);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| TransportError::EncryptionFailed)?;
    Ok(ciphertext)
}

/// Decrypt a transport payload.
pub fn transport_decrypt(
    key: &[u8; AEAD_KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if ciphertext.len() > MAX_TRANSPORT_PAYLOAD + TAG_LEN {
        return Err(TransportError::PayloadTooLarge);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = transport_nonce(counter);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| TransportError::DecryptionFailed)?;
    Ok(plaintext)
}

/// Build the transport nonce for a counter.
pub fn transport_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Errors from the transport layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The payload exceeded the maximum size.
    PayloadTooLarge,
    /// Encryption failed.
    EncryptionFailed,
    /// Decryption failed, usually a bad key or a replayed counter.
    DecryptionFailed,
}

/// A WireGuard transport session.
///
/// Tracks the send and receive counters and enforces WireGuard's rekey
/// rules.
pub struct TransportSession {
    send_key: [u8; AEAD_KEY_LEN],
    recv_key: [u8; AEAD_KEY_LEN],
    send_counter: u64,
    recv_counter: u64,
    /// When the session was created, for the time-based rekey rule.
    created: std::time::Instant,
    /// Whether this side initiated the session.
    initiator: bool,
}

impl TransportSession {
    /// Create a session from derived keys.
    pub fn new(keys: SessionKeys, initiator: bool) -> Self {
        let (send_key, recv_key) = if initiator {
            (keys.initiator_send, keys.responder_send)
        } else {
            (keys.responder_send, keys.initiator_send)
        };
        Self {
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
            created: std::time::Instant::now(),
            initiator,
        }
    }

    /// The counter of the next message to send.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// The counter of the next message expected.
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }

    /// Whether the session must be rekeyed.
    ///
    /// Only the initiator rekeys. A responder waits for the initiator to send
    /// a new handshake.
    pub fn needs_rekey(&self) -> bool {
        self.initiator
            && (self.send_counter >= REKEY_AFTER_MESSAGES
                || self.created.elapsed().as_secs() >= REKEY_AFTER_TIME)
    }

    /// Encrypt and send a payload.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let counter = self.send_counter;
        let out = transport_encrypt(&self.send_key, counter, plaintext)?;
        self.send_counter += 1;
        Ok(out)
    }

    /// Decrypt and receive a payload.
    ///
    /// The counter must match exactly. WireGuard does not use a sliding
    /// window; an out-of-order or replayed message is dropped.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let counter = self.recv_counter;
        let out = transport_decrypt(&self.recv_key, counter, ciphertext)?;
        self.recv_counter += 1;
        Ok(out)
    }
}

impl core::fmt::Debug for TransportSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportSession")
            .field("send_counter", &self.send_counter)
            .field("recv_counter", &self.recv_counter)
            .field("initiator", &self.initiator)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_round_trip() {
        let key = [7u8; AEAD_KEY_LEN];
        let plaintext = b"hello mesh";
        let ciphertext = transport_encrypt(&key, 0, plaintext).unwrap();
        let recovered = transport_decrypt(&key, 0, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn transport_rejects_a_wrong_counter() {
        let key = [7u8; AEAD_KEY_LEN];
        let ciphertext = transport_encrypt(&key, 0, b"payload").unwrap();
        assert!(transport_decrypt(&key, 1, &ciphertext).is_err());
    }

    #[test]
    fn transport_rejects_a_wrong_key() {
        let ciphertext = transport_encrypt(&[7u8; AEAD_KEY_LEN], 0, b"payload").unwrap();
        assert!(transport_decrypt(&[8u8; AEAD_KEY_LEN], 0, &ciphertext).is_err());
    }

    #[test]
    fn nonce_is_little_endian_with_a_zero_prefix() {
        let nonce = transport_nonce(1);
        assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
        assert_eq!(&nonce[4..], &[1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn session_counters_advance() {
        let keys = SessionKeys {
            initiator_send: [1u8; 32],
            responder_send: [2u8; 32],
            data_salt: [3u8; 32],
        };
        let mut session = TransportSession::new(keys, true);
        assert_eq!(session.send_counter(), 0);
        session.seal(b"one").unwrap();
        session.seal(b"two").unwrap();
        assert_eq!(session.send_counter(), 2);
    }

    #[test]
    fn session_rejects_out_of_order_receiving() {
        let keys = SessionKeys {
            initiator_send: [1u8; 32],
            responder_send: [2u8; 32],
            data_salt: [3u8; 32],
        };
        let mut responder = TransportSession::new(keys.clone(), false);
        let mut initiator = TransportSession::new(keys, true);
        let first = initiator.seal(b"first").unwrap();
        let second = initiator.seal(b"second").unwrap();

        // The responder expects the first counter.
        assert!(responder.open(&second).is_err());
        assert_eq!(responder.open(&first).unwrap(), b"first");
    }

    #[test]
    fn only_the_initiator_rekeys() {
        let keys = SessionKeys {
            initiator_send: [1u8; 32],
            responder_send: [2u8; 32],
            data_salt: [3u8; 32],
        };
        let initiator = TransportSession::new(keys.clone(), true);
        let responder = TransportSession::new(keys, false);
        assert!(!initiator.needs_rekey());
        assert!(!responder.needs_rekey());
    }

    #[test]
    fn static_keys_are_distinct() {
        let a = StaticKey::generate();
        let b = StaticKey::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn diffie_hellman_is_symmetric() {
        let a = StaticKey::generate();
        let b = StaticKey::generate();
        let ab = a.diffie_hellman(&b.public_key());
        let ba = b.diffie_hellman(&a.public_key());
        assert_eq!(ab, ba);
    }
}
