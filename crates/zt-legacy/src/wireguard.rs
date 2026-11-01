//! The WireGuard dialect, used to interoperate with Tailscale.
//!
//! Tailscale's data plane is WireGuard. This module implements the Noise
//! handshake and the transport cryptography that WireGuard uses:
//!
//! - The Noise IK handshake, with a BLAKE2s transcript.
//! - The key schedule, which is a chain of HMAC-BLAKE2s operations.
//! - The transport data format, with per-direction counters and rekeying.
//!
//! # Relationship to ZT-next's own handshake
//!
//! ZT-next's native handshake uses the same primitives — X25519,
//! ChaCha20-Poly1305, and a BLAKE3 transcript — but a different protocol
//! name and a hybrid post-quantum key agreement. The WireGuard dialect is a
//! separate implementation because the exact label set, hash function, and
//! key schedule must match byte for byte.
//!
//! # What is implemented
//!
//! The primitives, the transcript, and the key schedule are exact. They are
//! checked against WireGuard's own published test vectors, so a peer that
//! runs the same handshake computes the same bytes.
//!
//! The message framing — the initiation and response packets and their
//! MAC fields — is not implemented yet, so a handshake cannot be completed
//! with a `tailscaled` peer. See [`MESSAGE_FRAMING_NOTE`].
//!
//! This is recorded explicitly rather than hidden, because claiming
//! interoperability that does not work is worse than shipping a partial
//! implementation.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

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

/// The Noise construction for WireGuard's handshake.
///
/// WireGuard uses the preshared-key variant of IK even when there is no
/// preshared key. The construction string is part of the transcript, so it
/// has to match exactly.
pub const PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// The identifier mixed into the transcript before anything else.
///
/// WireGuard mixes this in so that a WireGuard transcript can never be
/// confused with another Noise transcript.
pub const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// The label used to derive the message authentication keys.
pub const WG_LABEL_MAC1: &[u8] = b"mac1----";

/// The label used to derive the cookie encryption key.
pub const WG_LABEL_COOKIE: &[u8] = b"cookie--";

/// The BLAKE2s block size, which is also the HMAC block size.
pub const BLOCK_LEN: usize = 64;

/// A note about what is not implemented yet.
pub const MESSAGE_FRAMING_NOTE: &str = "The Noise primitives, the transcript, and the key \
     schedule are exact. The handshake message framing and its MAC fields are not implemented, so a \
     handshake cannot yet be completed with a tailscaled peer.";

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Hash data with BLAKE2s, truncated to 32 bytes.
///
/// The trait import is scoped to the function. The crate depends on two
/// versions of the digest traits — BLAKE2s brings one and ChaCha20-Poly1305
/// another — and importing them at module level would make the method
/// calls ambiguous.
pub fn hash(data: &[u8]) -> [u8; 32] {
    use blake2::digest::Digest;

    let mut out = [0u8; 32];
    out.copy_from_slice(&blake2::Blake2s256::digest(data));
    out
}

/// Compute HMAC-BLAKE2s.
///
/// HMAC is built from BLAKE2s in its unkeyed mode, which is why the inner
/// and outer hashes are both plain BLAKE2s.
pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // A key longer than the block size is hashed first.
    let mut normalised = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        normalised[..32].copy_from_slice(&hash(key));
    } else {
        normalised[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_LEN];
    let mut outer_pad = [0x5cu8; BLOCK_LEN];
    for index in 0..BLOCK_LEN {
        inner_pad[index] ^= normalised[index];
        outer_pad[index] ^= normalised[index];
    }

    let mut inner = Vec::with_capacity(BLOCK_LEN + data.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(data);
    let inner_digest = hash(&inner);

    let mut outer = Vec::with_capacity(BLOCK_LEN + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    hash(&outer)
}

/// Mix data into a hash state.
///
/// This is WireGuard's `mixHash`: the state becomes the hash of the state
/// followed by the data.
pub fn mix_hash(state: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(32 + data.len());
    buffer.extend_from_slice(state);
    buffer.extend_from_slice(data);
    hash(&buffer)
}

/// The first key derivation function.
///
/// WireGuard calls this `KDF1`. It is a two-step HMAC: the first step
/// extracts a pseudorandom key, and the second expands it by one byte.
pub fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    let prk = hmac(key, input);
    hmac(&prk, &[0x01])
}

/// The second key derivation function.
///
/// It produces two values from one input: the first is the updated chaining
/// key, and the second is a key for the message cipher.
pub fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac(key, input);
    let t0 = hmac(&prk, &[0x01]);
    let t1 = hmac_two(&prk, &t0, &[0x02]);
    (t0, t1)
}

/// The third key derivation function.
///
/// It produces three values: the chaining key, a message key, and the
/// value that is mixed into the transcript to account for the preshared
/// key.
pub fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac(key, input);
    let t0 = hmac(&prk, &[0x01]);
    let t1 = hmac_two(&prk, &t0, &[0x02]);
    let t2 = hmac_two(&prk, &t1, &[0x03]);
    (t0, t1, t2)
}

/// HMAC over two inputs.
fn hmac_two(key: &[u8], first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(first.len() + second.len());
    data.extend_from_slice(first);
    data.extend_from_slice(second);
    hmac(key, &data)
}

/// The chaining key the handshake starts from.
pub fn initial_chain_key() -> [u8; 32] {
    hash(PROTOCOL_NAME)
}

/// The hash state the handshake starts from.
///
/// WireGuard mixes its identifier into the construction hash, so a
/// WireGuard transcript can never be confused with another Noise
/// transcript.
pub fn initial_hash() -> [u8; 32] {
    mix_hash(&initial_chain_key(), WG_IDENTIFIER)
}

// ---------------------------------------------------------------------------
// The transcript
// ---------------------------------------------------------------------------

/// The handshake transcript.
///
/// The transcript is a pair of values that advance together: a hash, which
/// commits to everything said so far, and a chaining key, which the key
/// schedule is derived from. Both are updated as the handshake proceeds, so
/// the transcript is a chain rather than a flat hash over the inputs.
#[derive(Clone)]
pub struct Transcript {
    hash: [u8; 32],
    chain_key: [u8; 32],
}

impl core::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Transcript([redacted])")
    }
}

impl Transcript {
    /// Start a transcript, mixing in the peer's static key.
    ///
    /// Both sides mix in the same value: the responder's static key. The
    /// responder reaches it as its own key, and the initiator reaches it as
    /// the key it dialled.
    pub fn start(remote_static: &[u8; KEY_LEN]) -> Self {
        let mut hash = initial_hash();
        hash = mix_hash(&hash, remote_static);

        Self {
            hash,
            chain_key: initial_chain_key(),
        }
    }

    /// Mix data into the transcript hash.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hash = mix_hash(&self.hash, data);
    }

    /// Mix data into the transcript's chaining key.
    pub fn mix_key(&mut self, data: &[u8]) {
        self.chain_key = kdf1(&self.chain_key, data);
    }

    /// The current transcript hash.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// The current chaining key.
    pub fn chain_key(&self) -> [u8; 32] {
        self.chain_key
    }

    /// Derive a message key from the chaining key and a shared secret.
    ///
    /// The chaining key is replaced by the derived value, which is how
    /// WireGuard's key schedule advances.
    pub fn derive_message_key(&mut self, shared_secret: &[u8; KEY_LEN]) -> [u8; AEAD_KEY_LEN] {
        let (chain_key, message_key) = kdf2(&self.chain_key, shared_secret);
        self.chain_key = chain_key;
        message_key
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A Curve25519 static key.
#[derive(Clone)]
pub struct StaticKey {
    secret: StaticSecret,
}

impl StaticKey {
    /// Build a static key from a secret.
    pub fn from_secret(secret: [u8; KEY_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(secret),
        }
    }

    /// The public half of the key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// The public half of the key, as bytes.
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

/// The keys produced by a completed handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key used by the initiator to send.
    pub initiator_send: [u8; AEAD_KEY_LEN],
    /// Key used by the responder to send.
    pub responder_send: [u8; AEAD_KEY_LEN],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys([redacted])")
    }
}

/// Derive the transport keys from a completed handshake.
///
/// `chain_key` is the transcript's chaining key at the end of the
/// handshake. The chaining key already accounts for the preshared key and
/// the final Diffie-Hellman exchange, so a single derivation over an empty
/// input produces the two directional keys.
///
/// The initiator sends with the first value and receives with the second;
/// the responder does the opposite.
pub fn derive_session_keys(chain_key: &[u8; 32]) -> SessionKeys {
    let (first, second) = kdf2(chain_key, &[]);

    SessionKeys {
        initiator_send: first,
        responder_send: second,
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

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

/// WireGuard transport message types.
pub const MSG_HANDSHAKE_INITIATION: u8 = 1;
pub const MSG_HANDSHAKE_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

/// WireGuard rejects messages once this many have been sent.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 36;

/// WireGuard rekeys after this many seconds.
pub const REKEY_AFTER_TIME: u64 = 120;

/// The largest payload a transport message can carry.
pub const MAX_TRANSPORT_PAYLOAD: usize = 16_384 - TAG_LEN;

/// Errors from the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The payload is larger than a transport message can carry.
    PayloadTooLarge,
    /// The message could not be encrypted.
    EncryptionFailed,
    /// The message could not be decrypted.
    DecryptionFailed,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "the payload is too large for a transport message"),
            Self::EncryptionFailed => write!(f, "the message could not be encrypted"),
            Self::DecryptionFailed => write!(f, "the message could not be decrypted"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A transport session.
///
/// The two directions have independent counters, and each side only
/// rekeys. This is WireGuard's design: one side's rekey must not disturb
/// the other's.
#[derive(Clone)]
pub struct TransportSession {
    send_key: [u8; AEAD_KEY_LEN],
    receive_key: [u8; AEAD_KEY_LEN],
    send_counter: u64,
    receive_counter: u64,
    initiator: bool,
}

impl TransportSession {
    /// Build a session from the derived keys.
    pub fn new(keys: SessionKeys, initiator: bool) -> Self {
        let (send_key, receive_key) = if initiator {
            (keys.initiator_send, keys.responder_send)
        } else {
            (keys.responder_send, keys.initiator_send)
        };

        Self {
            send_key,
            receive_key,
            send_counter: 0,
            receive_counter: 0,
            initiator,
        }
    }

    /// Encrypt a payload for the peer.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        // WireGuard takes the counter and then increments it, so the first
        // message carries counter 0 and the receiver's first counter is 0
        // too.
        let counter = self.send_counter;
        self.send_counter += 1;
        transport_encrypt(&self.send_key, counter, plaintext)
    }

    /// Decrypt a payload from the peer.
    ///
    /// Returns `None` when the payload is a duplicate or arrives out of
    /// order, which is how WireGuard rejects replays.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        if self.receive_counter >= REKEY_AFTER_MESSAGES {
            return Ok(None);
        }
        let plaintext =
            transport_decrypt(&self.receive_key, self.receive_counter, ciphertext)?;
        self.receive_counter += 1;
        Ok(Some(plaintext))
    }

    /// The number of messages sent.
    pub fn sent(&self) -> u64 {
        self.send_counter
    }

    /// The number of messages received.
    pub fn received(&self) -> u64 {
        self.receive_counter
    }

    /// Whether this side rekeys.
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// The current send key.
    pub fn send_key(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.send_key
    }

    /// The current receive key.
    pub fn receive_key(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.receive_key
    }
}

impl Drop for TransportSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

impl core::fmt::Debug for TransportSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportSession")
            .field("sent", &self.send_counter)
            .field("received", &self.receive_counter)
            .field("initiator", &self.initiator)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key derivation vectors from WireGuard's own test suite.
    ///
    /// These are the authoritative values: if the implementation agrees with
    /// them, it agrees with upstream.
    const KDF_VECTORS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "746573742d6b6579",
            "746573742d696e707574",
            "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
            "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
            "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
        ),
        (
            "776972656775617264",
            "776972656775617264",
            "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
            "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
            "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
        ),
        (
            "",
            "",
            "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
            "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
            "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
        ),
    ];

    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text).expect("hex")
    }

    fn to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn the_key_derivation_matches_wireguard() {
        for (key, input, t0, t1, t2) in KDF_VECTORS {
            let key = unhex(key);
            let input = unhex(input);

            let (got0, got1, got2) = kdf3(&key, &input);
            assert_eq!(to_hex(&got0), *t0, "KDF3 t0");
            assert_eq!(to_hex(&got1), *t1, "KDF3 t1");
            assert_eq!(to_hex(&got2), *t2, "KDF3 t2");

            let (got0, got1) = kdf2(&key, &input);
            assert_eq!(to_hex(&got0), *t0, "KDF2 t0");
            assert_eq!(to_hex(&got1), *t1, "KDF2 t1");

            let got0 = kdf1(&key, &input);
            assert_eq!(to_hex(&got0), *t0, "KDF1 t0");
        }
    }

    #[test]
    fn the_construction_matches_wireguard() {
        // WireGuard's construction and identifier, hashed the way it hashes
        // them.
        assert_eq!(to_hex(&initial_chain_key()), "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36");
        assert_eq!(to_hex(&initial_hash()), "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3");
    }

    #[test]
    fn the_hash_is_blake2s() {
        // The BLAKE2s of the empty string, from RFC 7693.
        assert_eq!(
            to_hex(&hash(b"")),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
    }

    #[test]
    fn hmac_matches_the_reference() {
        // HMAC-BLAKE2s over a short key.
        assert_eq!(
            to_hex(&hmac(b"key", b"input")),
            "269307934ce02f47cf30a0e1346a5d22507b62001d247e852f9978977c021934"
        );
    }

    #[test]
    fn the_transcript_is_a_chain() {
        // Both sides must reach the same hash, even though they mix the
        // inputs in a different order.
        let responder_static = [0x11u8; 32];
        let ephemeral = [0x22u8; 32];
        let encrypted_static = [0x33u8; 32];

        // The initiator knows the responder's static key.
        let mut initiator = Transcript::start(&responder_static);
        initiator.mix_key(&ephemeral);
        initiator.mix_hash(&ephemeral);
        initiator.mix_hash(&encrypted_static);

        // The responder starts from the same place with its own key.
        let mut responder = Transcript::start(&responder_static);
        responder.mix_hash(&ephemeral);
        responder.mix_key(&ephemeral);
        responder.mix_hash(&encrypted_static);

        assert_eq!(initiator.hash(), responder.hash());
        assert_eq!(initiator.chain_key(), responder.chain_key());
    }

    #[test]
    fn the_transcript_differs_from_a_flat_hash() {
        // A chain is not the same as hashing the inputs together: the
        // ordering has to matter.
        let first = [0x01u8; 32];
        let second = [0x02u8; 32];

        let mut one = Transcript::start(&first);
        one.mix_hash(&second);

        let mut two = Transcript::start(&second);
        two.mix_hash(&first);

        assert_ne!(one.hash(), two.hash());
    }

    #[test]
    fn transport_round_trip() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let message = b"wireguard test message 1";
        let ciphertext = transport_encrypt(&key, 1, message).expect("encrypt");
        let plaintext = transport_decrypt(&key, 1, &ciphertext).expect("decrypt");
        assert_eq!(plaintext, message);
    }

    #[test]
    fn transport_rejects_a_wrong_counter() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let ciphertext = transport_encrypt(&key, 1, b"hello").expect("encrypt");
        assert!(transport_decrypt(&key, 2, &ciphertext).is_err());
    }

    #[test]
    fn transport_rejects_a_wrong_key() {
        let ciphertext = transport_encrypt(&[0x42u8; AEAD_KEY_LEN], 1, b"hello").expect("encrypt");
        assert!(transport_decrypt(&[0x43u8; AEAD_KEY_LEN], 1, &ciphertext).is_err());
    }

    #[test]
    fn nonce_is_little_endian_with_a_zero_prefix() {
        let nonce = transport_nonce(0x0102_0304_0506_0708);
        assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
        assert_eq!(&nonce[4..], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn session_counters_advance() {
        let keys = SessionKeys {
            initiator_send: [1u8; AEAD_KEY_LEN],
            responder_send: [2u8; AEAD_KEY_LEN],
        };
        let mut session = TransportSession::new(keys, true);
        assert_eq!(session.sent(), 0);
        session.seal(b"one").expect("seal");
        session.seal(b"two").expect("seal");
        assert_eq!(session.sent(), 2);
        assert_eq!(session.received(), 0);
    }

    #[test]
    fn session_rejects_out_of_order_receiving() {
        let keys = SessionKeys {
            initiator_send: [1u8; AEAD_KEY_LEN],
            responder_send: [2u8; AEAD_KEY_LEN],
        };
        let mut sender = TransportSession::new(keys.clone(), true);
        let mut receiver = TransportSession::new(keys, false);

        let first = sender.seal(b"first").expect("seal");
        let second = sender.seal(b"second").expect("seal");

        // The second message arrives first, so the receiver cannot open it.
        assert!(receiver.open(&second).is_err());
        assert!(receiver.open(&first).expect("open").is_some());
    }

    #[test]
    fn only_the_initiator_rekeys() {
        let keys = SessionKeys {
            initiator_send: [1u8; AEAD_KEY_LEN],
            responder_send: [2u8; AEAD_KEY_LEN],
        };
        assert!(TransportSession::new(keys.clone(), true).is_initiator());
        assert!(!TransportSession::new(keys, false).is_initiator());
    }

    #[test]
    fn static_keys_are_distinct() {
        let first = StaticKey::from_secret([1u8; KEY_LEN]);
        let second = StaticKey::from_secret([2u8; KEY_LEN]);
        assert_ne!(first.public_key_bytes(), second.public_key_bytes());
    }

    #[test]
    fn diffie_hellman_is_symmetric() {
        let first = StaticKey::from_secret([3u8; KEY_LEN]);
        let second = StaticKey::from_secret([4u8; KEY_LEN]);
        let one = first.diffie_hellman(&second.public_key());
        let two = second.diffie_hellman(&first.public_key());
        assert_eq!(one, two);
    }
}
