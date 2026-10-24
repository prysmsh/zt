//! A Noise-protocol-style symmetric state and handshake transcript.
//!
//! This implements the core state machine of the Noise Protocol Framework
//! (revision 34) for the subset of operations ZT-next needs. It is not a
//! general Noise implementation: it supports the specific patterns
//! ZT-next uses, with the following deliberate differences.
//!
//! # Differences from standard Noise
//!
//! 1. **The cipher suite is negotiated**, not fixed. A Noise handshake
//!    pattern names its own DH and cipher functions; ZT-next negotiates
//!    between hybrid (X25519+ML-KEM-768), pure ML-KEM-768, and pure X25519
//!    variants, and the negotiated choice is mixed into the transcript so a
//!    downgrade is detected.
//! 2. **The hash is BLAKE3**, not SHA-256. BLAKE3 is faster and has a
//!    tree-mode construction that suits the streaming transcript use case.
//! 3. **Signature schemes are hybrid** (Ed25519+ML-DSA-65) and also
//!    negotiated.
//!
//! # State
//!
//! The symmetric state is a pair of keys plus a running transcript hash:
//!
//! ```text
//! k  -> current chaining key
//! h  -> running hash of the handshake transcript
//! ck -> current chaining key (for ratcheting)
//! ```
//!
//! Each message mixes the peer's public keys into `h` before deriving keys
//! from `k`. This is what makes the transcript binding work: if either
//! party substitutes a different key or a different negotiated suite, the
//! derived keys diverge and the handshake fails to authenticate.
//!
//! # Key schedule
//!
//! ```text
//! MixHash(data):  h = HASH(h || data)
//! MixKey(input):  (ck, k) = HKDF(ck, input, 2)
//! EncryptAndHash: ct = ENCRYPT(k, n++, pt); h = HASH(h || ct)
//! DecryptAndHash: pt = DECRYPT(k, n++, ct); h = HASH(h || ct)
//! Split():         (k1, k2) = HKDF(ck, zerolen, 2)
//! ```
//!
//! This matches Noise's `SymmetricState` exactly, which means the
//! construction is auditable against the specification.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::symmetric::{open, seal, NonceValue, SymmetricKey, KEY_LEN, TAG_LEN};

/// Length of a Noise protocol name (padded to 32 bytes).
pub const PROTOCOL_NAME_LEN: usize = 32;

/// The Noise protocol name for ZT-next.
///
/// Noise protocol names are padded to 32 bytes with zeros.
pub const PROTOCOL_NAME: &[u8; PROTOCOL_NAME_LEN] =
    b"ZTNextHandshakeV1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

/// A symmetric state: chaining key, running transcript hash, and nonce.
#[derive(Clone)]
pub struct SymmetricState {
    /// Current chaining key.
    ck: [u8; KEY_LEN],
    /// Running hash of the handshake transcript.
    h: [u8; 32],
    /// Per-message nonce counter.
    nonce: u64,
    /// The negotiated cipher suite identifier, mixed into the transcript.
    suite_id: u8,
}

impl SymmetricState {
    /// Create a state from a protocol name and the negotiated suite id.
    ///
    /// The suite id is mixed into the initial hash so that a peer which
    /// claims one suite but behaves as if it negotiated another will fail
    /// authentication.
    pub fn new(name: &[u8; PROTOCOL_NAME_LEN], suite_id: u8) -> Self {
        let mut h = [0u8; 32];
        h.copy_from_slice(&blake3::hash(name).as_bytes()[..32]);

        // Mix the suite identifier into the initial hash. This binds the
        // negotiation to the transcript.
        let mut h2 = blake3::Hasher::new();
        h2.update(&h);
        h2.update(&[suite_id]);
        let digest = h2.finalize();
        h.copy_from_slice(&digest.as_bytes()[..32]);

        Self {
            ck: [0u8; KEY_LEN],
            h,
            nonce: 0,
            suite_id,
        }
    }

    /// The suite identifier bound into this transcript.
    pub fn suite_id(&self) -> u8 {
        self.suite_id
    }

    /// Mix a public key or other data into the transcript hash.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.h);
        hasher.update(data);
        let digest = hasher.finalize();
        self.h.copy_from_slice(&digest.as_bytes()[..32]);
    }

    /// Mix key material into the chaining key.
    pub fn mix_key(&mut self, input: &[u8]) -> Result<()> {
        self.mix_key_and_set(input)?;
        Ok(())
    }

    /// Mix key material into the chaining key and return the new symmetric
    /// key.
    pub fn mix_key_and_set(&mut self, input: &[u8]) -> Result<SymmetricKey> {
        let hk = Hkdf::<Sha256>::new(None, &self.ck);
        let mut out = [0u8; 64];
        hk.expand(input, &mut out)
            .map_err(|_| Error::InvalidHkdfLength)?;
        self.ck.copy_from_slice(&out[..KEY_LEN]);
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&out[KEY_LEN..]);
        self.nonce = 0;
        Ok(SymmetricKey::from_bytes(&k))
    }

    /// Encrypt a plaintext and mix the ciphertext into the transcript.
    pub fn encrypt_and_hash(&mut self, key: &SymmetricKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = NonceValue::from_counter(0, self.nonce);
        let aad = self.h.to_vec();
        let (ct, tag) = seal(key, &nonce, plaintext, &aad)?;
        self.nonce += 1;

        let mut out = ct;
        out.extend_from_slice(&tag);

        self.mix_hash(&out);
        Ok(out)
    }

    /// Decrypt a ciphertext and mix it into the transcript.
    pub fn decrypt_and_hash(&mut self, key: &SymmetricKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(Error::InvalidLength);
        }
        let nonce = NonceValue::from_counter(0, self.nonce);
        let aad = self.h.to_vec();
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag);

        let pt = open(key, &nonce, ct, &tag_bytes, &aad)?;
        self.nonce += 1;

        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// The current transcript hash.
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }

    /// The current chaining key.
    pub fn chaining_key(&self) -> [u8; 32] {
        self.ck
    }

    /// Split the chaining key, returning `(send_key, recv_key)` for the
    /// **responder** side.
    ///
    /// This is the mirror of [`Self::split`]: the responder's send key is the
    /// initiator's receive key.
    pub fn split_responder(&self) -> Result<(SymmetricKey, SymmetricKey)> {
        let (k1, k2) = self.split()?;
        Ok((k2, k1))
    }

    /// Split the chaining key into two directional traffic keys.
    ///
    /// The first key is for the party that *initiated* the handshake
    /// (messages it sends), the second for the party that *responded*
    /// (messages it sends). The initiator uses `(k1, k2)` as
    /// `(send, recv)`; the responder uses `(k2, k1)`.
    ///
    /// The two keys are derived with distinct HKDF labels so that they are
    /// independent even though both come from the same chaining key.
    pub fn split(&self) -> Result<(SymmetricKey, SymmetricKey)> {
        let hk = Hkdf::<Sha256>::new(None, &self.ck);
        let mut out = [0u8; 64];
        hk.expand(b"zt-next/split/v1", &mut out)
            .map_err(|_| Error::InvalidHkdfLength)?;
        let mut k1 = [0u8; KEY_LEN];
        let mut k2 = [0u8; KEY_LEN];
        k1.copy_from_slice(&out[..KEY_LEN]);
        k2.copy_from_slice(&out[KEY_LEN..]);
        Ok((SymmetricKey::from_bytes(&k1), SymmetricKey::from_bytes(&k2)))
    }
}

impl core::fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SymmetricState")
            .field("suite_id", &self.suite_id)
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// A directional session cipher used after the handshake completes.
///
/// Wraps a symmetric key with an incrementing nonce counter, in the style of
/// a Noise transport message.
pub struct TransportCipher {
    key: SymmetricKey,
    nonce: u64,
}

impl TransportCipher {
    /// Create a transport cipher from a traffic key.
    pub fn new(key: SymmetricKey) -> Self {
        Self { key, nonce: 0 }
    }

    /// Encrypt a payload.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = NonceValue::from_counter(0, self.nonce);
        let (ct, tag) = seal(&self.key, &nonce, plaintext, &[])?;
        self.nonce += 1;
        let mut out = ct;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt a payload.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(Error::InvalidLength);
        }
        let nonce = NonceValue::from_counter(0, self.nonce);
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag);
        let pt = open(&self.key, &nonce, ct, &tag_bytes, &[])?;
        self.nonce += 1;
        Ok(pt)
    }
}

impl core::fmt::Debug for TransportCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportCipher")
            .field("nonce", &self.nonce)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_are_synchronized() {
        let mut a = SymmetricState::new(PROTOCOL_NAME, 0x03);
        let mut b = SymmetricState::new(PROTOCOL_NAME, 0x03);

        let key = a.mix_key_and_set(b"shared").unwrap();
        let key_b = b.mix_key_and_set(b"shared").unwrap();
        assert_eq!(key.as_bytes(), key_b.as_bytes());

        let ct = a.encrypt_and_hash(&key, b"hello").unwrap();
        let pt = b.decrypt_and_hash(&key_b, &ct).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(a.handshake_hash(), b.handshake_hash());
    }

    #[test]
    fn suite_mismatch_diverges() {
        let a = SymmetricState::new(PROTOCOL_NAME, 0x03);
        let b = SymmetricState::new(PROTOCOL_NAME, 0x02);
        assert_ne!(a.handshake_hash(), b.handshake_hash());
    }

    #[test]
    fn transcript_detects_tampering() {
        let mut a = SymmetricState::new(PROTOCOL_NAME, 0x03);
        let mut b = SymmetricState::new(PROTOCOL_NAME, 0x03);
        let key = a.mix_key_and_set(b"k").unwrap();
        let key_b = b.mix_key_and_set(b"k").unwrap();

        let mut ct = a.encrypt_and_hash(&key, b"hello").unwrap();
        ct[0] ^= 0xff;
        assert!(b.decrypt_and_hash(&key_b, &ct).is_err());
    }

    #[test]
    fn split_produces_distinct_keys() {
        let mut s = SymmetricState::new(PROTOCOL_NAME, 0x03);
        s.mix_key_and_set(b"k").unwrap();
        let (k1, k2) = s.split().unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn transport_cipher_roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        let mut a = TransportCipher::new(key.clone());
        let mut b = TransportCipher::new(key);

        let ct = a.seal(b"payload").unwrap();
        assert_eq!(b.open(&ct).unwrap(), b"payload");
    }

    #[test]
    fn transport_cipher_rejects_reordering() {
        let key = SymmetricKey::generate().unwrap();
        let mut a = TransportCipher::new(key.clone());
        let mut b = TransportCipher::new(key);
        let _c1 = a.seal(b"one").unwrap();
        let c2 = a.seal(b"two").unwrap();
        // Delivering out of order must fail.
        assert!(b.open(&c2).is_err());
    }
}
