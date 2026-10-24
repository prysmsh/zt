//! Symmetric encryption and key derivation.
//!
//! # Design notes
//!
//! ZT-next deliberately uses **only** primitives that have standardized,
//! well-audited implementations:
//!
//! - **ChaCha20-Poly1305** (RFC 8439) for AEAD — widely implemented in
//!   constant time, no AES hardware dependency.
//! - **X25519** (RFC 7748) for key agreement.
//! - **HKDF-SHA256** (RFC 5869) for key derivation, replacing ZeroTier's
//!   hand-rolled SHA-512 counter-mode KDF.
//! - **Ed25519** (RFC 8032) for signatures, in its standard form.
//!
//! Nothing in this module is hand-rolled cryptography; all primitives come
//! from the RustCrypto family.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Length of a ChaCha20-Poly1305 key.
pub const KEY_LEN: usize = 32;
/// Length of a ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;
/// Length of the Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// A ChaCha20-Poly1305 key.
///
/// Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Build a key from raw bytes.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        SymmetricKey(*bytes)
    }

    /// The raw key bytes.
    ///
    /// Exposed for serialization and test-vector output only.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Generate a random key.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Ok(SymmetricKey(bytes))
    }
}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey([redacted])")
    }
}

/// A ChaCha20-Poly1305 nonce.
///
/// Compared in constant time where it is used as part of a nonce-reuse guard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NonceValue([u8; NONCE_LEN]);

impl NonceValue {
    /// Build a nonce from raw bytes.
    pub fn from_bytes(bytes: &[u8; NONCE_LEN]) -> Self {
        NonceValue(*bytes)
    }

    /// The raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    /// Derive a nonce from a 64-bit counter and a 32-bit session/epoch salt.
    ///
    /// The counter occupies the first 8 bytes (big-endian) and the salt the
    /// last 4. This layout matches the "nonce = prefix || counter" convention
    /// used by Noise, so a single 32-bit salt prefix plus a 64-bit counter
    /// yields a unique nonce for every packet in a session.
    pub fn from_counter(salt: u32, counter: u64) -> Self {
        let mut out = [0u8; NONCE_LEN];
        out[..8].copy_from_slice(&counter.to_be_bytes());
        out[8..].copy_from_slice(&salt.to_be_bytes());
        NonceValue(out)
    }

    /// The counter value encoded in this nonce.
    pub fn counter(&self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.0[..8]);
        u64::from_be_bytes(b)
    }

    /// The salt value encoded in this nonce.
    pub fn salt(&self) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.0[8..]);
        u32::from_be_bytes(b)
    }
}

impl core::fmt::Debug for NonceValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NonceValue({})", hex::encode(self.0))
    }
}

/// Encrypt and authenticate `plaintext` in place-appended style.
///
/// Returns `(ciphertext, tag)`.
pub fn seal(
    key: &SymmetricKey,
    nonce: &NonceValue,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce.as_bytes());
    let mut ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::InvalidLength)?;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&ciphertext[ciphertext.len() - TAG_LEN..]);
    ciphertext.truncate(ciphertext.len() - TAG_LEN);
    Ok((ciphertext, tag))
}

/// Decrypt and verify `ciphertext` with the given `tag`.
///
/// Returns the plaintext, or `Error::AuthenticationFailed` if the tag does
/// not verify.
pub fn open(
    key: &SymmetricKey,
    nonce: &NonceValue,
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if tag.len() != TAG_LEN {
        return Err(Error::InvalidLength);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce.as_bytes());
    let mut buf = ciphertext.to_vec();
    buf.extend_from_slice(tag);
    cipher
        .decrypt(nonce, Payload { msg: &buf, aad })
        .map_err(|_| Error::AuthenticationFailed)
}

/// HKDF-SHA256 key derivation.
///
/// Extracts a pseudorandom key from `ikm` and `salt`, then expands it to
/// `info`-labelled output of `out.len()` bytes.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| Error::InvalidHkdfLength)
}

/// Derive a session key from a shared secret.
///
/// The shared secret is run through HKDF with the given context label, and
/// the result is split into a directional pair of keys.
pub fn derive_session_keys(
    shared_secret: &[u8],
    context: &[u8],
) -> Result<(SymmetricKey, SymmetricKey)> {
    let mut out = [0u8; 64];
    hkdf_sha256(shared_secret, &[], context, &mut out)?;
    let mut a = [0u8; KEY_LEN];
    let mut b = [0u8; KEY_LEN];
    a.copy_from_slice(&out[..KEY_LEN]);
    b.copy_from_slice(&out[KEY_LEN..]);
    Ok((SymmetricKey(a), SymmetricKey(b)))
}

/// Constant-time equality for byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn fill_secure_random(buf: &mut [u8]) {
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        let nonce = NonceValue::from_counter(7, 0);
        let (ct, tag) = seal(&key, &nonce, b"hello world", b"aad").unwrap();
        assert_ne!(&ct[..], b"hello world");
        let pt = open(&key, &nonce, &ct, &tag, b"aad").unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn wrong_aad_fails_authentication() {
        let key = SymmetricKey::generate().unwrap();
        let nonce = NonceValue::from_counter(1, 0);
        let (ct, tag) = seal(&key, &nonce, b"secret", b"aad1").unwrap();
        assert_eq!(
            open(&key, &nonce, &ct, &tag, b"aad2").unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = SymmetricKey::generate().unwrap();
        let nonce = NonceValue::from_counter(1, 0);
        let (mut ct, tag) = seal(&key, &nonce, b"secret payload", b"").unwrap();
        ct[0] ^= 0xff;
        assert!(open(&key, &nonce, &ct, &tag, b"").is_err());
    }

    #[test]
    fn nonce_counter_roundtrip() {
        let n = NonceValue::from_counter(0xdead_beef, 0x0102_0304_0506_0708);
        assert_eq!(n.counter(), 0x0102_0304_0506_0708);
        assert_eq!(n.salt(), 0xdead_beef);
    }

    #[test]
    fn hkdf_is_deterministic_and_separated() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        hkdf_sha256(b"ikm", b"salt", b"info", &mut a).unwrap();
        hkdf_sha256(b"ikm", b"salt", b"info", &mut b).unwrap();
        hkdf_sha256(b"ikm", b"salt", b"other", &mut c).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hkdf_rejects_oversized_output() {
        let mut out = vec![0u8; 255 * 32 + 1];
        assert!(hkdf_sha256(b"ikm", b"", b"", &mut out).is_err());
    }

    #[test]
    fn session_keys_are_distinct() {
        let (a, b) = derive_session_keys(b"shared", b"ctx").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
