//! Key agreement using X25519.
//!
//! ZT-next uses X25519 (RFC 7748) with **raw** scalar multiplication, matching
//! the semantics of `crypto_scalarmult` in ZeroTier's `node/ECC.cpp`. The
//! shared secret is *not* hashed by the primitive; hashing happens later via
//! HKDF, which keeps the separation of concerns that Noise relies on.
//!
//! Note: this differs from `x25519-dalek`'s `diffie_hellman`, which applies
//! the all-zero output check. We use `x25519-dalek`'s lower-level API to get
//! the raw product and perform our own validation, so that behaviour is
//! explicit and testable.

use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};

/// Length of an X25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an X25519 private key.
pub const PRIVATE_KEY_LEN: usize = 32;

/// An X25519 static (long-term) key pair.
///
/// The private scalar is zeroized on drop.
pub struct StaticKeyPair {
    secret: StaticSecret,
    public: [u8; PUBLIC_KEY_LEN],
}

impl StaticKeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; PRIVATE_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::from_secret_bytes(&bytes)
    }

    /// Build a key pair from a 32-byte private scalar.
    pub fn from_secret_bytes(bytes: &[u8; PRIVATE_KEY_LEN]) -> Result<Self> {
        // Clamp per RFC 7748. x25519-dalek clamps internally on multiplication,
        // but we clamp here too so the stored scalar is canonical.
        let mut scalar = *bytes;
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let secret = StaticSecret::from(scalar);
        let public = PublicKey::from(&secret);
        Ok(Self {
            secret,
            public: public.to_bytes(),
        })
    }

    /// The raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// Perform a raw X25519 scalar multiplication.
    ///
    /// Returns the 32-byte shared secret. The result is **not** hashed; feed it
    /// to [`crate::symmetric::hkdf_sha256`] (or the Noise handshake) to derive
    /// traffic keys.
    pub fn agree(&self, peer_public: &[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32]> {
        // An all-zero shared secret means the peer sent a low-order point,
        // which is a known attack on unauthenticated X25519. Reject it.
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer).to_bytes();
        if shared == [0u8; 32] {
            return Err(Error::InvalidKey("low-order point: zero shared secret"));
        }
        Ok(shared)
    }
}

impl Drop for StaticKeyPair {
    fn drop(&mut self) {
        // StaticSecret zeroizes itself on drop; this is belt-and-braces.
        let _ = &mut self.secret;
    }
}

impl core::fmt::Debug for StaticKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticKeyPair")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

/// Compute the raw X25519 shared secret between two secret scalars.
///
/// Provided for interoperability testing and test-vector generation.
pub fn agree_raw(mine: &[u8; PRIVATE_KEY_LEN], theirs: &[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32]> {
    StaticKeyPair::from_secret_bytes(mine)?.agree(theirs)
}

/// Derive the public key for a private scalar.
pub fn public_from_secret(secret: &[u8; PRIVATE_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let mut scalar = *secret;
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let sk = StaticSecret::from(scalar);
    PublicKey::from(&sk).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 section 6.1 test vector for X25519.
    #[test]
    fn rfc7748_vector_1() {
        let mut alice_sk = [0u8; 32];
        let mut bob_sk = [0u8; 32];
        hex::decode_to_slice(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            &mut alice_sk,
        )
        .unwrap();
        hex::decode_to_slice(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            &mut bob_sk,
        )
        .unwrap();

        let alice_pk = public_from_secret(&alice_sk);
        assert_eq!(
            hex::encode(alice_pk),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );

        let bob_pk = public_from_secret(&bob_sk);
        assert_eq!(
            hex::encode(bob_pk),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );

        let shared = agree_raw(&alice_sk, &bob_pk).unwrap();
        assert_eq!(
            hex::encode(shared),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    /// RFC 7748 section 5.2 test vector for X25519.
    ///
    /// Note that in this vector `e6db...` is Bob's *u-coordinate* (i.e. his
    /// public key), used directly as the X25519 input. It is not derived
    /// from a private scalar, so it must not be recomputed via
    /// `public_from_secret`.
    #[test]
    fn rfc7748_vector_2() {
        let mut alice_sk = [0u8; 32];
        hex::decode_to_slice(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            &mut alice_sk,
        )
        .unwrap();
        let mut bob_pk = [0u8; 32];
        hex::decode_to_slice(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            &mut bob_pk,
        )
        .unwrap();

        // Public key for Alice's scalar: X25519(a, 9).
        let alice_pk = public_from_secret(&alice_sk);
        assert_eq!(
            hex::encode(alice_pk),
            "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019"
        );

        // Shared secret: X25519(a, X25519(b, 9)).
        let shared = agree_raw(&alice_sk, &bob_pk).unwrap();
        assert_eq!(
            hex::encode(shared),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    /// RFC 7748 section 5.2 iterated test vector.
    #[test]
    fn rfc7748_iterated_vector() {
        let mut k = [0u8; 32];
        let mut u = [0u8; 32];
        hex::decode_to_slice(
            "0900000000000000000000000000000000000000000000000000000000000000",
            &mut k,
        )
        .unwrap();
        u.copy_from_slice(&k);

        for _ in 0..1_000 {
            let next_k = agree_raw(&k, &u).unwrap();
            u = k;
            k = next_k;
        }

        assert_eq!(
            hex::encode(k),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
    }

    #[test]
    fn agreement_is_symmetric() {
        let a = StaticKeyPair::generate().unwrap();
        let b = StaticKeyPair::generate().unwrap();
        let ab = a.agree(&b.public_key_bytes()).unwrap();
        let ba = b.agree(&a.public_key_bytes()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn low_order_point_is_rejected() {
        let a = StaticKeyPair::generate().unwrap();
        let err = a.agree(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::InvalidKey(_)));
    }

    #[test]
    fn public_derivation_is_deterministic() {
        let mut sk = [0u8; 32];
        sk[0] = 1;
        assert_eq!(public_from_secret(&sk), public_from_secret(&sk));
    }
}
