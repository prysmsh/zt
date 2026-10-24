//! Node identity: long-term Ed25519 signing key plus derived address.
//!
//! # Addressing model
//!
//! ZT-next uses **per-network** addresses, unlike ZeroTier's single global
//! address. A node's address on a given network is:
//!
//! ```text
//! network_address = SHA256(domain_sep || network_id || ed25519_pubkey)[0..10]
//! ```
//!
//! The domain separator prevents cross-protocol key reuse. Truncating to 10
//! bytes matches ZeroTier's address width so that existing tooling, address
//! parsing, and UI expectations carry over.
//!
//! Because the address binds the network ID, the same node has a *different*
//! address on every network it joins. That gives two properties ZeroTier
//! lacks:
//!
//! 1. **Per-network ACLs** without maintaining a global identity registry.
//! 2. **Collision freedom across networks** — two nodes on different networks
//!    can never be confused for one another.

use core::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 private key seed in bytes.
pub const PRIVATE_KEY_LEN: usize = 32;
/// Length of a derived network address in bytes.
pub const ADDRESS_LEN: usize = 10;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Domain separator for network address derivation.
///
/// Binds addresses to this protocol so that a key used elsewhere cannot
/// produce a valid-looking address.
const ADDRESS_DOMAIN: &[u8] = b"zt-next/addr/v1";

/// A node's long-term identity.
///
/// Holds an Ed25519 signing key. The public half is the node's stable
/// cryptographic identity; the address is derived per-network from it.
///
/// The private key is zeroized on drop.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a new random identity.
    pub fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut rng);
        Ok(Self { signing })
    }

    /// Build an identity from a 32-byte Ed25519 seed.
    pub fn from_bytes(seed: &[u8; PRIVATE_KEY_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Build an identity from a 32-byte Ed25519 seed, returning an error if
    /// the seed is malformed.
    pub fn try_from_bytes(seed: &[u8; PRIVATE_KEY_LEN]) -> Result<Self> {
        Ok(Self::from_bytes(seed))
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// The raw 32-byte Ed25519 private key seed.
    ///
    /// Exposed for serialization only. Prefer not to call this directly.
    pub fn private_key_bytes(&self) -> [u8; PRIVATE_KEY_LEN] {
        self.signing.to_bytes()
    }

    /// Derive this node's address on the given network.
    pub fn address_for_network(&self, network_id: u64) -> Address {
        Address::derive(network_id, &self.public_key_bytes())
    }

    /// Sign a message with this identity's long-term key.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        use ed25519_dalek::Signer;
        self.signing.sign(msg).to_bytes()
    }

    /// Verify a signature produced by `public_key` over `msg`.
    pub fn verify(
        public_key: &[u8; PUBLIC_KEY_LEN],
        msg: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<()> {
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|_| Error::InvalidKey("bad ed25519 public key"))?;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        use ed25519_dalek::Verifier;
        vk.verify(msg, &sig)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print private key material.
        f.debug_struct("Identity")
            .field("public_key", &self.public_key_bytes())
            .finish()
    }
}

/// A node's address on a specific network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// The all-zero address, used as a "null" / unspecified value.
    pub const ZERO: Address = Address([0u8; ADDRESS_LEN]);

    /// Derive an address for a network from a node's public key.
    pub fn derive(network_id: u64, public_key: &[u8; PUBLIC_KEY_LEN]) -> Address {
        let mut hasher = Sha256::new();
        hasher.update(ADDRESS_DOMAIN);
        hasher.update(network_id.to_be_bytes());
        hasher.update(public_key);
        let digest = hasher.finalize();
        let mut out = [0u8; ADDRESS_LEN];
        out.copy_from_slice(&digest[..ADDRESS_LEN]);
        Address(out)
    }

    /// The raw address bytes.
    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    /// Build an address from raw bytes.
    pub fn from_bytes(bytes: &[u8; ADDRESS_LEN]) -> Address {
        Address(*bytes)
    }

    /// Parse a hex-encoded address.
    pub fn from_hex(s: &str) -> Result<Address> {
        let raw = hex::decode(s).map_err(|_| Error::InvalidKey("address is not valid hex"))?;
        if raw.len() != ADDRESS_LEN {
            return Err(Error::InvalidKey("address has wrong length"));
        }
        let mut out = [0u8; ADDRESS_LEN];
        out.copy_from_slice(&raw);
        Ok(Address(out))
    }

    /// Render the address as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Render the address in the `zt`-style human form, e.g. `a1b2c3d4e5`.
    pub fn to_string_human(&self) -> String {
        self.to_hex()
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; ADDRESS_LEN]> for Address {
    fn from(v: [u8; ADDRESS_LEN]) -> Self {
        Address(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_generates_and_roundtrips() {
        let id = Identity::generate().unwrap();
        let seed = id.private_key_bytes();
        let id2 = Identity::from_bytes(&seed);
        assert_eq!(id.public_key_bytes(), id2.public_key_bytes());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = Identity::generate().unwrap();
        let msg = b"the quick brown fox";
        let sig = id.sign(msg);
        Identity::verify(&id.public_key_bytes(), msg, &sig).unwrap();
        assert!(Identity::verify(&id.public_key_bytes(), b"tampered", &sig).is_err());
    }

    #[test]
    fn address_is_deterministic() {
        let id = Identity::generate().unwrap();
        let a1 = id.address_for_network(0xdead_beef_0000_0001);
        let a2 = id.address_for_network(0xdead_beef_0000_0001);
        assert_eq!(a1, a2);
    }

    #[test]
    fn address_differs_per_network() {
        let id = Identity::generate().unwrap();
        let a1 = id.address_for_network(1);
        let a2 = id.address_for_network(2);
        assert_ne!(a1, a2);
    }

    #[test]
    fn address_is_ten_bytes() {
        let id = Identity::generate().unwrap();
        let a = id.address_for_network(42);
        assert_eq!(a.as_bytes().len(), 10);
        assert_eq!(a.to_hex().len(), 20);
    }

    #[test]
    fn address_hex_roundtrip() {
        let id = Identity::generate().unwrap();
        let a = id.address_for_network(7);
        assert_eq!(Address::from_hex(&a.to_hex()).unwrap(), a);
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let id = Identity::generate().unwrap();
        let seed = id.private_key_bytes();
        let dbg = format!("{:?}", id);
        assert!(!dbg.contains(&hex::encode(seed)));
    }
}
