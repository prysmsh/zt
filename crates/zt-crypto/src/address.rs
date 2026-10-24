//! Identifier derivation helpers.
//!
//! ZT-next derives short identifiers from public keys. The derivation is
//! domain-separated so that a key used in one context cannot produce a valid
//! identifier in another.

use sha2::{Digest, Sha256};

/// Domain separator for controller identifiers.
const CONTROLLER_ID_DOMAIN: &[u8] = b"zt-next/controller/v1";

/// Derive a 16-byte controller identifier from a public key.
///
/// The identifier is a truncated SHA-256 over a domain-separated public key.
/// Controllers present this identifier in issued credentials, allowing nodes
/// to check that a credential came from a controller they recognize without
/// carrying the full public key in every packet.
pub fn derive_id(public_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(CONTROLLER_ID_DOMAIN);
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_deterministic() {
        let pk = [3u8; 32];
        assert_eq!(derive_id(&pk), derive_id(&pk));
    }

    #[test]
    fn id_differs_per_key() {
        assert_ne!(derive_id(&[1u8; 32]), derive_id(&[2u8; 32]));
    }

    #[test]
    fn id_is_sixteen_bytes() {
        assert_eq!(derive_id(&[0u8; 32]).len(), 16);
    }
}
