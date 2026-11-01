//! ZeroTier's memory-hard identity hash.
//!
//! A ZeroTier node's address is not derived with a plain hash. It comes from
//! a memory-hard construction that expands a 2 MiB buffer, which makes
//! generating vanity addresses expensive and stops an attacker from grinding
//! addresses cheaply.
//!
//! The construction is:
//!
//! 1. `digest = SHA512(public_key_set)`
//! 2. Fill a 2 MiB buffer by repeatedly encrypting 64-byte blocks with
//!    Salsa20/20 in a CBC-like configuration, each block seeded from the
//!    previous one.
//! 3. Walk the buffer in pairs of 64-bit words, using each as an index into
//!    the buffer to shuffle entries between the buffer and the digest.
//!
//! The node's address is the last five bytes of the digest.
//!
//! This is the only part of the legacy dialect that is deliberately
//! expensive. It runs once per identity, never on a hot path.

use crate::salsa20::Salsa20;

/// The size of the memory-hard working buffer.
pub const GEN_MEMORY: usize = 2_097_152;

/// The maximum first byte of the digest for a valid identity.
///
/// Identities whose digest starts above this threshold are rejected, which
/// is what makes address grinding expensive.
pub const HASHCASH_FIRST_BYTE_LESS_THAN: u8 = 17;

/// Compute the memory-hard digest of a public key set.
///
/// Returns the 64-byte digest.
pub fn memory_hard_hash(public_key_set: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut digest = [0u8; 64];
    digest.copy_from_slice(&Sha512::digest(public_key_set));

    // The cipher uses the first half of the digest as the key and the second
    // half as the IV.
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&digest[32..40]);
    let mut cipher = Salsa20::new(key, iv);

    // Fill the working buffer. The first block is 64 zero bytes. Each
    // subsequent block's plaintext is the previous block's ciphertext, and
    // the cipher's counter keeps advancing across the whole buffer. This
    // makes the construction sequential rather than randomly seekable.
    let mut buffer = vec![0u8; GEN_MEMORY];
    let mut previous = [0u8; 64];
    for chunk in buffer.chunks_exact_mut(64) {
        chunk.copy_from_slice(&previous);
        cipher.crypt20(chunk);
        previous.copy_from_slice(chunk);
    }

    // Shuffle entries between the buffer and the digest.
    let words = GEN_MEMORY / 8;
    let mut index = 0usize;
    while index < words {
        let raw1 = u64::from_le_bytes(
            buffer[index * 8..index * 8 + 8]
                .try_into()
                .expect("8 bytes"),
        );
        let raw2 = u64::from_le_bytes(
            buffer[(index + 1) * 8..(index + 1) * 8 + 8]
                .try_into()
                .expect("8 bytes"),
        );
        index += 2;

        let idx1 = (raw1.swap_bytes() % 8) as usize;
        let idx2 = (raw2.swap_bytes() % words as u64) as usize;

        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&buffer[idx2 * 8..idx2 * 8 + 8]);
        buffer[idx2 * 8..idx2 * 8 + 8].copy_from_slice(&digest[idx1 * 8..idx1 * 8 + 8]);
        digest[idx1 * 8..idx1 * 8 + 8].copy_from_slice(&tmp);

        let mut round = [0u8; 64];
        round.copy_from_slice(&digest);
        cipher.crypt20(&mut round);
        digest.copy_from_slice(&round);
    }

    digest
}

/// Derive the ZeroTier address of a public key set.
///
/// The address is the last five bytes of the memory-hard digest.
pub fn address_from_public_key(public_key_set: &[u8]) -> [u8; 5] {
    let digest = memory_hard_hash(public_key_set);
    let mut address = [0u8; 5];
    address.copy_from_slice(&digest[59..64]);
    address
}

/// Whether a public key set satisfies the hashcash condition.
pub fn satisfies_hashcash(public_key_set: &[u8]) -> bool {
    memory_hard_hash(public_key_set)[0] < HASHCASH_FIRST_BYTE_LESS_THAN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_deterministic() {
        let key = [7u8; 64];
        assert_eq!(memory_hard_hash(&key), memory_hard_hash(&key));
    }

    #[test]
    fn the_hash_differs_for_different_keys() {
        assert_ne!(memory_hard_hash(&[7u8; 64]), memory_hard_hash(&[8u8; 64]));
    }

    #[test]
    fn the_address_is_five_bytes() {
        let address = address_from_public_key(&[7u8; 64]);
        assert_eq!(address.len(), 5);
    }
}
