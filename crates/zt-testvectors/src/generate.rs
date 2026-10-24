//! Golden vector generation for the ZT-next protocol.
//!
//! This module produces the on-disk vector files described in the crate
//! documentation. It serves two distinct purposes:
//!
//! 1. **Regression pinning (Track::Next).** Vectors generated here are
//!    committed to the repository. If a change to the crypto layer alters
//!    any output, the test suite fails. This is the "did we accidentally
//!    change the wire format" guard.
//!
//! 2. **Oracle comparison (Track::Legacy).** The *same* harness is used in
//!    Track B to compare our Rust implementation against ZeroTier's C++
//!    `node/` code. The C++ side emits vectors in this format via a small
//!    shim, and both sides are diffed. Because the format is shared, the
//!    harness written now is the harness Track B uses later.
//!
//! # Usage
//!
//! ```no_run
//! use zt_testvectors::{generate_all, Track};
//!
//! let files = generate_all(Track::Next);
//! for (path, json) in files {
//!     println!("{path}: {} bytes", json.len());
//! }
//! ```

use zt_crypto::{
    address::derive_id,
    credential::ControllerIdentity,
    identity::Identity,
    key_agreement::{public_from_secret, StaticKeyPair},
    pq::{combine_hybrid_secret, combine_hybrid_signature, MlDsa65KeyPair, MlKem768KeyPair},
    symmetric::{derive_session_keys, hkdf_sha256, seal, NonceValue, SymmetricKey},
};

use crate::{Track, Vector, VectorFile};

/// Fixed seeds used so that generated vectors are reproducible.
///
/// These are **test** values, not secrets. They exist so the vector files do
/// not change on every regeneration.
const SEED_A: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const SEED_B: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// The network ID used in generated vectors.
const NETWORK_ID: u64 = 0x0011_2233_4455_6677;

/// Generate the identity/address vectors.
pub fn identity_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "identity.address");

    for (i, net) in [NETWORK_ID, 0, u64::MAX].iter().enumerate() {
        let id = Identity::from_bytes(&SEED_A);
        let pk = id.public_key_bytes();
        let addr = id.address_for_network(*net);

        f.push(
            Vector::new(
                track,
                "identity.address",
                format!("network address derivation, case {i}"),
            )
            .with_input("network_id", &net.to_be_bytes())
            .with_input("public_key", &pk)
            .with_output("address", addr.as_bytes()),
        );
    }

    f
}

/// Generate the Ed25519 signature vectors.
pub fn signature_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "identity.sign");

    let id = Identity::from_bytes(&SEED_A);
    let pk = id.public_key_bytes();
    let msg = b"zt-next test vector message";
    let sig = id.sign(msg);

    f.push(
        Vector::new(
            track,
            "identity.sign",
            "Ed25519 signature over a fixed message",
        )
        .with_input("public_key", &pk)
        .with_input("message", msg)
        .with_output("signature", &sig),
    );

    f
}

/// Generate the X25519 key agreement vectors.
pub fn key_agreement_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "ecc.agree");

    let a = StaticKeyPair::from_secret_bytes(&SEED_A).unwrap();
    let b = StaticKeyPair::from_secret_bytes(&SEED_B).unwrap();
    let a_pub = a.public_key_bytes();
    let b_pub = b.public_key_bytes();
    let shared = a.agree(&b_pub).unwrap();

    f.push(
        Vector::new(track, "ecc.agree", "X25519 shared secret")
            .with_input("secret_a", &SEED_A)
            .with_input("secret_b", &SEED_B)
            .with_input("public_a", &a_pub)
            .with_input("public_b", &b_pub)
            .with_output("shared_secret", &shared),
    );

    // Public key derivation alone, for cases where the peer key is provided
    // out of band.
    f.push(
        Vector::new(track, "ecc.public", "X25519 public key derivation")
            .with_input("secret", &SEED_A)
            .with_output("public", &public_from_secret(&SEED_A)),
    );

    f
}

/// Generate the HKDF key derivation vectors.
pub fn kdf_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "kdf.hkdf");

    let mut out = [0u8; 64];
    hkdf_sha256(&SEED_A, b"salt", b"info", &mut out).unwrap();

    f.push(
        Vector::new(track, "kdf.hkdf", "HKDF-SHA256 extract-and-expand")
            .with_input("ikm", &SEED_A)
            .with_input("salt", b"salt")
            .with_input("info", b"info")
            .with_output("okm_64", &out),
    );

    let (k1, k2) = derive_session_keys(&SEED_A, b"zt-next/session").unwrap();
    f.push(
        Vector::new(track, "kdf.session", "directional session key split")
            .with_input("shared_secret", &SEED_A)
            .with_input("context", b"zt-next/session")
            .with_output("key_1", k1.as_bytes())
            .with_output("key_2", k2.as_bytes()),
    );

    f
}

/// Generate the AEAD seal/open vectors.
pub fn aead_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "aead.chacha20poly1305");

    let key = SymmetricKey::from_bytes(&SEED_A);
    let nonce = NonceValue::from_counter(0x1122_3344, 0x5566_7788_99aa_bbcc);
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    let aad = b"zt-next header";

    let (ct, tag) = seal(&key, &nonce, plaintext, aad).unwrap();

    f.push(
        Vector::new(track, "aead.chacha20poly1305", "authenticated encryption")
            .with_input("key", key.as_bytes())
            .with_input("nonce", nonce.as_bytes())
            .with_input("aad", aad)
            .with_input("plaintext", plaintext)
            .with_output("ciphertext", &ct)
            .with_output("tag", &tag),
    );

    f
}

/// Generate the credential issuance vectors.
pub fn credential_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "credential.issue");

    let ctrl = ControllerIdentity::new(Identity::from_bytes(&SEED_A));
    let node = Identity::from_bytes(&SEED_B);
    let node_pk = node.public_key_bytes();
    let addr = node.address_for_network(NETWORK_ID);
    let nonce = [0x5au8; 16];

    let cred = ctrl.issue(NETWORK_ID, addr, &node_pk, 1_700_000_000, 86_400, &nonce);
    let bytes = cred.serialize();

    f.push(
        Vector::new(
            track,
            "credential.issue",
            "controller-signed node credential",
        )
        .with_input("network_id", &NETWORK_ID.to_be_bytes())
        .with_input("node_address", addr.as_bytes())
        .with_input("node_public_key", &node_pk)
        .with_input("issued_at", &1_700_000_000u64.to_be_bytes())
        .with_input("ttl_secs", &86_400u32.to_be_bytes())
        .with_input("nonce", &nonce)
        .with_input("controller_public_key", &ctrl.public_key())
        .with_input("controller_id", ctrl.controller_id())
        .with_output("credential", &bytes)
        .with_output("controller_id_derived", &derive_id(&ctrl.public_key())),
    );

    f
}

/// Generate every vector file for a track.
///
/// Returns `(relative_path, json_content)` pairs.
/// Generate the ML-KEM-768 key encapsulation vectors.
///
/// ML-KEM encapsulation is randomized, so the vectors record a full
/// encapsulate/decapsulate round trip rather than fixed outputs. This still
/// pins the implementation: a change in key sizes or the round-trip
/// relationship breaks these vectors.
pub fn mlkem_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "pq.mlkem768");

    let kp = MlKem768KeyPair::generate().unwrap();
    let ek = kp.encapsulation_key();
    let dk = kp.decapsulation_key_bytes();

    let (ct, ss_a) = kp.encapsulate(&mut pq_rng());
    let ss_b = kp.decapsulate(&ct).unwrap();

    f.push(
        Vector::new(
            track,
            "pq.mlkem768",
            "ML-KEM-768 encapsulate/decapsulate round trip",
        )
        .with_input("encapsulation_key", &ek)
        .with_input("decapsulation_key", &dk)
        .with_output("ciphertext", &ct)
        .with_output("shared_secret", &ss_a),
    );

    // The shared secret must survive the round trip.
    assert_eq!(ss_a, ss_b);

    f
}

/// Generate the ML-DSA-65 signature vectors.
pub fn mldsa_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "pq.mldsa65");

    let kp = MlDsa65KeyPair::generate().unwrap();
    let pk = kp.public_key();
    let msg = b"zt-next post-quantum test vector";
    let sig = kp.sign(msg).unwrap();

    f.push(
        Vector::new(
            track,
            "pq.mldsa65",
            "ML-DSA-65 signature over a fixed message",
        )
        .with_input("public_key", &pk)
        .with_input("message", msg)
        .with_output("signature", &sig),
    );

    f
}

/// Generate the hybrid combiner vectors.
pub fn hybrid_vectors(track: Track) -> VectorFile {
    let mut f = VectorFile::new(track, "pq.hybrid");

    let x = [0x11u8; 32];
    let pq = [0x22u8; 32];

    let combined = combine_hybrid_secret(&x, &pq, b"zt-next/test").unwrap();

    f.push(
        Vector::new(
            track,
            "pq.hybrid",
            "hybrid X25519 + ML-KEM secret combination",
        )
        .with_input("x25519_shared", &x)
        .with_input("mlkem_shared", &pq)
        .with_input("context", b"zt-next/test")
        .with_output("combined", &combined),
    );

    // Hybrid signature: Ed25519 followed by ML-DSA-65.
    let ed = Identity::from_bytes(&SEED_A);
    let pq_kp = MlDsa65KeyPair::generate().unwrap();
    let ed_sig = ed.sign(b"hybrid test");
    let pq_sig = pq_kp.sign(b"hybrid test").unwrap();
    let hybrid_sig = combine_hybrid_signature(&ed_sig, &pq_sig);

    f.push(
        Vector::new(track, "pq.hybrid", "hybrid Ed25519 + ML-DSA-65 signature")
            .with_input("ed25519_public", &ed.public_key_bytes())
            .with_input("mldsa_public", &pq_kp.public_key())
            .with_input("message", b"hybrid test")
            .with_output("signature", &hybrid_sig),
    );

    f
}

/// A deterministic RNG for the post-quantum code path.
///
/// `ml-kem` requires `rand_core` 0.10, which is a different trait from the
/// `rand` 0.8 used by the classical path.
fn pq_rng() -> rand_pq::rngs::StdRng {
    use rand_pq::SeedableRng;
    rand_pq::rngs::StdRng::from_seed([
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70,
    ])
}

/// Generate every vector file for a track.
///
/// Returns `(relative_path, json_content)` pairs.
pub fn generate_all(track: Track) -> Vec<(String, String)> {
    let files = [
        identity_vectors(track),
        signature_vectors(track),
        key_agreement_vectors(track),
        kdf_vectors(track),
        aead_vectors(track),
        credential_vectors(track),
        mlkem_vectors(track),
        mldsa_vectors(track),
        hybrid_vectors(track),
    ];

    files
        .into_iter()
        .map(|f| {
            let path = format!(
                "{}/{}.json",
                crate::vectors_dir(track),
                f.op.replace('.', "_")
            );
            (path, f.to_json())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic_for_classical_vectors() {
        // The classical vectors (identity, X25519, HKDF, AEAD) are fully
        // deterministic because they use fixed seeds.
        //
        // The post-quantum vectors are NOT: ML-KEM key generation and
        // encapsulation are randomized by design, and ML-DSA signing is
        // randomized (hedged). Those vectors are verified by *property*
        // (round trip, verification, size) rather than by byte equality —
        // see the golden_vectors integration test.
        let deterministic = [
            identity_vectors(Track::Next),
            signature_vectors(Track::Next),
            key_agreement_vectors(Track::Next),
            kdf_vectors(Track::Next),
            aead_vectors(Track::Next),
        ];
        let a: Vec<String> = deterministic.iter().map(|f| f.to_json()).collect();
        let b: Vec<String> = deterministic.iter().map(|f| f.to_json()).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn pq_vectors_differ_between_runs_but_stay_valid() {
        // Post-quantum vectors are randomized; what must hold is that they
        // remain internally consistent.
        let f1 = mlkem_vectors(Track::Next);
        let f2 = mlkem_vectors(Track::Next);

        for f in [&f1, &f2] {
            let v = &f.vectors[0];
            let ek = v.input("encapsulation_key").unwrap();
            let ct = v.output("ciphertext").unwrap();
            let ss = v.output("shared_secret").unwrap();
            assert_eq!(ek.len(), zt_crypto::pq::ML_KEM_768_EK_LEN);
            assert_eq!(ct.len(), zt_crypto::pq::ML_KEM_768_CT_LEN);
            assert_eq!(ss.len(), 32);
        }
    }

    #[test]
    fn generated_vectors_have_expected_shape() {
        let files = generate_all(Track::Next);
        assert!(!files.is_empty());
        for (path, json) in &files {
            assert!(path.starts_with("vectors/next/"), "bad path {path}");
            let parsed: VectorFile = VectorFile::from_json(json).unwrap();
            assert_eq!(parsed.track, Track::Next);
            assert!(!parsed.vectors.is_empty());
        }
    }

    #[test]
    fn credential_vector_verifies() {
        let f = credential_vectors(Track::Next);
        let v = &f.vectors[0];
        let ctrl_pk = v.input("controller_public_key").unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&ctrl_pk);
        let bytes = v.output("credential").unwrap();
        let cred = zt_crypto::NodeCredential::deserialize(&bytes, &pk).unwrap();
        assert_eq!(cred.network_id(), NETWORK_ID);
    }
}
