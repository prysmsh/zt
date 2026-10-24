//! Regression guard: the committed golden vectors must still match.
//!
//! This test is the "did we accidentally change the wire format?" detector.
//! If any crypto output changes, the committed vector files no longer match
//! and this test fails.
//!
//! In Track B this same mechanism is reused in the opposite direction: the
//! `legacy` vector files are produced by the ZeroTier C++ oracle and must
//! match our Rust implementation byte-for-byte.

use std::path::PathBuf;

use zt_crypto::{
    credential::ControllerIdentity,
    identity::Identity,
    key_agreement::{public_from_secret, StaticKeyPair},
    symmetric::{derive_session_keys, hkdf_sha256, seal, NonceValue, SymmetricKey},
};
use zt_testvectors::{load, Track, VectorFile};

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(Track::Next.dir_name())
}

/// Load a committed vector file, skipping if it is absent.
///
/// A missing file means the vectors have not been generated yet; the
/// `gen_vectors` binary creates them.
fn load_optional(op: &str) -> Option<VectorFile> {
    let path = vectors_root().join(format!("{op}.json"));
    if !path.exists() {
        eprintln!("skipping: {} not generated", path.display());
        return None;
    }
    Some(load(&path).expect("vector file is valid"))
}

#[test]
fn identity_address_vectors_match() {
    let Some(file) = load_optional("identity_address") else {
        return;
    };
    for v in &file.vectors {
        let net = u64::from_be_bytes(v.input("network_id").unwrap().try_into().unwrap());
        let pk: [u8; 32] = v.input("public_key").unwrap().try_into().unwrap();
        let expected = v.output("address").unwrap();

        // Re-derive using the public key directly.
        let derived = zt_crypto::identity::Address::derive(net, &pk);
        assert_eq!(
            derived.as_bytes(),
            &expected[..],
            "address derivation changed"
        );
    }
}

#[test]
fn signature_vectors_match() {
    let Some(file) = load_optional("identity_sign") else {
        return;
    };
    for v in &file.vectors {
        let pk: [u8; 32] = v.input("public_key").unwrap().try_into().unwrap();
        let msg = v.input("message").unwrap();
        let expected = v.output("signature").unwrap();

        // The seed is not stored in the vector, so verify the signature
        // rather than re-signing.
        Identity::verify(&pk, &msg, &expected.try_into().unwrap())
            .expect("committed signature must verify");
    }
}

#[test]
fn key_agreement_vectors_match() {
    let Some(file) = load_optional("ecc_agree") else {
        return;
    };
    for v in &file.vectors {
        if v.op != "ecc.agree" {
            continue;
        }
        let secret_a: [u8; 32] = v.input("secret_a").unwrap().try_into().unwrap();
        let secret_b: [u8; 32] = v.input("secret_b").unwrap().try_into().unwrap();
        let public_a: [u8; 32] = v.input("public_a").unwrap().try_into().unwrap();
        let public_b: [u8; 32] = v.input("public_b").unwrap().try_into().unwrap();
        let expected = v.output("shared_secret").unwrap();

        let a = StaticKeyPair::from_secret_bytes(&secret_a).unwrap();
        let b = StaticKeyPair::from_secret_bytes(&secret_b).unwrap();
        assert_eq!(a.public_key_bytes(), public_a);
        assert_eq!(b.public_key_bytes(), public_b);

        let shared = a.agree(&public_b).unwrap();
        assert_eq!(shared, &expected[..], "X25519 output changed");

        // Agreement must be symmetric.
        assert_eq!(b.agree(&public_a).unwrap(), shared);
    }
}

#[test]
fn kdf_vectors_match() {
    let Some(file) = load_optional("kdf_hkdf") else {
        return;
    };
    for v in &file.vectors {
        if v.op != "kdf.hkdf" {
            continue;
        }
        let ikm = v.input("ikm").unwrap();
        let salt = v.input("salt").unwrap();
        let info = v.input("info").unwrap();
        let expected = v.output("okm_64").unwrap();

        let mut out = [0u8; 64];
        hkdf_sha256(&ikm, &salt, &info, &mut out).unwrap();
        assert_eq!(&out[..], &expected[..], "HKDF output changed");
    }
}

#[test]
fn session_key_vectors_match() {
    let Some(file) = load_optional("kdf_hkdf") else {
        return;
    };
    for v in &file.vectors {
        if v.op != "kdf.session" {
            continue;
        }
        let shared = v.input("shared_secret").unwrap();
        let context = v.input("context").unwrap();
        let (k1, k2) = derive_session_keys(&shared, &context).unwrap();
        assert_eq!(k1.as_bytes(), &v.output("key_1").unwrap()[..]);
        assert_eq!(k2.as_bytes(), &v.output("key_2").unwrap()[..]);
    }
}

#[test]
fn aead_vectors_match() {
    let Some(file) = load_optional("aead_chacha20poly1305") else {
        return;
    };
    for v in &file.vectors {
        let key: [u8; 32] = v.input("key").unwrap().try_into().unwrap();
        let nonce: [u8; 12] = v.input("nonce").unwrap().try_into().unwrap();
        let aad = v.input("aad").unwrap();
        let plaintext = v.input("plaintext").unwrap();
        let expected_ct = v.output("ciphertext").unwrap();
        let expected_tag: [u8; 16] = v.output("tag").unwrap().try_into().unwrap();

        let (ct, tag) = seal(
            &SymmetricKey::from_bytes(&key),
            &NonceValue::from_bytes(&nonce),
            &plaintext,
            &aad,
        )
        .unwrap();

        assert_eq!(ct, expected_ct, "AEAD ciphertext changed");
        assert_eq!(&tag[..], &expected_tag[..], "AEAD tag changed");
    }
}

#[test]
fn credential_vectors_match() {
    let Some(file) = load_optional("credential_issue") else {
        return;
    };
    for v in &file.vectors {
        let ctrl_pk: [u8; 32] = v
            .input("controller_public_key")
            .unwrap()
            .try_into()
            .unwrap();
        let bytes = v.output("credential").unwrap();

        let cred = zt_crypto::NodeCredential::deserialize(&bytes, &ctrl_pk)
            .expect("committed credential must verify");

        let network_id = u64::from_be_bytes(v.input("network_id").unwrap().try_into().unwrap());
        assert_eq!(cred.network_id(), network_id);

        // The controller ID embedded in the credential must match the
        // independently derived one.
        let derived = zt_crypto::address::derive_id(&ctrl_pk);
        assert_eq!(cred.controller_id(), &derived[..]);
        assert_eq!(
            cred.controller_id(),
            &v.output("controller_id_derived").unwrap()[..]
        );
    }
}

#[test]
fn public_key_derivation_vector_matches() {
    let Some(file) = load_optional("ecc_agree") else {
        return;
    };
    for v in &file.vectors {
        if v.op != "ecc.public" {
            continue;
        }
        let secret: [u8; 32] = v.input("secret").unwrap().try_into().unwrap();
        let expected = v.output("public").unwrap();
        assert_eq!(&public_from_secret(&secret)[..], &expected[..]);
    }
}

#[test]
fn controller_issue_is_reproducible() {
    let Some(file) = load_optional("credential_issue") else {
        return;
    };
    for v in &file.vectors {
        let ctrl_pk: [u8; 32] = v
            .input("controller_public_key")
            .unwrap()
            .try_into()
            .unwrap();
        let ctrl_id: [u8; 16] = v.input("controller_id").unwrap().try_into().unwrap();
        let node_pk: [u8; 32] = v.input("node_public_key").unwrap().try_into().unwrap();
        let node_addr: [u8; 10] = v.input("node_address").unwrap().try_into().unwrap();
        let issued_at = u64::from_be_bytes(v.input("issued_at").unwrap().try_into().unwrap());
        let ttl = u32::from_be_bytes(v.input("ttl_secs").unwrap().try_into().unwrap());
        let nonce: [u8; 16] = v.input("nonce").unwrap().try_into().unwrap();
        let network_id = u64::from_be_bytes(v.input("network_id").unwrap().try_into().unwrap());

        // Re-issue using a controller reconstructed from a fresh identity is
        // not possible (the seed is not stored), so instead verify the
        // credential's embedded fields match the vector inputs.
        let cred =
            zt_crypto::NodeCredential::deserialize(&v.output("credential").unwrap(), &ctrl_pk)
                .unwrap();

        assert_eq!(cred.network_id(), network_id);
        assert_eq!(cred.node_address().as_bytes(), &node_addr[..]);
        assert_eq!(cred.public_key(), &node_pk);
        assert_eq!(cred.issued_at(), issued_at);
        assert_eq!(cred.ttl_secs(), ttl);
        assert_eq!(cred.nonce(), &nonce);
        assert_eq!(cred.controller_id(), &ctrl_id[..]);
        assert_eq!(cred.not_after(), issued_at + ttl as u64);
    }
}

/// Sanity check that the controller id derivation helper agrees with the
/// value embedded in an issued credential.
#[test]
fn controller_identity_is_self_consistent() {
    let ctrl = ControllerIdentity::new(Identity::generate().unwrap());
    let expected = zt_crypto::address::derive_id(&ctrl.public_key());
    assert_eq!(ctrl.controller_id(), &expected[..]);
}
