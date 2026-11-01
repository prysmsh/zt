//! Golden-vector tests for the legacy ZeroTier cipher suite.
//!
//! These vectors come from ZeroTier's own `Salsa20` and `Poly1305`
//! implementations, via the oracle in `oracle/zt_oracle.cpp`.

use std::path::Path;

use serde_json::Value;
use zt_legacy::salsa20::{Poly1305, Salsa20};

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf()
}

fn load_vector(relative: &str) -> Value {
    let path = repo_root().join("vectors/legacy").join(relative);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&contents).unwrap_or_else(|error| panic!("invalid JSON: {error}"))
}

fn input<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector["inputs"]
        .as_array()
        .expect("inputs array")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("missing input {name}"))["value"]
        .as_str()
        .expect("string value")
}

fn output<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector["outputs"]
        .as_array()
        .expect("outputs array")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("missing output {name}"))["value"]
        .as_str()
        .expect("string value")
}

fn decode(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value).expect("valid hex")
}

/// The Salsa20 keystream must match ZeroTier byte for byte.
///
/// This pins ZeroTier's permuted state layout, which differs from the
/// conventional Salsa20 arrangement.
#[test]
fn salsa20_keystream_matches_the_oracle() {
    let document = load_vector("cipher_vectors.json");
    let vectors = document["vectors"].as_array().expect("vectors");

    let mut checked = 0;
    for vector in vectors {
        if vector["op"] != "cipher.salsa20" {
            continue;
        }
        let key_bytes = decode(input(vector, "key"));
        let iv_bytes = decode(input(vector, "iv"));
        let expected = decode(output(vector, "keystream"));

        let key: [u8; 32] = key_bytes[..].try_into().expect("32-byte key");
        let iv: [u8; 8] = iv_bytes[..].try_into().expect("8-byte iv");

        // ZeroTier generates the keystream by encrypting zeroes.
        let mut actual = vec![0u8; expected.len()];
        Salsa20::new(key, iv).crypt12(&mut actual);

        assert_eq!(
            actual, expected,
            "Salsa20/12 keystream must match ZeroTier byte for byte"
        );
        checked += 1;
    }
    assert!(checked > 0, "expected at least one Salsa20 vector");
}

/// The Poly1305 MAC must match ZeroTier byte for byte.
#[test]
fn poly1305_matches_the_oracle() {
    let document = load_vector("cipher_vectors.json");
    let vectors = document["vectors"].as_array().expect("vectors");

    let mut checked = 0;
    for vector in vectors {
        if vector["op"] != "cipher.poly1305" {
            continue;
        }
        let key_bytes = decode(input(vector, "key"));
        let message = decode(input(vector, "message"));
        let expected = decode(output(vector, "mac"));

        let key: [u8; 32] = key_bytes[..].try_into().expect("32-byte key");
        let actual = Poly1305::compute(&key, &message);

        assert_eq!(
            actual.to_vec(),
            expected,
            "Poly1305 MAC must match ZeroTier byte for byte"
        );
        checked += 1;
    }
    assert!(checked > 0, "expected at least one Poly1305 vector");
}

/// The Poly1305 implementation must also match the RFC 7539 reference
/// vector, which is the canonical test for the construction.
#[test]
fn poly1305_matches_the_rfc7539_reference() {
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";
    let expected = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];
    assert_eq!(Poly1305::compute(&key, message), expected);
}
