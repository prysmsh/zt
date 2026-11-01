//! Golden-vector tests for the legacy ZeroTier membership credentials.
//!
//! These vectors come from ZeroTier's own `CertificateOfMembership` and
//! `CertificateOfOwnership` implementations, via the oracle.

use std::path::Path;

use serde_json::Value;
use zt_legacy::credential::{CertificateOfMembership, CertificateOfOwnership};
use zt_legacy::zerotier::{LegacyAddress, LegacyIdentity, KEY_SET_LEN};

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

/// A COM built by our code must serialize byte-for-byte like ZeroTier's.
#[test]
fn certificate_of_membership_matches_the_oracle() {
    let document = load_vector("credential_vectors.json");
    let vectors = document["vectors"].as_array().expect("vectors");

    let mut checked = 0;
    for vector in vectors {
        if vector["op"] != "credential.com" {
            continue;
        }

        let member_bytes = decode(input(vector, "member_public_key"));
        let controller_bytes = decode(input(vector, "controller_public_key"));
        let expected = decode(output(vector, "serialized"));

        assert_eq!(member_bytes.len(), KEY_SET_LEN);
        assert_eq!(controller_bytes.len(), KEY_SET_LEN);

        // The timestamp and delta are little-endian in the vector inputs.
        let timestamp_bytes = decode(input(vector, "timestamp"));
        let delta_bytes = decode(input(vector, "timestamp_max_delta"));
        let network_bytes = decode(input(vector, "network_id"));

        let timestamp = u64::from_le_bytes(timestamp_bytes[..].try_into().unwrap());
        let delta = u64::from_le_bytes(delta_bytes[..].try_into().unwrap());
        let network_id = u64::from_le_bytes(network_bytes[..].try_into().unwrap());

        // Rebuild the member identity from its public key set. The COM
        // embeds a hash of the member's address and key set, so the address
        // must match the one ZeroTier derived.
        let member = LegacyIdentity::from_bytes(&member_bytes[..].try_into().unwrap());

        let com = CertificateOfMembership::issue(timestamp, delta, network_id, &member);
        let actual = com.serialize();

        // ZeroTier's COM is signed, so it carries a 5-byte signer address and
        // a 96-byte signature that our unsigned credential does not have.
        // The qualifier block is the first 3 + 7*24 = 171 bytes.
        const QUALIFIER_BLOCK: usize = 3 + 7 * 24;
        assert_eq!(
            actual.len() + 5 + 96,
            expected.len(),
            "COM length must match ZeroTier once signed"
        );

        // The qualifier block must be identical byte for byte.
        assert_eq!(
            &actual[..QUALIFIER_BLOCK],
            &expected[..QUALIFIER_BLOCK],
            "COM qualifiers must match ZeroTier byte for byte"
        );

        // The qualifier values must also match exactly.
        let parsed = CertificateOfMembership::deserialize(&expected).expect("parse");
        assert_eq!(parsed.qualifiers().len(), com.qualifiers().len());
        for (ours, theirs) in com.qualifiers().iter().zip(parsed.qualifiers()) {
            assert_eq!(ours.id, theirs.id);
            assert_eq!(ours.value, theirs.value);
            assert_eq!(ours.max_delta, theirs.max_delta);
        }

        // The signing bytes must match, which is what the signature covers.
        assert_eq!(
            com.signing_bytes(),
            parsed.signing_bytes(),
            "COM signing bytes must match"
        );

        checked += 1;
    }
    assert!(checked > 0, "expected at least one COM vector");
}

/// A COO built by our code must serialize byte-for-byte like ZeroTier's.
#[test]
fn certificate_of_ownership_matches_the_oracle() {
    let document = load_vector("credential_vectors.json");
    let vectors = document["vectors"].as_array().expect("vectors");

    let mut checked = 0;
    for vector in vectors {
        if vector["op"] != "credential.coo" {
            continue;
        }

        let expected = decode(output(vector, "serialized"));

        let network_bytes = decode(input(vector, "network_id"));
        let timestamp_bytes = decode(input(vector, "timestamp"));
        let flags_bytes = decode(input(vector, "flags"));

        let network_id = u64::from_le_bytes(network_bytes[..].try_into().unwrap());
        let timestamp = u64::from_le_bytes(timestamp_bytes[..].try_into().unwrap());
        let flags = u64::from_le_bytes(flags_bytes[..].try_into().unwrap());

        // Parse ZeroTier's COO to recover the exact claims it makes.
        let parsed = CertificateOfOwnership::deserialize(&expected).expect("parse");

        let coo = CertificateOfOwnership::new(
            network_id,
            timestamp,
            flags,
            parsed.id(),
            parsed.things().to_vec(),
            parsed.issued_to(),
            parsed.signed_by(),
        );

        assert_eq!(
            coo.network_id(),
            parsed.network_id(),
            "COO network ID must match"
        );
        assert_eq!(coo.id(), parsed.id(), "COO node address must match");
        assert_eq!(
            coo.things().len(),
            parsed.things().len(),
            "COO thing count must match"
        );

        // The serialized form is identical because the signature is absent
        // on both sides: ZeroTier's vector is unsigned.
        assert_eq!(
            coo.serialize(),
            expected,
            "COO must serialize byte for byte like ZeroTier"
        );

        checked += 1;
    }
    assert!(checked > 0, "expected at least one COO vector");
}

/// The identity hash embedded in a COM must match ZeroTier's SHA-384 hash
/// of the address and public key set.
#[test]
fn identity_hash_matches_the_oracle() {
    let document = load_vector("credential_vectors.json");
    let vectors = document["vectors"].as_array().expect("vectors");

    for vector in vectors {
        if vector["op"] != "credential.com" {
            continue;
        }
        let member_bytes = decode(input(vector, "member_public_key"));
        let member = LegacyIdentity::from_bytes(&member_bytes[..].try_into().unwrap());
        let _ = &member;

        // Rebuild the COM and check that the identity hash qualifiers
        // reproduce what ZeroTier stored.
        let expected = CertificateOfMembership::deserialize(&decode(output(vector, "serialized")))
            .expect("parse");

        let timestamp = expected.qualifier(0).expect("timestamp qualifier").value;
        let network_id = expected.qualifier(1).expect("network id qualifier").value;
        let delta = expected
            .qualifier(0)
            .expect("timestamp qualifier")
            .max_delta;

        let ours = CertificateOfMembership::issue(timestamp, delta, network_id, &member);
        for (index, qualifier) in ours.qualifiers().iter().enumerate() {
            let theirs = expected.qualifiers()[index];
            assert_eq!(qualifier.id, theirs.id, "qualifier {index} id");
            assert_eq!(qualifier.value, theirs.value, "qualifier {index} value");
        }
    }
}

/// A signed COM must verify against the controller's public key.
#[test]
fn signed_com_verifies() {
    let identity = LegacyIdentity::from_bytes(&[5u8; KEY_SET_LEN]);
    let controller = LegacyIdentity::from_bytes(&[9u8; KEY_SET_LEN]);

    let mut com = CertificateOfMembership::issue(1_700_000_000, 60, 42, &identity);
    com.sign(&controller);

    assert!(com.is_signed());
    assert!(com.verify(&controller.ed25519_public()));
    assert!(!com.verify(&identity.ed25519_public()));
}

/// A COM signed by one controller must not verify against another.
#[test]
fn com_rejects_a_different_controller() {
    let identity = LegacyIdentity::from_bytes(&[5u8; KEY_SET_LEN]);
    let controller = LegacyIdentity::from_bytes(&[9u8; KEY_SET_LEN]);
    let impostor = LegacyIdentity::from_bytes(&[11u8; KEY_SET_LEN]);

    let mut com = CertificateOfMembership::issue(1_700_000_000, 60, 42, &identity);
    com.sign(&controller);

    assert!(!com.verify(&impostor.ed25519_public()));
}

/// The COM's issued-to address must be the member's own address.
#[test]
fn com_issued_to_matches_the_member_address() {
    let identity = LegacyIdentity::from_bytes(&[3u8; KEY_SET_LEN]);
    let com = CertificateOfMembership::issue(1_700_000_000, 60, 42, &identity);

    let qualifier = com.qualifier(2).expect("issued-to qualifier");
    let expected = zt_legacy::credential::address_to_u64(&identity.address());
    assert_eq!(qualifier.value, expected);
}

/// The issued-to address must be recoverable from the qualifier.
#[test]
fn address_packing_round_trips() {
    let address = LegacyAddress::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let packed = zt_legacy::credential::address_to_u64(&address);

    // The address occupies the low five bytes, read big endian.
    let bytes = packed.to_be_bytes();
    assert_eq!(&bytes[3..], address.as_bytes());
    assert_eq!(packed, 0x0000_00aa_bbcc_ddee);
}
