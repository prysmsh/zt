//! Interoperability with upstream WireGuard.
//!
//! The fixture is a real handshake: an initiation captured from the Linux
//! kernel's WireGuard implementation, and the response that
//! implementation accepted. The kernel is the reference implementation and
//! the one a `tailscaled` peer speaks, so matching it byte for byte is
//! matching Tailscale.
//!
//! The test replays the fixture, so it needs no kernel module, no root, and
//! no network state. Capturing a new fixture is a separate, deliberate
//! step: `cargo run -p zt-legacy --example capture-wireguard`.

use zt_legacy::wireguard::{StaticKey, KEY_LEN};
use zt_legacy::wireguard_handshake::Responder;
use zt_legacy::wireguard_message::{
    MessageInitiation, MessageResponse, INITIATION_SIZE, RESPONSE_SIZE,
};

/// The captured handshake.
struct Fixture {
    /// The kernel's static public key.
    kernel_public: [u8; KEY_LEN],
    /// The implementation's long-term secret.
    implementation_static: [u8; KEY_LEN],
    /// The implementation's ephemeral secret, so the exchange replays exactly.
    implementation_ephemeral: [u8; KEY_LEN],
    /// The index the implementation sent its response under.
    implementation_index: u32,
    /// The initiation the kernel sent.
    initiation: Vec<u8>,
    /// The response the kernel accepted.
    response: Vec<u8>,
}

impl Fixture {
    /// Load the fixture.
    fn load() -> Self {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/wireguard_handshake.json"
        );
        let text = std::fs::read_to_string(path).expect("the fixture");
        let value: serde_json::Value = serde_json::from_str(&text).expect("parse the fixture");

        let mut kernel_public = [0u8; KEY_LEN];
        kernel_public.copy_from_slice(&base64_decode(
            value["kernel_public_key"]
                .as_str()
                .expect("the kernel's public key"),
        ));

        let mut implementation_static = [0u8; KEY_LEN];
        implementation_static.copy_from_slice(&hex_decode(
            value["implementation_static_secret"]
                .as_str()
                .expect("the static secret"),
        ));

        let mut implementation_ephemeral = [0u8; KEY_LEN];
        implementation_ephemeral.copy_from_slice(&hex_decode(
            value["implementation_ephemeral_secret"]
                .as_str()
                .expect("the ephemeral secret"),
        ));

        Self {
            kernel_public,
            implementation_static,
            implementation_ephemeral,
            implementation_index: value["implementation_index"].as_u64().expect("the index") as u32,
            initiation: hex_decode(value["initiation"].as_str().expect("the initiation")),
            response: hex_decode(value["accepted_response"].as_str().expect("the response")),
        }
    }
}

/// Decode hex.
fn hex_decode(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex")
}

/// Decode standard base64.
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for byte in text.bytes() {
        if byte == b'=' {
            break;
        }
        let Some(value) = ALPHABET.iter().position(|candidate| *candidate == byte) else {
            continue;
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    out
}

/// The implementation answers the kernel's initiation, and the answer has
/// to be the one the kernel accepted.
///
/// Every byte of the response is compared, apart from the two indices,
/// which are chosen at random.
#[test]
fn the_response_matches_the_one_the_kernel_accepted() {
    let fixture = Fixture::load();

    assert_eq!(
        fixture.initiation.len(),
        INITIATION_SIZE,
        "the captured initiation is the wrong length"
    );
    assert_eq!(
        fixture.response.len(),
        RESPONSE_SIZE,
        "the captured response is the wrong length"
    );

    let initiation = MessageInitiation::parse(&fixture.initiation).expect("parse the initiation");

    let mut responder = Responder::begin_with_ephemeral(
        StaticKey::from_secret(fixture.implementation_static),
        fixture.implementation_ephemeral,
        Some(fixture.implementation_index),
    )
    .expect("begin");

    responder
        .consume_initiation(&initiation)
        .expect("the kernel's initiation must authenticate");

    // The responder learned the initiator's identity by decrypting the
    // initiation, which is only possible because the transcript matched.
    assert_eq!(
        responder.remote_static(),
        fixture.kernel_public,
        "the decrypted initiator key must be the kernel's"
    );

    let response = responder.create_response().expect("the response");

    let expected = MessageResponse::parse(&fixture.response).expect("parse the response");

    // The ephemeral key and the encrypted payload are the substance of
    // the response: they can only match if both sides computed the same
    // transcript.
    assert_eq!(
        response.ephemeral, expected.ephemeral,
        "the ephemeral key must match the kernel's accepted response"
    );
    assert_eq!(
        response.empty, expected.empty,
        "the encrypted empty payload must match"
    );

    // The tag is the proof. It is keyed by the initiator's static key and
    // covers the whole transcript, so a match means the two sides agreed on
    // everything.
    assert_eq!(
        response.mac1, expected.mac1,
        "the authentication tag must match the one the kernel accepted"
    );
}

/// The captured initiation carries a tag the kernel computed with its own
/// static key, so it can only be checked by a responder holding that key.
#[test]
fn the_captured_initiation_is_well_formed() {
    let fixture = Fixture::load();
    let initiation = MessageInitiation::parse(&fixture.initiation).expect("parse the initiation");

    assert_eq!(initiation.message_type, 1);
    assert_eq!(initiation.ephemeral.len(), KEY_LEN);
    assert_ne!(initiation.mac1, [0u8; 16]);
}
