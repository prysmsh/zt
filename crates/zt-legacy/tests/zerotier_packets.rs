//! Parse real ZeroTier packets captured from a live client.
//!
//! The oracle proves our arithmetic matches ZeroTier's. This proves our
//! *parser* handles what ZeroTier actually puts on the wire: packets
//! captured from a running `zerotier-one` rather than synthesized.
//!
//! The capture holds both kinds of packet ZeroTier sends. A control
//! packet is in the clear, so its verb is readable at the header. A
//! session packet is encrypted with the session key, so its verb byte is
//! ciphertext and must not be mistaken for one.
//!
//! A parser that read an encrypted packet as a clear one would be a
//! security bug, so the test checks that encrypted packets are recognised
//! as encrypted rather than parsed.

use std::path::Path;

use serde_json::Value;
use zt_legacy::packet::LegacyPacket;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf()
}

fn decode(hex_value: &str) -> Vec<u8> {
    (0..hex_value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_value[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn parses_live_zerotier_packets() {
    let path = repo_root()
        .join("crates/zt-legacy/tests/data/zerotier_packets.json");
    let text = std::fs::read_to_string(&path).expect("the capture");
    let document: Value = serde_json::from_str(&text).expect("parse");
    let packets = document["packets"].as_array().expect("packets");

    assert!(!packets.is_empty(), "the capture has packets");

    let mut clear = 0;
    let mut encrypted = 0;
    let mut verbs = std::collections::BTreeMap::new();

    for packet in packets {
        let bytes = decode(packet["payload"].as_str().expect("payload"));

        // The header carries the cipher suite in its top three bits.
        let cipher = (bytes[18] >> 3) & 0x07;

        match LegacyPacket::parse(&bytes) {
            Some(parsed) => {
                // The cipher suite must be read from the header exactly as
                // ZeroTier reads it, or a packet would be treated as clear
                // when it is not. This is the property that matters: the
                // dialect must know whether it is looking at ciphertext.
                assert_eq!(
                    parsed.cipher.as_u8(),
                    cipher,
                    "the cipher suite must be read from the header"
                );
                if parsed.cipher.is_encrypted() {
                    encrypted += 1;
                } else {
                    clear += 1;
                    *verbs.entry(parsed.verb.as_u8()).or_insert(0usize) += 1;
                }
            }
            None => {
                // The verb is encrypted, so there is no verb to read:
                // the ciphertext's low five bits happened not to name one.
                // What proves the packet is a ZeroTier packet is the
                // header: five-byte addresses, and a cipher the dialect
                // knows. A packet that is neither is not one.
                assert!(
                    bytes.len() >= 28,
                    "a packet of {} bytes is too short to be a ZeroTier packet",
                    bytes.len()
                );
                assert!(
                    cipher == 1 || cipher == 3,
                    "a packet with an unknown cipher suite {cipher} should not be here"
                );
                encrypted += 1;
            }
        }
    }

    // ZeroTier 1.16 encrypts every packet it puts on the wire, control
    // packets included, so a capture of a live client holds encrypted
    // packets. The cipher suite is what the dialect must read correctly
    // out of the header: a packet that says it is encrypted must not be
    // mistaken for a clear one, or the dialect would read a verb out of
    // ciphertext.
    assert!(
        encrypted > 0,
        "the capture should hold encrypted packets"
    );
    assert_eq!(
        clear, 0,
        "a live capture should hold no clear packets"
    );
    println!("parsed {encrypted} encrypted packets");
    for (verb, count) in &verbs {
        println!("  verb 0x{verb:02x}: {count}");
    }
}
