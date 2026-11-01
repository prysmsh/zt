//! The WireGuard handshake messages.
//!
//! WireGuard's handshake is two messages. The initiator sends an initiation,
//! which carries its ephemeral key, its static key encrypted to the
//! responder, and a timestamp. The responder answers with a response, which
//! carries its own ephemeral key.
//!
//! Both messages are authenticated by two MAC fields. The first is computed
//! with a key derived from the *peer's* static key, so it proves the sender
//! knows the responder's identity. The second is computed with a cookie
//! that the responder hands out under load; on a first handshake there is no
//! cookie, and the field is zero.
//!
//! Every field is at a fixed offset and the integers are little-endian, so
//! the byte layout has to match exactly.

use blake2::digest::consts::U16;
use blake2::digest::{FixedOutput, KeyInit, Update};

use crate::wireguard::{hash, hmac, initial_hash, mix_hash, KEY_LEN};

/// The size of a keyed BLAKE2s-128 tag.
pub const MAC_LEN: usize = 16;

/// The type of an initiation message.
pub const MESSAGE_INITIATION: u32 = 1;

/// The type of a response message.
pub const MESSAGE_RESPONSE: u32 = 2;

/// The type of a cookie reply.
pub const MESSAGE_COOKIE_REPLY: u32 = 3;

/// The type of a transport message.
pub const MESSAGE_TRANSPORT: u32 = 4;

/// The size of an initiation message.
pub const INITIATION_SIZE: usize = 148;

/// The size of a response message.
pub const RESPONSE_SIZE: usize = 92;

/// The size of a transport message header.
pub const TRANSPORT_HEADER_SIZE: usize = 16;

/// The TAI64N base offset.
///
/// TAI64N counts seconds from a different epoch than Unix, so the seconds
/// field carries an offset. Without it, a timestamp would be rejected as
/// being in the distant past.
const TAI64N_BASE: u64 = 0x4000_0000_0000_000a;

/// Keyed BLAKE2s-128, which is what WireGuard's MAC fields use.
type Blake2sMac128 = blake2::Blake2sMac<U16>;

/// Errors from the handshake messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// The message has the wrong length.
    WrongLength,
    /// The message has an unexpected type.
    WrongType,
    /// The message's MAC does not verify.
    BadMac,
    /// The message could not be decrypted.
    DecryptionFailed,
    /// The timestamp is not valid.
    BadTimestamp,
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength => write!(f, "the message has the wrong length"),
            Self::WrongType => write!(f, "the message has an unexpected type"),
            Self::BadMac => write!(f, "the message's MAC does not verify"),
            Self::DecryptionFailed => write!(f, "the message could not be decrypted"),
            Self::BadTimestamp => write!(f, "the timestamp is not valid"),
        }
    }
}

impl std::error::Error for MessageError {}

/// Compute a keyed BLAKE2s-128 tag.
fn mac128(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = Blake2sMac128::new_from_slice(key).expect("a key of any length is valid");
    mac.update(data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&mac.finalize_fixed());
    out
}

/// The key used to authenticate a message to a peer.
///
/// Both sides compute the same value: the initiator uses the responder's
/// static key, and the responder uses the initiator's.
pub fn mac1_key(peer_static: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(8 + KEY_LEN);
    buffer.extend_from_slice(crate::wireguard::WG_LABEL_MAC1);
    buffer.extend_from_slice(peer_static);
    hash(&buffer)
}

/// The current time, as a TAI64N timestamp.
///
/// The nanosecond field is truncated to 24 bits, which is what WireGuard
/// does. The remaining bits are a whitener, so a timestamp cannot be
/// predicted precisely enough to be forged.
pub fn timestamp_now() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    let seconds = TAI64N_BASE + (now / 1_000_000_000) as u64;
    let nanoseconds = ((now % 1_000_000_000) as u32) & !0x00ff_ffff;

    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&nanoseconds.to_be_bytes());
    out
}

/// An initiation message.
#[derive(Clone, Debug)]
pub struct MessageInitiation {
    /// Always [`MESSAGE_INITIATION`].
    pub message_type: u32,
    /// The sender's index, chosen at random.
    pub sender: u32,
    /// The initiator's ephemeral public key.
    pub ephemeral: [u8; KEY_LEN],
    /// The initiator's static key, encrypted, with its authentication tag.
    pub static_key: [u8; KEY_LEN + 16],
    /// The timestamp, encrypted, with its authentication tag.
    pub timestamp: [u8; 12 + 16],
    /// The first authentication tag.
    pub mac1: [u8; MAC_LEN],
    /// The second authentication tag. Zero on a first handshake.
    pub mac2: [u8; MAC_LEN],
}

impl MessageInitiation {
    /// Parse an initiation message.
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() != INITIATION_SIZE {
            return Err(MessageError::WrongLength);
        }

        let message_type = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
        if message_type != MESSAGE_INITIATION {
            return Err(MessageError::WrongType);
        }

        let mut ephemeral = [0u8; KEY_LEN];
        ephemeral.copy_from_slice(&bytes[8..40]);
        let mut static_key = [0u8; KEY_LEN + 16];
        static_key.copy_from_slice(&bytes[40..88]);
        let mut timestamp = [0u8; 12 + 16];
        timestamp.copy_from_slice(&bytes[88..116]);
        let mut mac1 = [0u8; MAC_LEN];
        mac1.copy_from_slice(&bytes[116..132]);
        let mut mac2 = [0u8; MAC_LEN];
        mac2.copy_from_slice(&bytes[132..148]);

        Ok(Self {
            message_type,
            sender: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            ephemeral,
            static_key,
            timestamp,
            mac1,
            mac2,
        })
    }

    /// Serialize the message.
    pub fn serialize(&self) -> [u8; INITIATION_SIZE] {
        let mut out = [0u8; INITIATION_SIZE];
        out[0..4].copy_from_slice(&self.message_type.to_le_bytes());
        out[4..8].copy_from_slice(&self.sender.to_le_bytes());
        out[8..40].copy_from_slice(&self.ephemeral);
        out[40..88].copy_from_slice(&self.static_key);
        out[88..116].copy_from_slice(&self.timestamp);
        out[116..132].copy_from_slice(&self.mac1);
        out[132..148].copy_from_slice(&self.mac2);
        out
    }

    /// Verify the first authentication tag.
    ///
    /// The key is derived from the responder's static key, because the
    /// initiator computed the tag with it.
    pub fn verify_mac1(&self, responder_static: &[u8; KEY_LEN]) -> bool {
        let key = mac1_key(responder_static);
        let packet = self.serialize();
        let expected = mac128(&key, &packet[..116]);
        expected == self.mac1
    }

    /// Compute and set the first authentication tag.
    pub fn set_mac1(&mut self, responder_static: &[u8; KEY_LEN]) {
        let key = mac1_key(responder_static);
        let packet = self.serialize();
        self.mac1 = mac128(&key, &packet[..116]);
    }
}

/// A response message.
#[derive(Clone, Debug)]
pub struct MessageResponse {
    /// Always [`MESSAGE_RESPONSE`].
    pub message_type: u32,
    /// The responder's index.
    pub sender: u32,
    /// The initiator's index, which the responder echoes.
    pub receiver: u32,
    /// The responder's ephemeral public key.
    pub ephemeral: [u8; KEY_LEN],
    /// An empty plaintext, with its authentication tag.
    pub empty: [u8; 16],
    /// The first authentication tag.
    pub mac1: [u8; MAC_LEN],
    /// The second authentication tag. Zero on a first handshake.
    pub mac2: [u8; MAC_LEN],
}

impl MessageResponse {
    /// Parse a response message.
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() != RESPONSE_SIZE {
            return Err(MessageError::WrongLength);
        }

        let message_type = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
        if message_type != MESSAGE_RESPONSE {
            return Err(MessageError::WrongType);
        }

        let mut ephemeral = [0u8; KEY_LEN];
        ephemeral.copy_from_slice(&bytes[12..44]);
        let mut empty = [0u8; 16];
        empty.copy_from_slice(&bytes[44..60]);
        let mut mac1 = [0u8; MAC_LEN];
        mac1.copy_from_slice(&bytes[60..76]);
        let mut mac2 = [0u8; MAC_LEN];
        mac2.copy_from_slice(&bytes[76..92]);

        Ok(Self {
            message_type,
            sender: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            receiver: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            ephemeral,
            empty,
            mac1,
            mac2,
        })
    }

    /// Serialize the message.
    pub fn serialize(&self) -> [u8; RESPONSE_SIZE] {
        let mut out = [0u8; RESPONSE_SIZE];
        out[0..4].copy_from_slice(&self.message_type.to_le_bytes());
        out[4..8].copy_from_slice(&self.sender.to_le_bytes());
        out[8..12].copy_from_slice(&self.receiver.to_le_bytes());
        out[12..44].copy_from_slice(&self.ephemeral);
        out[44..60].copy_from_slice(&self.empty);
        out[60..76].copy_from_slice(&self.mac1);
        out[76..92].copy_from_slice(&self.mac2);
        out
    }

    /// Verify the first authentication tag.
    ///
    /// The key is derived from the initiator's static key, because the
    /// responder computed the tag with it.
    pub fn verify_mac1(&self, initiator_static: &[u8; KEY_LEN]) -> bool {
        let key = mac1_key(initiator_static);
        let packet = self.serialize();
        let expected = mac128(&key, &packet[..60]);
        expected == self.mac1
    }

    /// Compute and set the first authentication tag.
    pub fn set_mac1(&mut self, initiator_static: &[u8; KEY_LEN]) {
        let key = mac1_key(initiator_static);
        let packet = self.serialize();
        self.mac1 = mac128(&key, &packet[..60]);
    }
}

/// A transport message.
///
/// The receiver's index is echoed so the peer knows which keypair the
/// message belongs to.
#[derive(Clone, Debug)]
pub struct MessageTransport {
    /// Always [`MESSAGE_TRANSPORT`].
    pub message_type: u32,
    /// The receiver's index.
    pub receiver: u32,
    /// The sending counter.
    pub counter: u64,
    /// The encrypted payload.
    pub content: Vec<u8>,
}

impl MessageTransport {
    /// Parse a transport message.
    pub fn parse(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() < TRANSPORT_HEADER_SIZE {
            return Err(MessageError::WrongLength);
        }

        let message_type = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
        if message_type != MESSAGE_TRANSPORT {
            return Err(MessageError::WrongType);
        }

        Ok(Self {
            message_type,
            receiver: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            counter: u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")),
            content: bytes[TRANSPORT_HEADER_SIZE..].to_vec(),
        })
    }

    /// Serialize the message.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRANSPORT_HEADER_SIZE + self.content.len());
        out.extend_from_slice(&self.message_type.to_le_bytes());
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.content);
        out
    }
}

/// Verify a MAC field against a packet.
///
/// The field is the last sixteen bytes of the packet.
pub fn verify_trailing_mac(packet: &[u8], key: &[u8; 32]) -> bool {
    if packet.len() < MAC_LEN {
        return false;
    }
    let split = packet.len() - MAC_LEN;
    let expected = mac128(key, &packet[..split]);
    expected == packet[split..]
}

/// Compute an HMAC-BLAKE2s over two inputs.
///
/// This is used for the transport's own authentication, which is keyed the
/// same way as WireGuard's message MACs.
pub fn mac_over(key: &[u8], first: &[u8], second: &[u8]) -> [u8; MAC_LEN] {
    let mut data = Vec::with_capacity(first.len() + second.len());
    data.extend_from_slice(first);
    data.extend_from_slice(second);
    let full = hmac(key, &data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// The initial hash of the transcript, exposed for testing.
pub fn transcript_start() -> [u8; 32] {
    initial_hash()
}

/// Mix a value into a hash state, exposed for testing.
pub fn transcript_mix(state: &[u8; 32], data: &[u8]) -> [u8; 32] {
    mix_hash(state, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::{initial_chain_key, WG_IDENTIFIER};

    #[test]
    fn the_keyed_mac_matches_the_reference() {
        // Keyed BLAKE2s-128, which is what WireGuard's MAC fields use.
        let key = [0x42u8; 32];
        assert_eq!(
            hex::encode(mac128(&key, b"payload")),
            "40def79036007e221495b8b3b9ab9d86"
        );
    }

    #[test]
    fn the_mac1_key_is_derived_from_the_label() {
        let peer = [0x11u8; KEY_LEN];
        let mut expected = Vec::new();
        expected.extend_from_slice(crate::wireguard::WG_LABEL_MAC1);
        expected.extend_from_slice(&peer);
        assert_eq!(mac1_key(&peer), hash(&expected));
    }

    #[test]
    fn an_initiation_round_trips() {
        let message = MessageInitiation {
            message_type: MESSAGE_INITIATION,
            sender: 0x1234_5678,
            ephemeral: [0x22; KEY_LEN],
            static_key: [0x33; KEY_LEN + 16],
            timestamp: [0x44; 12 + 16],
            mac1: [0x55; MAC_LEN],
            mac2: [0x66; MAC_LEN],
        };

        let bytes = message.serialize();
        assert_eq!(bytes.len(), INITIATION_SIZE);

        let parsed = MessageInitiation::parse(&bytes).expect("parse");
        assert_eq!(parsed.sender, message.sender);
        assert_eq!(parsed.ephemeral, message.ephemeral);
        assert_eq!(parsed.static_key, message.static_key);
        assert_eq!(parsed.timestamp, message.timestamp);
        assert_eq!(parsed.mac1, message.mac1);
        assert_eq!(parsed.mac2, message.mac2);
    }

    #[test]
    fn a_response_round_trips() {
        let message = MessageResponse {
            message_type: MESSAGE_RESPONSE,
            sender: 1,
            receiver: 2,
            ephemeral: [0x77; KEY_LEN],
            empty: [0x88; 16],
            mac1: [0x99; MAC_LEN],
            mac2: [0xaa; MAC_LEN],
        };

        let bytes = message.serialize();
        assert_eq!(bytes.len(), RESPONSE_SIZE);

        let parsed = MessageResponse::parse(&bytes).expect("parse");
        assert_eq!(parsed.sender, message.sender);
        assert_eq!(parsed.receiver, message.receiver);
        assert_eq!(parsed.ephemeral, message.ephemeral);
        assert_eq!(parsed.empty, message.empty);
        assert_eq!(parsed.mac1, message.mac1);
        assert_eq!(parsed.mac2, message.mac2);
    }

    #[test]
    fn a_message_of_the_wrong_length_is_refused() {
        assert!(matches!(
            MessageInitiation::parse(&[0u8; 10]),
            Err(MessageError::WrongLength)
        ));
        assert!(matches!(
            MessageResponse::parse(&[0u8; 10]),
            Err(MessageError::WrongLength)
        ));
    }

    #[test]
    fn a_message_of_the_wrong_type_is_refused() {
        let mut bytes = [0u8; INITIATION_SIZE];
        bytes[0..4].copy_from_slice(&MESSAGE_RESPONSE.to_le_bytes());
        assert!(matches!(
            MessageInitiation::parse(&bytes),
            Err(MessageError::WrongType)
        ));
    }

    #[test]
    fn a_mac_is_verified_over_the_packet() {
        let responder = [0x11u8; KEY_LEN];
        let mut message = MessageInitiation {
            message_type: MESSAGE_INITIATION,
            sender: 7,
            ephemeral: [0x22; KEY_LEN],
            static_key: [0x33; KEY_LEN + 16],
            timestamp: [0x44; 12 + 16],
            mac1: [0u8; MAC_LEN],
            mac2: [0u8; MAC_LEN],
        };
        message.set_mac1(&responder);

        assert!(message.verify_mac1(&responder));

        // The wrong responder key does not verify.
        assert!(!message.verify_mac1(&[0x12u8; KEY_LEN]));

        // A tampered message does not verify.
        let mut bytes = message.serialize();
        bytes[20] ^= 0xff;
        let tampered = MessageInitiation::parse(&bytes).expect("parse");
        assert!(!tampered.verify_mac1(&responder));
    }

    #[test]
    fn the_timestamp_carries_the_tai64n_offset() {
        let stamp = timestamp_now();
        let seconds = u64::from_be_bytes(stamp[..8].try_into().expect("8 bytes"));
        // The offset has to be there, or the timestamp looks like it is from
        // the distant past.
        assert!(seconds >= TAI64N_BASE);
        // And it has to be near the current time.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        assert!((seconds - TAI64N_BASE).abs_diff(now) < 5);
    }

    #[test]
    fn the_transcript_starts_from_the_construction() {
        assert_eq!(transcript_start(), crate::wireguard::initial_hash());
        assert_eq!(initial_chain_key(), hash(crate::wireguard::PROTOCOL_NAME));
        assert_eq!(
            transcript_mix(&initial_chain_key(), WG_IDENTIFIER),
            transcript_start()
        );
    }

    #[test]
    fn a_transport_message_round_trips() {
        let message = MessageTransport {
            message_type: MESSAGE_TRANSPORT,
            receiver: 9,
            counter: 12_345,
            content: vec![1, 2, 3, 4],
        };

        let bytes = message.serialize();
        assert_eq!(bytes.len(), TRANSPORT_HEADER_SIZE + 4);

        let parsed = MessageTransport::parse(&bytes).expect("parse");
        assert_eq!(parsed.receiver, message.receiver);
        assert_eq!(parsed.counter, message.counter);
        assert_eq!(parsed.content, message.content);
    }
}
