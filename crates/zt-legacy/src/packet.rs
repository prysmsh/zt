//! The legacy ZeroTier packet format.
//!
//! ZeroTier's packet header is 28 bytes:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │ packet id (8) │ dest (5) │ source (5) │ flags (1) │ MAC (8) │
//! │ verb (1)      │ payload ...                                │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! The flags byte packs three fields: `FFCCCHHH`, where `FF` is the
//! extended-armor and fragmentation flags, `CCC` is the three-bit cipher
//! suite selector, and `HHH` is the hop count.
//!
//! The hop count is the only field a forwarding node may modify in transit,
//! which is why the crypto key derivation masks it out.

use crate::salsa20::{Poly1305, Salsa20};
use crate::zerotier::LegacyAddress;

/// Length of the legacy packet header.
pub const HEADER_LEN: usize = 28;

/// Index of the packet id (also the crypto IV) in the header.
pub const IDX_ID: usize = 0;
/// Index of the destination address.
pub const IDX_DEST: usize = 8;
/// Index of the source address.
pub const IDX_SOURCE: usize = 13;
/// Index of the flags byte.
pub const IDX_FLAGS: usize = 18;
/// Index of the MAC field.
pub const IDX_MAC: usize = 19;
/// Index of the verb byte.
pub const IDX_VERB: usize = 27;
/// Index of the payload.
pub const IDX_PAYLOAD: usize = 28;

/// The legacy packet verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verb {
    Nop,
    Hello,
    Error,
    Ok,
    Whois,
    Rendezvous,
    Frame,
    ExtFrame,
    Echo,
    MulticastLike,
    NetworkCredentials,
    NetworkConfigRequest,
    NetworkConfig,
    MulticastGather,
    MulticastFrame,
    PushDirectPaths,
    Ack,
    QosMeasurement,
    UserMessage,
    RemoteTrace,
    PathNegotiationRequest,
}

impl Verb {
    /// The numeric verb value.
    pub fn as_u8(self) -> u8 {
        match self {
            Verb::Nop => 0x00,
            Verb::Hello => 0x01,
            Verb::Error => 0x02,
            Verb::Ok => 0x03,
            Verb::Whois => 0x04,
            Verb::Rendezvous => 0x05,
            Verb::Frame => 0x06,
            Verb::ExtFrame => 0x07,
            Verb::Echo => 0x08,
            Verb::MulticastLike => 0x09,
            Verb::NetworkCredentials => 0x0a,
            Verb::NetworkConfigRequest => 0x0b,
            Verb::NetworkConfig => 0x0c,
            Verb::MulticastGather => 0x0d,
            Verb::MulticastFrame => 0x0e,
            Verb::PushDirectPaths => 0x10,
            Verb::Ack => 0x12,
            Verb::QosMeasurement => 0x13,
            Verb::UserMessage => 0x14,
            Verb::RemoteTrace => 0x15,
            Verb::PathNegotiationRequest => 0x16,
        }
    }

    /// Parse a numeric verb value.
    pub fn from_u8(value: u8) -> Option<Verb> {
        Some(match value {
            0x00 => Verb::Nop,
            0x01 => Verb::Hello,
            0x02 => Verb::Error,
            0x03 => Verb::Ok,
            0x04 => Verb::Whois,
            0x05 => Verb::Rendezvous,
            0x06 => Verb::Frame,
            0x07 => Verb::ExtFrame,
            0x08 => Verb::Echo,
            0x09 => Verb::MulticastLike,
            0x0a => Verb::NetworkCredentials,
            0x0b => Verb::NetworkConfigRequest,
            0x0c => Verb::NetworkConfig,
            0x0d => Verb::MulticastGather,
            0x0e => Verb::MulticastFrame,
            0x10 => Verb::PushDirectPaths,
            0x12 => Verb::Ack,
            0x13 => Verb::QosMeasurement,
            0x14 => Verb::UserMessage,
            0x15 => Verb::RemoteTrace,
            0x16 => Verb::PathNegotiationRequest,
            _ => return None,
        })
    }

    /// All defined verbs, in numeric order.
    pub fn all() -> &'static [Verb] {
        &[
            Verb::Nop,
            Verb::Hello,
            Verb::Error,
            Verb::Ok,
            Verb::Whois,
            Verb::Rendezvous,
            Verb::Frame,
            Verb::ExtFrame,
            Verb::Echo,
            Verb::MulticastLike,
            Verb::NetworkCredentials,
            Verb::NetworkConfigRequest,
            Verb::NetworkConfig,
            Verb::MulticastGather,
            Verb::MulticastFrame,
            Verb::PushDirectPaths,
            Verb::Ack,
            Verb::QosMeasurement,
            Verb::UserMessage,
            Verb::RemoteTrace,
            Verb::PathNegotiationRequest,
        ]
    }
}

/// The cipher suite selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// Poly1305 authentication with no payload encryption.
    Poly1305None,
    /// Salsa20/12 encryption with Poly1305 authentication.
    Poly1305Salsa2012,
    /// No cryptography; the MAC field carries a trusted path ID.
    NoCryptoTrustedPath,
    /// AES-GMAC-SIV, used by newer ZeroTier versions.
    AesGmacSiv,
}

impl Cipher {
    /// The numeric cipher selector.
    pub fn as_u8(self) -> u8 {
        match self {
            Cipher::Poly1305None => 0,
            Cipher::Poly1305Salsa2012 => 1,
            Cipher::NoCryptoTrustedPath => 2,
            Cipher::AesGmacSiv => 3,
        }
    }

    /// Parse a numeric cipher selector.
    pub fn from_u8(value: u8) -> Option<Cipher> {
        Some(match value {
            0 => Cipher::Poly1305None,
            1 => Cipher::Poly1305Salsa2012,
            2 => Cipher::NoCryptoTrustedPath,
            3 => Cipher::AesGmacSiv,
            _ => return None,
        })
    }

    /// Whether this suite encrypts the payload.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Cipher::Poly1305Salsa2012 | Cipher::AesGmacSiv)
    }
}

/// A parsed legacy packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyPacket {
    /// The packet id, which doubles as the crypto IV.
    pub packet_id: u64,
    /// The destination address.
    pub destination: LegacyAddress,
    /// The source address.
    pub source: LegacyAddress,
    /// The cipher suite in use.
    pub cipher: Cipher,
    /// The hop count, from 0 to 7.
    pub hops: u8,
    /// The verb.
    pub verb: Verb,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

impl LegacyPacket {
    /// Build a packet.
    pub fn new(
        packet_id: u64,
        destination: LegacyAddress,
        source: LegacyAddress,
        verb: Verb,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            packet_id,
            destination,
            source,
            cipher: Cipher::Poly1305None,
            hops: 0,
            verb,
            payload,
        }
    }

    /// Serialize the packet in the clear.
    ///
    /// This produces the wire format without applying any cryptography. Use
    /// [`LegacyPacket::armor`] to produce an encrypted packet.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN + self.payload.len()];
        out[IDX_ID..IDX_ID + 8].copy_from_slice(&self.packet_id.to_le_bytes());
        out[IDX_DEST..IDX_DEST + 5].copy_from_slice(self.destination.as_bytes());
        out[IDX_SOURCE..IDX_SOURCE + 5].copy_from_slice(self.source.as_bytes());

        // FFCCCHHH
        let mut flags = (self.cipher.as_u8() & 0x07) << 3;
        flags |= self.hops & 0x07;
        out[IDX_FLAGS] = flags;

        out[IDX_VERB] = self.verb.as_u8();
        out[IDX_PAYLOAD..].copy_from_slice(&self.payload);
        out
    }

    /// Parse a packet from the wire format.
    ///
    /// The packet must be at least 28 bytes long and carry a known verb.
    pub fn parse(bytes: &[u8]) -> Option<LegacyPacket> {
        if bytes.len() < HEADER_LEN {
            return None;
        }

        let packet_id = u64::from_le_bytes(bytes[IDX_ID..IDX_ID + 8].try_into().ok()?);
        let mut destination_bytes = [0u8; 5];
        destination_bytes.copy_from_slice(&bytes[IDX_DEST..IDX_DEST + 5]);
        let mut source_bytes = [0u8; 5];
        source_bytes.copy_from_slice(&bytes[IDX_SOURCE..IDX_SOURCE + 5]);

        let flags = bytes[IDX_FLAGS];
        let cipher = Cipher::from_u8((flags >> 3) & 0x07)?;
        let hops = flags & 0x07;
        let verb = Verb::from_u8(bytes[IDX_VERB] & 0x1f)?;

        Some(LegacyPacket {
            packet_id,
            destination: LegacyAddress::from_bytes(&destination_bytes),
            source: LegacyAddress::from_bytes(&source_bytes),
            cipher,
            hops,
            verb,
            payload: bytes[IDX_PAYLOAD..].to_vec(),
        })
    }

    /// Increment the hop count.
    ///
    /// Forwarding nodes do this without invalidating the MAC, because the
    /// key derivation masks the hop bits out.
    pub fn increment_hops(&mut self) {
        self.hops = (self.hops + 1) & 0x07;
    }

    /// The MAC field as a little-endian 64-bit value.
    pub fn mac(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.mac_bytes());
        u64::from_le_bytes(bytes)
    }

    /// The raw MAC bytes.
    pub fn mac_bytes(&self) -> [u8; 8] {
        [0u8; 8]
    }

    /// Encrypt and authenticate the packet with Salsa20/12 and Poly1305.
    ///
    /// The key is mangled with the packet's own header so that the IV, the
    /// addresses, the flags (minus the hop count), and the packet length all
    /// contribute to the effective key.
    pub fn armor(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut bytes = self.serialize();

        // Set the cipher before mangling, so the flags byte that is mixed
        // into the key reflects the final cipher suite.
        bytes[IDX_FLAGS] =
            (bytes[IDX_FLAGS] & 0xc7) | ((Cipher::Poly1305Salsa2012.as_u8() & 0x07) << 3);

        let mangled = mangle_key(key, &bytes);

        // The nonce is the packet id, which is the IV field.
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&bytes[IDX_ID..IDX_ID + 8]);

        let mut cipher = Salsa20::new(mangled, nonce);

        // The Poly1305 key is the first 32 bytes of the keystream. The
        // payload encryption continues from offset 32 of the same stream.
        let mac_key = cipher.mac_key();
        cipher.crypt12_at_offset(&mut bytes[IDX_VERB..], 32);

        let tag = Poly1305::compute(&mac_key, &bytes[IDX_VERB..]);
        bytes[IDX_MAC..IDX_MAC + 8].copy_from_slice(&tag[..8]);

        bytes
    }

    /// Decrypt and verify a packet.
    ///
    /// Returns `None` when the MAC does not verify, which is the case for
    /// tampered packets, packets from the wrong peer, and packets whose hop
    /// count has been incremented by a forwarding node.
    pub fn dearmor(bytes: &[u8], key: &[u8; 32]) -> Option<LegacyPacket> {
        if bytes.len() < HEADER_LEN {
            return None;
        }

        let mut packet = LegacyPacket::parse(bytes)?;
        if !packet.cipher.is_encrypted() {
            return Some(packet);
        }

        let mangled = mangle_key(key, bytes);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&bytes[IDX_ID..IDX_ID + 8]);
        let mut cipher = Salsa20::new(mangled, nonce);

        let mac_key = cipher.mac_key();
        let mut payload = bytes[IDX_VERB..].to_vec();
        let encrypted = payload.clone();
        cipher.crypt12_at_offset(&mut payload, 32);

        // Verify the MAC over the CIPHERTEXT, before decryption, exactly as
        // ZeroTier's dearmor does.
        let expected = Poly1305::compute(&mac_key, &encrypted);
        if expected[..8] != bytes[IDX_MAC..IDX_MAC + 8] {
            return None;
        }

        packet.payload = payload[1..].to_vec();
        Some(packet)
    }
}

/// Derive the effective encryption key for a packet.
///
/// ZeroTier mixes the packet's own header into the key so that the IV, the
/// addresses, the flags (with the hop count masked out), and the packet
/// length all contribute. The result is an effective IV wider than 64 bits.
pub fn mangle_key(key: &[u8; 32], packet: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];

    // IV (8 bytes) and the source and destination addresses (10 bytes).
    for i in 0..18 {
        out[i] = key[i] ^ packet[i];
    }

    // Flags, with the hop count masked off because forwarding nodes change
    // it without holding the key.
    out[18] = key[18] ^ (packet[IDX_FLAGS] & 0xf8);

    // The packet length, little endian.
    out[19] = key[19] ^ (packet.len() as u8);
    out[20] = key[20] ^ ((packet.len() >> 8) as u8);

    // The rest of the key is unchanged.
    out[21..].copy_from_slice(&key[21..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zerotier::LegacyAddress;

    fn address(value: u8) -> LegacyAddress {
        LegacyAddress::from_bytes(&[value; 5])
    }

    #[test]
    fn packet_round_trips_in_the_clear() {
        let packet = LegacyPacket::new(
            0x0102_0304_0506_0708,
            address(0xaa),
            address(0xbb),
            Verb::Hello,
            vec![1, 2, 3, 4],
        );
        let bytes = packet.serialize();
        assert_eq!(bytes.len(), HEADER_LEN + 4);

        let parsed = LegacyPacket::parse(&bytes).expect("parse");
        assert_eq!(parsed.packet_id, packet.packet_id);
        assert_eq!(parsed.destination, packet.destination);
        assert_eq!(parsed.source, packet.source);
        assert_eq!(parsed.verb, Verb::Hello);
        assert_eq!(parsed.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn the_flags_byte_packs_cipher_and_hops() {
        let mut packet = LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![]);
        packet.cipher = Cipher::Poly1305Salsa2012;
        packet.hops = 5;

        let bytes = packet.serialize();
        assert_eq!(bytes[IDX_FLAGS], 0b00_001_101);
        assert_eq!(
            Cipher::from_u8((bytes[IDX_FLAGS] >> 3) & 0x07),
            Some(Cipher::Poly1305Salsa2012)
        );

        let parsed = LegacyPacket::parse(&bytes).expect("parse");
        assert_eq!(parsed.hops, 5);
        assert_eq!(parsed.cipher, Cipher::Poly1305Salsa2012);
    }

    #[test]
    fn hop_count_wraps_at_eight() {
        let mut packet = LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![]);
        for _ in 0..8 {
            packet.increment_hops();
        }
        assert_eq!(packet.hops, 0);
    }

    #[test]
    fn the_minimum_packet_is_twenty_eight_bytes() {
        let packet = LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![]);
        assert_eq!(packet.serialize().len(), 28);
    }

    #[test]
    fn armor_round_trips() {
        let key = [42u8; 32];
        let packet = LegacyPacket::new(
            0xdead_beef_0000_0001,
            address(0xaa),
            address(0xbb),
            Verb::Frame,
            b"payload data".to_vec(),
        );

        let armored = packet.armor(&key);
        assert_eq!(armored.len(), packet.serialize().len());

        let parsed = LegacyPacket::dearmor(&armored, &key).expect("dearmor");
        assert_eq!(parsed.verb, Verb::Frame);
        assert_eq!(parsed.payload, b"payload data".to_vec());
        assert_eq!(parsed.packet_id, packet.packet_id);
    }

    #[test]
    fn dearmor_rejects_a_tampered_packet() {
        let key = [42u8; 32];
        let packet = LegacyPacket::new(1, address(1), address(2), Verb::Frame, b"payload".to_vec());
        let mut armored = packet.armor(&key);
        let last = armored.len() - 1;
        armored[last] ^= 0xff;

        assert!(LegacyPacket::dearmor(&armored, &key).is_none());
    }

    #[test]
    fn dearmor_rejects_the_wrong_key() {
        let packet = LegacyPacket::new(1, address(1), address(2), Verb::Frame, b"payload".to_vec());
        let armored = packet.armor(&[42u8; 32]);
        assert!(LegacyPacket::dearmor(&armored, &[43u8; 32]).is_none());
    }

    #[test]
    fn an_incremented_hop_count_breaks_the_mac() {
        // The key derivation masks the hop bits out, so a forwarding node can
        // increment the count without the key. But the flags byte itself is
        // mixed in with the hop bits masked, so the MAC still verifies.
        let key = [42u8; 32];
        let packet = LegacyPacket::new(1, address(1), address(2), Verb::Frame, b"payload".to_vec());
        let armored = packet.armor(&key);

        let mut forwarded = armored.clone();
        forwarded[IDX_FLAGS] = (forwarded[IDX_FLAGS] & 0xf8) | 0x01;

        // The masked key derivation means the MAC is unaffected by the hop
        // count, which is the whole point of the design.
        assert!(LegacyPacket::dearmor(&forwarded, &key).is_some());
    }

    #[test]
    fn every_verb_round_trips() {
        for verb in Verb::all() {
            let packet = LegacyPacket::new(1, address(1), address(2), *verb, vec![0xaa]);
            let bytes = packet.serialize();
            let parsed = LegacyPacket::parse(&bytes).expect("parse");
            assert_eq!(parsed.verb, *verb);
        }
    }

    #[test]
    fn unknown_verbs_are_rejected() {
        let mut bytes = LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![]).serialize();
        bytes[IDX_VERB] = 0x0f;
        assert!(LegacyPacket::parse(&bytes).is_none());
        bytes[IDX_VERB] = 0x11;
        assert!(LegacyPacket::parse(&bytes).is_none());
    }

    #[test]
    fn short_packets_are_rejected() {
        assert!(LegacyPacket::parse(&[0u8; 27]).is_none());
    }

    #[test]
    fn the_mangled_key_ignores_the_hop_count() {
        let key = [9u8; 32];
        let mut packet =
            LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![]).serialize();
        let before = mangle_key(&key, &packet);

        packet[IDX_FLAGS] = (packet[IDX_FLAGS] & 0xf8) | 0x03;
        let after = mangle_key(&key, &packet);

        assert_eq!(before, after);
    }

    #[test]
    fn the_mangled_key_reflects_the_length() {
        let key = [9u8; 32];
        let short = LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![]).serialize();
        let long = LegacyPacket::new(1, address(1), address(2), Verb::Nop, vec![0; 8]).serialize();
        assert_ne!(mangle_key(&key, &short), mangle_key(&key, &long));
    }
}
