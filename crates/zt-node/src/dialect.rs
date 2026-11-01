//! Transport dialect detection.
//!
//! A ZT-next node can speak several wire protocols over a single UDP socket.
//! The dialects are distinguished by inspecting the datagram header, which
//! is unambiguous because their prefixes do not overlap.
//!
//! | Dialect | Detection |
//! |---|---|
//! | ZT-next | `00 5a 54 00` magic, or a handshake type byte of `0x01`/`0x02` |
//! | Tailscale | WireGuard message type `1`–`4` with a zero reserved field |
//! | ZeroTier | Legacy framing of at least 28 bytes with a 5-byte destination address |
//!
//! Classification never guesses: a datagram that matches nothing is
//! [`Dialect::Unknown`] and is dropped.

/// The wire protocol spoken by a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// The native ZT-next protocol.
    ZtNext,
    /// The Tailscale dialect, which is WireGuard.
    Tailscale,
    /// The legacy ZeroTier dialect.
    ZeroTier,
    /// The datagram did not match any known dialect.
    Unknown,
}

/// WireGuard message types.
///
/// These are the four values from the Noise_IK_25519_ChaChaPoly_BLAKE2s
/// construction that Tailscale's `wgengine` uses.
const WIREGUARD_TYPE_INITIATION: u8 = 1;
const WIREGUARD_TYPE_TRANSPORT: u8 = 4;

/// Minimum size of a legacy ZeroTier packet.
///
/// The framing is an 8-byte packet ID, a 5-byte destination, a 5-byte
/// source, one flags byte, an 8-byte MAC, and one verb byte.
pub const LEGACY_MIN_PACKET: usize = 28;

/// Classify a datagram by inspecting its header.
///
/// The native ZT-next formats are checked first because their magic prefix
/// is exact, while the foreign dialects are matched on looser structural
/// rules. Checking the exact match first prevents a foreign datagram that
/// happens to begin with `0x01` or `0x02` from being misrouted.
pub fn classify(datagram: &[u8]) -> Dialect {
    if is_zt_next(datagram) {
        return Dialect::ZtNext;
    }
    if is_tailscale(datagram) {
        return Dialect::Tailscale;
    }
    if is_zerotier(datagram) {
        return Dialect::ZeroTier;
    }
    Dialect::Unknown
}

/// True when the datagram is a native ZT-next handshake or data packet.
///
/// Both native formats carry a magic prefix, so they are never confused with
/// a foreign dialect.
pub fn is_zt_next(datagram: &[u8]) -> bool {
    zt_crypto::packet::is_data_packet(datagram) || zt_crypto::packet::is_handshake_packet(datagram)
}

/// True when the datagram looks like a WireGuard message.
///
/// The first four bytes are a little-endian message type followed by a
/// three-byte reserved field. The reserved field must be zero, which is what
/// keeps this from matching arbitrary datagrams.
pub fn is_tailscale(datagram: &[u8]) -> bool {
    if datagram.len() < 4 {
        return false;
    }
    let message_type = datagram[0];
    if !(WIREGUARD_TYPE_INITIATION..=WIREGUARD_TYPE_TRANSPORT).contains(&message_type) {
        return false;
    }
    datagram[1] == 0 && datagram[2] == 0 && datagram[3] == 0
}

/// True when the datagram looks like a legacy ZeroTier packet.
///
/// The legacy framing always includes a 5-byte destination address at a
/// fixed offset. Combined with the minimum packet size this is a reliable
/// discriminator, because the other dialects never place an arbitrary
/// 5-byte field at offset 8.
///
/// The verb byte sits at offset 27 in the legacy framing and must be one of
/// the defined verbs. The top three bits are encrypted flags, so only the
/// low five bits carry the verb.
pub fn is_zerotier(datagram: &[u8]) -> bool {
    if datagram.len() < LEGACY_MIN_PACKET {
        return false;
    }
    let verb = datagram[27] & 0x1f;
    is_known_legacy_verb(verb)
}

/// The legacy packet verbs defined by ZeroTier's `node/Packet.hpp`.
///
/// Note the gaps: `0x0f` and `0x11` are not assigned.
fn is_known_legacy_verb(verb: u8) -> bool {
    matches!(
        verb,
        0x00 | 0x01
            | 0x02
            | 0x03
            | 0x04
            | 0x05
            | 0x06
            | 0x07
            | 0x08
            | 0x09
            | 0x0a
            | 0x0b
            | 0x0c
            | 0x0d
            | 0x0e
            | 0x10
            | 0x12
            | 0x13
            | 0x14
            | 0x15
            | 0x16
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zt_next_data_packets_are_recognised() {
        let mut datagram = vec![0x00, 0x5a, 0x54, 0x00, 0x00];
        datagram.extend_from_slice(&[0u8; 32]);
        assert_eq!(classify(&datagram), Dialect::ZtNext);
    }

    #[test]
    fn zt_next_handshakes_are_recognised() {
        // [magic(3)][type][tag][len_hi][len_lo]
        assert_eq!(
            classify(&[0x00, 0x5a, 0x54, 0x01, 0x01, 0x00, 0x20]),
            Dialect::ZtNext
        );
        assert_eq!(
            classify(&[0x00, 0x5a, 0x54, 0x02, 0x02, 0x00, 0x20]),
            Dialect::ZtNext
        );
    }

    #[test]
    fn a_bare_type_byte_is_not_a_handshake() {
        // Too short and missing the magic, so it is not a valid ZT-next
        // handshake. It is also not a valid WireGuard message.
        assert_eq!(classify(&[0x01]), Dialect::Unknown);
        assert_eq!(classify(&[0x02]), Dialect::Unknown);
    }

    #[test]
    fn wireguard_messages_are_recognised() {
        for message_type in 1u8..=4 {
            let datagram = vec![message_type, 0x00, 0x00, 0x00, 0xAA];
            assert_eq!(classify(&datagram), Dialect::Tailscale);
        }
    }

    #[test]
    fn wireguard_rejects_a_nonzero_reserved_field() {
        // The reserved field must be entirely zero. A nonzero byte makes
        // this malformed as WireGuard, and without the native magic it is
        // not a ZT-next handshake either.
        let datagram = vec![1u8, 0x01, 0x00, 0x00];
        assert_eq!(classify(&datagram), Dialect::Unknown);
    }

    #[test]
    fn wireguard_requires_the_reserved_field_to_be_zero() {
        assert!(is_tailscale(&[1, 0, 0, 0]));
        assert!(!is_tailscale(&[1, 1, 0, 0]));
        assert!(!is_tailscale(&[1, 0, 1, 0]));
        assert!(!is_tailscale(&[1, 0, 0, 1]));
    }

    #[test]
    fn wireguard_rejects_unknown_message_types() {
        let datagram = vec![5u8, 0x00, 0x00, 0x00, 0xAA];
        assert_eq!(classify(&datagram), Dialect::Unknown);
    }

    #[test]
    fn legacy_packets_are_recognised() {
        let mut datagram = vec![0u8; LEGACY_MIN_PACKET];
        datagram[27] = 0x01; // HELLO
        assert_eq!(classify(&datagram), Dialect::ZeroTier);
    }

    #[test]
    fn legacy_packets_reject_unassigned_verbs() {
        let mut datagram = vec![0u8; LEGACY_MIN_PACKET];
        datagram[27] = 0x0f;
        assert_eq!(classify(&datagram), Dialect::Unknown);
        datagram[27] = 0x11;
        assert_eq!(classify(&datagram), Dialect::Unknown);
    }

    #[test]
    fn short_datagrams_are_unknown() {
        assert_eq!(classify(&[]), Dialect::Unknown);
        assert_eq!(classify(&[0x03]), Dialect::Unknown);
        assert_eq!(classify(&[0xff]), Dialect::Unknown);
    }

    #[test]
    fn wireguard_types_one_and_two_are_not_stolen_by_the_native_handshake() {
        // WireGuard uses message types 1 and 2, which are the same values
        // ZT-next uses for its handshake types. The native magic prefix
        // keeps them apart.
        let initiation = vec![1u8, 0x00, 0x00, 0x00];
        assert_eq!(classify(&initiation), Dialect::Tailscale);
        let response = vec![2u8, 0x00, 0x00, 0x00];
        assert_eq!(classify(&response), Dialect::Tailscale);
    }

    #[test]
    fn dialects_do_not_shadow_each_other() {
        // A WireGuard transport message must never be read as legacy.
        let wireguard = vec![4u8, 0x00, 0x00, 0x00, 0xAA, 0xBB];
        assert_eq!(classify(&wireguard), Dialect::Tailscale);

        // A ZT-next handshake must never be read as WireGuard.
        let handshake = vec![0x00u8, 0x5a, 0x54, 0x01, 0x01, 0x00, 0x20];
        assert_eq!(classify(&handshake), Dialect::ZtNext);
    }
}
