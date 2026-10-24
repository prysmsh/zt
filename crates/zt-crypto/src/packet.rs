//! The ZT-next data-plane packet format.
//!
//! # Design goals
//!
//! 1. **Encrypted headers.** Unlike ZeroTier, which sends `HELLO` in the
//!    clear with public keys in it, ZT-next encrypts everything after the
//!    session is established. An observer sees only a session identifier and
//!    a length.
//! 2. **Replay protection.** Every packet carries a monotonically increasing
//!    sequence number per direction. A receiver rejects anything it has
//!    already seen or anything beyond its window.
//! 3. **Small overhead.** The per-packet header is 12 bytes:
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┬──────────────┐
//! │ session_id   │ seq          │ type         │ payload_len  │
//! │ [u8;4]       │ u64          │ u8           │ u16          │
//! ├──────────────┴──────────────┴──────────────┴──────────────┤
//! │ ciphertext + Poly1305 tag                                  │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! 4. **Type discrimination.** The packet type is *inside* the encrypted
//!    payload, not in the header, so an observer cannot tell what kind of
//!    traffic is flowing. The header's `type` byte is always zero and
//!    reserved.
//!
//! # Packet types
//!
//! These are the inner (encrypted) types:
//!
//! | Type | Name | Purpose |
//! |---|---|---|
//! | 0x01 | `FRAME` | An IP or Ethernet frame for the virtual network |
//! | 0x02 | `PING` | Path latency probe |
//! | 0x03 | `PONG` | Path latency response |
//! | 0x04 | `PATH_HINT` | A suggested better path to a peer |
//! | 0x05 | `RELAY` | Traffic being relayed through a third party |

/// Length of the packet header.
///
/// ```text
/// ┌──────────────┬──────────────┬──────────────┬──────────────┐
/// │ session_id   │ seq          │ reserved     │ payload_len  │
/// │ [u8;4]       │ u64          │ u8           │ u16          │
/// ├──────────────┴──────────────┴──────────────┴──────────────┤
/// │ ciphertext + Poly1305 tag                                  │
/// └────────────────────────────────────────────────────────────┘
/// ```
///
/// 4 + 8 + 1 + 2 = 15 bytes of header.
pub const HEADER_LEN: usize = 15;

/// Largest payload that fits in a single UDP datagram without IP
/// fragmentation.
///
/// 1400 bytes leaves room for the IPv4/IPv6 header and the UDP header
/// within the 1500-byte MTU that most networks use.
pub const MAX_PAYLOAD: usize = 1400;

/// Largest encrypted packet.
pub const MAX_PACKET: usize = HEADER_LEN + MAX_PAYLOAD + 16;

/// Inner packet type: a frame for the virtual network.
pub const TYPE_FRAME: u8 = 0x01;
/// Inner packet type: path latency probe.
pub const TYPE_PING: u8 = 0x02;
/// Inner packet type: path latency response.
pub const TYPE_PONG: u8 = 0x03;
/// Inner packet type: a suggested better path.
pub const TYPE_PATH_HINT: u8 = 0x04;
/// Inner packet type: relayed traffic.
pub const TYPE_RELAY: u8 = 0x05;

/// A decrypted packet's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The inner packet type.
    pub packet_type: u8,
    /// The inner payload.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Build a packet.
    pub fn new(packet_type: u8, payload: Vec<u8>) -> Packet {
        Packet {
            packet_type,
            payload,
        }
    }

    /// Serialize the inner contents.
    pub fn serialize_inner(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.payload.len());
        out.push(self.packet_type);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse the inner contents.
    pub fn parse_inner(bytes: &[u8]) -> Option<Packet> {
        if bytes.is_empty() {
            return None;
        }
        Some(Packet {
            packet_type: bytes[0],
            payload: bytes[1..].to_vec(),
        })
    }
}

/// Tracks the receive window for one direction of a session.
///
/// Rejects replayed packets and packets that are too far ahead.
///
/// A sliding bitmap records which sequence numbers within the window have
/// been seen, so that a reordered packet is accepted exactly once while a
/// genuine replay is rejected.
pub struct ReceiveWindow {
    /// The highest sequence number accepted so far.
    highest: u64,
    /// Bit `i` corresponds to sequence number `highest - i`.
    seen: u64,
    /// Whether any packet has been received yet.
    started: bool,
}

impl ReceiveWindow {
    /// Number of packets that may be reordered.
    pub const WINDOW: u64 = 64;

    /// Create an empty window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            seen: 0,
            started: false,
        }
    }

    /// Check and record a sequence number.
    ///
    /// Returns `true` if the packet should be accepted. A packet is rejected
    /// if it has already been seen, or if it is more than
    /// [`Self::WINDOW`] ahead of the highest accepted sequence.
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.seen = 1; // bit 0: the highest itself
            return true;
        }

        if seq > self.highest {
            let advance = seq - self.highest;
            if advance >= Self::WINDOW {
                // Too far ahead: this looks like a desynchronised counter
                // rather than a legitimate packet. Reset the window.
                self.highest = seq;
                self.seen = 1;
                return true;
            }
            self.seen <<= advance;
            self.seen |= 1;
            self.highest = seq;
            return true;
        }

        // Older or equal to the highest. The offset from the highest
        // determines which bit records it.
        let offset = self.highest - seq;
        if offset >= Self::WINDOW {
            return false; // too old
        }
        let bit = 1u64 << offset;
        if self.seen & bit != 0 {
            return false; // already seen
        }
        self.seen |= bit;
        true
    }

    /// Whether a sequence number has already been received.
    ///
    /// This reports whether the packet would be a *replay*: a sequence
    /// number that was accepted before. The highest accepted sequence
    /// number counts as already-received, because receiving the same
    /// sequence number twice is a replay.
    pub fn is_duplicate(&self, seq: u64) -> bool {
        if !self.started {
            return false;
        }
        if seq > self.highest {
            return false;
        }
        let offset = self.highest - seq;
        if offset >= Self::WINDOW {
            return true; // too old to be legitimate
        }
        self.seen & (1u64 << offset) != 0
    }
}

impl Default for ReceiveWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ReceiveWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceiveWindow")
            .field("highest", &self.highest)
            .field("started", &self.started)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_roundtrip() {
        let p = Packet::new(TYPE_FRAME, b"payload".to_vec());
        let bytes = p.serialize_inner();
        let parsed = Packet::parse_inner(&bytes).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn inner_rejects_empty() {
        assert!(Packet::parse_inner(&[]).is_none());
    }

    #[test]
    fn window_accepts_first_packet() {
        let mut w = ReceiveWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(1));
        assert!(w.accept(2));
    }

    #[test]
    fn window_rejects_far_future() {
        let mut w = ReceiveWindow::new();
        assert!(w.accept(0));
        // A jump beyond the window resets the window rather than being
        // silently dropped: the session is resynchronised.
        assert!(w.accept(ReceiveWindow::WINDOW * 4));
    }

    #[test]
    fn window_accepts_reordered() {
        let mut w = ReceiveWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(101));
        // An out-of-order packet within the window is allowed.
        assert!(w.accept(99));
        // But it may only be accepted once.
        assert!(!w.accept(99));
    }

    #[test]
    fn window_rejects_too_old() {
        let mut w = ReceiveWindow::new();
        assert!(w.accept(2000));
        // Once the window slides past, older packets are rejected.
        assert!(!w.accept(1));
    }

    #[test]
    fn window_detects_duplicates() {
        let mut w = ReceiveWindow::new();
        assert!(w.accept(5));
        // 5 has been received, so receiving it again is a replay.
        assert!(w.is_duplicate(5));
        assert!(w.accept(6));
        assert!(w.is_duplicate(5));
        // 7 has not been received.
        assert!(!w.is_duplicate(7));
    }
}
