//! An established session: the data plane after a successful handshake.
//!
//! A [`Session`] owns the directional transport ciphers and the replay
//! protection windows. It is the object the node's peer-management layer
//! actually holds once a handshake completes.

use crate::error::{Error, Result};
use crate::noise::TransportCipher;
use crate::packet::{Packet, ReceiveWindow, HEADER_LEN, MAX_PAYLOAD, PACKET_MAGIC};
use crate::symmetric::SymmetricKey;

/// An established, encrypted session between two peers.
pub struct Session {
    /// Cipher for packets we send.
    send: TransportCipher,
    /// Cipher for packets we receive.
    recv: TransportCipher,
    /// Next sequence number for outgoing packets.
    send_seq: u64,
    /// Replay protection for incoming packets.
    recv_window: ReceiveWindow,
}

impl Session {
    /// Create a session from the handshake's derived keys.
    pub fn new(send_key: SymmetricKey, recv_key: SymmetricKey) -> Session {
        Session {
            send: TransportCipher::new(send_key),
            recv: TransportCipher::new(recv_key),
            send_seq: 0,
            recv_window: ReceiveWindow::new(),
        }
    }

    /// Encrypt a packet for transmission.
    pub fn seal(&mut self, packet: &Packet) -> Result<Vec<u8>> {
        if packet.payload.len() > MAX_PAYLOAD {
            return Err(Error::InvalidLength);
        }
        let inner = packet.serialize_inner();
        let ciphertext = self.send.seal(&inner)?;

        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&PACKET_MAGIC);
        out.extend_from_slice(&self.send_seq.to_be_bytes());
        out.push(0); // reserved: the inner type is encrypted
        out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        self.send_seq += 1;
        Ok(out)
    }

    /// Decrypt a received packet.
    ///
    /// Returns `None` if the packet is a replay, is out of the receive
    /// window, or fails authentication.
    pub fn open(&mut self, bytes: &[u8]) -> Result<Option<Packet>> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::InvalidLength);
        }
        if bytes.len() > HEADER_LEN + MAX_PAYLOAD + 16 {
            return Err(Error::InvalidLength);
        }
        if bytes[..PACKET_MAGIC.len()] != PACKET_MAGIC {
            return Err(Error::InvalidKey("not a ZT-next data packet"));
        }

        let seq_start = PACKET_MAGIC.len();
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&bytes[seq_start..seq_start + 8]);
        let seq = u64::from_be_bytes(seq_bytes);

        // The reserved byte sits between the sequence number and the length.
        let len_start = seq_start + 8 + 1;
        let payload_len = u16::from_be_bytes([bytes[len_start], bytes[len_start + 1]]) as usize;
        if bytes.len() != HEADER_LEN + payload_len {
            return Err(Error::InvalidLength);
        }

        // Replay check happens before decryption so that a replayed packet
        // is rejected without spending CPU on the AEAD.
        if self.recv_window.is_duplicate(seq) {
            return Ok(None);
        }

        let ciphertext = &bytes[HEADER_LEN..];
        let inner = self.recv.open(ciphertext)?;

        // Only record the sequence number after successful decryption: a
        // forged packet must not consume a slot in the replay window.
        if !self.recv_window.accept(seq) {
            return Ok(None);
        }

        Ok(Packet::parse_inner(&inner))
    }

    /// The next sequence number that will be used.
    pub fn next_sequence(&self) -> u64 {
        self.send_seq
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("send_seq", &self.send_seq)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::TYPE_FRAME;

    fn pair() -> (Session, Session) {
        let key_a = SymmetricKey::generate().unwrap();
        let key_b = SymmetricKey::generate().unwrap();
        (
            Session::new(key_a.clone(), key_b.clone()),
            Session::new(key_b, key_a),
        )
    }

    #[test]
    fn packet_roundtrip() {
        let (mut a, mut b) = pair();
        let p = Packet::new(TYPE_FRAME, b"hello world".to_vec());
        let bytes = a.seal(&p).unwrap();
        let out = b.open(&bytes).unwrap().unwrap();
        assert_eq!(out, p);
    }

    #[test]
    fn data_packets_have_the_magic_prefix() {
        let (mut a, _) = pair();
        let bytes = a.seal(&Packet::new(TYPE_FRAME, vec![1])).unwrap();
        assert_eq!(&bytes[..4], &PACKET_MAGIC[..]);
        assert!(crate::packet::is_data_packet(&bytes));
        assert!(!crate::packet::is_handshake_packet(&bytes));
    }

    #[test]
    fn handshake_messages_are_distinguishable() {
        // A handshake message starts with the native magic prefix.
        assert!(crate::packet::is_handshake_packet(&[
            0x00, 0x5a, 0x54, 0x01, 0x00
        ]));
        assert!(crate::packet::is_handshake_packet(&[
            0x00, 0x5a, 0x54, 0x02, 0x00
        ]));
        assert!(!crate::packet::is_data_packet(&[0x00, 0x5a, 0x54, 0x01]));
        // A datagram without the magic is neither a handshake nor data.
        assert!(!crate::packet::is_handshake_packet(&[0x01, 0x00]));
        assert!(!crate::packet::is_data_packet(&[0x01, 0x00]));
        // A data packet is never mistaken for a handshake message.
        let (mut a, _) = pair();
        let bytes = a.seal(&Packet::new(TYPE_FRAME, vec![1])).unwrap();
        assert!(!crate::packet::is_handshake_packet(&bytes));
    }

    #[test]
    fn multiple_packets_in_order() {
        let (mut a, mut b) = pair();
        for i in 0..10u8 {
            let p = Packet::new(TYPE_FRAME, vec![i]);
            let bytes = a.seal(&p).unwrap();
            assert_eq!(b.open(&bytes).unwrap().unwrap(), p);
        }
    }

    #[test]
    fn replayed_packet_is_rejected() {
        let (mut a, mut b) = pair();
        let p = Packet::new(TYPE_FRAME, b"once".to_vec());
        let bytes = a.seal(&p).unwrap();
        assert!(b.open(&bytes).unwrap().is_some());
        // The same bytes again must be rejected.
        assert!(b.open(&bytes).unwrap().is_none());
    }

    #[test]
    fn tampered_packet_fails_authentication() {
        let (mut a, mut b) = pair();
        let mut bytes = a.seal(&Packet::new(TYPE_FRAME, b"data".to_vec())).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        assert!(b.open(&bytes).is_err());
    }

    #[test]
    fn truncated_packet_is_rejected() {
        let (mut a, mut b) = pair();
        let bytes = a.seal(&Packet::new(TYPE_FRAME, b"data".to_vec())).unwrap();
        assert!(b.open(&bytes[..5]).is_err());
    }

    #[test]
    fn non_magic_prefix_is_rejected() {
        let (mut a, mut b) = pair();
        let mut bytes = a.seal(&Packet::new(TYPE_FRAME, b"data".to_vec())).unwrap();
        bytes[0] = 0xff;
        assert!(b.open(&bytes).is_err());
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let (mut a, _) = pair();
        let p = Packet::new(TYPE_FRAME, vec![0u8; MAX_PAYLOAD + 1]);
        assert!(a.seal(&p).is_err());
    }
}
