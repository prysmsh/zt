//! An established session: the data plane after a successful handshake.
//!
//! A [`Session`] owns the directional transport ciphers and the replay
//! protection windows. It is the object the node's peer-management layer
//! actually holds once a handshake completes.

use crate::error::{Error, Result};
use crate::noise::TransportCipher;
use crate::packet::{Packet, ReceiveWindow, HEADER_LEN, MAX_PAYLOAD};
use crate::symmetric::SymmetricKey;

/// Length of the session identifier.
pub const SESSION_ID_LEN: usize = 4;

/// An established, encrypted session between two peers.
pub struct Session {
    /// The session identifier, unique per handshake.
    pub session_id: [u8; SESSION_ID_LEN],
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
    ///
    /// `session_id` must be unique for this peer pair; reusing one across
    /// sessions would allow ciphertexts from an old session to be replayed
    /// into a new one.
    pub fn new(
        session_id: [u8; SESSION_ID_LEN],
        send_key: SymmetricKey,
        recv_key: SymmetricKey,
    ) -> Session {
        Session {
            session_id,
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
        out.extend_from_slice(&self.session_id);
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

        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id.copy_from_slice(&bytes[..SESSION_ID_LEN]);
        if session_id != self.session_id {
            return Err(Error::InvalidKey("wrong session"));
        }

        let seq_start = SESSION_ID_LEN;
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
            .field("session_id", &hex::encode(self.session_id))
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
        let id = [1u8, 2, 3, 4];
        (
            Session::new(id, key_a.clone(), key_b.clone()),
            Session::new(id, key_b, key_a),
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
    fn wrong_session_is_rejected() {
        let key_a = SymmetricKey::generate().unwrap();
        let key_b = SymmetricKey::generate().unwrap();
        let mut a = Session::new([1, 1, 1, 1], key_a.clone(), key_b.clone());
        let mut b = Session::new([2, 2, 2, 2], key_b, key_a);
        let bytes = a.seal(&Packet::new(TYPE_FRAME, vec![1])).unwrap();
        assert!(b.open(&bytes).is_err());
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
    fn oversized_payload_is_rejected() {
        let (mut a, _) = pair();
        let p = Packet::new(TYPE_FRAME, vec![0u8; MAX_PAYLOAD + 1]);
        assert!(a.seal(&p).is_err());
    }
}
