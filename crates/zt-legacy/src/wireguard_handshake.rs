//! The WireGuard handshake.
//!
//! Two parties, an initiator and a responder, exchange two messages and end
//! up with the same transport keys. The transcript is a chain, so every
//! message advances it and a peer that replays an old message cannot
//! produce a matching transcript.
//!
//! The order of operations matters. Both sides must mix the same values into
//! the transcript in the same order, even though they reach them by
//! different routes: the initiator knows the responder's static key because
//! it dialled it, and the responder because it owns it.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wireguard::{
    hash, initial_chain_key, kdf3, mix_hash, SessionKeys, StaticKey, Transcript, KEY_LEN,
};
use crate::wireguard_message::{
    mac1_key, timestamp_now, MessageError, MessageInitiation, MessageResponse, MAC_LEN,
    MESSAGE_INITIATION, MESSAGE_RESPONSE,
};

/// The nonce used to encrypt the static key and the timestamp.
///
/// WireGuard uses an all-zero nonce for both, because the keys are derived
/// fresh for each use.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Errors from the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// The message was malformed.
    Message(MessageError),
    /// The message did not authenticate.
    AuthenticationFailed,
    /// The handshake was already complete.
    AlreadyComplete,
    /// A random value could not be produced.
    RandomFailed,
}

impl From<MessageError> for HandshakeError {
    fn from(error: MessageError) -> Self {
        Self::Message(error)
    }
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Message(error) => write!(f, "{error}"),
            Self::AuthenticationFailed => write!(f, "the handshake message did not authenticate"),
            Self::AlreadyComplete => write!(f, "the handshake is already complete"),
            Self::RandomFailed => write!(f, "a random value could not be produced"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Fill a buffer with random bytes.
fn random_bytes(buffer: &mut [u8]) -> Result<(), HandshakeError> {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buffer);
    Ok(())
}

/// A random index, used to route handshake messages.
fn random_index() -> Result<u32, HandshakeError> {
    let mut bytes = [0u8; 4];
    random_bytes(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// The initiator's half of the handshake.
#[derive(Debug)]
pub struct Initiator {
    /// The initiator's long-term key.
    local_static: StaticKey,
    /// The responder's long-term key.
    remote_static: [u8; KEY_LEN],
    /// The shared secret between the two long-term keys.
    precomputed_static_static: [u8; KEY_LEN],
    /// The transcript.
    transcript: Transcript,
    /// The initiator's ephemeral key.
    local_ephemeral: StaticKey,
    /// The initiator's index.
    local_index: u32,
    /// The responder's index, learned from the response.
    remote_index: u32,
    /// The responder's ephemeral key, learned from the response.
    remote_ephemeral: [u8; KEY_LEN],
}

impl Initiator {
    /// Begin a handshake.
    ///
    /// `remote_static` is the responder's long-term key, which the
    /// initiator must already know.
    pub fn begin(
        local_static: StaticKey,
        remote_static: [u8; KEY_LEN],
    ) -> Result<Self, HandshakeError> {
        let precomputed_static_static =
            local_static.diffie_hellman(&PublicKey::from(remote_static));

        let mut secret = [0u8; KEY_LEN];
        random_bytes(&mut secret)?;
        let local_ephemeral = StaticKey::from_secret(secret);

        Ok(Self {
            transcript: Transcript::start(&remote_static),
            local_static,
            remote_static,
            precomputed_static_static,
            local_ephemeral,
            local_index: random_index()?,
            remote_index: 0,
            remote_ephemeral: [0u8; KEY_LEN],
        })
    }

    /// Build the initiation message.
    pub fn create_initiation(&mut self) -> Result<MessageInitiation, HandshakeError> {
        let ephemeral = self.local_ephemeral.public_key_bytes();

        // The transcript advances with the ephemeral key before the static
        // key is encrypted, so the encryption is bound to it.
        self.transcript.mix_key(&ephemeral);
        self.transcript.mix_hash(&ephemeral);

        // The static key is encrypted to the responder's static key.
        let shared = self
            .local_ephemeral
            .diffie_hellman(&PublicKey::from(self.remote_static));
        let key = self.transcript.derive_message_key(&shared);

        let mut static_key = [0u8; KEY_LEN + 16];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &self.local_static.public_key_bytes(),
                    aad: &self.transcript.hash(),
                },
            )
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        static_key.copy_from_slice(&sealed);
        self.transcript.mix_hash(&static_key);

        // The timestamp is encrypted with the long-term shared secret, so a
        // replay is detected by the responder.
        let key = self
            .transcript
            .derive_message_key(&self.precomputed_static_static);
        let timestamp = timestamp_now();
        let mut sealed_timestamp = [0u8; 12 + 16];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &timestamp,
                    aad: &self.transcript.hash(),
                },
            )
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        sealed_timestamp.copy_from_slice(&sealed);
        self.transcript.mix_hash(&sealed_timestamp);

        let mut message = MessageInitiation {
            message_type: MESSAGE_INITIATION,
            sender: self.local_index,
            ephemeral,
            static_key,
            timestamp: sealed_timestamp,
            mac1: [0u8; MAC_LEN],
            mac2: [0u8; MAC_LEN],
        };

        // The first authentication tag is keyed by the responder's static
        // key, because only the two of them can derive it.
        message.set_mac1(&self.remote_static);

        Ok(message)
    }

    /// Consume the responder's response and derive the transport keys.
    pub fn consume_response(
        &mut self,
        message: &MessageResponse,
    ) -> Result<SessionKeys, HandshakeError> {
        // The responder's index must match the one the initiator sent.
        if message.receiver != self.local_index {
            return Err(HandshakeError::AuthenticationFailed);
        }

        // The response authenticates the responder, because its tag is
        // keyed by the initiator's static key.
        if !message.verify_mac1(&self.local_static.public_key_bytes()) {
            return Err(HandshakeError::AuthenticationFailed);
        }

        self.transcript.mix_hash(&message.ephemeral);
        self.transcript.mix_key(&message.ephemeral);

        // The two Diffie-Hellman exchanges, mixed into the chaining key.
        let shared = self
            .local_ephemeral
            .diffie_hellman(&PublicKey::from(message.ephemeral));
        self.transcript.mix_key(&shared);

        let shared = self
            .local_static
            .diffie_hellman(&PublicKey::from(message.ephemeral));
        self.transcript.mix_key(&shared);

        // The preshared key, which is all zeros for a plain peer. The
        // third output is the key for the empty payload; the first is the
        // new chaining key.
        let (chain_key, tau, key) = kdf3(&self.transcript.chain_key(), &[0u8; 32]);
        self.transcript.set_chain_key(chain_key);
        self.transcript.mix_hash(&tau);

        // The empty payload, encrypted to prove the responder knows the
        // chain key.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let empty = cipher
            .encrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &[],
                    aad: &self.transcript.hash(),
                },
            )
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        self.transcript.mix_hash(&empty);

        // The responder's copy of the empty payload has to match.
        if empty != message.empty {
            return Err(HandshakeError::AuthenticationFailed);
        }

        self.remote_index = message.sender;
        self.remote_ephemeral = message.ephemeral;

        Ok(crate::wireguard::derive_session_keys(
            &self.transcript.chain_key(),
        ))
    }
}

/// The responder's half of the handshake.
#[derive(Debug)]
pub struct Responder {
    /// The responder's long-term key.
    local_static: StaticKey,
    /// The initiator's long-term key, learned from the initiation.
    remote_static: [u8; KEY_LEN],
    /// The shared secret between the two long-term keys.
    precomputed_static_static: [u8; KEY_LEN],
    /// The transcript.
    transcript: Transcript,
    /// The responder's ephemeral key.
    local_ephemeral: StaticKey,
    /// The responder's index.
    local_index: u32,
    /// The initiator's index.
    remote_index: u32,
    /// The initiator's ephemeral key.
    remote_ephemeral: [u8; KEY_LEN],
}

impl Responder {
    /// Begin a handshake.
    pub fn begin(local_static: StaticKey) -> Result<Self, HandshakeError> {
        let mut secret = [0u8; KEY_LEN];
        random_bytes(&mut secret)?;
        Self::begin_with_ephemeral(local_static, secret, None)
    }

    /// Begin a handshake with a chosen ephemeral key and index.
    ///
    /// The ephemeral key and the index are normally random. Taking them as
    /// parameters lets a handshake be replayed exactly, which is how the
    /// interoperability test checks the implementation against a captured
    /// exchange.
    pub fn begin_with_ephemeral(
        local_static: StaticKey,
        ephemeral: [u8; KEY_LEN],
        local_index: Option<u32>,
    ) -> Result<Self, HandshakeError> {
        Ok(Self {
            transcript: Transcript::start(&local_static.public_key_bytes()),
            local_static,
            remote_static: [0u8; KEY_LEN],
            precomputed_static_static: [0u8; KEY_LEN],
            local_ephemeral: StaticKey::from_secret(ephemeral),
            local_index: match local_index {
                Some(index) => index,
                None => random_index()?,
            },
            remote_index: 0,
            remote_ephemeral: [0u8; KEY_LEN],
        })
    }

    /// Consume an initiation and check that it authenticates.
    pub fn consume_initiation(
        &mut self,
        message: &MessageInitiation,
    ) -> Result<(), HandshakeError> {
        // The tag is keyed by the responder's own static key.
        if !message.verify_mac1(&self.local_static.public_key_bytes()) {
            return Err(HandshakeError::AuthenticationFailed);
        }

        self.transcript = Transcript::start(&self.local_static.public_key_bytes());
        self.transcript.mix_hash(&message.ephemeral);
        self.transcript.mix_key(&message.ephemeral);

        // Decrypt the initiator's static key.
        let shared = self
            .local_static
            .diffie_hellman(&PublicKey::from(message.ephemeral));
        let key = self.transcript.derive_message_key(&shared);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let opened = cipher
            .decrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &message.static_key,
                    aad: &self.transcript.hash(),
                },
            )
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let mut remote_static = [0u8; KEY_LEN];
        remote_static.copy_from_slice(&opened);
        self.transcript.mix_hash(&message.static_key);
        self.remote_static = remote_static;

        // Decrypt the timestamp, which proves the initiator is not replaying.
        self.precomputed_static_static = self
            .local_static
            .diffie_hellman(&PublicKey::from(remote_static));
        let key = self
            .transcript
            .derive_message_key(&self.precomputed_static_static);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let opened = cipher
            .decrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &message.timestamp,
                    aad: &self.transcript.hash(),
                },
            )
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let mut timestamp = [0u8; 12];
        timestamp.copy_from_slice(&opened);
        self.transcript.mix_hash(&message.timestamp);

        self.remote_ephemeral = message.ephemeral;
        self.remote_index = message.sender;

        Ok(())
    }

    /// The index this side sends its messages under.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// The initiator's static key, learned by decrypting the initiation.
    pub fn remote_static(&self) -> [u8; KEY_LEN] {
        self.remote_static
    }

    /// Build the response message.
    pub fn create_response(&mut self) -> Result<MessageResponse, HandshakeError> {
        let ephemeral = self.local_ephemeral.public_key_bytes();

        self.transcript.mix_hash(&ephemeral);
        self.transcript.mix_key(&ephemeral);

        // The two Diffie-Hellman exchanges.
        let shared = self
            .local_ephemeral
            .diffie_hellman(&PublicKey::from(self.remote_ephemeral));
        self.transcript.mix_key(&shared);

        let shared = self
            .local_ephemeral
            .diffie_hellman(&PublicKey::from(self.remote_static));
        self.transcript.mix_key(&shared);

        // The preshared key, which is all zeros for a plain peer.
        let (chain_key, tau, key) = kdf3(&self.transcript.chain_key(), &[0u8; 32]);
        self.transcript.mix_hash(&tau);

        // The empty payload, encrypted to prove the responder knows the
        // chain key.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let empty = cipher
            .encrypt(
                Nonce::from_slice(&ZERO_NONCE),
                Payload {
                    msg: &[],
                    aad: &self.transcript.hash(),
                },
            )
            .map_err(|_| HandshakeError::AuthenticationFailed)?;
        self.transcript.mix_hash(&empty);

        let mut empty_field = [0u8; 16];
        empty_field.copy_from_slice(&empty);

        let mut message = MessageResponse {
            message_type: MESSAGE_RESPONSE,
            sender: self.local_index,
            receiver: self.remote_index,
            ephemeral,
            empty: empty_field,
            mac1: [0u8; MAC_LEN],
            mac2: [0u8; MAC_LEN],
        };

        // The tag is keyed by the initiator's static key.
        message.set_mac1(&self.remote_static);

        // The chaining key is the one the session keys come from.
        self.transcript.set_chain_key(chain_key);

        Ok(message)
    }
}

/// The hash of a handshake state, exposed for testing.
pub fn state_hash(state: &[u8; 32]) -> [u8; 32] {
    mix_hash(state, &[])
}

/// A hash helper, exposed for testing.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    hash(data)
}

/// The mac1 key helper, exposed for testing.
pub fn peer_mac1_key(peer_static: &[u8; KEY_LEN]) -> [u8; 32] {
    mac1_key(peer_static)
}

/// A static key helper, exposed for testing.
pub fn key_from_secret(secret: [u8; KEY_LEN]) -> StaticKey {
    StaticKey::from_secret(secret)
}

/// The initial chaining key, exposed for testing.
pub fn chain_key_start() -> [u8; 32] {
    initial_chain_key()
}

/// A random secret, exposed for testing.
pub fn random_secret() -> Result<[u8; KEY_LEN], HandshakeError> {
    let mut secret = [0u8; KEY_LEN];
    random_bytes(&mut secret)?;
    Ok(secret)
}

/// A random index, exposed for testing.
pub fn random_handshake_index() -> Result<u32, HandshakeError> {
    random_index()
}

/// A static secret, exposed for testing.
pub fn static_secret(secret: [u8; KEY_LEN]) -> StaticSecret {
    StaticSecret::from(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The responder must reject an initiation whose tag does not verify.
    #[test]
    fn an_initiation_with_a_bad_tag_is_refused() {
        let initiator_static = key_from_secret([1u8; KEY_LEN]);
        let responder_static = key_from_secret([2u8; KEY_LEN]);

        let mut initiator =
            Initiator::begin(initiator_static, responder_static.public_key_bytes()).expect("begin");
        let mut responder = Responder::begin(responder_static).expect("begin");

        let mut initiation = initiator.create_initiation().expect("initiation");
        initiation.mac1[0] ^= 0xff;

        assert!(matches!(
            responder.consume_initiation(&initiation),
            Err(HandshakeError::AuthenticationFailed)
        ));
    }

    /// A response addressed to the wrong initiator must be refused.
    #[test]
    fn a_response_for_another_initiator_is_refused() {
        let initiator_static = key_from_secret([1u8; KEY_LEN]);
        let responder_static = key_from_secret([2u8; KEY_LEN]);

        let mut initiator =
            Initiator::begin(initiator_static, responder_static.public_key_bytes()).expect("begin");
        let mut responder = Responder::begin(responder_static).expect("begin");

        let initiation = initiator.create_initiation().expect("initiation");
        responder
            .consume_initiation(&initiation)
            .expect("consume initiation");
        let mut response = responder.create_response().expect("response");
        response.receiver ^= 0xff;

        assert!(matches!(
            initiator.consume_response(&response),
            Err(HandshakeError::AuthenticationFailed)
        ));
    }

    /// The two sides must agree on the transcript.
    #[test]
    fn both_sides_agree_on_the_transcript() {
        let initiator_static = key_from_secret([3u8; KEY_LEN]);
        let responder_static = key_from_secret([4u8; KEY_LEN]);

        let mut initiator =
            Initiator::begin(initiator_static, responder_static.public_key_bytes()).expect("begin");
        let mut responder = Responder::begin(responder_static).expect("begin");

        let initiation = initiator.create_initiation().expect("initiation");
        responder
            .consume_initiation(&initiation)
            .expect("consume initiation");
        let response = responder.create_response().expect("response");
        initiator
            .consume_response(&response)
            .expect("consume response");

        // The transcripts agree, so the chaining keys agree.
        assert_eq!(
            initiator.transcript.chain_key(),
            responder.transcript.chain_key()
        );
        assert_eq!(initiator.transcript.hash(), responder.transcript.hash());
    }

    /// The transport keys must match on both sides.
    #[test]
    fn the_transport_keys_match() {
        let initiator_static = key_from_secret([5u8; KEY_LEN]);
        let responder_static = key_from_secret([6u8; KEY_LEN]);

        let mut initiator =
            Initiator::begin(initiator_static, responder_static.public_key_bytes()).expect("begin");
        let mut responder = Responder::begin(responder_static).expect("begin");

        let initiation = initiator.create_initiation().expect("initiation");
        responder
            .consume_initiation(&initiation)
            .expect("consume initiation");
        let response = responder.create_response().expect("response");
        let initiator_keys = initiator
            .consume_response(&response)
            .expect("consume response");

        // The responder's chaining key is the same one, so it derives the
        // same keys with the roles reversed.
        let responder_keys =
            crate::wireguard::derive_session_keys(&responder.transcript.chain_key());

        assert_eq!(initiator_keys.initiator_send, responder_keys.initiator_send);
        assert_eq!(initiator_keys.responder_send, responder_keys.responder_send);
    }
}
