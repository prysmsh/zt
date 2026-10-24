//! The ZT-next handshake.
//!
//! # Pattern
//!
//! ZT-next uses a Noise-**IK**-style pattern: the initiator knows the
//! responder's static public key beforehand, so the responder's identity is
//! authenticated in the first message and the handshake completes in one
//! round trip.
//!
//! ```text
//! Initiator                                Responder
//!    │                                         │
//!    ├── msg1 ────────────────────────────────▶│
//!    │    e, s, mlkem_ek, payload              │
//!    │                                         │
//!    │◀── msg2 ────────────────────────────────┤
//!    │    e, mlkem_ct, payload                 │
//!    │                                         │
//!    ├── transport keys derived ───────────────┤
//! ```
//!
//! # Message framing
//!
//! Every message is a sequence of length-prefixed fields:
//!
//! ```text
//! <[1] message type>
//! <[1] field tag> <[2] field length> <[..] field value> ...
//! ```
//!
//! Fields are self-describing, so a field the receiver does not recognise
//! can be skipped rather than causing a parse failure. This is what allows
//! the protocol to be extended without breaking older peers.
//!
//! # Post-quantum augmentation
//!
//! Standard Noise has no post-quantum DH. ZT-next adds an ML-KEM-768
//! exchange in parallel to the X25519 one:
//!
//! - The initiator sends its ML-KEM encapsulation key in `msg1`.
//! - The responder encapsulates to it, producing a ciphertext and shared
//!   secret, and sends the ciphertext in `msg2`.
//! - The initiator decapsulates, recovering the same shared secret.
//!
//! The X25519 and ML-KEM shared secrets are combined via HKDF, matching
//! `draft-ietf-tls-hybrid-design`.
//!
//! # Why the static keys are not used for DH
//!
//! Noise IK mixes `es` and `se` — DH between an ephemeral and the peer's
//! *static* key. ZT-next's static key is Ed25519, which cannot perform DH.
//! The responder's static DH contribution therefore comes from its
//! *ephemeral* plus the ML-KEM exchange instead.
//!
//! This does not weaken the construction. The responder's long-term
//! identity is still authenticated, by its **signature over the
//! transcript** rather than by a DH contribution. The ephemeral exchange
//! provides forward secrecy, and the signature provides authentication.
//!
//! # Signature authentication
//!
//! After the DH chain completes, each party signs the transcript hash with
//! its hybrid key (Ed25519 ‖ ML-DSA-65). Because the transcript hash covers
//! the negotiated suite id and all exchanged public keys, a party that
//! substitutes a key or downgrades the suite produces a different hash and
//! the signature check fails.
//!
//! # Downgrade protection
//!
//! The negotiated suite id is mixed into the transcript hash before any key
//! material. A peer that negotiates one suite but performs another produces
//! a different transcript and the signature check fails.

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::noise::{SymmetricState, PROTOCOL_NAME};
use crate::pq::{KemSuite, MlDsa65KeyPair, SigSuite};
use crate::symmetric::SymmetricKey;

/// Maximum size of a handshake message.
pub const MAX_HANDSHAKE_MESSAGE: usize = 16384;

/// Message type: handshake initiation.
pub const MSG_INIT: u8 = 0x01;
/// Message type: handshake response.
pub const MSG_RESPONSE: u8 = 0x02;

/// Field tag: ephemeral X25519 public key.
pub const TAG_EPHEMERAL: u8 = 0x01;
/// Field tag: static Ed25519 public key.
pub const TAG_STATIC: u8 = 0x02;
/// Field tag: ML-KEM-768 encapsulation key or ciphertext.
pub const TAG_MLKEM: u8 = 0x03;
/// Field tag: encrypted payload.
pub const TAG_PAYLOAD: u8 = 0x04;

/// The number of signature bytes for a given signature suite.
///
/// The hybrid suite carries both an Ed25519 and an ML-DSA-65 signature; the
/// pure suites carry one.
pub fn signature_len(sig_suite: SigSuite) -> usize {
    match sig_suite {
        SigSuite::Ed25519 => 64,
        SigSuite::MlDsa65 => crate::pq::ML_DSA_65_SIG_LEN,
        SigSuite::HybridEd25519MlDsa65 => 64 + crate::pq::ML_DSA_65_SIG_LEN,
    }
}

/// Sign a message with the given suite, returning the signature bytes.
///
/// For the hybrid suite the result is `Ed25519 ‖ ML-DSA-65`.
pub fn sign_message(
    identity: &Identity,
    pq: &MlDsa65KeyPair,
    sig_suite: SigSuite,
    msg: &[u8],
) -> Result<Vec<u8>> {
    match sig_suite {
        SigSuite::Ed25519 => Ok(identity.sign(msg).to_vec()),
        SigSuite::MlDsa65 => pq.sign(msg),
        SigSuite::HybridEd25519MlDsa65 => {
            let mut out = identity.sign(msg).to_vec();
            out.extend_from_slice(&pq.sign(msg)?);
            Ok(out)
        }
    }
}

/// Verify a signature produced by [`sign_message`].
pub fn verify_message(
    sig_suite: SigSuite,
    ed25519_key: &[u8; 32],
    ml_dsa_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<()> {
    match sig_suite {
        SigSuite::Ed25519 => {
            if signature.len() != 64 {
                return Err(Error::InvalidLength);
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(signature);
            Identity::verify(ed25519_key, msg, &sig)
        }
        SigSuite::MlDsa65 => MlDsa65KeyPair::verify(ml_dsa_key, msg, signature),
        SigSuite::HybridEd25519MlDsa65 => {
            if signature.len() != 64 + crate::pq::ML_DSA_65_SIG_LEN {
                return Err(Error::InvalidLength);
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&signature[..64]);
            Identity::verify(ed25519_key, msg, &sig)?;
            MlDsa65KeyPair::verify(ml_dsa_key, msg, &signature[64..])
        }
    }
}

/// The static identity material for one side of a handshake.
#[derive(Clone)]
pub struct StaticIdentity {
    /// The Ed25519 identity key.
    pub identity: Identity,
    /// The ML-DSA-65 signing key.
    pub pq: MlDsa65KeyPair,
}

impl StaticIdentity {
    /// Create a static identity from an Ed25519 key, generating an ML-DSA
    /// key for it.
    pub fn new(identity: Identity) -> Result<Self> {
        Ok(Self {
            identity,
            pq: MlDsa65KeyPair::generate()?,
        })
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key_bytes()
    }

    /// The ML-DSA-65 public key.
    pub fn pq_public_key(&self) -> Vec<u8> {
        self.pq.public_key()
    }

    /// Produce an independent copy of this identity.
    ///
    /// A handshake needs its own copy of the static key material, so that
    /// the owning node can keep using its identity for subsequent
    /// handshakes.
    pub fn clone_identity(&self) -> StaticIdentity {
        self.clone()
    }
}

impl core::fmt::Debug for StaticIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticIdentity")
            .field("public_key", &hex::encode(self.public_key()))
            .finish()
    }
}

/// The client's view of a peer, as known before the handshake.
#[derive(Clone, Debug)]
pub struct PeerStatic {
    /// The peer's Ed25519 public key.
    pub ed25519: [u8; 32],
    /// The peer's ML-DSA-65 public key.
    pub ml_dsa: Vec<u8>,
}

/// The result of a completed handshake.
pub struct HandshakeResult {
    /// Key for encrypting messages we send.
    pub send_key: SymmetricKey,
    /// Key for decrypting messages we receive.
    pub recv_key: SymmetricKey,
    /// The negotiated key agreement suite.
    pub kem_suite: KemSuite,
    /// The negotiated signature suite.
    pub sig_suite: SigSuite,
    /// The final transcript hash.
    pub transcript_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Field framing
// ---------------------------------------------------------------------------

/// A parsed message: a list of tagged fields.
pub struct Message {
    /// The message type.
    pub msg_type: u8,
    /// The fields, in order.
    pub fields: Vec<(u8, Vec<u8>)>,
}

impl Message {
    /// Find a field by tag.
    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, v)| v.as_slice())
    }

    /// Serialize to the wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(self.msg_type);
        for (tag, value) in &self.fields {
            out.push(*tag);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// Parse from the wire format.
    ///
    /// A message must contain at least the type byte and one complete field.
    /// A bare type byte is rejected: accepting it would allow an empty
    /// message to be treated as valid.
    pub fn deserialize(bytes: &[u8]) -> Result<Message> {
        if bytes.len() < 4 {
            return Err(Error::InvalidLength);
        }
        let msg_type = bytes[0];
        let mut pos = 1usize;
        let mut fields = Vec::new();

        while pos < bytes.len() {
            if bytes.len() < pos + 3 {
                return Err(Error::InvalidLength);
            }
            let tag = bytes[pos];
            let len = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
            pos += 3;
            if bytes.len() < pos + len {
                return Err(Error::InvalidLength);
            }
            fields.push((tag, bytes[pos..pos + len].to_vec()));
            pos += len;
        }

        if fields.is_empty() {
            return Err(Error::InvalidLength);
        }

        Ok(Message { msg_type, fields })
    }
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Message")
            .field("msg_type", &self.msg_type)
            .field(
                "fields",
                &self
                    .fields
                    .iter()
                    .map(|(t, v)| (*t, v.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl core::fmt::Debug for HandshakeResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeResult")
            .field("kem_suite", &self.kem_suite)
            .field("sig_suite", &self.sig_suite)
            .field("transcript_hash", &hex::encode(self.transcript_hash))
            .finish()
    }
}

impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Initiator")
            .field("kem_suite", &self.suite)
            .field("sig_suite", &self.sig_suite)
            .finish()
    }
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder")
            .field("kem_suite", &self.suite)
            .field("sig_suite", &self.sig_suite)
            .finish()
    }
}

/// The initiator's handshake state.
pub struct Initiator {
    suite: KemSuite,
    sig_suite: SigSuite,
    /// The symmetric state, exposed for diagnostics and testing.
    pub state: SymmetricState,
    static_identity: StaticIdentity,
    peer: PeerStatic,
    x25519_ephemeral: Option<[u8; 32]>,
    mlkem_dk: Option<crate::pq::MlKem768KeyPair>,
}

impl Initiator {
    /// Begin a handshake as the initiator.
    ///
    /// `peer` is the responder's static public key, which the initiator must
    /// already know.
    pub fn begin(
        static_identity: StaticIdentity,
        peer: PeerStatic,
        kem_suite: KemSuite,
        sig_suite: SigSuite,
    ) -> Result<Self> {
        let state = SymmetricState::new(PROTOCOL_NAME, kem_suite.to_u8());

        let mut x_eph = None;
        let mut mlkem_dk = None;

        if matches!(kem_suite, KemSuite::X25519 | KemSuite::HybridX25519MlKem768) {
            let mut secret = [0u8; 32];
            crate::key_agreement::fill_random(&mut secret)?;
            x_eph = Some(secret);
        }
        if matches!(
            kem_suite,
            KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768
        ) {
            mlkem_dk = Some(crate::pq::MlKem768KeyPair::generate()?);
        }

        Ok(Self {
            suite: kem_suite,
            sig_suite,
            state,
            static_identity,
            peer,
            x25519_ephemeral: x_eph,
            mlkem_dk,
        })
    }

    /// Produce the first message.
    pub fn write_message_1(&mut self) -> Result<Vec<u8>> {
        let mut fields: Vec<(u8, Vec<u8>)> = Vec::new();

        // --- e: the initiator's ephemeral X25519 public key ---
        if let Some(secret) = self.x25519_ephemeral {
            let public = crate::key_agreement::public_from_secret(&secret);
            self.state.mix_hash(&public);
            fields.push((TAG_EPHEMERAL, public.to_vec()));
        }

        // --- the initiator's static public key ---
        let static_public = self.static_identity.public_key();
        self.state.mix_hash(&static_public);
        fields.push((TAG_STATIC, static_public.to_vec()));

        // --- the initiator's ML-KEM encapsulation key ---
        if let Some(kp) = &self.mlkem_dk {
            let ek = kp.encapsulation_key();
            self.state.mix_hash(&ek);
            fields.push((TAG_MLKEM, ek));
        }

        // --- payload: the hybrid signature over the transcript ---
        // The payload is encrypted under a key derived by mixing the empty
        // input. The transcript hash embedded in the payload is the one
        // *after* that mixing, so both sides compute it at the same point.
        let key = self.state.mix_key_and_set(b"")?;
        let payload = self.build_signature_payload()?;
        let encrypted = self.state.encrypt_and_hash(&key, &payload)?;
        fields.push((TAG_PAYLOAD, encrypted));

        Ok(Message {
            msg_type: MSG_INIT,
            fields,
        }
        .serialize())
    }

    fn build_signature_payload(&self) -> Result<Vec<u8>> {
        let h = self.state.handshake_hash();
        let mut payload = Vec::with_capacity(h.len() + 64);
        payload.extend_from_slice(&h);
        payload.push(self.sig_suite.to_u8());
        // Both parties must sign over the *same* bytes. The canonical order
        // is initiator's ML-DSA key then responder's, regardless of which
        // side is building the payload.
        payload.extend_from_slice(&self.initiator_ml_dsa_key());
        payload.extend_from_slice(&self.responder_ml_dsa_key());

        // The signature is appended after the keys it covers.
        let signed = payload.clone();
        let sig = sign_message(
            &self.static_identity.identity,
            &self.static_identity.pq,
            self.sig_suite,
            &signed,
        )?;
        payload.extend_from_slice(&sig);
        Ok(payload)
    }

    /// The initiator's ML-DSA public key, in canonical position.
    fn initiator_ml_dsa_key(&self) -> Vec<u8> {
        self.static_identity.pq_public_key()
    }

    /// The responder's ML-DSA public key, in canonical position.
    fn responder_ml_dsa_key(&self) -> Vec<u8> {
        self.peer.ml_dsa.clone()
    }

    /// Process the responder's second message and complete the handshake.
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<HandshakeResult> {
        let parsed = Message::deserialize(msg)?;
        if parsed.msg_type != MSG_RESPONSE {
            return Err(Error::InvalidKey("expected a handshake response"));
        }

        // --- e: the responder's ephemeral ---
        // The pure ML-KEM suite has no X25519 ephemeral.
        if let Some(eph_bytes) = parsed.get(TAG_EPHEMERAL) {
            if eph_bytes.len() != 32 {
                return Err(Error::InvalidLength);
            }
            let mut eph = [0u8; 32];
            eph.copy_from_slice(eph_bytes);
            self.state.mix_hash(&eph);

            // --- ee: DH between the ephemerals ---
            if let Some(secret) = self.x25519_ephemeral {
                let shared = crate::key_agreement::agree_raw(&secret, &eph)?;
                self.state.mix_key_and_set(&shared)?;
            }
        }

        // --- the responder's ML-KEM ciphertext ---
        if matches!(
            self.suite,
            KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768
        ) {
            let ct = parsed
                .get(TAG_MLKEM)
                .ok_or(Error::InvalidKey("missing ML-KEM ciphertext"))?;
            if ct.len() != crate::pq::ML_KEM_768_CT_LEN {
                return Err(Error::InvalidLength);
            }
            self.state.mix_hash(ct);
            let kp = self
                .mlkem_dk
                .as_ref()
                .ok_or(Error::InvalidKey("mlkem key missing"))?;
            let pq_shared = kp.decapsulate(ct)?;
            self.state.mix_key_and_set(&pq_shared)?;
        }

        // --- payload ---
        let encrypted = parsed
            .get(TAG_PAYLOAD)
            .ok_or(Error::InvalidKey("missing payload"))?;
        let key = self.state.mix_key_and_set(b"")?;
        // Capture the transcript hash at exactly the point the peer used to
        // build the payload: after the key mixing, before decryption.
        let expected_hash = self.state.handshake_hash();
        let payload = self.state.decrypt_and_hash(&key, encrypted)?;

        self.verify_signature(&payload, &expected_hash)?;

        let (send, recv) = self.state.split()?;
        Ok(HandshakeResult {
            send_key: send,
            recv_key: recv,
            kem_suite: self.suite,
            sig_suite: self.sig_suite,
            transcript_hash: self.state.handshake_hash(),
        })
    }

    fn verify_signature(&self, payload: &[u8], expected_hash: &[u8; 32]) -> Result<()> {
        // Canonical layout: hash (32) || sig_suite (1) || initiator_pq_key
        //                 || responder_pq_key || signature
        if payload.len() < 33 {
            return Err(Error::InvalidLength);
        }
        if &payload[..32] != expected_hash {
            return Err(Error::AuthenticationFailed);
        }
        if payload[32] != self.sig_suite.to_u8() {
            return Err(Error::AuthenticationFailed);
        }

        const PQ_KEY_LEN: usize = crate::pq::ML_DSA_65_PK_LEN;
        let responder_key_len = self.peer.ml_dsa.len();
        let sig_len = signature_len(self.sig_suite);
        if payload.len() < 33 + PQ_KEY_LEN + responder_key_len + sig_len {
            return Err(Error::InvalidLength);
        }

        // The initiator's key comes first in canonical order.
        let responder_key = &payload[33 + PQ_KEY_LEN..33 + PQ_KEY_LEN + responder_key_len];
        let signed = &payload[..33 + PQ_KEY_LEN + responder_key_len];
        let sig = &payload[33 + PQ_KEY_LEN + responder_key_len..];

        // The responder's key must match what we expected.
        if responder_key != self.peer.ml_dsa.as_slice() {
            return Err(Error::AuthenticationFailed);
        }

        verify_message(
            self.sig_suite,
            &self.peer.ed25519,
            responder_key,
            signed,
            sig,
        )
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// The responder's handshake state.
pub struct Responder {
    suite: KemSuite,
    sig_suite: SigSuite,
    /// The symmetric state, exposed for diagnostics and testing.
    pub state: SymmetricState,
    static_identity: StaticIdentity,
    x25519_ephemeral: Option<[u8; 32]>,
    peer_ephemeral: Option<[u8; 32]>,
    pending_ek: Option<Vec<u8>>,
    peer_ed25519: Option<[u8; 32]>,
    peer_ml_dsa: Vec<u8>,
}

impl Responder {
    /// Begin a handshake as the responder.
    pub fn begin(
        static_identity: StaticIdentity,
        kem_suite: KemSuite,
        sig_suite: SigSuite,
    ) -> Result<Self> {
        let state = SymmetricState::new(PROTOCOL_NAME, kem_suite.to_u8());

        let mut x_eph = None;

        if matches!(kem_suite, KemSuite::X25519 | KemSuite::HybridX25519MlKem768) {
            let mut secret = [0u8; 32];
            crate::key_agreement::fill_random(&mut secret)?;
            x_eph = Some(secret);
        }

        Ok(Self {
            suite: kem_suite,
            sig_suite,
            state,
            static_identity,
            x25519_ephemeral: x_eph,
            peer_ephemeral: None,
            pending_ek: None,
            peer_ed25519: None,
            peer_ml_dsa: Vec::new(),
        })
    }

    /// Process the initiator's first message.
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<()> {
        let parsed = Message::deserialize(msg)?;
        if parsed.msg_type != MSG_INIT {
            return Err(Error::InvalidKey("expected a handshake initiation"));
        }

        // --- e: the responder's ephemeral ---
        // The pure ML-KEM suite has no X25519 ephemeral; the ML-KEM exchange
        // provides the key agreement instead.
        if let Some(eph_bytes) = parsed.get(TAG_EPHEMERAL) {
            if eph_bytes.len() != 32 {
                return Err(Error::InvalidLength);
            }
            let mut eph = [0u8; 32];
            eph.copy_from_slice(eph_bytes);
            self.peer_ephemeral = Some(eph);
            self.state.mix_hash(&eph);
        }

        // --- the initiator's static key ---
        let static_public = parsed
            .get(TAG_STATIC)
            .ok_or(Error::InvalidKey("missing static key"))?;
        if static_public.len() != 32 {
            return Err(Error::InvalidLength);
        }
        let mut peer_ed = [0u8; 32];
        peer_ed.copy_from_slice(static_public);
        self.peer_ed25519 = Some(peer_ed);
        self.state.mix_hash(&peer_ed);

        // --- the initiator's ML-KEM encapsulation key ---
        if matches!(
            self.suite,
            KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768
        ) {
            let ek = parsed
                .get(TAG_MLKEM)
                .ok_or(Error::InvalidKey("missing ML-KEM key"))?;
            if ek.len() != crate::pq::ML_KEM_768_EK_LEN {
                return Err(Error::InvalidLength);
            }
            self.state.mix_hash(ek);
            self.pending_ek = Some(ek.to_vec());
        }

        // --- payload ---
        let encrypted = parsed
            .get(TAG_PAYLOAD)
            .ok_or(Error::InvalidKey("missing payload"))?;
        let key = self.state.mix_key_and_set(b"")?;
        // The peer built the payload at this exact point in the transcript.
        let expected_hash = self.state.handshake_hash();
        let payload = self.state.decrypt_and_hash(&key, encrypted)?;
        self.verify_initiator_signature(&payload, &expected_hash)?;

        Ok(())
    }

    /// Produce the second message.
    pub fn write_message_2(&mut self) -> Result<Vec<u8>> {
        let mut fields: Vec<(u8, Vec<u8>)> = Vec::new();

        // --- e: the responder's ephemeral ---
        // The pure ML-KEM suite has no X25519 ephemeral; the ML-KEM exchange
        // provides the key agreement instead.
        if let Some(eph_secret) = self.x25519_ephemeral {
            let eph_public = crate::key_agreement::public_from_secret(&eph_secret);
            self.state.mix_hash(&eph_public);
            fields.push((TAG_EPHEMERAL, eph_public.to_vec()));
        }

        // --- ee ---
        // The initiator's ephemeral was mixed into the transcript; the DH
        // contribution is computed from the responder's ephemeral secret and
        // the initiator's ephemeral public key, which the responder keeps.
        if let Some(shared) = self.peer_ephemeral_shared() {
            self.state.mix_key_and_set(&shared)?;
        }

        // --- the ML-KEM ciphertext ---
        if matches!(
            self.suite,
            KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768
        ) {
            let ek = self
                .pending_ek
                .as_ref()
                .ok_or(Error::InvalidKey("no peer ML-KEM key"))?;
            let (ct, ss) = encapsulate_to(ek)?;
            self.state.mix_hash(&ct);
            self.state.mix_key_and_set(&ss)?;
            fields.push((TAG_MLKEM, ct));
        }

        // --- payload ---
        let key = self.state.mix_key_and_set(b"")?;
        let payload = self.build_signature_payload()?;
        let encrypted = self.state.encrypt_and_hash(&key, &payload)?;
        fields.push((TAG_PAYLOAD, encrypted));

        Ok(Message {
            msg_type: MSG_RESPONSE,
            fields,
        }
        .serialize())
    }

    /// Split the chaining key into the responder's directional traffic keys.
    ///
    /// Returns `(send_key, recv_key)`. These are the mirror of the
    /// initiator's: the responder's send key is the initiator's receive key.
    pub fn split_traffic_keys(&self) -> Result<(SymmetricKey, SymmetricKey)> {
        self.state.split_responder()
    }

    /// The final transcript hash.
    ///
    /// Both sides compute the same value, so it can be used as a shared
    /// session nonce.
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.state.handshake_hash()
    }

    fn peer_ephemeral_shared(&self) -> Option<[u8; 32]> {
        let secret = self.x25519_ephemeral?;
        let peer = self.peer_ephemeral?;
        crate::key_agreement::agree_raw(&secret, &peer).ok()
    }

    fn build_signature_payload(&self) -> Result<Vec<u8>> {
        let h = self.state.handshake_hash();
        let mut payload = Vec::with_capacity(h.len() + 64);
        payload.extend_from_slice(&h);
        payload.push(self.sig_suite.to_u8());
        // Canonical order: initiator's key first, then the responder's.
        payload.extend_from_slice(&self.peer_ml_dsa);
        payload.extend_from_slice(&self.static_identity.pq_public_key());

        let signed = payload.clone();
        let sig = sign_message(
            &self.static_identity.identity,
            &self.static_identity.pq,
            self.sig_suite,
            &signed,
        )?;
        payload.extend_from_slice(&sig);
        Ok(payload)
    }

    fn verify_initiator_signature(
        &mut self,
        payload: &[u8],
        expected_hash: &[u8; 32],
    ) -> Result<()> {
        // Canonical layout: hash (32) || sig_suite (1) || initiator_pq_key
        //                 || responder_pq_key || signature
        if payload.len() < 33 {
            return Err(Error::InvalidLength);
        }
        if &payload[..32] != expected_hash {
            return Err(Error::AuthenticationFailed);
        }
        if payload[32] != self.sig_suite.to_u8() {
            return Err(Error::AuthenticationFailed);
        }

        const PQ_KEY_LEN: usize = crate::pq::ML_DSA_65_PK_LEN;
        let responder_key_len = self.static_identity.pq_public_key().len();
        let sig_len = signature_len(self.sig_suite);
        if payload.len() < 33 + PQ_KEY_LEN + responder_key_len + sig_len {
            return Err(Error::InvalidLength);
        }

        let initiator_pq_key = &payload[33..33 + PQ_KEY_LEN];
        let responder_pq_key = &payload[33 + PQ_KEY_LEN..33 + PQ_KEY_LEN + responder_key_len];
        self.peer_ml_dsa = initiator_pq_key.to_vec();

        // The responder's own key must match.
        if responder_pq_key != self.static_identity.pq_public_key().as_slice() {
            return Err(Error::AuthenticationFailed);
        }

        let signed = &payload[..33 + PQ_KEY_LEN + responder_key_len];
        let sig = &payload[33 + PQ_KEY_LEN + responder_key_len..];

        let peer_ed = self.peer_ed25519.ok_or(Error::InvalidKey("no peer key"))?;
        verify_message(self.sig_suite, &peer_ed, initiator_pq_key, signed, sig)
    }
}

/// Encapsulate to a peer's ML-KEM encapsulation key.
fn encapsulate_to(peer_ek: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    use ml_kem::{Encapsulate as _, TryKeyInit as _};

    let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(peer_ek)
        .map_err(|_| Error::InvalidKey("bad ML-KEM encapsulation key"))?;

    let mut seed = [0u8; 32];
    crate::symmetric::fill_secure_random(&mut seed);
    use rand_pq::SeedableRng;
    let mut rng = rand_pq::rngs::StdRng::from_seed(seed);
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_ref());
    let ct_bytes: &[u8] = ct.as_ref();
    Ok((ct_bytes.to_vec(), out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> (StaticIdentity, StaticIdentity) {
        let client = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
        let server = StaticIdentity::new(Identity::generate().unwrap()).unwrap();
        (client, server)
    }

    fn peer_of(s: &StaticIdentity) -> PeerStatic {
        PeerStatic {
            ed25519: s.public_key(),
            ml_dsa: s.pq_public_key(),
        }
    }

    fn full_handshake(kem: KemSuite, sig: SigSuite) -> Result<HandshakeResult> {
        let (client, server) = identities();
        let mut init = Initiator::begin(client, peer_of(&server), kem, sig)?;
        let mut resp = Responder::begin(server, kem, sig)?;

        let m1 = init.write_message_1()?;
        resp.read_message_1(&m1)?;
        let m2 = resp.write_message_2()?;
        init.read_message_2(&m2)
    }

    #[test]
    fn message_roundtrips() {
        let m = Message {
            msg_type: MSG_INIT,
            fields: vec![(TAG_EPHEMERAL, vec![1u8; 32]), (TAG_STATIC, vec![2u8; 32])],
        };
        let ser = m.serialize();
        let parsed = Message::deserialize(&ser).unwrap();
        assert_eq!(parsed.msg_type, MSG_INIT);
        assert_eq!(parsed.get(TAG_EPHEMERAL).unwrap(), &[1u8; 32]);
        assert_eq!(parsed.get(TAG_STATIC).unwrap(), &[2u8; 32]);
    }

    #[test]
    fn message_parsing_rejects_truncation() {
        let m = Message {
            msg_type: MSG_INIT,
            fields: vec![(TAG_EPHEMERAL, vec![1u8; 32])],
        };
        let ser = m.serialize();
        for len in 1..ser.len() {
            assert!(Message::deserialize(&ser[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn handshake_completes_with_hybrid() {
        let r = full_handshake(
            KemSuite::HybridX25519MlKem768,
            SigSuite::HybridEd25519MlDsa65,
        )
        .unwrap();
        assert_eq!(r.kem_suite, KemSuite::HybridX25519MlKem768);
        assert_ne!(r.send_key.as_bytes(), r.recv_key.as_bytes());
    }

    #[test]
    fn handshake_completes_with_pure_pq() {
        let r = full_handshake(KemSuite::MlKem768, SigSuite::MlDsa65).unwrap();
        assert_eq!(r.kem_suite, KemSuite::MlKem768);
    }

    #[test]
    fn handshake_completes_with_classical() {
        let r = full_handshake(KemSuite::X25519, SigSuite::Ed25519).unwrap();
        assert_eq!(r.kem_suite, KemSuite::X25519);
    }

    #[test]
    fn both_sides_derive_the_same_keys() {
        let (client, server) = identities();
        let mut init = Initiator::begin(
            client,
            peer_of(&server),
            KemSuite::HybridX25519MlKem768,
            SigSuite::HybridEd25519MlDsa65,
        )
        .unwrap();
        let mut resp = Responder::begin(
            server,
            KemSuite::HybridX25519MlKem768,
            SigSuite::HybridEd25519MlDsa65,
        )
        .unwrap();

        let m1 = init.write_message_1().unwrap();
        resp.read_message_1(&m1).unwrap();
        let m2 = resp.write_message_2().unwrap();
        let client_result = init.read_message_2(&m2).unwrap();

        // The responder's keys are the mirror of the initiator's.
        let (resp_send, resp_recv) = resp.split_traffic_keys().unwrap();
        assert_eq!(client_result.send_key.as_bytes(), resp_recv.as_bytes());
        assert_eq!(client_result.recv_key.as_bytes(), resp_send.as_bytes());
    }
}
