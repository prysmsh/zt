//! Hybrid key exchange with algorithm negotiation.
//!
//! This module implements the key-agreement half of the ZT-next handshake.
//! It is deliberately separate from the Noise state machine (M1 proper):
//! this layer owns *which* algorithms are used and *how* their outputs are
//! combined, while the Noise layer owns the message flow.
//!
//! # Flow
//!
//! ```text
//! Initiator                              Responder
//!    │                                       │
//!    ├─── kem_suite (negotiated) ───────────▶│
//!    ├─── x25519_pub (32 B) ───────────────▶│
//!    ├─── mlkem_ek (1184 B, if hybrid) ─────▶│
//!    │                                       │
//!    │◀── x25519_pub (32 B) ─────────────────┤
//!    │◀── mlkem_ct (1088 B, if hybrid) ──────┤
//!    │                                       │
//!    ├── both sides derive shared secret ────┤
//!    └── both sides derive traffic keys ─────┤
//! ```
//!
//! # Sizes
//!
//! | Suite | Initiator → Responder | Responder → Initiator |
//! |---|---|---|
//! | `X25519` | 32 B | 32 B |
//! | `MlKem768` | 1184 B (ek) | 1088 B (ct) |
//! | `HybridX25519MlKem768` | 1216 B | 1120 B |
//!
//! A hybrid handshake costs roughly **2.3 KB** in total. This is paid once
//! per session; the per-packet data path is unaffected.

use core::fmt;

use crate::error::{Error, Result};
use crate::key_agreement::{agree_raw, public_from_secret};
use crate::pq::{
    combine_hybrid_secret, KemSuite, MlKem768KeyPair, ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN,
};

/// Size of an X25519 public key.
pub const X25519_PK_LEN: usize = 32;

/// The ephemeral key material sent by one side of a handshake.
///
/// This bundles everything a peer needs to derive the shared secret. The
/// layout depends on the negotiated suite.
///
/// # ML-KEM direction
///
/// In an ML-KEM exchange the responder encapsulates to the initiator's
/// encapsulation key, so the *responder's* message carries the ML-KEM
/// **ciphertext** while the *initiator's* message carries the **encapsulation
/// key**. The [`role`](KemRole) field records which side sent the message
/// so the two are never confused.
#[derive(Clone, PartialEq, Eq)]
pub struct KemEphemeral {
    /// The negotiated suite this material belongs to.
    pub suite: KemSuite,
    /// Which side of the exchange sent this message.
    pub role: KemRole,
    /// X25519 public key, present for `X25519` and hybrid suites.
    pub x25519: Option<[u8; X25519_PK_LEN]>,
    /// ML-KEM-768 encapsulation key (initiator) or ciphertext (responder),
    /// present for `MlKem768` and hybrid suites.
    pub mlkem_ek: Option<Vec<u8>>,
}

/// The role of a side in a key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemRole {
    /// The side that initiates the exchange.
    Initiator,
    /// The side that responds to the exchange.
    Responder,
}

impl KemEphemeral {
    /// Total serialized length for the given suite.
    pub fn serialized_len(suite: KemSuite) -> usize {
        match suite {
            KemSuite::X25519 => X25519_PK_LEN,
            KemSuite::MlKem768 => ML_KEM_768_EK_LEN,
            KemSuite::HybridX25519MlKem768 => X25519_PK_LEN + ML_KEM_768_EK_LEN,
        }
    }

    /// Serialize to the wire format.
    ///
    /// The format is suite-specific and self-describing by length.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KemEphemeral::serialized_len(self.suite));
        match self.suite {
            KemSuite::X25519 => {
                out.extend_from_slice(self.x25519.as_ref().expect("x25519 key present"));
            }
            KemSuite::MlKem768 => {
                out.extend_from_slice(self.mlkem_ek.as_ref().expect("mlkem key present"));
            }
            KemSuite::HybridX25519MlKem768 => {
                out.extend_from_slice(self.x25519.as_ref().expect("x25519 key present"));
                out.extend_from_slice(self.mlkem_ek.as_ref().expect("mlkem key present"));
            }
        }
        out
    }

    /// Parse from the wire format for a given suite and role.
    pub fn deserialize(suite: KemSuite, role: KemRole, bytes: &[u8]) -> Result<KemEphemeral> {
        let expected = KemEphemeral::serialized_len(suite);
        if bytes.len() != expected {
            return Err(Error::InvalidLength);
        }
        match suite {
            KemSuite::X25519 => {
                let mut k = [0u8; X25519_PK_LEN];
                k.copy_from_slice(bytes);
                Ok(KemEphemeral {
                    suite,
                    role,
                    x25519: Some(k),
                    mlkem_ek: None,
                })
            }
            KemSuite::MlKem768 => Ok(KemEphemeral {
                suite,
                role,
                x25519: None,
                mlkem_ek: Some(bytes.to_vec()),
            }),
            KemSuite::HybridX25519MlKem768 => {
                let mut k = [0u8; X25519_PK_LEN];
                k.copy_from_slice(&bytes[..X25519_PK_LEN]);
                Ok(KemEphemeral {
                    suite,
                    role,
                    x25519: Some(k),
                    mlkem_ek: Some(bytes[X25519_PK_LEN..].to_vec()),
                })
            }
        }
    }
}

impl fmt::Debug for KemEphemeral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemEphemeral")
            .field("suite", &self.suite)
            .field("role", &self.role)
            .field("x25519", &self.x25519.is_some())
            .field("mlkem", &self.mlkem_ek.is_some())
            .finish()
    }
}

/// The initiator's ephemeral state for a handshake.
///
/// Consumed by [`KemHandshakeInitiator::complete`] to derive the shared
/// secret.
pub struct KemHandshakeInitiator {
    suite: KemSuite,
    x25519_secret: Option<[u8; 32]>,
    mlkem_key: Option<MlKem768KeyPair>,
    peer: Option<KemEphemeral>,
}

impl KemHandshakeInitiator {
    /// Begin a handshake as the initiator, generating ephemeral key material.
    pub fn begin(suite: KemSuite) -> Result<(Self, KemEphemeral)> {
        let mut x_secret = None;
        let mut x_public = None;
        let mut mlkem_key = None;
        let mut mlkem_ek = None;

        if matches!(suite, KemSuite::X25519 | KemSuite::HybridX25519MlKem768) {
            let mut secret = [0u8; 32];
            crate::key_agreement::fill_random(&mut secret)?;
            x_public = Some(public_from_secret(&secret));
            x_secret = Some(secret);
        }
        if matches!(suite, KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768) {
            let kp = MlKem768KeyPair::generate()?;
            mlkem_ek = Some(kp.encapsulation_key());
            mlkem_key = Some(kp);
        }

        let ephemeral = KemEphemeral {
            suite,
            role: KemRole::Initiator,
            x25519: x_public,
            mlkem_ek,
        };

        Ok((
            KemHandshakeInitiator {
                suite,
                x25519_secret: x_secret,
                mlkem_key,
                peer: None,
            },
            ephemeral,
        ))
    }

    /// Process the responder's ephemeral material.
    pub fn accept_peer(&mut self, peer: KemEphemeral) -> Result<()> {
        if peer.suite != self.suite {
            return Err(Error::InvalidKey("peer used a different KEM suite"));
        }
        if peer.role != KemRole::Responder {
            return Err(Error::InvalidKey("expected a responder message"));
        }
        self.peer = Some(peer);
        Ok(())
    }

    /// Derive the shared secret.
    pub fn complete(&self, context: &[u8]) -> Result<[u8; 32]> {
        let peer = self
            .peer
            .as_ref()
            .ok_or(Error::InvalidKey("peer key not received"))?;
        derive_shared_secret(
            self.suite,
            self.x25519_secret.as_ref(),
            self.mlkem_key.as_ref(),
            peer,
            context,
        )
    }
}

impl fmt::Debug for KemHandshakeInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemHandshakeInitiator")
            .field("suite", &self.suite)
            .field("has_peer", &self.peer.is_some())
            .finish()
    }
}

/// The responder's ephemeral state for a handshake.
pub struct KemHandshakeResponder {
    suite: KemSuite,
    x25519_secret: Option<[u8; 32]>,
    x25519_public: Option<[u8; X25519_PK_LEN]>,
    peer: Option<KemEphemeral>,
}

impl KemHandshakeResponder {
    /// Begin a handshake as the responder.
    ///
    /// The returned ephemeral message carries the X25519 public key and, for
    /// ML-KEM suites, is filled in later by [`Self::complete`] with the
    /// ciphertext produced by encapsulating to the initiator's key. Use
    /// [`Self::take_ephemeral`] to obtain the final message.
    pub fn begin(suite: KemSuite) -> Result<(Self, KemEphemeral)> {
        let mut x_secret = None;
        let mut x_public = None;

        if matches!(suite, KemSuite::X25519 | KemSuite::HybridX25519MlKem768) {
            let mut secret = [0u8; 32];
            crate::key_agreement::fill_random(&mut secret)?;
            x_public = Some(public_from_secret(&secret));
            x_secret = Some(secret);
        }

        // The responder does not need its own ML-KEM key pair: the exchange
        // is initiated by the initiator's encapsulation key.
        let ephemeral = KemEphemeral {
            suite,
            role: KemRole::Responder,
            x25519: x_public,
            mlkem_ek: None,
        };

        Ok((
            KemHandshakeResponder {
                suite,
                x25519_secret: x_secret,
                x25519_public: x_public,
                peer: None,
            },
            ephemeral,
        ))
    }

    /// Process the initiator's ephemeral material.
    pub fn accept_peer(&mut self, peer: KemEphemeral) -> Result<()> {
        if peer.suite != self.suite {
            return Err(Error::InvalidKey("peer used a different KEM suite"));
        }
        if peer.role != KemRole::Initiator {
            return Err(Error::InvalidKey("expected an initiator message"));
        }
        self.peer = Some(peer);
        Ok(())
    }

    /// Produce the responder's final ephemeral message and the shared secret.
    ///
    /// For ML-KEM suites the message carries the ciphertext of encapsulating
    /// to the initiator's encapsulation key; the initiator decapsulates it
    /// with its own key.
    pub fn complete(&mut self, context: &[u8]) -> Result<(KemEphemeral, [u8; 32])> {
        let peer = self
            .peer
            .clone()
            .ok_or(Error::InvalidKey("peer key not received"))?;

        let mut ephemeral = KemEphemeral {
            suite: self.suite,
            role: KemRole::Responder,
            x25519: self.x25519_public,
            mlkem_ek: None,
        };

        let mlkem_shared = if matches!(
            self.suite,
            KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768
        ) {
            let peer_ek = peer
                .mlkem_ek
                .as_ref()
                .ok_or(Error::InvalidKey("peer ML-KEM key missing"))?;
            let (ct, ss) = encapsulate_to(peer_ek)?;
            ephemeral.mlkem_ek = Some(ct);
            Some(ss)
        } else {
            None
        };

        let secret = derive_shared_secret_with_mlkem(
            self.suite,
            self.x25519_secret.as_ref(),
            None,
            &peer,
            mlkem_shared.as_ref(),
            context,
        )?;

        Ok((ephemeral, secret))
    }
}

/// Encapsulate to a peer's ML-KEM encapsulation key, returning the
/// ciphertext and shared secret.
///
/// The `ml-kem` crate exposes encapsulation only through a key pair, so a
/// transient key pair is used to reach the standalone encapsulation path.
fn encapsulate_to(peer_ek: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    use ml_kem::{Encapsulate as _, TryKeyInit as _};

    let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(peer_ek)
        .map_err(|_| Error::InvalidKey("bad ML-KEM encapsulation key"))?;

    let mut rng = pq_rng();
    let (ct, ss) = ek.encapsulate_with_rng(&mut rng);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_ref());
    let ct_bytes: &[u8] = ct.as_ref();
    Ok((ct_bytes.to_vec(), out))
}

/// Construct a cryptographically secure RNG for the PQ code path.
///
/// `ml-kem` requires `rand_core` 0.10; the classical code path uses
/// `rand` 0.8. The two are kept separate because their `CryptoRng` traits
/// are distinct types.
fn pq_rng() -> rand_pq::rngs::StdRng {
    use rand_pq::SeedableRng;
    // Seed from the OS CSPRNG.
    let mut seed = [0u8; 32];
    crate::symmetric::fill_secure_random(&mut seed);
    rand_pq::rngs::StdRng::from_seed(seed)
}

fn derive_shared_secret(
    suite: KemSuite,
    x_secret: Option<&[u8; 32]>,
    mlkem_key: Option<&MlKem768KeyPair>,
    peer: &KemEphemeral,
    context: &[u8],
) -> Result<[u8; 32]> {
    // The initiator side: for ML-KEM suites the peer message carries the
    // ciphertext, which we decapsulate with our own decapsulation key.
    derive_shared_secret_with_mlkem(suite, x_secret, mlkem_key, peer, None, context)
}

fn derive_shared_secret_with_mlkem(
    suite: KemSuite,
    x_secret: Option<&[u8; 32]>,
    mlkem_key: Option<&MlKem768KeyPair>,
    peer: &KemEphemeral,
    mlkem_shared: Option<&[u8; 32]>,
    context: &[u8],
) -> Result<[u8; 32]> {
    match suite {
        KemSuite::X25519 => {
            let secret = x_secret.ok_or(Error::InvalidKey("x25519 secret missing"))?;
            let peer_pk = peer
                .x25519
                .as_ref()
                .ok_or(Error::InvalidKey("peer x25519 key missing"))?;
            agree_raw(secret, peer_pk)
        }
        KemSuite::MlKem768 => {
            // The responder encapsulated to our key and returned the
            // ciphertext; we decapsulate it with our own key. If we already
            // have the shared secret (responder side), use it directly.
            let shared = match mlkem_shared {
                Some(s) => *s,
                None => {
                    let kp = mlkem_key.ok_or(Error::InvalidKey("mlkem key missing"))?;
                    let ct = peer
                        .mlkem_ek
                        .as_ref()
                        .ok_or(Error::InvalidKey("peer mlkem ciphertext missing"))?;
                    if ct.len() != ML_KEM_768_CT_LEN {
                        return Err(Error::InvalidLength);
                    }
                    kp.decapsulate(ct)?
                }
            };
            let mut out = [0u8; 32];
            out.copy_from_slice(&shared);
            Ok(out)
        }
        KemSuite::HybridX25519MlKem768 => {
            let secret = x_secret.ok_or(Error::InvalidKey("x25519 secret missing"))?;
            let peer_pk = peer
                .x25519
                .as_ref()
                .ok_or(Error::InvalidKey("peer x25519 key missing"))?;
            let x_shared = agree_raw(secret, peer_pk)?;

            let pq_shared = match mlkem_shared {
                Some(s) => *s,
                None => {
                    // Initiator side: decapsulate the responder's ciphertext.
                    let kp = mlkem_key.ok_or(Error::InvalidKey("mlkem key missing"))?;
                    let ct = peer
                        .mlkem_ek
                        .as_ref()
                        .ok_or(Error::InvalidKey("peer mlkem ciphertext missing"))?;
                    if ct.len() != ML_KEM_768_CT_LEN {
                        return Err(Error::InvalidLength);
                    }
                    kp.decapsulate(ct)?
                }
            };

            combine_hybrid_secret(&x_shared, &pq_shared, context)
        }
    }
}

impl fmt::Debug for KemHandshakeResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemHandshakeResponder")
            .field("suite", &self.suite)
            .field("has_peer", &self.peer.is_some())
            .finish()
    }
}

/// Derive the two directional traffic keys from a shared secret.
pub fn derive_traffic_keys(
    shared_secret: &[u8; 32],
    suite: KemSuite,
) -> Result<(
    crate::symmetric::SymmetricKey,
    crate::symmetric::SymmetricKey,
)> {
    let context: &[u8] = match suite {
        KemSuite::X25519 => b"zt-next/traffic/x25519/v1",
        KemSuite::MlKem768 => b"zt-next/traffic/mlkem768/v1",
        KemSuite::HybridX25519MlKem768 => b"zt-next/traffic/hybrid/v1",
    };
    crate::symmetric::derive_session_keys(shared_secret, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(suite: KemSuite) -> Result<([u8; 32], [u8; 32])> {
        let (mut init, init_eph) = KemHandshakeInitiator::begin(suite)?;
        let (mut resp, _resp_eph) = KemHandshakeResponder::begin(suite)?;

        resp.accept_peer(init_eph.clone())?;
        let (resp_eph, resp_secret) = resp.complete(b"ctx")?;

        init.accept_peer(resp_eph)?;
        let init_secret = init.complete(b"ctx")?;

        Ok((init_secret, resp_secret))
    }

    #[test]
    fn x25519_handshake_agrees() {
        let (a, b) = handshake(KemSuite::X25519).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mlkem768_handshake_agrees() {
        let (a, b) = handshake(KemSuite::MlKem768).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hybrid_handshake_agrees() {
        let (a, b) = handshake(KemSuite::HybridX25519MlKem768).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ephemeral_sizes_match_suite() {
        for suite in KemSuite::offered() {
            let (_, eph) = KemHandshakeInitiator::begin(*suite).unwrap();
            let ser = eph.serialize();
            assert_eq!(ser.len(), KemEphemeral::serialized_len(*suite));
            let parsed = KemEphemeral::deserialize(*suite, KemRole::Initiator, &ser).unwrap();
            assert_eq!(parsed, eph);
        }
    }

    #[test]
    fn ephemeral_roundtrip_hybrid() {
        let suite = KemSuite::HybridX25519MlKem768;
        let (_, eph) = KemHandshakeInitiator::begin(suite).unwrap();
        let ser = eph.serialize();
        assert_eq!(ser.len(), X25519_PK_LEN + ML_KEM_768_EK_LEN);
        let parsed = KemEphemeral::deserialize(suite, KemRole::Initiator, &ser).unwrap();
        assert_eq!(parsed.suite, suite);
        assert!(parsed.x25519.is_some());
        assert!(parsed.mlkem_ek.is_some());
    }

    #[test]
    fn ephemeral_rejects_wrong_length() {
        let suite = KemSuite::HybridX25519MlKem768;
        assert!(KemEphemeral::deserialize(suite, KemRole::Initiator, &[0u8; 10]).is_err());
    }

    #[test]
    fn role_is_enforced() {
        let suite = KemSuite::X25519;
        let (_, init_eph) = KemHandshakeInitiator::begin(suite).unwrap();
        let (mut init, _) = KemHandshakeInitiator::begin(suite).unwrap();
        // The initiator must not accept another initiator's message.
        assert!(init.accept_peer(init_eph.clone()).is_err());

        let (mut resp, _) = KemHandshakeResponder::begin(suite).unwrap();
        // The responder must not accept a responder's message.
        let (_, resp_eph) = KemHandshakeResponder::begin(suite).unwrap();
        assert!(resp.accept_peer(resp_eph).is_err());
    }

    #[test]
    fn suite_mismatch_is_rejected() {
        let (_, init_eph) = KemHandshakeInitiator::begin(KemSuite::X25519).unwrap();
        let (mut resp, _) = KemHandshakeResponder::begin(KemSuite::MlKem768).unwrap();
        assert!(resp.accept_peer(init_eph).is_err());
    }

    #[test]
    fn traffic_keys_differ_by_direction() {
        let secret = [5u8; 32];
        let (k1, k2) = derive_traffic_keys(&secret, KemSuite::HybridX25519MlKem768).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn traffic_keys_differ_by_suite() {
        let secret = [5u8; 32];
        let (a, _) = derive_traffic_keys(&secret, KemSuite::X25519).unwrap();
        let (b, _) = derive_traffic_keys(&secret, KemSuite::HybridX25519MlKem768).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
