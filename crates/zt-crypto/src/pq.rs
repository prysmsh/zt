//! Post-quantum and hybrid cryptography.
//!
//! # Threat model
//!
//! A network that carries traffic today may still be decrypting that traffic
//! in ten years. Against a cryptographically relevant quantum computer
//! (CRQC), any traffic protected solely by X25519 and Ed25519 is
//! retroactively exposed: an attacker can harvest ciphertexts today and
//! decrypt them once a CRQC exists.
//!
//! ZT-next therefore defaults to **hybrid** constructions that combine a
//! classical primitive with a NIST-standard post-quantum primitive. A hybrid
//! is secure as long as *either* component holds, so a flaw in one does not
//! compromise the session.
//!
//! # Constructions
//!
//! | Purpose | Classical | Post-quantum | Combined size |
//! |---|---|---|---|
//! | Key agreement | X25519 | ML-KEM-768 | 64 B shared secret |
//! | Signatures | Ed25519 | ML-DSA-65 | 3373 B |
//!
//! # Algorithm negotiation
//!
//! Peers negotiate a suite before the handshake. This is deliberate: it
//! allows a network to be deployed with hybrid protection today, to fall
//! back to classical-only if a PQ implementation turns out to be broken, and
//! to move to pure-PQ when that becomes viable. The negotiation is itself
//! authenticated, so an attacker cannot downgrade a peer without detection.
//!
//! # Standards
//!
//! - ML-KEM-768 — NIST FIPS 203
//! - ML-DSA-65 — NIST FIPS 204
//! - Hybrid combination follows the structure of `draft-ietf-tls-hybrid-design`
//!   (the same shape used by Chrome, Cloudflare, and the TLS 1.3 ML-KEM
//!   draft): both secrets are concatenated and fed into a single HKDF extract.
//!
//! # Size considerations
//!
//! PQ primitives are large. ML-KEM-768 encapsulation keys are 1184 bytes and
//! ciphertexts 1088 bytes; ML-DSA-65 signatures are 3309 bytes. These costs
//! are paid **once per session**, never per packet. The per-packet data path
//! remains ChaCha20-Poly1305 with a 32-byte key, so throughput is unaffected.

use core::fmt;

use crate::error::{Error, Result};
use crate::symmetric::hkdf_sha256;
use ml_dsa::{
    Generate as MlDsaGenerate, KeyExport as MlDsaKeyExport, KeyInit as MlDsaKeyInit,
    Keypair as MlDsaKeypair, MlDsa65, SignatureEncoding as MlDsaSignatureEncoding,
    Signer as MlDsaSigner, Verifier as MlDsaVerifier,
};
use ml_kem::{
    Decapsulate as MlKemDecapsulate, Encapsulate as MlKemEncapsulate, Generate as MlKemGenerate,
    MlKem768,
};

/// Length of an ML-KEM-768 encapsulation (public) key.
pub const ML_KEM_768_EK_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// Length of an ML-KEM-768 shared secret.
pub const ML_KEM_768_SS_LEN: usize = 32;
/// Length of an ML-DSA-65 public key.
pub const ML_DSA_65_PK_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature.
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// Length of an ML-DSA-65 seed (secret key).
pub const ML_DSA_65_SEED_LEN: usize = 32;

/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// Total length of a hybrid signature: Ed25519 followed by ML-DSA-65.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

/// Length of a hybrid shared secret: X25519 followed by ML-KEM-768.
pub const HYBRID_SS_LEN: usize = 32 + ML_KEM_768_SS_LEN;

// ---------------------------------------------------------------------------
// Algorithm negotiation
// ---------------------------------------------------------------------------

/// A cryptographic suite for key agreement.
///
/// The suite is negotiated before the handshake begins. Values are stable and
/// must never be reused for a different meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum KemSuite {
    /// X25519 only. Classical, not quantum-resistant.
    ///
    /// Provided for constrained deployments and as a fallback. **Never the
    /// default.**
    X25519 = 0x01,
    /// ML-KEM-768 only. Pure post-quantum.
    MlKem768 = 0x02,
    /// X25519 combined with ML-KEM-768. Secure if either primitive holds.
    HybridX25519MlKem768 = 0x03,
}

impl KemSuite {
    /// The wire value.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a wire value.
    pub fn from_u8(v: u8) -> Result<KemSuite> {
        match v {
            0x01 => Ok(KemSuite::X25519),
            0x02 => Ok(KemSuite::MlKem768),
            0x03 => Ok(KemSuite::HybridX25519MlKem768),
            _ => Err(Error::InvalidKey("unknown KEM suite")),
        }
    }

    /// Whether this suite provides post-quantum protection.
    pub fn is_post_quantum(self) -> bool {
        matches!(self, KemSuite::MlKem768 | KemSuite::HybridX25519MlKem768)
    }

    /// Whether this suite is a hybrid of classical and post-quantum.
    pub fn is_hybrid(self) -> bool {
        matches!(self, KemSuite::HybridX25519MlKem768)
    }

    /// The suites this implementation offers, in preference order.
    ///
    /// Hybrid is preferred because it is secure if either component holds.
    pub fn offered() -> &'static [KemSuite] {
        &[
            KemSuite::HybridX25519MlKem768,
            KemSuite::MlKem768,
            KemSuite::X25519,
        ]
    }

    /// Choose the best mutually-supported suite.
    ///
    /// Both peers supply their supported lists in preference order. The
    /// result is the first entry in `local` that also appears in `remote`.
    /// Returns `None` if there is no overlap.
    pub fn negotiate(local: &[KemSuite], remote: &[KemSuite]) -> Option<KemSuite> {
        local
            .iter()
            .copied()
            .find(|candidate| remote.contains(candidate))
    }
}

/// A signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SigSuite {
    /// Ed25519 only. Classical.
    Ed25519 = 0x01,
    /// ML-DSA-65 only. Pure post-quantum.
    MlDsa65 = 0x02,
    /// Ed25519 combined with ML-DSA-65.
    HybridEd25519MlDsa65 = 0x03,
}

impl SigSuite {
    /// The wire value.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a wire value.
    pub fn from_u8(v: u8) -> Result<SigSuite> {
        match v {
            0x01 => Ok(SigSuite::Ed25519),
            0x02 => Ok(SigSuite::MlDsa65),
            0x03 => Ok(SigSuite::HybridEd25519MlDsa65),
            _ => Err(Error::InvalidKey("unknown signature suite")),
        }
    }

    /// Whether this suite provides post-quantum protection.
    pub fn is_post_quantum(self) -> bool {
        matches!(self, SigSuite::MlDsa65 | SigSuite::HybridEd25519MlDsa65)
    }

    /// The suites this implementation offers, in preference order.
    pub fn offered() -> &'static [SigSuite] {
        &[
            SigSuite::HybridEd25519MlDsa65,
            SigSuite::MlDsa65,
            SigSuite::Ed25519,
        ]
    }

    /// Choose the best mutually-supported suite.
    pub fn negotiate(local: &[SigSuite], remote: &[SigSuite]) -> Option<SigSuite> {
        local
            .iter()
            .copied()
            .find(|candidate| remote.contains(candidate))
    }
}

/// A negotiated combination of algorithms for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedSuites {
    /// Key agreement suite.
    pub kem: KemSuite,
    /// Signature suite.
    pub sig: SigSuite,
}

impl NegotiatedSuites {
    /// Whether this combination offers post-quantum protection.
    pub fn is_post_quantum(self) -> bool {
        self.kem.is_post_quantum() && self.sig.is_post_quantum()
    }

    /// Negotiate suites from both peers' advertised lists.
    pub fn negotiate(
        local_kem: &[KemSuite],
        local_sig: &[SigSuite],
        remote_kem: &[KemSuite],
        remote_sig: &[SigSuite],
    ) -> Option<NegotiatedSuites> {
        Some(NegotiatedSuites {
            kem: KemSuite::negotiate(local_kem, remote_kem)?,
            sig: SigSuite::negotiate(local_sig, remote_sig)?,
        })
    }
}

// ---------------------------------------------------------------------------
// ML-KEM-768
// ---------------------------------------------------------------------------

/// An ML-KEM-768 key pair (FIPS 203).
///
/// Holds the encapsulation key and the decapsulation key. The decapsulation
/// key is held in its compact seed form so that storage is 64 bytes rather
/// than the expanded 2400-byte form.
pub struct MlKem768KeyPair {
    ek: ml_kem::EncapsulationKey<MlKem768>,
    dk: ml_kem::DecapsulationKey<MlKem768>,
}

impl MlKem768KeyPair {
    /// Generate a new key pair.
    pub fn generate() -> Result<Self> {
        let dk = <ml_kem::DecapsulationKey<MlKem768> as MlKemGenerate>::generate();
        let ek = dk.encapsulation_key().clone();
        Ok(Self { ek, dk })
    }

    /// The encapsulation (public) key, 1184 bytes.
    pub fn encapsulation_key(&self) -> Vec<u8> {
        let array = self.ek.to_bytes();
        let bytes: &[u8] = array.as_ref();
        bytes.to_vec()
    }

    /// The decapsulation (secret) key in seed form, 64 bytes.
    pub fn decapsulation_key_bytes(&self) -> Vec<u8> {
        let array = self.dk.to_bytes();
        let bytes: &[u8] = array.as_ref();
        bytes.to_vec()
    }

    /// Encapsulate to a peer, producing a ciphertext and shared secret.
    pub fn encapsulate(&self, rng: &mut impl rand_core_pq::CryptoRng) -> (Vec<u8>, [u8; 32]) {
        let (ct, ss) = self.ek.encapsulate_with_rng(rng);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_ref());
        let ct_bytes: &[u8] = ct.as_ref();
        (ct_bytes.to_vec(), out)
    }

    /// Decapsulate a peer's ciphertext, recovering the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_| Error::InvalidLength)?;
        let ss = self.dk.decapsulate(&ct);
        let mut out = [0u8; 32];
        out.copy_from_slice(ss.as_ref());
        Ok(out)
    }
}

impl fmt::Debug for MlKem768KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768KeyPair")
            .field("ek_len", &ML_KEM_768_EK_LEN)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ML-DSA-65
// ---------------------------------------------------------------------------

/// An ML-DSA-65 signing key pair (FIPS 204).
pub struct MlDsa65KeyPair {
    sk: ml_dsa::SigningKey<MlDsa65>,
}

impl Clone for MlDsa65KeyPair {
    fn clone(&self) -> Self {
        // `SigningKey` is `Clone` upstream; the derived `Clone` is needed
        // because `ControllerIdentity` is `Clone`.
        Self {
            sk: self.sk.clone(),
        }
    }
}

impl MlDsa65KeyPair {
    /// Generate a new key pair.
    pub fn generate() -> Result<Self> {
        let sk = <ml_dsa::SigningKey<MlDsa65> as MlDsaGenerate>::generate();
        Ok(Self { sk })
    }

    /// Restore a key pair from its 32-byte seed.
    ///
    /// The seed is what a node keeps, so its key survives a restart and
    /// its peers do not have to learn a new one.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // The seed is a fixed-size array in the underlying crate, and the
        // conversion is checked by the type.
        let seed: ml_dsa::Seed = seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey("the ML-DSA seed must be 32 bytes"))?;
        let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);
        Ok(Self { sk })
    }

    /// The verification (public) key, 1952 bytes.
    pub fn public_key(&self) -> Vec<u8> {
        let array = self.sk.verifying_key().to_bytes();
        let bytes: &[u8] = array.as_ref();
        bytes.to_vec()
    }

    /// Sign a message, producing a 3309-byte signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .sk
            .try_sign(msg)
            .map_err(|_| Error::InvalidKey("ML-DSA signing failed"))?;
        Ok(sig.to_bytes().to_vec())
    }

    /// Verify a signature against a public key.
    pub fn verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<()> {
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::new_from_slice(public_key)
            .map_err(|_| Error::InvalidKey("bad ML-DSA public key"))?;
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
            .map_err(|_| Error::InvalidSignature)?;
        vk.verify(msg, &sig)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

impl fmt::Debug for MlDsa65KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa65KeyPair")
            .field("pk_len", &ML_DSA_65_PK_LEN)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Hybrid combinations
// ---------------------------------------------------------------------------

/// Combine an X25519 shared secret with an ML-KEM-768 shared secret.
///
/// Both secrets are concatenated and run through HKDF-SHA256 with a
/// domain-separated context. The result is secure if either primitive holds:
/// breaking the classical half still leaves the PQ half intact, and vice
/// versa. This mirrors the structure used in TLS 1.3 hybrid key exchange.
pub fn combine_hybrid_secret(
    x25519_secret: &[u8; 32],
    mlkem_secret: &[u8; 32],
    context: &[u8],
) -> Result<[u8; 32]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_secret);
    ikm[32..].copy_from_slice(mlkem_secret);

    let mut out = [0u8; 32];
    hkdf_sha256(&ikm, b"zt-next/hybrid-kem/v1", context, &mut out)?;
    Ok(out)
}

/// A hybrid signature: Ed25519 followed by ML-DSA-65.
///
/// Verification requires **both** signatures to be valid. This is
/// deliberately stricter than a "either is sufficient" combiner: a signature
/// made by a compromised ML-DSA implementation is still rejected if Ed25519
/// fails, and vice versa.
pub fn combine_hybrid_signature(ed_sig: &[u8; 64], ml_dsa_sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
    out.extend_from_slice(ed_sig);
    out.extend_from_slice(ml_dsa_sig);
    out
}

/// Verify a hybrid signature produced by [`combine_hybrid_signature`].
pub fn verify_hybrid_signature(
    ed_public_key: &[u8; 32],
    ml_dsa_public_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != HYBRID_SIG_LEN {
        return Err(Error::InvalidLength);
    }
    let (ed_sig, pq_sig) = signature.split_at(ED25519_SIG_LEN);

    let mut ed_bytes = [0u8; 64];
    ed_bytes.copy_from_slice(ed_sig);
    crate::identity::Identity::verify(ed_public_key, msg, &ed_bytes)?;

    MlDsa65KeyPair::verify(ml_dsa_public_key, msg, pq_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> rand_pq::rngs::StdRng {
        use rand_pq::SeedableRng;
        rand_pq::rngs::StdRng::from_seed([42u8; 32])
    }

    /// A generator with a distinct seed, so two calls produce independent
    /// randomness rather than repeating the same stream.
    fn rng2() -> rand_pq::rngs::StdRng {
        use rand_pq::SeedableRng;
        rand_pq::rngs::StdRng::from_seed([43u8; 32])
    }

    #[test]
    fn mlkem768_roundtrip() {
        let kp = MlKem768KeyPair::generate().unwrap();
        assert_eq!(kp.encapsulation_key().len(), ML_KEM_768_EK_LEN);
        assert_eq!(kp.decapsulation_key_bytes().len(), 64);

        let (ct, ss_a) = kp.encapsulate(&mut rng());
        assert_eq!(ct.len(), ML_KEM_768_CT_LEN);

        let ss_b = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn mlkem768_is_randomized() {
        let kp = MlKem768KeyPair::generate().unwrap();
        // Two independent generators, so the two encapsulations use different
        // randomness. Reusing one seeded generator would continue the same
        // deterministic stream and make this comparison meaningless.
        let (ct1, ss1) = kp.encapsulate(&mut rng());
        let (ct2, ss2) = kp.encapsulate(&mut rng2());
        assert_ne!(ct1, ct2);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn an_ml_dsa_key_pair_is_restored_from_its_seed() {
        let seed = [0x5au8; 32];
        let first = MlDsa65KeyPair::from_seed(&seed).expect("key");
        let second = MlDsa65KeyPair::from_seed(&seed).expect("key");

        assert_eq!(first.public_key(), second.public_key());

        // The same key signs, and the same key verifies.
        let message = b"the same key after a restart";
        let signature = first.sign(message).expect("sign");
        MlDsa65KeyPair::verify(&second.public_key(), message, &signature).expect("verify");
    }

    #[test]
    fn mlkem768_rejects_bad_ciphertext() {
        let kp = MlKem768KeyPair::generate().unwrap();
        let (mut ct, _) = kp.encapsulate(&mut rng());
        ct[0] ^= 0xff;
        // FIPS 203 decapsulation is implicit-rejection: it returns a
        // pseudorandom shared secret rather than erroring.
        let ss = kp.decapsulate(&ct).unwrap();
        // The result must not equal the honest shared secret.
        let (_, honest) = kp.encapsulate(&mut rng());
        assert_ne!(ss, honest);
    }

    #[test]
    fn mlkem768_rejects_wrong_length() {
        let kp = MlKem768KeyPair::generate().unwrap();
        assert!(kp.decapsulate(&[0u8; 10]).is_err());
    }

    #[test]
    fn mldsa65_sign_verify() {
        let kp = MlDsa65KeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.len(), ML_DSA_65_PK_LEN);

        let msg = b"post-quantum message";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);

        MlDsa65KeyPair::verify(&pk, msg, &sig).unwrap();
        assert!(MlDsa65KeyPair::verify(&pk, b"other", &sig).is_err());
    }

    #[test]
    fn mldsa65_rejects_tampered_signature() {
        let kp = MlDsa65KeyPair::generate().unwrap();
        let pk = kp.public_key();
        let msg = b"post-quantum message";
        let mut sig = kp.sign(msg).unwrap();
        sig[100] ^= 0xff;
        assert!(MlDsa65KeyPair::verify(&pk, msg, &sig).is_err());
    }

    #[test]
    fn hybrid_secret_combiner_depends_on_both_halves() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        let s1 = combine_hybrid_secret(&a, &b, b"ctx").unwrap();
        let s2 = combine_hybrid_secret(&a, &c, b"ctx").unwrap();
        let s3 = combine_hybrid_secret(&c, &b, b"ctx").unwrap();

        assert_ne!(s1, s2, "changing the PQ half must change the result");
        assert_ne!(s1, s3, "changing the classical half must change the result");
    }

    #[test]
    fn hybrid_secret_combiner_is_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(
            combine_hybrid_secret(&a, &b, b"ctx").unwrap(),
            combine_hybrid_secret(&a, &b, b"ctx").unwrap()
        );
    }

    #[test]
    fn hybrid_signature_requires_both_halves() {
        let ed = crate::identity::Identity::generate().unwrap();
        let pq = MlDsa65KeyPair::generate().unwrap();
        let pq_pk = pq.public_key();
        let msg = b"hybrid signed";

        let ed_sig = ed.sign(msg);
        let pq_sig = pq.sign(msg).unwrap();
        let combined = combine_hybrid_signature(&ed_sig, &pq_sig);
        assert_eq!(combined.len(), HYBRID_SIG_LEN);

        verify_hybrid_signature(&ed.public_key_bytes(), &pq_pk, msg, &combined).unwrap();

        // Corrupt the Ed25519 half: must fail even though the PQ half is valid.
        let mut corrupt = combined.clone();
        corrupt[0] ^= 0xff;
        assert!(verify_hybrid_signature(&ed.public_key_bytes(), &pq_pk, msg, &corrupt).is_err());

        // Corrupt the PQ half: must fail even though the Ed25519 half is valid.
        let mut corrupt = combined.clone();
        let n = corrupt.len();
        corrupt[n - 1] ^= 0xff;
        assert!(verify_hybrid_signature(&ed.public_key_bytes(), &pq_pk, msg, &corrupt).is_err());
    }

    #[test]
    fn hybrid_signature_rejects_wrong_length() {
        assert!(verify_hybrid_signature(&[0u8; 32], &[0u8; 1952], b"m", &[0u8; 10]).is_err());
    }

    #[test]
    fn kem_negotiation_prefers_hybrid() {
        let local = KemSuite::offered();
        let remote = KemSuite::offered();
        let chosen = KemSuite::negotiate(local, remote).unwrap();
        assert_eq!(chosen, KemSuite::HybridX25519MlKem768);
        assert!(chosen.is_post_quantum());
        assert!(chosen.is_hybrid());
    }

    #[test]
    fn kem_negotiation_falls_back_when_needed() {
        // Peer only supports classical.
        let chosen = KemSuite::negotiate(KemSuite::offered(), &[KemSuite::X25519]).unwrap();
        assert_eq!(chosen, KemSuite::X25519);
        assert!(!chosen.is_post_quantum());
    }

    #[test]
    fn kem_negotiation_detects_no_overlap() {
        assert!(KemSuite::negotiate(&[KemSuite::MlKem768], &[KemSuite::X25519]).is_none());
    }

    #[test]
    fn sig_negotiation_prefers_hybrid() {
        let chosen = SigSuite::negotiate(SigSuite::offered(), SigSuite::offered()).unwrap();
        assert_eq!(chosen, SigSuite::HybridEd25519MlDsa65);
        assert!(chosen.is_post_quantum());
    }

    #[test]
    fn suite_roundtrip_through_wire_values() {
        for s in KemSuite::offered() {
            assert_eq!(KemSuite::from_u8(s.to_u8()).unwrap(), *s);
        }
        for s in SigSuite::offered() {
            assert_eq!(SigSuite::from_u8(s.to_u8()).unwrap(), *s);
        }
    }

    #[test]
    fn unknown_suite_is_rejected() {
        assert!(KemSuite::from_u8(0xff).is_err());
        assert!(SigSuite::from_u8(0xff).is_err());
    }

    #[test]
    fn negotiated_suites_report_pq_status() {
        let n = NegotiatedSuites::negotiate(
            KemSuite::offered(),
            SigSuite::offered(),
            &[KemSuite::HybridX25519MlKem768],
            &[SigSuite::HybridEd25519MlDsa65],
        )
        .unwrap();
        assert!(n.is_post_quantum());
    }
}
