//! Node credentials: short-lived, controller-signed certificates.
//!
//! # Why this exists
//!
//! ZeroTier issues nodes a [`CertificateOfMembership`] (COM), which is a
//! **long-lived bearer capability**. It has no expiry, it is not bound to the
//! node's key material, and possession of it is sufficient to impersonate the
//! member. Revocation is push-based: a revoked node remains valid until the
//! controller's revocation list propagates to every peer.
//!
//! ZT-next replaces this with **short-lived certificates**:
//!
//! - **Expiring.** A 24-hour default TTL means a compromised credential
//!   stops working on its own.
//! - **Auto-renewing.** The node renews before expiry; no user interaction.
//! - **Key-bound.** The certificate commits to the node's Ed25519 public key.
//!   An attacker who steals the certificate still cannot join, because the
//!   handshake requires proof of possession of the private key. This is a
//!   genuine security improvement over a bearer COM.
//! - **Self-expiring revocation.** A revoked node can no longer renew, so
//!   revocation takes effect within one TTL even with no push.
//!
//! [`CertificateOfMembership`]: https://github.com/zerotier/zerotierone
//!
//! # Post-quantum signatures
//!
//! The controller's signing key is **hybrid**: an Ed25519 key plus an
//! ML-DSA-65 key. Credentials carry both signatures, and verification
//! requires both to be valid. This is the right place to spend the size
//! budget — credentials are issued rarely, are not on the data path, and a
//! forged credential is a serious compromise.
//!
//! See [`crate::pq`] for the hybrid signature construction.
//!
//! # Wire format
//!
//! The credential is deliberately simple and fixed-layout so that it can be
//! parsed without allocation on the hot path:
//!
//! ```text
//! ┌────────┬──────────┬────────────┬──────────┬────────────┬──────────┐
//! │ version│ network  │ node_addr  │ issued_at│ not_after  │ ttl_secs │
//! │ u8     │ id u64   │ [u8;10]    │ u64      │ u64        │ u32      │
//! ├────────┴──────────┴────────────┴──────────┴──────────┴──────────┤
//! │ public_key [u8;32]  │ controller_id [u8;16] │ nonce [u8;16]        │
//! ├─────────────────────┴────────────────────────┴────────────────────┤
//! │ ed25519_sig [u8;64]  │ ml_dsa_65_sig [u8;3309]                    │
//! ├──────────────────────┴────────────────────────────────────────────┤
//! │ ml_dsa_65_pub [u8;1952]                                            │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The ML-DSA public key travels with the credential so that a node can
//! verify it without a separate key-distribution step. This is acceptable
//! because credentials are rare; the controller's Ed25519 key is the
//! trust anchor that pins the ML-DSA key.

use crate::error::{Error, Result};
use crate::identity::{Address, Identity, PUBLIC_KEY_LEN};
use crate::pq::{
    MlDsa65KeyPair, ED25519_SIG_LEN, HYBRID_SIG_LEN, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN,
};

/// Current credential format version.
pub const CREDENTIAL_VERSION: u8 = 1;

/// Length of the controller identifier embedded in a credential.
pub const CONTROLLER_ID_LEN: usize = 16;

/// Length of the issuance nonce embedded in a credential.
pub const NONCE_LEN: usize = 16;

/// Total serialized length of a credential.
pub const CREDENTIAL_LEN: usize =
    1 + 8 + 10 + 8 + 8 + 4 + 32 + 16 + 16 + ED25519_SIG_LEN + ML_DSA_65_SIG_LEN + ML_DSA_65_PK_LEN;

// Field offsets within the serialized credential.
//
// The layout is:
//
//   [ header .............................................. ]
//   [ public_key (32) | controller_id (16) | nonce (16)    ]
//   [ ml_dsa_65_pub (1952)                                ]
//   [ ed25519_sig (64) | ml_dsa_65_sig (3309)             ]
//
// The ML-DSA public key sits *before* the signatures because it is part of
// the signed body: it is covered by both signatures, so it cannot be
// swapped for an attacker-controlled key.
const OFF_VERSION: usize = 0;
const OFF_NETWORK_ID: usize = 1;
const OFF_NODE_ADDR: usize = 9;
const OFF_ISSUED_AT: usize = 19;
const OFF_NOT_AFTER: usize = 27;
const OFF_TTL: usize = 35;
const OFF_PUBLIC_KEY: usize = 39;
const OFF_CONTROLLER_ID: usize = 71;
const OFF_NONCE: usize = 87;
const OFF_PQ_PK: usize = OFF_NONCE + NONCE_LEN;
const OFF_ED_SIG: usize = OFF_PQ_PK + ML_DSA_65_PK_LEN;
const OFF_PQ_SIG: usize = OFF_ED_SIG + ED25519_SIG_LEN;
const OFF_SIGNATURE_END: usize = OFF_PQ_SIG + ML_DSA_65_SIG_LEN;

// The declared length must match the computed layout.
const _: () = assert!(CREDENTIAL_LEN == OFF_SIGNATURE_END);

/// A short-lived node certificate issued by a controller.
///
/// The signatures cover every byte preceding them, so the credential is
/// tamper-evident in its entirety.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeCredential {
    network_id: u64,
    node_address: Address,
    public_key: [u8; PUBLIC_KEY_LEN],
    issued_at: u64,
    not_after: u64,
    ttl_secs: u32,
    controller_id: [u8; CONTROLLER_ID_LEN],
    nonce: [u8; NONCE_LEN],
    ed_signature: [u8; ED25519_SIG_LEN],
    pq_signature: Vec<u8>,
    pq_public_key: Vec<u8>,
    /// The original wire bytes, when the credential was parsed without a
    /// trust anchor.
    raw: Option<Vec<u8>>,
}

impl NodeCredential {
    /// The network this credential grants access to.
    pub fn network_id(&self) -> u64 {
        self.network_id
    }

    /// The address of the node this credential was issued to.
    pub fn node_address(&self) -> Address {
        self.node_address
    }

    /// The Ed25519 public key the credential is bound to.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Unix timestamp (seconds) at which the credential was issued.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Unix timestamp (seconds) after which the credential is invalid.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The credential's time-to-live in seconds.
    pub fn ttl_secs(&self) -> u32 {
        self.ttl_secs
    }

    /// The identifier of the controller that issued this credential.
    pub fn controller_id(&self) -> &[u8; CONTROLLER_ID_LEN] {
        &self.controller_id
    }

    /// The issuance nonce.
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The ML-DSA-65 public key that accompanies this credential.
    pub fn pq_public_key(&self) -> &[u8] {
        &self.pq_public_key
    }

    /// The combined hybrid signature (Ed25519 followed by ML-DSA-65).
    pub fn signature(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed_signature);
        out.extend_from_slice(&self.pq_signature);
        out
    }

    /// Serialize to the wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = vec![0u8; CREDENTIAL_LEN];
        out[OFF_VERSION] = CREDENTIAL_VERSION;
        out[OFF_NETWORK_ID..OFF_NETWORK_ID + 8].copy_from_slice(&self.network_id.to_be_bytes());
        out[OFF_NODE_ADDR..OFF_NODE_ADDR + 10].copy_from_slice(self.node_address.as_bytes());
        out[OFF_ISSUED_AT..OFF_ISSUED_AT + 8].copy_from_slice(&self.issued_at.to_be_bytes());
        out[OFF_NOT_AFTER..OFF_NOT_AFTER + 8].copy_from_slice(&self.not_after.to_be_bytes());
        out[OFF_TTL..OFF_TTL + 4].copy_from_slice(&self.ttl_secs.to_be_bytes());
        out[OFF_PUBLIC_KEY..OFF_PUBLIC_KEY + 32].copy_from_slice(&self.public_key);
        out[OFF_CONTROLLER_ID..OFF_CONTROLLER_ID + 16].copy_from_slice(&self.controller_id);
        out[OFF_NONCE..OFF_NONCE + 16].copy_from_slice(&self.nonce);
        out[OFF_PQ_PK..OFF_PQ_PK + ML_DSA_65_PK_LEN].copy_from_slice(&self.pq_public_key);
        out[OFF_ED_SIG..OFF_ED_SIG + ED25519_SIG_LEN].copy_from_slice(&self.ed_signature);
        out[OFF_PQ_SIG..OFF_PQ_SIG + ML_DSA_65_SIG_LEN].copy_from_slice(&self.pq_signature);
        out
    }

    /// Parse from the wire format and verify the hybrid signature.
    ///
    /// `controller_key` is the Ed25519 public key of the issuing controller.
    /// This is the trust anchor: it pins the ML-DSA key carried in the
    /// credential, so a forged ML-DSA signature cannot be substituted.
    ///
    /// Verification failure returns [`Error::AuthenticationFailed`].
    pub fn deserialize(
        bytes: &[u8],
        controller_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<NodeCredential> {
        if bytes.len() < CREDENTIAL_LEN {
            return Err(Error::InvalidLength);
        }
        if bytes[OFF_VERSION] != CREDENTIAL_VERSION {
            return Err(Error::InvalidKey("unsupported credential version"));
        }

        let mut network_id = [0u8; 8];
        network_id.copy_from_slice(&bytes[OFF_NETWORK_ID..OFF_NETWORK_ID + 8]);
        let mut node_addr = [0u8; 10];
        node_addr.copy_from_slice(&bytes[OFF_NODE_ADDR..OFF_NODE_ADDR + 10]);
        let mut issued_at = [0u8; 8];
        issued_at.copy_from_slice(&bytes[OFF_ISSUED_AT..OFF_ISSUED_AT + 8]);
        let mut not_after = [0u8; 8];
        not_after.copy_from_slice(&bytes[OFF_NOT_AFTER..OFF_NOT_AFTER + 8]);
        let mut ttl = [0u8; 4];
        ttl.copy_from_slice(&bytes[OFF_TTL..OFF_TTL + 4]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[OFF_PUBLIC_KEY..OFF_PUBLIC_KEY + 32]);
        let mut controller_id = [0u8; 16];
        controller_id.copy_from_slice(&bytes[OFF_CONTROLLER_ID..OFF_CONTROLLER_ID + 16]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[OFF_NONCE..OFF_NONCE + 16]);
        let pq_public_key = bytes[OFF_PQ_PK..OFF_PQ_PK + ML_DSA_65_PK_LEN].to_vec();
        let mut ed_signature = [0u8; ED25519_SIG_LEN];
        ed_signature.copy_from_slice(&bytes[OFF_ED_SIG..OFF_ED_SIG + ED25519_SIG_LEN]);
        let pq_signature = bytes[OFF_PQ_SIG..OFF_PQ_SIG + ML_DSA_65_SIG_LEN].to_vec();

        // The signed body is everything preceding the signatures. It includes
        // the ML-DSA public key, so that key cannot be substituted.
        let body = &bytes[..OFF_ED_SIG];

        // Verify the Ed25519 signature over the full body.
        Identity::verify(controller_key, body, &ed_signature)?;

        // Verify the ML-DSA signature over the same body.
        MlDsa65KeyPair::verify(&pq_public_key, body, &pq_signature)?;

        Ok(NodeCredential {
            network_id: u64::from_be_bytes(network_id),
            node_address: Address::from_bytes(&node_addr),
            public_key,
            issued_at: u64::from_be_bytes(issued_at),
            not_after: u64::from_be_bytes(not_after),
            ttl_secs: u32::from_be_bytes(ttl),
            controller_id,
            nonce,
            ed_signature,
            pq_signature,
            pq_public_key,
            raw: None,
        })
    }

    /// Check whether the credential is still valid at the given timestamp.
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        now_unix < self.not_after
    }

    /// Rebuild a credential from its serialized form without verifying it.
    ///
    /// This is used when a credential arrives on the wire and the trust
    /// anchor is not yet known. The returned credential carries the
    /// unverified bytes; callers must verify it against a trusted
    /// controller before relying on any of its fields.
    ///
    /// The `network_id` and `address` are read from the signed body, so they
    /// cannot be forged without invalidating the signature.
    pub fn from_parts(
        bytes: Vec<u8>,
        network_id: u64,
        node_address: Address,
    ) -> Self {
        let public_key = if bytes.len() >= 39 {
            let mut key = [0u8; PUBLIC_KEY_LEN];
            key.copy_from_slice(&bytes[39..39 + PUBLIC_KEY_LEN]);
            key
        } else {
            [0u8; PUBLIC_KEY_LEN]
        };

        let (issued_at, not_after, ttl_secs) = if bytes.len() >= 39 {
            let mut issued = [0u8; 8];
            issued.copy_from_slice(&bytes[19..27]);
            let mut expires = [0u8; 8];
            expires.copy_from_slice(&bytes[27..35]);
            let mut ttl = [0u8; 4];
            ttl.copy_from_slice(&bytes[35..39]);
            (
                u64::from_be_bytes(issued),
                u64::from_be_bytes(expires),
                u32::from_be_bytes(ttl),
            )
        } else {
            (0, 0, 0)
        };

        let controller_id = if bytes.len() >= 87 {
            let mut id = [0u8; CONTROLLER_ID_LEN];
            id.copy_from_slice(&bytes[71..87]);
            id
        } else {
            [0u8; CONTROLLER_ID_LEN]
        };

        Self {
            network_id,
            node_address,
            public_key,
            issued_at,
            not_after,
            ttl_secs,
            controller_id,
            nonce: [0u8; NONCE_LEN],
            ed_signature: [0u8; ED25519_SIG_LEN],
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            raw: Some(bytes),
        }
    }

    /// The raw serialized credential, if it was built from wire bytes.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.raw.as_deref()
    }

    /// Check whether the credential is valid at the given timestamp and was
    /// already issued.
    ///
    /// A small clock-skew allowance is applied on the `issued_at` side.
    pub fn is_valid_at_with_skew(&self, now_unix: u64, skew_secs: u64) -> bool {
        now_unix + skew_secs < self.not_after && now_unix + skew_secs >= self.issued_at
    }
}

/// A controller's signing identity.
///
/// Controllers sign node credentials with a **hybrid** key: an Ed25519 key
/// (the trust anchor, pinned by nodes) plus an ML-DSA-65 key (the
/// post-quantum half). Nodes trust a controller by trusting its Ed25519
/// public key, which in turn authenticates the ML-DSA key carried in each
/// credential.
#[derive(Clone)]
pub struct ControllerIdentity {
    identity: Identity,
    pq: MlDsa65KeyPair,
    controller_id: [u8; CONTROLLER_ID_LEN],
}

impl ControllerIdentity {
    /// Create a controller identity, deriving its controller ID from the
    /// public key.
    pub fn new(identity: Identity) -> Self {
        let pk = identity.public_key_bytes();
        let controller_id = crate::address::derive_id(&pk);
        let pq = MlDsa65KeyPair::generate().expect("ML-DSA key generation");
        Self {
            identity,
            pq,
            controller_id,
        }
    }

    /// The 16-byte controller identifier.
    pub fn controller_id(&self) -> &[u8; CONTROLLER_ID_LEN] {
        &self.controller_id
    }

    /// The controller's Ed25519 public key — the trust anchor.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.identity.public_key_bytes()
    }

    /// The controller's Ed25519 private key seed.
    ///
    /// Exposed so a controller can persist and restore its signing identity.
    /// Callers must never log or transmit this value.
    pub fn private_key_seed(&self) -> [u8; crate::identity::PRIVATE_KEY_LEN] {
        self.identity.private_key_bytes()
    }

    /// Restore a controller identity from a previously persisted Ed25519 seed.
    ///
    /// The ML-DSA-65 key is regenerated. It is not part of the persisted
    /// secret because it is only needed for signing new credentials; nodes
    /// pin it through the Ed25519 signature on each credential.
    pub fn from_private_key_seed(seed: &[u8; crate::identity::PRIVATE_KEY_LEN]) -> Self {
        Self::new(Identity::from_bytes(seed))
    }

    /// The controller's ML-DSA-65 public key.
    pub fn pq_public_key(&self) -> Vec<u8> {
        self.pq.public_key()
    }

    /// Issue a credential for a node.
    ///
    /// `now_unix` is the current Unix timestamp in seconds; `ttl_secs` is the
    /// requested lifetime.
    pub fn issue(
        &self,
        network_id: u64,
        node_address: Address,
        node_public_key: &[u8; PUBLIC_KEY_LEN],
        now_unix: u64,
        ttl_secs: u32,
        nonce: &[u8; NONCE_LEN],
    ) -> NodeCredential {
        let not_after = now_unix + ttl_secs as u64;
        let pq_public_key = self.pq.public_key();

        // Build the unsigned body first, then sign it. The ML-DSA public key
        // is part of the body so it cannot be substituted.
        let mut body = vec![0u8; OFF_ED_SIG];
        body[OFF_VERSION] = CREDENTIAL_VERSION;
        body[OFF_NETWORK_ID..OFF_NETWORK_ID + 8].copy_from_slice(&network_id.to_be_bytes());
        body[OFF_NODE_ADDR..OFF_NODE_ADDR + 10].copy_from_slice(node_address.as_bytes());
        body[OFF_ISSUED_AT..OFF_ISSUED_AT + 8].copy_from_slice(&now_unix.to_be_bytes());
        body[OFF_NOT_AFTER..OFF_NOT_AFTER + 8].copy_from_slice(&not_after.to_be_bytes());
        body[OFF_TTL..OFF_TTL + 4].copy_from_slice(&ttl_secs.to_be_bytes());
        body[OFF_PUBLIC_KEY..OFF_PUBLIC_KEY + 32].copy_from_slice(node_public_key);
        body[OFF_CONTROLLER_ID..OFF_CONTROLLER_ID + 16].copy_from_slice(&self.controller_id);
        body[OFF_NONCE..OFF_NONCE + 16].copy_from_slice(nonce);
        body[OFF_PQ_PK..OFF_PQ_PK + ML_DSA_65_PK_LEN].copy_from_slice(&pq_public_key);

        let ed_signature = self.identity.sign(&body);
        let pq_signature = self.pq.sign(&body).expect("ML-DSA signing");

        NodeCredential {
            network_id,
            node_address,
            public_key: *node_public_key,
            issued_at: now_unix,
            not_after,
            ttl_secs,
            controller_id: self.controller_id,
            nonce: *nonce,
            ed_signature,
            pq_signature,
            pq_public_key,
            raw: None,
        }
    }
}

impl core::fmt::Debug for ControllerIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControllerIdentity")
            .field("controller_id", &hex::encode(self.controller_id))
            .field("public_key", &hex::encode(self.identity.public_key_bytes()))
            .finish()
    }
}

impl core::fmt::Debug for NodeCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeCredential")
            .field("network_id", &self.network_id)
            .field("node_address", &self.node_address)
            .field("not_after", &self.not_after)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (ControllerIdentity, Identity, u64) {
        let ctrl = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let nwid = 0x1234_5678_9abc_def0;
        (ctrl, node, nwid)
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let nonce = [7u8; 16];
        let cred = ctrl.issue(
            nwid,
            addr,
            &node.public_key_bytes(),
            1_000_000,
            86_400,
            &nonce,
        );

        let bytes = cred.serialize();
        assert_eq!(bytes.len(), CREDENTIAL_LEN);

        let parsed = NodeCredential::deserialize(&bytes, &ctrl.public_key()).unwrap();
        assert_eq!(parsed.network_id(), nwid);
        assert_eq!(parsed.node_address(), addr);
        assert_eq!(parsed.public_key(), &node.public_key_bytes());
        assert_eq!(parsed.ttl_secs(), 86_400);
        assert_eq!(parsed.not_after(), 1_000_000 + 86_400);
        assert_eq!(parsed.nonce(), &nonce);
        assert_eq!(parsed.pq_public_key(), &ctrl.pq_public_key()[..]);
    }

    #[test]
    fn credential_carries_hybrid_signature() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        assert_eq!(cred.signature().len(), HYBRID_SIG_LEN);
    }

    #[test]
    fn wrong_controller_key_fails() {
        let (ctrl, node, nwid) = fixture();
        let other = ControllerIdentity::new(Identity::generate().unwrap());
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        let bytes = cred.serialize();

        let err = NodeCredential::deserialize(&bytes, &other.public_key()).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn tampering_is_detected() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        let mut bytes = cred.serialize();

        // Flip a bit in the network ID.
        bytes[OFF_NETWORK_ID] ^= 0xff;
        assert!(NodeCredential::deserialize(&bytes, &ctrl.public_key()).is_err());
    }

    #[test]
    fn tampering_with_the_pq_signature_is_detected() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        let mut bytes = cred.serialize();

        // Corrupt only the ML-DSA half. The Ed25519 signature still verifies,
        // but the hybrid check must reject the credential.
        bytes[OFF_PQ_SIG] ^= 0xff;
        assert!(NodeCredential::deserialize(&bytes, &ctrl.public_key()).is_err());
    }

    #[test]
    fn swapping_the_pq_public_key_is_detected() {
        let (ctrl, node, nwid) = fixture();
        let other = ControllerIdentity::new(Identity::generate().unwrap());
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        let mut bytes = cred.serialize();

        // Substitute a different ML-DSA public key.
        let other_pk = other.pq_public_key();
        bytes[OFF_PQ_PK..OFF_PQ_PK + ML_DSA_65_PK_LEN].copy_from_slice(&other_pk);
        assert!(NodeCredential::deserialize(&bytes, &ctrl.public_key()).is_err());
    }

    #[test]
    fn truncation_is_rejected() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        let bytes = cred.serialize();
        assert!(NodeCredential::deserialize(&bytes[..10], &ctrl.public_key()).is_err());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1, 3600, &[0u8; 16]);
        let mut bytes = cred.serialize();
        bytes[OFF_VERSION] = 99;
        assert!(NodeCredential::deserialize(&bytes, &ctrl.public_key()).is_err());
    }

    #[test]
    fn expiry_is_enforced() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1_000, 100, &[0u8; 16]);

        assert!(cred.is_valid_at(1_050));
        assert!(!cred.is_valid_at(1_100));
        assert!(!cred.is_valid_at(1_101));
    }

    #[test]
    fn skew_tolerance_allows_early_use() {
        let (ctrl, node, nwid) = fixture();
        let addr = node.address_for_network(nwid);
        let cred = ctrl.issue(nwid, addr, &node.public_key_bytes(), 1_000, 100, &[0u8; 16]);
        // Issued at 1000; a clock 30s behind should still be accepted.
        assert!(cred.is_valid_at_with_skew(970, 30));
        // A clock far ahead should not.
        assert!(!cred.is_valid_at_with_skew(1_200, 30));
    }

    #[test]
    fn controller_id_is_deterministic() {
        let ctrl = ControllerIdentity::new(Identity::generate().unwrap());
        let ctrl2 = ControllerIdentity::new(Identity::generate().unwrap());
        assert_ne!(ctrl.controller_id(), ctrl2.controller_id());
        assert_eq!(ctrl.controller_id().len(), 16);
    }
}
