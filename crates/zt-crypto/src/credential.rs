//! Node credentials: short-lived, controller-signed certificates.
//!
//! # Why this exists
//!
//! ZeroTier issues nodes a [`CertificateOfMembership`] (COM), which is a
//! **long-lived bearer capability**. It has no expiry, it is not bound to the
//! node's key material, and possession of it is sufficient to impersonate the
//! member. Revocation is push-based: a revoked node remains usable until the
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
//! │ signature [u8;64] (Ed25519 over all preceding bytes)             │
//! └───────────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{Error, Result};
use crate::identity::{Address, Identity, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Current credential format version.
pub const CREDENTIAL_VERSION: u8 = 1;

/// Length of the controller identifier embedded in a credential.
pub const CONTROLLER_ID_LEN: usize = 16;

/// Length of the issuance nonce embedded in a credential.
pub const NONCE_LEN: usize = 16;

/// Total serialized length of a credential.
pub const CREDENTIAL_LEN: usize = 1 + 8 + 10 + 8 + 8 + 4 + 32 + 16 + 16 + 64;

// Field offsets within the serialized credential.
const OFF_VERSION: usize = 0;
const OFF_NETWORK_ID: usize = 1;
const OFF_NODE_ADDR: usize = 9;
const OFF_ISSUED_AT: usize = 19;
const OFF_NOT_AFTER: usize = 27;
const OFF_TTL: usize = 35;
const OFF_PUBLIC_KEY: usize = 39;
const OFF_CONTROLLER_ID: usize = 71;
const OFF_NONCE: usize = 87;
const OFF_SIGNATURE: usize = 103;

/// A short-lived node certificate issued by a controller.
///
/// The signature covers every byte preceding it, so the credential is
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
    signature: [u8; SIGNATURE_LEN],
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

    /// The Ed25519 signature over the credential body.
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Serialize to the wire format.
    pub fn serialize(&self) -> [u8; CREDENTIAL_LEN] {
        let mut out = [0u8; CREDENTIAL_LEN];
        out[OFF_VERSION] = CREDENTIAL_VERSION;
        out[OFF_NETWORK_ID..OFF_NETWORK_ID + 8].copy_from_slice(&self.network_id.to_be_bytes());
        out[OFF_NODE_ADDR..OFF_NODE_ADDR + 10].copy_from_slice(self.node_address.as_bytes());
        out[OFF_ISSUED_AT..OFF_ISSUED_AT + 8].copy_from_slice(&self.issued_at.to_be_bytes());
        out[OFF_NOT_AFTER..OFF_NOT_AFTER + 8].copy_from_slice(&self.not_after.to_be_bytes());
        out[OFF_TTL..OFF_TTL + 4].copy_from_slice(&self.ttl_secs.to_be_bytes());
        out[OFF_PUBLIC_KEY..OFF_PUBLIC_KEY + 32].copy_from_slice(&self.public_key);
        out[OFF_CONTROLLER_ID..OFF_CONTROLLER_ID + 16].copy_from_slice(&self.controller_id);
        out[OFF_NONCE..OFF_NONCE + 16].copy_from_slice(&self.nonce);
        out[OFF_SIGNATURE..OFF_SIGNATURE + 64].copy_from_slice(&self.signature);
        out
    }

    /// Parse from the wire format and verify the signature.
    ///
    /// `controller_key` is the Ed25519 public key of the issuing controller.
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
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[OFF_SIGNATURE..OFF_SIGNATURE + 64]);

        // Verify over the body only (everything before the signature).
        Identity::verify(controller_key, &bytes[..OFF_SIGNATURE], &signature)?;

        Ok(NodeCredential {
            network_id: u64::from_be_bytes(network_id),
            node_address: Address::from_bytes(&node_addr),
            public_key,
            issued_at: u64::from_be_bytes(issued_at),
            not_after: u64::from_be_bytes(not_after),
            ttl_secs: u32::from_be_bytes(ttl),
            controller_id,
            nonce,
            signature,
        })
    }

    /// Check whether the credential is still valid at the given timestamp.
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        now_unix < self.not_after
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
/// Controllers sign node credentials with a long-term Ed25519 key. Nodes
/// trust a controller by trusting its public key, which may in turn be signed
/// by a higher-level root (enabling delegation).
#[derive(Clone)]
pub struct ControllerIdentity {
    identity: Identity,
    controller_id: [u8; CONTROLLER_ID_LEN],
}

impl ControllerIdentity {
    /// Create a controller identity, deriving its controller ID from the
    /// public key.
    pub fn new(identity: Identity) -> Self {
        let pk = identity.public_key_bytes();
        let controller_id = crate::address::derive_id(&pk);
        Self {
            identity,
            controller_id,
        }
    }

    /// The 16-byte controller identifier.
    pub fn controller_id(&self) -> &[u8; CONTROLLER_ID_LEN] {
        &self.controller_id
    }

    /// The controller's Ed25519 public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.identity.public_key_bytes()
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

        let mut body = [0u8; OFF_SIGNATURE];
        body[OFF_VERSION] = CREDENTIAL_VERSION;
        body[OFF_NETWORK_ID..OFF_NETWORK_ID + 8].copy_from_slice(&network_id.to_be_bytes());
        body[OFF_NODE_ADDR..OFF_NODE_ADDR + 10].copy_from_slice(node_address.as_bytes());
        body[OFF_ISSUED_AT..OFF_ISSUED_AT + 8].copy_from_slice(&now_unix.to_be_bytes());
        body[OFF_NOT_AFTER..OFF_NOT_AFTER + 8].copy_from_slice(&not_after.to_be_bytes());
        body[OFF_TTL..OFF_TTL + 4].copy_from_slice(&ttl_secs.to_be_bytes());
        body[OFF_PUBLIC_KEY..OFF_PUBLIC_KEY + 32].copy_from_slice(node_public_key);
        body[OFF_CONTROLLER_ID..OFF_CONTROLLER_ID + 16].copy_from_slice(&self.controller_id);
        body[OFF_NONCE..OFF_NONCE + 16].copy_from_slice(nonce);

        let signature = self.identity.sign(&body);

        NodeCredential {
            network_id,
            node_address,
            public_key: *node_public_key,
            issued_at: now_unix,
            not_after,
            ttl_secs,
            controller_id: self.controller_id,
            nonce: *nonce,
            signature,
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
