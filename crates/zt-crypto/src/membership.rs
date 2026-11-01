//! Node membership credentials and their presentation in the handshake.
//!
//! # The problem this solves
//!
//! ZT-next's control plane issues short-lived, key-bound credentials. A node
//! may only take part in a network if the controller has issued it a
//! credential for that network, and that credential must still be valid.
//!
//! Without this, a node could complete a handshake with any peer that knew
//! its public key. The credential is what binds a peer to a network.
//!
//! # How a credential is presented
//!
//! The initiator sends its credential in the first handshake message. The
//! responder checks three things:
//!
//! 1. The credential was signed by a controller it trusts.
//! 2. The credential has not expired.
//! 3. The credential is bound to the initiator's static key.
//!
//! The responder replies with its own credential, and the initiator checks
//! the same three properties.
//!
//! Both checks happen **before** the handshake completes, so an
//! unauthorized peer never establishes a session.

use crate::credential::{NodeCredential, CONTROLLER_ID_LEN};
use crate::error::{Error, Result};
use crate::identity::{Address, PUBLIC_KEY_LEN};

/// The credential the responder expects from an initiator.
///
/// A node trusts one or more controllers. Each controller is identified by
/// its Ed25519 public key, which is the trust anchor.
#[derive(Clone, Debug)]
pub struct TrustedController {
    /// The controller's Ed25519 public key.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// The controller's identifier, for logging and diagnostics.
    pub controller_id: [u8; CONTROLLER_ID_LEN],
}

/// A set of trusted controllers.
///
/// A node may trust several controllers, for example during a controller
/// migration or when a shared control plane serves multiple networks.
#[derive(Clone, Debug, Default)]
pub struct ControllerTrust {
    controllers: Vec<TrustedController>,
}

impl ControllerTrust {
    /// Build an empty trust set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a trust set from a list of controllers.
    pub fn from_controllers(controllers: Vec<TrustedController>) -> Self {
        Self { controllers }
    }

    /// Trust a controller.
    pub fn add(&mut self, controller: TrustedController) {
        self.controllers.push(controller);
    }

    /// The number of trusted controllers.
    pub fn len(&self) -> usize {
        self.controllers.len()
    }

    /// Whether no controller is trusted.
    pub fn is_empty(&self) -> bool {
        self.controllers.is_empty()
    }

    /// The trusted controllers.
    pub fn controllers(&self) -> &[TrustedController] {
        &self.controllers
    }

    /// Verify a credential against the trusted controllers.
    ///
    /// Returns the credential when it is valid and signed by a trusted
    /// controller.
    pub fn verify<'a>(
        &self,
        credential: &'a NodeCredential,
        now_unix: u64,
    ) -> Result<&'a NodeCredential> {
        if self.controllers.is_empty() {
            return Err(Error::AuthenticationFailed);
        }

        // A credential that arrived over the wire keeps its original bytes,
        // so the signature can be checked against them. One that was issued
        // locally is re-serialized, which reproduces the same bytes.
        let bytes = credential.raw_bytes().map(<[u8]>::to_vec).unwrap_or_else(|| credential.serialize());

        for controller in &self.controllers {
            match NodeCredential::deserialize(&bytes, &controller.public_key) {
                Ok(parsed) => {
                    if parsed.is_valid_at(now_unix) {
                        return Ok(credential);
                    }
                    // The signature was valid but the credential has expired.
                    return Err(Error::AuthenticationFailed);
                }
                Err(_) => continue,
            }
        }
        Err(Error::AuthenticationFailed)
    }
}

/// The membership a node presents to its peers.
///
/// A node may belong to several networks. Each membership names the
/// credential for that network.
#[derive(Clone, Debug, Default)]
pub struct Membership {
    entries: Vec<MembershipEntry>,
}

/// One network membership.
#[derive(Clone, Debug)]
pub struct MembershipEntry {
    /// The network this membership is for.
    pub network_id: u64,
    /// The node's address on that network.
    pub address: Address,
    /// The credential that proves the membership.
    pub credential: NodeCredential,
}

impl Membership {
    /// Build an empty membership set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a membership.
    pub fn add(&mut self, network_id: u64, credential: NodeCredential) {
        let address = credential.node_address();
        self.entries.retain(|entry| entry.network_id != network_id);
        self.entries.push(MembershipEntry {
            network_id,
            address,
            credential,
        });
    }

    /// The number of memberships.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the node has no memberships.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The memberships.
    pub fn entries(&self) -> &[MembershipEntry] {
        &self.entries
    }

    /// Look up a membership by network.
    pub fn for_network(&self, network_id: u64) -> Option<&MembershipEntry> {
        self.entries
            .iter()
            .find(|entry| entry.network_id == network_id)
    }

    /// Select the membership to present to a peer.
    ///
    /// When the peer expects a specific network, that membership is used.
    /// Otherwise the first one is presented.
    pub fn select(&self, network_id: Option<u64>) -> Option<&MembershipEntry> {
        match network_id {
            Some(network_id) => self.for_network(network_id),
            None => self.entries.first(),
        }
    }

    /// Serialize the memberships for transmission.
    ///
    /// The wire format is a count followed by one credential per membership.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.entries.len() as u8);
        for entry in &self.entries {
            let credential = entry.credential.serialize();
            out.extend_from_slice(&(credential.len() as u16).to_be_bytes());
            out.extend_from_slice(&credential);
        }
        out
    }

    /// Parse memberships from the wire format.
    pub fn deserialize(bytes: &[u8]) -> Result<Membership> {
        if bytes.is_empty() {
            return Err(Error::InvalidLength);
        }
        let count = bytes[0] as usize;
        let mut offset = 1usize;
        let mut membership = Membership::new();

        for _ in 0..count {
            if bytes.len() < offset + 2 {
                return Err(Error::InvalidLength);
            }
            let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;
            if bytes.len() < offset + length {
                return Err(Error::InvalidLength);
            }
            // The credential is verified later, once the trust set is known.
            // Here we only need its network and address, which are inside the
            // signed body, so they are read from the wire format directly.
            let raw = &bytes[offset..offset + length];
            offset += length;

            if raw.len() < 19 {
                return Err(Error::InvalidLength);
            }
            let version = raw[0];
            if version != 1 {
                return Err(Error::InvalidKey("unsupported credential version"));
            }
            let mut network_bytes = [0u8; 8];
            network_bytes.copy_from_slice(&raw[1..9]);
            let network_id = u64::from_be_bytes(network_bytes);

            let mut address_bytes = [0u8; 10];
            address_bytes.copy_from_slice(&raw[9..19]);
            let address = Address::from_bytes(&address_bytes);

            membership.entries.push(MembershipEntry {
                network_id,
                address,
                credential: NodeCredential::from_parts(
                    raw.to_vec(),
                    network_id,
                    address,
                ),
            });
        }

        Ok(membership)
    }
}

/// Check that a credential is bound to a specific static key.
///
/// A credential proves membership for one node. If it is replayed by a
/// different node, the handshake signature will not match the credential's
/// public key, and the session must be rejected.
pub fn credential_matches_key(
    credential: &NodeCredential,
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> bool {
    credential.public_key() == public_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::ControllerIdentity;
    use crate::identity::Identity;

    fn credential(controller: &ControllerIdentity, node: &Identity, network_id: u64) -> NodeCredential {
        let address = node.address_for_network(network_id);
        controller.issue(
            network_id,
            address,
            &node.public_key_bytes(),
            1_700_000_000,
            3600,
            &[7u8; 16],
        )
    }

    #[test]
    fn a_trusted_controller_verifies_a_credential() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let cred = credential(&controller, &node, 42);

        let mut trust = ControllerTrust::new();
        trust.add(TrustedController {
            public_key: controller.public_key(),
            controller_id: *controller.controller_id(),
        });

        assert!(trust.verify(&cred, 1_700_000_100).is_ok());
    }

    #[test]
    fn an_untrusted_controller_is_rejected() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let other = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let cred = credential(&controller, &node, 42);

        let mut trust = ControllerTrust::new();
        trust.add(TrustedController {
            public_key: other.public_key(),
            controller_id: *other.controller_id(),
        });

        assert!(trust.verify(&cred, 1_700_000_100).is_err());
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let cred = credential(&controller, &node, 42);

        let mut trust = ControllerTrust::new();
        trust.add(TrustedController {
            public_key: controller.public_key(),
            controller_id: *controller.controller_id(),
        });

        // The credential was issued at 1_700_000_000 with a one-hour TTL,
        // so it expires at 1_700_003_600.
        assert!(trust.verify(&cred, 1_700_003_000).is_ok());
        assert!(trust.verify(&cred, 1_700_003_700).is_err());
    }

    #[test]
    fn an_empty_trust_set_rejects_everything() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let cred = credential(&controller, &node, 42);
        let trust = ControllerTrust::new();
        assert!(trust.verify(&cred, 1_700_000_100).is_err());
    }

    #[test]
    fn membership_round_trips() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();

        let mut membership = Membership::new();
        membership.add(42, credential(&controller, &node, 42));
        membership.add(99, credential(&controller, &node, 99));

        let bytes = membership.serialize();
        let parsed = Membership::deserialize(&bytes).expect("parse");

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.for_network(42).unwrap().network_id, 42);
        assert_eq!(parsed.for_network(99).unwrap().network_id, 99);
        assert!(parsed.for_network(1).is_none());
    }

    #[test]
    fn membership_selects_by_network() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();

        let mut membership = Membership::new();
        membership.add(42, credential(&controller, &node, 42));
        membership.add(99, credential(&controller, &node, 99));

        assert_eq!(membership.select(Some(99)).unwrap().network_id, 99);
        assert_eq!(membership.select(None).unwrap().network_id, 42);
    }

    #[test]
    fn adding_a_membership_replaces_the_previous_one() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();

        let mut membership = Membership::new();
        membership.add(42, credential(&controller, &node, 42));
        membership.add(42, credential(&controller, &node, 42));

        assert_eq!(membership.len(), 1);
    }

    #[test]
    fn a_credential_must_match_the_presenting_key() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();

        let cred = credential(&controller, &node, 42);
        assert!(credential_matches_key(&cred, &node.public_key_bytes()));
        assert!(!credential_matches_key(&cred, &other.public_key_bytes()));
    }
}
