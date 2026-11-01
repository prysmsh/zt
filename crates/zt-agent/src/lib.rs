//! The ZT-next node agent.
//!
//! The agent is the piece that connects the control plane to the data
//! plane. It:
//!
//! 1. Holds the node's long-term identity.
//! 2. Enrolls with a controller and stores the issued credential.
//! 3. Renews the credential before it expires.
//! 4. Verifies credentials presented by peers during the handshake.
//!
//! # Why this is separate from `zt-node`
//!
//! `zt-node` is the transport and session layer. It knows nothing about
//! controllers. The agent sits above it and supplies the membership
//! material that the handshake needs. Keeping them separate means the
//! protocol core has no HTTP dependencies.

pub mod client;
pub mod error;
pub mod state;

use std::path::PathBuf;
use std::time::Duration;

use zt_crypto::credential::NodeCredential;
use zt_crypto::membership::{ControllerTrust, Membership, TrustedController};

pub use client::{ControllerClient, ControllerNode, EnrollResponse};
pub use error::{AgentError, Result};
pub use state::{default_state_path, NodeState};

/// Configuration for an agent.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// The controller's base URL.
    pub controller_url: String,
    /// The tenant the node belongs to.
    pub tenant: String,
    /// The network the node joins.
    pub network_id: String,
    /// Where the node state is stored.
    pub state_path: PathBuf,
    /// Renew the credential when this fraction of its lifetime has elapsed.
    pub renew_after_fraction: f64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            controller_url: "http://127.0.0.1:8080".into(),
            tenant: String::new(),
            network_id: String::new(),
            state_path: default_state_path(),
            // Renew once three quarters of the lifetime has elapsed, leaving
            // room for a retry if the controller is briefly unavailable.
            renew_after_fraction: 0.75,
        }
    }
}

/// The node agent.
pub struct Agent {
    config: AgentConfig,
    client: ControllerClient,
    state: NodeState,
}

impl Agent {
    /// Open the agent, creating the node identity if needed.
    pub fn open(config: AgentConfig) -> Result<Self> {
        let mut config = config;

        // The tenant-scoped API takes a tenant ID. Resolve a slug to one so
        // operators can use the name they see in the console. This happens
        // before the client is built, so every request is addressed by ID.
        if !config.tenant.is_empty() {
            let resolver = ControllerClient::new(&config.controller_url, &config.tenant);
            config.tenant = resolver.resolve_tenant(&config.tenant)?;
        }

        let client = ControllerClient::new(&config.controller_url, &config.tenant);

        // On first run the controller's public key is fetched, because it is
        // the trust anchor and must not be guessed.
        let (controller_key, controller_id) = if config.state_path.exists() {
            (None, None)
        } else {
            let (key, id) = fetch_controller_identity(&client)?;
            (Some(key), Some(id))
        };

        let state = NodeState::load_or_create(&config.state_path, controller_key, controller_id)?;

        // The client presents the node's credential, so the controller can
        // tell which node is calling. A node that has not enrolled yet has
        // no credential, and its first request is refused.
        let client = match state.credential_hex() {
            Some(credential) => client.with_credential(credential),
            None => client,
        };

        Ok(Self {
            config,
            client,
            state,
        })
    }

    /// The agent's current state.
    pub fn state(&self) -> &NodeState {
        &self.state
    }

    /// The agent's state, mutably.
    pub fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    /// Write the agent's state to disk.
    pub fn save(&self) -> Result<()> {
        self.state.write(&self.config.state_path)
    }

    /// The controller client.
    pub fn client(&self) -> &ControllerClient {
        &self.client
    }

    /// Enroll this node with the controller.
    ///
    /// The node sends only its public key. The controller returns a
    /// short-lived credential, which is stored.
    pub fn enroll(&mut self, name: &str, tags: &[String]) -> Result<EnrollResponse> {
        let public_key = self.state.public_key_hex()?;
        let pq_public_key = self.state.pq_public_key_hex()?;

        let response = self.client.enroll(
            &self.config.network_id,
            name,
            &public_key,
            &pq_public_key,
            tags,
        )?;

        self.state.set_credential(
            &response.node.id,
            &response.node.network_id,
            &response.credential,
            response.credential_not_after,
        );
        self.state.write(&self.config.state_path)?;
        self.client.set_credential(&response.credential);

        Ok(response)
    }

    /// Adopt a credential that an operator issued for this node.
    ///
    /// The controller authenticates a node with the credential it issued
    /// it, so a node that was enrolled by an operator adopts that
    /// credential instead of enrolling itself. The node then asks the
    /// controller who it is, which is how it learns its own identifier.
    ///
    /// This is the path a real deployment takes: the operator enrols the
    /// node from the console, and the credential is handed to the node.
    pub fn adopt(&mut self, credential: &str) -> Result<ControllerNode> {
        // The credential is verified against the pinned controller key
        // before it is stored, so a wrong or foreign credential is refused
        // rather than kept.
        let parsed = NodeCredential::deserialize(
            &hex::decode(credential)
                .map_err(|_| AgentError::Credential("the credential is not hex".into()))?,
            &self.state.controller_public_key()?,
        )
        .map_err(|error| AgentError::Credential(error.to_string()))?;

        self.state
            .set_credential("", "", credential, parsed.not_after());
        self.client.set_credential(credential);

        // The controller knows which node the credential belongs to.
        let node = self.client.self_node()?;
        self.state
            .set_credential(&node.id, &node.network_id, credential, parsed.not_after());
        self.state.write(&self.config.state_path)?;

        Ok(node)
    }

    /// Renew the credential now, whether it is due or not.
    ///
    /// The node has to know its own identifier to renew, which it learns
    /// by adopting the credential the operator issued it.
    pub fn renew_now(&mut self) -> Result<EnrollResponse> {
        if self.state.node_id.is_empty() {
            return Err(AgentError::NotEnrolled);
        }

        let response = self.client.renew_credential(&self.state.node_id)?;
        self.state.set_credential(
            &response.node.id,
            &response.node.network_id,
            &response.credential,
            response.credential_not_after,
        );
        self.state.write(&self.config.state_path)?;
        self.client.set_credential(&response.credential);
        Ok(response)
    }

    /// Renew the credential if it is due for renewal.
    ///
    /// Returns the new credential when a renewal happened.
    pub fn renew_if_due(&mut self, now_unix: u64) -> Result<Option<EnrollResponse>> {
        if self.state.node_id.is_empty() {
            return Err(AgentError::NotEnrolled);
        }
        if !self.needs_renewal(now_unix) {
            return Ok(None);
        }

        let response = self.client.renew_credential(&self.state.node_id)?;
        self.state.set_credential(
            &response.node.id,
            &response.node.network_id,
            &response.credential,
            response.credential_not_after,
        );
        self.state.write(&self.config.state_path)?;
        self.client.set_credential(&response.credential);
        Ok(Some(response))
    }

    /// Whether the credential should be renewed now.
    pub fn needs_renewal(&self, now_unix: u64) -> bool {
        if self.state.node_id.is_empty() {
            return true;
        }
        if self.state.credential_expired(now_unix) {
            return true;
        }

        let lifetime = self.state.credential_ttl(now_unix);
        let _ = lifetime;

        // The credential is renewed once most of its lifetime has elapsed.
        // The threshold is relative to the issued time, which is not stored
        // separately, so the age is estimated from the remaining time.
        let issued_at = self
            .state
            .credential_not_after
            .saturating_sub(self.config_credential_lifetime());
        let age = now_unix.saturating_sub(issued_at);
        let total = self.config_credential_lifetime();
        if total == 0 {
            return true;
        }
        age as f64 / total as f64 >= self.config.renew_after_fraction
    }

    fn config_credential_lifetime(&self) -> u64 {
        // The lifetime is the credential's TTL. It is recovered by asking the
        // controller, or inferred from the stored credential.
        self.state
            .credential()
            .map(|credential| credential.ttl_secs() as u64)
            .unwrap_or(0)
    }

    /// Build the membership this node presents to peers.
    pub fn membership(&self) -> Result<Membership> {
        let credential = self.state.credential()?;
        let mut membership = Membership::new();
        membership.add(credential.network_id(), credential);
        Ok(membership)
    }

    /// Build the set of controllers this node trusts.
    pub fn trust(&self) -> Result<ControllerTrust> {
        let controller_key = self.state.controller_public_key()?;
        let controller_id = hex::decode(&self.state.controller_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or([0u8; 16]);

        let mut trust = ControllerTrust::new();
        trust.add(TrustedController {
            public_key: controller_key,
            controller_id,
        });
        Ok(trust)
    }

    /// Verify a credential presented by a peer.
    pub fn verify_peer_credential(
        &self,
        credential: &zt_crypto::credential::NodeCredential,
        now_unix: u64,
    ) -> Result<()> {
        self.trust()?.verify(credential, now_unix)?;
        Ok(())
    }
}

/// Fetch the controller's public trust anchor and identity.
fn fetch_controller_identity(client: &ControllerClient) -> Result<([u8; 32], [u8; 16])> {
    let response = client.controller_info()?;

    let key = hex::decode(&response.public_key)
        .map_err(|_| AgentError::InvalidConfig("controller key is not valid hex".into()))?
        .try_into()
        .map_err(|_| AgentError::InvalidConfig("controller key must be 32 bytes".into()))?;

    let id = hex::decode(&response.id)
        .map_err(|_| AgentError::InvalidConfig("controller id is not valid hex".into()))?
        .try_into()
        .map_err(|_| AgentError::InvalidConfig("controller id must be 16 bytes".into()))?;

    Ok((key, id))
}

/// How long the agent should wait between renewal checks.
pub const RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use zt_crypto::credential::ControllerIdentity;
    use zt_crypto::identity::Identity;

    #[test]
    fn an_unenrolled_node_needs_enrollment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");
        let state =
            NodeState::load_or_create(&path, Some([3u8; 32]), Some([4u8; 16])).expect("create");
        let config = AgentConfig {
            state_path: path,
            ..Default::default()
        };
        let agent = Agent {
            config,
            client: ControllerClient::new("http://127.0.0.1:8080", "acme"),
            state,
        };

        assert!(agent.needs_renewal(1_000));
        assert!(matches!(agent.membership(), Err(AgentError::NotEnrolled)));
    }

    #[test]
    fn a_fresh_credential_does_not_need_renewal() {
        let controller = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let now = 1_700_000_000u64;

        let credential = controller.issue(
            42,
            node.address_for_network(42),
            &node.public_key_bytes(),
            now,
            3600,
            &[7u8; 16],
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");
        let mut state = NodeState::load_or_create(
            &path,
            Some(controller.public_key()),
            Some(*controller.controller_id()),
        )
        .expect("create");
        state.set_credential(
            "node-1",
            "net-1",
            &hex::encode(credential.serialize()),
            credential.not_after(),
        );

        let config = AgentConfig {
            state_path: path,
            ..Default::default()
        };
        let agent = Agent {
            config,
            client: ControllerClient::new("http://127.0.0.1:8080", "acme"),
            state,
        };

        assert!(!agent.needs_renewal(now + 60));
        // Three quarters through the lifetime, renewal is due.
        assert!(agent.needs_renewal(now + 2800));

        let membership = agent.membership().expect("membership");
        assert_eq!(membership.len(), 1);
        assert_eq!(membership.for_network(42).unwrap().network_id, 42);
    }

    #[test]
    fn a_peer_credential_from_an_untrusted_controller_is_rejected() {
        let trusted = ControllerIdentity::new(Identity::generate().unwrap());
        let other = ControllerIdentity::new(Identity::generate().unwrap());
        let node = Identity::generate().unwrap();
        let now = 1_700_000_000u64;

        let credential = other.issue(
            42,
            node.address_for_network(42),
            &node.public_key_bytes(),
            now,
            3600,
            &[7u8; 16],
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");
        let state = NodeState::load_or_create(
            &path,
            Some(trusted.public_key()),
            Some(*trusted.controller_id()),
        )
        .expect("create");

        let config = AgentConfig {
            state_path: path,
            ..Default::default()
        };
        let agent = Agent {
            config,
            client: ControllerClient::new("http://127.0.0.1:8080", "acme"),
            state,
        };

        assert!(agent.verify_peer_credential(&credential, now).is_err());
    }
}
