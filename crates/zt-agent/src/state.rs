//! Persistent node state.
//!
//! A node's state is small enough to keep in one file: its long-term
//! identity, the controller it trusts, and the credentials it has been
//! issued. The file is written with owner-only permissions because it
//! contains private key material.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zt_crypto::credential::NodeCredential;
use zt_crypto::identity::Identity;

use crate::error::{AgentError, Result};

/// The on-disk state of a node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeState {
    /// The node's long-term Ed25519 seed, hex encoded.
    pub identity_seed: String,
    /// The controller's Ed25519 public key, hex encoded.
    pub controller_key: String,
    /// The controller's identifier, hex encoded.
    pub controller_id: String,
    /// The node's ID in the controller.
    pub node_id: String,
    /// The network the node belongs to.
    pub network_id: String,
    /// The credential for that network, hex encoded.
    pub credential: String,
    /// When the credential expires.
    pub credential_not_after: u64,
}

impl NodeState {
    /// Load the state, creating an identity if the file does not exist.
    ///
    /// The controller's public key must be supplied on first run, because it
    /// is the trust anchor and cannot be guessed.
    pub fn load_or_create(
        path: &Path,
        controller_public_key: Option<[u8; 32]>,
        controller_id: Option<[u8; 16]>,
    ) -> Result<NodeState> {
        if path.exists() {
            return Self::read(path);
        }

        let Some(controller_key) = controller_public_key else {
            return Err(AgentError::InvalidConfig(
                "a controller public key is required to create a new node".into(),
            ));
        };

        let identity = Identity::generate()
            .map_err(|error| AgentError::Crypto(error.to_string()))?;

        let state = NodeState {
            identity_seed: hex::encode(identity.private_key_bytes()),
            controller_key: hex::encode(controller_key),
            controller_id: hex::encode(controller_id.unwrap_or([0u8; 16])),
            node_id: String::new(),
            network_id: String::new(),
            credential: String::new(),
            credential_not_after: 0,
        };

        state.write(path)?;
        Ok(state)
    }

    /// Read the state from disk.
    pub fn read(path: &Path) -> Result<NodeState> {
        let contents = std::fs::read_to_string(path).map_err(|error| {
            AgentError::Io(format!("cannot read {}: {error}", path.display()))
        })?;
        serde_json::from_str(&contents)
            .map_err(|error| AgentError::InvalidConfig(format!("invalid node state: {error}")))
    }

    /// Write the state to disk with owner-only permissions.
    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    AgentError::Io(format!("cannot create {}: {error}", parent.display()))
                })?;
            }
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|error| AgentError::InvalidConfig(error.to_string()))?;

        // Write to a temporary file and rename it, so a crash cannot leave a
        // half-written state file behind.
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, json).map_err(|error| {
            AgentError::Io(format!("cannot write {}: {error}", temporary.display()))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    AgentError::Io(format!("cannot set permissions: {error}"))
                })?;
        }

        std::fs::rename(&temporary, path).map_err(|error| {
            AgentError::Io(format!("cannot replace {}: {error}", path.display()))
        })?;
        Ok(())
    }

    /// The node's long-term identity.
    pub fn identity(&self) -> Result<Identity> {
        let bytes = hex::decode(&self.identity_seed)
            .map_err(|_| AgentError::InvalidConfig("identity seed is not valid hex".into()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AgentError::InvalidConfig("identity seed must be 32 bytes".into()))?;
        Ok(Identity::from_bytes(&seed))
    }

    /// The node's public key, hex encoded.
    pub fn public_key_hex(&self) -> Result<String> {
        Ok(hex::encode(self.identity()?.public_key_bytes()))
    }

    /// The controller's public key.
    pub fn controller_public_key(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.controller_key)
            .map_err(|_| AgentError::InvalidConfig("controller key is not valid hex".into()))?;
        bytes
            .try_into()
            .map_err(|_| AgentError::InvalidConfig("controller key must be 32 bytes".into()))
    }

    /// The controller's identity, reconstructed for signing.
    ///
    /// A controller identity is built from a private seed, so it cannot be
    /// reconstructed from a public key. The trust anchor is therefore used
    /// directly, via [`NodeState::controller_public_key`].
    pub fn controller_trust_anchor(&self) -> Result<[u8; 32]> {
        self.controller_public_key()
    }

    /// The current credential.
    pub fn credential(&self) -> Result<NodeCredential> {
        if self.credential.is_empty() {
            return Err(AgentError::NotEnrolled);
        }
        let bytes = hex::decode(&self.credential)
            .map_err(|_| AgentError::InvalidConfig("credential is not valid hex".into()))?;
        let controller_key = self.controller_public_key()?;
        NodeCredential::deserialize(&bytes, &controller_key)
            .map_err(|error| AgentError::Credential(error.to_string()))
    }

    /// The credential, hex encoded, if the node has enrolled.
    pub fn credential_hex(&self) -> Option<String> {
        if self.credential.is_empty() {
            None
        } else {
            Some(self.credential.clone())
        }
    }

    /// Whether the credential has expired.
    pub fn credential_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.credential_not_after
    }

    /// How long until the credential expires, in seconds.
    pub fn credential_ttl(&self, now_unix: u64) -> u64 {
        self.credential_not_after.saturating_sub(now_unix)
    }

    /// Store a newly issued credential.
    pub fn set_credential(
        &mut self,
        node_id: &str,
        network_id: &str,
        credential: &str,
        not_after: u64,
    ) {
        self.node_id = node_id.to_string();
        self.network_id = network_id.to_string();
        self.credential = credential.to_string();
        self.credential_not_after = not_after;
    }
}

/// The default location of the node state file.
pub fn default_state_path() -> PathBuf {
    PathBuf::from("zt-node.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");

        let state = NodeState::load_or_create(&path, Some([3u8; 32]), Some([4u8; 16])).expect("create");
        // A fresh node has an identity but has not enrolled, so it has no
        // controller-assigned identifiers yet.
        assert!(state.node_id.is_empty());
        assert!(state.network_id.is_empty());
        assert!(!state.identity_seed.is_empty());

        let loaded = NodeState::read(&path).expect("read");
        assert_eq!(loaded.identity_seed, state.identity_seed);
        assert_eq!(loaded.controller_key, state.controller_key);
    }

    #[test]
    fn creating_requires_a_controller_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");
        let result = NodeState::load_or_create(&path, None, None);
        assert!(matches!(result, Err(AgentError::InvalidConfig(_))));
    }

    #[test]
    fn the_identity_is_stable_across_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");

        let state = NodeState::load_or_create(&path, Some([3u8; 32]), Some([4u8; 16])).expect("create");
        let key = state.public_key_hex().expect("key");

        let loaded = NodeState::read(&path).expect("read");
        assert_eq!(loaded.public_key_hex().expect("key"), key);
    }

    #[test]
    fn expiry_is_calculated_from_the_stored_timestamp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");
        let mut state =
            NodeState::load_or_create(&path, Some([3u8; 32]), Some([4u8; 16])).expect("create");

        state.set_credential("node-1", "net-1", "00", 2_000);
        assert!(!state.credential_expired(1_000));
        assert!(state.credential_expired(2_000));
        assert_eq!(state.credential_ttl(1_000), 1_000);
        assert_eq!(state.credential_ttl(3_000), 0);
    }

    #[cfg(unix)]
    #[test]
    fn the_state_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.json");
        NodeState::load_or_create(&path, Some([3u8; 32]), Some([4u8; 16])).expect("create");

        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
