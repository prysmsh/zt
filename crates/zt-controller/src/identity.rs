//! Controller identity storage.
//!
//! The controller's signing key is the root of trust for every credential it
//! issues. It is stored separately from operational data so that backups and
//! migrations can treat it as a distinct, highly sensitive secret.

use std::path::{Path, PathBuf};

use zt_crypto::credential::ControllerIdentity;
use zt_crypto::identity::{Identity, PRIVATE_KEY_LEN};

use crate::error::{ControllerError, Result};

/// On-disk layout for the controller identity.
#[derive(Clone, Debug)]
pub struct IdentityStore {
    path: PathBuf,
}

impl IdentityStore {
    /// Create a store rooted at `path`.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// The identity file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the identity, creating it if the file does not exist.
    pub fn load_or_create(&self) -> Result<ControllerIdentity> {
        if self.path.exists() {
            return self.load();
        }
        let identity = ControllerIdentity::new(Identity::generate()?);
        self.save(&identity)?;
        Ok(identity)
    }

    /// Load an existing identity.
    pub fn load(&self) -> Result<ControllerIdentity> {
        let contents = std::fs::read_to_string(&self.path).map_err(|error| {
            ControllerError::Internal(format!(
                "cannot read controller identity {}: {error}",
                self.path.display()
            ))
        })?;
        let trimmed = contents.trim();
        let bytes = hex::decode(trimmed).map_err(|_| {
            ControllerError::Internal("controller identity is not valid hex".into())
        })?;
        if bytes.len() != PRIVATE_KEY_LEN {
            return Err(ControllerError::Internal(
                "controller identity must be a 32-byte Ed25519 seed".into(),
            ));
        }
        let mut seed = [0u8; PRIVATE_KEY_LEN];
        seed.copy_from_slice(&bytes);
        Ok(ControllerIdentity::from_private_key_seed(&seed))
    }

    /// Write the identity to disk with owner-only permissions.
    pub fn save(&self, identity: &ControllerIdentity) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    ControllerError::Internal(format!(
                        "cannot create identity directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }

        let mut file = std::fs::File::create(&self.path).map_err(|error| {
            ControllerError::Internal(format!(
                "cannot create controller identity {}: {error}",
                self.path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    ControllerError::Internal(format!(
                        "cannot set controller identity permissions: {error}"
                    ))
                })?;
        }
        use std::io::Write;
        writeln!(file, "{}", hex::encode(identity.private_key_seed())).map_err(|error| {
            ControllerError::Internal(format!("cannot write identity: {error}"))
        })?;
        Ok(())
    }
}
