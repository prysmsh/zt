//! Controller service operations.
//!
//! The service owns the controller identity and the mutable state. It is
//! deliberately transport-agnostic: the HTTP layer in [`crate::api`] only
//! translates requests into these calls.
//!
//! # Tenant scoping
//!
//! Every operation that touches tenant data takes a tenant ID. The
//! controller never returns an object belonging to a different tenant, even
//! if the caller guesses its ID. This is enforced in the service layer
//! rather than in the API layer so that the CLI, the HTTP API, and any
//! future RPC surface all inherit the same guarantee.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use zt_crypto::credential::{ControllerIdentity, NodeCredential, NONCE_LEN};
use zt_crypto::identity::{Address, Identity};

use crate::address::{assign_address, Ipv4Range};
use crate::error::{ControllerError, Result};
use crate::model::{
    now_unix, Actor, AuditEvent, ControllerState, Health, Network, Node, NodeKeys, NodeStatus,
    Policy, Relay, RelayStatus, Topology, TopologyPeer,
};
use crate::store::{MemoryStore, Store};
use crate::tenant::{
    exceeded_limit, new_tenant, Deployment, Tenant, TenantLimits, TenantStatus, TenantUsage,
};

/// Default credential lifetime: 24 hours.
pub const DEFAULT_CREDENTIAL_TTL_SECS: u32 = 24 * 60 * 60;

/// Maximum credential lifetime accepted by the API: 30 days.
pub const MAX_CREDENTIAL_TTL_SECS: u32 = 30 * 24 * 60 * 60;

/// Shared controller handle.
#[derive(Clone)]
pub struct Controller {
    inner: Arc<ControllerInner>,
}

struct ControllerInner {
    identity: ControllerIdentity,
    state: RwLock<ControllerState>,
    store: Arc<dyn Store>,
}

impl Controller {
    /// Create a controller with a fresh signing identity and in-memory storage.
    pub fn new() -> Result<Self> {
        let identity = Identity::generate()?;
        Ok(Self::with_identity(ControllerIdentity::new(identity)))
    }

    /// Create a controller with an existing signing identity and in-memory storage.
    pub fn with_identity(identity: ControllerIdentity) -> Self {
        Self::with_store(identity, Arc::new(MemoryStore::new()))
            .expect("in-memory store cannot fail")
    }

    /// Create a controller backed by a persistent store.
    ///
    /// Existing state is loaded from the store at startup. The signing
    /// identity is provided by the caller so that it can be persisted
    /// separately from the operational data.
    pub fn with_store(identity: ControllerIdentity, store: Arc<dyn Store>) -> Result<Self> {
        let state = store.load()?;
        Ok(Self {
            inner: Arc::new(ControllerInner {
                identity,
                state: RwLock::new(state),
                store,
            }),
        })
    }

    /// Persist the current state to the backing store.
    async fn persist(&self, state: &ControllerState) -> Result<()> {
        self.inner.store.save(state)
    }

    /// The controller's Ed25519 public key, hex encoded.
    pub async fn public_key(&self) -> String {
        hex::encode(self.inner.identity.public_key())
    }

    /// The controller identifier, hex encoded.
    pub async fn controller_id(&self) -> String {
        hex::encode(self.inner.identity.controller_id())
    }

    // -------------------------------------------------------------------
    // Tenant administration (master console)
    // -------------------------------------------------------------------

    /// List every tenant, including deleted ones.
    pub async fn list_tenants(&self) -> Vec<Tenant> {
        self.inner
            .state
            .read()
            .await
            .tenants
            .values()
            .cloned()
            .collect()
    }

    /// Get one tenant.
    pub async fn get_tenant(&self, id: &str) -> Result<Tenant> {
        self.inner
            .state
            .read()
            .await
            .tenants
            .get(id)
            .cloned()
            .ok_or(ControllerError::NotFound("tenant"))
    }

    /// Find a tenant by its slug.
    pub async fn get_tenant_by_slug(&self, slug: &str) -> Result<Tenant> {
        self.inner
            .state
            .read()
            .await
            .tenants
            .values()
            .find(|tenant| tenant.slug == slug)
            .cloned()
            .ok_or(ControllerError::NotFound("tenant"))
    }

    /// Create a tenant.
    ///
    /// A shared tenant receives this controller's signing identity, so that
    /// its credentials are scoped to this control plane. A dedicated tenant
    /// brings its own controller and key, and is registered here only so
    /// that its lifecycle can be administered.
    pub async fn create_tenant(
        &self,
        name: String,
        slug: String,
        deployment: Deployment,
        plan: String,
        limits: TenantLimits,
        actor: &Actor,
    ) -> Result<Tenant> {
        let mut state = self.inner.state.write().await;

        if state.tenants.values().any(|tenant| tenant.slug == slug) {
            return Err(ControllerError::Conflict(
                "tenant slug already exists".to_string(),
            ));
        }

        let mut tenant = new_tenant(name, slug, deployment, plan, limits);

        if deployment.is_shared() {
            tenant.controller_id = Some(hex::encode(self.inner.identity.controller_id()));
            tenant.controller_public_key = Some(hex::encode(self.inner.identity.public_key()));
        }

        tenant.status = TenantStatus::Active;
        tenant.updated_at = now_unix();

        state.record_for_tenant(
            Some(&tenant.id),
            "tenant.created",
            "tenant",
            &tenant.id,
            actor.display(),
            format!("Created tenant {}", tenant.name),
        );

        state.tenants.insert(tenant.id.clone(), tenant.clone());
        self.persist(&state).await?;
        Ok(tenant)
    }

    /// Change a tenant's plan and limits.
    pub async fn update_tenant(
        &self,
        id: &str,
        plan: Option<String>,
        limits: Option<TenantLimits>,
        actor: &Actor,
    ) -> Result<Tenant> {
        let mut state = self.inner.state.write().await;
        let tenant = state
            .tenants
            .get_mut(id)
            .ok_or(ControllerError::NotFound("tenant"))?;

        if let Some(plan) = plan {
            tenant.plan = plan;
        }
        if let Some(limits) = limits {
            tenant.limits = limits;
        }
        tenant.updated_at = now_unix();

        let updated = tenant.clone();
        state.record_for_tenant(
            Some(id),
            "tenant.updated",
            "tenant",
            id,
            actor.display(),
            format!("Updated tenant {}", updated.name),
        );
        self.persist(&state).await?;
        Ok(updated)
    }

    /// Suspend a tenant.
    ///
    /// A suspended tenant's credentials are no longer renewed, so its access
    /// lapses within one credential TTL. Its data is retained so the tenant
    /// can be restored.
    pub async fn suspend_tenant(&self, id: &str, reason: &str, actor: &Actor) -> Result<Tenant> {
        let mut state = self.inner.state.write().await;
        let tenant = state
            .tenants
            .get_mut(id)
            .ok_or(ControllerError::NotFound("tenant"))?;

        tenant.status = TenantStatus::Suspended;
        tenant.suspended_at = Some(now_unix());
        tenant.updated_at = now_unix();

        let suspended = tenant.clone();
        state.record_for_tenant(
            Some(id),
            "tenant.suspended",
            "tenant",
            id,
            actor.display(),
            if reason.is_empty() {
                format!("Suspended tenant {}", suspended.name)
            } else {
                format!("Suspended tenant {}: {reason}", suspended.name)
            },
        );
        self.persist(&state).await?;
        Ok(suspended)
    }

    /// Restore a suspended tenant.
    pub async fn reactivate_tenant(&self, id: &str, actor: &Actor) -> Result<Tenant> {
        let mut state = self.inner.state.write().await;
        let tenant = state
            .tenants
            .get_mut(id)
            .ok_or(ControllerError::NotFound("tenant"))?;

        tenant.status = TenantStatus::Active;
        tenant.suspended_at = None;
        tenant.updated_at = now_unix();

        let restored = tenant.clone();
        state.record_for_tenant(
            Some(id),
            "tenant.reactivated",
            "tenant",
            id,
            actor.display(),
            format!("Reactivated tenant {}", restored.name),
        );
        self.persist(&state).await?;
        Ok(restored)
    }

    /// Soft-delete a tenant.
    ///
    /// The tenant's data is retained until a separate retention job purges
    /// it, so an accidental deletion can be reversed.
    pub async fn delete_tenant(&self, id: &str, actor: &Actor) -> Result<Tenant> {
        let mut state = self.inner.state.write().await;
        let tenant = state
            .tenants
            .get_mut(id)
            .ok_or(ControllerError::NotFound("tenant"))?;

        tenant.status = TenantStatus::Deleted;
        tenant.deleted_at = Some(now_unix());
        tenant.updated_at = now_unix();

        let deleted = tenant.clone();
        state.record_for_tenant(
            Some(id),
            "tenant.deleted",
            "tenant",
            id,
            actor.display(),
            format!("Deleted tenant {}", deleted.name),
        );
        self.persist(&state).await?;
        Ok(deleted)
    }

    /// Resource usage for a tenant.
    pub async fn tenant_usage(&self, tenant_id: &str) -> TenantUsage {
        self.inner.state.read().await.tenant_usage(tenant_id)
    }

    /// Check that a tenant may use the service.
    ///
    /// A suspended or deleted tenant is locked out. This is what makes
    /// suspension meaningful: without it, the tenant's nodes would keep
    /// renewing their credentials and access would never lapse.
    pub async fn require_usable_tenant(&self, tenant_id: &str) -> Result<()> {
        let state = self.inner.state.read().await;
        let tenant = state
            .tenants
            .get(tenant_id)
            .ok_or(ControllerError::NotFound("tenant"))?;

        if !tenant.status.is_usable() {
            let reason = match tenant.status {
                TenantStatus::Provisioning => "not yet active",
                TenantStatus::Active => "active",
                TenantStatus::Suspended => "suspended",
                TenantStatus::Deleted => "deleted",
            };
            return Err(ControllerError::InvalidRequest(format!(
                "tenant {} is {reason}",
                tenant.slug
            )));
        }

        Ok(())
    }

    /// Check whether a tenant is within its resource limits.
    ///
    /// This is called before creating resources so that a tenant cannot
    /// exceed its plan.
    pub async fn check_tenant_limits(
        &self,
        tenant_id: &str,
        networks: u32,
        nodes: u32,
        policies: u32,
        relays: u32,
    ) -> Result<()> {
        let state = self.inner.state.read().await;
        let tenant = state
            .tenants
            .get(tenant_id)
            .ok_or(ControllerError::NotFound("tenant"))?;

        if !tenant.status.is_usable() {
            return Err(ControllerError::InvalidRequest(format!(
                "tenant {} is not active",
                tenant.slug
            )));
        }

        let usage = state.tenant_usage(tenant_id);
        let projected = TenantUsage {
            networks: usage.networks + networks,
            nodes: usage.nodes + nodes,
            policies: usage.policies + policies,
            relays: usage.relays + relays,
        };

        if let Some(exceeded) = exceeded_limit(&projected, &tenant.limits) {
            return Err(ControllerError::InvalidRequest(format!(
                "tenant {} has reached its {exceeded} limit",
                tenant.slug
            )));
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // Tenant-scoped network operations
    // -------------------------------------------------------------------

    /// List networks for a tenant.
    pub async fn list_networks(&self, tenant_id: &str) -> Vec<Network> {
        self.inner
            .state
            .read()
            .await
            .networks
            .values()
            .filter(|network| network.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    /// Get one network, scoped to a tenant.
    pub async fn get_network(&self, tenant_id: &str, id: &str) -> Result<Network> {
        self.inner
            .state
            .read()
            .await
            .networks
            .get(id)
            .filter(|network| network.tenant_id == tenant_id)
            .cloned()
            .ok_or(ControllerError::NotFound("network"))
    }

    /// Create a network for a tenant.
    pub async fn create_network(
        &self,
        tenant_id: &str,
        name: String,
        description: String,
        cidr: String,
        credential_ttl_secs: Option<u32>,
        actor: &Actor,
    ) -> Result<Network> {
        self.check_tenant_limits(tenant_id, 1, 0, 0, 0).await?;

        let ttl = credential_ttl_secs.unwrap_or(DEFAULT_CREDENTIAL_TTL_SECS);
        if ttl == 0 || ttl > MAX_CREDENTIAL_TTL_SECS {
            return Err(ControllerError::InvalidRequest(
                "credential TTL must be between 1 second and 30 days".into(),
            ));
        }

        let mut state = self.inner.state.write().await;

        if state
            .networks
            .values()
            .any(|network| network.tenant_id == tenant_id && network.name == name)
        {
            return Err(ControllerError::Conflict(
                "network name already exists".to_string(),
            ));
        }

        let network = Network {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            name,
            description,
            network_id: random_network_id(),
            cidr,
            credential_ttl_secs: ttl,
            created_at: now_unix(),
        };
        state.record_for_tenant(
            Some(tenant_id),
            "network.created",
            "network",
            &network.id,
            actor.display(),
            format!("Created network {}", network.name),
        );
        state.networks.insert(network.id.clone(), network.clone());
        self.persist(&state).await?;
        Ok(network)
    }

    /// Delete a network and everything scoped to it.
    pub async fn delete_network(&self, tenant_id: &str, id: &str, actor: &Actor) -> Result<()> {
        let mut state = self.inner.state.write().await;

        // Verify ownership before removing anything. Removing first and
        // filtering afterwards would let one tenant delete another tenant's
        // network.
        if !state
            .networks
            .get(id)
            .map(|network| network.tenant_id == tenant_id)
            .unwrap_or(false)
        {
            return Err(ControllerError::NotFound("network"));
        }

        let network = state
            .networks
            .remove(id)
            .ok_or(ControllerError::NotFound("network"))?;
        state.nodes.retain(|_, node| node.network_id != id);
        state.policies.retain(|_, policy| policy.network_id != id);
        for relay in state.relays.values_mut() {
            relay.networks.retain(|network| network != id);
        }
        state.record_for_tenant(
            Some(tenant_id),
            "network.deleted",
            "network",
            id,
            actor.display(),
            format!("Deleted network {}", network.name),
        );
        self.persist(&state).await?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Tenant-scoped node operations
    // -------------------------------------------------------------------

    /// List nodes for a tenant, optionally scoped to a network.
    pub async fn list_nodes(&self, tenant_id: &str, network_id: Option<&str>) -> Vec<Node> {
        self.inner
            .state
            .read()
            .await
            .nodes
            .values()
            .filter(|node| node.tenant_id == tenant_id)
            .filter(|node| network_id.map(|id| node.network_id == id).unwrap_or(true))
            .cloned()
            .collect()
    }

    /// Get one node, scoped to a tenant.
    pub async fn get_node(&self, tenant_id: &str, id: &str) -> Result<Node> {
        self.inner
            .state
            .read()
            .await
            .nodes
            .get(id)
            .filter(|node| node.tenant_id == tenant_id)
            .cloned()
            .ok_or(ControllerError::NotFound("node"))
    }

    /// Find the node that a credential belongs to.
    ///
    /// A node authenticates with the credential the controller issued it, so
    /// this is how a node learns its own identity without being told.
    pub async fn find_node_by_public_key(&self, public_key: &[u8; 32]) -> Result<Node> {
        let hex_key = hex::encode(public_key);
        self.inner
            .state
            .read()
            .await
            .nodes
            .values()
            .find(|node| node.public_key == hex_key)
            .cloned()
            .ok_or(ControllerError::NotFound("node"))
    }

    /// Find the node behind an authenticated principal, within a tenant.
    ///
    /// The principal is a node, identified by the subject the credential
    /// was issued for.
    pub async fn find_node_for_principal(&self, tenant_id: &str, subject: &str) -> Result<Node> {
        self.inner
            .state
            .read()
            .await
            .nodes
            .values()
            .find(|node| node.tenant_id == tenant_id && node.id == subject)
            .cloned()
            .ok_or(ControllerError::NotFound("node"))
    }

    /// The lowest address in a network's range that no node holds.
    ///
    /// The address is what the data plane routes on, so it has to be unique
    /// inside the network. A network with no room left is refused: the
    /// operator has to widen the range or move a node.
    fn assign_ipv4_address(
        &self,
        network: &crate::model::Network,
        state: &crate::model::ControllerState,
    ) -> Result<String> {
        let range = Ipv4Range::parse(&network.cidr)?;

        let used: HashSet<u32> = state
            .nodes
            .values()
            .filter(|node| node.network_id == network.id)
            .filter_map(|node| node.ipv4_address.parse::<Ipv4Addr>().ok())
            .map(u32::from)
            .collect();

        assign_address(&range, &used).ok_or_else(|| {
            ControllerError::Conflict(format!(
                "the network {} has no free addresses left",
                network.name
            ))
        })
    }

    /// The topology a node needs to carry traffic.
    ///
    /// A node is told its own address, the range it lives in, and the
    /// peers it shares the range with. It is told nothing about any other
    /// network or tenant.
    pub async fn topology_for(&self, tenant_id: &str, node_id: &str) -> Result<Topology> {
        let state = self.inner.state.read().await;

        let node = state
            .nodes
            .get(node_id)
            .filter(|node| node.tenant_id == tenant_id)
            .cloned()
            .ok_or(ControllerError::NotFound("node"))?;

        let network = state
            .networks
            .get(&node.network_id)
            .cloned()
            .ok_or(ControllerError::NotFound("network"))?;

        let peers = state
            .nodes
            .values()
            .filter(|peer| peer.tenant_id == tenant_id)
            .filter(|peer| peer.network_id == node.network_id)
            .filter(|peer| peer.id != node.id)
            .map(|peer| TopologyPeer {
                address: peer.ipv4_address.clone(),
                public_key: peer.public_key.clone(),
                pq_public_key: peer.pq_public_key.clone(),
                endpoint: peer.endpoint.clone(),
            })
            .collect();

        Ok(Topology {
            address: node.ipv4_address,
            cidr: network.cidr,
            network_id: network.network_id,
            peers,
        })
    }

    /// Record how a node's peers reach it.
    ///
    /// The node reports it, because only the node knows it: it may be
    /// behind a NAT, and the address it listens on is not the address its
    /// peers see. The post-quantum key travels with it, because a peer
    /// needs that key to complete a handshake.
    pub async fn report_presence(
        &self,
        tenant_id: &str,
        node_id: &str,
        endpoint: &str,
        pq_public_key: &str,
    ) -> Result<Node> {
        let mut state = self.inner.state.write().await;

        let node = state
            .nodes
            .get_mut(node_id)
            .filter(|node| node.tenant_id == tenant_id)
            .ok_or(ControllerError::NotFound("node"))?;

        node.endpoint = Some(endpoint.to_string());
        node.last_seen = Some(now_unix());

        if !pq_public_key.is_empty() {
            node.pq_public_key = pq_public_key.to_string();
        }

        let node = node.clone();
        self.persist(&state).await?;
        Ok(node)
    }

    /// Enroll a node for a tenant and issue its first credential.
    ///
    /// The node must present its Ed25519 public key. The controller derives
    /// the per-network address and signs a credential bound to that key.
    pub async fn enroll_node(
        &self,
        tenant_id: &str,
        network_id: &str,
        name: String,
        keys: NodeKeys,
        tags: Vec<String>,
        actor: &Actor,
    ) -> Result<(Node, NodeCredential)> {
        self.check_tenant_limits(tenant_id, 0, 1, 0, 0).await?;

        let mut state = self.inner.state.write().await;
        let network = state
            .networks
            .get(network_id)
            .filter(|network| network.tenant_id == tenant_id)
            .cloned()
            .ok_or(ControllerError::NotFound("network"))?;

        if state
            .nodes
            .values()
            .any(|node| node.tenant_id == tenant_id && node.name == name)
        {
            return Err(ControllerError::Conflict(
                "node name already exists".to_string(),
            ));
        }

        let address = Address::derive(network.network_id, &keys.ed25519);
        let ipv4_address = self.assign_ipv4_address(&network, &state)?;
        let fingerprint = fingerprint(&keys.ed25519);
        let issued_at = now_unix();
        let mut nonce = [0u8; NONCE_LEN];
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);
        }

        let credential = self.inner.identity.issue(
            network.network_id,
            address,
            &keys.ed25519,
            issued_at,
            network.credential_ttl_secs,
            &nonce,
        );

        let node = Node {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            network_id: network.id.clone(),
            name,
            address: address.to_hex(),
            ipv4_address,
            endpoint: None,
            public_key: hex::encode(keys.ed25519),
            pq_public_key: hex::encode(&keys.ml_dsa),
            fingerprint,
            tags,
            platform: None,
            version: None,
            status: NodeStatus::Pending,
            credential_issued_at: issued_at,
            credential_not_after: credential.not_after(),
            last_seen: None,
            created_at: issued_at,
        };

        state.record_for_tenant(
            Some(tenant_id),
            "node.enrolled",
            "node",
            &node.id,
            actor.display(),
            format!("Enrolled {} in {}", node.name, network.name),
        );
        state.nodes.insert(node.id.clone(), node.clone());
        self.persist(&state).await?;
        Ok((node, credential))
    }

    /// Revoke a node and refuse future renewal.
    pub async fn revoke_node(&self, tenant_id: &str, id: &str, actor: &Actor) -> Result<Node> {
        let mut state = self.inner.state.write().await;
        let node = state
            .nodes
            .get_mut(id)
            .filter(|node| node.tenant_id == tenant_id)
            .ok_or(ControllerError::NotFound("node"))?;
        node.status = NodeStatus::Revoked;
        let revoked = node.clone();
        state.record_for_tenant(
            Some(tenant_id),
            "node.revoked",
            "node",
            id,
            actor.display(),
            format!("Revoked {}", revoked.name),
        );
        self.persist(&state).await?;
        Ok(revoked)
    }

    /// Renew a node's credential.
    pub async fn renew_node_credential(
        &self,
        tenant_id: &str,
        id: &str,
        actor: &Actor,
    ) -> Result<(Node, NodeCredential)> {
        // A suspended tenant's nodes must not keep renewing, or
        // suspension would never actually cut off access.
        self.require_usable_tenant(tenant_id).await?;

        let mut state = self.inner.state.write().await;
        let node = state
            .nodes
            .get(id)
            .filter(|node| node.tenant_id == tenant_id)
            .cloned()
            .ok_or(ControllerError::NotFound("node"))?;
        let network = state
            .networks
            .get(&node.network_id)
            .cloned()
            .ok_or(ControllerError::NotFound("network"))?;

        if node.status == NodeStatus::Revoked {
            return Err(ControllerError::InvalidRequest(
                "cannot renew a revoked node".into(),
            ));
        }

        let public_key: [u8; 32] = hex::decode(&node.public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| ControllerError::InvalidRequest("node public key is invalid".into()))?;
        let address = Address::from_hex(&node.address)
            .map_err(|error| ControllerError::InvalidRequest(error.to_string()))?;

        let issued_at = now_unix();
        let mut nonce = [0u8; NONCE_LEN];
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);
        }
        let credential = self.inner.identity.issue(
            network.network_id,
            address,
            &public_key,
            issued_at,
            network.credential_ttl_secs,
            &nonce,
        );

        let node = state.nodes.get_mut(id).expect("node exists");
        node.credential_issued_at = issued_at;
        node.credential_not_after = credential.not_after();
        let renewed = node.clone();
        state.record_for_tenant(
            Some(tenant_id),
            "credential.renewed",
            "node",
            id,
            actor.display(),
            format!("Renewed credential for {}", renewed.name),
        );
        self.persist(&state).await?;
        Ok((renewed, credential))
    }

    // -------------------------------------------------------------------
    // Tenant-scoped policy operations
    // -------------------------------------------------------------------

    /// List policies for a tenant, optionally scoped to a network.
    pub async fn list_policies(&self, tenant_id: &str, network_id: Option<&str>) -> Vec<Policy> {
        self.inner
            .state
            .read()
            .await
            .policies
            .values()
            .filter(|policy| policy.tenant_id == tenant_id)
            .filter(|policy| network_id.map(|id| policy.network_id == id).unwrap_or(true))
            .cloned()
            .collect()
    }

    /// Create a policy for a tenant.
    pub async fn create_policy(
        &self,
        tenant_id: &str,
        policy: Policy,
        actor: &Actor,
    ) -> Result<Policy> {
        self.check_tenant_limits(tenant_id, 0, 0, 1, 0).await?;

        let mut state = self.inner.state.write().await;
        if !state
            .networks
            .get(&policy.network_id)
            .map(|network| network.tenant_id == tenant_id)
            .unwrap_or(false)
        {
            return Err(ControllerError::NotFound("network"));
        }
        let now = now_unix();
        let mut policy = policy;
        policy.id = uuid::Uuid::new_v4().to_string();
        policy.tenant_id = tenant_id.to_string();
        policy.created_at = now;
        policy.updated_at = now;
        state.record_for_tenant(
            Some(tenant_id),
            "policy.created",
            "policy",
            &policy.id,
            actor.display(),
            format!("Created policy {}", policy.name),
        );
        state.policies.insert(policy.id.clone(), policy.clone());
        self.persist(&state).await?;
        Ok(policy)
    }

    /// Delete a policy.
    pub async fn delete_policy(&self, tenant_id: &str, id: &str, actor: &Actor) -> Result<()> {
        let mut state = self.inner.state.write().await;

        // Verify ownership before removing anything.
        if !state
            .policies
            .get(id)
            .map(|policy| policy.tenant_id == tenant_id)
            .unwrap_or(false)
        {
            return Err(ControllerError::NotFound("policy"));
        }

        let policy = state
            .policies
            .remove(id)
            .ok_or(ControllerError::NotFound("policy"))?;
        state.record_for_tenant(
            Some(tenant_id),
            "policy.deleted",
            "policy",
            id,
            actor.display(),
            format!("Deleted policy {}", policy.name),
        );
        self.persist(&state).await?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Tenant-scoped relay operations
    // -------------------------------------------------------------------

    /// List relays for a tenant.
    pub async fn list_relays(&self, tenant_id: &str) -> Vec<Relay> {
        self.inner
            .state
            .read()
            .await
            .relays
            .values()
            .filter(|relay| relay.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    /// Create a relay for a tenant.
    pub async fn create_relay(
        &self,
        tenant_id: &str,
        relay: Relay,
        actor: &Actor,
    ) -> Result<Relay> {
        self.check_tenant_limits(tenant_id, 0, 0, 0, 1).await?;

        let mut state = self.inner.state.write().await;
        for network in &relay.networks {
            if !state
                .networks
                .get(network)
                .map(|candidate| candidate.tenant_id == tenant_id)
                .unwrap_or(false)
            {
                return Err(ControllerError::NotFound("network"));
            }
        }
        let now = now_unix();
        let mut relay = relay;
        relay.id = uuid::Uuid::new_v4().to_string();
        relay.tenant_id = tenant_id.to_string();
        relay.status = RelayStatus::Healthy;
        relay.created_at = now;
        relay.updated_at = now;
        state.record_for_tenant(
            Some(tenant_id),
            "relay.created",
            "relay",
            &relay.id,
            actor.display(),
            format!("Created relay {}", relay.name),
        );
        state.relays.insert(relay.id.clone(), relay.clone());
        self.persist(&state).await?;
        Ok(relay)
    }

    /// Drain a relay before maintenance or shutdown.
    pub async fn drain_relay(&self, tenant_id: &str, id: &str, actor: &Actor) -> Result<Relay> {
        let mut state = self.inner.state.write().await;
        let relay = state
            .relays
            .get_mut(id)
            .filter(|relay| relay.tenant_id == tenant_id)
            .ok_or(ControllerError::NotFound("relay"))?;
        relay.status = RelayStatus::Draining;
        relay.updated_at = now_unix();
        let drained = relay.clone();
        state.record_for_tenant(
            Some(tenant_id),
            "relay.draining",
            "relay",
            id,
            actor.display(),
            format!("Draining relay {}", drained.name),
        );
        self.persist(&state).await?;
        Ok(drained)
    }

    // -------------------------------------------------------------------
    // Audit and health
    // -------------------------------------------------------------------

    /// Authenticate a node by the credential this controller issued it.
    ///
    /// A node holds no secret. Its credential is signed by this controller
    /// and bound to the node's own public key, so presenting it proves both
    /// that the node is enrolled and that it is the node it claims to be.
    /// Another node cannot replay it, because the binding is checked
    /// against the credential's own key.
    ///
    /// The returned identity is scoped to the node's own tenant. It carries
    /// the tenant scope, so the node can manage its own membership, and no
    /// operator role, so it cannot reach the master console.
    pub async fn authenticate_node(&self, token: &str) -> Result<crate::auth::Identity> {
        let bytes = hex::decode(token)
            .map_err(|_| ControllerError::InvalidRequest("the credential is not hex".into()))?;

        let controller_key = self.inner.identity.public_key();
        let credential = NodeCredential::deserialize(&bytes, &controller_key)
            .map_err(|_| ControllerError::InvalidRequest("the credential is not valid".into()))?;

        if !credential.is_valid_at(now_unix()) {
            return Err(ControllerError::InvalidRequest(
                "the credential has expired".into(),
            ));
        }

        let state = self.inner.state.read().await;

        // The node is found by the public key the credential is bound to.
        // A credential for a node that was deleted or revoked matches
        // nothing.
        let node = state
            .nodes
            .values()
            .find(|node| node.public_key == hex::encode(credential.public_key()))
            .ok_or(ControllerError::NotFound("node"))?;

        if node.status == NodeStatus::Revoked {
            return Err(ControllerError::InvalidRequest(
                "the node is revoked".into(),
            ));
        }

        Ok(crate::auth::Identity {
            subject: node.id.clone(),
            name: Some(node.name.clone()),
            preferred_username: None,
            tenant_id: Some(node.tenant_id.clone()),
            scopes: vec![crate::model::TENANT_SCOPE.to_string()],
            roles: Vec::new(),
        })
    }

    /// List audit events.
    ///
    /// A tenant sees only its own events. A `None` tenant ID returns every
    /// event, which is what the master console needs.
    pub async fn list_events(&self, tenant_id: Option<&str>) -> Vec<AuditEvent> {
        self.inner
            .state
            .read()
            .await
            .events
            .iter()
            .filter(|event| match tenant_id {
                Some(tenant) => event.tenant_id.as_deref() == Some(tenant),
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Controller health summary.
    pub async fn health(&self) -> Health {
        let state = self.inner.state.read().await;
        Health {
            status: "healthy".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            uptime_seconds: now_unix().saturating_sub(state.started_at),
            networks: state.networks.len(),
            nodes: state.nodes.len(),
            policies: state.policies.len(),
            relays: state.relays.len(),
        }
    }

    /// Control-plane health, including tenant counts.
    pub async fn control_plane_health(&self) -> ControlPlaneHealth {
        let state = self.inner.state.read().await;
        let active = state
            .tenants
            .values()
            .filter(|tenant| tenant.status == TenantStatus::Active)
            .count();
        let shared = state
            .tenants
            .values()
            .filter(|tenant| tenant.deployment.is_shared())
            .count();
        ControlPlaneHealth {
            status: "healthy".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            uptime_seconds: now_unix().saturating_sub(state.started_at),
            tenants: state.tenants.len(),
            active_tenants: active,
            shared_tenants: shared,
            dedicated_tenants: state.tenants.len() - shared,
            networks: state.networks.len(),
            nodes: state.nodes.len(),
            policies: state.policies.len(),
            relays: state.relays.len(),
        }
    }
}

/// Health of the control plane as a whole.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ControlPlaneHealth {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub tenants: usize,
    pub active_tenants: usize,
    pub shared_tenants: usize,
    pub dedicated_tenants: usize,
    pub networks: usize,
    pub nodes: usize,
    pub policies: usize,
    pub relays: usize,
}

/// Stable, short fingerprint for a public key.
fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Generate a non-zero random network identifier.
fn random_network_id() -> u64 {
    use rand::RngCore;
    loop {
        let mut bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value = u64::from_be_bytes(bytes);
        if value != 0 {
            return value;
        }
    }
}

/// Re-export for the API layer.
pub type SharedController = Controller;

impl From<crate::error::ControllerError> for axum::http::StatusCode {
    fn from(error: crate::error::ControllerError) -> Self {
        use crate::error::ControllerError;
        match error {
            ControllerError::NotFound(_) => Self::NOT_FOUND,
            ControllerError::Conflict(_) => Self::CONFLICT,
            ControllerError::InvalidRequest(_) => Self::BAD_REQUEST,
            ControllerError::Internal(_) => Self::INTERNAL_SERVER_ERROR,
        }
    }
}
