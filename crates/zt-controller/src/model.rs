//! Core control-plane domain model.
//!
//! The controller owns four first-class objects:
//!
//! - **Networks** — isolated address spaces and policy boundaries.
//! - **Nodes** — enrolled members of a network, each with a short-lived
//!   credential bound to its own Ed25519 public key.
//! - **Policies** — default-deny access rules between node selectors.
//! - **Relays** — per-network infrastructure used when direct paths fail.
//!
//! Every mutation is recorded in an append-only audit log.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Current Unix timestamp in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A stable, human-readable identifier.
pub type EntityId = String;

/// An isolated overlay network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Network {
    pub id: EntityId,
    /// The tenant that owns this network.
    pub tenant_id: EntityId,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The numeric network identifier used by the wire protocol.
    pub network_id: u64,
    /// IPv4 CIDR assigned to the network.
    pub cidr: String,
    /// Default credential lifetime in seconds.
    pub credential_ttl_secs: u32,
    pub created_at: u64,
}

/// A node enrolled in a network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub id: EntityId,
    /// The tenant that owns this node.
    pub tenant_id: EntityId,
    pub network_id: EntityId,
    pub name: String,
    /// Per-network address rendered as lowercase hex.
    pub address: String,
    /// The IPv4 address in the network's range, assigned when the node
    /// enrols.
    ///
    /// The protocol address is an identifier; this one is an address the
    /// data plane routes on.
    pub ipv4_address: String,
    /// The node's UDP endpoint, as the node last reported it.
    pub endpoint: Option<String>,
    /// Ed25519 public key of the node, hex encoded.
    pub public_key: String,
    /// Fingerprint shown to operators.
    pub fingerprint: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Platform reported by the node, when it has checked in.
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    pub status: NodeStatus,
    pub credential_issued_at: u64,
    pub credential_not_after: u64,
    pub last_seen: Option<u64>,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Pending,
    Online,
    Degraded,
    Offline,
    Revoked,
}

/// What a node needs to carry traffic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Topology {
    /// The node's own address in the network's range.
    pub address: String,
    /// The network's range, in the `10.88.0.0/24` form.
    pub cidr: String,
    /// The network's numeric identifier.
    pub network_id: u64,
    /// The peers in the same network.
    pub peers: Vec<TopologyPeer>,
}

/// A peer in the topology.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyPeer {
    /// The peer's address in the network's range.
    pub address: String,
    /// The peer's Ed25519 public key, hex encoded.
    pub public_key: String,
    /// The peer's UDP endpoint, when it has reported one.
    pub endpoint: Option<String>,
}

/// A default-deny access rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub id: EntityId,
    /// The tenant that owns this policy.
    pub tenant_id: EntityId,
    pub network_id: EntityId,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub protocol: Protocol,
    /// A single port, an inclusive range, or `any`.
    pub port: PortSpec,
    pub source: Selector,
    pub destination: Selector,
    pub enabled: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
}

impl PortSpec {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(value) => *value == port,
            Self::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

/// A node selector used by a policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Selector {
    Any,
    Node { node_id: EntityId },
    Tag { tag: String },
    Platform { platform: String },
    Subnet { cidr: String },
    Network { network_id: EntityId },
}

/// A relay that can carry sessions for one or more networks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Relay {
    pub id: EntityId,
    /// The tenant that owns this relay.
    pub tenant_id: EntityId,
    pub name: String,
    /// The node acting as a relay.
    pub node_id: EntityId,
    /// Publicly routable UDP endpoint.
    pub endpoint: String,
    #[serde(default)]
    pub networks: Vec<EntityId>,
    pub enabled: bool,
    pub status: RelayStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayStatus {
    Healthy,
    Degraded,
    Offline,
    Draining,
}

/// Who performed an action.
///
/// The actor is the authenticated principal that made the request. An action
/// the controller takes on its own behalf is attributed to the system, so
/// the audit log never has an empty actor.
///
/// The subject is the identity's stable identifier. The name is what the
/// operator is called, and it is only present when the identity provider
/// supplies one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    subject: String,
    name: Option<String>,
}

impl Actor {
    /// An action the controller took on its own behalf.
    pub fn system() -> Self {
        Self {
            subject: "system".to_string(),
            name: None,
        }
    }

    /// An authenticated principal.
    pub fn principal(subject: impl Into<String>, name: Option<String>) -> Self {
        Self {
            subject: subject.into(),
            name: name.filter(|value| !value.trim().is_empty()),
        }
    }

    /// The stable identifier of the actor.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// How the actor appears in the audit log.
    ///
    /// A named principal is shown by name, with the subject in brackets, so
    /// the log is readable and the identity is still unambiguous.
    pub fn display(&self) -> String {
        match &self.name {
            Some(name) => format!("{name} [{}]", self.subject),
            None => self.subject.clone(),
        }
    }
}

/// An append-only audit event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: EntityId,
    /// The tenant the event belongs to, or `None` for a control-plane event.
    pub tenant_id: Option<EntityId>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    /// Who performed the action.
    pub actor: String,
    pub detail: String,
    pub timestamp: u64,
}

/// The scope a tenant-scoped token must carry.
///
/// The name is the one the identity provider uses, so the scope a token
/// carries is the same name the controller checks for.
pub const TENANT_SCOPE: &str = "zt:tenant";

/// The role that grants access to the master console.
pub const OPERATOR_ROLE: &str = "zt:operator";

/// Controller health summary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub networks: usize,
    pub nodes: usize,
    pub policies: usize,
    pub relays: usize,
}

/// In-memory controller state.
///
/// Persistence is deliberately behind this boundary. A later milestone can
/// replace the map with a database without changing the API layer.
#[derive(Clone, Debug)]
pub struct ControllerState {
    /// The tenants served by this control plane.
    pub tenants: BTreeMap<EntityId, crate::tenant::Tenant>,
    pub networks: BTreeMap<EntityId, Network>,
    pub nodes: BTreeMap<EntityId, Node>,
    pub policies: BTreeMap<EntityId, Policy>,
    pub relays: BTreeMap<EntityId, Relay>,
    pub events: Vec<AuditEvent>,
    pub started_at: u64,
}

impl Default for ControllerState {
    fn default() -> Self {
        Self {
            tenants: BTreeMap::new(),
            networks: BTreeMap::new(),
            nodes: BTreeMap::new(),
            policies: BTreeMap::new(),
            relays: BTreeMap::new(),
            events: Vec::new(),
            started_at: now_unix(),
        }
    }
}

impl ControllerState {
    /// Record an audit event scoped to a tenant.
    pub fn record_for_tenant(
        &mut self,
        tenant_id: Option<&str>,
        action: impl Into<String>,
        target_type: impl Into<String>,
        target_id: impl Into<String>,
        actor: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.events.push(AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.map(str::to_string),
            action: action.into(),
            target_type: target_type.into(),
            target_id: target_id.into(),
            actor: actor.into(),
            detail: detail.into(),
            timestamp: now_unix(),
        });
    }

    /// Record an audit event with no tenant scope.
    pub fn record(
        &mut self,
        action: impl Into<String>,
        target_type: impl Into<String>,
        target_id: impl Into<String>,
        actor: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.record_for_tenant(None, action, target_type, target_id, actor, detail);
    }

    /// Node count scoped to a network.
    pub fn node_count(&self, network_id: &str) -> usize {
        self.nodes
            .values()
            .filter(|node| node.network_id == network_id)
            .count()
    }

    /// Resource usage for a tenant.
    pub fn tenant_usage(&self, tenant_id: &str) -> crate::tenant::TenantUsage {
        crate::tenant::TenantUsage {
            networks: self
                .networks
                .values()
                .filter(|n| n.tenant_id == tenant_id)
                .count() as u32,
            nodes: self
                .nodes
                .values()
                .filter(|n| n.tenant_id == tenant_id)
                .count() as u32,
            policies: self
                .policies
                .values()
                .filter(|p| p.tenant_id == tenant_id)
                .count() as u32,
            relays: self
                .relays
                .values()
                .filter(|r| r.tenant_id == tenant_id)
                .count() as u32,
        }
    }
}
