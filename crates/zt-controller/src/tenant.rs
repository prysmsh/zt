//! Multi-tenancy model for the ZT-next control plane.
//!
//! # The two-tier design
//!
//! ZT-next supports two deployment shapes, and the control plane must
//! administer both through one interface:
//!
//! - **Shared** — small tenants share one controller process and one
//!   database. Every query is scoped by tenant, and every tenant gets its
//!   own controller signing key so that credentials from different tenants
//!   can never be confused.
//! - **Dedicated** — larger or regulated tenants get their own controller
//!   process, database, and signing key. The shared control plane tracks
//!   their lifecycle but does not hold their data.
//!
//! The distinction matters because a shared controller signs credentials for
//! every tenant it serves. Even though the credentials are scoped by
//! network ID, a dedicated controller removes that shared trust anchor
//! entirely.
//!
//! # Tenant lifecycle
//!
//! ```text
//!   provisioning ──▶ active ──▶ suspended ──▶ active
//!        │              │            │
//!        │              ▼            ▼
//!        └──────────▶ deleted ◀─────┘
//! ```
//!
//! - **Provisioning** — the tenant exists, but its controller identity and
//!   resources are still being set up.
//! - **Active** — the tenant can use the service.
//! - **Suspended** — access is blocked, but data is retained so the tenant
//!   can be restored.
//! - **Deleted** — the tenant is soft-deleted. Data is purged by a separate
//!   retention job, never inline, so a mistake can be corrected.

use serde::{Deserialize, Serialize};

use crate::model::{now_unix, EntityId};

/// A tenant of the control plane.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tenant {
    pub id: EntityId,
    /// The tenant's display name.
    pub name: String,
    /// A stable slug used in URLs and CLI commands.
    pub slug: String,
    /// How the tenant's control plane is hosted.
    pub deployment: Deployment,
    pub status: TenantStatus,
    /// The plan the tenant is on.
    pub plan: String,
    /// Resource limits for the tenant.
    pub limits: TenantLimits,
    /// What the tenant is charged for.
    pub rates: TenantRates,
    /// The controller identity for a shared tenant.
    ///
    /// `None` for a dedicated tenant, whose controller holds its own key.
    pub controller_id: Option<String>,
    /// The controller's Ed25519 public key, hex encoded.
    pub controller_public_key: Option<String>,
    /// When the tenant was created.
    pub created_at: u64,
    /// When the tenant was last updated.
    pub updated_at: u64,
    /// When the tenant was suspended, if it is suspended.
    pub suspended_at: Option<u64>,
    /// When the tenant was deleted, if it is deleted.
    pub deleted_at: Option<u64>,
}

/// How a tenant's control plane is hosted.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Deployment {
    /// Shares the control plane process and database with other tenants.
    Shared,
    /// Runs its own controller process, database, and signing key.
    Dedicated,
}

impl Deployment {
    /// Whether the shared control plane holds this tenant's data.
    pub fn is_shared(self) -> bool {
        matches!(self, Deployment::Shared)
    }
}

/// A tenant's lifecycle state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    /// Being set up. Not yet usable.
    Provisioning,
    /// Fully operational.
    Active,
    /// Access blocked, data retained.
    Suspended,
    /// Soft-deleted. Purged later by a retention job.
    Deleted,
}

impl TenantStatus {
    /// Whether a tenant in this state may use the service.
    pub fn is_usable(self) -> bool {
        matches!(self, TenantStatus::Active)
    }
}

/// Resource limits applied to a tenant.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantLimits {
    /// Maximum number of networks.
    pub max_networks: u32,
    /// Maximum number of enrolled nodes across all networks.
    pub max_nodes: u32,
    /// Maximum number of access rules.
    pub max_policies: u32,
    /// Maximum number of relays.
    pub max_relays: u32,
    /// Maximum credential lifetime the tenant may request, in seconds.
    pub max_credential_ttl_secs: u32,
}

impl Default for TenantLimits {
    fn default() -> Self {
        Self {
            max_networks: 10,
            max_nodes: 500,
            max_policies: 100,
            max_relays: 10,
            max_credential_ttl_secs: 24 * 60 * 60,
        }
    }
}

/// Current resource usage for a tenant.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TenantUsage {
    pub networks: u32,
    pub nodes: u32,
    pub policies: u32,
    pub relays: u32,
}

/// What a tenant is charged for.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRates {
    /// The price of one node for a month, in cents.
    pub node_month_cents: u64,
    /// The price of one gigabyte relayed, in cents.
    pub gigabyte_cents: u64,
    /// The currency the prices are in.
    pub currency: String,
}

impl Default for TenantRates {
    fn default() -> Self {
        Self {
            node_month_cents: 1200,
            gigabyte_cents: 2,
            currency: "EUR".to_string(),
        }
    }
}

/// What a tenant has used over a period.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageSummary {
    /// When the period started.
    pub period_start: u64,
    /// When the period ends.
    pub period_end: u64,
    /// Bytes received by the tenant's nodes.
    pub bytes_in: u64,
    /// Bytes sent by the tenant's nodes.
    pub bytes_out: u64,
    /// Packets carried in both directions.
    pub packets: u64,
    /// Node-seconds: the integral of the node count over the period.
    pub node_seconds: u64,
    /// The samples the summary was built from.
    pub samples: u64,
}

impl UsageSummary {
    /// The bytes carried in both directions.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }

    /// The node-seconds as hours.
    pub fn node_hours(&self) -> f64 {
        self.node_seconds as f64 / 3600.0
    }
}

/// What a tenant owes for a period.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invoice {
    /// The tenant the invoice is for.
    pub tenant_id: String,
    /// The usage the charges are computed from.
    pub usage: UsageSummary,
    /// The price of one node for a month, in cents.
    pub node_month_cents: u64,
    /// The price of one gigabyte relayed, in cents.
    pub gigabyte_cents: u64,
    /// The charge for the nodes, in cents.
    pub node_charges_cents: u64,
    /// The charge for the traffic, in cents.
    pub traffic_charges_cents: u64,
    /// The total, in cents.
    pub total_cents: u64,
    /// The currency the amounts are in.
    pub currency: String,
}

/// Whether a usage snapshot exceeds any of a tenant's limits.
///
/// Returns the name of the first exceeded limit, if any.
pub fn exceeded_limit(usage: &TenantUsage, limits: &TenantLimits) -> Option<&'static str> {
    if usage.networks > limits.max_networks {
        return Some("networks");
    }
    if usage.nodes > limits.max_nodes {
        return Some("nodes");
    }
    if usage.policies > limits.max_policies {
        return Some("policies");
    }
    if usage.relays > limits.max_relays {
        return Some("relays");
    }
    None
}

/// Build a tenant in the provisioning state.
pub fn new_tenant(
    name: String,
    slug: String,
    deployment: Deployment,
    plan: String,
    limits: TenantLimits,
) -> Tenant {
    let now = now_unix();
    Tenant {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        slug,
        deployment,
        status: TenantStatus::Provisioning,
        plan,
        limits,
        rates: TenantRates::default(),
        controller_id: None,
        controller_public_key: None,
        created_at: now,
        updated_at: now,
        suspended_at: None,
        deleted_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_tenant_starts_in_provisioning() {
        let tenant = new_tenant(
            "Acme".into(),
            "acme".into(),
            Deployment::Shared,
            "starter".into(),
            TenantLimits::default(),
        );
        assert_eq!(tenant.status, TenantStatus::Provisioning);
        assert!(!tenant.status.is_usable());
        assert_eq!(tenant.deployment, Deployment::Shared);
        assert!(tenant.deployment.is_shared());
    }

    #[test]
    fn a_dedicated_tenant_is_not_shared() {
        let tenant = new_tenant(
            "Big".into(),
            "big".into(),
            Deployment::Dedicated,
            "enterprise".into(),
            TenantLimits::default(),
        );
        assert!(!tenant.deployment.is_shared());
    }

    #[test]
    fn limits_are_detected() {
        let limits = TenantLimits::default();
        let usage = TenantUsage {
            networks: 11,
            ..Default::default()
        };
        assert_eq!(exceeded_limit(&usage, &limits), Some("networks"));

        let usage = TenantUsage {
            nodes: 501,
            ..Default::default()
        };
        assert_eq!(exceeded_limit(&usage, &limits), Some("nodes"));

        let usage = TenantUsage::default();
        assert_eq!(exceeded_limit(&usage, &limits), None);
    }
}
