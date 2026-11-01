//! ZT-next control plane.
//!
//! The controller owns networks, node membership, access policies, relays,
//! and credential issuance. It is designed to be embedded in the node agent
//! or run as a standalone service.
//!
//! # Security model
//!
//! - Node credentials are short-lived and bound to the node's Ed25519 key.
//! - The controller signs credentials with a hybrid Ed25519 + ML-DSA-65 key.
//! - Revocation is pull-based: a revoked node cannot renew, so its access
//!   expires within one credential TTL.
//! - Every administrative mutation is written to an append-only audit log.

pub mod address;
pub mod api;
pub mod auth;
pub mod error;
pub mod identity;
pub mod middleware;
pub mod model;
pub mod principal;
pub mod retention;
pub mod service;
pub mod store;
pub mod tenant;

pub use api::{router, router_with_auth};
pub use auth::{AuthConfig, Verifier};
pub use error::{ControllerError, Result};
pub use identity::IdentityStore;
pub use middleware::AuthState;
pub use model::{
    now_unix, Actor, AuditEvent, ControllerState, Health, Network, Node, NodeStatus, Policy,
    PortSpec, Protocol, Relay, RelayStatus, Selector,
};
pub use principal::Principal;
pub use service::{Controller, SharedController, DEFAULT_CREDENTIAL_TTL_SECS};
pub use store::{MemoryStore, SqliteStore, Store};
pub use tenant::{Deployment, Tenant, TenantLimits, TenantStatus, TenantUsage};
