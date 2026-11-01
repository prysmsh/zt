//! SQLite-backed persistence for controller state.
//!
//! The store owns the schema and all reads/writes. The service layer in
//! [`crate::service`] talks to this trait, which keeps persistence out of the
//! HTTP layer and makes the in-memory and SQLite implementations swappable.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::error::{ControllerError, Result};
use crate::model::{AuditEvent, ControllerState, Network, Node, Policy, Relay};

/// Trait implemented by controller storage backends.
pub trait Store: Send + Sync + 'static {
    /// Load the full controller state.
    fn load(&self) -> Result<ControllerState>;

    /// Persist the full controller state.
    fn save(&self, state: &ControllerState) -> Result<()>;
}

/// In-memory store, used for tests and ephemeral deployments.
#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<Mutex<ControllerState>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn load(&self) -> Result<ControllerState> {
        let state = self.state.lock().expect("controller state poisoned");
        Ok(state.clone())
    }

    fn save(&self, state: &ControllerState) -> Result<()> {
        let mut stored = self.state.lock().expect("controller state poisoned");
        *stored = state.clone();
        Ok(())
    }
}

/// SQLite store.
pub struct SqliteStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Open (or create) a database at `path` and apply migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    /// Open an in-memory database. Useful for tests.
    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let connection = self.connection.lock().expect("connection poisoned");
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                deployment TEXT NOT NULL,
                status TEXT NOT NULL,
                plan TEXT NOT NULL,
                limits TEXT NOT NULL,
                controller_id TEXT,
                controller_public_key TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                suspended_at INTEGER,
                deleted_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS networks (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                network_id INTEGER NOT NULL,
                cidr TEXT NOT NULL,
                credential_ttl_secs INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                ipv4_address TEXT NOT NULL DEFAULT '',
                endpoint TEXT,
                public_key TEXT NOT NULL,
                pq_public_key TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                platform TEXT,
                version TEXT,
                status TEXT NOT NULL,
                credential_issued_at INTEGER NOT NULL,
                credential_not_after INTEGER NOT NULL,
                last_seen INTEGER,
                created_at INTEGER NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS nodes_network_name
                ON nodes(network_id, name);

            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL,
                port TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS relays (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                node_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                networks TEXT NOT NULL DEFAULT '[]',
                enabled INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                detail TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS networks_tenant ON networks(tenant_id);
            CREATE INDEX IF NOT EXISTS nodes_tenant ON nodes(tenant_id);
            CREATE INDEX IF NOT EXISTS policies_tenant ON policies(tenant_id);
            CREATE INDEX IF NOT EXISTS relays_tenant ON relays(tenant_id);
            "#,
        )?;

        // An existing database was created before the node carried an IPv4
        // address or an endpoint. SQLite has no ADD COLUMN IF NOT EXISTS,
        // so the columns are checked first.
        for (column, definition) in [
            ("ipv4_address", "TEXT NOT NULL DEFAULT ''"),
            ("endpoint", "TEXT"),
            ("pq_public_key", "TEXT NOT NULL DEFAULT ''"),
        ] {
            if !self.column_exists(&connection, "nodes", column) {
                connection.execute(
                    &format!("ALTER TABLE nodes ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }

        let version: Option<i64> = connection
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if version.is_none() {
            connection.execute("INSERT INTO schema_version(version) VALUES (1)", [])?;
        }
        Ok(())
    }

    /// Whether a table has a column.
    fn column_exists(&self, connection: &Connection, table: &str, column: &str) -> bool {
        let mut statement = match connection.prepare(&format!("PRAGMA table_info({table})")) {
            Ok(statement) => statement,
            Err(_) => return false,
        };

        let rows = statement.query_map([], |row| row.get::<_, String>(1));
        match rows {
            Ok(rows) => rows.flatten().any(|name| name == column),
            Err(_) => false,
        }
    }

    fn load_tenants(&self, connection: &Connection) -> Result<Vec<crate::tenant::Tenant>> {
        let mut statement = connection.prepare(
            "SELECT id, name, slug, deployment, status, plan, limits, controller_id,
                    controller_public_key, created_at, updated_at, suspended_at, deleted_at
             FROM tenants ORDER BY created_at, id",
        )?;
        let rows = statement
            .query_map([], |row| {
                let deployment: String = row.get(3)?;
                let status: String = row.get(4)?;
                let limits_json: String = row.get(6)?;
                let limits: crate::tenant::TenantLimits =
                    serde_json::from_str(&limits_json).unwrap_or_default();
                Ok(crate::tenant::Tenant {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    slug: row.get(2)?,
                    deployment: parse_deployment(&deployment),
                    status: parse_tenant_status(&status),
                    plan: row.get(5)?,
                    limits,
                    controller_id: row.get(7)?,
                    controller_public_key: row.get(8)?,
                    created_at: row.get::<_, i64>(9)? as u64,
                    updated_at: row.get::<_, i64>(10)? as u64,
                    suspended_at: row.get::<_, Option<i64>>(11)?.map(|v| v as u64),
                    deleted_at: row.get::<_, Option<i64>>(12)?.map(|v| v as u64),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn load_networks(&self, connection: &Connection) -> Result<Vec<Network>> {
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, name, description, network_id, cidr, credential_ttl_secs, created_at
             FROM networks ORDER BY created_at, id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(Network {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                    network_id: row.get::<_, i64>(4)? as u64,
                    cidr: row.get(5)?,
                    credential_ttl_secs: row.get::<_, i64>(6)? as u32,
                    created_at: row.get::<_, i64>(7)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn load_nodes(&self, connection: &Connection) -> Result<Vec<Node>> {
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, network_id, name, address, ipv4_address, endpoint,
                    public_key, pq_public_key, fingerprint, tags,
                    platform, version, status, credential_issued_at, credential_not_after,
                    last_seen, created_at
             FROM nodes ORDER BY created_at, id",
        )?;
        let rows = statement
            .query_map([], |row| {
                let tags_json: String = row.get(10)?;
                let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                let status: String = row.get(13)?;
                Ok(Node {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    network_id: row.get(2)?,
                    name: row.get(3)?,
                    address: row.get(4)?,
                    ipv4_address: row.get(5)?,
                    endpoint: row.get(6)?,
                    public_key: row.get(7)?,
                    pq_public_key: row.get(8)?,
                    fingerprint: row.get(9)?,
                    tags,
                    platform: row.get(11)?,
                    version: row.get(12)?,
                    status: parse_node_status(&status),
                    credential_issued_at: row.get::<_, i64>(14)? as u64,
                    credential_not_after: row.get::<_, i64>(15)? as u64,
                    last_seen: row.get::<_, Option<i64>>(16)?.map(|value| value as u64),
                    created_at: row.get::<_, i64>(17)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn load_policies(&self, connection: &Connection) -> Result<Vec<Policy>> {
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, network_id, name, description, protocol, port, source,
                    destination, enabled, created_at, updated_at
             FROM policies ORDER BY created_at, id",
        )?;
        let rows = statement
            .query_map([], |row| {
                let protocol: String = row.get(5)?;
                let port: Value =
                    serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or(Value::Null);
                let source: Value =
                    serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or(Value::Null);
                let destination: Value =
                    serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or(Value::Null);
                Ok(Policy {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    network_id: row.get(2)?,
                    name: row.get(3)?,
                    description: row.get(4)?,
                    protocol: parse_protocol(&protocol),
                    port: parse_port(&port),
                    source: parse_selector(&source),
                    destination: parse_selector(&destination),
                    enabled: row.get::<_, i64>(9)? != 0,
                    created_at: row.get::<_, i64>(10)? as u64,
                    updated_at: row.get::<_, i64>(11)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn load_relays(&self, connection: &Connection) -> Result<Vec<Relay>> {
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, name, node_id, endpoint, networks, enabled, status,
                    created_at, updated_at
             FROM relays ORDER BY created_at, id",
        )?;
        let rows = statement
            .query_map([], |row| {
                let networks: Vec<String> =
                    serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default();
                let status: String = row.get(7)?;
                Ok(Relay {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    name: row.get(2)?,
                    node_id: row.get(3)?,
                    endpoint: row.get(4)?,
                    networks,
                    enabled: row.get::<_, i64>(6)? != 0,
                    status: parse_relay_status(&status),
                    created_at: row.get::<_, i64>(8)? as u64,
                    updated_at: row.get::<_, i64>(9)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn load_events(&self, connection: &Connection) -> Result<Vec<AuditEvent>> {
        let mut statement = connection.prepare(
            "SELECT id, tenant_id, action, target_type, target_id, actor, detail, timestamp
             FROM events ORDER BY timestamp, rowid",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    action: row.get(2)?,
                    target_type: row.get(3)?,
                    target_id: row.get(4)?,
                    actor: row.get(5)?,
                    detail: row.get(6)?,
                    timestamp: row.get::<_, i64>(7)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

impl Store for SqliteStore {
    fn load(&self) -> Result<ControllerState> {
        let connection = self.connection.lock().expect("connection poisoned");
        Ok(ControllerState {
            tenants: self
                .load_tenants(&connection)?
                .into_iter()
                .map(|tenant| (tenant.id.clone(), tenant))
                .collect(),
            networks: self
                .load_networks(&connection)?
                .into_iter()
                .map(|network| (network.id.clone(), network))
                .collect(),
            nodes: self
                .load_nodes(&connection)?
                .into_iter()
                .map(|node| (node.id.clone(), node))
                .collect(),
            policies: self
                .load_policies(&connection)?
                .into_iter()
                .map(|policy| (policy.id.clone(), policy))
                .collect(),
            relays: self
                .load_relays(&connection)?
                .into_iter()
                .map(|relay| (relay.id.clone(), relay))
                .collect(),
            events: self.load_events(&connection)?,
            started_at: crate::model::now_unix(),
        })
    }

    fn save(&self, state: &ControllerState) -> Result<()> {
        let mut connection = self.connection.lock().expect("connection poisoned");
        let transaction = connection.transaction()?;

        transaction.execute("DELETE FROM events", [])?;
        transaction.execute("DELETE FROM relays", [])?;
        transaction.execute("DELETE FROM policies", [])?;
        transaction.execute("DELETE FROM nodes", [])?;
        transaction.execute("DELETE FROM networks", [])?;
        transaction.execute("DELETE FROM tenants", [])?;

        for tenant in state.tenants.values() {
            transaction.execute(
                "INSERT INTO tenants(id, name, slug, deployment, status, plan, limits,
                                     controller_id, controller_public_key, created_at,
                                     updated_at, suspended_at, deleted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    tenant.id,
                    tenant.name,
                    tenant.slug,
                    format!("{:?}", tenant.deployment).to_lowercase(),
                    format!("{:?}", tenant.status).to_lowercase(),
                    tenant.plan,
                    serde_json::to_string(&tenant.limits).unwrap_or_else(|_| "{}".into()),
                    tenant.controller_id,
                    tenant.controller_public_key,
                    tenant.created_at as i64,
                    tenant.updated_at as i64,
                    tenant.suspended_at.map(|v| v as i64),
                    tenant.deleted_at.map(|v| v as i64),
                ],
            )?;
        }

        for network in state.networks.values() {
            transaction.execute(
                "INSERT INTO networks(id, tenant_id, name, description, network_id, cidr,
                                     credential_ttl_secs, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    network.id,
                    network.tenant_id,
                    network.name,
                    network.description,
                    network.network_id as i64,
                    network.cidr,
                    network.credential_ttl_secs as i64,
                    network.created_at as i64,
                ],
            )?;
        }

        for node in state.nodes.values() {
            transaction.execute(
                "INSERT INTO nodes(id, tenant_id, network_id, name, address, ipv4_address,
                                   endpoint, public_key, pq_public_key, fingerprint, tags,
                                   platform, version, status, credential_issued_at,
                                   credential_not_after, last_seen, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                         ?16, ?17, ?18)",
                params![
                    node.id,
                    node.tenant_id,
                    node.network_id,
                    node.name,
                    node.address,
                    node.ipv4_address,
                    node.endpoint,
                    node.public_key,
                    node.pq_public_key,
                    node.fingerprint,
                    serde_json::to_string(&node.tags).unwrap_or_else(|_| "[]".into()),
                    node.platform,
                    node.version,
                    format!("{:?}", node.status).to_lowercase(),
                    node.credential_issued_at as i64,
                    node.credential_not_after as i64,
                    node.last_seen.map(|value| value as i64),
                    node.created_at as i64,
                ],
            )?;
        }

        for policy in state.policies.values() {
            transaction.execute(
                "INSERT INTO policies(id, tenant_id, network_id, name, description, protocol,
                                      port, source, destination, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    policy.id,
                    policy.tenant_id,
                    policy.network_id,
                    policy.name,
                    policy.description,
                    format!("{:?}", policy.protocol).to_lowercase(),
                    serde_json::to_string(&policy.port).unwrap_or_else(|_| "null".into()),
                    serde_json::to_string(&policy.source).unwrap_or_else(|_| "null".into()),
                    serde_json::to_string(&policy.destination).unwrap_or_else(|_| "null".into()),
                    i64::from(policy.enabled),
                    policy.created_at as i64,
                    policy.updated_at as i64,
                ],
            )?;
        }

        for relay in state.relays.values() {
            transaction.execute(
                "INSERT INTO relays(id, tenant_id, name, node_id, endpoint, networks, enabled,
                                    status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    relay.id,
                    relay.tenant_id,
                    relay.name,
                    relay.node_id,
                    relay.endpoint,
                    serde_json::to_string(&relay.networks).unwrap_or_else(|_| "[]".into()),
                    i64::from(relay.enabled),
                    format!("{:?}", relay.status).to_lowercase(),
                    relay.created_at as i64,
                    relay.updated_at as i64,
                ],
            )?;
        }

        for event in &state.events {
            transaction.execute(
                "INSERT INTO events(id, tenant_id, action, target_type, target_id, actor, detail,
                                    timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.id,
                    event.tenant_id,
                    event.action,
                    event.target_type,
                    event.target_id,
                    event.actor,
                    event.detail,
                    event.timestamp as i64,
                ],
            )?;
        }

        transaction.commit()?;
        Ok(())
    }
}

fn parse_deployment(value: &str) -> crate::tenant::Deployment {
    match value {
        "dedicated" => crate::tenant::Deployment::Dedicated,
        _ => crate::tenant::Deployment::Shared,
    }
}

fn parse_tenant_status(value: &str) -> crate::tenant::TenantStatus {
    match value {
        "active" => crate::tenant::TenantStatus::Active,
        "suspended" => crate::tenant::TenantStatus::Suspended,
        "deleted" => crate::tenant::TenantStatus::Deleted,
        _ => crate::tenant::TenantStatus::Provisioning,
    }
}

fn parse_node_status(value: &str) -> crate::model::NodeStatus {
    match value {
        "online" => crate::model::NodeStatus::Online,
        "degraded" => crate::model::NodeStatus::Degraded,
        "offline" => crate::model::NodeStatus::Offline,
        "revoked" => crate::model::NodeStatus::Revoked,
        _ => crate::model::NodeStatus::Pending,
    }
}

fn parse_relay_status(value: &str) -> crate::model::RelayStatus {
    match value {
        "degraded" => crate::model::RelayStatus::Degraded,
        "offline" => crate::model::RelayStatus::Offline,
        "draining" => crate::model::RelayStatus::Draining,
        _ => crate::model::RelayStatus::Healthy,
    }
}

fn parse_protocol(value: &str) -> crate::model::Protocol {
    match value {
        "tcp" => crate::model::Protocol::Tcp,
        "udp" => crate::model::Protocol::Udp,
        "icmp" => crate::model::Protocol::Icmp,
        _ => crate::model::Protocol::Any,
    }
}

fn parse_port(value: &Value) -> crate::model::PortSpec {
    if let Some(single) = value.get("single").and_then(Value::as_u64) {
        return crate::model::PortSpec::Single(single as u16);
    }
    if let Some(range) = value.get("range").and_then(Value::as_array) {
        if let (Some(start), Some(end)) = (
            range.first().and_then(Value::as_u64),
            range.get(1).and_then(Value::as_u64),
        ) {
            return crate::model::PortSpec::Range(start as u16, end as u16);
        }
    }
    crate::model::PortSpec::Any
}

fn parse_selector(value: &Value) -> crate::model::Selector {
    let kind = value.get("kind").and_then(Value::as_str).unwrap_or("any");
    match kind {
        "node" => crate::model::Selector::Node {
            node_id: value
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        "tag" => crate::model::Selector::Tag {
            tag: value
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        "platform" => crate::model::Selector::Platform {
            platform: value
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        "subnet" => crate::model::Selector::Subnet {
            cidr: value
                .get("cidr")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        "network" => crate::model::Selector::Network {
            network_id: value
                .get("network_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        _ => crate::model::Selector::Any,
    }
}

impl From<rusqlite::Error> for ControllerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(format!("database error: {error}"))
    }
}
