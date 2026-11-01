//! HTTP API for the ZT-next control plane.
//!
//! # Two API surfaces
//!
//! The control plane exposes two distinct APIs:
//!
//! - **`/api/v1/tenants/...`** — the master console. It administers tenant
//!   lifecycle, plans, limits, and the control plane as a whole. Access is
//!   restricted to operators.
//! - **`/api/v1/t/{tenant}/...`** — the tenant API. Every path carries the
//!   tenant ID, and every query is scoped to it. This is what a tenant's
//!   own console and CLI use.
//!
//! The two surfaces share a store but never share a scope. There is no
//! endpoint that returns one tenant's objects to another tenant, because
//! the service layer filters by tenant before returning anything.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ControllerError;
use crate::middleware::{require_auth, AuthState};
use crate::model::{Network, Node, NodeKeys, Policy, Relay, Selector, Topology};
use crate::principal::Principal;
use crate::service::NodeUsage;
use crate::service::{ControlPlaneHealth, Controller};
use crate::tenant::Invoice;
use crate::tenant::{Deployment, Tenant, TenantLimits};

/// Build the application router.
///
/// This router has **no authentication**. It is intended for tests and for
/// binding to a loopback interface where the operator is trusted. Use
/// [`router_with_auth`] for anything reachable from another host.
pub fn router(controller: Controller) -> Router {
    build_router(controller)
}

/// Build the application router, with bearer-token authentication.
///
/// Every route except the health checks requires a token from the
/// configured OIDC provider. Tenant-scoped routes additionally require the
/// token to name the tenant in the path, and the master console requires
/// the operator role.
pub fn router_with_auth(controller: Controller, auth: AuthState) -> Router {
    build_router(controller).layer(axum::middleware::from_fn_with_state(auth, require_auth))
}

/// The routes, without the auth layer.
fn build_router(controller: Controller) -> Router {
    Router::new()
        // Control plane and master console.
        .route("/api/v1/health", get(health))
        .route("/api/v1/controller", get(controller_info))
        .route("/api/v1/control-plane", get(control_plane))
        .route("/api/v1/tenants", get(list_tenants).post(create_tenant))
        .route("/api/v1/tenants/{id}", get(get_tenant).patch(update_tenant))
        .route("/api/v1/tenants/{id}/suspend", post(suspend_tenant))
        .route("/api/v1/tenants/{id}/reactivate", post(reactivate_tenant))
        .route("/api/v1/tenants/{id}/usage", get(tenant_usage))
        // What a tenant owes for the period. The tenant sees its own, and
        // the operator sees any tenant's.
        .route("/api/v1/t/{tenant}/billing", get(tenant_billing))
        // The agent asks the controller what address it appears from, so it
        // can tell its peers where to reach it. This is how NAT traversal
        // works without a STUN server: the controller sits on the public
        // internet and sees the source address of every request.
        .route("/api/v1/my-endpoint", get(my_endpoint))
        .route("/api/v1/tenants/{id}/billing", get(tenant_billing_for))
        .route("/api/v1/tenants/{id}/events", get(tenant_events))
        .route("/api/v1/tenants/{id}", delete(delete_tenant))
        // Tenant-scoped API.
        .route(
            "/api/v1/t/{tenant}/networks",
            get(list_networks).post(create_network),
        )
        .route("/api/v1/t/{tenant}/networks/{id}", delete(delete_network))
        .route(
            "/api/v1/t/{tenant}/nodes",
            get(list_nodes).post(enroll_node),
        )
        .route(
            "/api/v1/t/{tenant}/nodes/{id}",
            get(get_node).delete(revoke_node),
        )
        // A node asks who it is, using the credential it was issued. This
        // is how a node learns its own identity without being told.
        .route("/api/v1/t/{tenant}/nodes/self", get(get_self))
        // The topology a node needs to carry traffic: its own address, the
        // range it lives in, and the peers it shares the range with.
        .route("/api/v1/t/{tenant}/topology", get(get_topology))
        // A node reports how its peers reach it: the endpoint they send
        // to, and the post-quantum key they check its signature with.
        .route(
            "/api/v1/t/{tenant}/nodes/self/presence",
            post(report_presence),
        )
        .route(
            "/api/v1/t/{tenant}/nodes/{id}/credential",
            post(renew_credential),
        )
        .route(
            "/api/v1/t/{tenant}/policies",
            get(list_policies).post(create_policy),
        )
        .route("/api/v1/t/{tenant}/policies/{id}", delete(delete_policy))
        .route(
            "/api/v1/t/{tenant}/relays",
            get(list_relays).post(create_relay),
        )
        .route("/api/v1/t/{tenant}/relays/{id}/drain", post(drain_relay))
        .route("/api/v1/t/{tenant}/events", get(list_events))
        .with_state(controller)
}

/// The current Unix time in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

impl IntoResponse for ControllerError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        let status = StatusCode::from(self);
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct NetworkQuery {
    network: Option<String>,
}

// ---------------------------------------------------------------------------
// Control plane and master console
// ---------------------------------------------------------------------------

async fn health(State(controller): State<Controller>) -> Json<ControlPlaneHealth> {
    Json(controller.control_plane_health().await)
}

async fn controller_info(State(controller): State<Controller>) -> Json<serde_json::Value> {
    Json(json!({
        "id": controller.controller_id().await,
        "public_key": controller.public_key().await,
        "credential_ttl_secs": crate::service::DEFAULT_CREDENTIAL_TTL_SECS,
    }))
}

async fn control_plane(State(controller): State<Controller>) -> Json<ControlPlaneHealth> {
    Json(controller.control_plane_health().await)
}

#[derive(Debug, Serialize)]
struct TenantList {
    items: Vec<Tenant>,
    total: usize,
}

async fn list_tenants(State(controller): State<Controller>) -> Json<TenantList> {
    let items = controller.list_tenants().await;
    let total = items.len();
    Json(TenantList { items, total })
}

async fn get_tenant(
    State(controller): State<Controller>,
    Path(id): Path<String>,
) -> Result<Json<Tenant>, ControllerError> {
    Ok(Json(controller.get_tenant(&id).await?))
}

#[derive(Debug, Deserialize)]
struct CreateTenantRequest {
    name: String,
    slug: String,
    #[serde(default = "default_deployment")]
    deployment: Deployment,
    #[serde(default = "default_plan")]
    plan: String,
    #[serde(default)]
    limits: Option<TenantLimits>,
}

fn default_deployment() -> Deployment {
    Deployment::Shared
}

fn default_plan() -> String {
    "starter".into()
}

async fn create_tenant(
    State(controller): State<Controller>,
    principal: Principal,
    Json(request): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<Tenant>), ControllerError> {
    let tenant = controller
        .create_tenant(
            request.name,
            request.slug,
            request.deployment,
            request.plan,
            request.limits.unwrap_or_default(),
            &principal.actor(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(tenant)))
}

#[derive(Debug, Deserialize)]
struct UpdateTenantRequest {
    plan: Option<String>,
    limits: Option<TenantLimits>,
}

async fn update_tenant(
    State(controller): State<Controller>,
    principal: Principal,
    Path(id): Path<String>,
    Json(request): Json<UpdateTenantRequest>,
) -> Result<Json<Tenant>, ControllerError> {
    Ok(Json(
        controller
            .update_tenant(&id, request.plan, request.limits, &principal.actor())
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
struct SuspendTenantRequest {
    #[serde(default)]
    reason: String,
}

async fn suspend_tenant(
    State(controller): State<Controller>,
    principal: Principal,
    Path(id): Path<String>,
    Json(request): Json<SuspendTenantRequest>,
) -> Result<Json<Tenant>, ControllerError> {
    Ok(Json(
        controller
            .suspend_tenant(&id, &request.reason, &principal.actor())
            .await?,
    ))
}

async fn reactivate_tenant(
    State(controller): State<Controller>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<Tenant>, ControllerError> {
    Ok(Json(
        controller
            .reactivate_tenant(&id, &principal.actor())
            .await?,
    ))
}

async fn delete_tenant(
    State(controller): State<Controller>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<Tenant>, ControllerError> {
    Ok(Json(
        controller.delete_tenant(&id, &principal.actor()).await?,
    ))
}

#[derive(Debug, Serialize)]
struct UsageResponse {
    usage: crate::tenant::TenantUsage,
    limits: TenantLimits,
}

/// The public address the agent appears from.
///
/// Cloudflare and Caddy both add forwarded headers, so the controller sees
/// the real source address even though the request arrived through two
/// proxies. The agent reports this address as its endpoint, so its peers
/// can reach it through the NAT.
async fn my_endpoint(
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    // The forwarded headers, in the order the proxies add them. The first
    // one that is set is the one closest to the client, which is the
    // address the rest of the internet sees.
    let source = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(|value| value.trim().to_string())
                .unwrap_or_default()
        });

    Json(serde_json::json!({ "address": source }))
}

/// What a tenant owes for the period that contains today.
async fn tenant_billing(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
    principal: Principal,
) -> Result<Json<Invoice>, ControllerError> {
    // The tenant may only see its own invoice. The operator may see any
    // tenant's, which the tier above already allows.
    if let Some(subject) = principal.tenant_id() {
        if subject != tenant {
            return Err(ControllerError::NotFound("tenant"));
        }
    }

    let invoice = controller.invoice(&tenant, now_unix()).await?;
    Ok(Json(invoice))
}

/// What a tenant owes, for the operator.
async fn tenant_billing_for(
    State(controller): State<Controller>,
    Path(id): Path<String>,
) -> Result<Json<Invoice>, ControllerError> {
    let invoice = controller.invoice(&id, now_unix()).await?;
    Ok(Json(invoice))
}

async fn tenant_usage(
    State(controller): State<Controller>,
    Path(id): Path<String>,
) -> Result<Json<UsageResponse>, ControllerError> {
    let tenant = controller.get_tenant(&id).await?;
    let usage = controller.tenant_usage(&id).await;
    Ok(Json(UsageResponse {
        usage,
        limits: tenant.limits,
    }))
}

#[derive(Debug, Serialize)]
struct EventList {
    items: Vec<crate::model::AuditEvent>,
    total: usize,
}

async fn tenant_events(
    State(controller): State<Controller>,
    Path(id): Path<String>,
) -> Result<Json<EventList>, ControllerError> {
    // Confirm the tenant exists so a typo does not return an empty list.
    controller.get_tenant(&id).await?;
    let items = controller.list_events(Some(&id)).await;
    let total = items.len();
    Ok(Json(EventList { items, total }))
}

// ---------------------------------------------------------------------------
// Tenant-scoped API
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct NetworkList {
    items: Vec<Network>,
    total: usize,
}

async fn list_networks(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
) -> Result<Json<NetworkList>, ControllerError> {
    let items = controller.list_networks(&tenant).await;
    let total = items.len();
    Ok(Json(NetworkList { items, total }))
}

#[derive(Debug, Deserialize)]
struct CreateNetworkRequest {
    name: String,
    #[serde(default)]
    description: String,
    cidr: String,
    credential_ttl_secs: Option<u32>,
}

async fn create_network(
    State(controller): State<Controller>,
    principal: Principal,
    Path(tenant): Path<String>,
    Json(request): Json<CreateNetworkRequest>,
) -> Result<(StatusCode, Json<Network>), ControllerError> {
    let network = controller
        .create_network(
            &tenant,
            request.name,
            request.description,
            request.cidr,
            request.credential_ttl_secs,
            &principal.actor(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(network)))
}

async fn delete_network(
    State(controller): State<Controller>,
    principal: Principal,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<StatusCode, ControllerError> {
    controller
        .delete_network(&tenant, &id, &principal.actor())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct NodeList {
    items: Vec<Node>,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: usize,
}

async fn list_nodes(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
    Query(query): Query<NetworkQuery>,
    Query(page): Query<ListQuery>,
) -> Result<Json<NodeList>, ControllerError> {
    let all = controller
        .list_nodes(&tenant, query.network.as_deref())
        .await;
    let total = all.len();

    let items = all
        .into_iter()
        .skip(page.offset)
        .take(page.limit.unwrap_or(500))
        .collect();

    Ok(Json(NodeList { items, total }))
}

#[derive(Debug, Deserialize)]
struct EnrollNodeRequest {
    network_id: String,
    name: String,
    /// Hex-encoded Ed25519 public key.
    public_key: String,
    /// Hex-encoded ML-DSA-65 public key.
    ///
    /// A peer needs it to complete a handshake, so a node that does not
    /// send it cannot be reached.
    #[serde(default)]
    pq_public_key: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EnrollNodeResponse {
    node: Node,
    /// Hex-encoded serialized credential. Shown once.
    credential: String,
    credential_not_after: u64,
}

async fn enroll_node(
    State(controller): State<Controller>,
    principal: Principal,
    Path(tenant): Path<String>,
    Json(request): Json<EnrollNodeRequest>,
) -> Result<(StatusCode, Json<EnrollNodeResponse>), ControllerError> {
    let bytes = hex::decode(&request.public_key)
        .map_err(|_| ControllerError::InvalidRequest("public_key must be hex encoded".into()))?;
    let public_key: [u8; 32] = bytes.try_into().map_err(|_| {
        ControllerError::InvalidRequest("public_key must be exactly 32 bytes".into())
    })?;

    let pq_public_key = hex::decode(&request.pq_public_key)
        .map_err(|_| ControllerError::InvalidRequest("pq_public_key must be hex encoded".into()))?;

    let (node, credential) = controller
        .enroll_node(
            &tenant,
            &request.network_id,
            request.name,
            NodeKeys {
                ed25519: public_key,
                ml_dsa: pq_public_key,
            },
            request.tags,
            &principal.actor(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollNodeResponse {
            node,
            credential: hex::encode(credential.serialize()),
            credential_not_after: credential.not_after(),
        }),
    ))
}

async fn get_node(
    State(controller): State<Controller>,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<Json<Node>, ControllerError> {
    Ok(Json(controller.get_node(&tenant, &id).await?))
}

/// The node behind the request's credential.
async fn get_self(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
    principal: Principal,
) -> Result<Json<Node>, ControllerError> {
    // The credential is bound to the node's own key, and the subject of the
    // token is the node's identifier, so the node is found by that subject.
    let node = controller
        .find_node_for_principal(&tenant, principal.subject())
        .await?;
    Ok(Json(node))
}

async fn get_topology(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
    principal: Principal,
) -> Result<Json<Topology>, ControllerError> {
    // The subject of a node's credential is the node's identifier, so the
    // node is found by that subject. A node only ever sees its own
    // network.
    let topology = controller
        .topology_for(&tenant, principal.subject())
        .await?;
    Ok(Json(topology))
}

#[derive(Debug, Deserialize)]
struct PresenceRequest {
    /// The address the node's peers reach it at.
    endpoint: String,
    /// The node's ML-DSA-65 public key, hex encoded.
    ///
    /// A peer needs it to complete a handshake. The key is generated when
    /// the node starts, so a node reports it every time it comes up.
    #[serde(default)]
    pq_public_key: String,
    /// What the node carried since it last reported.
    #[serde(default)]
    usage: UsageRequest,
    /// Whether the node forwards packets between the others.
    #[serde(default)]
    relay: bool,
}

/// What a node carried since it last reported.
#[derive(Debug, Default, Deserialize)]
struct UsageRequest {
    #[serde(default)]
    bytes_in: u64,
    #[serde(default)]
    bytes_out: u64,
    #[serde(default)]
    packets: u64,
}

async fn report_presence(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
    principal: Principal,
    Json(request): Json<PresenceRequest>,
) -> Result<Json<Node>, ControllerError> {
    // A node may only report its own presence. The subject of its
    // credential is its identifier, so there is no path to tamper with.
    let node = controller
        .report_presence(
            &tenant,
            principal.subject(),
            &request.endpoint,
            &request.pq_public_key,
            request.relay,
            NodeUsage {
                bytes_in: request.usage.bytes_in,
                bytes_out: request.usage.bytes_out,
                packets: request.usage.packets,
            },
        )
        .await?;
    Ok(Json(node))
}

async fn revoke_node(
    State(controller): State<Controller>,
    principal: Principal,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<Json<Node>, ControllerError> {
    Ok(Json(
        controller
            .revoke_node(&tenant, &id, &principal.actor())
            .await?,
    ))
}

#[derive(Debug, Serialize)]
struct CredentialResponse {
    node: Node,
    credential: String,
    credential_not_after: u64,
}

async fn renew_credential(
    State(controller): State<Controller>,
    principal: Principal,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<Json<CredentialResponse>, ControllerError> {
    let (node, credential) = controller
        .renew_node_credential(&tenant, &id, &principal.actor())
        .await?;
    Ok(Json(CredentialResponse {
        node,
        credential: hex::encode(credential.serialize()),
        credential_not_after: credential.not_after(),
    }))
}

#[derive(Debug, Serialize)]
struct PolicyList {
    items: Vec<Policy>,
    total: usize,
}

async fn list_policies(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
    Query(query): Query<NetworkQuery>,
    Query(page): Query<ListQuery>,
) -> Result<Json<PolicyList>, ControllerError> {
    let all = controller
        .list_policies(&tenant, query.network.as_deref())
        .await;
    let total = all.len();

    let items = all
        .into_iter()
        .skip(page.offset)
        .take(page.limit.unwrap_or(500))
        .collect();

    Ok(Json(PolicyList { items, total }))
}

#[derive(Debug, Deserialize)]
struct CreatePolicyRequest {
    network_id: String,
    name: String,
    #[serde(default)]
    description: String,
    protocol: crate::model::Protocol,
    port: crate::model::PortSpec,
    source: Selector,
    destination: Selector,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

async fn create_policy(
    State(controller): State<Controller>,
    principal: Principal,
    Path(tenant): Path<String>,
    Json(request): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<Policy>), ControllerError> {
    let policy = controller
        .create_policy(
            &tenant,
            Policy {
                id: String::new(),
                tenant_id: String::new(),
                network_id: request.network_id,
                name: request.name,
                description: request.description,
                protocol: request.protocol,
                port: request.port,
                source: request.source,
                destination: request.destination,
                enabled: request.enabled,
                created_at: 0,
                updated_at: 0,
            },
            &principal.actor(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn delete_policy(
    State(controller): State<Controller>,
    principal: Principal,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<StatusCode, ControllerError> {
    controller
        .delete_policy(&tenant, &id, &principal.actor())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct RelayList {
    items: Vec<Relay>,
    total: usize,
}

async fn list_relays(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
) -> Result<Json<RelayList>, ControllerError> {
    let items = controller.list_relays(&tenant).await;
    let total = items.len();
    Ok(Json(RelayList { items, total }))
}

#[derive(Debug, Deserialize)]
struct CreateRelayRequest {
    name: String,
    node_id: String,
    endpoint: String,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

async fn create_relay(
    State(controller): State<Controller>,
    principal: Principal,
    Path(tenant): Path<String>,
    Json(request): Json<CreateRelayRequest>,
) -> Result<(StatusCode, Json<Relay>), ControllerError> {
    let relay = controller
        .create_relay(
            &tenant,
            Relay {
                id: String::new(),
                tenant_id: String::new(),
                name: request.name,
                node_id: request.node_id,
                endpoint: request.endpoint,
                networks: request.networks,
                enabled: request.enabled,
                status: crate::model::RelayStatus::Healthy,
                created_at: 0,
                updated_at: 0,
            },
            &principal.actor(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(relay)))
}

async fn drain_relay(
    State(controller): State<Controller>,
    principal: Principal,
    Path((tenant, id)): Path<(String, String)>,
) -> Result<Json<Relay>, ControllerError> {
    Ok(Json(
        controller
            .drain_relay(&tenant, &id, &principal.actor())
            .await?,
    ))
}

async fn list_events(
    State(controller): State<Controller>,
    Path(tenant): Path<String>,
) -> Result<Json<EventList>, ControllerError> {
    let items = controller.list_events(Some(&tenant)).await;
    let total = items.len();
    Ok(Json(EventList { items, total }))
}
