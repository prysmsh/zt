//! Request authentication middleware.
//!
//! The controller's routes fall into three tiers:
//!
//! 1. **Public** — health checks. Anyone may call them.
//! 2. **Tenant** — the tenant-scoped API. The caller's token must name the
//!    tenant in the path, so a token for one tenant cannot address another.
//! 3. **Operator** — the master console. The caller's token must carry the
//!    operator role, because these routes create and delete tenants.
//!
//! The tier is decided by the request path, not by the handler. A handler
//! cannot accidentally forget to check, because the middleware runs first
//! and rejects the request before the handler sees it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use std::time::Duration;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::auth::{bearer_token, AuthError, Identity, Verifier};
use crate::service::Controller;

/// The shared state the middleware needs.
/// How many requests a token may make in a second.
const RATE_LIMIT_PER_SECOND: u32 = 100;

/// How many join-path requests a single source may make per second.
///
/// The join routes carry no token, so this is what keeps them from being
/// flooded. Polling hosts check in every couple of seconds, and a real
/// network rarely joins more than a few hosts at once.
const ANONYMOUS_RATE_LIMIT: u32 = 10;

/// Whether the path is one of the open join routes.
fn is_join_path(path: &str) -> bool {
    path == "/api/v1/join" || path.starts_with("/api/v1/join/")
}

/// The address a request appears to come from.
///
/// Behind Cloudflare and Caddy the socket peer is the proxy, so the
/// forwarded headers carry the real caller. The fallback is a single
/// shared bucket: coarse, but it still blunts a flood from callers that
/// hide their address.
fn client_address(headers: &HeaderMap) -> String {
    for name in ["cf-connecting-ip", "x-real-ip"] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            return value.to_string();
        }
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string())
}

/// A fixed-window rate limiter keyed by the caller's token.
///
/// In-memory on purpose: the controller is one process, and a rate limit
/// that survives a restart would need shared state the controller does
/// not have. A deployment that needs more than this puts a limiter in
/// front, which is where it belongs.
#[derive(Clone)]
pub struct RateLimiter {
    window: Arc<Mutex<HashMap<String, (u32, std::time::Instant)>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            window: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether a caller may make another request now.
    ///
    /// The key is whatever identifies the caller: its token's subject, or
    /// its address when it has no token.
    pub fn allows(&self, key: &str, limit: u32) -> bool {
        let mut window = self.window.lock().expect("rate limiter poisoned");
        let now = std::time::Instant::now();

        let entry = window.entry(key.to_string()).or_insert((0, now));

        // The window is a second. When it has elapsed, the count restarts.
        if now.duration_since(entry.1) >= Duration::from_secs(1) {
            *entry = (1, now);
            return true;
        }

        entry.0 += 1;
        entry.0 <= limit
    }
}

#[derive(Clone)]
pub struct AuthState {
    /// The rate limiter, shared by every request.
    pub limiter: RateLimiter,
    /// The token verifier.
    pub verifier: Arc<Verifier>,
    /// The controller, which verifies a node's own credential.
    pub controller: Controller,
    /// The scope a tenant-scoped token must carry.
    pub tenant_scope: String,
    /// The scope an operator token must carry.
    pub operator_scope: String,
}

/// The error body returned to an unauthenticated caller.
#[derive(Debug)]
pub struct AuthRejection {
    status: StatusCode,
    message: String,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<AuthError> for AuthRejection {
    fn from(error: AuthError) -> Self {
        let status = match error {
            AuthError::Missing => StatusCode::UNAUTHORIZED,
            AuthError::Invalid(_) => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

/// The tier a path belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// No authentication needed.
    Public,
    /// A tenant-scoped token naming the tenant in the path.
    Tenant,
    /// An operator token.
    Operator,
}

/// Work out which tier a path belongs to.
///
/// The master console lives under `/api/v1/tenants`. The tenant API lives
/// under `/api/v1/t/{tenant}`. Everything else is public.
fn tier_of(path: &str) -> Tier {
    if path.starts_with("/api/v1/t/") {
        return Tier::Tenant;
    }
    if path.starts_with("/api/v1/tenants") {
        return Tier::Operator;
    }
    Tier::Public
}

/// The tenant named in a tenant-scoped path.
///
/// The path is `/api/v1/t/{tenant}/...`, so the tenant is the segment after
/// `/api/v1/t/`.
fn tenant_of(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/api/v1/t/")?;
    let tenant = rest.split('/').next()?;
    if tenant.is_empty() {
        None
    } else {
        Some(tenant)
    }
}

/// Authenticate a request and enforce its tier.
///
/// This is the middleware that guards every route.
pub async fn require_auth(
    State(state): State<AuthState>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    if tier_of(&path) == Tier::Public {
        // The join routes are open by design — the security lives in the
        // approval. Open is not unguarded: the limit here keys on the
        // caller's address instead of a token, so a flood of fake join
        // requests cannot crowd out real ones. Ten a second is far more
        // than a real host or even a busy office NAT needs, and far less
        // than a script spamming pending requests would want.
        if is_join_path(&path) {
            let source = client_address(&headers);
            if !state.limiter.allows(&format!("ip:{source}"), ANONYMOUS_RATE_LIMIT) {
                return (StatusCode::TOO_MANY_REQUESTS, Json(crate::api::ErrorBody {
                    error: "rate limited".into(),
                })).into_response();
            }
        }
        return next.run(request).await;
    }

    let Some(token) = bearer_token(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
    ) else {
        return AuthRejection::from(AuthError::Missing).into_response();
    };

    // The limit is per token, so one tenant cannot consume the controller's
    // capacity and starve the others. The controller's own health probe is
    // exempt, because it has no token at all.
    if !state.limiter.allows(token, RATE_LIMIT_PER_SECOND) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(crate::api::ErrorBody {
            error: "rate limited".into(),
        })).into_response();
    }

    // A node authenticates with the credential the controller issued it.
    // The credential is signed by this controller and bound to the node's
    // own key, so it needs no shared secret and cannot be replayed by
    // another node.
    let identity = match state.controller.authenticate_node(token).await {
        Ok(identity) => identity,
        Err(_) => match state.verifier.verify(token).await {
            Ok(claims) => Identity {
                subject: claims.sub.clone(),
                name: claims.name.clone(),
                preferred_username: claims.preferred_username.clone(),
                tenant_id: claims.tenant_id.clone(),
                scopes: claims
                    .scopes()
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect(),
                roles: claims.roles().iter().map(|role| role.to_string()).collect(),
            },
            Err(error) => return AuthRejection::from(error).into_response(),
        },
    };

    // The identity is handed to the handler through the request extensions,
    // so the handler can attribute its audit events to the caller without
    // reaching into ambient state.
    request.extensions_mut().insert(identity.clone());

    match tier_of(&path) {
        Tier::Public => next.run(request).await,

        Tier::Tenant => {
            // An operator may reach any tenant. The master console is how
            // an operator administers a tenant other than their own, so
            // refusing them here would make the console unable to do its
            // job.
            let is_operator = identity.has_role(&state.operator_scope)
                || identity.has_scope(&state.operator_scope);

            if !is_operator {
                let Some(path_tenant) = tenant_of(&path) else {
                    return AuthRejection::from(AuthError::Forbidden(
                        "the request does not name a tenant".into(),
                    ))
                    .into_response();
                };

                // The token must name a tenant, and it must be the tenant in
                // the path. A token without a tenant claim cannot address
                // any tenant-scoped route.
                let Some(token_tenant) = identity.tenant_id.as_deref() else {
                    return AuthRejection::from(AuthError::Forbidden(
                        "this token does not belong to a tenant".into(),
                    ))
                    .into_response();
                };

                if token_tenant != path_tenant {
                    return AuthRejection::from(AuthError::Forbidden(
                        "this token cannot access another tenant".into(),
                    ))
                    .into_response();
                }

                if !identity.has_scope(&state.tenant_scope) {
                    return AuthRejection::from(AuthError::Forbidden(format!(
                        "this token is missing the {} scope",
                        state.tenant_scope
                    )))
                    .into_response();
                }

                // A suspended or deleted tenant is locked out of its own
                // API. Without this, suspension would only stop new
                // resources: the tenant's nodes would keep renewing their
                // credentials, and access would never lapse.
                if let Err(error) = state.controller.require_usable_tenant(path_tenant).await {
                    return AuthRejection::from(AuthError::Forbidden(error.to_string()))
                        .into_response();
                }
            }

            next.run(request).await
        }

        Tier::Operator => {
            if !identity.has_role(&state.operator_scope)
                && !identity.has_scope(&state.operator_scope)
            {
                return AuthRejection::from(AuthError::Forbidden(format!(
                    "this token is missing the {} role",
                    state.operator_scope
                )))
                .into_response();
            }
            next.run(request).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tier_is_derived_from_the_path() {
        assert_eq!(tier_of("/api/v1/health"), Tier::Public);
        assert_eq!(tier_of("/api/v1/controller"), Tier::Public);
        assert_eq!(tier_of("/api/v1/tenants"), Tier::Operator);
        assert_eq!(tier_of("/api/v1/tenants/abc/suspend"), Tier::Operator);
        assert_eq!(tier_of("/api/v1/t/acme/networks"), Tier::Tenant);
        assert_eq!(tier_of("/api/v1/t/acme/nodes"), Tier::Tenant);
    }

    #[test]
    fn the_tenant_is_read_from_the_path() {
        assert_eq!(tenant_of("/api/v1/t/acme/networks"), Some("acme"));
        assert_eq!(tenant_of("/api/v1/t/acme"), Some("acme"));
        assert_eq!(tenant_of("/api/v1/t/acme/nodes/1/credential"), Some("acme"));
        assert_eq!(tenant_of("/api/v1/tenants"), None);
        assert_eq!(tenant_of("/api/v1/health"), None);
    }

    #[test]
    fn a_tenant_id_with_a_dash_is_not_mistaken_for_a_path() {
        // Tenant IDs are UUIDs, which contain dashes. The tenant is still
        // the first path segment.
        assert_eq!(
            tenant_of("/api/v1/t/263118d9-cd2c-419b-81c3-7bf499c5bd80/networks"),
            Some("263118d9-cd2c-419b-81c3-7bf499c5bd80")
        );
    }
}
