//! Standalone ZT-next controller service.
//!
//! # Authentication
//!
//! The controller requires bearer tokens when it is configured with an OIDC
//! provider. Without one it runs unauthenticated, which is only safe on a
//! loopback interface.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `ZT_OIDC_ISSUER` | The issuer tokens must come from |
//! | `ZT_OIDC_AUDIENCE` | The audience tokens must be minted for |
//! | `ZT_OIDC_JWKS` | The JWKS endpoint. Discovered from the issuer if unset |
//! | `ZT_OIDC_OPERATOR_ROLE` | The role that grants master-console access |
//! | `ZT_OIDC_TENANT_SCOPE` | The scope a tenant-scoped token must carry |
//!
//! The JWKS endpoint is discovered from the issuer's OpenID configuration
//! when `ZT_OIDC_JWKS` is not set.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::{router, router_with_auth, Controller, IdentityStore, SqliteStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind: SocketAddr = std::env::var("ZT_CONTROLLER_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;

    let data_dir =
        PathBuf::from(std::env::var("ZT_CONTROLLER_DATA_DIR").unwrap_or_else(|_| "data".into()));
    std::fs::create_dir_all(&data_dir)?;

    let database_path = data_dir.join("controller.db");
    let identity_path = data_dir.join("controller.key");

    let identity = IdentityStore::new(&identity_path).load_or_create()?;
    let store = Arc::new(SqliteStore::open(&database_path)?);
    let controller = Controller::with_store_and_retention(identity, store, Default::default())?;

    tracing::info!(
        %bind,
        database = %database_path.display(),
        identity = %identity_path.display(),
        "ZT-next controller listening"
    );

    let app = match auth_state(&controller).await? {
        Some(state) => {
            tracing::info!("authentication enabled");
            router_with_auth(controller, state)
        }
        None => {
            // Without authentication, the master console can create and
            // delete tenants, so the controller must not be reachable from
            // another host. Binding to loopback is the safe default.
            if !bind.ip().is_loopback() {
                return Err(format!(
                    "refusing to run unauthenticated on {bind}: \
                     set ZT_OIDC_ISSUER and ZT_OIDC_AUDIENCE, or bind to loopback"
                )
                .into());
            }
            tracing::warn!(
                "authentication disabled — the controller is unauthenticated and \
                 must stay on loopback"
            );
            router(controller)
        }
    };

    let listener = TcpListener::bind(bind).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Build the auth state from the environment, if it is configured.
async fn auth_state(controller: &Controller) -> Result<Option<AuthState>, Box<dyn std::error::Error>> {
    let issuer = match std::env::var("ZT_OIDC_ISSUER") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return Ok(None),
    };
    let audience = std::env::var("ZT_OIDC_AUDIENCE")
        .map_err(|_| "ZT_OIDC_ISSUER is set, so ZT_OIDC_AUDIENCE must be set too")?
        .trim()
        .to_string();

    let jwks_uri = match std::env::var("ZT_OIDC_JWKS") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => discover_jwks(&issuer).await?,
    };

    let mut config = AuthConfig::new(&issuer, &audience, &jwks_uri);

    if let Ok(role) = std::env::var("ZT_OIDC_OPERATOR_ROLE") {
        if !role.trim().is_empty() {
            config.operator_role = role.trim().to_string();
        }
    }

    let tenant_scope = std::env::var("ZT_OIDC_TENANT_SCOPE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "zt:tenant".to_string());

    tracing::info!(issuer = %issuer, audience = %audience, jwks = %jwks_uri, "OIDC configured");

    Ok(Some(AuthState {
            limiter: zt_controller::middleware::RateLimiter::new(),
        verifier: Arc::new(Verifier::new(config)),
        controller: controller.clone(),
        tenant_scope,
        operator_scope: std::env::var("ZT_OIDC_OPERATOR_ROLE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "zt:operator".to_string()),
    }))
}

/// Discover the JWKS endpoint from the issuer's OpenID configuration.
async fn discover_jwks(issuer: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("could not reach the issuer at {url}: {error}"))?;

    let document: serde_json::Value = response.json().await.map_err(|error| {
        format!("the issuer at {url} returned malformed metadata: {error}")
    })?;

    document
        .get("jwks_uri")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("the issuer at {url} did not advertise a jwks_uri").into())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown requested");
}
