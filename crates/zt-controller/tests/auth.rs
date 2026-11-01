//! Authentication tests for the controller's HTTP API.
//!
//! These tests cover the three access tiers: public health checks,
//! tenant-scoped routes, and the operator-only master console. The
//! boundary that matters most is the tenant one: a token for one tenant
//! must not reach another tenant's objects.
//!
//! Tokens are signed with a locally generated key, and the verifier is
//! pointed at a JWKS endpoint served by the test itself. The signatures are
//! real, so the tests exercise the same code path production uses.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::{router_with_auth, Controller};

/// The issuer the tests sign tokens for.
const ISSUER: &str = "https://auth.example.test/oidc";
/// The audience the tests mint tokens for.
const AUDIENCE: &str = "https://zt.example.test/api";

/// A test key pair, with the JWKS document it produces.
struct TestKeys {
    kid: String,
    encoding: EncodingKey,
    jwks: Value,
}

/// Generate a key pair and its JWKS document.
fn test_keys() -> TestKeys {
    // A fixed RSA key, so the tests do not depend on randomness.
    let pem = include_str!("../tests/data/test-key.pem");
    let kid = "test-key-1".to_string();

    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": MODULUS,
            "e": "AQAB",
        }]
    });

    TestKeys {
        kid,
        encoding: EncodingKey::from_rsa_pem(pem.as_bytes()).expect("key"),
        jwks,
    }
}

/// The modulus of the test key, base64url without padding.
///
/// This is the `n` value from the test key's public part. It is written out
/// so the JWKS document matches the private key.
const MODULUS: &str = include_str!("../tests/data/test-key-modulus.txt");

/// A header naming the test signing key.
fn header(keys: &TestKeys) -> Header {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(keys.kid.clone());
    header
}

/// Mint a token with the given claims.
fn mint(keys: &TestKeys, mut claims: serde_json::Map<String, Value>) -> String {
    claims.insert("iss".into(), json!(ISSUER));
    claims.insert("aud".into(), json!(AUDIENCE));
    claims.insert("exp".into(), json!(u64::MAX / 2));

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    // The verifier looks the signing key up by key ID, so the header must
    // name it.
    header.kid = Some(keys.kid.clone());

    encode(&header, &Value::Object(claims), &keys.encoding).expect("token")
}

/// Start a JWKS server and build an authenticated router.
async fn authenticated_app() -> (axum::Router, TestKeys) {
    let keys = test_keys();
    let jwks = keys.jwks.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address: SocketAddr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => continue,
            };

            let body = serde_json::to_string(&jwks).unwrap_or_default();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );

            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    let config = AuthConfig::new(ISSUER, AUDIENCE, format!("http://{address}/jwks"));
    let verifier = Arc::new(Verifier::new(config));

    let controller = Controller::new().expect("controller");

    let state = AuthState {
        controller: controller.clone(),
        verifier,
        tenant_scope: "zt:tenant".to_string(),
        operator_scope: "zt:operator".to_string(),
    };

    (router_with_auth(controller, state), keys)
}

/// A request with a bearer token.
fn authorized(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn status_of(response: axum::response::Response) -> StatusCode {
    response.status()
}

// ---------------------------------------------------------------------------
// Public routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_health_check_needs_no_token() {
    let (app, _) = authenticated_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Unauthenticated requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_without_a_token_is_rejected() {
    let (app, _) = authenticated_app().await;

    for path in ["/api/v1/tenants", "/api/v1/t/acme/networks"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            status_of(response).await,
            StatusCode::UNAUTHORIZED,
            "{path} should require a token"
        );
    }
}

#[tokio::test]
async fn a_malformed_token_is_rejected() {
    let (app, _) = authenticated_app().await;
    let response = app
        .oneshot(authorized("/api/v1/tenants", "not-a-jwt"))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// The master console
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_master_console_needs_the_operator_role() {
    let (app, keys) = authenticated_app().await;

    // A tenant token without the operator role.
    let token = mint(
        &keys,
        serde_json::Map::from_iter([(
            "tenant_id".to_string(),
            json!("acme"),
        )]),
    );

    let response = app
        .oneshot(authorized("/api/v1/tenants", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_operator_token_reaches_the_master_console() {
    let (app, keys) = authenticated_app().await;

    let token = mint(
        &keys,
        serde_json::Map::from_iter([("roles".to_string(), json!(["zt:operator"]))]),
    );

    let response = app
        .oneshot(authorized("/api/v1/tenants", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Tenant scoping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tenant_token_reaches_its_own_tenant() {
    let (app, keys) = authenticated_app().await;

    let token = mint(
        &keys,
        serde_json::Map::from_iter([
            ("tenant_id".to_string(), json!("acme")),
            ("scope".to_string(), json!("zt:tenant")),
        ]),
    );

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::OK);
}

#[tokio::test]
async fn a_tenant_token_cannot_reach_another_tenant() {
    let (app, keys) = authenticated_app().await;

    let token = mint(
        &keys,
        serde_json::Map::from_iter([
            ("tenant_id".to_string(), json!("acme")),
            ("scope".to_string(), json!("zt:tenant")),
        ]),
    );

    // The very same token, pointed at a different tenant.
    let response = app
        .oneshot(authorized("/api/v1/t/globex/networks", &token))
        .await
        .unwrap();
    assert_eq!(
        status_of(response).await,
        StatusCode::FORBIDDEN,
        "a tenant token must not reach another tenant"
    );
}

#[tokio::test]
async fn a_token_without_a_tenant_cannot_reach_any_tenant() {
    let (app, keys) = authenticated_app().await;

    let token = mint(
        &keys,
        serde_json::Map::from_iter([("scope".to_string(), json!("zt:tenant"))]),
    );

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_operator_token_reaches_any_tenant() {
    let (app, keys) = authenticated_app().await;

    // The master console is how an operator administers a tenant other
    // than their own, so the operator role reaches every tenant.
    let token = mint(
        &keys,
        serde_json::Map::from_iter([("roles".to_string(), json!(["zt:operator"]))]),
    );

    let response = app
        .clone()
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::OK);

    // And a tenant it does not own.
    let response = app
        .oneshot(authorized("/api/v1/t/globex/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::OK);
}

#[tokio::test]
async fn a_tenant_token_without_the_tenant_scope_is_rejected() {
    let (app, keys) = authenticated_app().await;

    let token = mint(
        &keys,
        serde_json::Map::from_iter([("tenant_id".to_string(), json!("acme"))]),
    );

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Token validity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_token_for_another_audience_is_rejected() {
    let (app, keys) = authenticated_app().await;

    let token = encode(
        &header(&keys),
        &json!({
            "iss": ISSUER,
            "aud": "https://some-other-service.test/api",
            "tenant_id": "acme",
            "scope": "zt:tenant",
            "exp": u64::MAX / 2,
        }),
        &keys.encoding,
    )
    .expect("token");

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_from_another_issuer_is_rejected() {
    let (app, keys) = authenticated_app().await;

    let token = encode(
        &header(&keys),
        &json!({
            "iss": "https://evil.test/oidc",
            "aud": AUDIENCE,
            "tenant_id": "acme",
            "scope": "zt:tenant",
            "exp": u64::MAX / 2,
        }),
        &keys.encoding,
    )
    .expect("token");

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_expired_token_is_rejected() {
    let (app, keys) = authenticated_app().await;

    let token = encode(
        &header(&keys),
        &json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "tenant_id": "acme",
            "scope": "zt:tenant",
            "exp": 1_000_000,
            "iat": 999_000,
        }),
        &keys.encoding,
    )
    .expect("token");

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_signed_by_another_key_is_rejected() {
    let (app, _) = authenticated_app().await;

    // A different key, whose public half is not in the JWKS.
    let other = include_str!("../tests/data/other-key.pem");
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let token = encode(
        &header,
        &json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "tenant_id": "acme",
            "scope": "zt:tenant",
            "exp": u64::MAX / 2,
        }),
        &EncodingKey::from_rsa_pem(other.as_bytes()).expect("key"),
    )
    .expect("token");

    let response = app
        .oneshot(authorized("/api/v1/t/acme/networks", &token))
        .await
        .unwrap();
    assert_eq!(status_of(response).await, StatusCode::UNAUTHORIZED);
}

/// The unused import guard.
#[allow(dead_code)]
fn _unused(_: HashMap<String, String>) {}
