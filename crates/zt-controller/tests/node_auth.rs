//! Node authentication with a credential.
//!
//! A node holds no secret. Its credential is signed by the controller and
//! bound to the node's own public key, so presenting it proves both that
//! the node is enrolled and that it is the node it claims to be.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::model::NodeKeys;
use zt_controller::{router_with_auth, Controller};

/// A post-quantum public key for a test node.
fn pq_public_key() -> Vec<u8> {
    vec![7u8; 1952]
}

/// A controller with authentication enabled, and the identity state a node
/// needs to enrol.
struct Fixture {
    app: axum::Router,
    controller: Controller,
}

async fn fixture() -> Fixture {
    let controller = Controller::new().expect("controller");
    let state = AuthState {
        verifier: std::sync::Arc::new(Verifier::new(AuthConfig::new(
            "https://issuer.test",
            "https://audience.test",
            "https://issuer.test/jwks",
        ))),
        controller: controller.clone(),
        tenant_scope: "zt:tenant".into(),
        operator_scope: "zt:operator".into(),
    };

    Fixture {
        app: router_with_auth(controller.clone(), state),
        controller,
    }
}

/// A request carrying a bearer token.
fn with_token(path: &str, method: &str, token: &str, body: Option<&str>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");

    match body {
        Some(body) => builder.body(Body::from(body.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

#[tokio::test]
async fn a_node_credential_authenticates_its_owner() {
    let fixture = fixture().await;

    // Enrol a node the way the console does, with an operator token. The
    // operator token is not valid here, so the enrolment is done through
    // the service layer.
    let tenant = fixture
        .controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("tenant");

    let network = fixture
        .controller
        .create_network(
            &tenant.id,
            "Production".into(),
            String::new(),
            "10.42.0.0/24".into(),
            None,
            &zt_controller::Actor::system(),
        )
        .await
        .expect("network");

    let node_key = [7u8; 32];
    let (node, credential) = fixture
        .controller
        .enroll_node(
            &tenant.id,
            &network.id,
            "web-01".into(),
            NodeKeys {
                ed25519: node_key,
                ml_dsa: pq_public_key(),
            },
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    // The node authenticates with the credential the controller issued it.
    let token = hex::encode(credential.serialize());
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{}/nodes", tenant.id),
            "GET",
            &token,
            None,
        ))
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the node's own credential must authenticate it"
    );

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(body["items"][0]["name"], json!("web-01"));
    assert_eq!(body["items"][0]["id"], json!(node.id));
}

#[tokio::test]
async fn a_node_credential_cannot_reach_the_master_console() {
    let fixture = fixture().await;

    let tenant = fixture
        .controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("tenant");

    let network = fixture
        .controller
        .create_network(
            &tenant.id,
            "Production".into(),
            String::new(),
            "10.42.0.0/24".into(),
            None,
            &zt_controller::Actor::system(),
        )
        .await
        .expect("network");

    let (_, credential) = fixture
        .controller
        .enroll_node(
            &tenant.id,
            &network.id,
            "web-01".into(),
            NodeKeys {
                ed25519: [7u8; 32],
                ml_dsa: pq_public_key(),
            },
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    let token = hex::encode(credential.serialize());
    let response = fixture
        .app
        .clone()
        .oneshot(with_token("/api/v1/tenants", "GET", &token, None))
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a node must not reach the master console"
    );
}

#[tokio::test]
async fn a_node_credential_cannot_reach_another_tenant() {
    let fixture = fixture().await;

    let first = fixture
        .controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("tenant");

    let second = fixture
        .controller
        .create_tenant(
            "Globex".into(),
            "globex".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("tenant");

    let network = fixture
        .controller
        .create_network(
            &first.id,
            "Production".into(),
            String::new(),
            "10.42.0.0/24".into(),
            None,
            &zt_controller::Actor::system(),
        )
        .await
        .expect("network");

    let (_, credential) = fixture
        .controller
        .enroll_node(
            &first.id,
            &network.id,
            "web-01".into(),
            NodeKeys {
                ed25519: [7u8; 32],
                ml_dsa: pq_public_key(),
            },
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    let token = hex::encode(credential.serialize());
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{}/networks", second.id),
            "GET",
            &token,
            None,
        ))
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a node must not reach another tenant"
    );
}

#[tokio::test]
async fn a_credential_for_an_unknown_node_is_refused() {
    let fixture = fixture().await;

    // A credential signed by another controller does not verify here.
    let other = zt_crypto::credential::ControllerIdentity::new(
        zt_crypto::identity::Identity::generate().expect("identity"),
    );
    let key = [9u8; 32];
    let credential = other.issue(
        42,
        zt_crypto::identity::Address::derive(42, &key),
        &key,
        1_800_000_000,
        3600,
        &[0u8; 16],
    );

    let token = hex::encode(credential.serialize());
    let response = fixture
        .app
        .clone()
        .oneshot(with_token("/api/v1/t/acme/nodes", "GET", &token, None))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_garbage_credential_is_refused() {
    let fixture = fixture().await;

    for token in ["not-hex", "", "abcd", "00"] {
        let response = fixture
            .app
            .clone()
            .oneshot(with_token("/api/v1/t/acme/nodes", "GET", token, None))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the token {token:?} must be refused"
        );
    }
}

#[tokio::test]
async fn a_node_asks_the_controller_who_it_is() {
    let fixture = fixture().await;

    let tenant = fixture
        .controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("tenant");

    let network = fixture
        .controller
        .create_network(
            &tenant.id,
            "Production".into(),
            String::new(),
            "10.42.0.0/24".into(),
            None,
            &zt_controller::Actor::system(),
        )
        .await
        .expect("network");

    let (node, credential) = fixture
        .controller
        .enroll_node(
            &tenant.id,
            &network.id,
            "web-01".into(),
            NodeKeys {
                ed25519: [7u8; 32],
                ml_dsa: pq_public_key(),
            },
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    let token = hex::encode(credential.serialize());
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant_id}/nodes/self", tenant_id = tenant.id),
            "GET",
            &token,
            None,
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(body["id"], json!(node.id));
    assert_eq!(body["name"], json!("web-01"));
}
