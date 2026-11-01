//! The topology a node is handed.
//!
//! A node needs to know its own address in the network's range, and it
//! needs to know where its peers are. The controller hands that out, and
//! only that: a node is told about its own network and nothing else.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::{router_with_auth, Controller};

/// A controller with authentication enabled.
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

/// The body of a response, as JSON.
async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// A tenant with one network, and the ids of both.
async fn tenant_with_network(
    fixture: &Fixture,
    name: &str,
    slug: &str,
    cidr: &str,
) -> (String, String) {
    let tenant = fixture
        .controller
        .create_tenant(
            name.into(),
            slug.into(),
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
            cidr.into(),
            None,
            &zt_controller::Actor::system(),
        )
        .await
        .expect("network");

    (tenant.id, network.id)
}

/// Enrol a node and return its credential, hex encoded.
async fn enroll(
    fixture: &Fixture,
    tenant: &str,
    network: &str,
    name: &str,
    key: [u8; 32],
) -> (zt_controller::model::Node, String) {
    let (node, credential) = fixture
        .controller
        .enroll_node(
            tenant,
            network,
            name.into(),
            key,
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    (node, hex::encode(credential.serialize()))
}

#[tokio::test]
async fn nodes_in_a_network_are_given_different_addresses() {
    let fixture = fixture().await;
    let (tenant, network) = tenant_with_network(&fixture, "Acme", "acme", "10.42.0.0/24").await;

    let (first, _) = enroll(&fixture, &tenant, &network, "web-01", [1u8; 32]).await;
    let (second, _) = enroll(&fixture, &tenant, &network, "web-02", [2u8; 32]).await;

    assert_eq!(first.ipv4_address, "10.42.0.1");
    assert_eq!(second.ipv4_address, "10.42.0.2");
    assert_ne!(first.ipv4_address, second.ipv4_address);
}

#[tokio::test]
async fn a_node_is_told_its_own_address_and_its_peers() {
    let fixture = fixture().await;
    let (tenant, network) = tenant_with_network(&fixture, "Acme", "acme", "10.42.0.0/24").await;

    let (_, first_token) = enroll(&fixture, &tenant, &network, "web-01", [1u8; 32]).await;
    let (second, _) = enroll(&fixture, &tenant, &network, "web-02", [2u8; 32]).await;

    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant}/topology"),
            "GET",
            &first_token,
            None,
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;

    assert_eq!(body["address"], json!("10.42.0.1"));
    assert_eq!(body["cidr"], json!("10.42.0.0/24"));
    assert!(body["network_id"].as_u64().unwrap() > 0);

    let peers = body["peers"].as_array().expect("peers");
    assert_eq!(peers.len(), 1, "the node should see its one peer");
    assert_eq!(peers[0]["address"], json!("10.42.0.2"));
    assert_eq!(peers[0]["public_key"], json!(second.public_key));
    assert!(
        peers[0]["endpoint"].is_null(),
        "the peer has not reported an endpoint yet"
    );
}

#[tokio::test]
async fn a_node_is_told_nothing_about_another_tenant() {
    let fixture = fixture().await;
    let (tenant, network) = tenant_with_network(&fixture, "Acme", "acme", "10.42.0.0/24").await;
    let (other_tenant, other_network) =
        tenant_with_network(&fixture, "Other", "other", "10.99.0.0/24").await;

    let (_, token) = enroll(&fixture, &tenant, &network, "web-01", [1u8; 32]).await;
    enroll(
        &fixture,
        &other_tenant,
        &other_network,
        "secret-01",
        [9u8; 32],
    )
    .await;

    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant}/topology"),
            "GET",
            &token,
            None,
        ))
        .await
        .expect("response");

    let body = json_body(response).await;
    assert_eq!(body["peers"].as_array().expect("peers").len(), 0);
}

#[tokio::test]
async fn a_reported_endpoint_reaches_the_other_node() {
    let fixture = fixture().await;
    let (tenant, network) = tenant_with_network(&fixture, "Acme", "acme", "10.42.0.0/24").await;

    let (_, first_token) = enroll(&fixture, &tenant, &network, "web-01", [1u8; 32]).await;
    let (_, second_token) = enroll(&fixture, &tenant, &network, "web-02", [2u8; 32]).await;

    // The second node reports where it can be reached.
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant}/nodes/self/endpoint"),
            "POST",
            &second_token,
            Some(&json!({ "endpoint": "198.51.100.7:9994" }).to_string()),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["endpoint"], json!("198.51.100.7:9994"));

    // The first node now sees it.
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant}/topology"),
            "GET",
            &first_token,
            None,
        ))
        .await
        .expect("response");

    let body = json_body(response).await;
    let peers = body["peers"].as_array().expect("peers");
    assert_eq!(peers[0]["endpoint"], json!("198.51.100.7:9994"));
}

#[tokio::test]
async fn a_node_cannot_report_the_endpoint_of_another_node() {
    let fixture = fixture().await;
    let (tenant, network) = tenant_with_network(&fixture, "Acme", "acme", "10.42.0.0/24").await;

    let (first, first_token) = enroll(&fixture, &tenant, &network, "web-01", [1u8; 32]).await;
    let (second, _) = enroll(&fixture, &tenant, &network, "web-02", [2u8; 32]).await;

    // The route takes no node identifier, so there is nothing to point at
    // somebody else's node.
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant}/nodes/self/endpoint"),
            "POST",
            &first_token,
            Some(&json!({ "endpoint": "198.51.100.7:9994" }).to_string()),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["id"], json!(first.id));
    assert_ne!(body["id"], json!(second.id));
}
