//! Metering, and what a tenant owes.
//!
//! A tenant is charged for the nodes it ran and the traffic it carried.
//! The bytes come from the nodes themselves; the node-hours are the
//! integral of the node count over the period.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::model::NodeKeys;
use zt_controller::service::NodeUsage;
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

/// A tenant with a network and a node, and the node's credential.
async fn tenant_with_node(fixture: &Fixture) -> (String, String, String) {
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
                ml_dsa: vec![9u8; 1952],
            },
            Vec::new(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("enrol");

    (tenant.id, node.id, hex::encode(credential.serialize()))
}

#[tokio::test]
async fn what_a_node_carried_is_recorded() {
    let fixture = fixture().await;
    let (tenant, node, _) = tenant_with_node(&fixture).await;

    fixture
        .controller
        .report_presence(
            &tenant,
            &node,
            "198.51.100.7:9994",
            "",
            NodeUsage {
                bytes_in: 1_000,
                bytes_out: 4_000,
                packets: 50,
            },
        )
        .await
        .expect("report");

    let summary = fixture.controller.usage_summary(&tenant, now_unix()).await;

    assert_eq!(summary.bytes_in, 1_000);
    assert_eq!(summary.bytes_out, 4_000);
    assert_eq!(summary.packets, 50);
    assert_eq!(summary.samples, 1);
    assert_eq!(summary.period_end - summary.period_start, 30 * 86_400);
}

#[tokio::test]
async fn an_invoice_is_the_usage_times_the_rates() {
    let fixture = fixture().await;
    let (tenant, node, _) = tenant_with_node(&fixture).await;

    fixture
        .controller
        .report_presence(
            &tenant,
            &node,
            "198.51.100.7:9994",
            "",
            NodeUsage {
                bytes_in: 0,
                bytes_out: 2_500_000_000,
                packets: 10,
            },
        )
        .await
        .expect("report");

    let invoice = fixture
        .controller
        .invoice(&tenant, now_unix())
        .await
        .expect("invoice");

    // Two and a half gigabytes is charged as three.
    assert_eq!(invoice.usage.total_bytes(), 2_500_000_000);
    assert_eq!(invoice.gigabyte_cents * 3, invoice.traffic_charges_cents);
    assert_eq!(
        invoice.total_cents,
        invoice.node_charges_cents + invoice.traffic_charges_cents
    );
    assert!(!invoice.currency.is_empty());
}

#[tokio::test]
async fn a_tenant_may_only_see_its_own_invoice() {
    let fixture = fixture().await;
    let (tenant, _, credential) = tenant_with_node(&fixture).await;

    let other = fixture
        .controller
        .create_tenant(
            "Other".into(),
            "other".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::system(),
        )
        .await
        .expect("tenant");

    // The node's own tenant may ask.
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{tenant}/billing"),
            "GET",
            &credential,
            None,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["tenant_id"], json!(tenant.as_str()));
    assert!(body["total_cents"].as_u64().is_some());

    // Another tenant may not.
    let response = fixture
        .app
        .clone()
        .oneshot(with_token(
            &format!("/api/v1/t/{}/billing", other.id),
            "GET",
            &credential,
            None,
        ))
        .await
        .expect("response");
    assert!(
        !response.status().is_success(),
        "another tenant's invoice must not be visible"
    );
}

/// The current Unix time in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
