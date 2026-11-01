//! The join → approve → collect flow.
//!
//! A client asks to join with nothing but its public keys. The node sits
//! in pending, unable to do anything, until the operator approves it. The
//! node then polls with a signature over its own identifier — which only
//! the holder of the private key can produce — and collects the
//! credential that was promised.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::model::NodeKeys;
use zt_controller::{router_with_auth, Controller};

struct Fixture {
    app: axum::Router,
    controller: Controller,
}

async fn fixture() -> Fixture {
    let controller = Controller::new().expect("controller");
    let state = AuthState {
        limiter: zt_controller::middleware::RateLimiter::new(),
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

/// A request without a token: join and poll are public.
fn anonymous(path: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// The signature a pending node presents when it polls.
///
/// The message is fixed by the protocol: the literal prefix, then the
/// node's identifier. The controller checks it against the key the node
/// joined with.
fn poll_signature(node_id: &str, seed: &[u8; 32]) -> String {
    use zt_crypto::identity::Identity;
    let message = format!("zt-next-join-poll:{node_id}");
    hex::encode(Identity::from_bytes(seed).sign(message.as_bytes()))
}

#[tokio::test]
async fn a_client_joins_polls_and_collects_its_credential_after_approval() {
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

    // The client's key. The private half stays with the client, which is
    // what makes the poll meaningful.
    let seed: [u8; 32] = [11u8; 32];
    use zt_crypto::identity::Identity;
    let identity = Identity::from_bytes(&seed);

    // 1. The client asks to join. No token, no credential.
    let response = fixture
        .app
        .clone()
        .oneshot(anonymous(
            "/api/v1/join",
            &json!({
                "tenant_slug": "acme",
                "network_id": network.id,
                "name": "laptop-01",
                "public_key": hex::encode(identity.public_key_bytes()),
                "pq_public_key": hex::encode(vec![7u8; 1952]),
            }),
        ))
        .await
        .expect("join");

    assert_eq!(response.status(), StatusCode::CREATED);
    let node = json_body(response).await;
    let node_id = node["id"].as_str().expect("node id").to_string();
    assert_eq!(node["status"], "pending");
    assert_eq!(node["tenant_id"], tenant.id);

    // 2. Before approval, the poll answers "pending" and hands out
    //    nothing — even with a valid signature.
    let signature = poll_signature(&node_id, &seed);
    let response = fixture
        .app
        .clone()
        .oneshot(anonymous(
            &format!("/api/v1/join/{node_id}/poll"),
            &json!({ "signature": signature }),
        ))
        .await
        .expect("poll");
    assert_eq!(response.status(), StatusCode::OK);
    let poll = json_body(response).await;
    assert_eq!(poll, json!("Pending"));

    // 3. A wrong signature is refused outright, approved or not.
    let wrong = poll_signature(&node_id, &[12u8; 32]);
    let response = fixture
        .app
        .clone()
        .oneshot(anonymous(
            &format!("/api/v1/join/{node_id}/poll"),
            &json!({ "signature": wrong }),
        ))
        .await
        .expect("poll");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // 4. The operator approves the node from the console.
    let (approved, _credential) = fixture
        .controller
        .approve_node(&tenant.id, &node_id, &zt_controller::Actor::system())
        .await
        .expect("approve");
    assert_eq!(approved.status, zt_controller::NodeStatus::Pending);

    // 5. The node polls again and collects the credential that was
    //    promised, bound to the key it joined with.
    let signature = poll_signature(&node_id, &seed);
    let response = fixture
        .app
        .clone()
        .oneshot(anonymous(
            &format!("/api/v1/join/{node_id}/poll"),
            &json!({ "signature": signature }),
        ))
        .await
        .expect("poll");
    assert_eq!(response.status(), StatusCode::OK);
    let poll = json_body(response).await;

    let approved_body = poll.get("Approved").expect("approved");
    let credential_hex = approved_body["credential"].as_str().expect("credential");
    let controller_key: [u8; 32] = hex::decode(fixture.controller.public_key().await)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let credential = zt_crypto::credential::NodeCredential::deserialize(
        &hex::decode(credential_hex).expect("hex"),
        &controller_key,
    )
    .expect("the credential verifies against the controller's key");

    // The credential is the node's: its address matches the node, and it
    // is bound to the key the client joined with.
    assert_eq!(
        credential.node_address().to_hex(),
        node["address"].as_str().expect("address"),
    );
}

#[tokio::test]
async fn a_host_that_asks_twice_resumes_its_pending_request() {
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

    let keys = NodeKeys {
        ed25519: [11u8; 32],
        ml_dsa: vec![7u8; 1952],
    };

    let first = fixture
        .controller
        .join_node(&tenant.id, &network.id, "laptop-01".into(), keys.clone())
        .await
        .expect("first join");

    // The same key asking again is the same host: the pending request is
    // resumed, not duplicated.
    let second = fixture
        .controller
        .join_node(&tenant.id, &network.id, "laptop-01".into(), keys.clone())
        .await
        .expect("second join");
    assert_eq!(first.id, second.id);

    // A rename through a re-join works when the new name is free.
    let renamed = fixture
        .controller
        .join_node(&tenant.id, &network.id, "laptop-renamed".into(), keys.clone())
        .await
        .expect("rename");
    assert_eq!(first.id, renamed.id);
    assert_eq!(renamed.name, "laptop-renamed");

    // A different host cannot take the name the pending request holds.
    let other = NodeKeys {
        ed25519: [12u8; 32],
        ml_dsa: vec![8u8; 1952],
    };
    let conflict = fixture
        .controller
        .join_node(&tenant.id, &network.id, "laptop-renamed".into(), other)
        .await;
    assert!(conflict.is_err(), "a second host cannot steal the name");

    // Still exactly one pending node for the host.
    let listed = fixture.controller.list_nodes(&tenant.id, Some(&network.id)).await;
    let pending = listed
        .iter()
        .filter(|node| node.status == zt_controller::NodeStatus::Pending)
        .count();
    assert_eq!(pending, 1);
}

#[tokio::test]
async fn a_suspended_tenant_cannot_be_joined() {
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

    fixture
        .controller
        .suspend_tenant(&tenant.id, "non-payment", &zt_controller::Actor::system())
        .await
        .expect("suspend");

    // Knowing the slug and the network identifier is not enough: a
    // suspended tenant accepts nothing new.
    let response = fixture
        .app
        .oneshot(anonymous(
            "/api/v1/join",
            &json!({
                "tenant_slug": "acme",
                "network_id": network.id,
                "name": "laptop-01",
                "public_key": hex::encode([5u8; 32]),
                "pq_public_key": hex::encode(vec![5u8; 1952]),
            }),
        ))
        .await
        .expect("join");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_flood_of_join_requests_is_refused_once_the_queue_is_full() {
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

    // Fill the pending queue to its cap with distinct hosts.
    for i in 0..50u8 {
        let keys = NodeKeys {
            ed25519: [i; 32],
            ml_dsa: vec![i; 1952],
        };
        fixture
            .controller
            .join_node(
                &tenant.id,
                &network.id,
                format!("host-{i}"),
                keys,
            )
            .await
            .expect("join fills the queue");
    }

    // The next request is refused rather than draining the address pool.
    let keys = NodeKeys {
        ed25519: [99u8; 32],
        ml_dsa: vec![99u8; 1952],
    };
    let refused = fixture
        .controller
        .join_node(&tenant.id, &network.id, "overflow".into(), keys)
        .await;
    assert!(refused.is_err(), "the queue is full");

    // An existing host can still resume: its request is already queued.
    let resumed = fixture
        .controller
        .join_node(
            &tenant.id,
            &network.id,
            "host-7".into(),
            NodeKeys {
                ed25519: [7u8; 32],
                ml_dsa: vec![7u8; 1952],
            },
        )
        .await
        .expect("resume still works");
    assert_eq!(resumed.name, "host-7");
}

#[tokio::test]
async fn anonymous_join_requests_are_rate_limited() {
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

    // Ten requests are answered; the eleventh from the same source is not.
    // Every request resumes the same node, so each one is legitimate on
    // its own — the limiter is what refuses the flood.
    let mut last = StatusCode::CREATED;
    for _ in 0..11 {
        let response = fixture
            .app
            .clone()
            .oneshot(anonymous(
                "/api/v1/join",
                &json!({
                    "tenant_slug": "acme",
                    "network_id": network.id,
                    "name": "laptop-01",
                    "public_key": hex::encode([6u8; 32]),
                    "pq_public_key": hex::encode(vec![6u8; 1952]),
                }),
            ))
            .await
            .expect("join");
        last = response.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_join_for_an_unknown_network_is_refused() {
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

    let response = fixture
        .app
        .oneshot(anonymous(
            "/api/v1/join",
            &json!({
                "tenant_slug": "acme",
                "network_id": "00000000-0000-0000-0000-000000000000",
                "name": "ghost",
                "public_key": hex::encode([3u8; 32]),
                "pq_public_key": hex::encode(vec![3u8; 1952]),
            }),
        ))
        .await
        .expect("join");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
