//! The status a node shows.
//!
//! A node holds a credential from the moment it enrols, but it is not
//! part of the mesh until it talks to the controller. The console shows
//! that difference, so the status has to follow what the node is actually
//! doing.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;
use zt_controller::model::NodeKeys;
use zt_controller::{Actor, Controller, Deployment, SqliteStore, Store, TenantLimits};
use zt_crypto::credential::ControllerIdentity;
use zt_crypto::identity::Identity;

/// A post-quantum public key for a test node.
fn pq_public_key() -> Vec<u8> {
    vec![7u8; 1952]
}

/// A controller with a store, so the state can be edited between calls.
struct Fixture {
    controller: Controller,
    store: std::sync::Arc<SqliteStore>,
    tenant: String,
    network: String,
}

async fn fixture() -> Fixture {
    let identity = ControllerIdentity::new(Identity::generate().expect("identity"));
    let store = std::sync::Arc::new(SqliteStore::open_in_memory().expect("store"));
    let controller = Controller::with_store(identity, store.clone()).expect("controller");

    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            Deployment::Shared,
            "team".into(),
            TenantLimits::default(),
            &Actor::system(),
        )
        .await
        .expect("tenant");

    let network = controller
        .create_network(
            &tenant.id,
            "Production".into(),
            String::new(),
            "10.42.0.0/24".into(),
            None,
            &Actor::system(),
        )
        .await
        .expect("network");

    Fixture {
        controller,
        store,
        tenant: tenant.id,
        network: network.id,
    }
}

impl Fixture {
    /// Enrol a node.
    async fn enroll(&self, name: &str) -> zt_controller::model::Node {
        self.try_enroll(name).await.expect("enrol")
    }

    /// Enrol a node, and report the failure rather than panicking.
    async fn try_enroll(
        &self,
        name: &str,
    ) -> Result<zt_controller::model::Node, zt_controller::ControllerError> {
        let (node, _) = self
            .controller
            .enroll_node(
                &self.tenant,
                &self.network,
                name.into(),
                NodeKeys {
                    ed25519: [1u8; 32],
                    ml_dsa: pq_public_key(),
                },
                Vec::new(),
                &Actor::system(),
            )
            .await?;

        Ok(node)
    }

    /// The status the console would show for a node.
    async fn status(&self, id: &str) -> String {
        let nodes = self.controller.list_nodes(&self.tenant, None).await;
        let node = nodes.iter().find(|node| node.id == id).expect("node");
        format!("{:?}", node.status).to_lowercase()
    }

    /// Move a node's last sighting into the past.
    ///
    /// The controller keeps the state in memory, so the store is edited
    /// and the controller is started again over it.
    fn stale(&self, id: &str, seconds_ago: u64) -> Controller {
        let mut state = self.store.load().expect("state");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();

        state.nodes.get_mut(id).expect("node").last_seen = Some(now.saturating_sub(seconds_ago));

        self.store.save(&state).expect("save");

        let identity = ControllerIdentity::new(Identity::generate().expect("identity"));
        Controller::with_store(identity, self.store.clone()).expect("controller")
    }
}

#[tokio::test]
async fn a_node_that_has_never_checked_in_is_pending() {
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    assert_eq!(fixture.status(&node.id).await, "pending");
}

#[tokio::test]
async fn a_node_that_reports_its_presence_is_online() {
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    fixture
        .controller
        .report_presence(&fixture.tenant, &node.id, "198.51.100.7:9994", "")
        .await
        .expect("report");

    assert_eq!(fixture.status(&node.id).await, "online");
}

#[tokio::test]
async fn a_node_that_has_gone_quiet_is_offline() {
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    fixture
        .controller
        .report_presence(&fixture.tenant, &node.id, "198.51.100.7:9994", "")
        .await
        .expect("report");

    assert_eq!(fixture.status(&node.id).await, "online");

    // The node stops talking to the controller.
    let restarted = fixture.stale(&node.id, 600);

    let nodes = restarted.list_nodes(&fixture.tenant, None).await;
    let node = nodes.iter().find(|node| node.id == node.id).expect("node");
    assert_eq!(format!("{:?}", node.status).to_lowercase(), "offline");
}

#[tokio::test]
async fn a_revoked_node_stays_revoked_however_recently_it_was_seen() {
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    fixture
        .controller
        .report_presence(&fixture.tenant, &node.id, "198.51.100.7:9994", "")
        .await
        .expect("report");

    fixture
        .controller
        .revoke_node(&fixture.tenant, &node.id, &Actor::system())
        .await
        .expect("revoke");

    assert_eq!(fixture.status(&node.id).await, "revoked");
}

#[tokio::test]
async fn a_renewal_is_a_check_in() {
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    assert_eq!(fixture.status(&node.id).await, "pending");

    fixture
        .controller
        .renew_node_credential(&fixture.tenant, &node.id, &Actor::system())
        .await
        .expect("renew");

    assert_eq!(fixture.status(&node.id).await, "online");
}

#[tokio::test]
async fn a_revoked_nodes_name_can_be_used_again() {
    // A host that is rebuilt comes back with the same name, so a revoked
    // node's name has to be free again.
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    fixture
        .controller
        .revoke_node(&fixture.tenant, &node.id, &Actor::system())
        .await
        .expect("revoke");

    let again = fixture.enroll("web-01").await;
    assert_ne!(again.id, node.id);
    assert_eq!(again.ipv4_address, "10.42.0.2");
}

#[tokio::test]
async fn a_live_nodes_name_cannot_be_used_again() {
    let fixture = fixture().await;
    fixture.enroll("web-01").await;

    let conflict = fixture.try_enroll("web-01").await;
    assert!(conflict.is_err(), "the name should be taken");
}

#[tokio::test]
async fn the_api_reports_the_same_status() {
    let fixture = fixture().await;
    let node = fixture.enroll("web-01").await;

    let app = zt_controller::router(fixture.controller.clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{}/nodes", fixture.tenant))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    assert_eq!(body["items"][0]["status"], json!("pending"));

    fixture
        .controller
        .report_presence(&fixture.tenant, &node.id, "198.51.100.7:9994", "")
        .await
        .expect("report");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{}/nodes", fixture.tenant))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    assert_eq!(body["items"][0]["status"], json!("online"));
}
