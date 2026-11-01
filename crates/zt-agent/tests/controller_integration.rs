//! Integration tests between the node agent and a real controller.
//!
//! These tests start the controller on a real loopback port and drive the
//! agent through it over HTTP, because the agent's whole job is to talk to
//! a controller. In-process router tests would not exercise the HTTP
//! client at all.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use zt_agent::{Agent, AgentConfig, ControllerClient};
use zt_controller::{router, Controller, IdentityStore, SqliteStore};

/// A controller running on a loopback port for the duration of a test.
struct TestController {
    address: SocketAddr,
    _data_dir: tempfile::TempDir,
}

impl TestController {
    async fn start() -> TestController {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let identity_path = data_dir.path().join("controller.key");
        let database_path = data_dir.path().join("controller.db");

        let identity = IdentityStore::new(&identity_path).load_or_create().expect("identity");
        let store = Arc::new(SqliteStore::open(&database_path).expect("store"));
        let controller = Controller::with_store(identity, store).expect("controller");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let app = router(controller);
            let _ = axum::serve(listener, app).await;
        });

        // Wait for the listener to accept a connection, so the test does not
        // race the server's startup.
        for _ in 0..100 {
            match tokio::net::TcpStream::connect(address).await {
                Ok(stream) => {
                    drop(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }

        TestController {
            address,
            _data_dir: data_dir,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

/// Create a tenant and a network, returning the network's ID.
async fn seed(controller: &TestController) -> String {
    let client = ControllerClient::new(controller.url(), "");

    let response = client
        .post::<serde_json::Value>(
            &format!("{}/api/v1/tenants", controller.url()),
            &serde_json::json!({
                "name": "Agent Test",
                "slug": "agent-test",
                "deployment": "shared",
            }),
        )
        .expect("create tenant");

    let tenant_id = response["id"].as_str().expect("tenant id").to_string();

    let response = client
        .post::<serde_json::Value>(
            &format!("{}/api/v1/t/{tenant_id}/networks", controller.url()),
            &serde_json::json!({
                "name": "Agent Net",
                "cidr": "10.77.0.0/24",
            }),
        )
        .expect("create network");

    response["id"].as_str().expect("network id").to_string()
}

/// The current Unix time in seconds.
fn current_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Build an agent config pointed at the test controller.
fn config(controller: &TestController, state_path: PathBuf) -> AgentConfig {
    AgentConfig {
        controller_url: controller.url(),
        tenant: "agent-test".to_string(),
        network_id: String::new(),
        state_path,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_enrolls_and_stores_a_valid_credential() {
    let controller = TestController::start().await;
    let network_id = seed(&controller).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("node.json");

    let mut config = config(&controller, state_path.clone());
    config.network_id = network_id.clone();

    let mut agent = Agent::open(config.clone()).expect("open");
    let response = agent.enroll("web-01", &["web".to_string()]).expect("enroll");

    assert_eq!(response.node.name, "web-01");
    assert!(!response.credential.is_empty());
    assert!(response.credential_not_after > 0);

    // The credential must be stored on disk, and it must validate against
    // the controller key the agent pinned on first run.
    let state = agent.state();
    assert_eq!(state.node_id, response.node.id);
    assert_eq!(state.network_id, network_id);
    assert!(!state.controller_key.is_empty());

    let credential = state.credential().expect("credential parses");
    let identity = state.identity().expect("identity");
    assert_eq!(credential.public_key(), &identity.public_key_bytes());

    // A second agent reading the same file sees the same identity.
    let reopened = Agent::open(config).expect("reopen");
    assert_eq!(
        reopened.state().public_key_hex().expect("key"),
        state.public_key_hex().expect("key")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_renews_an_expiring_credential() {
    let controller = TestController::start().await;
    let network_id = seed(&controller).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("node.json");

    let mut config = config(&controller, state_path);
    config.network_id = network_id;

    let mut agent = Agent::open(config).expect("open");
    agent.enroll("web-01", &[]).expect("enroll");

    let original = agent.state().credential_not_after;

    // A fresh credential is not due for renewal.
    let now = current_unix();
    assert!(agent.renew_if_due(now).expect("renew check").is_none());

    // Forcing a renewal reaches the controller and replaces the credential.
    let renewed = agent
        .client()
        .renew_credential(&agent.state().node_id.clone())
        .expect("renew");
    assert!(renewed.credential_not_after >= original);
    assert_ne!(renewed.credential, agent.state().credential);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_rejects_a_credential_from_an_untrusted_controller() {
    let controller = TestController::start().await;
    let network_id = seed(&controller).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("node.json");

    let mut config = config(&controller, state_path);
    config.network_id = network_id;

    let mut agent = Agent::open(config).expect("open");
    agent.enroll("web-01", &[]).expect("enroll");

    let trusted_credential = agent.state().credential().expect("credential");

    let now = current_unix();

    // A credential issued by a different controller must not verify against
    // the pinned trust anchor.
    let rogue = zt_crypto::credential::ControllerIdentity::new(
        zt_crypto::identity::Identity::generate().expect("identity"),
    );
    let identity = agent.state().identity().expect("identity");
    let node_key = identity.public_key_bytes();
    let rogue_credential = rogue.issue(
        42,
        zt_crypto::identity::Address::derive(42, &node_key),
        &node_key,
        now,
        3600,
        &[0u8; 16],
    );

    assert!(agent
        .verify_peer_credential(&rogue_credential, now)
        .is_err());

    // The genuine credential must verify.
    agent
        .verify_peer_credential(&trusted_credential, now)
        .expect("genuine credential verifies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_cannot_enroll_into_another_tenants_network() {
    let controller = TestController::start().await;
    let network_id = seed(&controller).await;

    let dir = tempfile::tempdir().expect("tempdir");

    // A second tenant that does not own the network.
    let client = ControllerClient::new(controller.url(), "");
    client
        .post::<serde_json::Value>(
            &format!("{}/api/v1/tenants", controller.url()),
            &serde_json::json!({
                "name": "Other",
                "slug": "other",
                "deployment": "shared",
            }),
        )
        .expect("create tenant");

    let mut config = config(&controller, dir.path().join("node.json"));
    config.tenant = "other".to_string();
    config.network_id = network_id;

    let mut agent = Agent::open(config).expect("open");
    let result = agent.enroll("intruder", &[]);

    // The controller must refuse. Cross-tenant enrollment is not possible.
    assert!(result.is_err(), "enrollment into another tenant must fail");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_slug_resolves_to_the_tenant_id() {
    let controller = TestController::start().await;
    seed(&controller).await;
    let client = ControllerClient::new(controller.url(), "");

    let resolved = client.resolve_tenant("agent-test").expect("resolve");
    assert_eq!(resolved.len(), 36);
    assert!(resolved.contains('-'));

    // An unknown tenant is an error, not a silent fallback.
    assert!(client.resolve_tenant("no-such-tenant").is_err());
}
