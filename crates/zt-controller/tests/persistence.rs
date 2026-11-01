//! Tests for controller persistence and tenant isolation.

use std::sync::Arc;

use zt_controller::{Controller, Deployment, IdentityStore, SqliteStore, TenantLimits};
use zt_crypto::credential::ControllerIdentity;
use zt_crypto::identity::Identity;

fn identity() -> ControllerIdentity {
    ControllerIdentity::new(Identity::generate().expect("identity"))
}

async fn tenant(controller: &Controller, name: &str) -> String {
    controller
        .create_tenant(
            name.into(),
            name.to_lowercase(),
            Deployment::Shared,
            "starter".into(),
            TenantLimits::default(),
        )
        .await
        .expect("tenant")
        .id
}

#[tokio::test]
async fn sqlite_store_round_trips_controller_state() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    let controller = Controller::with_store(identity(), store.clone()).expect("controller");

    let tenant_id = tenant(&controller, "Acme").await;

    let network = controller
        .create_network(
            &tenant_id,
            "Production".into(),
            "Core services".into(),
            "10.42.0.0/24".into(),
            Some(3600),
        )
        .await
        .expect("network");

    let node_public_key = [7u8; 32];
    let (node, _) = controller
        .enroll_node(
            &tenant_id,
            &network.id,
            "web-01".into(),
            node_public_key,
            vec!["web".into()],
        )
        .await
        .expect("node");

    controller
        .create_policy(
            &tenant_id,
            zt_controller::Policy {
                id: String::new(),
                tenant_id: String::new(),
                network_id: network.id.clone(),
                name: "Web to database".into(),
                description: String::new(),
                protocol: zt_controller::Protocol::Tcp,
                port: zt_controller::PortSpec::Single(5432),
                source: zt_controller::Selector::Tag { tag: "web".into() },
                destination: zt_controller::Selector::Tag {
                    tag: "database".into(),
                },
                enabled: true,
                created_at: 0,
                updated_at: 0,
            },
        )
        .await
        .expect("policy");

    controller
        .create_relay(
            &tenant_id,
            zt_controller::Relay {
                id: String::new(),
                tenant_id: String::new(),
                name: "relay-ams".into(),
                node_id: "10.42.0.2/24".into(),
                endpoint: "198.51.100.2:9994".into(),
                networks: vec![network.id.clone()],
                enabled: true,
                status: zt_controller::RelayStatus::Healthy,
                created_at: 0,
                updated_at: 0,
            },
        )
        .await
        .expect("relay");

    // Reload from the same store with a fresh controller instance.
    let reloaded = Controller::with_store(identity(), store).expect("reload");

    let networks = reloaded.list_networks(&tenant_id).await;
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].name, "Production");
    assert_eq!(networks[0].cidr, "10.42.0.0/24");
    assert_eq!(networks[0].credential_ttl_secs, 3600);

    let nodes = reloaded.list_nodes(&tenant_id, Some(&network.id)).await;
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "web-01");
    assert_eq!(nodes[0].address, node.address);
    assert_eq!(nodes[0].tags, vec!["web".to_string()]);
    assert_eq!(nodes[0].status, zt_controller::NodeStatus::Pending);

    let policies = reloaded.list_policies(&tenant_id, Some(&network.id)).await;
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "Web to database");
    assert_eq!(policies[0].port, zt_controller::PortSpec::Single(5432));

    let relays = reloaded.list_relays(&tenant_id).await;
    assert_eq!(relays.len(), 1);
    assert_eq!(relays[0].name, "relay-ams");

    let events = reloaded.list_events(Some(&tenant_id)).await;
    // Tenant creation, network creation, enrollment, policy, relay.
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].action, "tenant.created");
    assert_eq!(events[1].action, "network.created");
}

#[tokio::test]
async fn node_status_survives_reload() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    let controller = Controller::with_store(identity(), store.clone()).expect("controller");
    let tenant_id = tenant(&controller, "Acme").await;

    let network = controller
        .create_network(
            &tenant_id,
            "Net".into(),
            String::new(),
            "10.0.0.0/24".into(),
            None,
        )
        .await
        .expect("network");
    let (node, _) = controller
        .enroll_node(&tenant_id, &network.id, "node-1".into(), [1u8; 32], vec![])
        .await
        .expect("node");
    controller
        .revoke_node(&tenant_id, &node.id)
        .await
        .expect("revoke");

    let reloaded = Controller::with_store(identity(), store).expect("reload");
    let nodes = reloaded.list_nodes(&tenant_id, None).await;
    assert_eq!(nodes[0].status, zt_controller::NodeStatus::Revoked);
}

#[tokio::test]
async fn deleting_network_removes_scoped_objects() {
    let store = Arc::new(SqliteStore::open_in_memory().expect("store"));
    let controller = Controller::with_store(identity(), store.clone()).expect("controller");
    let tenant_id = tenant(&controller, "Acme").await;

    let network = controller
        .create_network(
            &tenant_id,
            "Net".into(),
            String::new(),
            "10.0.0.0/24".into(),
            None,
        )
        .await
        .expect("network");
    controller
        .enroll_node(&tenant_id, &network.id, "node-1".into(), [1u8; 32], vec![])
        .await
        .expect("node");

    controller
        .delete_network(&tenant_id, &network.id)
        .await
        .expect("delete");

    let reloaded = Controller::with_store(identity(), store).expect("reload");
    assert!(reloaded.list_networks(&tenant_id).await.is_empty());
    assert!(reloaded.list_nodes(&tenant_id, None).await.is_empty());
}

#[tokio::test]
async fn identity_store_round_trips_the_signing_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("controller.key");

    let store = zt_controller::IdentityStore::new(&path);
    let identity = store.load_or_create().expect("create");
    assert!(path.exists());

    let loaded = store.load().expect("load");
    assert_eq!(loaded.public_key(), identity.public_key());
    assert_eq!(loaded.controller_id(), identity.controller_id());

    // A second load must not rotate the key.
    let again = store.load_or_create().expect("reload");
    assert_eq!(again.public_key(), identity.public_key());
}

#[cfg(unix)]
#[tokio::test]
async fn identity_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("controller.key");
    let store = zt_controller::IdentityStore::new(&path);
    store.load_or_create().expect("create");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn state_survives_a_restart_using_the_same_database_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = dir.path().join("controller.db");
    let identity_path = dir.path().join("controller.key");

    // First "process": create the identity, a tenant, and a network.
    let identity = IdentityStore::new(&identity_path)
        .load_or_create()
        .expect("identity");
    let controller_key = identity.public_key();
    let controller = Controller::with_store(
        identity,
        Arc::new(SqliteStore::open(&database).expect("store")),
    )
    .expect("controller");
    let tenant_id = tenant(&controller, "Acme").await;
    controller
        .create_network(
            &tenant_id,
            "Production".into(),
            "Core services".into(),
            "10.42.0.0/24".into(),
            None,
        )
        .await
        .expect("network");
    controller
        .enroll_node(
            &tenant_id,
            "",
            "web-01".into(),
            [4u8; 32],
            vec!["web".into()],
        )
        .await
        .ok();

    // Second "process": reopen the same files.
    let identity = IdentityStore::new(&identity_path).load().expect("identity");
    assert_eq!(identity.public_key(), controller_key);
    let controller = Controller::with_store(
        identity,
        Arc::new(SqliteStore::open(&database).expect("store")),
    )
    .expect("controller");

    assert_eq!(controller.list_tenants().await.len(), 1);
    assert_eq!(controller.list_networks(&tenant_id).await.len(), 1);
}

#[tokio::test]
async fn migrating_an_existing_database_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = dir.path().join("controller.db");

    {
        let store = SqliteStore::open(&database).expect("store");
        let controller = Controller::with_store(identity(), Arc::new(store)).expect("controller");
        let tenant_id = tenant(&controller, "Acme").await;
        controller
            .create_network(
                &tenant_id,
                "Net".into(),
                String::new(),
                "10.0.0.0/24".into(),
                None,
            )
            .await
            .expect("network");
    }

    // Reopening runs migrations again; it must not fail or lose data.
    let store = SqliteStore::open(&database).expect("reopen");
    let controller = Controller::with_store(identity(), Arc::new(store)).expect("controller");
    assert_eq!(controller.list_tenants().await.len(), 1);
}
