//! End-to-end tests for the controller HTTP API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::{router, Controller};

fn app() -> axum::Router {
    router(Controller::new().expect("controller"))
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Create a tenant and return its ID.
async fn tenant(app: &axum::Router, name: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tenants")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": name,
                        "slug": name.to_lowercase(),
                        "deployment": "shared"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn network(app: &axum::Router, tenant: &str, name: &str, cidr: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/networks"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": name, "cidr": cidr }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await
}

#[tokio::test]
async fn health_reports_control_plane_state() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["tenants"], 0);
}

#[tokio::test]
async fn network_lifecycle_works() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;

    let created = network(&app, &tenant, "Production", "10.42.0.0/24").await;
    let network_id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["name"], "Production");
    assert_eq!(created["cidr"], "10.42.0.0/24");
    assert!(created["network_id"].as_u64().unwrap() > 0);
    assert_eq!(created["tenant_id"], tenant.as_str());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{tenant}/networks"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list = json_body(response).await;
    assert_eq!(list["total"], 1);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/t/{tenant}/networks/{network_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn enrolling_node_issues_verifiable_credential() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;
    let network = network(&app, &tenant, "Production", "10.42.0.0/24").await;
    let network_id = network["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/nodes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": network_id,
                        "name": "web-01",
                        "public_key": "aa".repeat(32),
                        "tags": ["production", "web"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(body["node"]["name"], "web-01");
    assert_eq!(body["node"]["status"], "pending");
    assert_eq!(body["node"]["tags"][0], "production");
    assert_eq!(body["node"]["tenant_id"], tenant.as_str());
    assert!(body["node"]["address"].as_str().unwrap().len() == 20);

    let credential_bytes = hex::decode(body["credential"].as_str().unwrap()).unwrap();
    assert_eq!(
        credential_bytes.len(),
        zt_crypto::credential::CREDENTIAL_LEN
    );
}

#[tokio::test]
async fn joining_by_request_approving_and_revoking_works_over_http() {
    let app = app();
    let tenant_id = tenant(&app, "Acme").await;
    let network = network(&app, &tenant_id, "Production", "10.42.0.0/24").await;

    // The client asks to join. No token.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/join")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "tenant_slug": "acme",
                        "network_id": network["id"],
                        "name": "laptop-01",
                        "public_key": "bb".repeat(32),
                        "pq_public_key": hex::encode(vec![7u8; 1952])
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let node = json_body(response).await;
    let node_id = node["id"].as_str().unwrap().to_string();

    // The operator approves it through the console's route.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{node_id}/approve"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let approved = json_body(response).await;
    assert_eq!(approved["id"], node["id"].as_str().unwrap());

    // The console revokes through the POST form.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{node_id}/revoke"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let revoked = json_body(response).await;
    assert_eq!(revoked["status"], "revoked");
}

#[tokio::test]
async fn rejecting_pending_revokes_junk_and_leaves_members_alone() {
    let app = app();
    let tenant_id = tenant(&app, "Acme").await;
    let network = network(&app, &tenant_id, "Production", "10.42.0.0/24").await;

    // Two hosts ask to join, and a third is enrolled the old way —
    // approved, holding a credential, a member.
    let mut pending_ids = Vec::new();
    for i in 0..2u8 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/join")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "tenant_slug": "acme",
                            "network_id": network["id"],
                            "name": format!("junk-{i}"),
                            "public_key": hex::encode([20u8 + i; 32]),
                            "pq_public_key": hex::encode(vec![20u8 + i; 1952])
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let node = json_body(response).await;
        pending_ids.push(node["id"].as_str().unwrap().to_string());
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": network["id"],
                        "name": "member-01",
                        "public_key": "cc".repeat(32)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let member = json_body(response).await;

    // One call rejects every pending request.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/reject-pending"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["rejected"], 2);

    for id in &pending_ids {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/t/{tenant_id}/nodes/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(json_body(response).await["status"], "revoked");
    }

    // The member is untouched.
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/t/{tenant_id}/nodes/{}",
                    member["node"]["id"].as_str().unwrap()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let node = json_body(response).await;
    assert_eq!(node["status"], "pending");
    assert!(node["credential_issued_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn bulk_revoke_skips_foreign_and_already_revoked_nodes() {
    let app = app();
    let tenant_id = tenant(&app, "Acme").await;
    let other_tenant = tenant(&app, "Other").await;
    let network_id = network(&app, &tenant_id, "Production", "10.42.0.0/24").await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let other_network_id = network(&app, &other_tenant, "Prod", "10.43.0.0/24").await["id"]
        .as_str()
        .unwrap()
        .to_string();

    async fn enroll(
        app: &axum::Router,
        tenant: &str,
        network_id: &str,
        name: &str,
        key: u8,
    ) -> String {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/t/{tenant}/nodes"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "network_id": network_id,
                            "name": name,
                            "public_key": hex::encode([key; 32])
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        json_body(response).await["node"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    let mine = enroll(&app, &tenant_id, &network_id, "mine", 30).await;
    let mine_too = enroll(&app, &tenant_id, &network_id, "mine-too", 31).await;
    let theirs = enroll(&app, &other_tenant, &other_network_id, "theirs", 32).await;

    // One batch: two of mine (one of them twice — already revoked on the
    // first pass), and one that belongs to someone else.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/bulk-revoke"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ids": [mine, mine, theirs, "00000000-0000-0000-0000-000000000000"] })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // `mine` is revoked once; the duplicate id is skipped because the
    // node is already revoked, `theirs` belongs to another tenant, and
    // the unknown id does not exist.
    assert_eq!(json_body(response).await["revoked"], 1);

    // The other tenant's node is untouched.
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{other_tenant}/nodes/{theirs}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(response).await["status"], "pending");
    let _ = mine_too;
}

#[tokio::test]
async fn deleting_a_node_requires_revocation_first_and_frees_the_row() {
    let app = app();
    let tenant_id = tenant(&app, "Acme").await;
    let network_id = network(&app, &tenant_id, "Production", "10.42.0.0/24").await["id"]
        .as_str()
        .unwrap()
        .to_string();

    async fn enroll(app: axum::Router, tenant_id: String, network_id: String, name: &str, key: u8) -> String {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/t/{tenant_id}/nodes"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "network_id": network_id,
                            "name": name,
                            "public_key": hex::encode([key; 32])
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        json_body(response).await["node"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    let junk = enroll(app.clone(), tenant_id.clone(), network_id.clone(), "junk", 40).await;
    let member = enroll(app.clone(), tenant_id.clone(), network_id, "member", 41).await;

    // Deleting a live node is refused: revocation is the decision, and
    // deletion is only the cleanup after it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{member}/delete"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Revoke, then delete. The row is gone for good.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{junk}/revoke"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{junk}/delete"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{junk}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The member is untouched, and "clear revoked" reports one and
    // leaves it alone.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes/delete-revoked"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["deleted"], 0);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{tenant_id}/nodes/{member}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json_body(response).await["status"], "pending");
}

#[tokio::test]
async fn deleting_a_network_takes_its_nodes_with_it() {
    let app = app();
    let tenant_id = tenant(&app, "Acme").await;
    let network_id = network(&app, &tenant_id, "Production", "10.42.0.0/24").await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/nodes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": network_id,
                        "name": "web-01",
                        "public_key": "dd".repeat(32)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let node_id = json_body(response).await["node"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Delete the network. The node that lived in it goes with it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/t/{tenant_id}/networks/{network_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // The node list no longer holds it, and the network list no longer
    // holds the network.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{tenant_id}/nodes"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json_body(response).await;
    let ids: Vec<String> = listed["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|node| node["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(!ids.contains(&node_id), "the node went with its network");

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = json_body(response).await;
    let networks: Vec<String> = listed["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|network| network["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(!networks.contains(&network_id), "the network is gone");
}

#[tokio::test]
async fn enrollment_rejects_invalid_public_key() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;
    let network = network(&app, &tenant, "Production", "10.42.0.0/24").await;
    let network_id = network["id"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/nodes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": network_id,
                        "name": "bad",
                        "public_key": "zz"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_creation_validates_the_network() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/policies"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": "missing",
                        "name": "SSH",
                        "protocol": "tcp",
                        "port": { "single": 22 },
                        "source": { "kind": "tag", "tag": "admin" },
                        "destination": { "kind": "platform", "platform": "linux" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn policy_creation_succeeds_within_a_tenant() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;
    let network = network(&app, &tenant, "Production", "10.42.0.0/24").await;
    let network_id = network["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/policies"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": network_id,
                        "name": "Operator SSH",
                        "protocol": "tcp",
                        "port": { "single": 22 },
                        "source": { "kind": "tag", "tag": "admin" },
                        "destination": { "kind": "platform", "platform": "linux" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(body["name"], "Operator SSH");
    assert_eq!(body["enabled"], true);
}

#[tokio::test]
async fn audit_log_records_mutations() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;
    network(&app, &tenant, "Production", "10.42.0.0/24").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{tenant}/events"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let events = json_body(response).await;
    // Two events: the tenant was created, and then the network.
    assert_eq!(events["total"], 2);
    assert_eq!(events["items"][1]["action"], "network.created");
    assert_eq!(events["items"][0]["action"], "tenant.created");
    assert_eq!(events["items"][0]["tenant_id"], tenant.as_str());
}

#[tokio::test]
async fn relays_can_be_created_and_drained() {
    let app = app();
    let tenant = tenant(&app, "Acme").await;
    let network = network(&app, &tenant, "Production", "10.42.0.0/24").await;
    let network_id = network["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/relays"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "relay-ams",
                        "node_id": "10.42.0.2/24",
                        "endpoint": "198.51.100.2:9994",
                        "networks": [network_id]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let relay = json_body(response).await;
    let relay_id = relay["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/relays/{relay_id}/drain"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], "draining");
}
