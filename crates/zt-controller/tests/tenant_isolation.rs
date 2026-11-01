//! Tenant isolation and master-console tests.
//!
//! Isolation is the most security-critical property of a multi-tenant
//! control plane. These tests assert that a tenant can never observe or
//! mutate another tenant's data, even when it knows the object IDs.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::{router, Controller, Deployment, TenantLimits};

fn app() -> axum::Router {
    router(Controller::new().expect("controller"))
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn create_tenant(app: &axum::Router, name: &str) -> Value {
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
    json_body(response).await
}

async fn create_network(app: &axum::Router, tenant: &str, name: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant}/networks"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": name, "cidr": "10.0.0.0/24" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await
}

#[tokio::test]
async fn a_tenant_cannot_see_another_tenants_networks() {
    let app = app();
    let acme = create_tenant(&app, "Acme").await;
    let globex = create_tenant(&app, "Globex").await;

    let acme_id = acme["id"].as_str().unwrap();
    let globex_id = globex["id"].as_str().unwrap();

    create_network(&app, acme_id, "Acme Production").await;
    create_network(&app, globex_id, "Globex Internal").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{acme_id}/networks"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list = json_body(response).await;

    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["name"], "Acme Production");
}

#[tokio::test]
async fn a_tenant_cannot_delete_another_tenants_network() {
    let app = app();
    let acme = create_tenant(&app, "Acme").await;
    let globex = create_tenant(&app, "Globex").await;

    let acme_id = acme["id"].as_str().unwrap();
    let globex_id = globex["id"].as_str().unwrap();

    let victim = create_network(&app, globex_id, "Globex Internal").await;
    let victim_id = victim["id"].as_str().unwrap();

    // Acme tries to delete Globex's network by ID.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/t/{acme_id}/networks/{victim_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The network must still exist.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{globex_id}/networks"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list = json_body(response).await;
    assert_eq!(list["total"], 1);
}

#[tokio::test]
async fn a_tenant_cannot_enroll_a_node_into_another_tenants_network() {
    let app = app();
    let acme = create_tenant(&app, "Acme").await;
    let globex = create_tenant(&app, "Globex").await;

    let acme_id = acme["id"].as_str().unwrap();
    let globex_id = globex["id"].as_str().unwrap();

    let victim = create_network(&app, globex_id, "Globex Internal").await;
    let victim_id = victim["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{acme_id}/nodes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": victim_id,
                        "name": "intruder",
                        "public_key": "aa".repeat(32)
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
async fn a_tenant_cannot_renew_another_tenants_node() {
    let app = app();
    let acme = create_tenant(&app, "Acme").await;
    let globex = create_tenant(&app, "Globex").await;

    let acme_id = acme["id"].as_str().unwrap();
    let globex_id = globex["id"].as_str().unwrap();

    let network = create_network(&app, globex_id, "Globex Internal").await;
    let network_id = network["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{globex_id}/nodes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "network_id": network_id,
                        "name": "victim",
                        "public_key": "bb".repeat(32)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let enrolled = json_body(response).await;
    let node_id = enrolled["node"]["id"].as_str().unwrap();

    // Acme tries to renew the credential.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{acme_id}/nodes/{node_id}/credential"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_tenant_cannot_see_another_tenants_events() {
    let app = app();
    let acme = create_tenant(&app, "Acme").await;
    let globex = create_tenant(&app, "Globex").await;

    let acme_id = acme["id"].as_str().unwrap();
    let globex_id = globex["id"].as_str().unwrap();

    create_network(&app, acme_id, "Acme Production").await;
    create_network(&app, globex_id, "Globex Internal").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/t/{acme_id}/events"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let events = json_body(response).await;

    // Acme sees its own two events: tenant creation and network creation.
    // Globex's network creation is not visible.
    assert_eq!(events["total"], 2);
    let details: Vec<&str> = events["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["detail"].as_str().unwrap_or(""))
        .collect();
    assert!(details.contains(&"Created network Acme Production"));
    assert!(details.contains(&"Created tenant Acme"));
    assert!(!details.iter().any(|detail| detail.contains("Globex")));
}

#[tokio::test]
async fn the_master_console_sees_every_tenant() {
    let app = app();
    create_tenant(&app, "Acme").await;
    create_tenant(&app, "Globex").await;
    create_tenant(&app, "Initech").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list = json_body(response).await;
    assert_eq!(list["total"], 3);
}

#[tokio::test]
async fn a_tenant_can_be_suspended_and_reactivated() {
    let app = app();
    let tenant = create_tenant(&app, "Acme").await;
    let tenant_id = tenant["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tenants/{tenant_id}/suspend"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "reason": "payment overdue" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let suspended = json_body(response).await;
    assert_eq!(suspended["status"], "suspended");

    // A suspended tenant cannot create resources.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "New Net", "cidr": "10.1.0.0/24" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Reactivating restores access.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/tenants/{tenant_id}/reactivate"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let reactivated = json_body(response).await;
    assert_eq!(reactivated["status"], "active");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "New Net", "cidr": "10.1.0.0/24" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_deleted_tenant_is_soft_deleted() {
    let app = app();
    let tenant = create_tenant(&app, "Acme").await;
    let tenant_id = tenant["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/tenants/{tenant_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let deleted = json_body(response).await;
    assert_eq!(deleted["status"], "deleted");
    assert!(deleted["deleted_at"].is_number());

    // The tenant is still listed, so an accidental deletion can be found.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/tenants")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list = json_body(response).await;
    assert_eq!(list["total"], 1);
}

#[tokio::test]
async fn tenant_quotas_are_enforced() {
    let app = app();

    // Create a tenant with a single-network limit.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tenants")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Tiny",
                        "slug": "tiny",
                        "deployment": "shared",
                        "limits": {
                            "max_networks": 1,
                            "max_nodes": 2,
                            "max_policies": 1,
                            "max_relays": 1,
                            "max_credential_ttl_secs": 3600
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let tenant = json_body(response).await;
    let tenant_id = tenant["id"].as_str().unwrap();

    create_network(&app, tenant_id, "First").await;

    // The second network exceeds the quota.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "name": "Second", "cidr": "10.1.0.0/24" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn usage_is_reported_per_tenant() {
    let app = app();
    let acme = create_tenant(&app, "Acme").await;
    let acme_id = acme["id"].as_str().unwrap();

    create_network(&app, acme_id, "First").await;
    create_network(&app, acme_id, "Second").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/tenants/{acme_id}/usage"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let usage = json_body(response).await;
    assert_eq!(usage["usage"]["networks"], 2);
    assert_eq!(usage["limits"]["max_networks"], 10);
}

#[tokio::test]
async fn the_control_plane_health_counts_tenants() {
    let app = app();
    create_tenant(&app, "Acme").await;
    create_tenant(&app, "Globex").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/control-plane")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let health = json_body(response).await;
    assert_eq!(health["tenants"], 2);
    assert_eq!(health["active_tenants"], 2);
    assert_eq!(health["shared_tenants"], 2);
    assert_eq!(health["dedicated_tenants"], 0);
}

#[tokio::test]
async fn a_dedicated_tenant_has_no_shared_controller_key() {
    let app = app();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tenants")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Big Corp",
                        "slug": "big-corp",
                        "deployment": "dedicated"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let tenant = json_body(response).await;

    assert_eq!(tenant["deployment"], "dedicated");
    assert!(tenant["controller_id"].is_null());
    assert!(tenant["controller_public_key"].is_null());
}

#[tokio::test]
async fn a_shared_tenant_receives_the_controller_trust_anchor() {
    let app = app();
    let tenant = create_tenant(&app, "Acme").await;

    assert_eq!(tenant["deployment"], "shared");
    assert!(tenant["controller_id"].is_string());
    assert!(tenant["controller_public_key"].is_string());
}

#[tokio::test]
async fn duplicate_tenant_slugs_are_rejected() {
    let app = app();
    create_tenant(&app, "Acme").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tenants")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Acme Two",
                        "slug": "acme",
                        "deployment": "shared"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_tenant_can_find_itself_by_slug() {
    let controller = Controller::new().expect("controller");
    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            Deployment::Shared,
            "starter".into(),
            TenantLimits::default(),
        )
        .await
        .expect("tenant");

    let found = controller.get_tenant_by_slug("acme").await.expect("found");
    assert_eq!(found.id, tenant.id);
    assert!(controller.get_tenant_by_slug("nope").await.is_err());
}
