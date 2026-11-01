//! The tenant lifecycle, and what each state actually enforces.
//!
//! A tenant that is suspended must be locked out of its own API. Without
//! that, suspension only stops new resources: the tenant's nodes keep
//! renewing their credentials and access never lapses.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::{router_with_auth, Actor, Controller, Deployment};

/// A controller with authentication enabled.
fn authenticated() -> (axum::Router, Controller) {
    let controller = Controller::new().expect("controller");
    let state = AuthState {
        // The verifier points nowhere, so no provider token is accepted.
        // A node's own credential is the only way in.
        verifier: std::sync::Arc::new(Verifier::new(AuthConfig::new(
            "https://issuer.invalid",
            "https://audience.invalid",
            "https://issuer.invalid/jwks",
        ))),
        controller: controller.clone(),
        tenant_scope: "zt:tenant".into(),
        operator_scope: "zt:operator".into(),
    };

    (router_with_auth(controller.clone(), state), controller)
}

/// A tenant with a network and an enrolled node.
async fn tenant_with_node(controller: &Controller) -> (String, String, String) {
    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            Deployment::Shared,
            "team".into(),
            Default::default(),
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

    let (node, credential) = controller
        .enroll_node(
            &tenant.id,
            &network.id,
            "web-01".into(),
            [7u8; 32],
            Vec::new(),
            &Actor::system(),
        )
        .await
        .expect("node");

    (tenant.id, node.id, hex::encode(credential.serialize()))
}

#[tokio::test]
async fn a_suspended_tenant_cannot_renew_its_nodes() {
    let (_app, controller) = authenticated();
    let (tenant_id, node_id, _credential) = tenant_with_node(&controller).await;

    controller
        .suspend_tenant(&tenant_id, "non-payment", &Actor::system())
        .await
        .expect("suspend");

    let result = controller
        .renew_node_credential(&tenant_id, &node_id, &Actor::system())
        .await;
    assert!(
        result.is_err(),
        "a suspended tenant must not be able to renew its credentials"
    );
}

#[tokio::test]
async fn a_suspended_tenant_is_locked_out_of_its_api() {
    let (app, controller) = authenticated();
    let (tenant_id, _node_id, credential) = tenant_with_node(&controller).await;

    controller
        .suspend_tenant(&tenant_id, "non-payment", &Actor::system())
        .await
        .expect("suspend");

    // The node's own credential authenticates it, but the tenant is
    // suspended, so the request is refused.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a suspended tenant must not reach its own API"
    );
}

#[tokio::test]
async fn an_active_tenant_reaches_its_api() {
    let (app, controller) = authenticated();
    let (tenant_id, _node_id, credential) = tenant_with_node(&controller).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_deleted_tenant_is_locked_out() {
    let (app, controller) = authenticated();
    let (tenant_id, _node_id, credential) = tenant_with_node(&controller).await;

    controller
        .delete_tenant(&tenant_id, &Actor::system())
        .await
        .expect("delete");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a deleted tenant must not reach its own API"
    );
}

#[tokio::test]
async fn reactivating_a_tenant_restores_access() {
    let (app, controller) = authenticated();
    let (tenant_id, _node_id, credential) = tenant_with_node(&controller).await;

    controller
        .suspend_tenant(&tenant_id, "maintenance", &Actor::system())
        .await
        .expect("suspend");
    controller
        .reactivate_tenant(&tenant_id, &Actor::system())
        .await
        .expect("reactivate");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/t/{tenant_id}/networks"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn deleting_a_tenant_keeps_its_data() {
    let (_app, controller) = authenticated();
    let (tenant_id, _node_id, _credential) = tenant_with_node(&controller).await;

    controller
        .delete_tenant(&tenant_id, &Actor::system())
        .await
        .expect("delete");

    // The data is retained, so a mistake can be corrected. A separate
    // retention job purges it later.
    let tenant = controller.get_tenant(&tenant_id).await.expect("tenant");
    assert_eq!(tenant.status, zt_controller::TenantStatus::Deleted);
    assert!(tenant.deleted_at.is_some());
    assert_eq!(controller.list_nodes(&tenant_id, None).await.len(), 1);
}
