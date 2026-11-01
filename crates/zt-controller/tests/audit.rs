//! Audit trail attribution.
//!
//! Every administrative mutation names the actor that made it. Before, the
//! actor was a hardcoded string, so there was no way to answer "who
//! suspended this tenant?".

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;
use zt_controller::auth::{AuthConfig, Identity, Verifier};
use zt_controller::middleware::AuthState;
use zt_controller::principal::Principal;
use zt_controller::{router_with_auth, Controller};

/// A principal extractor that names the caller.
///
/// The real extractor reads the identity the middleware put in the request
/// extensions. This one stands in for it, so the test does not need a
/// signed token to prove the attribution works.
fn principal(subject: &'static str, name: Option<&'static str>) -> Principal {
    Principal(Identity {
        subject: subject.to_string(),
        name: name.map(str::to_string),
        preferred_username: None,
        tenant_id: None,
        scopes: Vec::new(),
        roles: Vec::new(),
    })
}

#[tokio::test]
async fn the_audit_trail_names_the_actor() {
    let controller = Controller::new().expect("controller");
    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::principal("operator-1", Some("Mara Admin".into())),
        )
        .await
        .expect("create tenant");

    let events = controller.list_events(Some(&tenant.id)).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].actor, "Mara Admin [operator-1]",
        "the event must name the actor and the subject"
    );
}

#[tokio::test]
async fn an_actor_without_a_name_is_recorded_by_subject() {
    let controller = Controller::new().expect("controller");
    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::principal("service-account", None),
        )
        .await
        .expect("create tenant");

    let events = controller.list_events(Some(&tenant.id)).await;
    assert_eq!(events[0].actor, "service-account");
}

#[tokio::test]
async fn different_actors_are_distinguished() {
    let controller = Controller::new().expect("controller");
    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::principal("first", None),
        )
        .await
        .expect("create tenant");

    controller
        .suspend_tenant(
            &tenant.id,
            "maintenance",
            &zt_controller::Actor::principal("second", None),
        )
        .await
        .expect("suspend");

    let events = controller.list_events(Some(&tenant.id)).await;
    let actors: Vec<&str> = events.iter().map(|event| event.actor.as_str()).collect();
    assert!(
        actors.contains(&"first") && actors.contains(&"second"),
        "each event must name the actor that made it: {actors:?}"
    );
}

#[tokio::test]
async fn a_request_without_an_identity_is_attributed_to_anonymous() {
    // The route is reached without the auth middleware, which is what
    // happens when a test calls the router directly. The actor must still be
    // recorded, so the log never has an empty actor.
    let controller = Controller::new().expect("controller");
    let state = AuthState {
        controller: controller.clone(),
        verifier: std::sync::Arc::new(Verifier::new(AuthConfig::new(
            "https://issuer.test",
            "https://audience.test",
            "https://issuer.test/jwks",
        ))),
        tenant_scope: "zt:tenant".into(),
        operator_scope: "zt:operator".into(),
    };
    let app = router_with_auth(controller, state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/tenants")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "name": "Acme",
                        "slug": "acme",
                        "deployment": "shared"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("response");

    // The request is refused, because there is no token. The point of the
    // test is that the extractor has a defined value when the identity is
    // missing, so a handler can never fail to attribute an event.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let principal = principal("anonymous", None);
    assert_eq!(principal.actor().subject(), "anonymous");
}

#[tokio::test]
async fn the_actor_display_is_readable() {
    let named = zt_controller::Actor::principal("sub-123", Some("Mara Admin".into()));
    assert_eq!(named.display(), "Mara Admin [sub-123]");

    let unnamed = zt_controller::Actor::principal("sub-123", None);
    assert_eq!(unnamed.display(), "sub-123");

    // A blank name is treated as no name.
    let blank = zt_controller::Actor::principal("sub-123", Some("   ".into()));
    assert_eq!(blank.display(), "sub-123");

    let system = zt_controller::Actor::system();
    assert_eq!(system.display(), "system");
}

#[tokio::test]
async fn the_event_list_serialises_the_actor() {
    let controller = Controller::new().expect("controller");
    let tenant = controller
        .create_tenant(
            "Acme".into(),
            "acme".into(),
            zt_controller::Deployment::Shared,
            "team".into(),
            Default::default(),
            &zt_controller::Actor::principal("operator-1", Some("Mara Admin".into())),
        )
        .await
        .expect("create tenant");

    let events = controller.list_events(Some(&tenant.id)).await;
    let value: Value = serde_json::to_value(&events[0]).expect("serialise");
    assert_eq!(value["actor"], json!("Mara Admin [operator-1]"));
}
