//! Request-scoped helpers for the API layer.
//!
//! The authentication middleware puts the authenticated identity into the
//! request extensions. The extractor here reads it back, so a handler can
//! attribute its audit events to the caller.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::Identity;
use crate::model::Actor;

/// The authenticated principal behind a request.
///
/// A handler that mutates state takes one of these, so every audit event
/// names the actor that caused it.
#[derive(Clone, Debug)]
pub struct Principal(pub Identity);

impl Principal {
    /// The actor to attribute an action to.
    pub fn actor(&self) -> Actor {
        self.0.actor()
    }

    /// The subject of the token.
    pub fn subject(&self) -> &str {
        &self.0.subject
    }

    /// The tenant the token belongs to, when it names one.
    pub fn tenant_id(&self) -> Option<&str> {
        self.0.tenant_id.as_deref()
    }
}

impl<S> FromRequestParts<S> for Principal
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // The middleware inserts the identity before the handler runs. A
        // missing identity means the route was reached without the auth
        // middleware, which only happens in a unit test that calls the
        // router directly.
        let identity = parts
            .extensions
            .get::<Identity>()
            .cloned()
            .unwrap_or_else(|| Identity {
                subject: "anonymous".to_string(),
                name: None,
                preferred_username: None,
                tenant_id: None,
                scopes: Vec::new(),
                roles: Vec::new(),
            });

        Ok(Principal(identity))
    }
}
