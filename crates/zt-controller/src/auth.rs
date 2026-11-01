//! Authentication for the controller's HTTP API.
//!
//! The controller accepts bearer tokens issued by an OpenID Connect
//! provider. Tokens are verified against the provider's JWKS, so a token
//! signed by anyone else is rejected.
//!
//! # What is protected
//!
//! Every API route requires a valid token. The tenant-scoped routes are
//! additionally checked against the token's tenant claim, so a token for one
//! tenant cannot address another tenant's objects. The master-console
//! routes require an operator role.
//!
//! # Why the master console needs a role
//!
//! The master console can create, suspend, and delete tenants. Without a
//! role check, any authenticated user could delete a customer's account.
//! The role names are configurable because they depend on the provider's
//! claim shape.

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

/// The claims the controller reads from a bearer token.
///
/// Only the fields the controller acts on are modelled. The full token is
/// still verified cryptographically, so unknown claims cannot be used to
/// smuggle in data.
#[derive(Clone, Debug, Deserialize)]
pub struct Claims {
    /// The subject — the user or service that authenticated.
    #[serde(default)]
    pub sub: String,
    /// The display name of the subject, when the provider supplies one.
    #[serde(default)]
    pub name: Option<String>,
    /// The preferred username of the subject, when the provider supplies one.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// The issuer that signed the token.
    #[serde(default)]
    pub iss: String,
    /// The audience the token was minted for.
    #[serde(default)]
    pub aud: String,
    /// The tenant this token belongs to.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// The scopes granted to the token.
    #[serde(default)]
    pub scope: Option<String>,
    /// The roles granted to the token.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    /// Expiry, as a Unix timestamp.
    pub exp: u64,
    /// Issued-at, as a Unix timestamp.
    #[serde(default)]
    pub iat: u64,
}

impl Claims {
    /// The scopes granted to the token.
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_deref()
            .map(|scope| scope.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// The roles granted to the token.
    pub fn roles(&self) -> Vec<&str> {
        self.roles
            .as_deref()
            .map(|roles| roles.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

/// Errors from token verification.
#[derive(Debug)]
pub enum AuthError {
    /// No token was supplied.
    Missing,
    /// The token could not be parsed or verified.
    Invalid(String),
    /// The token is valid but does not grant what the route needs.
    Forbidden(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "authentication required"),
            Self::Invalid(message) => write!(f, "invalid token: {message}"),
            Self::Forbidden(message) => write!(f, "forbidden: {message}"),
        }
    }
}

/// A result from the auth layer.
pub type Result<T> = std::result::Result<T, AuthError>;

/// The configuration for token verification.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// The issuer that tokens must come from.
    pub issuer: String,
    /// The audience tokens must be minted for.
    pub audience: String,
    /// The JWKS endpoint.
    pub jwks_uri: String,
    /// The role that grants access to the master console.
    pub operator_role: String,
    /// The claim that carries the tenant identifier.
    pub tenant_claim: String,
}

impl AuthConfig {
    /// Build a configuration for an OIDC provider.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_uri: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_uri: jwks_uri.into(),
            operator_role: "zt-operator".to_string(),
            tenant_claim: "tenant_id".to_string(),
        }
    }
}

/// A JWK, as served by the provider's JWKS endpoint.
#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    /// The algorithm the key is used with.
    #[serde(default)]
    #[allow(dead_code)]
    alg: Option<String>,
    /// The RSA modulus.
    #[serde(default)]
    n: Option<String>,
    /// The RSA exponent.
    #[serde(default)]
    e: Option<String>,
    /// The elliptic curve.
    #[serde(default)]
    crv: Option<String>,
    /// The elliptic curve x coordinate.
    #[serde(default)]
    x: Option<String>,
    /// The elliptic curve y coordinate.
    #[serde(default)]
    y: Option<String>,
}

/// The JWKS document.
#[derive(Clone, Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// Verifies bearer tokens against an OIDC provider's JWKS.
///
/// The JWKS is fetched once and cached. If a token arrives with an unknown
/// key ID, the cache is refreshed, because providers rotate keys.
#[derive(Clone)]
pub struct Verifier {
    config: AuthConfig,
    client: reqwest::Client,
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
}

impl Verifier {
    /// Build a verifier.
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// The configuration in use.
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Verify a bearer token and return its claims.
    pub async fn verify(&self, token: &str) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|error| AuthError::Invalid(format!("malformed token: {error}")))?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::Invalid("the token has no key id".into()))?;

        // A key the cache does not have means the provider rotated its
        // signing keys, so the cache is refreshed once and the lookup is
        // retried.
        if !self.keys.read().await.contains_key(&kid) {
            self.refresh().await?;
        }

        let key = {
            let keys = self.keys.read().await;
            keys.get(&kid).cloned()
        };
        let key = match key {
            Some(key) => key,
            None => {
                self.refresh().await?;
                let keys = self.keys.read().await;
                keys.get(&kid).cloned().ok_or_else(|| {
                    AuthError::Invalid("the token was signed with an unknown key".into())
                })?
            }
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        // The provider may use ES256, which the library calls ES256. The
        // algorithm is taken from the token header, but it is pinned to the
        // asymmetric set so an attacker cannot downgrade to `none` or to a
        // symmetric algorithm with the public key as the secret.
        validation.algorithms = match header.alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => Vec::new(),
            other => vec![other],
        };

        let data = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|error| AuthError::Invalid(error.to_string()))?;

        Ok(data.claims)
    }

    /// Fetch the JWKS and rebuild the key cache.
    async fn refresh(&self) -> Result<()> {
        let response = self
            .client
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|error| {
                AuthError::Invalid(format!("could not reach the provider: {error}"))
            })?;

        let document: Jwks = response
            .json()
            .await
            .map_err(|error| AuthError::Invalid(format!("malformed JWKS: {error}")))?;

        let mut keys = HashMap::new();
        for jwk in document.keys {
            // The library takes the base64url components as they arrived, so
            // no decoding is needed here. The padding is stripped, because
            // the JSON Web Key format specifies unpadded base64url.
            let key = match jwk.kty.as_str() {
                "RSA" => {
                    let (Some(n), Some(e)) = (&jwk.n, &jwk.e) else {
                        continue;
                    };
                    DecodingKey::from_rsa_components(&unpadded(n), &unpadded(e)).ok()
                }
                "EC" => {
                    let (Some(x), Some(y)) = (&jwk.x, &jwk.y) else {
                        continue;
                    };
                    match jwk.crv.as_deref() {
                        Some("P-256") => {
                            DecodingKey::from_ec_components(&unpadded(x), &unpadded(y)).ok()
                        }
                        Some("P-384") => {
                            DecodingKey::from_ec_components(&unpadded(x), &unpadded(y)).ok()
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some(key) = key else { continue };

            keys.insert(jwk.kid.clone(), key);
        }

        if keys.is_empty() {
            return Err(AuthError::Invalid(
                "the provider returned no usable signing keys".into(),
            ));
        }

        *self.keys.write().await = keys;
        Ok(())
    }
}

/// Strip the padding from a base64url string.
///
/// The JWT library expects base64url without padding, which is what the
/// JSON Web Key format specifies. Some providers pad anyway, so the padding
/// is removed rather than trusted.
fn unpadded(input: &str) -> String {
    input.trim_end_matches('=').to_string()
}

/// The identity a request was authenticated as.
#[derive(Clone, Debug)]
pub struct Identity {
    /// The subject of the token.
    pub subject: String,
    /// The display name of the subject, when the provider supplies one.
    pub name: Option<String>,
    /// The preferred username of the subject, when the provider supplies one.
    pub preferred_username: Option<String>,
    /// The tenant the token belongs to, if it is a tenant-scoped token.
    pub tenant_id: Option<String>,
    /// The scopes the token carries.
    pub scopes: Vec<String>,
    /// The roles the token carries.
    pub roles: Vec<String>,
}

impl Identity {
    /// Whether the identity has a scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }

    /// Whether the identity has a role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|granted| granted == role)
    }

    /// The actor this identity acts as.
    ///
    /// The display name falls back to the preferred username, so an
    /// operator is recognisable in the audit log even when the provider
    /// supplies no name.
    pub fn actor(&self) -> crate::model::Actor {
        crate::model::Actor::principal(
            self.subject.clone(),
            self.name
                .clone()
                .or_else(|| self.preferred_username.clone()),
        )
    }
}

/// Extract the bearer token from an `Authorization` header.
pub fn bearer_token(header: Option<&str>) -> Option<&str> {
    let header = header?;
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_token_is_extracted() {
        assert_eq!(bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(Some("bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(Some("BEARER abc123")), Some("abc123"));
    }

    #[test]
    fn a_missing_or_wrong_token_is_rejected() {
        assert_eq!(bearer_token(None), None);
        assert_eq!(bearer_token(Some("")), None);
        assert_eq!(bearer_token(Some("Basic abc123")), None);
        assert_eq!(bearer_token(Some("Bearer")), None);
        assert_eq!(bearer_token(Some("Bearer   ")), None);
    }

    #[test]
    fn base64url_padding_is_stripped() {
        // The JWT library needs unpadded components.
        assert_eq!(unpadded("aGVsbG8="), "aGVsbG8");
        assert_eq!(unpadded("aGVsbG8"), "aGVsbG8");
        assert_eq!(unpadded("YWJjZA=="), "YWJjZA");
    }

    #[test]
    fn scopes_and_roles_are_split() {
        let claims = Claims {
            sub: "user".into(),
            name: None,
            preferred_username: None,
            iss: "issuer".into(),
            aud: "audience".into(),
            tenant_id: Some("acme".into()),
            scope: Some("read write".into()),
            roles: Some(vec!["zt-operator".into()]),
            exp: 0,
            iat: 0,
        };
        assert_eq!(claims.scopes(), vec!["read", "write"]);
        assert_eq!(claims.roles(), vec!["zt-operator"]);
    }

    #[test]
    fn absent_claims_do_not_panic() {
        let claims = Claims {
            sub: "user".into(),
            name: None,
            preferred_username: None,
            iss: String::new(),
            aud: String::new(),
            tenant_id: None,
            scope: None,
            roles: None,
            exp: 0,
            iat: 0,
        };
        assert!(claims.scopes().is_empty());
        assert!(claims.roles().is_empty());
    }
}
