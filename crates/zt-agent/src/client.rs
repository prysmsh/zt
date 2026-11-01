//! HTTP client for the ZT-next controller.
//!
//! This is the client side of the control-plane API. It is deliberately
//! small and dependency-light: the node agent only needs to enroll, renew,
//! and report status.
//!
//! The controller is normally reached over HTTPS, through a reverse proxy,
//! so the client speaks TLS and follows redirects.

use std::time::Duration;

use serde::Deserialize;

/// Errors from the controller client.
#[derive(Debug)]
pub enum ClientError {
    /// The controller could not be reached.
    Unreachable(String),
    /// The controller returned an error.
    Api { status: u16, message: String },
    /// The response could not be parsed.
    InvalidResponse(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(message) => write!(f, "controller unreachable: {message}"),
            Self::Api { status, message } => write!(f, "controller returned {status}: {message}"),
            Self::InvalidResponse(message) => write!(f, "invalid controller response: {message}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A result from the controller client.
pub type Result<T> = std::result::Result<T, ClientError>;

/// A node as the controller reports it.
#[derive(Clone, Debug, Deserialize)]
pub struct ControllerNode {
    pub id: String,
    pub network_id: String,
    pub name: String,
    pub address: String,
    pub status: String,
    pub credential_not_after: u64,
}

/// The result of enrolling a node.
#[derive(Clone, Debug, Deserialize)]
pub struct EnrollResponse {
    pub node: ControllerNode,
    /// The credential, hex encoded. Shown once.
    pub credential: String,
    pub credential_not_after: u64,
}

/// Information about the controller itself.
#[derive(Clone, Debug, Deserialize)]
pub struct ControllerInfo {
    /// The controller's identifier, hex encoded.
    pub id: String,
    /// The controller's Ed25519 public key, hex encoded.
    ///
    /// This is the trust anchor. A node pins it at enrollment and refuses to
    /// accept credentials signed by anything else.
    pub public_key: String,
    /// The default credential lifetime in seconds.
    pub credential_ttl_secs: u32,
}

/// A tenant as the master console reports it.
#[derive(Clone, Debug, Deserialize)]
pub struct TenantInfo {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub status: String,
}

#[derive(Deserialize)]
struct TenantList {
    items: Vec<TenantInfo>,
}

/// A network as the controller reports it.
#[derive(Clone, Debug, Deserialize)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub cidr: String,
    pub credential_ttl_secs: u32,
}

#[derive(Deserialize)]
struct NetworkList {
    items: Vec<NetworkInfo>,
}

/// What a node carried since it last reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeUsage {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
}

/// A peer in the topology the controller hands a node.
#[derive(Clone, Debug, Deserialize)]
pub struct TopologyPeer {
    /// The peer's address in the network's range.
    pub address: String,
    /// The peer's Ed25519 public key, hex encoded.
    pub public_key: String,
    /// The peer's ML-DSA-65 public key, hex encoded.
    pub pq_public_key: String,
    /// The peer's UDP endpoint, when it has reported one.
    pub endpoint: Option<String>,
}

/// The topology the controller hands a node.
///
/// It holds the node's own address, the range it lives in, and the peers it
/// shares the range with. Nothing about any other network.
#[derive(Clone, Debug, Deserialize)]
pub struct Topology {
    /// The node's own address in the network's range.
    pub address: String,
    /// The network's range, in the `10.42.0.0/24` form.
    pub cidr: String,
    /// The network's numeric identifier.
    pub network_id: u64,
    /// The peers in the same network.
    pub peers: Vec<TopologyPeer>,
}

/// A minimal blocking HTTP client for the controller API.
///
/// The node authenticates with the credential the controller issued it. The
/// credential is signed by the controller and bound to the node's own key,
/// so the node holds no secret.
#[derive(Clone)]
pub struct ControllerClient {
    base_url: String,
    tenant: String,
    timeout: Duration,
    /// The credential presented on every request.
    credential: Option<String>,
}

impl ControllerClient {
    /// Build a client for a tenant's API.
    pub fn new(base_url: impl Into<String>, tenant: impl Into<String>) -> Self {
        let base_url = base_url.into();
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            tenant: tenant.into(),
            timeout: Duration::from_secs(10),
            credential: None,
        }
    }

    /// Set the credential the client presents.
    ///
    /// The node authenticates with the credential the controller issued it.
    /// The credential is signed by the controller and bound to the node's
    /// own key, so the node holds no secret.
    pub fn with_credential(mut self, credential: impl Into<String>) -> Self {
        self.credential = Some(credential.into());
        self
    }

    /// Replace the credential the client presents.
    ///
    /// The credential changes when the node enrolls or renews, so the
    /// client is updated rather than rebuilt.
    pub fn set_credential(&mut self, credential: impl Into<String>) {
        self.credential = Some(credential.into());
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn tenant_url(&self, path: &str) -> String {
        format!(
            "{}/api/v1/t/{}/{}",
            self.base_url,
            self.tenant,
            path.trim_start_matches('/')
        )
    }

    /// Fetch the controller's identity and trust anchor.
    pub fn controller_info(&self) -> Result<ControllerInfo> {
        let url = format!("{}/api/v1/controller", self.base_url);
        self.get(&url)
    }

    /// Resolve a tenant slug to its identifier.
    ///
    /// The tenant-scoped API paths take a tenant ID. Operators think in
    /// slugs, so the agent accepts either and resolves the slug here.
    pub fn resolve_tenant(&self, slug_or_id: &str) -> Result<String> {
        if slug_or_id.contains('-') && slug_or_id.len() == 36 {
            // Already an ID.
            return Ok(slug_or_id.to_string());
        }

        let url = format!("{}/api/v1/tenants", self.base_url);
        let list: TenantList = self.get(&url)?;

        let matches: Vec<&TenantInfo> = list
            .items
            .iter()
            .filter(|tenant| tenant.slug == slug_or_id || tenant.id == slug_or_id)
            .collect();

        // Prefer an active tenant. A deleted or suspended tenant has the
        // same slug as its live successor in some deployments, and the live
        // one is the one an operator means.
        let chosen = matches
            .iter()
            .find(|tenant| tenant.status == "active")
            .or_else(|| matches.first())
            .copied();

        match chosen {
            Some(tenant) => Ok(tenant.id.clone()),
            None => Err(ClientError::Api {
                status: 404,
                message: format!("no tenant named {slug_or_id}"),
            }),
        }
    }

    /// Enroll a node and receive its credential.
    pub fn enroll(
        &self,
        network_id: &str,
        name: &str,
        public_key: &str,
        pq_public_key: &str,
        tags: &[String],
    ) -> Result<EnrollResponse> {
        let body = serde_json::json!({
            "network_id": network_id,
            "name": name,
            "public_key": public_key,
            "pq_public_key": pq_public_key,
            "tags": tags,
        });
        self.post(&self.tenant_url("nodes"), &body)
    }

    /// Ask the controller for this node's topology.
    ///
    /// The topology is what a node needs to carry traffic: its own address
    /// in the network's range, and the peers it shares the range with.
    pub fn topology(&self) -> Result<Topology> {
        self.get(&self.tenant_url("topology"))
    }

    /// Ask the controller what address this agent appears from.
    ///
    /// The controller sits on the public internet, so the source address
    /// of the request is the address the rest of the internet sees. A node
    /// behind a NAT uses this to learn its public endpoint, and its peers
    /// use that endpoint to reach it.
    pub fn observed_endpoint(&self) -> Result<String> {
        let result: serde_json::Value = self.get("/api/v1/my-endpoint")?;
        Ok(result["address"]
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    /// Report how this node's peers reach it, and what it carried.
    ///
    /// The endpoint is where the node listens. The post-quantum key is the
    /// one the node signs its handshakes with, which a peer needs to check
    /// them. The usage is what the tenant is charged for.
    pub fn report_presence(
        &self,
        endpoint: &str,
        pq_public_key: &str,
        usage: &NodeUsage,
    ) -> Result<ControllerNode> {
        let body = serde_json::json!({
            "endpoint": endpoint,
            "pq_public_key": pq_public_key,
            "usage": {
                "bytes_in": usage.bytes_in,
                "bytes_out": usage.bytes_out,
                "packets": usage.packets,
            },
        });
        self.post(&self.tenant_url("nodes/self/presence"), &body)
    }

    /// Ask the controller which node this credential belongs to.
    ///
    /// This is how a node learns its own identifier, which it needs to
    /// renew its credential.
    pub fn self_node(&self) -> Result<ControllerNode> {
        self.get(&self.tenant_url("nodes/self"))
    }

    /// Renew a node's credential.
    pub fn renew_credential(&self, node_id: &str) -> Result<EnrollResponse> {
        let body = serde_json::json!({});
        self.post(
            &self.tenant_url(&format!("nodes/{node_id}/credential")),
            &body,
        )
    }

    /// List the networks available to the tenant.
    pub fn list_networks(&self) -> Result<Vec<NetworkInfo>> {
        let result: NetworkList = self.get(&self.tenant_url("networks"))?;
        Ok(result.items)
    }

    /// Look up a network by its ID.
    pub fn get_network(&self, network_id: &str) -> Result<NetworkInfo> {
        self.get(&self.tenant_url(&format!("networks/{network_id}")))
    }

    /// Revoke a node.
    pub fn revoke_node(&self, node_id: &str) -> Result<()> {
        let body = serde_json::json!({});
        self.post::<serde_json::Value>(&self.tenant_url(&format!("nodes/{node_id}/revoke")), &body)
            .map(|_| ())
    }

    /// Send a GET request and decode the JSON response.
    fn get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let mut request = ureq::get(url).timeout(self.timeout);
        if let Some(credential) = &self.credential {
            request = request.set("Authorization", &format!("Bearer {credential}"));
        }

        let response = request
            .call()
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;

        decode(response)
    }

    /// Send a POST request and decode the JSON response.
    ///
    /// This is public so a caller can reach a route the client does not
    /// model yet, without waiting for a release.
    pub fn post<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let mut request = ureq::post(url).timeout(self.timeout);
        if let Some(credential) = &self.credential {
            request = request.set("Authorization", &format!("Bearer {credential}"));
        }

        let response = request
            .send_json(body.clone())
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;

        decode(response)
    }
}

/// Decode a response body, turning an error status into an error.
fn decode<T: for<'de> Deserialize<'de>>(response: ureq::Response) -> Result<T> {
    let status = response.status();
    let text = response
        .into_string()
        .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;

    if !(200..300).contains(&status) {
        // The controller answers with {"error": "..."}. Anything else is
        // reported as the status, so the operator still sees what happened.
        let message = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| text.chars().take(200).collect());

        return Err(ClientError::Api { status, message });
    }

    serde_json::from_str(&text).map_err(|error| ClientError::InvalidResponse(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tenant_url_is_scoped() {
        let client = ControllerClient::new("http://localhost:8080", "acme");
        assert_eq!(
            client.tenant_url("nodes"),
            "http://localhost:8080/api/v1/t/acme/nodes"
        );
    }

    #[test]
    fn a_trailing_slash_is_trimmed() {
        let client = ControllerClient::new("http://localhost:8080/", "acme");
        assert_eq!(
            client.tenant_url("nodes"),
            "http://localhost:8080/api/v1/t/acme/nodes"
        );
    }
}
