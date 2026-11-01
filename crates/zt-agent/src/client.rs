//! HTTP client for the ZT-next controller.
//!
//! This is the client side of the control-plane API. It is deliberately
//! small and dependency-light: the node agent only needs to enroll, renew,
//! and report status.

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

/// A minimal blocking HTTP client for the controller API.
///
/// The node agent does its control-plane work rarely, so a blocking client
/// keeps the dependency footprint and the failure modes small.
pub struct ControllerClient {
    base_url: String,
    tenant: String,
    timeout: Duration,
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
        }
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
        tags: &[String],
    ) -> Result<EnrollResponse> {
        let body = serde_json::json!({
            "network_id": network_id,
            "name": name,
            "public_key": public_key,
            "tags": tags,
        });
        self.post(&self.tenant_url("nodes"), &body)
    }

    /// Renew a node's credential.
    pub fn renew_credential(&self, node_id: &str) -> Result<EnrollResponse> {
        self.post(
            &self.tenant_url(&format!("nodes/{node_id}/credential")),
            &serde_json::json!({}),
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
        self.post::<serde_json::Value>(
            &self.tenant_url(&format!("nodes/{node_id}/revoke")),
            &serde_json::json!({}),
        )
        .map(|_| ())
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let request = format!("GET {url} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
        let response = self.round_trip(&request)?;
        parse_body(&response)
    }

    /// Send a POST request and decode the JSON response.
    pub fn post<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let payload = serde_json::to_string(body)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        let request = format!(
            "POST {url} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let response = self.round_trip(&request)?;
        parse_body(&response)
    }

    /// Send a request over TCP and read the whole response.
    fn round_trip(&self, request: &str) -> Result<Vec<u8>> {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpStream;

        let host_port = self
            .base_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        let address = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{host_port}:80")
        };

        let mut stream = TcpStream::connect(&address)
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;

        stream
            .write_all(request.as_bytes())
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;
        stream
            .flush()
            .map_err(|error| ClientError::Unreachable(error.to_string()))?;

        // The response is read against its Content-Length when the server
        // provides one. Relying on the connection close alone is unreliable,
        // because a server that half-closes leaves the socket readable until
        // the read timeout fires, which surfaces as a spurious error.
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut expected: Option<usize> = None;
        let mut header_end: Option<usize> = None;

        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    buffer.extend_from_slice(&chunk[..count]);

                    if header_end.is_none() {
                        header_end = find_header_end(&buffer);
                        if let Some(end) = header_end {
                            expected = content_length(&buffer[..end]);
                            // Everything up to the body has arrived.
                            if let Some(length) = expected {
                                if buffer.len() >= end + length {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    // A timeout is only acceptable once the whole body has
                    // arrived. Otherwise the response is incomplete.
                    match (header_end, expected) {
                        (Some(end), Some(length)) if buffer.len() >= end + length => break,
                        _ => {
                            return Err(ClientError::Unreachable(format!(
                                "timed out reading the response: {error}"
                            )))
                        }
                    }
                }
                Err(error) => return Err(ClientError::Unreachable(error.to_string())),
            }
        }

        Ok(buffer)
    }
}

/// Find the end of the HTTP headers.
///
/// Returns the index just past the blank line that separates the headers
/// from the body.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4)
}

/// Read the `Content-Length` header value.
fn content_length(headers: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
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

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

/// Parse an HTTP response and extract its JSON body.
fn parse_body<T: for<'de> Deserialize<'de>>(response: &[u8]) -> Result<T> {
    let text = String::from_utf8_lossy(response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| ClientError::InvalidResponse("malformed response".into()))?;

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    if !(200..300).contains(&status) {
        let message = serde_json::from_str::<ErrorBody>(body)
            .map(|parsed| parsed.error)
            .unwrap_or_else(|_| format!("HTTP {status}"));
        return Err(ClientError::Api { status, message });
    }

    serde_json::from_str(body).map_err(|error| ClientError::InvalidResponse(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_response_is_reported() {
        let response = b"HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"network not found\"}";
        let result: Result<NetworkInfo> = parse_body(response);
        match result {
            Err(ClientError::Api { status, message }) => {
                assert_eq!(status, 404);
                assert_eq!(message, "network not found");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn a_success_response_is_parsed() {
        let response = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"n1\",\"name\":\"Prod\",\"description\":\"\",\"cidr\":\"10.0.0.0/24\",\"credential_ttl_secs\":86400}";
        let result: Result<NetworkInfo> = parse_body(response);
        let network = result.expect("parse");
        assert_eq!(network.name, "Prod");
        assert_eq!(network.credential_ttl_secs, 86400);
    }

    #[test]
    fn a_malformed_response_is_rejected() {
        let result: Result<NetworkInfo> = parse_body(b"garbage");
        assert!(matches!(result, Err(ClientError::InvalidResponse(_))));
    }

    #[test]
    fn the_tenant_url_is_scoped() {
        let client = ControllerClient::new("http://localhost:8080", "acme");
        assert_eq!(
            client.tenant_url("nodes"),
            "http://localhost:8080/api/v1/t/acme/nodes"
        );
    }

    #[test]
    fn the_header_end_is_found() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
        let expected = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("separator")
            + 4;
        assert_eq!(find_header_end(response), Some(expected));
    }

    #[test]
    fn the_content_length_is_read() {
        let headers = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 42\r\n\r\n";
        assert_eq!(content_length(headers), Some(42));

        // A response without a length is read until the connection closes.
        let headers = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n";
        assert_eq!(content_length(headers), None);
    }

    #[test]
    fn a_header_without_a_colon_does_not_stop_the_scan() {
        let headers = b"HTTP/1.1 200 OK\r\nmalformed-header\r\ncontent-length: 7\r\n\r\n";
        assert_eq!(content_length(headers), Some(7));
    }
}
