//! Errors from the node agent.

use std::fmt;

/// Errors the agent can produce.
#[derive(Debug)]
pub enum AgentError {
    /// A configuration or state file is invalid.
    InvalidConfig(String),
    /// The node has not enrolled yet.
    NotEnrolled,
    /// The controller rejected a request.
    Controller(String),
    /// A cryptographic operation failed.
    Crypto(String),
    /// The credential could not be validated.
    Credential(String),
    /// A file operation failed.
    Io(String),
    /// The command line was not understood.
    Usage(String),
    /// The node's data plane failed.
    Node(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid configuration: {message}"),
            Self::NotEnrolled => write!(f, "this node has not been enrolled"),
            Self::Controller(message) => write!(f, "controller error: {message}"),
            Self::Crypto(message) => write!(f, "cryptographic error: {message}"),
            Self::Credential(message) => write!(f, "credential error: {message}"),
            Self::Io(message) => write!(f, "{message}"),
            Self::Node(message) => write!(f, "node error: {message}"),
            Self::Usage(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<zt_crypto::Error> for AgentError {
    fn from(error: zt_crypto::Error) -> Self {
        AgentError::Crypto(error.to_string())
    }
}

impl From<crate::client::ClientError> for AgentError {
    fn from(error: crate::client::ClientError) -> Self {
        match error {
            crate::client::ClientError::Unreachable(message) => {
                AgentError::Controller(format!("unreachable: {message}"))
            }
            crate::client::ClientError::Api { status, message } => {
                AgentError::Controller(format!("HTTP {status}: {message}"))
            }
            crate::client::ClientError::InvalidResponse(message) => {
                AgentError::Controller(format!("invalid response: {message}"))
            }
        }
    }
}

impl From<zt_node::NodeError> for AgentError {
    fn from(error: zt_node::NodeError) -> Self {
        Self::Node(error.to_string())
    }
}

/// A result from the agent.
pub type Result<T> = std::result::Result<T, AgentError>;
