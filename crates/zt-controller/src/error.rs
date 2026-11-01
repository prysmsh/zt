//! Controller errors.

use std::fmt;

/// Errors returned by controller operations.
#[derive(Debug)]
pub enum ControllerError {
    /// The requested entity does not exist.
    NotFound(&'static str),
    /// The request conflicts with existing state.
    Conflict(String),
    /// The request was malformed or violates a business rule.
    InvalidRequest(String),
    /// An internal failure.
    Internal(String),
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(kind) => write!(f, "{kind} not found"),
            Self::Conflict(message) => write!(f, "{message}"),
            Self::InvalidRequest(message) => write!(f, "{message}"),
            Self::Internal(message) => write!(f, "internal controller error: {message}"),
        }
    }
}

impl std::error::Error for ControllerError {}

impl From<zt_crypto::error::Error> for ControllerError {
    fn from(error: zt_crypto::error::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, ControllerError>;
