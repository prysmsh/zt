//! Error types for the `zt-crypto` crate.

use core::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by cryptographic operations.
///
/// These deliberately avoid carrying secret material in their payloads: an
/// `Error` is safe to log, serialize, and send over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A key was structurally invalid (wrong length, malformed point).
    InvalidKey(&'static str),
    /// A nonce was reused for the same key. This is always a bug in the caller.
    NonceReuse,
    /// Authentication tag verification failed.
    AuthenticationFailed,
    /// A ciphertext or plaintext was longer than the cipher allows.
    InvalidLength,
    /// HKDF expansion was asked for more output than the limit permits.
    InvalidHkdfLength,
    /// Underlying RNG failure.
    RandomFailed(&'static str),
    /// A signature was structurally malformed.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey(why) => write!(f, "invalid key: {why}"),
            Error::NonceReuse => write!(f, "nonce reused with the same key"),
            Error::AuthenticationFailed => write!(f, "authentication failed"),
            Error::InvalidLength => write!(f, "invalid message length"),
            Error::InvalidHkdfLength => write!(f, "invalid HKDF output length"),
            Error::RandomFailed(why) => write!(f, "random generation failed: {why}"),
            Error::InvalidSignature => write!(f, "malformed signature"),
        }
    }
}

impl std::error::Error for Error {}
