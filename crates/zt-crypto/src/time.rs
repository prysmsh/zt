//! Wall-clock time.
//!
//! The protocol needs the current Unix time in seconds to check credential
//! expiry. The clock lives here so that the crypto crate does not depend on
//! the controller or the agent.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current Unix time in seconds.
///
/// Returns zero if the system clock is before the Unix epoch, which would
/// only happen on a badly misconfigured host. A zero timestamp makes
/// credentials look expired, which fails closed.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_is_after_2020() {
        // A sanity check. If this fails, the clock is wrong, and every
        // credential in the system is about to be misjudged.
        assert!(now_unix() > 1_577_836_800);
    }
}
