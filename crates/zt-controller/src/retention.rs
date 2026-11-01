//! Retention: what the control plane keeps, and for how long.
//!
//! Soft deletion keeps a tenant's data so a mistake can be corrected. A
//! separate job purges it later. The usage samples are the raw material
//! for an invoice, so they are kept for the period an invoice might be
//! disputed and pruned after that.

use std::sync::Arc;

use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::store::Store;

/// How long a soft-deleted tenant's data is kept.
const TENANT_RETENTION: u64 = 90 * 86_400;

/// How long usage samples are kept.
///
/// The samples feed an invoice for the period they cover. Once a period
/// is closed and the invoice issued, the samples behind it are not worth
/// the storage.
const SAMPLE_RETENTION: u64 = 400 * 86_400;

/// How often the retention job runs.
const RUN_EVERY: u64 = 6 * 60 * 60;

/// The retention policy the controller applies.
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    /// How long a soft-deleted tenant's data is kept, in seconds.
    pub tenant_retention: u64,
    /// How long usage samples are kept, in seconds.
    pub sample_retention: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            tenant_retention: TENANT_RETENTION,
            sample_retention: SAMPLE_RETENTION,
        }
    }
}

impl Retention {
    /// The time before `now` that the retention horizon sits at.
    pub fn before(&self, now: u64) -> u64 {
        now.saturating_sub(self.sample_retention.min(self.tenant_retention))
    }
}

/// Prune what the retention policy says to prune, and report the counts.
pub async fn run(store: &Arc<dyn Store>, policy: &Retention, now: u64) -> usize {
    let tenants = store
        .purge_deleted_tenants(now.saturating_sub(policy.tenant_retention) as i64)
        .unwrap_or(0);
    store
        .prune_usage_samples(now.saturating_sub(policy.sample_retention) as i64)
        .unwrap_or(());

    tenants
}

/// Run the retention job on a timer, forever.
///
/// A failure to prune is not fatal: the job logs it and runs again on the
/// next tick.
pub async fn run_forever(store: Arc<dyn Store>, policy: Retention) {
    let mut timer = interval(Duration::from_secs(RUN_EVERY));
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        timer.tick().await;
        let now = now_unix();
        let purged = run(&store, &policy, now).await;
        if purged > 0 {
            tracing::info!(purged, "retention pruned");
        }
    }
}

/// The current Unix time in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
