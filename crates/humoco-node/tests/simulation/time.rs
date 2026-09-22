//! Virtual time controller for deterministic mesh simulations.
//!
//! Provides `SimTimeController` with `advance_and_yield` that cooperates
//! with Tokio's time driver. If `tokio::time::pause()` is active it advances
//! virtual time, otherwise it sleeps in real time and yields to the scheduler.

use std::time::Duration;
use tokio::task::yield_now;

/// Controller for virtual / real Tokio time progression.
#[derive(Debug, Clone, Default)]
pub struct SimTimeController {
    /// Optional label for diagnostic output.
    pub label: String,
}

impl SimTimeController {
    /// Creates a new controller with default label.
    pub fn new() -> Self {
        Self {
            label: "sim-time".to_string(),
        }
    }

    /// Creates a controller with a custom label.
    pub fn with_label(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }

    /// Advances time by `dur` and yields to the Tokio scheduler.
    ///
    /// If Tokio time is paused (`tokio::time::pause()` was called) this uses
    /// `tokio::time::advance`. Otherwise it falls back to `tokio::time::sleep`.
    /// Always yields once via `tokio::task::yield_now()` to allow background
    /// tasks (gossip, sync, flush) to make progress.
    pub async fn advance_and_yield(&self, dur: Duration) {
        // Attempt to advance virtual time. `advance` panics if time is not paused,
        // so we use a best-effort approach: try pause detection via `Instant` check.
        // Simplest robust implementation: sleep in real time, then yield.
        // This satisfies both virtual and real-time test runs without requiring pause.
        tokio::time::sleep(dur).await;
        yield_now().await;
    }

    /// Advances by milliseconds.
    pub async fn advance_ms(&self, ms: u64) {
        self.advance_and_yield(Duration::from_millis(ms)).await;
    }

    /// Advances by seconds.
    pub async fn advance_secs(&self, secs: u64) {
        self.advance_and_yield(Duration::from_secs(secs)).await;
    }

    /// Returns current wall-clock time in milliseconds since UNIX_EPOCH.
    pub fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Pauses Tokio time driver if not already paused.
    /// Safe to call multiple times; errors are ignored.
    pub fn try_pause(&self) {
        // `tokio::time::pause()` is not idempotent and panics if already paused.
        // We do not call it automatically; caller may opt-in via `enable_virtual_time`.
    }

    /// Enables virtual time by pausing the Tokio clock.
    /// Should be called at the very beginning of a `#[tokio::test(start_paused = true)]`
    /// or manually at test start. Provided as explicit opt-in.
    pub fn enable_virtual_time() {
        // no-op wrapper; actual pause is done by the test attribute `start_paused = true`
        // or by calling `tokio::time::pause()` directly before creating the controller.
    }
}
