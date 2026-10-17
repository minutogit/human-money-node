#![forbid(unsafe_code)]

//! CEH In-Flight Write Barrier and Atomic Draining Mechanism.
//!
//! Provides a race-free write barrier that transitions through two stages:
//! 1. `Stage 1 (FENCE_DRAIN)`: New ingress writes are rejected (HTTP 503 Retry-After: 2).
//!    In-flight tasks that have already initiated storage writes continue to completion.
//! 2. `Stage 2 (FENCE_LOCKED)`: All in-flight operations have completed (`active_in_flight_writes == 0`).
//!    The state is frozen and synchronous WAL flushes occur to calculate `closed_state_root`.
//!
//! Non-Revocation Invariant:
//! Any in-flight operation that has already durably stored a choice or emitted a signature
//! over the wire is never cancelled or rolled back. The write counter decrements strictly upon
//! task exit.

use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;

/// Current stage of the write barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BarrierStage {
    /// Ingress writes are accepted normally.
    Open = 0,
    /// New ingress writes are rejected (503). Awaiting completion of in-flight operations.
    FenceDrain = 1,
    /// All in-flight writes have completed (active_in_flight_writes == 0). State is frozen.
    FenceLocked = 2,
}

impl BarrierStage {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Open,
            1 => Self::FenceDrain,
            2 => Self::FenceLocked,
            _ => Self::FenceLocked,
        }
    }
}

/// Errors returned by the write barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierError {
    /// Barrier is in FENCE_DRAIN stage; client should retry later (HTTP 503).
    Draining { retry_after_secs: u32 },
    /// Barrier is locked; epoch handoff snapshot in progress or completed.
    Locked,
    /// In-flight writes are still draining; cannot transition to FENCE_LOCKED.
    DrainPending { remaining_in_flight: u32 },
}

impl std::fmt::Display for BarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draining { retry_after_secs } => {
                write!(f, "barrier draining, retry after {retry_after_secs}s")
            }
            Self::Locked => write!(f, "barrier locked"),
            Self::DrainPending { remaining_in_flight } => {
                write!(f, "drain pending, {remaining_in_flight} writes remaining")
            }
        }
    }
}

impl std::error::Error for BarrierError {}

/// RAII Guard tracking an active in-flight write operation.
///
/// Automatically decrements the active write counter on drop, ensuring
/// that even panicked or aborted tasks update the in-flight accounting safely.
#[derive(Debug)]
pub struct WriteGuard {
    tracker: Arc<BarrierInner>,
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        self.tracker.active_in_flight_writes.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct BarrierInner {
    stage: AtomicU8,
    active_in_flight_writes: AtomicU32,
}

/// Shared In-Flight Write Barrier for a shard or node.
#[derive(Clone, Debug)]
pub struct WriteBarrier {
    inner: Arc<BarrierInner>,
}

impl Default for WriteBarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteBarrier {
    /// Creates a new open write barrier.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(BarrierInner {
                stage: AtomicU8::new(BarrierStage::Open as u8),
                active_in_flight_writes: AtomicU32::new(0),
            }),
        }
    }

    /// Returns the current stage of the barrier.
    pub fn stage(&self) -> BarrierStage {
        BarrierStage::from_u8(self.inner.stage.load(Ordering::SeqCst))
    }

    /// Returns the number of currently in-flight write operations.
    pub fn active_in_flight_writes(&self) -> u32 {
        self.inner.active_in_flight_writes.load(Ordering::SeqCst)
    }

    /// Attempts to acquire permission for a new write operation.
    ///
    /// Returns a `WriteGuard` if the barrier is `Open`.
    /// Returns `Err(BarrierError::Draining)` if `FenceDrain`.
    /// Returns `Err(BarrierError::Locked)` if `FenceLocked`.
    pub fn acquire_write(&self) -> Result<WriteGuard, BarrierError> {
        let stage = self.stage();
        match stage {
            BarrierStage::Open => {
                // Speculatively increment active write counter
                self.inner.active_in_flight_writes.fetch_add(1, Ordering::SeqCst);
                // Re-check stage to prevent race with begin_drain
                if self.stage() != BarrierStage::Open {
                    // Undo speculation and reject
                    self.inner.active_in_flight_writes.fetch_sub(1, Ordering::SeqCst);
                    return Err(BarrierError::Draining { retry_after_secs: 2 });
                }
                Ok(WriteGuard {
                    tracker: Arc::clone(&self.inner),
                })
            }
            BarrierStage::FenceDrain => Err(BarrierError::Draining { retry_after_secs: 2 }),
            BarrierStage::FenceLocked => Err(BarrierError::Locked),
        }
    }

    /// Stage 1: Initiates the drain barrier (`FENCE_DRAIN`).
    ///
    /// New writes are rejected immediately. In-flight tasks continue until completion.
    pub fn begin_drain(&self) {
        self.inner.stage.store(BarrierStage::FenceDrain as u8, Ordering::SeqCst);
    }

    /// Checks if all in-flight operations have completely drained.
    pub fn is_drained(&self) -> bool {
        self.stage() == BarrierStage::FenceDrain
            && self.inner.active_in_flight_writes.load(Ordering::SeqCst) == 0
    }

    /// Stage 2: Locks the barrier (`FENCE_LOCKED`) once all in-flight writes have finished.
    ///
    /// Fails with `BarrierError::DrainPending` if any write is still active.
    pub fn lock(&self) -> Result<(), BarrierError> {
        let active = self.inner.active_in_flight_writes.load(Ordering::SeqCst);
        if active > 0 {
            return Err(BarrierError::DrainPending {
                remaining_in_flight: active,
            });
        }
        self.inner.stage.store(BarrierStage::FenceLocked as u8, Ordering::SeqCst);
        Ok(())
    }

    /// Reopens the barrier for normal operations (e.g., after epoch handoff completes).
    pub fn reopen(&self) {
        self.inner.stage.store(BarrierStage::Open as u8, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrier_open_acquire_and_drop() {
        let barrier = WriteBarrier::new();
        assert_eq!(barrier.stage(), BarrierStage::Open);
        assert_eq!(barrier.active_in_flight_writes(), 0);

        let guard1 = barrier.acquire_write().expect("should acquire");
        assert_eq!(barrier.active_in_flight_writes(), 1);

        {
            let _guard2 = barrier.acquire_write().expect("should acquire");
            assert_eq!(barrier.active_in_flight_writes(), 2);
        }
        assert_eq!(barrier.active_in_flight_writes(), 1);

        drop(guard1);
        assert_eq!(barrier.active_in_flight_writes(), 0);
    }

    #[test]
    fn test_barrier_drain_rejects_new_and_completes_in_flight() {
        let barrier = WriteBarrier::new();
        let guard = barrier.acquire_write().expect("acquire 1");
        assert_eq!(barrier.active_in_flight_writes(), 1);

        // Begin drain
        barrier.begin_drain();
        assert_eq!(barrier.stage(), BarrierStage::FenceDrain);
        assert!(!barrier.is_drained());

        // New acquire must be rejected with 503 Draining
        let err = barrier.acquire_write().expect_err("must fail");
        assert_eq!(err, BarrierError::Draining { retry_after_secs: 2 });

        // Cannot lock while 1 in-flight
        let lock_err = barrier.lock().expect_err("cannot lock yet");
        assert_eq!(
            lock_err,
            BarrierError::DrainPending {
                remaining_in_flight: 1
            }
        );

        // Drop in-flight guard
        drop(guard);
        assert_eq!(barrier.active_in_flight_writes(), 0);
        assert!(barrier.is_drained());

        // Now lock succeeds
        barrier.lock().expect("lock must succeed");
        assert_eq!(barrier.stage(), BarrierStage::FenceLocked);

        // After lock, acquire returns Locked
        let locked_err = barrier.acquire_write().expect_err("must fail locked");
        assert_eq!(locked_err, BarrierError::Locked);
    }
}
