//! # Spec 11 (Section 7): P2P Network-Adjusted Time (`net_time`)
//!
//! Autonomous F2F median of time offsets from direct F2F peers with 3 security barriers:
//! 1. WoT Gating: Only heartbeats originating from `is_f2f_friend` may be incorporated.
//! 2. Clamping: `|time_offset| <= 15 minutes` (900_000 ms).
//! 3. Strict Monotonicity: `net_time = max(net_time, last_seen_time + 1 ms)`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Minimum number of F2F samples required to compute median target (Spec 11: >= 10 samples)
pub const MIN_SAMPLES_FOR_MEDIAN: usize = 10;

/// Threshold for safe local clock drift (45 seconds = 45,000 ms)
pub const CLOCK_SKEW_THRESHOLD_MS: i64 = 45_000;

/// Maximum default allowed logical time offset (15 minutes = 900.000 ms)
pub const MAX_TIME_OFFSET_CLAMP_MS: i64 = 15 * 60 * 1000;

/// Maximum number of rolling samples in ring buffer
pub const MAX_ROLLING_SAMPLES: usize = 128;

#[derive(Debug, Clone)]
struct ClockState {
    samples: VecDeque<i64>,
    logical_offset: i64,
    /// Maximum allowed logical time offset clamp (default: 15 min, dynamically adapted on mesh merges)
    max_clamp_ms: i64,
}

/// Thread-safe P2P network clock for median-adjusted timekeeping in the mesh
#[derive(Debug)]
pub struct NetworkClock {
    inner: RwLock<ClockState>,
    /// Base physical epoch timestamp in ms recorded at clock creation
    base_epoch_ms: u64,
    /// Monotonic instant recorded at clock creation
    base_instant: Instant,
    /// Current logical time offset in milliseconds (lock-free on the hot path)
    time_offset: AtomicI64,
    /// Highest net_time timestamp issued so far for strict monotonicity (never moves backward, lock-free)
    last_net_time: AtomicU64,
    /// Atomic sequence counter for sequence tie-breaking without inflating physical consensus time
    sequence_counter: AtomicU64,
}

/// Canonical alias for NetworkClock
pub type P2pClock = NetworkClock;

impl Default for NetworkClock {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkClock {
    pub fn new() -> Self {
        let initial_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            inner: RwLock::new(ClockState {
                samples: VecDeque::with_capacity(MAX_ROLLING_SAMPLES),
                logical_offset: 0,
                max_clamp_ms: MAX_TIME_OFFSET_CLAMP_MS,
            }),
            base_epoch_ms: initial_now,
            base_instant: Instant::now(),
            time_offset: AtomicI64::new(0),
            last_net_time: AtomicU64::new(initial_now),
            sequence_counter: AtomicU64::new(0),
        }
    }

    /// Returns the current adjusted network time in milliseconds (< 1µs, lock-free).
    /// Decoupled from query frequency: physical time is derived from monotonic elapsed time + median offset.
    /// Monotonicity guarantee: `net_time` is non-decreasing (never steps backward), but rapid successive calls
    /// within the same physical millisecond return the true physical time and do NOT artificially inflate consensus time.
    #[inline]
    pub fn net_time_ms(&self) -> u64 {
        let elapsed_ms = self.base_instant.elapsed().as_millis() as u64;
        let physical_now = self.base_epoch_ms.saturating_add(elapsed_ms);

        let offset = self.time_offset.load(Ordering::Relaxed);
        let candidate = if offset >= 0 {
            physical_now.saturating_add(offset as u64)
        } else {
            physical_now.saturating_sub((-offset) as u64)
        };

        // Monotonicity enforcement via CAS loop (lock-free):
        // If candidate <= last, returns last (no backward step, zero query-frequency inflation!)
        let mut last = self.last_net_time.load(Ordering::Relaxed);
        loop {
            if candidate <= last {
                return last;
            }
            match self.last_net_time.compare_exchange_weak(
                last,
                candidate,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return candidate,
                Err(actual) => last = actual,
            }
        }
    }

    /// Returns the current consensus time along with an atomic sequence counter for tie-breaking.
    /// Allows strict tie-breaking without inflating physical consensus time.
    #[inline]
    pub fn next_sequence_time_ms(&self) -> (u64, u64) {
        let time = self.net_time_ms();
        let seq = self.sequence_counter.fetch_add(1, Ordering::Relaxed);
        (time, seq)
    }

    /// Allows the clock to re-anchor and dynamically adapt when a network/mesh merge occurs.
    /// Relaxes or expands the 15-minute clamp to the merge offset so partitions separated
    /// for > 15 minutes can converge deterministically.
    pub fn fast_reseed_on_merge(&self, target_offset_ms: i64) {
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        state.max_clamp_ms = state.max_clamp_ms.max(target_offset_ms.abs());
        state.logical_offset = target_offset_ms;
        state.samples.clear();
        state.samples.push_back(target_offset_ms);
        self.time_offset.store(target_offset_ms, Ordering::Release);
        tracing::info!(
            target_offset_ms,
            clamp_ms = state.max_clamp_ms,
            "NetworkClock re-anchored on mesh merge: clamp dynamically adapted"
        );
    }

    /// Returns the current physical time in milliseconds derived from monotonic elapsed time.
    ///
    /// This method uses `base_epoch_ms + base_instant.elapsed()` instead of
    /// `SystemTime::now()` to avoid unanchored NTP step artifacts (Rule 2 & Spec 07).
    /// NTP corrections can cause the wall clock to jump forward or backward, which would
    /// corrupt the median offset calculation and potentially allow an attacker to manipulate
    /// consensus time. The monotonic `Instant` guarantees strictly forward progression.
    #[inline]
    pub fn physical_now_ms(&self) -> u64 {
        let elapsed_ms = self.base_instant.elapsed().as_millis() as u64;
        self.base_epoch_ms.saturating_add(elapsed_ms)
    }

    /// Records a heartbeat time sample:
    /// `offset = t_peer_heartbeat - t_local_system_clock`.
    /// 
    /// Security barriers:
    /// 1. WoT Gating: Discards samples immediately (`return false`) if `is_f2f_friend == false`.
    /// 2. Clamping: Keeps logical `time_offset` strictly within `[-max_clamp, max_clamp]`.
    pub fn record_sample(
        &self,
        is_f2f_friend: bool,
        peer_heartbeat_time_ms: u64,
        local_system_clock_ms: u64,
    ) -> bool {
        // Barrier 1: WoT Gating
        if !is_f2f_friend {
            return false;
        }

        let offset = peer_heartbeat_time_ms as i64 - local_system_clock_ms as i64;
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());

        if state.samples.len() >= MAX_ROLLING_SAMPLES {
            state.samples.pop_front();
        }
        state.samples.push_back(offset);

        // Check if >= 10 samples are available
        if state.samples.len() >= MIN_SAMPLES_FOR_MEDIAN {
            let offset_target = Self::calculate_median_from_slice(&state.samples);
            let clamp_limit = state.max_clamp_ms;

            // If |offset_target| > 45_000 ms, smoothly adjust logical time_offset
            if offset_target.abs() > CLOCK_SKEW_THRESHOLD_MS {
                tracing::warn!(
                    peer_offset_median_ms = offset_target,
                    threshold_ms = CLOCK_SKEW_THRESHOLD_MS,
                    "F2F clock skew exceeds 45s threshold — median damping applied"
                );
                let diff: i64 = offset_target - state.logical_offset;
                let step = if diff.abs() <= 1_000 {
                    diff
                } else {
                    diff / 2
                };
                let raw_offset = state.logical_offset + step;
                // Barrier 2: Clamping to max_clamp_ms (default: 15 minutes, or adapted on merge)
                state.logical_offset = raw_offset.clamp(-clamp_limit, clamp_limit);
                self.time_offset.store(state.logical_offset, Ordering::Release);
            } else if state.logical_offset != 0 {
                // When peer clocks return within tolerance (<= 45s),
                // smoothly decay any existing offset back to 0.
                let diff: i64 = -state.logical_offset;
                let step = if diff.abs() <= 1_000 {
                    diff
                } else {
                    diff / 2
                };
                state.logical_offset = (state.logical_offset + step).clamp(-clamp_limit, clamp_limit);
                if state.logical_offset.abs() <= MAX_TIME_OFFSET_CLAMP_MS {
                    state.max_clamp_ms = MAX_TIME_OFFSET_CLAMP_MS;
                }
                self.time_offset.store(state.logical_offset, Ordering::Release);
            }
        }

        true
    }

    /// Helper method to record a heartbeat using the current local physical clock.
    ///
    /// Uses `self.physical_now_ms()` (monotonic elapsed time) instead of
    /// `SystemTime::now()` to avoid unanchored NTP step artifacts (Rule 2 & Spec 07).
    /// NTP corrections can cause the wall clock to jump forward or backward, which would
    /// corrupt the median offset calculation and potentially allow an attacker to manipulate
    /// consensus time. The monotonic `Instant` guarantees strictly forward progression.
    pub fn record_heartbeat(&self, is_f2f_friend: bool, peer_heartbeat_time_ms: u64) -> bool {
        let local_now = self.physical_now_ms();
        self.record_sample(is_f2f_friend, peer_heartbeat_time_ms, local_now)
    }

    /// Computes the median from a slice/VecDeque of samples
    pub fn calculate_median_from_slice(samples: &VecDeque<i64>) -> i64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted: Vec<i64> = samples.iter().copied().collect();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        }
    }

    /// Returns the number of samples currently stored in the ring buffer
    pub fn sample_count(&self) -> usize {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).samples.len()
    }

    /// Computes the current median offset of samples, if >= 10 samples are present
    pub fn current_median_offset(&self) -> Option<i64> {
        let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if state.samples.len() >= MIN_SAMPLES_FOR_MEDIAN {
            Some(Self::calculate_median_from_slice(&state.samples))
        } else {
            None
        }
    }

    /// Returns true if a forward clock jump of `jump_ms` is corroborated by the F2F network median offset.
    pub fn is_time_corroborated(&self, jump_ms: u64) -> bool {
        if let Some(median) = self.current_median_offset() {
            let median_abs = median.unsigned_abs();
            median_abs >= jump_ms
        } else {
            false
        }
    }

    /// Returns the current logical offset in milliseconds
    pub fn logical_offset_ms(&self) -> i64 {
        self.time_offset.load(Ordering::Relaxed)
    }

    /// Returns the last issued `net_time` in milliseconds (monotonic anchor, lock-free).
    #[inline]
    pub fn last_net_time_ms(&self) -> u64 {
        self.last_net_time.load(Ordering::Relaxed)
    }

    /// Sets an offset directly (with clamping to current max clamp) for tests
    pub fn set_offset_for_testing(&self, offset_ms: i64) {
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let clamped = offset_ms.clamp(-state.max_clamp_ms, state.max_clamp_ms);
        state.logical_offset = clamped;
        self.time_offset.store(clamped, Ordering::Release);
    }

    /// Performs an incremental adjustment step toward the median target
    pub fn step_adjustment(&self) {
        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if state.samples.len() >= MIN_SAMPLES_FOR_MEDIAN {
            let offset_target = Self::calculate_median_from_slice(&state.samples);
            let target = if offset_target.abs() > CLOCK_SKEW_THRESHOLD_MS {
                offset_target
            } else {
                0
            };
            let diff: i64 = target - state.logical_offset;
            let step = if diff.abs() <= 1_000 {
                diff
            } else {
                diff / 2
            };
            let clamp_limit = state.max_clamp_ms;
            state.logical_offset = (state.logical_offset + step).clamp(-clamp_limit, clamp_limit);
            if state.logical_offset.abs() <= MAX_TIME_OFFSET_CLAMP_MS {
                state.max_clamp_ms = MAX_TIME_OFFSET_CLAMP_MS;
            }
            self.time_offset.store(state.logical_offset, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_wot_gating_rejects_non_f2f() {
        let clock = NetworkClock::new();
        let local_time = 1_000_000_000;
        let peer_time = 1_000_060_000; // +60s

        // Non-F2F sample must be strictly rejected
        let accepted = clock.record_sample(false, peer_time, local_time);
        assert!(!accepted, "Non-F2F sample must be rejected by WoT-gating");
        assert_eq!(clock.sample_count(), 0);
        assert_eq!(clock.logical_offset_ms(), 0);
        assert_eq!(clock.current_median_offset(), None);

        // F2F sample is accepted into rolling buffer
        let accepted = clock.record_sample(true, peer_time, local_time);
        assert!(accepted, "F2F sample must be accepted");
        assert_eq!(clock.sample_count(), 1);
    }

    #[test]
    fn test_clock_f2f_median_calculation_and_skew_threshold() {
        let clock = NetworkClock::new();
        let local_time = 1_000_000_000;

        // Feed 9 samples (< 10 threshold) with +60s
        for _ in 0..9 {
            clock.record_sample(true, local_time + 60_000, local_time);
        }
        assert_eq!(clock.sample_count(), 9);
        assert_eq!(clock.current_median_offset(), None);
        assert_eq!(clock.logical_offset_ms(), 0, "No tracking before 10 samples");

        // 10th sample triggers median calculation
        clock.record_sample(true, local_time + 60_000, local_time);
        assert_eq!(clock.sample_count(), 10);
        assert_eq!(clock.current_median_offset(), Some(60_000));
        // Since |60_000| > 45_000 ms, logical_offset must be updated toward 60_000
        assert!(clock.logical_offset_ms() > 0);
        assert!(clock.logical_offset_ms() <= 60_000);

        // Feed samples within normal tolerance (|skew| <= 45s)
        let clock_normal = NetworkClock::new();
        for _ in 0..15 {
            clock_normal.record_sample(true, local_time + 30_000, local_time);
        }
        assert_eq!(clock_normal.current_median_offset(), Some(30_000));
        assert_eq!(
            clock_normal.logical_offset_ms(),
            0,
            "Skew <= 45s must not trigger offset adjustment"
        );
    }

    #[test]
    fn test_clock_clamping_to_15_minutes() {
        let clock = NetworkClock::new();
        let local_time = 1_000_000_000;

        // Try extreme future offset (+2 hours = +7_200_000 ms)
        for _ in 0..20 {
            clock.record_sample(true, local_time + 7_200_000, local_time);
            clock.step_adjustment();
        }

        assert!(clock.logical_offset_ms() <= MAX_TIME_OFFSET_CLAMP_MS);
        assert_eq!(clock.logical_offset_ms(), 900_000); // exactly 15 min clamp

        // Direct test method must also clamp
        clock.set_offset_for_testing(10_000_000);
        assert_eq!(clock.logical_offset_ms(), 900_000);

        clock.set_offset_for_testing(-10_000_000);
        assert_eq!(clock.logical_offset_ms(), -900_000);
    }

    #[test]
    fn test_clock_strict_monotonicity_and_no_inflation() {
        let clock = NetworkClock::new();

        let mut prev = clock.net_time_ms();
        for _ in 0..10_000 {
            let next = clock.net_time_ms();
            assert!(
                next >= prev,
                "Monotonicity: next ({next}) must be >= prev ({prev})"
            );
            prev = next;
        }

        // Rapid queries in tight loop must NOT inflate physical consensus time
        let start = clock.net_time_ms();
        for _ in 0..20_000 {
            clock.net_time_ms();
        }
        let end = clock.net_time_ms();
        assert!(
            end.saturating_sub(start) < 500,
            "20,000 queries must not inflate time by seconds (elapsed was {} ms)",
            end - start
        );

        // Sequence counter provides strict ordering without inflating physical time
        let (t1, s1) = clock.next_sequence_time_ms();
        let (t2, s2) = clock.next_sequence_time_ms();
        assert!(t2 >= t1);
        assert_eq!(s2, s1 + 1);

        // Simulate local time jump backwards by setting negative offset
        clock.set_offset_for_testing(-900_000);
        let next_after_backwards_jump = clock.net_time_ms();
        assert!(
            next_after_backwards_jump >= prev,
            "Even after negative time warp, net_time must stay monotonic (never jump backwards)"
        );
    }

    #[test]
    fn test_clock_mesh_merge_dynamic_clamp() {
        let clock = NetworkClock::new();
        // Separated by 2 hours (+7_200_000 ms)
        let two_hours_ms = 2 * 3600 * 1000;
        clock.fast_reseed_on_merge(two_hours_ms);
        assert_eq!(clock.logical_offset_ms(), two_hours_ms);

        // Subsequent samples adjust within the expanded clamp
        clock.set_offset_for_testing(two_hours_ms + 10_000);
        assert_eq!(clock.logical_offset_ms(), two_hours_ms);
    }
}
