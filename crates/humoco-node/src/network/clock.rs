//! # Proof-Gate G4: Time, Slots & Reentry (Contract G4 / Spec 07, Spec 11)
//!
//! Architectural Invariants: INV-0701, INV-0704, INV-1203, INV-1206 (Decentralized Time & Slot Composition)
//!
//! - DECENTRALIZED MEDIAN TIME (net_time): Network time is derived strictly from the median of time
//!   offsets from trusted direct F2F friends (WoT gating, clamp |offset| <= 15m, strict monotonicity).
//!   Consensus paths NEVER query raw uncalibrated OS system time (INV-1202).
//! - ANTI-JUMP GUARD (INV-1203): Uncorroborated forward time jumps > 24h are rejected; TTL pruning
//!   is frozen until multi-peer consensus validates time advancement.
//! - ENTRY-ONLY WALLET FRESHNESS (DEC-061 / DEC-062): Wallet intent timestamps T0 are validated
//!   strictly upon ingress write admission (|T_entry - T0| <= 30s). Transport latency, fsync delays,
//!   or persistence queues NEVER invalidate an already-admitted transaction.
//! - ROOT TTL HORIZON & REENTRY: State validity is tied to root.valid_until + 30s grace window.
//!   Suspended nodes (3 missed hourly slots) must emit fresh sequence heartbeats and complete G2 shard
//!   recovery before resuming consensus voting.
//!
//! # Spec 11 (Section 7): P2P Network-Adjusted Time (`net_time`)
//!
//! Autonomous F2F median of time offsets from direct F2F peers with 3 security barriers:
//! 1. WoT Gating: Only heartbeats originating from `is_f2f_friend` may be incorporated.
//! 2. Clamping: `|time_offset| <= 15 minutes` (900_000 ms).
//! 3. Strict Monotonicity: `net_time = max(net_time, last_seen_time + 1 ms)`.

use std::collections::{HashMap, VecDeque};
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
    peer_samples: HashMap<[u8; 32], i64>,
    sample_order: VecDeque<[u8; 32]>,
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
                peer_samples: HashMap::with_capacity(MAX_ROLLING_SAMPLES),
                sample_order: VecDeque::with_capacity(MAX_ROLLING_SAMPLES),
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
        state.max_clamp_ms = state.max_clamp_ms.max(target_offset_ms.saturating_abs());
        state.logical_offset = target_offset_ms;
        state.peer_samples.clear();
        state.sample_order.clear();
        let reseed_key = [0xffu8; 32];
        state.peer_samples.insert(reseed_key, target_offset_ms);
        state.sample_order.push_back(reseed_key);
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

    /// Records a heartbeat time sample for an authenticated peer:
    /// `offset = t_peer_heartbeat - t_local_system_clock`.
    ///
    /// Security barriers:
    /// 1. WoT Gating: Discards samples immediately (`return false`) if `is_f2f_friend == false`.
    /// 2. 1-Sample per F2F Friend: Each direct friend has at most 1 active sample in the median pool (A11-01).
    /// 3. Overflow protection: Uses i128 difference and rejects out-of-domain offsets (A11-03).
    /// 4. Clamping: Keeps logical `time_offset` strictly within `[-max_clamp, max_clamp]`.
    pub fn record_sample_for_peer(
        &self,
        peer_pubkey: [u8; 32],
        is_f2f_friend: bool,
        peer_heartbeat_time_ms: u64,
        local_system_clock_ms: u64,
    ) -> bool {
        // Barrier 1: WoT Gating
        if !is_f2f_friend {
            return false;
        }

        // A11-03: Use i128 for raw offset calculation to avoid u64 as i64 overflow/wraparound
        let raw_offset: i128 =
            i128::from(peer_heartbeat_time_ms) - i128::from(local_system_clock_ms);

        let Ok(offset) = i64::try_from(raw_offset) else {
            return false;
        };

        // Reject extreme / out-of-domain offsets (e.g. > 365 days)
        const MAX_SANE_CLOCK_OFFSET_MS: i64 = 365 * 86_400_000;
        if offset.saturating_abs() > MAX_SANE_CLOCK_OFFSET_MS {
            return false;
        }

        let mut state = self.inner.write().unwrap_or_else(|e| e.into_inner());

        // A11-01: 1 vote per authenticated F2F friend
        if !state.peer_samples.contains_key(&peer_pubkey) {
            if state.peer_samples.len() >= MAX_ROLLING_SAMPLES {
                if let Some(oldest_peer) = state.sample_order.pop_front() {
                    state.peer_samples.remove(&oldest_peer);
                }
            }
            state.sample_order.push_back(peer_pubkey);
        } else {
            state.sample_order.retain(|k| k != &peer_pubkey);
            state.sample_order.push_back(peer_pubkey);
        }
        state.peer_samples.insert(peer_pubkey, offset);

        // Check if >= 10 samples are available
        if state.peer_samples.len() >= MIN_SAMPLES_FOR_MEDIAN {
            let samples: Vec<i64> = state.peer_samples.values().copied().collect();
            let offset_target = Self::calculate_median_from_slice(&samples);
            let clamp_limit = state.max_clamp_ms;

            // If |offset_target| > 45_000 ms, smoothly adjust logical time_offset
            if offset_target.saturating_abs() > CLOCK_SKEW_THRESHOLD_MS {
                tracing::warn!(
                    peer_offset_median_ms = offset_target,
                    threshold_ms = CLOCK_SKEW_THRESHOLD_MS,
                    "F2F clock skew exceeds 45s threshold — median damping applied"
                );
                let diff: i64 = offset_target.saturating_sub(state.logical_offset);
                let step = if diff.saturating_abs() <= 1_000 { diff } else { diff / 2 };
                let raw_offset = state.logical_offset.saturating_add(step);
                // Barrier 2: Clamping to max_clamp_ms (default: 15 minutes, or adapted on merge)
                state.logical_offset = raw_offset.clamp(-clamp_limit, clamp_limit);
                self.time_offset
                    .store(state.logical_offset, Ordering::Release);
            } else if state.logical_offset != 0 {
                // When peer clocks return within tolerance (<= 45s),
                // smoothly decay any existing offset back to 0.
                let diff: i64 = 0i64.saturating_sub(state.logical_offset);
                let step = if diff.saturating_abs() <= 1_000 { diff } else { diff / 2 };
                state.logical_offset =
                    (state.logical_offset.saturating_add(step)).clamp(-clamp_limit, clamp_limit);
                if state.logical_offset.saturating_abs() <= MAX_TIME_OFFSET_CLAMP_MS {
                    state.max_clamp_ms = MAX_TIME_OFFSET_CLAMP_MS;
                }
                self.time_offset
                    .store(state.logical_offset, Ordering::Release);
            }
        }

        true
    }

    /// Records a heartbeat time sample (assigns a unique synthetic peer ID for tests).
    pub fn record_sample(
        &self,
        is_f2f_friend: bool,
        peer_heartbeat_time_ms: u64,
        local_system_clock_ms: u64,
    ) -> bool {
        static SYNTHETIC_PEER_SEQ: AtomicU64 = AtomicU64::new(1);
        let id = SYNTHETIC_PEER_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut synthetic_peer = [0u8; 32];
        synthetic_peer[..8].copy_from_slice(&id.to_le_bytes());
        self.record_sample_for_peer(
            synthetic_peer,
            is_f2f_friend,
            peer_heartbeat_time_ms,
            local_system_clock_ms,
        )
    }

    /// Records a peer heartbeat for an authenticated F2F friend using the local physical clock.
    pub fn record_peer_heartbeat(
        &self,
        peer_pubkey: [u8; 32],
        is_f2f_friend: bool,
        peer_heartbeat_time_ms: u64,
    ) -> bool {
        let local_now = self.physical_now_ms();
        self.record_sample_for_peer(
            peer_pubkey,
            is_f2f_friend,
            peer_heartbeat_time_ms,
            local_now,
        )
    }

    /// Helper method to record a heartbeat using the current local physical clock.
    pub fn record_heartbeat(&self, is_f2f_friend: bool, peer_heartbeat_time_ms: u64) -> bool {
        let local_now = self.physical_now_ms();
        self.record_sample(is_f2f_friend, peer_heartbeat_time_ms, local_now)
    }

    /// Computes the median from a slice of samples
    pub fn calculate_median_from_slice(samples: &[i64]) -> i64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted: Vec<i64> = samples.to_vec();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            ((i128::from(sorted[mid - 1]) + i128::from(sorted[mid])) / 2) as i64
        } else {
            sorted[mid]
        }
    }

    /// Returns the number of samples currently stored in the ring buffer
    pub fn sample_count(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .peer_samples
            .len()
    }

    /// Returns true if at least MIN_SAMPLES_FOR_MEDIAN (>= 10) distinct peer samples are present
    pub fn has_quorum_samples(&self) -> bool {
        self.sample_count() >= MIN_SAMPLES_FOR_MEDIAN
    }

    /// Computes the current median offset of samples, if >= 10 samples are present
    pub fn current_median_offset(&self) -> Option<i64> {
        let state = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if state.peer_samples.len() >= MIN_SAMPLES_FOR_MEDIAN {
            let samples: Vec<i64> = state.peer_samples.values().copied().collect();
            Some(Self::calculate_median_from_slice(&samples))
        } else {
            None
        }
    }

    /// Returns true if a forward clock jump of `forward_jump_ms` is corroborated by the F2F network median offset.
    /// A11-02: If forward_jump_ms == 0, returns whether quorum samples are present.
    /// For forward_jump_ms > 0, ONLY a positive median offset can corroborate a forward jump.
    pub fn is_time_corroborated(&self, forward_jump_ms: u64) -> bool {
        if forward_jump_ms == 0 {
            return self.has_quorum_samples();
        }
        if let Some(median) = self.current_median_offset() {
            u64::try_from(median).is_ok_and(|pos_median| pos_median >= forward_jump_ms)
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
        if state.peer_samples.len() >= MIN_SAMPLES_FOR_MEDIAN {
            let samples: Vec<i64> = state.peer_samples.values().copied().collect();
            let offset_target = Self::calculate_median_from_slice(&samples);
            let target = if offset_target.saturating_abs() > CLOCK_SKEW_THRESHOLD_MS {
                offset_target
            } else {
                0
            };
            let diff: i64 = target.saturating_sub(state.logical_offset);
            let step = if diff.saturating_abs() <= 1_000 { diff } else { diff / 2 };
            let clamp_limit = state.max_clamp_ms;
            state.logical_offset =
                (state.logical_offset.saturating_add(step)).clamp(-clamp_limit, clamp_limit);
            if state.logical_offset.saturating_abs() <= MAX_TIME_OFFSET_CLAMP_MS {
                state.max_clamp_ms = MAX_TIME_OFFSET_CLAMP_MS;
            }
            self.time_offset
                .store(state.logical_offset, Ordering::Release);
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
        assert_eq!(
            clock.logical_offset_ms(),
            0,
            "No tracking before 10 samples"
        );

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

    #[test]
    fn test_a11_01_single_friend_cannot_inflate_quorum() {
        let clock = NetworkClock::new();
        let friend = [0x42u8; 32];
        let local_time = 1_000_000_000;

        // Same friend sends 20 heartbeats with varying timestamps
        for i in 0..20 {
            let accepted = clock.record_sample_for_peer(friend, true, local_time + 60_000 + i, local_time);
            assert!(accepted);
        }

        // Even though 20 heartbeats were sent, they all belong to 1 peer:
        assert_eq!(clock.sample_count(), 1, "1 friend must only occupy 1 sample slot");
        assert!(!clock.has_quorum_samples(), "1 friend must never establish quorum");
        assert_eq!(clock.current_median_offset(), None);
        assert_eq!(clock.logical_offset_ms(), 0);

        // Now add 9 other distinct friends
        for i in 1..10 {
            let mut other_friend = [0x55u8; 32];
            other_friend[0] = i as u8;
            clock.record_sample_for_peer(other_friend, true, local_time + 60_000, local_time);
        }

        // Now we have 10 distinct friends -> Quorum reached!
        assert_eq!(clock.sample_count(), 10);
        assert!(clock.has_quorum_samples());
        assert_eq!(clock.current_median_offset(), Some(60_000));
    }

    #[test]
    fn test_a11_02_directional_forward_jump_corroboration() {
        let clock = NetworkClock::new();
        let local_time = 1_000_000_000;

        // Quorum check with 0 jump: false when empty
        assert!(!clock.is_time_corroborated(0));

        // Add 10 peers with strong NEGATIVE offset (-100_000_000 ms, peers in past)
        for i in 0..10 {
            let mut friend = [0x11u8; 32];
            friend[0] = i as u8;
            clock.record_sample_for_peer(friend, true, local_time - 100_000_000, local_time);
        }

        assert!(clock.has_quorum_samples());
        assert!(clock.is_time_corroborated(0));
        assert_eq!(clock.current_median_offset(), Some(-100_000_000));

        // A negative median must NEVER corroborate a positive forward jump (+86_400_000 ms)!
        assert!(
            !clock.is_time_corroborated(86_400_000),
            "Negative median must NEVER corroborate a forward jump >24h"
        );

        // Reset with 10 peers with POSITIVE offset (+90_000_000 ms)
        let clock_pos = NetworkClock::new();
        for i in 0..10 {
            let mut friend = [0x22u8; 32];
            friend[0] = i as u8;
            clock_pos.record_sample_for_peer(friend, true, local_time + 90_000_000, local_time);
        }
        assert_eq!(clock_pos.current_median_offset(), Some(90_000_000));
        assert!(
            clock_pos.is_time_corroborated(86_400_000),
            "Positive median >= 86_400_000 must corroborate the forward jump"
        );
        assert!(
            !clock_pos.is_time_corroborated(100_000_000),
            "Forward jump greater than positive median must be rejected"
        );
    }

    #[test]
    fn test_a11_03_extreme_timestamp_arithmetic_overflow_safety() {
        let clock = NetworkClock::new();
        let local_time = 1_700_000_000_000u64;

        // 1. Extreme timestamp: 1 << 63
        let extreme_1 = 1u64 << 63;
        let accepted = clock.record_sample(true, extreme_1, local_time);
        assert!(!accepted, "Extreme timestamp 1 << 63 must be rejected cleanly without panic");

        // 2. u64::MAX
        let extreme_max = u64::MAX;
        let accepted_max = clock.record_sample(true, extreme_max, local_time);
        assert!(!accepted_max, "u64::MAX timestamp must be rejected cleanly without panic");

        // 3. calculate_median_from_slice with extreme values that would overflow i64 on addition
        let samples = vec![i64::MAX - 10, i64::MAX - 2];
        let median = NetworkClock::calculate_median_from_slice(&samples);
        assert_eq!(median, i64::MAX - 6);

        let samples_min = vec![i64::MIN + 2, i64::MIN + 10];
        let median_min = NetworkClock::calculate_median_from_slice(&samples_min);
        assert_eq!(median_min, i64::MIN + 6);
    }
}
