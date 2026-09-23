//! # Spec 09: Netzwerk-Thermometer, Byte-Jahre & Dynamische Quotas
//!
//! This module implements the physical currency of **Byte-Years** (storage-time product),
//! decentralized **quartile sampling**, the **28-day slotted ring buffer** for median smoothing,
//! the **Zipf spread damper**, and the **deterministic 2-stage quota model with whale brake**.

use crate::types::NodeId;
use std::collections::HashMap;

/// Exact size of a `StoredLock` in shard RAM (144B wire + 32B canon hash + 8B TTL + 8B padding)
pub const STORED_LOCK_BYTES: u64 = 192;

/// Standard seconds per calendar year (365 days)
pub const SECONDS_PER_YEAR: u64 = 31_536_000;

/// Non-undercuttable hard-floor baseline: 960,000 Byte-Years / day
/// Guarantees every node at least 1,000 five-year locks or 5,000 one-year locks per day.
pub const HARD_FLOOR_BASELINE_DAILY: u64 = 960_000;

/// Non-undercuttable read hard-floor baseline: 50,000 reads / day (approx. 2,083 reads/h)
/// Since read operations are served toll-free from RAM and gateways distribute read load
/// stochastically across 20 shard nodes, this baseline guarantees sufficient buffer
/// for aggregating gateways and checkout-intensive applications.
pub const HARD_FLOOR_READ_BASELINE_DAILY: u64 = 50_000;
pub const READ_TO_WRITE_RATIO: u64 = 5;

/// Maximum whale brake (K <= 5.0)
pub const MAX_WHALE_MULTIPLIER: f64 = 5.0;

/// Standard multiplier for fully active nodes (status ACTIVE)
pub const STANDARD_K_MULTIPLIER: f64 = 1.0;

/// Sandbox multiplier for unconfirmed/sandbox nodes (5%)
pub const SANDBOX_K_MULTIPLIER: f64 = 0.05;

/// Helper functions for precise computation of the storage-time product (Byte-Years)
pub struct ByteYears;

impl ByteYears {
    /// Computes Byte-Years from TTL in seconds: (STORED_LOCK_BYTES * ttl_seconds) / SECONDS_PER_YEAR
    /// With commercial rounding (at least 1 Byte-Year).
    pub fn from_ttl_seconds(ttl_seconds: u64) -> u64 {
        if ttl_seconds == 0 {
            return 1;
        }
        let total_byte_seconds = (STORED_LOCK_BYTES as u128) * (ttl_seconds as u128);
        let byte_years = (total_byte_seconds + (SECONDS_PER_YEAR as u128 / 2)) / (SECONDS_PER_YEAR as u128);
        (byte_years as u64).max(1)
    }

    /// Computes Byte-Years from days
    pub fn from_ttl_days(days: u64) -> u64 {
        Self::from_ttl_seconds(days * 86_400)
    }

    /// Computes Byte-Years from years (e.g. 5.0 years = 960 Byte-Years)
    pub fn from_ttl_years(years: f64) -> u64 {
        let ttl_seconds = (years * (SECONDS_PER_YEAR as f64)).round() as u64;
        Self::from_ttl_seconds(ttl_seconds)
    }
}

/// Statistical quartile distribution (Q1, median/Q2, Q3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuartileStats {
    pub q1: u64,
    pub median: u64,
    pub q3: u64,
}

impl QuartileStats {
    /// Deterministically computes Q1 (25%), median (50%), and Q3 (75%)
    pub fn calculate(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self {
                q1: HARD_FLOOR_BASELINE_DAILY,
                median: HARD_FLOOR_BASELINE_DAILY,
                q3: HARD_FLOOR_BASELINE_DAILY,
            };
        }

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let n = sorted.len();

        let median = if n % 2 == 1 {
            sorted[n / 2]
        } else {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2
        };

        let q1 = sorted[n / 4];
        let q3 = sorted[(3 * n) / 4];

        Self { q1, median, q3 }
    }

    /// Computes the Zipf spread damper:
    /// Spread_Damper = max(0.5, min(1.0, (1.0 - (Q1 / Q3)) / 0.66))
    pub fn spread_damper(&self) -> f64 {
        if self.q3 == 0 || self.q1 >= self.q3 {
            return 0.5;
        }

        let ratio = self.q1 as f64 / self.q3 as f64;
        let damper = (1.0 - ratio) / 0.66;
        damper.clamp(0.5, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Shared ring-buffer helpers — eliminate repetitive array manipulation
// ---------------------------------------------------------------------------

#[inline]
fn filled_array<const N: usize>(val: u64) -> [u64; N] {
    [val; N]
}

#[inline]
fn slice_sum(slice: &[u64]) -> u128 {
    slice.iter().map(|&x| x as u128).sum()
}

#[inline]
fn array_sum<const N: usize>(arr: &[u64; N]) -> u128 {
    arr.iter().map(|&x| x as u128).sum()
}

fn seeded_epoch_hours(current_epoch_hour: u64) -> [u64; 24] {
    std::array::from_fn(|i| current_epoch_hour.saturating_sub((23 - i) as u64))
}

/// 28-day slotted ring buffer for sluggish median smoothing
#[derive(Clone, Debug)]
pub struct SlottedMedianRingBuffer {
    slots: [u64; 28],
    count: usize,
    write_idx: usize,
}

impl SlottedMedianRingBuffer {
    pub fn new() -> Self {
        Self {
            slots: filled_array(0),
            count: 0,
            write_idx: 0,
        }
    }

    /// Writes the daily median into the next 28-day slot
    pub fn push_daily_median(&mut self, daily_median: u64) {
        self.slots[self.write_idx] = daily_median;
        self.write_idx = (self.write_idx + 1) % 28;
        if self.count < 28 {
            self.count += 1;
        }
    }

    /// Initializes all 28 slots with a seed median and lower bound
    pub fn seed_with_floor(&mut self, seed_median: u64, floor: u64) {
        let eff_seed = seed_median.max(floor);
        self.slots = filled_array(eff_seed);
        self.count = 28;
        self.write_idx = 0;
    }

    /// [INV-0907] [INV-0908]
    /// Initializes all 28 slots with a seed median (e.g. on cold-start join
    /// into an existing large network or during fast re-seed on a network merge).
    pub fn seed(&mut self, seed_median: u64) {
        self.seed_with_floor(seed_median, HARD_FLOOR_BASELINE_DAILY);
    }

    /// Returns the rolling 28-day average, or None if no data is available yet
    pub fn moving_average(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let sum = slice_sum(&self.slots[..self.count]);
        Some((sum / self.count as u128) as u64)
    }

    /// Computes the rolling 28-day average of the median (fallback: HARD_FLOOR_BASELINE_DAILY)
    pub fn moving_average_median(&self) -> u64 {
        self.moving_average().unwrap_or(HARD_FLOOR_BASELINE_DAILY)
    }

    pub fn days_recorded(&self) -> usize {
        self.count
    }
}

impl Default for SlottedMedianRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// [Pillar B]
/// Computes the integer EMA (exponential moving average) with time-based linear decay:
/// - Overflow-safe via u128 and `saturating_sub` / `saturating_add`.
/// - When `delta_secs == 0`: no decay, only addition of the footprint.
/// - When `delta_secs >= 86_400`: old EMA decays completely to 0.
pub fn calculate_integer_ema(old_ema: u64, delta_secs: u64, footprint_micro_bj: u64) -> u64 {
    let elapsed = delta_secs.min(86_400) as u128;
    let decay_amount = ((old_ema as u128 * elapsed) / 86_400) as u64;
    old_ema.saturating_sub(decay_amount).saturating_add(footprint_micro_bj)
}

/// [Pillar C]
/// 24-hour slotted ring buffer for collecting hourly medians and rolling 24h values.
#[derive(Clone, Debug)]
pub struct HourlySlottedRingBuffer {
    slots: [u64; 24],
    epoch_hours: [u64; 24],
    count: usize,
    last_epoch_hour: u64,
}

impl HourlySlottedRingBuffer {
    pub fn new() -> Self {
        Self {
            slots: filled_array(0),
            epoch_hours: filled_array(0),
            count: 0,
            last_epoch_hour: 0,
        }
    }

    /// Records an hourly median.
    /// - Protection against NTP backward jumps: if `epoch_hour < self.last_epoch_hour`, ignore and do not update backwards.
    /// - Slot index: `(epoch_hour % 24) as usize`.
    /// - Writes `slots[idx] = median` and `epoch_hours[idx] = epoch_hour`.
    /// - Updates `self.last_epoch_hour = epoch_hour.max(self.last_epoch_hour)`.
    /// - Increments `count = (count + 1).min(24)`.
    pub fn record_hourly_median(&mut self, epoch_hour: u64, median: u64) {
        if self.count > 0 && epoch_hour < self.last_epoch_hour {
            return;
        }

        let idx = (epoch_hour % 24) as usize;
        self.slots[idx] = median;
        self.epoch_hours[idx] = epoch_hour;
        self.last_epoch_hour = epoch_hour.max(self.last_epoch_hour);
        self.count = (self.count + 1).min(24);
    }

    /// Sums all slots (via u128 to prevent overflow) and returns u64.
    /// Fallback when `count == 0`: 0.
    pub fn rolling_24h_sum(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let sum = array_sum(&self.slots);
        sum.min(u64::MAX as u128) as u64
    }

    /// Computes the rolling 24h average: `rolling_24h_sum() / count.max(1) as u64`.
    pub fn rolling_24h_average(&self) -> u64 {
        self.rolling_24h_sum() / (self.count.max(1) as u64)
    }

    /// Fills all 24 slots with the seed value for a clean cold start.
    pub fn seed_with_floor(&mut self, seed_hourly_median: u64, current_epoch_hour: u64) {
        self.slots = filled_array(seed_hourly_median);
        self.epoch_hours = seeded_epoch_hours(current_epoch_hour);
        self.count = 24;
        self.last_epoch_hour = current_epoch_hour;
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn last_epoch_hour(&self) -> u64 {
        self.last_epoch_hour
    }

    pub fn slots(&self) -> &[u64; 24] {
        &self.slots
    }

    pub fn epoch_hours(&self) -> &[u64; 24] {
        &self.epoch_hours
    }
}

impl Default for HourlySlottedRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// [INV-0909]
/// The 3-zone plausibility result for evaluating `429 QuotaExceeded` reports
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaPlausibilityVerdict {
    /// Zone 1: Clear fraud/laziness zone (< 75% of limit)
    /// Sender is far below the limit -> shard node wrongly refuses work -> malus +8!
    FraudulentRejection { malus_increment: u8 },
    /// Zone 2: Tolerant boundary band (75% to 125% of limit)
    /// Sender is near the limit -> shard node is an honest frontrunner at the limit -> no malus (0)!
    BoundaryCutoff { malus_increment: u8 },
    /// Zone 3: Genuine overload zone (> 125% of limit)
    /// Sender is far above the limit -> regular quota rejection -> no malus (0)!
    LegitimateOverload { malus_increment: u8 },
}

impl QuotaPlausibilityVerdict {
    pub fn malus(&self) -> u8 {
        match self {
            Self::FraudulentRejection { malus_increment } => *malus_increment,
            Self::BoundaryCutoff { malus_increment } => *malus_increment,
            Self::LegitimateOverload { malus_increment } => *malus_increment,
        }
    }
}

/// [INV-0909]
/// Evaluates a `429 QuotaExceeded` claim from a shard node against the locally measured sender volume:
/// - < 75% of limit: fraud / refusal to work (malus +8)
/// - 75% .. 125% of limit: tolerant boundary band / honest frontrunner (malus 0)
/// - > 125% of limit: genuine overload (malus 0)
pub fn evaluate_quota_exceeded_claim(sender_volume: u64, quota_limit: u64) -> QuotaPlausibilityVerdict {
    let lower_tolerance = (quota_limit as u128 * 75 / 100) as u64; // 75%
    let upper_tolerance = (quota_limit as u128 * 125 / 100) as u64; // 125%

    if sender_volume < lower_tolerance {
        QuotaPlausibilityVerdict::FraudulentRejection { malus_increment: 8 }
    } else if sender_volume <= upper_tolerance {
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    } else {
        QuotaPlausibilityVerdict::LegitimateOverload { malus_increment: 0 }
    }
}

/// Full decentralized network thermometer with quota enforcement
#[derive(Clone, Debug)]
pub struct NetworkThermometer {
    ring_buffer: SlottedMedianRingBuffer,
    read_ring_buffer: SlottedMedianRingBuffer,
    hourly_ring_buffer: HourlySlottedRingBuffer,
    current_epoch_day: u64,
    node_daily_usage: HashMap<NodeId, u64>,
    node_daily_read_usage: HashMap<NodeId, u64>,
}

impl NetworkThermometer {
    pub fn new() -> Self {
        Self {
            ring_buffer: SlottedMedianRingBuffer::new(),
            read_ring_buffer: SlottedMedianRingBuffer::new(),
            hourly_ring_buffer: HourlySlottedRingBuffer::new(),
            current_epoch_day: 0,
            node_daily_usage: HashMap::new(),
            node_daily_read_usage: HashMap::new(),
        }
    }

    /// [INV-0907]
    /// Initializes the thermometer of a new node with the current peer median
    pub fn seed_from_peers(&mut self, peer_median: u64) {
        self.ring_buffer.seed(peer_median);
    }

    /// [INV-0908]
    /// Fast re-seed on network merges (e.g. village A docks onto the global mesh)
    pub fn fast_reseed_on_merge(&mut self, global_median: u64) {
        self.ring_buffer.seed(global_median);
        self.read_ring_buffer.seed_with_floor(global_median / READ_TO_WRITE_RATIO, HARD_FLOOR_READ_BASELINE_DAILY);
    }

    /// Adds a daily median (called at the end of a day)
    pub fn record_daily_median(&mut self, median: u64) {
        self.ring_buffer.push_daily_median(median);
    }

    /// Adds a daily read median
    pub fn record_daily_read_median(&mut self, median: u64) {
        self.read_ring_buffer.push_daily_median(median);
    }

    /// Computes the effective reference value NCB_eff = max(Moving_Median, HARD_FLOOR_BASELINE_DAILY)
    pub fn effective_ncb(&self) -> u64 {
        let moving_median = self.ring_buffer.moving_average_median();
        moving_median.max(HARD_FLOOR_BASELINE_DAILY)
    }

    /// Computes the effective reference value NCB_read_eff = max(Moving_Read_Median, HARD_FLOOR_READ_BASELINE_DAILY)
    pub fn effective_read_ncb(&self) -> u64 {
        let moving_read_median = self.read_ring_buffer.moving_average().unwrap_or(HARD_FLOOR_READ_BASELINE_DAILY);
        moving_read_median.max(HARD_FLOOR_READ_BASELINE_DAILY)
    }

    /// Computes the daily quota for a node:
    /// Quota = NCB_eff * min(K, 5.0) * Spread_Damper
    pub fn calculate_daily_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        let ncb_eff = self.effective_ncb();
        let k = k_multiplier.clamp(0.0, MAX_WHALE_MULTIPLIER);
        let damper = spread_damper.clamp(0.5, 1.0);
        ((ncb_eff as f64) * k * damper).round() as u64
    }

    /// Computes the daily read quota for a node:
    /// Read_Quota = NCB_read_eff * min(K, 5.0) * Spread_Damper
    pub fn calculate_daily_read_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        let ncb_read_eff = self.effective_read_ncb();
        let k = k_multiplier.clamp(0.0, MAX_WHALE_MULTIPLIER);
        let damper = spread_damper.clamp(0.5, 1.0);
        ((ncb_read_eff as f64) * k * damper).round() as u64
    }

    /// Checks and registers a lock ingress for the node.
    /// Returns `true` if the lock is within the daily budget.
    /// Returns `false` if the budget is exceeded (silent dropping).
    pub fn try_accept_lock(
        &mut self,
        epoch_day: u64,
        node_id: NodeId,
        footprint_byte_years: u64,
        quota_byte_years: u64,
    ) -> bool {
        // Epoch change: on a new day, clear the daily usage register
        if epoch_day > self.current_epoch_day {
            self.current_epoch_day = epoch_day;
            self.node_daily_usage.clear();
            self.node_daily_read_usage.clear();
        }

        let current_usage = self.node_daily_usage.entry(node_id).or_insert(0);
        if let Some(new_usage) = current_usage.checked_add(footprint_byte_years) {
            if new_usage <= quota_byte_years {
                *current_usage = new_usage;
                true
            } else {
                // Quota exceeded -> silent dropping
                false
            }
        } else {
            false
        }
    }

    /// Checks and registers a read ingress for the node.
    /// Returns `true` if the read is within the daily budget.
    /// Returns `false` if the budget is exceeded (silent dropping).
    pub fn try_accept_read(
        &mut self,
        epoch_day: u64,
        node_id: NodeId,
        credits: u64,
        quota: u64,
    ) -> bool {
        // Epoch change: on a new day, clear the daily usage register
        if epoch_day > self.current_epoch_day {
            self.current_epoch_day = epoch_day;
            self.node_daily_usage.clear();
            self.node_daily_read_usage.clear();
        }

        let current_usage = self.node_daily_read_usage.entry(node_id).or_insert(0);
        if let Some(new_usage) = current_usage.checked_add(credits) {
            if new_usage <= quota {
                *current_usage = new_usage;
                true
            } else {
                // Quota exceeded -> silent dropping
                false
            }
        } else {
            false
        }
    }

    /// Returns the current daily usage of a node
    pub fn get_node_usage(&self, node_id: NodeId) -> u64 {
        self.node_daily_usage.get(&node_id).copied().unwrap_or(0)
    }

    /// Returns the current daily read usage of a node
    pub fn get_node_read_usage(&self, node_id: NodeId) -> u64 {
        self.node_daily_read_usage.get(&node_id).copied().unwrap_or(0)
    }

    /// Initializes the read thermometer of a new node with the current peer read median
    pub fn seed_read_from_peers(&mut self, peer_median: u64) {
        self.read_ring_buffer.seed_with_floor(peer_median, HARD_FLOOR_READ_BASELINE_DAILY);
    }

    /// Fast re-seed for the read thermometer on network merge
    pub fn fast_reseed_read_on_merge(&mut self, global_median: u64) {
        self.read_ring_buffer.seed_with_floor(global_median / READ_TO_WRITE_RATIO, HARD_FLOOR_READ_BASELINE_DAILY);
    }

    /// Computes sync read credits based on the number of locks:
    /// StatusQuery = 1, Sync = 1 + Locks/10 (0 locks = 1 credit; 1..10 = 2 credits, 11..20 = 3 credits)
    pub fn calculate_sync_read_credits(locks_count: usize) -> u64 {
        if locks_count == 0 {
            1
        } else {
            1 + (locks_count as u64).div_ceil(10)
        }
    }

    /// [Pillar C]
    /// Registers an hourly median in the rolling 24-hour ring buffer
    pub fn record_hourly_median(&mut self, epoch_hour: u64, median: u64) {
        self.hourly_ring_buffer.record_hourly_median(epoch_hour, median);
    }

    /// [Pillar C]
    /// Returns a reference to the hourly 24h ring buffer
    pub fn hourly_buffer(&self) -> &HourlySlottedRingBuffer {
        &self.hourly_ring_buffer
    }

    /// [Pillar C]
    /// Returns a mutable reference to the hourly 24h ring buffer
    pub fn hourly_buffer_mut(&mut self) -> &mut HourlySlottedRingBuffer {
        &mut self.hourly_ring_buffer
    }

    /// [Pillar C]
    /// Computes the current rolling 24h average from the hourly ring buffer
    pub fn rolling_24h_average(&self) -> u64 {
        self.hourly_ring_buffer.rolling_24h_average()
    }
}

impl Default for NetworkThermometer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_years_calculation() {
        // 5 Jahre = 960 Byte-Jahre
        let by_5y = ByteYears::from_ttl_years(5.0);
        assert_eq!(by_5y, 960);

        // 1 Jahr = 192 Byte-Jahre
        let by_1y = ByteYears::from_ttl_years(1.0);
        assert_eq!(by_1y, 192);

        // 30 Tage (~1 Monat) = 16 Byte-Jahre
        let by_30d = ByteYears::from_ttl_days(30);
        assert_eq!(by_30d, 16);
    }

    #[test]
    fn test_quartiles_and_damper() {
        let samples = vec![100, 200, 300, 400, 500, 600, 700, 800];
        let stats = QuartileStats::calculate(&samples);
        assert_eq!(stats.median, 450);
        assert_eq!(stats.q1, 300);
        assert_eq!(stats.q3, 700);

        // Spread Damper
        let damper = stats.spread_damper();
        assert!((0.5..=1.0).contains(&damper));
    }

    #[test]
    fn test_integer_ema_time_decay() {
        let old_ema = 100_000u64;

        // delta = 0: Kein Decay, nur Addition des Footprints
        let ema_delta_0 = calculate_integer_ema(old_ema, 0, 5_000);
        assert_eq!(ema_delta_0, 105_000);

        // delta = 43_200 (Halbierung von 86_400s)
        // decay = (100_000 * 43_200) / 86_400 = 50_000
        // rest = 50_000 + 10_000 = 60_000
        let ema_delta_half = calculate_integer_ema(old_ema, 43_200, 10_000);
        assert_eq!(ema_delta_half, 60_000);

        // delta = 86,400: old EMA decays completely to 0
        // decay = (100,000 * 86,400) / 86,400 = 100,000
        // rest = 0 + 7,000 = 7,000
        let ema_delta_day = calculate_integer_ema(old_ema, 86_400, 7_000);
        assert_eq!(ema_delta_day, 7_000);

        // delta > 86,400: old EMA decays completely to 0
        let ema_delta_more = calculate_integer_ema(old_ema, 100_000, 8_000);
        assert_eq!(ema_delta_more, 8_000);
    }

    #[test]
    fn test_integer_ema_u128_overflow_safety() {
        // Test with values near u64::MAX
        let old_ema = u64::MAX;
        let delta_secs = 10;
        let footprint = 500_000;
        // At u64::MAX a small part decays; saturating_add protects against overflow
        let ema = calculate_integer_ema(old_ema, delta_secs, footprint);
        assert!(ema > 0);

        // If old_ema = u64::MAX and delta = 0, saturating_add stays at u64::MAX
        let ema_max = calculate_integer_ema(u64::MAX, 0, 1_000);
        assert_eq!(ema_max, u64::MAX);

        // Large footprint
        let ema_large_footprint = calculate_integer_ema(1_000_000, 86_400, u64::MAX);
        assert_eq!(ema_large_footprint, u64::MAX);
    }

    #[test]
    fn test_hourly_slotted_ring_buffer_rolling_sum() {
        let mut buffer = HourlySlottedRingBuffer::new();
        assert_eq!(buffer.rolling_24h_sum(), 0);
        assert_eq!(buffer.rolling_24h_average(), 0);
        assert_eq!(buffer.count(), 0);

        // 72 simulated hours, each hour records (h + 1) * 1000
        for h in 0..72 {
            let val = (h + 1) * 1_000;
            buffer.record_hourly_median(h, val);
        }

        assert_eq!(buffer.count(), 24);

        // The last 24 hours are h = 48..72 (i.e. 48 to 71)
        // Values: (49..=72) * 1,000
        let expected_sum: u64 = (49..=72).map(|x| x * 1_000).sum();
        assert_eq!(buffer.rolling_24h_sum(), expected_sum);
        assert_eq!(buffer.rolling_24h_average(), expected_sum / 24);
    }

    #[test]
    fn test_hourly_slotted_ring_buffer_ntp_backwards_safety() {
        let mut buffer = HourlySlottedRingBuffer::new();

        // Record hours 10 and 11
        buffer.record_hourly_median(10, 500);
        buffer.record_hourly_median(11, 600);
        assert_eq!(buffer.last_epoch_hour(), 11);
        assert_eq!(buffer.rolling_24h_sum(), 1100);

        // NTP backward jump to hour 9 or 10 must not corrupt the buffer
        buffer.record_hourly_median(9, 9999);
        assert_eq!(buffer.last_epoch_hour(), 11);
        // Sum must not have changed
        assert_eq!(buffer.rolling_24h_sum(), 1100);

        buffer.record_hourly_median(10, 8888);
        assert_eq!(buffer.last_epoch_hour(), 11);
        assert_eq!(buffer.rolling_24h_sum(), 1100);
    }

    #[test]
    fn test_diurnal_cycle_invariance() {
        let mut buffer = HourlySlottedRingBuffer::new();

        // 24-hour day/night cycle: day (hour 6..18) high (10,000), night (18..6) low (2,000)
        for h in 0..24 {
            let val = if (6..18).contains(&(h % 24)) {
                10_000
            } else {
                2_000
            };
            buffer.record_hourly_median(h, val);
        }

        // Day: 12 hours * 10,000 = 120,000
        // Night: 12 hours * 2,000 = 24,000
        // Sum = 144,000, avg = 6,000
        assert_eq!(buffer.rolling_24h_sum(), 144_000);
        assert_eq!(buffer.rolling_24h_average(), 6_000);

        // Simulate another 24 hours with identical day/night pattern
        for h in 24..48 {
            let val = if (6..18).contains(&(h % 24)) {
                10_000
            } else {
                2_000
            };
            buffer.record_hourly_median(h, val);
        }

        // Rolling 24h sum and average must remain exactly invariant despite day/night fluctuation
        assert_eq!(buffer.rolling_24h_sum(), 144_000);
        assert_eq!(buffer.rolling_24h_average(), 6_000);
    }
}
