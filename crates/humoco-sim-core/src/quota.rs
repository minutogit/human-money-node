//! # Spec 09: Netzwerk-Thermometer, Byte-Jahre & Dynamische Quotas
//!
//! This module implements the physical currency of **Byte-Years** (storage-time product),
//! decentralized **quartile sampling**, the **28-day slotted ring buffer** for median smoothing,
//! the **Zipf spread damper**, and the **deterministic 2-stage quota model with whale brake**.

use crate::types::NodeId;
use std::collections::HashMap;

/// Exact size of a `StoredLock` in shard RAM (144B wire + 32B canon hash + 8B TTL + 8B padding).
///
/// # Architectural Invariant (Spec 09 vs. Spec 12 Reconciliation):
/// - `192` Bytes is the normative consensus multiplier for the Byte-Years quota formula (Spec 09:20).
/// - Spec 12:116 refers to `≈224` Bytes as the internal in-memory footprint when including runtime hash map pointers.
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
        let byte_years =
            (total_byte_seconds + (SECONDS_PER_YEAR as u128 / 2)) / (SECONDS_PER_YEAR as u128);
        u64::try_from(byte_years).unwrap_or(u64::MAX).max(1)
    }

    /// Computes micro-Byte-Years (µBJ) from TTL in seconds: (STORED_LOCK_BYTES * ttl_seconds * 1_000_000) / SECONDS_PER_YEAR
    /// With commercial rounding (at least 1 micro-Byte-Year).
    pub fn micro_from_ttl_seconds(ttl_seconds: u64) -> u64 {
        if ttl_seconds == 0 {
            return 1;
        }
        let total_micro_byte_seconds =
            (STORED_LOCK_BYTES as u128) * (ttl_seconds as u128) * 1_000_000u128;
        let micro_byte_years = (total_micro_byte_seconds + (SECONDS_PER_YEAR as u128 / 2))
            / (SECONDS_PER_YEAR as u128);
        u64::try_from(micro_byte_years).unwrap_or(u64::MAX).max(1)
    }

    /// Computes Byte-Years from days
    pub fn from_ttl_days(days: u64) -> u64 {
        Self::from_ttl_seconds(days.saturating_mul(86_400))
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
            let low = sorted[n / 2 - 1] as u128;
            let high = sorted[n / 2] as u128;
            ((low + high) / 2) as u64
        };

        let q1 = sorted[n / 4];
        let q3 = sorted[(3 * n) / 4];

        Self { q1, median, q3 }
    }

    /// Computes the Zipf spread damper:
    /// Spread_Damper = max(0.5, min(1.0, (1.0 - (Q1 / Q3)) / 0.66))
    pub fn spread_damper(&self) -> f64 {
        if self.q1 >= self.q3 {
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
fn array_sum<const N: usize>(arr: &[u64; N]) -> u128 {
    arr.iter().map(|&x| x as u128).sum()
}

fn seeded_epoch_hours(current_epoch_hour: u64) -> [u64; 24] {
    std::array::from_fn(|i| current_epoch_hour.saturating_sub((23 - i) as u64))
}

/// Generic fixed-capacity slotted ring buffer for time-series smoothing and rolling metrics.
#[derive(Clone, Debug)]
pub struct SlottedRingBuffer<const N: usize> {
    slots: [u64; N],
    count: usize,
    write_idx: usize,
}

impl<const N: usize> SlottedRingBuffer<N> {
    pub const fn new() -> Self {
        Self {
            slots: [0; N],
            count: 0,
            write_idx: 0,
        }
    }

    /// Appends a new value sequentially into the ring buffer
    pub fn push(&mut self, val: u64) {
        self.slots[self.write_idx] = val;
        self.write_idx = (self.write_idx + 1) % N;
        if self.count < N {
            self.count += 1;
        }
    }

    /// Sets a value at a specific slot index
    pub fn set_slot(&mut self, idx: usize, val: u64) {
        let slot = idx % N;
        self.slots[slot] = val;
    }

    /// Seeds all slots with a uniform value
    pub fn seed(&mut self, val: u64) {
        self.slots = [val; N];
        self.count = N;
        self.write_idx = 0;
    }

    /// Seeds all slots with a uniform value subject to a minimum floor
    pub fn seed_with_floor(&mut self, seed_val: u64, floor: u64) {
        self.seed(seed_val.max(floor));
    }

    /// Returns the sum of all populated slots
    pub fn sum(&self) -> u128 {
        array_sum(&self.slots)
    }

    /// Returns the rolling average across populated slots
    pub fn average(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some((self.sum() / self.count as u128) as u64)
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn slots(&self) -> &[u64; N] {
        &self.slots
    }
}

impl<const N: usize> Default for SlottedRingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// 28-day slotted ring buffer for sluggish median smoothing
#[derive(Clone, Debug, Default)]
pub struct SlottedMedianRingBuffer {
    inner: SlottedRingBuffer<28>,
}

impl SlottedMedianRingBuffer {
    pub fn new() -> Self {
        Self {
            inner: SlottedRingBuffer::new(),
        }
    }

    /// Writes the daily median into the next 28-day slot
    pub fn push_daily_median(&mut self, daily_median: u64) {
        self.inner.push(daily_median);
    }

    /// Initializes all 28 slots with a seed median and lower bound
    pub fn seed_with_floor(&mut self, seed_median: u64, floor: u64) {
        self.inner.seed_with_floor(seed_median, floor);
    }

    /// [INV-0907] [INV-0908]
    /// Initializes all 28 slots with a seed median (e.g. on cold-start join
    /// into an existing large network or during fast re-seed on a network merge).
    pub fn seed(&mut self, seed_median: u64) {
        self.seed_with_floor(seed_median, HARD_FLOOR_BASELINE_DAILY);
    }

    /// Returns the rolling 28-day average, or None if no data is available yet
    pub fn moving_average(&self) -> Option<u64> {
        self.inner.average()
    }

    /// Computes the rolling 28-day average of the median (fallback: HARD_FLOOR_BASELINE_DAILY)
    pub fn moving_average_median(&self) -> u64 {
        self.moving_average().unwrap_or(HARD_FLOOR_BASELINE_DAILY)
    }

    pub fn days_recorded(&self) -> usize {
        self.inner.count()
    }

    pub fn slots(&self) -> &[u64; 28] {
        self.inner.slots()
    }
}

/// 65-entry dyadic lookup table for 2^(-i/64) * 2^32, i in 0..=64.
/// Represents 64 uniform intervals of length 1,350s within a 24h half-life (86,400s).
/// Interpolation error across the entire 24h domain is strictly bounded < 0.002%.
const DYADIC_HALF_LIFE_TABLE: [u64; 65] = [
    0x100000000,
    0xfd3e0c0d,
    0xfa83b2db,
    0xf7d0df73,
    0xf5257d15,
    0xf281773c,
    0xefe4b99c,
    0xed4f301f,
    0xeac0c6e8,
    0xe8396a50,
    0xe5b906e7,
    0xe33f8973,
    0xe0ccdeec,
    0xde60f482,
    0xdbfbb798,
    0xd99d15c2,
    0xd744fccb,
    0xd4f35aac,
    0xd2a81d92,
    0xd06333db,
    0xce248c15,
    0xcbec14ff,
    0xc9b9bd86,
    0xc78d74c9,
    0xc5672a11,
    0xc346ccda,
    0xc12c4cca,
    0xbf1799b6,
    0xbd08a39f,
    0xbaff5ab2,
    0xb8fbaf47,
    0xb6fd91e3,
    0xb504f334,
    0xb311c413,
    0xb123f582,
    0xaf3b78ad,
    0xad583eea,
    0xab7a39b6,
    0xa9a15ab5,
    0xa7cd93b5,
    0xa5fed6aa,
    0xa43515ae,
    0xa2704303,
    0xa0b05110,
    0x9ef53261,
    0x9d3ed9a7,
    0x9b8d39ba,
    0x99e04593,
    0x9837f052,
    0x96942d37,
    0x94f4efa9,
    0x935a2b2f,
    0x91c3d374,
    0x9031dc43,
    0x8ea4398b,
    0x8d1adf5b,
    0x8b95c1e4,
    0x8a14d575,
    0x88980e81,
    0x871f6197,
    0x85aac368,
    0x843a28c4,
    0x82cd8699,
    0x8164d1f4,
    0x80000000,
];

/// Computes the exponential decay of a metric with a 24-hour half-life (86,400s):
/// - Decays exactly 50% every 86,400s (24 hours).
/// - 100% pure integer arithmetic, overflow-safe via u128.
/// - 64-step dyadic lookup table with linear interpolation (error < 0.002%).
/// - If `delta_secs == 0`: returns `value` without modification.
/// - If `delta_secs >= 64 * 86_400`: decays completely to 0.
pub fn decay_integer_ema(value: u64, delta_secs: u64) -> u64 {
    if value == 0 || delta_secs == 0 {
        return value;
    }
    let half_lives = delta_secs / 86_400;
    if half_lives >= 64 {
        return 0;
    }
    let r = delta_secs % 86_400;
    let i = (r / 1_350) as usize;
    let step_rem = r % 1_350;

    let y0 = DYADIC_HALF_LIFE_TABLE[i];
    let y1 = DYADIC_HALF_LIFE_TABLE[i + 1];
    let factor = y0 - ((y0 - y1) * step_rem) / 1_350;

    ((value as u128 * factor as u128) >> (32 + half_lives)) as u64
}

/// Computes the integer EMA with 24h half-life decay followed by addition of footprint:
/// - First applies 24h half-life decay via `decay_integer_ema(old_ema, delta_secs)`.
/// - Then adds `footprint` using `saturating_add` (overflow-safe).
pub fn calculate_integer_ema(old_ema: u64, delta_secs: u64, footprint: u64) -> u64 {
    decay_integer_ema(old_ema, delta_secs).saturating_add(footprint)
}

/// Converts a 24h half-life EMA accumulator value to its equivalent 24h daily rate:
/// Rate = (EMA * ln(2)) ≈ (EMA * 693_147) / 1_000_000.
pub fn ema_to_daily_rate(ema: u64) -> u64 {
    ((ema as u128 * 693_147) / 1_000_000) as u64
}

/// [Pillar C]
/// 24-hour slotted ring buffer for collecting hourly medians and rolling 24h values.
#[derive(Clone, Debug, Default)]
pub struct HourlySlottedRingBuffer {
    slots: SlottedRingBuffer<24>,
    epoch_hours: [u64; 24],
    last_epoch_hour: u64,
    occupied: [bool; 24],
}

impl HourlySlottedRingBuffer {
    pub fn new() -> Self {
        Self {
            slots: SlottedRingBuffer::new(),
            epoch_hours: [0; 24],
            last_epoch_hour: 0,
            occupied: [false; 24],
        }
    }

    /// Records an hourly median.
    /// - Protection against NTP backward jumps: if `epoch_hour < self.last_epoch_hour`, ignore and do not update backwards.
    /// - Slot index: `(epoch_hour % 24) as usize`.
    /// - Writes `slots[idx] = median` and `epoch_hours[idx] = epoch_hour`.
    /// - Updates `self.last_epoch_hour = epoch_hour.max(self.last_epoch_hour)`.
    /// - Increments `count = (count + 1).min(24)` only when a previously unoccupied slot is populated.
    pub fn record_hourly_median(&mut self, epoch_hour: u64, median: u64) {
        if epoch_hour < self.last_epoch_hour {
            return;
        }

        let idx = (epoch_hour % 24) as usize;
        self.slots.set_slot(idx, median);
        self.epoch_hours[idx] = epoch_hour;
        self.last_epoch_hour = epoch_hour.max(self.last_epoch_hour);
        if !self.occupied[idx] {
            self.occupied[idx] = true;
            if self.slots.count < 24 {
                self.slots.count += 1;
            }
        }
    }

    /// Sums all slots (via u128 to prevent overflow) and returns u64.
    /// Fallback when `count == 0`: 0.
    pub fn rolling_24h_sum(&self) -> u64 {
        if self.slots.count() == 0 {
            return 0;
        }
        let sum = self.slots.sum();
        sum.min(u64::MAX as u128) as u64
    }

    /// Computes the rolling 24h average: `rolling_24h_sum() / count.max(1) as u64`.
    pub fn rolling_24h_average(&self) -> u64 {
        self.rolling_24h_sum() / (self.slots.count().max(1) as u64)
    }

    /// Fills all 24 slots with the seed value for a clean cold start.
    pub fn seed_with_floor(&mut self, seed_hourly_median: u64, current_epoch_hour: u64) {
        self.slots.seed(seed_hourly_median);
        self.epoch_hours = seeded_epoch_hours(current_epoch_hour);
        self.last_epoch_hour = current_epoch_hour;
        self.occupied = [true; 24];
    }

    pub fn count(&self) -> usize {
        self.slots.count()
    }

    pub fn last_epoch_hour(&self) -> u64 {
        self.last_epoch_hour
    }

    pub fn slots(&self) -> &[u64; 24] {
        self.slots.slots()
    }

    pub fn epoch_hours(&self) -> &[u64; 24] {
        &self.epoch_hours
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
pub fn evaluate_quota_exceeded_claim(
    sender_volume: u64,
    quota_limit: u64,
) -> QuotaPlausibilityVerdict {
    let sender = sender_volume as u128;
    let limit = quota_limit as u128;
    let lower_tolerance = limit * 75 / 100; // 75%
    let upper_tolerance = limit * 125 / 100; // 125%

    if sender < lower_tolerance {
        QuotaPlausibilityVerdict::FraudulentRejection { malus_increment: 8 }
    } else if sender <= upper_tolerance {
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    } else {
        QuotaPlausibilityVerdict::LegitimateOverload { malus_increment: 0 }
    }
}

/// Continuous rolling quota tracker using the 24-hour half-life integer EMA (`decay_integer_ema`).
/// Eliminates discrete UTC midnight rollover cliffs (`epoch_day` resets) and backward-timestamp races.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RollingQuotaCounter {
    decayed_usage: u64,
    last_update_sec: Option<u64>,
}

impl RollingQuotaCounter {
    /// Creates a new, empty rolling quota counter.
    pub const fn new() -> Self {
        Self {
            decayed_usage: 0,
            last_update_sec: None,
        }
    }

    /// Computes the effective decayed usage at timestamp `now_sec`.
    ///
    /// Monotonicity guarantees:
    /// - Returns 0 if no usage has ever been recorded (`last_update_sec.is_none()`).
    /// - If `now_sec < last_sec` (e.g. out-of-order packet arrival or clock jitter),
    ///   `delta_secs = 0` so decay never resets or inflates backwards.
    pub fn usage_at(&self, now_sec: u64) -> u64 {
        match self.last_update_sec {
            None => 0,
            Some(last_sec) => {
                let delta_secs = now_sec.saturating_sub(last_sec);
                decay_integer_ema(self.decayed_usage, delta_secs)
            }
        }
    }

    /// Returns the raw cached usage at the last recorded timestamp (without projecting forward).
    pub const fn raw_cached_usage(&self) -> u64 {
        self.decayed_usage
    }

    /// Returns the timestamp in seconds of the last recorded update, or None if empty.
    pub const fn last_update_sec(&self) -> Option<u64> {
        self.last_update_sec
    }

    /// Attempts to consume `amount` against `limit` at timestamp `now_sec`.
    ///
    /// Returns:
    /// - `Ok(new_usage)`: Consumption accepted. State is updated: `decayed_usage = new_usage`
    ///   and `last_update_sec` is monotonically advanced to `max(last, now_sec)`.
    /// - `Err(available)`: Quota exceeded or overflow. `self` is completely unmodified.
    ///   The error payload contains the remaining available budget at `now_sec` (`limit.saturating_sub(current)`).
    pub fn try_consume(&mut self, now_sec: u64, amount: u64, limit: u64) -> Result<u64, u64> {
        let current = self.usage_at(now_sec);
        match current.checked_add(amount) {
            Some(new_usage) if new_usage <= limit => {
                self.decayed_usage = new_usage;
                self.last_update_sec =
                    Some(self.last_update_sec.map_or(now_sec, |last| last.max(now_sec)));
                Ok(new_usage)
            }
            _ => Err(limit.saturating_sub(current)),
        }
    }
}

/// Maximum number of tracked nodes in RAM before stale zero-usage nodes are purged.
pub const MAX_TRACKED_NODES: usize = 16_384;

/// Full decentralized network thermometer with quota enforcement
#[derive(Clone, Debug)]
pub struct NetworkThermometer {
    ring_buffer: SlottedMedianRingBuffer,
    read_ring_buffer: SlottedMedianRingBuffer,
    node_write_usage: HashMap<NodeId, RollingQuotaCounter>,
    node_read_usage: HashMap<NodeId, RollingQuotaCounter>,
    write_ema_micro_bj: u64,
    last_write_ema_sec: Option<u64>,
    read_ema_credits: u64,
    last_read_ema_sec: Option<u64>,
}

impl NetworkThermometer {
    pub fn new() -> Self {
        Self {
            ring_buffer: SlottedMedianRingBuffer::new(),
            read_ring_buffer: SlottedMedianRingBuffer::new(),
            node_write_usage: HashMap::new(),
            node_read_usage: HashMap::new(),
            write_ema_micro_bj: 0,
            last_write_ema_sec: None,
            read_ema_credits: 0,
            last_read_ema_sec: None,
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
        self.read_ring_buffer.seed_with_floor(
            global_median / READ_TO_WRITE_RATIO,
            HARD_FLOOR_READ_BASELINE_DAILY,
        );
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
        let moving_read_median = self
            .read_ring_buffer
            .moving_average()
            .unwrap_or(HARD_FLOOR_READ_BASELINE_DAILY);
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

    /// Checks and consumes a lock ingress for the node using rolling 24h half-life EMA decay.
    /// Returns `Ok(new_usage)` if accepted, or `Err(available_budget)` if rejected.
    pub fn try_consume_lock(
        &mut self,
        now_sec: u64,
        node_id: NodeId,
        footprint_byte_years: u64,
        quota_byte_years: u64,
    ) -> Result<u64, u64> {
        if !self.node_write_usage.contains_key(&node_id)
            && self.node_write_usage.len() >= MAX_TRACKED_NODES
        {
            self.node_write_usage
                .retain(|_, counter| counter.usage_at(now_sec) > 0);
        }
        let counter = self.node_write_usage.entry(node_id).or_default();
        counter.try_consume(now_sec, footprint_byte_years, quota_byte_years)
    }

    /// Checks and registers a lock ingress for the node using rolling 24h half-life EMA decay.
    /// Returns `true` if the lock is within the budget.
    /// Returns `false` if the budget is exceeded (silent dropping).
    pub fn try_accept_lock(
        &mut self,
        now_sec: u64,
        node_id: NodeId,
        footprint_byte_years: u64,
        quota_byte_years: u64,
    ) -> bool {
        self.try_consume_lock(now_sec, node_id, footprint_byte_years, quota_byte_years)
            .is_ok()
    }

    /// Checks and consumes a read ingress for the node using rolling 24h half-life EMA decay.
    /// Returns `Ok(new_usage)` if accepted, or `Err(available_budget)` if rejected.
    pub fn try_consume_read(
        &mut self,
        now_sec: u64,
        node_id: NodeId,
        credits: u64,
        quota: u64,
    ) -> Result<u64, u64> {
        if !self.node_read_usage.contains_key(&node_id)
            && self.node_read_usage.len() >= MAX_TRACKED_NODES
        {
            self.node_read_usage
                .retain(|_, counter| counter.usage_at(now_sec) > 0);
        }
        let counter = self.node_read_usage.entry(node_id).or_default();
        counter.try_consume(now_sec, credits, quota)
    }

    /// Checks and registers a read ingress for the node using rolling 24h half-life EMA decay.
    /// Returns `true` if the read is within the budget.
    /// Returns `false` if the budget is exceeded (silent dropping).
    pub fn try_accept_read(
        &mut self,
        now_sec: u64,
        node_id: NodeId,
        credits: u64,
        quota: u64,
    ) -> bool {
        self.try_consume_read(now_sec, node_id, credits, quota)
            .is_ok()
    }

    /// Returns the current write usage of a node decayed to `now_sec`
    pub fn get_node_usage_at(&self, node_id: NodeId, now_sec: u64) -> u64 {
        self.node_write_usage
            .get(&node_id)
            .map_or(0, |c| c.usage_at(now_sec))
    }

    /// Returns the raw cached write usage of a node (at last recorded update)
    pub fn get_node_usage(&self, node_id: NodeId) -> u64 {
        self.node_write_usage
            .get(&node_id)
            .map_or(0, |c| c.raw_cached_usage())
    }

    /// Returns the total write usage across all nodes decayed to `now_sec`
    pub fn total_write_usage_at(&self, now_sec: u64) -> u64 {
        self.node_write_usage
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.usage_at(now_sec)))
    }

    /// Returns the total raw cached write usage across all nodes in the network
    pub fn total_daily_write_usage(&self) -> u64 {
        self.node_write_usage
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.raw_cached_usage()))
    }

    /// Returns the current read usage of a node decayed to `now_sec`
    pub fn get_node_read_usage_at(&self, node_id: NodeId, now_sec: u64) -> u64 {
        self.node_read_usage
            .get(&node_id)
            .map_or(0, |c| c.usage_at(now_sec))
    }

    /// Returns the raw cached read usage of a node (at last recorded update)
    pub fn get_node_read_usage(&self, node_id: NodeId) -> u64 {
        self.node_read_usage
            .get(&node_id)
            .map_or(0, |c| c.raw_cached_usage())
    }

    /// Returns the total read usage across all nodes decayed to `now_sec`
    pub fn total_read_usage_at(&self, now_sec: u64) -> u64 {
        self.node_read_usage
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.usage_at(now_sec)))
    }

    /// Returns the total raw cached read usage across all nodes in the network
    pub fn total_daily_read_usage(&self) -> u64 {
        self.node_read_usage
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.raw_cached_usage()))
    }

    /// Returns a reference to a node's rolling write quota counter, if present.
    pub fn get_node_write_counter(&self, node_id: NodeId) -> Option<&RollingQuotaCounter> {
        self.node_write_usage.get(&node_id)
    }

    /// Returns a reference to a node's rolling read quota counter, if present.
    pub fn get_node_read_counter(&self, node_id: NodeId) -> Option<&RollingQuotaCounter> {
        self.node_read_usage.get(&node_id)
    }

    /// Initializes the read thermometer of a new node with the current peer read median
    pub fn seed_read_from_peers(&mut self, peer_median: u64) {
        self.read_ring_buffer
            .seed_with_floor(peer_median, HARD_FLOOR_READ_BASELINE_DAILY);
    }

    /// Fast re-seed for the read thermometer on network merge
    pub fn fast_reseed_read_on_merge(&mut self, global_median: u64) {
        self.read_ring_buffer.seed_with_floor(
            global_median / READ_TO_WRITE_RATIO,
            HARD_FLOOR_READ_BASELINE_DAILY,
        );
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

    /// Records write ingress into the continuous 24h half-life Write-EMA
    pub fn record_write_ingress(&mut self, now_sec: u64, footprint_micro_bj: u64) {
        let delta = match self.last_write_ema_sec {
            None => 0,
            Some(last) => now_sec.saturating_sub(last),
        };
        self.write_ema_micro_bj =
            calculate_integer_ema(self.write_ema_micro_bj, delta, footprint_micro_bj);
        self.last_write_ema_sec = Some(match self.last_write_ema_sec {
            None => now_sec,
            Some(last) => now_sec.max(last),
        });
    }

    /// Returns the current raw write EMA accumulator in micro-Byte-Years (µBJ)
    pub fn current_write_ema_micro_bj(&self) -> u64 {
        self.write_ema_micro_bj
    }

    /// Returns the current write EMA in Byte-Years (BJ)
    pub fn current_write_ema_byte_years(&self) -> u64 {
        self.write_ema_micro_bj / 1_000_000
    }

    /// Computes the rolling 24-hour write daily rate in Byte-Years at a specific time `now_sec`
    pub fn rolling_24h_average_at(&self, now_sec: u64) -> u64 {
        let delta = match self.last_write_ema_sec {
            None => 0,
            Some(last) => now_sec.saturating_sub(last),
        };
        let decayed_ema_micro = decay_integer_ema(self.write_ema_micro_bj, delta);
        let daily_rate_micro = ema_to_daily_rate(decayed_ema_micro);
        daily_rate_micro / 1_000_000
    }

    /// Computes the current rolling 24-hour write daily rate in Byte-Years
    pub fn rolling_24h_average(&self) -> u64 {
        self.rolling_24h_average_at(self.last_write_ema_sec.unwrap_or(0))
    }

    /// Records read ingress into the continuous 24h half-life Read-EMA
    pub fn record_read_ingress(&mut self, now_sec: u64, credits: u64) {
        let delta = match self.last_read_ema_sec {
            None => 0,
            Some(last) => now_sec.saturating_sub(last),
        };
        self.read_ema_credits = calculate_integer_ema(self.read_ema_credits, delta, credits);
        self.last_read_ema_sec = Some(match self.last_read_ema_sec {
            None => now_sec,
            Some(last) => now_sec.max(last),
        });
    }

    /// Returns the current raw read EMA accumulator in credits
    pub fn current_read_ema_credits(&self) -> u64 {
        self.read_ema_credits
    }

    /// Computes the rolling 24-hour read daily rate in credits at a specific time `now_sec`
    pub fn rolling_24h_read_average_at(&self, now_sec: u64) -> u64 {
        let delta = match self.last_read_ema_sec {
            None => 0,
            Some(last) => now_sec.saturating_sub(last),
        };
        let decayed_read_ema = decay_integer_ema(self.read_ema_credits, delta);
        ema_to_daily_rate(decayed_read_ema)
    }

    /// Computes the current rolling 24-hour read daily rate in credits
    pub fn rolling_24h_read_average(&self) -> u64 {
        self.rolling_24h_read_average_at(self.last_read_ema_sec.unwrap_or(0))
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
    fn test_micro_from_ttl_seconds() {
        // 1 year = 192 Byte-Years = 192_000_000 micro-Byte-Years
        assert_eq!(
            ByteYears::micro_from_ttl_seconds(SECONDS_PER_YEAR),
            192_000_000
        );
        // 5 years = 960 Byte-Years = 960_000_000 micro-Byte-Years
        assert_eq!(
            ByteYears::micro_from_ttl_seconds(5 * SECONDS_PER_YEAR),
            960_000_000
        );
        // 0 seconds = at least 1 micro-Byte-Year
        assert_eq!(ByteYears::micro_from_ttl_seconds(0), 1);
    }

    #[test]
    fn test_integer_ema_time_decay() {
        let old_ema = 100_000u64;

        // delta = 0: Kein Decay, nur Addition des Footprints
        let ema_delta_0 = calculate_integer_ema(old_ema, 0, 5_000);
        assert_eq!(ema_delta_0, 105_000);

        // delta = 86_400 (24h half-life): exactly 50% decay
        let decayed_1d = decay_integer_ema(old_ema, 86_400);
        assert_eq!(decayed_1d, 50_000);
        let ema_delta_1d = calculate_integer_ema(old_ema, 86_400, 7_000);
        assert_eq!(ema_delta_1d, 57_000);

        // delta = 172_800 (48h = 2 half-lives): exactly 25% remaining (75% decay)
        let decayed_2d = decay_integer_ema(old_ema, 172_800);
        assert_eq!(decayed_2d, 25_000);

        // delta = 259_200 (72h = 3 half-lives): exactly 12.5% remaining
        let decayed_3d = decay_integer_ema(old_ema, 259_200);
        assert_eq!(decayed_3d, 12_500);

        // delta >= 64 half-lives: decay to 0
        let decayed_ext = decay_integer_ema(old_ema, 64 * 86_400);
        assert_eq!(decayed_ext, 0);

        // ema_to_daily_rate: 1_000_000 EMA -> 693_147 Daily Rate
        assert_eq!(ema_to_daily_rate(1_000_000), 693_147);
    }

    #[test]
    fn test_decay_integer_ema_golden_vectors() {
        let base = 1_000_000_000u64;

        // 1. delta_secs = 0s (no decay)
        assert_eq!(decay_integer_ema(base, 0), 1_000_000_000);

        // 2. delta_secs = 12h (43,200s, exactly half a half-life: factor 2^(-0.5) ≈ 0.70710678)
        // Table entry 32 gives 0xb504f334. (1_000_000_000 * 0xb504f334) >> 32 = 707_106_781
        let decayed_12h = decay_integer_ema(base, 43_200);
        assert_eq!(decayed_12h, 707_106_781);

        // 3. delta_secs = 24h (86,400s, exactly 1 half-life: 50% remaining)
        let decayed_24h = decay_integer_ema(base, 86_400);
        assert_eq!(decayed_24h, 500_000_000);

        // 4. delta_secs = 48h (172,800s, exactly 2 half-lives: 25% remaining)
        let decayed_48h = decay_integer_ema(base, 172_800);
        assert_eq!(decayed_48h, 250_000_000);

        // 5. delta_secs = 64 * 86,400s (64 half-lives: decays completely to 0)
        let decayed_64hl = decay_integer_ema(base, 64 * 86_400);
        assert_eq!(decayed_64hl, 0);

        // Check boundary beyond 64 half-lives
        assert_eq!(decay_integer_ema(base, 65 * 86_400), 0);

        // Standard 1_000_000 unit vector
        assert_eq!(decay_integer_ema(1_000_000, 0), 1_000_000);
        assert_eq!(decay_integer_ema(1_000_000, 43_200), 707_106);
        assert_eq!(decay_integer_ema(1_000_000, 86_400), 500_000);
        assert_eq!(decay_integer_ema(1_000_000, 172_800), 250_000);
        assert_eq!(decay_integer_ema(1_000_000, 64 * 86_400), 0);

        // Daily rate conversion golden vector: floor(EMA * ln(2))
        assert_eq!(ema_to_daily_rate(1_000_000), 693_147);
        assert_eq!(ema_to_daily_rate(base), 693_147_000);
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

    #[test]
    fn test_byte_years_edge_cases() {
        // ttl_seconds == 0 -> min 1
        assert_eq!(ByteYears::from_ttl_seconds(0), 1);
        // from_ttl_days(0) -> 1
        assert_eq!(ByteYears::from_ttl_days(0), 1);
        // from_ttl_years(0.0) -> 1
        assert_eq!(ByteYears::from_ttl_years(0.0), 1);
    }

    #[test]
    fn test_quartiles_edge_cases_and_spread_damper() {
        // Empty samples fallback to HARD_FLOOR_BASELINE_DAILY
        let empty_stats = QuartileStats::calculate(&[]);
        assert_eq!(empty_stats.q1, HARD_FLOOR_BASELINE_DAILY);
        assert_eq!(empty_stats.median, HARD_FLOOR_BASELINE_DAILY);
        assert_eq!(empty_stats.q3, HARD_FLOOR_BASELINE_DAILY);
        assert_eq!(empty_stats.spread_damper(), 0.5);

        // Odd length samples
        let odd_samples = vec![10, 20, 30, 40, 50];
        let odd_stats = QuartileStats::calculate(&odd_samples);
        assert_eq!(odd_stats.median, 30);
        assert_eq!(odd_stats.q1, 20); // 5/4 = 1 -> sorted[1]
        assert_eq!(odd_stats.q3, 40); // 15/4 = 3 -> sorted[3]

        // Even length samples
        let even_samples = vec![10, 20, 30, 40];
        let even_stats = QuartileStats::calculate(&even_samples);
        assert_eq!(even_stats.median, 25); // (20 + 30) / 2
        assert_eq!(even_stats.q1, 20); // 4/4 = 1 -> sorted[1]
        assert_eq!(even_stats.q3, 40); // 12/4 = 3 -> sorted[3]

        // Spread damper edge cases
        // 1. q3 == 0 -> 0.5
        let zero_q3 = QuartileStats {
            q1: 0,
            median: 0,
            q3: 0,
        };
        assert_eq!(zero_q3.spread_damper(), 0.5);

        // 2. q1 >= q3 -> 0.5
        let equal_q = QuartileStats {
            q1: 100,
            median: 100,
            q3: 100,
        };
        assert_eq!(equal_q.spread_damper(), 0.5);
        let inverted_q = QuartileStats {
            q1: 200,
            median: 100,
            q3: 100,
        };
        assert_eq!(inverted_q.spread_damper(), 0.5);

        // 3. (1.0 - ratio) / 0.66 < 0.5 (e.g. ratio = 0.9 -> damper ~0.1515 -> clamped to 0.5)
        let high_ratio = QuartileStats {
            q1: 900,
            median: 950,
            q3: 1000,
        };
        assert_eq!(high_ratio.spread_damper(), 0.5);

        // 4. (1.0 - ratio) / 0.66 > 1.0 (e.g. ratio = 0.0 -> damper ~1.515 -> clamped to 1.0)
        let zero_ratio = QuartileStats {
            q1: 0,
            median: 500,
            q3: 1000,
        };
        assert_eq!(zero_ratio.spread_damper(), 1.0);

        // 5. Exactly 1.0 damper when ratio = 0.34 ((1.0 - 0.34) / 0.66 = 1.0)
        let exact_one = QuartileStats {
            q1: 340,
            median: 500,
            q3: 1000,
        };
        let damper = exact_one.spread_damper();
        assert!((damper - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_a13_01_quartiles_and_byte_years_overflow_safety() {
        // A13-01: calculate median on [u64::MAX, u64::MAX] must not overflow
        let stats = QuartileStats::calculate(&[u64::MAX, u64::MAX]);
        assert_eq!(stats.median, u64::MAX);

        let stats_near_max = QuartileStats::calculate(&[u64::MAX - 1, u64::MAX]);
        assert_eq!(stats_near_max.median, u64::MAX - 1);

        // A13-02: from_ttl_days(u64::MAX) must saturate and not panic
        let by_max = ByteYears::from_ttl_days(u64::MAX);
        assert!(by_max > 0);
    }

    #[test]
    fn test_slotted_ring_buffer_and_median_buffer_lifecycle() {
        let mut rb: SlottedRingBuffer<4> = SlottedRingBuffer::new();
        assert_eq!(rb.count(), 0);
        assert_eq!(rb.average(), None);
        assert_eq!(rb.sum(), 0);

        rb.push(10);
        assert_eq!(rb.count(), 1);
        assert_eq!(rb.average(), Some(10));
        assert_eq!(rb.sum(), 10);

        rb.push(20);
        rb.push(30);
        rb.push(40);
        assert_eq!(rb.count(), 4);
        assert_eq!(rb.sum(), 100);
        assert_eq!(rb.average(), Some(25));
        assert_eq!(rb.slots(), &[10, 20, 30, 40]);

        // Push 5th element -> overwrites index 0
        rb.push(50);
        assert_eq!(rb.count(), 4);
        assert_eq!(rb.slots(), &[50, 20, 30, 40]);
        assert_eq!(rb.sum(), 140);
        assert_eq!(rb.average(), Some(35));

        // set_slot
        rb.set_slot(1, 100);
        assert_eq!(rb.slots(), &[50, 100, 30, 40]);

        // seed & seed_with_floor
        rb.seed(77);
        assert_eq!(rb.slots(), &[77, 77, 77, 77]);
        assert_eq!(rb.count(), 4);

        rb.seed_with_floor(50, 100);
        assert_eq!(rb.slots(), &[100, 100, 100, 100]);

        // SlottedMedianRingBuffer
        let mut smb = SlottedMedianRingBuffer::new();
        assert_eq!(smb.moving_average(), None);
        assert_eq!(smb.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
        assert_eq!(smb.days_recorded(), 0);

        smb.seed(1_500_000);
        assert_eq!(smb.days_recorded(), 28);
        assert_eq!(smb.moving_average_median(), 1_500_000);
        assert_eq!(smb.slots(), &[1_500_000; 28]);

        smb.push_daily_median(2_000_000);
        assert!(smb.moving_average_median() > 1_500_000);

        let default_smb = SlottedMedianRingBuffer::default();
        assert_eq!(default_smb.days_recorded(), 0);
    }

    #[test]
    fn test_hourly_slotted_ring_buffer_boundaries_and_accessors() {
        let mut hrb = HourlySlottedRingBuffer::new();
        assert_eq!(hrb.count(), 0);
        assert_eq!(hrb.last_epoch_hour(), 0);
        assert_eq!(hrb.slots(), &[0u64; 24]);
        assert_eq!(hrb.epoch_hours(), &[0u64; 24]);

        // 1. Initial record
        hrb.record_hourly_median(5, 500);
        assert_eq!(hrb.count(), 1);
        assert_eq!(hrb.last_epoch_hour(), 5);
        assert_eq!(hrb.slots()[5], 500);
        assert_eq!(hrb.epoch_hours()[5], 5);

        // 2. Same slot / same hour update (slot == last_slot)
        hrb.record_hourly_median(5, 750);
        assert_eq!(hrb.slots()[5], 750);
        assert_eq!(hrb.last_epoch_hour(), 5);
        assert_eq!(hrb.count(), 1);

        // 3. Wrap-around (e.g. hour 29 = slot 5)
        hrb.record_hourly_median(29, 999);
        assert_eq!(hrb.last_epoch_hour(), 29);
        assert_eq!(hrb.slots()[5], 999);
        assert_eq!(hrb.epoch_hours()[5], 29);
        assert_eq!(hrb.count(), 1);

        // 4. seed_with_floor
        let mut seeded_hrb = HourlySlottedRingBuffer::new();
        seeded_hrb.seed_with_floor(1234, 100);
        assert_eq!(seeded_hrb.count(), 24);
        assert_eq!(seeded_hrb.last_epoch_hour(), 100);
        assert_eq!(seeded_hrb.slots(), &[1234u64; 24]);
        // Check epoch_hours are descending towards past
        assert_eq!(seeded_hrb.epoch_hours()[23], 100);
        assert_eq!(seeded_hrb.epoch_hours()[0], 100 - 23);
    }

    #[test]
    fn test_evaluate_quota_exceeded_claim_thresholds() {
        let limit = 1000u64;
        // 75% = 750, 125% = 1250

        // Zone 1: < 75% (FraudulentRejection)
        let v1 = evaluate_quota_exceeded_claim(749, limit);
        assert_eq!(
            v1,
            QuotaPlausibilityVerdict::FraudulentRejection { malus_increment: 8 }
        );
        assert_eq!(v1.malus(), 8);

        // Zone 2: == 75% (BoundaryCutoff)
        let v2 = evaluate_quota_exceeded_claim(750, limit);
        assert_eq!(
            v2,
            QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
        );
        assert_eq!(v2.malus(), 0);

        // Zone 2: within [75%, 125%]
        let v3 = evaluate_quota_exceeded_claim(1000, limit);
        assert_eq!(
            v3,
            QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
        );
        assert_eq!(v3.malus(), 0);

        // Zone 2: == 125% (BoundaryCutoff)
        let v4 = evaluate_quota_exceeded_claim(1250, limit);
        assert_eq!(
            v4,
            QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
        );
        assert_eq!(v4.malus(), 0);

        // Zone 3: > 125% (LegitimateOverload)
        let v5 = evaluate_quota_exceeded_claim(1251, limit);
        assert_eq!(
            v5,
            QuotaPlausibilityVerdict::LegitimateOverload { malus_increment: 0 }
        );
        assert_eq!(v5.malus(), 0);
    }

    #[test]
    fn test_network_thermometer_full_lifecycle_and_reseed() {
        let mut therm = NetworkThermometer::new();
        assert_eq!(therm.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);
        assert_eq!(therm.effective_read_ncb(), HARD_FLOOR_READ_BASELINE_DAILY);

        // seed_from_peers & seed_read_from_peers
        therm.seed_from_peers(1_200_000);
        assert_eq!(therm.effective_ncb(), 1_200_000);

        therm.seed_read_from_peers(80_000);
        assert_eq!(therm.effective_read_ncb(), 80_000);

        // fast_reseed_on_merge arithmetic & scaling
        therm.fast_reseed_on_merge(2_500_000);
        assert_eq!(therm.effective_ncb(), 2_500_000);
        // read quota = 2_500_000 / 5 = 500_000 (which is > 50_000 floor)
        assert_eq!(therm.effective_read_ncb(), 500_000);

        // fast_reseed_read_on_merge with value below floor
        therm.fast_reseed_read_on_merge(100_000); // 100_000 / 5 = 20_000 < 50_000 floor -> 50_000
        assert_eq!(therm.effective_read_ncb(), HARD_FLOOR_READ_BASELINE_DAILY);
        // fast_reseed_read_on_merge with value above floor (verifies / vs %)
        therm.fast_reseed_read_on_merge(500_000); // 500_000 / 5 = 100_000 > 50_000 floor -> 100_000
        assert_eq!(therm.effective_read_ncb(), 100_000);

        // calculate_daily_quota & calculate_daily_read_quota arithmetic
        // ncb = 2_500_000, k = 1.0, damper = 1.0 -> 2_500_000
        assert_eq!(therm.calculate_daily_quota(1.0, 1.0), 2_500_000);
        // k clamping: k > 5.0 -> clamped to 5.0
        assert_eq!(therm.calculate_daily_quota(10.0, 1.0), 12_500_000);
        // k clamping: k < 0.0 -> clamped to 0.0
        assert_eq!(therm.calculate_daily_quota(-1.0, 1.0), 0);
        // damper clamping: damper < 0.5 -> clamped to 0.5
        assert_eq!(therm.calculate_daily_quota(1.0, 0.1), 1_250_000);
        // damper clamping: damper > 1.0 -> clamped to 1.0
        assert_eq!(therm.calculate_daily_quota(1.0, 2.0), 2_500_000);

        // calculate_daily_read_quota
        // ncb_read = 100_000, k = 2.0, damper = 0.8 -> 100_000 * 2.0 * 0.8 = 160_000
        assert_eq!(therm.calculate_daily_read_quota(2.0, 0.8), 160_000);

        // calculate_sync_read_credits
        assert_eq!(NetworkThermometer::calculate_sync_read_credits(0), 1);
        assert_eq!(NetworkThermometer::calculate_sync_read_credits(1), 2);
        assert_eq!(NetworkThermometer::calculate_sync_read_credits(10), 2);
        assert_eq!(NetworkThermometer::calculate_sync_read_credits(11), 3);
        assert_eq!(NetworkThermometer::calculate_sync_read_credits(20), 3);
        assert_eq!(NetworkThermometer::calculate_sync_read_credits(21), 4);

        // try_accept_lock & try_accept_read tracking and continuous 24h rolling EMA decay
        let node = 42u16;
        let quota = 1000u64;
        let t0 = 1000u64;
        assert_eq!(therm.get_node_usage(node), 0);
        assert_eq!(therm.get_node_read_usage(node), 0);

        // Ingress within quota
        assert!(therm.try_accept_lock(t0, node, 600, quota));
        assert_eq!(therm.get_node_usage(node), 600);

        // Exceeding quota
        assert!(!therm.try_accept_lock(t0, node, 500, quota));
        assert_eq!(therm.get_node_usage(node), 600);

        // Read ingress within quota
        assert!(therm.try_accept_read(t0, node, 400, quota));
        assert_eq!(therm.get_node_read_usage(node), 400);

        // Read ingress exceeding quota
        assert!(!therm.try_accept_read(t0, node, 700, quota));
        assert_eq!(therm.get_node_read_usage(node), 400);

        // Continuous 24h half-life EMA decay recovery (24h later: 50% recovered)
        let t_24h = t0 + 86_400;
        assert_eq!(therm.get_node_usage_at(node, t_24h), 300);
        assert_eq!(therm.get_node_read_usage_at(node, t_24h), 200);

        // Ingress at t_24h: 300 + 300 = 600 <= 1000 succeeds!
        assert!(therm.try_accept_lock(t_24h, node, 300, quota));
        assert_eq!(therm.get_node_usage(node), 600);

        // Read ingress at t_24h: 200 + 300 = 500 <= 1000 succeeds!
        assert!(therm.try_accept_read(t_24h, node, 300, quota));
        assert_eq!(therm.get_node_read_usage(node), 500);

        // Total usages across nodes
        assert_eq!(therm.total_daily_write_usage(), 600);
        assert_eq!(therm.total_daily_read_usage(), 500);
        assert_eq!(therm.total_write_usage_at(t_24h), 600);
        assert_eq!(therm.total_read_usage_at(t_24h), 500);

        // record_daily_median & record_daily_read_median
        therm.record_daily_median(3_000_000);
        therm.record_daily_read_median(600_000);

        // Write-EMA & Read-EMA continuous 24h metrics
        therm.record_write_ingress(1000, 100_000_000); // 100 BY in µBJ
        assert_eq!(therm.current_write_ema_micro_bj(), 100_000_000);
        assert_eq!(therm.current_write_ema_byte_years(), 100);
        assert_eq!(therm.rolling_24h_average(), 69); // 100 * 0.693147

        therm.record_read_ingress(1000, 500);
        assert_eq!(therm.current_read_ema_credits(), 500);
        assert_eq!(therm.rolling_24h_read_average(), 346); // 500 * 0.693147

        let default_therm = NetworkThermometer::default();
        assert_eq!(default_therm.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn test_rolling_quota_counter_basic_and_decay() {
        let mut counter = RollingQuotaCounter::new();
        assert_eq!(counter.raw_cached_usage(), 0);
        assert_eq!(counter.last_update_sec(), None);
        assert_eq!(counter.usage_at(0), 0);
        assert_eq!(counter.usage_at(1000), 0);

        let limit = 100_000u64;

        // 1. Initial consumption at t = 1000
        let res1 = counter.try_consume(1000, 40_000, limit);
        assert_eq!(res1, Ok(40_000));
        assert_eq!(counter.raw_cached_usage(), 40_000);
        assert_eq!(counter.last_update_sec(), Some(1000));
        assert_eq!(counter.usage_at(1000), 40_000);

        // 2. Second consumption at same timestamp t = 1000
        let res2 = counter.try_consume(1000, 50_000, limit);
        assert_eq!(res2, Ok(90_000));
        assert_eq!(counter.usage_at(1000), 90_000);

        // 3. Exceeding consumption returns Err with remaining budget (100_000 - 90_000 = 10_000)
        let res3 = counter.try_consume(1000, 20_000, limit);
        assert_eq!(res3, Err(10_000));
        // Counter unmodified
        assert_eq!(counter.raw_cached_usage(), 90_000);
        assert_eq!(counter.usage_at(1000), 90_000);

        // 4. Time advances by 24h (86_400s) -> decays 50% from 90_000 to 45_000
        let t_24h = 1000 + 86_400;
        assert_eq!(counter.usage_at(t_24h), 45_000);
        // Raw cached usage is still 90_000 until next consumed
        assert_eq!(counter.raw_cached_usage(), 90_000);

        // 5. Consume at t_24h: current 45_000 + 30_000 = 75_000 <= 100_000
        let res4 = counter.try_consume(t_24h, 30_000, limit);
        assert_eq!(res4, Ok(75_000));
        assert_eq!(counter.raw_cached_usage(), 75_000);
        assert_eq!(counter.last_update_sec(), Some(t_24h));

        // 6. 64 half-lives later -> decays completely to 0
        let t_ext = t_24h + 64 * 86_400;
        assert_eq!(counter.usage_at(t_ext), 0);
        let res5 = counter.try_consume(t_ext, 100_000, limit);
        assert_eq!(res5, Ok(100_000));
    }

    #[test]
    fn test_rolling_quota_counter_backward_timestamp_monotonicity() {
        let mut counter = RollingQuotaCounter::new();
        let limit = 100_000u64;

        // Packet at t = 5000
        assert_eq!(counter.try_consume(5000, 30_000, limit), Ok(30_000));
        assert_eq!(counter.last_update_sec(), Some(5000));

        // Delayed out-of-order packet arriving with timestamp in the past (t = 2000)
        // Must yield delta_secs = 0, so usage does NOT decay or reset backwards!
        assert_eq!(counter.usage_at(2000), 30_000);
        let res = counter.try_consume(2000, 20_000, limit);
        assert_eq!(res, Ok(50_000));
        // Monotonic anchor stays at 5000
        assert_eq!(counter.last_update_sec(), Some(5000));
        assert_eq!(counter.raw_cached_usage(), 50_000);
    }

    #[test]
    fn test_rolling_quota_counter_boundary_conditions() {
        let mut counter = RollingQuotaCounter::new();

        // Exact boundary (amount == limit)
        assert_eq!(counter.try_consume(100, 500, 500), Ok(500));
        // Over-limit with 0 remaining
        assert_eq!(counter.try_consume(100, 1, 500), Err(0));

        // Overflow safety with huge amount near u64::MAX
        assert_eq!(counter.try_consume(100, u64::MAX, 500), Err(0));
    }

    #[test]
    fn test_network_thermometer_table_cleanup_on_limit() {
        let mut therm = NetworkThermometer::new();
        let limit = 10_000u64;

        // Insert MAX_TRACKED_NODES entries at t = 100
        for i in 0..MAX_TRACKED_NODES {
            let node = i as u16;
            assert!(therm.try_accept_lock(100, node, 100, limit));
        }
        assert_eq!(therm.node_write_usage.len(), MAX_TRACKED_NODES);

        // Advance time by 64 half-lives so all existing entries decay to 0
        let t_decayed = 100 + 64 * 86_400;
        let new_node = 20_000u16;
        assert!(therm.try_accept_lock(t_decayed, new_node, 500, limit));

        // The map must have purged the zero-usage entries, leaving only the newly inserted node!
        assert_eq!(therm.node_write_usage.len(), 1);
        assert_eq!(therm.get_node_usage(new_node), 500);
    }
}
