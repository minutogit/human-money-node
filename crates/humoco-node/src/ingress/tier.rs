use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use parking_lot::RwLock as PlRwLock;
use thiserror::Error;

use humoco_sim_core::quota::{ByteYears, NetworkThermometer, MAX_WHALE_MULTIPLIER};
use humoco_sim_core::types::NodeId;
use crate::ingress::pow::{PowEngine, PowError};
use crate::storage::{RedbStorage, StorageError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IngressTier {
    Tier1Vip,
    Tier2F2F,
    Tier3Public,
}

/// DTO for registered F2F ingress client credentials.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct F2fClientDto {
    pub token_hash: String,
    pub label: String,
    pub writes_today: u64,
    pub daily_limit: u64,
    pub whale_brake_active: bool,
    pub last_active_sec: Option<u64>,
    #[serde(default)]
    pub token: Option<String>,
}

/// Internal metadata stored for registered F2F client tokens.
#[derive(Debug, Clone)]
pub struct F2fClientMeta {
    pub token: String,
    pub token_hash: String,
    pub label: String,
    pub registered_at_ms: u64,
    pub last_active_ms: Option<u64>,
}

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("Invalid or unknown VIP auth token")]
    InvalidAuthToken,

    #[error("VIP Quota exceeded: required {required} byte-years, available {available}")]
    QuotaExceeded { available: u64, required: u64 },

    #[error("Invalid or unknown F2F peer token")]
    InvalidPeerToken,

    #[error("Proof of Work required")]
    PoWRequired {
        challenge: String,
        difficulty: u32,
        expires_at: u64,
    },

    #[error("Invalid or expired Proof of Work: {0}")]
    InvalidPoW(#[from] PowError),

    #[error("Storage error during quota verification: {0}")]
    Storage(#[from] StorageError),

    #[error("Read quota exceeded: required {required} reads, available {available}")]
    ReadQuotaExceeded { available: u64, required: u64 },
}

/// # Architectural Invariant: Ingress vs. Peer Telemetry Decoupling (INV-1701 & Spec 13/17)
///
/// `TierController` is intentionally **not** coupled to `PeerManager` or peer telemetry
/// (connection quality, latency histograms, failure counters). Ingress admission control
/// (VIP quota, F2F token check, BLAKE3 Hashcash PoW) runs on the PoS checkout hot-path
/// (`POST /v1/lock`) and must stay deterministic, constant-time and self-contained.
///
/// Rationale (INV-1701 — Non-Authoritative Telemetry):
/// Telemetry is operator-facing diagnosis only (`triggers_auto_ban() == false`). If ingress
/// decisions consumed peer health signals, a degraded peer or a telemetry spike would
/// feed back into admission control, throttling or rejecting legitimate PoS payments and
/// creating a **self-induced DoS** on the checkout path. By decoupling ingress from
/// subjective peer observations, the hot-path guarantees liveness even when the P2P mesh
/// is under stress, gossip is delayed, or `NetworkThermometer` is recalibrating. Peer
/// failures are handled exclusively inside `PeerManager` via local TTL pruning / circuit
/// breaker, never via ingress denial (cf. `AGENTS.md` — Local Node Perspective / First-Party
/// Evidence doctrine).
/// FIFO-sequenced VIP quota persist operation.
#[derive(Debug, Clone, Copy)]
struct VipQuotaPersistOp {
    account_tag: [u8; 32],
    remaining: u64,
}

#[derive(Clone)]
pub struct TierController {
    storage: Arc<RedbStorage>,
    pow_engine: Arc<PowEngine>,
    vip_tokens: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    vip_tags: Arc<RwLock<HashSet<[u8; 32]>>>,
    f2f_tokens: Arc<RwLock<HashSet<String>>>,
    f2f_clients: Arc<RwLock<HashMap<String, F2fClientMeta>>>,
    thermometer: Arc<RwLock<NetworkThermometer>>,
    vip_quota_cache: Arc<PlRwLock<HashMap<[u8; 32], u64>>>,
    vip_writes_today: Arc<AtomicU64>,
    f2f_writes_today: Arc<AtomicU64>,
    free_writes_today: Arc<AtomicU64>,
    epoch_seq: Arc<AtomicU64>,
    cumulative_micro_byte_years: Arc<AtomicU64>,
    prev_day_final_bytes: Arc<AtomicU64>,
    current_epoch_day_cached: Arc<AtomicU64>,
    last_thermometer_day: Arc<AtomicU64>,
    vip_persist_tx: tokio::sync::mpsc::Sender<VipQuotaPersistOp>,
    vip_persist_worker: tokio::task::AbortHandle,
    vip_persist_failed: Arc<AtomicBool>,
}

impl TierController {
    /// Creates a new TierController with storage, PoW engine, and initialized NetworkThermometer.
    ///
    /// Spawns a FIFO-sequenced VIP quota persist worker that processes write operations
    /// in strict order, preventing out-of-order write races from unsequenced `tokio::spawn`.
    pub fn new(storage: Arc<RedbStorage>, pow_engine: Arc<PowEngine>) -> Self {
        let (vip_persist_tx, mut vip_persist_rx) = tokio::sync::mpsc::channel::<VipQuotaPersistOp>(1_024);
        let persist_storage = storage.clone();
        let vip_persist_failed = Arc::new(AtomicBool::new(false));
        let worker_failed = vip_persist_failed.clone();
        let worker = tokio::spawn(async move {
            while let Some(op) = vip_persist_rx.recv().await {
                let storage = persist_storage.clone();
                let res = tokio::task::spawn_blocking(move || {
                    storage.set_quota(&op.account_tag, op.remaining)
                }).await;
                if !matches!(res, Ok(Ok(()))) {
                    worker_failed.store(true, Ordering::Release);
                    tracing::warn!(?res, "FIFO VIP quota persistence failed");
                }
            }
        });

        Self {
            storage,
            pow_engine,
            vip_tokens: Arc::new(RwLock::new(HashMap::new())),
            vip_tags: Arc::new(RwLock::new(HashSet::new())),
            f2f_tokens: Arc::new(RwLock::new(HashSet::new())),
            f2f_clients: Arc::new(RwLock::new(HashMap::new())),
            thermometer: Arc::new(RwLock::new(NetworkThermometer::new())),
            vip_quota_cache: Arc::new(PlRwLock::new(HashMap::new())),
            vip_writes_today: Arc::new(AtomicU64::new(0)),
            f2f_writes_today: Arc::new(AtomicU64::new(0)),
            free_writes_today: Arc::new(AtomicU64::new(0)),
            epoch_seq: Arc::new(AtomicU64::new(0)),
            cumulative_micro_byte_years: Arc::new(AtomicU64::new(0)),
            prev_day_final_bytes: Arc::new(AtomicU64::new(0)),
            current_epoch_day_cached: Arc::new(AtomicU64::new(0)),
            last_thermometer_day: Arc::new(AtomicU64::new(0)),
            vip_persist_tx,
            vip_persist_worker: worker.abort_handle(),
            vip_persist_failed,
        }
    }

    /// Registers natural FIFO quota-worker completion with daemon teardown.
    /// All controller senders must be dropped before waiting for this handle.
    pub fn quota_worker_abort_handle(&self) -> tokio::task::AbortHandle {
        self.vip_persist_worker.clone()
    }

    /// Local persistence failure evidence for truthful daemon completion, never peer punishment.
    pub fn quota_worker_failure_handle(&self) -> Arc<AtomicBool> {
        self.vip_persist_failed.clone()
    }

    /// Increments and returns the next epoch_seq for Spec 10 Signed Ingress Envelopes.
    pub fn next_epoch_seq(&self) -> u64 {
        self.epoch_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Records gateway declared usage, advancing day roll-over if needed, and returns:
    /// `(epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes)`.
    pub fn record_declared_usage(&self, now_ms: u64, footprint_micro_bj: u64) -> (u32, u64, u64, u64) {
        let day = self.current_epoch_day_at(now_ms);
        let last_day = self.current_epoch_day_cached.load(Ordering::Relaxed);
        if day > last_day
            && self.current_epoch_day_cached.compare_exchange(last_day, day, Ordering::SeqCst, Ordering::Relaxed).is_ok()
        {
            let prev_cum = self.cumulative_micro_byte_years.swap(0, Ordering::SeqCst);
            self.prev_day_final_bytes.store(prev_cum, Ordering::SeqCst);
            self.epoch_seq.store(0, Ordering::SeqCst);
        }
        let seq = self.next_epoch_seq();
        let cum = self.cumulative_micro_byte_years.fetch_add(footprint_micro_bj, Ordering::SeqCst) + footprint_micro_bj;
        let prev = self.prev_day_final_bytes.load(Ordering::Relaxed);
        (day as u32, seq, cum, prev)
    }

    /// Returns the tier write counters: (vip, f2f, free).
    pub fn tier_counters(&self) -> (u64, u64, u64) {
        (
            self.vip_writes_today.load(Ordering::Relaxed),
            self.f2f_writes_today.load(Ordering::Relaxed),
            self.free_writes_today.load(Ordering::Relaxed),
        )
    }

    /// Returns the cached VIP quota for an account, if present in the in-memory cache.
    pub fn get_cached_vip_quota(&self, account_tag: &[u8; 32]) -> Option<u64> {
        self.vip_quota_cache.read().get(account_tag).copied()
    }

    /// Sets the cached VIP quota directly (e.g. after top-up via control plane).
    pub fn set_cached_vip_quota(&self, account_tag: [u8; 32], balance: u64) {
        self.vip_quota_cache.write().insert(account_tag, balance);
    }

    /// Tops up VIP quota for an account, updating cache and persisting asynchronously.
    pub fn topup_vip_quota(&self, account_tag: [u8; 32], byte_years: u64) -> Result<u64, IngressError> {
        let mut cache = self.vip_quota_cache.write();
        let bal = cache
            .entry(account_tag)
            .or_insert_with(|| self.storage.get_quota(&account_tag).unwrap_or(0));
        *bal = bal.saturating_add(byte_years);
        let new_balance = *bal;
        drop(cache);
        self.persist_vip_quota_async(account_tag, new_balance);
        Ok(new_balance)
    }

    /// Returns all cached VIP quota balances.
    pub fn list_cached_vip_quotas(&self) -> Vec<([u8; 32], u64)> {
        self.vip_quota_cache
            .read()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Returns all VIP accounts, resolving each registered quota tag to its friendly token name (if known) or hex-string.
    pub fn list_vip_accounts(&self) -> Vec<(String, u64)> {
        let tokens_map = self.vip_tokens.read().unwrap_or_else(|e| e.into_inner());
        let mut tag_to_name = HashMap::new();
        for (name, tag) in tokens_map.iter() {
            tag_to_name.insert(*tag, name.clone());
        }
        drop(tokens_map);

        let cache = self.vip_quota_cache.read();
        let mut list = Vec::with_capacity(cache.len());
        for (tag, balance) in cache.iter() {
            let name = tag_to_name.get(tag).cloned().unwrap_or_else(|| hex::encode(tag));
            list.push((name, *balance));
        }
        list.sort_by(|a, b| a.0.cmp(&b.0));
        list
    }

    /// Hydrates the in-memory cache from durable storage (read-only, no fsync).
    pub fn hydrate_vip_quota(&self, account_tag: &[u8; 32]) -> Result<u64, StorageError> {
        let bal = self.storage.get_quota(account_tag)?;
        self.vip_quota_cache.write().insert(*account_tag, bal);
        Ok(bal)
    }

    /// Flushes a single cached balance to durable storage asynchronously without blocking hot-path.
    ///
    /// Uses a FIFO channel to sequence writes, preventing out-of-order write races
    /// that could occur with unsequenced `tokio::spawn` calls.
    fn persist_vip_quota_async(&self, account_tag: [u8; 32], remaining: u64) {
        let op = VipQuotaPersistOp { account_tag, remaining };
        if let Err(e) = self.vip_persist_tx.try_send(op) {
            tracing::warn!("FIFO VIP quota persist channel send failed: {:?}", e);
        }
    }

    /// In-memory atomic check-and-charge for VIP quota (hot-path, <1µs, no fsync stall).
    /// Returns remaining balance after deduction or QuotaExceeded.
    pub fn try_charge_vip_in_memory(&self, account_tag: &[u8; 32], required: u64) -> Result<u64, IngressError> {
        let mut cache = self.vip_quota_cache.write();
        let bal = cache.entry(*account_tag).or_insert_with(|| self.storage.get_quota(account_tag).unwrap_or(0));
        if *bal < required {
            return Err(IngressError::QuotaExceeded {
                available: *bal,
                required,
            });
        }
        *bal -= required;
        let remaining = *bal;
        drop(cache);
        self.persist_vip_quota_async(*account_tag, remaining);
        Ok(remaining)
    }

    /// Returns a reference to the decentralized network thermometer (Spec 09).
    pub fn thermometer(&self) -> Arc<RwLock<NetworkThermometer>> {
        self.thermometer.clone()
    }

    /// [INV-0907]
    /// Initializes the thermometer of a new node with the current peer median
    pub fn seed_from_peers(&self, peer_median: u64) {
        self.thermometer.write().unwrap_or_else(|e| e.into_inner()).seed_from_peers(peer_median);
    }

    /// [INV-0908]
    /// Fast re-seed on network merges (e.g., village A docks into the global mesh)
    pub fn fast_reseed_on_merge(&self, global_median: u64) {
        self.thermometer.write().unwrap_or_else(|e| e.into_inner()).fast_reseed_on_merge(global_median);
    }

    /// [INV-0922] Records a daily median in the 28-day slotted ring buffer
    pub fn record_daily_median(&self, median: u64) {
        self.thermometer.write().unwrap_or_else(|e| e.into_inner()).record_daily_median(median);
    }

    /// Returns the rolling 24-hour write daily rate in Byte-Years
    pub fn rolling_24h_average(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).rolling_24h_average()
    }

    /// Returns the rolling 24-hour write daily rate in Byte-Years at a specific second
    pub fn rolling_24h_average_at(&self, now_sec: u64) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).rolling_24h_average_at(now_sec)
    }

    /// Returns the current raw write EMA in micro-Byte-Years (µBJ)
    pub fn current_write_ema_micro_bj(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).current_write_ema_micro_bj()
    }

    /// Returns the current raw read EMA in credits
    pub fn current_read_ema_credits(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).current_read_ema_credits()
    }

    /// Returns the current rolling 24-hour read daily rate in credits
    pub fn rolling_24h_read_average(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).rolling_24h_read_average()
    }

    /// Returns the rolling 24-hour read daily rate in credits at a specific second
    pub fn rolling_24h_read_average_at(&self, now_sec: u64) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).rolling_24h_read_average_at(now_sec)
    }

    /// [INV-0923] Records a daily read median
    pub fn record_daily_read_median(&self, median: u64) {
        self.thermometer.write().unwrap_or_else(|e| e.into_inner()).record_daily_read_median(median);
    }

    /// [INV-0903/0904] Autonomous thermometer day roll-over (Spec 09 Phase 9 P1).
    ///
    /// Called periodically by the daemon ticker (hourly in production, fast in
    /// simulation mode). On epoch-day change (`now_ms / 86_400_000`) the locally
    /// measured 24h rolling rates are rotated into the 28-day slotted ring
    /// buffer so the moving median stays autonomous without manual intervention.
    ///
    /// Returns `Some(new_day)` when at least one daily slot was rotated,
    /// otherwise `None` (same day or cold-start init). Never fails; purely
    /// local time-based progression, no I/O, no peer telemetry coupling.
    pub fn advance_epoch_day(&self, now_ms: u64) -> Option<u64> {
        let day = self.current_epoch_day_at(now_ms);
        let last = self.last_thermometer_day.load(Ordering::Relaxed);
        if last == 0 {
            // Cold-start init: anchor to current day without recording a spurious median.
            let _ = self.last_thermometer_day.compare_exchange(
                0,
                day,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
            return None;
        }
        if day <= last {
            return None;
        }
        // Claim exactly one day-step at a time to avoid duplicate rotation under concurrency.
        if self
            .last_thermometer_day
            .compare_exchange(last, day, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let now_sec = now_ms / 1000;
        let write_median = self.rolling_24h_average_at(now_sec);
        let read_median = self.rolling_24h_read_average_at(now_sec);
        // Catch up missed days (offline / downtime) in a bounded way (max 28 slots).
        let missed = (day.saturating_sub(last)).clamp(1, 28);
        for _ in 0..missed {
            self.record_daily_median(write_median);
            self.record_daily_read_median(read_median);
        }
        Some(day)
    }

    /// Returns the last thermometer day that was rotated into the ring buffer (0 = not yet anchored).
    pub fn last_thermometer_day(&self) -> u64 {
        self.last_thermometer_day.load(Ordering::Relaxed)
    }

    /// [INV-0924] Calculates effective reference value NCB_eff = max(Moving_Median, HARD_FLOOR_BASELINE_DAILY)
    pub fn effective_ncb(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).effective_ncb()
    }

    /// [INV-0925] Calculates effective reference value NCB_read_eff = max(Moving_Read_Median, HARD_FLOOR_READ_BASELINE_DAILY)
    pub fn effective_read_ncb(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).effective_read_ncb()
    }

    /// Calculates dynamic daily quota with 5x Whale Brake K <= 5.0 (Spec 09)
    pub fn calculate_daily_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).calculate_daily_quota(k_multiplier, spread_damper)
    }

    /// [INV-0927] Calculates daily read quota for a node:
    /// Read_Quota = NCB_read_eff * min(K, 5.0) * Spread_Damper
    pub fn calculate_daily_read_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).calculate_daily_read_quota(k_multiplier, spread_damper)
    }

    /// [INV-0928] Evaluates read quota for a client: Returns `Ok(())` if the read is within the daily budget.
    /// Returns `Err(IngressError::ReadQuotaExceeded)` if the budget is exceeded (silent dropping).
    pub fn evaluate_read_quota(&self, client_id: NodeId, credits: u64, epoch_day: u64, k_multiplier: f64) -> Result<(), IngressError> {
        let daily_quota = self.calculate_daily_read_quota(k_multiplier, 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        if thermo.try_accept_read(epoch_day, client_id, credits, daily_quota) {
            let now_sec = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(epoch_day * 86_400);
            thermo.record_read_ingress(now_sec, credits);
            Ok(())
        } else {
            let used = thermo.get_node_read_usage(client_id);
            let available = daily_quota.saturating_sub(used);
            Err(IngressError::ReadQuotaExceeded {
                available,
                required: credits,
            })
        }
    }

    /// Returns the epoch day since UNIX epoch for a given timestamp in milliseconds
    pub fn current_epoch_day_at(&self, now_ms: u64) -> u64 {
        now_ms / (86_400 * 1000)
    }

    /// Returns the current epoch day since UNIX epoch (using system time as fallback)
    pub fn current_epoch_day(&self) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.current_epoch_day_at(now_ms)
    }

    /// Evaluates and registers dynamic ingress for F2F peers against daily quota (K=1.0)
    pub fn evaluate_f2f_quota(&self, peer_token: &str, required_byte_years: u64, epoch_day: u64) -> Result<(), IngressError> {
        let token_hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
        let peer_node_id: NodeId = u16::from_be_bytes([token_hash[0], token_hash[1]]);
        let daily_quota = self.calculate_daily_quota(1.0, 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        if thermo.try_accept_lock(epoch_day, peer_node_id, required_byte_years, daily_quota) {
            Ok(())
        } else {
            let used = thermo.get_node_usage(peer_node_id);
            let available = daily_quota.saturating_sub(used);
            Err(IngressError::QuotaExceeded {
                available,
                required: required_byte_years,
            })
        }
    }

    /// Evaluates and registers dynamic ingress for VIP accounts against daily quota with 5x Whale Brake (K <= 5.0)
    pub fn evaluate_vip_quota(&self, account_tag: &[u8; 32], required_byte_years: u64, epoch_day: u64, k_multiplier: f64) -> Result<(), IngressError> {
        let vip_node_id: NodeId = u16::from_be_bytes([account_tag[0], account_tag[1]]);
        let daily_quota = self.calculate_daily_quota(k_multiplier.clamp(0.0, MAX_WHALE_MULTIPLIER), 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        if thermo.try_accept_lock(epoch_day, vip_node_id, required_byte_years, daily_quota) {
            Ok(())
        } else {
            let used = thermo.get_node_usage(vip_node_id);
            let available = daily_quota.saturating_sub(used);
            Err(IngressError::QuotaExceeded {
                available,
                required: required_byte_years,
            })
        }
    }

    /// Evaluates and registers dynamic ingress for a network node against the 5x Whale Brake daily write limit.
    pub fn evaluate_node_write_quota(
        &self,
        sender_pubkey: &[u8; 32],
        required_byte_years: u64,
        epoch_day: u64,
    ) -> Result<(), IngressError> {
        let node_id: NodeId = u16::from_be_bytes([sender_pubkey[0], sender_pubkey[1]]);
        let daily_quota = self.calculate_daily_quota(MAX_WHALE_MULTIPLIER, 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        if thermo.try_accept_lock(epoch_day, node_id, required_byte_years, daily_quota) {
            Ok(())
        } else {
            let used = thermo.get_node_usage(node_id);
            let available = daily_quota.saturating_sub(used);
            Err(IngressError::QuotaExceeded {
                available,
                required: required_byte_years,
            })
        }
    }

    /// Evaluates and registers dynamic ingress for a network node against the 5x Whale Brake daily read limit.
    pub fn evaluate_node_read_quota(
        &self,
        sender_pubkey: &[u8; 32],
        required_credits: u64,
        epoch_day: u64,
    ) -> Result<(), IngressError> {
        let node_id: NodeId = u16::from_be_bytes([sender_pubkey[0], sender_pubkey[1]]);
        let daily_read_quota = self.calculate_daily_read_quota(MAX_WHALE_MULTIPLIER, 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        if thermo.try_accept_read(epoch_day, node_id, required_credits, daily_read_quota) {
            Ok(())
        } else {
            let used = thermo.get_node_read_usage(node_id);
            let available = daily_read_quota.saturating_sub(used);
            Err(IngressError::ReadQuotaExceeded {
                available,
                required: required_credits,
            })
        }
    }

    /// Registers an auth token associated with a specific VIP account tag.
    pub fn register_vip_token(&self, token: impl Into<String>, account_tag: [u8; 32]) {
        let token_str = token.into();
        self.vip_tokens.write().unwrap_or_else(|e| e.into_inner()).insert(token_str, account_tag);
        self.vip_tags.write().unwrap_or_else(|e| e.into_inner()).insert(account_tag);
    }

    /// Registers an authorized VIP account tag directly.
    pub fn register_vip_tag(&self, account_tag: [u8; 32]) {
        self.vip_tags.write().unwrap_or_else(|e| e.into_inner()).insert(account_tag);
    }

    /// Registers a trusted F2F client with optional friendly label and stores metadata.
    pub fn register_f2f_client(&self, token: &str, label: Option<&str>) {
        let token_trimmed = token.trim();
        let token_hash = hex::encode(blake3::hash(token_trimmed.as_bytes()).as_bytes());
        let client_label = match label {
            Some(l) if !l.trim().is_empty() => l.trim().to_string(),
            _ => format!("Client-{}", &token_hash[..8]),
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let meta = F2fClientMeta {
            token: token_trimmed.to_string(),
            token_hash: token_hash.clone(),
            label: client_label,
            registered_at_ms: now_ms,
            last_active_ms: None,
        };

        self.f2f_clients
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_hash, meta);
        self.f2f_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_trimmed.to_string());
    }

    /// Registers a trusted F2F peer token.
    pub fn register_f2f_peer(&self, token: impl Into<String>) {
        let token_str = token.into();
        self.register_f2f_client(&token_str, None);
    }

    /// Removes an F2F client by token string or token hash. Returns true if removed.
    pub fn remove_f2f_client(&self, token_or_hash: &str) -> bool {
        let target = token_or_hash.trim();
        let mut clients = self.f2f_clients.write().unwrap_or_else(|e| e.into_inner());
        let mut tokens = self.f2f_tokens.write().unwrap_or_else(|e| e.into_inner());

        let mut found_hash = None;
        let mut found_token = None;

        for (h, meta) in clients.iter() {
            if h == target || meta.token == target {
                found_hash = Some(h.clone());
                found_token = Some(meta.token.clone());
                break;
            }
        }

        if let Some(h) = found_hash {
            clients.remove(&h);
            if let Some(t) = found_token {
                tokens.remove(&t);
            }
            true
        } else {
            tokens.remove(target)
        }
    }

    /// Lists all registered F2F clients with their today's writes and quota status.
    pub fn list_f2f_clients(&self, now_ms: u64, _epoch_day: u64) -> Vec<F2fClientDto> {
        let clients = self.f2f_clients.read().unwrap_or_else(|e| e.into_inner());
        let thermo = self.thermometer.read().unwrap_or_else(|e| e.into_inner());
        let daily_limit = thermo.calculate_daily_quota(1.0, 1.0);

        let mut list = Vec::with_capacity(clients.len());
        for meta in clients.values() {
            let raw_hash = *blake3::hash(meta.token.as_bytes()).as_bytes();
            let peer_node_id: NodeId = u16::from_be_bytes([raw_hash[0], raw_hash[1]]);
            let writes_today = thermo.get_node_usage(peer_node_id);
            let whale_brake_active = writes_today >= daily_limit;
            let last_active_sec = meta.last_active_ms.map(|t| now_ms.saturating_sub(t) / 1000);

            list.push(F2fClientDto {
                token_hash: meta.token_hash.clone(),
                label: meta.label.clone(),
                writes_today,
                daily_limit,
                whale_brake_active,
                last_active_sec,
                token: None,
            });
        }

        list.sort_by(|a, b| a.label.cmp(&b.label));
        list
    }

    /// [INV-0929] Evaluates tier credentials, validates authorization, deducts quota (for VIP), or validates PoW (for Public).
    pub async fn evaluate_and_charge(
        &self,
        auth_token: Option<&str>,
        peer_token: Option<&str>,
        pow_challenge: Option<&str>,
        pow_nonce: Option<u64>,
        ttl_seconds: u64,
        parent_lock: Option<&[u8; 32]>,
    ) -> Result<IngressTier, IngressError> {
        self.evaluate_and_charge_with_time(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            parent_lock,
            None,
        )
        .await
    }

    /// [INV-0929] Evaluates tier credentials with decentralized network time, validates authorization, deducts quota (for VIP), or validates PoW (for Public).
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_and_charge_with_time(
        &self,
        auth_token: Option<&str>,
        peer_token: Option<&str>,
        pow_challenge: Option<&str>,
        pow_nonce: Option<u64>,
        ttl_seconds: u64,
        parent_lock: Option<&[u8; 32]>,
        now_ms: Option<u64>,
    ) -> Result<IngressTier, IngressError> {
        let now_sec = match now_ms {
            Some(ms) => ms / 1000,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let footprint_micro_bj = ByteYears::micro_from_ttl_seconds(ttl_seconds);

        // 1. Check Tier 1 (VIP) - in-memory atomic cache, no synchronous fsync stall (INV-0929 hot-path)
        if let Some(token) = auth_token {
            let account_tag = self.resolve_account_tag(token)?;
            let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
            self.try_charge_vip_in_memory(&account_tag, required_byte_years)?;
            self.vip_writes_today.fetch_add(1, Ordering::Relaxed);
            let vip_node_id: NodeId = u16::from_be_bytes([account_tag[0], account_tag[1]]);
            let epoch_day = match now_ms {
                Some(ms) => self.current_epoch_day_at(ms),
                None => self.current_epoch_day(),
            };
            let daily_quota = self.calculate_daily_quota(5.0, 1.0);
            let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
            thermo.try_accept_lock(epoch_day, vip_node_id, required_byte_years, daily_quota);
            thermo.record_write_ingress(now_sec, footprint_micro_bj);
            return Ok(IngressTier::Tier1Vip);
        }

        // 2. Check Tier 2 (F2F Peer) with Spec 09 dynamic daily quota
        if let Some(token) = peer_token {
            let token_trimmed = token.trim();
            let is_valid = self.f2f_tokens.read().unwrap_or_else(|e| e.into_inner()).contains(token_trimmed);
            if is_valid {
                let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
                let epoch_day = match now_ms {
                    Some(ms) => self.current_epoch_day_at(ms),
                    None => self.current_epoch_day(),
                };
                self.evaluate_f2f_quota(token_trimmed, required_byte_years, epoch_day)?;
                self.f2f_writes_today.fetch_add(1, Ordering::Relaxed);
                self.thermometer
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_write_ingress(now_sec, footprint_micro_bj);

                // Update last active timestamp
                let token_hash = hex::encode(blake3::hash(token_trimmed.as_bytes()).as_bytes());
                let activity_ms = match now_ms {
                    Some(ms) => ms,
                    None => std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0),
                };
                if let Some(meta) = self
                    .f2f_clients
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(&token_hash)
                {
                    meta.last_active_ms = Some(activity_ms);
                }

                return Ok(IngressTier::Tier2F2F);
            } else {
                return Err(IngressError::InvalidPeerToken);
            }
        }

        // 3. Check Tier 3 (Public - BLAKE3 PoW)
        let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
        let epoch_day = match now_ms {
            Some(ms) => self.current_epoch_day_at(ms),
            None => self.current_epoch_day(),
        };
        let p = parent_lock.copied().unwrap_or([0u8; 32]);
        let free_node_id: NodeId = u16::from_be_bytes([p[0], p[1]]);
        let daily_quota = self.calculate_daily_quota(1.0, 1.0);

        if self.pow_engine.default_difficulty() == 0 {
            self.free_writes_today.fetch_add(1, Ordering::Relaxed);
            let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
            thermo.try_accept_lock(epoch_day, free_node_id, required_byte_years, daily_quota);
            thermo.record_write_ingress(now_sec, footprint_micro_bj);
            return Ok(IngressTier::Tier3Public);
        }

        let load_factor = (self.rolling_24h_average_at(now_sec) as f64 / self.effective_ncb().max(1) as f64).clamp(0.0, 1.0);
        let dynamic_difficulty = self.pow_engine.required_difficulty_for_load(load_factor);

        match (pow_challenge, pow_nonce) {
            (Some(challenge), Some(nonce)) => {
                self.pow_engine.verify_pow_for_parent(challenge, nonce, dynamic_difficulty, parent_lock).await?;
                self.free_writes_today.fetch_add(1, Ordering::Relaxed);
                let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
                thermo.try_accept_lock(epoch_day, free_node_id, required_byte_years, daily_quota);
                thermo.record_write_ingress(now_sec, footprint_micro_bj);
                Ok(IngressTier::Tier3Public)
            }
            _ => {
                let (challenge, _, expires_at) = self.pow_engine.generate_challenge_for_parent(&p);
                Err(IngressError::PoWRequired {
                    challenge,
                    difficulty: dynamic_difficulty,
                    expires_at,
                })
            }
        }
    }

    /// Resolves an account tag from an auth token or direct hex representation.
    pub fn resolve_account_tag(&self, token: &str) -> Result<[u8; 32], IngressError> {
        // Strip optional "Bearer " prefix
        let token_cleaned = token.strip_prefix("Bearer ").unwrap_or(token).trim();

        // 1. Check registered token map
        if let Some(tag) = self.vip_tokens.read().unwrap_or_else(|e| e.into_inner()).get(token_cleaned) {
            return Ok(*tag);
        }

        // 2. If 64 hex characters, check direct account tag
        if token_cleaned.len() == 64 {
            if let Ok(bytes) = hex::decode(token_cleaned) {
                let mut tag = [0u8; 32];
                tag.copy_from_slice(&bytes);
                if self.vip_tags.read().unwrap_or_else(|e| e.into_inner()).contains(&tag) {
                    return Ok(tag);
                }
            }
        }

        Err(IngressError::InvalidAuthToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_tier_controller_vip_quota_deduction() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let controller = TierController::new(storage.clone(), pow);

        let account_tag = [0x55u8; 32];
        let token = "vip_secret_token_123";
        controller.register_vip_token(token, account_tag);

        // Initial quota: 1000 Byte-Years
        storage.set_quota(&account_tag, 1000).unwrap();

        // 1 Year TTL = 192 Byte-Years
        let tier = controller.evaluate_and_charge(
            Some(token),
            None,
            None,
            None,
            31_536_000,
            None,
        ).await.expect("VIP access");

        assert_eq!(tier, IngressTier::Tier1Vip);
        // In-memory cache must reflect deduction atomically (<1µs, no fsync stall)
        assert_eq!(controller.get_cached_vip_quota(&account_tag), Some(1000 - 192));
        // Durable storage is updated asynchronously; wait for background persist
        for _ in 0..30 {
            if storage.get_quota(&account_tag).unwrap() == 1000 - 192 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(storage.get_quota(&account_tag).unwrap(), 1000 - 192);

        // Exceed quota
        let result = controller.evaluate_and_charge(
            Some(token),
            None,
            None,
            None,
            31_536_000 * 5, // 5 years = 960 BY, available is 808
            None,
        ).await;
        assert!(matches!(result, Err(IngressError::QuotaExceeded { .. })));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_peer() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let controller = TierController::new(storage, pow);
        controller.register_f2f_peer("friend_node_token_abc");

        let tier = controller.evaluate_and_charge(
            None,
            Some("friend_node_token_abc"),
            None,
            None,
            60,
            None,
        ).await.expect("F2F access");
        assert_eq!(tier, IngressTier::Tier2F2F);

        let err = controller.evaluate_and_charge(
            None,
            Some("unknown_peer"),
            None,
            None,
            60,
            None,
        ).await;
        assert!(matches!(err, Err(IngressError::InvalidPeerToken)));
    }

    #[tokio::test]
    async fn test_tier_controller_public_pow() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_pow.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));

        let controller = TierController::new(storage, pow.clone());

        // Without PoW -> PoWRequired
        let err = controller.evaluate_and_charge(None, None, None, None, 60, None).await;
        let challenge = match err {
            Err(IngressError::PoWRequired { challenge, difficulty, .. }) => {
                assert_eq!(difficulty, 8);
                challenge
            }
            _ => panic!("Expected PoWRequired"),
        };

        // Solve PoW
        let nonce = PowEngine::solve_pow(&challenge, 8, 5000).expect("Solve");
        let tier = controller.evaluate_and_charge(
            None,
            None,
            Some(&challenge),
            Some(nonce),
            60,
            None,
        ).await.expect("PoW accepted");
        assert_eq!(tier, IngressTier::Tier3Public);
    }

    #[tokio::test]
    async fn test_tier_controller_network_thermometer_seeding_and_fast_reseed() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_thermo.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        // Initial state: default hard floor baseline
        assert_eq!(controller.effective_ncb(), 960_000);

        // Kaltstart / Seed from peers
        controller.seed_from_peers(2_000_000);
        assert_eq!(controller.effective_ncb(), 2_000_000);

        // Fast-Re-Seed on merge (z.B. Dorf dockt an Weltnetz an)
        controller.fast_reseed_on_merge(10_000_000);
        assert_eq!(controller.effective_ncb(), 10_000_000);

        // Hard-Floor guarantee: seeding below hard floor cannot drop below baseline
        controller.seed_from_peers(100);
        assert_eq!(controller.effective_ncb(), 960_000);

        // Push daily medians to 28-day slotted ring buffer
        for _ in 0..28 {
            controller.record_daily_median(1_500_000);
        }
        assert_eq!(controller.effective_ncb(), 1_500_000);
    }

    #[tokio::test]
    async fn test_tier_controller_dynamic_f2f_and_vip_quotas_with_whale_brake() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_quotas.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        // Baseline: 960_000
        let quota_standard = controller.calculate_daily_quota(1.0, 1.0);
        assert_eq!(quota_standard, 960_000);

        // Whale brake: K clamped to 5.0
        let quota_whale_k5 = controller.calculate_daily_quota(5.0, 1.0);
        assert_eq!(quota_whale_k5, 960_000 * 5);

        let quota_whale_k10 = controller.calculate_daily_quota(10.0, 1.0);
        assert_eq!(quota_whale_k10, 960_000 * 5, "Whale brake must clamp K <= 5.0");

        // F2F dynamic quota evaluation
        let peer_token = "peer_token_dynamic_123";
        controller.register_f2f_peer(peer_token);

        // 1 Year TTL = 192 Byte-Years, fits easily into 960_000
        let res = controller.evaluate_f2f_quota(peer_token, 192, 1);
        assert!(matches!(res, Ok(())), "F2F quota 192 must be Ok, got {:?}", res);

        // Exceed daily quota in single epoch day
        let res_exceed = controller.evaluate_f2f_quota(peer_token, 960_000, 1);
        assert!(matches!(res_exceed, Err(IngressError::QuotaExceeded { .. })));

        // Next epoch day resets usage
        let res_next_day = controller.evaluate_f2f_quota(peer_token, 192, 2);
        assert!(matches!(res_next_day, Ok(())), "next day quota must reset, got {:?}", res_next_day);

        // VIP dynamic quota evaluation
        let vip_tag = [0x77u8; 32];
        let res_vip = controller.evaluate_vip_quota(&vip_tag, 960_000 * 4, 1, 5.0);
        assert!(matches!(res_vip, Ok(())), "VIP quota must be Ok, got {:?}", res_vip);

        // Exceeding K=5.0 limit for VIP
        let res_vip_exceed = controller.evaluate_vip_quota(&vip_tag, 960_000 * 2, 1, 5.0);
        assert!(matches!(res_vip_exceed, Err(IngressError::QuotaExceeded { .. })));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_client_registration_and_list() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f_clients.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        let token = "my_pos_terminal_token_xyz";
        controller.register_f2f_client(token, Some("Kasse-1"));

        let now_ms = 1_700_000_000_000;
        let epoch_day = controller.current_epoch_day_at(now_ms);

        let clients = controller.list_f2f_clients(now_ms, epoch_day);
        assert_eq!(clients.len(), 1);
        let c = &clients[0];
        assert_eq!(c.label, "Kasse-1");
        assert_eq!(c.writes_today, 0);
        assert_eq!(c.daily_limit, 960_000);
        assert!(!c.whale_brake_active);
        assert_eq!(c.last_active_sec, None);
        assert_eq!(c.token, None);

        // Perform an authenticated F2F write
        let tier = controller
            .evaluate_and_charge_with_time(None, Some(token), None, None, 60, None, Some(now_ms))
            .await
            .expect("F2F write allowed");
        assert_eq!(tier, IngressTier::Tier2F2F);

        // Check list after 10 seconds
        let clients_after = controller.list_f2f_clients(now_ms + 10_000, epoch_day);
        assert_eq!(clients_after.len(), 1);
        assert_eq!(clients_after[0].last_active_sec, Some(10));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_client_removal() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f_remove.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new([0x11; 32], 8));
        let controller = TierController::new(storage, pow);

        let token = "removable_client_token";
        controller.register_f2f_client(token, Some("Kasse-Alt"));

        let token_hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());

        // Remove by hash
        assert!(controller.remove_f2f_client(&token_hash));
        assert_eq!(controller.list_f2f_clients(0, 0).len(), 0);

        // Re-register and remove by token
        controller.register_f2f_client(token, None);
        assert_eq!(controller.list_f2f_clients(0, 0).len(), 1);
        assert!(controller.remove_f2f_client(token));
        assert_eq!(controller.list_f2f_clients(0, 0).len(), 0);

        // Non-existent returns false
        assert!(!controller.remove_f2f_client("non_existent"));
    }
}
