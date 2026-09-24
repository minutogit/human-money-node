use std::collections::{HashMap, HashSet};
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
#[derive(Clone)]
pub struct TierController {
    storage: Arc<RedbStorage>,
    pow_engine: Arc<PowEngine>,
    vip_tokens: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    vip_tags: Arc<RwLock<HashSet<[u8; 32]>>>,
    f2f_tokens: Arc<RwLock<HashSet<String>>>,
    thermometer: Arc<RwLock<NetworkThermometer>>,
    vip_quota_cache: Arc<PlRwLock<HashMap<[u8; 32], u64>>>,
}

impl TierController {
    /// Creates a new TierController with storage, PoW engine, and initialized NetworkThermometer.
    pub fn new(storage: Arc<RedbStorage>, pow_engine: Arc<PowEngine>) -> Self {
        Self {
            storage,
            pow_engine,
            vip_tokens: Arc::new(RwLock::new(HashMap::new())),
            vip_tags: Arc::new(RwLock::new(HashSet::new())),
            f2f_tokens: Arc::new(RwLock::new(HashSet::new())),
            thermometer: Arc::new(RwLock::new(NetworkThermometer::new())),
            vip_quota_cache: Arc::new(PlRwLock::new(HashMap::new())),
        }
    }

    /// Returns the cached VIP quota for an account, if present in the in-memory cache.
    pub fn get_cached_vip_quota(&self, account_tag: &[u8; 32]) -> Option<u64> {
        self.vip_quota_cache.read().get(account_tag).copied()
    }

    /// Sets the cached VIP quota directly (e.g. after top-up via control plane).
    pub fn set_cached_vip_quota(&self, account_tag: [u8; 32], balance: u64) {
        self.vip_quota_cache.write().insert(account_tag, balance);
    }

    /// Hydrates the in-memory cache from durable storage (read-only, no fsync).
    pub fn hydrate_vip_quota(&self, account_tag: &[u8; 32]) -> Result<u64, StorageError> {
        let bal = self.storage.get_quota(account_tag)?;
        self.vip_quota_cache.write().insert(*account_tag, bal);
        Ok(bal)
    }

    /// Flushes a single cached balance to durable storage asynchronously without blocking hot-path.
    fn persist_vip_quota_async(&self, account_tag: [u8; 32], remaining: u64) {
        let storage = self.storage.clone();
        tokio::spawn(async move {
            let res = tokio::task::spawn_blocking(move || storage.set_quota(&account_tag, remaining)).await;
            if let Err(e) = res {
                tracing::warn!("async VIP quota persist join error: {:?}", e);
            }
        });
    }

    /// In-memory atomic check-and-charge for VIP quota (hot-path, <1µs, no fsync stall).
    /// Returns remaining balance after deduction or QuotaExceeded.
    pub fn try_charge_vip_in_memory(&self, account_tag: &[u8; 32], required: u64) -> Result<u64, IngressError> {
        let mut cache = self.vip_quota_cache.write();
        let bal = cache.entry(*account_tag).or_insert_with(|| self.storage.get_quota(account_tag).unwrap_or(0));
        // If cached insufficient, refresh from disk once (handles top-up race before blocking)
        if *bal < required {
            let disk_bal = self.storage.get_quota(account_tag).unwrap_or(0);
            if disk_bal > *bal {
                *bal = disk_bal;
            }
            if *bal < required {
                return Err(IngressError::QuotaExceeded {
                    available: *bal,
                    required,
                });
            }
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

    /// [INV-0921] Records an hourly median in the 24-hour slotted ring buffer
    pub fn record_hourly_median(&self, epoch_hour: u64, median: u64) {
        self.thermometer.write().unwrap_or_else(|e| e.into_inner()).record_hourly_median(epoch_hour, median);
    }

    /// Returns the current rolling 24-hour average of the hourly ring buffer
    pub fn rolling_24h_average(&self) -> u64 {
        self.thermometer.read().unwrap_or_else(|e| e.into_inner()).rolling_24h_average()
    }

    /// [INV-0923] Records a daily read median
    pub fn record_daily_read_median(&self, median: u64) {
        self.thermometer.write().unwrap_or_else(|e| e.into_inner()).record_daily_read_median(median);
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

    /// Registers a trusted F2F peer token.
    pub fn register_f2f_peer(&self, token: impl Into<String>) {
        self.f2f_tokens.write().unwrap_or_else(|e| e.into_inner()).insert(token.into());
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
        // 1. Check Tier 1 (VIP) - in-memory atomic cache, no synchronous fsync stall (INV-0929 hot-path)
        if let Some(token) = auth_token {
            let account_tag = self.resolve_account_tag(token)?;
            let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
            self.try_charge_vip_in_memory(&account_tag, required_byte_years)?;
            return Ok(IngressTier::Tier1Vip);
        }

        // 2. Check Tier 2 (F2F Peer) with Spec 09 dynamic daily quota
        if let Some(token) = peer_token {
            let is_valid = self.f2f_tokens.read().unwrap_or_else(|e| e.into_inner()).contains(token);
            if is_valid {
                let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
                let epoch_day = match now_ms {
                    Some(ms) => self.current_epoch_day_at(ms),
                    None => self.current_epoch_day(),
                };
                self.evaluate_f2f_quota(token, required_byte_years, epoch_day)?;
                return Ok(IngressTier::Tier2F2F);
            } else {
                return Err(IngressError::InvalidPeerToken);
            }
        }

        // 3. Check Tier 3 (Public - BLAKE3 PoW)
        if self.pow_engine.default_difficulty() == 0 {
            return Ok(IngressTier::Tier3Public);
        }

        let load_factor = (self.rolling_24h_average() as f64 / self.effective_ncb().max(1) as f64).clamp(0.0, 1.0);
        let dynamic_difficulty = self.pow_engine.required_difficulty_for_load(load_factor);

        match (pow_challenge, pow_nonce) {
            (Some(challenge), Some(nonce)) => {
                self.pow_engine.verify_pow_for_parent(challenge, nonce, dynamic_difficulty, parent_lock).await?;
                Ok(IngressTier::Tier3Public)
            }
            _ => {
                let p = parent_lock.copied().unwrap_or([0u8; 32]);
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
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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
}
