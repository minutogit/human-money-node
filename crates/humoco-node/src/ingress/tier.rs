use parking_lot::RwLock as PlRwLock;
use rand::RngCore;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::ingress::pow::{PowEngine, PowError};
use crate::storage::{RedbStorage, StorageError};
use humoco_sim_core::quota::{
    ByteYears, NetworkThermometer, RollingQuotaCounter, MAX_WHALE_MULTIPLIER,
};
use humoco_sim_core::types::NodeId;

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

/// Returns true if the token matches the required random 128-bit secret format `f2f_<32 hex digits>` (AGENTS.md / A25-R4).
pub fn is_valid_client_token(token: &str) -> bool {
    let t = token.trim();
    if !t.starts_with("f2f_") {
        return false;
    }
    let suffix = &t[4..];
    suffix.len() == 32 && suffix.chars().all(|c| c.is_ascii_hexdigit())
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

    #[error("VIP Quota persistence queue is full or closed")]
    QuotaPersistenceUnavailable,

    #[error("Ingress accounting persistence unavailable")]
    AccountingPersistenceUnavailable,

    #[error("Internal ingress error: {0}")]
    Internal(String),
}

/// FIFO-sequenced VIP quota persist operation.
#[derive(Debug, Clone, Copy)]
struct VipQuotaPersistOp {
    account_tag: [u8; 32],
    remaining: u64,
}

pub const INGRESS_SEQ_LEASE_BLOCK: u64 = 1024;

#[derive(Debug, Default)]
struct IngressAccountingState {
    current_day: u64,
    epoch_seq: u64,
    last_timestamp_ms: u64,
    cumulative_micro_byte_years: u64,
    prev_day_final_bytes: u64,
    persisted_day: u64,
    persisted_reserved_seq: u64,
}

/// Sealed allocation result returned by `record_declared_usage` (S05-11).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeclaredIngressAllocation {
    pub epoch_day: u32,
    pub epoch_seq: u64,
    pub timestamp_ms: u64,
    pub cumulative_micro_byte_years: u64,
    pub prev_day_final_bytes: u64,
    pub declared_write_ema_micro_bj: u64,
    pub declared_read_ema_credits: u64,
}

pub const DOMAIN_VIP_BEARER_TOKEN: &[u8] = b"HUMOCO_V1_VIP_BEARER_TOKEN";

/// Computes length-prefixed domain-separated hash of a VIP bearer secret (S05-12).
pub fn compute_vip_token_hash(token: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[DOMAIN_VIP_BEARER_TOKEN.len() as u8]);
    hasher.update(DOMAIN_VIP_BEARER_TOKEN);
    hasher.update(token.as_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone)]
pub struct TierController {
    storage: Arc<RedbStorage>,
    pow_engine: Arc<PowEngine>,
    vip_credentials: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    f2f_tokens: Arc<RwLock<HashSet<String>>>,
    f2f_clients: Arc<RwLock<HashMap<String, F2fClientMeta>>>,
    thermometer: Arc<RwLock<NetworkThermometer>>,
    vip_quota_cache: Arc<PlRwLock<HashMap<[u8; 32], u64>>>,
    vip_writes_today: Arc<AtomicU64>,
    f2f_writes_today: Arc<AtomicU64>,
    free_writes_today: Arc<AtomicU64>,
    accounting_state: Arc<parking_lot::Mutex<IngressAccountingState>>,
    last_thermometer_day: Arc<AtomicU64>,
    vip_persist_tx: tokio::sync::mpsc::Sender<VipQuotaPersistOp>,
    vip_persist_worker: tokio::task::AbortHandle,
    vip_persist_failed: Arc<AtomicBool>,
    accounting_persist_tx: tokio::sync::mpsc::Sender<(
        crate::storage::PersistedIngressAccountingState,
        tokio::sync::oneshot::Sender<Result<(), IngressError>>,
    )>,
    accounting_persist_worker: tokio::task::AbortHandle,
    accounting_persist_failed: Arc<AtomicBool>,
    vip_rolling_usage: Arc<RwLock<HashMap<[u8; 32], RollingQuotaCounter>>>,
    f2f_rolling_usage: Arc<RwLock<HashMap<[u8; 32], RollingQuotaCounter>>>,
    free_rolling_usage: Arc<RwLock<RollingQuotaCounter>>,
    p2p_node_usage: Arc<RwLock<HashMap<[u8; 32], RollingQuotaCounter>>>,
    p2p_node_read_usage: Arc<RwLock<HashMap<[u8; 32], RollingQuotaCounter>>>,
}

/// Derives a deterministic opaque diagnostic identifier for a VIP account tag.
/// This identifier is safe to display in operator dashboards, telemetry, and event logs,
/// as it reveals zero information about the bearer secret and cannot be used for authentication.
pub fn vip_diagnostic_id(account_tag: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("HUMOCO_V1_VIP_DIAG_ID");
    hasher.update(account_tag);
    let digest = hasher.finalize();
    format!("vip_{}", &hex::encode(digest.as_bytes())[..16])
}

impl TierController {
    /// Creates a new TierController backed by storage, PoW engine, and network thermometer.
    /// Spawns a background worker for asynchronous persistence of VIP quotas with default channel capacity 1024.
    pub fn new(storage: Arc<RedbStorage>, pow_engine: Arc<PowEngine>) -> Self {
        Self::new_with_persist_capacity(storage, pow_engine, 1024)
    }

    /// Creates a new TierController with custom persist channel capacity (for testing queue saturation).
    pub fn new_with_persist_capacity(
        storage: Arc<RedbStorage>,
        pow_engine: Arc<PowEngine>,
        persist_channel_capacity: usize,
    ) -> Self {
        let (vip_persist_tx, mut vip_persist_rx) =
            tokio::sync::mpsc::channel::<VipQuotaPersistOp>(persist_channel_capacity.max(1));
        let storage_clone = storage.clone();
        let vip_persist_failed = Arc::new(AtomicBool::new(false));
        let vip_persist_failed_clone = vip_persist_failed.clone();

        let worker = tokio::spawn(async move {
            while let Some(first_op) = vip_persist_rx.recv().await {
                let mut batch = vec![(first_op.account_tag, first_op.remaining)];
                while let Ok(op) = vip_persist_rx.try_recv() {
                    batch.push((op.account_tag, op.remaining));
                    if batch.len() >= 256 {
                        break;
                    }
                }
                let s = storage_clone.clone();
                let res =
                    tokio::task::spawn_blocking(move || s.set_quotas_batch(&batch)).await;
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        eprintln!("CRITICAL: VIP quota async persist error: {:?}", e);
                        vip_persist_failed_clone.store(true, Ordering::Release);
                    }
                    Err(join_err) => {
                        eprintln!(
                            "CRITICAL: VIP quota async persist panic/cancelled: {:?}",
                            join_err
                        );
                        vip_persist_failed_clone.store(true, Ordering::Release);
                    }
                }
            }
        });

        let (accounting_persist_tx, mut accounting_persist_rx) =
            tokio::sync::mpsc::channel::<(
                crate::storage::PersistedIngressAccountingState,
                tokio::sync::oneshot::Sender<Result<(), IngressError>>,
            )>(persist_channel_capacity.max(1));
        let accounting_storage = storage.clone();
        let accounting_persist_failed = Arc::new(AtomicBool::new(false));
        let accounting_persist_failed_clone = accounting_persist_failed.clone();

        let accounting_worker = tokio::spawn(async move {
            while let Some((first_state, first_tx)) = accounting_persist_rx.recv().await {
                let mut highest = first_state;
                let mut waiters: Vec<tokio::sync::oneshot::Sender<Result<(), IngressError>>> =
                    vec![first_tx];
                while let Ok((next_state, next_tx)) = accounting_persist_rx.try_recv() {
                    if next_state.current_day > highest.current_day
                        || (next_state.current_day == highest.current_day
                            && (next_state.reserved_epoch_seq > highest.reserved_epoch_seq
                                || (next_state.reserved_epoch_seq == highest.reserved_epoch_seq
                                    && next_state.cumulative_micro_byte_years > highest.cumulative_micro_byte_years)))
                    {
                        highest = next_state;
                    }
                    waiters.push(next_tx);
                    if waiters.len() >= 256 {
                        break;
                    }
                }
                let s = accounting_storage.clone();
                let res = tokio::task::spawn_blocking(move || {
                    s.store_ingress_accounting_state(&highest)
                })
                .await;

                match res {
                    Ok(Ok(())) => {
                        for tx in waiters {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("CRITICAL: Ingress accounting async persist error: {:?}", e);
                        accounting_persist_failed_clone.store(true, Ordering::Release);
                        for tx in waiters {
                            let _ = tx.send(Err(IngressError::AccountingPersistenceUnavailable));
                        }
                    }
                    Err(join_err) => {
                        eprintln!(
                            "CRITICAL: Ingress accounting async persist panic/cancelled: {:?}",
                            join_err
                        );
                        accounting_persist_failed_clone.store(true, Ordering::Release);
                        for tx in waiters {
                            let _ = tx.send(Err(IngressError::AccountingPersistenceUnavailable));
                        }
                    }
                }
            }
        });

        let mut initial_accounting = IngressAccountingState::default();
        match storage.load_ingress_accounting_state() {
            Ok(Some(st)) => {
                let start_day = st.current_day;
                let start_seq = st.reserved_epoch_seq;
                initial_accounting.last_timestamp_ms = st.last_timestamp_ms;
                initial_accounting.cumulative_micro_byte_years = st.cumulative_micro_byte_years;
                initial_accounting.prev_day_final_bytes = st.prev_day_final_bytes;

                let pre_reserved = start_seq.saturating_add(INGRESS_SEQ_LEASE_BLOCK);
                let pre_state = crate::storage::PersistedIngressAccountingState {
                    current_day: start_day,
                    reserved_epoch_seq: pre_reserved,
                    last_timestamp_ms: initial_accounting.last_timestamp_ms,
                    cumulative_micro_byte_years: initial_accounting.cumulative_micro_byte_years,
                    prev_day_final_bytes: initial_accounting.prev_day_final_bytes,
                };
                match storage.store_ingress_accounting_state(&pre_state) {
                    Ok(()) => {
                        initial_accounting.current_day = start_day;
                        initial_accounting.epoch_seq = start_seq;
                        initial_accounting.persisted_day = start_day;
                        initial_accounting.persisted_reserved_seq = pre_reserved;
                    }
                    Err(e) => {
                        eprintln!("CRITICAL: Failed to pre-reserve ingress lease block: {:?}", e);
                        accounting_persist_failed.store(true, Ordering::Release);
                    }
                }
            }
            Ok(None) => {
                let boot_day = pow_engine.now_ms() / (86_400 * 1000);
                let pre_state = crate::storage::PersistedIngressAccountingState {
                    current_day: boot_day,
                    reserved_epoch_seq: INGRESS_SEQ_LEASE_BLOCK,
                    last_timestamp_ms: 0,
                    cumulative_micro_byte_years: 0,
                    prev_day_final_bytes: 0,
                };
                match storage.store_ingress_accounting_state(&pre_state) {
                    Ok(()) => {
                        initial_accounting.current_day = boot_day;
                        initial_accounting.epoch_seq = 0;
                        initial_accounting.persisted_day = boot_day;
                        initial_accounting.persisted_reserved_seq = INGRESS_SEQ_LEASE_BLOCK;
                    }
                    Err(e) => {
                        eprintln!("CRITICAL: Failed to pre-reserve ingress lease block: {:?}", e);
                        accounting_persist_failed.store(true, Ordering::Release);
                    }
                }
            }
            Err(e) => {
                eprintln!("CRITICAL: Failed to load ingress accounting state: {:?}", e);
                accounting_persist_failed.store(true, Ordering::Release);
            }
        }

        let mut initial_vip_credentials = HashMap::new();
        match storage.all_vip_credentials() {
            Ok(creds) => {
                for (token_hash, account_tag) in creds {
                    initial_vip_credentials.insert(token_hash, account_tag);
                }
            }
            Err(e) => {
                eprintln!("CRITICAL: Failed to load VIP credentials: {:?}", e);
            }
        }

        let mut initial_cache = HashMap::new();
        if let Ok(all) = storage.all_quotas() {
            for (tag, bal) in all {
                initial_cache.insert(tag, bal);
            }
        }

        Self {
            storage,
            pow_engine,
            vip_credentials: Arc::new(RwLock::new(initial_vip_credentials)),
            f2f_tokens: Arc::new(RwLock::new(HashSet::new())),
            f2f_clients: Arc::new(RwLock::new(HashMap::new())),
            thermometer: Arc::new(RwLock::new(NetworkThermometer::new())),
            vip_quota_cache: Arc::new(PlRwLock::new(initial_cache)),
            vip_writes_today: Arc::new(AtomicU64::new(0)),
            f2f_writes_today: Arc::new(AtomicU64::new(0)),
            free_writes_today: Arc::new(AtomicU64::new(0)),
            accounting_state: Arc::new(parking_lot::Mutex::new(initial_accounting)),
            last_thermometer_day: Arc::new(AtomicU64::new(0)),
            vip_persist_tx,
            vip_persist_worker: worker.abort_handle(),
            vip_persist_failed,
            accounting_persist_tx,
            accounting_persist_worker: accounting_worker.abort_handle(),
            accounting_persist_failed,
            vip_rolling_usage: Arc::new(RwLock::new(HashMap::new())),
            f2f_rolling_usage: Arc::new(RwLock::new(HashMap::new())),
            free_rolling_usage: Arc::new(RwLock::new(RollingQuotaCounter::new())),
            p2p_node_usage: Arc::new(RwLock::new(HashMap::new())),
            p2p_node_read_usage: Arc::new(RwLock::new(HashMap::new())),
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

    /// Registers natural FIFO accounting-worker completion with daemon teardown (S05-11).
    pub fn accounting_worker_abort_handle(&self) -> tokio::task::AbortHandle {
        self.accounting_persist_worker.clone()
    }

    /// Local persistence failure evidence for truthful accounting worker failure (S05-11).
    pub fn accounting_worker_failure_handle(&self) -> Arc<AtomicBool> {
        self.accounting_persist_failed.clone()
    }
}

impl TierController {

    /// Injects an accounting persistence failure for testing.
    pub fn fail_accounting_persistence_for_test(&self) {
        self.accounting_persist_failed.store(true, Ordering::Release);
    }

    /// Reserves an accounting persistence permit to simulate queue saturation for testing.
    pub fn reserve_accounting_permit_for_test(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.accounting_persist_tx
            .clone()
            .try_reserve_owned()
            .ok()
            .map(|permit| Box::new(permit) as Box<dyn std::any::Any + Send>)
    }

    /// Returns the effective consensus timestamp in milliseconds, preferring explicit caller timestamp,
    /// falling back to the attached NetworkClock (or SystemTime when unclocked).
    pub fn effective_now_ms(&self, now_ms: Option<u64>) -> u64 {
        now_ms.unwrap_or_else(|| self.pow_engine.now_ms())
    }

    /// Returns the current consensus timestamp in milliseconds from the attached clock/engine.
    #[inline]
    pub fn now_ms(&self) -> u64 {
        self.effective_now_ms(None)
    }

    /// Returns decayed write EMA at `now_sec` (S07-10).
    pub fn write_ema_micro_bj_at(&self, now_sec: u64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .write_ema_micro_bj_at(now_sec)
    }

    /// Returns decayed read EMA credits at `now_sec` (S07-10).
    pub fn read_ema_credits_at(&self, now_sec: u64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .read_ema_credits_at(now_sec)
    }

    /// Records gateway declared usage, advancing day roll-over if needed, persisting state durably
    /// before releasing allocation to callers (S05-11).
    ///
    /// Uses a single short-held mutex covering day selection/rollover, sequence allocation,
    /// and cumulative usage. Awaits durable batch persistence before returning Ok.
    pub async fn record_declared_usage(
        &self,
        now_ms: u64,
        footprint_micro_bj: u64,
    ) -> Result<DeclaredIngressAllocation, IngressError> {
        if self.accounting_persist_failed.load(Ordering::Acquire) {
            return Err(IngressError::AccountingPersistenceUnavailable);
        }

        let permit = self
            .accounting_persist_tx
            .try_reserve()
            .map_err(|_| IngressError::AccountingPersistenceUnavailable)?;

        let incoming_day = self.current_epoch_day_at(now_ms);
        let (
            persisted,
            effective_day,
            seq,
            effective_ts_ms,
            cum,
            prev,
            already_durably_reserved,
            target_reserved_seq,
        ) = {
            let mut state = self.accounting_state.lock();
            if state.current_day == 0 {
                state.current_day = incoming_day;
            } else if incoming_day > state.current_day {
                state.prev_day_final_bytes = state.cumulative_micro_byte_years;
                state.cumulative_micro_byte_years = 0;
                state.epoch_seq = 0;
                state.current_day = incoming_day;
            } else if incoming_day < state.current_day && state.epoch_seq == 0 {
                // If no envelopes have ever been issued, adopt the incoming day (e.g. simulated test time)
                state.current_day = incoming_day;
                state.persisted_day = 0;
                state.persisted_reserved_seq = 0;
            }
            let effective_day = state.current_day;
            let effective_ts_ms = now_ms
                .max(state.last_timestamp_ms)
                .max(effective_day.saturating_mul(86_400_000));
            let seq = state
                .epoch_seq
                .checked_add(1)
                .ok_or_else(|| IngressError::Internal("epoch_seq overflow".into()))?;
            state.epoch_seq = seq;
            state.last_timestamp_ms = effective_ts_ms;
            state.cumulative_micro_byte_years = state
                .cumulative_micro_byte_years
                .saturating_add(footprint_micro_bj);
            let cum = state.cumulative_micro_byte_years;
            let prev = state.prev_day_final_bytes;

            let already_durably_reserved =
                effective_day == state.persisted_day && seq <= state.persisted_reserved_seq;
            let target_reserved_seq = if already_durably_reserved {
                state.persisted_reserved_seq
            } else {
                seq.saturating_add(INGRESS_SEQ_LEASE_BLOCK.saturating_sub(1))
            };
            let persisted = crate::storage::PersistedIngressAccountingState {
                current_day: effective_day,
                reserved_epoch_seq: target_reserved_seq,
                last_timestamp_ms: effective_ts_ms,
                cumulative_micro_byte_years: cum,
                prev_day_final_bytes: prev,
            };
            (
                persisted,
                effective_day,
                seq,
                effective_ts_ms,
                cum,
                prev,
                already_durably_reserved,
                target_reserved_seq,
            )
        };

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        permit.send((persisted, ack_tx));

        let (declared_write_ema, declared_read_ema) = self
            .thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint_emas_at(effective_ts_ms / 1000);

        if !already_durably_reserved {
            match ack_rx.await {
                Ok(Ok(())) => {
                    let mut st = self.accounting_state.lock();
                    st.persisted_day = effective_day;
                    st.persisted_reserved_seq = target_reserved_seq;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(IngressError::AccountingPersistenceUnavailable),
            }
        }

        Ok(DeclaredIngressAllocation {
            epoch_day: effective_day as u32,
            epoch_seq: seq,
            timestamp_ms: effective_ts_ms,
            cumulative_micro_byte_years: cum,
            prev_day_final_bytes: prev,
            declared_write_ema_micro_bj: declared_write_ema,
            declared_read_ema_credits: declared_read_ema,
        })
    }

    /// Flushes all queued ingress accounting updates to storage and awaits completion.
    pub async fn wait_for_accounting_drain(&self) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let persisted = {
            let state = self.accounting_state.lock();
            crate::storage::PersistedIngressAccountingState {
                current_day: state.current_day,
                reserved_epoch_seq: state.persisted_reserved_seq,
                last_timestamp_ms: state.last_timestamp_ms,
                cumulative_micro_byte_years: state.cumulative_micro_byte_years,
                prev_day_final_bytes: state.prev_day_final_bytes,
            }
        };
        if let Ok(permit) = self.accounting_persist_tx.reserve().await {
            permit.send((persisted, ack_tx));
            let _ = ack_rx.await;
        }
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

    /// Tops up VIP quota for an account, updating cache and persisting with strict FIFO ordering (A02-02).
    /// Resolves cold misses outside the write lock, reserves persistence capacity, and sends
    /// the updated balance before releasing the cache write lock.
    pub fn topup_vip_quota(
        &self,
        account_tag: [u8; 32],
        byte_years: u64,
    ) -> Result<u64, IngressError> {
        if self.vip_persist_failed.load(Ordering::Acquire) {
            return Err(IngressError::QuotaPersistenceUnavailable);
        }

        let pre_bal = if !self.vip_quota_cache.read().contains_key(&account_tag) {
            Some(self.storage.get_quota(&account_tag)?)
        } else {
            None
        };

        let mut cache = self.vip_quota_cache.write();
        if let Some(bal) = pre_bal {
            cache.entry(account_tag).or_insert(bal);
        }
        let permit = self
            .vip_persist_tx
            .try_reserve()
            .map_err(|_| IngressError::QuotaPersistenceUnavailable)?;
        let bal = cache.entry(account_tag).or_insert(0);
        *bal = bal.saturating_add(byte_years);
        let new_balance = *bal;
        permit.send(VipQuotaPersistOp {
            account_tag,
            remaining: new_balance,
        });
        drop(cache);
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

    /// Returns all VIP accounts with deterministic opaque diagnostic identifiers.
    /// Never returns raw bearer secrets or authenticatable credentials.
    pub fn list_vip_accounts(&self) -> Vec<(String, u64)> {
        let cache = self.vip_quota_cache.read();
        let mut list = Vec::with_capacity(cache.len());
        for (tag, balance) in cache.iter() {
            list.push((vip_diagnostic_id(tag), *balance));
        }
        list.sort_by(|a, b| a.0.cmp(&b.0));
        list
    }

    /// Hydrates the in-memory cache from durable storage (read-only, no fsync).
    /// Idempotent with respect to cached balance: preserves an already-initialized or mutated balance.
    pub fn hydrate_vip_quota(&self, account_tag: &[u8; 32]) -> Result<u64, StorageError> {
        if let Some(existing) = self.vip_quota_cache.read().get(account_tag).copied() {
            return Ok(existing);
        }
        let bal = self.storage.get_quota(account_tag)?;
        let mut cache = self.vip_quota_cache.write();
        let current = *cache.entry(*account_tag).or_insert(bal);
        Ok(current)
    }

    /// Ensures that the specified VIP account tag is hydrated in the in-memory cache.
    /// If not present (cold miss), loads it asynchronously from durable storage via spawn_blocking,
    /// avoiding synchronous disk I/O under the cache write lock (A05-01).
    /// Uses `entry().or_insert()` to ensure concurrent mutations are never overwritten.
    pub async fn ensure_vip_quota_cached(
        &self,
        account_tag: &[u8; 32],
    ) -> Result<(), IngressError> {
        if self.vip_quota_cache.read().contains_key(account_tag) {
            return Ok(());
        }
        let storage = self.storage.clone();
        let tag = *account_tag;
        let bal = tokio::task::spawn_blocking(move || storage.get_quota(&tag))
            .await
            .map_err(|e| {
                IngressError::Storage(StorageError::Io(std::io::Error::other(e.to_string())))
            })?
            .map_err(IngressError::Storage)?;
        self.vip_quota_cache.write().entry(*account_tag).or_insert(bal);
        Ok(())
    }

    /// In-memory atomic check-and-charge for VIP quota (hot-path, <1µs, no fsync stall).
    /// Enforces Reservation-First: reserves persistence capacity BEFORE mutating RAM balance (A02-02).
    /// Dispatches permit into FIFO channel BEFORE dropping cache write lock to preserve strict ordering.
    pub fn try_charge_vip_in_memory(
        &self,
        account_tag: &[u8; 32],
        required: u64,
    ) -> Result<u64, IngressError> {
        if self.vip_persist_failed.load(Ordering::Acquire) {
            return Err(IngressError::QuotaPersistenceUnavailable);
        }
        let mut cache = self.vip_quota_cache.write();
        let bal = cache.entry(*account_tag).or_insert(0);
        if *bal < required {
            return Err(IngressError::QuotaExceeded {
                available: *bal,
                required,
            });
        }
        let permit = self
            .vip_persist_tx
            .try_reserve()
            .map_err(|_| IngressError::QuotaPersistenceUnavailable)?;
        *bal -= required;
        let remaining = *bal;
        permit.send(VipQuotaPersistOp {
            account_tag: *account_tag,
            remaining,
        });
        drop(cache);
        Ok(remaining)
    }

    /// Returns a reference to the decentralized network thermometer (Spec 09).
    pub fn thermometer(&self) -> Arc<RwLock<NetworkThermometer>> {
        self.thermometer.clone()
    }

    /// [INV-0907]
    /// Initializes the thermometer of a new node with the current peer median
    pub fn seed_from_peers(&self, peer_median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .seed_from_peers(peer_median);
    }

    /// [INV-0908]
    /// Fast re-seed on network merges (e.g., village A docks into the global mesh)
    pub fn fast_reseed_on_merge(&self, global_median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .fast_reseed_on_merge(global_median);
    }

    /// [INV-0922] Records a daily median in the 28-day slotted ring buffer
    pub fn record_daily_median(&self, median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .record_daily_median(median);
    }

    /// Returns the rolling 24-hour write daily rate in Byte-Years
    pub fn rolling_24h_average(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_average()
    }

    /// Returns the rolling 24-hour write daily rate in Byte-Years at a specific second
    pub fn rolling_24h_average_at(&self, now_sec: u64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_average_at(now_sec)
    }

    /// Returns the current raw write EMA in micro-Byte-Years (µBJ)
    pub fn current_write_ema_micro_bj(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current_write_ema_micro_bj()
    }

    /// Returns the current raw read EMA in credits
    pub fn current_read_ema_credits(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current_read_ema_credits()
    }

    /// Returns the current rolling 24-hour read daily rate in credits
    pub fn rolling_24h_read_average(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_read_average()
    }

    /// Returns the rolling 24-hour read daily rate in credits at a specific second
    pub fn rolling_24h_read_average_at(&self, now_sec: u64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .rolling_24h_read_average_at(now_sec)
    }

    /// [INV-0923] Records a daily read median
    pub fn record_daily_read_median(&self, median: u64) {
        self.thermometer
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .record_daily_read_median(median);
    }

    /// [INV-0903/0904] Autonomous thermometer day roll-over (Spec 09 Phase 9 P1).
    pub fn advance_epoch_day(&self, now_ms: u64) -> Option<u64> {
        let day = self.current_epoch_day_at(now_ms);
        let last = self.last_thermometer_day.load(Ordering::Relaxed);
        if last == 0 {
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
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .effective_ncb()
    }

    /// [INV-0925] Calculates effective reference value NCB_read_eff = max(Moving_Read_Median, HARD_FLOOR_READ_BASELINE_DAILY)
    pub fn effective_read_ncb(&self) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .effective_read_ncb()
    }

    /// Calculates dynamic daily quota with 5x Whale Brake K <= 5.0 (Spec 09)
    pub fn calculate_daily_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .calculate_daily_quota(k_multiplier, spread_damper)
    }

    /// [INV-0927] Calculates daily read quota for a node:
    /// Read_Quota = NCB_read_eff * min(K, 5.0) * Spread_Damper
    pub fn calculate_daily_read_quota(&self, k_multiplier: f64, spread_damper: f64) -> u64 {
        self.thermometer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .calculate_daily_read_quota(k_multiplier, spread_damper)
    }

    /// Evaluates read quota for a client using decentralized consensus time and rolling EMA counter.
    /// Returns `Ok(())` if the read is within the daily budget.
    /// Returns `Err(IngressError::ReadQuotaExceeded)` if the budget is exceeded.
    pub fn evaluate_read_quota_with_time(
        &self,
        client_id: NodeId,
        credits: u64,
        k_multiplier: f64,
        now_ms: Option<u64>,
    ) -> Result<(), IngressError> {
        let eff_now_ms = self.effective_now_ms(now_ms);
        let now_sec = eff_now_ms / 1000;
        let daily_quota = self.calculate_daily_read_quota(k_multiplier, 1.0);
        let mut thermo = self.thermometer.write().unwrap_or_else(|e| e.into_inner());
        match thermo.try_consume_read(now_sec, client_id, credits, daily_quota) {
            Ok(_) => {
                thermo.record_read_ingress(now_sec, credits);
                Ok(())
            }
            Err(available) => Err(IngressError::ReadQuotaExceeded {
                available,
                required: credits,
            }),
        }
    }

    /// Returns the epoch day since UNIX epoch for a given timestamp in milliseconds
    pub fn current_epoch_day_at(&self, now_ms: u64) -> u64 {
        now_ms / (86_400 * 1000)
    }

    /// Returns the current epoch day since UNIX epoch (using consensus time from pow_engine)
    pub fn current_epoch_day(&self) -> u64 {
        self.current_epoch_day_at(self.effective_now_ms(None))
    }

    /// Evaluates and registers dynamic ingress for F2F peers against daily quota (K=1.0) using continuous rolling EMA decay.
    pub fn evaluate_f2f_quota(
        &self,
        peer_token: &str,
        required_byte_years: u64,
        now_ms: u64,
    ) -> Result<(), IngressError> {
        let token_hash = *blake3::hash(peer_token.as_bytes()).as_bytes();
        let daily_quota = self.calculate_daily_quota(1.0, 1.0);
        let now_sec = now_ms / 1000;
        let mut f2f_usage = self
            .f2f_rolling_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let counter = f2f_usage.entry(token_hash).or_default();
        counter
            .try_consume(now_sec, required_byte_years, daily_quota)
            .map(|_| ())
            .map_err(|available| IngressError::QuotaExceeded {
                available,
                required: required_byte_years,
            })
    }

    /// Evaluates and registers dynamic ingress for VIP accounts against daily quota with 5x Whale Brake (K <= 5.0) using continuous rolling EMA decay.
    pub fn evaluate_vip_quota(
        &self,
        account_tag: &[u8; 32],
        required_byte_years: u64,
        now_ms: u64,
        k_multiplier: f64,
    ) -> Result<(), IngressError> {
        let daily_quota =
            self.calculate_daily_quota(k_multiplier.clamp(0.0, MAX_WHALE_MULTIPLIER), 1.0);
        let now_sec = now_ms / 1000;
        let mut vip_usage = self
            .vip_rolling_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let counter = vip_usage.entry(*account_tag).or_default();
        counter
            .try_consume(now_sec, required_byte_years, daily_quota)
            .map(|_| ())
            .map_err(|available| IngressError::QuotaExceeded {
                available,
                required: required_byte_years,
            })
    }

    /// Evaluates and registers dynamic ingress for a network node against the 5x Whale Brake daily write limit using continuous rolling EMA decay.
    ///
    /// W4 (Audit 19): Sender-specific P2P write budgets are isolated by full 32-byte `NodePubKey`
    /// in `p2p_node_usage`, preventing 16-bit prefix contention across distinct network nodes.
    pub fn evaluate_node_write_quota(
        &self,
        sender_pubkey: &[u8; 32],
        required_byte_years: u64,
        now_ms: u64,
    ) -> Result<(), IngressError> {
        let daily_quota = self.calculate_daily_quota(MAX_WHALE_MULTIPLIER, 1.0);
        let now_sec = now_ms / 1000;
        let mut p2p_usage = self
            .p2p_node_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if !p2p_usage.contains_key(sender_pubkey) && p2p_usage.len() >= 16_384 {
            p2p_usage.retain(|_, counter| counter.usage_at(now_sec) > 0);
        }
        let counter = p2p_usage.entry(*sender_pubkey).or_default();
        counter
            .try_consume(now_sec, required_byte_years, daily_quota)
            .map(|_| ())
            .map_err(|available| IngressError::QuotaExceeded {
                available,
                required: required_byte_years,
            })
    }

    /// Evaluates and registers dynamic ingress for a network node against the 5x Whale Brake daily read limit using continuous rolling EMA decay.
    ///
    /// W4 (Audit 19): Sender-specific P2P read credits are isolated by full 32-byte `NodePubKey`
    /// in `p2p_node_read_usage`, preventing 16-bit prefix contention across distinct network nodes.
    pub fn evaluate_node_read_quota(
        &self,
        sender_pubkey: &[u8; 32],
        required_credits: u64,
        now_ms: u64,
    ) -> Result<(), IngressError> {
        let daily_read_quota = self.calculate_daily_read_quota(MAX_WHALE_MULTIPLIER, 1.0);
        let now_sec = now_ms / 1000;
        let mut p2p_read_usage = self
            .p2p_node_read_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if !p2p_read_usage.contains_key(sender_pubkey) && p2p_read_usage.len() >= 16_384 {
            p2p_read_usage.retain(|_, counter| counter.usage_at(now_sec) > 0);
        }
        let counter = p2p_read_usage.entry(*sender_pubkey).or_default();
        counter
            .try_consume(now_sec, required_credits, daily_read_quota)
            .map(|_| ())
            .map_err(|available| IngressError::ReadQuotaExceeded {
                available,
                required: required_credits,
            })
    }

    /// Provisions a new cryptographically random VIP bearer credential for an account tag (S05-12).
    /// Generates 32 CSPRNG bytes, returns the plaintext bearer secret once, and stores only its hash.
    pub fn provision_vip_credential(&self, account_tag: [u8; 32]) -> Result<String, IngressError> {
        let mut random_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random_bytes);
        let bearer_token = format!("vip_{}", hex::encode(random_bytes));
        let token_hash = compute_vip_token_hash(&bearer_token);
        self.storage.put_vip_credential(&token_hash, &account_tag)?;
        self.vip_credentials
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_hash, account_tag);
        self.register_vip_tag(account_tag);
        Ok(bearer_token)
    }

    /// Registers a VIP bearer token after strictly validating its independence from the account tag.
    /// Rejects empty, raw 64-char hex (e.g. NodePubKey), account tag plaintext, diagnostic IDs, and f2f tokens.
    pub fn try_register_vip_token(
        &self,
        token: &str,
        account_tag: [u8; 32],
    ) -> Result<(), IngressError> {
        let trimmed = token.trim();
        let stripped = if trimmed.len() >= 7
            && trimmed.as_bytes()[..7].eq_ignore_ascii_case(b"bearer ")
        {
            trimmed[7..].trim()
        } else {
            trimmed
        };

        if stripped.is_empty() {
            return Err(IngressError::InvalidAuthToken);
        }
        // Reject raw 64-char hex strings (blocks all raw NodePubKey / account_tag hex strings)
        if stripped.len() == 64 && stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IngressError::InvalidAuthToken);
        }
        // Reject registering account's own plaintext tag/name as bearer secret
        if crate::control::parse_account_tag(stripped) == account_tag {
            return Err(IngressError::InvalidAuthToken);
        }
        // Reject diagnostic ID
        if stripped == vip_diagnostic_id(&account_tag) {
            return Err(IngressError::InvalidAuthToken);
        }
        // Reject f2f peer token
        if stripped.starts_with("f2f_") {
            return Err(IngressError::InvalidAuthToken);
        }

        let token_hash = compute_vip_token_hash(stripped);
        self.storage.put_vip_credential(&token_hash, &account_tag)?;
        self.vip_credentials
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token_hash, account_tag);
        self.register_vip_tag(account_tag);
        Ok(())
    }

    /// Registers an auth token associated with a specific VIP account tag.
    pub fn register_vip_token(&self, token: impl Into<String>, account_tag: [u8; 32]) {
        let _ = self.try_register_vip_token(&token.into(), account_tag);
    }

    /// Registers an authorized VIP account tag directly, hydrating cache if absent.
    /// Idempotent with respect to cached balance: preserves an already-initialized or mutated balance.
    pub fn register_vip_tag(&self, account_tag: [u8; 32]) {
        if !self.vip_quota_cache.read().contains_key(&account_tag) {
            if let Ok(bal) = self.storage.get_quota(&account_tag) {
                if bal > 0 {
                    self.vip_quota_cache
                        .write()
                        .entry(account_tag)
                        .or_insert(bal);
                }
            }
        }
    }

    /// Registers a trusted F2F client with optional friendly label and stores metadata.
    pub fn register_f2f_client(&self, token: &str, label: Option<&str>) {
        let token_trimmed = token.trim();
        let token_hash = hex::encode(blake3::hash(token_trimmed.as_bytes()).as_bytes());
        let client_label = match label {
            Some(l) if !l.trim().is_empty() => l.trim().to_string(),
            _ => format!("Client-{}", &token_hash[..8]),
        };
        let now_ms = self.effective_now_ms(None);

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

    /// Lists all registered F2F clients with their rolling usage and quota status.
    pub fn list_f2f_clients(&self, now_ms: u64) -> Vec<F2fClientDto> {
        let clients = self.f2f_clients.read().unwrap_or_else(|e| e.into_inner());
        let daily_limit = self.calculate_daily_quota(1.0, 1.0);
        let f2f_usage = self
            .f2f_rolling_usage
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let now_sec = now_ms / 1000;

        let mut list = Vec::with_capacity(clients.len());
        for meta in clients.values() {
            let token_hash = *blake3::hash(meta.token.as_bytes()).as_bytes();
            let writes_today = f2f_usage
                .get(&token_hash)
                .map_or(0, |counter| counter.usage_at(now_sec));
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
        self.evaluate_and_charge_with_time_and_retry(
            auth_token,
            peer_token,
            pow_challenge,
            pow_nonce,
            ttl_seconds,
            parent_lock,
            now_ms,
            false,
        )
        .await
    }

    /// [INV-0929] Evaluates tier credentials with decentralized network time, validates authorization,
    /// deducts quota (for VIP non-retries), or validates PoW (for Public).
    /// When `is_retry` is true, validates credentials and rate admission without double-charging storage or daily writes.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_and_charge_with_time_and_retry(
        &self,
        auth_token: Option<&str>,
        peer_token: Option<&str>,
        pow_challenge: Option<&str>,
        pow_nonce: Option<u64>,
        ttl_seconds: u64,
        parent_lock: Option<&[u8; 32]>,
        now_ms: Option<u64>,
        is_retry: bool,
    ) -> Result<IngressTier, IngressError> {
        let eff_now_ms = self.effective_now_ms(now_ms);
        let now_sec = eff_now_ms / 1000;
        let footprint_micro_bj = ByteYears::micro_from_ttl_seconds(ttl_seconds);

        // 1. Check Tier 1 (VIP) - in-memory atomic cache, no synchronous fsync stall (INV-0929 hot-path)
        if let Some(token) = auth_token {
            let account_tag = self.resolve_account_tag(token)?;

            if is_retry {
                return Ok(IngressTier::Tier1Vip);
            }

            if self.vip_persist_failed.load(Ordering::Acquire) {
                return Err(IngressError::QuotaPersistenceUnavailable);
            }

            // Hydrate cold miss asynchronously before acquiring write lock (A05-01)
            self.ensure_vip_quota_cached(&account_tag).await?;

            let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
            let daily_quota = self.calculate_daily_quota(5.0, 1.0);

            // 1. Check daily rolling quota
            let mut vip_usage = self
                .vip_rolling_usage
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let counter = vip_usage.entry(account_tag).or_default();
            let current_usage = counter.usage_at(now_sec);
            if current_usage.saturating_add(required_byte_years) > daily_quota {
                let available = daily_quota.saturating_sub(current_usage);
                return Err(IngressError::QuotaExceeded {
                    available,
                    required: required_byte_years,
                });
            }

            // 2. Check purchased credit balance in RAM cache
            let mut cache = self.vip_quota_cache.write();
            let bal = cache.entry(account_tag).or_insert(0);
            if *bal < required_byte_years {
                return Err(IngressError::QuotaExceeded {
                    available: *bal,
                    required: required_byte_years,
                });
            }

            // 3. Reserve persistence capacity BEFORE mutating RAM balance (A02-02)
            let permit = self
                .vip_persist_tx
                .try_reserve()
                .map_err(|_| IngressError::QuotaPersistenceUnavailable)?;

            // 4. All checks passed! Apply all mutations atomically with zero partial state on errors
            *bal = bal.saturating_sub(required_byte_years);
            let remaining = *bal;
            permit.send(VipQuotaPersistOp {
                account_tag,
                remaining,
            });
            drop(cache);

            let _ = counter.try_consume(now_sec, required_byte_years, daily_quota);
            drop(vip_usage);

            self.vip_writes_today.fetch_add(1, Ordering::Relaxed);
            self.thermometer
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .record_write_ingress(now_sec, footprint_micro_bj);

            return Ok(IngressTier::Tier1Vip);
        }

        // 2. Check Tier 2 (F2F Peer) with Spec 09 dynamic daily quota
        if let Some(token) = peer_token {
            let token_trimmed = token.trim();
            let is_valid = self
                .f2f_tokens
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains(token_trimmed);
            if !is_valid {
                return Err(IngressError::InvalidPeerToken);
            }

            let token_hash = *blake3::hash(token_trimmed.as_bytes()).as_bytes();
            let token_hash_hex = hex::encode(token_hash);
            if let Some(meta) = self
                .f2f_clients
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&token_hash_hex)
            {
                meta.last_active_ms = Some(eff_now_ms);
            }

            if is_retry {
                return Ok(IngressTier::Tier2F2F);
            }

            let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
            self.evaluate_f2f_quota(token_trimmed, required_byte_years, eff_now_ms)?;
            self.f2f_writes_today.fetch_add(1, Ordering::Relaxed);
            self.thermometer
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .record_write_ingress(now_sec, footprint_micro_bj);

            return Ok(IngressTier::Tier2F2F);
        }

        // 3. Check Tier 3 (Public - BLAKE3 PoW)
        // Fix S05-06: Shared O(1) RollingQuotaCounter for the entire anonymous pool - zero parent_lock hashmap!
        let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
        let daily_quota = self.calculate_daily_quota(1.0, 1.0);
        let p = parent_lock.copied().unwrap_or([0u8; 32]);

        if self.pow_engine.default_difficulty() == 0 {
            if is_retry {
                return Ok(IngressTier::Tier3Public);
            }

            let mut free_usage = self
                .free_rolling_usage
                .write()
                .unwrap_or_else(|e| e.into_inner());
            free_usage
                .try_consume(now_sec, required_byte_years, daily_quota)
                .map_err(|available| IngressError::QuotaExceeded {
                    available,
                    required: required_byte_years,
                })?;
            drop(free_usage);

            self.free_writes_today.fetch_add(1, Ordering::Relaxed);
            self.thermometer
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .record_write_ingress(now_sec, footprint_micro_bj);
            return Ok(IngressTier::Tier3Public);
        }

        let load_factor = (self.rolling_24h_average_at(now_sec) as f64
            / self.effective_ncb().max(1) as f64)
            .clamp(0.0, 1.0);
        let dynamic_difficulty = self.pow_engine.required_difficulty_for_load(load_factor);

        match (pow_challenge, pow_nonce) {
            (Some(challenge), Some(nonce)) => {
                self.pow_engine
                    .verify_pow_for_parent_at(
                        challenge,
                        nonce,
                        dynamic_difficulty,
                        parent_lock,
                        now_sec,
                    )
                    .await?;

                if is_retry {
                    return Ok(IngressTier::Tier3Public);
                }

                let mut free_usage = self
                    .free_rolling_usage
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                free_usage
                    .try_consume(now_sec, required_byte_years, daily_quota)
                    .map_err(|available| IngressError::QuotaExceeded {
                        available,
                        required: required_byte_years,
                    })?;
                drop(free_usage);

                self.free_writes_today.fetch_add(1, Ordering::Relaxed);
                self.thermometer
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_write_ingress(now_sec, footprint_micro_bj);
                Ok(IngressTier::Tier3Public)
            }
            _ => {
                let (challenge, _, expires_at) =
                    self.pow_engine.generate_challenge_for_parent_at(&p, now_sec);
                Err(IngressError::PoWRequired {
                    challenge,
                    difficulty: dynamic_difficulty,
                    expires_at,
                })
            }
        }
    }

    /// Resolves an account tag from an auth token (S05-12 / INV-1302).
    /// ONLY registered bearer secrets in `vip_credentials` can authenticate VIP ingress.
    /// Diagnostic IDs, hex representations, and unauthorized strings are strictly rejected.
    pub fn resolve_account_tag(&self, token: &str) -> Result<[u8; 32], IngressError> {
        let trimmed = token.trim();
        let stripped = if trimmed.len() >= 7
            && trimmed.as_bytes()[..7].eq_ignore_ascii_case(b"bearer ")
        {
            trimmed[7..].trim()
        } else {
            trimmed
        };

        if stripped.is_empty() {
            return Err(IngressError::InvalidAuthToken);
        }
        if stripped.len() == 64 && stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IngressError::InvalidAuthToken);
        }
        if stripped.starts_with("f2f_") {
            return Err(IngressError::InvalidAuthToken);
        }

        let token_hash = compute_vip_token_hash(stripped);
        if let Some(tag) = self
            .vip_credentials
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&token_hash)
        {
            return Ok(*tag);
        }

        Err(IngressError::InvalidAuthToken)
    }

    /// Returns recorded rolling VIP usage for the given account tag at `now_ms` (for test assertion).
    pub fn vip_rolling_usage_at_for_test(&self, account_tag: &[u8; 32], now_ms: u64) -> u64 {
        let guard = self
            .vip_rolling_usage
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let now_sec = now_ms / 1000;
        guard.get(account_tag).map_or(0, |c| c.usage_at(now_sec))
    }

    /// Exhausts the public Tier-3 rolling quota pool for testing.
    pub fn exhaust_public_quota_for_test(&self, now_ms: u64) {
        let daily_limit = self.calculate_daily_quota(1.0, 1.0);
        let now_sec = now_ms / 1000;
        let mut free = self
            .free_rolling_usage
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let current = free.usage_at(now_sec);
        let needed = daily_limit.saturating_sub(current);
        if needed > 0 {
            let _ = free.try_consume(now_sec, needed, daily_limit);
        }
    }

    /// Returns the public Tier-3 rolling usage for testing.
    pub fn free_rolling_usage_at_for_test(&self, now_ms: u64) -> u64 {
        let guard = self
            .free_rolling_usage
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard.usage_at(now_ms / 1000)
    }

    /// Reserves a VIP persistence permit to simulate channel saturation for testing.
    /// Dropping the returned guard releases the permit back to the queue.
    pub fn reserve_persist_permit_for_test(&self) -> Option<Box<dyn std::any::Any + Send>> {
        self.vip_persist_tx
            .clone()
            .try_reserve_owned()
            .ok()
            .map(|permit| Box::new(permit) as Box<dyn std::any::Any + Send>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_tier_controller_dynamic_quota_evaluation() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_dynamic_quota.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new(8));
        let controller = TierController::new(storage, pow);

        // F2F dynamic quota evaluation
        let peer_token = "peer_token_dynamic_123";
        controller.register_f2f_peer(peer_token);

        let now_ms = 1_000_000_000_000;
        // 1 Year TTL = 192 Byte-Years, fits easily into 960_000
        let res = controller.evaluate_f2f_quota(peer_token, 192, now_ms);
        assert!(
            matches!(res, Ok(())),
            "F2F quota 192 must be Ok, got {:?}",
            res
        );

        // Exceed daily quota in single epoch day
        let res_exceed = controller.evaluate_f2f_quota(peer_token, 960_000, now_ms);
        assert!(matches!(
            res_exceed,
            Err(IngressError::QuotaExceeded { .. })
        ));

        // After decaying (20 days later = 20 * 86_400_000 ms), quota recovers
        let later_ms = now_ms + 20 * 86_400_000;
        let res_later = controller.evaluate_f2f_quota(peer_token, 192, later_ms);
        assert!(
            matches!(res_later, Ok(())),
            "decayed quota must allow write, got {:?}",
            res_later
        );

        // VIP dynamic quota evaluation
        let vip_tag = [0x77u8; 32];
        let res_vip = controller.evaluate_vip_quota(&vip_tag, 960_000 * 4, now_ms, 5.0);
        assert!(
            matches!(res_vip, Ok(())),
            "VIP quota must be Ok, got {:?}",
            res_vip
        );

        // Exceeding K=5.0 limit for VIP
        let res_vip_exceed = controller.evaluate_vip_quota(&vip_tag, 960_000 * 2, now_ms, 5.0);
        assert!(matches!(
            res_vip_exceed,
            Err(IngressError::QuotaExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_client_registration_and_list() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f_clients.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new(8));
        let controller = TierController::new(storage, pow);

        let token = "my_pos_terminal_token_xyz";
        controller.register_f2f_client(token, Some("Kasse-1"));

        let now_ms = 1_700_000_000_000;

        let clients = controller.list_f2f_clients(now_ms);
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
        let clients_after = controller.list_f2f_clients(now_ms + 10_000);
        assert_eq!(clients_after.len(), 1);
        assert_eq!(clients_after[0].last_active_sec, Some(10));
    }

    #[tokio::test]
    async fn test_tier_controller_f2f_client_removal() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_f2f_remove.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new(8));
        let controller = TierController::new(storage, pow);

        let token = "removable_client_token";
        controller.register_f2f_client(token, Some("Kasse-Alt"));

        let token_hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());

        // Remove by hash
        assert!(controller.remove_f2f_client(&token_hash));
        assert_eq!(controller.list_f2f_clients(0).len(), 0);

        // Re-register and remove by token
        controller.register_f2f_client(token, None);
        assert_eq!(controller.list_f2f_clients(0).len(), 1);
        assert!(controller.remove_f2f_client(token));
        assert_eq!(controller.list_f2f_clients(0).len(), 0);

        // Non-existent returns false
        assert!(!controller.remove_f2f_client("non_existent"));
    }

    #[tokio::test]
    async fn test_a02_02_vip_quota_saturation_no_credit_loss() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_a02_02.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new(8));

        let account_tag = [0x42u8; 32];
        let initial_balance = 2000u64;
        storage.set_quota(&account_tag, initial_balance).unwrap();

        let controller = TierController::new(storage.clone(), pow);
        controller.register_vip_tag(account_tag);

        // Channel capacity is 1,024. Without yielding to the background persistence worker,
        // synchronously attempt 1,025 charges of 1 unit each.
        let mut success_count = 0;
        let mut saturated = false;
        for _ in 0..1025 {
            match controller.try_charge_vip_in_memory(&account_tag, 1) {
                Ok(_) => success_count += 1,
                Err(IngressError::QuotaPersistenceUnavailable) => {
                    saturated = true;
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        assert!(
            saturated,
            "1025th charge must trigger QuotaPersistenceUnavailable"
        );
        assert_eq!(
            success_count, 1024,
            "Exactly 1,024 charges must succeed before saturation"
        );

        // Crucial invariant: Rejected debit must NOT decrement RAM balance!
        let ram_balance = controller.get_cached_vip_quota(&account_tag).unwrap();
        assert_eq!(
            ram_balance,
            initial_balance - 1024,
            "RAM balance must reflect only accepted debits (2000 - 1024 = 976)"
        );

        // Allow FIFO persistence worker to drain
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if storage.get_quota(&account_tag).unwrap() == ram_balance {
                break;
            }
        }

        let disk_balance = storage.get_quota(&account_tag).unwrap();
        assert_eq!(
            disk_balance, ram_balance,
            "Persisted balance must match RAM balance exactly; no debits lost!"
        );

        // Restarting controller from same database must hydrate the exact balance
        let restored_pow = Arc::new(PowEngine::new(8));
        let restored_controller = TierController::new(storage.clone(), restored_pow);
        assert_eq!(
            restored_controller.get_cached_vip_quota(&account_tag),
            Some(ram_balance),
            "Startup hydration must restore exact persisted balance"
        );
    }

    #[tokio::test]
    async fn test_a02_02_strict_fifo_ordering_under_concurrency() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_fifo.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new(8));

        let account_tag = [0x99u8; 32];
        storage.set_quota(&account_tag, 10_000).unwrap();

        let controller = Arc::new(TierController::new(storage.clone(), pow));
        controller.register_vip_tag(account_tag);

        let mut tasks = Vec::new();
        // Spawn 20 tasks: 10 performing debits, 10 performing top-ups
        for i in 0..20 {
            let tc = controller.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..20 {
                    if i % 2 == 0 {
                        let _ = tc.try_charge_vip_in_memory(&account_tag, 5);
                    } else {
                        let _ = tc.topup_vip_quota(account_tag, 5);
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        let ram_balance = controller.get_cached_vip_quota(&account_tag).unwrap();

        // Wait for FIFO worker to drain
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if storage.get_quota(&account_tag).unwrap() == ram_balance {
                break;
            }
        }

        let disk_balance = storage.get_quota(&account_tag).unwrap();
        assert_eq!(
            disk_balance, ram_balance,
            "FIFO ordering guarantees persisted balance matches RAM balance after concurrent mutations"
        );
    }

    #[tokio::test]
    async fn test_a05_01_startup_hydration_and_cold_miss_async() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test_hydration.redb");
        let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
        let pow = Arc::new(PowEngine::new(8));

        let tag1 = [0x01u8; 32];
        let tag2 = [0x02u8; 32];
        let tag3 = [0x03u8; 32];
        storage.set_quota(&tag1, 100).unwrap();
        storage.set_quota(&tag2, 200).unwrap();
        storage.set_quota(&tag3, 300).unwrap();

        // Startup hydration: all 3 accounts must be present in RAM immediately
        let controller = TierController::new(storage.clone(), pow);
        assert_eq!(controller.get_cached_vip_quota(&tag1), Some(100));
        assert_eq!(controller.get_cached_vip_quota(&tag2), Some(200));
        assert_eq!(controller.get_cached_vip_quota(&tag3), Some(300));

        // Cold miss: tag4 is added to storage directly, bypassing controller
        let tag4 = [0x04u8; 32];
        storage.set_quota(&tag4, 500).unwrap();
        assert_eq!(controller.get_cached_vip_quota(&tag4), None);

        // ensure_vip_quota_cached hydrates asynchronously via spawn_blocking without write-lock stall
        controller.ensure_vip_quota_cached(&tag4).await.unwrap();
        assert_eq!(controller.get_cached_vip_quota(&tag4), Some(500));

        // Normal charge succeeds
        let remaining = controller.try_charge_vip_in_memory(&tag4, 50).unwrap();
        assert_eq!(remaining, 450);
        assert_eq!(controller.get_cached_vip_quota(&tag4), Some(450));
    }
}
