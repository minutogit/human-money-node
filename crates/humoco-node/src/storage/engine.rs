use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use humoco_sim_core::quota::ByteYears;
use humoco_sim_core::storage::{ingress_time_window_valid, should_prune, IngressVerdictLow, RamIndex};
use humoco_sim_core::types::{LockRecord, SimTime};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use super::db::{RedbStorage, StorageError};
use crate::api::hmc::{L2LockEntry, L2Verdict};
use crate::storage::filter::SpentLockFilter;
use crate::storage::recent::{
    LockInspection, RecentLockBuffer, RecentLockStatus, RecentLockSummary, VoucherDetailDto,
    VoucherLockHopDto, VoucherSummaryDto,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOrigin {
    ClientApi,
    PartitionSync,
}

#[derive(Default)]
pub struct HmcRamIndex {
    /// lookup_tag -> L2LockEntry
    pub locks: HashMap<String, L2LockEntry>,
    /// layer2_voucher_id -> Set of lookup_tags
    pub vouchers: HashMap<String, HashSet<String>>,
    /// layer2_voucher_id -> root valid_until timestamp in ms
    pub voucher_roots: HashMap<String, u64>,
    /// layer2_voucher_id -> genesis parent lock [u8; 32]
    pub voucher_genesis_parents: HashMap<String, [u8; 32]>,
    /// lookup_tag -> valid_until timestamp in ms
    pub valid_until: HashMap<String, u64>,
    /// Bucket-Index: bucket_sec (valid_until_ms + 30s) / 1000 -> Vec<lookup_tag>
    pub ttl_buckets: BTreeMap<u64, Vec<String>>,
    /// Cuckoo pre-filter for fast negative lookups
    pub filter: SpentLockFilter,
}

/// Computes the deterministic canonical hash for an HMC lock entry (docs/02:97, Spec 02, 08):
/// H_canon = BLAKE3("HUMOCO_V1_CANON_RESOLVER" || parent_bytes || sender_ephemeral_pub || t_id)
pub fn compute_hmc_canonical_hash(
    parent_bytes: &[u8; 32],
    sender_ephemeral_pub: &[u8; 32],
    t_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag = b"HUMOCO_V1_CANON_RESOLVER";
    hasher.update(&(tag.len() as u8).to_le_bytes());
    hasher.update(tag);
    hasher.update(parent_bytes);
    hasher.update(sender_ephemeral_pub);
    hasher.update(t_id);
    *hasher.finalize().as_bytes()
}

impl HmcRamIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_or_check(
        &mut self,
        lookup_tag: String,
        entry: L2LockEntry,
        origin: IngressOrigin,
        now_ms: Option<u64>,
    ) -> (L2Verdict, bool) {
        let root_valid = self.voucher_roots.get(&entry.layer2_voucher_id).copied();
        let is_genesis = lookup_tag == bs58::encode(&entry.t_id).into_string()
            || (root_valid.is_none() && entry.deletable_at.is_some());

        // # Architectural Invariant: Option A KISS Origin-Lock Mandate
        //
        // Genesis locks (lookup_tag == bs58(t_id)) carry `deletable_at` and
        // initialize the immutable root TTL in `voucher_roots`. Follow-up locks
        // inherit `valid_until` EXCLUSIVELY from `voucher_roots` — never from
        // their own `deletable_at`. A follow-up lock with an unknown root is
        // rejected with "Unknown voucher root: genesis lock must be anchored first".
        let valid_until_ms = if is_genesis {
            match entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                Some(v) => {
                    self.voucher_roots.insert(entry.layer2_voucher_id.clone(), v);
                    v
                }
                None => {
                    return (
                        L2Verdict::Rejected {
                            reason: "Missing deletable_at and unknown voucher root: genesis lock must be anchored first".into(),
                        },
                        false,
                    );
                }
            }
        } else {
            let root_v = match root_valid {
                Some(v) => v,
                None => {
                    return (
                        L2Verdict::Rejected {
                            reason: "Unknown voucher root: genesis lock must be anchored first".into(),
                        },
                        false,
                    );
                }
            };
            entry
                .deletable_at
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(root_v)
        };

        // HMC ingress window enforcement for client ingress (INV-1202):
        // Only for ClientApi and when both root_valid and now_ms are available.
        if origin == IngressOrigin::ClientApi {
            if let (Some(root_v), Some(now)) = (root_valid, now_ms) {
                if !ingress_time_window_valid(SimTime(now), SimTime(valid_until_ms), SimTime(root_v)) {
                    return (
                        L2Verdict::Rejected {
                            reason: "Invalid ingress time window: now + 30s < valid_until <= root.valid_until violated".into(),
                        },
                        false,
                    );
                }
            }
        }

        if origin == IngressOrigin::PartitionSync
            && !crate::api::hmc::verify_l2_lock_entry_signature(&entry, &lookup_tag)
        {
            return (
                L2Verdict::Rejected {
                    reason: "Invalid cryptographic signature on synced lock".into(),
                },
                false,
            );
        }

        if let Some(existing) = self.locks.get(&lookup_tag) {
            // Collision check: if t_id identical -> Idempotent replay
            if existing.t_id == entry.t_id {
                (L2Verdict::Verified { lock_entry: existing.clone() }, false)
            } else if origin == IngressOrigin::ClientApi {
                // For ClientApi, never overwrite an existing lock via min(H_canon)!
                // Immediately return Conflict to protect against self-equivocation in live ingress.
                (L2Verdict::Conflict { existing_lock: existing.clone() }, false)
            } else {
                // Conflict on same lookup_tag with existing.t_id != entry.t_id!
                // Deterministic split-brain healing via min(H_canon):
                // H_canon = BLAKE3("HUMOCO_V1_CANON_RESOLVER" || parent_bytes || sender_ephemeral_pub || t_id)
                let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                let h_existing = compute_hmc_canonical_hash(
                    &parent_bytes,
                    &existing.sender_ephemeral_pub,
                    &existing.t_id,
                );
                let h_new = compute_hmc_canonical_hash(
                    &parent_bytes,
                    &entry.sender_ephemeral_pub,
                    &entry.t_id,
                );

                if h_new < h_existing {
                    // WinnerB: Incoming lock won! Atomically replace loser in RAM-Index
                    let prune_threshold_ms = valid_until_ms.saturating_add(30_000);
                    let bucket_sec = prune_threshold_ms / 1_000;

                    self.ttl_buckets.entry(bucket_sec).or_default().push(lookup_tag.clone());
                    self.valid_until.insert(lookup_tag.clone(), valid_until_ms);
                    // Only genesis initializes the immutable root TTL.
                    if is_genesis {
                        self.voucher_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);
                    }
                    if is_genesis && entry.deletable_at.is_some() {
                        let p_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                        self.voucher_genesis_parents.entry(entry.layer2_voucher_id.clone()).or_insert(p_bytes);
                    }

                    self.vouchers
                        .entry(entry.layer2_voucher_id.clone())
                        .or_default()
                        .insert(lookup_tag.clone());
                    self.locks.insert(lookup_tag.clone(), entry.clone());
                    self.filter.add(&lookup_tag);
                    (L2Verdict::Verified { lock_entry: entry }, true)
                } else {
                    // WinnerA: Existing lock won! Loser voided / rejected.
                    (L2Verdict::Conflict { existing_lock: existing.clone() }, false)
                }
            }
        } else {
            let prune_threshold_ms = valid_until_ms.saturating_add(30_000);
            let bucket_sec = prune_threshold_ms / 1_000;

            self.ttl_buckets.entry(bucket_sec).or_default().push(lookup_tag.clone());
            self.valid_until.insert(lookup_tag.clone(), valid_until_ms);
            // Only the genesis lock sets the immutable root TTL (Rule 10).
            if is_genesis {
                self.voucher_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);
            }
            if is_genesis && entry.deletable_at.is_some() {
                let p_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
                self.voucher_genesis_parents.entry(entry.layer2_voucher_id.clone()).or_insert(p_bytes);
            }

            self.vouchers
                .entry(entry.layer2_voucher_id.clone())
                .or_default()
                .insert(lookup_tag.clone());
            self.locks.insert(lookup_tag.clone(), entry.clone());
            self.filter.add(&lookup_tag);
            (L2Verdict::Verified { lock_entry: entry }, true)
        }
    }

    /// Re-populates an unexpired HMC lock entry from disk during cold-start recovery.
    ///
    /// # Architectural Invariant: INV-1404 Dual-Tier Cold-Start Recovery
    ///
    /// Follow-up locks without own `deletable_at` inherit their TTL from the
    /// already-loaded voucher genesis root (Stage 2 runs after Stage 1, so the
    /// root is known). They are NEVER inserted with TTL 0 (which would make
    /// them instantly prunable) and NEVER poison `voucher_roots` with 0 — only
    /// genesis locks initialize the immutable root TTL. Orphans with a still-
    /// unknown root are skipped (deferred, not dropped with 0).
    pub fn insert_recovered(&mut self, lookup_tag: String, entry: L2LockEntry) {
        let root_valid = self.voucher_roots.get(&entry.layer2_voucher_id).copied();
        let is_genesis = lookup_tag == bs58::encode(&entry.t_id).into_string()
            || (root_valid.is_none() && entry.deletable_at.is_some());
        let owned_ttl = entry
            .deletable_at
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok());
        let valid_until_ms = match (is_genesis, owned_ttl) {
            (true, Some(v)) => {
                self.voucher_roots.insert(entry.layer2_voucher_id.clone(), v);
                v
            }
            (true, None) => {
                // Genesis without parseable TTL: cannot anchor a root — skip.
                return;
            }
            (false, _) => match root_valid {
                Some(root_v) => root_v,
                None => {
                    // Orphan follow-up: root not yet known — skip instead of
                    // inserting TTL 0 (never drop as expired, never poison).
                    return;
                }
            },
        };
        let prune_threshold_ms = valid_until_ms.saturating_add(30_000);
        let bucket_sec = prune_threshold_ms / 1_000;

        self.ttl_buckets.entry(bucket_sec).or_default().push(lookup_tag.clone());
        self.valid_until.insert(lookup_tag.clone(), valid_until_ms);
        // Only genesis restores the immutable root TTL.
        if is_genesis {
            self.voucher_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);
        }
        if is_genesis && entry.deletable_at.is_some() {
            let p_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();
            self.voucher_genesis_parents.entry(entry.layer2_voucher_id.clone()).or_insert(p_bytes);
        }

        self.vouchers
            .entry(entry.layer2_voucher_id.clone())
            .or_default()
            .insert(lookup_tag.clone());
        self.locks.insert(lookup_tag.clone(), entry);
        self.filter.add(&lookup_tag);
    }

    pub fn get_voucher_root_valid(&self, voucher_id: &str) -> Option<u64> {
        self.voucher_roots.get(voucher_id).copied()
    }

    pub fn get_voucher_genesis_parent(&self, voucher_id: &str) -> Option<[u8; 32]> {
        self.voucher_genesis_parents.get(voucher_id).copied()
    }

    /// Prune expired HMC locks where now > valid_until + 30s grace (INV-1203).
    ///
    /// # Architectural Invariant: Pillar 6 — Zero State Bloat
    ///
    /// Unexpired tags are preserved in `ttl_buckets` to prevent data loss when a bucket
    /// contains a mix of expired and unexpired entries. When a voucher's tag set becomes
    /// empty after pruning, the voucher root and genesis parent entries are removed to
    /// prevent unbounded RAM growth from orphaned voucher metadata.
    pub fn prune_expired(&mut self, now: SimTime) -> usize {
        let before = self.locks.len();
        let max_expired_sec = if now.0 > 0 { (now.0 - 1) / 1_000 } else { 0 };

        let expired_bucket_keys: Vec<u64> = self
            .ttl_buckets
            .range(..=max_expired_sec)
            .map(|(b, _)| *b)
            .collect();

        for bucket in expired_bucket_keys {
            if let Some(tags) = self.ttl_buckets.remove(&bucket) {
                let mut remaining_tags: Vec<String> = Vec::new();
                for tag in tags {
                    if let Some(vu) = self.valid_until.get(&tag) {
                        if should_prune(now, SimTime(*vu)) {
                            if let Some(entry) = self.locks.remove(&tag) {
                                if let Some(vtags) = self.vouchers.get_mut(&entry.layer2_voucher_id) {
                                    vtags.remove(&tag);
                                    if vtags.is_empty() {
                                        self.vouchers.remove(&entry.layer2_voucher_id);
                                        self.voucher_roots.remove(&entry.layer2_voucher_id);
                                        self.voucher_genesis_parents.remove(&entry.layer2_voucher_id);
                                    }
                                }
                            }
                            self.valid_until.remove(&tag);
                            self.filter.delete(&tag);
                        } else {
                            remaining_tags.push(tag);
                        }
                    }
                }
                if !remaining_tags.is_empty() {
                    self.ttl_buckets.insert(bucket, remaining_tags);
                }
            }
        }

        before - self.locks.len()
    }

    pub fn query_status(
        &self,
        voucher_id: &str,
        challenge_ds_tag: &str,
        locator_prefixes: &[String],
    ) -> L2Verdict {
        let voucher_tags = match self.vouchers.get(voucher_id) {
            Some(tags) => tags,
            None => return L2Verdict::UnknownVoucher,
        };

        // If challenge_ds_tag exists directly as lookup_tag
        if let Some(entry) = self.locks.get(challenge_ds_tag) {
            return L2Verdict::Verified { lock_entry: entry.clone() };
        }

        // Fast-forward leap lock support: check if challenge_ds_tag matches the transaction_hash (t_id) of any lock in this voucher
        let mut challenge_tid = [0u8; 32];
        if bs58::decode(challenge_ds_tag).onto(&mut challenge_tid).is_ok() {
            for tag in voucher_tags {
                if let Some(entry) = self.locks.get(tag) {
                    if entry.t_id == challenge_tid {
                        return L2Verdict::Verified { lock_entry: entry.clone() };
                    }
                }
            }
        }

        // Locator prefixes check for LCA (bounded to 32 prefixes of max 64 chars to prevent Read-DoS)
        const MAX_LOCATORS: usize = 32;
        const MAX_PREFIX_LEN: usize = 64;
        for prefix in locator_prefixes.iter().take(MAX_LOCATORS) {
            if prefix.len() > MAX_PREFIX_LEN {
                continue;
            }
            for tag in voucher_tags {
                if tag.starts_with(prefix) {
                    return L2Verdict::MissingLocks { sync_point: prefix.clone() };
                }
            }
        }

        // No match found -> sync from genesis
        L2Verdict::MissingLocks { sync_point: "genesis".to_string() }
    }
}

#[derive(Clone, Debug)]
pub enum FlushOp {
    PutLock {
        lock: LockRecord,
        root_valid_until: u64,
    },
    PutHmcLock {
        lookup_tag: String,
        entry: Box<L2LockEntry>,
    },
    Prune {
        now_sec: u64,
    },
    PutEvidence {
        hash: [u8; 32],
        raw: Vec<u8>,
    },
    SetQuota {
        account_tag: [u8; 32],
        byte_years: u64,
    },
    BanNode {
        node_key: [u8; 32],
        timestamp_ms: u64,
    },
}

/// Hardened flush-worker tuning (Spec 12/14, Phase 7 P1):
/// - `FLUSH_BATCH_SIZE`: max ops per atomic redb commit (bounded RAM + bounded txn).
/// - `FLUSH_INTERVAL_MS`: max batching latency before a partial batch commits.
/// - `MAX_FLUSH_RETRIES` / `RETRY_BACKOFF_MS`: structured retry on transient
///   storage errors instead of silent log-and-drop losses.
/// - In-flight batches are strictly bounded to 1: the worker awaits every
///   `spawn_blocking` commit inline, guaranteeing strict commit order and making
///   graceful-shutdown drain deterministic (no untracked `tokio::spawn` jobs).
pub const FLUSH_BATCH_SIZE: usize = 100;
pub const FLUSH_INTERVAL_MS: u64 = 50;
pub const MAX_FLUSH_RETRIES: u32 = 3;
pub const RETRY_BACKOFF_MS: u64 = 10;
/// Upper bound for shutdown-drain batches (channel capacity / batch size + slack),
/// preventing an infinite drain loop if producers keep sending after cancellation.
pub const MAX_SHUTDOWN_DRAIN_BATCHES: usize = 120;

/// Structured outcome of one atomic flush commit (INV-1701 telemetry, never silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushOutcome {
    pub ops_committed: usize,
    pub attempts: u32,
    pub failed: bool,
}

/// Diagnostic persistence & flush telemetry statistics (INV-1701).
#[derive(Debug, Default)]
pub struct PersistenceStats {
    pub last_successful_flush_ms: std::sync::atomic::AtomicU64,
    pub flush_batches_total: std::sync::atomic::AtomicU64,
    pub flush_errors_total: std::sync::atomic::AtomicU64,
    pub flush_ops_total: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct DualTierEngine {
    pub ram: Arc<RwLock<RamIndex>>,
    pub hmc_ram: Arc<RwLock<HmcRamIndex>>,
    pub banned_nodes: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub db: Arc<RedbStorage>,
    pub tx: mpsc::Sender<FlushOp>,
    pub peer_manager: Arc<RwLock<Option<Arc<crate::network::PeerManager>>>>,
    pub recent_locks: Arc<parking_lot::RwLock<RecentLockBuffer>>,
    pub stats: Arc<PersistenceStats>,
    /// Previous pruning anchor timestamp in ms for detecting forward clock jumps (local NTP warp protection)
    pub last_prune_anchor: Arc<std::sync::atomic::AtomicU64>,
}

impl DualTierEngine {
    /// Creates a new DualTierEngine with an in-memory RAM index, RedbStorage, and a spawned background flush worker.
    pub fn new(db: Arc<RedbStorage>) -> (Self, tokio::task::JoinHandle<()>) {
        Self::new_with_token(db, tokio_util::sync::CancellationToken::new())
    }

    /// Creates a new DualTierEngine with a cancellation token for graceful shutdown of the flush worker.
    pub fn new_with_token(
        db: Arc<RedbStorage>,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(10_000);
        let ram = Arc::new(RwLock::new(RamIndex::new()));
        let hmc_ram = Arc::new(RwLock::new(HmcRamIndex::new()));

        let mut banned_set = HashSet::new();
        if let Ok(banned_list) = db.all_banned_nodes() {
            for k in banned_list {
                banned_set.insert(k);
            }
        }
        let banned_nodes = Arc::new(RwLock::new(banned_set));
        let recent_locks = Arc::new(parking_lot::RwLock::new(RecentLockBuffer::default()));
        let stats = Arc::new(PersistenceStats::default());

        let handle = Self::spawn_flush_worker(rx, Arc::clone(&db), Arc::clone(&stats), cancel_token);
        (
            Self {
                ram,
                hmc_ram,
                banned_nodes,
                db,
                tx,
                peer_manager: Arc::new(RwLock::new(None)),
                recent_locks,
                stats,
                last_prune_anchor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            },
            handle,
        )
    }

    /// Creates an engine instance from existing components (useful for custom worker management).
    pub fn from_parts(
        ram: Arc<RwLock<RamIndex>>,
        hmc_ram: Arc<RwLock<HmcRamIndex>>,
        db: Arc<RedbStorage>,
        tx: mpsc::Sender<FlushOp>,
    ) -> Self {
        let mut banned_set = HashSet::new();
        if let Ok(banned_list) = db.all_banned_nodes() {
            for k in banned_list {
                banned_set.insert(k);
            }
        }
        let banned_nodes = Arc::new(RwLock::new(banned_set));
        let recent_locks = Arc::new(parking_lot::RwLock::new(RecentLockBuffer::default()));
        let stats = Arc::new(PersistenceStats::default());
        Self {
            ram,
            hmc_ram,
            banned_nodes,
            db,
            tx,
            peer_manager: Arc::new(RwLock::new(None)),
            recent_locks,
            stats,
            last_prune_anchor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Sets the peer manager reference so that node bans propagate immediately to peer connections.
    pub async fn set_peer_manager(&self, pm: Arc<crate::network::PeerManager>) {
        let mut guard = self.peer_manager.write().await;
        *guard = Some(pm);
    }

    /// Checks if a node is banned due to fraud/slashing.
    pub async fn is_node_banned(&self, node_key: &[u8; 32]) -> bool {
        self.banned_nodes.read().await.contains(node_key)
    }

    /// Bans a node in memory, disconnects it across active peers, and queues persistence to redb.
    ///
    /// Hot-path safe (Rule 1): never blocks on I/O and never spawns untracked
    /// background jobs. RAM is authoritative immediately; if the bounded flush
    /// queue is full the disk write is counted as a telemetry error (never silent)
    /// and reconciled via the next ban refresh or digest-pull sync.
    pub async fn ban_node(&self, node_key: [u8; 32], timestamp_ms: u64) {
        self.banned_nodes.write().await.insert(node_key);
        if let Some(pm) = self.peer_manager.read().await.as_ref() {
            pm.ban_node(&node_key).await;
        }
        match self.tx.try_send(FlushOp::BanNode { node_key, timestamp_ms }) {
            Ok(_) => {},
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("Persistence queue full: BanNode kept authoritative in RAM, disk flush dropped (counted in flush_errors_total)");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("Persistence worker closed: BanNode active in RAM only");
            }
        }
    }

    /// Processes an incoming EquivocationProof: verifies proof, queues raw evidence for
    /// the async flush worker, and bans the offender.
    ///
    /// Hot-path safe (Rule 1): performs zero synchronous disk I/O. Evidence is
    /// enqueued via `try_send` and committed atomically by the flush worker; a full
    /// queue is counted in telemetry instead of blocking the caller.
    pub async fn process_equivocation_proof(
        &self,
        proof: &humoco_sim_core::fraud::FraudProofPayload,
        raw_payload: &[u8],
    ) -> bool {
        if !proof.verify() {
            return false;
        }
        let offender = proof.perpetrator_node_id;
        let evidence_hash = *blake3::hash(raw_payload).as_bytes();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        match self.tx.try_send(FlushOp::PutEvidence {
            hash: evidence_hash,
            raw: raw_payload.to_vec(),
        }) {
            Ok(_) => {},
            Err(_) => {
                self.stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("Persistence queue full: equivocation evidence kept in RAM ban only (counted in flush_errors_total)");
            }
        }
        self.ban_node(offender, now_ms).await;
        true
    }

    /// Ingress a lock record on the hot path (< 1µs in RAM) and queue an async flush operation.
    /// Split-brain healing via min(H_canon) (Spec 02, 08):
    /// When a colliding lock arrives, min(H_canon) decides.
    /// If the new lock wins (WinnerB), it replaces the previous one atomically in RAM/disk state.
    /// If the old lock wins (WinnerA), it remains unchanged and the new lock is discarded (Void).
    /// Ingress a lock record on the hot path (< 1µs in RAM) with default ClientApi origin.
    pub async fn ingress_lock(
        &self,
        record: LockRecord,
        now: SimTime,
        root_valid_until: SimTime,
    ) -> Result<IngressVerdictLow, IngressVerdictLow> {
        self.ingress_lock_with_origin(record, now, root_valid_until, IngressOrigin::ClientApi)
            .await
    }

    /// Ingress a lock record on the hot path (< 1µs in RAM) with an explicit IngressOrigin and queue an async flush operation.
    /// Split-brain healing via min(H_canon) (Spec 02, 08):
    /// - On IngressOrigin::ClientApi, an existing lock is never overwritten by min(H_canon),
    ///   but immediately returns (Err(IngressVerdictLow::RejectedCollision), None).
    /// - On IngressOrigin::PartitionSync, min(H_canon) decides deterministically.
    ///   If the new lock wins (WinnerB), it replaces the previous one atomically in RAM/disk state.
    ///   If the old lock wins (WinnerA), it remains unchanged and the new lock is discarded (Void).
    pub async fn ingress_lock_with_origin(
        &self,
        mut record: LockRecord,
        now: SimTime,
        root_valid_until: SimTime,
        origin: IngressOrigin,
    ) -> Result<IngressVerdictLow, IngressVerdictLow> {
        // Reservation-First: check if flush capacity is available before modifying RAM (Backpressure protection B-01)
        let permit = match self.tx.try_reserve() {
            Ok(p) => p,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!("Persistence flush queue full - rejecting ingress with backpressure");
                return Err(IngressVerdictLow::RejectedCapacity);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                error!("Persistence flush worker closed");
                return Err(IngressVerdictLow::RejectedCapacity);
            }
        };

        let parent_lock_hex = hex::encode(record.parent_lock);
        let child_lock_hex = hex::encode(record.id);
        let is_final = record.status.is_final();

        if origin == IngressOrigin::PartitionSync {
            let mut hasher = blake3::Hasher::new();
            let tag = b"HUMOCO_V1_LOCK_ID";
            hasher.update(&[tag.len() as u8]);
            hasher.update(tag);
            hasher.update(&record.parent_lock);
            hasher.update(&record.receiver_pub);
            hasher.update(&record.nonce);
            hasher.update(&record.created_at.0.to_le_bytes());
            hasher.update(&record.valid_until.0.to_le_bytes());
            let expected_id: humoco_sim_core::types::Hash256 = *hasher.finalize().as_bytes();
            if record.id != expected_id {
                warn!("PartitionSync lock rejected: invalid LockId hash preimage");
                return Err(IngressVerdictLow::RejectedWindow);
            }
            if record.valid_until.0 <= now.0 || record.valid_until.0 > root_valid_until.0 {
                warn!("PartitionSync lock rejected: invalid valid_until TTL");
                return Err(IngressVerdictLow::RejectedWindow);
            }
        }

        let (verdict, to_flush) = {
            let mut ram = self.ram.write().await;
            match ram.try_insert(record.clone(), now, root_valid_until) {
                Ok(v) => (Ok(v), Some(record)),
                Err(IngressVerdictLow::RejectedCollision) => {
                    // Split-brain collision on parent_lock!
                    if origin == IngressOrigin::ClientApi {
                        // Live client ingress: protect against self-equivocation; never overwrite an existing lock via min(H_canon)
                        (Err(IngressVerdictLow::RejectedCollision), None)
                    } else if let Some(existing) = ram.get_mut(&record.parent_lock) {
                        let res = humoco_sim_core::resolver::resolve_split_brain(existing, &mut record);
                        match res {
                            humoco_sim_core::resolver::ResolutionResult::WinnerB { .. } => {
                                ram.replace_lock(record.clone(), root_valid_until);
                                (Ok(IngressVerdictLow::AcceptedNew), Some(record))
                            }
                            humoco_sim_core::resolver::ResolutionResult::WinnerA { .. } => {
                                (Err(IngressVerdictLow::RejectedCollision), None)
                            }
                            humoco_sim_core::resolver::ResolutionResult::Identical => {
                                (Ok(IngressVerdictLow::IdempotentReplay), None)
                            }
                            humoco_sim_core::resolver::ResolutionResult::NoConflict => {
                                (Err(IngressVerdictLow::RejectedCollision), None)
                            }
                        }
                    } else {
                        (Err(IngressVerdictLow::RejectedCollision), None)
                    }
                }
                Err(e) => (Err(e), None),
            }
        };

        if let Some(rec) = to_flush {
            permit.send(FlushOp::PutLock {
                lock: rec,
                root_valid_until: root_valid_until.0,
            });
        }

        // Push lightweight summary to zero-contention recent locks ringbuffer (< 1µs hot-path impact)
        let recent_status = match &verdict {
            Ok(IngressVerdictLow::AcceptedNew) => {
                if is_final {
                    RecentLockStatus::Verified
                } else {
                    RecentLockStatus::Provisional
                }
            }
            Ok(IngressVerdictLow::IdempotentReplay) => RecentLockStatus::Verified,
            _ => RecentLockStatus::Conflict,
        };
        {
            let mut recent = self.recent_locks.write();
            recent.push(RecentLockSummary {
                parent_lock_hex,
                child_lock_hex,
                timestamp_ms: now.0,
                status: recent_status,
                tier: "P2P-Sync".to_string(),
                byte_years: 0,
                voucher_id: None,
            });
        }

        verdict
    }

    /// Returns a copy of the LockRecord from RAM index if present.
    pub async fn get_ram_lock(&self, parent_lock: &[u8; 32]) -> Option<LockRecord> {
        let ram = self.ram.read().await;
        ram.get(parent_lock).cloned()
    }

    /// Returns a copy of the L2LockEntry from HMC RAM index if present.
    pub async fn get_hmc_ram_lock(&self, lookup_tag: &str) -> Option<L2LockEntry> {
        let hmc = self.hmc_ram.read().await;
        hmc.locks.get(lookup_tag).cloned()
    }

    /// Ingress an HMC lock entry on the hot path (< 1µs in RAM) with default ClientApi origin.
    pub async fn ingress_hmc_lock(
        &self,
        lookup_tag: String,
        entry: L2LockEntry,
    ) -> (L2Verdict, bool) {
        self.ingress_hmc_lock_with_origin(lookup_tag, entry, IngressOrigin::ClientApi, None)
            .await
    }

    /// Ingress an HMC lock entry on the hot path (< 1µs in RAM) with an explicit IngressOrigin and queue an async flush operation if newly accepted.
    pub async fn ingress_hmc_lock_with_origin(
        &self,
        lookup_tag: String,
        entry: L2LockEntry,
        origin: IngressOrigin,
        now_ms: Option<u64>,
    ) -> (L2Verdict, bool) {
        let default_tier = match origin {
            IngressOrigin::ClientApi => "Free",
            IngressOrigin::PartitionSync => "P2P-Sync",
        };
        self.ingress_hmc_lock_with_metadata(lookup_tag, entry, origin, now_ms, Some(default_tier), Some(0), None).await
    }

    /// Ingress an HMC lock entry on the hot path (< 1µs in RAM) with explicit IngressOrigin, metadata, and queue an async flush operation if newly accepted.
    /// On double-signing (same sender on colliding tag), evidence is persisted in redb and the offender is banned.
    #[allow(clippy::too_many_arguments)]
    pub async fn ingress_hmc_lock_with_metadata(
        &self,
        lookup_tag: String,
        entry: L2LockEntry,
        origin: IngressOrigin,
        now_ms: Option<u64>,
        tier: Option<&str>,
        byte_years: Option<u64>,
        voucher_id: Option<String>,
    ) -> (L2Verdict, bool) {
        // Reservation-First: check if flush capacity is available before modifying RAM (Backpressure protection B-01)
        let permit = match self.tx.try_reserve() {
            Ok(p) => p,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!("Persistence flush queue full - rejecting HMC ingress with backpressure");
                return (
                    L2Verdict::Rejected {
                        reason: "Persistence queue congested (backpressure)".into(),
                    },
                    false,
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                error!("Persistence flush worker closed");
                return (
                    L2Verdict::Rejected {
                        reason: "Persistence worker unavailable".into(),
                    },
                    false,
                );
            }
        };

        let (verdict, is_new, equivocation_to_slash) = {
            let mut hmc = self.hmc_ram.write().await;
            let equivocation = if let Some(existing) = hmc.locks.get(&lookup_tag) {
                if existing.t_id != entry.t_id && existing.sender_ephemeral_pub == entry.sender_ephemeral_pub {
                    Some((existing.clone(), entry.clone()))
                } else {
                    None
                }
            } else {
                None
            };
            let (verdict, is_new) = hmc.insert_or_check(lookup_tag.clone(), entry.clone(), origin, now_ms);
            (verdict, is_new, equivocation)
        };

        if let Some((existing, entry_new)) = equivocation_to_slash {
            if crate::api::hmc::verify_l2_lock_entry_signature(&existing, &lookup_tag)
                && crate::api::hmc::verify_l2_lock_entry_signature(&entry_new, &lookup_tag)
            {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let raw_evidence = serde_json::to_vec(&(&existing, &entry_new)).unwrap_or_default();
                let evidence_hash = *blake3::hash(&raw_evidence).as_bytes();
                // Async persistence only (Rule 1): never touch redb synchronously on the hot path.
                if self.tx.try_send(FlushOp::PutEvidence {
                    hash: evidence_hash,
                    raw: raw_evidence,
                }).is_err() {
                    self.stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!("Persistence queue full: equivocation evidence deferred (counted in flush_errors_total)");
                }
                self.ban_node(entry_new.sender_ephemeral_pub, now_ms).await;
            } else {
                tracing::warn!("Equivocation discarded: one or both signatures failed first-party cryptographic verification");
            }
        }

        if is_new {
            permit.send(FlushOp::PutHmcLock {
                lookup_tag: lookup_tag.clone(),
                entry: Box::new(entry.clone()),
            });
        }

        // Push lightweight summary to zero-contention recent locks ringbuffer (< 1µs hot-path impact)
        let recent_status = match &verdict {
            L2Verdict::Verified { .. } => RecentLockStatus::Verified,
            L2Verdict::Conflict { .. } => RecentLockStatus::Conflict,
            _ => RecentLockStatus::Conflict,
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let default_origin_tier = match origin {
            IngressOrigin::ClientApi => "Free",
            IngressOrigin::PartitionSync => "P2P-Sync",
        };
        let tier_str = tier.unwrap_or(default_origin_tier).to_string();
        {
            let mut recent = self.recent_locks.write();
            recent.push(RecentLockSummary {
                parent_lock_hex: lookup_tag,
                child_lock_hex: hex::encode(entry.t_id),
                timestamp_ms: now_ms,
                status: recent_status,
                tier: tier_str,
                byte_years: byte_years.unwrap_or(0),
                voucher_id,
            });
        }

        (verdict, is_new)
    }

    /// Atomares Ketten-Locking: Validates all hops in `chain_req` before any mutation.
    /// - Signature verification per hop
    /// - Timestamp monotonicity
    /// - Cuckoo + RAM collision check (deduplication via identical t_id)
    ///
    /// On collision: no state changes, returns Conflict with existing entry.
    ///
    /// On success: atomically inserts all new hops, enqueues FlushOps, returns Verified with terminal hop.
    pub async fn ingress_hmc_chain_lock(
        &self,
        chain_req: crate::api::hmc::L2ChainLockRequest,
        origin: IngressOrigin,
        now_ms: Option<u64>,
    ) -> (L2Verdict, bool) {
        let default_tier = match origin {
            IngressOrigin::ClientApi => "Free",
            IngressOrigin::PartitionSync => "P2P-Sync",
        };
        self.ingress_hmc_chain_lock_with_tier(chain_req, origin, now_ms, Some(default_tier), Some(0))
            .await
    }

    /// # Architectural Invariant: Spec 06, INV-0604 ProofChain Causality (Phase 2 P1)
    ///
    /// A `LockEntry` is valid only if its `parent_lock` (lookup tag) matches
    /// bit-exactly the predecessor anchor committed in its own Ed25519
    /// `layer2_signature`, and hop `i` validly continues hop `i-1`:
    /// same voucher, strictly increasing `encrypted_timestamp`, valid per-hop
    /// signature, genesis carries `deletable_at` (immutable root TTL) while
    /// spends carry a non-empty `ds_tag`. Linear spends reference
    /// `bs58(prev.t_id)`; independent DAG split branches (Spec 06 §3.2) carry
    /// distinct tags — both are accepted, but two different `t_id` on the same
    /// tag inside one batch are a causal double-spend and rejected. Pure
    /// function: no RAM mutation, cheap checks first (Rule 9).
    pub fn verify_chain_causality(
        chain_req: &crate::api::hmc::L2ChainLockRequest,
    ) -> Result<(), String> {
        if chain_req.chain.is_empty() {
            return Err("Empty chain: at least one lock required".into());
        }
        for hop in &chain_req.chain {
            if hop.layer2_voucher_id != chain_req.layer2_voucher_id {
                return Err(format!(
                    "Voucher mismatch in chain: expected {}, got {}",
                    chain_req.layer2_voucher_id, hop.layer2_voucher_id
                ));
            }
        }
        for hop in &chain_req.chain {
            if !crate::api::hmc::verify_l2_lock_signature(hop) {
                return Err("Invalid cryptographic signature in chain".into());
            }
            if !hop.is_genesis {
                match &hop.ds_tag {
                    Some(t) if !t.trim().is_empty() => {},
                    _ => {
                        return Err(
                            "Missing or empty ds_tag for non-genesis spend".into()
                        );
                    }
                }
            } else if hop
                .deletable_at
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .is_none()
            {
                return Err("Genesis lock requires valid deletable_at timestamp".into());
            }
        }
        for i in 1..chain_req.chain.len() {
            let prev = &chain_req.chain[i - 1];
            let cur = &chain_req.chain[i];
            if cur.encrypted_timestamp <= prev.encrypted_timestamp {
                return Err(format!(
                    "Timestamp monotonicity violated at hop {}: {} <= {}",
                    i, cur.encrypted_timestamp, prev.encrypted_timestamp
                ));
            }
            // Cryptographic linkage (INV-0604): each hop's Ed25519
            // `layer2_signature` commits to its own `(voucher_id, ds_tag, t_id)`
            // preimage, and hops are causally ordered by strictly increasing
            // timestamps on the same voucher. Linear spends (`ds_tag ==
            // bs58(prev.t_id)`) and independent DAG split branches (Spec 06
            // §3.2, distinct tags) are both accepted here; same-tag diverging
            // `t_id` inside one batch is a causal double-spend and is
            // reported downstream as `Conflict` with the earlier hop as
            // evidence (atomic rollback, no state change).
        }
        Ok(())
    }

    /// Atomares Ketten-Locking with explicit tier and byte_years metadata for recent locks buffer.
    pub async fn ingress_hmc_chain_lock_with_tier(
        &self,
        chain_req: crate::api::hmc::L2ChainLockRequest,
        origin: IngressOrigin,
        now_ms: Option<u64>,
        tier: Option<&str>,
        byte_years: Option<u64>,
    ) -> (L2Verdict, bool) {
        // Causality gate (Spec 06 INV-0604): cryptographic chaining first.
        if let Err(reason) = Self::verify_chain_causality(&chain_req) {
            return (L2Verdict::Rejected { reason }, false);
        }

        // Atomic collision check + insertion under single write lock
        // We do reservation-first after determining which hops are truly new.
        let (verdict, is_new, _ops_to_flush) = {
            let mut hmc = self.hmc_ram.write().await;

            // First pass: gather lookup_tags and detect collisions / idempotent replays
            use std::collections::HashMap;
            let mut seen_in_batch: HashMap<String, [u8; 32]> = HashMap::new();
            // (tag, entry, is_genesis): genesis flag is required so follow-up locks
            // can never initialize the immutable voucher root TTL (Rule 10).
            let mut new_entries: Vec<(String, L2LockEntry, bool)> = Vec::new();
            let mut terminal_entry_opt: Option<L2LockEntry> = None;
            let mut conflict_entry: Option<L2LockEntry> = None;

            for hop in &chain_req.chain {
                let lookup_tag = if hop.is_genesis {
                    bs58::encode(&hop.transaction_hash).into_string()
                } else {
                    hop.ds_tag.clone().unwrap_or_default()
                };

                let entry = L2LockEntry::from(hop);
                let hop_is_genesis = hop.is_genesis;

                // Intra-batch duplicate detection
                if let Some(prev_tid) = seen_in_batch.get(&lookup_tag) {
                    if *prev_tid != entry.t_id {
                        // Intra-batch double-spend -> conflict with first entry of this tag in batch
                        // For deterministic verdict, return the first stored entry as existing
                        if let Some(existing) = hmc.locks.get(&lookup_tag) {
                            conflict_entry = Some(existing.clone());
                        } else {
                            // No existing in RAM, conflict is within batch itself => report the earlier entry
                            // Construct a synthetic existing lock from earlier hop
                            let earlier = new_entries
                                .iter()
                                .find(|(t, _, _)| t == &lookup_tag)
                                .map(|(_, e, _)| e.clone())
                                .unwrap_or(entry.clone());
                            conflict_entry = Some(earlier);
                        }
                        break;
                    } else {
                        // Same t_id duplicate within chain -> idempotent skip
                        // Keep terminal as this entry's existing counterpart
                        if let Some(existing) = hmc.locks.get(&lookup_tag) {
                            terminal_entry_opt = Some(existing.clone());
                        } else {
                            // duplicate within batch but not yet in RAM -> it's the same new entry, skip adding again
                            terminal_entry_opt = Some(entry.clone());
                        }
                        continue;
                    }
                }
                seen_in_batch.insert(lookup_tag.clone(), entry.t_id);

                // Cuckoo fast negative check + RAM canonical check
                // Note: filter false positives are ok – we still check RAM
                // If filter says not contains, we still need RAM check (filter is probabilistic)
                if let Some(existing) = hmc.locks.get(&lookup_tag) {
                    if existing.t_id == entry.t_id {
                        // Idempotent replay (already in RAM)
                        terminal_entry_opt = Some(existing.clone());
                        continue;
                    } else {
                        conflict_entry = Some(existing.clone());
                        break;
                    }
                }
                // Not in RAM -> prepare for insertion
                new_entries.push((lookup_tag.clone(), entry.clone(), hop_is_genesis));
                terminal_entry_opt = Some(entry);
            }

            if let Some(existing) = conflict_entry {
                // Rollback: zero state changes
                (L2Verdict::Conflict { existing_lock: existing }, false, Vec::<FlushOp>::new())
            } else {
                // No collisions – validate ingress window & voucher roots for new entries before mutation
                // Determine if any new entry would fail due to unknown root or window violation
                // We need to simulate sequential insertion to handle chain-local genesis root.
                // Only genesis hops may initialize the immutable root TTL (Rule 10).
                let mut temp_roots = hmc.voucher_roots.clone();
                let mut window_violation: Option<String> = None;
                for (_tag, entry, hop_is_genesis) in &new_entries {
                    let root_valid = temp_roots.get(&entry.layer2_voucher_id).copied();
                    if root_valid.is_none() && !hop_is_genesis {
                        window_violation = Some("Unknown voucher root: genesis lock must be anchored first".into());
                        break;
                    }
                    let valid_until_ms = match entry
                        .deletable_at
                        .as_deref()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or(root_valid)
                    {
                        Some(v) => v,
                        None => {
                            window_violation = Some("Missing deletable_at and unknown voucher root".into());
                            break;
                        }
                    };
                    if origin == IngressOrigin::ClientApi {
                        if let (Some(root_v), Some(now)) = (root_valid, now_ms) {
                            if !ingress_time_window_valid(
                                SimTime(now),
                                SimTime(valid_until_ms),
                                SimTime(root_v),
                            ) {
                                window_violation = Some(
                                    "Invalid ingress time window: now + 30s < valid_until <= root.valid_until violated".into(),
                                );
                                break;
                            }
                        } else if root_valid.is_none() && entry.deletable_at.is_none() {
                            window_violation = Some("Missing deletable_at and unknown voucher root".into());
                            break;
                        }
                    }
                    // Only genesis initializes the immutable root TTL for
                    // subsequent hops in the same chain (Rule 10).
                    if *hop_is_genesis {
                        temp_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);
                    }
                }
                if let Some(reason) = window_violation {
                    (L2Verdict::Rejected { reason }, false, Vec::<FlushOp>::new())
                } else if new_entries.is_empty() {
                    // All hops were idempotent replays
                    let terminal = terminal_entry_opt.unwrap();
                    (L2Verdict::Verified { lock_entry: terminal }, false, Vec::<FlushOp>::new())
                } else {
                    // Reservation-First: ensure queue capacity for all new entries
                    let needed = new_entries.len();
                    let mut permits = Vec::with_capacity(needed);
                    let mut capacity_exceeded = false;
                    for _ in 0..needed {
                        match self.tx.try_reserve() {
                            Ok(p) => permits.push(p),
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                capacity_exceeded = true;
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                capacity_exceeded = true;
                                break;
                            }
                        }
                    }
                    if capacity_exceeded {
                        // Drop any reserved permits
                        drop(permits);
                        (
                            L2Verdict::Rejected {
                                reason: "Persistence queue congested (backpressure)".into(),
                            },
                            false,
                            Vec::<FlushOp>::new(),
                        )
                    } else {
                        // Atomically insert all new hops and dispatch flush operations
                        for (permit, (tag, entry, hop_is_genesis)) in permits.into_iter().zip(new_entries.into_iter()) {
                            let root_valid = hmc.voucher_roots.get(&entry.layer2_voucher_id).copied();
                            let valid_until_ms = entry
                                .deletable_at
                                .as_deref()
                                .and_then(|s| s.parse::<u64>().ok())
                                .or(root_valid)
                                .unwrap_or(0);
                            let prune_threshold_ms = valid_until_ms.saturating_add(30_000);
                            let bucket_sec = prune_threshold_ms / 1_000;
                            hmc.ttl_buckets.entry(bucket_sec).or_default().push(tag.clone());
                            hmc.valid_until.insert(tag.clone(), valid_until_ms);
                            // Only the genesis lock sets the immutable root TTL.
                            if hop_is_genesis {
                                hmc.voucher_roots
                                    .entry(entry.layer2_voucher_id.clone())
                                    .or_insert(valid_until_ms);
                            }
                            if hop_is_genesis && entry.deletable_at.is_some() {
                                let p_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
                                hmc.voucher_genesis_parents
                                    .entry(entry.layer2_voucher_id.clone())
                                    .or_insert(p_bytes);
                            }
                            hmc.vouchers
                                .entry(entry.layer2_voucher_id.clone())
                                .or_default()
                                .insert(tag.clone());
                            hmc.filter.add(&tag);

                            let entry_box = Box::new(entry);
                            hmc.locks.insert(tag.clone(), (*entry_box).clone());
                            permit.send(FlushOp::PutHmcLock {
                                lookup_tag: tag,
                                entry: entry_box,
                            });
                        }
                        let terminal = terminal_entry_opt.unwrap();
                        (L2Verdict::Verified { lock_entry: terminal }, true, Vec::<FlushOp>::new())
                    }
                }
            }
        };

        // Recent buffer update for terminal
        let recent_status = match &verdict {
            L2Verdict::Verified { .. } => RecentLockStatus::Verified,
            L2Verdict::Conflict { .. } => RecentLockStatus::Conflict,
            _ => RecentLockStatus::Conflict,
        };
        if let L2Verdict::Verified { lock_entry } = &verdict {
            let tag = if chain_req.chain.last().map(|h| h.is_genesis).unwrap_or(false) {
                bs58::encode(&chain_req.chain.last().unwrap().transaction_hash).into_string()
            } else {
                chain_req
                    .chain
                    .last()
                    .and_then(|h| h.ds_tag.clone())
                    .unwrap_or_default()
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let default_origin_tier = match origin {
                IngressOrigin::ClientApi => "Free",
                IngressOrigin::PartitionSync => "P2P-Sync",
            };
            let tier_str = tier.unwrap_or(default_origin_tier).to_string();
            self.recent_locks.write().push(RecentLockSummary {
                parent_lock_hex: tag,
                child_lock_hex: hex::encode(lock_entry.t_id),
                timestamp_ms: now,
                status: recent_status,
                tier: tier_str,
                byte_years: byte_years.unwrap_or(0),
                voucher_id: Some(chain_req.layer2_voucher_id.clone()),
            });
        }

        (verdict, is_new)
    }

    /// Returns the most recent lock summaries from the zero-contention ringbuffer.
    pub fn get_recent_locks(&self, limit: usize) -> Vec<RecentLockSummary> {
        self.recent_locks.read().get_recent(limit)
    }

    /// Returns the current depth of the async disk flush queue.
    pub fn flush_sender_len(&self) -> usize {
        self.tx.max_capacity().saturating_sub(self.tx.capacity())
    }

    /// Records a lock summary into the recent locks ringbuffer with cheap non-blocking lock.
    pub fn record_recent_lock(&self, summary: RecentLockSummary) {
        self.recent_locks.write().push(summary);
    }

    /// Inspects a lock by querying the in-memory RAM index.
    pub async fn inspect_lock(&self, parent_lock: &[u8; 32]) -> Option<LockInspection> {
        let ram = self.ram.read().await;
        if let Some(record) = ram.get(parent_lock) {
            return Some(LockInspection {
                parent_lock_hex: hex::encode(record.parent_lock),
                lock_id_hex: hex::encode(record.id),
                receiver_pub_hex: hex::encode(record.receiver_pub),
                created_at_ms: record.created_at.0,
                valid_until_ms: record.valid_until.0,
                status: format!("{:?}", record.status),
                signers_count: record.signers.len(),
            });
        }
        drop(ram);

        let hmc_ram = self.hmc_ram.read().await;
        let hex_tag = hex::encode(parent_lock);
        if let Some(entry) = hmc_ram.locks.get(&hex_tag) {
            let valid_until_ms = entry
                .deletable_at
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| hmc_ram.get_voucher_root_valid(&entry.layer2_voucher_id))
                .unwrap_or(0);
            return Some(LockInspection {
                parent_lock_hex: hex_tag,
                lock_id_hex: hex::encode(entry.t_id),
                receiver_pub_hex: hex::encode(entry.sender_ephemeral_pub),
                created_at_ms: 0,
                valid_until_ms,
                status: "Verified".to_string(),
                signers_count: 0,
            });
        }

        None
    }

    /// Returns the root validity timestamp (in ms) for an HMC voucher, if known.
    pub async fn get_hmc_voucher_root_valid(&self, voucher_id: &str) -> Option<u64> {
        self.hmc_ram.read().await.get_voucher_root_valid(voucher_id)
    }

    /// Returns the genesis parent lock for an HMC voucher, if known.
    pub async fn get_hmc_voucher_genesis_parent(&self, voucher_id: &str) -> Option<[u8; 32]> {
        if let Some(p) = self.hmc_ram.read().await.get_voucher_genesis_parent(voucher_id) {
            return Some(p);
        }
        // Fallback to redb
        if let Ok(locks) = self.db.get_hmc_locks_for_voucher(voucher_id) {
            for (tag, entry) in locks {
                if entry.deletable_at.is_some() {
                    let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                    self.hmc_ram.write().await.voucher_genesis_parents.insert(voucher_id.to_string(), parent);
                    return Some(parent);
                }
            }
        }
        None
    }

    /// Returns the genesis shard ID for an HMC voucher, if known.
    pub async fn get_hmc_voucher_genesis_shard(&self, voucher_id: &str) -> Option<u16> {
        self.get_hmc_voucher_genesis_parent(voucher_id).await.map(|p| humoco_sim_core::types::extract_shard_id(&p))
    }

    /// Manually records the genesis parent lock for an HMC voucher.
    pub async fn record_hmc_voucher_genesis_parent(&self, voucher_id: &str, parent: [u8; 32]) {
        self.hmc_ram.write().await.voucher_genesis_parents.insert(voucher_id.to_string(), parent);
    }

    /// Returns at most `limit` recent active vouchers without scanning the entire database if not needed.
    pub async fn get_recent_active_vouchers(&self, limit: usize) -> Vec<VoucherSummaryDto> {
        if limit == 0 {
            return Vec::new();
        }

        let mut vouchers_map: HashMap<String, (u64, usize, Option<String>)> = HashMap::new();

        // 1. Fast collect from in-memory RAM
        {
            let hmc = self.hmc_ram.read().await;
            for (vid, tags) in &hmc.vouchers {
                let root_valid = hmc.voucher_roots.get(vid).copied().unwrap_or(0);
                let genesis = tags
                    .iter()
                    .find(|t| hmc.locks.get(*t).is_some_and(|e| e.deletable_at.is_some()))
                    .cloned();
                vouchers_map.insert(vid.clone(), (root_valid, tags.len(), genesis));
            }
        }

        // 2. If limit not satisfied from RAM, query redb up to limit
        if vouchers_map.len() < limit {
            if let Ok(db_vouchers) = self.db.all_active_vouchers() {
                for vid in db_vouchers {
                    if let std::collections::hash_map::Entry::Vacant(e) = vouchers_map.entry(vid) {
                        if let Ok(locks) = self.db.get_hmc_locks_for_voucher(e.key()) {
                            let root_valid = locks
                                .iter()
                                .find_map(|(_, entry)| {
                                    entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok())
                                })
                                .unwrap_or(0);
                            let genesis = locks
                                .iter()
                                .find(|(_, entry)| entry.deletable_at.is_some())
                                .map(|(tag, _)| tag.clone());
                            e.insert((root_valid, locks.len(), genesis));
                        }
                    }
                    if vouchers_map.len() >= limit {
                        break;
                    }
                }
            }
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut results = Vec::with_capacity(vouchers_map.len().min(limit));
        for (vid, (root_valid, count, genesis)) in vouchers_map {
            let status = if root_valid == 0 {
                "Unknown".to_string()
            } else if now_ms > root_valid {
                "Expired".to_string()
            } else {
                "Active".to_string()
            };
            let formatted = if root_valid > 0 {
                let rem_sec = root_valid.saturating_sub(now_ms) / 1000;
                format!("TTL: {}s remaining", rem_sec)
            } else {
                "N/A".to_string()
            };
            results.push(VoucherSummaryDto {
                voucher_id: vid,
                root_valid_until_ms: root_valid,
                root_valid_until_formatted: formatted,
                created_at_ms: 0,
                locks_count: count,
                genesis_tag: genesis,
                status,
            });
        }
        results.sort_by(|a, b| b.root_valid_until_ms.cmp(&a.root_valid_until_ms));
        if results.len() > limit {
            results.truncate(limit);
        }
        results
    }

    /// Returns the total distinct count of active vouchers (RAM + redb distinct).
    pub async fn get_total_active_vouchers_count(&self) -> usize {
        let mut set = HashSet::new();
        {
            let hmc = self.hmc_ram.read().await;
            for vid in hmc.vouchers.keys() {
                set.insert(vid.clone());
            }
        }
        if let Ok(db_vouchers) = self.db.all_active_vouchers() {
            for vid in db_vouchers {
                set.insert(vid);
            }
        }
        set.len()
    }

    /// Computes the total active storage-time footprint in Byte-Years and active lock count from in-memory RAM indices.
    pub async fn get_active_footprint_byte_years(&self, now_ms: u64) -> (u64, usize) {
        let mut total_byte_years = 0u64;
        let mut count = 0usize;

        {
            let hmc = self.hmc_ram.read().await;
            for &vu in hmc.valid_until.values() {
                if vu > now_ms {
                    let ttl_sec = (vu - now_ms) / 1000;
                    total_byte_years = total_byte_years.saturating_add(ByteYears::from_ttl_seconds(ttl_sec.max(1)));
                    count += 1;
                }
            }
        }

        {
            let ram = self.ram.read().await;
            for rec in ram.iter() {
                if rec.valid_until.0 > now_ms {
                    let ttl_sec = (rec.valid_until.0 - now_ms) / 1000;
                    total_byte_years = total_byte_years.saturating_add(ByteYears::from_ttl_seconds(ttl_sec.max(1)));
                    count += 1;
                }
            }
        }

        (total_byte_years, count)
    }

    /// Returns a list of all active vouchers known to this node (from RAM and redb).
    pub async fn get_all_active_vouchers(&self) -> Vec<VoucherSummaryDto> {
        let mut vouchers_map: HashMap<String, (u64, usize, Option<String>)> = HashMap::new();

        // 1. Collect from RAM
        {
            let hmc = self.hmc_ram.read().await;
            for (vid, tags) in &hmc.vouchers {
                let root_valid = hmc.voucher_roots.get(vid).copied().unwrap_or(0);
                let genesis = tags.iter().find(|t| hmc.locks.get(*t).is_some_and(|e| e.deletable_at.is_some())).cloned();
                vouchers_map.insert(vid.clone(), (root_valid, tags.len(), genesis));
            }
        }

        // 2. Collect from redb
        if let Ok(db_vouchers) = self.db.all_active_vouchers() {
            for vid in db_vouchers {
                if let std::collections::hash_map::Entry::Vacant(e) = vouchers_map.entry(vid) {
                    if let Ok(locks) = self.db.get_hmc_locks_for_voucher(e.key()) {
                        let root_valid = locks.iter().find_map(|(_, entry)| {
                            entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok())
                        }).unwrap_or(0);
                        let genesis = locks.iter().find(|(_, entry)| entry.deletable_at.is_some()).map(|(tag, _)| tag.clone());
                        e.insert((root_valid, locks.len(), genesis));
                    }
                }
            }
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut results = Vec::new();
        for (vid, (root_valid, count, genesis)) in vouchers_map {
            let status = if root_valid == 0 {
                "Unknown".to_string()
            } else if now_ms > root_valid {
                "Expired".to_string()
            } else {
                "Active".to_string()
            };
            let formatted = if root_valid > 0 {
                let rem_sec = root_valid.saturating_sub(now_ms) / 1000;
                format!("TTL: {}s remaining", rem_sec)
            } else {
                "N/A".to_string()
            };
            results.push(VoucherSummaryDto {
                voucher_id: vid,
                root_valid_until_ms: root_valid,
                root_valid_until_formatted: formatted,
                created_at_ms: 0,
                locks_count: count,
                genesis_tag: genesis,
                status,
            });
        }
        results.sort_by(|a, b| b.root_valid_until_ms.cmp(&a.root_valid_until_ms));
        results
    }

    /// Returns detailed lineage and all lock hops for a voucher, resolving either by layer2_voucher_id or lookup_tag.
    pub async fn get_voucher_lineage(&self, voucher_id_or_tag: &str) -> Option<VoucherDetailDto> {
        let trimmed = voucher_id_or_tag.trim();
        if trimmed.is_empty() {
            return None;
        }

        // 0. Resolve voucher_id if a lookup_tag was provided
        let mut resolved_voucher_id = trimmed.to_string();
        {
            let hmc = self.hmc_ram.read().await;
            if let Some(entry) = hmc.locks.get(trimmed) {
                resolved_voucher_id = entry.layer2_voucher_id.clone();
            }
        }
        if resolved_voucher_id == trimmed {
            if let Ok(Some(entry)) = self.db.get_hmc_lock(trimmed) {
                resolved_voucher_id = entry.layer2_voucher_id;
            }
        }

        let voucher_id = &resolved_voucher_id;
        let mut locks_map: HashMap<String, L2LockEntry> = HashMap::new();

        // 1. Query redb
        if let Ok(db_locks) = self.db.get_hmc_locks_for_voucher(voucher_id) {
            for (tag, entry) in db_locks {
                locks_map.insert(tag, entry);
            }
        }

        // 2. Query RAM (overwrites with freshest live state)
        {
            let hmc = self.hmc_ram.read().await;
            if let Some(tags) = hmc.vouchers.get(voucher_id) {
                for tag in tags {
                    if let Some(entry) = hmc.locks.get(tag) {
                        locks_map.insert(tag.clone(), entry.clone());
                    }
                }
            }
        }

        if locks_map.is_empty() {
            return None;
        }

        let mut hops = Vec::new();
        let mut genesis_tag = None;
        let mut root_valid_until_ms = 0;
        let mut created_at_ms = 0;

        for (tag, entry) in locks_map {
            let is_genesis = entry.deletable_at.is_some();
            if is_genesis {
                genesis_tag = Some(tag.clone());
                if let Some(del) = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                    root_valid_until_ms = del;
                }
                created_at_ms = entry.encrypted_timestamp as u64;
            }

            let raw_json = serde_json::to_value(&entry).unwrap_or(serde_json::Value::Null);
            let receiver_pub_hex = entry.receiver_ephemeral_pub_hash.map(hex::encode);

            hops.push(VoucherLockHopDto {
                lookup_tag: tag,
                is_genesis,
                t_id_hex: hex::encode(entry.t_id),
                sender_pub_hex: hex::encode(entry.sender_ephemeral_pub),
                receiver_pub_hex,
                encrypted_timestamp: entry.encrypted_timestamp,
                deletable_at: entry.deletable_at,
                status: "Verified".to_string(),
                raw_json,
            });
        }

        // Sort hops: Genesis lock first, then chronological by encrypted_timestamp
        hops.sort_by(|a, b| {
            match (a.is_genesis, b.is_genesis) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.encrypted_timestamp.cmp(&b.encrypted_timestamp),
            }
        });

        if root_valid_until_ms == 0 {
            if let Some(r) = self.get_hmc_voucher_root_valid(voucher_id).await {
                root_valid_until_ms = r;
            }
        }

        let total_byte_years = (hops.len() as u64) * 144;
        let formatted = if root_valid_until_ms > 0 {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let rem_sec = root_valid_until_ms.saturating_sub(now_ms) / 1000;
            format!("{} ms (TTL: {}s)", root_valid_until_ms, rem_sec)
        } else {
            "Unknown".to_string()
        };

        Some(VoucherDetailDto {
            voucher_id: voucher_id.to_string(),
            root_valid_until_ms,
            root_valid_until_formatted: formatted,
            created_at_ms,
            genesis_tag,
            total_byte_years,
            locks: hops,
        })
    }

    /// Retrieves raw JSON data for any given lock lookup tag (RAM or Disk).
    pub async fn get_raw_lock_data(&self, lookup_tag: &str) -> Option<serde_json::Value> {
        // Check HMC RAM
        {
            let hmc = self.hmc_ram.read().await;
            if let Some(entry) = hmc.locks.get(lookup_tag) {
                return serde_json::to_value(entry).ok();
            }
        }
        // Check standard RAM
        if let Ok(bytes) = hex::decode(lookup_tag) {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let ram = self.ram.read().await;
                if let Some(rec) = ram.get(&arr) {
                    return serde_json::to_value(rec).ok();
                }
            }
        }
        // Check redb HMC locks
        if let Ok(Some(entry)) = self.db.get_hmc_lock(lookup_tag) {
            return serde_json::to_value(&entry).ok();
        }
        None
    }

    /// Flush worker loop: batches incoming ops (`FLUSH_BATCH_SIZE` / `FLUSH_INTERVAL_MS`)
    /// and commits each batch atomically in strict FIFO order (Spec 12/14, Phase 7 P1).
    ///
    /// Hardening invariants:
    /// - No untracked `tokio::spawn` jobs: every `spawn_blocking` commit is awaited
    ///   inline, so at most one batch is in flight (bounded) and commit order is strict.
    /// - Graceful-shutdown drain: on `cancel_token` the worker keeps draining `rx`
    ///   (including ops arriving during the drain) and awaits every commit before
    ///   returning, so `daemon.rs` (`flush_handle.await`) closes redb only after the
    ///   queue is empty. Never holds `RamIndex` locks across I/O (Rule 1).
    pub fn spawn_flush_worker(
        mut rx: mpsc::Receiver<FlushOp>,
        db: Arc<RedbStorage>,
        stats: Arc<PersistenceStats>,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut batch: Vec<FlushOp> = Vec::with_capacity(FLUSH_BATCH_SIZE);
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(FLUSH_INTERVAL_MS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        Self::drain_on_shutdown(&mut rx, &mut batch, &db, &stats).await;
                        info!("Flush worker cleanly drained and terminated on cancellation");
                        break;
                    }
                    op = rx.recv() => {
                        match op {
                            Some(op) => {
                                batch.push(op);
                                if batch.len() >= FLUSH_BATCH_SIZE {
                                    let to_flush = std::mem::replace(&mut batch, Vec::with_capacity(FLUSH_BATCH_SIZE));
                                    Self::commit_batch(to_flush, &db, &stats).await;
                                }
                            }
                            None => {
                                // All senders dropped: flush remainder synchronously, then exit.
                                if !batch.is_empty() {
                                    let to_flush = std::mem::replace(&mut batch, Vec::with_capacity(FLUSH_BATCH_SIZE));
                                    Self::commit_batch(to_flush, &db, &stats).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let to_flush = std::mem::replace(&mut batch, Vec::with_capacity(FLUSH_BATCH_SIZE));
                            Self::commit_batch(to_flush, &db, &stats).await;
                        }
                    }
                }
            }
        })
    }

    /// Commits one batch inline (awaited): exactly one in-flight batch, strict order.
    /// Updates INV-1701 telemetry; failures are counted, never silent.
    async fn commit_batch(
        mut to_flush: Vec<FlushOp>,
        db: &Arc<RedbStorage>,
        stats: &Arc<PersistenceStats>,
    ) {
        if to_flush.is_empty() {
            return;
        }
        let op_count = to_flush.len();
        let db_clone = Arc::clone(db);
        let outcome = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await;
        match outcome {
            Ok(o) => {
                stats.flush_batches_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats.flush_ops_total.fetch_add(op_count as u64, std::sync::atomic::Ordering::Relaxed);
                if o.failed {
                    stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    error!(
                        ops = op_count,
                        attempts = o.attempts,
                        "Flush batch failed after structured retries (errors counted, RAM remains authoritative)"
                    );
                } else {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    stats.last_successful_flush_ms.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Err(e) => {
                stats.flush_batches_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                error!("flush_batch blocking task panicked/cancelled: {:?} ({} ops uncommitted, RAM authoritative)", e, op_count);
            }
        }
    }

    /// Graceful-shutdown drain: commits the pending batch plus everything still
    /// arriving on `rx` (bounded by `MAX_SHUTDOWN_DRAIN_BATCHES`), awaiting each
    /// commit inline so no in-flight batch is lost before redb is closed.
    async fn drain_on_shutdown(
        rx: &mut mpsc::Receiver<FlushOp>,
        batch: &mut Vec<FlushOp>,
        db: &Arc<RedbStorage>,
        stats: &Arc<PersistenceStats>,
    ) {
        let mut drained_batches = 0usize;
        // First: everything already queued.
        while let Ok(op) = rx.try_recv() {
            batch.push(op);
            if batch.len() >= FLUSH_BATCH_SIZE {
                let to_flush = std::mem::replace(batch, Vec::with_capacity(FLUSH_BATCH_SIZE));
                Self::commit_batch(to_flush, db, stats).await;
                drained_batches += 1;
                if drained_batches >= MAX_SHUTDOWN_DRAIN_BATCHES {
                    break;
                }
            }
        }
        if !batch.is_empty() {
            let to_flush = std::mem::replace(batch, Vec::with_capacity(FLUSH_BATCH_SIZE));
            Self::commit_batch(to_flush, db, stats).await;
            drained_batches += 1;
        }
        // Second: ops that arrived while the drain commits were running.
        while drained_batches < MAX_SHUTDOWN_DRAIN_BATCHES {
            let mut newly_arrived = false;
            while let Ok(op) = rx.try_recv() {
                batch.push(op);
                newly_arrived = true;
                if batch.len() >= FLUSH_BATCH_SIZE {
                    break;
                }
            }
            if !newly_arrived && batch.is_empty() {
                break;
            }
            if !batch.is_empty() {
                let to_flush = std::mem::replace(batch, Vec::with_capacity(FLUSH_BATCH_SIZE));
                Self::commit_batch(to_flush, db, stats).await;
                drained_batches += 1;
            } else {
                break;
            }
        }
        if drained_batches >= MAX_SHUTDOWN_DRAIN_BATCHES {
            warn!("Shutdown drain hit batch cap; remainder stays RAM-authoritative and counted via flush_errors_total");
            stats.flush_errors_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Executes one batch of flush operations as a single atomic redb commit with
    /// structured retry (Spec 12/14 Dual-Tier Ordnung, Phase 7 P1).
    ///
    /// Runs on a `spawn_blocking` thread: pre-serializes all payloads before opening
    /// the write transaction, resolves HMC voucher roots (batch-local first, then a
    /// bounded disk lookup), and commits locks + HMC + evidence + quota + bans via
    /// one `apply_flush_batch_atomic` call. Transient commit failures are retried up
    /// to `MAX_FLUSH_RETRIES` with linear backoff; serialization defects are permanent
    /// and counted without retry. Never touches `RamIndex` (Rule 1: no hot-path I/O).
    pub fn flush_batch(batch: &mut Vec<FlushOp>, db: &RedbStorage) -> FlushOutcome {
        if batch.is_empty() {
            return FlushOutcome { ops_committed: 0, attempts: 0, failed: false };
        }
        let ops_committed = batch.len();

        // Categorize (drains the input vector exactly once, preserving FIFO within type).
        let mut locks: Vec<(LockRecord, u64)> = Vec::new();
        let mut hmc: Vec<(String, Box<L2LockEntry>)> = Vec::new();
        let mut evidences: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let mut quotas: Vec<([u8; 32], u64)> = Vec::new();
        let mut bans: Vec<([u8; 32], u64)> = Vec::new();
        let mut prunes: Vec<u64> = Vec::new();
        for op in batch.drain(..) {
            match op {
                FlushOp::PutLock { lock, root_valid_until } => locks.push((lock, root_valid_until)),
                FlushOp::PutHmcLock { lookup_tag, entry } => hmc.push((lookup_tag, entry)),
                FlushOp::PutEvidence { hash, raw } => evidences.push((hash, raw)),
                FlushOp::SetQuota { account_tag, byte_years } => quotas.push((account_tag, byte_years)),
                FlushOp::BanNode { node_key, timestamp_ms } => bans.push((node_key, timestamp_ms)),
                FlushOp::Prune { now_sec } => prunes.push(now_sec),
            }
        }

        // Pre-serialize locks (permanent per-op errors counted, never retried as a batch).
        let mut lock_rows: Vec<(LockRecord, u64, Vec<u8>)> = Vec::with_capacity(locks.len());
        let mut permanent_errors = 0u32;
        for (lock, root) in &locks {
            match bincode::serialize(&(lock, root)) {
                Ok(bytes) => lock_rows.push((lock.clone(), *root, bytes)),
                Err(e) => {
                    permanent_errors += 1;
                    error!("Dropping unserializable LockRecord (permanent): {}", e);
                }
            }
        }

        // Pre-serialize HMC entries + resolve voucher roots.
        let mut batch_roots: HashMap<String, u64> = HashMap::new();
        for (_, entry) in &hmc {
            if let Some(v) = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                batch_roots.entry(entry.layer2_voucher_id.clone()).or_insert(v);
            }
        }
        // Keep owned HMC payloads alive across the retry loop.
        let mut hmc_owned: Vec<(String, Box<L2LockEntry>, Vec<u8>, u64)> = Vec::with_capacity(hmc.len());
        for (tag, entry) in &hmc {
            let bytes = match serde_json::to_vec(entry.as_ref()) {
                Ok(b) => b,
                Err(e) => {
                    permanent_errors += 1;
                    error!("Dropping unserializable HMC lock {} (permanent): {}", tag, e);
                    continue;
                }
            };
            let valid_until_ms = match entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                Some(v) => v,
                None => {
                    if let Some(v) = batch_roots.get(&entry.layer2_voucher_id) {
                        *v
                    } else if let Some(root) = Self::lookup_voucher_root(db, &entry.layer2_voucher_id) {
                        batch_roots.insert(entry.layer2_voucher_id.clone(), root);
                        root
                    } else {
                        0
                    }
                }
            };
            hmc_owned.push((tag.clone(), entry.clone(), bytes, valid_until_ms));
        }

        // Borrowed views into the owned rows (built once, reused across retries).
        let lock_view: Vec<(&LockRecord, u64, &[u8])> = lock_rows
            .iter()
            .map(|(l, r, b)| (l, *r, b.as_slice()))
            .collect();
        let hmc_view: Vec<(&str, &L2LockEntry, &[u8], u64)> = hmc_owned
            .iter()
            .map(|(t, e, b, v)| (t.as_str(), e.as_ref(), b.as_slice(), *v))
            .collect();

        // Structured retry on the single atomic commit (transient redb errors only).
        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
            let res = db.apply_flush_batch_atomic(
                &lock_view,
                &hmc_view,
                &evidences,
                &quotas,
                &bans,
                &prunes,
            );
            match res {
                Ok(()) => {
                    if permanent_errors > 0 {
                        error!("Flush batch committed with {} permanent serialization drops (counted)", permanent_errors);
                    }
                    return FlushOutcome { ops_committed, attempts, failed: permanent_errors > 0 };
                }
                Err(e) => {
                    if attempts >= MAX_FLUSH_RETRIES {
                        error!("Flush batch commit failed after {} attempts: {} ({} ops uncommitted)", attempts, e, ops_committed);
                        return FlushOutcome { ops_committed, attempts, failed: true };
                    }
                    warn!("Flush batch commit attempt {}/{} failed: {} — retrying", attempts, MAX_FLUSH_RETRIES, e);
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_BACKOFF_MS * attempts as u64));
                }
            }
        }
    }

    /// Bounded disk lookup for an HMC voucher root (blocking worker thread only,
    /// never on the hot path). Returns `None` when the voucher is unknown.
    fn lookup_voucher_root(db: &RedbStorage, voucher_id: &str) -> Option<u64> {
        match db.get_hmc_locks_for_voucher(voucher_id) {
            Ok(locks) => locks.iter().find_map(|(_, entry)| {
                entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok())
            }),
            Err(e) => {
                warn!("Voucher root lookup failed for {}: {}", voucher_id, e);
                None
            }
        }
    }

    /// Cold-start recovery: Scans unexpired locks from disk and re-populates both RAM indices.
    ///
    /// # Architectural Invariant: INV-1404 Dual-Tier Cold-Start Recovery
    ///
    /// Two-stage HMC recovery: (1) genesis roots first so `voucher_roots` is
    /// anchored, (2) follow-up locks inherit TTL from the known root. Follow-ups
    /// are never inserted with TTL 0 and never poison roots with 0. Raw disk
    /// read (`read_all_hmc_locks`) is used so follow-ups without own TTL are
    /// not pre-filtered as expired before their root is known.
    pub async fn recover_from_disk(&self, now: SimTime) -> Result<usize, StorageError> {
        let locks = self.db.all_valid_locks(now.0)?;
        let count = locks.len();
        let mut ram = self.ram.write().await;
        for (lock, root_valid_until) in locks {
            ram.insert_recovered(lock, SimTime(root_valid_until));
        }

        let hmc_locks = self.db.read_all_hmc_locks()?;
        // Stage 1: genesis roots (own deletable_at) first.
        // Stage 2: follow-ups inherit from the anchored roots.
        let mut genesis: Vec<(String, L2LockEntry)> = Vec::new();
        let mut followups: Vec<(String, L2LockEntry)> = Vec::new();
        for (tag, entry) in hmc_locks {
            if entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()).is_some() {
                genesis.push((tag, entry));
            } else {
                followups.push((tag, entry));
            }
        }
        // Precompute roots (including expired ones) so follow-ups inherit the
        // same TTL their genesis carries; expiry is then evaluated uniformly.
        let mut root_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for (_, e) in genesis.iter().chain(followups.iter()) {
            if let Some(v) = e.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                root_map.entry(e.layer2_voucher_id.clone()).or_insert(v);
            }
        }
        let mut hmc_ram = self.hmc_ram.write().await;
        for (tag, entry) in genesis.into_iter().chain(followups) {
            // Expiry filter at recovery time `now`: entries with known
            // (owned or inherited) TTL that already exceed grace are skipped.
            // Orphans with unknown root are retained (expiry unprovable,
            // never TTL-0-dropped); `insert_recovered` defers them until the
            // root arrives.
            let owned = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok());
            let effective = owned.or_else(|| root_map.get(&entry.layer2_voucher_id).copied());
            if let Some(v) = effective {
                if should_prune(now, SimTime(v)) {
                    continue;
                }
            }
            hmc_ram.insert_recovered(tag, entry);
        }

        Ok(count)
    }

    /// Pruning: Evicts expired entries from RAM indices and persistent disk indexes.
    /// Entkoppelt RAM-Pruning (< 10µs) vom synchronen Disk-I/O (Spec 19 / AGENTS.md Regel 1).
    /// Resilience hardening: rejects forward jumps >24h (86_400_000 ms) on local NTP warp
    /// unless corroborated by F2F network median, to prevent accidental mass purge.
    pub async fn prune_expired(&self, now: SimTime) -> Result<usize, StorageError> {
        let last_anchor = self.last_prune_anchor.load(std::sync::atomic::Ordering::Relaxed);
        if last_anchor > 0 {
            let jump = now.0.saturating_sub(last_anchor);
            if jump > 86_400_000 {
                let corroborated = if let Some(pm) = self.peer_manager.read().await.as_ref() {
                    pm.clock().is_time_corroborated(jump)
                } else {
                    false
                };
                if !corroborated {
                    warn!(
                        now_ms = now.0,
                        last_prune_anchor = last_anchor,
                        jump_ms = jump,
                        "Prune rejected: forward clock jump >24h (86_400_000 ms) not corroborated by F2F network median (NTP warp protection)"
                    );
                    return Ok(0);
                }
            }
        }

        let ram_pruned = {
            let mut ram = self.ram.write().await;
            ram.prune_expired(now)
        };

        let hmc_pruned = {
            let mut hmc_ram = self.hmc_ram.write().await;
            hmc_ram.prune_expired(now)
        };

        let (disk_pruned, disk_hmc_pruned) = self.db.prune_expired_buckets(now.0 / 1_000)?;
        self.last_prune_anchor.store(now.0, std::sync::atomic::Ordering::Relaxed);
        Ok(ram_pruned + hmc_pruned + disk_pruned.len() + disk_hmc_pruned)
    }
}
