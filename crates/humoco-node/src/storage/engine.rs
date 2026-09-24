use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use humoco_sim_core::storage::{ingress_time_window_valid, should_prune, IngressVerdictLow, RamIndex};
use humoco_sim_core::types::{LockRecord, SimTime};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, warn};

use super::db::{RedbStorage, StorageError};
use crate::api::hmc::{L2LockEntry, L2Verdict};
use crate::storage::filter::SpentLockFilter;
use crate::storage::recent::{
    LockInspection, RecentLockBuffer, RecentLockStatus, RecentLockSummary,
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
        let valid_until_ms = match entry
            .deletable_at
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .or(root_valid)
        {
            Some(v) => v,
            None => {
                return (
                    L2Verdict::Rejected {
                        reason: "Missing deletable_at and unknown voucher root".into(),
                    },
                    false,
                );
            }
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
                    self.voucher_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);

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
            self.voucher_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);

            self.vouchers
                .entry(entry.layer2_voucher_id.clone())
                .or_default()
                .insert(lookup_tag.clone());
            self.locks.insert(lookup_tag.clone(), entry.clone());
            self.filter.add(&lookup_tag);
            (L2Verdict::Verified { lock_entry: entry }, true)
        }
    }

    pub fn get_voucher_root_valid(&self, voucher_id: &str) -> Option<u64> {
        self.voucher_roots.get(voucher_id).copied()
    }

    /// Prune expired HMC locks where now > valid_until + 30s grace (INV-1203).
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
                for tag in tags {
                    if let Some(vu) = self.valid_until.get(&tag) {
                        if should_prune(now, SimTime(*vu)) {
                            if let Some(entry) = self.locks.remove(&tag) {
                                if let Some(vtags) = self.vouchers.get_mut(&entry.layer2_voucher_id) {
                                    vtags.remove(&tag);
                                    if vtags.is_empty() {
                                        self.vouchers.remove(&entry.layer2_voucher_id);
                                    }
                                }
                            }
                            self.valid_until.remove(&tag);
                            self.filter.delete(&tag);
                        }
                    }
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
        for tag in voucher_tags {
            if let Some(entry) = self.locks.get(tag) {
                if bs58::encode(&entry.t_id).into_string() == challenge_ds_tag {
                    return L2Verdict::Verified { lock_entry: entry.clone() };
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

#[derive(Clone)]
pub struct DualTierEngine {
    pub ram: Arc<RwLock<RamIndex>>,
    pub hmc_ram: Arc<RwLock<HmcRamIndex>>,
    pub banned_nodes: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub db: Arc<RedbStorage>,
    pub tx: mpsc::Sender<FlushOp>,
    pub peer_manager: Arc<RwLock<Option<Arc<crate::network::PeerManager>>>>,
    pub recent_locks: Arc<parking_lot::RwLock<RecentLockBuffer>>,
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

        let handle = Self::spawn_flush_worker(rx, Arc::clone(&db), cancel_token);
        (
            Self {
                ram,
                hmc_ram,
                banned_nodes,
                db,
                tx,
                peer_manager: Arc::new(RwLock::new(None)),
                recent_locks,
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
        Self {
            ram,
            hmc_ram,
            banned_nodes,
            db,
            tx,
            peer_manager: Arc::new(RwLock::new(None)),
            recent_locks,
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
    pub async fn ban_node(&self, node_key: [u8; 32], timestamp_ms: u64) {
        self.banned_nodes.write().await.insert(node_key);
        if let Some(pm) = self.peer_manager.read().await.as_ref() {
            pm.ban_node(&node_key).await;
        }
        match self.tx.try_send(FlushOp::BanNode { node_key, timestamp_ms }) {
            Ok(_) => {},
            Err(tokio::sync::mpsc::error::TrySendError::Full(op)) => {
                warn!("Persistence queue full: BanNode persisted to RAM immediately, queuing disk flush in background");
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(1), tx.send(op)).await {
                        Ok(Ok(_)) => {},
                        Ok(Err(e)) => {
                            warn!("Async background flush for BanNode failed: {}", e);
                        }
                        Err(_) => {
                            warn!("Async background flush for BanNode timed out after 1s (queue congested)");
                        }
                    }
                });
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                warn!("Persistence worker closed: BanNode active in RAM only");
            }
        }
    }

    /// Processes an incoming EquivocationProof: verifies proof, commits raw evidence to redb, and bans the offender.
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
        let _ = self.db.put_evidence(&evidence_hash, raw_payload);
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
    /// On double-signing (same sender on colliding tag), evidence is persisted in redb and the offender is banned.
    pub async fn ingress_hmc_lock_with_origin(
        &self,
        lookup_tag: String,
        entry: L2LockEntry,
        origin: IngressOrigin,
        now_ms: Option<u64>,
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
                let _ = self.db.put_evidence(&evidence_hash, &raw_evidence);
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
        {
            let mut recent = self.recent_locks.write();
            recent.push(RecentLockSummary {
                parent_lock_hex: lookup_tag,
                child_lock_hex: hex::encode(entry.t_id),
                timestamp_ms: now_ms,
                status: recent_status,
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
        // Vorgabe: Empty chain rejection
        if chain_req.chain.is_empty() {
            return (
                L2Verdict::Rejected {
                    reason: "Empty chain: at least one lock required".into(),
                },
                false,
            );
        }
        // Voucher consistency check
        for hop in &chain_req.chain {
            if hop.layer2_voucher_id != chain_req.layer2_voucher_id {
                return (
                    L2Verdict::Rejected {
                        reason: format!(
                            "Voucher mismatch in chain: expected {}, got {}",
                            chain_req.layer2_voucher_id, hop.layer2_voucher_id
                        ),
                    },
                    false,
                );
            }
        }
        // Stateless signature verification and basic field checks (cheap checks first)
        for hop in &chain_req.chain {
            if !crate::api::hmc::verify_l2_lock_signature(hop) {
                return (
                    L2Verdict::Rejected {
                        reason: "Invalid cryptographic signature in chain".into(),
                    },
                    false,
                );
            }
            if !hop.is_genesis {
                match &hop.ds_tag {
                    Some(t) if !t.trim().is_empty() => {},
                    _ => {
                        return (
                            L2Verdict::Rejected {
                                reason: "Missing or empty ds_tag for non-genesis spend".into(),
                            },
                            false,
                        )
                    }
                }
            } else if hop.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()).is_none() {
                return (
                    L2Verdict::Rejected {
                        reason: "Genesis lock requires valid deletable_at timestamp".into(),
                    },
                    false,
                );
            }
        }
        // Timestamp monotonicity (strictly increasing)
        for i in 1..chain_req.chain.len() {
            let prev = chain_req.chain[i - 1].encrypted_timestamp;
            let cur = chain_req.chain[i].encrypted_timestamp;
            if cur <= prev {
                return (
                    L2Verdict::Rejected {
                        reason: format!(
                            "Timestamp monotonicity violated at hop {}: {} <= {}",
                            i, cur, prev
                        ),
                    },
                    false,
                );
            }
        }

        // Atomic collision check + insertion under single write lock
        // We do reservation-first after determining which hops are truly new.
        let (verdict, is_new, _ops_to_flush) = {
            let mut hmc = self.hmc_ram.write().await;

            // First pass: gather lookup_tags and detect collisions / idempotent replays
            use std::collections::HashMap;
            let mut seen_in_batch: HashMap<String, [u8; 32]> = HashMap::new();
            let mut new_entries: Vec<(String, L2LockEntry)> = Vec::new();
            let mut terminal_entry_opt: Option<L2LockEntry> = None;
            let mut conflict_entry: Option<L2LockEntry> = None;

            for hop in &chain_req.chain {
                let lookup_tag = if hop.is_genesis {
                    bs58::encode(&hop.transaction_hash).into_string()
                } else {
                    hop.ds_tag.clone().unwrap()
                };

                let entry = L2LockEntry::from(hop);

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
                                .find(|(t, _)| t == &lookup_tag)
                                .map(|(_, e)| e.clone())
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
                new_entries.push((lookup_tag.clone(), entry.clone()));
                terminal_entry_opt = Some(entry);
            }

            if let Some(existing) = conflict_entry {
                // Rollback: zero state changes
                (L2Verdict::Conflict { existing_lock: existing }, false, Vec::<FlushOp>::new())
            } else {
                // No collisions – validate ingress window & voucher roots for new entries before mutation
                // Determine if any new entry would fail due to unknown root or window violation
                // We need to simulate sequential insertion to handle chain-local genesis root
                let mut temp_roots = hmc.voucher_roots.clone();
                let mut window_violation: Option<String> = None;
                for (_tag, entry) in &new_entries {
                    let root_valid = temp_roots.get(&entry.layer2_voucher_id).copied();
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
                    // Update temp_roots for subsequent hops in same chain
                    temp_roots.entry(entry.layer2_voucher_id.clone()).or_insert(valid_until_ms);
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
                        for (permit, (tag, entry)) in permits.into_iter().zip(new_entries.into_iter()) {
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
                            hmc.voucher_roots
                                .entry(entry.layer2_voucher_id.clone())
                                .or_insert(valid_until_ms);
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
            self.recent_locks.write().push(RecentLockSummary {
                parent_lock_hex: tag,
                child_lock_hex: hex::encode(lock_entry.t_id),
                timestamp_ms: now,
                status: recent_status,
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

    /// Flush worker loop: Batches incoming flush operations with 50ms timeout or batch size of 100.
    /// On cancellation signal (cancel_token), the queue is fully drained and committed atomically.
    pub fn spawn_flush_worker(
        mut rx: mpsc::Receiver<FlushOp>,
        db: Arc<RedbStorage>,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(100);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(50));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        // Node is shutting down: drain any pending ops from rx and flush!
                        while let Ok(op) = rx.try_recv() {
                            batch.push(op);
                            if batch.len() >= 100 {
                                let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                let db_clone = Arc::clone(&db);
                                if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
                                    error!("flush_batch panicked during shutdown drain: {:?}", e);
                                }
                            }
                        }
                        if !batch.is_empty() {
                            let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                            let db_clone = Arc::clone(&db);
                            if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
                                error!("flush_batch panicked during shutdown final flush: {:?}", e);
                            }
                        }
                        tracing::info!("Flush worker cleanly drained and terminated on cancellation");
                        break;
                    }
                    op = rx.recv() => {
                        match op {
                            Some(op) => {
                                batch.push(op);
                                if batch.len() >= 100 {
                                    let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                    let db_clone = Arc::clone(&db);
                                    if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
                                        error!("flush_batch panicked: {:?}", e);
                                    }
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                    let db_clone = Arc::clone(&db);
                                    if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
                                        error!("flush_batch panicked on channel close: {:?}", e);
                                    }
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                            let db_clone = Arc::clone(&db);
                            if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
                                error!("flush_batch panicked on interval flush: {:?}", e);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Executes a batch of flush operations on the database.
    pub fn flush_batch(batch: &mut Vec<FlushOp>, db: &RedbStorage) {
        if batch.is_empty() {
            return;
        }

        let mut locks_to_put = Vec::new();
        for op in batch.drain(..) {
            match op {
                FlushOp::PutLock { lock, root_valid_until } => {
                    locks_to_put.push((lock, root_valid_until));
                }
                FlushOp::PutHmcLock { lookup_tag, entry } => {
                    if let Err(e) = db.put_hmc_lock(&lookup_tag, &entry) {
                        error!("Failed to put HMC lock to redb: {}", e);
                    }
                }
                FlushOp::Prune { now_sec } => {
                    if let Err(e) = db.prune_expired_buckets(now_sec) {
                        error!("Failed to prune expired buckets in flush worker: {}", e);
                    }
                }
                FlushOp::PutEvidence { hash, raw } => {
                    if let Err(e) = db.put_evidence(&hash, &raw) {
                        error!("Failed to put evidence in flush worker: {}", e);
                    }
                }
                FlushOp::SetQuota { account_tag, byte_years } => {
                    if let Err(e) = db.set_quota(&account_tag, byte_years) {
                        error!("Failed to set quota in flush worker: {}", e);
                    }
                }
                FlushOp::BanNode { node_key, timestamp_ms } => {
                    if let Err(e) = db.ban_node(&node_key, timestamp_ms) {
                        error!("Failed to persist banned node to redb: {}", e);
                    }
                }
            }
        }

        if !locks_to_put.is_empty() {
            let items: Vec<(&LockRecord, u64)> = locks_to_put.iter().map(|(l, r)| (l, *r)).collect();
            if let Err(e) = db.put_locks_batch(items) {
                error!("Failed to batch put locks to redb: {}", e);
            }
        }
    }

    /// Cold-start recovery: Scans unexpired locks from disk and re-populates both RAM indices.
    pub async fn recover_from_disk(&self, now: SimTime) -> Result<usize, StorageError> {
        let locks = self.db.all_valid_locks(now.0)?;
        let count = locks.len();
        let mut ram = self.ram.write().await;
        for (lock, root_valid_until) in locks {
            ram.insert_recovered(lock, SimTime(root_valid_until));
        }

        let hmc_locks = self.db.all_valid_hmc_locks(now.0)?;
        let mut hmc_ram = self.hmc_ram.write().await;
        for (tag, entry) in hmc_locks {
            hmc_ram.insert_or_check(tag, entry, IngressOrigin::PartitionSync, None);
        }

        Ok(count)
    }

    /// Pruning: Evicts expired entries from RAM indices and persistent disk indexes.
    /// Entkoppelt RAM-Pruning (< 10µs) vom synchronen Disk-I/O (Spec 19 / AGENTS.md Regel 1).
    /// Resilience hardening: rejects forward jumps >24h (86_400_000 ms) on local NTP warp
    /// unless corroborated by F2F network median, to prevent accidental mass purge.
    pub async fn prune_expired(&self, now: SimTime) -> Result<usize, StorageError> {
        if let Some(pm) = self.peer_manager.read().await.as_ref() {
            let last = pm.clock().last_net_time_ms();
            if last > 0 {
                let jump = now.0.saturating_sub(last);
                if jump > 86_400_000 {
                    let corroborated = pm
                        .clock()
                        .current_median_offset()
                        .map(|median| {
                            let median_abs = median.unsigned_abs();
                            // Network median is clamped to 15 min (900_000 ms); a 24h jump can never be corroborated
                            // by median alone. This strict check ensures only an explicit large median would allow it.
                            median_abs >= 86_400_000 || median_abs >= jump.saturating_sub(900_000)
                        })
                        .unwrap_or(false);
                    if !corroborated {
                        warn!(
                            now_ms = now.0,
                            last_net_time = last,
                            jump_ms = jump,
                            "Prune rejected: forward clock jump >24h (86_400_000 ms) not corroborated by F2F network median (NTP warp protection)"
                        );
                        return Ok(0);
                    }
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
        Ok(ram_pruned + hmc_pruned + disk_pruned.len() + disk_hmc_pruned)
    }
}
