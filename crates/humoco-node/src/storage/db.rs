pub mod install;
pub mod projection;
pub mod roots;
mod signing;
pub use signing::TABLE_SIGNING_STATE;
pub mod snapshot;
pub mod support;

use humoco_sim_core::storage::should_prune;
use humoco_sim_core::types::SimTime;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

/// Canonical grace horizon ceiling bucket formula (A22-R1):
/// Converts a millisecond expiry horizon to an integer second bucket with ceiling rounding,
/// ensuring that records are never prematurely expired before their full +30s grace window passes.
#[inline(always)]
pub const fn grace_expiry_bucket_sec(root_valid_until_ms: u64) -> u64 {
    (root_valid_until_ms.saturating_add(30_000) / 1_000).saturating_add(1)
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("FAIL_CLOSED_CORRUPT: signing history integrity unavailable")]
    SigningHistoryCorrupt,
    #[error("Unsupported database schema version: {found} (supported: {supported})")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("Invalid backup destination: {0}")]
    InvalidBackupDestination(String),
    #[error("Redb database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("Redb transaction error: {0}")]
    Transaction(Box<redb::TransactionError>),

    #[error("Redb table error: {0}")]
    Table(Box<redb::TableError>),

    #[error("Redb commit error: {0}")]
    Commit(Box<redb::CommitError>),

    #[error("Redb compaction error: {0}")]
    Compaction(Box<redb::CompactionError>),

    #[error("Redb storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("Bincode serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    #[error("Quota exceeded: required {required} byte-years, available {available}")]
    QuotaExceeded { available: u64, required: u64 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Own signing decision conflicts with retained history")]
    OwnChoiceConflict,

    #[error("Durable commit failed: {0}")]
    DurableCommitFailed(String),
}

impl From<redb::TransactionError> for StorageError {
    fn from(err: redb::TransactionError) -> Self {
        StorageError::Transaction(Box::new(err))
    }
}

impl From<redb::TableError> for StorageError {
    fn from(err: redb::TableError) -> Self {
        StorageError::Table(Box::new(err))
    }
}

impl From<redb::CommitError> for StorageError {
    fn from(err: redb::CommitError) -> Self {
        StorageError::Commit(Box::new(err))
    }
}

impl From<redb::CompactionError> for StorageError {
    fn from(err: redb::CompactionError) -> Self {
        StorageError::Compaction(Box::new(err))
    }
}

pub const TABLE_SCHEMA_METADATA: TableDefinition<&str, u32> =
    TableDefinition::new("schema_metadata");
pub const CURRENT_DB_SCHEMA_VERSION: u32 = 1;

pub const MAX_SYNC_TAG_BYTES: usize = 128;
pub const MAX_SYNC_ROW_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_SYNC_LOCKS: usize = 10_000;
pub const DEFAULT_MAX_SYNC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;


pub(crate) fn validate_sync_shape(
    tag: &str,
    entry: &crate::api::hmc::L2LockEntry,
) -> Result<(), StorageError> {
    if tag.len() > MAX_SYNC_TAG_BYTES || serde_json::to_vec(entry)?.len() > MAX_SYNC_ROW_BYTES {
        return Err(StorageError::DurableCommitFailed(
            "HMC entry exceeds synchronization limits".into(),
        ));
    }
    Ok(())
}

pub const TABLE_PROVISIONAL_HMC_LOCKS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("provisional_hmc_locks");
pub const TABLE_PROVISIONAL_HMC_VOUCHER_INDEX: TableDefinition<(&str, &str), ()> =
    TableDefinition::new("prov_hmc_voucher_index");
pub const TABLE_SLASHING_EVIDENCE: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("slashing_evidence");
pub const TABLE_QUOTA_ACCOUNTS: TableDefinition<&[u8; 32], u64> =
    TableDefinition::new("quota_accounts");
pub const TABLE_HMC_LOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("hmc_locks");
pub const TABLE_HMC_VOUCHER_INDEX: TableDefinition<(&str, &str), ()> =
    TableDefinition::new("hmc_voucher_index");
pub const TABLE_HMC_TTL_INDEX: TableDefinition<(u64, &str), ()> =
    TableDefinition::new("hmc_ttl_index");
pub const TABLE_BANNED_NODES: TableDefinition<&[u8; 32], u64> =
    TableDefinition::new("banned_nodes");
pub const TABLE_SYSTEM_AUDIT_EVENTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("system_audit_events");
pub const TABLE_TICKET_OBSERVATIONS: TableDefinition<&[u8; 64], u64> =
    TableDefinition::new("ticket_observations");

/// Node-local original signing protection. Never included in shard synchronization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OwnSigningChoice {
    #[serde(default)]
    pub generation: u64,
    pub child: [u8; 32],
    pub valid_until_ms: u64,
    /// First exact original approval in each binary confirmation class.
    pub approvals: [Option<Vec<u8>>; 2],
}

pub const TABLE_OWN_CHOICES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("own_signing_choices");
pub const TABLE_OWN_CHOICE_COMMITMENTS: TableDefinition<&str, &[u8; 32]> =
    TableDefinition::new("own_choice_commitments");
pub const TABLE_OWN_CHOICE_TTL: TableDefinition<(u64, &str), ()> =
    TableDefinition::new("own_signing_choice_ttl");

/// Target specification for an original approval within an atomic group commit (A05-02).
#[derive(Clone, Debug)]
pub enum OriginalApprovalTarget {
    Hmc {
        tag: String,
        entry: Box<crate::api::hmc::L2LockEntry>,
    },
}

/// An individual approval entry submitted as part of a group-commit batch (A05-02).
#[derive(Clone, Debug)]
pub struct OriginalApprovalBatchEntry {
    pub target: OriginalApprovalTarget,
    pub node: [u8; 32],
    pub approval: Vec<u8>,
    pub class: u8,
    pub root_valid_until_ms: u64,
}

#[derive(Clone)]
pub struct RedbStorage {
    db: Arc<Database>,
    path: std::path::PathBuf,
    signing_corrupt: Arc<std::sync::atomic::AtomicBool>,
}

impl RedbStorage {
    /// Opens or creates a new redb database at the specified path and ensures all tables exist.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let db = if path.exists() {
            Database::open(path)?
        } else {
            Database::create(path)?
        };

        Self::initialize_database(db, path)
    }

    /// Atomically reserves a NEW database for an explicit regional bootstrap.
    /// Existing paths, including interrupted empty files, are never reopened here.
    pub fn create_new_region(path: &Path) -> Result<Self, StorageError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        let db = Database::builder().create_file(file)?;
        Self::initialize_database(db, path)
    }

    #[doc(hidden)]
    pub fn open_with_backend(
        backend: impl redb::StorageBackend,
        path: &Path,
    ) -> Result<Self, StorageError> {
        let db = Database::builder().create_with_backend(backend)?;
        Self::initialize_database(db, path)
    }

    fn initialize_database(db: Database, path: &Path) -> Result<Self, StorageError> {
        // Initialize tables in a write transaction
        let write_txn = db.begin_write()?;
        {
            let mut schema_table = write_txn.open_table(TABLE_SCHEMA_METADATA)?;
            let existing_version = schema_table.get("schema_version")?.map(|g| g.value());
            match existing_version {
                Some(v) => {
                    if v > CURRENT_DB_SCHEMA_VERSION {
                        return Err(StorageError::UnsupportedSchemaVersion {
                            found: v,
                            supported: CURRENT_DB_SCHEMA_VERSION,
                        });
                    }
                }
                None => {
                    schema_table.insert("schema_version", CURRENT_DB_SCHEMA_VERSION)?;
                }
            }
        }
        {
            let _ = write_txn.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
            let _ = write_txn.open_table(TABLE_OWN_CHOICES)?;
            let _ = write_txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
            let _ = write_txn.open_table(TABLE_OWN_CHOICE_TTL)?;
            let _ = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let _ = write_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
            let _ = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            let _ = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            let _ = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let _ = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let _ = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let _ = write_txn.open_table(TABLE_BANNED_NODES)?;
            let _ = write_txn.open_table(TABLE_SYSTEM_AUDIT_EVENTS)?;
            let _ = write_txn.open_table(TABLE_TICKET_OBSERVATIONS)?;
        }
        roots::initialize(&write_txn)?;
        let corrupt = signing::initialize(&write_txn)?;
        write_txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
            path: path.to_path_buf(),
            signing_corrupt: signing::latch(corrupt),
        })
    }

    /// Commits a batch of compatible original approvals in a single atomic transaction with `Durability::Immediate` (A05-02).
    ///
    /// # Architectural Invariant: Atomic Group-Commit for Original Approvals (A05-02 / DEC-029)
    /// Under concurrent PoS checkout load, contiguous original spend approvals are grouped
    /// into a single `redb::WriteTransaction` with `Durability::Immediate` to avoid serializing N
    /// separate fsync barriers.
    ///
    /// 1. Strict Durable-before-Vote (DEC-029): The caller releases completion acknowledgments ONLY
    ///    after this function returns `Ok(...)`, guaranteeing durable redb commit of the entire group.
    /// 2. Failure Isolation: Individual `StorageError::OwnChoiceConflict` errors (conflicting parent spend)
    ///    are isolated to the conflicting entry; they do NOT poison or roll back valid sibling approvals.
    /// 3. Fail-Closed History Integrity: If signing history corruption is detected, the transaction
    ///    is latched corrupt, uncommitted entries are discarded, and `StorageError::SigningHistoryCorrupt` is returned.
    pub fn commit_original_approvals_group(
        &self,
        entries: &[OriginalApprovalBatchEntry],
    ) -> Result<Vec<Result<Vec<u8>, StorageError>>, StorageError> {
        if !self.is_signing_history_healthy() {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);

        let mut results = Vec::with_capacity(entries.len());

        for entry in entries {
            if entry.class > 1
                || entry.approval.is_empty()
                || entry.approval.len() > 16_384
                || entry.root_valid_until_ms == 0
            {
                results.push(Err(StorageError::DurableCommitFailed(
                    "Invalid original approval context".into(),
                )));
                continue;
            }

            match &entry.target {
                OriginalApprovalTarget::Hmc {
                    tag,
                    entry: hmc_entry,
                } => {
                    if roots::is_root(tag, hmc_entry) {
                        results.push(Err(StorageError::DurableCommitFailed(
                            "genesis is a root proof, not an original spend approval".into(),
                        )));
                        continue;
                    }

                    let slot = format!("{}:{}", hex::encode(entry.node), tag);
                    let mut choice = match self.validate_and_prepare_own_choice(
                        &txn,
                        slot.as_str(),
                        hmc_entry.t_id,
                        entry.root_valid_until_ms,
                        entry.class,
                        &entry.approval,
                    ) {
                        Ok(c) => c,
                        Err(StorageError::OwnChoiceConflict) => {
                            results.push(Err(StorageError::OwnChoiceConflict));
                            continue;
                        }
                        Err(StorageError::SigningHistoryCorrupt) => {
                            self.latch_corruption_in_txn(&txn);
                            let _ = txn.commit();
                            return Err(StorageError::SigningHistoryCorrupt);
                        }
                        Err(e) => {
                            results.push(Err(e));
                            continue;
                        }
                    };

                    let mut locks = txn.open_table(TABLE_HMC_LOCKS)?;
                    let is_new = if let Some(old) = locks.get(tag.as_str())? {
                        let old: crate::api::hmc::L2LockEntry =
                            serde_json::from_slice(old.value())?;
                        if old.t_id != hmc_entry.t_id
                            || old.layer2_voucher_id != hmc_entry.layer2_voucher_id
                            || old.sender_ephemeral_pub != hmc_entry.sender_ephemeral_pub
                        {
                            results.push(Err(StorageError::OwnChoiceConflict));
                            continue;
                        }
                        false
                    } else {
                        true
                    };

                    if let Err(e) = signing::put_choice(&txn, slot.as_str(), &mut choice) {
                        drop(locks);
                        self.latch_corruption_in_txn(&txn);
                        let _ = txn.commit();
                        return Err(e);
                    }

                    let expires_sec = grace_expiry_bucket_sec(entry.root_valid_until_ms);
                    if is_new {
                        let lock_bytes = serde_json::to_vec(hmc_entry)?;
                        locks.insert(tag.as_str(), lock_bytes.as_slice())?;
                        drop(locks);

                        txn.open_table(TABLE_HMC_VOUCHER_INDEX)?
                            .insert((hmc_entry.layer2_voucher_id.as_str(), tag.as_str()), ())?;
                        txn.open_table(TABLE_HMC_TTL_INDEX)?
                            .insert(&(expires_sec, tag.as_str()), ())?;
                    } else {
                        drop(locks);
                    }
                    txn.open_table(TABLE_OWN_CHOICE_TTL)?
                        .insert(&(expires_sec, slot.as_str()), ())?;

                    let retained = match choice.approvals[usize::from(entry.class)].clone() {
                        Some(a) => a,
                        None => {
                            results.push(Err(StorageError::DurableCommitFailed(
                                "Missing retained approval".into(),
                            )));
                            continue;
                        }
                    };
                    results.push(Ok(retained));
                }
            }
        }

        txn.commit()?;
        Ok(results)
    }

    /// Atomically commits the exact collision entry and immutable own choice.
    /// The slot spans time buckets and provisional/final promotion. A canonical
    /// merge can replace a lock, but it can never rewrite this private choice.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_original_approval(
        &self,
        tag: &str,
        entry: &crate::api::hmc::L2LockEntry,
        node: &[u8; 32],
        approval: &[u8],
        class: u8,
        valid_until_ms: u64,
    ) -> Result<Vec<u8>, StorageError> {
        let batch = [OriginalApprovalBatchEntry {
            target: OriginalApprovalTarget::Hmc {
                tag: tag.to_string(),
                entry: Box::new(entry.clone()),
            },
            node: *node,
            approval: approval.to_vec(),
            class,
            root_valid_until_ms: valid_until_ms,
        }];
        let mut results = self.commit_original_approvals_group(&batch)?;
        results
            .pop()
            .unwrap_or(Err(StorageError::DurableCommitFailed("No result".into())))
    }

    /// Reconciles and validates own choice table cardinality, existing choice row encoding,
    /// generation monotonicity, and TTL index consistency before admitting an original decision.
    fn validate_and_prepare_own_choice(
        &self,
        txn: &redb::WriteTransaction,
        slot: &str,
        expected_child: [u8; 32],
        expected_valid_until_ms: u64,
        class: u8,
        approval: &[u8],
    ) -> Result<OwnSigningChoice, StorageError> {
        let state = signing::read(txn)?;
        if state.corrupt {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        let choices = txn.open_table(TABLE_OWN_CHOICES)?;
        let table_len = choices.len()?;
        if table_len != state.count {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        let previous = match choices.get(slot)? {
            Some(v) => {
                let commitments = txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
                let fp = signing::fingerprint(slot, v.value());
                match commitments.get(slot)? {
                    Some(stored_fp) if stored_fp.value() == &fp => {}
                    _ => return Err(StorageError::SigningHistoryCorrupt),
                }
                let choice: OwnSigningChoice = serde_json::from_slice(v.value())
                    .map_err(|_| StorageError::SigningHistoryCorrupt)?;
                if choice.generation > state.generation {
                    return Err(StorageError::SigningHistoryCorrupt);
                }
                let expiry = grace_expiry_bucket_sec(choice.valid_until_ms);
                let ttl_ok = txn
                    .open_table(TABLE_OWN_CHOICE_TTL)
                    .map(|ttl| {
                        ttl.get(&(expiry, slot))
                            .map(|opt| opt.is_some())
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if !ttl_ok {
                    return Err(StorageError::SigningHistoryCorrupt);
                }
                Some(choice)
            }
            None => {
                let commitments = txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
                if commitments.get(slot)?.is_some() {
                    return Err(StorageError::SigningHistoryCorrupt);
                }
                None
            }
        };
        let mut choice = previous.unwrap_or(OwnSigningChoice {
            generation: 0,
            child: expected_child,
            valid_until_ms: expected_valid_until_ms,
            approvals: [None, None],
        });
        if choice.child != expected_child || choice.valid_until_ms != expected_valid_until_ms {
            return Err(StorageError::OwnChoiceConflict);
        }
        choice.approvals[usize::from(class)].get_or_insert_with(|| approval.to_vec());
        Ok(choice)
    }

    /// Reads retained local approvals for recovery; never a source of remote authority.
    pub fn own_signing_choice(
        &self,
        node: &[u8; 32],
        tag: &str,
    ) -> Result<Option<OwnSigningChoice>, StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_OWN_CHOICES)?;
        let slot = format!("{}:{}", hex::encode(node), tag);
        table
            .get(slot.as_str())?
            .map(|v| serde_json::from_slice(v.value()).map_err(StorageError::from))
            .transpose()
    }

    /// Test-only hook to inject simulated fault/corruption without public API exposure.
    #[doc(hidden)]
    pub fn raw_database_for_test(&self) -> &Arc<Database> {
        &self.db
    }

    /// Test-only hook to simulate logical choice row loss.
    #[doc(hidden)]
    pub fn inject_remove_own_choice_for_test(&self, slot: &str) -> Result<(), StorageError> {
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);
        txn.open_table(TABLE_OWN_CHOICES)?.remove(slot)?;
        txn.commit()?;
        Ok(())
    }

    /// Returns database storage statistics: (active_locks, db_size_bytes, page_allocations).
    pub fn get_stats(&self) -> Result<(u64, u64, Option<u64>), StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_locks = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let lock_count = table_locks.len()?;
        let db_size_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let page_allocations = if let Ok(write_txn) = self.db.begin_write() {
            write_txn.stats().ok().map(|s| s.allocated_pages())
        } else {
            None
        };
        Ok((lock_count, db_size_bytes, page_allocations))
    }

    /// Returns the filesystem path to the underlying database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prunes expired HMC locks up to now_sec from TABLE_HMC_TTL_INDEX.
    /// Returns the number of pruned locks.
    pub fn prune_expired_buckets(&self, now_sec: u64) -> Result<usize, StorageError> {
        let write_txn = self.db.begin_write()?;
        let mut pruned_hmc_count = 0;
        {
            // Prune HMC TTL index
            let mut table_hmc_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let mut table_prov_vidx = write_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
            let roots_table = write_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;

            let expired_hmc_entries: Vec<(u64, String)> = table_hmc_ttl
                .range(..(now_sec.saturating_add(1), ""))?
                .take(256)
                .map(|row| row.map(|(k, _)| (k.value().0, k.value().1.to_string())))
                .collect::<Result<Vec<_>, _>>()?;

            for (sec, tag) in expired_hmc_entries {
                let mut root_valid_ms = None;
                let voucher_id = if let Some(guard) = table_hmc.get(tag.as_str())? {
                    serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                        .ok()
                        .map(|e| e.layer2_voucher_id)
                } else if let Some(guard) = table_prov_hmc.get(tag.as_str())? {
                    serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                        .ok()
                        .map(|e| e.layer2_voucher_id)
                } else {
                    None
                };
                if let Some(vid) = voucher_id {
                    if let Some(r_guard) = roots_table.get(vid.as_str())? {
                        if let Ok(root_entry) =
                            serde_json::from_slice::<crate::api::hmc::L2LockEntry>(r_guard.value())
                        {
                            if let Ok(v) = roots::root_valid_until(&root_entry) {
                                root_valid_ms = Some(v);
                            }
                        }
                    }
                }
                if let Some(rv) = root_valid_ms {
                    if now_sec < grace_expiry_bucket_sec(rv) {
                        continue;
                    }
                }

                table_hmc_ttl.remove(&(sec, tag.as_str()))?;
                write_txn
                    .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                    .remove(tag.as_str())?;
                if let Some(guard) = table_hmc.get(tag.as_str())? {
                    if let Ok(entry) =
                        serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                    {
                        table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                    }
                }
                // Quarantined minority copy shares the same TTL and is purged
                // together with live state at voucher expiration (F09, DEC-035).
                let mut prov_quarantined = false;
                if let Some(guard) = table_prov_hmc.get(tag.as_str())? {
                    if let Ok(entry) =
                        serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                    {
                        table_prov_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                        table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                    }
                    prov_quarantined = true;
                }
                if prov_quarantined {
                    table_prov_hmc.remove(tag.as_str())?;
                }
                table_hmc.remove(tag.as_str())?;
                pruned_hmc_count += 1;
            }
        }
        self.prune_voucher_roots(&write_txn, now_sec)?;
        Self::prune_own_choices(&write_txn, now_sec)?;
        write_txn.commit()?;
        Ok(pruned_hmc_count)
    }

    /// Stores fraud slashing evidence raw packet by its evidence hash.
    pub fn put_evidence(&self, hash: &[u8; 32], raw: &[u8]) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table_evidence = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            table_evidence.insert(hash, raw)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieves fraud slashing evidence raw packet by its evidence hash.
    pub fn get_evidence(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_evidence = read_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
        if let Some(guard) = table_evidence.get(hash)? {
            Ok(Some(guard.value().to_vec()))
        } else {
            Ok(None)
        }
    }

    /// Marks a node as banned due to fraud/slashing evidence.
    pub fn ban_node(&self, node_key: &[u8; 32], timestamp_ms: u64) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_BANNED_NODES)?;
            table.insert(node_key, timestamp_ms)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Checks if a node is banned.
    pub fn is_node_banned(&self, node_key: &[u8; 32]) -> Result<bool, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_BANNED_NODES)?;
        Ok(table.get(node_key)?.is_some())
    }

    /// Atomically persists fraud slashing evidence and the corresponding node ban in a single redb transaction (A20-01).
    ///
    /// # Architectural Invariant: A20-01 / INV-1402 — Atomic Persistence of Slashing Evidence & Sanctions
    /// Slashing evidence and the perpetrator's permanent ban MUST be committed in one atomic transaction.
    /// If storage fails, neither is stored; if successful, both are guaranteed to be durable.
    pub fn commit_slashing_evidence_and_ban(
        &self,
        evidence_hash: &[u8; 32],
        evidence_raw: &[u8],
        offender_node_key: &[u8; 32],
        timestamp_ms: u64,
    ) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table_evidence = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            table_evidence.insert(evidence_hash, evidence_raw)?;
            let mut table_banned = write_txn.open_table(TABLE_BANNED_NODES)?;
            table_banned.insert(offender_node_key, timestamp_ms)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Reconstructs any missing node bans from persisted slashing evidence (A20-01).
    ///
    /// Iterates `TABLE_SLASHING_EVIDENCE`, deserializes each proof payload, and validates
    /// its first-party Ed25519 signatures (anti-framing protection). If a valid evidence
    /// entry has no corresponding ban in `TABLE_BANNED_NODES`, the ban is committed.
    /// Returns the list of reconstructed banned node keys.
    pub fn reconstruct_missing_bans_from_evidence(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        let mut to_ban: Vec<([u8; 32], u64)> = Vec::new();

        {
            let read_txn = self.db.begin_read()?;
            let table_evidence = read_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            let table_banned = read_txn.open_table(TABLE_BANNED_NODES)?;

            for item in table_evidence.iter()? {
                let (_hash_guard, payload_guard) = match item {
                    Ok(entry) => entry,
                    Err(err) => {
                        warn!("Corrupt entry in TABLE_SLASHING_EVIDENCE iterator: {}", err);
                        continue;
                    }
                };
                let raw = payload_guard.value();
                let Ok(proof) =
                    bincode::deserialize::<humoco_sim_core::fraud::FraudProofPayload>(raw)
                else {
                    warn!("Failed to deserialize evidence packet in TABLE_SLASHING_EVIDENCE during boot reconstruction");
                    continue;
                };

                let offender = proof.perpetrator_node_id;
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&offender) else {
                    continue;
                };

                // Anti-framing check: verify that the evidence contains genuine Ed25519 signatures from the accused key
                if !crate::network::transport::verify_equivocation_first_party(&vk, &proof) {
                    warn!(
                        offender = %hex::encode(offender),
                        "Skipping unverified or forged evidence packet during ban reconstruction"
                    );
                    continue;
                }

                // Check if already in TABLE_BANNED_NODES
                if table_banned.get(&offender)?.is_none() {
                    to_ban.push((offender, 0));
                }
            }
        }

        if to_ban.is_empty() {
            return Ok(Vec::new());
        }

        let write_txn = self.db.begin_write()?;
        let mut reconstructed = Vec::with_capacity(to_ban.len());
        {
            let mut table_banned = write_txn.open_table(TABLE_BANNED_NODES)?;
            for (offender, ts) in to_ban {
                table_banned.insert(&offender, ts)?;
                reconstructed.push(offender);
            }
        }
        write_txn.commit()?;
        info!(
            reconstructed_count = reconstructed.len(),
            "Reconstructed missing node bans from durable slashing evidence (A20-01)"
        );
        Ok(reconstructed)
    }

    /// Retrieves all banned node keys.
    /// Defensive against corrupted entries: catches iterator errors, logs a warning, and skips defective entries.
    /// Reconstructs any missing bans from slashing evidence before returning (A20-01).
    pub fn all_banned_nodes(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        let _ = self.reconstruct_missing_bans_from_evidence();
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_BANNED_NODES)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (k_guard, _) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_BANNED_NODES iterator: {}", err);
                    continue;
                }
            };
            results.push(*k_guard.value());
        }
        Ok(results)
    }

}

/// Persisted `(node_pubkey, hrw_routing_id, first_seen_ms)` maturation record.
pub type TicketObservationRow = ([u8; 32], [u8; 32], u64);

impl RedbStorage {
    /// Persists first-seen timestamps (`first_seen_ms`) for `(node_pubkey, hrw_routing_id)` pairs
    /// only when absent so maturation history survives daemon restarts without resetting existing
    /// or shortening newly mined 24h incubation windows (INV-0303).
    pub fn record_ticket_observations_if_absent(
        &self,
        entries: &[TicketObservationRow],
    ) -> Result<usize, StorageError> {
        if entries.is_empty() {
            return Ok(0);
        }
        // Fast read pass to skip write transaction if all entries are already recorded
        let read_txn = self.db.begin_read()?;
        let mut missing = Vec::new();
        {
            let table = read_txn.open_table(TABLE_TICKET_OBSERVATIONS)?;
            for &(pubkey, hrw, seen_ms) in entries {
                let mut key = [0u8; 64];
                key[..32].copy_from_slice(&pubkey);
                key[32..].copy_from_slice(&hrw);
                if table.get(&key)?.is_none() {
                    missing.push((key, seen_ms));
                }
            }
        }
        drop(read_txn);
        if missing.is_empty() {
            return Ok(0);
        }

        let write_txn = self.db.begin_write()?;
        let mut inserted = 0usize;
        {
            let mut table = write_txn.open_table(TABLE_TICKET_OBSERVATIONS)?;
            for (key, seen_ms) in missing {
                if table.get(&key)?.is_none() {
                    table.insert(&key, seen_ms)?;
                    inserted += 1;
                }
            }
        }
        write_txn.commit()?;
        Ok(inserted)
    }

    /// Loads all persisted `(node_pubkey, hrw_routing_id, first_seen_ms)` maturation entries.
    pub fn all_ticket_observations(&self) -> Result<Vec<TicketObservationRow>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_TICKET_OBSERVATIONS)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!(
                        "Corrupt entry in TABLE_TICKET_OBSERVATIONS iterator: {}",
                        err
                    );
                    continue;
                }
            };
            let raw = k_guard.value();
            let mut pubkey = [0u8; 32];
            let mut hrw = [0u8; 32];
            pubkey.copy_from_slice(&raw[..32]);
            hrw.copy_from_slice(&raw[32..]);
            results.push((pubkey, hrw, v_guard.value()));
        }
        Ok(results)
    }

    /// Retrieves quota remaining byte years for an account tag. Defaults to 0 if not present.
    pub fn get_quota(&self, account_tag: &[u8; 32]) -> Result<u64, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_quota = read_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
        if let Some(guard) = table_quota.get(account_tag)? {
            Ok(guard.value())
        } else {
            Ok(0)
        }
    }

    /// Retrieves all persisted VIP quota accounts and their balances from TABLE_QUOTA_ACCOUNTS.
    /// Defensive against corrupted entries: catches iterator errors, logs a warning, and skips defective entries.
    pub fn all_quotas(&self) -> Result<Vec<([u8; 32], u64)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
        let mut results = Vec::new();
        for item in table.iter()? {
            let (k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_QUOTA_ACCOUNTS iterator: {}", err);
                    continue;
                }
            };
            results.push((*k_guard.value(), v_guard.value()));
        }
        Ok(results)
    }

    /// Sets quota remaining byte years for an account tag.
    pub fn set_quota(&self, account_tag: &[u8; 32], byte_years: u64) -> Result<(), StorageError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table_quota = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            table_quota.insert(account_tag, byte_years)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Sets quota remaining byte years for multiple account tags in a single atomic transaction.
    pub fn set_quotas_batch(&self, quotas: &[([u8; 32], u64)]) -> Result<(), StorageError> {
        if quotas.is_empty() {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            let mut table_quota = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            for (tag, byte_years) in quotas {
                table_quota.insert(tag, *byte_years)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically checks and charges quota for an account tag in a single write transaction.
    /// Returns the remaining byte years or StorageError::QuotaExceeded if insufficient.
    pub fn check_and_charge_quota(
        &self,
        account_tag: &[u8; 32],
        required: u64,
    ) -> Result<u64, StorageError> {
        let write_txn = self.db.begin_write()?;
        let remaining = {
            let mut table_quota = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            let available = table_quota
                .get(account_tag)?
                .map(|g| g.value())
                .unwrap_or(0);
            if available < required {
                return Err(StorageError::QuotaExceeded {
                    available,
                    required,
                });
            }
            let remaining = available - required;
            table_quota.insert(account_tag, remaining)?;
            remaining
        };
        write_txn.commit()?;
        Ok(remaining)
    }

    /// Scans active unexpired HMC locks whose canonical voucher root belongs to `shard_id`.
    /// Skips scanning or deserializing locks for vouchers belonging to other shards (A21-R2).
    pub fn active_hmc_locks_for_shard(
        &self,
        shard_id: u16,
        now_ms: u64,
    ) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
        let mut shard_roots = std::collections::HashMap::new();
        for root in self.all_voucher_roots()? {
            let Ok(validity) = roots::root_valid_until(&root) else {
                continue;
            };
            if validity <= now_ms {
                continue;
            }
            let tag = bs58::encode(root.t_id).into_string();
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
            if humoco_sim_core::types::canonical_voucher_shard(&parent) == shard_id {
                shard_roots.insert(root.layer2_voucher_id.clone(), validity);
            }
        }
        if shard_roots.is_empty() {
            return Ok(Vec::new());
        }

        let read_txn = self.db.begin_read()?;
        let table_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let mut results = Vec::new();

        for item in table_hmc.iter()? {
            let (k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!(
                        "Corrupt entry in TABLE_HMC_LOCKS iterator for shard {}: {}",
                        shard_id, err
                    );
                    continue;
                }
            };
            let entry: crate::api::hmc::L2LockEntry = match serde_json::from_slice(v_guard.value())
            {
                Ok(e) => e,
                Err(err) => {
                    warn!(
                        "Failed to deserialize HMC lock in active_hmc_locks_for_shard: {}",
                        err
                    );
                    continue;
                }
            };
            if let Some(&root_v) = shard_roots.get(&entry.layer2_voucher_id) {
                let owned_ttl = entry
                    .deletable_at
                    .as_deref()
                    .and_then(|s| s.parse::<u64>().ok());
                let effective_ttl = owned_ttl.unwrap_or(root_v);
                if !should_prune(SimTime(now_ms), SimTime(effective_ttl)) {
                    results.push((k_guard.value().to_string(), entry));
                }
            }
        }
        Ok(results)
    }

    /// Quarantines unconfirmed local minority locks for a shard that are missing from
    /// the dominant quorum state (Spec 08, Pillar 4, DEC-064).
    ///
    /// Moves HMC locks from TABLE_HMC_LOCKS to TABLE_PROVISIONAL_HMC_LOCKS, preventing minority state from poisoning
    /// the active shard digest while preserving recoverable state and own-choice integrity.
    ///
    /// TTL index entries (TABLE_HMC_TTL_INDEX) are intentionally
    /// preserved (F09, DEC-035): quarantined records are purged automatically at
    /// voucher expiration by the shared bounded expiry worker together with the
    /// live tables, so zero state bloat (Pillar 6) always holds for quarantine
    /// storage as well.
    pub fn quarantine_subquorum_locks(
        &self,
        shard_id: u16,
        keep_hmc_tags: &std::collections::HashSet<String>,
    ) -> Result<Vec<String>, StorageError> {
        let write_txn = self.db.begin_write()?;
        let mut quarantined_hmc = Vec::new();
        {
            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let mut table_prov_vidx = write_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;

            let mut to_remove_hmc = Vec::new();
            for item in table_hmc.iter()? {
                let (k_guard, v_guard) = match item {
                    Ok(g) => g,
                    Err(err) => {
                        warn!(
                            "Corrupt entry in TABLE_HMC_LOCKS iterator during quarantine: {}",
                            err
                        );
                        continue;
                    }
                };
                let tag = k_guard.value().to_string();
                let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(v_guard.value())?;
                let roots = write_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
                let root = roots
                    .get(entry.layer2_voucher_id.as_str())?
                    .ok_or_else(|| {
                        StorageError::DurableCommitFailed("quarantine spend lacks root".into())
                    })?;
                let root: crate::api::hmc::L2LockEntry = serde_json::from_slice(root.value())?;
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                    &bs58::encode(root.t_id).into_string(),
                );
                let sid = humoco_sim_core::types::canonical_voucher_shard(&parent);
                if sid == shard_id && !keep_hmc_tags.contains(&tag) {
                    if let Some(value) = write_txn
                        .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                        .get(tag.as_str())?
                    {
                        let fact: support::ConfirmationSupport =
                            serde_json::from_slice(value.value())?;
                        if fact.class > 0 {
                            return Err(StorageError::DurableCommitFailed(
                                "refusing omission of verified confirmation support".into(),
                            ));
                        }
                    }
                    to_remove_hmc.push((tag, v_guard.value().to_vec()));
                }
            }

            for (tag, val_bytes) in to_remove_hmc {
                table_hmc.remove(tag.as_str())?;
                table_prov_hmc.insert(tag.as_str(), val_bytes.as_slice())?;
                if let Ok(entry) =
                    serde_json::from_slice::<crate::api::hmc::L2LockEntry>(&val_bytes)
                {
                    let _ = table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()));
                    table_prov_vidx.insert((entry.layer2_voucher_id.as_str(), tag.as_str()), ())?;
                    // TTL index entry (TABLE_HMC_TTL_INDEX) is preserved so the
                    // shared expiry worker purges the quarantined record at
                    // voucher expiration (F09, DEC-035, Pillar 6).
                }
                quarantined_hmc.push(tag);
            }
        }
        write_txn.commit()?;
        Ok(quarantined_hmc)
    }

    /// Retrieves a provisional (quarantined) HMC lock entry by its lookup tag.
    pub fn get_provisional_hmc_lock(
        &self,
        lookup_tag: &str,
    ) -> Result<Option<crate::api::hmc::L2LockEntry>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_prov = read_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
        if let Some(guard) = table_prov.get(lookup_tag)? {
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(guard.value())?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Stores an HMC lock entry and updates the voucher index and TTL index.
    pub fn put_hmc_lock(
        &self,
        lookup_tag: &str,
        entry: &crate::api::hmc::L2LockEntry,
    ) -> Result<(), StorageError> {
        validate_sync_shape(lookup_tag, entry)?;
        if roots::is_root(lookup_tag, entry) {
            let txn = self.db.begin_write()?;
            roots::put(&txn, entry)?;
            txn.commit()?;
            return Ok(());
        }
        let val_bytes = serde_json::to_vec(entry)?;
        // A spend never supplies its own root lifetime, even when a legacy
        // client leaves a deletable_at hint on the entry.
        let root = self
            .voucher_root(&entry.layer2_voucher_id)?
            .ok_or_else(|| {
                StorageError::DurableCommitFailed("spend requires a committed Root Anchor".into())
            })?;
        let valid_until_ms = roots::root_valid_until(&root)?;
        if entry
            .causal_output
            .as_ref()
            .is_some_and(|proof| proof.root_valid_until_ms != valid_until_ms)
        {
            return Err(StorageError::DurableCommitFailed(
                "Output proof lifetime differs from voucher root".into(),
            ));
        }
        let bucket_sec = grace_expiry_bucket_sec(valid_until_ms);

        let write_txn = self.db.begin_write()?;
        {
            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            table_hmc.insert(lookup_tag, val_bytes.as_slice())?;

            let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut table_prov_vidx = write_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
            if let Some(old_prov) = table_prov_hmc.remove(lookup_tag)? {
                if let Ok(prov_entry) =
                    serde_json::from_slice::<crate::api::hmc::L2LockEntry>(old_prov.value())
                {
                    let _ = table_prov_vidx
                        .remove(&(prov_entry.layer2_voucher_id.as_str(), lookup_tag));
                }
            }
            let _ = table_prov_vidx.remove(&(entry.layer2_voucher_id.as_str(), lookup_tag));

            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            table_vidx.insert((entry.layer2_voucher_id.as_str(), lookup_tag), ())?;

            let mut table_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            table_ttl.insert(&(bucket_sec, lookup_tag), ())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically applies one mixed flush batch (locks + HMC + evidence + quota + bans)
    /// in a single ACID write transaction (Spec 12/14 Dual-Tier Ordnung, Phase 7).
    ///
    /// Serialization is performed by the caller before opening the transaction; this
    /// method only executes the ordered table inserts and commits once, guaranteeing
    /// strict commit order per batch. Prune markers are applied in the same transaction
    /// after all inserts so a batch never resurrects pruned state.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_flush_batch_atomic(
        &self,
        hmc: &[(&str, &crate::api::hmc::L2LockEntry, &[u8], u64)],
        evidences: &[([u8; 32], Vec<u8>)],
        quotas: &[([u8; 32], u64)],
        bans: &[([u8; 32], u64)],
        prune_now_secs: &[u64],
    ) -> Result<(), StorageError> {
        if hmc.is_empty()
            && evidences.is_empty()
            && quotas.is_empty()
            && bans.is_empty()
            && prune_now_secs.is_empty()
        {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            if !hmc.is_empty() {
                let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
                let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
                let mut table_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
                for (tag, entry, bytes, valid_until_ms) in hmc {
                    if tag.len() > MAX_SYNC_TAG_BYTES || bytes.len() > MAX_SYNC_ROW_BYTES {
                        return Err(StorageError::DurableCommitFailed(
                            "HMC entry exceeds synchronization limits".into(),
                        ));
                    }
                    if roots::is_root(tag, entry) {
                        roots::put(&write_txn, entry)?;
                        continue;
                    }
                    let roots = write_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
                    let root = roots
                        .get(entry.layer2_voucher_id.as_str())?
                        .ok_or_else(|| {
                            StorageError::DurableCommitFailed(
                                "spend requires a committed Root Anchor".into(),
                            )
                        })?;
                    let root: crate::api::hmc::L2LockEntry = serde_json::from_slice(root.value())?;
                    let inherited = roots::root_valid_until(&root)?;
                    if inherited != *valid_until_ms {
                        return Err(StorageError::DurableCommitFailed(
                            "spend root lifetime mismatch".into(),
                        ));
                    }
                    if entry
                        .causal_output
                        .as_ref()
                        .is_some_and(|proof| proof.root_valid_until_ms != inherited)
                    {
                        return Err(StorageError::DurableCommitFailed(
                            "Output proof lifetime differs from voucher root".into(),
                        ));
                    }
                    let bucket_sec = grace_expiry_bucket_sec(inherited);
                    table_hmc.insert(*tag, *bytes)?;
                    table_vidx.insert((entry.layer2_voucher_id.as_str(), *tag), ())?;
                    table_ttl.insert(&(bucket_sec, *tag), ())?;
                }
            }
            if !evidences.is_empty() {
                let mut table_evidence = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
                for (hash, raw) in evidences {
                    table_evidence.insert(hash, raw.as_slice())?;
                }
            }
            if !quotas.is_empty() {
                let mut table_quota = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
                for (account_tag, byte_years) in quotas {
                    table_quota.insert(account_tag, *byte_years)?;
                }
            }
            if !bans.is_empty() {
                let mut table_banned = write_txn.open_table(TABLE_BANNED_NODES)?;
                for (node_key, timestamp_ms) in bans {
                    table_banned.insert(node_key, *timestamp_ms)?;
                }
            }
            for now_sec in prune_now_secs {
                self.prune_expired_in_txn(&write_txn, *now_sec)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn prune_own_choices(txn: &redb::WriteTransaction, now_sec: u64) -> Result<(), StorageError> {
        let mut ttl = txn.open_table(TABLE_OWN_CHOICE_TTL)?;
        let expired = ttl
            .range(..(now_sec.saturating_add(1), ""))?
            .take(256)
            .map(|row| row.map(|(key, _)| (key.value().0, key.value().1.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        for (sec, slot) in expired {
            if sec <= now_sec {
                signing::remove_choice(txn, slot.as_str())?;
                ttl.remove(&(sec, slot.as_str()))?;
            }
        }
        Ok(())
    }

    /// Prunes expired voucher root records and TTL index entries (A22-03).
    ///
    /// Shared helper called within write transactions by both `prune_expired_buckets`
    /// and `prune_expired_in_txn`. Bounded to 256 deletions per pass, while inspecting
    /// up to 2048 candidate expired roots to guarantee bounded work and avoid starvation from pinned roots.
    fn prune_voucher_roots(
        &self,
        txn: &redb::WriteTransaction,
        now_sec: u64,
    ) -> Result<usize, StorageError> {
        const MAX_PRUNED_ROOTS: usize = 256;
        const MAX_CANDIDATE_ROOTS: usize = 2048;

        // 1. Fast-path check: if no candidate roots are expired, return immediately (O(1))
        let ttl_read = txn.open_table(roots::TABLE_VOUCHER_ROOT_TTL)?;
        let mut candidate_iter = ttl_read.range(..(now_sec.saturating_add(1), ""))?;
        let first_candidate = match candidate_iter.next() {
            Some(res) => res?,
            None => return Ok(0),
        };

        // 2. Open voucher index and provisional voucher index once for pure O(1) B-tree prefix seeks
        let vidx = txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
        let prov_vidx = txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
        let roots_read = txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;

        let voucher_has_spends = |vid: &str| -> Result<bool, StorageError> {
            let mut prov_range = prov_vidx.range((vid, "")..)?;
            if let Some(item) = prov_range.next() {
                let (k, _) = item?;
                if k.value().0 == vid {
                    return Ok(true);
                }
            }
            let mut range = vidx.range((vid, "")..)?;
            if let Some(item) = range.next() {
                let (k, _) = item?;
                if k.value().0 == vid {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        // 3. Stream candidate expired roots up to MAX_CANDIDATE_ROOTS to find up to MAX_PRUNED_ROOTS childless roots
        let mut to_remove = Vec::with_capacity(MAX_PRUNED_ROOTS);
        let mut inspected = 0usize;

        let candidate_stream = std::iter::once(Ok(first_candidate)).chain(candidate_iter);
        for item in candidate_stream {
            inspected += 1;
            let (key_guard, _) = item?;
            let (second, voucher_str) = key_guard.value();
            if second <= now_sec {
                let should_remove = if let Some(guard) = roots_read.get(voucher_str)? {
                    if let Ok(entry) =
                        serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                    {
                        if let Ok(exp) = roots::root_valid_until(&entry) {
                            if now_sec >= grace_expiry_bucket_sec(exp) {
                                !voucher_has_spends(voucher_str)?
                            } else {
                                false
                            }
                        } else {
                            self.latch_corruption_in_txn(txn);
                            false
                        }
                    } else {
                        self.latch_corruption_in_txn(txn);
                        false
                    }
                } else {
                    true
                };
                if should_remove {
                    to_remove.push((second, voucher_str.to_string()));
                    if to_remove.len() >= MAX_PRUNED_ROOTS {
                        break;
                    }
                }
            }
            if inspected >= MAX_CANDIDATE_ROOTS {
                break;
            }
        }
        drop(ttl_read);
        drop(roots_read);
        drop(vidx);
        drop(prov_vidx);

        if to_remove.is_empty() {
            return Ok(0);
        }

        // 4. Atomically remove identified childless roots
        let mut ttl = txn.open_table(roots::TABLE_VOUCHER_ROOT_TTL)?;
        let mut roots = txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        let count = to_remove.len();
        for (second, voucher) in to_remove {
            roots.remove(voucher.as_str())?;
            ttl.remove((second, voucher.as_str()))?;
        }
        Ok(count)
    }

    /// Prunes expired buckets inside an already-open write transaction.
    fn prune_expired_in_txn(
        &self,
        write_txn: &redb::WriteTransaction,
        now_sec: u64,
    ) -> Result<(), StorageError> {
        let mut table_hmc_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
        let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
        let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
        let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
        let mut table_prov_vidx = write_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
        let roots_table = write_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        let expired_hmc_entries: Vec<(u64, String)> = table_hmc_ttl
            .range(..(now_sec.saturating_add(1), ""))?
            .take(256)
            .map(|row| row.map(|(k, _)| (k.value().0, k.value().1.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        for (sec, tag) in expired_hmc_entries {
            let mut root_valid_ms = None;
            let voucher_id = if let Some(guard) = table_hmc.get(tag.as_str())? {
                serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                    .ok()
                    .map(|e| e.layer2_voucher_id)
            } else if let Some(guard) = table_prov_hmc.get(tag.as_str())? {
                serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                    .ok()
                    .map(|e| e.layer2_voucher_id)
            } else {
                None
            };
            if let Some(vid) = voucher_id {
                if let Some(r_guard) = roots_table.get(vid.as_str())? {
                    if let Ok(root_entry) =
                        serde_json::from_slice::<crate::api::hmc::L2LockEntry>(r_guard.value())
                    {
                        if let Ok(v) = roots::root_valid_until(&root_entry) {
                            root_valid_ms = Some(v);
                        }
                    }
                }
            }
            if let Some(rv) = root_valid_ms {
                if now_sec < grace_expiry_bucket_sec(rv) {
                    continue;
                }
            }

            table_hmc_ttl.remove(&(sec, tag.as_str()))?;
            write_txn
                .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                .remove(tag.as_str())?;
            if let Some(guard) = table_hmc.get(tag.as_str())? {
                if let Ok(entry) =
                    serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                {
                    table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                }
            }
            // Quarantined minority copy shares the same TTL and is purged
            // together with live state at voucher expiration (F09, DEC-035).
            let mut prov_quarantined = false;
            if let Some(guard) = table_prov_hmc.get(tag.as_str())? {
                if let Ok(entry) =
                    serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value())
                {
                    table_prov_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                    table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                }
                prov_quarantined = true;
            }
            if prov_quarantined {
                table_prov_hmc.remove(tag.as_str())?;
            }
            table_hmc.remove(tag.as_str())?;
        }
        drop(table_hmc_ttl);
        drop(table_hmc);
        drop(table_prov_hmc);
        drop(table_vidx);
        drop(table_prov_vidx);
        drop(roots_table);

        Self::prune_own_choices(write_txn, now_sec)?;
        self.prune_voucher_roots(write_txn, now_sec)?;
        Ok(())
    }
    pub fn get_hmc_lock(
        &self,
        lookup_tag: &str,
    ) -> Result<Option<crate::api::hmc::L2LockEntry>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
        if let Some(guard) = table_hmc.get(lookup_tag)? {
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(guard.value())?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Retrieves all HMC locks stored on disk.
    /// Defensive against corrupted entries: catches deserialization errors, logs a warning, and skips defective records.
    pub fn all_hmc_locks(
        &self,
    ) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let mut results = Vec::new();
        for item in table_hmc.iter()? {
            let (k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_HMC_LOCKS iterator: {}", err);
                    continue;
                }
            };
            let entry: crate::api::hmc::L2LockEntry = match serde_json::from_slice(v_guard.value())
            {
                Ok(e) => e,
                Err(err) => {
                    warn!(
                        "Failed to deserialize HMC lock from TABLE_HMC_LOCKS: {}",
                        err
                    );
                    continue;
                }
            };
            results.push((k_guard.value().to_string(), entry));
        }
        Ok(results)
    }

    /// Retrieves all unexpired HMC locks stored on disk at now_ms.
    /// Defensive against corrupted entries: catches deserialization errors, logs a warning, and skips defective records.
    ///
    /// # Architectural Invariant: INV-1404 Dual-Tier Cold-Start Recovery
    ///
    /// Follow-up locks carry no own `deletable_at`; their TTL is strictly
    /// inherited from the known voucher genesis root (Rule 10, Origin-Lock
    /// Mandate). They MUST NEVER be dropped as expired with TTL 0, nor may a
    /// 0 TTL poison `voucher_roots`. Two-stage evaluation: (1) collect genesis
    /// roots first, (2) evaluate follow-ups with inherited TTL. Orphans with a
    /// still-unknown root are retained (not pruned) — expiry cannot be proven
    /// without the root, and dropping them would lose recoverable state.
    pub fn all_valid_hmc_locks(
        &self,
        now_ms: u64,
    ) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let mut raw: Vec<(String, crate::api::hmc::L2LockEntry)> = Vec::new();
        for item in table_hmc.iter()? {
            let (k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_HMC_LOCKS iterator: {}", err);
                    continue;
                }
            };
            let entry: crate::api::hmc::L2LockEntry = match serde_json::from_slice(v_guard.value())
            {
                Ok(e) => e,
                Err(err) => {
                    warn!(
                        "Failed to deserialize HMC lock from TABLE_HMC_LOCKS: {}",
                        err
                    );
                    continue;
                }
            };
            raw.push((k_guard.value().to_string(), entry));
        }
        drop(table_hmc);
        drop(read_txn);
        // Stage 1: collect genesis roots.
        let mut roots: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for root in self.all_voucher_roots()? {
            roots.insert(
                root.layer2_voucher_id.clone(),
                roots::root_valid_until(&root)?,
            );
        }
        for (_, entry) in &raw {
            if let Some(v) = entry
                .deletable_at
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
            {
                roots.entry(entry.layer2_voucher_id.clone()).or_insert(v);
            }
        }
        // Stage 2: evaluate expiry with inherited TTL; never use TTL 0.
        let mut results = Vec::new();
        for (tag, entry) in raw {
            let owned_ttl = entry
                .deletable_at
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok());
            let inherited = roots.get(&entry.layer2_voucher_id).copied();
            match (owned_ttl, inherited) {
                (Some(v), _) => {
                    if !should_prune(SimTime(now_ms), SimTime(v)) {
                        results.push((tag, entry));
                    }
                }
                (None, Some(root_v)) => {
                    if !should_prune(SimTime(now_ms), SimTime(root_v)) {
                        results.push((tag, entry));
                    }
                }
                (None, None) => {
                    // Orphan follow-up with unknown root: expiry unprovable —
                    // retain instead of dropping with TTL 0.
                    results.push((tag, entry));
                }
            }
        }
        Ok(results)
    }

    /// Raw unfiltered read of all HMC locks (no TTL evaluation).
    /// Used by cold-start recovery Stage 1/2 so follow-ups never see TTL 0.
    pub fn read_all_hmc_locks(
        &self,
    ) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
        self.all_hmc_locks()
    }

    /// Single-transaction committed MVCC snapshot of HMC locks for /v1/sync.
    /// Fails closed on redb or integrity errors instead of returning an incomplete view.
    pub fn read_committed_sync_snapshot(
        &self,
        now_ms: u64,
    ) -> Result<Vec<crate::api::dto::HmcSyncRow>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let table_roots = read_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        let table_support = read_txn.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
        let mut hmc_locks = Vec::new();

        for item in table_hmc.iter()? {
            let (k_guard, v_guard) = item?;
            let tag = k_guard.value().to_string();
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(v_guard.value())?;
            let root_guard = table_roots
                .get(entry.layer2_voucher_id.as_str())?
                .ok_or_else(|| {
                    StorageError::DurableCommitFailed("sync HMC lock missing root anchor".into())
                })?;
            let root_anchor: crate::api::hmc::L2LockEntry =
                serde_json::from_slice(root_guard.value())?;
            let root_valid_until_ms = roots::root_valid_until(&root_anchor)?;
            if should_prune(SimTime(now_ms), SimTime(root_valid_until_ms))
                || root_valid_until_ms <= now_ms
            {
                continue;
            }
            let support = table_support
                .get(tag.as_str())?
                .map(|g| serde_json::from_slice::<support::ConfirmationSupport>(g.value()))
                .transpose()?;
            let row = encode_hmc_sync_row(tag, entry, root_anchor, support)?;
            hmc_locks.push(row);
        }

        Ok(hmc_locks)
    }

    /// Single-transaction committed MVCC snapshot of HMC locks for /v1/sync,
    /// bounded strictly before materialization by max_locks and max_total_bytes (S01-03).
    /// Known sparse locators are filtered early during iteration so they do not consume limit budget.
    pub fn read_committed_sync_snapshot_bounded(
        &self,
        now_ms: u64,
        locators: &std::collections::HashSet<String>,
        max_locks: usize,
        max_total_bytes: usize,
    ) -> Result<Vec<crate::api::dto::HmcSyncRow>, StorageError> {
        const MIN_SYNC_ENVELOPE_OVERHEAD: usize = 64;
        let content_cap = max_total_bytes.saturating_sub(MIN_SYNC_ENVELOPE_OVERHEAD);

        let read_txn = self.db.begin_read()?;
        let mut accumulated_bytes: usize = 0;

        let table_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let table_roots = read_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        let table_support = read_txn.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
        let mut hmc_locks = Vec::new();

        if max_locks > 0 && accumulated_bytes < content_cap {
            for item in table_hmc.iter()? {
                if hmc_locks.len() >= max_locks {
                    break;
                }
                let (k_guard, v_guard) = item?;
                let tag = k_guard.value().to_string();
                let parent_hex = hex::encode(blake3::hash(tag.as_bytes()).as_bytes());
                if locators.contains(&parent_hex) || locators.contains(&tag) {
                    continue;
                }
                let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(v_guard.value())?;
                let id_hex = hex::encode(entry.t_id);
                if locators.contains(&id_hex) {
                    continue;
                }
                let root_guard = table_roots
                    .get(entry.layer2_voucher_id.as_str())?
                    .ok_or_else(|| {
                        StorageError::DurableCommitFailed("sync HMC lock missing root anchor".into())
                    })?;
                let root_anchor: crate::api::hmc::L2LockEntry =
                    serde_json::from_slice(root_guard.value())?;
                let root_valid_until_ms = roots::root_valid_until(&root_anchor)?;
                if should_prune(SimTime(now_ms), SimTime(root_valid_until_ms))
                    || root_valid_until_ms <= now_ms
                {
                    continue;
                }
                let support = table_support
                    .get(tag.as_str())?
                    .map(|g| serde_json::from_slice::<support::ConfirmationSupport>(g.value()))
                    .transpose()?;
                let row = encode_hmc_sync_row(tag, entry, root_anchor, support)?;
                let row_bytes = serde_json::to_vec(&row)?.len();
                let row_cost = row_bytes.saturating_add(1);
                let Some(next_total) = accumulated_bytes.checked_add(row_cost) else {
                    break;
                };
                if next_total > content_cap {
                    break;
                }
                accumulated_bytes = next_total;
                hmc_locks.push(row);
            }
        }

        Ok(hmc_locks)
    }

    /// Performs a consistent snapshot backup of all tables to destination_path using a read transaction.
    /// Returns the total number of locks backed up.
    pub fn create_backup(&self, destination_path: &Path) -> Result<usize, StorageError> {
        let file_name = destination_path.file_name().ok_or_else(|| {
            StorageError::InvalidBackupDestination("Destination path must have a file name".into())
        })?;

        let dest_parent = match destination_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let dest_parent_canon = dest_parent.canonicalize()?;
        let dest_resolved = dest_parent_canon.join(file_name);

        let src_canon = self.path.canonicalize()?;
        let src_meta = std::fs::metadata(&src_canon)?;

        if dest_resolved == src_canon {
            return Err(StorageError::InvalidBackupDestination(
                "Destination path resolves to active database".into(),
            ));
        }

        if let Ok(dest_symlink_meta) = std::fs::symlink_metadata(destination_path) {
            if dest_symlink_meta.is_dir() {
                return Err(StorageError::InvalidBackupDestination(
                    "Destination cannot be a directory".into(),
                ));
            }
            if let Ok(dest_canon) = std::fs::canonicalize(destination_path) {
                if dest_canon == src_canon {
                    return Err(StorageError::InvalidBackupDestination(
                        "Destination path resolves to active database".into(),
                    ));
                }
            }
            if let Ok(dest_target_meta) = std::fs::metadata(destination_path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if (dest_target_meta.dev(), dest_target_meta.ino())
                        == (src_meta.dev(), src_meta.ino())
                    {
                        return Err(StorageError::InvalidBackupDestination(
                            "Destination path resolves to active database".into(),
                        ));
                    }
                }
            }
            let _ = std::fs::remove_file(destination_path);
        }
        let dest_storage = RedbStorage::open(destination_path)?;
        let read_txn = self.db.begin_read()?;
        let write_txn = dest_storage.db.begin_write()?;
        let mut locks_count = 0;
        {
            // 1. TABLE_PROVISIONAL_HMC_LOCKS
            let src_prov_hmc = read_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut dst_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            for item in src_prov_hmc.iter()? {
                let (k, v) = item?;
                dst_prov_hmc.insert(k.value(), v.value())?;
            }

            // 2. TABLE_PROVISIONAL_HMC_VOUCHER_INDEX
            let src_prov_vidx = read_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
            let mut dst_prov_vidx = write_txn.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?;
            for item in src_prov_vidx.iter()? {
                let (k, v) = item?;
                dst_prov_vidx.insert(k.value(), v.value())?;
            }

            // 3. TABLE_SLASHING_EVIDENCE
            let src_ev = read_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            let mut dst_ev = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            for item in src_ev.iter()? {
                let (k, v) = item?;
                dst_ev.insert(k.value(), v.value())?;
            }

            // 4. TABLE_QUOTA_ACCOUNTS
            let src_quota = read_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            let mut dst_quota = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            for item in src_quota.iter()? {
                let (k, v) = item?;
                dst_quota.insert(k.value(), v.value())?;
            }

            // 5. TABLE_HMC_LOCKS
            let src_hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut dst_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            for item in src_hmc.iter()? {
                let (k, v) = item?;
                dst_hmc.insert(k.value(), v.value())?;
                locks_count += 1;
            }

            // 6. TABLE_HMC_VOUCHER_INDEX
            let src_vidx = read_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let mut dst_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            for item in src_vidx.iter()? {
                let (k, v) = item?;
                dst_vidx.insert(k.value(), v.value())?;
            }

            // 7. TABLE_HMC_TTL_INDEX
            let src_hmc_ttl = read_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let mut dst_hmc_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            for item in src_hmc_ttl.iter()? {
                let (k, v) = item?;
                dst_hmc_ttl.insert(k.value(), v.value())?;
            }

            // 8. TABLE_BANNED_NODES
            let src_banned = read_txn.open_table(TABLE_BANNED_NODES)?;
            let mut dst_banned = write_txn.open_table(TABLE_BANNED_NODES)?;
            for item in src_banned.iter()? {
                let (k, v) = item?;
                dst_banned.insert(k.value(), v.value())?;
            }

            // 8b. TABLE_TICKET_OBSERVATIONS
            let src_tickets = read_txn.open_table(TABLE_TICKET_OBSERVATIONS)?;
            let mut dst_tickets = write_txn.open_table(TABLE_TICKET_OBSERVATIONS)?;
            for item in src_tickets.iter()? {
                let (k, v) = item?;
                dst_tickets.insert(k.value(), v.value())?;
            }

            let support_src = read_txn.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
            let mut support_dst = write_txn.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
            for row in support_src.iter()? {
                let (key, value) = row?;
                support_dst.insert(key.value(), value.value())?;
            }

            let source_roots = read_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let mut target_roots = write_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            for row in source_roots.iter()? {
                let (key, value) = row?;
                target_roots.insert(key.value(), value.value())?;
            }
            let source_root_ttl = read_txn.open_table(roots::TABLE_VOUCHER_ROOT_TTL)?;
            let mut target_root_ttl = write_txn.open_table(roots::TABLE_VOUCHER_ROOT_TTL)?;
            for row in source_root_ttl.iter()? {
                let (key, _) = row?;
                target_root_ttl.insert(key.value(), ())?;
            }

            // Private own decisions are part of a consistent operator backup,
            // never of peer state synchronization.
            let signing = read_txn.open_table(signing::TABLE_SIGNING_STATE)?;
            let mut signing_dst = write_txn.open_table(signing::TABLE_SIGNING_STATE)?;
            for row in signing.iter()? {
                let (key, value) = row?;
                signing_dst.insert(key.value(), value.value())?;
            }
            let own = read_txn.open_table(TABLE_OWN_CHOICES)?;
            let mut own_dst = write_txn.open_table(TABLE_OWN_CHOICES)?;
            for row in own.iter()? {
                let (key, value) = row?;
                own_dst.insert(key.value(), value.value())?;
            }
            let own_commitments = read_txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
            let mut own_commitments_dst = write_txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
            for row in own_commitments.iter()? {
                let (key, value) = row?;
                own_commitments_dst.insert(key.value(), value.value())?;
            }
            let own_ttl = read_txn.open_table(TABLE_OWN_CHOICE_TTL)?;
            let mut own_ttl_dst = write_txn.open_table(TABLE_OWN_CHOICE_TTL)?;
            for row in own_ttl.iter()? {
                let (key, _) = row?;
                own_ttl_dst.insert(key.value(), ())?;
            }

            // 9. TABLE_SYSTEM_AUDIT_EVENTS
            let src_audit = read_txn.open_table(TABLE_SYSTEM_AUDIT_EVENTS)?;
            let mut dst_audit = write_txn.open_table(TABLE_SYSTEM_AUDIT_EVENTS)?;
            for item in src_audit.iter()? {
                let (k, v) = item?;
                dst_audit.insert(k.value(), v.value())?;
            }

            // 10. TABLE_SCHEMA_METADATA
            let src_schema = read_txn.open_table(TABLE_SCHEMA_METADATA)?;
            let mut dst_schema = write_txn.open_table(TABLE_SCHEMA_METADATA)?;
            for item in src_schema.iter()? {
                let (k, v) = item?;
                dst_schema.insert(k.value(), v.value())?;
            }
        }
        write_txn.commit()?;
        Ok(locks_count)
    }

    /// Retrieves all HMC locks belonging to a specific voucher_id from redb.
    pub fn get_hmc_locks_for_voucher(
        &self,
        voucher_id: &str,
    ) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let vidx = read_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
        let locks_table = read_txn.open_table(TABLE_HMC_LOCKS)?;
        let mut results = Vec::new();

        let range = vidx.range((voucher_id, "")..)?;
        for entry in range {
            let (k, _) = entry?;
            let (vid, tag) = k.value();
            if vid != voucher_id {
                break;
            }
            if let Some(val) = locks_table.get(tag)? {
                let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(val.value())?;
                results.push((tag.to_string(), entry));
            }
        }
        Ok(results)
    }

    /// Retrieves all active voucher IDs indexed in redb.
    pub fn all_active_vouchers(&self) -> Result<Vec<String>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let vidx = read_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
        let mut vouchers = std::collections::HashSet::new();
        for entry in vidx.iter()? {
            let (k, _) = entry?;
            let (vid, _) = k.value();
            vouchers.insert(vid.to_string());
        }
        for row in read_txn.open_table(roots::TABLE_VOUCHER_ROOTS)?.iter()? {
            let (voucher, _) = row?;
            vouchers.insert(voucher.value().to_owned());
        }
        let mut list: Vec<String> = vouchers.into_iter().collect();
        list.sort();
        Ok(list)
    }

    /// Inserts a system audit event, serializing it with `serde_json`, and prunes oldest entries
    /// if the total count in `TABLE_SYSTEM_AUDIT_EVENTS` exceeds 100 so the table never grows beyond 100 entries.
    pub fn insert_audit_event(
        &self,
        event: &crate::api::events::EventItem,
    ) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec(event)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_SYSTEM_AUDIT_EVENTS)?;
            table.insert(event.id, bytes.as_slice())?;

            let count = table.len()?;
            if count > 100 {
                let to_remove = (count - 100) as usize;
                let mut keys_to_remove = Vec::with_capacity(to_remove);
                for item in table.iter()? {
                    if keys_to_remove.len() >= to_remove {
                        break;
                    }
                    if let Ok((k, _)) = item {
                        keys_to_remove.push(k.value());
                    }
                }
                for k in keys_to_remove {
                    table.remove(k)?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Loads recent audit events from storage, up to `limit` entries, sorted by id/timestamp.
    pub fn load_recent_audit_events(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::api::events::EventItem>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_SYSTEM_AUDIT_EVENTS)?;
        let mut items = Vec::new();
        for entry in table.iter()? {
            let (_, val_guard) = match entry {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_SYSTEM_AUDIT_EVENTS: {}", err);
                    continue;
                }
            };
            match serde_json::from_slice::<crate::api::events::EventItem>(val_guard.value()) {
                Ok(event) => items.push(event),
                Err(err) => {
                    warn!("Failed to deserialize EventItem from storage: {}", err);
                }
            }
        }
        items.sort_by_key(|e| e.id);
        if items.len() > limit {
            Ok(items[items.len() - limit..].to_vec())
        } else {
            Ok(items)
        }
    }

    /// Compacts the redb database at the specified path while offline.
    ///
    /// Verifies schema version compatibility before compacting.
    /// Returns `Ok(true)` if compaction freed pages, or `Ok(false)` if no compaction was needed.
    pub fn compact_database(path: impl AsRef<Path>) -> Result<bool, StorageError> {
        let path = path.as_ref();
        let mut db = Database::open(path)?;

        // Verify schema version before compacting
        {
            let write_txn = db.begin_write()?;
            {
                let mut schema_table = write_txn.open_table(TABLE_SCHEMA_METADATA)?;
                let existing_version = schema_table.get("schema_version")?.map(|g| g.value());
                match existing_version {
                    Some(v) => {
                        if v > CURRENT_DB_SCHEMA_VERSION {
                            return Err(StorageError::UnsupportedSchemaVersion {
                                found: v,
                                supported: CURRENT_DB_SCHEMA_VERSION,
                            });
                        }
                    }
                    None => {
                        schema_table.insert("schema_version", CURRENT_DB_SCHEMA_VERSION)?;
                    }
                }
            }
            write_txn.commit()?;
        }

        let freed = db.compact()?;
        Ok(freed)
    }
}

fn encode_hmc_sync_row(
    tag: String,
    entry: crate::api::hmc::L2LockEntry,
    root_anchor: crate::api::hmc::L2LockEntry,
    support: Option<support::ConfirmationSupport>,
) -> Result<crate::api::dto::HmcSyncRow, StorageError> {
    if entry.layer2_voucher_id != root_anchor.layer2_voucher_id {
        return Err(StorageError::DurableCommitFailed(
            "sync root identity mismatch".into(),
        ));
    }

    let root_valid_until_ms = roots::root_valid_until(&root_anchor)?;
    let parent = *blake3::hash(tag.as_bytes()).as_bytes();
    let confirmation_class = support
        .filter(|fact| {
            fact.parent == parent
                && fact.child == entry.t_id
                && fact.root_valid_until_ms == root_valid_until_ms
        })
        .map_or(0, |fact| fact.class);

    Ok(crate::api::dto::HmcSyncRow {
        lookup_tag: tag,
        entry,
        root_anchor,
        root_valid_until_ms,
        confirmation_class,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::hmc::L2LockEntry;

    fn sample_root(voucher_id: &str, valid_until_ms: u64) -> L2LockEntry {
        L2LockEntry {
            causal_output: None,
            layer2_voucher_id: voucher_id.to_string(),
            t_id: [1; 32],
            sender_ephemeral_pub: [2; 32],
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 1_000,
            deletable_at: Some(valid_until_ms.to_string()),
            privacy_guard: None,
        }
    }

    #[test]
    fn test_grace_expiry_bucket_sec_boundary() {
        // At 50_000 ms, 50_000 + 30_000 = 80_000 ms.
        // Second 80 (80_000 ms) is NOT > 80_000 ms. Bucket must be 81.
        assert_eq!(grace_expiry_bucket_sec(50_000), 81);
        assert_eq!(grace_expiry_bucket_sec(50_001), 81);
        assert_eq!(grace_expiry_bucket_sec(50_999), 81);
        assert_eq!(grace_expiry_bucket_sec(51_000), 82);
    }

    #[test]
    fn test_regression_a04_01_prune_boundary_50000ms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("prune_boundary.redb");
        let storage = RedbStorage::open(&db_path).expect("open db");

        let root_valid_until_ms = 50_000u64;
        let voucher_id = "test-voucher-50000";
        let root = sample_root(voucher_id, root_valid_until_ms);
        let root_tag = bs58::encode(root.t_id).into_string();
        storage.put_hmc_lock(&root_tag, &root).expect("put root");

        let mut spend = sample_root(voucher_id, root_valid_until_ms);
        spend.t_id = [2; 32];
        spend.deletable_at = None;
        let spend_tag = "hmc-spend-50000";
        storage.put_hmc_lock(spend_tag, &spend).expect("put spend");

        // now_sec = 79: must NOT delete
        let pruned_79 = storage.prune_expired_buckets(79).expect("prune 79");
        assert_eq!(pruned_79, 0);
        assert!(storage
            .get_hmc_lock(spend_tag)
            .expect("get_hmc_lock")
            .is_some());
        assert!(storage
            .voucher_root(voucher_id)
            .expect("voucher_root")
            .is_some());

        // now_sec = 80: must NOT delete (grace period +30s expires strictly at >80_000 ms)
        let pruned_80 = storage.prune_expired_buckets(80).expect("prune 80");
        assert_eq!(pruned_80, 0);
        assert!(storage
            .get_hmc_lock(spend_tag)
            .expect("get_hmc_lock")
            .is_some());
        assert!(storage
            .voucher_root(voucher_id)
            .expect("voucher_root")
            .is_some());

        // now_sec = 81: MUST delete
        let pruned_81 = storage.prune_expired_buckets(81).expect("prune 81");
        assert!(pruned_81 > 0);
        assert!(storage
            .get_hmc_lock(spend_tag)
            .expect("get_hmc_lock")
            .is_none());
        assert!(storage
            .voucher_root(voucher_id)
            .expect("voucher_root")
            .is_none());
    }

    #[test]
    fn test_db_schema_version_initialization_and_rejection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("schema_test.redb");

        // 1. Initial open creates TABLE_SCHEMA_METADATA with CURRENT_DB_SCHEMA_VERSION
        {
            let storage = RedbStorage::open(&db_path).expect("open new db");
            let read_txn = storage.db.begin_read().expect("begin_read");
            let table = read_txn
                .open_table(TABLE_SCHEMA_METADATA)
                .expect("open schema table");
            let val = table.get("schema_version").expect("get").expect("exists");
            assert_eq!(val.value(), CURRENT_DB_SCHEMA_VERSION);
        }

        // 2. Re-opening existing DB succeeds
        {
            let _storage = RedbStorage::open(&db_path).expect("reopen valid db");
        }

        // 3. Modifying version to future version causes open to fail closed
        {
            let raw_db = Database::open(&db_path).expect("open raw db");
            let write_txn = raw_db.begin_write().expect("begin_write");
            {
                let mut table = write_txn
                    .open_table(TABLE_SCHEMA_METADATA)
                    .expect("open table");
                table
                    .insert("schema_version", 99u32)
                    .expect("insert future version");
            }
            write_txn.commit().expect("commit");
        }

        let reopen_res = RedbStorage::open(&db_path);
        match reopen_res {
            Err(StorageError::UnsupportedSchemaVersion { found, supported }) => {
                assert_eq!(found, 99);
                assert_eq!(supported, CURRENT_DB_SCHEMA_VERSION);
            }
            Ok(_) => panic!("Expected UnsupportedSchemaVersion error, got Ok"),
            Err(err) => panic!("Expected UnsupportedSchemaVersion error, got: {err:?}"),
        }

        // 4. compact_database also fails closed on unsupported schema version
        let compact_res = RedbStorage::compact_database(&db_path);
        match compact_res {
            Err(StorageError::UnsupportedSchemaVersion { found, supported }) => {
                assert_eq!(found, 99);
                assert_eq!(supported, CURRENT_DB_SCHEMA_VERSION);
            }
            other => panic!(
                "Expected UnsupportedSchemaVersion error in compact, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_db_compaction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("compact_test.redb");

        {
            let storage = RedbStorage::open(&db_path).expect("open db");
            let root = sample_root("compact-voucher", 10_000);
            let root_tag = bs58::encode(root.t_id).into_string();
            storage.put_hmc_lock(&root_tag, &root).expect("put root");

            for i in 0..100u8 {
                let mut spend = sample_root("compact-voucher", 10_000);
                spend.t_id = [i + 1; 32];
                spend.deletable_at = None;
                let tag = format!("spend-{}", i);
                storage.put_hmc_lock(&tag, &spend).expect("put_hmc_lock");
            }
            let _ = storage.prune_expired_buckets(50).expect("prune");
        }

        // Run offline compaction
        let freed = RedbStorage::compact_database(&db_path).expect("compact_database");
        let _ = freed;

        // Re-open compacted database to verify integrity
        let storage = RedbStorage::open(&db_path).expect("reopen after compaction");
        let (active_locks, _, _) = storage.get_stats().expect("get_stats");
        assert_eq!(active_locks, 0);
    }

    #[test]
    fn test_sync_limits_and_f2_lifetime_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("f1_f2_test.redb");
        let storage = RedbStorage::open(&db_path).expect("open db");

        let root = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-v1".into(),
            t_id: [1; 32],
            sender_ephemeral_pub: [2; 32],
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 1_000,
            deletable_at: Some("50000".into()),
            privacy_guard: None,
        };
        let root_tag = bs58::encode(root.t_id).into_string();
        storage.put_hmc_lock(&root_tag, &root).expect("put root");

        // 1. Oversize tag is rejected by put_hmc_lock
        let long_tag = "x".repeat(MAX_SYNC_TAG_BYTES + 1);
        let mut spend = root.clone();
        spend.t_id = [3; 32];
        spend.deletable_at = None;
        assert!(storage.put_hmc_lock(&long_tag, &spend).is_err());

        // 2. F2: Spend with causal_output lifetime differing from voucher root is rejected
        let proof = humoco_proto::causal::CausalOutputProof {
            version: 1,
            voucher_id: root.layer2_voucher_id.clone(),
            transaction_id: spend.t_id,
            state_hash: [4; 32],
            sender_pubkey: spend.sender_ephemeral_pub,
            receiver_pubkey_hash: None,
            change_pubkey_hash: None,
            root_valid_until_ms: 60_000, // root is 50_000!
            is_root: false,
            signature: [0; 64],
        };
        spend.causal_output = Some(proof);
        let spend_tag = "spend_tag_1";
        let res = storage.put_hmc_lock(spend_tag, &spend);
        match res {
            Err(StorageError::DurableCommitFailed(msg)) => {
                assert_eq!(msg, "Output proof lifetime differs from voucher root");
            }
            other => panic!("expected lifetime mismatch error, got {other:?}"),
        }

        // 3. Oversize HMC lock is rejected
        let mut big_spend = spend.clone();
        big_spend.privacy_guard = Some("x".repeat(MAX_SYNC_ROW_BYTES + 1));
        let big_tag = "big_spend_tag";
        assert!(storage.put_hmc_lock(big_tag, &big_spend).is_err());
    }
}
