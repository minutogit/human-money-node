mod signing;

use std::path::Path;
use std::sync::Arc;
use humoco_sim_core::types::LockRecord;
use humoco_sim_core::storage::should_prune;
use humoco_sim_core::types::SimTime;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("FAIL_CLOSED_CORRUPT: signing history integrity unavailable")]
    SigningHistoryCorrupt,
    #[error("Redb database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("Redb transaction error: {0}")]
    Transaction(Box<redb::TransactionError>),

    #[error("Redb table error: {0}")]
    Table(Box<redb::TableError>),

    #[error("Redb commit error: {0}")]
    Commit(Box<redb::CommitError>),

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

    #[error("Own signing decision conflicts with retained history") ]
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

pub const TABLE_LOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("locks");
pub const TABLE_PROVISIONAL_LOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("provisional_locks");
pub const TABLE_PROVISIONAL_HMC_LOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("provisional_hmc_locks");
pub const TABLE_TTL_INDEX: TableDefinition<(u64, &[u8; 32]), ()> = TableDefinition::new("ttl_index");
pub const TABLE_SLASHING_EVIDENCE: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("slashing_evidence");
pub const TABLE_QUOTA_ACCOUNTS: TableDefinition<&[u8; 32], u64> = TableDefinition::new("quota_accounts");
pub const TABLE_HMC_LOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("hmc_locks");
pub const TABLE_HMC_VOUCHER_INDEX: TableDefinition<(&str, &str), ()> = TableDefinition::new("hmc_voucher_index");
pub const TABLE_HMC_TTL_INDEX: TableDefinition<(u64, &str), ()> = TableDefinition::new("hmc_ttl_index");
pub const TABLE_BANNED_NODES: TableDefinition<&[u8; 32], u64> = TableDefinition::new("banned_nodes");
pub const TABLE_SYSTEM_AUDIT_EVENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("system_audit_events");

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

pub const TABLE_OWN_CHOICES: TableDefinition<&str, &[u8]> = TableDefinition::new("own_signing_choices");
pub const TABLE_OWN_CHOICE_TTL: TableDefinition<(u64, &str), ()> = TableDefinition::new("own_signing_choice_ttl");

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

        // Initialize tables in a write transaction
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(TABLE_OWN_CHOICES)?;
            let _ = write_txn.open_table(TABLE_OWN_CHOICE_TTL)?;
            let _ = write_txn.open_table(TABLE_LOCKS)?;
            let _ = write_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;
            let _ = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let _ = write_txn.open_table(TABLE_TTL_INDEX)?;
            let _ = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            let _ = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            let _ = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let _ = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let _ = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let _ = write_txn.open_table(TABLE_BANNED_NODES)?;
            let _ = write_txn.open_table(TABLE_SYSTEM_AUDIT_EVENTS)?;
        }
        let corrupt = signing::initialize(&write_txn)?;
        write_txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
            path: path.to_path_buf(),
            signing_corrupt: signing::latch(corrupt),
        })
    }

    /// Atomically commits the exact collision entry and immutable own choice.
    /// The slot spans time buckets and provisional/final promotion. A canonical
    /// merge can replace a lock, but it can never rewrite this private choice.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_original_approval(
        &self, tag: &str, entry: &crate::api::hmc::L2LockEntry,
        node: &[u8; 32], approval: &[u8], class: u8, valid_until_ms: u64,
    ) -> Result<Vec<u8>, StorageError> {
        if !self.is_signing_history_healthy() { return Err(StorageError::SigningHistoryCorrupt); }
        if class > 1 || approval.is_empty() || approval.len() > 16_384 || valid_until_ms == 0 {
            return Err(StorageError::DurableCommitFailed("Invalid original approval context".into()));
        }
        let slot = format!("{}:{}", hex::encode(node), tag);
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);
        let retained = {
            let choices = txn.open_table(TABLE_OWN_CHOICES)?;
            let previous = choices.get(slot.as_str())?
                .map(|v| serde_json::from_slice::<OwnSigningChoice>(v.value()))
                .transpose()?;
            let mut choice = previous.unwrap_or(OwnSigningChoice {
                generation: 0, child: entry.t_id, valid_until_ms, approvals: [None, None],
            });
            if choice.child != entry.t_id || choice.valid_until_ms != valid_until_ms {
                return Err(StorageError::OwnChoiceConflict);
            }
            let mut locks = txn.open_table(TABLE_HMC_LOCKS)?;
            if let Some(old) = locks.get(tag)? {
                let old: crate::api::hmc::L2LockEntry = serde_json::from_slice(old.value())?;
                if old.t_id != entry.t_id { return Err(StorageError::OwnChoiceConflict); }
            }
            choice.approvals[usize::from(class)].get_or_insert_with(|| approval.to_vec());
            drop(choices);
            signing::put_choice(&txn, slot.as_str(), &mut choice)?;
            let lock_bytes = serde_json::to_vec(entry)?;
            locks.insert(tag, lock_bytes.as_slice())?;
            txn.open_table(TABLE_HMC_VOUCHER_INDEX)?.insert((entry.layer2_voucher_id.as_str(), tag), ())?;
            let expires_sec = valid_until_ms.saturating_add(30_999) / 1_000;
            txn.open_table(TABLE_HMC_TTL_INDEX)?.insert(&(expires_sec, tag), ())?;
            txn.open_table(TABLE_OWN_CHOICE_TTL)?.insert(&(expires_sec, slot.as_str()), ())?;
            choice.approvals[usize::from(class)].clone().ok_or_else(|| StorageError::DurableCommitFailed("Missing retained approval".into()))?
        };
        txn.commit()?;
        Ok(retained)
    }

    /// Pure collision-record variant of the same private durable decision gate.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_original_record_approval(
        &self, record: &LockRecord, root_valid_until_ms: u64, node: &[u8; 32],
        approval: &[u8], class: u8,
    ) -> Result<Vec<u8>, StorageError> {
        if !self.is_signing_history_healthy() { return Err(StorageError::SigningHistoryCorrupt); }
        if class > 1 || approval.is_empty() || approval.len() > 16_384 || root_valid_until_ms == 0 {
            return Err(StorageError::DurableCommitFailed("Invalid original approval context".into()));
        }
        let tag = hex::encode(record.parent_lock);
        let slot = format!("{}:{}", hex::encode(node), tag);
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);
        let retained = {
            let choices = txn.open_table(TABLE_OWN_CHOICES)?;
            let mut choice = choices.get(slot.as_str())?
                .map(|v| serde_json::from_slice::<OwnSigningChoice>(v.value())).transpose()?
                .unwrap_or(OwnSigningChoice { generation: 0, child: record.id, valid_until_ms: root_valid_until_ms, approvals: [None, None] });
            if choice.child != record.id || choice.valid_until_ms != root_valid_until_ms { return Err(StorageError::OwnChoiceConflict); }
            let mut locks = txn.open_table(TABLE_LOCKS)?;
            if let Some(old) = locks.get(&record.parent_lock)? {
                let (old, _): (LockRecord, u64) = bincode::deserialize(old.value())?;
                if old.id != record.id { return Err(StorageError::OwnChoiceConflict); }
            }
            choice.approvals[usize::from(class)].get_or_insert_with(|| approval.to_vec());
            drop(choices);
            signing::put_choice(&txn, slot.as_str(), &mut choice)?;
            let bytes = bincode::serialize(&(record, root_valid_until_ms))?;
            locks.insert(&record.parent_lock, bytes.as_slice())?;
            let expires_sec = root_valid_until_ms.saturating_add(30_999) / 1_000;
            txn.open_table(TABLE_TTL_INDEX)?.insert(&(expires_sec, &record.parent_lock), ())?;
            txn.open_table(TABLE_OWN_CHOICE_TTL)?.insert(&(expires_sec, slot.as_str()), ())?;
            choice.approvals[usize::from(class)].clone().ok_or_else(|| StorageError::DurableCommitFailed("Missing retained approval".into()))?
        };
        txn.commit()?;
        Ok(retained)
    }

    /// Reads retained local approvals for recovery; never a source of remote authority.
    pub fn own_signing_choice(&self, node: &[u8; 32], tag: &str) -> Result<Option<OwnSigningChoice>, StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_OWN_CHOICES)?;
        let slot = format!("{}:{}", hex::encode(node), tag);
        table.get(slot.as_str())?.map(|v| serde_json::from_slice(v.value()).map_err(StorageError::from)).transpose()
    }

    /// Returns database storage statistics: (active_locks, db_size_bytes, page_allocations).
    pub fn get_stats(&self) -> Result<(u64, u64, Option<u64>), StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_locks = read_txn.open_table(TABLE_LOCKS)?;
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

    /// Stores a lock record and updates the TTL index.
    pub fn put_lock(&self, lock: &LockRecord, root_valid_until: u64) -> Result<(), StorageError> {
        let value_bytes = bincode::serialize(&(lock, root_valid_until))?;
        let bucket_sec = root_valid_until.saturating_add(30_000) / 1_000;

        let write_txn = self.db.begin_write()?;
        {
            let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
            table_locks.insert(&lock.parent_lock, value_bytes.as_slice())?;

            let mut table_prov_locks = write_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;
            let _ = table_prov_locks.remove(&lock.parent_lock);

            let mut table_ttl = write_txn.open_table(TABLE_TTL_INDEX)?;
            table_ttl.insert(&(bucket_sec, &lock.parent_lock), ())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Stores multiple lock records in a single transaction.
    pub fn put_locks_batch<'a, I>(&self, locks: I) -> Result<(), StorageError>
    where
        I: IntoIterator<Item = (&'a LockRecord, u64)>,
    {
        let write_txn = self.db.begin_write()?;
        {
            let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
            let mut table_ttl = write_txn.open_table(TABLE_TTL_INDEX)?;

            for (lock, root_valid_until) in locks {
                let value_bytes = bincode::serialize(&(lock, root_valid_until))?;
                let bucket_sec = root_valid_until.saturating_add(30_000) / 1_000;

                table_locks.insert(&lock.parent_lock, value_bytes.as_slice())?;
                table_ttl.insert(&(bucket_sec, &lock.parent_lock), ())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieves a lock record by its parent_lock hash.
    pub fn get_lock(&self, parent_lock: &[u8; 32]) -> Result<Option<(LockRecord, u64)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_locks = read_txn.open_table(TABLE_LOCKS)?;
        if let Some(guard) = table_locks.get(parent_lock)? {
            let (record, root_valid_until): (LockRecord, u64) = bincode::deserialize(guard.value())?;
            Ok(Some((record, root_valid_until)))
        } else {
            Ok(None)
        }
    }

    /// Prunes expired locks up to now_sec from TABLE_TTL_INDEX and deletes corresponding records from TABLE_LOCKS.
    /// Returns (pruned_parents, pruned_hmc_count).
    pub fn prune_expired_buckets(&self, now_sec: u64) -> Result<(Vec<[u8; 32]>, usize), StorageError> {
        let write_txn = self.db.begin_write()?;
        let mut pruned = Vec::new();
        let mut pruned_hmc_count = 0;
        {
            let mut table_ttl = write_txn.open_table(TABLE_TTL_INDEX)?;
            let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
            let mut table_prov_locks = write_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;

            // Range up to now_sec inclusive
            let max_key = (now_sec, &[0xFFu8; 32]);
            let expired_entries: Vec<(u64, [u8; 32])> = table_ttl
                .range(..(max_key.0.saturating_add(1), &[0x00u8; 32]))?
                .take(256)
                .map(|item| {
                    let (k_guard, _) = item?;
                    let (sec, parent) = k_guard.value();
                    let mut p = [0u8; 32];
                    p.copy_from_slice(parent);
                    Ok::<_, StorageError>((sec, p))
                })
                .collect::<Result<Vec<_>, _>>()?;

            for (sec, parent) in expired_entries {
                if sec <= now_sec {
                    table_ttl.remove(&(sec, &parent))?;
                    table_locks.remove(&parent)?;
                    // Quarantined minority copies (TABLE_PROVISIONAL_LOCKS) share
                    // the same TTL and are purged together here (F09, DEC-035).
                    table_prov_locks.remove(&parent)?;
                    pruned.push(parent);
                }
            }

            // Prune HMC TTL index
            let mut table_hmc_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;

            let expired_hmc_entries: Vec<(u64, String)> = table_hmc_ttl
                .range(..(now_sec.saturating_add(1), ""))?
                .take(256)
                .map(|row| row.map(|(k, _)| (k.value().0, k.value().1.to_string())))
                .collect::<Result<Vec<_>, _>>()?;

            for (sec, tag) in expired_hmc_entries {
                table_hmc_ttl.remove(&(sec, tag.as_str()))?;
                if let Some(guard) = table_hmc.get(tag.as_str())? {
                    if let Ok(entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value()) {
                        table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                    }
                }
                // Quarantined minority copy shares the same TTL and is purged
                // together with live state at voucher expiration (F09, DEC-035).
                let mut prov_quarantined = false;
                if let Some(guard) = table_prov_hmc.get(tag.as_str())? {
                    if let Ok(entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value()) {
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
        Self::prune_own_choices(&write_txn, now_sec)?;
        write_txn.commit()?;
        Ok((pruned, pruned_hmc_count))
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

    /// Retrieves all banned node keys.
    /// Defensive against corrupted entries: catches iterator errors, logs a warning, and skips defective entries.
    pub fn all_banned_nodes(&self) -> Result<Vec<[u8; 32]>, StorageError> {
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

    /// Alias for all_banned_nodes: Retrieves all slashed node keys.
    /// Defensive against corrupted entries: catches errors, logs a warning, and skips defective entries.
    pub fn all_slashed_nodes(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        self.all_banned_nodes()
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
            let available = table_quota.get(account_tag)?.map(|g| g.value()).unwrap_or(0);
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

    /// Scans all locks from TABLE_LOCKS and returns all unexpired ones at now_ms.
    /// Defensive against corrupted entries: catches deserialization errors, logs a warning, and skips defective records.
    pub fn all_valid_locks(&self, now_ms: u64) -> Result<Vec<(LockRecord, u64)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_locks = read_txn.open_table(TABLE_LOCKS)?;
        let mut results = Vec::new();

        for item in table_locks.iter()? {
            let (_k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_LOCKS iterator: {}", err);
                    continue;
                }
            };
            let (record, root_valid_until): (LockRecord, u64) = match bincode::deserialize(v_guard.value()) {
                Ok(data) => data,
                Err(err) => {
                    warn!("Failed to deserialize LockRecord from TABLE_LOCKS: {}", err);
                    continue;
                }
            };
            if !should_prune(SimTime(now_ms), SimTime(root_valid_until)) && record.valid_until.0 > now_ms {
                results.push((record, root_valid_until));
            }
        }

        Ok(results)
    }

    /// Scans all locks from TABLE_LOCKS for a specific shard_id and returns all unexpired ones at now_ms.
    /// Defensive against corrupted entries: catches deserialization errors, logs a warning, and skips defective records.
    pub fn active_locks_for_shard(&self, shard_id: u16, now_ms: u64) -> Result<Vec<(LockRecord, u64)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_locks = read_txn.open_table(TABLE_LOCKS)?;
        let mut results = Vec::new();

        for item in table_locks.iter()? {
            let (_k_guard, v_guard) = match item {
                Ok(g) => g,
                Err(err) => {
                    warn!("Corrupt entry in TABLE_LOCKS iterator for shard {}: {}", shard_id, err);
                    continue;
                }
            };
            let (record, root_valid_until): (LockRecord, u64) = match bincode::deserialize(v_guard.value()) {
                Ok(data) => data,
                Err(err) => {
                    warn!("Failed to deserialize LockRecord for shard {}: {}", shard_id, err);
                    continue;
                }
            };
            let sid = u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]);
            if sid == shard_id && !should_prune(SimTime(now_ms), SimTime(root_valid_until)) && record.valid_until.0 > now_ms {
                results.push((record, root_valid_until));
            }
        }

        Ok(results)
    }

    /// Quarantines unconfirmed local minority locks for a shard that are missing from
    /// the dominant quorum state (Spec 08, Pillar 4, DEC-064).
    ///
    /// Moves native locks from TABLE_LOCKS to TABLE_PROVISIONAL_LOCKS and HMC locks from
    /// TABLE_HMC_LOCKS to TABLE_PROVISIONAL_HMC_LOCKS, preventing minority state from poisoning
    /// the active shard digest while preserving recoverable state and own-choice integrity.
    ///
    /// TTL index entries (TABLE_TTL_INDEX / TABLE_HMC_TTL_INDEX) are intentionally
    /// preserved (F09, DEC-035): quarantined records are purged automatically at
    /// voucher expiration by the shared bounded expiry worker together with the
    /// live tables, so zero state bloat (Pillar 6) always holds for quarantine
    /// storage as well.
    pub fn quarantine_subquorum_locks(
        &self,
        shard_id: u16,
        keep_native_parents: &std::collections::HashSet<[u8; 32]>,
        keep_hmc_tags: &std::collections::HashSet<String>,
    ) -> Result<(Vec<[u8; 32]>, Vec<String>), StorageError> {
        let write_txn = self.db.begin_write()?;
        let mut quarantined_native = Vec::new();
        let mut quarantined_hmc = Vec::new();
        {
            let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
            let mut table_prov_locks = write_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;

            let mut to_remove_native = Vec::new();
            for item in table_locks.iter()? {
                let (k_guard, v_guard) = match item {
                    Ok(g) => g,
                    Err(err) => {
                        warn!("Corrupt entry in TABLE_LOCKS iterator during quarantine: {}", err);
                        continue;
                    }
                };
                let parent: [u8; 32] = *k_guard.value();
                let sid = u16::from_be_bytes([parent[0], parent[1]]);
                if sid == shard_id && !keep_native_parents.contains(&parent) {
                    to_remove_native.push((parent, v_guard.value().to_vec()));
                }
            }

            for (parent, val_bytes) in to_remove_native {
                table_locks.remove(&parent)?;
                table_prov_locks.insert(&parent, val_bytes.as_slice())?;
                // TTL index entry (TABLE_TTL_INDEX) is preserved so the shared
                // expiry worker purges the quarantined record at voucher
                // expiration (F09, DEC-035, Pillar 6).
                quarantined_native.push(parent);
            }

            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;

            let mut to_remove_hmc = Vec::new();
            for item in table_hmc.iter()? {
                let (k_guard, v_guard) = match item {
                    Ok(g) => g,
                    Err(err) => {
                        warn!("Corrupt entry in TABLE_HMC_LOCKS iterator during quarantine: {}", err);
                        continue;
                    }
                };
                let tag = k_guard.value().to_string();
                let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
                let sid = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
                if sid == shard_id && !keep_hmc_tags.contains(&tag) {
                    to_remove_hmc.push((tag, v_guard.value().to_vec()));
                }
            }

            for (tag, val_bytes) in to_remove_hmc {
                table_hmc.remove(tag.as_str())?;
                table_prov_hmc.insert(tag.as_str(), val_bytes.as_slice())?;
                if let Ok(entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(&val_bytes) {
                    let _ = table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()));
                    // TTL index entry (TABLE_HMC_TTL_INDEX) is preserved so the
                    // shared expiry worker purges the quarantined record at
                    // voucher expiration (F09, DEC-035, Pillar 6).
                }
                quarantined_hmc.push(tag);
            }
        }
        write_txn.commit()?;
        Ok((quarantined_native, quarantined_hmc))
    }

    /// Retrieves a provisional (quarantined) native lock record by its parent_lock hash.
    pub fn get_provisional_lock(&self, parent_lock: &[u8; 32]) -> Result<Option<(LockRecord, u64)>, StorageError> {
        let read_txn = self.db.begin_read()?;
        let table_prov = read_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;
        if let Some(guard) = table_prov.get(parent_lock)? {
            let (record, root_valid_until): (LockRecord, u64) = bincode::deserialize(guard.value())?;
            Ok(Some((record, root_valid_until)))
        } else {
            Ok(None)
        }
    }

    /// Retrieves a provisional (quarantined) HMC lock entry by its lookup tag.
    pub fn get_provisional_hmc_lock(&self, lookup_tag: &str) -> Result<Option<crate::api::hmc::L2LockEntry>, StorageError> {
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
    pub fn put_hmc_lock(&self, lookup_tag: &str, entry: &crate::api::hmc::L2LockEntry) -> Result<(), StorageError> {
        let val_bytes = serde_json::to_vec(entry)?;
        let valid_until_ms = if let Some(v) = entry
            .deletable_at
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
        {
            v
        } else {
            // Inherit from existing voucher root if present; otherwise default to 0 for immediate pruning
            let read_txn = self.db.begin_read()?;
            let vidx = read_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let hmc = read_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut root_valid = None;
            let range = vidx.range((entry.layer2_voucher_id.as_str(), "").. )?;
            for item in range {
                let (k, _) = item?;
                let (vid, tag) = k.value();
                if vid != entry.layer2_voucher_id.as_str() {
                    break;
                }
                if let Some(guard) = hmc.get(tag)? {
                    if let Ok(root_entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value()) {
                        if let Some(d) = root_entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                            root_valid = Some(d);
                            break;
                        }
                    }
                }
            }
            root_valid.unwrap_or(0)
        };
        let bucket_sec = valid_until_ms.saturating_add(30_000) / 1_000;

        let write_txn = self.db.begin_write()?;
        {
            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            table_hmc.insert(lookup_tag, val_bytes.as_slice())?;

            let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let _ = table_prov_hmc.remove(lookup_tag);

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
        locks: &[(&LockRecord, u64, &[u8])],
        hmc: &[(&str, &crate::api::hmc::L2LockEntry, &[u8], u64)],
        evidences: &[([u8; 32], Vec<u8>)],
        quotas: &[([u8; 32], u64)],
        bans: &[([u8; 32], u64)],
        prune_now_secs: &[u64],
    ) -> Result<(), StorageError> {
        if locks.is_empty()
            && hmc.is_empty()
            && evidences.is_empty()
            && quotas.is_empty()
            && bans.is_empty()
            && prune_now_secs.is_empty()
        {
            return Ok(());
        }
        let write_txn = self.db.begin_write()?;
        {
            if !locks.is_empty() {
                let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
                let mut table_ttl = write_txn.open_table(TABLE_TTL_INDEX)?;
                for (lock, root_valid_until, bytes) in locks {
                    let bucket_sec = root_valid_until.saturating_add(30_000) / 1_000;
                    table_locks.insert(&lock.parent_lock, *bytes)?;
                    table_ttl.insert(&(bucket_sec, &lock.parent_lock), ())?;
                }
            }
            if !hmc.is_empty() {
                let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
                let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
                let mut table_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
                for (tag, entry, bytes, valid_until_ms) in hmc {
                    let bucket_sec = valid_until_ms.saturating_add(30_000) / 1_000;
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
                Self::prune_expired_in_txn(&write_txn, *now_sec)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    fn prune_own_choices(txn: &redb::WriteTransaction, now_sec: u64) -> Result<(), StorageError> {
        let mut ttl = txn.open_table(TABLE_OWN_CHOICE_TTL)?;
        let expired = ttl.range(..(now_sec, ""))?.take(256)
            .map(|row| row.map(|(key, _)| (key.value().0, key.value().1.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        for (sec, slot) in expired {
            signing::remove_choice(txn, slot.as_str())?;
            ttl.remove(&(sec, slot.as_str()))?;
        }
        Ok(())
    }

    /// Prunes expired buckets inside an already-open write transaction.
    fn prune_expired_in_txn(
        write_txn: &redb::WriteTransaction,
        now_sec: u64,
    ) -> Result<(), StorageError> {
        Self::prune_own_choices(write_txn, now_sec)?;
        let mut table_ttl = write_txn.open_table(TABLE_TTL_INDEX)?;
        let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
        let mut table_prov_locks = write_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;
        let expired_entries: Vec<(u64, [u8; 32])> = table_ttl
            .range(..(now_sec.saturating_add(1), &[0x00u8; 32]))?
            .take(256)
            .map(|item| {
                let (k_guard, _) = item?;
                let (sec, parent) = k_guard.value();
                let mut p = [0u8; 32];
                p.copy_from_slice(parent);
                Ok::<_, StorageError>((sec, p))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (sec, parent) in expired_entries {
            if sec <= now_sec {
                table_ttl.remove(&(sec, &parent))?;
                table_locks.remove(&parent)?;
                // Quarantined minority copies (TABLE_PROVISIONAL_LOCKS) share the
                // same TTL and are purged together here (F09, DEC-035).
                table_prov_locks.remove(&parent)?;
            }
        }
        drop(table_ttl);
        drop(table_locks);
        drop(table_prov_locks);

        let mut table_hmc_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
        let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
        let mut table_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
        let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
        let expired_hmc_entries: Vec<(u64, String)> = table_hmc_ttl
            .range(..(now_sec.saturating_add(1), ""))?
            .take(256)
            .map(|row| row.map(|(k, _)| (k.value().0, k.value().1.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        for (sec, tag) in expired_hmc_entries {
            table_hmc_ttl.remove(&(sec, tag.as_str()))?;
            if let Some(guard) = table_hmc.get(tag.as_str())? {
                if let Ok(entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value()) {
                    table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                }
            }
            // Quarantined minority copy shares the same TTL and is purged
            // together with live state at voucher expiration (F09, DEC-035).
            let mut prov_quarantined = false;
            if let Some(guard) = table_prov_hmc.get(tag.as_str())? {
                if let Ok(entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value()) {
                    table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                }
                prov_quarantined = true;
            }
            if prov_quarantined {
                table_prov_hmc.remove(tag.as_str())?;
            }
            table_hmc.remove(tag.as_str())?;
        }
        Ok(())
    }
    pub fn get_hmc_lock(&self, lookup_tag: &str) -> Result<Option<crate::api::hmc::L2LockEntry>, StorageError> {
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
    pub fn all_hmc_locks(&self) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
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
            let entry: crate::api::hmc::L2LockEntry = match serde_json::from_slice(v_guard.value()) {
                Ok(e) => e,
                Err(err) => {
                    warn!("Failed to deserialize HMC lock from TABLE_HMC_LOCKS: {}", err);
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
    pub fn all_valid_hmc_locks(&self, now_ms: u64) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
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
            let entry: crate::api::hmc::L2LockEntry = match serde_json::from_slice(v_guard.value()) {
                Ok(e) => e,
                Err(err) => {
                    warn!("Failed to deserialize HMC lock from TABLE_HMC_LOCKS: {}", err);
                    continue;
                }
            };
            raw.push((k_guard.value().to_string(), entry));
        }
        drop(table_hmc);
        drop(read_txn);
        // Stage 1: collect genesis roots.
        let mut roots: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for (_, entry) in &raw {
            if let Some(v) = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                roots.entry(entry.layer2_voucher_id.clone()).or_insert(v);
            }
        }
        // Stage 2: evaluate expiry with inherited TTL; never use TTL 0.
        let mut results = Vec::new();
        for (tag, entry) in raw {
            let owned_ttl = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok());
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
    pub fn read_all_hmc_locks(&self) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
        self.all_hmc_locks()
    }

    /// Performs a consistent snapshot backup of all tables to destination_path using a read transaction.
    /// Returns the total number of locks backed up.
    pub fn create_backup(&self, destination_path: &Path) -> Result<usize, StorageError> {
        if destination_path.exists() {
            let _ = std::fs::remove_file(destination_path);
        }
        let dest_storage = RedbStorage::open(destination_path)?;
        let read_txn = self.db.begin_read()?;
        let write_txn = dest_storage.db.begin_write()?;
        let mut locks_count = 0;
        {
            // 1. TABLE_LOCKS
            let src_locks = read_txn.open_table(TABLE_LOCKS)?;
            let mut dst_locks = write_txn.open_table(TABLE_LOCKS)?;
            for item in src_locks.iter()? {
                let (k, v) = item?;
                dst_locks.insert(k.value(), v.value())?;
                locks_count += 1;
            }

            // 1b. TABLE_PROVISIONAL_LOCKS
            let src_prov_locks = read_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;
            let mut dst_prov_locks = write_txn.open_table(TABLE_PROVISIONAL_LOCKS)?;
            for item in src_prov_locks.iter()? {
                let (k, v) = item?;
                dst_prov_locks.insert(k.value(), v.value())?;
            }

            // 1c. TABLE_PROVISIONAL_HMC_LOCKS
            let src_prov_hmc = read_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            let mut dst_prov_hmc = write_txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?;
            for item in src_prov_hmc.iter()? {
                let (k, v) = item?;
                dst_prov_hmc.insert(k.value(), v.value())?;
            }

            // 2. TABLE_TTL_INDEX
            let src_ttl = read_txn.open_table(TABLE_TTL_INDEX)?;
            let mut dst_ttl = write_txn.open_table(TABLE_TTL_INDEX)?;
            for item in src_ttl.iter()? {
                let (k, v) = item?;
                dst_ttl.insert(k.value(), v.value())?;
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
        let mut list: Vec<String> = vouchers.into_iter().collect();
        list.sort();
        Ok(list)
    }

    /// Inserts a system audit event, serializing it with `serde_json`, and prunes oldest entries
    /// if the total count in `TABLE_SYSTEM_AUDIT_EVENTS` exceeds 100 so the table never grows beyond 100 entries.
    pub fn insert_audit_event(&self, event: &crate::api::events::EventItem) -> Result<(), StorageError> {
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
    pub fn load_recent_audit_events(&self, limit: usize) -> Result<Vec<crate::api::events::EventItem>, StorageError> {
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
}
