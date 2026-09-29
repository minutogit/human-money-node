use std::path::Path;
use std::sync::Arc;
use humoco_sim_core::types::LockRecord;
use humoco_sim_core::storage::should_prune;
use humoco_sim_core::types::SimTime;
use redb::{Database, ReadableTable, TableDefinition};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum StorageError {
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
pub const TABLE_TTL_INDEX: TableDefinition<(u64, &[u8; 32]), ()> = TableDefinition::new("ttl_index");
pub const TABLE_SLASHING_EVIDENCE: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("slashing_evidence");
pub const TABLE_QUOTA_ACCOUNTS: TableDefinition<&[u8; 32], u64> = TableDefinition::new("quota_accounts");
pub const TABLE_HMC_LOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("hmc_locks");
pub const TABLE_HMC_VOUCHER_INDEX: TableDefinition<(&str, &str), ()> = TableDefinition::new("hmc_voucher_index");
pub const TABLE_HMC_TTL_INDEX: TableDefinition<(u64, &str), ()> = TableDefinition::new("hmc_ttl_index");
pub const TABLE_BANNED_NODES: TableDefinition<&[u8; 32], u64> = TableDefinition::new("banned_nodes");

#[derive(Clone)]
pub struct RedbStorage {
    db: Arc<Database>,
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
            let _ = write_txn.open_table(TABLE_LOCKS)?;
            let _ = write_txn.open_table(TABLE_TTL_INDEX)?;
            let _ = write_txn.open_table(TABLE_SLASHING_EVIDENCE)?;
            let _ = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
            let _ = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let _ = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            let _ = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let _ = write_txn.open_table(TABLE_BANNED_NODES)?;
        }
        write_txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
        })
    }

    /// Stores a lock record and updates the TTL index.
    pub fn put_lock(&self, lock: &LockRecord, root_valid_until: u64) -> Result<(), StorageError> {
        let value_bytes = bincode::serialize(&(lock, root_valid_until))?;
        let bucket_sec = root_valid_until.saturating_add(30_000) / 1_000;

        let write_txn = self.db.begin_write()?;
        {
            let mut table_locks = write_txn.open_table(TABLE_LOCKS)?;
            table_locks.insert(&lock.parent_lock, value_bytes.as_slice())?;

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

            // Range up to now_sec inclusive
            let max_key = (now_sec, &[0xFFu8; 32]);
            let expired_entries: Vec<(u64, [u8; 32])> = table_ttl
                .range(..(max_key.0 + 1, &[0x00u8; 32]))?
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
                    pruned.push(parent);
                }
            }

            // Prune HMC TTL index
            let mut table_hmc_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            let mut table_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;

            let expired_hmc_entries: Vec<(u64, String)> = table_hmc_ttl
                .iter()?
                .filter_map(|res| res.ok().map(|(k, _)| (k.value().0, k.value().1.to_string())))
                .filter(|(sec, _)| *sec <= now_sec)
                .collect();

            for (sec, tag) in expired_hmc_entries {
                table_hmc_ttl.remove(&(sec, tag.as_str()))?;
                if let Some(guard) = table_hmc.get(tag.as_str())? {
                    if let Ok(entry) = serde_json::from_slice::<crate::api::hmc::L2LockEntry>(guard.value()) {
                        table_vidx.remove(&(entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                    }
                }
                table_hmc.remove(tag.as_str())?;
                pruned_hmc_count += 1;
            }
        }
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

            let mut table_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
            table_vidx.insert((entry.layer2_voucher_id.as_str(), lookup_tag), ())?;

            let mut table_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
            table_ttl.insert(&(bucket_sec, lookup_tag), ())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieves an HMC lock entry by lookup_tag.
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
    pub fn all_valid_hmc_locks(&self, now_ms: u64) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, StorageError> {
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
            let valid_until_ms = entry
                .deletable_at
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if !should_prune(SimTime(now_ms), SimTime(valid_until_ms)) {
                results.push((k_guard.value().to_string(), entry));
            }
        }
        Ok(results)
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
        }
        write_txn.commit()?;
        Ok(locks_count)
    }
}
