//! Bounded active-state cursors over an immutable redb read transaction.
use super::*;
use crate::network::framing::{ActiveSyncRequest, ActiveSyncResponse, SyncPayload};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_CUTS: usize = 32;
const CUT_LIFETIME: Duration = Duration::from_secs(30);
const MAX_PAGE_BYTES: usize = 48 * 1024;
const MAX_ROW_BYTES: usize = 16 * 1024;
const CURSOR_STRIDE: u64 = 1 << 32;

struct Cut {
    txn: redb::ReadTransaction,
    owner: [u8; 32],
    bucket: Option<u64>,
    shard: Option<u16>,
    expires: Instant,
    root_after: Option<String>,
    roots_done: bool,
    native_after: Option<[u8; 32]>,
    native_done: bool,
    hmc_after: Option<String>,
    next_cursor: u64,
}
/// Fixed, short-lived MVCC cuts. Cursors are bound to the authenticated requester
/// and selection; no offset is evaluated against a newer database version.
#[derive(Default)]
pub struct SnapshotCuts {
    state: Mutex<(u64, HashMap<u64, Cut>)>,
}
fn invalid(reason: &str) -> StorageError {
    StorageError::DurableCommitFailed(reason.into())
}
impl SnapshotCuts {
    /// Execute only in the sync blocking worker, never on a runtime thread.
    pub fn page(
        &self,
        db: &RedbStorage,
        req: ActiveSyncRequest,
        owner: [u8; 32],
    ) -> Result<ActiveSyncResponse, StorageError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("snapshot lock poisoned"))?;
        state.1.retain(|_, cut| cut.expires > Instant::now());
        let key = if req.cursor == 0 {
            if state.1.len() >= MAX_CUTS {
                return Err(invalid("snapshot capacity exhausted"));
            }
            state.0 = state
                .0
                .checked_add(CURSOR_STRIDE)
                .ok_or_else(|| invalid("cursor exhausted"))?;
            let key = state.0;
            state.1.insert(
                key,
                Cut {
                    txn: db.db.begin_read()?,
                    owner,
                    bucket: req.target_bucket_id,
                    shard: req.target_shard,
                    expires: Instant::now() + CUT_LIFETIME,
                    root_after: None,
                    roots_done: false,
                    native_after: None,
                    native_done: false,
                    hmc_after: None,
                    next_cursor: key,
                },
            );
            key
        } else {
            req.cursor & !(CURSOR_STRIDE - 1)
        };
        let cut = state
            .1
            .get_mut(&key)
            .ok_or_else(|| invalid("snapshot missing or expired"))?;
        if cut.owner != owner
            || cut.bucket != req.target_bucket_id
            || cut.shard != req.target_shard
            || (req.cursor != 0 && req.cursor != cut.next_cursor)
        {
            return Err(invalid("snapshot context or cursor mismatch"));
        }
        let result = cut.page(req.limit.clamp(1, 500));
        match result {
            Ok((payload, done)) => {
                let cursor = cut
                    .next_cursor
                    .checked_add(1)
                    .ok_or_else(|| invalid("cursor exhausted"))?;
                cut.next_cursor = cursor;
                if done {
                    state.1.remove(&key);
                }
                Ok(ActiveSyncResponse::new(
                    payload,
                    !done,
                    (!done).then_some(cursor),
                ))
            }
            Err(error) => {
                state.1.remove(&key);
                Err(error)
            }
        }
    }
}
impl Cut {
    fn page(&mut self, limit: usize) -> Result<(SyncPayload, bool), StorageError> {
        let mut payload = SyncPayload::default();
        let mut size = 0usize;
        let mut scanned = 0usize;
        // Root proofs precede spend rows in the same immutable cut. They travel
        // as metadata entries and are installed exclusively in voucher_roots.
        if !self.roots_done {
            let table = self.txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let lower = self
                .root_after
                .as_deref()
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
            for row in table.range::<&str>((lower, std::ops::Bound::Unbounded))? {
                let (key, bytes) = row?;
                if bytes.value().len() > MAX_ROW_BYTES {
                    return Err(invalid("oversize root proof"));
                }
                let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(bytes.value())?;
                let tag = bs58::encode(entry.t_id).into_string();
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                if self
                    .shard
                    .is_none_or(|s| humoco_sim_core::types::canonical_voucher_shard(&parent) == s)
                {
                    if size + bytes.value().len() + tag.len() > MAX_PAGE_BYTES
                        || payload.hmc_locks.len() >= limit
                    {
                        return Ok((payload, false));
                    }
                    size += bytes.value().len() + tag.len();
                    payload.hmc_locks.push((tag, entry));
                }
                self.root_after = Some(key.value().into());
                scanned += 1;
                if scanned >= 1_000 {
                    return Ok((payload, false));
                }
            }
            self.roots_done = true;
        }
        if !self.native_done {
            let table = self.txn.open_table(TABLE_LOCKS)?;
            let lower = self
                .native_after
                .as_ref()
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
            let rows = table.range::<&[u8; 32]>((lower, std::ops::Bound::Unbounded))?;
            for row in rows {
                let (key, bytes) = row?;
                if bytes.value().len() > MAX_ROW_BYTES {
                    return Err(invalid("oversize snapshot row"));
                }
                let (record, root): (LockRecord, u64) = bincode::deserialize(bytes.value())?;
                let selected = self.shard.is_none_or(|s| {
                    u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]) == s
                }) && self.bucket.is_none_or(|b| {
                    humoco_sim_core::types::timestamp_to_bucket_id(record.created_at.0) == b
                });
                if selected {
                    let key = support::native_key(&record.parent_lock);
                    let metadata = support_metadata(&self.txn,support::TABLE_NATIVE_SUPPORT,0,&key)?;
                    let metadata_bytes = metadata.as_ref().map(bincode::serialized_size).transpose()?.unwrap_or(0) as usize;
                    if size + bytes.value().len() + metadata_bytes > MAX_PAGE_BYTES
                        || payload.locks.len() + payload.hmc_locks.len() >= limit
                    {
                        return Ok((payload, false));
                    }
                    size += bytes.value().len() + metadata_bytes;
                    if let Some(metadata) = metadata { payload.support.push(metadata); }
                    payload.locks.push((record, root));
                }
                self.native_after = Some(*key.value());
                scanned += 1;
                if scanned >= 1_000 {
                    return Ok((payload, false));
                }
            }
            self.native_done = true;
        }
        let table = self.txn.open_table(TABLE_HMC_LOCKS)?;
        let lower = self
            .hmc_after
            .as_deref()
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let rows = table.range::<&str>((lower, std::ops::Bound::Unbounded))?;
        for row in rows {
            let (key, bytes) = row?;
            if bytes.value().len() > MAX_ROW_BYTES || key.value().len() > 128 {
                return Err(invalid("oversize snapshot row"));
            }
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(bytes.value())?;
            let roots = self.txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let root = roots
                .get(entry.layer2_voucher_id.as_str())?
                .ok_or_else(|| invalid("snapshot spend lacks root anchor"))?;
            let root: crate::api::hmc::L2LockEntry = serde_json::from_slice(root.value())?;
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                &bs58::encode(root.t_id).into_string(),
            );
            let selected = self
                .shard
                .is_none_or(|s| humoco_sim_core::types::canonical_voucher_shard(&parent) == s)
                && self.bucket.is_none_or(|b| {
                    humoco_sim_core::types::timestamp_to_bucket_id(entry.created_at_ms) == b
                });
            if selected {
                let metadata = support_metadata(&self.txn,support::TABLE_CONFIRMATION_SUPPORT,1,key.value())?;
                let metadata_bytes = metadata.as_ref().map(bincode::serialized_size).transpose()?.unwrap_or(0) as usize;
                if size + bytes.value().len() + key.value().len() + metadata_bytes > MAX_PAGE_BYTES
                    || payload.locks.len() + payload.hmc_locks.len() >= limit
                {
                    return Ok((payload, false));
                }
                size += bytes.value().len() + key.value().len() + metadata_bytes;
                if let Some(metadata) = metadata { payload.support.push(metadata); }
                payload.hmc_locks.push((key.value().into(), entry));
            }
            self.hmc_after = Some(key.value().into());
            scanned += 1;
            if scanned >= 1_000 {
                return Ok((payload, false));
            }
        }
        Ok((payload, true))
    }
}

type SupportMetadata = (u8,String,support::ConfirmationSupport);
fn support_metadata(tx:&redb::ReadTransaction,table:TableDefinition<&str,&[u8]>,kind:u8,key:&str)
    -> Result<Option<SupportMetadata>,StorageError> {
    if key.len() > 128 { return Err(invalid("oversize support key")); }
    let table=tx.open_table(table)?;
    let Some(value)=table.get(key)? else { return Ok(None); };
    if value.value().len() > 2048 { return Err(invalid("oversize support metadata")); }
    Ok(Some((kind,key.into(),serde_json::from_slice(value.value())?)))
}
