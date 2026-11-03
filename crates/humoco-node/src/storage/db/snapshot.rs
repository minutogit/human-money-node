//! # Proof-Gate G2: Source-Complete State Transfer & Safe Activation (Contract G2 / S3 / S4)
//!
//! Architectural Invariants: INV-0304, INV-0307, INV-1605 (Demand-Triggered State Recovery)
//!
//! - BOUNDED MVCC CUTS: Fixed, short-lived (30s) snapshot cuts over an immutable read transaction.
//! - MONOTONIC STREAMING: Pages stream strictly monotonically (cursor_next > cursor_curr),
//!   capped at 48 KiB per page and 16 KiB per row to prevent memory exhaustion and DoS.
//! - ZERO STATE BLOAT: Synchronizes strictly objective active state (non-expired locks within
//!   root.valid_until + 30s grace horizon); legacy signatures or historical certificates are never streamed.
//! - SAFE ACTIVATION BARRIER: Shards remain `NOT_READY` until complete snapshot transfer finishes,
//!   atomic redb commit succeeds, and the local post-sync digest matches the dominant quorum digest
//!   (D_local(S) == D_dominant(S) attested by >= 14 committee members).
//! - ANTI-EMPTY-REPLICA RULE: Agreeing empty replicas or unready peers can NEVER establish completeness;
//!   explicit dominant quorum confirmation is mandatory.
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
const MAX_STORED_PARSE_BYTES: usize = 256 * 1024;
const CURSOR_STRIDE: u64 = 1 << 32;

struct Cut {
    txn: redb::ReadTransaction,
    owner: [u8; 32],
    bucket: Option<u64>,
    shard: Option<u16>,
    expires: Instant,
    root_after: Option<String>,
    roots_done: bool,
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
                if bytes.value().len() > MAX_STORED_PARSE_BYTES {
                    return Err(invalid("oversize root proof"));
                }
                let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(bytes.value())?;
                let tag = bs58::encode(entry.t_id).into_string();
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                let selected = self
                    .shard
                    .is_none_or(|s| humoco_sim_core::types::canonical_voucher_shard(&parent) == s);
                if selected {
                    if bytes.value().len() > MAX_SYNC_ROW_BYTES || tag.len() > MAX_SYNC_TAG_BYTES {
                        return Err(invalid("oversize root proof"));
                    }
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
        let table = self.txn.open_table(TABLE_HMC_LOCKS)?;
        let lower = self
            .hmc_after
            .as_deref()
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let rows = table.range::<&str>((lower, std::ops::Bound::Unbounded))?;
        for row in rows {
            let (key, bytes) = row?;
            if bytes.value().len() > MAX_STORED_PARSE_BYTES {
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
                if bytes.value().len() > MAX_SYNC_ROW_BYTES
                    || key.value().len() > MAX_SYNC_TAG_BYTES
                {
                    return Err(invalid("oversize snapshot row"));
                }
                let metadata = support_metadata(
                    &self.txn,
                    support::TABLE_CONFIRMATION_SUPPORT,
                    1,
                    key.value(),
                )?;
                let metadata_bytes = metadata
                    .as_ref()
                    .map(bincode::serialized_size)
                    .transpose()?
                    .unwrap_or(0) as usize;
                if size + bytes.value().len() + key.value().len() + metadata_bytes > MAX_PAGE_BYTES
                    || payload.hmc_locks.len() >= limit
                {
                    return Ok((payload, false));
                }
                size += bytes.value().len() + key.value().len() + metadata_bytes;
                if let Some(metadata) = metadata {
                    payload.support.push(metadata);
                }
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

type SupportMetadata = (u8, String, support::ConfirmationSupport);
fn support_metadata(
    tx: &redb::ReadTransaction,
    table: TableDefinition<&str, &[u8]>,
    kind: u8,
    key: &str,
) -> Result<Option<SupportMetadata>, StorageError> {
    if key.len() > MAX_SYNC_TAG_BYTES {
        return Err(invalid("oversize support key"));
    }
    let table = tx.open_table(table)?;
    let Some(value) = table.get(key)? else {
        return Ok(None);
    };
    if value.value().len() > 2048 {
        return Err(invalid("oversize support metadata"));
    }
    Ok(Some((
        kind,
        key.into(),
        serde_json::from_slice(value.value())?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oversize_foreign_shard_does_not_block_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot_shard_first.redb");
        let db = RedbStorage::open(&path).unwrap();

        let find_tag_for_shard = |target_shard: u16| -> (String, crate::api::hmc::L2LockEntry) {
            for i in 0u64..100_000 {
                let tid = *blake3::hash(&i.to_le_bytes()).as_bytes();
                let tag = bs58::encode(tid).into_string();
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                if humoco_sim_core::types::canonical_voucher_shard(&parent) == target_shard {
                    let entry = crate::api::hmc::L2LockEntry {
                        causal_output: None,
                        t_id: tid,
                        layer2_voucher_id: format!("voucher-{}", target_shard),
                        sender_ephemeral_pub: [1; 32],
                        receiver_ephemeral_pub_hash: None,
                        change_ephemeral_pub_hash: None,
                        layer2_signature: [0; 64],
                        trap_r: None,
                        trap_s: None,
                        encrypted_timestamp: 1,
                        created_at_ms: 1_000,
                        deletable_at: Some("50000".into()),
                        privacy_guard: None,
                    };
                    return (tag, entry);
                }
            }
            panic!("no tag found");
        };

        let (root1_tag, root1) = find_tag_for_shard(1);
        let (root2_tag, root2) = find_tag_for_shard(2);
        db.put_hmc_lock(&root1_tag, &root1).unwrap();
        db.put_hmc_lock(&root2_tag, &root2).unwrap();

        let mut lock1 = root1.clone();
        lock1.t_id = [11; 32];
        let lock1_tag = "tag1";
        db.put_hmc_lock(lock1_tag, &lock1).unwrap();

        let mut lock2 = root2.clone();
        lock2.t_id = [22; 32];
        let lock2_tag = "tag2";
        {
            let tx = db.db.begin_write().unwrap();
            {
                let mut table = tx.open_table(TABLE_HMC_LOCKS).unwrap();
                let mut oversize_entry = lock2;
                oversize_entry.trap_r = Some("x".repeat(20 * 1024));
                let json = serde_json::to_vec(&oversize_entry).unwrap();
                table.insert(lock2_tag, json.as_slice()).unwrap();
            }
            tx.commit().unwrap();
        }

        let cuts = SnapshotCuts::default();
        let owner = [99u8; 32];

        // 1. Snapshotting shard 1 succeeds despite oversize row in shard 2
        let mut req_shard1 = ActiveSyncRequest::new(0, 100);
        req_shard1.target_shard = Some(1);
        let resp1 = cuts
            .page(&db, req_shard1, owner)
            .expect("snapshot shard 1 succeeds");
        assert_eq!(resp1.payload.hmc_locks.len(), 2);
        assert_eq!(resp1.payload.hmc_locks[0].0, root1_tag);
        assert_eq!(resp1.payload.hmc_locks[1].0, lock1_tag);

        // 2. Snapshotting shard 2 fails due to oversize row
        let mut req_shard2 = ActiveSyncRequest::new(0, 100);
        req_shard2.target_shard = Some(2);
        let res2 = cuts.page(&db, req_shard2, owner);
        assert!(res2.is_err());
    }
}
