//! A committed snapshot projects collision rows into their canonical root shard.
use super::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedShardRecord {
    pub id: [u8; 32],
    pub parent_lock: [u8; 32],
    pub receiver_pub: [u8; 32],
    pub nonce: Vec<u8>,
    pub created_at_ms: u64,
}

impl CommittedShardRecord {
    pub fn new(
        parent_lock: [u8; 32],
        receiver_pub: [u8; 32],
        nonce: Vec<u8>,
        created_at_ms: u64,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&parent_lock);
        hasher.update(&receiver_pub);
        hasher.update(&nonce);
        let id = *hasher.finalize().as_bytes();
        Self {
            id,
            parent_lock,
            receiver_pub,
            nonce,
            created_at_ms,
        }
    }
}

impl RedbStorage {
    /// Uses one redb cut, excludes pending RAM, and never treats root proofs as
    /// spends. The original SST parent key remains in the hashed projection.
    pub fn committed_shard_records(
        &self,
        shard: u16,
        now: u64,
    ) -> Result<Vec<CommittedShardRecord>, StorageError> {
        let txn = self.db.begin_read()?;
        let mut records = Vec::new();
        let roots = txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        for row in txn.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (tag, value) = row?;
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(value.value())?;
            let Some(root) = roots.get(entry.layer2_voucher_id.as_str())? else {
                return Err(StorageError::DurableCommitFailed(
                    "committed spend lacks root proof".into(),
                ));
            };
            let root: crate::api::hmc::L2LockEntry = serde_json::from_slice(root.value())?;
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                &bs58::encode(root.t_id).into_string(),
            );
            let validity = roots::root_valid_until(&root)?;
            if humoco_sim_core::types::canonical_voucher_shard(&parent) == shard && validity > now {
                records.push(CommittedShardRecord::new(
                    *blake3::hash(tag.value().as_bytes()).as_bytes(),
                    entry.sender_ephemeral_pub,
                    entry.t_id.to_vec(),
                    entry.created_at_ms,
                ));
            }
        }
        Ok(records)
    }
}
