//! A committed snapshot projects collision rows into their canonical root shard.
use super::*;
impl RedbStorage {
    /// Uses one redb cut, excludes pending RAM, and never treats root proofs as
    /// spends. The original SST parent key remains in the hashed projection.
    pub fn committed_shard_records(&self, shard: u16, now: u64) -> Result<Vec<LockRecord>, StorageError> {
        let txn = self.db.begin_read()?;
        let mut records = Vec::new();
        for row in txn.open_table(TABLE_LOCKS)?.iter()? {
            let (_, value) = row?;
            let (record, _): (LockRecord, u64) = bincode::deserialize(value.value())?;
            if u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]) == shard && !record.status.is_void() && record.valid_until.0 > now { records.push(record); }
        }
        let roots = txn.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        for row in txn.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (tag, value) = row?;
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(value.value())?;
            let Some(root) = roots.get(entry.layer2_voucher_id.as_str())? else { return Err(StorageError::DurableCommitFailed("committed spend lacks root proof".into())); };
            let root: crate::api::hmc::L2LockEntry = serde_json::from_slice(root.value())?;
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode(root.t_id).into_string());
            let validity = roots::root_valid_until(&root)?;
            if humoco_sim_core::types::canonical_voucher_shard(&parent) == shard && validity > now {
                records.push(LockRecord::new(*blake3::hash(tag.value().as_bytes()).as_bytes(), entry.sender_ephemeral_pub, entry.t_id.to_vec(), SimTime(entry.created_at_ms), SimTime(validity)));
            }
        }
        Ok(records)
    }
}
