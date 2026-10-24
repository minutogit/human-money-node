//! Disk-backed full cuts. Receiving pages never changes the productive registry.
use super::*;
use crate::{api::hmc::{L2LockEntry, verify_l2_lock_entry_signature}, network::framing::SyncPayload};
const PROJECTION: TableDefinition<&[u8;32], &[u8]> = TableDefinition::new("sync_projection");
const PAGE: usize = 500;
fn invalid(message: &str) -> StorageError { StorageError::DurableCommitFailed(message.into()) }
/// A temporary redb cut with a small cache. Drop removes it, including on cancellation.
pub struct ShardStage {
    pub(crate) storage: RedbStorage,
    _file: tempfile::NamedTempFile,
    pub(crate) shard: u16,
    now: u64,
    cuts: snapshot::SnapshotCuts,
}
impl ShardStage {
    pub fn new(shard: u16, now: u64) -> Result<Self, StorageError> {
        let file = tempfile::NamedTempFile::new()?;
        let mut builder = Database::builder();
        builder.set_cache_size(64 * 1024);
        let db = builder.create_file(file.reopen()?)?;
        let storage = RedbStorage::initialize_database(db, file.path())?;
        let tx = storage.db.begin_write()?;
        tx.open_table(PROJECTION)?;
        tx.commit()?;
        Ok(Self { storage, _file: file, shard, now, cuts: snapshot::SnapshotCuts::default() })
    }
    /// Returns the path to the temporary database backing this stage.
    pub fn storage_path(&self) -> &std::path::Path {
        self.storage.path()
    }
    /// Validate one bounded page and spill immediately. No whole-cut RAM vectors.
    pub fn append(&self, page: SyncPayload) -> Result<(), StorageError> {
        if page.locks.len() + page.hmc_locks.len() > PAGE || bincode::serialized_size(&page)? > 64*1024 {
            return Err(invalid("staging page ceiling exceeded"));
        }
        let tx = self.storage.db.begin_write()?;
        for (tag, entry) in page.hmc_locks {
            if tag.len() > 128 || serde_json::to_vec(&entry)?.len() > 16*1024
                || !verify_l2_lock_entry_signature(&entry, &tag) { return Err(invalid("invalid staged HMC row")); }
            if roots::is_root(&tag, &entry) {
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                if humoco_sim_core::types::canonical_voucher_shard(&parent) != self.shard { return Err(invalid("foreign staged root")); }
                roots::put(&tx, &entry)?;
                continue;
            }
            let table = tx.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let root = table.get(entry.layer2_voucher_id.as_str())?.ok_or_else(|| invalid("staged spend lacks root"))?;
            let root: L2LockEntry = serde_json::from_slice(root.value())?;
            let validity = roots::root_valid_until(&root)?;
            if entry.causal_output.as_ref().is_some_and(|proof| !proof.verify() || proof.is_root
                || proof.transaction_id != entry.t_id || proof.sender_pubkey != entry.sender_ephemeral_pub
                || proof.voucher_id != entry.layer2_voucher_id || proof.root_valid_until_ms != validity) {
                return Err(invalid("invalid staged output commitment"));
            }
            let record = LockRecord::new(*blake3::hash(tag.as_bytes()).as_bytes(), entry.sender_ephemeral_pub,
                entry.t_id.to_vec(), SimTime(entry.created_at_ms), SimTime(validity));
            Self::project(&tx, &record, self.now)?;
            let bytes = serde_json::to_vec(&entry)?;
            if tx.open_table(TABLE_HMC_LOCKS)?.insert(tag.as_str(), bytes.as_slice())?.is_some() { return Err(invalid("duplicate staged collision key")); }
        }
        for (mut record, root) in page.locks {
            let expected = LockRecord::new(record.parent_lock, record.receiver_pub, record.nonce.clone(), record.created_at, record.valid_until);
            if record.id != expected.id || record.valid_until.0 > root || record.nonce.len() > 16*1024
                || u16::from_be_bytes([record.parent_lock[0], record.parent_lock[1]]) != self.shard { return Err(invalid("invalid staged native row")); }
            // A source's historical status/signers cannot establish support.
            record.signers.clear();
            Self::project(&tx, &record, self.now)?;
            let bytes = bincode::serialize(&(record.clone(), root))?;
            if tx.open_table(TABLE_LOCKS)?.insert(&record.parent_lock, bytes.as_slice())?.is_some() { return Err(invalid("duplicate staged native key")); }
        }
        tx.commit()?;
        Ok(())
    }
    fn project(tx: &redb::WriteTransaction, row: &LockRecord, now: u64) -> Result<(), StorageError> {
        if row.valid_until.0 <= now || row.status.is_void() { return Ok(()); }
        let bytes = bincode::serialize(row)?;
        if tx.open_table(PROJECTION)?.insert(&row.parent_lock, bytes.as_slice())?.is_some() { return Err(invalid("ambiguous staged projection")); }
        Ok(())
    }
    /// Streaming canonical fingerprint; the B-tree supplies the canonical order.
    pub fn digest(&self) -> Result<[u8;32], StorageError> {
        let tx = self.storage.db.begin_read()?;
        let mut hash = blake3::Hasher::new();
        hash.update(&[0x01]);
        hash.update(&self.shard.to_le_bytes());
        for row in tx.open_table(PROJECTION)?.iter()? {
            let (_, value) = row?;
            let row: LockRecord = bincode::deserialize(value.value())?;
            hash.update(&row.parent_lock); hash.update(&row.receiver_pub);
            hash.update(&row.nonce); hash.update(&row.id);
        }
        Ok(*hash.finalize().as_bytes())
    }
    /// Bounded, roots-first replay into RAM AFTER the productive commit.
    pub fn page(&self, cursor: u64) -> Result<crate::network::framing::ActiveSyncResponse, StorageError> {
        // Internal cursor uses its own authenticated local identity and fixed cut.
        self.cuts.page(&self.storage,
            crate::network::framing::ActiveSyncRequest::new(cursor, PAGE), [0;32])
    }
}

impl RedbStorage {
    /// The caller owns a drained per-shard admission fence and a frozen live
    /// quorum witness. Current quorum agreement establishes support; source
    /// status fields or historical signature bundles do not establish it.
    pub(crate) fn install_shard_cut(&self, stage: &ShardStage, expected: [u8;32], class: u8,
        context: [u8;32], witnesses: usize) -> Result<(), StorageError> {
        if !self.is_signing_history_healthy() || !(1..=2).contains(&class)
            || witnesses == 0 || (class == 2 && witnesses < 14) || stage.digest()? != expected {
            return Err(invalid("unqualified shard installation"));
        }
        let source = stage.storage.db.begin_read()?;
        let mut tx = self.db.begin_write()?;
        tx.set_durability(redb::Durability::Immediate);
        // All validation, omission quarantine, replacement, indexes and support
        // share ONE transaction. Every error below rolls the entire cut back.
        for item in source.open_table(roots::TABLE_VOUCHER_ROOTS)?.iter()? {
            let (_, value) = item?;
            roots::put(&tx, &serde_json::from_slice::<L2LockEntry>(value.value())?)?;
        }
        let mut after = None;
        loop {
            let mut page = Vec::new();
            {
                let table = tx.open_table(TABLE_LOCKS)?;
                let lower = after.as_ref().map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                for row in table.range::<&[u8;32]>((lower, std::ops::Bound::Unbounded))?.take(16) {
                    let (key, value) = row?; if value.value().len() > 16*1024 { return Err(invalid("oversize local native row")); } page.push((*key.value(), value.value().to_vec()));
                }
            }
            if page.is_empty() { break; }
            for (key, bytes) in page {
                after = Some(key);
                if u16::from_be_bytes([key[0], key[1]]) != stage.shard { continue; }
                let (old, old_root): (LockRecord, u64) = bincode::deserialize(&bytes)?;
                let incoming = source.open_table(TABLE_LOCKS)?.get(&key)?.map(|v| bincode::deserialize::<(LockRecord,u64)>(v.value())).transpose()?;
                if incoming.as_ref().is_some_and(|(_,root)|*root != old_root) { return Err(invalid("native root lifetime changed")); }
                let old_class = old.status.confirmation_class();
                if old.valid_until.0 > stage.now && !old.status.is_void() {
                    if incoming.as_ref().is_none_or(|(new,_)| new.valid_until.0 <= stage.now || new.status.is_void()) && old_class > 0 {
                        return Err(invalid("quorum cut omits confirmed native choice"));
                    }
                    if let Some((new,_)) = &incoming {
                        if new.id != old.id && (old_class > class || (old_class == class
                            && humoco_sim_core::crypto::compute_canonical_hash(&key,&old.receiver_pub,&old.nonce)
                             < humoco_sim_core::crypto::compute_canonical_hash(&key,&new.receiver_pub,&new.nonce))) {
                            return Err(invalid("quorum cut loses native class/hash ordering"));
                        }
                    }
                }
                tx.open_table(TABLE_PROVISIONAL_LOCKS)?.insert(&key,bytes.as_slice())?;
                tx.open_table(TABLE_LOCKS)?.remove(&key)?;
            }
        }
        let mut after: Option<String> = None;
        loop {
            let mut page = Vec::new();
            {
                let table = tx.open_table(TABLE_HMC_LOCKS)?;
                let lower = after.as_deref().map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                for row in table.range::<&str>((lower, std::ops::Bound::Unbounded))?.take(16) {
                    let (key, value) = row?; if value.value().len() > 16*1024 || key.value().len() > 128 { return Err(invalid("oversize local HMC row")); } page.push((key.value().to_string(), value.value().to_vec()));
                }
            }
            if page.is_empty() { break; }
            for (tag, bytes) in page {
                after = Some(tag.clone());
                let old: L2LockEntry = serde_json::from_slice(&bytes)?;
                let roots = tx.open_table(roots::TABLE_VOUCHER_ROOTS)?;
                let root = roots.get(old.layer2_voucher_id.as_str())?.ok_or_else(|| invalid("local spend lacks root"))?;
                let root: L2LockEntry = serde_json::from_slice(root.value())?;
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode(root.t_id).into_string());
                if humoco_sim_core::types::canonical_voucher_shard(&parent) != stage.shard { continue; }
                let incoming = source.open_table(TABLE_HMC_LOCKS)?.get(tag.as_str())?.map(|v| serde_json::from_slice::<L2LockEntry>(v.value())).transpose()?;
                let support = tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
                let old_fact = support.get(tag.as_str())?.map(|v| serde_json::from_slice::<support::ConfirmationSupport>(v.value())).transpose()?;
                let old_class = old_fact.as_ref().filter(|f| f.child == old.t_id).map_or(0, |f| f.class);
                if roots::root_valid_until(&root)? > stage.now {
                    if incoming.is_none() && old_class > 0 { return Err(invalid("quorum cut omits verified support")); }
                    if let Some(new) = &incoming {
                        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                        if old.t_id != new.t_id && (old_class > class || (old_class == class
                            && crate::storage::compute_hmc_canonical_hash(&parent,&old.sender_ephemeral_pub,&old.t_id)
                             < crate::storage::compute_hmc_canonical_hash(&parent,&new.sender_ephemeral_pub,&new.t_id))) {
                            return Err(invalid("quorum cut loses HMC class/hash ordering"));
                        }
                    }
                }
                tx.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?.insert(tag.as_str(),bytes.as_slice())?;
                tx.open_table(TABLE_HMC_LOCKS)?.remove(tag.as_str())?;
                tx.open_table(TABLE_HMC_VOUCHER_INDEX)?.remove((old.layer2_voucher_id.as_str(),tag.as_str()))?;
            }
        }
        for item in source.open_table(TABLE_LOCKS)?.iter()? {
            let (key, value) = item?;
            let (mut row, root): (LockRecord,u64) = bincode::deserialize(value.value())?;
            if row.valid_until.0 <= stage.now || row.status.is_void() { continue; }
            row.status = if class == 2 { humoco_sim_core::types::LockStatus::Final { sigs: witnesses } }
                else { humoco_sim_core::types::LockStatus::Provisional { sigs: witnesses, required: witnesses } };
            if let Some(old) = tx.open_table(TABLE_PROVISIONAL_LOCKS)?.get(key.value())? {
                let (old,_): (LockRecord,u64) = bincode::deserialize(old.value())?;
                if old.id == row.id && old.status.confirmation_class() > row.status.confirmation_class() { row.status = old.status; }
            }
            let bytes = bincode::serialize(&(row,root))?;
            tx.open_table(TABLE_LOCKS)?.insert(key.value(), bytes.as_slice())?;
            tx.open_table(TABLE_PROVISIONAL_LOCKS)?.remove(key.value())?;
            tx.open_table(TABLE_TTL_INDEX)?.insert((root.saturating_add(30_000)/1000,key.value()),())?;
        }
        for item in source.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (tag, value) = item?;
            let row: L2LockEntry = serde_json::from_slice(value.value())?;
            let roots = source.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let root = roots.get(row.layer2_voucher_id.as_str())?.ok_or_else(|| invalid("staged root missing"))?;
            let root: L2LockEntry = serde_json::from_slice(root.value())?;
            let validity = roots::root_valid_until(&root)?;
            if validity <= stage.now { continue; }
            tx.open_table(TABLE_HMC_LOCKS)?.insert(tag.value(),value.value())?;
            tx.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?.remove(tag.value())?;
            tx.open_table(TABLE_HMC_VOUCHER_INDEX)?.insert((row.layer2_voucher_id.as_str(),tag.value()),())?;
            tx.open_table(TABLE_HMC_TTL_INDEX)?.insert((validity.saturating_add(30_000)/1000,tag.value()),())?;
            let mut fact = support::ConfirmationSupport { child: row.t_id, parent: *blake3::hash(tag.value().as_bytes()).as_bytes(),
                class, root_valid_until_ms: validity, verified_context: context };
            if let Some(old) = tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)?.get(tag.value())? {
                let old: support::ConfirmationSupport = serde_json::from_slice(old.value())?;
                if old.child == fact.child && old.class > fact.class { fact = old; }
            }
            let bytes = serde_json::to_vec(&fact)?;
            tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)?.insert(tag.value(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }
}
impl RedbStorage {
    /// External-sort committed objective rows with a 64 KiB cache instead of a
    /// whole-shard Vec. One read transaction supplies the complete source cut.
    pub fn committed_shard_digest(&self, shard: u16, now: u64) -> Result<([u8;32],u64),StorageError> {
        let sorted = ShardStage::new(shard, now)?;
        let source = self.db.begin_read()?;
        // Native rows already have canonical parent order. Avoid copying an
        // otherwise native-only cut into an unnecessary external sort tree.
        if source.open_table(TABLE_HMC_LOCKS)?.len()? == 0 {
            let mut hash = blake3::Hasher::new(); hash.update(&[0x01]); hash.update(&shard.to_le_bytes());
            let mut count = 0u64;
            for item in source.open_table(TABLE_LOCKS)?.iter()? {
                let (_,value) = item?;
                let (row,_): (LockRecord,u64) = bincode::deserialize(value.value())?;
                if u16::from_be_bytes([row.parent_lock[0],row.parent_lock[1]]) == shard && !row.status.is_void() && row.valid_until.0 > now {
                    hash.update(&row.parent_lock); hash.update(&row.receiver_pub); hash.update(&row.nonce); hash.update(&row.id); count += 1;
                }
            }
            return Ok((*hash.finalize().as_bytes(),count));
        }
        let tx = sorted.storage.db.begin_write()?;
        let mut count = 0u64;
        for item in source.open_table(TABLE_LOCKS)?.iter()? {
            let (_,value) = item?;
            let (row,_): (LockRecord,u64) = bincode::deserialize(value.value())?;
            if u16::from_be_bytes([row.parent_lock[0],row.parent_lock[1]]) == shard && !row.status.is_void() && row.valid_until.0 > now {
                ShardStage::project(&tx,&row,now)?; count += 1;
            }
        }
        let roots = source.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        for item in source.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (tag,value) = item?;
            let row: L2LockEntry = serde_json::from_slice(value.value())?;
            let root = roots.get(row.layer2_voucher_id.as_str())?.ok_or_else(||invalid("committed spend lacks root"))?;
            let root: L2LockEntry = serde_json::from_slice(root.value())?;
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode(root.t_id).into_string());
            let validity = roots::root_valid_until(&root)?;
            if humoco_sim_core::types::canonical_voucher_shard(&parent) == shard && validity > now {
                let row = LockRecord::new(*blake3::hash(tag.value().as_bytes()).as_bytes(),row.sender_ephemeral_pub,
                    row.t_id.to_vec(),SimTime(row.created_at_ms),SimTime(validity));
                ShardStage::project(&tx,&row,now)?; count += 1;
            }
        }
        tx.commit()?;
        Ok((sorted.digest()?,count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    #[test]
    fn confirmed_omission_rolls_back_root_registration_and_all_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let author = crate::identity::NodeIdentity::generate();
        let mut root = L2LockEntry {
            causal_output: None,layer2_voucher_id:"atomic-root".into(),t_id:[42;32],sender_ephemeral_pub:*author.node_pubkey(),
            receiver_ephemeral_pub_hash:None,change_ephemeral_pub_hash:None,layer2_signature:[0;64],trap_r:None,trap_s:None,
            encrypted_timestamp:0,created_at_ms:1_000,deletable_at:Some("600000".into()),privacy_guard:None,
        };
        let tag = bs58::encode(root.t_id).into_string();
        let payload = crate::api::hmc::calculate_l2_payload_hash_raw(crate::api::hmc::TRAP_NONE_PLACEHOLDER,&tag,&root.t_id,&root.sender_ephemeral_pub,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,crate::api::hmc::TRAP_NONE_PLACEHOLDER,0,1_000,root.deletable_at.as_deref(),"");
        root.layer2_signature = author.signing_key().sign(&payload).to_bytes();
        let shard = humoco_sim_core::types::canonical_voucher_shard(&humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag));
        let mut parent = [3;32]; parent[..2].copy_from_slice(&shard.to_be_bytes());
        let mut old = LockRecord::new(parent,[4;32],vec![5],SimTime(1_000),SimTime(600_000));
        old.status = humoco_sim_core::types::LockStatus::Final { sigs:14 };
        db.put_lock(&old,600_000).unwrap();
        let stage = ShardStage::new(shard,1_000).unwrap();
        stage.append(SyncPayload { locks:vec![],hmc_locks:vec![(tag,root.clone())] }).unwrap();
        assert!(db.install_shard_cut(&stage,stage.digest().unwrap(),2,[1;32],14).is_err());
        assert!(db.voucher_root(&root.layer2_voucher_id).unwrap().is_none());
        assert_eq!(db.get_lock(&parent).unwrap().unwrap().0.id,old.id);
        assert!(db.get_provisional_lock(&parent).unwrap().is_none());
    }
    #[test]
    fn lower_current_quorum_never_downgrades_recovered_final_native_choice() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let mut old = LockRecord::new([3;32],[4;32],vec![5],SimTime(1_000),SimTime(600_000));
        old.status = humoco_sim_core::types::LockStatus::Final { sigs:14 };
        db.put_lock(&old,600_000).unwrap();
        let shard = u16::from_be_bytes([3,3]);
        let stage = ShardStage::new(shard,1_000).unwrap();
        let mut incoming = old.clone(); incoming.status = humoco_sim_core::types::LockStatus::Pending;
        stage.append(SyncPayload { locks:vec![(incoming,600_000)],hmc_locks:vec![] }).unwrap();
        db.install_shard_cut(&stage,stage.digest().unwrap(),1,[1;32],3).unwrap();
        assert_eq!(db.get_lock(&old.parent_lock).unwrap().unwrap().0.status.confirmation_class(),2);
    }
}
