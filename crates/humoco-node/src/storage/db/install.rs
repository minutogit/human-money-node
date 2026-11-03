//! Disk-backed full cuts. Receiving pages never changes the productive registry.
use super::*;
use crate::{
    api::hmc::{verify_l2_lock_entry_signature, L2LockEntry},
    network::framing::SyncPayload,
};
const PROJECTION: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("sync_projection");
const PAGE: usize = 500;
const MAX_STAGE_ENTRIES: usize = 50_000;
const MAX_STAGE_BYTES: u64 = 32 * 1024 * 1024;
fn invalid(message: &str) -> StorageError {
    StorageError::DurableCommitFailed(message.into())
}
/// A temporary redb cut with a small cache. Drop removes it, including on cancellation.
pub struct ShardStage {
    pub(crate) storage: RedbStorage,
    _file: tempfile::NamedTempFile,
    pub(crate) shard: u16,
    now: u64,
    cuts: snapshot::SnapshotCuts,
    total_entries: std::sync::atomic::AtomicUsize,
    total_bytes: std::sync::atomic::AtomicU64,
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
        Ok(Self {
            storage,
            _file: file,
            shard,
            now,
            cuts: snapshot::SnapshotCuts::default(),
            total_entries: std::sync::atomic::AtomicUsize::new(0),
            total_bytes: std::sync::atomic::AtomicU64::new(0),
        })
    }
    /// Returns the path to the temporary database backing this stage.
    pub fn storage_path(&self) -> &std::path::Path {
        self.storage.path()
    }
    /// Validate one bounded page and spill immediately. No whole-cut RAM vectors.
    pub fn append(&self, page: SyncPayload) -> Result<(), StorageError> {
        let page_entries = page.support.len() + page.hmc_locks.len();
        let page_bytes = bincode::serialized_size(&page)?;
        if page.support.len() > PAGE
            || page.hmc_locks.len() > PAGE
            || page_bytes > 64 * 1024
        {
            return Err(invalid("staging page ceiling exceeded"));
        }
        let prev_entries = self
            .total_entries
            .fetch_add(page_entries, std::sync::atomic::Ordering::SeqCst);
        let prev_bytes = self
            .total_bytes
            .fetch_add(page_bytes, std::sync::atomic::Ordering::SeqCst);
        if prev_entries + page_entries > MAX_STAGE_ENTRIES
            || prev_bytes + page_bytes > MAX_STAGE_BYTES
        {
            return Err(invalid("staging total ceiling exceeded"));
        }
        let tx = self.storage.db.begin_write()?;
        for (_kind, key, fact) in page.support {
            if key.len() > MAX_SYNC_TAG_BYTES || !(1..=2).contains(&fact.class) {
                return Err(invalid("invalid support metadata"));
            }
            let bytes = serde_json::to_vec(&fact)?;
            if tx
                .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                .insert(key.as_str(), bytes.as_slice())?
                .is_some()
            {
                return Err(invalid("duplicate support metadata"));
            }
        }
        for (tag, entry) in page.hmc_locks {
            if tag.len() > MAX_SYNC_TAG_BYTES
                || serde_json::to_vec(&entry)?.len() > MAX_SYNC_ROW_BYTES
                || !verify_l2_lock_entry_signature(&entry, &tag)
            {
                return Err(invalid("invalid staged HMC row"));
            }
            if roots::is_root(&tag, &entry) {
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
                if humoco_sim_core::types::canonical_voucher_shard(&parent) != self.shard {
                    return Err(invalid("foreign staged root"));
                }
                roots::put(&tx, &entry)?;
                continue;
            }
            let table = tx.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let root = table
                .get(entry.layer2_voucher_id.as_str())?
                .ok_or_else(|| invalid("staged spend lacks root"))?;
            let root: L2LockEntry = serde_json::from_slice(root.value())?;
            let validity = roots::root_valid_until(&root)?;
            if entry.causal_output.as_ref().is_some_and(|proof| {
                !proof.verify()
                    || proof.is_root
                    || proof.transaction_id != entry.t_id
                    || proof.sender_pubkey != entry.sender_ephemeral_pub
                    || proof.voucher_id != entry.layer2_voucher_id
                    || proof.root_valid_until_ms != validity
            }) {
                return Err(invalid("invalid staged output commitment"));
            }
            let record = projection::CommittedShardRecord::new(
                *blake3::hash(tag.as_bytes()).as_bytes(),
                entry.sender_ephemeral_pub,
                entry.t_id.to_vec(),
                entry.created_at_ms,
            );
            Self::project(&tx, &record, self.now, validity)?;
            let bytes = serde_json::to_vec(&entry)?;
            if tx
                .open_table(TABLE_HMC_LOCKS)?
                .insert(tag.as_str(), bytes.as_slice())?
                .is_some()
            {
                return Err(invalid("duplicate staged collision key"));
            }
        }
        tx.commit()?;
        Ok(())
    }
    fn project(
        tx: &redb::WriteTransaction,
        row: &projection::CommittedShardRecord,
        now: u64,
        validity: u64,
    ) -> Result<(), StorageError> {
        if validity <= now {
            return Ok(());
        }
        let bytes = bincode::serialize(row)?;
        if tx
            .open_table(PROJECTION)?
            .insert(&row.parent_lock, bytes.as_slice())?
            .is_some()
        {
            return Err(invalid("ambiguous staged projection"));
        }
        Ok(())
    }
    /// Streaming canonical fingerprint; the B-tree supplies the canonical order.
    pub fn digest(&self) -> Result<[u8; 32], StorageError> {
        let tx = self.storage.db.begin_read()?;
        let mut hash = blake3::Hasher::new();
        hash.update(&[0x01]);
        hash.update(&self.shard.to_le_bytes());
        for row in tx.open_table(PROJECTION)?.iter()? {
            let (_, value) = row?;
            let row: projection::CommittedShardRecord = bincode::deserialize(value.value())?;
            hash.update(&row.parent_lock);
            hash.update(&row.receiver_pub);
            hash.update(&row.nonce);
            hash.update(&row.id);
        }
        Ok(*hash.finalize().as_bytes())
    }
    pub(crate) fn support_digest(&self) -> Result<[u8; 32], StorageError> {
        self.storage.inherited_support_digest(self.shard, self.now)
    }
    /// Bounded, roots-first replay into RAM AFTER the productive commit.
    pub fn page(
        &self,
        cursor: u64,
    ) -> Result<crate::network::framing::ActiveSyncResponse, StorageError> {
        // Internal cursor uses its own authenticated local identity and fixed cut.
        self.cuts.page(
            &self.storage,
            crate::network::framing::ActiveSyncRequest::new(cursor, PAGE),
            [0; 32],
        )
    }
}

impl RedbStorage {
    /// The caller owns a drained per-shard admission fence and a frozen live
    /// quorum witness. Current quorum agreement establishes support; source
    /// status fields or historical signature bundles do not establish it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_shard_cut(
        &self,
        stage: &ShardStage,
        expected: [u8; 32],
        class: u8,
        context: [u8; 32],
        witnesses: usize,
        inherited: Option<&support::VerifiedInheritedCut>,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), StorageError> {
        let support_is_quorum_verified = if let Some(proof) = inherited {
            proof.validate(stage, expected)?
        } else if stage
            .storage
            .db
            .begin_read()?
            .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
            .len()?
            != 0
        {
            return Err(invalid("inherited support lacks qualified admission"));
        } else {
            false
        };
        if !self.is_signing_history_healthy()
            || !(1..=2).contains(&class)
            || witnesses == 0
            || (class == 2 && witnesses < 14)
            || stage.digest()? != expected
        {
            return Err(invalid("unqualified shard installation"));
        }
        let source = stage.storage.db.begin_read()?;
        let mut tx = self.db.begin_write()?;
        tx.set_durability(redb::Durability::Immediate);
        // All validation, omission quarantine, replacement, indexes and support
        // share ONE transaction. Every error below rolls the entire cut back.
        for item in source.open_table(roots::TABLE_VOUCHER_ROOTS)?.iter()? {
            let (key, value) = item?;
            let root: L2LockEntry = serde_json::from_slice(value.value())?;
            if key.value() != root.layer2_voucher_id.as_str() {
                return Err(invalid("sync root key mismatch"));
            }
            let root_tag = bs58::encode(root.t_id).into_string();
            if !roots::is_root(&root_tag, &root)
                || !crate::api::hmc::verify_l2_lock_entry_signature(&root, &root_tag)
                || humoco_sim_core::types::canonical_voucher_shard(
                    &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
                ) != stage.shard
            {
                return Err(invalid("invalid sync root"));
            }
            let is_canonical = root.layer2_voucher_id.len() == 64
                && root
                    .layer2_voucher_id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit());
            let is_new = tx
                .open_table(roots::TABLE_VOUCHER_ROOTS)?
                .get(root.layer2_voucher_id.as_str())?
                .is_none();
            if is_new && is_canonical && root.causal_output.is_none() {
                return Err(invalid("new canonical sync root lacks author output proof"));
            }
            roots::put(&tx, &root)?;
        }
        let mut after: Option<String> = None;
        loop {
            let mut page = Vec::new();
            {
                let table = tx.open_table(TABLE_HMC_LOCKS)?;
                let lower = after
                    .as_deref()
                    .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                for row in table
                    .range::<&str>((lower, std::ops::Bound::Unbounded))?
                    .take(16)
                {
                    let (key, value) = row?;
                    if value.value().len() > MAX_SYNC_ROW_BYTES
                        || key.value().len() > MAX_SYNC_TAG_BYTES
                    {
                        return Err(invalid("oversize local HMC row"));
                    }
                    page.push((key.value().to_string(), value.value().to_vec()));
                }
            }
            if page.is_empty() {
                break;
            }
            for (tag, bytes) in page {
                after = Some(tag.clone());
                let old: L2LockEntry = serde_json::from_slice(&bytes)?;
                let roots = tx.open_table(roots::TABLE_VOUCHER_ROOTS)?;
                let root_opt = roots.get(old.layer2_voucher_id.as_str())?;
                let root: L2LockEntry = match root_opt {
                    Some(r) => serde_json::from_slice(r.value())?,
                    None => {
                        warn!("Orphaned HMC spend {} lacks voucher root anchor; isolating into provisional storage", tag);
                        tx.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?
                            .insert(tag.as_str(), bytes.as_slice())?;
                        tx.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?
                            .insert((old.layer2_voucher_id.as_str(), tag.as_str()), ())?;
                        tx.open_table(TABLE_HMC_LOCKS)?.remove(tag.as_str())?;
                        tx.open_table(TABLE_HMC_VOUCHER_INDEX)?
                            .remove((old.layer2_voucher_id.as_str(), tag.as_str()))?;
                        continue;
                    }
                };
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                    &bs58::encode(root.t_id).into_string(),
                );
                if humoco_sim_core::types::canonical_voucher_shard(&parent) != stage.shard {
                    continue;
                }
                let incoming = source
                    .open_table(TABLE_HMC_LOCKS)?
                    .get(tag.as_str())?
                    .map(|v| serde_json::from_slice::<L2LockEntry>(v.value()))
                    .transpose()?;
                let support = tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)?;
                let old_fact = support
                    .get(tag.as_str())?
                    .map(|v| serde_json::from_slice::<support::ConfirmationSupport>(v.value()))
                    .transpose()?;
                let old_class = old_fact
                    .as_ref()
                    .filter(|f| f.child == old.t_id)
                    .map_or(0, |f| f.class);
                let incoming_id = incoming.as_ref().map(|new| new.t_id);
                let new_class = source
                    .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                    .get(tag.as_str())?
                    .map(|v| serde_json::from_slice::<support::ConfirmationSupport>(v.value()))
                    .transpose()?
                    .filter(|f| incoming_id.as_ref().is_some_and(|id| f.child == *id))
                    .map_or(class, |f| {
                        class.max(if support_is_quorum_verified {
                            f.class
                        } else {
                            0
                        })
                    });
                if roots::root_valid_until(&root)? > stage.now {
                    if incoming.is_none() && old_class > 0 {
                        return Err(invalid("quorum cut omits verified support"));
                    }
                    if let Some(new) = &incoming {
                        if old.t_id == new.t_id
                            && (old.sender_ephemeral_pub != new.sender_ephemeral_pub
                                || old.layer2_voucher_id != new.layer2_voucher_id)
                        {
                            return Err(invalid("inconsistent HMC child identity"));
                        }
                        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                        if old.t_id != new.t_id
                            && (old_class > new_class
                                || (old_class == new_class
                                    && crate::storage::compute_hmc_canonical_hash(
                                        &parent,
                                        &old.sender_ephemeral_pub,
                                        &old.t_id,
                                    ) < crate::storage::compute_hmc_canonical_hash(
                                        &parent,
                                        &new.sender_ephemeral_pub,
                                        &new.t_id,
                                    )))
                        {
                            return Err(invalid("quorum cut loses HMC class/hash ordering"));
                        }
                    }
                }
                tx.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?
                    .insert(tag.as_str(), bytes.as_slice())?;
                tx.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?
                    .insert((old.layer2_voucher_id.as_str(), tag.as_str()), ())?;
                tx.open_table(TABLE_HMC_LOCKS)?.remove(tag.as_str())?;
                tx.open_table(TABLE_HMC_VOUCHER_INDEX)?
                    .remove((old.layer2_voucher_id.as_str(), tag.as_str()))?;
            }
        }

        for item in source.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (tag, value) = item?;
            let row: L2LockEntry = serde_json::from_slice(value.value())?;
            let roots = source.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let root = roots
                .get(row.layer2_voucher_id.as_str())?
                .ok_or_else(|| invalid("staged root missing"))?;
            let root: L2LockEntry = serde_json::from_slice(root.value())?;
            let validity = roots::root_valid_until(&root)?;
            if validity <= stage.now {
                continue;
            }
            // Same-shard occupants were moved to provisional storage above.
            // Any surviving occupant belongs to another shard and is protected
            // by a different admission fence.
            if tx.open_table(TABLE_HMC_LOCKS)?.get(tag.value())?.is_some() {
                return Err(invalid("HMC collision key belongs to another shard"));
            }
            let prov_voucher_id = if let Some(prov_bytes) = tx
                .open_table(TABLE_PROVISIONAL_HMC_LOCKS)?
                .get(tag.value())?
                .map(|g| g.value().to_vec())
            {
                let prov: L2LockEntry = serde_json::from_slice(&prov_bytes)?;
                if let Some(prov_root_bytes) = tx
                    .open_table(roots::TABLE_VOUCHER_ROOTS)?
                    .get(prov.layer2_voucher_id.as_str())?
                    .map(|g| g.value().to_vec())
                {
                    let prov_root: L2LockEntry = serde_json::from_slice(&prov_root_bytes)?;
                    let prov_parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                        &bs58::encode(prov_root.t_id).into_string(),
                    );
                    if humoco_sim_core::types::canonical_voucher_shard(&prov_parent) != stage.shard
                    {
                        return Err(invalid(
                            "provisional HMC collision key belongs to another shard",
                        ));
                    }
                }
                Some(prov.layer2_voucher_id)
            } else {
                None
            };
            tx.open_table(TABLE_HMC_LOCKS)?
                .insert(tag.value(), value.value())?;
            tx.open_table(TABLE_PROVISIONAL_HMC_LOCKS)?
                .remove(tag.value())?;
            if let Some(vid) = prov_voucher_id {
                tx.open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?
                    .remove((vid.as_str(), tag.value()))?;
            }
            let _ = tx
                .open_table(TABLE_PROVISIONAL_HMC_VOUCHER_INDEX)?
                .remove((row.layer2_voucher_id.as_str(), tag.value()));
            tx.open_table(TABLE_HMC_VOUCHER_INDEX)?
                .insert((row.layer2_voucher_id.as_str(), tag.value()), ())?;
            tx.open_table(TABLE_HMC_TTL_INDEX)?
                .insert((super::grace_expiry_bucket_sec(validity), tag.value()), ())?;
            let inherited = if support_is_quorum_verified {
                source
                    .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                    .get(tag.value())?
                    .map(|v| serde_json::from_slice::<support::ConfirmationSupport>(v.value()))
                    .transpose()?
                    .filter(|f| f.child == row.t_id && f.root_valid_until_ms == validity)
                    .map_or(0, |f| f.class)
            } else {
                0
            };
            let mut fact = support::ConfirmationSupport {
                child: row.t_id,
                parent: *blake3::hash(tag.value().as_bytes()).as_bytes(),
                class: class.max(inherited),
                root_valid_until_ms: validity,
                verified_context: context,
            };
            if let Some(old) = tx
                .open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                .get(tag.value())?
            {
                let old: support::ConfirmationSupport = serde_json::from_slice(old.value())?;
                if old.child == fact.child && old.class > fact.class {
                    fact = old;
                }
            }
            let bytes = serde_json::to_vec(&fact)?;
            tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)?
                .insert(tag.value(), bytes.as_slice())?;
        }
        if let Some(dl) = deadline {
            if std::time::Instant::now() >= dl {
                return Err(invalid(
                    "installation aborted: source lease deadline expired",
                ));
            }
        }
        tx.commit()?;
        Ok(())
    }
}
impl RedbStorage {
    /// External-sort committed objective rows with a 64 KiB cache instead of a
    /// whole-shard Vec. One read transaction supplies the complete source cut.
    pub fn committed_shard_digest(
        &self,
        shard: u16,
        now: u64,
    ) -> Result<([u8; 32], u64), StorageError> {
        let sorted = ShardStage::new(shard, now)?;
        let source = self.db.begin_read()?;
        let tx = sorted.storage.db.begin_write()?;
        let mut count = 0u64;
        let roots = source.open_table(roots::TABLE_VOUCHER_ROOTS)?;
        for item in source.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (tag, value) = item?;
            let row: L2LockEntry = serde_json::from_slice(value.value())?;
            let root = roots
                .get(row.layer2_voucher_id.as_str())?
                .ok_or_else(|| invalid("committed spend lacks root"))?;
            let root: L2LockEntry = serde_json::from_slice(root.value())?;
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
                &bs58::encode(root.t_id).into_string(),
            );
            let validity = roots::root_valid_until(&root)?;
            if humoco_sim_core::types::canonical_voucher_shard(&parent) == shard && validity > now {
                let record = projection::CommittedShardRecord::new(
                    *blake3::hash(tag.value().as_bytes()).as_bytes(),
                    row.sender_ephemeral_pub,
                    row.t_id.to_vec(),
                    row.created_at_ms,
                );
                ShardStage::project(&tx, &record, now, validity)?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok((sorted.digest()?, count))
    }
}

#[cfg(test)]
mod review_commit_fault {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct SyncFault {
        inner: Arc<redb::backends::InMemoryBackend>,
        armed: Arc<AtomicBool>,
    }

    impl redb::StorageBackend for SyncFault {
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
            self.inner.read(offset, len)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.inner.set_len(len)
        }
        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(offset, data)
        }
        fn sync_data(&self, eventual: bool) -> std::io::Result<()> {
            self.inner.sync_data(eventual)?;
            if self.armed.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::other("injected commit sync failure"));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn failed_install_commit_must_latch_signing_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(redb::backends::InMemoryBackend::new());
        let database = redb::Database::builder()
            .create_with_backend(SyncFault {
                inner: inner.clone(),
                armed: armed.clone(),
            })
            .unwrap();
        let db = Arc::new(
            RedbStorage::initialize_database(database, &dir.path().join("fault.redb")).unwrap(),
        );
        let cancel = tokio_util::sync::CancellationToken::new();
        let (engine, worker) = crate::storage::DualTierEngine::new_with_token(db, cancel.clone());
        let author = crate::identity::NodeIdentity::generate();
        let mut root = L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "fault-root".into(),
            t_id: [42; 32],
            sender_ephemeral_pub: *author.node_pubkey(),
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 1_000,
            deletable_at: Some("600000".into()),
            privacy_guard: None,
        };
        let tag = bs58::encode(root.t_id).into_string();
        let payload = crate::api::hmc::calculate_l2_payload_hash_raw(
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            &tag,
            &root.t_id,
            &root.sender_ephemeral_pub,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            0,
            1_000,
            root.deletable_at.as_deref(),
            "",
        );
        use ed25519_dalek::Signer;
        root.layer2_signature = author.signing_key().sign(&payload).to_bytes();
        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag),
        );
        let stage = Arc::new(ShardStage::new(shard, 1_000).unwrap());
        stage
            .append(SyncPayload {
                hmc_locks: vec![(tag.clone(), root.clone())],
                support: vec![],
            })
            .unwrap();
        let expected = stage.digest().unwrap();
        armed.store(true, Ordering::SeqCst);
        let result = engine
            .install_shard_snapshot(stage, expected, 1, [1; 32], 1, None, None)
            .await;
        assert!(
            matches!(result, Err(StorageError::Commit(_))),
            "fault must occur at commit: {result:?}"
        );
        let healthy = engine.is_signing_healthy();
        // Snapshot the bytes already written before the sync error, modelling
        // crash recovery independently of the still-running old RAM index.
        use redb::StorageBackend;
        let image = inner.read(0, inner.len().unwrap() as usize).unwrap();
        let recovered_backend = redb::backends::InMemoryBackend::new();
        recovered_backend.set_len(image.len() as u64).unwrap();
        recovered_backend.write(0, &image).unwrap();
        let recovered_database = redb::Database::builder()
            .create_with_backend(recovered_backend)
            .unwrap();
        let recovered = RedbStorage::initialize_database(
            recovered_database,
            &dir.path().join("recovered.redb"),
        )
        .unwrap();
        assert!(
            recovered
                .voucher_root(&root.layer2_voucher_id)
                .unwrap()
                .is_some(),
            "the failed sync may leave the new cut recoverable on storage"
        );
        assert!(
            !engine.hmc_ram.read().await.locks.contains_key(&tag),
            "old RAM cut is still active"
        );
        cancel.cancel();
        worker.await.unwrap();
        assert!(
            !healthy,
            "uncertain failed commit must not reopen signing admission"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use ed25519_dalek::Signer;

    #[test]
    fn confirmed_omission_rolls_back_root_registration_and_all_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let author = crate::identity::NodeIdentity::generate();
        let mut root = L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "atomic-root".into(),
            t_id: [42; 32],
            sender_ephemeral_pub: *author.node_pubkey(),
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 1_000,
            deletable_at: Some("600000".into()),
            privacy_guard: None,
        };
        let tag = bs58::encode(root.t_id).into_string();
        let payload = crate::api::hmc::calculate_l2_payload_hash_raw(
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            &tag,
            &root.t_id,
            &root.sender_ephemeral_pub,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            0,
            1_000,
            root.deletable_at.as_deref(),
            "",
        );
        root.layer2_signature = author.signing_key().sign(&payload).to_bytes();
        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag),
        );
        db.put_hmc_lock(&tag, &root).unwrap();

        let mut old = root.clone();
        old.t_id = [43; 32];
        old.deletable_at = None;
        let spend_tag = "old-spend-tag";
        let spend_payload = crate::api::hmc::calculate_l2_payload_hash_raw(
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            spend_tag,
            &old.t_id,
            &old.sender_ephemeral_pub,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            crate::api::hmc::TRAP_NONE_PLACEHOLDER,
            0,
            1_000,
            None,
            "",
        );
        old.layer2_signature = author.signing_key().sign(&spend_payload).to_bytes();
        db.put_hmc_lock(spend_tag, &old).unwrap();
        let fact = support::ConfirmationSupport {
            parent: *blake3::hash(spend_tag.as_bytes()).as_bytes(),
            child: old.t_id,
            class: 2,
            root_valid_until_ms: 600_000,
            verified_context: [1; 32],
        };
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)
                .unwrap()
                .insert(spend_tag, serde_json::to_vec(&fact).unwrap().as_slice())
                .unwrap();
            tx.commit().unwrap();
        }

        // Stage a new root for the same shard, but omitting the old spend
        let stage = ShardStage::new(shard, 1_000).unwrap();
        stage
            .append(SyncPayload {
                hmc_locks: vec![(tag.clone(), root.clone())],
                support: vec![],
            })
            .unwrap();
        assert!(db
            .install_shard_cut(&stage, stage.digest().unwrap(), 2, [1; 32], 14, None, None)
            .is_err());
        assert!(db.get_hmc_lock(spend_tag).unwrap().is_some());
        assert!(db.get_provisional_hmc_lock(spend_tag).unwrap().is_none());
    }

    #[test]
    fn lower_current_quorum_never_downgrades_recovered_final_choice() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let (stage, spend_tag, spend, root_valid_until) = stage_with_class_two_support(1_000);
        let root = stage
            .storage
            .db
            .begin_read()
            .unwrap()
            .open_table(roots::TABLE_VOUCHER_ROOTS)
            .unwrap()
            .get(spend.layer2_voucher_id.as_str())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        let root_entry: L2LockEntry = serde_json::from_slice(&root).unwrap();
        let root_tag = bs58::encode(root_entry.t_id).into_string();
        db.put_hmc_lock(&root_tag, &root_entry).unwrap();
        db.put_hmc_lock(&spend_tag, &spend).unwrap();
        let fact = support::ConfirmationSupport {
            parent: *blake3::hash(spend_tag.as_bytes()).as_bytes(),
            child: spend.t_id,
            class: 2,
            root_valid_until_ms: root_valid_until,
            verified_context: [1; 32],
        };
        {
            let tx = db.db.begin_write().unwrap();
            tx.open_table(support::TABLE_CONFIRMATION_SUPPORT)
                .unwrap()
                .insert(spend_tag.as_str(), serde_json::to_vec(&fact).unwrap().as_slice())
                .unwrap();
            tx.commit().unwrap();
        }

        let incoming_stage = ShardStage::new(stage.shard, 1_000).unwrap();
        incoming_stage
            .append(SyncPayload {
                hmc_locks: vec![
                    (root_tag.clone(), root_entry.clone()),
                    (spend_tag.clone(), spend.clone()),
                ],
                support: vec![],
            })
            .unwrap();

        // Installing stage with class 1, 3 witnesses must not downgrade from class 2 to class 1
        db.install_shard_cut(
            &incoming_stage,
            incoming_stage.digest().unwrap(),
            1,
            [1; 32],
            3,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            db.confirmation_support(&spend_tag).unwrap().unwrap().class,
            2
        );
    }

    fn stage_with_class_two_support(now: u64) -> (ShardStage, String, L2LockEntry, u64) {
        let author = NodeIdentity::generate();
        let mut root = L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-v1".into(),
            t_id: [1; 32],
            sender_ephemeral_pub: *author.node_pubkey(),
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: now,
            deletable_at: Some((now + 600_000).to_string()),
            privacy_guard: None,
        };
        let root_tag = bs58::encode(root.t_id).into_string();
        let payload = crate::api::hmc::calculate_l2_payload_hash_for_entry(&root, &root_tag);
        root.layer2_signature = author.signing_key().sign(&payload).to_bytes();
        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
        );
        let mut spend = root.clone();
        spend.t_id = [2; 32];
        spend.deletable_at = None;
        let spend_tag = "test-spend-tag";
        let spend_payload =
            crate::api::hmc::calculate_l2_payload_hash_for_entry(&spend, spend_tag);
        spend.layer2_signature = author.signing_key().sign(&spend_payload).to_bytes();

        let fact = support::ConfirmationSupport {
            parent: *blake3::hash(spend_tag.as_bytes()).as_bytes(),
            child: spend.t_id,
            class: 2,
            root_valid_until_ms: now + 600_000,
            verified_context: [77; 32],
        };
        let stage = ShardStage::new(shard, now).unwrap();
        stage
            .append(SyncPayload {
                hmc_locks: vec![(root_tag, root), (spend_tag.to_string(), spend.clone())],
                support: vec![(1, spend_tag.to_string(), fact)],
            })
            .unwrap();
        (stage, spend_tag.to_string(), spend, now + 600_000)
    }

    fn inherited_cut(
        stage: &ShardStage,
        objective: [u8; 32],
        receiver: &NodeIdentity,
        source_identities: &[NodeIdentity],
        support_digests: &[[u8; 32]],
        qualified: &[[u8; 32]],
    ) -> support::VerifiedInheritedCut {
        let committee: Vec<_> = std::iter::once(*receiver.node_pubkey())
            .chain(
                source_identities
                    .iter()
                    .map(|identity| *identity.node_pubkey()),
            )
            .collect();
        let proofs: Vec<_> = source_identities
            .iter()
            .zip(support_digests)
            .enumerate()
            .map(|(index, (identity, support_digest))| {
                let mut reply = crate::network::framing::FrozenShardReply {
                    version: 2,
                    token: [index as u8; 16],
                    digest: objective,
                    lease_ms: 25_000,
                    support_digest: *support_digest,
                    signature: Vec::new(),
                };
                reply.signature = identity
                    .signing_key()
                    .sign(&reply.signing_digest(
                        humoco_sim_core::types::NetworkId::Mainnet,
                        stage.shard,
                        identity.node_pubkey(),
                        receiver.node_pubkey(),
                    ))
                    .to_bytes()
                    .to_vec();
                (*identity.node_pubkey(), reply)
            })
            .collect();
        support::VerifiedInheritedCut::verify(
            humoco_sim_core::types::NetworkId::Mainnet,
            stage.shard,
            *receiver.node_pubkey(),
            &committee,
            3,
            objective,
            &support_digests
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
            qualified,
            &proofs,
        )
        .unwrap()
    }

    #[test]
    fn support_digest_without_quorum_cannot_promote_class_two() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let (stage, spend_tag, _, _) = stage_with_class_two_support(1_000);
        let objective = stage.digest().unwrap();
        let staged_support = stage.support_digest().unwrap();
        let receiver = NodeIdentity::generate();
        let sources: Vec<_> = (0..3).map(|_| NodeIdentity::generate()).collect();
        let support_digests = [staged_support, [8; 32], [8; 32]];
        let inherited = inherited_cut(
            &stage,
            objective,
            &receiver,
            &sources,
            &support_digests,
            &[],
        );
        db.install_shard_cut(&stage, objective, 1, [1; 32], 3, Some(&inherited), None)
            .unwrap();
        assert_eq!(
            db.confirmation_support(&spend_tag).unwrap().unwrap().class,
            1
        );
    }

    #[test]
    fn support_digest_with_quorum_can_inherit_class_two() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let (stage, spend_tag, _, _) = stage_with_class_two_support(1_000);
        let objective = stage.digest().unwrap();
        let staged_support = stage.support_digest().unwrap();
        let receiver = NodeIdentity::generate();
        let sources: Vec<_> = (0..3).map(|_| NodeIdentity::generate()).collect();
        let support_digests = [staged_support; 3];
        let inherited = inherited_cut(
            &stage,
            objective,
            &receiver,
            &sources,
            &support_digests,
            &[staged_support],
        );
        db.install_shard_cut(&stage, objective, 1, [1; 32], 3, Some(&inherited), None)
            .unwrap();
        assert_eq!(
            db.confirmation_support(&spend_tag).unwrap().unwrap().class,
            2
        );
    }
    #[test]
    fn test_orphaned_hmc_spend_does_not_poison_other_shards() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        // Insert an unanchored/corrupt spend into TABLE_HMC_LOCKS that lacks a voucher root
        {
            let tx = db.db.begin_write().unwrap();
            let orphan_entry = L2LockEntry {
                causal_output: None,
                layer2_voucher_id: "missing-root-uuid".into(),
                t_id: [88; 32],
                sender_ephemeral_pub: [99; 32],
                layer2_signature: [0; 64],
                trap_r: None,
                trap_s: None,
                encrypted_timestamp: 0,
                created_at_ms: 1_000,
                deletable_at: Some("600000".into()),
                privacy_guard: None,
            };
            let bytes = serde_json::to_vec(&orphan_entry).unwrap();
            tx.open_table(TABLE_HMC_LOCKS)
                .unwrap()
                .insert("orphan-tag", bytes.as_slice())
                .unwrap();
            tx.commit().unwrap();
        }

        // Now install a completely normal cut for shard 5
        let shard = 5u16;
        let now = 1_000u64;
        let stage = ShardStage::new(shard, now).unwrap();
        let digest = stage.digest().unwrap();

        let res = db.install_shard_cut(&stage, digest, 1, [0; 32], 3, None, None);
        assert!(
            res.is_ok(),
            "install_shard_cut must not fail on orphaned foreign HMC spends without root: {:?}",
            res.err()
        );
    }
    #[test]
    fn test_install_shard_cut_with_expired_deadline_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let db = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
        let shard = 5u16;
        let now = 1_000u64;
        let stage = ShardStage::new(shard, now).unwrap();
        let digest = stage.digest().unwrap();

        let expired = std::time::Instant::now() - std::time::Duration::from_secs(5);
        let res = db.install_shard_cut(&stage, digest, 1, [0; 32], 3, None, Some(expired));
        assert!(
            res.is_err(),
            "install_shard_cut must abort with error when lease deadline expired before commit"
        );
    }
}
