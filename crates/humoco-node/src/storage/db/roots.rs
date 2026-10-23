//! Genesis is an immutable voucher root proof, NEVER a collision lock or vote.
//! Keeping this separate is essential: the first spend must not collide with a
//! fictitious genesis spend. The canonical L1 SST ds_tag is unchanged.
use super::*;
pub const TABLE_VOUCHER_ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("voucher_roots");
pub const TABLE_VOUCHER_ROOT_TTL: TableDefinition<(u64, &str), ()> =
    TableDefinition::new("voucher_root_ttl");

pub fn is_root(tag: &str, entry: &crate::api::hmc::L2LockEntry) -> bool {
    tag == bs58::encode(entry.t_id).into_string() && entry.deletable_at.is_some()
}
/// An idempotent root retry may not replace its original L1 author or deed.
/// Legacy unsigned output hints are not authority; the sidecar authenticates
/// actual outputs separately and can be added once by the original author.
pub(crate) fn same_root_deed(a: &crate::api::hmc::L2LockEntry, b: &crate::api::hmc::L2LockEntry) -> bool {
    a.layer2_voucher_id == b.layer2_voucher_id && a.t_id == b.t_id
        && a.sender_ephemeral_pub == b.sender_ephemeral_pub
        && a.layer2_signature == b.layer2_signature
        && a.trap_r == b.trap_r && a.trap_s == b.trap_s
        && a.encrypted_timestamp == b.encrypted_timestamp && a.created_at_ms == b.created_at_ms
        && a.deletable_at == b.deletable_at && a.privacy_guard == b.privacy_guard
        && match (&a.causal_output, &b.causal_output) { (Some(old), Some(new)) => old == new, _ => true }
}
pub fn root_valid_until(entry: &crate::api::hmc::L2LockEntry) -> Result<u64, StorageError> {
    let raw = entry
        .deletable_at
        .as_deref()
        .ok_or_else(|| StorageError::DurableCommitFailed("root validity missing".into()))?;
    let legacy = raw
        .parse::<u64>()
        .ok()
        .or_else(|| {
            chrono::DateTime::parse_from_rfc3339(raw)
                .ok()
                .and_then(|date| u64::try_from(date.timestamp_millis()).ok())
        })
        .ok_or_else(|| StorageError::DurableCommitFailed("invalid signed root validity".into()))?;
    if let Some(proof) = &entry.causal_output {
        if !proof.is_root
            || !proof.verify()
            || proof.transaction_id != entry.t_id
            || proof.sender_pubkey != entry.sender_ephemeral_pub
            || proof.voucher_id != entry.layer2_voucher_id
            || proof.root_valid_until_ms > legacy
        {
            return Err(StorageError::DurableCommitFailed(
                "invalid root output proof".into(),
            ));
        }
        // Preserve the immutable Core L1 root-ID preimage. A valid signature
        // from an arbitrary author must not preempt somebody else's root ID.
        if entry.layer2_voucher_id.len() == 64 && entry.layer2_voucher_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            hash.update(entry.t_id);
            hash.update(entry.sender_ephemeral_pub);
            if let Some(receiver) = proof.receiver_pubkey_hash { hash.update(receiver); }
            hash.update(raw.as_bytes());
            if hex::encode(hash.finalize()) != entry.layer2_voucher_id {
                return Err(StorageError::DurableCommitFailed("root proof does not derive the canonical L1 voucher identity".into()));
            }
        }
        Ok(proof.root_valid_until_ms)
    } else {
        Ok(legacy)
    }
}
pub(super) fn put(
    txn: &redb::WriteTransaction,
    entry: &crate::api::hmc::L2LockEntry,
) -> Result<(), StorageError> {
    let expiry = root_valid_until(entry)?;
    let bytes = serde_json::to_vec(entry)?;
    let mut roots = txn.open_table(TABLE_VOUCHER_ROOTS)?;
    if let Some(previous) = roots.get(entry.layer2_voucher_id.as_str())? {
        let previous: crate::api::hmc::L2LockEntry = serde_json::from_slice(previous.value())?;
        if !same_root_deed(&previous, entry) || root_valid_until(&previous)? != expiry {
            return Err(StorageError::OwnChoiceConflict);
        }
        if previous.causal_output.is_some() && entry.causal_output.is_none() {
            return Ok(()); // A legacy retry cannot erase an authenticated output proof.
        }
    }
    roots.insert(entry.layer2_voucher_id.as_str(), bytes.as_slice())?;
    txn.open_table(TABLE_VOUCHER_ROOT_TTL)?.insert(
        (
            expiry.saturating_add(30_000) / 1_000,
            entry.layer2_voucher_id.as_str(),
        ),
        (),
    )?;
    Ok(())
}
/// Atomic bounded-chunk migration of old self-loop genesis records. Private old
/// own signatures remain protected until their original TTL; no new root vote is
/// issued, and no L1/SST bytes are rewritten or re-signed.
pub(super) fn initialize(txn: &redb::WriteTransaction) -> Result<(), StorageError> {
    let _ = txn.open_table(TABLE_VOUCHER_ROOTS)?;
    let _ = txn.open_table(TABLE_VOUCHER_ROOT_TTL)?;
    let mut after: Option<String> = None;
    loop {
        let mut page = Vec::new();
        {
            let table = txn.open_table(TABLE_HMC_LOCKS)?;
            let lower = after
                .as_deref()
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
            for row in table
                .range::<&str>((lower, std::ops::Bound::Unbounded))?
                .take(256)
            {
                let (key, value) = row?;
                let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(value.value())?;
                page.push((key.value().to_string(), entry));
            }
        }
        if page.is_empty() {
            break;
        }
        for (tag, entry) in page {
            after = Some(tag.clone());
            if is_root(&tag, &entry) {
                put(txn, &entry)?;
                txn.open_table(TABLE_HMC_LOCKS)?.remove(tag.as_str())?;
                txn.open_table(TABLE_HMC_VOUCHER_INDEX)?
                    .remove((entry.layer2_voucher_id.as_str(), tag.as_str()))?;
                txn.open_table(super::support::TABLE_CONFIRMATION_SUPPORT)?
                    .remove(tag.as_str())?;
            }
        }
    }
    Ok(())
}
impl RedbStorage {
    pub fn voucher_root(
        &self,
        voucher: &str,
    ) -> Result<Option<crate::api::hmc::L2LockEntry>, StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_VOUCHER_ROOTS)?;
        table
            .get(voucher)?
            .map(|value| serde_json::from_slice(value.value()).map_err(StorageError::from))
            .transpose()
    }
    pub fn all_voucher_roots(&self) -> Result<Vec<crate::api::hmc::L2LockEntry>, StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_VOUCHER_ROOTS)?;
        table
            .iter()?
            .map(|row| {
                let (_, value) = row?;
                serde_json::from_slice(value.value()).map_err(StorageError::from)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_root_sidecar_cannot_preempt_an_unrelated_voucher_identity() {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let mut proof = humoco_proto::causal::CausalOutputProof { version: 1, voucher_id: String::new(), transaction_id: [7; 32], state_hash: [6; 32], sender_pubkey: key.verifying_key().to_bytes(), receiver_pubkey_hash: Some([9; 32]), change_pubkey_hash: None, root_valid_until_ms: 50_000, is_root: true, signature: [0; 64] };
        let mut hash = Sha256::new();
        hash.update(proof.transaction_id); hash.update(proof.sender_pubkey); hash.update([9; 32]); hash.update(b"50000");
        proof.voucher_id = hex::encode(hash.finalize());
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
        let mut entry = crate::api::hmc::L2LockEntry { causal_output: Some(proof.clone()), layer2_voucher_id: proof.voucher_id.clone(), t_id: proof.transaction_id, sender_ephemeral_pub: proof.sender_pubkey, receiver_ephemeral_pub_hash: None, change_ephemeral_pub_hash: None, layer2_signature: [0; 64], trap_r: None, trap_s: None, encrypted_timestamp: 0, created_at_ms: 1_000, deletable_at: Some("50000".into()), privacy_guard: None };
        assert_eq!(root_valid_until(&entry).unwrap(), 50_000);
        proof.voucher_id = "00".repeat(32);
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
        assert!(proof.verify(), "the attacker owns a genuine signing key");
        entry.layer2_voucher_id = proof.voucher_id.clone();
        entry.causal_output = Some(proof);
        assert!(root_valid_until(&entry).is_err(), "a genuine unrelated author cannot preempt a root ID");
    }
    #[test]
    fn legacy_genesis_migrates_to_root_metadata_and_never_occupies_a_spend_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.redb");
        let root = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "legacy-root".into(),
            t_id: [7; 32],
            sender_ephemeral_pub: [8; 32],
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 1_000,
            deletable_at: Some("50000".into()),
            privacy_guard: None,
        };
        let tag = bs58::encode(root.t_id).into_string();
        {
            let db = RedbStorage::open(&path).unwrap();
            let txn = db.db.begin_write().unwrap();
            let bytes = serde_json::to_vec(&root).unwrap();
            txn.open_table(TABLE_HMC_LOCKS).unwrap().insert(tag.as_str(), bytes.as_slice()).unwrap();
            txn.open_table(TABLE_HMC_VOUCHER_INDEX).unwrap().insert((root.layer2_voucher_id.as_str(),tag.as_str()), ()).unwrap();
            txn.commit().unwrap();
        }
        let db = RedbStorage::open(&path).unwrap();
        assert!(db.get_hmc_lock(&tag).unwrap().is_none());
        assert_eq!(db.voucher_root(&root.layer2_voucher_id).unwrap(), Some(root.clone()));
        assert!(db.get_hmc_locks_for_voucher(&root.layer2_voucher_id).unwrap().is_empty());
        let mut different = root.clone();
        different.t_id = [9; 32];
        assert!(db.put_hmc_lock(&bs58::encode(different.t_id).into_string(), &different).is_err());
    }
}
