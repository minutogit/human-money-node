//! Durable verified support facts, never historical signature archives.
use super::*;
use crate::api::dto::QuorumCertificateDto;
use humoco_sim_core::types::NetworkId;
use std::collections::HashSet;

pub(crate) const TABLE_NATIVE_SUPPORT: TableDefinition<&str, &[u8]> = TableDefinition::new("native_confirmation_support");
pub const TABLE_CONFIRMATION_SUPPORT: TableDefinition<&str, &[u8]> =
    TableDefinition::new("confirmation_support");
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConfirmationSupport {
    pub child: [u8; 32],
    pub parent: [u8; 32],
    pub class: u8,
    pub root_valid_until_ms: u64,
    pub verified_context: [u8; 32],
}
/// Only cryptographic verification can construct an admissible support update.
pub struct VerifiedSupport {
    tag: String,
    fact: ConfirmationSupport,
}
impl VerifiedSupport {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        tag: String,
        child: [u8; 32],
        root: u64,
        cert: &QuorumCertificateDto,
        committee: &[[u8; 32]],
        quorum: usize,
        final_allowed: bool,
        network: NetworkId,
    ) -> Result<Self, StorageError> {
        let invalid =
            || StorageError::DurableCommitFailed("unverified confirmation support".into());
        if committee.is_empty()
            || committee.len() > 20
            || committee.iter().copied().collect::<HashSet<_>>().len() != committee.len()
            || quorum == 0
            || quorum > committee.len()
            || (cert.status == 1 && (!final_allowed || committee.len() != 20 || quorum < 14))
            || cert.status > 1
            || root == 0
            || cert.signatures.len() > 20
            || cert.signer_count != cert.signatures.len()
            || cert.lock_id != hex::encode(child)
        {
            return Err(invalid());
        }
        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
        let domain = if cert.status == 1 {
            humoco_sim_core::crypto::domain_approve_final(network)
        } else {
            humoco_sim_core::crypto::domain_approve_prov(network)
        };
        let digest = humoco_sim_core::crypto::compute_sig_digest(
            domain,
            0,
            0,
            0,
            cert.shard_id,
            cert.status,
            &humoco_sim_core::crypto::compute_attestation_payload_digest(&parent, &child),
        );
        let mut signers = HashSet::new();
        for att in &cert.signatures {
            let key = att.node_pubkey_bytes().ok_or_else(invalid)?;
            if !committee.contains(&key)
                || !signers.insert(key)
                || att.shard_id != cert.shard_id
                || att.lock_id != cert.lock_id
                || att.parent_lock != hex::encode(parent)
            {
                return Err(invalid());
            }
            let bytes: [u8; 64] = hex::decode(&att.signature)
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| invalid())?;
            vk.verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&bytes))
                .map_err(|_| invalid())?;
        }
        if signers.len() < quorum {
            return Err(invalid());
        }
        let mut h = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_CONFIRMED_SUPPORT";
        h.update(&[domain.len() as u8]);
        h.update(domain);
        h.update(&digest);
        for key in committee {
            h.update(key);
        }
        Ok(Self {
            tag,
            fact: ConfirmationSupport {
                child,
                parent,
                class: if cert.status == 1 { 2 } else { 1 },
                root_valid_until_ms: root,
                verified_context: *h.finalize().as_bytes(),
            },
        })
    }
}
impl RedbStorage {
    pub fn commit_confirmation_support(
        &self,
        verified: VerifiedSupport,
    ) -> Result<ConfirmationSupport, StorageError> {
        if !self.is_signing_history_healthy() {
            return Err(StorageError::SigningHistoryCorrupt);
        }
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Immediate);
        let mut fact = verified.fact;
        {
            let locks = txn.open_table(TABLE_HMC_LOCKS)?;
            let value = locks
                .get(verified.tag.as_str())?
                .ok_or_else(|| StorageError::DurableCommitFailed("support lock missing".into()))?;
            let entry: crate::api::hmc::L2LockEntry = serde_json::from_slice(value.value())?;
            if entry.t_id != fact.child {
                return Err(StorageError::OwnChoiceConflict);
            }
            let mut table = txn.open_table(TABLE_CONFIRMATION_SUPPORT)?;
            if let Some(value) = table.get(verified.tag.as_str())? {
                let old: ConfirmationSupport = serde_json::from_slice(value.value())?;
                if old.child == fact.child && old.class > fact.class {
                    fact = old;
                }
            }
            let bytes = serde_json::to_vec(&fact)?;
            table.insert(verified.tag.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(fact)
    }
    /// Compact admitted native support, separate from legacy row status.
    pub fn native_confirmation_support(&self,parent:&[u8;32]) -> Result<Option<ConfirmationSupport>,StorageError> {
        let tx=self.db.begin_read()?;
        let table=tx.open_table(TABLE_NATIVE_SUPPORT)?;
        table.get(native_key(parent).as_str())?.map(|value|serde_json::from_slice(value.value()).map_err(StorageError::from)).transpose()
    }
    pub fn confirmation_support(
        &self,
        tag: &str,
    ) -> Result<Option<ConfirmationSupport>, StorageError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TABLE_CONFIRMATION_SUPPORT)?;
        table
            .get(tag)?
            .map(|value| serde_json::from_slice(value.value()).map_err(StorageError::from))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{api::routes::create_attestation_for_network, identity::NodeIdentity};
    fn certificate(tag: &str, child: [u8; 32], keys: &[NodeIdentity]) -> QuorumCertificateDto {
        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
        QuorumCertificateDto {
            lock_id: hex::encode(child),
            shard_id: 42,
            status: 1,
            active_nodes_count: 20,
            signer_count: 14,
            signatures: keys[..14]
                .iter()
                .map(|key| {
                    create_attestation_for_network(
                        key,
                        child,
                        parent,
                        42,
                        1,
                        1_000,
                        NetworkId::Mainnet,
                    )
                })
                .collect(),
            signer_bitmap: (1 << 14) - 1,
        }
    }
    #[tokio::test]
    async fn verified_final_support_survives_restart_and_expires_with_root() {
        let keys: Vec<_> = (0..20).map(|_| NodeIdentity::generate()).collect();
        let committee: Vec<_> = keys.iter().map(|k| *k.node_pubkey()).collect();
        let tag = "support-test";
        let child = [3; 32];
        let cert = certificate(tag, child, &keys);
        assert!(VerifiedSupport::verify(
            tag.into(),
            child,
            50_000,
            &cert,
            &committee,
            14,
            true,
            NetworkId::Mainnet
        )
        .is_ok());
        let mut bad = cert.clone();
        bad.signatures[13] = bad.signatures[0].clone();
        assert!(VerifiedSupport::verify(
            tag.into(),
            child,
            50_000,
            &bad,
            &committee,
            14,
            true,
            NetworkId::Mainnet
        )
        .is_err());
        bad = cert.clone();
        bad.signatures[0].signature = hex::encode([0; 64]);
        assert!(VerifiedSupport::verify(
            tag.into(),
            child,
            50_000,
            &bad,
            &committee,
            14,
            true,
            NetworkId::Mainnet
        )
        .is_err());
        assert!(VerifiedSupport::verify(
            tag.into(),
            child,
            50_000,
            &cert,
            &committee,
            14,
            false,
            NetworkId::Mainnet
        )
        .is_err());
        assert!(VerifiedSupport::verify(
            tag.into(),
            child,
            50_000,
            &cert,
            &committee,
            14,
            true,
            NetworkId::Testnet
        )
        .is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.redb");
        let backup = dir.path().join("backup.redb");
        {
            let db = RedbStorage::open(&path).unwrap();
            let entry = crate::api::hmc::L2LockEntry {
                causal_output: None,
                t_id: child,
                layer2_voucher_id: "support-root".into(),
                sender_ephemeral_pub: [4; 32],
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
            let mut root = entry.clone();
            root.t_id = [1; 32];
            db.put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root).unwrap();
            db.put_hmc_lock(tag, &entry).unwrap();
            db.commit_confirmation_support(
                VerifiedSupport::verify(
                    tag.into(),
                    child,
                    50_000,
                    &cert,
                    &committee,
                    14,
                    true,
                    NetworkId::Mainnet,
                )
                .unwrap(),
            )
            .unwrap();
            db.create_backup(&backup).unwrap();
        }
        let db = Arc::new(RedbStorage::open(&path).unwrap());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (engine, worker) =
            crate::storage::DualTierEngine::new_with_token(db.clone(), cancel.clone());
        engine.recover_from_disk(SimTime(2_000)).await.unwrap();
        assert_eq!(engine.hmc_ram.read().await.get_confirmation_class(tag), 2);
        let restored = RedbStorage::open(&backup).unwrap();
        assert_eq!(
            restored.confirmation_support(tag).unwrap().unwrap().class,
            2
        );
        db.prune_expired_buckets(81).unwrap();
        assert!(db.confirmation_support(tag).unwrap().is_none());
        cancel.cancel();
        worker.await.unwrap();
    }
}

/// Disjoint from base58 HMC collision tags. Native status fields are not provenance.
pub(crate) fn native_key(parent: &[u8;32]) -> String { format!("native:{}",hex::encode(parent)) }

impl RedbStorage {
    /// Bounded streaming commitment over both objective identities and admitted support.
    /// Unknown provenance commits to class zero, including legacy native FINAL rows.
    pub(crate) fn inherited_support_digest(&self, shard: u16, now: u64) -> Result<[u8;32],StorageError> {
        let tx = self.db.begin_read()?;
        let mut h = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_INHERITED_SUPPORT_STATE";
        h.update(&[domain.len() as u8]); h.update(domain); h.update(&[1]);
        h.update(&shard.to_le_bytes());
        let support = tx.open_table(TABLE_CONFIRMATION_SUPPORT)?;
        for item in tx.open_table(TABLE_LOCKS)?.iter()? {
            let (_,bytes) = item?;
            let (row,root): (LockRecord,u64) = bincode::deserialize(bytes.value())?;
            if u16::from_be_bytes([row.parent_lock[0],row.parent_lock[1]]) != shard || row.valid_until.0 <= now || row.status.is_void() { continue; }
            let key = native_key(&row.parent_lock);
            let fact = tx.open_table(TABLE_NATIVE_SUPPORT)?.get(key.as_str())?.map(|v|serde_json::from_slice::<ConfirmationSupport>(v.value())).transpose()?;
            hash_fact(&mut h,0,&key,&row.parent_lock,&row.id,&[0;32],root,
                admitted_class(fact.as_ref(),&row.parent_lock,&row.id,root)?)?;
        }
        for item in tx.open_table(TABLE_HMC_LOCKS)?.iter()? {
            let (key,bytes) = item?;
            let row: crate::api::hmc::L2LockEntry = serde_json::from_slice(bytes.value())?;
            let roots = tx.open_table(roots::TABLE_VOUCHER_ROOTS)?;
            let root = roots.get(row.layer2_voucher_id.as_str())?.ok_or_else(||StorageError::DurableCommitFailed("support root missing".into()))?;
            let root: crate::api::hmc::L2LockEntry = serde_json::from_slice(root.value())?;
            let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode(root.t_id).into_string());
            let ttl = roots::root_valid_until(&root)?;
            if humoco_sim_core::types::canonical_voucher_shard(&parent) != shard || ttl <= now { continue; }
            let parent = *blake3::hash(key.value().as_bytes()).as_bytes();
            let fact = support.get(key.value())?.map(|v|serde_json::from_slice::<ConfirmationSupport>(v.value())).transpose()?;
            hash_fact(&mut h,1,key.value(),&parent,&row.t_id,&root.t_id,ttl,
                admitted_class(fact.as_ref(),&parent,&row.t_id,ttl)?)?;
        }
        Ok(*h.finalize().as_bytes())
    }
}
fn admitted_class(fact: Option<&ConfirmationSupport>,parent: &[u8;32],child: &[u8;32],ttl:u64) -> Result<u8,StorageError> {
    match fact {
        None => Ok(0),
        Some(fact) if fact.parent == *parent && fact.child == *child && fact.root_valid_until_ms == ttl && (1..=2).contains(&fact.class) => Ok(fact.class),
        _ => Err(StorageError::DurableCommitFailed("inconsistent inherited support".into())),
    }
}
#[allow(clippy::too_many_arguments)]
fn hash_fact(h: &mut blake3::Hasher,kind:u8,key:&str,parent:&[u8;32],child:&[u8;32],root:&[u8;32],ttl:u64,class:u8) -> Result<(),StorageError> {
    if key.len() > 128 { return Err(StorageError::DurableCommitFailed("support key too long".into())); }
    h.update(&[kind]); h.update(&(key.len() as u16).to_le_bytes()); h.update(key.as_bytes());
    h.update(parent); h.update(child); h.update(root); h.update(&ttl.to_le_bytes()); h.update(&[class]); Ok(())
}

/// Constructible only after independent authentication of the qualified source set.
/// Its class claims concern inherited exclusions, never current checkout authority.
#[derive(Clone)]
pub(crate) struct VerifiedInheritedCut {
    objective: [u8;32],
    support: [u8;32],
    shard: u16,
}
impl VerifiedInheritedCut {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify(network: NetworkId,shard:u16,receiver:[u8;32],committee:&[[u8;32]],quorum:usize,
        objective:[u8;32],support:[u8;32],sources:&[([u8;32],crate::network::framing::FrozenShardReply)]) -> Result<Self,StorageError> {
        let invalid = || StorageError::DurableCommitFailed("unsupported inherited cut".into());
        if committee.is_empty() || committee.len() > 20 || quorum == 0 || quorum > committee.len()
            || !committee.contains(&receiver) || committee.iter().collect::<HashSet<_>>().len() != committee.len() || sources.len() > 20 { return Err(invalid()); }
        let mut seen = HashSet::new();
        for (key,reply) in sources {
            if !committee.contains(key) || *key == receiver || !seen.insert(*key) || reply.version != 2 || reply.lease_ms != 25_000
                || reply.digest != objective || reply.support_digest != support { return Err(invalid()); }
            let vk = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_|invalid())?;
            let sig = ed25519_dalek::Signature::from_slice(&reply.signature).map_err(|_|invalid())?;
            vk.verify_strict(&reply.signing_digest(network,shard,key,&receiver),&sig).map_err(|_|invalid())?;
        }
        if seen.len() < quorum { return Err(invalid()); }
        Ok(Self { objective,support,shard })
    }
    pub(crate) fn validate(&self,stage:&super::install::ShardStage,objective:[u8;32]) -> Result<(),StorageError> {
        if self.objective != objective || self.shard != stage.shard || stage.support_digest()? != self.support {
            return Err(StorageError::DurableCommitFailed("inherited cut commitment mismatch".into()));
        }
        Ok(())
    }
}
