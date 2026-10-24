//! Bounded cold-path installation and no-gap source leases.
use super::*;
use super::super::{activity::Lease, db::install::ShardStage};
use std::time::{Duration, Instant};
pub(crate) const SOURCE_LEASE_MS: u64 = 25_000;
pub(crate) const LEASE_COOLDOWN_MS: u64 = 2_000;
pub(crate) struct SourceLease {
    owner: [u8;32],
    token: [u8;16],
    expires: Instant,
    _admission: Lease,
}
struct Installation {
    _admission: Lease,
    health: Arc<PersistenceStats>,
    uncertain: bool,
}
impl Drop for Installation {
    fn drop(&mut self) {
        // A cancelled blocking commit may still complete. Never publish signing
        // readiness from RAM whose relation to the committed cut is uncertain.
        if self.uncertain { self.health.signing_failed.store(true,std::sync::atomic::Ordering::Release); }
    }
}
fn error(message: &str) -> StorageError { StorageError::DurableCommitFailed(message.into()) }
impl DualTierEngine {
    pub(crate) fn expire_source_leases(&self) {
        let now = Instant::now();
        let mut leases = self.source_leases.lock();
        let mut cooldowns = self.lease_cooldowns.lock();
        cooldowns.retain(|_, until| *until > now);
        leases.retain(|shard, lease| {
            if lease.expires > now {
                true
            } else {
                cooldowns.insert(*shard, now + Duration::from_millis(LEASE_COOLDOWN_MS));
                false
            }
        });
    }
    async fn persistence_fence(&self) -> Result<(),StorageError> {
        let (complete, ack) = tokio::sync::oneshot::channel();
        self.tx.send(FlushOp::Fence { complete }).await.map_err(|_| error("persistence worker closed"))?;
        if !ack.await.map_err(|_| error("persistence fence lost"))? { return Err(error("earlier persistence failed")); }
        if !self.is_signing_healthy() { return Err(StorageError::SigningHistoryCorrupt); }
        Ok(())
    }
    /// A source admits no new writes until receiver activation or absolute expiry.
    /// This closes the gap between a full cut and publication without lock gossip.
    pub(crate) async fn freeze_source_shard(&self, shard: u16, owner: [u8;32]) -> Result<[u8;16],StorageError> {
        self.expire_source_leases();
        {
            let cooldowns = self.lease_cooldowns.lock();
            if let Some(until) = cooldowns.get(&shard) {
                if *until > Instant::now() {
                    return Err(error("source shard in lease cooldown"));
                }
            }
        }
        {
            let leases = self.source_leases.lock();
            if leases.len() >= 32 { return Err(error("source lease capacity exhausted")); }
            if let Some(lease) = leases.get(&shard) {
                if lease.owner == owner { return Err(error("source lease already active; deadline is not renewable")); }
                return Err(error("source shard already fenced"));
            }
        }
        let admission = self.activity.close(shard).await.ok_or_else(|| error("source shard busy"))?;
        self.persistence_fence().await?;
        let token: [u8;16] = rand::random();
        let mut leases = self.source_leases.lock();
        if leases.len() >= 32 { return Err(error("source lease capacity exhausted")); }
        leases.insert(shard, SourceLease { owner, token, expires: Instant::now()+Duration::from_millis(SOURCE_LEASE_MS), _admission: admission });
        Ok(token)
    }
    pub(crate) fn release_source_shard(&self, shard: u16, owner: [u8;32], token: [u8;16]) -> bool {
        let mut leases = self.source_leases.lock();
        if leases.get(&shard).is_some_and(|lease| lease.owner == owner && lease.token == token) {
            leases.remove(&shard);
            let mut cooldowns = self.lease_cooldowns.lock();
            cooldowns.insert(shard, Instant::now() + Duration::from_millis(LEASE_COOLDOWN_MS));
            return true;
        }
        false
    }
    /// Current distinct ready committee witnesses justify compact support for the
    /// complete objective cut. Never accept a source's claimed class or signers.
    pub(crate) async fn install_shard_snapshot(&self, stage: Arc<ShardStage>, expected: [u8;32],
        class: u8, context: [u8;32], witnesses: usize) -> Result<(), StorageError> {
        self.expire_source_leases();
        let admission = self.activity.close(stage.shard).await.ok_or_else(|| error("target shard busy"))?;
        let mut installation = Installation { _admission: admission, health: self.stats.clone(), uncertain: true };
        let result = self.install_closed_snapshot(stage,expected,class,context,witnesses).await;
        // An ordinary failed transaction rolled back; cancellation is different.
        // A publication failure AFTER commit remains fail-closed until restart.
        if result.is_ok() { installation.uncertain = false; }
        result
    }
    async fn install_closed_snapshot(&self, stage: Arc<ShardStage>, expected: [u8;32],
        class: u8, context: [u8;32], witnesses: usize) -> Result<(), StorageError> {
        self.persistence_fence().await?;
        let db = self.db.clone(); let cut = stage.clone();
        self.recovery_work.spawn_blocking(move || db.install_shard_cut(&cut, expected, class, context, witnesses))
            .await.map_err(|e| error(&format!("installation worker: {e}")))??;
        // Bounded RAM publication. Only this shard is gated; no index guard is
        // retained over disk work. Existing root metadata remains immutable.
        loop {
            let mut ram = self.ram.write().await;
            let keys: Vec<_> = ram.iter().filter(|r| u16::from_be_bytes([r.parent_lock[0],r.parent_lock[1]]) == stage.shard)
                .take(256).map(|r|r.parent_lock).collect();
            if keys.is_empty() { break; }
            for key in keys { ram.remove(&key); }
            drop(ram); tokio::task::yield_now().await;
        }
        loop {
            let mut ram = self.hmc_ram.write().await;
            let keys: Vec<_> = ram.locks.iter().filter(|(_,entry)| ram.root_anchors.get(&entry.layer2_voucher_id).is_some_and(|root| {
                let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&bs58::encode(root.t_id).into_string());
                humoco_sim_core::types::canonical_voucher_shard(&parent) == stage.shard
            })).take(256).map(|(tag,_)|tag.clone()).collect();
            if keys.is_empty() { break; }
            for key in keys { ram.remove_lock(&key); }
            drop(ram); tokio::task::yield_now().await;
        }
        let mut cursor = 0;
        loop {
            let cut = stage.clone(); let db = self.db.clone();
            let (page, classes) = self.recovery_work.spawn_blocking(move || {
                let mut page = cut.page(cursor)?;
                let mut native = Vec::new();
                for (row,_) in page.payload.locks { if let Some(row) = db.get_lock(&row.parent_lock)? { native.push(row); } }
                page.payload.locks = native;
                let mut classes = Vec::new();
                let mut hmc = Vec::new();
                for (tag,entry) in page.payload.hmc_locks {
                    if super::super::db::roots::is_root(&tag,&entry) {
                        if let Some(root) = db.voucher_root(&entry.layer2_voucher_id)? { hmc.push((tag,root)); classes.push(0); }
                    } else if let Some(row) = db.get_hmc_lock(&tag)? {
                        classes.push(db.confirmation_support(&tag)?.map_or(0,|f|f.class)); hmc.push((tag,row));
                    }
                }
                page.payload.hmc_locks = hmc;
                Ok::<_,StorageError>((page,classes))
            }).await.map_err(|e|error(&format!("publication worker: {e}")))??;
            {
                let mut ram = self.ram.write().await;
                for (row,root) in page.payload.locks { ram.insert_recovered(row,SimTime(root)); }
            }
            {
                let mut ram = self.hmc_ram.write().await;
                for ((tag,entry),class) in page.payload.hmc_locks.into_iter().zip(classes) {
                    ram.insert_recovered(tag.clone(),entry.clone());
                    ram.set_confirmation_class(&tag,class);
                    if let Some(root) = ram.voucher_roots.get(&entry.layer2_voucher_id).copied() { ram.mark_exact_durable(&tag,&entry,root); }
                }
            }
            if !page.has_more { break; }
            cursor = page.next_cursor.ok_or_else(||error("publication cursor missing"))?;
        }
        Ok(())
    }
}
