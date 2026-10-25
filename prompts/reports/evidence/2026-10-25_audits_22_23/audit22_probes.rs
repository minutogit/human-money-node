//! Audit-only probes. Each test asserts the required safe behavior.
#[path="common/recovery.rs"] mod recovery;
use humoco_node::{api::hmc::L2LockEntry, storage::{DualTierEngine, HmcRamIndex, IngressOrigin, RedbStorage}};
use humoco_sim_core::{crypto::compute_canonical_hash, resolver::resolve_split_brain, types::{LockRecord,LockStatus,SimTime}};
use std::sync::Arc;
fn row(created: u64, now:u64) -> LockRecord {
 let mut row=LockRecord::new([21;32],[22;32],vec![23],SimTime(created),SimTime(now+600_000));
 row.status=LockStatus::Provisional { sigs:3,required:3 }; row
}
#[test]
fn audit22_equal_native_hash_must_be_order_independent() {
 let a=row(1_000,1_000); let b=row(1_001,1_000);
 assert_ne!(a.id,b.id); assert_eq!(compute_canonical_hash(&a.parent_lock,&a.receiver_pub,&a.nonce),compute_canonical_hash(&b.parent_lock,&b.receiver_pub,&b.nonce));
 let (mut aa,mut bb)=(a.clone(),b.clone()); resolve_split_brain(&mut aa,&mut bb);
 let winner_ab=if aa.status.is_void(){bb.id}else{aa.id};
 let (mut bb,mut aa)=(b,a); resolve_split_brain(&mut bb,&mut aa);
 let winner_ba=if bb.status.is_void(){aa.id}else{bb.id};
 assert_eq!(winner_ab,winner_ba,"valid same-class native locks must converge independently of arrival order");
}
#[tokio::test]
async fn audit22_equal_native_hash_must_converge_over_real_quic() {
 let mut winners=Vec::new();
 for reverse in [false,true] {
  let peers=recovery::recovery_peers(4).await; let now=peers[0].manager.net_time_ms();
  let a=row(1_000,now); let b=row(1_001,now); let shard=u16::from_be_bytes([21;2]);
  let (source,target)=if reverse{(b.clone(),a.clone())}else{(a.clone(),b.clone())};
  for (index,peer) in peers.iter().enumerate() {
   peer.db.put_lock(if index<3{&source}else{&target},now+600_000).unwrap();
   peer.engine.recover_from_disk(SimTime(now)).await.unwrap();
   if index<3{peer.readiness.mark_shard_ready(shard);}
  }
  let p=&peers[3];
  assert!(humoco_node::daemon::sync_single_shard(shard,&p.network,&p.manager,&p.engine,&p.db,&p.identity,&p.readiness,&p.cancel).await.unwrap());
  let actual=p.engine.get_ram_lock(&[21;32]).await.unwrap();
  winners.push(actual.created_at.0);
  recovery::stop_recovery_peers(peers).await;
 }
 assert_eq!(winners[0],winners[1],"equal-hash same-class native cuts must choose the same lock");
}
fn root() -> L2LockEntry {L2LockEntry {causal_output:None,layer2_voucher_id:"audit22-root".into(),t_id:[1;32],sender_ephemeral_pub:[2;32],receiver_ephemeral_pub_hash:None,change_ephemeral_pub_hash:None,layer2_signature:[0;64],trap_r:None,trap_s:None,encrypted_timestamp:0,created_at_ms:1_000,deletable_at:Some("50000".into()),privacy_guard:None}}
#[tokio::test]
async fn audit22_normal_pruning_must_remove_expired_root_metadata() {
 let dir=tempfile::tempdir().unwrap(); let db=Arc::new(RedbStorage::open(&dir.path().join("root.redb")).unwrap());
 let root=root(); db.put_hmc_lock(&bs58::encode(root.t_id).into_string(),&root).unwrap();
 let cancel=tokio_util::sync::CancellationToken::new();
 let (engine,worker)=DualTierEngine::new_with_token(db.clone(),cancel.clone());
 engine.recover_from_disk(SimTime(1_000)).await.unwrap();
 for _ in 0..3 { engine.prune_expired(SimTime(81_000)).await.unwrap(); }
 assert!(engine.hmc_ram.read().await.root_anchors.is_empty());
 let remains=db.voucher_root(&root.layer2_voucher_id).unwrap().is_some();
 cancel.cancel(); worker.await.unwrap();
 assert!(!remains,"normal daemon expiry must physically remove root metadata from disk");
}
#[test]
fn audit22_late_support_publication_must_not_demote_same_child() {
 let root=root(); let mut spend=root.clone();spend.t_id=[3;32];spend.deletable_at=None;
 let mut ram=HmcRamIndex::new();ram.insert_or_check(bs58::encode(root.t_id).into_string(),root,IngressOrigin::ClientApi,None);
 ram.insert_or_check("audit22-slot".into(),spend,IngressOrigin::ClientApi,None);
 // Legal interleaving: class1 commits, class2 commits and publishes, class1 resumes.
 ram.set_confirmation_class("audit22-slot",2);ram.set_confirmation_class("audit22-slot",1);
 assert_eq!(ram.get_confirmation_class("audit22-slot"),2,"late same-child support must preserve the higher class");
}
