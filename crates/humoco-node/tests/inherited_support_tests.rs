//! Inherited support crosses actual authenticated current-cut recovery, never raw status.
#[path="common/recovery.rs"] mod recovery;
use humoco_node::{identity::NodeIdentity,storage::RedbStorage};
use humoco_sim_core::types::{SimTime,LockRecord,LockStatus};
use std::sync::Arc;
async fn sync(peer:&recovery::RecoveryPeer,shard:u16) -> bool {
 humoco_node::daemon::sync_single_shard(shard,&peer.network,&peer.manager,&peer.engine,&peer.db,&peer.identity,&peer.readiness,&peer.cancel).await.unwrap()
}
#[tokio::test]
async fn genuine_native_and_hmc_support_survives_fresh_island_transfer_backup_reopen_and_second_recipient() {
 let mut peers=recovery::recovery_peers(20).await;
 let now=peers[0].manager.net_time_ms();
 let (root_tag,root,tag,spend,shard)=signed_hmc_cut(now);
 let mut parent=[7;32]; parent[..2].copy_from_slice(&shard.to_be_bytes());
 let native=LockRecord::new(parent,[8;32],vec![9],SimTime(now),SimTime(now+600_000));
 for peer in &peers {peer.manager.set_ge20_anchor_for_test(now-86_400_001);}
 // Source availability/mature tickets are prepared premises. Native and HMC
 // class2 facts below are produced only by actual fourteen-source admission.
 for peer in &peers[5..] {
  peer.db.put_hmc_lock(&root_tag,&root).unwrap(); peer.db.put_hmc_lock(&tag,&spend).unwrap();
  peer.db.put_lock(&native,now+600_000).unwrap();
  peer.engine.recover_from_disk(SimTime(now)).await.unwrap(); peer.readiness.mark_shard_ready(shard);
 }
 for target in &peers[..3] {
  assert!(sync(target,shard).await);
  assert_eq!(target.db.confirmation_support(&tag).unwrap().unwrap().class,2);
  assert_eq!(target.db.get_lock(&parent).unwrap().unwrap().0.status.confirmation_class(),2);
  tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
 }
 for peer in &peers[..4] {
  for absent in &peers[4..] {peer.manager.set_last_seen_for_test(absent.identity.node_pubkey(),std::time::Instant::now()-std::time::Duration::from_secs(4*3600)).await;}
 }
 let target=&peers[3]; assert!(target.db.confirmation_support(&tag).unwrap().is_none());
 let mut weaker=native.clone();
 for n in 0u64..10_000 {
  weaker=LockRecord::new(parent,[8;32],n.to_le_bytes().to_vec(),SimTime(now),SimTime(now+600_000));
  if humoco_sim_core::crypto::compute_canonical_hash(&parent,&weaker.receiver_pub,&weaker.nonce)
    < humoco_sim_core::crypto::compute_canonical_hash(&parent,&native.receiver_pub,&native.nonce) {break;}
 }
 assert!(humoco_sim_core::crypto::compute_canonical_hash(&parent,&weaker.receiver_pub,&weaker.nonce)<humoco_sim_core::crypto::compute_canonical_hash(&parent,&native.receiver_pub,&native.nonce));
 weaker.status=LockStatus::Provisional{sigs:3,required:3};
 target.db.put_lock(&weaker,now+600_000).unwrap(); target.engine.recover_from_disk(SimTime(now)).await.unwrap();
 assert!(sync(target,shard).await);
 assert_eq!(target.db.confirmation_support(&tag).unwrap().unwrap().class,2);
 assert_eq!(target.engine.get_ram_lock(&parent).await.unwrap().status.confirmation_class(),2);
 assert_eq!(target.engine.get_ram_lock(&parent).await.unwrap().id,native.id);
 let backup=target._dir.path().join("inherited.backup.redb"); target.db.create_backup(&backup).unwrap();
 {
  let reopened=Arc::new(RedbStorage::open(&backup).unwrap());
  assert_eq!(reopened.confirmation_support(&tag).unwrap().unwrap().class,2);
  assert_eq!(reopened.get_lock(&parent).unwrap().unwrap().0.status.confirmation_class(),2);
  assert_eq!(reopened.native_confirmation_support(&parent).unwrap().unwrap().class,2);
  let token=tokio_util::sync::CancellationToken::new();
  let (engine,worker)=humoco_node::storage::DualTierEngine::new_with_token(reopened.clone(),token.clone());
  engine.recover_from_disk(SimTime(now)).await.unwrap();
  assert_eq!(engine.hmc_ram.read().await.get_confirmation_class(&tag),2);
  assert_eq!(engine.get_ram_lock(&parent).await.unwrap().status.confirmation_class(),2);
  reopened.prune_expired_buckets((now+631_000)/1000).unwrap();
  assert!(reopened.confirmation_support(&tag).unwrap().is_none());
  assert!(reopened.get_lock(&parent).unwrap().is_none());
  assert!(reopened.native_confirmation_support(&parent).unwrap().is_none());
  token.cancel(); worker.await.unwrap();
 }
 tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
 // Reopen the actual source database with the exact same node identity, fresh
 // handler and transport. Startup recovery alone does not grant readiness.
 let restarted=restart(peers.remove(3)).await;
 peers.insert(3,restarted);
 for peer in &peers {
  let addr=peers[3].network.local_addr().unwrap();
  peer.manager.register_f2f_friend(*peers[3].identity.node_pubkey(),Some(addr)).await;
  peer.manager.learn_node_from_gossip_with_hrw(*peers[3].identity.node_pubkey(),*peers[3].identity.hrw_routing_id(),addr,0,None).await;
 }
 assert!(!peers[3].readiness.is_shard_ready(shard));
 assert_eq!(peers[3].db.native_confirmation_support(&parent).unwrap().unwrap().class,2);
 assert_eq!(peers[3].engine.hmc_ram.read().await.get_confirmation_class(&tag),2);
 assert!(sync(&peers[3],shard).await);
 tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
 // A second fresh recipient has no earlier local support to preserve.
 for i in [0,1,3,4] {
  for (j,other) in peers.iter().enumerate() {
   peers[i].manager.set_last_seen_for_test(other.identity.node_pubkey(),if [0,1,3,4].contains(&j) {std::time::Instant::now()} else {std::time::Instant::now()-std::time::Duration::from_secs(4*3600)}).await;
  }
 }
 assert!(sync(&peers[4],shard).await);
 assert_eq!(peers[4].db.confirmation_support(&tag).unwrap().unwrap().class,2);
 assert_eq!(peers[4].engine.get_ram_lock(&parent).await.unwrap().status.confirmation_class(),2);
 recovery::stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn raw_native_final_status_cannot_establish_inherited_class_two() {
 let peers=recovery::recovery_peers(4).await;
 let now=peers[0].manager.net_time_ms();
 let mut row=LockRecord::new([17;32],[18;32],vec![19],SimTime(now),SimTime(now+60_000));
 row.status=LockStatus::Final { sigs:14 };
 let shard=u16::from_be_bytes([17;2]);
 for peer in &peers[..3] { peer.db.put_lock(&row,now+60_000).unwrap(); peer.engine.recover_from_disk(SimTime(now)).await.unwrap(); peer.readiness.mark_shard_ready(shard); }
 assert!(sync(&peers[3],shard).await);
 assert_eq!(peers[3].engine.get_ram_lock(&row.parent_lock).await.unwrap().status.confirmation_class(),1);
 assert_eq!(peers[3].db.native_confirmation_support(&row.parent_lock).unwrap().unwrap().class,1);
 recovery::stop_recovery_peers(peers).await;
}
#[tokio::test]
async fn real_quic_rejects_forged_cross_network_wrong_shard_and_wrong_receiver_support() {
 for fault in 1..=4 {
  let peers=recovery::recovery_peers_fault(4,false,fault).await;
  for peer in &peers[..3] {peer.readiness.mark_shard_ready(42);}
  assert!(!sync(&peers[3],42).await,"fault {fault}");
  assert!(!peers[3].readiness.is_shard_ready(42));
  recovery::stop_recovery_peers(peers).await;
 }
}

#[tokio::test]
async fn real_quic_source_only_promotion_and_expired_support_fail_before_install() {
 for fault in [5,6,7] {
  let peers=recovery::recovery_peers_fault(20,false,fault).await;
  let now=peers[0].manager.net_time_ms();
  let (root_tag,root,tag,spend,shard)=signed_hmc_cut(now);
  for peer in &peers[4..] {
   peer.db.put_hmc_lock(&root_tag,&root).unwrap(); peer.db.put_hmc_lock(&tag,&spend).unwrap();
   peer.engine.recover_from_disk(SimTime(now)).await.unwrap(); peer.readiness.mark_shard_ready(shard);
  }
  for target in &peers[..3] {
   assert!(sync(target,shard).await); assert_eq!(target.db.confirmation_support(&tag).unwrap().unwrap().class,1);
   tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
  }
  for peer in &peers[..4] {for absent in &peers[4..] {
   peer.manager.set_last_seen_for_test(absent.identity.node_pubkey(),std::time::Instant::now()-std::time::Duration::from_secs(4*3600)).await;
  }}
  let rejected=humoco_node::daemon::sync_single_shard(shard,&peers[3].network,&peers[3].manager,&peers[3].engine,&peers[3].db,&peers[3].identity,&peers[3].readiness,&peers[3].cancel).await;
  assert!(!matches!(rejected,Ok(true)),"fault {fault}");
  assert!(peers[3].db.get_hmc_lock(&tag).unwrap().is_none());
  assert!(peers[3].db.confirmation_support(&tag).unwrap().is_none());
  assert!(!peers[3].readiness.is_shard_ready(shard));
  recovery::stop_recovery_peers(peers).await;
 }
}

#[tokio::test]
async fn mixed_known_and_unknown_support_on_identical_objective_state_stays_unready() {
 let peers=recovery::recovery_peers(4).await;
 let now=peers[0].manager.net_time_ms();
 let row=LockRecord::new([21;32],[22;32],vec![23],SimTime(now),SimTime(now+60_000));
 let shard=u16::from_be_bytes([21;2]);
 for peer in &peers[1..] {
  peer.db.put_lock(&row,now+60_000).unwrap(); peer.engine.recover_from_disk(SimTime(now)).await.unwrap(); peer.readiness.mark_shard_ready(shard);
 }
 assert!(sync(&peers[0],shard).await);
 assert_eq!(peers[0].db.native_confirmation_support(&row.parent_lock).unwrap().unwrap().class,1);
 tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
 // Objective state agrees, but only source0 carries class1 provenance. The
 // full support-cut equality policy deliberately does not invent agreement.
 assert!(!sync(&peers[1],shard).await);
 assert!(!peers[1].readiness.is_shard_ready(shard));
 assert_eq!(peers[1].db.get_lock(&row.parent_lock).unwrap().unwrap().0.id,row.id);
 assert!(peers[1].db.native_confirmation_support(&row.parent_lock).unwrap().is_none());
 recovery::stop_recovery_peers(peers).await;
}

async fn restart(peer:recovery::RecoveryPeer) -> recovery::RecoveryPeer {
 use humoco_node::network::{NodeRequestHandler,QuicTransport};
 let recovery::RecoveryPeer { identity,manager,engine,db,network,readiness,cancel,worker,_dir }=peer;
 cancel.cancel(); network.close(); worker.await.unwrap();
 drop(network); drop(engine); drop(db); drop(readiness);
 // Wait for the actual redb file lock to be released by drained QUIC handlers.
 let mut reopened=None;
 for _ in 0..100 {
  match RedbStorage::open(&_dir.path().join("node.redb")) {
   Ok(db)=>{reopened=Some(db);break;},
   Err(_)=>tokio::time::sleep(std::time::Duration::from_millis(10)).await,
  }
 }
 let db=Arc::new(reopened.expect("all old source handles must release the database"));
 let cancel=tokio_util::sync::CancellationToken::new();
 let (engine,worker)=humoco_node::storage::DualTierEngine::new_with_token(db.clone(),cancel.clone());
 engine.recover_from_disk(SimTime(manager.net_time_ms())).await.unwrap();
 let readiness=Arc::new(humoco_node::daemon::ShardReadinessManager::new());
 let handler=Arc::new(NodeRequestHandler::with_peer_manager(engine.clone(),db.clone(),identity.clone(),manager.clone()).with_readiness_manager(readiness.clone()));
 let network=QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(),&identity,manager.clone(),handler,cancel.clone()).unwrap();
 network.spawn_accept_loop();
 recovery::RecoveryPeer { identity,manager,engine,db,network,readiness,cancel,worker,_dir }
}

fn signed_hmc_cut(now: u64) -> (String,humoco_node::api::hmc::L2LockEntry,String,humoco_node::api::hmc::L2LockEntry,u16) {
    use humoco_node::api::hmc::{L2AuthPayload,L2LockRequest,L2LockEntry,calculate_l2_payload_hash};
    use ed25519_dalek::Signer;
    use sha3::{Digest,Sha3_256};
    let author = NodeIdentity::generate();
    let mut root = L2LockRequest {
        causal_output:None,auth:L2AuthPayload { ephemeral_pubkey:*author.node_pubkey(),auth_signature:None },
        layer2_voucher_id:"current-support-fixture".into(),ds_tag:None,transaction_hash:[42;32],is_genesis:true,
        sender_ephemeral_pub:*author.node_pubkey(),receiver_ephemeral_pub_hash:None,change_ephemeral_pub_hash:None,
        layer2_signature:[0;64],trap_r:None,trap_s:None,encrypted_timestamp:0,created_at_ms:now,
        deletable_at:Some((now+600_000).to_string()),privacy_guard:None,
    };
    let mut proof = humoco_proto::causal::CausalOutputProof { version:1,voucher_id:root.layer2_voucher_id.clone(),
        transaction_id:root.transaction_hash,state_hash:[43;32],sender_pubkey:*author.node_pubkey(),
        receiver_pubkey_hash:Some(Sha3_256::digest(author.node_pubkey()).into()),change_pubkey_hash:None,
        root_valid_until_ms:now+600_000,is_root:true,signature:[0;64] };
    proof.signature = author.signing_key().sign(&proof.digest().unwrap()).to_bytes();
    root.causal_output = Some(proof);
    root.layer2_signature = author.signing_key().sign(&calculate_l2_payload_hash(&root)).to_bytes();
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    let shard = humoco_sim_core::types::canonical_voucher_shard(&humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag));
    let mut spend = root.clone(); spend.is_genesis = false; spend.deletable_at = None; spend.transaction_hash = [44;32];
    let mut hash = Sha3_256::new(); hash.update(32u32.to_le_bytes()); hash.update([43;32]);
    hash.update(32u32.to_le_bytes()); hash.update(author.node_pubkey());
    let spend_tag = bs58::encode(hash.finalize()).into_string(); spend.ds_tag = Some(spend_tag.clone());
    let mut proof = spend.causal_output.clone().unwrap(); proof.is_root = false; proof.transaction_id = spend.transaction_hash; proof.state_hash = [45;32];
    proof.signature = author.signing_key().sign(&proof.digest().unwrap()).to_bytes(); spend.causal_output = Some(proof);
    spend.layer2_signature = author.signing_key().sign(&calculate_l2_payload_hash(&spend)).to_bytes();
    (root_tag,L2LockEntry::from(&root),spend_tag,L2LockEntry::from(&spend),shard)
}

