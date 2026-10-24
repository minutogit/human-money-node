use humoco_node::identity::NodeIdentity;
use humoco_sim_core::types::SimTime;
#[tokio::main]
async fn main() {
 let peers=recovery::recovery_peers(20).await;
 let now=peers[0].manager.net_time_ms();
 let (root_tag,root,tag,spend,shard)=signed_hmc_cut(now);
 for peer in &peers {peer.manager.set_ge20_anchor_for_test(now-86_400_001);}
 for peer in &peers[4..] {
  peer.db.put_hmc_lock(&root_tag,&root).unwrap();
  peer.db.put_hmc_lock(&tag,&spend).unwrap();
  peer.engine.recover_from_disk(SimTime(now)).await.unwrap();
  peer.readiness.mark_shard_ready(shard);
 }
 for target in &peers[..3] {
  assert!(humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,&target.identity,&target.readiness,&target.cancel).await.unwrap());
  assert_eq!(target.db.confirmation_support(&tag).unwrap().unwrap().class,2);
  tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
 }
 for peer in &peers[..4] {
  for absent in &peers[4..] {peer.manager.set_last_seen_for_test(absent.identity.node_pubkey(),std::time::Instant::now()-std::time::Duration::from_secs(4*3600)).await;}
 }
 let target=&peers[3];
 assert!(target.db.confirmation_support(&tag).unwrap().is_none());
 assert!(humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,&target.identity,&target.readiness,&target.cancel).await.unwrap());
 let installed=target.db.confirmation_support(&tag).unwrap().unwrap().class;
 assert_eq!(installed,1);
 println!("AUDIT: three HMC sources obtained verified class2 via actual 14-witness QUIC sync; fresh island target installs class{installed} and becomes ready");
 recovery::stop_recovery_peers(peers).await;
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
    let mut proof = human_money_core::humoco_proto::causal::CausalOutputProof { version:1,voucher_id:root.layer2_voucher_id.clone(),
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

