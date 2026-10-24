use humoco_sim_core::{types::{LockRecord,SimTime},wire::{MsgType,WireHeader}};
#[tokio::main]
async fn main() {
 let peers=recovery::recovery_peers(2).await;
 let source=&peers[1]; let reader=&peers[0];
 let now=source.manager.net_time_ms();
 let row=LockRecord::new([7;32],[8;32],vec![9],SimTime(now),SimTime(now+600_000));
 let shard=u16::from_be_bytes([7,7]);
 source.engine.ram.write().await.insert_recovered(row.clone(),SimTime(now+600_000));
 source.engine.stats.signing_failed.store(true,std::sync::atomic::Ordering::Release);
 assert!(!source.engine.is_signing_healthy());
 assert!(!source.readiness.is_shard_ready(shard));
 assert!(source.db.get_lock(&row.parent_lock).unwrap().is_none());
 let conn=reader.network.connect_peer(source.network.local_addr().unwrap()).await.unwrap();
 let bytes=bincode::serialize(&(row.id,row.parent_lock,shard)).unwrap();
 let (header,reply)=reader.network.send_request(&conn,&WireHeader::new(MsgType::StatusQuery as u16,1,0,1,bytes.len() as u32),&bytes).await.unwrap();
 assert_eq!(header.flags,0);
 let approval=humoco_node::api::dto::AttestationDto::from_wire_bytes(&reply).unwrap();
 let digest=human_money_core::humoco_proto::live::original_approval_digest(0,shard,1,&row.parent_lock,&row.id).unwrap();
 let signature:[u8;64]=human_money_core::hex::decode(&approval.signature).unwrap().try_into().unwrap();
 source.identity.verifying_key().verify_strict(&digest,&ed25519_dalek::Signature::from_bytes(&signature)).unwrap();
 assert!(source.db.get_lock(&row.parent_lock).unwrap().is_none());
 println!("AUDIT: real QUIC StatusQuery returned a valid FINAL-domain original approval while signing health=false, shard readiness=false, and lock absent from disk");
 recovery::stop_recovery_peers(peers).await;
}
