use humoco_sim_core::types::{LockRecord,LockStatus,SimTime};
#[tokio::main]
async fn main() {
 let peers=recovery::recovery_peers(4).await;
 let shard:u16=0x4a71;
 let now=peers[0].manager.net_time_ms();
 let mut parent=[7;32]; parent[..2].copy_from_slice(&shard.to_be_bytes());
 let mut row=LockRecord::new(parent,[8;32],vec![9],SimTime(now),SimTime(now+600_000));
 row.status=LockStatus::Final{sigs:14};
 for peer in &peers[1..] {
  peer.db.put_lock(&row,now+600_000).unwrap();
  peer.engine.recover_from_disk(SimTime(now)).await.unwrap();
  assert_eq!(peer.db.get_lock(&parent).unwrap().unwrap().0.status.confirmation_class(),2);
  peer.readiness.mark_shard_ready(shard);
 }
 let target=&peers[0];
 assert!(humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,&target.identity,&target.readiness,&target.cancel).await.unwrap());
 let installed=target.db.get_lock(&parent).unwrap().unwrap().0.status.confirmation_class();
 assert_eq!(installed,1);
 println!("AUDIT: three ready sources store class2; fresh island target installs class{installed} over real QUIC and becomes ready");
 recovery::stop_recovery_peers(peers).await;
}
