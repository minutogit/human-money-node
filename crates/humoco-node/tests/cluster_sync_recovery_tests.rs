//! Wire-level immutable snapshot and resource-ceiling regressions.
use humoco_node::{
    identity::NodeIdentity,
    network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport},
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::{
    types::{LockRecord, SimTime},
    wire::{MsgType, WireHeader},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn fixed_snapshot_cursor_survives_concurrent_insert_delete_and_rejects_foreign_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let source = NodeIdentity::generate();
    let reader = NodeIdentity::generate();
    let outsider = NodeIdentity::generate();
    let source_pm = Arc::new(PeerManager::with_f2f(
        vec![],
        vec![*reader.node_pubkey(), *outsider.node_pubkey()],
    ));
    let reader_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    let other_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    let source_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &source,
        source_pm.clone(),
        Arc::new(NodeRequestHandler::new(engine, db.clone(), source.clone())),
        cancel.clone(),
    )
    .unwrap();
    let reader_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &reader,
        reader_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let other_net = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &outsider,
        other_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    for (key, addr) in [
        (*reader.node_pubkey(), reader_net.local_addr().unwrap()),
        (*outsider.node_pubkey(), other_net.local_addr().unwrap()),
    ] {
        source_pm.register_f2f_friend(key, Some(addr)).await;
    }
    for pm in [&reader_pm, &other_pm] {
        pm.register_f2f_friend(
            *source.node_pubkey(),
            Some(source_net.local_addr().unwrap()),
        )
        .await;
    }
    source_net.spawn_accept_loop();
    reader_net.spawn_accept_loop();
    other_net.spawn_accept_loop();
    let conn = reader_net
        .connect_peer(source_net.local_addr().unwrap())
        .await
        .unwrap();
    let other = other_net
        .connect_peer(source_net.local_addr().unwrap())
        .await
        .unwrap();
    let record =
        |i: u8| LockRecord::new([i; 32], [8; 32], vec![i], SimTime(1_000), SimTime(50_000));
    for i in 1..=3 {
        db.put_lock(&record(i), 50_000).unwrap();
    }
    let first = reader_net
        .request_active_sync_page(&conn, 1, 0, 1)
        .await
        .unwrap();
    assert_eq!(first.payload.locks[0].0.parent_lock, [1; 32]);
    let cursor = first.next_cursor.unwrap();
    db.prune_expired_buckets(81).unwrap();
    db.put_lock(&record(4), 50_000).unwrap();
    assert!(
        other_net
            .request_active_sync_page(&other, 2, cursor, 1)
            .await
            .is_err(),
        "an authenticated different peer cannot consume this cut"
    );
    let second = reader_net
        .request_active_sync_page(&conn, 3, cursor, 1)
        .await
        .unwrap();
    assert_eq!(second.payload.locks[0].0.parent_lock, [2; 32]);
    let third = reader_net
        .request_active_sync_page(&conn, 4, second.next_cursor.unwrap(), 1)
        .await
        .unwrap();
    assert_eq!(third.payload.locks[0].0.parent_lock, [3; 32]);
    assert!(!third.has_more);
    let fresh = reader_net
        .request_active_sync_page(&conn, 5, 0, 10)
        .await
        .unwrap();
    assert_eq!(fresh.payload.locks.len(), 1);
    assert_eq!(fresh.payload.locks[0].0.parent_lock, [4; 32]);
    // Send only the oversized header. Rejection must precede payload reads.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&WireHeader::new(MsgType::ActiveSyncRequest as u16, 6, 0, 0, 65_537).to_bytes())
        .await
        .unwrap();
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(1), recv.read_to_end(64))
        .await
        .expect("header rejection must not await the declared body");
    assert!(rejected.is_err() || rejected.unwrap().is_empty());
    cancel.cancel();
    worker.await.unwrap();
}

struct HoldSync {
    entered: tokio::sync::mpsc::Sender<()>,
    release: CancellationToken,
}
impl humoco_node::network::RequestHandler for HoldSync {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> humoco_node::network::BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::error::NodeError>>
    {
        let entered = self.entered.clone();
        let release = self.release.clone();
        Box::pin(async move {
            if header.msg_type == MsgType::ActiveSyncRequest as u16 {
                let _ = entered.send(()).await;
                release.cancelled().await;
            }
            humoco_node::network::RequestHandler::handle(&DefaultRequestHandler, header, payload)
                .await
        })
    }
}
#[tokio::test]
async fn thirty_two_stalled_sync_jobs_do_not_consume_reserved_shard_rpc_slots() {
    let source = NodeIdentity::generate();
    let reader = NodeIdentity::generate();
    let stop = CancellationToken::new();
    let release = CancellationToken::new();
    let source_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*reader.node_pubkey()]));
    let reader_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*source.node_pubkey()]));
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    let server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &source,
        source_pm.clone(),
        Arc::new(HoldSync {
            entered: tx,
            release: release.clone(),
        }),
        stop.clone(),
    )
    .unwrap();
    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &reader,
        reader_pm.clone(),
        Arc::new(DefaultRequestHandler),
        stop.clone(),
    )
    .unwrap();
    source_pm
        .register_f2f_friend(*reader.node_pubkey(), Some(client.local_addr().unwrap()))
        .await;
    reader_pm
        .register_f2f_friend(*source.node_pubkey(), Some(server.local_addr().unwrap()))
        .await;
    server.spawn_accept_loop();
    client.spawn_accept_loop();
    let conn = client
        .connect_peer(server.local_addr().unwrap())
        .await
        .unwrap();
    let mut jobs = tokio::task::JoinSet::new();
    for seq in 0..32 {
        let client = client.clone();
        let conn = conn.clone();
        jobs.spawn(async move {
            client
                .send_request(
                    &conn,
                    &WireHeader::new(MsgType::ActiveSyncRequest as u16, seq, 0, 0, 0),
                    &[],
                )
                .await
        });
    }
    for _ in 0..32 {
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(client
        .send_request(
            &conn,
            &WireHeader::new(MsgType::ActiveSyncRequest as u16, 33, 0, 0, 0),
            &[]
        )
        .await
        .is_err());
    let (reply, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 34, 0, 0, 0),
            &[],
        ),
    )
    .await
    .expect("shard RPC must progress while sync is stalled")
    .unwrap();
    assert_eq!(reply.msg_type, MsgType::StatusResponse as u16);
    release.cancel();
    while let Some(result) = jobs.join_next().await {
        assert!(result.unwrap().is_ok());
    }
    stop.cancel();
}

#[tokio::test]
async fn large_cut_installs_atomically_and_preserves_current_support_after_restart() {
    let peers = recovery_peers(4).await;
    let shard: u16 = 0x4721;
    let now = peers[0].manager.net_time_ms();
    let records: Vec<_> = (0..10_050u32).map(|i| {
        let mut parent = [0u8;32]; parent[..2].copy_from_slice(&shard.to_be_bytes()); parent[2..6].copy_from_slice(&i.to_be_bytes());
        LockRecord::new(parent,[9;32],i.to_le_bytes().to_vec(),SimTime(now),SimTime(now+600_000))
    }).collect();
    for source in &peers[1..] {
        source.db.put_locks_batch(records.iter().map(|row|(row,now+600_000))).unwrap();
        source.engine.recover_from_disk(SimTime(now)).await.unwrap();
        source.readiness.mark_shard_ready(shard);
    }
    let mut minority_parent = [255;32]; minority_parent[..2].copy_from_slice(&shard.to_be_bytes());
    let minority = LockRecord::new(minority_parent,[8;32],vec![8],SimTime(now),SimTime(now+600_000));
    peers[0].db.put_lock(&minority,now+600_000).unwrap();
    peers[0].engine.recover_from_disk(SimTime(now)).await.unwrap();
    assert!(!peers[0].readiness.is_shard_ready(shard));
    let target = &peers[0];
    let ready = humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,
        &target.identity,&target.readiness,&target.cancel).await.unwrap();
    assert!(ready,"a complete current quorum cut must activate after its commit");
    assert!(target.readiness.is_shard_ready(shard));
    assert!(target.db.get_lock(&minority_parent).unwrap().is_none());
    assert!(target.db.get_provisional_lock(&minority_parent).unwrap().is_some());
    assert_eq!(target.db.committed_shard_digest(shard,now).unwrap().1,10_050);
    for row in [&records[0],&records[10_049]] {
        let saved = target.db.get_lock(&row.parent_lock).unwrap().unwrap().0;
        assert_eq!(saved.id,row.id);
        assert_eq!(saved.status.confirmation_class(),1);
        assert_eq!(target.engine.get_ram_lock(&row.parent_lock).await.unwrap().id,row.id);
    }
    let reopen_db = target.db.clone();
    stop_recovery_peers(peers).await;
    let (recovered,worker) = DualTierEngine::new(reopen_db);
    recovered.recover_from_disk(SimTime(now)).await.unwrap();
    assert_eq!(recovered.get_ram_lock(&records[0].parent_lock).await.unwrap().status.confirmation_class(),1);
    drop(recovered); worker.abort();
}

#[tokio::test]
async fn authenticated_source_fence_blocks_same_shard_writes_and_rejects_foreign_release() {
    let peers = recovery_peers(4).await;
    let shard: u16 = 0x3124;
    let source = &peers[1]; let target = &peers[0]; let outsider = &peers[2];
    source.readiness.mark_shard_ready(shard);
    let conn = target.network.connect_peer(source.network.local_addr().unwrap()).await.unwrap();
    let lease = target.network.request_frozen_shard(&conn,shard,1).await.unwrap();
    let now = source.manager.net_time_ms();
    let make_row = |shard:u16| { let mut parent = [7;32]; parent[..2].copy_from_slice(&shard.to_be_bytes());
        LockRecord::new(parent,[8;32],vec![9],SimTime(now),SimTime(now+60_000)) };
    assert!(source.engine.ingress_lock(make_row(shard),SimTime(now),SimTime(now+60_000)).await.is_err());
    assert!(source.engine.ingress_lock(make_row(shard+1),SimTime(now),SimTime(now+60_000)).await.is_ok());
    let other_conn = outsider.network.connect_peer(source.network.local_addr().unwrap()).await.unwrap();
    assert!(outsider.network.release_frozen_shard(&other_conn,shard,2,lease.token).await.is_err());
    assert!(source.engine.ingress_lock(make_row(shard),SimTime(now),SimTime(now+60_000)).await.is_err());
    target.network.release_frozen_shard(&conn,shard,3,lease.token).await.unwrap();
    assert!(source.engine.ingress_lock(make_row(shard),SimTime(now),SimTime(now+60_000)).await.is_ok());
    assert!(target.network.release_frozen_shard(&conn,shard,4,lease.token).await.is_err());
    stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn corrupt_later_wire_page_keeps_productive_state_and_readiness_unchanged() {
    let peers = recovery_peers_mode(4,true).await;
    let shard: u16 = 0x2743;
    let now = peers[0].manager.net_time_ms();
    let rows: Vec<_> = (0..600u32).map(|i| {
        let mut parent = [0;32]; parent[..2].copy_from_slice(&shard.to_be_bytes()); parent[2..6].copy_from_slice(&i.to_be_bytes());
        LockRecord::new(parent,[9;32],i.to_le_bytes().to_vec(),SimTime(now),SimTime(now+600_000))
    }).collect();
    for source in &peers[1..] {
        source.db.put_locks_batch(rows.iter().map(|row|(row,now+600_000))).unwrap();
        source.engine.recover_from_disk(SimTime(now)).await.unwrap(); source.readiness.mark_shard_ready(shard);
    }
    let mut parent = [255;32]; parent[..2].copy_from_slice(&shard.to_be_bytes());
    let old = LockRecord::new(parent,[8;32],vec![7],SimTime(now),SimTime(now+600_000));
    let target = &peers[0]; target.db.put_lock(&old,now+600_000).unwrap(); target.engine.recover_from_disk(SimTime(now)).await.unwrap();
    let before = target.db.committed_shard_digest(shard,now).unwrap();
    let ready = humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,
        &target.identity,&target.readiness,&target.cancel).await.unwrap();
    assert!(!ready); assert!(!target.readiness.is_shard_ready(shard));
    assert_eq!(target.db.committed_shard_digest(shard,now).unwrap(),before);
    assert_eq!(target.engine.get_ram_lock(&parent).await.unwrap().id,old.id);
    assert!(target.db.get_provisional_lock(&parent).unwrap().is_none());
    assert!(target.engine.is_signing_healthy());
    for source in &peers[1..] { assert!(source.engine.ingress_lock(old.clone(),SimTime(now),SimTime(now+600_000)).await.is_ok(),"all source fences released after failed transfer"); }
    stop_recovery_peers(peers).await;
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

#[tokio::test]
async fn fourteen_live_cut_witnesses_establish_hmc_support_without_history_and_island_sync_preserves_class_two() {
    use std::time::{Duration,Instant};
    let peers = recovery_peers(20).await;
    let now = peers[0].manager.net_time_ms();
    let (root_tag,root,spend_tag,spend,shard) = signed_hmc_cut(now);
    for peer in &peers {
        peer.manager.set_ge20_anchor_for_test(now-86_400_001);
        assert!(peer.manager.is_network_stable_ge20_for_24h(now));
    }
    for source in &peers[1..15] {
        source.db.put_hmc_lock(&root_tag,&root).unwrap();
        source.db.put_hmc_lock(&spend_tag,&spend).unwrap();
        source.engine.recover_from_disk(SimTime(now)).await.unwrap();
        source.readiness.mark_shard_ready(shard);
        assert!(source.db.confirmation_support(&spend_tag).unwrap().is_none(),"no historical quorum bundles or invented source facts");
    }
    let target = &peers[0];
    let ready = humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,
        &target.identity,&target.readiness,&target.cancel).await.unwrap();
    assert!(ready,"14 real distinct authenticated current cut witnesses must suffice");
    assert_eq!(target.db.confirmation_support(&spend_tag).unwrap().unwrap().class,2);
    assert_eq!(target.engine.hmc_ram.read().await.get_confirmation_class(&spend_tag),2);
    assert!(target.db.get_hmc_lock(&root_tag).unwrap().is_none(),"root is never a collision lock");
    assert!(target.db.voucher_root(&root.layer2_voucher_id).unwrap().is_some());
    // Later the same current choices survive in an island. A lower current
    // threshold cannot erase previously verified class-2 support.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    for peer in &peers[..4] {
        for absent in &peers[4..] { peer.manager.set_last_seen_for_test(absent.identity.node_pubkey(),Instant::now()-Duration::from_secs(4*3600)).await; }
    }
    let ready = humoco_node::daemon::sync_single_shard(shard,&target.network,&target.manager,&target.engine,&target.db,
        &target.identity,&target.readiness,&target.cancel).await.unwrap();
    assert!(ready);
    assert_eq!(target.db.confirmation_support(&spend_tag).unwrap().unwrap().class,2);
    assert_eq!(target.engine.hmc_ram.read().await.get_confirmation_class(&spend_tag),2);
    let db = target.db.clone();
    stop_recovery_peers(peers).await;
    let (engine,worker) = DualTierEngine::new(db);
    engine.recover_from_disk(SimTime(now)).await.unwrap();
    assert_eq!(engine.hmc_ram.read().await.get_confirmation_class(&spend_tag),2);
    drop(engine); worker.abort();
}

#[tokio::test]
async fn shard_lease_cooldown_prevents_rapid_repeated_freezes() {
    let peers = recovery_peers(4).await;
    let shard: u16 = 0x3125;
    let source = &peers[1];
    let target = &peers[0];
    source.readiness.mark_shard_ready(shard);
    let conn = target.network.connect_peer(source.network.local_addr().unwrap()).await.unwrap();
    let lease = target.network.request_frozen_shard(&conn, shard, 1).await.unwrap();
    // Release the lease
    target.network.release_frozen_shard(&conn, shard, 2, lease.token).await.unwrap();
    // Immediate second freeze attempt on the same shard must fail due to lease cooldown
    let retry = target.network.request_frozen_shard(&conn, shard, 3).await;
    assert!(retry.is_err(), "lease cooldown must prevent rapid repeated freeze");
    // After cooldown period elapses (2.1s > LEASE_COOLDOWN_MS 2.0s), freezing succeeds again
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let second_lease = target.network.request_frozen_shard(&conn, shard, 4).await;
    assert!(second_lease.is_ok(), "refreeze must succeed after cooldown");
    let second_lease = second_lease.unwrap();
    target.network.release_frozen_shard(&conn, shard, 5, second_lease.token).await.unwrap();
    stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn small_mesh_growth_two_nodes_fails_closed_without_automatic_empty_db_fallback() {
    // Contract G2: A 2-node cluster requires 2/3 N + 1 = 2 witnesses for provisional quorum.
    // A target node cannot self-count its own unknown state, and 1 remote source is insufficient (< 2).
    // The target must fail closed and stay unready without an automatic empty-database fallback.
    let peers = recovery_peers(2).await;
    let shard: u16 = 0x1122;
    let target = &peers[0];
    let source = &peers[1];
    let now = target.manager.net_time_ms();
    let row = LockRecord::new([77; 32], [88; 32], vec![1], SimTime(now), SimTime(now + 600_000));
    source.db.put_lock(&row, now + 600_000).unwrap();
    source.engine.recover_from_disk(SimTime(now)).await.unwrap();
    source.readiness.mark_shard_ready(shard);

    // Target attempts sync
    let synced = humoco_node::daemon::sync_single_shard(
        shard,
        &target.network,
        &target.manager,
        &target.engine,
        &target.db,
        &target.identity,
        &target.readiness,
        &target.cancel,
    )
    .await
    .unwrap();
    assert!(!synced, "N=2 with only 1 remote cannot reach required quorum of 2");
    assert!(!target.readiness.is_shard_ready(shard), "shard must remain unready");
    assert!(target.db.get_lock(&row.parent_lock).unwrap().is_none(), "no partial unconfirmed import");
    stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn asymmetric_partition_8_6_6_blocks_finality_until_14_quorum_reunited() {
    // 20 peers: target is peer 0, remote peers 1..20 are all in the 20-node committee
    let peers = recovery_peers(20).await;
    let now = peers[0].manager.net_time_ms();
    let (root_tag, root, spend_tag, spend, shard) = signed_hmc_cut(now);
    for peer in &peers {
        peer.manager.set_ge20_anchor_for_test(now - 86_400_001);
    }
    // Partition into Group A (target peers[0] + sources peers[1..8] = 8 nodes),
    // Group B (peers[8..15] = 7 nodes), Group C (peers[15..20] = 5 nodes).
    // In Group A, sources 1..8 have the spend installed and ready.
    for source in &peers[1..8] {
        source.db.put_hmc_lock(&root_tag, &root).unwrap();
        source.db.put_hmc_lock(&spend_tag, &spend).unwrap();
        source.engine.recover_from_disk(SimTime(now)).await.unwrap();
        source.readiness.mark_shard_ready(shard);
    }
    // Group C (peers 15..20) has a conflicting minority lock on the same parent
    let mut rogue_spend = spend.clone();
    rogue_spend.t_id = [99; 32];
    for rogue in &peers[15..20] {
        rogue.db.put_hmc_lock(&root_tag, &root).unwrap();
        rogue.db.put_hmc_lock(&spend_tag, &rogue_spend).unwrap();
        rogue.engine.recover_from_disk(SimTime(now)).await.unwrap();
        rogue.readiness.mark_shard_ready(shard);
    }
    // Group B (peers 8..15) does not have the shard ready yet (partitioned).

    // In partition 8 (target can only collect 7 ready witnesses from peers 1..8): 7 remote < 14 required
    let target = &peers[0];
    let ready_in_partition = humoco_node::daemon::sync_single_shard(
        shard,
        &target.network,
        &target.manager,
        &target.engine,
        &target.db,
        &target.identity,
        &target.readiness,
        &target.cancel,
    )
    .await
    .unwrap();
    assert!(!ready_in_partition, "8-node partition (7 remote ready) cannot reach 14-node quorum");
    assert!(!target.readiness.is_shard_ready(shard));

    // Wait for lease cooldown from the first attempt before reuniting
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;

    // Now Group A and Group B reunite (peers 1..15 are ready and agree on the spend)
    for source in &peers[8..15] {
        source.db.put_hmc_lock(&root_tag, &root).unwrap();
        source.db.put_hmc_lock(&spend_tag, &spend).unwrap();
        source.engine.recover_from_disk(SimTime(now)).await.unwrap();
        source.readiness.mark_shard_ready(shard);
    }

    // Target now syncs with 14 available sources (peers 1..15 = 14 remote sources)
    let ready_after_merge = humoco_node::daemon::sync_single_shard(
        shard,
        &target.network,
        &target.manager,
        &target.engine,
        &target.db,
        &target.identity,
        &target.readiness,
        &target.cancel,
    )
    .await
    .unwrap();
    assert!(ready_after_merge, "14 reunited sources achieve BFT quorum and activate readiness");
    assert!(target.readiness.is_shard_ready(shard));
    assert_eq!(target.db.confirmation_support(&spend_tag).unwrap().unwrap().class, 2);

    // Group C node reconnects and syncs from dominant quorum after lease cooldown:
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let group_c_node = &peers[15];
    let mut minority_spend = spend.clone();
    minority_spend.t_id = [88; 32];
    let minority_tag = "minority-omitted-spend".to_string();
    group_c_node.db.put_hmc_lock(&minority_tag, &minority_spend).unwrap();
    group_c_node.engine.recover_from_disk(SimTime(now)).await.unwrap();

    let c_synced = humoco_node::daemon::sync_single_shard(
        shard,
        &group_c_node.network,
        &group_c_node.manager,
        &group_c_node.engine,
        &group_c_node.db,
        &group_c_node.identity,
        &group_c_node.readiness,
        &group_c_node.cancel,
    )
    .await
    .unwrap();
    assert!(c_synced, "Group C node adopts dominant quorum cut");
    assert!(group_c_node.readiness.is_shard_ready(shard));
    assert_eq!(group_c_node.db.get_hmc_lock(&spend_tag).unwrap().unwrap().t_id, spend.t_id);
    assert!(group_c_node.db.get_hmc_lock(&minority_tag).unwrap().is_none(), "omitted minority lock removed from active index");
    assert!(group_c_node.db.get_provisional_hmc_lock(&minority_tag).unwrap().is_some(), "omitted minority lock quarantined to provisional storage");

    stop_recovery_peers(peers).await;
}

#[path="common/recovery.rs"]
mod recovery;
use recovery::*;
