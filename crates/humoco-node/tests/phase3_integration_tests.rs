use std::sync::Arc;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::api::hmc::{L2LockEntry, L2Verdict};
use humoco_node::identity::NodeIdentity;
use humoco_node::network::{
    DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport,
};
use humoco_node::storage::{compute_hmc_canonical_hash, DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::crypto::{compute_canonical_hash, sign_lock_attestation};
use humoco_sim_core::fraud::FraudProofPayload;
use humoco_sim_core::storage::IngressVerdictLow;
use humoco_sim_core::types::{LockRecord, SimTime};
use humoco_sim_core::wire::{MsgType, WireHeader};

/// 1. Test for deterministic Split-Brain healing via min(H_canon)
/// Winner replaces loser in RAM/disk state for both Sim LockRecord and HMC L2LockEntry.
#[tokio::test]
async fn test_phase3_split_brain_deterministic_healing_min_h_canon() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_split_brain.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let now = SimTime(10_000);
    let root_valid = SimTime(600_000);

    // --- Part A: Sim LockRecord min(H_canon) Resolution ---
    let parent_lock = [0xAA; 32];
    let receiver_loser = [0x11; 32];
    let receiver_winner = [0x22; 32];

    // Find nonces such that h_winner < h_loser
    let nonce_loser = vec![0x01];
    let mut nonce_winner = vec![0x02];

    let h_loser = compute_canonical_hash(&parent_lock, &receiver_loser, &nonce_loser);
    let mut h_winner = compute_canonical_hash(&parent_lock, &receiver_winner, &nonce_winner);

    let mut counter = 0u32;
    while h_winner >= h_loser {
        counter += 1;
        nonce_winner = counter.to_le_bytes().to_vec();
        h_winner = compute_canonical_hash(&parent_lock, &receiver_winner, &nonce_winner);
    }
    assert!(h_winner < h_loser, "h_winner must be strictly smaller than h_loser");

    let lock_loser = LockRecord::new(
        parent_lock,
        receiver_loser,
        nonce_loser.clone(),
        now,
        SimTime(60_000),
    );
    let lock_winner = LockRecord::new(
        parent_lock,
        receiver_winner,
        nonce_winner.clone(),
        now,
        SimTime(60_000),
    );

    // Step A1: Ingress loser lock first -> accepted
    let v1 = engine.ingress_lock(lock_loser.clone(), now, root_valid).await;
    assert_eq!(v1, Ok(IngressVerdictLow::AcceptedNew));
    assert_eq!(
        engine.get_ram_lock(&parent_lock).await.map(|l| l.id),
        Some(lock_loser.id),
        "Loser lock must be initially present in RAM"
    );

    // Step A1.5: ClientApi ingress with colliding winner lock -> RejectedCollision (never overwrites on live ingress)
    let v_client = engine
        .ingress_lock_with_origin(lock_winner.clone(), now, root_valid, IngressOrigin::ClientApi)
        .await;
    assert_eq!(
        v_client,
        Err(IngressVerdictLow::RejectedCollision),
        "Live ClientApi ingress must never overwrite an existing lock via min(H_canon)"
    );

    // Step A2: PartitionSync ingress winner lock second -> collision -> min(H_canon) resolves in favor of lock_winner!
    let v2 = engine
        .ingress_lock_with_origin(lock_winner.clone(), now, root_valid, IngressOrigin::PartitionSync)
        .await;
    assert_eq!(
        v2,
        Ok(IngressVerdictLow::AcceptedNew),
        "Winner lock must be accepted and replace the loser during PartitionSync"
    );
    assert_eq!(
        engine.get_ram_lock(&parent_lock).await.map(|l| l.id),
        Some(lock_winner.id),
        "RAM entry must be atomically replaced by the winner"
    );

    // Step A3: Ingress another loser lock (higher hash) via PartitionSync -> rejected collision, winner stays
    let mut nonce_loser2 = vec![0xFF];
    let mut h_loser2 = compute_canonical_hash(&parent_lock, &receiver_loser, &nonce_loser2);
    while h_loser2 <= h_winner {
        counter += 1;
        nonce_loser2 = counter.to_le_bytes().to_vec();
        h_loser2 = compute_canonical_hash(&parent_lock, &receiver_loser, &nonce_loser2);
    }
    let lock_loser2 = LockRecord::new(
        parent_lock,
        receiver_loser,
        nonce_loser2,
        now,
        SimTime(60_000),
    );
    let v3 = engine
        .ingress_lock_with_origin(lock_loser2, now, root_valid, IngressOrigin::PartitionSync)
        .await;
    assert_eq!(
        v3,
        Err(IngressVerdictLow::RejectedCollision),
        "Inferior lock must be rejected on collision"
    );
    assert_eq!(
        engine.get_ram_lock(&parent_lock).await.map(|l| l.id),
        Some(lock_winner.id),
        "Winner must remain active in RAM"
    );

    // Step A4: Verify disk persistence of the winner after flush batch
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let disk_lock = storage.get_lock(&parent_lock).expect("disk get").expect("lock present");
    assert_eq!(disk_lock.0.id, lock_winner.id, "Disk entry must be the winner lock");

    // --- Part B: HMC L2LockEntry min(H_canon) Resolution ---
    let lookup_tag = "voucher_tag_split_brain_test".to_string();
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();

    let sender_a = [0x33; 32];
    let sender_b = [0x44; 32];
    let t_id_loser = [0x55; 32];
    let mut t_id_winner = [0x66; 32];

    let h_hmc_loser = compute_hmc_canonical_hash(&parent_bytes, &sender_a, &t_id_loser);
    let mut h_hmc_winner = compute_hmc_canonical_hash(&parent_bytes, &sender_b, &t_id_winner);

    let mut hmc_counter = 0u32;
    while h_hmc_winner >= h_hmc_loser {
        hmc_counter += 1;
        t_id_winner[0..4].copy_from_slice(&hmc_counter.to_le_bytes());
        h_hmc_winner = compute_hmc_canonical_hash(&parent_bytes, &sender_b, &t_id_winner);
    }
    assert!(h_hmc_winner < h_hmc_loser);

    let entry_loser = L2LockEntry {
        layer2_voucher_id: "voucher_hmc_1".into(),
        t_id: t_id_loser,
        sender_ephemeral_pub: sender_a,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };

    let entry_winner = L2LockEntry {
        layer2_voucher_id: "voucher_hmc_1".into(),
        t_id: t_id_winner,
        sender_ephemeral_pub: sender_b,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };

    // Ingress HMC loser lock first
    let (v_hmc1, is_new1) = engine.ingress_hmc_lock(lookup_tag.clone(), entry_loser.clone()).await;
    assert!(is_new1);
    assert!(matches!(v_hmc1, L2Verdict::Verified { .. }));
    assert_eq!(
        engine.get_hmc_ram_lock(&lookup_tag).await.map(|e| e.t_id),
        Some(t_id_loser)
    );

    // Verify ClientApi ingress with colliding winner lock -> Rejected/Conflict (never overwrites on live ingress)
    let (v_hmc_client, is_new_client) = engine
        .ingress_hmc_lock_with_origin(lookup_tag.clone(), entry_winner.clone(), IngressOrigin::ClientApi, None)
        .await;
    assert!(!is_new_client);
    assert!(matches!(v_hmc_client, L2Verdict::Conflict { .. }), "Live ClientApi ingress must reject colliding HMC lock");

    // Ingress HMC winner lock second via PartitionSync -> should replace loser via min(H_canon)
    let (v_hmc2, is_new2) = engine
        .ingress_hmc_lock_with_origin(lookup_tag.clone(), entry_winner.clone(), IngressOrigin::PartitionSync, None)
        .await;
    assert!(is_new2, "Winner must trigger a new flush op to replace loser");
    assert!(matches!(v_hmc2, L2Verdict::Verified { .. }));
    assert_eq!(
        engine.get_hmc_ram_lock(&lookup_tag).await.map(|e| e.t_id),
        Some(t_id_winner),
        "HMC RAM entry must be replaced by the winner"
    );

    // Ingress another inferior HMC lock via PartitionSync -> must receive Conflict with existing winner lock
    let mut t_id_loser2 = [0x77; 32];
    let mut h_hmc_loser2 = compute_hmc_canonical_hash(&parent_bytes, &sender_a, &t_id_loser2);
    while h_hmc_loser2 <= h_hmc_winner {
        hmc_counter += 1;
        t_id_loser2[0..4].copy_from_slice(&hmc_counter.to_le_bytes());
        h_hmc_loser2 = compute_hmc_canonical_hash(&parent_bytes, &sender_a, &t_id_loser2);
    }
    let entry_loser2 = L2LockEntry {
        layer2_voucher_id: "voucher_hmc_1".into(),
        t_id: t_id_loser2,
        sender_ephemeral_pub: sender_a,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    let (v_hmc3, is_new3) = engine
        .ingress_hmc_lock_with_origin(lookup_tag.clone(), entry_loser2, IngressOrigin::PartitionSync, None)
        .await;
    assert!(!is_new3);
    match v_hmc3 {
        L2Verdict::Conflict { existing_lock } => {
            assert_eq!(existing_lock.t_id, t_id_winner, "Conflict must point to winner as existing lock");
        }
        _ => panic!("Expected Conflict verdict for inferior HMC lock"),
    }

    // Verify HMC disk persistence of the winner after flush
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let disk_hmc = storage.get_hmc_lock(&lookup_tag).expect("get_hmc_lock").expect("hmc present");
    assert_eq!(disk_hmc.t_id, t_id_winner, "HMC Disk entry must match winner");
}

/// 2. Test for Multi-Shard Sync including regular LockRecords and HMC-Locks.
#[tokio::test]
async fn test_phase3_multi_shard_and_hmc_sync() {
    let temp_a = tempdir().expect("tempdir");
    let storage_a = Arc::new(RedbStorage::open(&temp_a.path().join("a.redb")).unwrap());
    let (engine_a, _w_a) = DualTierEngine::new(storage_a.clone());
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));
    let handler_a = Arc::new(NodeRequestHandler::with_peer_manager(
        engine_a.clone(),
        storage_a.clone(),
        identity_a.clone(),
        pm_a.clone(),
    ));
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        handler_a,
        cancel_a.clone(),
    )
    .expect("bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    // Node B (Syncer)
    let temp_b = tempdir().expect("tempdir");
    let storage_b = Arc::new(RedbStorage::open(&temp_b.path().join("b.redb")).unwrap());
    let (engine_b, _w_b) = DualTierEngine::new(storage_b.clone());
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));

    let handler_b = Arc::new(DefaultRequestHandler);
    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        handler_b,
        cancel_b.clone(),
    )
    .expect("bind transport B");
    let addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    // Register reciprocal F2F friends
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b)).await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a)).await;

    // Populate Node A with locks in multiple shards:
    // Shard 0 lock
    let mut parent_shard_0 = [0u8; 32];
    parent_shard_0[0..2].copy_from_slice(&0u16.to_be_bytes());
    let lock_shard_0 = LockRecord::new(
        parent_shard_0,
        [0x10; 32],
        b"nonce_shard_0".to_vec(),
        SimTime(0),
        SimTime(60_000),
    );
    let _ = engine_a.ingress_lock(lock_shard_0.clone(), SimTime(0), SimTime(600_000)).await;

    // Shard 42 lock
    let mut parent_shard_42 = [0u8; 32];
    parent_shard_42[0..2].copy_from_slice(&42u16.to_be_bytes());
    let lock_shard_42 = LockRecord::new(
        parent_shard_42,
        [0x20; 32],
        b"nonce_shard_42".to_vec(),
        SimTime(0),
        SimTime(60_000),
    );
    let _ = engine_a.ingress_lock(lock_shard_42.clone(), SimTime(0), SimTime(600_000)).await;

    // HMC lock on a specific voucher tag
    let hmc_tag = "voucher_multi_shard_sync_tag".to_string();
    let hmc_parent = *blake3::hash(hmc_tag.as_bytes()).as_bytes();
    let hmc_shard_id = u16::from_be_bytes([hmc_parent[0], hmc_parent[1]]);
    let hmc_entry = L2LockEntry {
        layer2_voucher_id: "voucher_sync_123".into(),
        t_id: [0x77; 32],
        sender_ephemeral_pub: [0x88; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    let _ = engine_a.ingress_hmc_lock(hmc_tag.clone(), hmc_entry.clone()).await;

    // Wait 100ms for flush on Node A
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect Node B to Node A
    let conn_b = transport_b.connect_peer(addr_a).await.expect("connect B -> A");

    // Execute ActiveSync request
    let sync_payload = transport_b.request_active_sync(&conn_b, 1).await.expect("request_active_sync");
    assert!(!sync_payload.locks.is_empty(), "Should receive regular locks");
    assert!(!sync_payload.hmc_locks.is_empty(), "Should receive HMC locks");

    // Ingress received sync locks into Node B's engine via PartitionSync
    for (rec, rv) in sync_payload.locks {
        let _ = engine_b
            .ingress_lock_with_origin(rec, SimTime(0), SimTime(rv), IngressOrigin::PartitionSync)
            .await;
    }
    for (tag, entry) in sync_payload.hmc_locks {
        let _ = engine_b
            .ingress_hmc_lock_with_origin(tag, entry, IngressOrigin::PartitionSync, None)
            .await;
    }

    // Verify Node B now contains all multi-shard entries
    assert_eq!(
        engine_b.get_ram_lock(&parent_shard_0).await.map(|l| l.id),
        Some(lock_shard_0.id),
        "Shard 0 lock must be synced to Node B"
    );
    assert_eq!(
        engine_b.get_ram_lock(&parent_shard_42).await.map(|l| l.id),
        Some(lock_shard_42.id),
        "Shard 42 lock must be synced to Node B"
    );
    assert_eq!(
        engine_b.get_hmc_ram_lock(&hmc_tag).await.map(|e| e.t_id),
        Some(hmc_entry.t_id),
        "HMC lock must be synced to Node B"
    );

    // Verify ShardDigest queries from Node B to Node A match local Node B state across shards
    let (d_shard0, _cnt0) = transport_b.request_shard_digest(&conn_b, 0, 2).await.expect("shard 0 digest");
    assert_ne!(d_shard0, [0u8; 32]);

    let (d_shard42, _cnt42) = transport_b.request_shard_digest(&conn_b, 42, 3).await.expect("shard 42 digest");
    assert_ne!(d_shard42, [0u8; 32]);

    let (d_hmc_shard, _cnt_hmc) = transport_b.request_shard_digest(&conn_b, hmc_shard_id, 4).await.expect("hmc shard digest");
    assert_ne!(d_hmc_shard, [0u8; 32]);
}

/// 3. Test for Equivocation-Ban & Peer-Disconnect.
#[tokio::test]
async fn test_phase3_equivocation_ban_and_peer_disconnect() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("equivocation.redb")).unwrap());
    let (engine, _w) = DualTierEngine::new(storage.clone());

    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();

    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));

    // Connect engine to peer manager
    engine.set_peer_manager(pm_a.clone()).await;

    let handler_a = Arc::new(NodeRequestHandler::with_peer_manager(
        engine.clone(),
        storage.clone(),
        identity_a.clone(),
        pm_a.clone(),
    ));
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        handler_a.clone(),
        cancel_a.clone(),
    )
    .expect("bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    // Node B transport
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("bind transport B");
    let addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    // Register reciprocal F2F friends
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b)).await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a)).await;

    // Establish connection B -> A
    let conn_b = transport_b.connect_peer(addr_a).await.expect("connect B -> A");

    // Verify Peer B is recognized and authorized
    let offender_node_id = *identity_b.node_id();
    assert!(!pm_a.is_banned(&offender_node_id).await);
    assert!(!engine.is_node_banned(&offender_node_id).await);
    assert!(pm_a.can_authorize_direct_rpc(&conn_b.remote_address(), Some(&offender_node_id)).await);

    // Create a valid First-Party Equivocation Proof:
    // Peer B signs two conflicting attestations for the same parent_lock with different lock_ids!
    let parent_lock = [0x55; 32];
    let lock_id_1 = [0x11; 32];
    let lock_id_2 = [0x22; 32];
    let node_u16 = u16::from_le_bytes([offender_node_id[0], offender_node_id[1]]);

    let att_1 = sign_lock_attestation(node_u16, &lock_id_1, &parent_lock, SimTime(100));
    let att_2 = sign_lock_attestation(node_u16, &lock_id_2, &parent_lock, SimTime(200));

    let proof = FraudProofPayload::new_shard_equivocation(att_1, att_2);
    assert!(proof.verify(), "Proof must be cryptographically valid");

    let raw_proof = bincode::serialize(&proof).expect("serialize proof");
    let evidence_hash = *blake3::hash(&raw_proof).as_bytes();

    // Send EquivocationProof over the wire to Node A
    let proof_header = WireHeader::new(
        MsgType::EquivocationProof as u16,
        1,
        0,
        0,
        raw_proof.len() as u32,
    );
    let (resp_hdr, _resp_payload) = transport_b.send_request(&conn_b, &proof_header, &raw_proof).await.expect("send EquivocationProof");
    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Wait a brief moment for ban and connection closure to settle
    for _ in 0..50 {
        if engine.is_node_banned(&proof.perpetrator_node_id).await {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    // Verify:
    // 1. Offender is immediately banned in engine and peer_manager
    assert!(engine.is_node_banned(&proof.perpetrator_node_id).await, "Offender must be banned in DualTierEngine");
    assert!(pm_a.is_banned(&proof.perpetrator_node_id).await, "Offender must be banned in PeerManager");

    // 2. Evidence is durably persisted in redb
    let stored_evidence = storage.get_evidence(&evidence_hash).expect("get_evidence").expect("evidence found");
    assert_eq!(stored_evidence, raw_proof);

    // 3. Peering path authorization is revoked immediately
    assert!(
        !pm_a.can_authorize_direct_rpc(&conn_b.remote_address(), Some(&proof.perpetrator_node_id)).await,
        "Direct RPC authorization must be revoked for banned node"
    );

    // 4. Ingress signed by banned offender is rejected
    let banned_lock = LockRecord::new(
        [0x99; 32],
        proof.perpetrator_node_id,
        b"banned_sender".to_vec(),
        SimTime(0),
        SimTime(60_000),
    );
    let payload = bincode::serialize(&humoco_node::network::framing::LockWirePayload::Sim(
        banned_lock,
        600_000,
    )).unwrap();
    let banned_ingress_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        2,
        0,
        0,
        payload.len() as u32,
    );

    use humoco_node::network::RequestHandler;
    let (ingress_resp_hdr, ingress_resp_bytes) = handler_a.handle(banned_ingress_header, payload).await.expect("handle");
    assert_eq!(ingress_resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);
    assert!(ingress_resp_bytes.is_empty(), "Banned node ingress must produce empty rejected response");
}
