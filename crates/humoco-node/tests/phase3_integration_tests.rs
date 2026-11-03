use ed25519_dalek::Signer;
use std::sync::Arc;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::api::hmc::{L2LockEntry, L2Verdict};
use humoco_node::identity::NodeIdentity;
use humoco_node::network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{
    compute_hmc_canonical_hash, DualTierEngine, IngressOrigin, RedbStorage,
};
use humoco_sim_core::fraud::FraudProofPayload;
use humoco_sim_core::types::SimTime;
use humoco_sim_core::wire::{MsgType, WireHeader};

async fn register_root(
    engine: &DualTierEngine,
    prototype: &L2LockEntry,
    key: &ed25519_dalek::SigningKey,
) -> String {
    use humoco_node::api::hmc::{
        calculate_l2_payload_hash_raw, privacy_guard_commitment, TRAP_NONE_PLACEHOLDER,
    };
    let mut root = prototype.clone();
    root.t_id = [0x42; 32];
    root.sender_ephemeral_pub = key.verifying_key().to_bytes();
    let tag = bs58::encode(root.t_id).into_string();
    let hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &tag,
        &root.t_id,
        &root.sender_ephemeral_pub,
        root.trap_r.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        root.trap_s.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        root.encrypted_timestamp,
        root.created_at_ms,
        root.deletable_at.as_deref(),
        privacy_guard_commitment(root.privacy_guard.as_deref()).as_str(),
    );
    root.layer2_signature = key.sign(&hash).to_bytes();
    let (verdict, _) = engine.ingress_hmc_lock(tag.clone(), root).await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));
    tag
}

/// 1. Test for deterministic Split-Brain healing via min(H_canon)
/// Winner replaces loser in RAM/disk state for HMC L2LockEntry.
#[tokio::test]
async fn test_phase3_split_brain_deterministic_healing_min_h_canon() {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_split_brain.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    // --- HMC L2LockEntry min(H_canon) Resolution ---
    let lookup_tag = "voucher_tag_split_brain_test".to_string();
    let parent_bytes = *blake3::hash(lookup_tag.as_bytes()).as_bytes();

    let key_a = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
    let sender_a = key_a.verifying_key().to_bytes();
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
    let sender_b = key_b.verifying_key().to_bytes();
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

    let sign_entry = |key: &ed25519_dalek::SigningKey, entry: &mut L2LockEntry| {
        use humoco_node::api::hmc::{
            calculate_l2_payload_hash_raw, privacy_guard_commitment, TRAP_NONE_PLACEHOLDER,
        };
        let is_genesis = lookup_tag == bs58::encode(&entry.t_id).into_string();
        let eff_v = if is_genesis {
            TRAP_NONE_PLACEHOLDER
        } else {
            &entry.layer2_voucher_id
        };
        let hash = calculate_l2_payload_hash_raw(
            eff_v,
            &lookup_tag,
            &entry.t_id,
            &entry.sender_ephemeral_pub,
            entry.trap_r.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
            entry.trap_s.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
            entry.encrypted_timestamp,
            entry.created_at_ms,
            entry.deletable_at.as_deref(),
            privacy_guard_commitment(entry.privacy_guard.as_deref()).as_str(),
        );
        entry.layer2_signature = key.sign(&hash).to_bytes();
    };

    let mut entry_loser = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "voucher_hmc_1".into(),
        t_id: t_id_loser,
        sender_ephemeral_pub: sender_a,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    sign_entry(&key_a, &mut entry_loser);

    let mut entry_winner = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "voucher_hmc_1".into(),
        t_id: t_id_winner,
        sender_ephemeral_pub: sender_b,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    sign_entry(&key_b, &mut entry_winner);

    register_root(&engine, &entry_loser, &key_a).await;

    // Ingress HMC loser lock first
    let (v_hmc1, is_new1) = engine
        .ingress_hmc_lock(lookup_tag.clone(), entry_loser.clone())
        .await;
    assert!(is_new1);
    assert!(matches!(v_hmc1, L2Verdict::Verified { .. }));
    assert_eq!(
        engine.get_hmc_ram_lock(&lookup_tag).await.map(|e| e.t_id),
        Some(t_id_loser)
    );

    // Verify ClientApi ingress with colliding winner lock -> Rejected/Conflict (never overwrites on live ingress)
    let (v_hmc_client, is_new_client) = engine
        .ingress_hmc_lock_with_origin(
            lookup_tag.clone(),
            entry_winner.clone(),
            IngressOrigin::ClientApi,
            None,
        )
        .await;
    assert!(!is_new_client);
    assert!(
        matches!(v_hmc_client, L2Verdict::Conflict { .. }),
        "Live ClientApi ingress must reject colliding HMC lock"
    );

    // Ingress HMC winner lock second via PartitionSync -> should replace loser via min(H_canon)
    let (v_hmc2, is_new2) = engine
        .ingress_hmc_lock_with_origin(
            lookup_tag.clone(),
            entry_winner.clone(),
            IngressOrigin::PartitionSync,
            None,
        )
        .await;
    assert!(
        is_new2,
        "Winner must trigger a new flush op to replace loser"
    );
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
    let mut entry_loser2 = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "voucher_hmc_1".into(),
        t_id: t_id_loser2,
        sender_ephemeral_pub: sender_a,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    sign_entry(&key_a, &mut entry_loser2);
    let (v_hmc3, is_new3) = engine
        .ingress_hmc_lock_with_origin(
            lookup_tag.clone(),
            entry_loser2,
            IngressOrigin::PartitionSync,
            None,
        )
        .await;
    assert!(!is_new3);
    match v_hmc3 {
        L2Verdict::Conflict { existing_lock } => {
            assert_eq!(
                existing_lock.t_id, t_id_winner,
                "Conflict must point to winner as existing lock"
            );
        }
        _ => panic!("Expected Conflict verdict for inferior HMC lock"),
    }

    // Verify HMC disk persistence of the winner after flush
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let disk_hmc = storage
        .get_hmc_lock(&lookup_tag)
        .expect("get_hmc_lock")
        .expect("hmc present");
    assert_eq!(
        disk_hmc.t_id, t_id_winner,
        "HMC Disk entry must match winner"
    );
}

/// 2. Test for Multi-Shard Sync with HMC-Locks.
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
        handler_a.clone(),
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
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a))
        .await;

    // Populate Node A with HMC locks:
    // Lock 1
    let hmc_tag_1 = "voucher_multi_shard_sync_tag_1".to_string();
    let hmc_key_1 = ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]);
    let hmc_pub_1 = hmc_key_1.verifying_key().to_bytes();
    let mut hmc_entry_1 = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "voucher_sync_1".into(),
        t_id: [0x77; 32],
        sender_ephemeral_pub: hmc_pub_1,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    {
        use humoco_node::api::hmc::{
            calculate_l2_payload_hash_raw, privacy_guard_commitment, TRAP_NONE_PLACEHOLDER,
        };
        let hash = calculate_l2_payload_hash_raw(
            &hmc_entry_1.layer2_voucher_id,
            &hmc_tag_1,
            &hmc_entry_1.t_id,
            &hmc_entry_1.sender_ephemeral_pub,
            TRAP_NONE_PLACEHOLDER,
            TRAP_NONE_PLACEHOLDER,
            hmc_entry_1.encrypted_timestamp,
            hmc_entry_1.created_at_ms,
            hmc_entry_1.deletable_at.as_deref(),
            privacy_guard_commitment(hmc_entry_1.privacy_guard.as_deref()).as_str(),
        );
        hmc_entry_1.layer2_signature = hmc_key_1.sign(&hash).to_bytes();
    }
    let root_tag_1 = register_root(&engine_a, &hmc_entry_1, &hmc_key_1).await;
    let root_parent_1 = *blake3::hash(root_tag_1.as_bytes()).as_bytes();
    let hmc_shard_id_1 = humoco_sim_core::types::extract_shard_id(&root_parent_1);
    let (verdict_1, _) = engine_a
        .ingress_hmc_lock(hmc_tag_1.clone(), hmc_entry_1.clone())
        .await;
    assert!(matches!(verdict_1, L2Verdict::Verified { .. }));

    // Lock 2
    let hmc_tag_2 = "voucher_multi_shard_sync_tag_2".to_string();
    let hmc_key_2 = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
    let hmc_pub_2 = hmc_key_2.verifying_key().to_bytes();
    let mut hmc_entry_2 = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "voucher_sync_2".into(),
        t_id: [0x78; 32],
        sender_ephemeral_pub: hmc_pub_2,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("600000".into()),
        privacy_guard: None,
    };
    {
        use humoco_node::api::hmc::{
            calculate_l2_payload_hash_raw, privacy_guard_commitment, TRAP_NONE_PLACEHOLDER,
        };
        let hash = calculate_l2_payload_hash_raw(
            &hmc_entry_2.layer2_voucher_id,
            &hmc_tag_2,
            &hmc_entry_2.t_id,
            &hmc_entry_2.sender_ephemeral_pub,
            TRAP_NONE_PLACEHOLDER,
            TRAP_NONE_PLACEHOLDER,
            hmc_entry_2.encrypted_timestamp,
            hmc_entry_2.created_at_ms,
            hmc_entry_2.deletable_at.as_deref(),
            privacy_guard_commitment(hmc_entry_2.privacy_guard.as_deref()).as_str(),
        );
        hmc_entry_2.layer2_signature = hmc_key_2.sign(&hash).to_bytes();
    }
    let root_tag_2 = register_root(&engine_a, &hmc_entry_2, &hmc_key_2).await;
    let root_parent_2 = *blake3::hash(root_tag_2.as_bytes()).as_bytes();
    let hmc_shard_id_2 = humoco_sim_core::types::extract_shard_id(&root_parent_2);
    let (verdict_2, _) = engine_a
        .ingress_hmc_lock(hmc_tag_2.clone(), hmc_entry_2.clone())
        .await;
    assert!(matches!(verdict_2, L2Verdict::Verified { .. }));

    // Wait 100ms for flush on Node A
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect Node B to Node A
    let conn_b = transport_b
        .connect_peer(addr_a)
        .await
        .expect("connect B -> A");

    // Execute ActiveSync request
    let sync_payload = transport_b
        .request_active_sync(&conn_b, 1)
        .await
        .expect("request_active_sync");
    assert!(
        !sync_payload.hmc_locks.is_empty(),
        "Should receive HMC locks"
    );

    // Ingress received sync locks into Node B's engine via PartitionSync
    for (tag, entry) in sync_payload.hmc_locks {
        let _ = engine_b
            .ingress_hmc_lock_with_origin(tag, entry, IngressOrigin::PartitionSync, None)
            .await;
    }

    // Verify Node B now contains all entries
    assert_eq!(
        engine_b.get_hmc_ram_lock(&hmc_tag_1).await.map(|e| e.t_id),
        Some(hmc_entry_1.t_id),
        "HMC lock 1 must be synced to Node B"
    );
    assert_eq!(
        engine_b.get_hmc_ram_lock(&hmc_tag_2).await.map(|e| e.t_id),
        Some(hmc_entry_2.t_id),
        "HMC lock 2 must be synced to Node B"
    );

    // Verify ShardDigest queries from Node B to Node A match local Node B state across shards
    handler_a.readiness_manager.mark_shard_ready(hmc_shard_id_1);
    handler_a.readiness_manager.mark_shard_ready(hmc_shard_id_2);
    let (d_hmc_shard_1, _cnt_1) = transport_b
        .request_shard_digest(&conn_b, hmc_shard_id_1, 2)
        .await
        .expect("hmc shard 1 digest");
    assert_ne!(d_hmc_shard_1, [0u8; 32]);

    let (d_hmc_shard_2, _cnt_2) = transport_b
        .request_shard_digest(&conn_b, hmc_shard_id_2, 3)
        .await
        .expect("hmc shard 2 digest");
    assert_ne!(d_hmc_shard_2, [0u8; 32]);
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
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a))
        .await;

    // Establish connection B -> A
    let conn_b = transport_b
        .connect_peer(addr_a)
        .await
        .expect("connect B -> A");

    // Verify Peer B is recognized and authorized
    let offender_node_id = *identity_b.node_id();
    assert!(!pm_a.is_banned(&offender_node_id).await);
    assert!(!engine.is_node_banned(&offender_node_id).await);
    assert!(
        pm_a.can_authorize_direct_rpc(&conn_b.remote_address(), Some(&offender_node_id))
            .await
    );

    // Create a valid First-Party Equivocation Proof:
    // Peer B signs two conflicting attestations for the same parent_lock with different lock_ids!
    let parent_lock = [0x55; 32];
    let lock_id_1 = [0x11; 32];
    let lock_id_2 = [0x22; 32];
    let node_u16 = u16::from_le_bytes([offender_node_id[0], offender_node_id[1]]);
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);

    // Parent_lock-bound payload digests (Phase 1 P0).
    let p1 = humoco_sim_core::crypto::compute_attestation_payload_digest(&parent_lock, &lock_id_1);
    let p2 = humoco_sim_core::crypto::compute_attestation_payload_digest(&parent_lock, &lock_id_2);
    let d1 = humoco_sim_core::crypto::compute_sig_digest(
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        0,
        0,
        shard_id,
        0,
        &p1,
    );
    let d2 = humoco_sim_core::crypto::compute_sig_digest(
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        0,
        0,
        shard_id,
        0,
        &p2,
    );

    use ed25519_dalek::Signer;
    let sig_1 = identity_b.signing_key().sign(&d1).to_bytes();
    let sig_2 = identity_b.signing_key().sign(&d2).to_bytes();

    let att_1 = humoco_sim_core::types::Attestation {
        node_id: node_u16,
        lock_id: lock_id_1,
        parent_lock,
        timestamp: SimTime(100),
        signature: sig_1,
        shard_id,
    };
    let att_2 = humoco_sim_core::types::Attestation {
        node_id: node_u16,
        lock_id: lock_id_2,
        parent_lock,
        timestamp: SimTime(200),
        signature: sig_2,
        shard_id,
    };

    let proof =
        FraudProofPayload::new_shard_equivocation_with_pubkey(att_1, att_2, offender_node_id);
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
    let (resp_hdr, _resp_payload) = transport_b
        .send_request(&conn_b, &proof_header, &raw_proof)
        .await
        .expect("send EquivocationProof");
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
    assert!(
        engine.is_node_banned(&proof.perpetrator_node_id).await,
        "Offender must be banned in DualTierEngine"
    );
    assert!(
        pm_a.is_banned(&proof.perpetrator_node_id).await,
        "Offender must be banned in PeerManager"
    );

    // 2. Evidence is durably persisted in redb
    let stored_evidence = storage
        .get_evidence(&evidence_hash)
        .expect("get_evidence")
        .expect("evidence found");
    assert_eq!(stored_evidence, raw_proof);

    // 3. Peering path authorization is revoked immediately
    assert!(
        !pm_a
            .can_authorize_direct_rpc(&conn_b.remote_address(), Some(&proof.perpetrator_node_id))
            .await,
        "Direct RPC authorization must be revoked for banned node"
    );

    // 4. Ingress signed by banned offender is rejected
    let payload = bincode::serialize(&humoco_node::network::framing::LockWirePayload::Hmc {
        req: humoco_node::api::hmc::L2LockRequest {
            causal_output: None,
            auth: humoco_node::api::hmc::L2AuthPayload {
                ephemeral_pubkey: [1; 32],
                auth_signature: None,
            },
            layer2_voucher_id: "voucher_banned".into(),
            ds_tag: Some("tag_banned".into()),
            transaction_hash: [0x99; 32],
            is_genesis: false,
            sender_ephemeral_pub: [1; 32],
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 0,
            deletable_at: None,
            privacy_guard: None,
        },
        chain: None,
        root_valid_until: 600_000,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: proof.perpetrator_node_id,
        sender_signature: [1; 64],
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    })
    .unwrap();
    let banned_ingress_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        2,
        0,
        0,
        payload.len() as u32,
    );

    use humoco_node::network::RequestHandler;
    let (ingress_resp_hdr, ingress_resp_bytes) = handler_a
        .handle(banned_ingress_header, payload)
        .await
        .expect("handle");
    assert_eq!(
        ingress_resp_hdr.msg_type,
        MsgType::LockVerifyResponse as u16
    );
    assert!(
        ingress_resp_bytes.is_empty(),
        "Banned node ingress must produce empty rejected response"
    );
}
