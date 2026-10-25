#![forbid(unsafe_code)]

//! Audit 23 permanent regression suite:
//! - A23-01: Runtime signing-history integrity, fail-closed latching, and live wire double-signature refusal

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;

use ed25519_dalek::{Signature, Signer, SigningKey};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::api::dto::AttestationDto;
use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest};
use humoco_node::identity::NodeIdentity;
use humoco_node::network::framing::LockWirePayload;
use humoco_node::network::{NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{
    DualTierEngine, RedbStorage, StorageError, TABLE_OWN_CHOICES, TABLE_SIGNING_STATE,
};
use humoco_sim_core::types::{LockRecord, NetworkId, SimTime};
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_COLLISION_DETECTED, FLAG_NOT_READY};

fn test_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_hmc_genesis(
    parent_hex: &str,
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{parent_hex}"),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_hmc_spend(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(parent_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

/// A23-01: Injected loss of a logical choice row must fail closed before contradictory approval.
#[test]
fn test_a23_01_runtime_missing_choice_must_fail_closed_and_latch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("runtime.redb");
    let db = RedbStorage::open(&path).unwrap();
    let identity = NodeIdentity::generate();
    let node = *identity.node_pubkey();

    let valid_until = 50_000u64;
    let a = LockRecord::new(
        [1; 32],
        [2; 32],
        vec![3],
        SimTime(1_000),
        SimTime(valid_until),
    );
    let b = LockRecord::new(
        [1; 32],
        [4; 32],
        vec![3],
        SimTime(1_000),
        SimTime(valid_until),
    );

    // Genuine attestation approval for A
    let attestation_a = humoco_node::api::routes::create_attestation_for_network(
        &identity,
        *blake3::hash(b"op_a").as_bytes(),
        a.parent_lock,
        humoco_sim_core::types::extract_shard_id(&a.parent_lock),
        0,
        1_000,
        NetworkId::Mainnet,
    );
    let approval_a = bincode::serialize(&attestation_a).unwrap();
    let committed_a = db
        .commit_original_record_approval(&a, valid_until, &node, &approval_a, 0)
        .unwrap();
    assert_eq!(committed_a, approval_a);
    assert!(db.is_signing_history_healthy());

    let (gen_before, fp_before) = db.signing_checkpoint().unwrap();
    assert_eq!(gen_before, 1);
    assert_ne!(fp_before, [0u8; 32]);

    // Model loss of the logical choice row without modifying independent metadata
    let tag = hex::encode(a.parent_lock);
    let slot = format!("{}:{}", hex::encode(node), tag);
    db.inject_remove_own_choice_for_test(&slot).unwrap();

    // Canonical collision state lawfully replaces with B
    db.put_lock(&b, valid_until).unwrap();

    let attestation_b = humoco_node::api::routes::create_attestation_for_network(
        &identity,
        *blake3::hash(b"op_b").as_bytes(),
        b.parent_lock,
        humoco_sim_core::types::extract_shard_id(&b.parent_lock),
        0,
        1_000,
        NetworkId::Mainnet,
    );
    let approval_b = bincode::serialize(&attestation_b).unwrap();

    let result = db.commit_original_record_approval(&b, valid_until, &node, &approval_b, 0);
    assert!(
        matches!(result, Err(StorageError::SigningHistoryCorrupt)),
        "missing retained history must reject contradictory original approval, got {result:?}"
    );
    assert!(
        !db.is_signing_history_healthy(),
        "detected corruption must latch immediately in memory"
    );

    // Assert no committed B approval was written
    let choice = db.own_signing_choice(&node, &tag).unwrap();
    assert!(
        choice.is_none(),
        "contradictory choice B must never be written to store"
    );
}

/// A23-01: Runtime malformed metadata, choice rows, and inconsistent relationships must latch.
#[test]
fn test_a23_01_runtime_malformed_state_and_row_integrity_latches() {
    let dir = tempdir().unwrap();

    // Case 1: Malformed SigningState JSON
    {
        let path = dir.path().join("malformed_state.redb");
        let db = RedbStorage::open(&path).unwrap();
        {
            let raw = db.raw_database_for_test();
            let tx = raw.begin_write().unwrap();
            tx.open_table(TABLE_SIGNING_STATE)
                .unwrap()
                .insert(0, b"not_valid_json".as_slice())
                .unwrap();
            tx.commit().unwrap();
        }
        let a = LockRecord::new([1; 32], [2; 32], vec![3], SimTime(1_000), SimTime(50_000));
        let res = db.commit_original_record_approval(&a, 50_000, &[7; 32], b"A", 0);
        assert!(res.is_err(), "parse failure must return error");
        assert!(
            !db.is_signing_history_healthy(),
            "runtime parse failure must set signing-corrupt latch"
        );
    }

    // Case 2: Malformed own-choice row JSON
    {
        let path = dir.path().join("malformed_row.redb");
        let db = RedbStorage::open(&path).unwrap();
        let a = LockRecord::new([1; 32], [2; 32], vec![3], SimTime(1_000), SimTime(50_000));
        let node = [7u8; 32];
        db.commit_original_record_approval(&a, 50_000, &node, b"valid_first", 0)
            .unwrap();
        assert!(db.is_signing_history_healthy());

        // Corrupt the choice row in redb
        let tag = hex::encode(a.parent_lock);
        let slot = format!("{}:{}", hex::encode(node), tag);
        {
            let raw = db.raw_database_for_test();
            let tx = raw.begin_write().unwrap();
            tx.open_table(TABLE_OWN_CHOICES)
                .unwrap()
                .insert(slot.as_str(), b"corrupted_choice_row".as_slice())
                .unwrap();
            tx.commit().unwrap();
        }

        let res = db.commit_original_record_approval(&a, 50_000, &node, b"retry", 0);
        assert!(
            matches!(res, Err(StorageError::SigningHistoryCorrupt)),
            "corrupt existing choice row must fail closed, got {res:?}"
        );
        assert!(
            !db.is_signing_history_healthy(),
            "malformed choice row must latch signing corrupt"
        );
    }
}

/// A23-01: Detected corruption latch must persist across reopen and backups.
#[test]
fn test_a23_01_persisted_latch_survives_reopen_and_backup() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("persist_latch.redb");
    let backup_path = dir.path().join("persist_latch_backup.redb");
    let node = [9u8; 32];
    let a = LockRecord::new([10; 32], [11; 32], vec![1], SimTime(1_000), SimTime(50_000));
    let b = LockRecord::new([10; 32], [12; 32], vec![1], SimTime(1_000), SimTime(50_000));

    {
        let db = RedbStorage::open(&path).unwrap();
        db.commit_original_record_approval(&a, 50_000, &node, b"original_a", 0)
            .unwrap();

        // Invalidate table cardinality
        let tag = hex::encode(a.parent_lock);
        let slot = format!("{}:{}", hex::encode(node), tag);
        db.inject_remove_own_choice_for_test(&slot).unwrap();

        // Trigger runtime integrity latch
        let res = db.commit_original_record_approval(&b, 50_000, &node, b"original_b", 0);
        assert!(matches!(res, Err(StorageError::SigningHistoryCorrupt)));
        assert!(!db.is_signing_history_healthy());

        db.create_backup(&backup_path).unwrap();
    }

    // Reopen primary database and verify latch survived
    let reopened = RedbStorage::open(&path).unwrap();
    assert!(
        !reopened.is_signing_history_healthy(),
        "persisted latch must survive reopening"
    );

    // Verify latch survived in backup
    let backup_db = RedbStorage::open(&backup_path).unwrap();
    assert!(
        !backup_db.is_signing_history_healthy(),
        "persisted latch must survive backup restoration"
    );
}

/// A23-01: Real authenticated QUIC release regression:
/// Under injected logical history loss, the shard node must refuse to sign or release
/// an incompatible original signature, close readiness, not ban the client, and return local unavailability.
#[tokio::test]
async fn test_a23_01_real_quic_signing_release_refuses_double_signature_under_fault() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("wire_audit23.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let shard_identity = NodeIdentity::generate();
    let client_identity = NodeIdentity::generate();

    let shard_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let shard_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let client_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    shard_pm
        .register_f2f_friend(
            *client_identity.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    shard_pm
        .learn_node_from_gossip_with_hrw(
            *shard_identity.node_pubkey(),
            *shard_identity.hrw_routing_id(),
            "127.0.0.1:1".parse().unwrap(),
            0,
            None,
        )
        .await;
    shard_pm
        .set_first_seen_for_test(
            shard_identity.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            shard_identity.clone(),
            shard_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(readiness.clone()),
    );

    let shard_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &shard_identity,
        shard_pm.clone(),
        handler,
        shard_cancel.clone(),
    )
    .expect("bind shard transport");
    shard_transport.set_sync_ready(true);
    let shard_addr = shard_transport.local_addr().expect("shard local addr");
    shard_transport.spawn_accept_loop();

    let client_dummy_handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            client_identity.clone(),
            client_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_identity,
        client_pm.clone(),
        client_dummy_handler,
        client_cancel.clone(),
    )
    .expect("bind client transport");
    let client_addr = client_transport.local_addr().expect("client local addr");
    client_transport.spawn_accept_loop();

    shard_pm
        .register_f2f_friend(*client_identity.node_pubkey(), Some(client_addr))
        .await;
    client_pm
        .register_f2f_friend(*shard_identity.node_pubkey(), Some(shard_addr))
        .await;

    let conn = client_transport
        .connect_peer(shard_addr)
        .await
        .expect("connect client to shard");

    // Establish genesis anchor
    let sender_key = SigningKey::from_bytes(&[2u8; 32]);
    let now = test_now_ms();
    let genesis_req = make_hmc_genesis("wire_audit23_genesis", now + 1_000_000, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let (v_gen, is_new_gen) = engine
        .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
        .await;
    assert!(is_new_gen);
    assert!(matches!(
        v_gen,
        humoco_node::api::hmc::L2Verdict::Verified { .. }
    ));

    // Send Lock A over live QUIC wire
    let parent_hex = hex::encode([0x88u8; 32]);
    let tx_hash_a = *blake3::hash(b"lock_a_audit23_tx").as_bytes();
    let lock_a_req = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex,
        tx_hash_a,
        now + 900_000,
        &sender_key,
    );
    let sender_pubkey = *client_identity.node_pubkey();
    let root_valid_until = now + 1_000_000;
    let ttl_s = root_valid_until.saturating_sub(now) / 1000;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

    let digest_a = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        0,
        now,
        0,
        0,
        footprint,
        false,
        &tx_hash_a,
    );
    let sender_sig_a = client_identity.signing_key().sign(&digest_a).to_bytes();

    let wire_payload_a = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_a_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey,
        sender_signature: sender_sig_a,
        timestamp_ms: now,
    })
    .expect("serialize wire payload a");

    let parent_p_bytes = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let p_shard = humoco_sim_core::types::extract_shard_id(&parent_p_bytes);
    readiness.mark_shard_ready(p_shard);

    let req_header_a = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0, // class 0
        wire_payload_a.len() as u32,
    );
    let (resp_header_a, resp_body_a) = client_transport
        .send_request(&conn, &req_header_a, &wire_payload_a)
        .await
        .expect("send request A");

    assert_eq!(
        resp_header_a.msg_type,
        MsgType::LockVerifyResponse as u16,
        "expected LockVerifyResponse"
    );
    assert_ne!(resp_body_a.len(), 0, "expected attestation for Lock A");
    let att_a = AttestationDto::from_wire_bytes(&resp_body_a)
        .expect("Response payload must be valid AttestationDto for Lock A");
    assert_eq!(att_a.lock_id, hex::encode(tx_hash_a));
    assert_eq!(
        att_a.node_pubkey_bytes(),
        Some(*shard_identity.node_pubkey()),
        "Attestation must be signed by the shard node"
    );

    // Cryptographically verify signature on attestation A
    {
        let domain_tag = humoco_sim_core::crypto::domain_approve_prov(NetworkId::Mainnet);
        let payload_digest = humoco_sim_core::crypto::compute_attestation_payload_digest(
            &parent_p_bytes,
            &tx_hash_a,
        );
        let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
            domain_tag,
            0,
            0,
            0,
            att_a.shard_id,
            0,
            &payload_digest,
        );
        let sig_bytes: [u8; 64] = hex::decode(&att_a.signature)
            .expect("hex")
            .try_into()
            .expect("64 bytes");
        let sig = Signature::from_bytes(&sig_bytes);
        shard_identity
            .verifying_key()
            .verify_strict(&sig_digest, &sig)
            .expect("Shard attestation signature for Lock A must be cryptographically valid");
    }

    // Inject loss of the logical own-choice row for Lock A
    let parent_tag = parent_hex.clone();
    let slot = format!(
        "{}:{}",
        hex::encode(shard_identity.node_pubkey()),
        parent_tag
    );
    storage.inject_remove_own_choice_for_test(&slot).unwrap();

    // Prepare Lock B for the same parent P
    let tx_hash_b = *blake3::hash(b"lock_b_audit23_tx").as_bytes();
    let lock_b_req = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex,
        tx_hash_b,
        now + 900_000,
        &sender_key,
    );

    // Lawfully replace current canonical state with B in storage and RAM index
    storage
        .put_hmc_lock(&parent_hex, &L2LockEntry::from(&lock_b_req))
        .unwrap();
    {
        let mut ram = engine.hmc_ram.write().await;
        ram.insert_lock_for_test(parent_hex.clone(), L2LockEntry::from(&lock_b_req));
    }

    let digest_b = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        2,
        now,
        0,
        0,
        footprint,
        false,
        &tx_hash_b,
    );
    let sender_sig_b = client_identity.signing_key().sign(&digest_b).to_bytes();

    let wire_payload_b = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_b_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 2,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey,
        sender_signature: sender_sig_b,
        timestamp_ms: now,
    })
    .expect("serialize wire payload b");

    let req_header_b = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        2,
        0,
        0,
        wire_payload_b.len() as u32,
    );

    let (resp_header_b, resp_body_b) = client_transport
        .send_request(&conn, &req_header_b, &wire_payload_b)
        .await
        .expect("send request B");

    // Under the history integrity gap, assert that the node refuses to sign Lock B:
    // It must return local unavailability (FLAG_NOT_READY), and signing readiness must close.
    assert!(
        !engine.is_signing_healthy(),
        "storage history failure must close engine signing health"
    );
    assert_ne!(
        resp_header_b.flags & (FLAG_NOT_READY | FLAG_COLLISION_DETECTED),
        0,
        "must express local unavailability or collision, got flags={:#b}",
        resp_header_b.flags
    );

    // If any attestation was returned, it must NOT be a valid attestation for B signed by shard!
    if let Some(att_b) = AttestationDto::from_wire_bytes(&resp_body_b) {
        let domain_tag = humoco_sim_core::crypto::domain_approve_prov(NetworkId::Mainnet);
        let payload_digest = humoco_sim_core::crypto::compute_attestation_payload_digest(
            &parent_p_bytes,
            &tx_hash_b,
        );
        let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
            domain_tag,
            0,
            0,
            0,
            att_b.shard_id,
            0,
            &payload_digest,
        );
        if let Ok(sig_bytes) = hex::decode(&att_b.signature) {
            if let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes.as_slice()) {
                let sig = Signature::from_bytes(&sig_array);
                let is_valid_b = shard_identity
                    .verifying_key()
                    .verify_strict(&sig_digest, &sig)
                    .is_ok();
                assert!(
                    !is_valid_b,
                    "shard must NEVER sign or release a valid attestation for conflicting Lock B!"
                );
            }
        }
    }

    // Client peer must NOT be banned or suspended
    assert!(
        !engine.is_node_banned(client_identity.node_pubkey()).await,
        "client must not be banned for local storage fault"
    );
}

/// A23-R1: Semantic row substitution (tampering with choice bytes or commitment hash)
/// must be detected at runtime, immediately fail closed, and latch corruption persistently.
#[test]
fn test_a23_r1_semantic_row_substitution_detected_at_runtime_and_latches_corruption() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("row_substitution.redb");
    let node = [42u8; 32];
    let record_a = LockRecord::new([1; 32], [2; 32], vec![3], SimTime(1_000), SimTime(50_000));
    let tag = hex::encode(record_a.parent_lock);
    let slot = format!("{}:{}", hex::encode(node), tag);

    {
        let db = RedbStorage::open(&path).unwrap();
        db.commit_original_record_approval(&record_a, 50_000, &node, b"approval_a", 0)
            .unwrap();
        assert!(db.is_signing_history_healthy());

        // Perform semantic row substitution in TABLE_OWN_CHOICES behind the back of TABLE_OWN_CHOICE_COMMITMENTS:
        // We replace the choice row with another valid JSON OwnSigningChoice that has a different child.
        let substituted_choice = serde_json::json!({
            "generation": 1,
            "child": vec![99u8; 32],
            "valid_until_ms": 50_000,
            "approvals": [Some(b"approval_a".to_vec()), None::<Vec<u8>>]
        });
        let sub_bytes = serde_json::to_vec(&substituted_choice).unwrap();

        {
            let raw = db.raw_database_for_test();
            let tx = raw.begin_write().unwrap();
            tx.open_table(TABLE_OWN_CHOICES)
                .unwrap()
                .insert(slot.as_str(), sub_bytes.as_slice())
                .unwrap();
            tx.commit().unwrap();
        }

        // Now attempt an operation on this slot:
        let res = db.commit_original_record_approval(&record_a, 50_000, &node, b"retry", 0);
        assert!(
            matches!(res, Err(StorageError::SigningHistoryCorrupt)),
            "semantic row substitution must be detected and return SigningHistoryCorrupt, got {res:?}"
        );
        assert!(
            !db.is_signing_history_healthy(),
            "corruption must latch in memory immediately"
        );
    }

    // Latch must persist across reopen:
    let reopened = RedbStorage::open(&path).unwrap();
    assert!(
        !reopened.is_signing_history_healthy(),
        "persisted latch must survive reopen after row substitution"
    );

    // Case 2: Tampered commitment hash in TABLE_OWN_CHOICE_COMMITMENTS must also latch
    let path2 = dir.path().join("commitment_substitution.redb");
    {
        let db = RedbStorage::open(&path2).unwrap();
        db.commit_original_record_approval(&record_a, 50_000, &node, b"approval_a", 0)
            .unwrap();
        assert!(db.is_signing_history_healthy());

        // Tamper with the commitment hash directly
        {
            let raw = db.raw_database_for_test();
            let tx = raw.begin_write().unwrap();
            tx.open_table(humoco_node::storage::TABLE_OWN_CHOICE_COMMITMENTS)
                .unwrap()
                .insert(slot.as_str(), &[0xee; 32])
                .unwrap();
            tx.commit().unwrap();
        }

        let res = db.commit_original_record_approval(&record_a, 50_000, &node, b"retry", 0);
        assert!(
            matches!(res, Err(StorageError::SigningHistoryCorrupt)),
            "tampered commitment must fail closed with SigningHistoryCorrupt"
        );
        assert!(!db.is_signing_history_healthy());
    }

    let reopened2 = RedbStorage::open(&path2).unwrap();
    assert!(
        !reopened2.is_signing_history_healthy(),
        "persisted latch must survive reopen after tampered commitment"
    );
}

