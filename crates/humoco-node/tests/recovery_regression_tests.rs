//! Regressions for Audit 21: Recovery Latch Precision and Lean Shard Sync (A21-R1 & A21-R2).

use humoco_node::{
    network::framing::SyncPayload,
    storage::{db::install::ShardStage, DualTierEngine, RedbStorage},
};
use humoco_sim_core::types::{LockRecord, LockStatus, SimTime};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;

#[tokio::test]
async fn test_rejected_snapshot_preserves_node_signing_health() {
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("recovery.redb")).expect("open redb"));
    let (engine_raw, _worker) = DualTierEngine::new(storage.clone());
    let engine = Arc::new(engine_raw);

    let shard = 42u16;
    let now = 10_000u64;

    // 1. Target node holds an active FINAL (Class 2) native lock
    let mut parent = [0u8; 32];
    parent[..2].copy_from_slice(&shard.to_be_bytes());
    parent[2] = 0x11;

    let mut winner_row = LockRecord::new(
        parent,
        [0xAA; 32],
        vec![1, 2, 3],
        SimTime(now),
        SimTime(now + 100_000),
    );
    winner_row.status = LockStatus::Final { sigs: 14 };
    storage
        .put_lock(&winner_row, now + 100_000)
        .expect("put winner");

    // 2. Incoming snapshot attempts to overwrite or omit the confirmed choice with unconfirmed Class 1
    let mut loser_row = LockRecord::new(
        parent,
        [0xBB; 32],
        vec![4, 5, 6],
        SimTime(now),
        SimTime(now + 100_000),
    );
    loser_row.status = LockStatus::Provisional {
        sigs: 3,
        required: 3,
    };

    let stage = Arc::new(ShardStage::new(shard, now).expect("new stage"));
    stage
        .append(SyncPayload {
            locks: vec![(loser_row.clone(), now + 100_000)],
            hmc_locks: vec![],
            support: vec![],
        })
        .expect("append loser");

    let digest = stage.digest().expect("stage digest");

    // Attempt installation: this MUST be rejected because incoming cut loses native class ordering
    let install_res = engine
        .install_shard_snapshot(
            stage,
            digest,
            1, // class 1
            [0x55; 32],
            3,
            None,
            Some(Instant::now() + Duration::from_secs(10)),
        )
        .await;

    assert!(
        install_res.is_err(),
        "Snapshot with inferior confirmation class must be rejected"
    );

    // A21-R1 invariant: Rejected snapshot (pre-commit rollback) MUST NOT latch signing failure!
    assert!(
        engine.is_signing_healthy(),
        "Node signing health must remain intact after pre-commit cut rejection"
    );

    // Verify existing confirmed choice was preserved
    let current = storage.get_lock(&parent).expect("get_lock");
    assert!(current.is_some());
    assert_eq!(current.unwrap().0.id, winner_row.id);
}

#[tokio::test]
async fn test_expired_lease_deadline_preserves_node_signing_health() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("lease.redb")).expect("open redb"));
    let (engine_raw, _worker) = DualTierEngine::new(storage.clone());
    let engine = Arc::new(engine_raw);

    let shard = 7u16;
    let now = 10_000u64;

    let stage = Arc::new(ShardStage::new(shard, now).expect("new stage"));
    let digest = stage.digest().expect("stage digest");

    // Pass a deadline that is already in the past
    let expired_deadline = Instant::now() - Duration::from_millis(50);
    let install_res = engine
        .install_shard_snapshot(
            stage,
            digest,
            1,
            [0x11; 32],
            3,
            None,
            Some(expired_deadline),
        )
        .await;

    assert!(
        install_res.is_err(),
        "Snapshot with expired lease deadline must be rejected"
    );

    // A21-R1 invariant: Lease expiry before commit MUST NOT latch signing failure!
    assert!(
        engine.is_signing_healthy(),
        "Node signing health must remain intact after expired lease rejection"
    );
}

#[tokio::test]
async fn test_active_hmc_locks_for_shard_filters_foreign_shards() {
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use humoco_node::api::hmc::{
        calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest,
    };

    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("filter.redb")).expect("open redb"));

    let now = 5_000u64;
    let valid_until = now + 100_000;
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let pubkey = signing_key.verifying_key().to_bytes();

    let make_genesis = |voucher_id: &str, tx_hash: [u8; 32]| -> L2LockRequest {
        let mut req = L2LockRequest {
            causal_output: None,
            auth: L2AuthPayload {
                ephemeral_pubkey: pubkey,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: None,
            transaction_hash: tx_hash,
            is_genesis: true,
            sender_ephemeral_pub: pubkey,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0u8; 64],
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: 0,
            created_at_ms: now,
            deletable_at: Some(valid_until.to_string()),
            privacy_guard: Some("none".into()),
        };
        let hash = calculate_l2_payload_hash(&req);
        req.layer2_signature = signing_key.sign(&hash).to_bytes();
        req
    };

    let make_spend = |voucher_id: &str, parent_tag: &str, tx_hash: [u8; 32]| -> L2LockRequest {
        let mut req = L2LockRequest {
            causal_output: None,
            auth: L2AuthPayload {
                ephemeral_pubkey: pubkey,
                auth_signature: None,
            },
            layer2_voucher_id: voucher_id.to_string(),
            ds_tag: Some(parent_tag.to_string()),
            transaction_hash: tx_hash,
            is_genesis: false,
            sender_ephemeral_pub: pubkey,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0u8; 64],
            trap_r: Some("none".into()),
            trap_s: Some("none".into()),
            encrypted_timestamp: 0,
            created_at_ms: now,
            deletable_at: Some(valid_until.to_string()),
            privacy_guard: Some("none".into()),
        };
        let hash = calculate_l2_payload_hash(&req);
        req.layer2_signature = signing_key.sign(&hash).to_bytes();
        req
    };

    // 1. Genesis A
    let gen_req_a = make_genesis("voucher_a", [0x01; 32]);
    let gen_tag_a = bs58::encode(gen_req_a.transaction_hash).into_string();
    let gen_entry_a = L2LockEntry::from(&gen_req_a);
    let parent_bytes_a = humoco_sim_core::types::genesis_parent_bytes_from_tag(&gen_tag_a);
    let shard_a = humoco_sim_core::types::canonical_voucher_shard(&parent_bytes_a);
    storage
        .put_hmc_lock(&gen_tag_a, &gen_entry_a)
        .expect("anchor a");

    // Spend A on Genesis A
    let spend_req_a = make_spend("voucher_a", &gen_tag_a, [0x02; 32]);
    let spend_entry_a = L2LockEntry::from(&spend_req_a);
    storage
        .put_hmc_lock("spend_tag_a", &spend_entry_a)
        .expect("put spend_a");

    // 2. Genesis B with different hash to guarantee different shard if possible, or distinct voucher
    let gen_req_b = make_genesis("voucher_b", [0xFF; 32]);
    let gen_tag_b = bs58::encode(gen_req_b.transaction_hash).into_string();
    let gen_entry_b = L2LockEntry::from(&gen_req_b);
    let parent_bytes_b = humoco_sim_core::types::genesis_parent_bytes_from_tag(&gen_tag_b);
    let shard_b = humoco_sim_core::types::canonical_voucher_shard(&parent_bytes_b);
    storage
        .put_hmc_lock(&gen_tag_b, &gen_entry_b)
        .expect("anchor b");

    // Spend B on Genesis B
    let spend_req_b = make_spend("voucher_b", &gen_tag_b, [0xFE; 32]);
    let spend_entry_b = L2LockEntry::from(&spend_req_b);
    storage
        .put_hmc_lock("spend_tag_b", &spend_entry_b)
        .expect("put spend_b");

    // 3. Query shard A
    let locks_a = storage
        .active_hmc_locks_for_shard(shard_a, now)
        .expect("query a");
    assert!(
        locks_a.iter().any(|(tag, _)| tag == "spend_tag_a"),
        "Shard A must contain spend_tag_a"
    );
    if shard_a != shard_b {
        assert!(
            !locks_a.iter().any(|(tag, _)| tag == "spend_tag_b"),
            "Shard A must NOT contain spend_tag_b"
        );
    }

    // 4. Query an unused shard (e.g. shard_a.wrapping_add(100))
    let unused_shard = shard_a.wrapping_add(12345);
    if unused_shard != shard_a && unused_shard != shard_b {
        let locks_unused = storage
            .active_hmc_locks_for_shard(unused_shard, now)
            .expect("query unused");
        assert!(
            locks_unused.is_empty(),
            "Unused shard must return empty list"
        );
    }
}
