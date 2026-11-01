#![forbid(unsafe_code)]

//! Reliability integration tests for Finding F1 and Finding F3.
//!
//! F1: Remote /v1/status fallback binds to confirmed durability, health, and shard readiness.
//! F3: Lossless committed-only HMC synchronization in /v1/sync with fail-closed integrity.

#[path = "common/recovery.rs"]
mod recovery;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use humoco_node::{
    api::{
        build_router,
        dto::{SyncRequest, SyncResponse},
        hmc::{L2AuthPayload, L2LockEntry, L2ResponseEnvelope, L2StatusQuery, L2Verdict},
        AppState,
    },
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::PeerManager,
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::types::{LockRecord, SimTime};
use std::sync::{atomic::Ordering, Arc};
use tower::ServiceExt;

async fn response_json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn create_sample_entry(voucher_id: &str, tag_num: u8, now_ms: u64, ttl_ms: u64) -> L2LockEntry {
    L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_id.to_string(),
        t_id: [tag_num; 32],
        sender_ephemeral_pub: [tag_num + 1; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [tag_num + 2; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now_ms,
        deletable_at: Some((now_ms + ttl_ms).to_string()),
        privacy_guard: None,
    }
}

fn setup_local_test_app() -> (
    axum::Router,
    Arc<RedbStorage>,
    DualTierEngine,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test_f1_f3.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let state = AppState::new(engine.clone(), storage.clone(), identity, tiers, pow);
    let router = build_router(state);
    (router, storage, engine, dir)
}

/// F1: pending_remote_never_becomes_verified
/// Real QUIC + HTTP gateway:
/// - Source DB lacks spend (only in source RAM) -> Gateway returns 503 SERVICE_UNAVAILABLE + Rejected { "Remote durable state pending" }
/// - Spend durably committed & shard ready -> Gateway returns 200 OK + Verified
/// - Source signing_failed is true -> Gateway returns 503 SERVICE_UNAVAILABLE + Rejected
/// - Source shard not ready -> Gateway returns 503 SERVICE_UNAVAILABLE + Rejected
#[tokio::test]
async fn test_f1_pending_remote_never_becomes_verified() {
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_node::api::hmc::{calculate_l2_payload_hash, L2LockRequest};
    use sha2::{Digest as _, Sha256};

    let peers = recovery::recovery_peers(2).await;
    let (reader, source) = (&peers[0], &peers[1]);
    let now = source.manager.net_time_ms();
    let owner = SigningKey::from_bytes(&[49; 32]);
    let sender_pub = owner.verifying_key().to_bytes();
    let root_tx_hash = *blake3::hash(b"f1-remote-canonical-root").as_bytes();
    let del_str = (now + 600_000).to_string();
    let mut id_hasher = Sha256::new();
    id_hasher.update(root_tx_hash);
    id_hasher.update(sender_pub);
    id_hasher.update(del_str.as_bytes());
    let voucher = hex::encode(id_hasher.finalize());
    let mut root_proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher.clone(),
        transaction_id: root_tx_hash,
        state_hash: root_tx_hash,
        sender_pubkey: sender_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    root_proof.signature = owner.sign(&root_proof.digest().unwrap()).to_bytes();
    let mut root_req = L2LockRequest {
        causal_output: Some(root_proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher.clone(),
        ds_tag: None,
        transaction_hash: root_tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    root_req.layer2_signature = owner.sign(&calculate_l2_payload_hash(&root_req)).to_bytes();
    let root = L2LockEntry::from(&root_req);
    let root_tag = bs58::encode(root.t_id).into_string();
    let anchor = humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag);
    let shard = humoco_sim_core::types::canonical_voucher_shard(&anchor);
    assert_ne!(shard, humoco_sim_core::types::voucher_shard_id(&voucher));
    let tag = "f1-remote-parent";
    source.db.put_hmc_lock(&root_tag, &root).unwrap();

    let entry = create_sample_entry(&voucher, 0x20, now, 600_000);

    // 1. Stage spend into source RAM ONLY (uncommitted on source disk)
    source
        .engine
        .hmc_ram
        .write()
        .await
        .insert_lock_for_test(tag.into(), entry.clone());
    source
        .engine
        .record_hmc_voucher_genesis_parent(&voucher, anchor)
        .await;
    source.readiness.mark_shard_ready(shard);

    assert!(source.db.get_hmc_lock(tag).unwrap().is_none());

    // Gateway setup on reader
    let pow = Arc::new(PowEngine::new(*reader.identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(reader.db.clone(), pow.clone()));
    let mut state = AppState::new(
        reader.engine.clone(),
        reader.db.clone(),
        reader.identity.clone(),
        tiers,
        pow,
    );
    let routing = Arc::new(PeerManager::new(vec![]));
    routing
        .learn_node_from_gossip_with_hrw(
            *source.identity.node_pubkey(),
            *source.identity.hrw_routing_id(),
            source.network.local_addr().unwrap(),
            0,
            None,
        )
        .await;
    routing
        .set_first_seen_for_test(
            source.identity.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    state.peer_manager = Some(routing.clone());
    state.transport = Some(reader.network.clone());

    let query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [1; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher.clone(),
        challenge_ds_tag: tag.into(),
        locator_prefixes: vec![],
        read_quorum: 1,
        root_context: Some(root.clone()),
    };

    let make_request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/status")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&query).unwrap()))
            .unwrap()
    };

    // 1a. Uncommitted spend: remote returns FLAG_NOT_READY, gateway returns 503 SERVICE_UNAVAILABLE
    let response = build_router(state.clone())
        .oneshot(make_request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let envelope: L2ResponseEnvelope = response_json(response).await;
    match &envelope.verdict {
        L2Verdict::Rejected { reason } => {
            assert!(
                reason.contains("Remote durable state pending"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected Rejected verdict for uncommitted remote spend, got {other:?}"),
    }

    // 2. Commit spend to source disk and recover so it becomes confirmed durable
    source.db.put_hmc_lock(tag, &entry).unwrap();
    source.engine.recover_from_disk(SimTime(now)).await.unwrap();
    source.readiness.mark_shard_ready(shard);

    // 2a. With committed spend and ready shard: returns 200 OK + Verified
    let response = build_router(state.clone())
        .oneshot(make_request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let envelope: L2ResponseEnvelope = response_json(response).await;
    match &envelope.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry, &entry);
        }
        other => panic!("expected Verified verdict for committed spend, got {other:?}"),
    }

    // 3. Signing failure on source node -> returns 503 SERVICE_UNAVAILABLE
    source
        .engine
        .stats
        .signing_failed
        .store(true, Ordering::Release);
    let response = build_router(state.clone())
        .oneshot(make_request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let envelope: L2ResponseEnvelope = response_json(response).await;
    assert!(matches!(envelope.verdict, L2Verdict::Rejected { .. }));

    // 4. Shard not ready on source node -> returns 503 SERVICE_UNAVAILABLE
    source
        .engine
        .stats
        .signing_failed
        .store(false, Ordering::Release);
    source.readiness.invalidate_shard(shard);
    let response = build_router(state.clone())
        .oneshot(make_request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let envelope: L2ResponseEnvelope = response_json(response).await;
    assert!(matches!(envelope.verdict, L2Verdict::Rejected { .. }));

    recovery::stop_recovery_peers(peers).await;
}

/// F3: sync_preserves_hmc_identity_lifetime_and_class
/// Committed spend on disk exports in `response.hmc_locks` with exact entry, root_anchor,
/// root_valid_until_ms > now(), confirmation_class == 0, response.locks.is_empty(),
/// and both JSON and bincode roundtrip of row.entry.
#[tokio::test]
async fn test_f3_sync_preserves_hmc_identity_lifetime_and_class() {
    let (router, storage, _engine, _dir) = setup_local_test_app();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let voucher_id = "f3-sync-voucher-1";
    let root = create_sample_entry(voucher_id, 0x11, now_ms, 600_000);
    let root_tag = bs58::encode(root.t_id).into_string();
    storage.put_hmc_lock(&root_tag, &root).unwrap();

    let spend = create_sample_entry(voucher_id, 0x22, now_ms, 600_000);
    let spend_tag = "f3-spend-tag-1";
    storage.put_hmc_lock(spend_tag, &spend).unwrap();

    let sync_req = SyncRequest {
        sparse_locators: vec![],
    };
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let sync_resp: SyncResponse = response_json(response).await;

    // Native locks must be empty; spend must be in hmc_locks
    assert!(sync_resp.locks.is_empty(), "native locks must be empty");
    assert_eq!(sync_resp.hmc_locks.len(), 1);

    let row = &sync_resp.hmc_locks[0];
    assert_eq!(row.lookup_tag, spend_tag);
    assert_eq!(row.entry, spend);
    assert_eq!(row.root_anchor, root);
    assert!(row.root_valid_until_ms > now_ms);
    assert_eq!(row.root_valid_until_ms, now_ms + 600_000);
    assert_eq!(row.confirmation_class, 0);

    // Roundtrip verification: JSON
    let json_bytes = serde_json::to_vec(&row.entry).unwrap();
    let json_deser: L2LockEntry = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(json_deser, row.entry);

    // Roundtrip verification: Bincode
    let bin_bytes = bincode::serialize(&row.entry).unwrap();
    let bin_deser: L2LockEntry = bincode::deserialize(&bin_bytes).unwrap();
    assert_eq!(bin_deser, row.entry);
}

/// F3: RFC3339 deletable_at on root anchor resolves root_valid_until_ms properly in /v1/sync.
#[tokio::test]
async fn test_f3_sync_resolves_rfc3339_root_lifetime() {
    let (router, storage, _engine, _dir) = setup_local_test_app();
    let now_ms = 1_700_000_000_000u64;
    let voucher_id = "f3-rfc3339-voucher";

    let rfc3339_str = "2035-06-15T12:00:00Z";
    let expected_ms = chrono::DateTime::parse_from_rfc3339(rfc3339_str)
        .unwrap()
        .timestamp_millis() as u64;

    let mut root = create_sample_entry(voucher_id, 0x31, now_ms, 600_000);
    root.deletable_at = Some(rfc3339_str.to_string());
    let root_tag = bs58::encode(root.t_id).into_string();
    storage.put_hmc_lock(&root_tag, &root).unwrap();

    let spend = create_sample_entry(voucher_id, 0x32, now_ms, 600_000);
    let spend_tag = "f3-spend-rfc3339";
    storage.put_hmc_lock(spend_tag, &spend).unwrap();

    let sync_req = SyncRequest {
        sparse_locators: vec![],
    };
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let sync_resp: SyncResponse = response_json(response).await;
    assert_eq!(sync_resp.hmc_locks.len(), 1);
    assert_eq!(sync_resp.hmc_locks[0].root_valid_until_ms, expected_ms);
}

/// F3: Pending-RAM HMC & native locks WITHOUT disk commit are NOT exported by /v1/sync.
#[tokio::test]
async fn test_f3_pending_ram_locks_without_commit_not_exported() {
    let (router, storage, engine, _dir) = setup_local_test_app();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // 1. Insert native lock into RAM only
    let native_rec = LockRecord::new(
        [0x55; 32],
        [0x66; 32],
        vec![1, 2, 3],
        SimTime(now_ms),
        SimTime(now_ms + 600_000),
    );
    engine
        .ram
        .write()
        .await
        .insert_recovered(native_rec, SimTime(now_ms + 600_000));

    // 2. Insert HMC lock into HMC RAM only
    let hmc_entry = create_sample_entry("ram-only-voucher", 0x77, now_ms, 600_000);
    engine
        .hmc_ram
        .write()
        .await
        .insert_lock_for_test("ram-only-tag".into(), hmc_entry);

    // Verify disk has no records
    assert!(storage.all_valid_locks(now_ms).unwrap().is_empty());
    assert!(storage.get_hmc_lock("ram-only-tag").unwrap().is_none());

    // 3. /v1/sync must return empty lists
    let sync_req = SyncRequest {
        sparse_locators: vec![],
    };
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let sync_resp: SyncResponse = response_json(response).await;
    assert!(
        sync_resp.locks.is_empty(),
        "uncommitted RAM native lock must not be exported"
    );
    assert!(
        sync_resp.hmc_locks.is_empty(),
        "uncommitted RAM HMC lock must not be exported"
    );
}

/// F3: Corrupted HMC row or missing root anchor in TABLE_HMC_LOCKS causes /v1/sync
/// to return non-200 error instead of 200 OK partial fallback.
#[tokio::test]
async fn test_f3_corrupted_row_or_missing_root_fails_closed() {
    let (router, storage, _engine, _dir) = setup_local_test_app();
    let raw_db = storage.raw_database_for_test();

    // 1. Inject an orphan HMC spend directly without a corresponding root anchor
    let orphan_spend = create_sample_entry("orphan-voucher", 0x88, 1_000, 600_000);
    let write_txn = raw_db.begin_write().unwrap();
    {
        let mut table = write_txn
            .open_table(humoco_node::storage::db::TABLE_HMC_LOCKS)
            .unwrap();
        let bytes = serde_json::to_vec(&orphan_spend).unwrap();
        table.insert("orphan_tag", bytes.as_slice()).unwrap();
    }
    write_txn.commit().unwrap();

    let sync_req = SyncRequest {
        sparse_locators: vec![],
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Must fail closed with SERVICE_UNAVAILABLE (503) or 500, NOT 200 OK
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "sync must fail closed when root anchor is missing"
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // 2. Inject corrupted bytes into TABLE_HMC_LOCKS
    let write_txn = raw_db.begin_write().unwrap();
    {
        let mut table = write_txn
            .open_table(humoco_node::storage::db::TABLE_HMC_LOCKS)
            .unwrap();
        table
            .insert("corrupt_tag", b"not_valid_json_garbage".as_slice())
            .unwrap();
    }
    write_txn.commit().unwrap();

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sync")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&sync_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "sync must fail closed on deserialization corruption"
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
