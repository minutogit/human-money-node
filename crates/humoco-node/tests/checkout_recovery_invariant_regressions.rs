//! Checkout and Recovery Invariant Regression Test Suite.
//!
//! Validates the critical consensus, storage, wire framing, and API ingress invariants:
//! - Root TTL formats (numeric ms and RFC3339) and sidecar proof verification.
//! - Rejection of shortened and lengthened root sidecars at admission, REST, and chain ingress.
//! - Idempotent retry, author upgrade to causal output proof, and fail-closed corruption latch on recovery.
//! - Protection against unbound canonical roots over live QUIC wire sync.
//! - Atomic transaction rollback leaving all 6 storage tables and digests unchanged on rejected shard install.
//! - Exact-entry persistence and digest stability under idempotent variant replays and concurrent submissions.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::{
        build_router,
        hmc::{
            calculate_l2_payload_hash_for_entry, verify_l2_lock_entry_signature, L2AuthPayload,
            L2ChainLockRequest, L2LockEntry, L2LockRequest, L2Verdict,
        },
        routes::create_attestation_for_network,
        AppState,
    },
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{
        framing::{LockWirePayload, SyncPayload},
        NodeRequestHandler, PeerManager,
    },
    storage::{
        db::{
            install::ShardStage,
            roots,
            support::{ConfirmationSupport, VerifiedInheritedCut},
            TABLE_HMC_LOCKS, TABLE_PROVISIONAL_HMC_LOCKS,
        },
        DualTierEngine, IngressOrigin, RedbStorage, StorageError,
    },
};
use humoco_proto::causal::CausalOutputProof;
use humoco_sim_core::{
    types::{
        canonical_voucher_shard, genesis_parent_bytes_from_tag, NetworkId, SimTime,
    },
    wire::{MsgType, WireHeader},
};
use redb::ReadableTable;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[path = "common/recovery.rs"]
mod recovery;

// ============================================================================
// Test Fixture Helpers
// ============================================================================

fn entry(key: &SigningKey, voucher: &str, child: u8, expiry: Option<u64>) -> L2LockEntry {
    L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher.into(),
        t_id: [child; 32],
        sender_ephemeral_pub: key.verifying_key().to_bytes(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 1_000,
        deletable_at: expiry.map(|v| v.to_string()),
        privacy_guard: None,
    }
}

fn sign(key: &SigningKey, tag: &str, row: &mut L2LockEntry) {
    row.layer2_signature = key
        .sign(&calculate_l2_payload_hash_for_entry(row, tag))
        .to_bytes();
    assert!(verify_l2_lock_entry_signature(row, tag));
}

fn canonical_root(key: &SigningKey, signed_expiry: u64, sidecar_expiry: u64) -> L2LockEntry {
    canonical_root_custom_expiry(key, &signed_expiry.to_string(), sidecar_expiry)
}

fn canonical_root_custom_expiry(
    key: &SigningKey,
    raw_expiry: &str,
    sidecar_expiry: u64,
) -> L2LockEntry {
    let mut row = entry(key, "", 1, None);
    row.deletable_at = Some(raw_expiry.to_string());
    let receiver = [9u8; 32];
    let mut hash = Sha256::new();
    hash.update(row.t_id);
    hash.update(row.sender_ephemeral_pub);
    hash.update(receiver);
    hash.update(raw_expiry.as_bytes());
    row.layer2_voucher_id = hex::encode(hash.finalize());

    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: row.layer2_voucher_id.clone(),
        transaction_id: row.t_id,
        state_hash: [8u8; 32],
        sender_pubkey: row.sender_ephemeral_pub,
        receiver_pubkey_hash: Some(receiver),
        change_pubkey_hash: None,
        root_valid_until_ms: sidecar_expiry,
        is_root: true,
        signature: [0u8; 64],
    };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    row.causal_output = Some(proof);
    let tag = bs58::encode(row.t_id).into_string();
    sign(key, &tag, &mut row);
    row
}

fn lock_request_from_entry(
    entry: &L2LockEntry,
    is_genesis: bool,
    ds_tag: Option<String>,
) -> L2LockRequest {
    L2LockRequest {
        causal_output: entry.causal_output.clone(),
        auth: L2AuthPayload {
            ephemeral_pubkey: entry.sender_ephemeral_pub,
            auth_signature: None,
        },
        layer2_voucher_id: entry.layer2_voucher_id.clone(),
        ds_tag,
        transaction_hash: entry.t_id,
        is_genesis,
        sender_ephemeral_pub: entry.sender_ephemeral_pub,
        layer2_signature: entry.layer2_signature,
        trap_r: entry.trap_r.clone(),
        trap_s: entry.trap_s.clone(),
        encrypted_timestamp: entry.encrypted_timestamp,
        created_at_ms: entry.created_at_ms,
        deletable_at: entry.deletable_at.clone(),
        privacy_guard: entry.privacy_guard.clone(),
    }
}

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct TestAppFixture {
    router: axum::Router,
    engine: DualTierEngine,
    storage: Arc<RedbStorage>,
    identity: NodeIdentity,
    tier_controller: Arc<TierController>,
    _temp: tempfile::TempDir,
    cancel: CancellationToken,
    worker: tokio::task::JoinHandle<()>,
}

fn setup_test_app() -> TestAppFixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let db_path = temp.path().join("test_api.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(storage.clone(), cancel.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let state = AppState::new(
        engine.clone(),
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine,
    );

    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    let router = build_router(state);
    TestAppFixture {
        router,
        engine,
        storage,
        identity,
        tier_controller,
        _temp: temp,
        cancel,
        worker,
    }
}

fn snapshot_table_str(
    db: &RedbStorage,
    def: redb::TableDefinition<&str, &[u8]>,
) -> Vec<(String, Vec<u8>)> {
    let txn = db.raw_database_for_test().begin_read().unwrap();
    let table = txn.open_table(def).unwrap();
    let mut rows = Vec::new();
    for row in table.iter().unwrap() {
        let (k, v) = row.unwrap();
        rows.push((k.value().to_string(), v.value().to_vec()));
    }
    rows
}

// ============================================================================
// Regression Tests
// ============================================================================

/// Scenario 1: Numeric ms and RFC3339 root TTL acceptance, rejection of mismatched
/// sidecar proofs at admission, REST, and chain ingress, and double-approval prevention.
#[tokio::test]
async fn root_ttl_numeric_and_rfc3339_accepted_and_mismatched_sidecar_rejected() {
    // 1. Parsing tests for parse_deletable_at_ms
    assert_eq!(roots::parse_deletable_at_ms("600000").unwrap(), 600_000);
    let rfc_str = "2030-01-01T00:10:00Z";
    let expected_rfc_ms = chrono::DateTime::parse_from_rfc3339(rfc_str)
        .unwrap()
        .timestamp_millis() as u64;
    assert_eq!(
        roots::parse_deletable_at_ms(rfc_str).unwrap(),
        expected_rfc_ms
    );
    assert!(roots::parse_deletable_at_ms("not-a-valid-timestamp").is_err());

    let key = SigningKey::from_bytes(&[7u8; 32]);

    // 2. Matching sidecars succeed at root_valid_until
    let num_root = canonical_root(&key, 600_000, 600_000);
    assert_eq!(roots::root_valid_until(&num_root).unwrap(), 600_000);

    let rfc_root = canonical_root_custom_expiry(&key, rfc_str, expected_rfc_ms);
    assert_eq!(roots::root_valid_until(&rfc_root).unwrap(), expected_rfc_ms);

    // 3. Mismatched sidecars fail at root_valid_until
    let short = canonical_root(&key, 600_000, 60_000);
    let err_short = roots::root_valid_until(&short).unwrap_err().to_string();
    assert!(
        err_short.contains("invalid root output proof"),
        "expected invalid root output proof, got: {err_short}"
    );

    let long = canonical_root(&key, 600_000, 900_000);
    let err_long = roots::root_valid_until(&long).unwrap_err().to_string();
    assert!(
        err_long.contains("invalid root output proof"),
        "expected invalid root output proof, got: {err_long}"
    );

    // 4. Admission rejection at engine level
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());

    let short_tag = bs58::encode(short.t_id).into_string();
    let (adm_short, _) = engine
        .ingress_hmc_lock_durable(
            short_tag,
            short.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(adm_short, L2Verdict::Rejected { ref reason } if reason.contains("invalid root output proof")),
        "shortened root must be rejected at engine admission: {adm_short:?}"
    );

    let long_tag = bs58::encode(long.t_id).into_string();
    let (adm_long, _) = engine
        .ingress_hmc_lock_durable(
            long_tag,
            long.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(adm_long, L2Verdict::Rejected { ref reason } if reason.contains("invalid root output proof")),
        "lengthened root must be rejected at engine admission: {adm_long:?}"
    );

    // 5. REST API rejection at POST /v1/lock and POST /v1/lock/chain
    let TestAppFixture {
        router: app,
        tier_controller: tier_ctrl,
        _temp: _app_temp,
        cancel: app_cancel,
        worker: app_worker,
        ..
    } = setup_test_app();
    tier_ctrl.register_f2f_peer("f2f_test_token");

    let live_now = test_now_ms();
    let mut live_short = canonical_root(&key, live_now + 600_000, live_now + 60_000);
    live_short.created_at_ms = live_now;
    let live_short_tag = bs58::encode(live_short.t_id).into_string();
    sign(&key, &live_short_tag, &mut live_short);

    let mut live_long = canonical_root(&key, live_now + 600_000, live_now + 900_000);
    live_long.created_at_ms = live_now;
    let live_long_tag = bs58::encode(live_long.t_id).into_string();
    sign(&key, &live_long_tag, &mut live_long);

    for bad_root in [&live_short, &live_long] {
        let req_bad = lock_request_from_entry(bad_root, true, None);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/lock")
                    .header("content-type", "application/json")
                    .header("x-peer-token", "f2f_test_token")
                    .body(Body::from(serde_json::to_vec(&req_bad).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "POST /v1/lock must reject mismatched sidecar root with BAD_REQUEST"
        );
        let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("Invalid genesis root TTL"),
            "expected Invalid genesis root TTL error body, got: {body_str}"
        );

        let chain_req = L2ChainLockRequest {
            auth: req_bad.auth.clone(),
            layer2_voucher_id: req_bad.layer2_voucher_id.clone(),
            chain: vec![req_bad.clone()],
        };
        let resp_chain = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/lock/chain")
                    .header("content-type", "application/json")
                    .header("x-peer-token", "f2f_test_token")
                    .body(Body::from(serde_json::to_vec(&chain_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp_chain.status(),
            StatusCode::BAD_REQUEST,
            "POST /v1/lock/chain must reject mismatched sidecar root with BAD_REQUEST"
        );
        let chain_body = http_body_util::BodyExt::collect(resp_chain.into_body())
            .await
            .unwrap()
            .to_bytes();
        let chain_str = String::from_utf8_lossy(&chain_body);
        assert!(
            chain_str.contains("Invalid genesis root TTL"),
            "expected Invalid genesis root TTL chain error body, got: {chain_str}"
        );
    }

    // 6. Double-approval flow reproduction
    let valid_root = canonical_root(&key, 600_000, 600_000);
    let root_tag = bs58::encode(valid_root.t_id).into_string();
    let (adm_valid, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            valid_root.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(adm_valid, L2Verdict::Verified { .. }),
        "valid root must be verified: {adm_valid:?}"
    );

    let spend_tag = "parent_spend_tag";
    let node = NodeIdentity::generate();
    let mut a = entry(&key, &valid_root.layer2_voucher_id, 2, None);
    sign(&key, spend_tag, &mut a);
    let (v_a, _) = engine
        .ingress_hmc_lock_durable(
            spend_tag.into(),
            a.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_a, L2Verdict::Verified { .. }));
    let parent = *blake3::hash(spend_tag.as_bytes()).as_bytes();
    let shard = engine
        .get_hmc_voucher_genesis_shard(&valid_root.layer2_voucher_id)
        .await
        .unwrap();
    let a_sig = create_attestation_for_network(
        &node,
        a.t_id,
        parent,
        shard,
        0,
        1_000,
        NetworkId::Mainnet,
    );
    engine
        .persist_original_approval(
            spend_tag.into(),
            a,
            *node.node_pubkey(),
            bincode::serialize(&a_sig).unwrap(),
            0,
            1_000,
        )
        .await
        .unwrap();

    // Advance time and prune: root remains alive because validity is 600_000
    engine.prune_expired(SimTime(91_000)).await.unwrap();
    assert!(db.is_signing_history_healthy());
    assert!(db
        .voucher_root(&valid_root.layer2_voucher_id)
        .unwrap()
        .is_some());

    // Spend B on same parent submitted at 91_000 must be rejected as Conflict / OwnChoiceConflict
    let mut b = entry(&key, &valid_root.layer2_voucher_id, 3, None);
    b.created_at_ms = 91_000;
    sign(&key, spend_tag, &mut b);
    let (v_b, _) = engine
        .ingress_hmc_lock_durable(
            spend_tag.into(),
            b.clone(),
            IngressOrigin::ClientApi,
            Some(91_000),
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(v_b, L2Verdict::Conflict { .. }),
        "diverging spend B must return Conflict: {v_b:?}"
    );
    let b_sig = create_attestation_for_network(
        &node,
        b.t_id,
        parent,
        shard,
        0,
        91_000,
        NetworkId::Mainnet,
    );
    let second = engine
        .persist_original_approval(
            spend_tag.into(),
            b,
            *node.node_pubkey(),
            bincode::serialize(&b_sig).unwrap(),
            0,
            91_000,
        )
        .await;
    assert!(
        second.is_err(),
        "same node must not release two diverging children for the same parent"
    );

    cancel.cancel();
    worker.await.unwrap();
    app_cancel.cancel();
    app_worker.await.unwrap();
}

/// Scenario 2: Valid root registration, idempotent retry, legacy root upgrade to
/// causal output proof, clean recovery, and fail-closed corruption latch preventing
/// silent deletion of corrupted signing history.
#[tokio::test]
async fn valid_root_registration_retry_upgrade_and_preexisting_corrupt_root_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());

    let author = SigningKey::from_bytes(&[1u8; 32]);
    let legacy_root = entry(&author, "voucher_upgrade_test", 1, Some(600_000));
    let root_tag = bs58::encode(legacy_root.t_id).into_string();
    let mut legacy_signed = legacy_root.clone();
    sign(&author, &root_tag, &mut legacy_signed);

    // 1. Ingest legacy root without sidecar
    let (v1, is_new1) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            legacy_signed.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v1, L2Verdict::Verified { .. }));
    assert!(is_new1);
    assert!(db
        .voucher_root("voucher_upgrade_test")
        .unwrap()
        .unwrap()
        .causal_output
        .is_none());

    // 2. Idempotent retry without sidecar
    let (v2, is_new2) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            legacy_signed.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v2, L2Verdict::Verified { .. }));
    assert!(!is_new2);

    // 3. Upgrade legacy root with valid causal output proof
    let receiver = [9u8; 32];
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: legacy_signed.layer2_voucher_id.clone(),
        transaction_id: legacy_signed.t_id,
        state_hash: [8u8; 32],
        sender_pubkey: legacy_signed.sender_ephemeral_pub,
        receiver_pubkey_hash: Some(receiver),
        change_pubkey_hash: None,
        root_valid_until_ms: 600_000,
        is_root: true,
        signature: [0u8; 64],
    };
    proof.signature = author.sign(&proof.digest().unwrap()).to_bytes();
    let mut upgraded = legacy_signed.clone();
    upgraded.causal_output = Some(proof);
    sign(&author, &root_tag, &mut upgraded);

    let (v3, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            upgraded.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v3, L2Verdict::Verified { .. }));
    assert!(db
        .voucher_root("voucher_upgrade_test")
        .unwrap()
        .unwrap()
        .causal_output
        .is_some());

    // 4. Retry upgraded root
    let (v4, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            upgraded.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v4, L2Verdict::Verified { .. }));

    // 5. Restart and recover from disk
    cancel.cancel();
    worker.await.unwrap();
    let cancel = CancellationToken::new();
    let (recovered, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    recovered.recover_from_disk(SimTime(1_000)).await.unwrap();
    assert!(recovered.is_signing_healthy());
    assert!(db.is_signing_history_healthy());

    // 6. Inject inconsistent corrupt root into TABLE_VOUCHER_ROOTS
    let mut corrupt = upgraded.clone();
    corrupt.layer2_voucher_id = "corrupt_voucher".into();
    let mut corrupt_proof = corrupt.causal_output.unwrap();
    corrupt_proof.voucher_id = "corrupt_voucher".into();
    corrupt_proof.root_valid_until_ms = 50_000; // Inconsistent with deletable_at = "600000"
    corrupt_proof.signature = author.sign(&corrupt_proof.digest().unwrap()).to_bytes();
    corrupt.causal_output = Some(corrupt_proof);
    assert!(roots::root_valid_until(&corrupt).is_err());

    let corrupt_bytes = serde_json::to_vec(&corrupt).unwrap();
    let mut txn = db.raw_database_for_test().begin_write().unwrap();
    txn.set_durability(redb::Durability::Immediate);
    txn.open_table(roots::TABLE_VOUCHER_ROOTS)
        .unwrap()
        .insert("corrupt_voucher", corrupt_bytes.as_slice())
        .unwrap();
    let sec = humoco_node::storage::db::grace_expiry_bucket_sec(600_000);
    txn.open_table(roots::TABLE_VOUCHER_ROOT_TTL)
        .unwrap()
        .insert((sec, "corrupt_voucher"), ())
        .unwrap();
    txn.commit().unwrap();

    // 7. Reopen: recover_from_disk must latch corruption and fail closed
    cancel.cancel();
    worker.await.unwrap();
    let cancel = CancellationToken::new();
    let (engine_corrupt, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let rec_res = engine_corrupt.recover_from_disk(SimTime(1_000)).await;
    assert!(
        matches!(rec_res, Err(StorageError::SigningHistoryCorrupt)),
        "recover_from_disk must return SigningHistoryCorrupt on corrupted root: {rec_res:?}"
    );
    assert!(!db.is_signing_history_healthy());
    assert!(!engine_corrupt.is_signing_healthy());

    // 8. Pruning must NOT silently delete the corrupt root
    engine_corrupt.prune_expired(SimTime(700_000)).await.unwrap();
    assert!(
        db.voucher_root("corrupt_voucher").unwrap().is_some(),
        "corrupted root must NOT be deleted by TTL pruning (fail-closed latch)"
    );

    cancel.cancel();
    worker.await.unwrap();
    drop(engine);
    drop(recovered);
    drop(engine_corrupt);
    drop(db);

    // 9. Cold process reopen via RedbStorage::open must immediately fail-close signing history
    let reopened = RedbStorage::open(&dir.path().join("node.redb")).unwrap();
    assert!(
        !reopened.is_signing_history_healthy(),
        "cold RedbStorage::open must detect inconsistent persisted root and latch signing corrupt"
    );
}

/// Scenario 3: Over live QUIC wire, a single poisoned sync source cannot authenticate
/// an unbound canonical root despite two honest empty-cut witnesses, and locally
/// committed consistent roots are preserved.
#[tokio::test]
async fn real_quic_single_poisoned_sync_source_cannot_install_unbound_canonical_root() {
    let peers = recovery::recovery_peers(4).await;
    let target = &peers[0];
    let now = target.manager.net_time_ms();

    let legitimate = canonical_root(
        &SigningKey::from_bytes(&[7u8; 32]),
        now + 600_000,
        now + 600_000,
    );
    let attacker = SigningKey::from_bytes(&[6u8; 32]);
    let mut forged = entry(&attacker, &legitimate.layer2_voucher_id, 2, Some(now + 600_000));
    let tag = bs58::encode(forged.t_id).into_string();
    sign(&attacker, &tag, &mut forged);
    let shard = canonical_voucher_shard(&genesis_parent_bytes_from_tag(&tag));

    // One source stores forged unbound root in its database; the other two contain no root.
    peers[1].db.put_hmc_lock(&tag, &forged).unwrap();
    let mut proofs = Vec::new();
    let mut poisoned_connection = None;
    for source in &peers[1..] {
        source.readiness.mark_shard_ready(shard);
        let conn = target
            .network
            .connect_peer(source.network.local_addr().unwrap())
            .await
            .unwrap();
        let reply = target
            .network
            .request_frozen_shard(&conn, shard, 1)
            .await
            .unwrap();
        proofs.push((*source.identity.node_pubkey(), reply));
        if source.identity.node_pubkey() == peers[1].identity.node_pubkey() {
            poisoned_connection = Some(conn);
        }
    }

    let objective = proofs[0].1.digest;
    let support = proofs[0].1.support_digest;
    assert!(proofs
        .iter()
        .all(|(_, reply)| reply.digest == objective && reply.support_digest == support));

    let committee: Vec<_> = peers.iter().map(|peer| *peer.identity.node_pubkey()).collect();
    let verified = VerifiedInheritedCut::verify(
        NetworkId::Mainnet,
        shard,
        *target.identity.node_pubkey(),
        &committee,
        3,
        objective,
        &[support],
        &[support],
        &proofs,
    )
    .unwrap();

    let page = target
        .network
        .request_active_sync_page_for_shard(&poisoned_connection.unwrap(), 2, 0, 500, shard)
        .await
        .unwrap();
    assert!(!page.has_more);

    let stage = Arc::new(ShardStage::new(shard, now).unwrap());
    stage.append(page.payload).unwrap();
    assert_eq!(stage.digest().unwrap(), objective);

    let install = target
        .engine
        .install_shard_snapshot(stage, objective, 1, [3u8; 32], 3, Some(verified), None)
        .await;
    let poisoned = target.db.voucher_root(&legitimate.layer2_voucher_id).unwrap();

    assert!(
        install.err().is_some_and(|error| {
            error
                .to_string()
                .contains("new canonical sync root lacks author output proof")
        }) && poisoned.is_none(),
        "one poisoned source must not authenticate an unbound root"
    );

    // Verify locally committed consistent legacy root (!is_new) is preserved across sync install,
    // without granting any exception to new unproved canonical roots.
    let legacy_local_voucher = "aa".repeat(32);
    let mut legacy_local = entry(&attacker, &legacy_local_voucher, 2, Some(now + 600_000));
    sign(&attacker, &tag, &mut legacy_local);
    target.db.put_hmc_lock(&tag, &legacy_local).unwrap();
    assert_eq!(
        target.db.voucher_root(&legacy_local_voucher).unwrap(),
        Some(legacy_local.clone())
    );
    let local_stage = Arc::new(ShardStage::new(shard, now).unwrap());
    local_stage
        .append(SyncPayload {
            hmc_locks: vec![(tag.clone(), legacy_local.clone())],
            support: vec![],
        })
        .unwrap();
    let local_stage_digest = local_stage.digest().unwrap();
    target
        .engine
        .install_shard_snapshot(local_stage, local_stage_digest, 1, [4u8; 32], 3, None, None)
        .await
        .expect("pre-existing local legacy root must remain valid during sync install");
    assert_eq!(
        target.db.voucher_root(&legacy_local_voucher).unwrap(),
        Some(legacy_local)
    );

    recovery::stop_recovery_peers(peers).await;
}

/// Scenario 4: Rejected snapshot installation cleanly aborts and rolls back the
/// transaction, leaving TABLE_VOUCHER_ROOTS, TABLE_LOCKS, TABLE_HMC_LOCKS,
/// TABLE_PROVISIONAL_LOCKS, TABLE_PROVISIONAL_HMC_LOCKS, TABLE_CONFIRMATION_SUPPORT,
/// and committed_shard_digest 100% byte-for-byte identical to before.
#[tokio::test]
async fn rejected_shard_install_leaves_root_lock_support_and_provisional_tables_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("target.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());

    let author = SigningKey::from_bytes(&[3u8; 32]);
    let valid_root = canonical_root(&author, 600_000, 600_000);
    let root_tag = bs58::encode(valid_root.t_id).into_string();

    // 1. Populate committed root
    let (v_root, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            valid_root.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    // 2. Populate active HMC lock
    let mut hmc_spend = entry(&author, &valid_root.layer2_voucher_id, 2, None);
    let hmc_tag = "hmc_active_spend";
    sign(&author, hmc_tag, &mut hmc_spend);
    let (v_hmc, _) = engine
        .ingress_hmc_lock_durable(
            hmc_tag.into(),
            hmc_spend.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_hmc, L2Verdict::Verified { .. }));

    // 3. Populate support row in TABLE_CONFIRMATION_SUPPORT and provisional HMC
    let support_fact = ConfirmationSupport {
        child: hmc_spend.t_id,
        parent: *blake3::hash(hmc_tag.as_bytes()).as_bytes(),
        class: 1,
        root_valid_until_ms: 600_000,
        verified_context: [0x50u8; 32],
    };
    let fact_bytes = serde_json::to_vec(&support_fact).unwrap();

    let prov_hmc = entry(&author, &valid_root.layer2_voucher_id, 99, None);
    let prov_hmc_bytes = serde_json::to_vec(&prov_hmc).unwrap();

    {
        let mut txn = db.raw_database_for_test().begin_write().unwrap();
        txn.set_durability(redb::Durability::Immediate);
        txn.open_table(humoco_node::storage::db::support::TABLE_CONFIRMATION_SUPPORT)
            .unwrap()
            .insert(hmc_tag, fact_bytes.as_slice())
            .unwrap();
        txn.open_table(TABLE_PROVISIONAL_HMC_LOCKS)
            .unwrap()
            .insert("prov_hmc_tag", prov_hmc_bytes.as_slice())
            .unwrap();
        txn.commit().unwrap();
    }

    let shard = canonical_voucher_shard(&genesis_parent_bytes_from_tag(&root_tag));

    // Snapshot raw contents of all 4 tables and committed shard digest BEFORE install
    let roots_before = snapshot_table_str(&db, roots::TABLE_VOUCHER_ROOTS);
    let hmc_locks_before = snapshot_table_str(&db, TABLE_HMC_LOCKS);
    let prov_hmc_locks_before = snapshot_table_str(&db, TABLE_PROVISIONAL_HMC_LOCKS);
    let support_before = snapshot_table_str(
        &db,
        humoco_node::storage::db::support::TABLE_CONFIRMATION_SUPPORT,
    );
    let digest_before = db.committed_shard_digest(shard, 1_000).unwrap();

    assert!(!roots_before.is_empty());
    assert!(!hmc_locks_before.is_empty());
    assert!(!prov_hmc_locks_before.is_empty());
    assert!(!support_before.is_empty());

    // Prepare a ShardStage with:
    // (a) a valid proved canonical root in `shard` (lexicographically earlier than "ffff...",
    //     so `roots::put` mutates `tx` first), AND
    // (b) an injected unbound canonical 64-hex root ("ffff...") in `shard` (lacking causal_output),
    //     which aborts and rolls back the already-dirtied transaction!
    let stage = Arc::new(ShardStage::new(shard, 1_000).unwrap());
    let valid_stage_author = SigningKey::from_bytes(&[0x44u8; 32]);
    let mut valid_stage_root = None;
    for candidate_idx in 2u32..200_000 {
        let mut candidate_tid = [0u8; 32];
        candidate_tid[..4].copy_from_slice(&candidate_idx.to_le_bytes());
        let candidate_tag = bs58::encode(candidate_tid).into_string();
        if canonical_voucher_shard(&genesis_parent_bytes_from_tag(&candidate_tag)) == shard {
            let mut row = entry(&valid_stage_author, "", 0, Some(600_000));
            row.t_id = candidate_tid;
            let receiver = [9u8; 32];
            let mut hash = Sha256::new();
            hash.update(row.t_id);
            hash.update(row.sender_ephemeral_pub);
            hash.update(receiver);
            hash.update(b"600000");
            row.layer2_voucher_id = hex::encode(hash.finalize());
            if row.layer2_voucher_id.as_str() < "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" {
                let mut proof = CausalOutputProof {
                    version: 1,
                    voucher_id: row.layer2_voucher_id.clone(),
                    transaction_id: row.t_id,
                    state_hash: [8u8; 32],
                    sender_pubkey: row.sender_ephemeral_pub,
                    receiver_pubkey_hash: Some(receiver),
                    change_pubkey_hash: None,
                    root_valid_until_ms: 600_000,
                    is_root: true,
                    signature: [0u8; 64],
                };
                proof.signature = valid_stage_author.sign(&proof.digest().unwrap()).to_bytes();
                row.causal_output = Some(proof);
                sign(&valid_stage_author, &candidate_tag, &mut row);
                valid_stage_root = Some((candidate_tag, row));
                break;
            }
        }
    }
    let (valid_stage_tag, valid_stage_entry) =
        valid_stage_root.expect("must find same-shard valid root");

    let unbound_attacker = SigningKey::from_bytes(&[0x99u8; 32]);
    let mut unbound_tid = [0u8; 32];
    for candidate_idx in 200_001u32..400_000 {
        let mut t = [0u8; 32];
        t[..4].copy_from_slice(&candidate_idx.to_le_bytes());
        let candidate_tag = bs58::encode(t).into_string();
        if canonical_voucher_shard(&genesis_parent_bytes_from_tag(&candidate_tag)) == shard {
            unbound_tid = t;
            break;
        }
    }
    let mut unbound_root = entry(
        &unbound_attacker,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        55,
        Some(600_000),
    );
    unbound_root.t_id = unbound_tid;
    let unbound_tag = bs58::encode(unbound_root.t_id).into_string();
    sign(&unbound_attacker, &unbound_tag, &mut unbound_root);
    stage
        .append(SyncPayload {
            hmc_locks: vec![
                (valid_stage_tag, valid_stage_entry),
                (unbound_tag, unbound_root),
            ],
            support: vec![],
        })
        .unwrap();

    let stage_digest = stage.digest().unwrap();
    let install_res = engine
        .install_shard_snapshot(stage, stage_digest, 1, [0x77u8; 32], 3, None, None)
        .await;

    assert!(
        install_res.is_err(),
        "snapshot installation with unbound root must fail"
    );
    let err_str = install_res.unwrap_err().to_string();
    assert!(
        err_str.contains("new canonical sync root lacks author output proof"),
        "unexpected install error: {err_str}"
    );

    // Snapshot raw contents AFTER failed install and assert 100% byte-for-byte equality
    let roots_after = snapshot_table_str(&db, roots::TABLE_VOUCHER_ROOTS);
    let hmc_locks_after = snapshot_table_str(&db, TABLE_HMC_LOCKS);
    let prov_hmc_locks_after = snapshot_table_str(&db, TABLE_PROVISIONAL_HMC_LOCKS);
    let support_after = snapshot_table_str(
        &db,
        humoco_node::storage::db::support::TABLE_CONFIRMATION_SUPPORT,
    );
    let digest_after = db.committed_shard_digest(shard, 1_000).unwrap();

    assert_eq!(
        roots_after, roots_before,
        "TABLE_VOUCHER_ROOTS must be unchanged"
    );
    assert_eq!(
        hmc_locks_after, hmc_locks_before,
        "TABLE_HMC_LOCKS must be unchanged"
    );
    assert_eq!(
        prov_hmc_locks_after, prov_hmc_locks_before,
        "TABLE_PROVISIONAL_HMC_LOCKS must be unchanged"
    );
    assert_eq!(
        support_after, support_before,
        "TABLE_CONFIRMATION_SUPPORT must be unchanged"
    );
    assert_eq!(
        digest_after, digest_before,
        "committed_shard_digest must be unchanged"
    );

    cancel.cancel();
    worker.await.unwrap();
}

/// Scenario 5: Idempotent variant replays (different created_at_ms or encrypted_timestamp)
/// preserve the exact original accepted entry A in RAM, disk, and original approval,
/// leave committed shard digest identical, survive cold restart, and reject divergent spends.
#[tokio::test]
async fn idempotent_variants_preserve_exact_entry_original_approval_digest_and_restart() {
    let TestAppFixture {
        router: app,
        engine,
        storage: db,
        identity,
        tier_controller: tier_ctrl,
        _temp,
        cancel,
        worker,
    } = setup_test_app();
    tier_ctrl.register_f2f_peer("test_peer_token");

    let now_ms = test_now_ms();
    let root_expiry = now_ms + 600_000;
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let mut root = canonical_root(&key, root_expiry, root_expiry);
    root.created_at_ms = now_ms;
    let root_tag = bs58::encode(root.t_id).into_string();
    sign(&key, &root_tag, &mut root);

    // Register root via REST API
    let root_req = lock_request_from_entry(&root, true, None);
    let res_root = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "test_peer_token")
                .body(Body::from(serde_json::to_vec(&root_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res_root.status().is_success(),
        "root registration failed: {}",
        res_root.status()
    );

    // Derive canonical SST ds_tag from root.t_id + sender_ephemeral_pub
    let spend_tag = {
        use sha3::{Digest as _, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(32u32.to_le_bytes());
        h.update(root.t_id);
        h.update(32u32.to_le_bytes());
        h.update(key.verifying_key().as_bytes());
        bs58::encode(h.finalize()).into_string()
    };

    // Submit spend A (baseline)
    let mut a = entry(&key, &root.layer2_voucher_id, 2, None);
    a.t_id = *blake3::hash(spend_tag.as_bytes()).as_bytes();
    a.created_at_ms = now_ms;
    a.encrypted_timestamp = 0;
    sign(&key, &spend_tag, &mut a);
    let req_a = lock_request_from_entry(&a, false, Some(spend_tag.clone()));
    let res_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "test_peer_token")
                .body(Body::from(serde_json::to_vec(&req_a).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_a.status(), StatusCode::CREATED);
    assert_eq!(db.get_hmc_lock(&spend_tag).unwrap().unwrap(), a);

    let shard_id = canonical_voucher_shard(&genesis_parent_bytes_from_tag(&root_tag));
    let before_digest = db.committed_shard_digest(shard_id, now_ms).unwrap();

    // Prepare variant B (same t_id, different created_at_ms and encrypted_timestamp)
    let mut b = a.clone();
    b.created_at_ms = now_ms + 1;
    b.encrypted_timestamp = 77;
    sign(&key, &spend_tag, &mut b);

    // 1. Ingress variant B via REST API -> returns 200 OK (idempotent), retains A in DB
    let req_b = lock_request_from_entry(&b, false, Some(spend_tag.clone()));
    let res_b = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "test_peer_token")
                .body(Body::from(serde_json::to_vec(&req_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_b.status(), StatusCode::OK);
    assert_eq!(
        db.get_hmc_lock(&spend_tag).unwrap().unwrap(),
        a,
        "DB must retain exact entry A after REST variant submission"
    );

    // 2. Ingress variant B over REAL QUIC wire (`LockVerifyRequest`)
    let pm_server = Arc::new(PeerManager::new(vec![]));
    pm_server.set_simulation_mode(true);
    pm_server.set_local_sync_ready(true);
    let pm_client = Arc::new(PeerManager::new(vec![]));
    pm_client.set_simulation_mode(true);
    pm_client.set_local_sync_ready(true);
    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    for s in 0..=u16::MAX {
        readiness.mark_shard_ready(s);
    }
    let sender_node = NodeIdentity::generate();
    let quic_cancel = CancellationToken::new();
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            db.clone(),
            identity.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(Arc::new(std::sync::atomic::AtomicBool::new(true)))
        .with_readiness_manager(readiness.clone()),
    );
    let server_transport = humoco_node::network::QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity,
        pm_server.clone(),
        handler,
        quic_cancel.clone(),
    )
    .unwrap();
    server_transport.set_sync_ready(true);
    let server_addr = server_transport.local_addr().unwrap();
    server_transport.spawn_accept_loop();

    let client_transport = humoco_node::network::QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &sender_node,
        pm_client.clone(),
        Arc::new(humoco_node::network::DefaultRequestHandler),
        quic_cancel.clone(),
    )
    .unwrap();
    let client_addr = client_transport.local_addr().unwrap();
    client_transport.spawn_accept_loop();

    for (pm, local_id, peer_id, peer_addr) in [
        (&pm_server, &identity, &sender_node, client_addr),
        (&pm_client, &sender_node, &identity, server_addr),
    ] {
        pm.register_f2f_friend(*peer_id.node_pubkey(), Some(peer_addr))
            .await;
        pm.learn_node_from_gossip_with_hrw(
            *peer_id.node_pubkey(),
            *peer_id.hrw_routing_id(),
            peer_addr,
            0,
            None,
        )
        .await;
        pm.set_first_seen_for_test(
            peer_id.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
        pm.learn_node_from_gossip_with_hrw(
            *local_id.node_pubkey(),
            *local_id.hrw_routing_id(),
            "127.0.0.1:1".parse().unwrap(),
            0,
            None,
        )
        .await;
        pm.set_first_seen_for_test(
            local_id.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    }

    let ttl_s = root_expiry.saturating_sub(now_ms + 1) / 1000;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let sender_pow = Arc::new(PowEngine::new(*sender_node.node_id(), 8));
    let sender_tier = TierController::new(db.clone(), sender_pow);
    let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
        sender_tier.record_declared_usage(now_ms + 1, footprint);
    let declared_write_ema = sender_tier.current_write_ema_micro_bj();
    let declared_read_ema = sender_tier.current_read_ema_credits();
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        sender_node.node_pubkey(),
        epoch_day,
        epoch_seq,
        now_ms + 1,
        declared_write_ema,
        declared_read_ema,
        footprint,
        false,
        &b.t_id,
    );
    let wire = LockWirePayload::Hmc {
        req: req_b.clone(),
        chain: None,
        root_valid_until: root_expiry,
        epoch_day,
        epoch_seq,
        cumulative_micro_byte_years,
        prev_day_final_bytes,
        current_anl_24h: 2,
        declared_write_ema_micro_bj: declared_write_ema,
        declared_read_ema_credits: declared_read_ema,
        sender_pubkey: *sender_node.node_pubkey(),
        sender_signature: sender_node.signing_key().sign(&digest).to_bytes(),
        timestamp_ms: now_ms + 1,
    };
    let payload = bincode::serialize(&wire).unwrap();
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );
    let conn = client_transport.connect_peer(server_addr).await.unwrap();
    let (resp_hdr, resp_bytes) = client_transport
        .send_request(&conn, &header, &payload)
        .await
        .expect("send LockVerifyRequest over real QUIC");
    assert_eq!(resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(
        resp_hdr.flags, 0,
        "real QUIC LockVerifyRequest must succeed without error flags"
    );
    assert!(!resp_bytes.is_empty());
    assert_eq!(
        db.get_hmc_lock(&spend_tag).unwrap().unwrap(),
        a,
        "DB must retain exact entry A after real QUIC LockVerifyRequest"
    );

    quic_cancel.cancel();
    client_transport.close();
    server_transport.close();

    // 3. Ingress variant B via ingress_hmc_lock_durable & persist_original_approval
    let (verdict_b, _) = engine
        .ingress_hmc_lock_durable(
            spend_tag.clone(),
            b.clone(),
            IngressOrigin::ClientApi,
            Some(now_ms + 1),
            None,
            None,
            None,
        )
        .await;
    let L2Verdict::Verified {
        lock_entry: acknowledged,
    } = verdict_b
    else {
        panic!("variant B must be verified: {verdict_b:?}")
    };
    assert_eq!(acknowledged, a, "acknowledged entry must equal exact A");
    assert_eq!(engine.get_hmc_ram_lock(&spend_tag).await.unwrap(), a);
    assert_eq!(db.get_hmc_lock(&spend_tag).unwrap().unwrap(), a);

    engine
        .persist_original_approval(
            spend_tag.clone(),
            b.clone(),
            [8u8; 32],
            b"retained-vote".to_vec(),
            0,
            now_ms + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        db.get_hmc_lock(&spend_tag).unwrap().unwrap(),
        a,
        "original approval persistence must retain exact entry A"
    );
    assert_eq!(
        db.committed_shard_digest(shard_id, now_ms).unwrap(),
        before_digest,
        "committed shard digest must remain unchanged"
    );

    // 4. Durability checks: A is durable, B is not
    assert!(engine.is_hmc_entry_durable(&spend_tag, &a, root_expiry).await);
    assert!(!engine.is_hmc_entry_durable(&spend_tag, &b, root_expiry).await);

    // 5. Restart and recover from disk
    cancel.cancel();
    worker.await.unwrap();

    let rec_cancel = CancellationToken::new();
    let (rec_engine, rec_worker) = DualTierEngine::new_with_token(db.clone(), rec_cancel.clone());
    rec_engine.recover_from_disk(SimTime(now_ms)).await.unwrap();
    assert_eq!(
        rec_engine.get_hmc_ram_lock(&spend_tag).await.unwrap(),
        a,
        "recovered RAM entry must equal exact A"
    );
    assert_eq!(
        db.get_hmc_lock(&spend_tag).unwrap().unwrap(),
        a,
        "recovered DB entry must equal exact A"
    );
    assert_eq!(
        db.committed_shard_digest(shard_id, now_ms).unwrap(),
        before_digest,
        "recovered shard digest must equal before_digest"
    );

    // 6. Cross-voucher same-t_id collision C on same parent tag returns Conflict and cannot persist approval
    let other_root = canonical_root(&key, root_expiry, root_expiry);
    let mut c = a.clone();
    c.layer2_voucher_id = "cc".repeat(32);
    assert_ne!(c.layer2_voucher_id, other_root.layer2_voucher_id);
    // Anchor a second legacy voucher root so c has a known root in RAM, isolating the cross-voucher t_id check
    let mut second_root = entry(&key, "other_voucher_divergent", 91, Some(root_expiry));
    second_root.created_at_ms = now_ms;
    let second_root_tag = bs58::encode(second_root.t_id).into_string();
    sign(&key, &second_root_tag, &mut second_root);
    let (v_sr, _) = rec_engine
        .ingress_hmc_lock_durable(
            second_root_tag,
            second_root,
            IngressOrigin::ClientApi,
            Some(now_ms),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_sr, L2Verdict::Verified { .. }));

    c.layer2_voucher_id = "other_voucher_divergent".into();
    sign(&key, &spend_tag, &mut c);
    let (verdict_c, _) = rec_engine
        .ingress_hmc_lock_durable(
            spend_tag.clone(),
            c.clone(),
            IngressOrigin::ClientApi,
            Some(now_ms + 2),
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(verdict_c, L2Verdict::Conflict { ref existing_lock } if *existing_lock == a),
        "cross-voucher same-t_id submission must return Conflict(A), got: {verdict_c:?}"
    );

    let persist_c = rec_engine
        .persist_original_approval(
            spend_tag,
            c,
            [8u8; 32],
            b"divergent-approval".to_vec(),
            0,
            now_ms + 2,
        )
        .await;
    assert!(
        matches!(persist_c, Err(StorageError::OwnChoiceConflict)),
        "cross-voucher same-t_id spend must fail with OwnChoiceConflict, got: {persist_c:?}"
    );

    rec_cancel.cancel();
    rec_worker.await.unwrap();
}

/// Scenario 6: Concurrent identical retries, timestamp variants, and diverging
/// double-spends executed across 30 concurrent tokio tasks preserve the exact winning
/// entry A in RAM and DB, keep signing history healthy, and survive cold restart cleanly.
#[tokio::test]
async fn concurrent_identical_and_diverging_submissions_preserve_exact_state_and_latch() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("concurrent.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let mut root = entry(&key, "voucher_concurrent", 1, Some(600_000));
    let root_tag = bs58::encode(root.t_id).into_string();
    sign(&key, &root_tag, &mut root);

    // Register root
    let (v_root, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            root.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    // Establish winning entry A
    let parent_tag = "concurrent_parent_tag";
    let mut a = entry(&key, "voucher_concurrent", 10, None);
    a.created_at_ms = 1_000;
    a.encrypted_timestamp = 0;
    sign(&key, parent_tag, &mut a);
    let (v_a, _) = engine
        .ingress_hmc_lock_durable(
            parent_tag.into(),
            a.clone(),
            IngressOrigin::ClientApi,
            Some(1_000),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_a, L2Verdict::Verified { .. }));
    engine
        .persist_original_approval(
            parent_tag.into(),
            a.clone(),
            [1u8; 32],
            b"winning-approval-a".to_vec(),
            0,
            1_000,
        )
        .await
        .unwrap();

    // Spawn 30 concurrent tasks:
    // - 10 exact retries of A
    // - 10 timestamp variants of A
    // - 10 diverging double-spend attempts
    let mut join_set = tokio::task::JoinSet::new();

    for i in 0..10 {
        let eng = engine.clone();
        let a_entry = a.clone();
        join_set.spawn(async move {
            let (v, _) = eng
                .ingress_hmc_lock_durable(
                    parent_tag.into(),
                    a_entry.clone(),
                    IngressOrigin::ClientApi,
                    Some(1_000),
                    None,
                    None,
                    None,
                )
                .await;
            assert!(matches!(v, L2Verdict::Verified { .. }));
            let _ = eng
                .persist_original_approval(
                    parent_tag.into(),
                    a_entry,
                    [1u8; 32],
                    format!("retry-approval-{i}").into_bytes(),
                    0,
                    1_000,
                )
                .await;
        });
    }

    for i in 0..10u64 {
        let eng = engine.clone();
        let mut b_variant = a.clone();
        b_variant.created_at_ms = 1_000 + i;
        b_variant.encrypted_timestamp = u128::from(i);
        sign(&key, parent_tag, &mut b_variant);
        join_set.spawn(async move {
            let (v, _) = eng
                .ingress_hmc_lock_durable(
                    parent_tag.into(),
                    b_variant.clone(),
                    IngressOrigin::ClientApi,
                    Some(1_000 + i),
                    None,
                    None,
                    None,
                )
                .await;
            assert!(matches!(v, L2Verdict::Verified { .. }));
            let _ = eng
                .persist_original_approval(
                    parent_tag.into(),
                    b_variant,
                    [1u8; 32],
                    format!("variant-approval-{i}").into_bytes(),
                    0,
                    1_000 + i,
                )
                .await;
        });
    }

    for i in 0..10 {
        let eng = engine.clone();
        let mut c_conflict = entry(&key, "voucher_concurrent", 20 + i as u8, None);
        c_conflict.created_at_ms = 1_000;
        sign(&key, parent_tag, &mut c_conflict);
        join_set.spawn(async move {
            let (v, _) = eng
                .ingress_hmc_lock_durable(
                    parent_tag.into(),
                    c_conflict.clone(),
                    IngressOrigin::ClientApi,
                    Some(1_000),
                    None,
                    None,
                    None,
                )
                .await;
            assert!(matches!(
                v,
                L2Verdict::Conflict { .. } | L2Verdict::Rejected { .. }
            ));
            let _ = eng
                .persist_original_approval(
                    parent_tag.into(),
                    c_conflict,
                    [1u8; 32],
                    format!("conflict-approval-{i}").into_bytes(),
                    0,
                    1_000,
                )
                .await;
        });
    }

    while let Some(res) = join_set.join_next().await {
        res.expect("concurrent task must complete without panic");
    }

    // Verify state: winner remains exact A in RAM and DB
    assert_eq!(
        engine.get_hmc_ram_lock(parent_tag).await.unwrap(),
        a,
        "RAM lock must remain exact A"
    );
    assert_eq!(
        db.get_hmc_lock(parent_tag).unwrap().unwrap(),
        a,
        "DB lock must remain exact A"
    );
    assert!(
        db.is_signing_history_healthy(),
        "signing history must remain healthy"
    );
    assert!(
        engine.is_signing_healthy(),
        "engine signing must remain healthy"
    );

    // Restart and recover
    cancel.cancel();
    worker.await.unwrap();

    let rec_cancel = CancellationToken::new();
    let (rec_engine, rec_worker) = DualTierEngine::new_with_token(db.clone(), rec_cancel.clone());
    rec_engine.recover_from_disk(SimTime(1_000)).await.unwrap();
    assert_eq!(
        rec_engine.get_hmc_ram_lock(parent_tag).await.unwrap(),
        a,
        "recovered RAM lock must remain exact A"
    );
    assert_eq!(
        db.get_hmc_lock(parent_tag).unwrap().unwrap(),
        a,
        "recovered DB lock must remain exact A"
    );

    rec_cancel.cancel();
    rec_worker.await.unwrap();
}
