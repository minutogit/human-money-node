//! Review boundary regression test suite (Findings F1–F5).
//!
//! Covers:
//! - F1: Oversize root rejection before mutation, foreign shard snapshot servability,
//!   exact ds_tag / entry size boundaries, and QUIC LockIngress verification.
//! - F2: Spend sidecar root_valid_until_ms validation (shorter/longer rejected,
//!   matching accepted, snapshotted, staged, and recovered).
//! - F3: Fail-closed latching and displacement prevention on cancelled confirmation support,
//!   plus I/O fault injection during persist_confirmation_support.
//! - F4: Signed /v1/status durability gating (uncommitted spend rejected until durable,
//!   committed spend verified, signing failure triggers 503 SERVICE_UNAVAILABLE).
//! - F5: Native idempotent replay preserving Final status on disk and across recovery.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use humoco_node::{
    api::{
        build_router,
        dto::QuorumCertificateDto,
        hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest,
            L2ResponseEnvelope, L2StatusQuery, L2Verdict,
        },
        routes::create_attestation_for_network,
        AppState,
    },
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::framing::{ActiveSyncRequest, SyncPayload},
    storage::{
        db::{install::ShardStage, snapshot::SnapshotCuts},
        DualTierEngine, HmcRamIndex, IngressOrigin, RedbStorage,
    },
};
use humoco_proto::causal::CausalOutputProof;
use humoco_sim_core::{
    storage::RamIndex,
    types::{
        canonical_voucher_shard, genesis_parent_bytes_from_tag, LockRecord, LockStatus, NetworkId,
        SimTime,
    },
};
use redb::StorageBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn sign(key: &SigningKey, req: &mut L2LockRequest) {
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(req)).to_bytes();
}

fn root(key: &SigningKey, at: u64) -> L2LockRequest {
    let sender = key.verifying_key().to_bytes();
    let expiry = (at + 600_000).to_string();
    let mut hash = Sha256::new();
    hash.update([1; 32]);
    hash.update(sender);
    hash.update(expiry.as_bytes());
    let voucher = hex::encode(hash.finalize());
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: voucher.clone(),
        transaction_id: [1; 32],
        state_hash: [2; 32],
        sender_pubkey: sender,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: at + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    let mut req = L2LockRequest {
        causal_output: Some(proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender,
            auth_signature: None,
        },
        layer2_voucher_id: voucher,
        ds_tag: None,
        transaction_hash: [1; 32],
        is_genesis: true,
        sender_ephemeral_pub: sender,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: at,
        deletable_at: Some(expiry),
        privacy_guard: None,
    };
    sign(key, &mut req);
    req
}

async fn submit(app: axum::Router, req: &L2LockRequest) -> StatusCode {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", "f2f_0123456789abcdef0123456789abcdef")
                .body(Body::from(serde_json::to_vec(req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    if !status.is_success() {
        let b = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        eprintln!("submit rejection response: {}", String::from_utf8_lossy(&b));
    }
    status
}

fn app(db: Arc<RedbStorage>, engine: DualTierEngine) -> axum::Router {
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 8));
    let tier = Arc::new(TierController::new(db.clone(), pow.clone()));
    tier.register_f2f_peer("f2f_0123456789abcdef0123456789abcdef");
    let state = AppState::new(engine, db, identity, tier, pow);
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    build_router(state)
}

#[derive(Clone, Debug)]
struct FaultBackend {
    inner: Arc<redb::backends::InMemoryBackend>,
    fail_sync: Arc<AtomicBool>,
}

impl StorageBackend for FaultBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }
    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.inner.set_len(len)
    }
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, std::io::Error> {
        self.inner.read(offset, len)
    }
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        self.inner.write(offset, data)
    }
    fn sync_data(&self, eventual: bool) -> Result<(), std::io::Error> {
        if self.fail_sync.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected sync fault"));
        }
        self.inner.sync_data(eventual)
    }
}

// ---------------------------------------------------------------------------
// Finding F1: Oversize root rejection & foreign shard snapshot servability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oversize_root_rejected_and_foreign_shard_snapshot_stays_servable(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let app = app(db.clone(), engine.clone());
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut req = root(&key, now());
    req.privacy_guard = Some("x".repeat(17_000));
    sign(&key, &mut req);
    assert!(serde_json::to_vec(&req)?.len() < 64 * 1024);

    let status = submit(app, &req).await;
    assert_ne!(
        status,
        StatusCode::CREATED,
        "oversize root must be rejected"
    );
    assert!(
        db.voucher_root(&req.layer2_voucher_id)?.is_none(),
        "db must not contain rejected root"
    );
    assert!(
        engine
            .hmc_ram
            .read()
            .await
            .get_voucher_genesis_parent(&req.layer2_voucher_id)
            .is_none(),
        "RAM must have no root anchor"
    );

    let root_shard = canonical_voucher_shard(&genesis_parent_bytes_from_tag(
        &bs58::encode(req.transaction_hash).into_string(),
    ));
    let mut query = ActiveSyncRequest::new(0, 500);
    query.target_shard = Some(root_shard.wrapping_add(1));
    let result = SnapshotCuts::default().page(&db, query, [0; 32]);
    assert!(
        result.is_ok(),
        "foreign shard snapshot stays servable: {:?}",
        result.err()
    );

    cancel.cancel();
    worker.await?;
    Ok(())
}

#[tokio::test]
async fn tag_and_entry_size_boundaries_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("boundary.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let key = SigningKey::from_bytes(&[17; 32]);
    let at = now();
    let valid_root = root(&key, at);
    let root_tag = bs58::encode(valid_root.transaction_hash).into_string();

    let (v_root, root_ok) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&valid_root),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(root_ok);
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    // Boundary 1: 128-byte ds_tag succeeds
    let tag_128 = "a".repeat(128);
    let mut spend_128 = valid_root.clone();
    spend_128.is_genesis = false;
    spend_128.ds_tag = Some(tag_128.clone());
    spend_128.transaction_hash = [80; 32];
    spend_128.deletable_at = None;
    if let Some(proof) = spend_128.causal_output.as_mut() {
        proof.is_root = false;
        proof.transaction_id = spend_128.transaction_hash;
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    }
    sign(&key, &mut spend_128);
    let (v_128, ok_128) = engine
        .ingress_hmc_lock_durable(
            tag_128,
            L2LockEntry::from(&spend_128),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(ok_128, "128-byte ds_tag must succeed");
    assert!(matches!(v_128, L2Verdict::Verified { .. }));

    // Boundary 2: 129-byte ds_tag is rejected
    let tag_129 = "b".repeat(129);
    let mut spend_129 = valid_root.clone();
    spend_129.is_genesis = false;
    spend_129.ds_tag = Some(tag_129.clone());
    spend_129.transaction_hash = [81; 32];
    spend_129.deletable_at = None;
    if let Some(proof) = spend_129.causal_output.as_mut() {
        proof.is_root = false;
        proof.transaction_id = spend_129.transaction_hash;
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    }
    sign(&key, &mut spend_129);
    let (v_129, ok_129) = engine
        .ingress_hmc_lock_durable(
            tag_129,
            L2LockEntry::from(&spend_129),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(!ok_129, "129-byte ds_tag must be rejected");
    assert!(matches!(v_129, L2Verdict::Rejected { .. }));

    // Boundary 3: <= 16 KiB serialized L2LockEntry succeeds
    let mut spend_16k = valid_root.clone();
    spend_16k.is_genesis = false;
    spend_16k.ds_tag = Some("tag-16k".into());
    spend_16k.transaction_hash = [82; 32];
    spend_16k.deletable_at = None;
    if let Some(proof) = spend_16k.causal_output.as_mut() {
        proof.is_root = false;
        proof.transaction_id = spend_16k.transaction_hash;
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    }
    spend_16k.privacy_guard = Some("x".repeat(14_000));
    sign(&key, &mut spend_16k);
    let entry_16k = L2LockEntry::from(&spend_16k);
    assert!(serde_json::to_vec(&entry_16k)?.len() <= 16 * 1024);
    let (v_16k, ok_16k) = engine
        .ingress_hmc_lock_durable(
            "tag-16k".into(),
            entry_16k,
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(ok_16k, "<= 16 KiB serialized entry must succeed");
    assert!(matches!(v_16k, L2Verdict::Verified { .. }));

    // Boundary 4: > 16 KiB serialized L2LockEntry is rejected
    let mut spend_over = valid_root.clone();
    spend_over.is_genesis = false;
    spend_over.ds_tag = Some("tag-over".into());
    spend_over.transaction_hash = [83; 32];
    spend_over.deletable_at = None;
    if let Some(proof) = spend_over.causal_output.as_mut() {
        proof.is_root = false;
        proof.transaction_id = spend_over.transaction_hash;
        proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    }
    spend_over.privacy_guard = Some("x".repeat(17_000));
    sign(&key, &mut spend_over);
    let entry_over = L2LockEntry::from(&spend_over);
    assert!(serde_json::to_vec(&entry_over)?.len() > 16 * 1024);
    let (v_over, ok_over) = engine
        .ingress_hmc_lock_durable(
            "tag-over".into(),
            entry_over,
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(!ok_over, "> 16 KiB serialized entry must be rejected");
    assert!(matches!(v_over, L2Verdict::Rejected { .. }));

    cancel.cancel();
    worker.await?;
    Ok(())
}

#[tokio::test]
async fn quic_lock_ingress_rejects_oversize_root() -> Result<(), Box<dyn std::error::Error>> {
    use humoco_node::daemon::ShardReadinessManager;
    use humoco_node::network::{DefaultRequestHandler, NodeRequestHandler, QuicTransport};
    use humoco_sim_core::wire::{MsgType, WireHeader};

    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("quic.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let identity = NodeIdentity::generate();
    let pm = Arc::new(humoco_node::network::PeerManager::new(Vec::new()));
    let ready = Arc::new(ShardReadinessManager::with_cancel_token(cancel.clone()));
    for shard in 0..=u16::MAX {
        ready.mark_shard_ready(shard);
    }

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            db.clone(),
            identity.clone(),
            pm.clone(),
        )
        .with_readiness_manager(ready.clone()),
    );

    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse()?,
        &identity,
        pm.clone(),
        handler,
        cancel.clone(),
    )?;
    server_transport.spawn_accept_loop();
    let server_addr = server_transport.local_addr()?;

    let client_identity = NodeIdentity::generate();
    let client_pm = Arc::new(humoco_node::network::PeerManager::new(Vec::new()));
    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse()?,
        &client_identity,
        client_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )?;

    pm.register_f2f_friend(
        *client_identity.node_pubkey(),
        Some(client_transport.local_addr()?),
    )
    .await;
    client_pm
        .register_f2f_friend(*identity.node_pubkey(), Some(server_addr))
        .await;

    let key = SigningKey::from_bytes(&[31; 32]);
    let at = now();
    let mut req = root(&key, at);
    req.privacy_guard = Some("x".repeat(17_000));
    sign(&key, &mut req);

    let root_valid_until = at + 600_000;
    let sender_pubkey = *client_identity.node_pubkey();
    let op_hash = req.transaction_hash;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        0,
        at,
        0,
        0,
        footprint,
        false,
        &op_hash,
    );
    let sender_signature = client_identity.signing_key().sign(&digest).to_bytes();

    let wire_payload = humoco_node::network::framing::LockWirePayload::Hmc {
        req: req.clone(),
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
        sender_signature,
        timestamp_ms: at,
    };
    let payload_bytes = bincode::serialize(&wire_payload)?;
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        payload_bytes.len() as u32,
    );

    let conn = client_transport.connect_peer(server_addr).await?;
    let (resp_header, resp_payload) = client_transport
        .send_request(&conn, &header, &payload_bytes)
        .await?;

    let is_rejected = resp_header.flags != 0
        || serde_json::from_slice::<L2Verdict>(&resp_payload)
            .map(|v| matches!(v, L2Verdict::Rejected { .. }))
            .unwrap_or(true);
    assert!(is_rejected, "oversize root over QUIC must be rejected");
    assert!(
        db.voucher_root(&req.layer2_voucher_id)?.is_none(),
        "db must not store oversize root"
    );
    assert!(
        engine
            .hmc_ram
            .read()
            .await
            .get_voucher_genesis_parent(&req.layer2_voucher_id)
            .is_none(),
        "RAM must not anchor oversize root"
    );

    cancel.cancel();
    worker.await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding F2: Sidecar root_valid_until_ms validation on spends
// ---------------------------------------------------------------------------

#[tokio::test]
async fn spend_with_mismatched_sidecar_ttl_rejected_and_matching_stages_cleanly(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("node.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let app = app(db.clone(), engine.clone());
    let key = SigningKey::from_bytes(&[8; 32]);
    let at = now();
    let root = root(&key, at);
    assert_eq!(submit(app.clone(), &root).await, StatusCode::CREATED);

    // 1. Shorter TTL: root_valid_until_ms = root_ttl - 540_000 (= at + 60_000)
    let mut spend_short = root.clone();
    spend_short.is_genesis = false;
    spend_short.transaction_hash = [3; 32];
    spend_short.ds_tag = Some("spend-short-parent".into());
    spend_short.deletable_at = None;
    let proof_short = spend_short.causal_output.as_mut().unwrap();
    proof_short.is_root = false;
    proof_short.transaction_id = spend_short.transaction_hash;
    proof_short.root_valid_until_ms = at + 600_000 - 540_000;
    proof_short.signature = key.sign(&proof_short.digest().unwrap()).to_bytes();
    sign(&key, &mut spend_short);

    let status_short = submit(app.clone(), &spend_short).await;
    assert_ne!(
        status_short,
        StatusCode::CREATED,
        "shorter TTL spend must be rejected"
    );
    assert!(db.get_hmc_lock("spend-short-parent")?.is_none());
    assert!(db.confirmation_support("spend-short-parent")?.is_none());
    assert!(engine
        .get_hmc_ram_lock("spend-short-parent")
        .await
        .is_none());

    // 2. Longer TTL: root_valid_until_ms = root_ttl + 60_000 (= at + 660_000)
    let mut spend_long = root.clone();
    spend_long.is_genesis = false;
    spend_long.transaction_hash = [4; 32];
    spend_long.ds_tag = Some("spend-long-parent".into());
    spend_long.deletable_at = None;
    let proof_long = spend_long.causal_output.as_mut().unwrap();
    proof_long.is_root = false;
    proof_long.transaction_id = spend_long.transaction_hash;
    proof_long.root_valid_until_ms = at + 600_000 + 60_000;
    proof_long.signature = key.sign(&proof_long.digest().unwrap()).to_bytes();
    sign(&key, &mut spend_long);

    let status_long = submit(app.clone(), &spend_long).await;
    assert_ne!(
        status_long,
        StatusCode::CREATED,
        "longer TTL spend must be rejected"
    );
    assert!(db.get_hmc_lock("spend-long-parent")?.is_none());
    assert!(db.confirmation_support("spend-long-parent")?.is_none());
    assert!(engine.get_hmc_ram_lock("spend-long-parent").await.is_none());

    // 3. Exact matching TTL: root_valid_until_ms = at + 600_000
    let mut spend_match = root.clone();
    spend_match.is_genesis = false;
    spend_match.transaction_hash = [5; 32];
    spend_match.ds_tag = Some("spend-match-parent".into());
    spend_match.deletable_at = None;
    let proof_match = spend_match.causal_output.as_mut().unwrap();
    proof_match.is_root = false;
    proof_match.transaction_id = spend_match.transaction_hash;
    proof_match.root_valid_until_ms = at + 600_000;
    proof_match.signature = key.sign(&proof_match.digest().unwrap()).to_bytes();
    sign(&key, &mut spend_match);

    let status_match = submit(app.clone(), &spend_match).await;
    assert_eq!(
        status_match,
        StatusCode::CREATED,
        "matching TTL spend must succeed"
    );
    assert!(db.get_hmc_lock("spend-match-parent")?.is_some());
    assert!(db.confirmation_support("spend-match-parent")?.is_some());
    assert!(engine
        .get_hmc_ram_lock("spend-match-parent")
        .await
        .is_some());

    // Snapshots via SnapshotCuts
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    let shard = canonical_voucher_shard(&genesis_parent_bytes_from_tag(&root_tag));
    let mut query = ActiveSyncRequest::new(0, 500);
    query.target_shard = Some(shard);
    let cuts_page = SnapshotCuts::default().page(&db, query, [0; 32]);
    assert!(
        cuts_page.is_ok(),
        "snapshot of matching spend must succeed: {:?}",
        cuts_page.err()
    );

    // Stages cleanly via ShardStage::append
    let stage = ShardStage::new(shard, at)?;
    stage.append(SyncPayload {
        locks: vec![],
        hmc_locks: vec![(root_tag, L2LockEntry::from(&root))],
        support: vec![],
    })?;
    stage.append(SyncPayload {
        locks: vec![],
        hmc_locks: vec![("spend-match-parent".into(), L2LockEntry::from(&spend_match))],
        support: vec![],
    })?;

    // Recovers via recover_from_disk unchanged
    let (tx, _rx) = mpsc::channel(16);
    let recovery_engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(RamIndex::new())),
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    recovery_engine.recover_from_disk(SimTime(at)).await?;
    let recovered_entry = recovery_engine.get_hmc_ram_lock("spend-match-parent").await;
    assert!(
        recovered_entry.is_some(),
        "recovered entry must exist in RAM"
    );
    assert_eq!(recovered_entry.unwrap().t_id, spend_match.transaction_hash);

    cancel.cancel();
    worker.await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding F3: Support commit cancellation fail-closed latching & fault injection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelled_support_commit_latches_fail_closed_and_blocks_displacement(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("support.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let key = SigningKey::from_bytes(&[25; 32]);
    let at = now();
    let root = root(&key, at);
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&root),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;

    let mut spend = root.clone();
    spend.is_genesis = false;
    spend.ds_tag = Some("support-parent".into());
    spend.transaction_hash = [26; 32];
    spend.deletable_at = None;
    spend.causal_output = None;
    sign(&key, &mut spend);
    let entry = L2LockEntry::from(&spend);
    engine
        .ingress_hmc_lock_durable(
            "support-parent".into(),
            entry.clone(),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;

    let parent = *blake3::hash(b"support-parent").as_bytes();
    let shard = canonical_voucher_shard(&genesis_parent_bytes_from_tag(&root_tag));
    let identity = NodeIdentity::generate();
    let att = create_attestation_for_network(
        &identity,
        entry.t_id,
        parent,
        shard,
        0,
        at,
        NetworkId::Mainnet,
    );
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(entry.t_id),
        shard_id: shard,
        status: 0,
        active_nodes_count: 1,
        signer_count: 1,
        signatures: vec![att],
        signer_bitmap: 1,
    };

    let mut support = Box::pin(engine.persist_confirmation_support(
        "support-parent".into(),
        cert,
        &identity,
        at,
        NetworkId::Mainnet,
        None,
    ));
    assert!(support
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());

    let guard = engine.hmc_ram.write().await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while db.confirmation_support("support-parent")?.is_none() {
            tokio::task::yield_now().await;
        }
        Ok::<_, humoco_node::storage::StorageError>(())
    })
    .await??;

    drop(support);
    drop(guard);

    assert!(
        !engine.is_signing_healthy(),
        "cancelled support commit must latch signing unhealthy (fail-closed)"
    );

    let old_hash = humoco_node::storage::engine::compute_hmc_canonical_hash(
        &parent,
        &entry.sender_ephemeral_pub,
        &entry.t_id,
    );
    let mut loser = spend.clone();
    let other_key = SigningKey::from_bytes(&[27; 32]);
    loser.sender_ephemeral_pub = other_key.verifying_key().to_bytes();
    let mut found = false;
    for i in 0u32..1000 {
        loser.transaction_hash[..4].copy_from_slice(&i.to_le_bytes());
        if humoco_node::storage::engine::compute_hmc_canonical_hash(
            &parent,
            &loser.sender_ephemeral_pub,
            &loser.transaction_hash,
        ) < old_hash
        {
            found = true;
            break;
        }
    }
    assert!(found);
    sign(&other_key, &mut loser);

    let (verdict, _) = engine
        .ingress_hmc_lock_durable(
            "support-parent".into(),
            L2LockEntry::from(&loser),
            IngressOrigin::PartitionSync,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(
        matches!(verdict, L2Verdict::Rejected { .. }),
        "competitor must be rejected when signing is unhealthy: {:?}",
        verdict
    );
    assert_eq!(
        db.get_hmc_lock("support-parent")?
            .ok_or("missing row")?
            .t_id,
        entry.t_id
    );
    assert_eq!(
        engine
            .get_hmc_ram_lock("support-parent")
            .await
            .ok_or("missing ram")?
            .t_id,
        entry.t_id
    );

    cancel.cancel();
    worker.await?;
    Ok(())
}

#[tokio::test]
async fn failed_support_commit_io_latches_signing_unavailable(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let backend = FaultBackend {
        inner: Arc::new(redb::backends::InMemoryBackend::new()),
        fail_sync: Arc::new(AtomicBool::new(false)),
    };
    let db = Arc::new(RedbStorage::open_with_backend(
        backend.clone(),
        &dir.path().join("fault.redb"),
    )?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let key = SigningKey::from_bytes(&[28; 32]);
    let at = now();
    let root = root(&key, at);
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&root),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;

    let mut spend = root.clone();
    spend.is_genesis = false;
    spend.ds_tag = Some("fault-parent".into());
    spend.transaction_hash = [29; 32];
    spend.deletable_at = None;
    spend.causal_output = None;
    sign(&key, &mut spend);
    let entry = L2LockEntry::from(&spend);
    engine
        .ingress_hmc_lock_durable(
            "fault-parent".into(),
            entry.clone(),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;

    let parent = *blake3::hash(b"fault-parent").as_bytes();
    let shard = canonical_voucher_shard(&genesis_parent_bytes_from_tag(&root_tag));
    let identity = NodeIdentity::generate();
    let att = create_attestation_for_network(
        &identity,
        entry.t_id,
        parent,
        shard,
        0,
        at,
        NetworkId::Mainnet,
    );
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(entry.t_id),
        shard_id: shard,
        status: 0,
        active_nodes_count: 1,
        signer_count: 1,
        signatures: vec![att],
        signer_bitmap: 1,
    };

    backend.fail_sync.store(true, Ordering::SeqCst);
    let res = engine
        .persist_confirmation_support(
            "fault-parent".into(),
            cert,
            &identity,
            at,
            NetworkId::Mainnet,
            None,
        )
        .await;
    assert!(
        res.is_err(),
        "sync fault must cause persist_confirmation_support to return Err"
    );
    assert!(
        !engine.is_signing_healthy(),
        "failed support commit I/O must latch signing unavailable"
    );

    cancel.cancel();
    worker.await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding F4: Status endpoint durability and health gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signed_http_status_rejects_uncommitted_spend_until_durable_and_checks_health(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("status.redb"))?);
    let key = SigningKey::from_bytes(&[22; 32]);
    let at = now();
    let root = root(&key, at);
    let tag = bs58::encode(root.transaction_hash).into_string();
    db.put_hmc_lock(&tag, &L2LockEntry::from(&root))?;

    // 1. Ingress spend with paused flush worker (dropped future before durable commit)
    let (tx, _rx) = mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(RamIndex::new())),
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    engine.recover_from_disk(SimTime(at)).await?;

    let mut spend = root.clone();
    spend.is_genesis = false;
    spend.ds_tag = Some("pending-parent".into());
    spend.transaction_hash = [23; 32];
    spend.deletable_at = None;
    spend.causal_output = None;
    sign(&key, &mut spend);

    let mut ingress = Box::pin(engine.ingress_hmc_lock_durable(
        "pending-parent".into(),
        L2LockEntry::from(&spend),
        IngressOrigin::ClientApi,
        Some(at),
        None,
        None,
        None,
    ));
    assert!(matches!(
        ingress
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(ingress);
    assert!(db.get_hmc_lock("pending-parent")?.is_none());

    let router1 = app(db.clone(), engine.clone());
    let query = L2StatusQuery {
        auth: root.auth.clone(),
        layer2_voucher_id: root.layer2_voucher_id.clone(),
        challenge_ds_tag: "pending-parent".into(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };

    let response = router1
        .clone()
        .oneshot(
            Request::post("/v1/status")
                .header("content-type", "application/json")
                .header("x-peer-token", "f2f_0123456789abcdef0123456789abcdef")
                .body(Body::from(serde_json::to_vec(&query)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await?
        .to_bytes();
    let envelope: L2ResponseEnvelope = serde_json::from_slice(&bytes)?;
    assert!(
        matches!(
            envelope.verdict,
            L2Verdict::Rejected { .. } | L2Verdict::MissingLocks { .. } | L2Verdict::UnknownVoucher
        ),
        "uncommitted spend must not be verified, got: {:?}",
        envelope.verdict
    );
    assert!(!matches!(envelope.verdict, L2Verdict::Verified { .. }));
    assert!(db.get_hmc_lock("pending-parent")?.is_none());

    // 2. Durably committed spend returns Verified
    let dir2 = tempfile::tempdir()?;
    let db2 = Arc::new(RedbStorage::open(&dir2.path().join("status2.redb"))?);
    let cancel2 = CancellationToken::new();
    let (engine2, worker2) = DualTierEngine::new_with_token(db2.clone(), cancel2.clone());
    let (v_root, _) = engine2
        .ingress_hmc_lock_durable(
            tag.clone(),
            L2LockEntry::from(&root),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    let mut spend2 = root.clone();
    spend2.is_genesis = false;
    spend2.ds_tag = Some("committed-parent".into());
    spend2.transaction_hash = [24; 32];
    spend2.deletable_at = None;
    spend2.causal_output = None;
    sign(&key, &mut spend2);

    let (v_spend, is_new) = engine2
        .ingress_hmc_lock_durable(
            "committed-parent".into(),
            L2LockEntry::from(&spend2),
            IngressOrigin::ClientApi,
            Some(at),
            None,
            None,
            None,
        )
        .await;
    assert!(is_new);
    assert!(matches!(v_spend, L2Verdict::Verified { .. }));
    assert!(db2.get_hmc_lock("committed-parent")?.is_some());

    let app2 = app(db2.clone(), engine2.clone());
    let query2 = L2StatusQuery {
        auth: root.auth.clone(),
        layer2_voucher_id: root.layer2_voucher_id.clone(),
        challenge_ds_tag: "committed-parent".into(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };
    let response2 = app2
        .clone()
        .oneshot(
            Request::post("/v1/status")
                .header("content-type", "application/json")
                .header("x-peer-token", "f2f_0123456789abcdef0123456789abcdef")
                .body(Body::from(serde_json::to_vec(&query2)?))?,
        )
        .await?;
    assert_eq!(response2.status(), StatusCode::OK);
    let bytes2 = http_body_util::BodyExt::collect(response2.into_body())
        .await?
        .to_bytes();
    let envelope2: L2ResponseEnvelope = serde_json::from_slice(&bytes2)?;
    assert!(
        matches!(envelope2.verdict, L2Verdict::Verified { .. }),
        "durably committed spend must return Verified: {:?}",
        envelope2.verdict
    );

    // 3. When signing_failed is latched: returns 503 SERVICE_UNAVAILABLE + Rejected
    engine2.stats.signing_failed.store(true, Ordering::SeqCst);
    let response3 = app2
        .oneshot(
            Request::post("/v1/status")
                .header("content-type", "application/json")
                .header("x-peer-token", "f2f_0123456789abcdef0123456789abcdef")
                .body(Body::from(serde_json::to_vec(&query2)?))?,
        )
        .await?;
    assert_eq!(response3.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes3 = http_body_util::BodyExt::collect(response3.into_body())
        .await?
        .to_bytes();
    let envelope3: L2ResponseEnvelope = serde_json::from_slice(&bytes3)?;
    assert!(matches!(envelope3.verdict, L2Verdict::Rejected { .. }));

    cancel2.cancel();
    worker2.await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding F5: Native idempotent replay preserves final status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn native_idempotent_replay_preserves_final_status_on_disk_and_recovery(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("native.redb"))?);
    let (tx, mut rx) = mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(RamIndex::new())),
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    let at = SimTime(1000);
    let root = SimTime(100_000);
    let mut record = LockRecord::new([10; 32], [11; 32], vec![12], at, root);
    record.status = LockStatus::Final { sigs: 14 };
    assert!(engine.ingress_lock(record.clone(), at, root).await.is_ok());

    let mut batch = vec![rx.recv().await.ok_or("missing op")?];
    assert!(!DualTierEngine::flush_batch(&mut batch, &db).failed);

    // Replay with Pending status
    let mut replay = record.clone();
    replay.status = LockStatus::Pending;
    assert!(engine.ingress_lock(replay, at, root).await.is_ok());

    // Assert no new FlushOp::PutLock emitted
    assert!(
        rx.try_recv().is_err(),
        "no FlushOp emitted on Pending replay of Final record"
    );

    // RAM retains Final
    let ram_rec = engine
        .get_ram_lock(&record.parent_lock)
        .await
        .ok_or("missing RAM row")?;
    assert_eq!(ram_rec.status, LockStatus::Final { sigs: 14 });

    // Disk retains Final
    let disk_rec = db
        .get_lock(&record.parent_lock)?
        .ok_or("missing disk row")?;
    assert_eq!(disk_rec.0.status, LockStatus::Final { sigs: 14 });

    // Fresh DualTierEngine retains Final after recover_from_disk
    let (tx2, _rx2) = mpsc::channel(16);
    let recovery_engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(RamIndex::new())),
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx2,
    );
    recovery_engine.recover_from_disk(at).await?;
    let recovered_ram_rec = recovery_engine
        .get_ram_lock(&record.parent_lock)
        .await
        .ok_or("missing recovered RAM row")?;
    assert_eq!(recovered_ram_rec.status, LockStatus::Final { sigs: 14 });

    Ok(())
}
