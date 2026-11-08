//! Wallet/node purpose separation and inspection of existing active Root Anchors.
#![forbid(unsafe_code)]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use humoco_node::{
    api::{
        build_router,
        dto::QuorumCertificateDto,
        hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2ChainLockRequest, L2LockEntry,
            L2LockRequest, L2Verdict,
        },
        routes::{build_operator_router, create_attestation_for_network},
        AppState,
    },
    daemon::ShardReadinessManager,
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{framing::LockWirePayload, NodeRequestHandler, PeerManager, QuicTransport},
    storage::{
        db::install::ShardStage, db::TABLE_HMC_LOCKS, DualTierEngine, IngressOrigin, RedbStorage,
        StorageError, TABLE_OWN_CHOICES, TABLE_OWN_CHOICE_COMMITMENTS,
    },
};
use humoco_proto::causal::CausalOutputProof;
use humoco_sim_core::{
    types::{canonical_voucher_shard, genesis_parent_bytes_from_tag, NetworkId, SimTime},
    wire::{MsgType, WireHeader, FLAG_COLLISION_DETECTED, FLAG_PEER_SUSPENDED},
};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::{error::Error, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[path = "common/recovery.rs"]
mod recovery;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn root_with_ttl(key: &SigningKey, seed: u8, now: u64, ttl_ms: u64) -> TestResult<L2LockRequest> {
    let sender = key.verifying_key().to_bytes();
    let transaction = [seed; 32];
    let expiry = now
        .checked_add(ttl_ms)
        .ok_or("expiry overflow")?
        .to_string();
    let receiver: [u8; 32] = Sha3_256::digest(sender).into();
    let mut hash = Sha256::new();
    hash.update(transaction);
    hash.update(sender);
    hash.update(receiver);
    hash.update(expiry.as_bytes());
    let voucher = hex::encode(hash.finalize());
    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: voucher.clone(),
        transaction_id: transaction,
        state_hash: transaction,
        sender_pubkey: sender,
        receiver_pubkey_hash: Some(receiver),
        change_pubkey_hash: None,
        root_valid_until_ms: expiry.parse()?,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key
        .sign(&proof.digest().map_err(std::io::Error::other)?)
        .to_bytes();
    let mut req = L2LockRequest {
        causal_output: Some(proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender,
            auth_signature: None,
        },
        layer2_voucher_id: voucher,
        ds_tag: None,
        transaction_hash: transaction,
        is_genesis: true,
        sender_ephemeral_pub: sender,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: u128::from(now),
        created_at_ms: now,
        deletable_at: Some(expiry),
        privacy_guard: None,
    };
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(&req)).to_bytes();
    Ok(req)
}

fn root(key: &SigningKey, seed: u8, now: u64) -> TestResult<L2LockRequest> {
    root_with_ttl(key, seed, now, 600_000)
}

fn spend(root: &L2LockRequest, seed: u8, key: &SigningKey) -> TestResult<L2LockRequest> {
    let mut req = root.clone();
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update(root.transaction_hash);
    hash.update(32u32.to_le_bytes());
    hash.update(key.verifying_key().as_bytes());
    req.ds_tag = Some(bs58::encode(hash.finalize()).into_string());
    req.transaction_hash = [seed; 32];
    req.is_genesis = false;
    req.deletable_at = None;
    let proof = req.causal_output.as_mut().ok_or("root proof missing")?;
    proof.transaction_id = req.transaction_hash;
    proof.state_hash = req.transaction_hash;
    proof.is_root = false;
    proof.signature = key
        .sign(&proof.digest().map_err(std::io::Error::other)?)
        .to_bytes();
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(&req)).to_bytes();
    Ok(req)
}

fn shard(root: &L2LockRequest) -> u16 {
    humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(
            &bs58::encode(root.transaction_hash).into_string(),
        ),
    )
}

async fn anchor(engine: &DualTierEngine, root: &L2LockRequest) -> TestResult {
    let (verdict, _) = engine
        .ingress_hmc_lock_durable(
            bs58::encode(root.transaction_hash).into_string(),
            root.into(),
            IngressOrigin::ClientApi,
            Some(root.created_at_ms),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }), "{verdict:?}");
    Ok(())
}

fn app_state(engine: DualTierEngine, db: Arc<RedbStorage>, identity: NodeIdentity) -> AppState {
    let pow = Arc::new(PowEngine::new(8));
    let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));
    tiers.register_f2f_peer("s02-client");
    AppState::new(engine, db, identity, tiers, pow)
}

async fn get_json(app: &axum::Router, path: &str) -> TestResult<(StatusCode, serde_json::Value)> {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty())?)
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}

#[tokio::test]
async fn root_inspector_uses_retained_anchor_before_after_spend_and_recovery() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("roots.redb");
    let identity = NodeIdentity::generate();
    let key = SigningKey::from_bytes(&[52; 32]);
    let now = now_ms()?;
    let root = root(&key, 1, now)?;
    let spend = spend(&root, 2, &key)?;
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    for phase in 0..4 {
        let db = Arc::new(RedbStorage::open(&path)?);
        let cancel = CancellationToken::new();
        let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
        if phase == 0 {
            anchor(&engine, &root).await?;
        } else {
            // The diagnostic lookup also works from committed root metadata
            // before RAM recovery; roots never lived in the spend tables.
            let detail = engine
                .get_voucher_lineage(&root.layer2_voucher_id)
                .await
                .ok_or("committed root detail missing")?;
            assert_eq!(detail.genesis_tag.as_deref(), Some(root_tag.as_str()));
            let list = engine.get_all_active_vouchers().await;
            assert_eq!(list[0].genesis_tag.as_deref(), Some(root_tag.as_str()));
            engine.recover_from_disk(SimTime(now)).await?;
        }
        if phase == 2 {
            let (verdict, _) = engine
                .ingress_hmc_lock_durable(
                    spend.ds_tag.clone().ok_or("spend tag missing")?,
                    (&spend).into(),
                    IngressOrigin::ClientApi,
                    Some(now),
                    None,
                    None,
                    None,
                )
                .await;
            assert!(matches!(verdict, L2Verdict::Verified { .. }));
        }
        let expected_spends = usize::from(phase >= 2);
        let state = app_state(engine.clone(), db.clone(), identity.clone());
        let app = build_operator_router(state);
        let (status, list) = get_json(&app, "/dashboard/vouchers").await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list[0]["genesis_tag"], root_tag);
        let (status, detail) = get_json(
            &app,
            &format!("/dashboard/voucher/{}", root.layer2_voucher_id),
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a listed Root Anchor must be inspectable (phase {phase})"
        );
        assert_eq!(detail["genesis_tag"], root_tag);
        assert_eq!(detail["created_at_ms"], now);
        assert_eq!(detail["root_valid_until_ms"], now + 600_000);
        assert_eq!(
            detail["locks"].as_array().ok_or("missing locks")?.len(),
            expected_spends
        );
        assert!(
            engine.get_hmc_ram_lock(&root_tag).await.is_none(),
            "inspection must not insert roots as collision locks"
        );
        assert_eq!(
            get_json(&app, "/dashboard/voucher/unknown").await?.0,
            StatusCode::NOT_FOUND
        );
        drop(app);
        if phase == 3 {
            engine.prune_expired(SimTime(now + 631_000)).await?;
            assert!(engine
                .get_voucher_lineage(&root.layer2_voucher_id)
                .await
                .is_none());
            assert!(db.voucher_root(&root.layer2_voucher_id)?.is_none());
        }
        cancel.cancel();
        worker.await?;
    }
    Ok(())
}

#[tokio::test]
async fn disk_lookup_tag_inspection_includes_newer_ram_spends() -> TestResult {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("overlay.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let key = SigningKey::from_bytes(&[53; 32]);
    let root = root(&key, 20, now_ms()?)?;
    anchor(&engine, &root).await?;
    let first = spend(&root, 21, &key)?;
    let second = spend(&first, 22, &key)?;
    let first_tag = first.ds_tag.as_ref().ok_or("first tag missing")?;
    db.put_hmc_lock(first_tag, &(&first).into())?;
    engine.hmc_ram.write().await.insert_recovered(
        second.ds_tag.clone().ok_or("second tag missing")?,
        (&second).into(),
    );
    assert!(engine.get_hmc_ram_lock(first_tag).await.is_none());
    let detail = engine
        .get_voucher_lineage(first_tag)
        .await
        .ok_or("disk-known tag must resolve its voucher")?;
    assert_eq!(detail.voucher_id, root.layer2_voucher_id);
    assert_eq!(
        detail.genesis_tag,
        Some(bs58::encode(root.transaction_hash).into_string())
    );
    assert_eq!(
        detail.locks.len(),
        2,
        "the resolved voucher must include its newer RAM spend"
    );
    assert!(detail
        .locks
        .iter()
        .any(|hop| hop.t_id_hex == hex::encode(second.transaction_hash)));
    cancel.cancel();
    worker.await?;
    Ok(())
}

#[tokio::test]
async fn public_wallet_remains_admissible_when_its_key_is_in_node_ban_registry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("public.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let identity = NodeIdentity::generate();
    let wallet = NodeIdentity::generate();
    let now = now_ms()?;
    let root = root(wallet.signing_key(), 7, now)?;
    let spend = spend(&root, 8, wallet.signing_key())?;
    let state = app_state(engine.clone(), db, identity);
    state.readiness_manager.mark_shard_ready(shard(&root));
    let app = build_router(state);
    engine.ban_node(*wallet.node_pubkey(), now).await;
    for (path, body) in [
        ("/v1/lock", serde_json::to_vec(&root)?),
        ("/v1/lock", serde_json::to_vec(&spend)?),
        (
            "/v1/lock/chain",
            serde_json::to_vec(&L2ChainLockRequest {
                auth: spend.auth.clone(),
                layer2_voucher_id: root.layer2_voucher_id.clone(),
                chain: vec![spend.clone()],
            })?,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-peer-token", "s02-client")
                    .body(Body::from(body))?,
            )
            .await?;
        assert!(
            response.status().is_success(),
            "node bans must not deny public wallet requests: {}",
            response.status()
        );
    }
    drop(app);
    cancel.cancel();
    worker.await?;
    Ok(())
}

struct WireNode {
    identity: NodeIdentity,
    engine: DualTierEngine,
    db: Arc<RedbStorage>,
    manager: Arc<PeerManager>,
    network: QuicTransport,
    ready: Arc<ShardReadinessManager>,
    cancel: CancellationToken,
    worker: tokio::task::JoinHandle<()>,
}

impl WireNode {
    async fn start(path: &Path, identity: NodeIdentity) -> TestResult<Self> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let db = loop {
            match RedbStorage::open(path) {
                Ok(db) => break Arc::new(db),
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => return Err(error.into()),
            }
        };
        let cancel = CancellationToken::new();
        let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
        let manager = Arc::new(PeerManager::new(vec![]));
        manager.set_simulation_mode(true);
        engine.set_peer_manager(manager.clone()).await;
        let ready = Arc::new(ShardReadinessManager::new());
        let handler = NodeRequestHandler::with_peer_manager(
            engine.clone(),
            db.clone(),
            identity.clone(),
            manager.clone(),
        )
        .with_readiness_manager(ready.clone());
        let network = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse()?,
            &identity,
            manager.clone(),
            Arc::new(handler),
            cancel.clone(),
        )?;
        network.spawn_accept_loop();
        // Committee eligibility and installed shard state are explicit premises;
        // this test exercises transport purpose separation, not ticket incubation.
        manager
            .learn_node_from_gossip_with_hrw(
                *identity.node_pubkey(),
                *identity.hrw_routing_id(),
                network.local_addr()?,
                0,
                None,
            )
            .await;
        manager
            .set_first_seen_for_test(
                identity.node_pubkey(),
                std::time::Instant::now() - Duration::from_secs(25 * 3600),
            )
            .await;
        Ok(Self {
            identity,
            engine,
            db,
            manager,
            network,
            ready,
            cancel,
            worker,
        })
    }

    async fn stop(self) -> TestResult {
        self.cancel.cancel();
        self.network.close();
        self.worker.await?;
        Ok(())
    }
}

async fn connect_friends(
    source: &WireNode,
    target: &WireNode,
) -> TestResult<humoco_node::network::pool::PeerConnectionLease> {
    source
        .manager
        .register_f2f_friend(
            *target.identity.node_pubkey(),
            Some(target.network.local_addr()?),
        )
        .await;
    target
        .manager
        .register_f2f_friend(
            *source.identity.node_pubkey(),
            Some(source.network.local_addr()?),
        )
        .await;
    Ok(source
        .network
        .connect_peer(target.network.local_addr()?)
        .await?)
}

async fn send_spend(
    source: &WireNode,
    connection: &quinn::Connection,
    req: &L2LockRequest,
    seq: u64,
    chain: bool,
) -> TestResult<(WireHeader, Vec<u8>)> {
    let now = source.manager.net_time_ms();
    let expiry = req
        .causal_output
        .as_ref()
        .ok_or("missing output proof")?
        .root_valid_until_ms;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(
        expiry.saturating_sub(now) / 1000,
    );
    let sender = *source.identity.node_pubkey();
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender,
        0,
        seq,
        now,
        0,
        0,
        footprint,
        false,
        &req.transaction_hash,
    );
    let wire = LockWirePayload::Hmc {
        req: req.clone(),
        chain: chain.then(|| L2ChainLockRequest {
            auth: req.auth.clone(),
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            chain: vec![req.clone()],
        }),
        root_valid_until: expiry,
        epoch_day: 0,
        epoch_seq: seq,
        cumulative_micro_byte_years: footprint.saturating_mul(seq),
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: sender,
        sender_signature: source.identity.signing_key().sign(&digest).to_bytes(),
        timestamp_ms: now,
    };
    let bytes = bincode::serialize(&wire)?;
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        seq,
        0,
        0,
        u32::try_from(bytes.len())?,
    );
    Ok(source
        .network
        .send_request(connection, &header, &bytes)
        .await?)
}

#[tokio::test]
async fn real_quic_wallet_conflict_preserves_node_identity_and_restart() -> TestResult {
    let dir = tempfile::tempdir()?;
    let source_path = dir.path().join("source.redb");
    let target_path = dir.path().join("target.redb");
    let source_id = NodeIdentity::generate();
    let target_id = NodeIdentity::generate();
    let wallet_node = NodeIdentity::generate();
    let now = now_ms()?;
    let root = root(wallet_node.signing_key(), 10, now)?;
    let first = spend(&root, 11, wallet_node.signing_key())?;
    let conflict = spend(&root, 12, wallet_node.signing_key())?;
    for restart in [false, true] {
        let source = WireNode::start(&source_path, source_id.clone()).await?;
        let target = WireNode::start(&target_path, target_id.clone()).await?;
        target
            .manager
            .register_f2f_friend(*wallet_node.node_pubkey(), None)
            .await;
        if restart {
            target.engine.recover_from_disk(SimTime(now)).await?;
        } else {
            anchor(&target.engine, &root).await?;
        }
        target.ready.mark_shard_ready(shard(&root));
        let connection = connect_friends(&source, &target).await?;
        let (reply, bytes) = send_spend(&source, &connection, &first, 1, false).await?;
        assert_eq!(reply.flags, if restart { humoco_sim_core::wire::FLAG_REPLAY } else { 0 });
        assert!(humoco_node::api::dto::AttestationDto::from_wire_bytes(&bytes).is_some());
        let (reply, bytes) = send_spend(&source, &connection, &conflict, 2, false).await?;
        assert_eq!(reply.flags, FLAG_COLLISION_DETECTED);
        assert_eq!(
            bincode::deserialize::<L2LockEntry>(&bytes)?.t_id,
            first.transaction_hash
        );
        assert!(
            !target
                .engine
                .is_node_banned(wallet_node.node_pubkey())
                .await
        );
        assert!(!target.manager.is_banned(wallet_node.node_pubkey()).await);
        assert!(
            target
                .manager
                .is_f2f_friend(wallet_node.node_pubkey())
                .await
        );
        assert!(!target.db.is_node_banned(wallet_node.node_pubkey())?);
        let wallet_signatures =
            serde_json::to_vec(&(L2LockEntry::from(&first), L2LockEntry::from(&conflict)))?;
        assert!(
            target
                .db
                .get_evidence(blake3::hash(&wallet_signatures).as_bytes())?
                .is_none(),
            "wallet signatures must not enter the permanent node-fraud archive"
        );

        if restart {
            // A real node ban remains scoped to infrastructure, even for the same key.
            target
                .engine
                .ban_node(*wallet_node.node_pubkey(), now)
                .await;
            for (seq, chain) in [(3, false), (4, true)] {
                let (reply, _) = send_spend(&source, &connection, &first, seq, chain).await?;
                assert_eq!(
                    reply.flags, humoco_sim_core::wire::FLAG_REPLAY,
                    "wallet replay via another gateway must remain admissible"
                );
            }
            target
                .engine
                .ban_node(*source.identity.node_pubkey(), now)
                .await;
            let denied = send_spend(&source, &connection, &first, 5, false).await;
            assert!(
                denied.is_err()
                    || denied
                        .as_ref()
                        .is_ok_and(|(header, _)| header.flags == FLAG_PEER_SUSPENDED),
                "a banned authenticated transport node must remain rejected"
            );
        }
        drop(connection);
        source.stop().await?;
        target.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_s02_05_prune_commitment_corruption_fails_closed_without_partial_delete() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("s02_05_a.redb");
    let key = SigningKey::from_bytes(&[81; 32]);
    let root_req = root(&key, 1, 10_000)?;
    let spend_req = spend(&root_req, 2, &key)?;
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;

    let node = [7u8; 32];
    let slot = format!("{}:{}", hex::encode(node), spend_tag);

    {
        let db = RedbStorage::open(&path)?;
        db.put_hmc_lock(&root_tag, &(&root_req).into())?;
        db.commit_original_approval(&spend_tag, &(&spend_req).into(), &node, b"appr", 0, 50_000)?;
        assert!(db.is_signing_history_healthy());

        // Corrupt TABLE_OWN_CHOICE_COMMITMENTS for `slot` without changing table cardinality
        let txn = db.raw_database_for_test().begin_write()?;
        {
            let mut commitments = txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
            commitments.insert(slot.as_str(), &[0xee; 32])?;
        }
        txn.commit()?;

        // Trigger prune_expired_buckets at now_sec = 81 (valid_until_ms = 50_000 -> expires_sec = 81)
        let prune_res = db.prune_expired_buckets(81);
        assert!(
            matches!(prune_res, Err(StorageError::SigningHistoryCorrupt)),
            "prune_expired_buckets must return SigningHistoryCorrupt, got: {prune_res:?}"
        );
        assert!(
            !db.is_signing_history_healthy(),
            "in-memory signing latch must be corrupt immediately"
        );

        // Verify corrupted row is NOT partially deleted (evidence preserved!)
        let read_txn = db.raw_database_for_test().begin_read()?;
        let choices = read_txn.open_table(TABLE_OWN_CHOICES)?;
        assert!(
            choices.get(slot.as_str())?.is_some(),
            "TABLE_OWN_CHOICES row must NOT be partially deleted upon corruption"
        );
        let commitments = read_txn.open_table(TABLE_OWN_CHOICE_COMMITMENTS)?;
        assert!(
            commitments.get(slot.as_str())?.is_some(),
            "TABLE_OWN_CHOICE_COMMITMENTS row must NOT be partially deleted upon corruption"
        );
    }

    // Latch must persist across RedbStorage::open reopen
    let reopened = RedbStorage::open(&path)?;
    assert!(
        !reopened.is_signing_history_healthy(),
        "corruption latch must survive database reopen"
    );

    // Committing another slot must be rejected fail-closed
    let another_res = reopened.commit_original_approval(
        "another-spend",
        &(&spend_req).into(),
        &node,
        b"appr2",
        0,
        50_000,
    );
    assert!(
        matches!(another_res, Err(StorageError::SigningHistoryCorrupt)),
        "committing another slot on corrupt DB must be rejected fail-closed"
    );

    Ok(())
}

#[tokio::test]
async fn test_s02_05_atomic_flush_batch_aborts_on_corruption_and_latches_durably() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("s02_05_b.redb");
    let key = SigningKey::from_bytes(&[82; 32]);
    let root_req = root(&key, 1, 10_000)?;
    let spend_req1 = spend(&root_req, 2, &key)?;
    let spend_req2 = spend(&spend_req1, 3, &key)?;
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    let spend_tag1 = spend_req1.ds_tag.clone().ok_or("missing spend tag 1")?;
    let spend_tag2 = spend_req2.ds_tag.clone().ok_or("missing spend tag 2")?;

    let node = [8u8; 32];
    let slot1 = format!("{}:{}", hex::encode(node), spend_tag1);

    let db = Arc::new(RedbStorage::open(&path)?);
    db.put_hmc_lock(&root_tag, &(&root_req).into())?;
    db.commit_original_approval(&spend_tag1, &(&spend_req1).into(), &node, b"appr1", 0, 50_000)?;
    assert!(db.is_signing_history_healthy());

    // Inject an inconsistent/premature TTL index entry: bucket sec = 1 while choice has valid_until_ms = 50_000 (bucket 81)
    let txn = db.raw_database_for_test().begin_write()?;
    {
        let mut ttl = txn.open_table(humoco_node::storage::db::TABLE_OWN_CHOICE_TTL)?;
        ttl.insert(&(1, slot1.as_str()), ())?;
    }
    txn.commit()?;

    // Attempt to flush a batch containing a new spend lock (spend2) AND prune_now_secs = [1]
    let entry2: L2LockEntry = (&spend_req2).into();
    let entry2_bytes = serde_json::to_vec(&entry2)?;
    let hmc_view = [(&spend_tag2[..], &entry2, &entry2_bytes[..], 600_000u64 + 10_000u64)];
    let res = db.apply_flush_batch_atomic(&hmc_view, &[], &[], &[], &[1]);

    // On unpatched code, prune_own_choices returned Ok(()) on !valid, committing the batch!
    // On patched code, it must return Err(SigningHistoryCorrupt).
    assert!(
        matches!(res, Err(StorageError::SigningHistoryCorrupt)),
        "apply_flush_batch_atomic must return SigningHistoryCorrupt, got: {res:?}"
    );

    // Verify batch write was aborted: new lock spend_tag2 must NOT exist in redb!
    assert!(
        db.get_hmc_lock(&spend_tag2)?.is_none(),
        "aborted flush batch must NOT commit spend_tag2 to redb"
    );

    // Verify corruption latch is persisted across reopen
    drop(db);

    let reopened = RedbStorage::open(&path)?;
    assert!(
        !reopened.is_signing_history_healthy(),
        "signing corruption latch must persist across reopen"
    );

    Ok(())
}

#[tokio::test]
async fn test_s02_06_persist_approval_race_latches_corruption_and_rejects_publication() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("s02_06_race.redb");
    let key = SigningKey::from_bytes(&[83; 32]);
    let root_req = root(&key, 1, 10_000)?;
    let spend_req = spend(&root_req, 2, &key)?;
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;

    let db = Arc::new(RedbStorage::open(&path)?);
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let hmc_ram = Arc::new(tokio::sync::RwLock::new(humoco_node::storage::HmcRamIndex::new()));
    let engine = DualTierEngine::from_parts(hmc_ram, db.clone(), tx);

    // Anchor root and insert spend lock in engine RAM
    let spend_entry: L2LockEntry = (&spend_req).into();
    engine.hmc_ram.write().await.insert_voucher_root_for_test(spend_entry.layer2_voucher_id.clone(), 600_000 + 10_000);
    engine.hmc_ram.write().await.insert_lock_for_test(spend_tag.clone(), spend_entry.clone());

    let node = [9u8; 32];
    let approval = b"original_approval_s02_06".to_vec();

    // Spawn persist_original_approval in a separate task
    let engine_clone = engine.clone();
    let spend_tag_clone = spend_tag.clone();
    let spend_entry_clone = spend_entry.clone();
    let handle = tokio::task::spawn(async move {
        engine_clone
            .persist_original_approval(
                spend_tag_clone,
                spend_entry_clone,
                node,
                approval,
                0,
                10_000,
            )
            .await
    });

    // Controlled persistence channel: receive the FlushOp from persist_original_approval
    let op = rx.recv().await.ok_or("must receive FlushOp")?;
    let complete = match op {
        humoco_node::storage::FlushOp::OriginalHmcApproval { complete, .. } => complete,
        other => return Err(format!("expected OriginalHmcApproval, got: {other:?}").into()),
    };

    // Acquire write_guard on hmc_ram while persist_original_approval is waiting in wait_original_approval
    let write_guard = engine.hmc_ram.write().await;

    // Complete the durable ACK while holding write_guard
    complete.send(Some(Ok(b"committed_bytes".to_vec())))?;

    // Yield so persist_original_approval wakes up from wait_original_approval and
    // is deterministically suspended at `let mut hmc = self.hmc_ram.write().await;`
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    // While write_guard is still held, latch signing corruption!
    engine.db.latch_corruption();
    assert!(!engine.is_signing_healthy());

    // Drop write_guard so persist_original_approval resumes and enters hmc_ram.write()
    drop(write_guard);

    // Await handle: MUST return Err(SigningHistoryCorrupt)!
    let res = handle.await?;
    assert!(
        matches!(res, Err(StorageError::SigningHistoryCorrupt)),
        "persist_original_approval must return Err(SigningHistoryCorrupt) if latched during wait, got: {res:?}"
    );

    // Verify it was NOT marked durable
    let ram = engine.hmc_ram.read().await;
    let root_val = ram.get_voucher_root_valid(&spend_entry.layer2_voucher_id).unwrap_or(0);
    assert!(
        !ram.is_entry_durable(&spend_tag, &spend_entry, root_val),
        "entry must NOT be marked durable when signing corruption occurred"
    );

    Ok(())
}

#[tokio::test]
async fn test_s02_06_real_quic_rollback_checkpoint_suppresses_attestation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let source_path = dir.path().join("s02_06_source.redb");
    let target_path = dir.path().join("s02_06_target.redb");
    let source_id = NodeIdentity::generate();
    let target_id = NodeIdentity::generate();
    let wallet_node = NodeIdentity::generate();
    let now = now_ms()?;
    let root_req = root(wallet_node.signing_key(), 30, now)?;
    let spend_req = spend(&root_req, 31, wallet_node.signing_key())?;

    let source = WireNode::start(&source_path, source_id).await?;
    let target = WireNode::start(&target_path, target_id).await?;
    target
        .manager
        .register_f2f_friend(*wallet_node.node_pubkey(), None)
        .await;
    anchor(&target.engine, &root_req).await?;
    target.ready.mark_shard_ready(shard(&root_req));

    // Latch corruption on target via a verified rollback checkpoint contradiction
    let corrupted = target
        .db
        .observe_verified_own_checkpoint(999, [0xcc; 32])?;
    assert!(corrupted, "observe_verified_own_checkpoint must detect contradiction");
    assert!(!target.engine.is_signing_healthy());

    let connection = connect_friends(&source, &target).await?;
    let (_reply, bytes) = send_spend(&source, &connection, &spend_req, 1, false).await?;

    // Verify NO attestation is released over the real QUIC connection
    let attestation = humoco_node::api::dto::AttestationDto::from_wire_bytes(&bytes);
    assert!(
        attestation.is_none(),
        "No attestation must be released over QUIC when signing history is latched corrupt"
    );

    drop(connection);
    source.stop().await?;
    target.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_s02_07_spend_lock_inherits_root_ttl_ignoring_short_spend_hint() -> TestResult {
    let dir = tempfile::tempdir()?;
    let db = RedbStorage::open(&dir.path().join("s02_07_a.redb"))?;

    let root_entry = L2LockEntry {
        causal_output: None,
        t_id: [0x41; 32],
        layer2_voucher_id: "voucher-s02-07-a".to_string(),
        sender_ephemeral_pub: [0x11; 32],
        layer2_signature: [0x22; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 1000,
        deletable_at: Some("105000".to_string()), // Root-TTL = 105_000
        privacy_guard: None,
    };
    let root_tag = bs58::encode(root_entry.t_id).into_string();
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag);
    let shard = humoco_sim_core::types::canonical_voucher_shard(&parent);
    db.put_hmc_lock(&root_tag, &root_entry)?;

    let spend_entry = L2LockEntry {
        causal_output: None,
        t_id: [0x42; 32],
        layer2_voucher_id: "voucher-s02-07-a".to_string(),
        sender_ephemeral_pub: [0x33; 32],
        layer2_signature: [0x44; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 2000,
        created_at_ms: 2000,
        deletable_at: Some("1".to_string()), // Spend hint = 1 (shorter than root)
        privacy_guard: None,
    };
    let spend_tag = "spend-s02-07-short-hint".to_string();
    db.put_hmc_lock(&spend_tag, &spend_entry)?;

    // At now_ms = 50_000 (valid under Root-TTL 105_000, expired under spend hint 1):
    let active_shard_locks = db.active_hmc_locks_for_shard(shard, 50_000)?;
    assert!(
        active_shard_locks.iter().any(|(tag, _)| tag == &spend_tag),
        "active_hmc_locks_for_shard must include spend lock at now=50000 deriving TTL from root"
    );

    let all_valid = db.all_valid_hmc_locks(50_000)?;
    assert!(
        all_valid.iter().any(|(tag, _)| tag == &spend_tag),
        "all_valid_hmc_locks must include spend lock at now=50000 deriving TTL from root"
    );

    Ok(())
}

#[tokio::test]
async fn test_s02_07_spend_lock_cannot_extend_expired_root_and_orphan_does_not_synthesize_root() -> TestResult {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&dir.path().join("s02_07_b.redb"))?);

    let root_entry = L2LockEntry {
        causal_output: None,
        t_id: [0x51; 32],
        layer2_voucher_id: "voucher-s02-07-b".to_string(),
        sender_ephemeral_pub: [0x11; 32],
        layer2_signature: [0x22; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 100,
        created_at_ms: 100,
        deletable_at: Some("1000".to_string()), // Root-TTL = 1000 (expires at 1000 + 30_000 = 31_000)
        privacy_guard: None,
    };
    let root_tag = bs58::encode(root_entry.t_id).into_string();
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag);
    let shard = humoco_sim_core::types::canonical_voucher_shard(&parent);
    db.put_hmc_lock(&root_tag, &root_entry)?;

    let spend_entry = L2LockEntry {
        causal_output: None,
        t_id: [0x52; 32],
        layer2_voucher_id: "voucher-s02-07-b".to_string(),
        sender_ephemeral_pub: [0x33; 32],
        layer2_signature: [0x44; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 200,
        created_at_ms: 200,
        deletable_at: Some("999999".to_string()), // Spend hint cannot extend root
        privacy_guard: None,
    };
    let spend_tag = "spend-s02-07-extended-hint".to_string();
    db.put_hmc_lock(&spend_tag, &spend_entry)?;

    // Orphan spend with no committed root
    let orphan_entry = L2LockEntry {
        causal_output: None,
        t_id: [0x53; 32],
        layer2_voucher_id: "orphan-voucher-unanchored".to_string(),
        sender_ephemeral_pub: [0x55; 32],
        layer2_signature: [0x66; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 300,
        created_at_ms: 300,
        deletable_at: Some("999999".to_string()),
        privacy_guard: None,
    };
    let orphan_tag = "orphan-spend-tag".to_string();
    let txn = db.raw_database_for_test().begin_write()?;
    {
        let mut locks = txn.open_table(TABLE_HMC_LOCKS)?;
        locks.insert(orphan_tag.as_str(), serde_json::to_vec(&orphan_entry)?.as_slice())?;
    }
    txn.commit()?;

    // At now_ms = 50_000 (past root TTL 1000 + 30s grace = 31000):
    let active_shard_locks = db.active_hmc_locks_for_shard(shard, 50_000)?;
    assert!(
        !active_shard_locks.iter().any(|(tag, _)| tag == &spend_tag),
        "spend hint must not extend expired root lifetime in active_hmc_locks_for_shard"
    );
    assert!(
        !active_shard_locks.iter().any(|(tag, _)| tag == &orphan_tag),
        "orphan spend must not appear in active_hmc_locks_for_shard"
    );

    let all_valid = db.all_valid_hmc_locks(50_000)?;
    assert!(
        !all_valid.iter().any(|(tag, _)| tag == &spend_tag),
        "spend hint must not extend expired root lifetime in all_valid_hmc_locks"
    );
    assert!(
        !all_valid.iter().any(|(tag, _)| tag == &orphan_tag),
        "orphan spend must not synthesize root in all_valid_hmc_locks"
    );

    // Also verify recover_from_disk does not synthesize a root or retain expired/orphan spend
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    engine.recover_from_disk(SimTime(50_000)).await?;
    let ram = engine.hmc_ram.read().await;
    assert!(
        !ram.locks().contains_key(&spend_tag),
        "recover_from_disk must not retain expired spend"
    );
    assert!(
        !ram.locks().contains_key(&orphan_tag),
        "recover_from_disk must not retain orphan spend without root"
    );
    assert!(
        !ram.voucher_roots().contains_key("orphan-voucher-unanchored"),
        "recover_from_disk must not synthesize a root from orphan spend hint"
    );
    cancel.cancel();
    worker.await?;

    Ok(())
}

#[tokio::test]
async fn test_s02_07_real_quic_shard_reconciliation_sees_inherited_ttl_spend() -> TestResult {
    let peers = recovery::recovery_peers(2).await;
    let (reader, source) = (&peers[0], &peers[1]);

    let key = SigningKey::from_bytes(&[85; 32]);
    let sender = key.verifying_key().to_bytes();
    let transaction = [0x61; 32];
    let expiry = "105000".to_string();
    let receiver: [u8; 32] = Sha3_256::digest(sender).into();
    let mut hash = Sha256::new();
    hash.update(transaction);
    hash.update(sender);
    hash.update(receiver);
    hash.update(expiry.as_bytes());
    let voucher = hex::encode(hash.finalize());

    let mut proof = CausalOutputProof {
        version: 1,
        voucher_id: voucher.clone(),
        transaction_id: transaction,
        state_hash: transaction,
        sender_pubkey: sender,
        receiver_pubkey_hash: Some(receiver),
        change_pubkey_hash: None,
        root_valid_until_ms: 105_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key
        .sign(&proof.digest().map_err(std::io::Error::other)?)
        .to_bytes();

    let mut root_req = L2LockRequest {
        causal_output: Some(proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender,
            auth_signature: None,
        },
        layer2_voucher_id: voucher.clone(),
        ds_tag: None,
        transaction_hash: transaction,
        is_genesis: true,
        sender_ephemeral_pub: sender,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 1000,
        created_at_ms: 1000,
        deletable_at: Some(expiry),
        privacy_guard: None,
    };
    root_req.layer2_signature = key.sign(&calculate_l2_payload_hash(&root_req)).to_bytes();

    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag);
    let shard = humoco_sim_core::types::canonical_voucher_shard(&parent);
    source.db.put_hmc_lock(&root_tag, &(&root_req).into())?;

    let mut spend_req = spend(&root_req, 0x62, &key)?;
    spend_req.deletable_at = Some("1".to_string()); // Spend hint = 1
    spend_req.layer2_signature = key.sign(&calculate_l2_payload_hash(&spend_req)).to_bytes();
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;
    source.db.put_hmc_lock(&spend_tag, &(&spend_req).into())?;

    // In unpatched code, source's active_hmc_locks_for_shard at 50_000 dropped the spend lock!
    let source_active = source.db.active_hmc_locks_for_shard(shard, 50_000)?;
    assert!(
        source_active.iter().any(|(t, _)| t == &spend_tag),
        "Source active_hmc_locks_for_shard must include spend lock deriving TTL from root"
    );

    // Connect reader to source over real QUIC
    let conn = reader
        .network
        .connect_peer(source.network.local_addr()?)
        .await?;

    // Request active sync page for shard over real QUIC
    let page = reader
        .network
        .request_active_sync_page_for_shard(&conn, 1, 0, 100, shard)
        .await?;

    // Verify page payload contains spend_tag
    assert!(
        page.payload.hmc_locks.iter().any(|(t, _)| t == &spend_tag),
        "Active sync page over real QUIC must include spend lock with inherited Root-TTL"
    );

    // Verify reader stages and installs the reconciled cut cleanly
    let stage = Arc::new(ShardStage::new(shard, 50_000)?);
    stage.append(page.payload)?;
    let digest = stage.digest()?;
    reader
        .engine
        .install_shard_snapshot(stage, digest, 1, [0x77; 32], 3, None, None)
        .await?;

    // Reader storage now holds the reconciled spend lock
    let installed = reader.db.get_hmc_lock(&spend_tag)?;
    assert!(installed.is_some(), "Installed snapshot must contain spend lock");
    assert_eq!(installed.unwrap().t_id, spend_req.transaction_hash);

    // Reader active shard query at now=50_000 also sees the lock
    let reader_active = reader.db.active_hmc_locks_for_shard(shard, 50_000)?;
    assert!(
        reader_active.iter().any(|(t, _)| t == &spend_tag),
        "Reader active_hmc_locks_for_shard must see reconciled lock at now=50000"
    );

    drop(conn);
    recovery::stop_recovery_peers(peers).await;
    Ok(())
}

// ============================================================================
// S02-08: Support persistence continuation participates in shutdown drain and
// preserves caller deadline independence
// ============================================================================

#[tokio::test]
async fn test_s02_08_persist_support_deadline_expiry_participates_in_drain() -> TestResult {
    let now = now_ms()?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let root_req = root(&key, 0x51, now)?;
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();

    let temp = tempfile::tempdir()?;
    let db = Arc::new(RedbStorage::open(&temp.path().join("s02_08_drain.redb"))?);
    let cancel = CancellationToken::new();
    let (engine, _worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());

    // Ingress root lock
    let (v_root, _) = engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&root_req),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_root, L2Verdict::Verified { .. }));

    // Ingress spend lock
    let spend_req = spend(&root_req, 0x52, &key)?;
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;
    let (v_spend, _) = engine
        .ingress_hmc_lock_durable(
            spend_tag.clone(),
            L2LockEntry::from(&spend_req),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_spend, L2Verdict::Verified { .. }));

    // Prepare valid provisional support certificate (status = 0, class = 1)
    let parent = *blake3::hash(spend_tag.as_bytes()).as_bytes();
    let genesis_parent = genesis_parent_bytes_from_tag(&root_tag);
    let shard = canonical_voucher_shard(&genesis_parent);
    let identity = NodeIdentity::generate();
    let att = create_attestation_for_network(
        &identity,
        spend_req.transaction_hash,
        parent,
        shard,
        0,
        now,
        NetworkId::Mainnet,
    );
    let cert = QuorumCertificateDto {
        lock_id: hex::encode(spend_req.transaction_hash),
        shard_id: shard,
        status: 0,
        active_nodes_count: 1,
        signer_count: 1,
        signatures: vec![att],
        signer_bitmap: 1,
    };

    // Hold a blocking redb write transaction to freeze support persistence commit
    let blocking_txn = db.raw_database_for_test().begin_write()?;

    // Call persist_confirmation_support_with_deadline with a tight deadline (15ms)
    let res = engine
        .persist_confirmation_support_with_deadline(
            spend_tag.clone(),
            cert,
            &identity,
            now,
            NetworkId::Mainnet,
            None,
            Some(tokio::time::Instant::now() + Duration::from_millis(15)),
        )
        .await;

    assert!(
        matches!(res, Err(StorageError::DurableCommitFailed(ref msg)) if msg.contains("deadline exceeded")),
        "Caller deadline must return Err immediately upon expiration: {:?}",
        res
    );

    // Continuation task is now in-flight, tracked under engine.recovery_work
    assert!(
        !engine.is_recovery_work_idle(),
        "Continuation must be tracked in recovery_work while commit is pending"
    );

    // Draining engine persistence tasks must NOT complete while the redb writer is blocked!
    let mut drain_fut = Box::pin(engine.drain_recovery_work());
    let drained_prematurely = tokio::time::timeout(Duration::from_millis(100), &mut drain_fut)
        .await
        .is_ok();
    assert!(
        !drained_prematurely,
        "Engine persistence drain must NOT complete while detached support commit is blocked on disk"
    );

    // Verify neither durable support nor RAM confirmation class is published yet
    assert!(
        db.confirmation_support(&spend_tag)?.is_none(),
        "Confirmation support must not be durably committed before unblocking"
    );
    assert_eq!(
        engine.hmc_ram.read().await.get_confirmation_class(&spend_tag),
        0,
        "RAM confirmation class must remain 0 before unblocking"
    );

    // Release blocking transaction
    drop(blocking_txn);

    // Drain must now complete cleanly within a short timeout
    tokio::time::timeout(Duration::from_secs(3), drain_fut)
        .await
        .map_err(|_| "Drain timed out after releasing blocking transaction")?;

    // Now durable support and RAM confirmation class must both be published!
    let durable_support = db.confirmation_support(&spend_tag)?;
    assert!(
        durable_support.is_some(),
        "Confirmation support must be durably committed after unblocking"
    );
    assert_eq!(durable_support.as_ref().map(|s| s.class), Some(1));
    assert_eq!(
        engine.hmc_ram.read().await.get_confirmation_class(&spend_tag),
        1,
        "RAM confirmation class must be updated to 1 after completion"
    );
    assert!(engine.is_recovery_work_idle());

    cancel.cancel();
    let _ = _worker.await;
    Ok(())
}

#[tokio::test]
async fn test_s02_09_persist_approval_refuses_publication_at_and_after_root_expiry() -> TestResult {
    for advance_beyond in [0u64, 1u64] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(format!("s02_09_expiry_{advance_beyond}.redb"));
        let key = SigningKey::from_bytes(&[85; 32]);
        let manager = Arc::new(PeerManager::new(vec![]));
        manager.set_simulation_mode(true);
        let base_now = manager.clock().net_time_ms();
        let root_ttl = 5_000u64;
        let root_expiry = base_now + root_ttl;
        let root_req = root_with_ttl(&key, 1, base_now, root_ttl)?;
        let spend_req = spend(&root_req, 2, &key)?;
        let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;

        let db = Arc::new(RedbStorage::open(&path)?);
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let hmc_ram = Arc::new(tokio::sync::RwLock::new(humoco_node::storage::HmcRamIndex::new()));
        let engine = DualTierEngine::from_parts(hmc_ram, db.clone(), tx);
        engine.set_peer_manager(manager.clone()).await;

        let spend_entry: L2LockEntry = (&spend_req).into();
        engine
            .hmc_ram
            .write()
            .await
            .insert_voucher_root_for_test(spend_entry.layer2_voucher_id.clone(), root_expiry);
        engine
            .hmc_ram
            .write()
            .await
            .insert_lock_for_test(spend_tag.clone(), spend_entry.clone());

        let node = [9u8; 32];
        let approval = b"original_approval_s02_09".to_vec();

        let engine_clone = engine.clone();
        let spend_tag_clone = spend_tag.clone();
        let spend_entry_clone = spend_entry.clone();
        let approval_clone = approval.clone();
        let handle = tokio::task::spawn(async move {
            engine_clone
                .persist_original_approval(
                    spend_tag_clone,
                    spend_entry_clone,
                    node,
                    approval_clone,
                    0,
                    base_now,
                )
                .await
        });

        let op = rx.recv().await.ok_or("must receive FlushOp")?;

        let current_clock = manager.clock().net_time_ms();
        let target_time = root_expiry + advance_beyond;
        if target_time > current_clock {
            manager.clock().advance_time_for_test(target_time - current_clock);
        }
        assert!(manager.clock().net_time_ms() >= target_time);

        let mut batch = vec![op];
        let outcome = DualTierEngine::flush_batch(&mut batch, &db);
        assert!(!outcome.failed && outcome.ops_committed > 0);

        let res = handle.await?;
        assert!(
            matches!(res, Err(StorageError::DurableCommitFailed(ref msg)) if msg.contains("Expired root")),
            "persist_original_approval must refuse publication at/after root expiry: {res:?}"
        );

        assert!(engine.is_signing_healthy());
        assert!(db.is_signing_history_healthy());

        assert!(
            db.get_hmc_lock(&spend_tag)?.is_some(),
            "committed lock must be preserved in redb"
        );
        assert!(
            db.own_signing_choice(&node, &spend_tag)?.is_some(),
            "committed own choice must be preserved in redb"
        );
        let ram = engine.hmc_ram.read().await;
        assert!(
            ram.is_entry_durable(&spend_tag, &spend_entry, root_expiry),
            "entry must be marked durable in RAM"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_s02_09_real_quic_rejects_expired_root_without_attestation_bytes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let source_path = dir.path().join("s02_09_quic_source.redb");
    let target_path = dir.path().join("s02_09_quic_target.redb");
    let source_id = NodeIdentity::generate();
    let target_id = NodeIdentity::generate();
    let wallet_node = NodeIdentity::generate();

    let source = WireNode::start(&source_path, source_id).await?;
    let target = WireNode::start(&target_path, target_id).await?;

    let now = target.manager.clock().net_time_ms();
    let root_ttl = 40_000u64;
    let root_expiry = now + root_ttl;
    let root_req = root_with_ttl(wallet_node.signing_key(), 40, now, root_ttl)?;
    let spend_req = spend(&root_req, 41, wallet_node.signing_key())?;
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;

    target
        .manager
        .register_f2f_friend(*wallet_node.node_pubkey(), None)
        .await;
    anchor(&target.engine, &root_req).await?;
    target.ready.mark_shard_ready(shard(&root_req));

    let blocking_txn = target.db.raw_database_for_test().begin_write()?;
    let connection = connect_friends(&source, &target).await?;

    let send_fut = async {
        send_spend(&source, &connection, &spend_req, 1, false).await
    };
    let step_fut = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        target.manager.clock().advance_time_for_test(root_ttl + 5_000);
        assert!(target.manager.clock().net_time_ms() > root_expiry);
        drop(blocking_txn);
    };

    let (send_res, ()) = tokio::join!(send_fut, step_fut);
    let (header, reply_bytes) = send_res?;

    assert_eq!(
        header.flags & humoco_sim_core::wire::FLAG_NOT_READY,
        humoco_sim_core::wire::FLAG_NOT_READY
    );
    let att = humoco_node::api::dto::AttestationDto::from_wire_bytes(&reply_bytes);
    assert!(
        att.is_none(),
        "attestation must NOT be released over QUIC when root is expired"
    );

    assert!(
        target.db.get_hmc_lock(&spend_tag)?.is_some(),
        "lock must remain committed in redb"
    );
    assert!(target.engine.is_signing_healthy());

    drop(connection);
    source.stop().await?;
    target.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_s02_09_unexpired_root_wallet_freshness_delay_still_publishes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("s02_09_freshness_control.redb");
    let key = SigningKey::from_bytes(&[86; 32]);
    let manager = Arc::new(PeerManager::new(vec![]));
    manager.set_simulation_mode(true);
    let base_now = manager.clock().net_time_ms();
    let root_ttl = 600_000u64;
    let root_expiry = base_now + root_ttl;
    let root_req = root_with_ttl(&key, 1, base_now, root_ttl)?;
    let spend_req = spend(&root_req, 2, &key)?;
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;

    let db = Arc::new(RedbStorage::open(&path)?);
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let hmc_ram = Arc::new(tokio::sync::RwLock::new(humoco_node::storage::HmcRamIndex::new()));
    let engine = DualTierEngine::from_parts(hmc_ram, db.clone(), tx);
    engine.set_peer_manager(manager.clone()).await;

    let spend_entry: L2LockEntry = (&spend_req).into();
    engine
        .hmc_ram
        .write()
        .await
        .insert_voucher_root_for_test(spend_entry.layer2_voucher_id.clone(), root_expiry);
    engine
        .hmc_ram
        .write()
        .await
        .insert_lock_for_test(spend_tag.clone(), spend_entry.clone());

    let node = [9u8; 32];
    let approval = b"original_approval_freshness_control".to_vec();

    let engine_clone = engine.clone();
    let spend_tag_clone = spend_tag.clone();
    let spend_entry_clone = spend_entry.clone();
    let approval_clone = approval.clone();
    let handle = tokio::task::spawn(async move {
        engine_clone
            .persist_original_approval(
                spend_tag_clone,
                spend_entry_clone,
                node,
                approval_clone,
                0,
                base_now,
            )
            .await
    });

    let op = rx.recv().await.ok_or("must receive FlushOp")?;

    // Advance calibrated time by 35s, crossing wallet entry freshness window (30s)
    manager.clock().advance_time_for_test(35_000);
    assert!(manager.clock().net_time_ms() < root_expiry);

    let mut batch = vec![op];
    let outcome = DualTierEngine::flush_batch(&mut batch, &db);
    assert!(!outcome.failed && outcome.ops_committed > 0);

    let res = handle.await?;
    assert_eq!(
        res.as_ref().map_err(|e| format!("{e:?}")),
        Ok(&approval),
        "unexpired root must publish approval even if wallet freshness window elapsed during commit"
    );
    assert!(engine.is_signing_healthy());
    Ok(())
}

#[tokio::test]
async fn test_s02_10_voucher_detail_canonical_byte_years_accounting() -> TestResult {
    use humoco_sim_core::quota::ByteYears;

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("s02_10_byte_years.redb");
    let key = SigningKey::from_bytes(&[87; 32]);
    let identity = NodeIdentity::generate();
    let db = Arc::new(RedbStorage::open(&path)?);
    let cancel = CancellationToken::new();
    let (engine, _worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let manager = Arc::new(PeerManager::new(vec![]));
    manager.set_simulation_mode(true);
    engine.set_peer_manager(manager.clone()).await;

    let state = app_state(engine.clone(), db.clone(), identity);
    let operator_app = build_operator_router(state);

    // 1. Root Anchor exclusion test (0 spend locks)
    let now = engine.calibrated_now_ms().await.ok_or("clock missing")?;
    let root_1y = root_with_ttl(&key, 1, now, 31_536_000 * 1000)?;
    anchor(&engine, &root_1y).await?;

    let lineage_0 = engine
        .get_voucher_lineage(&root_1y.layer2_voucher_id)
        .await
        .ok_or("voucher lineage missing")?;
    assert!(
        lineage_0.locks.is_empty(),
        "Root Anchor must be excluded from hops list: {:?}",
        lineage_0.locks
    );
    assert_eq!(
        lineage_0.total_byte_years, 0,
        "Voucher with only Root Anchor must have 0 total Byte-Years"
    );

    let (status, json_0) = get_json(
        &operator_app,
        &format!("/dashboard/voucher/{}", root_1y.layer2_voucher_id),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_0["total_byte_years"], 0);
    assert_eq!(json_0["locks"].as_array().map(|a| a.len()), Some(0));

    // 2. Short remaining lifetime (60 seconds) with 1 spend lock
    let root_60s = root_with_ttl(&key, 2, now, 60 * 1000)?;
    let spend_60s = spend(&root_60s, 3, &key)?;
    anchor(&engine, &root_60s).await?;
    let (v_spend_60s, _) = engine
        .ingress_hmc_lock_durable(
            spend_60s.ds_tag.clone().ok_or("tag missing")?,
            (&spend_60s).into(),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_spend_60s, L2Verdict::Verified { .. }));

    let lineage_60s = engine
        .get_voucher_lineage(&root_60s.layer2_voucher_id)
        .await
        .ok_or("voucher lineage 60s missing")?;
    assert_eq!(lineage_60s.locks.len(), 1);
    assert_eq!(
        lineage_60s.total_byte_years,
        ByteYears::from_ttl_seconds(60),
        "60s lifetime must evaluate to canonical Byte-Year (1)"
    );

    let (status, json_60s) = get_json(
        &operator_app,
        &format!("/dashboard/voucher/{}", root_60s.layer2_voucher_id),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_60s["total_byte_years"], 1);

    // 3. One-year lifetime (31,536,000 seconds) with 1 spend lock, then 2 spend locks
    let spend_1y_1 = spend(&root_1y, 4, &key)?;
    let (v_1y_1, _) = engine
        .ingress_hmc_lock_durable(
            spend_1y_1.ds_tag.clone().ok_or("tag missing")?,
            (&spend_1y_1).into(),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_1y_1, L2Verdict::Verified { .. }));

    let lineage_1y_1 = engine
        .get_voucher_lineage(&root_1y.layer2_voucher_id)
        .await
        .ok_or("voucher lineage 1y missing")?;
    assert_eq!(lineage_1y_1.locks.len(), 1);
    assert_eq!(
        lineage_1y_1.total_byte_years,
        ByteYears::from_ttl_seconds(31_536_000),
        "1 lock for 1 year must be canonical Byte-Years"
    );

    let (status, json_1y) = get_json(
        &operator_app,
        &format!("/dashboard/voucher/{}", root_1y.layer2_voucher_id),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_1y["total_byte_years"],
        ByteYears::from_ttl_seconds(31_536_000)
    );

    let spend_1y_2 = spend(&spend_1y_1, 5, &key)?;
    let (v_1y_2, _) = engine
        .ingress_hmc_lock_durable(
            spend_1y_2.ds_tag.clone().ok_or("tag missing")?,
            (&spend_1y_2).into(),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_1y_2, L2Verdict::Verified { .. }));

    let lineage_1y_2 = engine
        .get_voucher_lineage(&root_1y.layer2_voucher_id)
        .await
        .ok_or("voucher lineage 1y (2 locks) missing")?;
    assert_eq!(lineage_1y_2.locks.len(), 2);
    assert_eq!(
        lineage_1y_2.total_byte_years,
        2 * ByteYears::from_ttl_seconds(31_536_000),
        "2 locks for 1 year must be 2 * canonical Byte-Years"
    );

    // 4. Ten-year lifetime (10 * 31,536,000 seconds) with 1 spend lock
    let root_10y = root_with_ttl(&key, 6, now, 10 * 31_536_000 * 1000)?;
    let spend_10y = spend(&root_10y, 7, &key)?;
    anchor(&engine, &root_10y).await?;
    let (v_10y, _) = engine
        .ingress_hmc_lock_durable(
            spend_10y.ds_tag.clone().ok_or("tag missing")?,
            (&spend_10y).into(),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_10y, L2Verdict::Verified { .. }));

    let lineage_10y = engine
        .get_voucher_lineage(&root_10y.layer2_voucher_id)
        .await
        .ok_or("voucher lineage 10y missing")?;
    assert_eq!(lineage_10y.locks.len(), 1);
    assert_eq!(
        lineage_10y.total_byte_years,
        ByteYears::from_ttl_seconds(10 * 31_536_000),
        "1 lock for 10 years must be canonical Byte-Years"
    );

    let (status, json_10y) = get_json(
        &operator_app,
        &format!("/dashboard/voucher/{}", root_10y.layer2_voucher_id),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_10y["total_byte_years"],
        ByteYears::from_ttl_seconds(10 * 31_536_000)
    );

    cancel.cancel();
    let _ = _worker.await;
    Ok(())
}

#[tokio::test]
async fn test_s02_11_real_quic_missing_state_key_zero_suppresses_signatures_without_peer_ban() -> TestResult {
    let dir = tempfile::tempdir()?;
    let source_path = dir.path().join("s02_11_quic_source.redb");
    let target_path = dir.path().join("s02_11_quic_target.redb");
    let source_id = NodeIdentity::generate();
    let target_id = NodeIdentity::generate();
    let wallet_node = NodeIdentity::generate();

    let source = WireNode::start(&source_path, source_id).await?;
    let target = WireNode::start(&target_path, target_id).await?;

    let now = target.manager.clock().net_time_ms();
    let root_ttl = 60_000u64;
    let root_req = root_with_ttl(wallet_node.signing_key(), 11, now, root_ttl)?;
    let spend_req = spend(&root_req, 12, wallet_node.signing_key())?;

    target
        .manager
        .register_f2f_friend(*wallet_node.node_pubkey(), None)
        .await;
    anchor(&target.engine, &root_req).await?;
    target.ready.mark_shard_ready(shard(&root_req));

    // Remove state key 0 in target database during open session
    {
        let txn = target.db.raw_database_for_test().begin_write()?;
        txn.open_table(humoco_node::storage::TABLE_SIGNING_STATE)?.remove(0)?;
        txn.commit()?;
    }

    // Trigger signing_checkpoint via storage/transport heartbeat hook
    let ckpt = target.db.signing_checkpoint();
    assert!(matches!(ckpt, Err(StorageError::SigningHistoryCorrupt)));
    assert!(!target.db.is_signing_history_healthy());
    assert!(!target.engine.is_signing_healthy());

    let connection = connect_friends(&source, &target).await?;

    // 1. Spend request over QUIC must be refused with FLAG_NOT_READY and empty payload
    let (header, reply_bytes) = send_spend(&source, &connection, &spend_req, 1, false).await?;
    assert_eq!(
        header.flags & humoco_sim_core::wire::FLAG_NOT_READY,
        humoco_sim_core::wire::FLAG_NOT_READY,
        "Spend request over QUIC must be refused with FLAG_NOT_READY when signing history is corrupt"
    );
    assert!(
        humoco_node::api::dto::AttestationDto::from_wire_bytes(&reply_bytes).is_none(),
        "Attestation must not be released"
    );

    // 2. LiveStateRequest over QUIC must be refused with FLAG_NOT_READY
    let shard_id = shard(&root_req);
    let live_ctx = humoco_proto::live::LiveStateContext {
        version: 1,
        network: 0,
        shard_id,
        lookup_tag: spend_req.ds_tag.clone().unwrap_or_default(),
        voucher_id: spend_req.layer2_voucher_id.clone(),
        parent_lock: [0; 32],
        child_lock: spend_req.transaction_hash,
        root_valid_until: now + root_ttl,
        state_digest: [1; 32],
        recipient_nonce: [2; 32],
        committee: vec![*target.identity.node_pubkey()],
    };
    let live_bytes = serde_json::to_vec(&live_ctx)?;
    let live_header = WireHeader::new(
        MsgType::LiveStateRequest as u16,
        2,
        0,
        0,
        live_bytes.len() as u32,
    );
    let (live_resp, live_resp_bytes) = source.network.send_request(&connection, &live_header, &live_bytes).await?;
    assert_eq!(
        live_resp.flags & humoco_sim_core::wire::FLAG_NOT_READY,
        humoco_sim_core::wire::FLAG_NOT_READY,
        "LiveStateRequest must be refused with FLAG_NOT_READY when signing history is corrupt"
    );
    assert!(live_resp_bytes.is_empty());

    // 3. Assert NO peer ban or suspension on the honest caller
    assert!(
        !target.manager.is_banned(source.identity.node_pubkey()).await,
        "Caller must not be banned"
    );
    assert!(
        !target.manager.is_peer_suspended_by_id(source.identity.node_pubkey()).await,
        "Caller must not be suspended"
    );

    drop(connection);
    source.stop().await?;
    target.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_s02_12_real_quic_corruption_latched_during_clock_wait_suppresses_approval_release() -> TestResult {
    let dir = tempfile::tempdir()?;
    let source_path = dir.path().join("s02_12_quic_source.redb");
    let target_path = dir.path().join("s02_12_quic_target.redb");
    let source_id = NodeIdentity::generate();
    let target_id = NodeIdentity::generate();
    let wallet_node = NodeIdentity::generate();

    let source = WireNode::start(&source_path, source_id).await?;
    let target = WireNode::start(&target_path, target_id).await?;

    let now = target.manager.clock().net_time_ms();
    let root_ttl = 60_000u64;
    let root_expiry = now + root_ttl;
    let root_req = root_with_ttl(wallet_node.signing_key(), 21, now, root_ttl)?;
    let spend_req = spend(&root_req, 22, wallet_node.signing_key())?;
    let spend_tag = spend_req.ds_tag.clone().ok_or("missing spend tag")?;
    let spend_entry: L2LockEntry = (&spend_req).into();

    target
        .manager
        .register_f2f_friend(*wallet_node.node_pubkey(), None)
        .await;
    anchor(&target.engine, &root_req).await?;
    target.ready.mark_shard_ready(shard(&root_req));

    let connection = connect_friends(&source, &target).await?;

    let source_ref = &source;
    let conn_ref = &connection;
    let spend_req_ref = &spend_req;
    let send_fut = async move {
        send_spend(source_ref, conn_ref, spend_req_ref, 1, false).await
    };

    let target_engine = target.engine.clone();
    let target_db = target.db.clone();
    let spend_tag_clone = spend_tag.clone();
    let spend_entry_clone = spend_entry.clone();

    let step_fut = async move {
        // Wait until persist_original_approval has passed line 1116 and enqueued the op
        tokio::time::timeout(Duration::from_secs(5), async {
            while target_engine.pending_approvals_count_for_test() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending approval wait timed out");

        // Now acquire pm_guard: this intercepts line 1168 (calibrated_now_ms() wait)
        let pm_guard = target_engine.peer_manager_rwlock_for_test().write().await;

        // Wait deterministically until the entry is committed and marked durable in RAM
        tokio::time::timeout(Duration::from_secs(5), async {
            while !target_engine
                .hmc_ram
                .read()
                .await
                .is_entry_durable(&spend_tag_clone, &spend_entry_clone, root_expiry)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("durability marker wait timed out");

        // Latch corruption on target while persist_original_approval is awaiting pm_guard in calibrated_now_ms()
        target_db.latch_corruption();
        assert!(!target_engine.is_signing_healthy());

        // Release the clock guard
        drop(pm_guard);
    };

    let (send_res, ()) = tokio::join!(send_fut, step_fut);
    let (header, reply_bytes) = send_res?;

    assert_eq!(
        header.flags & humoco_sim_core::wire::FLAG_NOT_READY,
        humoco_sim_core::wire::FLAG_NOT_READY,
        "Approval release must be refused with FLAG_NOT_READY when corruption latched during clock wait"
    );
    assert!(
        humoco_node::api::dto::AttestationDto::from_wire_bytes(&reply_bytes).is_none(),
        "Attestation must not be released"
    );

    // Retained choices and committed locks must remain preserved in database
    assert!(
        target.db.get_hmc_lock(&spend_tag)?.is_some(),
        "committed lock must be preserved in redb"
    );
    assert!(
        target.db.own_signing_choice(target.identity.node_pubkey(), &spend_tag)?.is_some(),
        "committed own choice must be preserved in redb"
    );

    // Assert NO peer ban or suspension on the honest caller
    assert!(
        !target.manager.is_banned(source.identity.node_pubkey()).await,
        "Caller must not be banned"
    );
    assert!(
        !target.manager.is_peer_suspended_by_id(source.identity.node_pubkey()).await,
        "Caller must not be suspended"
    );

    drop(connection);
    source.stop().await?;
    target.stop().await?;
    Ok(())
}
