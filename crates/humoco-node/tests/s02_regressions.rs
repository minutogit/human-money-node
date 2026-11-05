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
        hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2ChainLockRequest, L2LockEntry,
            L2LockRequest, L2Verdict,
        },
        routes::build_operator_router,
        AppState,
    },
    daemon::ShardReadinessManager,
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{framing::LockWirePayload, NodeRequestHandler, PeerManager, QuicTransport},
    storage::{DualTierEngine, IngressOrigin, RedbStorage},
};
use humoco_proto::causal::CausalOutputProof;
use humoco_sim_core::{
    types::SimTime,
    wire::{MsgType, WireHeader, FLAG_COLLISION_DETECTED, FLAG_PEER_SUSPENDED},
};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::{error::Error, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn root(key: &SigningKey, seed: u8, now: u64) -> TestResult<L2LockRequest> {
    let sender = key.verifying_key().to_bytes();
    let transaction = [seed; 32];
    let expiry = now
        .checked_add(600_000)
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
    let pow = Arc::new(PowEngine::new(*identity.node_pubkey(), 8));
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
