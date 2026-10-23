#![forbid(unsafe_code)]

//! Integration tests for Wallet Backup Restoration & Status Reconciliation (Spec 06, 09, 10).
//!
//! Validates:
//! 1. When a wallet restores from backup and queries `POST /v1/status` on an unspent output:
//!    - Node returns `L2Verdict::MissingLocks { sync_point: "genesis" }` when no locators match.
//!    - Node returns `L2Verdict::MissingLocks { sync_point: prefix }` when a locator prefix matches.
//! 2. When a wallet queries `POST /v1/status` on an output that was already spent:
//!    - Node returns `L2Verdict::Verified { lock_entry }` carrying the child transaction hash (`t_id`).
//!    - This cryptographically proves to the wallet that the output is spent and supplies the spend proof.
//! 3. Explicit recipient-challenged current-state proofs use real, distinct,
//!    mature full-key committees over QUIC and enforce the full14 threshold.
//!    Fixture-installed readiness does not establish production recovery safety.

use std::sync::Arc;

use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::api::hmc::{
    calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest, L2ResponseEnvelope,
    L2StatusQuery, L2Verdict,
};
use humoco_node::api::{build_router, AppState};
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::network::{NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn force_stable_ge20(pm: &PeerManager) {
    pm.set_local_sync_ready(true);
    let now_ms = pm.net_time_ms();
    let anchor = now_ms.saturating_sub(86_400_001);
    let anchor = if anchor == 0 { 1 } else { anchor };
    pm.set_ge20_anchor_for_test(anchor);
    assert!(
        pm.is_network_stable_ge20_for_24h(now_ms),
        "Network must be marked ge20 stable for 24h"
    );
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
        created_at_ms: 0,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
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
        created_at_ms: 0,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_status_query(
    voucher_id: &str,
    challenge_tag: &str,
    locators: Vec<String>,
    read_quorum: u8,
) -> L2StatusQuery {
    L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [1u8; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        challenge_ds_tag: challenge_tag.to_string(),
        locator_prefixes: locators,
        read_quorum,
    }
}

#[tokio::test]
async fn test_status_query_unspent_and_spent_reconciliation() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("status_node.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 1));
    let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    tc.register_f2f_peer("status_test_token");

    let mut state = AppState::new(
        engine.clone(),
        storage,
        identity,
        tc,
        pow,
    );
    state.peer_manager = Some(pm);
    let app = build_router(state);

    // Anchor genesis lock for "voucher_reconcile"
    let genesis_key = SigningKey::from_bytes(&[55u8; 32]);
    let now = test_now_ms();
    let genesis_req = make_hmc_genesis("reconcile", now + 1_000_000, &genesis_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let voucher_id = genesis_req.layer2_voucher_id.clone();

    let (v_gen, is_new_gen) = engine
        .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
        .await;
    assert!(is_new_gen);
    assert!(matches!(v_gen, L2Verdict::Verified { .. }));

    // -----------------------------------------------------------------------
    // Part A: Query UNSPENT tag with no matching locators
    // Expected: MissingLocks { sync_point: "genesis" }
    // -----------------------------------------------------------------------
    let query_unspent = make_status_query(&voucher_id, "unspent_tag_1", Vec::new(), 1);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .header("x-peer-token", "status_test_token")
        .body(axum::body::Body::from(serde_json::to_vec(&query_unspent).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.expect("oneshot /v1/status");
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&body_bytes).unwrap();
    match env.verdict {
        L2Verdict::MissingLocks { sync_point } => {
            assert_eq!(sync_point, "genesis", "Unspent query without matching locators must sync from genesis");
        }
        other => panic!("Expected MissingLocks, got {:?}", other),
    }

    // -----------------------------------------------------------------------
    // Part B: Query UNSPENT tag with matching locator prefix
    // Expected: MissingLocks { sync_point: <matching_prefix> }
    // -----------------------------------------------------------------------
    let prefix = genesis_tag[..4].to_string();
    let query_locator = make_status_query(&voucher_id, "unspent_tag_2", vec![prefix.clone()], 1);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .header("x-peer-token", "status_test_token")
        .body(axum::body::Body::from(serde_json::to_vec(&query_locator).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.expect("oneshot /v1/status");
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&body_bytes).unwrap();
    match env.verdict {
        L2Verdict::MissingLocks { sync_point } => {
            assert_eq!(sync_point, prefix, "Unspent query with matching locator prefix must return that sync point");
        }
        other => panic!("Expected MissingLocks with matching prefix, got {:?}", other),
    }

    // -----------------------------------------------------------------------
    // Part C: Spend an output and query the SPENT tag
    // Expected: Verified { lock_entry } carrying child t_id
    // -----------------------------------------------------------------------
    let parent_spent = "spent_parent_output_tag";
    let child_tx_hash = *blake3::hash(b"child_spend_tx_payload").as_bytes();
    let spend_req = make_hmc_spend(&voucher_id, parent_spent, child_tx_hash, now + 800_000, &genesis_key);

    let (v_spend, is_new_spend) = engine
        .ingress_hmc_lock(parent_spent.to_string(), L2LockEntry::from(&spend_req))
        .await;
    assert!(is_new_spend);
    assert!(matches!(v_spend, L2Verdict::Verified { .. }));

    // Wallet queries the spent parent tag:
    let query_spent = make_status_query(&voucher_id, parent_spent, Vec::new(), 1);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .header("x-peer-token", "status_test_token")
        .body(axum::body::Body::from(serde_json::to_vec(&query_spent).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.expect("oneshot /v1/status");
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&body_bytes).unwrap();
    match env.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry.t_id, child_tx_hash, "Verified verdict must carry child transaction hash");
            assert_eq!(lock_entry.layer2_voucher_id, voucher_id);
        }
        other => panic!("Expected Verified child lock for spent output, got {:?}", other),
    }
}

#[tokio::test]
async fn test_current_state_quorum_requires_real_fourteen_distinct_live_votes() {
    use humoco_node::daemon::ShardReadinessManager;
    use humoco_proto::live::{LiveStateContext, LiveStateProof, verify_live_state_proof};
    use std::time::{Duration, Instant};
    const NUM_SHARDS: usize = 20;
    struct Shard {
        id: NodeIdentity, pm: Arc<PeerManager>, transport: QuicTransport,
        engine: DualTierEngine, ready: Arc<ShardReadinessManager>,
    }
    let temp = tempdir().unwrap();
    let cancel = CancellationToken::new();
    let gateway = NodeIdentity::generate();
    let gateway_pm = Arc::new(PeerManager::new(Vec::new()));
    let storage = Arc::new(RedbStorage::open(&temp.path().join("gateway.redb")).unwrap());
    let (gateway_engine, _worker) = DualTierEngine::new(storage.clone());
    let gateway_transport = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(), &gateway, gateway_pm.clone(), Arc::new(humoco_node::network::DefaultRequestHandler), cancel.clone()).unwrap();
    let gateway_addr = gateway_transport.local_addr().unwrap();
    let mut shards = Vec::new();
    for index in 0..NUM_SHARDS {
        let disk = Arc::new(RedbStorage::open(&temp.path().join(format!("shard{index}.redb"))).unwrap());
        let (engine, _worker) = DualTierEngine::new(disk.clone());
        let id = NodeIdentity::generate();
        let pm = Arc::new(PeerManager::new(Vec::new()));
        let ready = Arc::new(ShardReadinessManager::with_cancel_token(cancel.clone()));
        let handler = Arc::new(NodeRequestHandler::with_peer_manager(engine.clone(), disk, id.clone(), pm.clone()).with_readiness_manager(ready.clone()));
        let transport = QuicTransport::bind_with_options("127.0.0.1:0".parse().unwrap(), &id, pm.clone(), handler, cancel.clone()).unwrap();
        pm.register_f2f_friend(*gateway.node_pubkey(), Some(gateway_addr)).await;
        gateway_pm.register_f2f_friend(*id.node_pubkey(), Some(transport.local_addr().unwrap())).await;
        shards.push(Shard {id, pm, transport, engine, ready});
    }
    // Every observer receives the same authenticated full-key/ticket fixture.
    // Explicit maturity/readiness below is test setup, never a recovery proof.
    let mut roster: Vec<_> = shards.iter().map(|sh| (sh.id.clone(), sh.transport.local_addr().unwrap())).collect();
    roster.push((gateway.clone(), gateway_addr));
    for pm in std::iter::once(gateway_pm.clone()).chain(shards.iter().map(|sh| sh.pm.clone())) {
        for (id, addr) in &roster {
            pm.learn_node_from_gossip_with_hrw(*id.node_pubkey(), *id.hrw_routing_id(), *addr, 0, None).await;
            pm.set_first_seen_for_test(id.node_pubkey(), Instant::now() - Duration::from_secs(25*3600)).await;
        }
        force_stable_ge20(&pm).await;
    }
    let owner = SigningKey::from_bytes(&[77;32]);
    let now = gateway_pm.net_time_ms();
    let mut selected = None;
    for index in 0..1000 {
        let req = make_hmc_genesis(&format!("live_status_{index}"), now + 1_000_000, &owner);
        let tag = bs58::encode(req.transaction_hash).into_string();
        let sid = humoco_sim_core::types::extract_shard_id(blake3::hash(tag.as_bytes()).as_bytes());
        let (committee, _, _) = gateway_pm.shard_committee(*gateway.node_pubkey(), *gateway.hrw_routing_id(), sid).await;
        if !committee.iter().any(|member| member.node_pubkey == *gateway.node_pubkey()) {
            selected = Some((sid, req, committee.iter().map(|member| member.node_pubkey).collect::<Vec<_>>())); break;
        }
    }
    let (shard_id, genesis, committee) = selected.expect("find committee excluding gateway");
    let genesis_tag = bs58::encode(genesis.transaction_hash).into_string();
    let anchor = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let root = now + 1_000_000;
    let spend = make_hmc_spend(&genesis.layer2_voucher_id, "spent-parent", [91;32], now + 800_000, &owner);
    let entry = L2LockEntry::from(&spend);
    for shard in &shards {
        let (verdict, _) = shard.engine.ingress_hmc_lock_durable(genesis_tag.clone(), L2LockEntry::from(&genesis), humoco_node::storage::IngressOrigin::PartitionSync, Some(now), None, None, Some(genesis.layer2_voucher_id.clone())).await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
        let (verdict, _) = shard.engine.ingress_hmc_lock_durable("spent-parent".into(), entry.clone(), humoco_node::storage::IngressOrigin::PartitionSync, Some(now), None, None, Some(genesis.layer2_voucher_id.clone())).await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
        shard.engine.record_hmc_voucher_genesis_parent(&genesis.layer2_voucher_id, anchor).await;
        shard.ready.mark_shard_ready(shard_id);
        shard.transport.spawn_accept_loop();
    }
    gateway_transport.spawn_accept_loop();
    let pow = Arc::new(PowEngine::new(*gateway.node_id(), 1));
    let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let mut state = AppState::new(gateway_engine, storage, gateway, tiers, pow);
    state.peer_manager = Some(gateway_pm); state.transport = Some(gateway_transport.clone());
    let app = build_router(state);
    let context = LiveStateContext {version:1,network:0,shard_id,voucher_id:genesis.layer2_voucher_id.clone(),lookup_tag:"spent-parent".into(),parent_lock:*blake3::hash(b"spent-parent").as_bytes(),child_lock:entry.t_id,root_valid_until:root,state_digest:*blake3::hash(&serde_json::to_vec(&entry).unwrap()).as_bytes(),recipient_nonce:[71;32],committee};
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/v1/verify-current").header("content-type","application/json").body(axum::body::Body::from(serde_json::to_vec(&context).unwrap())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let proof: LiveStateProof = serde_json::from_slice(&bytes).unwrap();
    verify_live_state_proof(&proof, &context).expect("real 14/20 current proof");
    assert_eq!(proof.votes.len(),14);
    // Seven unavailable shards make FINAL impossible; the endpoint never lowers 14.
    for shard in shards.iter().take(7) {shard.ready.invalidate_shard(shard_id);}
    let mut next=context.clone(); next.recipient_nonce=[72;32];
    let response = app.oneshot(Request::builder().method("POST").uri("/v1/verify-current").header("content-type","application/json").body(axum::body::Body::from(serde_json::to_vec(&next).unwrap())).unwrap()).await.unwrap();
    assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
    assert!(verify_live_state_proof(&proof,&next).is_err(),"old nonce cannot satisfy next checkout");
    cancel.cancel();gateway_transport.close();for shard in shards {shard.transport.close();}
}
