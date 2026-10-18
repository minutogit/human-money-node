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
//! 3. When `read_quorum = 14` is requested:
//!    - Gateway fans out `StatusQuery` to the Top-20 shard committee.
//!    - Collects at least 14 attestations.
//!    - Attaches a valid BFT `QuorumCertificateDto` with `status = 1` (FINAL) and `signer_count >= 14`.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::api::dto::QuorumCertificateDto;
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

fn fake_pubkey(seed: u64) -> [u8; 32] {
    *blake3::hash(&seed.to_le_bytes()).as_bytes()
}

fn fake_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().expect("valid addr")
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
async fn test_status_query_read_quorum_14_collects_bft_certificate() {
    const NUM_SHARDS: usize = 20;

    let gateway_id = NodeIdentity::generate();
    let gw_cancel = CancellationToken::new();

    let pm_gw = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let dummy_storage = Arc::new(
        RedbStorage::open(&tempdir().expect("gw tempdir").path().join("gw_status.redb"))
            .expect("open redb"),
    );
    let (engine_gw, _worker_gw) = DualTierEngine::new(dummy_storage.clone());

    let gw_handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_gw.clone(),
            dummy_storage.clone(),
            gateway_id.clone(),
            pm_gw.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let gw_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &gateway_id,
        pm_gw.clone(),
        gw_handler,
        gw_cancel.clone(),
    )
    .expect("bind gateway transport");
    gw_transport.set_sync_ready(true);
    gw_transport.spawn_accept_loop();

    struct Shard {
        identity: NodeIdentity,
        addr: SocketAddr,
        transport: Arc<QuicTransport>,
        cancel: CancellationToken,
        engine: DualTierEngine,
    }

    let mut shards: Vec<Shard> = Vec::new();

    for s in 0..NUM_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("status_shard{s}.redb")))
                .expect("open shard redb"),
        );
        std::mem::forget(tmp);
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        let identity = NodeIdentity::generate();
        let cancel = CancellationToken::new();
        let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

        // Shard sees gateway as F2F friend
        pm.register_f2f_friend(
            *gateway_id.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

        for i in 0u64..18 {
            pm.register_f2f_friend(
                fake_pubkey(80_000 + (s as u64) * 100 + i),
                Some(fake_addr((56001 + i) as u16)),
            )
            .await;
        }
        assert_eq!(pm.active_nodes_count(), 20);
        force_stable_ge20(&pm).await;

        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(true))),
        );

        let transport = Arc::new(
            QuicTransport::bind_with_options(
                "127.0.0.1:0".parse().expect("addr"),
                &identity,
                pm.clone(),
                handler,
                cancel.clone(),
            )
            .expect("bind shard transport"),
        );
        transport.set_sync_ready(true);
        let addr = transport.local_addr().expect("shard local addr");
        transport.spawn_accept_loop();

        shards.push(Shard {
            identity,
            addr,
            transport,
            cancel,
            engine,
        });
    }

    // Gateway registers all 20 shards as F2F friends and preconnects
    let gw_addr = gw_transport.local_addr().expect("gw addr");
    for sh in &shards {
        pm_gw
            .register_f2f_friend(*sh.identity.node_pubkey(), Some(sh.addr))
            .await;
        sh.transport
            .peer_manager()
            .register_f2f_friend(*gateway_id.node_pubkey(), Some(gw_addr))
            .await;
        gw_transport
            .connect_peer(sh.addr)
            .await
            .expect("preconnect shard");
    }
    assert!(pm_gw.active_nodes_count() >= 20);
    force_stable_ge20(&pm_gw).await;

    // Pick a spent lock and populate on all 20 shards
    let sender_key = SigningKey::from_bytes(&[77u8; 32]);
    let now = test_now_ms();

    // Select a lock whose shard committee consists of the 20 shards
    let mut counter = 0u64;
    let (_target_shard_id, genesis_req) = loop {
        counter += 1;
        let req = make_hmc_genesis(&format!("status_bft_{counter}"), now + 1_000_000, &sender_key);
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = humoco_sim_core::types::extract_shard_id(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if rem.len() == 20 && !comm.iter().any(|m| m.node_pubkey == *gateway_id.node_pubkey()) {
            break (sid, req);
        }
    };

    let voucher_id = genesis_req.layer2_voucher_id.clone();
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();

    let parent_spent = format!("spent_parent_bft_{counter}");
    let child_tx_hash = *blake3::hash(b"child_spend_tx_payload_bft").as_bytes();
    let spend_req = make_hmc_spend(&voucher_id, &parent_spent, child_tx_hash, now + 800_000, &sender_key);
    let spend_entry = L2LockEntry::from(&spend_req);

    // Anchor genesis and spend lock on all 20 shards
    for sh in &shards {
        let _ = sh.engine
            .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
            .await;
        let _ = sh.engine
            .ingress_hmc_lock(parent_spent.clone(), spend_entry.clone())
            .await;
    }

    // Also populate on gateway so gateway local lookup finds the lock
    let _ = engine_gw
        .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
        .await;
    let _ = engine_gw
        .ingress_hmc_lock(parent_spent.clone(), spend_entry.clone())
        .await;

    let pow = Arc::new(PowEngine::new(*gateway_id.node_id(), 1));
    let tc = Arc::new(TierController::new(dummy_storage.clone(), pow.clone()));
    tc.register_f2f_peer("status_test_token");
    let mut state = AppState::new(
        engine_gw.clone(),
        dummy_storage,
        gateway_id.clone(),
        tc,
        pow,
    );
    state.peer_manager = Some(pm_gw);
    state.transport = Some(gw_transport.clone());
    let app = build_router(state);

    // Submit POST /v1/status requesting read_quorum: 14
    let query = make_status_query(&voucher_id, &parent_spent, Vec::new(), 14);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .header("x-peer-token", "status_test_token")
        .body(axum::body::Body::from(serde_json::to_vec(&query).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.expect("oneshot /v1/status");
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&body_bytes).unwrap();

    // Verify Verdict
    match env.verdict {
        L2Verdict::Verified { lock_entry } => {
            assert_eq!(lock_entry.t_id, child_tx_hash);
        }
        other => panic!("Expected Verified, got {:?}", other),
    }

    // Verify Quorum Certificate
    let cert: QuorumCertificateDto = env
        .quorum_certificate
        .expect("Response must attach QuorumCertificateDto for read_quorum = 14");

    assert!(
        cert.is_quorum_reached(),
        "Quorum must be reached: {}/{}",
        cert.signatures.len(),
        cert.required_quorum()
    );
    assert_eq!(
        cert.status, 1,
        "Status certificate must be FINAL (1) when 14 signatures are gathered in N>=20 cluster"
    );
    assert!(
        cert.signer_count >= 14,
        "Signer count must be at least 14, got {}",
        cert.signer_count
    );
    assert!(
        cert.signatures.len() >= 14,
        "Signatures len must be at least 14, got {}",
        cert.signatures.len()
    );
    assert!(
        cert.signer_bitmap.count_ones() >= 14,
        "Signer bitmap must have at least 14 bits set, got {}",
        cert.signer_bitmap.count_ones()
    );

    // Cleanup
    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}
