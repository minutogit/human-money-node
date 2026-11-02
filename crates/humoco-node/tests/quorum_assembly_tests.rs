#![forbid(unsafe_code)]
#![allow(clippy::needless_range_loop)]

//! Integration tests for Quorum Assembly (AGENTS.md, Spec 02, Spec 11).
//!
//! Validates that a gateway assembling a quorum certificate from shard nodes
//! correctly handles a mix of `201 Created` (newly accepted) and `200 OK`
//! (idempotent replay) responses.
//!
//! Specifically:
//! - 9 shard nodes already know Lock X (return Verified / 200 OK).
//! - 11 shard nodes receive Lock X for the first time (return Verified / 201 Created).
//! - The gateway collects all 9 + 11 = 20 attestations, populates the committee bitmap
//!   with all 20 bits set, and produces a `QuorumCertificateDto` with `status = 1` (`FINAL`).

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::api::dto::QuorumCertificateDto;
use humoco_node::api::hmc::{
    calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest, L2ResponseEnvelope,
    L2Verdict,
};
use humoco_node::api::routes::assemble_quorum_certificate_with_deadline;
use humoco_node::api::{build_router, AppState};
use humoco_node::error::NodeError;
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::network::transport::{BoxFuture, RequestHandler};
use humoco_node::network::{NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::wire::WireHeader;

/// Explicit isolated fixture premises: mature tickets and installed shard state.
/// These transport/collector tests do not prove bootstrap or recovery completeness.
fn prepared_readiness() -> Arc<humoco_node::daemon::ShardReadinessManager> {
    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    for shard in 0..=u16::MAX {
        readiness.mark_shard_ready(shard);
    }
    readiness
}

async fn prepare_mature_fixture(pm: &PeerManager, local: &NodeIdentity) {
    pm.set_simulation_mode(true);
    for peer in pm.list_peers().await {
        if let Some(key) = peer.node_id {
            let ticket = pm.get_hrw_routing_id(&key).await.unwrap_or(key);
            pm.learn_node_from_gossip_with_hrw(key, ticket, peer.addr, 0, None)
                .await;
            pm.set_first_seen_for_test(
                &key,
                std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
            )
            .await;
        }
    }
    pm.learn_node_from_gossip_with_hrw(
        *local.node_pubkey(),
        *local.hrw_routing_id(),
        "127.0.0.1:1".parse().unwrap(),
        0,
        None,
    )
    .await;
    pm.set_first_seen_for_test(
        local.node_pubkey(),
        std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
    )
    .await;
}

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
    pm.set_simulation_mode(true);
    pm.set_local_sync_ready(true);
    let now_ms = pm.net_time_ms();
    let anchor = now_ms.saturating_sub(86_400_001);
    let anchor = if anchor == 0 { 1 } else { anchor };
    pm.set_ge20_anchor_for_test(anchor);
    assert!(
        pm.is_network_stable_ge20_for_24h(now_ms),
        "PeerManager must report stable N>=20 after anchor override"
    );
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
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

#[tokio::test]
async fn test_gateway_assembles_quorum_from_mixed_200_and_201_responses() {
    // -----------------------------------------------------------------------
    // Setup: 20 Shard Nodes over real QUIC wire + 1 Stateless Gateway
    // -----------------------------------------------------------------------
    const NUM_SHARDS: usize = 20;
    const NUM_PRE_KNOWN: usize = 9; // 9 nodes already know Lock X (return Verified/200 OK)
    const NUM_NEW: usize = 11; // 11 nodes receive Lock X for first time (return Verified/201 Created)
    assert_eq!(NUM_PRE_KNOWN + NUM_NEW, NUM_SHARDS);

    let gw_temp = tempdir().expect("gw tempdir");
    let gw_storage =
        Arc::new(RedbStorage::open(&gw_temp.path().join("quorum_gw.redb")).expect("open gw redb"));
    let (gw_engine, _gw_worker) = DualTierEngine::new(gw_storage.clone());
    let gateway_id = NodeIdentity::generate();
    let gw_cancel = CancellationToken::new();
    let pm_gw = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    struct Shard {
        identity: NodeIdentity,
        addr: SocketAddr,
        transport: QuicTransport,
        cancel: CancellationToken,
        engine: DualTierEngine,
        _storage: Arc<RedbStorage>,
    }

    let mut shards: Vec<Shard> = Vec::new();

    for s in 0..NUM_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("quorum_shard{s}.redb")))
                .expect("open shard redb"),
        );
        std::mem::forget(tmp);
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        let identity = NodeIdentity::generate();
        let cancel = CancellationToken::new();
        let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

        // Shard sees gateway as F2F friend (authorizes inbound wire RPC).
        pm.register_f2f_friend(
            *gateway_id.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

        // Populate +18 dead F2F friends so total active count >= 20.
        for i in 0u64..18 {
            pm.register_f2f_friend(
                fake_pubkey(70_000 + (s as u64) * 100 + i),
                Some(fake_addr((55001 + i) as u16)),
            )
            .await;
        }
        prepare_mature_fixture(&pm, &identity).await;
        assert_eq!(pm.active_nodes_count(), 20);
        force_stable_ge20(&pm).await;

        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(true)))
            .with_readiness_manager(prepared_readiness()),
        );

        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .expect("bind shard transport");
        transport.set_sync_ready(true);
        let addr = transport.local_addr().expect("shard local addr");
        transport.spawn_accept_loop();

        shards.push(Shard {
            identity,
            addr,
            transport,
            cancel,
            engine,
            _storage: storage,
        });
    }

    // -----------------------------------------------------------------------
    // Connect Gateway to all 20 Shards
    // -----------------------------------------------------------------------
    for sh in &shards {
        pm_gw
            .register_f2f_friend(*sh.identity.node_pubkey(), Some(sh.addr))
            .await;
    }
    // Total active on gateway: 20 shards + self = 21 >= 20
    prepare_mature_fixture(&pm_gw, &gateway_id).await;
    assert!(pm_gw.active_nodes_count() >= 20);
    force_stable_ge20(&pm_gw).await;

    // -----------------------------------------------------------------------
    // Prepare Lock X:
    // Select a Lock X whose shard committee is composed strictly of the 20 shards
    // (i.e. the gateway is outside the top-20 for this shard, making it a pure
    // stateless routing gateway for this lock request).
    // -----------------------------------------------------------------------
    let sender_key = SigningKey::from_bytes(&[42u8; 32]);
    let now = test_now_ms();

    let mut counter = 0u64;
    let (_target_shard_id, root_req) = loop {
        counter += 1;
        let req = make_hmc_genesis(
            &format!("lock_x_quorum_{counter}"),
            now + 900_000,
            &sender_key,
        );
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = humoco_sim_core::types::extract_shard_id(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if rem.len() == 20
            && !comm
                .iter()
                .any(|m| m.node_pubkey == *gateway_id.node_pubkey())
        {
            break (sid, req);
        }
        if counter > 10_000 {
            panic!("Could not find shard where gateway is outside top-20 within 10,000 iterations");
        }
    };

    // Genesis is metadata only; the first spend owns the collision slot.
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    for engine in std::iter::once(&gw_engine).chain(shards.iter().map(|s| &s.engine)) {
        let (verdict, _) = engine
            .ingress_hmc_lock_with_origin(
                root_tag.clone(),
                L2LockEntry::from(&root_req),
                IngressOrigin::ClientApi,
                Some(now),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }
    use sha3::{Digest, Sha3_256};
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update(root_req.transaction_hash);
    hash.update(32u32.to_le_bytes());
    hash.update(sender_key.verifying_key().to_bytes());
    let lookup_tag = bs58::encode(hash.finalize()).into_string();
    let mut lock_x_req = root_req.clone();
    lock_x_req.is_genesis = false;
    lock_x_req.ds_tag = Some(lookup_tag.clone());
    lock_x_req.transaction_hash = [91; 32];
    lock_x_req.deletable_at = None;
    lock_x_req.layer2_signature = sender_key
        .sign(&calculate_l2_payload_hash(&lock_x_req))
        .to_bytes();
    let lock_x_entry = L2LockEntry::from(&lock_x_req);

    // Pre-populate Lock X on the first 9 shard nodes (shards 0..9).
    // When they later receive LockVerifyRequest for Lock X, it will be an
    // idempotent replay (verdict = Verified, is_new = false => 200 OK).
    for s in 0..NUM_PRE_KNOWN {
        let (verdict, is_new) = shards[s]
            .engine
            .ingress_hmc_lock_with_origin(
                lookup_tag.clone(),
                lock_x_entry.clone(),
                IngressOrigin::ClientApi,
                Some(now),
            )
            .await;
        assert!(
            is_new,
            "Initial pre-population on shard {s} must be newly accepted"
        );
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }

    // Verify that shards 9..20 (the 11 new nodes) do NOT know Lock X yet.
    for s in NUM_PRE_KNOWN..NUM_SHARDS {
        let existing = shards[s].engine.get_hmc_ram_lock(&lookup_tag).await;
        assert!(
            existing.is_none(),
            "Shard {s} must NOT know Lock X prior to quorum fanout"
        );
    }

    let gw_handler = Arc::new(NodeRequestHandler::with_peer_manager(
        gw_engine.clone(),
        gw_storage.clone(),
        gateway_id.clone(),
        pm_gw.clone(),
    ));

    let gw_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &gateway_id,
        pm_gw.clone(),
        gw_handler,
        gw_cancel.clone(),
    )
    .expect("bind gateway transport");
    let gw_addr = gw_transport.local_addr().expect("gw addr");
    gw_transport.spawn_accept_loop();

    // Register actual gateway address on all shards and preconnect
    for sh in &shards {
        sh.transport
            .peer_manager()
            .register_f2f_friend(*gateway_id.node_pubkey(), Some(gw_addr))
            .await;
        gw_transport
            .connect_peer(sh.addr)
            .await
            .expect("preconnect shard");
    }

    let pow_engine = Arc::new(PowEngine::new(*gateway_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(gw_storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("quorum_test_token");

    let mut state = AppState::new(
        gw_engine,
        gw_storage,
        gateway_id.clone(),
        tier_controller,
        pow_engine,
    );
    state.peer_manager = Some(pm_gw.clone());
    state.transport = Some(gw_transport.clone());
    let app = build_router(state);

    // -----------------------------------------------------------------------
    // Gateway Ingress: Submit Lock X via POST /v1/lock
    // -----------------------------------------------------------------------
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "quorum_test_token")
        .header("x-required-quorum", "20")
        .body(Body::from(
            serde_json::to_vec(&lock_x_req).expect("serialize lock request"),
        ))
        .expect("build request");

    let resp = app.oneshot(req).await.expect("execute request");
    let status = resp.status();
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "Gateway submission must succeed with 200/201, got {status}"
    );

    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let envelope: L2ResponseEnvelope =
        serde_json::from_slice(&body_bytes).expect("deserialize envelope");

    assert!(
        matches!(envelope.verdict, L2Verdict::Verified { .. }),
        "Verdict must be Verified, got {:?}",
        envelope.verdict
    );

    // -----------------------------------------------------------------------
    // Verify Quorum Certificate:
    // - All 20 attestations collected (9 replay + 11 new)
    // - Status is FINAL (1)
    // - Committee bitmap has all 20 bits set
    // -----------------------------------------------------------------------
    let cert: QuorumCertificateDto = envelope
        .quorum_certificate
        .expect("Response must attach QuorumCertificateDto");

    assert!(
        cert.is_quorum_reached(),
        "Quorum must be reached: {}/{}",
        cert.signatures.len(),
        cert.required_quorum()
    );
    assert_eq!(
        cert.status, 1,
        "Certificate status must be FINAL (1) for stable N>=20 cluster"
    );
    assert_eq!(
        cert.signer_count, 20,
        "All 20 shard nodes (9 replay + 11 new) must have signed the certificate"
    );
    assert_eq!(
        cert.signatures.len(),
        20,
        "Exactly 20 distinct attestations must be collected"
    );

    // Committee bitmap must have all 20 bits set: (1 << 20) - 1 = 0x000F_FFFF
    let expected_bitmap = (1u32 << NUM_SHARDS) - 1;
    assert_eq!(
        cert.signer_bitmap, expected_bitmap,
        "Committee bitmap must have all 20 bits set (0x{:05x}), got 0x{:05x}",
        expected_bitmap, cert.signer_bitmap
    );
    assert_eq!(cert.signer_bitmap.count_ones(), 20);

    // Verify all 20 shards now possess Lock X in RAM
    for s in 0..NUM_SHARDS {
        let stored = shards[s].engine.get_hmc_ram_lock(&lookup_tag).await;
        assert!(
            stored.is_some(),
            "Shard {s} must have Lock X in RAM after quorum processing"
        );
        assert_eq!(stored.unwrap().t_id, lock_x_req.transaction_hash);
    }

    // Cleanup tasks and transports
    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}

struct DelayedHandler {
    inner: Arc<NodeRequestHandler>,
    delay: Duration,
}

impl RequestHandler for DelayedHandler {
    fn handle_authenticated(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
        peer_identity: Option<[u8; 32]>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        let inner = self.inner.clone();
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            inner
                .handle_authenticated(header, payload, peer_identity)
                .await
        })
    }
}

/// A24-R1: End-to-end checkout deadline enforcement across persistence and quorum assembly.
/// When local persistence is delayed or peers respond slowly, the single 780ms checkout deadline
/// bounds the total execution time, cleanly aborts stragglers without false peer failure penalties,
/// and returns 503 Quorum Not Reached.
#[tokio::test]
async fn test_a24_r1_checkout_enforces_single_end_to_end_deadline_across_persistence_and_quorum() {
    const NUM_SHARDS: usize = 20;

    let gw_temp = tempdir().expect("gw tempdir");
    let gw_storage = Arc::new(
        RedbStorage::open(&gw_temp.path().join("quorum_gw_deadline.redb")).expect("open gw redb"),
    );
    let (gw_engine, _gw_worker) = DualTierEngine::new(gw_storage.clone());
    let gateway_id = NodeIdentity::generate();
    let gw_cancel = CancellationToken::new();
    let pm_gw = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    struct Shard {
        identity: NodeIdentity,
        addr: SocketAddr,
        transport: QuicTransport,
        cancel: CancellationToken,
        engine: DualTierEngine,
    }

    let mut shards: Vec<Shard> = Vec::new();

    // Spawn 20 shards with delayed responses (1200ms delay, exceeding the 780ms checkout deadline)
    for s in 0..NUM_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("deadline_shard{s}.redb")))
                .expect("open shard redb"),
        );
        std::mem::forget(tmp);
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        let identity = NodeIdentity::generate();
        let cancel = CancellationToken::new();
        let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

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
        prepare_mature_fixture(&pm, &identity).await;
        force_stable_ge20(&pm).await;

        let inner_handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(true)))
            .with_readiness_manager(prepared_readiness()),
        );

        let delayed_handler = Arc::new(DelayedHandler {
            inner: inner_handler,
            delay: Duration::from_millis(1200),
        });

        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            delayed_handler,
            cancel.clone(),
        )
        .expect("bind shard transport");
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

    for sh in &shards {
        pm_gw
            .register_f2f_friend(*sh.identity.node_pubkey(), Some(sh.addr))
            .await;
    }
    prepare_mature_fixture(&pm_gw, &gateway_id).await;
    force_stable_ge20(&pm_gw).await;

    let sender_key = SigningKey::from_bytes(&[43u8; 32]);
    let now = test_now_ms();

    let mut counter = 0u64;
    let (target_shard_id, root_req) = loop {
        counter += 1;
        let req = make_hmc_genesis(
            &format!("lock_deadline_{counter}"),
            now + 900_000,
            &sender_key,
        );
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = humoco_sim_core::types::extract_shard_id(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if rem.len() == 20
            && !comm
                .iter()
                .any(|m| m.node_pubkey == *gateway_id.node_pubkey())
        {
            break (sid, req);
        }
        if counter > 10_000 {
            panic!("Could not find shard committee outside gateway");
        }
    };

    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    for engine in std::iter::once(&gw_engine).chain(shards.iter().map(|s| &s.engine)) {
        let (verdict, _) = engine
            .ingress_hmc_lock_with_origin(
                root_tag.clone(),
                L2LockEntry::from(&root_req),
                IngressOrigin::ClientApi,
                Some(now),
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }

    use sha3::{Digest, Sha3_256};
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update(root_req.transaction_hash);
    hash.update(32u32.to_le_bytes());
    hash.update(sender_key.verifying_key().to_bytes());
    let lookup_tag = bs58::encode(hash.finalize()).into_string();
    let mut lock_req = root_req.clone();
    lock_req.is_genesis = false;
    lock_req.ds_tag = Some(lookup_tag.clone());
    lock_req.transaction_hash = [92; 32];
    lock_req.deletable_at = None;
    lock_req.layer2_signature = sender_key
        .sign(&calculate_l2_payload_hash(&lock_req))
        .to_bytes();

    let gw_handler = Arc::new(NodeRequestHandler::with_peer_manager(
        gw_engine.clone(),
        gw_storage.clone(),
        gateway_id.clone(),
        pm_gw.clone(),
    ));

    let gw_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &gateway_id,
        pm_gw.clone(),
        gw_handler,
        gw_cancel.clone(),
    )
    .expect("bind gateway transport");
    let gw_addr = gw_transport.local_addr().expect("gw addr");
    gw_transport.spawn_accept_loop();

    for sh in &shards {
        sh.transport
            .peer_manager()
            .register_f2f_friend(*gateway_id.node_pubkey(), Some(gw_addr))
            .await;
        gw_transport
            .connect_peer(sh.addr)
            .await
            .expect("preconnect shard");
    }

    let pow_engine = Arc::new(PowEngine::new(*gateway_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(gw_storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("quorum_deadline_token");

    let mut state = AppState::new(
        gw_engine,
        gw_storage,
        gateway_id.clone(),
        tier_controller,
        pow_engine,
    );
    state.peer_manager = Some(pm_gw.clone());
    state.transport = Some(gw_transport.clone());

    // -----------------------------------------------------------------------
    // Part 1: Direct assemble_quorum_certificate_with_deadline with simulated remaining budget
    // (simulating that local persistence already consumed ~430ms of 780ms budget, leaving 350ms).
    // -----------------------------------------------------------------------
    let partial_deadline = tokio::time::Instant::now() + Duration::from_millis(350);
    let start_partial = std::time::Instant::now();
    let (cert_partial, _) = assemble_quorum_certificate_with_deadline(
        &state,
        lock_req.transaction_hash,
        *blake3::hash(lookup_tag.as_bytes()).as_bytes(),
        target_shard_id,
        now,
        None,
        None,
        Some(partial_deadline),
    )
    .await;
    let elapsed_partial = start_partial.elapsed();
    assert!(
        elapsed_partial < Duration::from_millis(500),
        "Partial deadline must abort at ~350ms, not 800ms default timeout! Elapsed: {elapsed_partial:?}"
    );
    assert!(
        !cert_partial.is_quorum_reached(),
        "Quorum must not be reached when peers delay"
    );

    // Verify peers were NOT penalized for being cancelled by the deadline
    for sh in &shards {
        if let Some(entry) = pm_gw.get_peer(&sh.addr).await {
            assert_eq!(
                entry.missing_count, 0,
                "Aborted peers must not be penalized with failures"
            );
            assert!(
                entry.last_failure.is_none(),
                "Aborted peers must have no recorded failure timestamp"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Part 2: End-to-end /v1/lock HTTP route with 780ms checkout deadline
    // -----------------------------------------------------------------------
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "quorum_deadline_token")
        .header("x-required-quorum", "14")
        .body(Body::from(
            serde_json::to_vec(&lock_req).expect("serialize lock request"),
        ))
        .expect("build request");

    let start_http = std::time::Instant::now();
    let resp = app.oneshot(req).await.expect("execute request");
    let elapsed_http = start_http.elapsed();

    assert!(
        elapsed_http < Duration::from_millis(850),
        "End-to-end HTTP request must respect 780ms deadline! Elapsed: {elapsed_http:?}"
    );
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "Slow peers must trigger 503 Quorum Not Reached"
    );

    let body_bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let env: L2ResponseEnvelope = serde_json::from_slice(&body_bytes).expect("envelope");
    assert!(matches!(env.verdict, L2Verdict::Rejected { .. }));

    // Cleanup
    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}

/// S01-01: Bounded checkout completion respecting deadline during support persistence write contention,
/// with neutral cancellation (no false signing disablement) and safe eventual persistence.
#[tokio::test]
async fn test_s01_01_checkout_deadline_cancels_blocked_support_persistence_without_poisoning_signing_health() {
    const NUM_SHARDS: usize = 20;

    let gw_temp = tempdir().expect("gw tempdir");
    let gw_storage = Arc::new(
        RedbStorage::open(&gw_temp.path().join("quorum_gw_s01.redb")).expect("open gw redb"),
    );
    let (gw_engine, _gw_worker) = DualTierEngine::new(gw_storage.clone());
    let gateway_id = NodeIdentity::generate();
    let gw_cancel = CancellationToken::new();
    let pm_gw = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    struct Shard {
        identity: NodeIdentity,
        addr: SocketAddr,
        transport: QuicTransport,
        cancel: CancellationToken,
        engine: DualTierEngine,
        _storage: Arc<RedbStorage>,
    }

    let mut shards: Vec<Shard> = Vec::new();

    for s in 0..NUM_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("quorum_s01_shard{s}.redb")))
                .expect("open shard redb"),
        );
        std::mem::forget(tmp);
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        let identity = NodeIdentity::generate();
        let cancel = CancellationToken::new();
        let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

        pm.register_f2f_friend(
            *gateway_id.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

        for i in 0u64..18 {
            pm.register_f2f_friend(
                fake_pubkey(90_000 + (s as u64) * 100 + i),
                Some(fake_addr((57001 + i) as u16)),
            )
            .await;
        }
        prepare_mature_fixture(&pm, &identity).await;
        force_stable_ge20(&pm).await;

        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(true)))
            .with_readiness_manager(prepared_readiness()),
        );

        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .expect("bind shard transport");
        transport.set_sync_ready(true);
        let addr = transport.local_addr().expect("shard local addr");
        transport.spawn_accept_loop();

        shards.push(Shard {
            identity,
            addr,
            transport,
            cancel,
            engine,
            _storage: storage,
        });
    }

    for sh in &shards {
        pm_gw
            .register_f2f_friend(*sh.identity.node_pubkey(), Some(sh.addr))
            .await;
    }
    prepare_mature_fixture(&pm_gw, &gateway_id).await;
    force_stable_ge20(&pm_gw).await;

    let sender_key = SigningKey::from_bytes(&[44u8; 32]);
    let now = test_now_ms();

    let mut counter = 0u64;
    let (target_shard_id, root_req) = loop {
        counter += 1;
        let req = make_hmc_genesis(
            &format!("lock_s01_{counter}"),
            now + 900_000,
            &sender_key,
        );
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = humoco_sim_core::types::extract_shard_id(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if rem.len() == 20
            && !comm
                .iter()
                .any(|m| m.node_pubkey == *gateway_id.node_pubkey())
        {
            break (sid, req);
        }
        if counter > 10_000 {
            panic!("Could not find shard committee outside gateway");
        }
    };

    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    for engine in std::iter::once(&gw_engine).chain(shards.iter().map(|s| &s.engine)) {
        let (verdict, _) = engine
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
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }

    use sha3::{Digest, Sha3_256};
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update(root_req.transaction_hash);
    hash.update(32u32.to_le_bytes());
    hash.update(sender_key.verifying_key().to_bytes());
    let lookup_tag = bs58::encode(hash.finalize()).into_string();
    let mut lock_req = root_req.clone();
    lock_req.is_genesis = false;
    lock_req.ds_tag = Some(lookup_tag.clone());
    lock_req.transaction_hash = [93; 32];
    lock_req.deletable_at = None;
    lock_req.layer2_signature = sender_key
        .sign(&calculate_l2_payload_hash(&lock_req))
        .to_bytes();

    let lock_entry = L2LockEntry::from(&lock_req);

    for sh in &shards {
        let (verdict, _) = sh
            .engine
            .ingress_hmc_lock_durable(
                lookup_tag.clone(),
                lock_entry.clone(),
                IngressOrigin::ClientApi,
                Some(now),
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }

    let (gw_verdict, _) = gw_engine
        .ingress_hmc_lock_durable(
            lookup_tag.clone(),
            lock_entry.clone(),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(gw_verdict, L2Verdict::Verified { .. }));

    let gw_handler = Arc::new(NodeRequestHandler::with_peer_manager(
        gw_engine.clone(),
        gw_storage.clone(),
        gateway_id.clone(),
        pm_gw.clone(),
    ));

    let gw_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &gateway_id,
        pm_gw.clone(),
        gw_handler,
        gw_cancel.clone(),
    )
    .expect("bind gateway transport");
    let gw_addr = gw_transport.local_addr().expect("gw addr");
    gw_transport.spawn_accept_loop();

    for sh in &shards {
        sh.transport
            .peer_manager()
            .register_f2f_friend(*gateway_id.node_pubkey(), Some(gw_addr))
            .await;
        gw_transport
            .connect_peer(sh.addr)
            .await
            .expect("preconnect shard");
    }

    let pow_engine = Arc::new(PowEngine::new(*gateway_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(gw_storage.clone(), pow_engine.clone()));

    let mut state = AppState::new(
        gw_engine.clone(),
        gw_storage.clone(),
        gateway_id.clone(),
        tier_controller.clone(),
        pow_engine,
    );
    state.peer_manager = Some(pm_gw.clone());
    state.transport = Some(gw_transport.clone());

    let declared_write_ema = tier_controller.current_write_ema_micro_bj();
    let declared_read_ema = tier_controller.current_read_ema_credits();
    let sender_pubkey = *gateway_id.node_pubkey();
    let root_valid_until = now + 900_000;
    let ttl_sec = 900;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_sec);
    let op_hash = lock_req.transaction_hash;
    let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) =
        tier_controller.record_declared_usage(now, footprint);
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        epoch_day,
        epoch_seq,
        now,
        declared_write_ema,
        declared_read_ema,
        footprint,
        false,
        &op_hash,
    );
    let sender_signature = gateway_id.signing_key().sign(&digest).to_bytes();
    let current_anl_24h = declared_write_ema;

    let wire_payload = bincode::serialize(&humoco_node::network::framing::LockWirePayload::Hmc {
        req: lock_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day,
        epoch_seq,
        cumulative_micro_byte_years,
        prev_day_final_bytes,
        current_anl_24h,
        declared_write_ema_micro_bj: declared_write_ema,
        declared_read_ema_credits: declared_read_ema,
        sender_pubkey,
        sender_signature,
        timestamp_ms: now,
    })
    .expect("serialize wire payload");

    assert_eq!(gw_engine.support_updates_available_for_test(), 32);
    assert!(gw_engine.is_signing_healthy());

    // 1. Hold exclusive write transaction on local RedbStorage
    let blocking_write_txn = gw_storage
        .raw_database_for_test()
        .begin_write()
        .expect("hold blocking write txn");

    // 2. Call assemble_quorum_certificate_with_deadline with a 300ms deadline
    let checkout_deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    let start = std::time::Instant::now();

    let (cert, _) = assemble_quorum_certificate_with_deadline(
        &state,
        lock_req.transaction_hash,
        *blake3::hash(lookup_tag.as_bytes()).as_bytes(),
        target_shard_id,
        now,
        Some(wire_payload),
        Some(14),
        Some(checkout_deadline),
    )
    .await;

    let elapsed = start.elapsed();

    // Must complete bounded by the deadline, not stall on the blocked write txn
    assert!(
        elapsed < Duration::from_millis(600),
        "Checkout must respect the deadline and not stall on blocked write txn! Elapsed: {elapsed:?}"
    );

    // Returns degraded status 0 and empty signatures
    assert_eq!(
        cert.status, 0,
        "Certificate status must be degraded to 0 when support was not durably admitted within deadline"
    );
    assert_eq!(
        cert.signatures.len(), 0,
        "Signatures must be cleared when support persistence fails"
    );

    // 3. Neutral cancellation & no false signing disablement
    assert!(
        gw_engine.is_signing_healthy(),
        "Timeout waiting for support persistence must NOT trip signing health latch"
    );
    assert_eq!(
        gw_engine.support_updates_available_for_test(), 31,
        "support_updates permit must remain held while background commit is blocked"
    );

    // 4. Release blocking write txn and assert eventual safe persistence
    drop(blocking_write_txn);

    tokio::time::timeout(Duration::from_secs(3), async {
        while gw_storage
            .confirmation_support(&lookup_tag)
            .unwrap()
            .is_none()
            || gw_engine.support_updates_available_for_test() < 32
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background worker must complete and persist confirmation support");

    let class = gw_engine
        .hmc_ram
        .read()
        .await
        .get_confirmation_class(&lookup_tag);
    assert!(
        class > 0,
        "RAM confirmation class must be promoted once unblocked commit completes"
    );

    assert_eq!(
        gw_engine.support_updates_available_for_test(), 32,
        "support_updates permit must be released after completion"
    );

    assert!(
        gw_engine.is_signing_healthy(),
        "Signing must remain healthy after eventual support persistence"
    );

    // Cleanup
    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}
