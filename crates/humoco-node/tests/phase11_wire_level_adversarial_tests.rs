#![forbid(unsafe_code)]

//! Phase 11: Adversarial Wire-Level Tests & 100-Node Validation (Rule 11).
//!
//! Every defense is proven over real QUIC wire connections, never via
//! in-memory unit-test illusion alone:
//! a) Quorum-Gating: missed quorum forces HTTP 503/408, never 200/201.
//! b) FINAL attestation status at N>=20 over wire.
//! c) Adversarial TLS close + forged simulator fraud-proof rejected.
//! d) Shard-digest shard-isolation over wire.
//! e) Paginated sync over wire.
//! f) 100-node HRW/quorum validation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::api::hmc::{
    calculate_l2_payload_hash, L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2Verdict,
};
use humoco_node::api::{build_router, AppState};
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::network::{
    DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport,
};
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::types::{required_quorum, LockRecord, SimTime};
use humoco_sim_core::wire::{MsgType, WireHeader};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn fake_pubkey(seed: u64) -> [u8; 32] {
    *blake3::hash(&seed.to_le_bytes()).as_bytes()
}

fn fake_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().expect("valid addr")
}

async fn response_json<T: serde::de::DeserializeOwned>(
    res: axum::response::Response,
) -> T {
    let body_bytes = res.into_body().collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&body_bytes).expect("deserialize response")
}

/// Matures a PeerManager to N>=20 FINAL-readiness: sync-ready + old ge20 anchor.
/// The caller must have populated >=19 peers beforehand so active>=20.
async fn force_stable_ge20(pm: &PeerManager) {
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

// ---------------------------------------------------------------------------
// a) Quorum-Gating Wire Test: missed quorum => 503/408, never 200/201
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_phase11a_quorum_gating_wire_returns_503_never_200_201() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(
        RedbStorage::open(&temp.path().join("p11a.redb")).expect("open redb"),
    );
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let gateway_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();
    let pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    // 6 dead F2F shard peers: authorized for direct RPC, but no QUIC
    // listener exists -> every LockVerifyRequest fanout fails fast.
    for i in 0u64..6 {
        let nid = fake_pubkey(1000 + i);
        pm.register_f2f_friend(nid, Some(fake_addr(59901 + i as u16))).await;
    }
    // N = 1 + 6 = 7 => Q(7) = floor(14/3)+1 = 5. Self alone can never reach it.
    let total = pm.active_nodes_count();
    assert_eq!(total, 7, "gateway must see N=7 active nodes");
    let (required_q, is_final) = required_quorum(total);
    assert_eq!(required_q, 5);
    assert!(!is_final);

    let handler = Arc::new(NodeRequestHandler::with_peer_manager(
        engine.clone(),
        storage.clone(),
        gateway_id.clone(),
        pm.clone(),
    ));
    let transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &gateway_id,
        pm.clone(),
        handler,
        cancel.clone(),
    )
    .expect("bind gateway");
    transport.spawn_accept_loop();

    let pow_engine = Arc::new(PowEngine::new(*gateway_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
    tier_controller.register_f2f_peer("phase11_friend_token");

    let mut state = AppState::new(
        engine,
        storage,
        gateway_id,
        tier_controller,
        pow_engine,
    );
    state.peer_manager = Some(pm);
    state.transport = Some(transport.clone());
    let app = build_router(state);

    let sender_key = SigningKey::from_bytes(&[7u8; 32]);
    let now = test_now_ms();
    let lock_req = make_hmc_genesis(&"ab".repeat(32), now + 600_000, &sender_key);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "phase11_friend_token")
        .body(Body::from(serde_json::to_vec(&lock_req).expect("serialize")))
        .expect("request");
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::REQUEST_TIMEOUT,
        "quorum miss over wire must yield 503/408, got {status}"
    );
    assert!(
        status != StatusCode::OK && status != StatusCode::CREATED,
        "quorum miss must NEVER yield 200/201, got {status}"
    );
    // Body must explain the missed quorum.
    let envelope: L2ResponseEnvelope = response_json(resp).await;
    assert!(
        matches!(envelope.verdict, L2Verdict::Rejected { .. }),
        "quorum miss must carry Rejected verdict"
    );

    cancel.cancel();
    transport.close();
}

// ---------------------------------------------------------------------------
// b) FINAL attestation status at N>=20 over real QUIC wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_phase11b_final_attestation_status_wire_n_ge_20() {
    const NUM_REAL_SHARDS: usize = 16;
    const NUM_FAKE_GW: u64 = 3;

    let gw_temp = tempdir().expect("tempdir");
    let gw_storage = Arc::new(
        RedbStorage::open(&gw_temp.path().join("p11b_gw.redb")).expect("open redb"),
    );
    let (gw_engine, _gw_worker) = DualTierEngine::new(gw_storage.clone());
    let gateway_id = NodeIdentity::generate();
    let gw_cancel = CancellationToken::new();
    let pm_gw = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    struct ShardNode {
        identity: NodeIdentity,
        addr: SocketAddr,
        transport: QuicTransport,
        cancel: CancellationToken,
        _storage: Arc<RedbStorage>,
    }
    let mut shards: Vec<ShardNode> = Vec::new();

    for s in 0..NUM_REAL_SHARDS {
        let tmp = tempdir().expect("tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("p11b_shard{s}.redb")))
                .expect("open redb"),
        );
        // Keep tempdir alive via leaked path: storage file already created,
        // engine holds no dir handle, so we leak tmp intentionally for test.
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
        // +18 dead F2F fillers => N = 1 + 1 + 18 = 20 (always responsible).
        for i in 0u64..18 {
            pm.register_f2f_friend(
                fake_pubkey(50_000 + (s as u64) * 100 + i),
                Some(fake_addr((54001 + i) as u16)),
            )
            .await;
        }
        assert_eq!(pm.active_nodes_count(), 20);
        force_stable_ge20(&pm).await;

        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine,
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(true))),
        );
        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .expect("bind shard");
        transport.set_sync_ready(true);
        let addr = transport.local_addr().expect("local addr");
        transport.spawn_accept_loop();
        shards.push(ShardNode {
            identity,
            addr,
            transport,
            cancel,
            _storage: storage,
        });
    }

    // Gateway learns all real shards as F2F friends + 6 dead fillers => N=20.
    for sh in &shards {
        pm_gw
            .register_f2f_friend(*sh.identity.node_pubkey(), Some(sh.addr))
            .await;
    }
    for i in 0u64..NUM_FAKE_GW {
        pm_gw
            .register_f2f_friend(fake_pubkey(90_000 + i), Some(fake_addr((59101 + i) as u16)))
            .await;
    }
    assert_eq!(pm_gw.active_nodes_count(), 20);
    force_stable_ge20(&pm_gw).await;

    // Fix gateway-side stored friend addrs (shards registered gateway with a
    // dummy addr above; refresh to real gateway addr after bind below).
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
    .expect("bind gateway");
    let gw_addr = gw_transport.local_addr().expect("gw addr");
    gw_transport.spawn_accept_loop();
    for sh in &shards {
        sh.transport
            .peer_manager()
            .register_f2f_friend(*gateway_id.node_pubkey(), Some(gw_addr))
            .await;
    }

    let pow_engine = Arc::new(PowEngine::new(*gateway_id.node_id(), 8));
    let tier_controller = Arc::new(TierController::new(
        gw_storage.clone(),
        pow_engine.clone(),
    ));
    tier_controller.register_f2f_peer("phase11b_token");
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

    let sender_key = SigningKey::from_bytes(&[11u8; 32]);
    let now = test_now_ms();
    let lock_req = make_hmc_genesis(&"cd".repeat(32), now + 900_000, &sender_key);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("x-peer-token", "phase11b_token")
        .body(Body::from(serde_json::to_vec(&lock_req).expect("serialize")))
        .expect("request");
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "FINAL quorum over wire must yield 200/201, got {status}"
    );
    let envelope: L2ResponseEnvelope = response_json(resp).await;
    let cert = envelope
        .quorum_certificate
        .expect("FINAL path must attach quorum certificate");
    assert!(
        cert.is_quorum_reached(),
        "certificate must reach quorum: {}/{}",
        cert.signatures.len(),
        cert.required_quorum()
    );
    assert_eq!(
        cert.status, 1,
        "N>=20 stable network must certify status FINAL (1)"
    );
    assert!(
        cert.signatures.len() >= 14,
        "N>=20 requires 14/20 signatures, got {}",
        cert.signatures.len()
    );
    // Every collected FINAL attestation must verify under DOMAIN_APPROVE_FINAL.
    for att in &cert.signatures {
        assert!(!att.signature.is_empty());
        assert!(!att.lock_id.is_empty());
    }
    // Cryptographic proof: each attestation verifies under FINAL domain
    // (shards really signed status 1, gateway really accepted it).
    {
        use ed25519_dalek::Signature;
        fn decode32(s: &str) -> [u8; 32] {
            let v = hex::decode(s).expect("hex");
            assert_eq!(v.len(), 32, "expected 32 bytes");
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        }
        let lock_id = decode32(&cert.lock_id);
        for att in &cert.signatures {
            let sig_bytes = hex::decode(&att.signature).expect("sig hex");
            assert_eq!(sig_bytes.len(), 64);
            let sig = Signature::from_bytes(
                sig_bytes.as_slice().try_into().expect("64 bytes"),
            );
            let att_lock = decode32(&att.lock_id);
            assert_eq!(att_lock, lock_id, "quorum lock_id must match");
            let vk = if att.node_id == gateway_id.node_id_u16() {
                *gateway_id.verifying_key()
            } else {
                pm_gw
                    .get_peer_verifying_key(att.node_id)
                    .await
                    .expect("verifying key for FINAL signer")
            };
            let digest = humoco_sim_core::crypto::compute_sig_digest(
                humoco_sim_core::crypto::domain_approve_final(
                    humoco_sim_core::types::NetworkId::Mainnet,
                ),
                0,
                0,
                0,
                cert.shard_id,
                1,
                &lock_id,
            );
            vk.verify_strict(&digest, &sig).expect("FINAL attestation signature must verify");
        }
    }

    gw_cancel.cancel();
    gw_transport.close();
    for sh in &shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}

// ---------------------------------------------------------------------------
// c) Adversarial TLS close + forged simulator fraud-proof rejected (wire)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_phase11c_adversarial_tls_close_and_fake_fraud_rejected_wire() {
    // ---- c1: unauthorized QUIC connection is actively closed ----
    let server_id = NodeIdentity::generate();
    let server_cancel = CancellationToken::new();
    let pm_server = Arc::new(PeerManager::new(Vec::new()));
    let temp_s = tempdir().expect("tempdir");
    let storage_s = Arc::new(
        RedbStorage::open(&temp_s.path().join("p11c.redb")).expect("open redb"),
    );
    let (engine_s, _worker_s) = DualTierEngine::new(storage_s.clone());
    let handler_s = Arc::new(NodeRequestHandler::with_peer_manager(
        engine_s.clone(),
        storage_s.clone(),
        server_id.clone(),
        pm_server.clone(),
    ));
    let transport_s = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &server_id,
        pm_server.clone(),
        handler_s,
        server_cancel.clone(),
    )
    .expect("bind server");
    let server_addr = transport_s.local_addr().expect("addr");
    transport_s.spawn_accept_loop();

    let stranger_id = NodeIdentity::generate();
    let stranger_cancel = CancellationToken::new();
    let pm_stranger = Arc::new(PeerManager::new(Vec::new()));
    let transport_stranger = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &stranger_id,
        pm_stranger,
        Arc::new(DefaultRequestHandler),
        stranger_cancel.clone(),
    )
    .expect("bind stranger");
    transport_stranger.spawn_accept_loop();

    let conn = transport_stranger
        .connect_peer_unchecked(server_addr)
        .await
        .expect("unchecked connect");
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    // Unauthorized digest request: either per-stream rejection or closed conn.
    let digest_hdr = WireHeader::new(MsgType::ShardDigestRequest as u16, 1, 0, 0, 2);
    let probe = transport_stranger
        .send_request(&conn, &digest_hdr, &0u16.to_le_bytes())
        .await;
    if let Ok((resp_hdr, resp_payload)) = probe {
        assert_eq!(resp_hdr.msg_type, MsgType::StatusResponse as u16);
        assert_eq!(&resp_payload, b"unauthorized");
    }
    assert!(
        conn.close_reason().is_some(),
        "unauthorized QUIC connection must be actively closed by server"
    );

    // ---- c2: forged SIMULATOR fraud-proof over wire must NOT ban victim ----
    let victim_id = NodeIdentity::generate();
    let victim_pubkey = *victim_id.node_pubkey();
    let victim_u16 = u16::from_le_bytes([victim_pubkey[0], victim_pubkey[1]]);

    // Simulator (BLAKE3) attestations, valid in sim-core but NOT Ed25519.
    let parent = [0x77u8; 32];
    let lock_a = [0xAAu8; 32];
    let lock_b = [0xBBu8; 32];
    let att_a = humoco_sim_core::crypto::sign_lock_attestation(
        victim_u16,
        &lock_a,
        &parent,
        SimTime(1_000),
    );
    let att_b = humoco_sim_core::crypto::sign_lock_attestation(
        victim_u16,
        &lock_b,
        &parent,
        SimTime(2_000),
    );
    let mut forged =
        humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation(att_a, att_b);
    // Frame the real victim pubkey as perpetrator.
    forged.perpetrator_node_id = victim_pubkey;
    forged.perpetrator = victim_u16;
    // Sanity: simulator fallback verifies, strict Ed25519 does not.
    assert!(
        forged.verify(),
        "forged simulator proof must pass sim fallback (test setup)"
    );
    let strict_ok = humoco_node::network::transport::verify_equivocation_first_party(
        victim_id.verifying_key(),
        &forged,
    );
    assert!(
        !strict_ok,
        "forged simulator proof must FAIL strict Ed25519 first-party check"
    );

    // Authorize stranger for the fraud-proof RPC (else closed before handling).
    pm_server
        .learn_node_from_gossip(
            *stranger_id.node_id(),
            transport_stranger.local_addr().expect("stranger addr"),
            0,
            None,
        )
        .await;
    let conn2 = transport_stranger
        .connect_peer_unchecked(server_addr)
        .await
        .expect("reconnect");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let payload = bincode::serialize(&forged).expect("serialize proof");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        7,
        0,
        0,
        payload.len() as u32,
    );
    let (resp_hdr, _) = transport_stranger
        .send_request(&conn2, &hdr, &payload)
        .await
        .expect("send forged proof");
    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    assert!(
        !engine_s.is_node_banned(&victim_pubkey).await,
        "VICTIM MUST NOT be banned by forged simulator fraud-proof (anti-framing)"
    );
    assert!(
        !pm_server.is_banned(&victim_pubkey).await,
        "VICTIM MUST NOT be banned in PeerManager by forged proof"
    );

    server_cancel.cancel();
    stranger_cancel.cancel();
    transport_s.close();
    transport_stranger.close();
}

// ---------------------------------------------------------------------------
// d) Shard-digest shard-isolation over wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_phase11d_shard_digest_isolation_wire() {
    const SHARD_SAME: u16 = 0x1234;
    const SHARD_OTHER: u16 = 0x5678;

    async fn spawn_with_locks(
        same_count: usize,
        other_count: usize,
        other_seed: u8,
        now_ms: u64,
    ) -> (
        NodeIdentity,
        SocketAddr,
        QuicTransport,
        CancellationToken,
        Arc<PeerManager>,
        Arc<RedbStorage>,
    ) {
        let tmp = tempdir().expect("tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join("p11d.redb")).expect("open redb"),
        );
        std::mem::forget(tmp);
        let (engine, _worker) = DualTierEngine::new(storage.clone());
        // Identical locks for SHARD_SAME on both nodes.
        for i in 0..same_count {
            let mut parent = [0u8; 32];
            parent[0..2].copy_from_slice(&SHARD_SAME.to_be_bytes());
            parent[2..6].copy_from_slice(&(i as u32).to_be_bytes());
            parent[6] = 0xD1;
            let rec = LockRecord::new(
                parent,
                [0xA5; 32],
                vec![i as u8],
                SimTime(now_ms),
                SimTime(now_ms + 50_000_000),
            );
            let _ = engine
                .ingress_lock_with_origin(
                    rec,
                    SimTime(now_ms),
                    SimTime(now_ms + 50_000_000),
                    IngressOrigin::ClientApi,
                )
                .await;
        }
        // Divergent locks for SHARD_OTHER.
        for i in 0..other_count {
            let mut parent = [0u8; 32];
            parent[0..2].copy_from_slice(&SHARD_OTHER.to_be_bytes());
            parent[2..6].copy_from_slice(&(i as u32).to_be_bytes());
            parent[6] = other_seed;
            parent[7] = other_seed;
            let rec = LockRecord::new(
                parent,
                [other_seed; 32],
                vec![other_seed, i as u8],
                SimTime(now_ms),
                SimTime(now_ms + 50_000_000),
            );
            let _ = engine
                .ingress_lock_with_origin(
                    rec,
                    SimTime(now_ms),
                    SimTime(now_ms + 50_000_000),
                    IngressOrigin::ClientApi,
                )
                .await;
        }

        let identity = NodeIdentity::generate();
        let client_tmp_id = NodeIdentity::generate();
        let pm = Arc::new(PeerManager::with_f2f(
            Vec::new(),
            vec![*client_tmp_id.node_id()],
        ));
        let cancel = CancellationToken::new();
        let handler = Arc::new(NodeRequestHandler::with_peer_manager(
            engine,
            storage.clone(),
            identity.clone(),
            pm.clone(),
        ));
        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .expect("bind");
        let addr = transport.local_addr().expect("addr");
        transport.spawn_accept_loop();
        (identity, addr, transport, cancel, pm, storage)
    }

    let shared_now_ms = test_now_ms();
    let (id_a, addr_a, t_a, c_a, pm_a, _s_a) = spawn_with_locks(5, 3, 0x0A, shared_now_ms).await;
    let (id_b, addr_b, t_b, c_b, pm_b, _s_b) = spawn_with_locks(5, 7, 0x0B, shared_now_ms).await;

    // One client talks to both shards over real QUIC wire.
    let client_id = NodeIdentity::generate();
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*id_a.node_id(), *id_b.node_id()],
    ));
    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("bind client");
    let client_addr = client.local_addr().expect("client addr");
    client.spawn_accept_loop();
    pm_a
        .register_f2f_friend(*client_id.node_id(), Some(client_addr))
        .await;
    pm_b
        .register_f2f_friend(*client_id.node_id(), Some(client_addr))
        .await;
    pm_client.register_f2f_friend(*id_a.node_id(), Some(addr_a)).await;
    pm_client.register_f2f_friend(*id_b.node_id(), Some(addr_b)).await;

    let conn_a = client.connect_peer(addr_a).await.expect("connect A");
    let conn_b = client.connect_peer(addr_b).await.expect("connect B");

    let (digest_a, count_a) = client
        .request_shard_digest(&conn_a, SHARD_SAME, 1)
        .await
        .expect("digest A same");
    let (digest_b, count_b) = client
        .request_shard_digest(&conn_b, SHARD_SAME, 1)
        .await
        .expect("digest B same");
    assert_eq!(count_a, 5);
    assert_eq!(count_b, 5);
    assert_eq!(
        digest_a, digest_b,
        "identical shard data must yield identical digests despite foreign data elsewhere"
    );

    let (digest_oa, count_oa) = client
        .request_shard_digest(&conn_a, SHARD_OTHER, 2)
        .await
        .expect("digest A other");
    let (digest_ob, count_ob) = client
        .request_shard_digest(&conn_b, SHARD_OTHER, 3)
        .await
        .expect("digest B other");
    assert_eq!(count_oa, 3);
    assert_eq!(count_ob, 7);
    assert_ne!(
        digest_oa, digest_ob,
        "divergent foreign shards must yield divergent digests"
    );

    c_a.cancel();
    c_b.cancel();
    t_a.close();
    t_b.close();
    client.close();
}

// ---------------------------------------------------------------------------
// e) Paginated sync over wire is reliable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_phase11e_paginated_sync_wire_reliable() {
    const TOTAL: usize = 600;
    const PAGE: usize = 100;

    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(
        RedbStorage::open(&temp.path().join("p11e.redb")).expect("open redb"),
    );
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let now = SimTime(1_000);
    let root_valid = SimTime(1_000_000);
    for i in 0..TOTAL as u32 {
        let mut parent = [0u8; 32];
        parent[0] = 0x02;
        parent[2..6].copy_from_slice(&i.to_be_bytes());
        let rec = LockRecord::new(parent, [0xAA; 32], i.to_le_bytes().to_vec(), now, SimTime(500_000));
        let _ = engine
            .ingress_lock_with_origin(rec, now, root_valid, IngressOrigin::ClientApi)
            .await;
    }

    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();
    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*client_id.node_id()],
    ));
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_id()],
    ));
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine,
            storage,
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );
    let server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &server_id,
        pm_server.clone(),
        handler,
        cancel.clone(),
    )
    .expect("bind server");
    server.set_sync_ready(true);
    let server_addr = server.local_addr().expect("addr");
    server.spawn_accept_loop();

    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("bind client");
    let client_addr = client.local_addr().expect("client addr");
    client.spawn_accept_loop();
    pm_server
        .register_f2f_friend(*client_id.node_id(), Some(client_addr))
        .await;
    pm_client
        .register_f2f_friend(*server_id.node_id(), Some(server_addr))
        .await;

    let conn = client.connect_peer(server_addr).await.expect("connect");

    let mut all = Vec::new();
    let mut cursor = 0u64;
    let mut seq = 1u64;
    let mut pages = 0usize;
    let mut prev_cursor = 0u64;
    loop {
        let page = client
            .request_active_sync_page(&conn, seq, cursor, PAGE)
            .await
            .expect("sync page over wire");
        seq = seq.wrapping_add(1);
        pages += 1;
        assert!(
            page.payload.locks.len() <= PAGE,
            "wire page must respect limit"
        );
        all.extend(page.payload.locks);
        if !page.has_more {
            assert!(
                page.next_cursor.is_none(),
                "terminal page must carry no cursor"
            );
            break;
        }
        let next = page.next_cursor.expect("has_more requires next_cursor");
        assert!(next > prev_cursor, "wire cursors must advance monotonically");
        prev_cursor = next;
        cursor = next;
        assert!(pages < 50, "sync must terminate");
    }
    assert_eq!(all.len(), TOTAL, "paginated wire sync must deliver every lock");
    // No duplicates: parent_lock is the unique key.
    let mut seen = std::collections::HashSet::new();
    for (rec, _) in &all {
        assert!(seen.insert(rec.parent_lock), "duplicate lock in wire sync");
    }
    assert_eq!(pages, TOTAL / PAGE, "600 locks at limit 100 => 6 pages");

    // Full-sync convenience helper must agree.
    let conn2 = client.connect_peer(server_addr).await.expect("connect2");
    let full = client
        .request_active_sync(&conn2, 9000)
        .await
        .expect("full sync");
    assert_eq!(full.locks.len(), TOTAL);

    cancel.cancel();
    server.close();
    client.close();
}

// ---------------------------------------------------------------------------
// f) 100-node validation: HRW quorum math + wire spot-check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_phase11f_100_node_hrw_quorum_validation() {
    // Pure-math 100-node mesh.
    let pm = Arc::new(PeerManager::new(Vec::new()));
    pm.set_local_sync_ready(true);
    for i in 0u64..100 {
        let nid = fake_pubkey(777_000 + i);
        let addr: SocketAddr = format!("10.11.0.{}:9090", (i % 253) + 1)
            .parse()
            .expect("addr");
        pm.learn_node_from_gossip(nid, addr, 1, None).await;
        pm.set_first_seen_for_test(
            &nid,
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    }
    // 5 fresh immature newcomers must NOT inflate N.
    for i in 0u64..5 {
        let nid = fake_pubkey(999_000 + i);
        let addr: SocketAddr = format!("10.12.0.{}:9090", i + 1).parse().expect("addr");
        pm.learn_node_from_gossip(nid, addr, 1, None).await;
    }
    assert_eq!(
        pm.active_nodes_count(),
        101,
        "100 mature + self; 5 immature excluded"
    );
    let (q100, is_final_100) = required_quorum(101);
    assert_eq!(q100, 14);
    assert!(is_final_100);
    assert_eq!(required_quorum(100).0, 14);
    assert_eq!(required_quorum(19).0, 13);
    assert_eq!(required_quorum(7).0, 5);

    // HRW top-20 ranking is deterministic across calls.
    let shard: u16 = 0x2A2A;
    let top1 = pm.get_top_n_shards_for_lock(shard, 20).await;
    let top2 = pm.get_top_n_shards_for_lock(shard, 20).await;
    assert_eq!(top1.len(), 20);
    assert_eq!(top1, top2, "HRW ranking must be deterministic");
    // Different shards rank differently (sanity against degenerate scoring).
    let top_other = pm.get_top_n_shards_for_lock(0x7B7B, 20).await;
    assert_eq!(top_other.len(), 20);
    assert_ne!(top1, top_other, "distinct shards must rank differently");

    // Wire spot-check inside the 100-node world: digest pull still works.
    let tmp = tempdir().expect("tempdir");
    let storage = Arc::new(
        RedbStorage::open(&tmp.path().join("p11f.redb")).expect("open redb"),
    );
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*client_id.node_id()],
    ));
    let pm_client = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_id()],
    ));
    let handler = Arc::new(NodeRequestHandler::with_peer_manager(
        engine,
        storage,
        server_id.clone(),
        pm_server.clone(),
    ));
    let server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &server_id,
        pm_server.clone(),
        handler,
        CancellationToken::new(),
    )
    .expect("bind");
    let server_addr = server.local_addr().expect("addr");
    server.spawn_accept_loop();
    let client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        CancellationToken::new(),
    )
    .expect("bind client");
    let client_addr = client.local_addr().expect("client addr");
    client.spawn_accept_loop();
    pm_server
        .register_f2f_friend(*client_id.node_id(), Some(client_addr))
        .await;
    pm_client
        .register_f2f_friend(*server_id.node_id(), Some(server_addr))
        .await;
    let conn = client.connect_peer(server_addr).await.expect("connect");
    let (digest, count) = client
        .request_shard_digest(&conn, shard, 42)
        .await
        .expect("spot digest");
    assert_eq!(count, 0, "empty shard must report zero locks");
    assert_eq!(digest, humoco_sim_core::crypto::compute_shard_digest(shard, &[]));

    // Quorum liveness math: 14/20 FINAL fast-exit leaves 6 straggler budget.
    assert!(
        14 <= top1.len(),
        "top-20 must cover the 14/20 FINAL quorum"
    );
    let _ = Ordering::SeqCst;
    server.close();
    client.close();
}
