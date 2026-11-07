//! Regression tests for Slice S01 (S01-09, S01-10, S01-11).
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use ed25519_dalek::Signer;
use sha3::{Digest, Sha3_256};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::{
    api::{build_router, hmc::*, routes::AppState},
    daemon::ShardReadinessManager,
    identity::NodeIdentity,
    ingress::{PowEngine, TierController},
    network::{
        framing::LockWirePayload, DefaultRequestHandler, NodeRequestHandler, PeerManager,
        QuicTransport,
    },
    storage::{DualTierEngine, IngressOrigin, RedbStorage},
};
use humoco_sim_core::quota::ByteYears;
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_UNAUTHORIZED};

fn prepared_readiness() -> Arc<ShardReadinessManager> {
    let readiness = Arc::new(ShardReadinessManager::new());
    for shard in 0..=u16::MAX {
        readiness.mark_shard_ready(shard);
    }
    readiness
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

async fn prepare_mature_fixture(pm: &PeerManager, local: &NodeIdentity) {
    pm.set_simulation_mode(true);
    for peer in pm.list_peers().await {
        if let Some(key) = peer.node_id {
            let ticket = pm.get_hrw_routing_id(&key).await.unwrap_or(key);
            pm.learn_node_from_gossip_with_hrw(key, ticket, peer.addr, 0, None)
                .await;
            pm.set_first_seen_for_test(
                &key,
                std::time::Instant::now() - Duration::from_secs(25 * 3600),
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
        std::time::Instant::now() - Duration::from_secs(25 * 3600),
    )
    .await;
}

fn build_hop(
    key: &NodeIdentity,
    voucher: &str,
    id: u8,
    prev: Option<[u8; 32]>,
    now: u64,
) -> L2LockRequest {
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: *key.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: voucher.into(),
        ds_tag: prev.map(|p| {
            let mut h = Sha3_256::new();
            h.update(32u32.to_le_bytes());
            h.update(p);
            h.update(32u32.to_le_bytes());
            h.update(key.node_pubkey());
            bs58::encode(h.finalize()).into_string()
        }),
        transaction_hash: [id; 32],
        is_genesis: prev.is_none(),
        sender_ephemeral_pub: *key.node_pubkey(),
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: u128::from(id),
        created_at_ms: now,
        deletable_at: prev.is_none().then(|| (now + 600_000).to_string()),
        privacy_guard: None,
    };
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher.into(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: *key.node_pubkey(),
        receiver_pubkey_hash: Some(Sha3_256::digest(key.node_pubkey()).into()),
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: req.is_genesis,
        signature: [0; 64],
    };
    proof.signature = key.signing_key().sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = key
        .signing_key()
        .sign(&calculate_l2_payload_hash(&req))
        .to_bytes();
    req
}

// ============================================================================
// S01-11: Valid prefix retained when suffix contains invalid genesis root TTL
// ============================================================================

#[tokio::test]
async fn test_s01_11_http_and_quic_bad_suffix_genesis_retains_valid_prefix() {
    let now = test_now_ms();
    let voucher = "s01-11-voucher";
    let key = NodeIdentity::generate();

    let root_hop = build_hop(&key, voucher, 1, None, now);
    let spend_hop = build_hop(&key, voucher, 2, Some(root_hop.transaction_hash), now);

    // Hop 3 is an invalid later genesis without TTL and no ds_tag
    let mut invalid_hop = build_hop(&key, voucher, 3, None, now);
    invalid_hop.is_genesis = true;
    invalid_hop.ds_tag = None;
    invalid_hop.deletable_at = None; // Missing root TTL
    invalid_hop.causal_output = None;
    invalid_hop.layer2_signature = key
        .signing_key()
        .sign(&calculate_l2_payload_hash(&invalid_hop))
        .to_bytes();

    let chain_req = L2ChainLockRequest {
        auth: root_hop.auth.clone(),
        layer2_voucher_id: voucher.into(),
        chain: vec![root_hop.clone(), spend_hop.clone(), invalid_hop.clone()],
    };

    // ------------------------------------------------------------------------
    // (a) HTTP Test
    // ------------------------------------------------------------------------
    let dir_http = tempdir().unwrap();
    let db_path_http = dir_http.path().join("node_http.redb");
    {
        let db = Arc::new(RedbStorage::open(&db_path_http).unwrap());
        let cancel = CancellationToken::new();
        let (engine, _worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
        let id = NodeIdentity::generate();
        let pow = Arc::new(PowEngine::new(*id.node_id(), 8));
        let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));
        tiers.register_f2f_peer("f2f_s01_11");
        let state = AppState::new(engine.clone(), db.clone(), id.clone(), tiers, pow);

        let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
            &bs58::encode(root_hop.transaction_hash).into_string(),
        );
        state
            .readiness_manager
            .mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&parent));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.unwrap();
        });

        let res = reqwest::Client::new()
            .post(format!("http://{addr}/v1/lock/chain"))
            .header("X-Peer-Token", "f2f_s01_11")
            .json(&chain_req)
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
        let envelope: L2ResponseEnvelope = res.json().await.unwrap();
        assert!(
            matches!(envelope.verdict, L2Verdict::Rejected { ref reason } if reason.contains("step 2")),
            "Verdict must reject at step 2, got: {:?}",
            envelope.verdict
        );

        // Assert valid prefix was committed to RAM and redb
        let root_anchor = db.voucher_root(voucher).unwrap();
        assert!(root_anchor.is_some(), "Root anchor must be durably committed in redb");
        assert_eq!(root_anchor.unwrap().t_id, root_hop.transaction_hash);

        let spend_tag = spend_hop.ds_tag.as_ref().unwrap();
        let spend_lock = db.get_hmc_lock(spend_tag).unwrap();
        assert!(spend_lock.is_some(), "Valid spend hop 1 must be durably committed in redb");
        assert_eq!(spend_lock.unwrap().t_id, spend_hop.transaction_hash);

        // RAM verification
        assert!(engine.get_hmc_ram_lock(spend_tag).await.is_some());

        cancel.cancel();
        let _ = _worker.await;
        server.abort();
        let _ = server.await;
        drop(engine);
        drop(db);
    }

    // Reopen and verify prefix survives restart
    {
        let db_reopened = RedbStorage::open(&db_path_http).unwrap();
        let root_anchor = db_reopened.voucher_root(voucher).unwrap();
        assert!(root_anchor.is_some(), "Root anchor must survive database reopen");
        let spend_tag = spend_hop.ds_tag.as_ref().unwrap();
        let spend_lock = db_reopened.get_hmc_lock(spend_tag).unwrap();
        assert!(spend_lock.is_some(), "Spend lock must survive database reopen");
    }

    // ------------------------------------------------------------------------
    // (b) Real QUIC Wire Test
    // ------------------------------------------------------------------------
    let dir_quic = tempdir().unwrap();
    let db_path_quic = dir_quic.path().join("node_quic.redb");
    {
        let db = Arc::new(RedbStorage::open(&db_path_quic).unwrap());
        let cancel = CancellationToken::new();
        let (engine, _worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
        let server_id = NodeIdentity::generate();
        let client_id = NodeIdentity::generate();
        let server_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*client_id.node_pubkey()]));
        let client_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*server_id.node_pubkey()]));

        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(
                &bs58::encode(root_hop.transaction_hash).into_string(),
            ),
        );
        let ready = Arc::new(ShardReadinessManager::new());
        ready.mark_shard_ready(shard);

        let handler = Arc::new(
            NodeRequestHandler::new(engine.clone(), db.clone(), server_id.clone())
                .with_readiness_manager(ready),
        );
        let server_net = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &server_id,
            server_pm.clone(),
            handler,
            cancel.clone(),
        )
        .unwrap();
        let client_net = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &client_id,
            client_pm.clone(),
            Arc::new(DefaultRequestHandler),
            cancel.clone(),
        )
        .unwrap();

        server_pm
            .register_f2f_friend(*client_id.node_pubkey(), Some(client_net.local_addr().unwrap()))
            .await;
        client_pm
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_net.local_addr().unwrap()))
            .await;
        server_net.spawn_accept_loop();
        client_net.spawn_accept_loop();

        let conn = client_net
            .connect_peer(server_net.local_addr().unwrap())
            .await
            .unwrap();

        let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600) * 3;
        let last = chain_req.chain.last().unwrap().clone();
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            client_id.node_pubkey(),
            0,
            0,
            now,
            0,
            0,
            footprint,
            false,
            &last.transaction_hash,
        );
        let wire = LockWirePayload::Hmc {
            req: last,
            chain: Some(chain_req.clone()),
            root_valid_until: now + 600_000,
            epoch_day: 0,
            epoch_seq: 0,
            cumulative_micro_byte_years: 0,
            prev_day_final_bytes: 0,
            current_anl_24h: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            sender_pubkey: *client_id.node_pubkey(),
            sender_signature: client_id.signing_key().sign(&digest).to_bytes(),
            timestamp_ms: now,
        };
        let bytes = bincode::serialize(&wire).unwrap();
        let header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            0,
            0,
            bytes.len() as u32,
        );
        let (reply, body) = client_net
            .send_request(&conn, &header, &bytes)
            .await
            .unwrap();
        assert_ne!(reply.flags & FLAG_UNAUTHORIZED, 0);
        let verdict: L2Verdict = serde_json::from_slice(&body).unwrap();
        assert!(
            matches!(verdict, L2Verdict::Rejected { ref reason } if reason.contains("step 2")),
            "QUIC verdict: {:?}",
            verdict
        );

        // Assert valid prefix committed in redb
        let root_anchor = db.voucher_root(voucher).unwrap();
        assert!(root_anchor.is_some(), "QUIC root anchor must be committed");
        let spend_tag = spend_hop.ds_tag.as_ref().unwrap();
        assert!(db.get_hmc_lock(spend_tag).unwrap().is_some(), "QUIC spend must be committed");

        cancel.cancel();
        let _ = _worker.await;
        drop(server_net);
        drop(client_net);
        drop(engine);
        drop(db);
    }

    // Reopen and verify prefix survives restart
    {
        let db_reopened = RedbStorage::open(&db_path_quic).unwrap();
        assert!(db_reopened.voucher_root(voucher).unwrap().is_some());
        let spend_tag = spend_hop.ds_tag.as_ref().unwrap();
        assert!(db_reopened.get_hmc_lock(spend_tag).unwrap().is_some());
    }
}

// ============================================================================
// S01-10: Complete identical chain retries must NOT re-charge VIP Byte-Years
// ============================================================================

#[tokio::test]
async fn test_s01_10_vip_chain_retry_storage_not_recharged() {
    let now = test_now_ms();
    let voucher = "s01-10-vip-voucher";
    let key = NodeIdentity::generate();

    let root_hop = build_hop(&key, voucher, 10, None, now);
    let spend_1 = build_hop(&key, voucher, 11, Some(root_hop.transaction_hash), now);
    let spend_2 = build_hop(&key, voucher, 12, Some(spend_1.transaction_hash), now);

    let chain_initial = L2ChainLockRequest {
        auth: root_hop.auth.clone(),
        layer2_voucher_id: voucher.into(),
        chain: vec![root_hop.clone(), spend_1.clone()],
    };

    let dir = tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("vip_test.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, _worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let id = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*id.node_id(), 8));
    let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));

    // Provision VIP account
    let account_tag = [0x55u8; 32];
    let tag_hex = hex::encode(account_tag);
    let vip_token = format!("vip_{tag_hex}");
    tiers.register_vip_token(&vip_token, account_tag);

    // Calculate required Byte-Years for chain_initial (2 hops)
    let root_valid_until = now + 600_000;
    let ttl_seconds = root_valid_until.saturating_sub(now) / 1000;
    let required_bj = ByteYears::from_ttl_seconds(ttl_seconds);

    // Top up VIP quota with EXACTLY required_bj (sufficient for exactly one chain write)
    tiers.topup_vip_quota(account_tag, required_bj).unwrap();
    assert_eq!(tiers.get_cached_vip_quota(&account_tag), Some(required_bj));

    let state = AppState::new(engine.clone(), db.clone(), id.clone(), tiers.clone(), pow);
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
        &bs58::encode(root_hop.transaction_hash).into_string(),
    );
    state
        .readiness_manager
        .mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&parent));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });

    let client = reqwest::Client::new();

    // 1. First call: consumes the exact storage balance -> returns 201 Created
    let res1 = client
        .post(format!("http://{addr}/v1/lock/chain"))
        .header("Authorization", format!("Bearer {vip_token}"))
        .json(&chain_initial)
        .send()
        .await
        .unwrap();

    assert_eq!(res1.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        tiers.get_cached_vip_quota(&account_tag),
        Some(0),
        "Storage balance must be 0 after initial chain write"
    );

    // 2. Identical retry: MUST NOT recharge storage -> returns 200 OK!
    let res2 = client
        .post(format!("http://{addr}/v1/lock/chain"))
        .header("Authorization", format!("Bearer {vip_token}"))
        .json(&chain_initial)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res2.status(),
        reqwest::StatusCode::OK,
        "Identical chain retry must return 200 OK without re-charging Byte-Years storage"
    );

    // 3. Retry with invalid VIP credentials -> rejected with 401 Unauthorized
    let res_bad_auth = client
        .post(format!("http://{addr}/v1/lock/chain"))
        .header("Authorization", "Bearer invalid_vip_token")
        .json(&chain_initial)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_bad_auth.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Retry with invalid VIP credentials must be rejected with 401"
    );

    // 4. Partially new chain [root, spend1, spend2] with balance = 0 -> must NOT be treated as complete retry, returns 429
    let chain_extended = L2ChainLockRequest {
        auth: root_hop.auth.clone(),
        layer2_voucher_id: voucher.into(),
        chain: vec![root_hop.clone(), spend_1.clone(), spend_2.clone()],
    };

    let res_ext = client
        .post(format!("http://{addr}/v1/lock/chain"))
        .header("Authorization", format!("Bearer {vip_token}"))
        .json(&chain_extended)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_ext.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "Partially new chain must charge storage and reject with 429 when balance is exhausted"
    );

    cancel.cancel();
}

// ============================================================================
// S01-09: Quorum fast-exit and parallel remote QUIC collection when gateway
// persistence worker is blocked on disk I/O
// ============================================================================

#[tokio::test]
async fn test_s01_09_parallel_quorum_assembly_when_gateway_worker_blocked() {
    const NUM_REMOTE_SHARDS: usize = 19;

    let gw_temp = tempdir().expect("gw tempdir");
    let gw_storage = Arc::new(
        RedbStorage::open(&gw_temp.path().join("quorum_gw_s01_09.redb")).expect("open gw redb"),
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
    for s in 0..NUM_REMOTE_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("shard_{s}.redb"))).expect("open shard redb"),
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
        });
    }

    for sh in &shards {
        pm_gw
            .register_f2f_friend(*sh.identity.node_pubkey(), Some(sh.addr))
            .await;
    }
    prepare_mature_fixture(&pm_gw, &gateway_id).await;
    force_stable_ge20(&pm_gw).await;

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
    tier_controller.register_f2f_peer("s01_09_peer");

    let mut state = AppState::new(
        gw_engine.clone(),
        gw_storage.clone(),
        gateway_id.clone(),
        tier_controller.clone(),
        pow_engine,
    );
    state.peer_manager = Some(pm_gw.clone());
    state.transport = Some(gw_transport.clone());

    let sender_key = NodeIdentity::generate();
    let now = test_now_ms();

    // Select a shard committee where gateway is in the top 20 committee!
    let mut counter = 0u64;
    let (target_shard_id, root_req) = loop {
        counter += 1;
        let voucher_name = format!("s01_09_{counter}");
        let req = build_hop(&sender_key, &voucher_name, 1, None, now);
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
        let sid = humoco_sim_core::types::canonical_voucher_shard(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if comm.iter().any(|m| m.node_pubkey == *gateway_id.node_pubkey()) && rem.len() == 19 {
            break (sid, req);
        }
        if counter > 20_000 {
            panic!("Could not find shard committee containing gateway within 20,000 iterations");
        }
    };

    state.readiness_manager.mark_shard_ready(target_shard_id);

    // Register root anchor on all nodes before blocking
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

    // Start HTTP server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .unwrap();

    // ------------------------------------------------------------------------
    // (a) Single-lock new spend when gateway persistence worker is blocked
    // ------------------------------------------------------------------------
    let spend_a = build_hop(&sender_key, &root_req.layer2_voucher_id, 20, Some(root_req.transaction_hash), now);

    // Deterministically block gateway persistence worker
    let blocking_write_txn = gw_storage
        .raw_database_for_test()
        .begin_write()
        .expect("hold blocking write txn");

    let res_a = http_client
        .post(format!("http://{http_addr}/v1/lock"))
        .header("X-Peer-Token", "s01_09_peer")
        .json(&spend_a)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_a.status(),
        reqwest::StatusCode::CREATED,
        "Single-lock spend must return 201 Created via remote quorum even while gateway write worker is blocked"
    );

    let env_a: L2ResponseEnvelope = res_a.json().await.unwrap();
    assert!(matches!(env_a.verdict, L2Verdict::Verified { .. }));
    let cert_a = env_a.quorum_certificate.expect("quorum cert must be present");
    assert!(
        cert_a.is_quorum_reached(),
        "Quorum must be reached with remote signatures"
    );
    assert_eq!(
        cert_a.signatures.len(),
        14,
        "Exactly 14 remote signatures must be present"
    );
    assert!(
        !cert_a
            .signatures
            .iter()
            .any(|sig| sig.node_pubkey_bytes() == Some(*gateway_id.node_pubkey())),
        "Gateway signature must NOT be included in quorum certificate while local commit is blocked (DEC-029)"
    );

    // ------------------------------------------------------------------------
    // (b) Chain-lock when gateway persistence worker is blocked
    // ------------------------------------------------------------------------
    let spend_b = build_hop(&sender_key, &root_req.layer2_voucher_id, 30, Some(spend_a.transaction_hash), now);
    let chain_b = L2ChainLockRequest {
        auth: root_req.auth.clone(),
        layer2_voucher_id: root_req.layer2_voucher_id.clone(),
        chain: vec![root_req.clone(), spend_a.clone(), spend_b.clone()],
    };

    let res_b = http_client
        .post(format!("http://{http_addr}/v1/lock/chain"))
        .header("X-Peer-Token", "s01_09_peer")
        .json(&chain_b)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_b.status(),
        reqwest::StatusCode::CREATED,
        "Chain-lock must return 201 Created via remote quorum even while gateway write worker is blocked"
    );

    let env_b: L2ResponseEnvelope = res_b.json().await.unwrap();
    assert!(matches!(env_b.verdict, L2Verdict::Verified { .. }));
    let cert_b = env_b.quorum_certificate.expect("quorum cert must be present");
    assert!(cert_b.is_quorum_reached());
    assert_eq!(cert_b.signatures.len(), 14);
    assert!(
        !cert_b
            .signatures
            .iter()
            .any(|sig| sig.node_pubkey_bytes() == Some(*gateway_id.node_pubkey())),
        "Gateway signature must NOT be included while blocked"
    );

    // S02-08 / S01 Checkout support persistence trigger over real QUIC:
    // Support continuation for spend_a was triggered on checkout quorum and timed out on caller deadline,
    // but remains tracked under gw_engine.recovery_work while gateway write worker is blocked.
    let spend_a_tag = spend_a.ds_tag.clone().unwrap();
    assert!(
        !gw_engine.is_recovery_work_idle(),
        "Gateway recovery_work must track in-flight support persistence continuations while redb is blocked"
    );
    assert!(
        gw_storage.confirmation_support(&spend_a_tag).unwrap().is_none(),
        "Confirmation support for spend_a must remain uncommitted while redb writer is blocked"
    );
    assert_eq!(
        gw_engine.hmc_ram.read().await.get_confirmation_class(&spend_a_tag),
        0,
        "RAM confirmation class for spend_a must remain 0 while blocked"
    );

    // Release blocking transaction so we can prepare spend_c
    drop(blocking_write_txn);

    // Await tracked drain: recovery work drains to idle upon disk unblocking
    let mut idle = false;
    for _ in 0..100 {
        if gw_engine.is_recovery_work_idle() {
            idle = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(idle, "Gateway recovery work must drain to idle after unblocking");

    // Confirmation support must now be durably committed and RAM-published
    assert!(
        gw_storage.confirmation_support(&spend_a_tag).unwrap().is_some(),
        "Single-lock confirmation support must be committed to redb after unblocking"
    );
    assert!(
        gw_engine.hmc_ram.read().await.get_confirmation_class(&spend_a_tag) >= 1,
        "Single-lock RAM confirmation class must be published after unblocking"
    );

    // ------------------------------------------------------------------------
    // (c) Original-approval retry path when gateway worker is blocked
    // ------------------------------------------------------------------------
    // Spend C is admitted to RAM/db on gateway and shards first
    let spend_c = build_hop(&sender_key, &root_req.layer2_voucher_id, 40, Some(spend_b.transaction_hash), now);
    let spend_c_tag = spend_c.ds_tag.clone().unwrap();

    let (v_gw, _) = gw_engine
        .ingress_hmc_lock_durable(
            spend_c_tag.clone(),
            L2LockEntry::from(&spend_c),
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_gw, L2Verdict::Verified { .. }));

    for sh in &shards {
        sh.engine
            .ingress_hmc_lock_durable(
                spend_c_tag.clone(),
                L2LockEntry::from(&spend_c),
                IngressOrigin::ClientApi,
                Some(now),
                None,
                None,
                None,
            )
            .await;
    }

    // Now block gateway persistence again
    let blocking_write_txn_c = gw_storage
        .raw_database_for_test()
        .begin_write()
        .expect("hold blocking write txn for retry");

    let res_c = http_client
        .post(format!("http://{http_addr}/v1/lock"))
        .header("X-Peer-Token", "s01_09_peer")
        .json(&spend_c)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_c.status(),
        reqwest::StatusCode::OK,
        "Idempotent spend retry must return 200 OK via remote quorum even while gateway write worker is blocked"
    );

    let env_c: L2ResponseEnvelope = res_c.json().await.unwrap();
    assert!(matches!(env_c.verdict, L2Verdict::Verified { .. }));
    let cert_c = env_c.quorum_certificate.expect("quorum cert must be present");
    assert!(cert_c.is_quorum_reached());
    assert_eq!(cert_c.signatures.len(), 14);
    assert!(
        !cert_c
            .signatures
            .iter()
            .any(|sig| sig.node_pubkey_bytes() == Some(*gateway_id.node_pubkey())),
        "Gateway signature must NOT be included while blocked"
    );

    drop(blocking_write_txn_c);

    // Cleanup
    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}

// ============================================================================
// S01-14: Insufficient-work HTTP 429 responses must include X-Required-Difficulty
// across both supported HTTP chain forms (/v1/lock/chain and POST /v1/lock)
// ============================================================================

#[tokio::test]
async fn test_s01_14_insufficient_chain_pow_emits_429_and_required_difficulty_header() {
    let now = test_now_ms();
    let voucher = "s01-14-pow-voucher";
    let key = NodeIdentity::generate();

    let root_hop = build_hop(&key, voucher, 1, None, now);
    let spend_hop = build_hop(&key, voucher, 2, Some(root_hop.transaction_hash), now);

    let chain_req = L2ChainLockRequest {
        auth: root_hop.auth.clone(),
        layer2_voucher_id: voucher.into(),
        chain: vec![root_hop.clone(), spend_hop.clone()],
    };

    let dir = tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("pow_test.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, _worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let id = NodeIdentity::generate();
    // Default difficulty = 16
    let pow = Arc::new(PowEngine::new(*id.node_id(), 16));
    let tiers = Arc::new(TierController::new(db.clone(), pow.clone()));

    let state = AppState::new(engine.clone(), db.clone(), id.clone(), tiers, pow.clone());
    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(
        &bs58::encode(root_hop.transaction_hash).into_string(),
    );
    state
        .readiness_manager
        .mark_shard_ready(humoco_sim_core::types::canonical_voucher_shard(&parent));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });

    let client = reqwest::Client::new();

    // 1. Request challenge without credentials -> 401 Unauthorized with x-required-difficulty
    let res_no_cred = client
        .post(format!("http://{addr}/v1/lock/chain"))
        .json(&chain_req)
        .send()
        .await
        .unwrap();

    assert_eq!(res_no_cred.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        res_no_cred.headers().get("x-required-difficulty").and_then(|h| h.to_str().ok()),
        Some("16")
    );
    let err_resp: humoco_node::ErrorResponse = res_no_cred.json().await.unwrap();
    assert_eq!(err_resp.error, "PoWRequired");
    assert_eq!(err_resp.difficulty, Some(16));
    let challenge = err_resp.challenge.expect("challenge must be returned");

    // 2. HTTP Form A: POST /v1/lock/chain with insufficient nonce (difficulty 0 vs 16) -> 429 Too Many Requests
    let res_form_a = client
        .post(format!("http://{addr}/v1/lock/chain"))
        .header("X-PoW-Challenge", &challenge)
        .header("X-PoW-Nonce", "0")
        .json(&chain_req)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_form_a.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "Form A (/v1/lock/chain) with insufficient PoW must return 429"
    );
    assert_eq!(
        res_form_a.headers().get("x-required-difficulty").and_then(|h| h.to_str().ok()),
        Some("16"),
        "Form A must include x-required-difficulty header on 429"
    );
    let err_a: humoco_node::ErrorResponse = res_form_a.json().await.unwrap();
    assert_eq!(err_a.error, "InvalidPoW");
    assert_eq!(err_a.difficulty, Some(16));

    // 3. HTTP Form B: POST /v1/lock with chain payload and insufficient nonce -> 429 Too Many Requests
    let res_form_b = client
        .post(format!("http://{addr}/v1/lock"))
        .header("X-PoW-Challenge", &challenge)
        .header("X-PoW-Nonce", "0")
        .json(&chain_req)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_form_b.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "Form B (POST /v1/lock with chain payload) with insufficient PoW must return 429"
    );
    assert_eq!(
        res_form_b.headers().get("x-required-difficulty").and_then(|h| h.to_str().ok()),
        Some("16"),
        "Form B must include x-required-difficulty header on 429"
    );
    let err_b: humoco_node::ErrorResponse = res_form_b.json().await.unwrap();
    assert_eq!(err_b.error, "InvalidPoW");
    assert_eq!(err_b.difficulty, Some(16));

    cancel.cancel();
}

// ============================================================================
// S01-13: Fast-fail without awaiting local_task on quorum failure while
// preserving uncorrupted background durable commit upon redb unblocking
// ============================================================================

#[tokio::test]
async fn test_s01_13_prompt_quorum_failure_and_preserved_durable_commit_when_persistence_blocked() {
    const NUM_REMOTE_SHARDS: usize = 19;
    const NUM_NOT_READY: usize = 7;

    let gw_temp = tempdir().expect("gw tempdir");
    let gw_storage = Arc::new(
        RedbStorage::open(&gw_temp.path().join("quorum_gw_s01_13.redb")).expect("open gw redb"),
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
    for s in 0..NUM_REMOTE_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("shard_{s}.redb"))).expect("open shard redb"),
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
                fake_pubkey(85_000 + (s as u64) * 100 + i),
                Some(fake_addr((57001 + i) as u16)),
            )
            .await;
        }
        prepare_mature_fixture(&pm, &identity).await;
        force_stable_ge20(&pm).await;

        let readiness = Arc::new(ShardReadinessManager::new());
        if s >= NUM_NOT_READY {
            for shard in 0..=u16::MAX {
                readiness.mark_shard_ready(shard);
            }
        }
        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(s >= NUM_NOT_READY)))
            .with_readiness_manager(readiness),
        );

        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .expect("bind shard transport");
        transport.set_sync_ready(s >= NUM_NOT_READY);
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
    tier_controller.register_f2f_peer("s01_13_peer");

    let mut state = AppState::new(
        gw_engine.clone(),
        gw_storage.clone(),
        gateway_id.clone(),
        tier_controller.clone(),
        pow_engine,
    );
    state.peer_manager = Some(pm_gw.clone());
    state.transport = Some(gw_transport.clone());

    let sender_key = NodeIdentity::generate();
    let now = test_now_ms();

    // Select a shard committee where gateway is in the top 20 committee
    let mut counter = 0u64;
    let (target_shard_id, root_req) = loop {
        counter += 1;
        let voucher_name = format!("s01_13_{counter}");
        let req = build_hop(&sender_key, &voucher_name, 1, None, now);
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
        let sid = humoco_sim_core::types::canonical_voucher_shard(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if comm.iter().any(|m| m.node_pubkey == *gateway_id.node_pubkey()) && rem.len() == 19 {
            break (sid, req);
        }
        if counter > 20_000 {
            panic!("Could not find shard committee containing gateway within 20,000 iterations");
        }
    };

    state.readiness_manager.mark_shard_ready(target_shard_id);

    // Register root anchor on all nodes before blocking
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

    // Start HTTP server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .build()
        .unwrap();

    // ------------------------------------------------------------------------
    // (a) Single-lock write when gateway persistence is blocked & 7 remotes refuse
    // ------------------------------------------------------------------------
    let spend_single = build_hop(&sender_key, &root_req.layer2_voucher_id, 21, Some(root_req.transaction_hash), now);
    let spend_single_tag = spend_single.ds_tag.clone().unwrap();

    let blocking_write_txn_a = gw_storage
        .raw_database_for_test()
        .begin_write()
        .expect("hold blocking write txn a");

    let t0_single = std::time::Instant::now();
    let res_single = http_client
        .post(format!("http://{http_addr}/v1/lock"))
        .header("X-Peer-Token", "s01_13_peer")
        .json(&spend_single)
        .send()
        .await
        .unwrap();
    let elapsed_single = t0_single.elapsed();

    assert!(
        elapsed_single < Duration::from_millis(250),
        "Single-lock write must fail promptly on hopeless quorum without waiting on local disk, elapsed: {elapsed_single:?}"
    );
    assert_eq!(
        res_single.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "Quorum failure must return 503 Service Unavailable"
    );
    let env_single: L2ResponseEnvelope = res_single.json().await.unwrap();
    assert!(
        matches!(env_single.verdict, L2Verdict::Rejected { ref reason } if reason.contains("Quorum not reached")),
        "Expected Quorum not reached rejection, got: {:?}",
        env_single.verdict
    );

    // Assert neutral peer accounting (0 peer failure penalties)
    for peer in pm_gw.list_peers().await {
        assert_eq!(
            peer.missing_count, 0,
            "Neutral refusals must NOT incur peer failure penalties"
        );
        assert!(peer.last_failure.is_none());
    }

    // Release blocking transaction -> durable work must commit uncorrupted in background
    drop(blocking_write_txn_a);

    // Wait briefly for detached background task to commit to redb
    let mut committed = false;
    for _ in 0..50 {
        if gw_storage.get_hmc_lock(&spend_single_tag).unwrap().is_some() {
            committed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        committed,
        "Submitted local durable work must not be aborted mid-flight when checkout fails quorum"
    );

    // ------------------------------------------------------------------------
    // (b) Chain-lock write when gateway persistence is blocked & 7 remotes refuse
    // ------------------------------------------------------------------------
    let spend_chain_next = build_hop(&sender_key, &root_req.layer2_voucher_id, 31, Some(spend_single.transaction_hash), now);
    let spend_chain_tag = spend_chain_next.ds_tag.clone().unwrap();
    let chain_req = L2ChainLockRequest {
        auth: root_req.auth.clone(),
        layer2_voucher_id: root_req.layer2_voucher_id.clone(),
        chain: vec![root_req.clone(), spend_single.clone(), spend_chain_next.clone()],
    };

    let blocking_write_txn_b = gw_storage
        .raw_database_for_test()
        .begin_write()
        .expect("hold blocking write txn b");

    let t0_chain = std::time::Instant::now();
    let res_chain = http_client
        .post(format!("http://{http_addr}/v1/lock/chain"))
        .header("X-Peer-Token", "s01_13_peer")
        .json(&chain_req)
        .send()
        .await
        .unwrap();
    let elapsed_chain = t0_chain.elapsed();

    assert!(
        elapsed_chain < Duration::from_millis(250),
        "Chain-lock write must fail promptly on hopeless quorum without waiting on local disk, elapsed: {elapsed_chain:?}"
    );
    assert_eq!(
        res_chain.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "Chain quorum failure must return 503 Service Unavailable"
    );

    for peer in pm_gw.list_peers().await {
        assert_eq!(peer.missing_count, 0);
        assert!(peer.last_failure.is_none());
    }

    drop(blocking_write_txn_b);

    let mut committed_chain = false;
    for _ in 0..50 {
        if gw_storage.get_hmc_lock(&spend_chain_tag).unwrap().is_some() {
            committed_chain = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        committed_chain,
        "Submitted local chain durable work must not be aborted mid-flight"
    );

    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}

// ============================================================================
// S01-12: Frozen committee snapshot, excluded local signer prevention,
// and cryptographic approval context validation
// ============================================================================

#[tokio::test]
async fn test_s01_12_frozen_committee_and_strict_approval_context_validation() {
    const NUM_REMOTE_SHARDS: usize = 19;
    const NUM_NOT_READY: usize = 6; // 13 ready, 6 not ready

    let gw_temp = tempdir().expect("gw tempdir");
    let gw_storage = Arc::new(
        RedbStorage::open(&gw_temp.path().join("quorum_gw_s01_12.redb")).expect("open gw redb"),
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
    for s in 0..NUM_REMOTE_SHARDS {
        let tmp = tempdir().expect("shard tempdir");
        let storage = Arc::new(
            RedbStorage::open(&tmp.path().join(format!("shard_{s}.redb"))).expect("open shard redb"),
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
                Some(fake_addr((58001 + i) as u16)),
            )
            .await;
        }
        prepare_mature_fixture(&pm, &identity).await;
        force_stable_ge20(&pm).await;

        let readiness = Arc::new(ShardReadinessManager::new());
        if s >= NUM_NOT_READY {
            for shard in 0..=u16::MAX {
                readiness.mark_shard_ready(shard);
            }
        }
        let handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                identity.clone(),
                pm.clone(),
            )
            .with_sync_ready(Arc::new(AtomicBool::new(s >= NUM_NOT_READY)))
            .with_readiness_manager(readiness),
        );

        let transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().expect("addr"),
            &identity,
            pm.clone(),
            handler,
            cancel.clone(),
        )
        .expect("bind shard transport");
        transport.set_sync_ready(s >= NUM_NOT_READY);
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

    let sender_key = NodeIdentity::generate();
    let now = test_now_ms();

    // Select a shard committee where gateway is in the top 20 committee
    let mut counter = 0u64;
    let (target_shard_id, root_req) = loop {
        counter += 1;
        let voucher_name = format!("s01_12_{counter}");
        let req = build_hop(&sender_key, &voucher_name, 1, None, now);
        let tag = bs58::encode(&req.transaction_hash).into_string();
        let p_bytes = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
        let sid = humoco_sim_core::types::canonical_voucher_shard(&p_bytes);
        let (comm, rem, _) = pm_gw
            .shard_committee(*gateway_id.node_pubkey(), *gateway_id.hrw_routing_id(), sid)
            .await;
        if comm.iter().any(|m| m.node_pubkey == *gateway_id.node_pubkey()) && rem.len() == 19 {
            break (sid, req);
        }
        if counter > 20_000 {
            panic!("Could not find shard committee containing gateway within 20,000 iterations");
        }
    };

    // Register root anchor on all nodes
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

    let spend = build_hop(&sender_key, &root_req.layer2_voucher_id, 22, Some(root_req.transaction_hash), now);
    let parent_bytes = *blake3::hash(spend.ds_tag.as_deref().unwrap().as_bytes()).as_bytes();

    let declared_write_ema = state.tier_controller.current_write_ema_micro_bj();
    let declared_read_ema = state.tier_controller.current_read_ema_credits();
    let sender_pubkey = *state.identity.node_pubkey();
    let root_valid_until = now + 600_000;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
    let op_hash = spend.transaction_hash;
    let (epoch_day, epoch_seq, cumulative_micro_byte_years, prev_day_final_bytes) = state
        .tier_controller
        .record_declared_usage(now, footprint);
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
    let sender_signature = state.identity.signing_key().sign(&digest).to_bytes();
    let wire_payload = bincode::serialize(&LockWirePayload::Hmc {
        req: spend.clone(),
        chain: None,
        root_valid_until,
        epoch_day,
        epoch_seq,
        cumulative_micro_byte_years,
        prev_day_final_bytes,
        current_anl_24h: declared_write_ema,
        declared_write_ema_micro_bj: declared_write_ema,
        declared_read_ema_credits: declared_read_ema,
        sender_pubkey,
        sender_signature,
        timestamp_ms: now,
    })
    .ok();

    // ------------------------------------------------------------------------
    // Part 1: 13 remote signatures + EXCLUDED local signer -> MUST NOT reach quorum (13 < 14)
    // Gateway shard is NOT marked ready, so self_is_in_committee is false!
    // ------------------------------------------------------------------------
    // Notice: state.readiness_manager does NOT have target_shard_id marked ready!
    assert!(!state.readiness_manager.is_shard_ready(target_shard_id));

    // Provide a local task that attempts to sign and inject an attestation
    let fake_local_task = tokio::spawn({
        let state_identity = state.identity.clone();
        let net_id = state.network_id;
        async move {
            let att = humoco_node::api::routes::create_attestation_for_network(
                &state_identity,
                spend.transaction_hash,
                parent_bytes,
                target_shard_id,
                1,
                now,
                net_id,
            );
            Some(att)
        }
    });

    let snapshot = humoco_node::api::routes::FrozenCommitteeSnapshot::compute(&state, target_shard_id, now).await;

    let (cert_part1, _, _) = humoco_node::api::routes::assemble_quorum_certificate_with_deadline_and_local(
        &state,
        &snapshot,
        spend.transaction_hash,
        parent_bytes,
        target_shard_id,
        now,
        wire_payload.clone(),
        Some(tokio::time::Instant::now() + Duration::from_millis(500)),
        Some(fake_local_task),
    )
    .await;

    assert!(
        !cert_part1.is_quorum_reached(),
        "Quorum must NOT be reached when only 13 valid signatures are collected (need 14)"
    );
    assert!(
        !cert_part1
            .signatures
            .iter()
            .any(|s| s.node_pubkey_bytes() == Some(*gateway_id.node_pubkey())),
        "Excluded local signer must NOT be present in collected signatures"
    );

    // ------------------------------------------------------------------------
    // Part 2: Local signature with WRONG target_status (e.g. 0 vs expected 1)
    // Now gateway IS ready and in committee, but local task signs with target_status 0!
    // ------------------------------------------------------------------------
    state.readiness_manager.mark_shard_ready(target_shard_id);
    let snapshot_part2 = humoco_node::api::routes::FrozenCommitteeSnapshot::compute(&state, target_shard_id, now).await;
    assert!(snapshot_part2.self_is_in_committee);
    assert_eq!(snapshot_part2.target_status, 1);

    let wrong_status_local_task = tokio::spawn({
        let state_identity = state.identity.clone();
        let net_id = state.network_id;
        async move {
            // Sign with WRONG status 0 (provisional) instead of snapshot's status 1 (final)
            let att = humoco_node::api::routes::create_attestation_for_network(
                &state_identity,
                spend.transaction_hash,
                parent_bytes,
                target_shard_id,
                0, // WRONG STATUS
                now,
                net_id,
            );
            Some(att)
        }
    });

    let (cert_part2, _, _) = humoco_node::api::routes::assemble_quorum_certificate_with_deadline_and_local(
        &state,
        &snapshot_part2,
        spend.transaction_hash,
        parent_bytes,
        target_shard_id,
        now,
        wire_payload.clone(),
        Some(tokio::time::Instant::now() + Duration::from_millis(500)),
        Some(wrong_status_local_task),
    )
    .await;

    assert!(
        !cert_part2.is_quorum_reached(),
        "Quorum must NOT be reached when local signature has wrong target_status"
    );
    assert!(
        !cert_part2
            .signatures
            .iter()
            .any(|s| s.node_pubkey_bytes() == Some(*gateway_id.node_pubkey())),
        "Local attestation with wrong target_status must fail verification and not be present in certificate"
    );

    // ------------------------------------------------------------------------
    // Part 3: Direct Cryptographic Context Validation on verify_peer_attestation
    // Verify that every context parameter strictly rejects tampered attestations:
    // lock_id, parent_lock, shard_id, target_status, network_id, tls_pubkey
    // ------------------------------------------------------------------------
    let valid_att = humoco_node::api::routes::create_attestation_for_network(
        &gateway_id,
        spend.transaction_hash,
        parent_bytes,
        target_shard_id,
        1,
        now,
        state.network_id,
    );

    // Baseline: valid attestation passes verification
    assert!(
        humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (spend.transaction_hash, parent_bytes),
            target_shard_id,
            1,
            state.network_id,
            Some(*gateway_id.node_pubkey()),
        )
        .await,
        "Valid attestation must pass verification"
    );

    // 1. Wrong lock_id -> MUST fail
    let mut wrong_lock_id_bytes = spend.transaction_hash;
    wrong_lock_id_bytes[0] ^= 0xFF;
    assert!(
        !humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (wrong_lock_id_bytes, parent_bytes),
            target_shard_id,
            1,
            state.network_id,
            Some(*gateway_id.node_pubkey()),
        )
        .await,
        "Attestation verified with mismatched lock_id must be rejected"
    );

    // 2. Wrong parent_lock -> MUST fail
    let mut wrong_parent_bytes = parent_bytes;
    wrong_parent_bytes[0] ^= 0xFF;
    assert!(
        !humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (spend.transaction_hash, wrong_parent_bytes),
            target_shard_id,
            1,
            state.network_id,
            Some(*gateway_id.node_pubkey()),
        )
        .await,
        "Attestation verified with mismatched parent_lock must be rejected"
    );

    // 3. Wrong shard_id -> MUST fail
    assert!(
        !humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (spend.transaction_hash, parent_bytes),
            target_shard_id.wrapping_add(1),
            1,
            state.network_id,
            Some(*gateway_id.node_pubkey()),
        )
        .await,
        "Attestation verified with mismatched shard_id must be rejected"
    );

    // 4. Wrong target_status -> MUST fail
    assert!(
        !humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (spend.transaction_hash, parent_bytes),
            target_shard_id,
            0, // expected 0, but signed 1
            state.network_id,
            Some(*gateway_id.node_pubkey()),
        )
        .await,
        "Attestation verified with mismatched target_status must be rejected"
    );

    // 5. Wrong network_id -> MUST fail
    let wrong_net_id = humoco_sim_core::types::NetworkId::Testnet;
    assert!(
        !humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (spend.transaction_hash, parent_bytes),
            target_shard_id,
            1,
            wrong_net_id,
            Some(*gateway_id.node_pubkey()),
        )
        .await,
        "Attestation verified with mismatched network_id must be rejected"
    );

    // 6. Wrong TLS pubkey -> MUST fail
    let wrong_tls_pubkey = [0xAA; 32];
    assert!(
        !humoco_node::api::routes::verify_peer_attestation(
            &pm_gw,
            &valid_att,
            (spend.transaction_hash, parent_bytes),
            target_shard_id,
            1,
            state.network_id,
            Some(wrong_tls_pubkey),
        )
        .await,
        "Attestation verified with mismatched TLS pubkey must be rejected"
    );

    // ------------------------------------------------------------------------
    // Part 4: Committee changes in PeerManager after snapshot is frozen
    // The frozen snapshot must remain authoritative
    // ------------------------------------------------------------------------
    let snapshot_part3 = humoco_node::api::routes::FrozenCommitteeSnapshot::compute(&state, target_shard_id, now).await;
    // Modify PM by registering a new peer
    let intruder = NodeIdentity::generate();
    pm_gw
        .learn_node_from_gossip_with_hrw(
            *intruder.node_pubkey(),
            *intruder.hrw_routing_id(),
            "127.0.0.1:9999".parse().unwrap(),
            0,
            None,
        )
        .await;

    // Quorum assembly with frozen snapshot uses snapshot_part3 committee and required_q
    assert_eq!(snapshot_part3.required_q, 14);
    assert_eq!(snapshot_part3.committee.len(), 20);

    gw_cancel.cancel();
    gw_transport.close();
    for sh in shards {
        sh.cancel.cancel();
        sh.transport.close();
    }
}



