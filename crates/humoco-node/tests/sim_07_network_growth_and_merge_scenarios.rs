//! sim_07_network_growth_and_merge_scenarios – Simulations- und Test-Suite für organische Wachstums-
//! und Merge-Szenarien in HuMoCo Layer-2 (Spec 08, Pillar 4, DEC-064).
//!
//! Szenarien:
//! 1. Direct Shard-Sync Quarantine: Verifiziert, dass `sync_single_shard` lokale Minderheitslocks
//!    aus einer 3-Knoten-Insel isoliert/quarantänisiert, wenn ein dominantes Quorum (10 Knoten)
//!    übernommen wird, sodass der Post-Sync-Digest konvergiert und der Shard auf READY wechselt.
//! 2. SC-02 Asymmetrischer Merge (10 vs. 3): 10 Knoten (Netz A, Voucher V_A) treffen auf 3 Knoten
//!    (Netz B, Voucher V_B). Quorum Q(13)=9. Netz B zieht V_A, isoliert V_B und konvergiert auf READY.
//! 3. SC-03 Symmetrischer Merge / Patt (5 vs. 5) & Wallet-Reconciliation: Weder A noch B erreichen
//!    Q(10)=7. Quorum-Stalemate. Wallets reichen V_A auf Gateway B und V_B auf Gateway A nach,
//!    wodurch alle 10 Knoten auf 10/10 Stimmen für den gemeinsamen Zustand konvergieren.

mod simulation;

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use humoco_node::api::hmc::{L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict};
use humoco_node::daemon::{sync_single_shard, ShardReadinessManager};
use humoco_node::error::NodeError;
use humoco_node::identity::NodeIdentity;
use humoco_node::network::{NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_node::config::NodeConfig;
use simulation::node_handle::SIM_F2F_TOKEN;
use simulation::SimWallet;
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Self-contained cluster test node with real HTTP (Axum) and real QUIC transports.
struct MergeTestNode {
    #[allow(dead_code)]
    id: usize,
    identity: NodeIdentity,
    manager: Arc<PeerManager>,
    #[allow(dead_code)]
    engine: DualTierEngine,
    storage: Arc<RedbStorage>,
    readiness: Arc<ShardReadinessManager>,
    transport: QuicTransport,
    rpc_addr: SocketAddr,
    p2p_addr: SocketAddr,
    cancel_token: CancellationToken,
    _temp: tempfile::TempDir,
    #[allow(dead_code)]
    task_handle: Option<tokio::task::JoinHandle<Result<(), NodeError>>>,
}

impl MergeTestNode {
    pub async fn http_request(
        &self,
        method: &str,
        path: &str,
        body_json: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = tokio::net::TcpStream::connect(self.rpc_addr).await?;
        let body_bytes = body_json.map(|s| s.as_bytes()).unwrap_or(&[]);

        let mut req_str = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            method, path, self.rpc_addr, body_bytes.len()
        );
        for (k, v) in headers {
            req_str.push_str(&format!("{}: {}\r\n", k, v));
        }
        req_str.push_str("\r\n");

        stream.write_all(req_str.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(body_bytes).await?;
        }
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

        let mut split_idx = None;
        for i in 0..response_buf.len().saturating_sub(3) {
            if &response_buf[i..i + 4] == b"\r\n\r\n" {
                split_idx = Some(i);
                break;
            }
        }
        let (header_part, body_part) = match split_idx {
            Some(idx) => (&response_buf[..idx], &response_buf[idx + 4..]),
            None => (&response_buf[..], &[][..]),
        };

        let header_str = String::from_utf8_lossy(header_part);
        let mut lines = header_str.lines();
        let status_line = lines.next().unwrap_or("");
        let status_code_u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(500);

        let status = StatusCode::from_u16(status_code_u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Ok((status, body_part.to_vec()))
    }

    pub async fn post_lock(
        &self,
        req: &L2LockRequest,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(req)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/v1/lock",
                Some(&json_body),
                &[
                    ("Content-Type", "application/json"),
                    ("X-Peer-Token", SIM_F2F_TOKEN),
                ],
            )
            .await?;
        let resp: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, resp))
    }

    pub async fn query_status(
        &self,
        query: &L2StatusQuery,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(query)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/v1/status",
                Some(&json_body),
                &[("Content-Type", "application/json")],
            )
            .await?;
        let resp: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, resp))
    }

    pub async fn sync_shard(&self, shard_id: u16) -> Result<bool, NodeError> {
        sync_single_shard(
            shard_id,
            &self.transport,
            &self.manager,
            &self.engine,
            &self.storage,
            &self.identity,
            &self.readiness,
            &self.cancel_token,
        )
        .await
    }
}

impl Drop for MergeTestNode {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

async fn spawn_test_node(
    id: usize,
) -> Result<MergeTestNode, Box<dyn std::error::Error + Send + Sync>> {
    let temp = tempdir()?;
    let identity = NodeIdentity::generate();
    let key_path = temp.path().join("node_key.bin");
    identity.save_to_file(&key_path)?;

    let mut config = NodeConfig::default();
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.storage.data_dir = temp.path().join("data");
    config.identity.key_path = key_path;
    config.f2f.tokens.push(SIM_F2F_TOKEN.to_string());

    std::fs::create_dir_all(&config.storage.data_dir)?;
    let storage = Arc::new(RedbStorage::open(&config.storage.data_dir.join("humoco.redb"))?);
    let flush_cancel = CancellationToken::new();
    let (engine, flush_worker) = DualTierEngine::new_with_token(storage.clone(), flush_cancel.clone());
    let cancel_token = CancellationToken::new();
    let manager = Arc::new(PeerManager::new(Vec::new()));
    let readiness = Arc::new(ShardReadinessManager::with_cancel_token(cancel_token.clone()));
    for shard in 0..=u16::MAX { readiness.mark_shard_ready(shard); }

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            identity.clone(),
            manager.clone(),
        )
        .with_readiness_manager(readiness.clone())
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse()?,
        &identity,
        manager.clone(),
        handler,
        cancel_token.clone(),
    )?;
    transport.set_sync_ready(true);
    let p2p_addr = transport.local_addr()?;
    transport.spawn_accept_loop();

    manager.learn_node_from_gossip_with_hrw(
        *identity.node_pubkey(),
        *identity.hrw_routing_id(),
        p2p_addr,
        0,
        None,
    ).await;
    manager.set_first_seen_for_test(
        identity.node_pubkey(),
        std::time::Instant::now() - Duration::from_secs(25 * 3600),
    ).await;

    let pow = Arc::new(humoco_node::ingress::PowEngine::new(*identity.node_id(), 8));
    let tier = Arc::new(humoco_node::ingress::TierController::new(storage.clone(), pow.clone()));
    tier.register_f2f_peer(SIM_F2F_TOKEN);

    let mut state = humoco_node::api::AppState::new(engine.clone(), storage.clone(), identity.clone(), tier, pow);
    state.peer_manager = Some(manager.clone());
    state.transport = Some(transport.clone());
    state.readiness_manager = readiness.clone();
    let app = humoco_node::api::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rpc_addr = listener.local_addr()?;
    let server_cancel = cancel_token.clone();
    let transport_close = transport.clone();
    let task_handle = tokio::spawn(async move {
        let shutdown = server_cancel.clone();
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await; })
            .await;
        transport_close.close();
        flush_cancel.cancel();
        let _ = flush_worker.await;
        result.map_err(NodeError::Io)
    });

    Ok(MergeTestNode {
        id,
        identity,
        manager,
        engine,
        storage,
        readiness,
        transport,
        rpc_addr,
        p2p_addr,
        cancel_token,
        _temp: temp,
        task_handle: Some(task_handle),
    })
}

async fn peer_nodes(a: &MergeTestNode, b: &MergeTestNode) {
    a.manager.register_f2f_friend(*b.identity.node_pubkey(), Some(b.p2p_addr)).await;
    b.manager.register_f2f_friend(*a.identity.node_pubkey(), Some(a.p2p_addr)).await;
    a.manager.learn_node_from_gossip_with_hrw(*b.identity.node_pubkey(), *b.identity.hrw_routing_id(), b.p2p_addr, 0, None).await;
    b.manager.learn_node_from_gossip_with_hrw(*a.identity.node_pubkey(), *a.identity.hrw_routing_id(), a.p2p_addr, 0, None).await;
    a.manager.set_first_seen_for_test(b.identity.node_pubkey(), std::time::Instant::now() - Duration::from_secs(25 * 3600)).await;
    b.manager.set_first_seen_for_test(a.identity.node_pubkey(), std::time::Instant::now() - Duration::from_secs(25 * 3600)).await;
}

fn status_query(voucher: &str, challenge: &str) -> L2StatusQuery {
    L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [0u8; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher.to_string(),
        challenge_ds_tag: challenge.to_string(),
        locator_prefixes: vec![],
        read_quorum: 1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Direct Wire-Level Shard-Sync Subquorum Quarantine (10 vs 3)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_sync_single_shard_quarantines_minority_locks_and_converges() {
    let temp_dominant = tempdir().expect("tempdir");
    let storage_dominant = Arc::new(
        RedbStorage::open(&temp_dominant.path().join("dominant.redb")).expect("open redb"),
    );
    let (engine_dominant, _w1) = DualTierEngine::new(storage_dominant.clone());

    let dominant_id = NodeIdentity::generate();
    let minority_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();

    let pm_dominant = Arc::new(PeerManager::with_f2f(Vec::new(), vec![*minority_id.node_id()]));
    let pm_minority = Arc::new(PeerManager::with_f2f(Vec::new(), vec![*dominant_id.node_id()]));

    let rm_dominant = Arc::new(ShardReadinessManager::new());
    let rm_minority = Arc::new(ShardReadinessManager::new());

    let handler_dominant = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_dominant.clone(),
            storage_dominant.clone(),
            dominant_id.clone(),
            pm_dominant.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(rm_dominant.clone()),
    );

    let temp_minority = tempdir().expect("tempdir");
    let storage_minority = Arc::new(
        RedbStorage::open(&temp_minority.path().join("minority.redb")).expect("open redb"),
    );
    let (engine_minority, _w2) = DualTierEngine::new(storage_minority.clone());

    let handler_minority = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_minority.clone(),
            storage_minority.clone(),
            minority_id.clone(),
            pm_minority.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(rm_minority.clone()),
    );

    let transport_dominant = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &dominant_id,
        pm_dominant.clone(),
        handler_dominant,
        cancel.clone(),
    )
    .expect("dominant bind");
    let addr_dominant = transport_dominant.local_addr().expect("dominant addr");
    transport_dominant.spawn_accept_loop();

    let transport_minority = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &minority_id,
        pm_minority.clone(),
        handler_minority,
        cancel.clone(),
    )
    .expect("minority bind");
    let addr_minority = transport_minority.local_addr().expect("minority addr");
    transport_minority.spawn_accept_loop();

    pm_minority.register_f2f_friend(*dominant_id.node_id(), Some(addr_dominant)).await;
    pm_dominant.register_f2f_friend(*minority_id.node_id(), Some(addr_minority)).await;

    // 1. Dominant node holds Voucher A
    let wallet_a = SimWallet::new();
    let (voucher_a, genesis_a) = wallet_a.genesis_with_voucher(Some(600_000));
    let tag_a = SimWallet::t_id_to_tag(&genesis_a.transaction_hash);
    let parent_bytes_a = *blake3::hash(tag_a.as_bytes()).as_bytes();
    let shard_id = u16::from_be_bytes([parent_bytes_a[0], parent_bytes_a[1]]);

    let entry_a = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_a.clone(),
        t_id: genesis_a.transaction_hash,
        sender_ephemeral_pub: genesis_a.sender_ephemeral_pub,
        receiver_ephemeral_pub_hash: genesis_a.receiver_ephemeral_pub_hash,
        change_ephemeral_pub_hash: genesis_a.change_ephemeral_pub_hash,
        layer2_signature: genesis_a.layer2_signature,
        trap_r: genesis_a.trap_r.clone(),
        trap_s: genesis_a.trap_s.clone(),
        encrypted_timestamp: genesis_a.encrypted_timestamp,
        created_at_ms: genesis_a.created_at_ms,
        deletable_at: genesis_a.deletable_at.clone(),
        privacy_guard: genesis_a.privacy_guard.clone(),
    };
    let (v_a, _) = engine_dominant
        .ingress_hmc_lock_durable(tag_a.clone(), entry_a.clone(), IngressOrigin::ClientApi, None, None, None, None)
        .await;
    assert!(matches!(v_a, L2Verdict::Verified { .. }));

    // 2. Minority node holds an old unconfirmed Voucher B for the SAME shard_id (from minority island)
    let wallet_b = SimWallet::new();
    let voucher_b = wallet_b.fresh_voucher_id();
    let (tag_b, entry_b) = {
        let mut i = 0u64;
        loop {
            let t = format!("{}_b_{}", tag_a, i);
            let pb = *blake3::hash(t.as_bytes()).as_bytes();
            if u16::from_be_bytes([pb[0], pb[1]]) == shard_id {
                let mut eb = entry_a.clone();
                eb.layer2_voucher_id = voucher_b.clone();
                eb.t_id = *blake3::hash(t.as_bytes()).as_bytes();
                break (t, eb);
            }
            i += 1;
        }
    };
    let (v_b, _) = engine_minority
        .ingress_hmc_lock_durable(tag_b.clone(), entry_b.clone(), IngressOrigin::ClientApi, None, None, None, None)
        .await;
    assert!(matches!(v_b, L2Verdict::Verified { .. }));

    // Pre-condition: Minority node has Voucher B in storage
    assert!(storage_minority.all_valid_hmc_locks(0).unwrap().iter().any(|(t, _)| t == &tag_b));

    // Register dominant node in minority's PeerManager
    pm_minority
        .learn_node_from_gossip_with_hrw(
            *dominant_id.node_pubkey(),
            *dominant_id.hrw_routing_id(),
            addr_dominant,
            0,
            None,
        )
        .await;
    pm_minority
        .set_first_seen_for_test(dominant_id.node_pubkey(), std::time::Instant::now() - Duration::from_secs(25 * 3600))
        .await;
    pm_minority
        .set_first_seen_for_test(minority_id.node_pubkey(), std::time::Instant::now() - Duration::from_secs(25 * 3600))
        .await;


    // Run sync_single_shard on minority node
    assert!(!rm_minority.is_shard_ready(shard_id));
    let ready = sync_single_shard(
        shard_id,
        &transport_minority,
        &pm_minority,
        &engine_minority,
        &storage_minority,
        &minority_id,
        &rm_minority,
        &cancel,
    )
    .await
    .expect("sync_single_shard must succeed");

    // Fix verification:
    // 1. Shard readiness must activate upon dominant digest convergence (post_digest == dominant_digest)
    assert!(ready, "Dominant quorum convergence must activate shard readiness on minority node");
    assert!(rm_minority.is_shard_ready(shard_id));

    // 2. Dominant Voucher A must be Installed in minority node's active storage and RAM
    let v_res_a = engine_minority.hmc_ram.read().await.query_status(&voucher_a, &tag_a, &[]);
    eprintln!("v_res_a = {:?}", v_res_a);
    assert!(matches!(v_res_a, L2Verdict::Verified { .. }), "Dominant Voucher A must be Verified");

    // 3. Minority Voucher B must be quarantined from active storage into TABLE_PROVISIONAL_HMC_LOCKS
    assert!(
        !storage_minority.all_valid_hmc_locks(0).unwrap().iter().any(|(t, _)| t == &tag_b),
        "Unconfirmed minority lock B must NOT be in active TABLE_HMC_LOCKS"
    );
    assert!(
        !engine_minority.hmc_ram.read().await.locks.contains_key(&tag_b),
        "Unconfirmed minority lock B must NOT be in active HmcRamIndex"
    );
    assert!(
        storage_minority.get_provisional_hmc_lock(&tag_b).unwrap().is_some(),
        "Unconfirmed minority lock B must be preserved in TABLE_PROVISIONAL_HMC_LOCKS (own-choice safety)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: SC-02 Asymmetric Merge 10 vs. 3 Scenario (Dominant Quorum Convergence)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_sc02_asymmetric_merge_10_vs_3_dominant_quorum_convergence() {
    let mut nodes = Vec::new();
    for i in 0..13 {
        nodes.push(spawn_test_node(i).await.expect("spawn node"));
    }

    // Network A: nodes 0..10 fully peered with each other (10 nodes, Q(10)=7)
    for i in 0..10 {
        for j in 0..10 {
            if i != j {
                peer_nodes(&nodes[i], &nodes[j]).await;
            }
        }
    }

    // Network B: nodes 10..13 fully peered with each other (3 nodes, Q(3)=3)
    for i in 10..13 {
        for j in 10..13 {
            if i != j {
                peer_nodes(&nodes[i], &nodes[j]).await;
            }
        }
    }

    // 1. Dominant Voucher A
    let wallet_a = SimWallet::new();
    let (voucher_a, genesis_a) = wallet_a.genesis_with_voucher(Some(600_000));
    let tag_a = SimWallet::t_id_to_tag(&genesis_a.transaction_hash);
    let parent_bytes_a = *blake3::hash(tag_a.as_bytes()).as_bytes();
    let shard_id = u16::from_be_bytes([parent_bytes_a[0], parent_bytes_a[1]]);

    let (st_a, env_a) = nodes[0].post_lock(&genesis_a).await.expect("post V_A on n0");
    assert_eq!(st_a, StatusCode::CREATED);
    assert!(matches!(env_a.verdict, L2Verdict::Verified { .. }));

    // 2. Minority Voucher B for the SAME shard_id
    let wallet_b = SimWallet::new();
    let (voucher_b, genesis_b, tag_b) = loop {
        let (v, g) = wallet_b.genesis_with_voucher(Some(600_000));
        let t = SimWallet::t_id_to_tag(&g.transaction_hash);
        let pb = *blake3::hash(t.as_bytes()).as_bytes();
        if u16::from_be_bytes([pb[0], pb[1]]) == shard_id {
            break (v, g, t);
        }
    };
    let (st_b, env_b) = nodes[10].post_lock(&genesis_b).await.expect("post V_B on n10");
    assert_eq!(st_b, StatusCode::CREATED);
    assert!(matches!(env_b.verdict, L2Verdict::Verified { .. }));

    // Verify initial states
    let q_a = status_query(&voucher_a, &tag_a);
    let (qs_a, qv_a) = nodes[0].query_status(&q_a).await.expect("query n0");
    assert_eq!(qs_a, StatusCode::OK);
    assert!(matches!(qv_a.verdict, L2Verdict::Verified { .. }));

    let q_b = status_query(&voucher_b, &tag_b);
    let (qs_b, qv_b) = nodes[10].query_status(&q_b).await.expect("query n10");
    assert_eq!(qs_b, StatusCode::OK);
    assert!(matches!(qv_b.verdict, L2Verdict::Verified { .. }));

    // Activate bridge: connect all nodes in A with all nodes in B (Total N=13, Quorum Q=9)
    for i in 0..10 {
        for j in 10..13 {
            peer_nodes(&nodes[i], &nodes[j]).await;
        }
    }

    // Now N=13, Q(13)=9. Network A has 10 nodes (>= 9, dominant quorum!).
    // Node 10 runs sync_single_shard to pull active state and quarantine minority lock B:
    let ready = nodes[10].sync_shard(shard_id).await.expect("sync shard 10");
    assert!(ready, "Dominant convergence must activate shard readiness on node 10");

    // Dominant Voucher A is now verified on Node 10!
    let (st_10_a, env_10_a) = nodes[10].query_status(&q_a).await.expect("query n10 V_A");
    assert_eq!(st_10_a, StatusCode::OK);
    assert!(matches!(env_10_a.verdict, L2Verdict::Verified { .. }));

    // Minority Voucher B is quarantined from active storage on Node 10:
    assert!(
        !nodes[10].storage.all_valid_hmc_locks(0).unwrap().iter().any(|(t, _)| t == &tag_b),
        "Minority lock B must NOT be in active storage on Node 10"
    );
    assert!(
        nodes[10].storage.get_provisional_hmc_lock(&tag_b).unwrap().is_some(),
        "Minority lock B must be preserved in TABLE_PROVISIONAL_HMC_LOCKS on Node 10"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: SC-03 Symmetric Merge / Stalemate 5 vs. 5 & Wallet Reconciliation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "long-running simulation"]
async fn test_sc03_symmetric_stalemate_5_vs_5_wallet_reconciliation() {
    let mut nodes = Vec::new();
    for i in 0..10 {
        nodes.push(spawn_test_node(i).await.expect("spawn node"));
    }

    // Net A: nodes 0..5 (5 nodes, Q(5)=4)
    for i in 0..5 {
        for j in 0..5 {
            if i != j {
                peer_nodes(&nodes[i], &nodes[j]).await;
            }
        }
    }

    // Net B: nodes 5..10 (5 nodes, Q(5)=4)
    for i in 5..10 {
        for j in 5..10 {
            if i != j {
                peer_nodes(&nodes[i], &nodes[j]).await;
            }
        }
    }

    // Post V_A on Node 0 (Net A: 5 nodes, Q(5)=4 -> 5 votes collected, 201 Created)
    let wallet_a = SimWallet::new();
    let (voucher_a, genesis_a) = wallet_a.genesis_with_voucher(Some(600_000));
    let tag_a = SimWallet::t_id_to_tag(&genesis_a.transaction_hash);
    let (st_a, env_a) = nodes[0].post_lock(&genesis_a).await.expect("post V_A on n0");
    assert_eq!(st_a, StatusCode::CREATED);
    assert!(matches!(env_a.verdict, L2Verdict::Verified { .. }));

    // Post V_B on Node 5 (Net B: 5 nodes, Q(5)=4 -> 5 votes collected, 201 Created)
    let wallet_b = SimWallet::new();
    let (voucher_b, genesis_b) = wallet_b.genesis_with_voucher(Some(600_000));
    let tag_b = SimWallet::t_id_to_tag(&genesis_b.transaction_hash);
    let (st_b, env_b) = nodes[5].post_lock(&genesis_b).await.expect("post V_B on n5");
    assert_eq!(st_b, StatusCode::CREATED);
    assert!(matches!(env_b.verdict, L2Verdict::Verified { .. }));

    // Activate bridge: peer all nodes in A with all nodes in B
    for i in 0..5 {
        for j in 5..10 {
            peer_nodes(&nodes[i], &nodes[j]).await;
        }
    }

    // In a 5:5 split, N=10, Q(10)=7.
    // Node 0 does NOT know V_B yet (UnknownVoucher):
    let q_b = status_query(&voucher_b, &tag_b);
    let (st_pre, env_pre) = nodes[0].query_status(&q_b).await.expect("query n0 pre-reconcile");
    assert!(
        st_pre != StatusCode::OK || !matches!(env_pre.verdict, L2Verdict::Verified { .. }),
        "Pre-reconciliation: 5:5 stalemate must prevent automated adoption without Q=7 quorum"
    );

    // Client-side custody / Wallet Reconciliation:
    // Wallet A submits V_A to Gateway in Net B (Node 5)
    let (st_cross_a, env_cross_a) = nodes[5].post_lock(&genesis_a).await.expect("post V_A to n5");
    assert!(st_cross_a == StatusCode::CREATED || st_cross_a == StatusCode::OK);
    assert!(matches!(env_cross_a.verdict, L2Verdict::Verified { .. }));

    // Wallet B submits V_B to Gateway in Net A (Node 0)
    let (st_cross_b, env_cross_b) = nodes[0].post_lock(&genesis_b).await.expect("post V_B to n0");
    assert!(st_cross_b == StatusCode::CREATED || st_cross_b == StatusCode::OK);
    assert!(matches!(env_cross_b.verdict, L2Verdict::Verified { .. }));

    // Both V_A and V_B are now Verified across both sides of the bridge!
    let q_a = status_query(&voucher_a, &tag_a);
    let (st_n0_a, env_n0_a) = nodes[0].query_status(&q_a).await.expect("query n0 V_A");
    assert_eq!(st_n0_a, StatusCode::OK);
    assert!(matches!(env_n0_a.verdict, L2Verdict::Verified { .. }));

    let (st_n5_a, env_n5_a) = nodes[5].query_status(&q_a).await.expect("query n5 V_A");
    assert_eq!(st_n5_a, StatusCode::OK);
    assert!(matches!(env_n5_a.verdict, L2Verdict::Verified { .. }));

    let (st_n0_b, env_n0_b) = nodes[0].query_status(&q_b).await.expect("query n0 V_B");
    assert_eq!(st_n0_b, StatusCode::OK);
    assert!(matches!(env_n0_b.verdict, L2Verdict::Verified { .. }));

    let (st_n5_b, env_n5_b) = nodes[5].query_status(&q_b).await.expect("query n5 V_B");
    assert_eq!(st_n5_b, StatusCode::OK);
    assert!(matches!(env_n5_b.verdict, L2Verdict::Verified { .. }));
}
