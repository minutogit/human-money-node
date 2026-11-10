//! Production Readiness Integration Tests for Milestones M2, M3, and M4.
//!
//! Covers:
//! - M2: Advertised address propagation over real QUIC heartbeats.
//! - M2: Dual-stack IPv6 ([::]:0) endpoint dialing an IPv4 peer over real QUIC.
//! - M3: Shard readiness merge invalidation preserving in-flight syncs.
//! - M4: Control server refusal to unlink an active daemon's control socket.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use humoco_node::{
    config::NodeConfig,
    control::{ControlClient, ControlResponse, ControlServer},
    daemon::{BoundAddrs, NodeDaemon, ShardReadinessManager},
    error::NodeError,
    identity::NodeIdentity,
    network::{BoxFuture, DefaultRequestHandler, HeartbeatWirePayload, NodeRequestHandler, PeerManager, QuicTransport, RequestHandler},
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::wire::{MsgType, WireHeader};

/// Simple echo request handler for frame exchange verification.
#[derive(Clone, Default)]
struct EchoHandler {
    received_requests: Arc<AtomicUsize>,
}

impl EchoHandler {
    fn new() -> Self {
        Self {
            received_requests: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl RequestHandler for EchoHandler {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), NodeError>> {
        self.received_requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let resp_type = match header.msg_type {
                x if x == MsgType::LockVerifyRequest as u16 => MsgType::LockVerifyResponse as u16,
                x if x == MsgType::Heartbeat as u16 => MsgType::HeartbeatAck as u16,
                _ => MsgType::StatusResponse as u16,
            };
            let resp_header = WireHeader::new(
                resp_type,
                header.session_seq + 1,
                header.epoch_id,
                0,
                payload.len() as u32,
            );
            Ok((resp_header, payload))
        })
    }
}

/// M2: Verifies that when `advertised_addr` is configured with port 0, it inherits the bound P2P port
/// and correctly propagates over real QUIC heartbeats to peer nodes.
#[tokio::test]
async fn test_m2_advertised_addr_propagates_over_real_quic_heartbeat() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();

    // 1. Configure and bind Node B's QUIC transport and PeerManager
    let cancel_b = CancellationToken::new();
    let pm_b = Arc::new(PeerManager::new(vec![]));
    pm_b.set_simulation_mode(true);
    pm_b.register_f2f_friend(*identity_a.node_pubkey(), None)
        .await;

    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .expect("Bind Node B transport");
    let addr_b = transport_b.local_addr().expect("Node B local addr");
    let accept_handle_b = transport_b.spawn_accept_loop();

    // 2. Configure Node A daemon with advertised_addr "203.0.113.77:0" and listen on "0.0.0.0:0"
    let dir_a = tempfile::tempdir().expect("tempdir for Node A");
    let key_path_a = dir_a.path().join("node_key.bin");
    identity_a.save_to_file(&key_path_a).expect("save key a");

    let mut config_a = NodeConfig::default();
    config_a.storage.data_dir = dir_a.path().join("data");
    config_a.identity.key_path = key_path_a;
    config_a.network.p2p_listen_addr = "0.0.0.0:0".parse().unwrap();
    config_a.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
    config_a.network.advertised_addr = Some("203.0.113.77:0".parse().unwrap());
    config_a.network.simulation_mode = true;
    config_a
        .f2f
        .trusted_pubkeys
        .push(identity_b.public_key_hex());
    config_a
        .f2f
        .peers
        .push(format!("{}@{}", identity_b.public_key_hex(), addr_b));

    let cancel_a = CancellationToken::new();
    let (tx_a, rx_a) = tokio::sync::oneshot::channel::<BoundAddrs>();
    let daemon_a =
        NodeDaemon::with_bound_sender(config_a, identity_a.clone(), cancel_a.clone(), tx_a);
    let daemon_handle_a = tokio::spawn(async move { daemon_a.run().await });

    let bound_a = tokio::time::timeout(Duration::from_secs(5), rx_a)
        .await
        .expect("Timeout waiting for Node A to bind")
        .expect("Sender dropped");
    let bound_port_a = bound_a.p2p_addr.port();
    assert_ne!(bound_port_a, 0, "Bound port must be non-zero");

    let expected_addr: SocketAddr = format!("203.0.113.77:{}", bound_port_a).parse().unwrap();

    // 3. Wait until Node B learns Node A via real QUIC heartbeat (bounded timeout up to 10s)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut learned_addr = None;
    while tokio::time::Instant::now() < deadline {
        if let Some(addr) = pm_b.get_known_node_addr(identity_a.node_pubkey()).await {
            learned_addr = Some(addr);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let learned = learned_addr.expect("Node B did not learn Node A via heartbeat within timeout");
    assert_eq!(
        learned, expected_addr,
        "Learned address must match advertised IP and bound port"
    );
    assert_ne!(
        learned.ip(),
        "0.0.0.0".parse::<std::net::IpAddr>().unwrap(),
        "Must not leak unspecified 0.0.0.0"
    );
    assert_eq!(
        learned.ip(),
        "203.0.113.77".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(learned.port(), bound_port_a);
    assert!(
        pm_b.is_known_addr(&expected_addr).await,
        "Learned address must be recognized as known"
    );

    // 4. Clean shutdown
    cancel_a.cancel();
    let res_a = daemon_handle_a.await;
    assert!(res_a.is_ok(), "Daemon A join handle failed: {:?}", res_a);
    cancel_b.cancel();
    transport_b.close();
    let _ = accept_handle_b.await;
}

/// M2: Verifies that a dual-stack IPv6 endpoint bound to `[::]:0` can successfully dial
/// an IPv4 `127.0.0.1` peer over real QUIC using IPv4-mapped IPv6 translation and P2P_QUIC_SNI.
#[tokio::test]
async fn test_m2_dual_stack_ipv6_endpoint_dials_ipv4_peer_over_real_quic() {
    let cancel_token = CancellationToken::new();

    let id_ipv6 = NodeIdentity::generate();
    let id_ipv4 = NodeIdentity::generate();

    let bind_ipv6_addr: SocketAddr = match "[::]:0".parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("Failed to parse [::]:0; skipping IPv6 dual-stack test");
            return;
        }
    };

    let pm_ipv6 = Arc::new(PeerManager::new(vec![]));
    let transport_ipv6 = match QuicTransport::bind_with_options(
        bind_ipv6_addr,
        &id_ipv6,
        pm_ipv6.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "IPv6 dual-stack [::]:0 binding unsupported or disabled in this environment ({}); skipping test",
                e
            );
            return;
        }
    };

    let echo_handler = Arc::new(EchoHandler::new());
    let pm_ipv4 = Arc::new(PeerManager::new(vec![]));
    let transport_ipv4 = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &id_ipv4,
        pm_ipv4.clone(),
        echo_handler.clone(),
        cancel_token.clone(),
    )
    .expect("Bind IPv4 transport");

    let addr_ipv6 = transport_ipv6.local_addr().expect("IPv6 local addr");
    let addr_ipv4 = transport_ipv4.local_addr().expect("IPv4 local addr");

    let accept_handle_ipv6 = transport_ipv6.spawn_accept_loop();
    let accept_handle_ipv4 = transport_ipv4.spawn_accept_loop();

    // Mutually register as F2F friends
    pm_ipv6
        .register_f2f_friend(*id_ipv4.node_pubkey(), Some(addr_ipv4))
        .await;
    pm_ipv4
        .register_f2f_friend(*id_ipv6.node_pubkey(), Some(addr_ipv6))
        .await;

    // Dial IPv4 peer from IPv6 dual-stack endpoint
    let conn = transport_ipv6
        .connect_peer(addr_ipv4)
        .await
        .expect("Connect IPv6 dual-stack -> IPv4 peer");

    // Frame exchange over real QUIC
    let test_payload = b"m2 dual stack frame exchange".to_vec();
    let req_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        1,
        0,
        test_payload.len() as u32,
    );

    let (resp_header, resp_payload) = transport_ipv6
        .send_request(&conn, &req_header, &test_payload)
        .await
        .expect("Send request & receive response");

    assert_eq!(resp_header.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(resp_payload, test_payload);
    assert_eq!(echo_handler.received_requests.load(Ordering::SeqCst), 1);

    // Clean teardown
    cancel_token.cancel();
    transport_ipv6.close();
    transport_ipv4.close();
    let _ = accept_handle_ipv6.await;
    let _ = accept_handle_ipv4.await;
}

/// M3: Verifies that invalidate_ready_shards cleans only Ready shards on network merge
/// while preserving active in-flight sync requests (Syncing state).
#[test]
fn test_m3_shard_readiness_merge_invalidation_preserves_inflight_syncs() {
    let readiness = ShardReadinessManager::new();

    // Mark shards 1 and 2 as Ready
    readiness.mark_shard_ready(1);
    readiness.mark_shard_ready(2);
    assert!(readiness.is_shard_ready(1));
    assert!(readiness.is_shard_ready(2));

    // Enqueue shard 3 for syncing
    assert!(readiness.request_sync(3), "request_sync(3) must succeed");
    assert_eq!(readiness.syncing_count(), 1);
    assert!(!readiness.is_shard_ready(3));
    assert!(readiness.is_shard_ready_or_syncing(3));

    // Invalidate ready shards on mesh merge
    let invalidated = readiness.invalidate_ready_shards();

    // Invalidation must drop exactly shards 1 and 2, keeping shard 3 in Syncing state
    assert_eq!(invalidated, 2, "Expected 2 shards to be invalidated");
    assert!(
        !readiness.is_shard_ready(1),
        "Shard 1 must no longer be ready"
    );
    assert!(
        !readiness.is_shard_ready(2),
        "Shard 2 must no longer be ready"
    );
    assert_eq!(
        readiness.syncing_count(),
        1,
        "Shard 3 must remain in syncing state"
    );
    assert!(
        readiness.is_shard_ready_or_syncing(3),
        "Shard 3 must remain recognized as syncing"
    );
}

/// M4: Verifies that ControlServer refuses to unlink an active daemon's control socket,
/// returning AddrInUse and keeping the primary server fully responsive.
#[tokio::test]
async fn test_m4_control_server_refuses_to_unlink_active_daemon_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("control_test.redb");
    let socket_path = dir.path().join("humoco.sock");

    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let peer_manager = Arc::new(PeerManager::new(vec![]));

    let cancel_token_1 = CancellationToken::new();
    let server_1 = ControlServer::new(
        socket_path.clone(),
        storage.clone(),
        engine.clone(),
        peer_manager.clone(),
        identity.clone(),
        dir.path().to_path_buf(),
        cancel_token_1.clone(),
    );

    let handle_1 = tokio::spawn(async move { server_1.run().await });

    // Wait briefly until connecting to humoco.sock succeeds
    let mut connected = false;
    for _ in 0..50 {
        if tokio::net::UnixStream::connect(&socket_path).await.is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        connected,
        "First ControlServer failed to start listening on socket"
    );

    // Attempt to run a second ControlServer on the exact same socket path
    let cancel_token_2 = CancellationToken::new();
    let server_2 = ControlServer::new(
        socket_path.clone(),
        storage.clone(),
        engine.clone(),
        peer_manager.clone(),
        NodeIdentity::generate(),
        dir.path().to_path_buf(),
        cancel_token_2.clone(),
    );

    let result_2 = server_2.run().await;
    match result_2 {
        Err(NodeError::IoWithPath { source, path }) => {
            assert_eq!(source.kind(), std::io::ErrorKind::AddrInUse);
            assert_eq!(path, socket_path);
        }
        other => panic!(
            "Expected Err(NodeError::IoWithPath) with AddrInUse, got: {:?}",
            other
        ),
    }

    // Verify socket file still exists and was NOT unlinked
    assert!(
        socket_path.exists(),
        "Active control socket must not be unlinked by competing server"
    );

    // Verify the first server still responds
    let client = ControlClient::new(socket_path.clone());
    let status = client
        .get_status()
        .await
        .expect("First ControlServer must still respond after competing server fails");
    match status {
        ControlResponse::Status { node_id, .. } => {
            assert_eq!(node_id, identity.node_id_hex());
        }
        other => panic!("Expected ControlResponse::Status, got: {:?}", other),
    }

    // Cleanly cancel the first server
    cancel_token_1.cancel();
    let res_1 = tokio::time::timeout(Duration::from_secs(3), handle_1)
        .await
        .expect("ControlServer 1 shutdown timed out")
        .expect("ControlServer 1 task join error");
    assert!(
        res_1.is_ok(),
        "ControlServer 1 finished with error: {:?}",
        res_1
    );

    flush_handle.abort();
}

/// Verifies that 24h HRW ticket maturation persisted in `TABLE_TICKET_OBSERVATIONS` survives
/// daemon restarts without resetting the cluster into a 24h outage, while a newly mined
/// `HrwRoutingId` for the same `NodePubKey` still enforces the full 24h incubation wall.
#[tokio::test]
async fn test_persisted_ticket_observations_survive_restart_while_new_tickets_incubate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("tickets.redb");

    let (local_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();
    let (qualified_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();
    let (unqualified_old_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();
    let (young_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();

    let now_ms: u64 = 1_750_000_000_000;
    let mature_seen_ms = now_ms - (25 * 3600 * 1000); // observed 25h ago
    let young_seen_ms = now_ms - (2 * 3600 * 1000);   // observed 2h ago

    {
        let storage = RedbStorage::open(&db_path).expect("open redb");
        let inserted = storage
            .record_ticket_observations(&[
                (
                    *local_id.node_pubkey(),
                    *local_id.hrw_routing_id(),
                    mature_seen_ms,
                    true,
                ),
                (
                    *qualified_peer.node_pubkey(),
                    *qualified_peer.hrw_routing_id(),
                    mature_seen_ms,
                    true,
                ),
                (
                    *unqualified_old_peer.node_pubkey(),
                    *unqualified_old_peer.hrw_routing_id(),
                    mature_seen_ms,
                    false,
                ),
                (
                    *young_peer.node_pubkey(),
                    *young_peer.hrw_routing_id(),
                    young_seen_ms,
                    true,
                ),
            ])
            .expect("persist ticket observations");
        assert_eq!(inserted, 4);

        // Re-recording with a newer timestamp must update last_seen_ms while preserving the original first_seen_ms and latched qualified flag.
        let updated = storage
            .record_ticket_observations(&[(
                *qualified_peer.node_pubkey(),
                *qualified_peer.hrw_routing_id(),
                now_ms,
                false,
            )])
            .expect("update last_seen");
        assert_eq!(updated, 1);

        // An identical re-record with unchanged timestamps is idempotent (0 modifications).
        let idempotent = storage
            .record_ticket_observations(&[(
                *qualified_peer.node_pubkey(),
                *qualified_peer.hrw_routing_id(),
                now_ms,
                false,
            )])
            .expect("idempotent re-record");
        assert_eq!(idempotent, 0);
    }

    // Simulate daemon restart: reopen RedbStorage and seed a fresh PeerManager (production 24h mode)
    let storage = RedbStorage::open(&db_path).expect("reopen redb");
    let pm = PeerManager::new(vec![]);
    pm.set_min_work_floor_for_test(1);
    for (pk, hrw, seen_ms, _last_seen_ms, qualified) in storage
        .all_ticket_observations()
        .expect("load observations")
    {
        let age = Duration::from_millis(now_ms.saturating_sub(seen_ms));
        pm.seed_persisted_ticket_state(pk, hrw, age, qualified);
        if pk == *local_id.node_pubkey() && hrw == *local_id.hrw_routing_id() {
            pm.seed_local_ticket_age(pk, hrw, age);
        }
    }

    // 1. Qualified peer reconnects -> immediately HRW & committee-eligible!
    let qualified_addr = "127.0.0.1:19991".parse().unwrap();
    pm.learn_node_from_gossip_with_hrw_work_and_auth(
        *qualified_peer.node_pubkey(),
        *qualified_peer.hrw_routing_id(),
        qualified_addr,
        0,
        Some(qualified_addr),
        1,
        true,
    )
    .await;

    // 2. Unqualified old peer (age >= 24h, but admission_qualified = false) connects -> NOT eligible!
    let unqualified_addr = "127.0.0.1:19992".parse().unwrap();
    pm.learn_node_from_gossip_with_hrw_work_and_auth(
        *unqualified_old_peer.node_pubkey(),
        *unqualified_old_peer.hrw_routing_id(),
        unqualified_addr,
        0,
        Some(unqualified_addr),
        1,
        true,
    )
    .await;

    // 3. Artificially young entry (age < 24h, admission_qualified = true) connects -> NOT eligible until age >= 24h!
    let young_addr = "127.0.0.1:19993".parse().unwrap();
    pm.learn_node_from_gossip_with_hrw_work_and_auth(
        *young_peer.node_pubkey(),
        *young_peer.hrw_routing_id(),
        young_addr,
        0,
        Some(young_addr),
        1,
        true,
    )
    .await;

    // Verify snapshot_qualified_tickets only includes qualified mature nodes
    let snap = pm.snapshot_qualified_tickets().await;
    let snap_pks: HashSet<[u8; 32]> = snap.into_iter().map(|(pk, ..)| pk).collect();
    assert!(snap_pks.contains(qualified_peer.node_pubkey()), "Qualified peer must be in snapshot");
    assert!(!snap_pks.contains(unqualified_old_peer.node_pubkey()), "Unqualified old peer must NOT be in snapshot");
    assert!(!snap_pks.contains(young_peer.node_pubkey()), "Young peer must NOT be in snapshot");

    let (committee, _, total) = pm
        .shard_committee(*local_id.node_pubkey(), *local_id.hrw_routing_id(), 42)
        .await;
    assert_eq!(
        total, 2,
        "Only local node and genuinely qualified mature peer must be committee-eligible"
    );
    assert_eq!(committee.len(), 2);
    let committee_pks: Vec<[u8; 32]> = committee.iter().map(|m| m.node_pubkey).collect();
    assert!(committee_pks.contains(local_id.node_pubkey()));
    assert!(committee_pks.contains(qualified_peer.node_pubkey()));
    assert!(!committee_pks.contains(unqualified_old_peer.node_pubkey()));
    assert!(!committee_pks.contains(young_peer.node_pubkey()));

    // Anti-shard-hopping invariant: if qualified peer re-mines a brand-new HrwRoutingId, it MUST incubate for 24h!
    let fresh_peer_ticket = [0xABu8; 32];
    pm.learn_node_from_gossip_with_hrw_work_and_auth(
        *qualified_peer.node_pubkey(),
        fresh_peer_ticket,
        qualified_addr,
        0,
        Some(qualified_addr),
        10,
        true,
    )
    .await;
    assert!(
        pm.hrw_incubation_remaining(qualified_peer.node_pubkey())
            .await
            .is_some(),
        "Newly mined replacement ticket must enter 24h pending incubation"
    );
}

/// S06-04: Verifies that real QUIC heartbeats delivered from a mature qualified peer
/// establish immediate committee eligibility, whereas heartbeats from a mature unqualified
/// old peer (lacking admission qualification) do NOT enter the active shard committee.
#[tokio::test]
async fn test_real_quic_heartbeat_persisted_ticket_eligibility() {
    let cancel_token = CancellationToken::new();

    // 1. Generate 3 nodes with mined Argon2d shard tickets
    let (local_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();
    let (qualified_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();
    let (unqualified_old_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();

    // 2. Set up local PeerManager and seed persisted ticket observations
    let pm_local = Arc::new(PeerManager::new(vec![]));
    pm_local.set_min_work_floor_for_test(1);
    let now_ms = pm_local.clock().now_ms();
    let mature_seen_ms = now_ms.saturating_sub(25 * 3600 * 1000); // 25 hours ago

    let mature_age = Duration::from_millis(now_ms.saturating_sub(mature_seen_ms));
    pm_local.seed_local_ticket_age(*local_id.node_pubkey(), *local_id.hrw_routing_id(), mature_age);
    pm_local.seed_persisted_ticket_state(
        *qualified_peer.node_pubkey(),
        *qualified_peer.hrw_routing_id(),
        mature_age,
        true, // admission_qualified = true
    );
    pm_local.seed_persisted_ticket_state(
        *unqualified_old_peer.node_pubkey(),
        *unqualified_old_peer.hrw_routing_id(),
        mature_age,
        false, // admission_qualified = false
    );

    // 3. Bind local QuicTransport and spawn accept loop
    let transport_local = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &local_id,
        pm_local.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("Bind local transport");
    let addr_local = transport_local.local_addr().expect("local addr");
    let accept_handle_local = transport_local.spawn_accept_loop();

    // 4. Bind transport for qualified peer
    let pm_qualified = Arc::new(PeerManager::new(vec![]));
    let transport_qualified = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &qualified_peer,
        pm_qualified.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("Bind qualified peer transport");
    let addr_qualified = transport_qualified.local_addr().expect("qualified addr");
    let accept_handle_qualified = transport_qualified.spawn_accept_loop();

    // 5. Bind transport for unqualified old peer
    let pm_unqualified = Arc::new(PeerManager::new(vec![]));
    let transport_unqualified = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &unqualified_old_peer,
        pm_unqualified.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("Bind unqualified peer transport");
    let addr_unqualified = transport_unqualified.local_addr().expect("unqualified addr");
    let accept_handle_unqualified = transport_unqualified.spawn_accept_loop();

    // 6. Mutual F2F friendship setup so direct QUIC heartbeats pass the gossip barrier
    pm_local
        .register_f2f_friend(*qualified_peer.node_pubkey(), Some(addr_qualified))
        .await;
    pm_qualified
        .register_f2f_friend(*local_id.node_pubkey(), Some(addr_local))
        .await;

    pm_local
        .register_f2f_friend(*unqualified_old_peer.node_pubkey(), Some(addr_unqualified))
        .await;
    pm_unqualified
        .register_f2f_friend(*local_id.node_pubkey(), Some(addr_local))
        .await;

    // 7. Deliver real QUIC heartbeat from qualified peer to local node
    let conn_qualified = transport_qualified
        .connect_peer(addr_local)
        .await
        .expect("Qualified peer connects to local node");

    let mut hb_qualified = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *qualified_peer.node_pubkey(),
        addr: addr_qualified,
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: qualified_peer.nonce(),
        hrw_routing_id: *qualified_peer.hrw_routing_id(),
        ticket_epoch_t0: qualified_peer.t0(),
        ttl: 16,
    };
    hb_qualified.sign_origin(&qualified_peer, 0, humoco_sim_core::types::NetworkId::default());
    let payload_q = bincode::serialize(&hb_qualified).expect("serialize qualified hb");
    let header_q = WireHeader::new(
        MsgType::Heartbeat as u16,
        1,
        0,
        0,
        payload_q.len() as u32,
    );
    transport_qualified
        .send_unidirectional(&conn_qualified, &header_q, &payload_q)
        .await
        .expect("Send qualified heartbeat over QUIC");

    // 8. Deliver real QUIC heartbeat from unqualified old peer to local node
    let conn_unqualified = transport_unqualified
        .connect_peer(addr_local)
        .await
        .expect("Unqualified peer connects to local node");

    let mut hb_unqualified = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *unqualified_old_peer.node_pubkey(),
        addr: addr_unqualified,
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: unqualified_old_peer.nonce(),
        hrw_routing_id: *unqualified_old_peer.hrw_routing_id(),
        ticket_epoch_t0: unqualified_old_peer.t0(),
        ttl: 16,
    };
    hb_unqualified.sign_origin(&unqualified_old_peer, 0, humoco_sim_core::types::NetworkId::default());
    let payload_u = bincode::serialize(&hb_unqualified).expect("serialize unqualified hb");
    let header_u = WireHeader::new(
        MsgType::Heartbeat as u16,
        1,
        0,
        0,
        payload_u.len() as u32,
    );
    transport_unqualified
        .send_unidirectional(&conn_unqualified, &header_u, &payload_u)
        .await
        .expect("Send unqualified heartbeat over QUIC");

    // 9. Wait for both heartbeats to be processed by local PeerManager
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let snap = pm_local.snapshot_qualified_tickets().await;
        if snap.iter().any(|(pk, ..)| pk == qualified_peer.node_pubkey()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 10. Assert exact committee eligibility
    assert!(
        pm_local.is_hrw_eligible(qualified_peer.node_pubkey()).await,
        "Mature qualified peer must be HRW eligible after real QUIC heartbeat"
    );
    assert!(
        !pm_local.is_hrw_eligible(unqualified_old_peer.node_pubkey()).await,
        "Mature unqualified peer must NOT be HRW eligible after real QUIC heartbeat"
    );

    let (committee, _, total) = pm_local
        .shard_committee(*local_id.node_pubkey(), *local_id.hrw_routing_id(), 42)
        .await;
    assert_eq!(
        total, 2,
        "Only local node and qualified peer should be committee-eligible"
    );
    assert_eq!(committee.len(), 2);
    let committee_pks: Vec<[u8; 32]> = committee.iter().map(|m| m.node_pubkey).collect();
    assert!(committee_pks.contains(local_id.node_pubkey()));
    assert!(committee_pks.contains(qualified_peer.node_pubkey()));
    assert!(!committee_pks.contains(unqualified_old_peer.node_pubkey()));

    // 11. Clean teardown
    cancel_token.cancel();
    transport_local.close();
    transport_qualified.close();
    transport_unqualified.close();
    let _ = accept_handle_local.await;
    let _ = accept_handle_qualified.await;
    let _ = accept_handle_unqualified.await;
}

#[tokio::test]
async fn test_s06_10_dormant_remote_ticket_retention_60_days_and_restart() {
    let cancel = CancellationToken::new();
    let observer = NodeIdentity::generate();
    let relay = NodeIdentity::generate();
    let (origin, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket origin");

    let pm_obs = Arc::new(PeerManager::with_f2f(vec![], vec![*relay.node_pubkey()]));
    pm_obs.set_min_work_floor_for_test(1);
    let pm_rel = Arc::new(PeerManager::with_f2f(vec![], vec![*observer.node_pubkey()]));
    pm_rel.set_min_work_floor_for_test(1);

    let receiver = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &observer,
        pm_obs.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind receiver");

    let sender = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &relay,
        pm_rel.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind sender");

    let receiver_addr = receiver.local_addr().expect("receiver addr");
    let sender_addr = sender.local_addr().expect("sender addr");

    pm_obs.register_f2f_friend(*relay.node_pubkey(), Some(sender_addr)).await;
    pm_rel.register_f2f_friend(*observer.node_pubkey(), Some(receiver_addr)).await;

    receiver.spawn_accept_loop();
    sender.spawn_accept_loop();

    let conn = sender
        .connect_peer_unchecked(receiver_addr)
        .await
        .expect("connect");

    let origin_addr: SocketAddr = "127.0.0.1:32010".parse().unwrap();

    // Seed legitimately qualified state for remote non-friend origin (>24h incubation, qualified=true)
    pm_obs.seed_persisted_ticket_state(
        *origin.node_pubkey(),
        *origin.hrw_routing_id(),
        Duration::from_secs(25 * 3600),
        true,
    );
    pm_obs
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *origin.node_pubkey(),
            *origin.hrw_routing_id(),
            origin_addr,
            1,
            Some(sender_addr),
            origin.work_score(),
            true,
        )
        .await;

    // Simulate 61 days of dormancy (>60-day remote metadata retention per Spec 07 §4 / INV-0705)
    pm_obs
        .set_last_seen_for_test(
            origin.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(61 * 86_400),
        )
        .await;

    // Prior to new heartbeat: origin is stale and excluded from committee
    let (before_comm, _, _) = pm_obs
        .shard_committee(*observer.node_pubkey(), *observer.hrw_routing_id(), 42)
        .await;
    assert!(
        !before_comm.iter().any(|m| m.node_pubkey == *origin.node_pubkey()),
        "Stale origin must be excluded from committee"
    );

    // Deliver ONE fresh authenticated origin-signed heartbeat over real QUIC via relay
    let mut hb = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *origin.node_pubkey(),
        addr: origin_addr,
        timestamp_ms: pm_obs.net_time_ms(),
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: *origin.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 15,
    };
    hb.sign_origin(&origin, pm_obs.net_time_ms(), humoco_sim_core::types::NetworkId::Mainnet);
    let bytes = bincode::serialize(&hb).unwrap();
    let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bytes.len() as u32);
    hdr.reserved = 1; // hops = 1 (relayed)
    sender.send_unidirectional(&conn, &hdr, &bytes).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    // S06-10 Invariant: After 61 days of dormancy, delivering 1 heartbeat must NOT restore immediate
    // committee eligibility or latched qualification! The expired remote identity must re-incubate as a newcomer.
    let (after_comm, _, _) = pm_obs
        .shard_committee(*observer.node_pubkey(), *observer.hrw_routing_id(), 42)
        .await;
    assert!(
        !after_comm.iter().any(|m| m.node_pubkey == *origin.node_pubkey()),
        "S06-10: Returning remote non-friend dormant for 61d (>60d retention) must NOT be committee-eligible after 1 heartbeat"
    );
    assert!(
        !pm_obs.is_hrw_eligible(origin.node_pubkey()).await,
        "S06-10: Returning remote non-friend dormant for 61d must NOT be HRW eligible after 1 heartbeat"
    );

    // 2. Retention boundary test inside retention (< 60 days, e.g. 59 days):
    let (inside_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket inside");
    let inside_addr: SocketAddr = "127.0.0.1:32011".parse().unwrap();
    pm_obs.seed_persisted_ticket_state(
        *inside_peer.node_pubkey(),
        *inside_peer.hrw_routing_id(),
        Duration::from_secs(25 * 3600),
        true,
    );
    pm_obs
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *inside_peer.node_pubkey(),
            *inside_peer.hrw_routing_id(),
            inside_addr,
            1,
            Some(sender_addr),
            inside_peer.work_score(),
            true,
        )
        .await;
    pm_obs
        .set_last_seen_for_test(
            inside_peer.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(59 * 86_400),
        )
        .await;

    // Inside 60 days: fresh heartbeat refreshes presence and retains justified admission
    let mut hb_inside = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *inside_peer.node_pubkey(),
        addr: inside_addr,
        timestamp_ms: pm_obs.net_time_ms(),
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: *inside_peer.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 15,
    };
    hb_inside.sign_origin(&inside_peer, pm_obs.net_time_ms(), humoco_sim_core::types::NetworkId::Mainnet);
    let bytes_inside = bincode::serialize(&hb_inside).unwrap();
    let mut hdr_inside = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, bytes_inside.len() as u32);
    hdr_inside.reserved = 1;
    sender.send_unidirectional(&conn, &hdr_inside, &bytes_inside).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if pm_obs.is_hrw_eligible(inside_peer.node_pubkey()).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        pm_obs.is_hrw_eligible(inside_peer.node_pubkey()).await,
        "Remote non-friend returning within < 60 days must retain qualified admission"
    );

    // 3. RedbStorage + daemon restart restoration:
    // Persisted remote ticket observations older than 60 days MUST NOT resurrect qualification on restart.
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("retention_test.redb");
    let now_boot_ms: u64 = 2_000_000_000_000;
    let expired_last_seen = now_boot_ms - (61 * 86_400 * 1000);
    let valid_last_seen = now_boot_ms - (59 * 86_400 * 1000);
    let (expired_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket expired");
    let (retained_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket retained");
    let (friend_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine ticket friend");

    {
        let storage = RedbStorage::open(&db_path).expect("open redb");
        storage
            .record_ticket_observation_records(&[
                (
                    *expired_peer.node_pubkey(),
                    *expired_peer.hrw_routing_id(),
                    now_boot_ms - (70 * 86_400 * 1000),
                    expired_last_seen,
                    true,
                ),
                (
                    *retained_peer.node_pubkey(),
                    *retained_peer.hrw_routing_id(),
                    now_boot_ms - (70 * 86_400 * 1000),
                    valid_last_seen,
                    true,
                ),
                (
                    *friend_peer.node_pubkey(),
                    *friend_peer.hrw_routing_id(),
                    now_boot_ms - (70 * 86_400 * 1000),
                    expired_last_seen, // 61 days ago for direct friend
                    true,
                ),
            ])
            .expect("record records");
    }

    // Reopen and simulate startup restoration with friend configured
    let storage = RedbStorage::open(&db_path).expect("reopen redb");
    let pm_fresh = Arc::new(PeerManager::with_f2f(vec![], vec![*friend_peer.node_pubkey()]));
    pm_fresh.set_min_work_floor_for_test(1);

    let observations = storage.all_ticket_observations().expect("load all");
    for (pk, hrw, first_seen_ms, last_seen_ms, admission_qualified) in &observations {
        let is_direct_friend = pm_fresh.is_f2f_friend(pk).await;
        let retention_ms = if is_direct_friend {
            humoco_node::network::manager::DIRECT_FRIEND_RETENTION_MS
        } else {
            humoco_node::network::manager::REMOTE_METADATA_RETENTION_MS
        };
        let elapsed = now_boot_ms.saturating_sub(*last_seen_ms);
        if elapsed > retention_ms {
            continue; // Dropped on startup
        }
        let age = Duration::from_millis(now_boot_ms.saturating_sub(*first_seen_ms));
        pm_fresh.seed_persisted_ticket_state_with_last_seen(*pk, *hrw, age, *admission_qualified, *last_seen_ms);
    }

    // Connect them to pm_fresh:
    let addr_test: SocketAddr = "127.0.0.1:32015".parse().unwrap();
    // 1) Expired remote peer: qualification was dropped, treated as newcomer (immature)
    pm_fresh
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *expired_peer.node_pubkey(),
            *expired_peer.hrw_routing_id(),
            addr_test,
            1,
            Some(addr_test),
            expired_peer.work_score(),
            true,
        )
        .await;
    assert!(
        !pm_fresh.is_hrw_eligible(expired_peer.node_pubkey()).await,
        "Expired remote peer (>60d) must NOT have qualification restored on restart"
    );

    // 2) Retained remote peer (<60d): qualification preserved
    pm_fresh
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *retained_peer.node_pubkey(),
            *retained_peer.hrw_routing_id(),
            addr_test,
            1,
            Some(addr_test),
            retained_peer.work_score(),
            true,
        )
        .await;
    assert!(
        pm_fresh.is_hrw_eligible(retained_peer.node_pubkey()).await,
        "Retained remote peer (<60d) MUST have qualification restored on restart"
    );

    // 3) Direct friend (61d inactive): within 1-year direct friend retention, qualification preserved!
    let work_friend = friend_peer.work_score().max(retained_peer.work_score());
    pm_fresh
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *friend_peer.node_pubkey(),
            *friend_peer.hrw_routing_id(),
            addr_test,
            0,
            Some(addr_test),
            work_friend,
            true,
        )
        .await;
    assert!(
        pm_fresh.is_hrw_eligible(friend_peer.node_pubkey()).await,
        "Direct friend inactive for 61d (within 1-year policy) MUST have qualification preserved on restart"
    );

    // 4) Invariant verification: Live voucher locks and fraud bans never expired
    let ban_pk = [0xbb; 32];
    storage.ban_node(&ban_pk, now_boot_ms).expect("record ban");
    assert!(storage.is_node_banned(&ban_pk).expect("check ban"));
    // Prune dormant ticket observations
    storage
        .prune_dormant_ticket_observations(now_boot_ms, |pk| *pk == *friend_peer.node_pubkey())
        .expect("prune");
    assert!(
        storage.is_node_banned(&ban_pk).expect("check ban intact"),
        "Irreversible fraud bans must NEVER be pruned by metadata retention"
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_s06_11_periodic_ticket_persistence_preserves_last_seen_and_retention_boundary() {
    let cancel = CancellationToken::new();

    let observer = NodeIdentity::generate();
    let relay = NodeIdentity::generate();
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("s06_11.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (obs_engine, _) = DualTierEngine::new(storage.clone());

    let pm_obs = Arc::new(PeerManager::with_f2f(vec![], vec![*relay.node_pubkey()]));
    pm_obs.set_storage(Arc::downgrade(&storage));
    pm_obs.set_engine(&obs_engine);
    pm_obs.set_min_work_floor_for_test(1);

    let pm_rel = Arc::new(PeerManager::with_f2f(vec![], vec![*observer.node_pubkey()]));
    pm_rel.set_min_work_floor_for_test(1);

    let receiver = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &observer,
        pm_obs.clone(),
        Arc::new(NodeRequestHandler::with_peer_manager(
            obs_engine.clone(),
            storage.clone(),
            observer.clone(),
            pm_obs.clone(),
        )),
        cancel.clone(),
    )
    .expect("bind receiver");

    let sender = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &relay,
        pm_rel.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind sender");

    let receiver_addr = receiver.local_addr().expect("receiver addr");
    let sender_addr = sender.local_addr().expect("sender addr");

    pm_obs.register_f2f_friend(*relay.node_pubkey(), Some(sender_addr)).await;
    pm_rel.register_f2f_friend(*observer.node_pubkey(), Some(receiver_addr)).await;

    receiver.spawn_accept_loop();
    sender.spawn_accept_loop();

    let _conn = sender
        .connect_peer_unchecked(receiver_addr)
        .await
        .expect("connect");

    // 1. Remote tickets
    let (origin, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine origin");
    let origin_addr: SocketAddr = "127.0.0.1:32010".parse().unwrap();

    let (retained_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine retained");
    let retained_addr: SocketAddr = "127.0.0.1:32011".parse().unwrap();

    let (direct_friend_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine friend");
    let friend_addr: SocketAddr = "127.0.0.1:32012".parse().unwrap();
    pm_obs.register_f2f_friend(*direct_friend_peer.node_pubkey(), Some(friend_addr)).await;

    let (observed_peer, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine observed");
    let observed_addr: SocketAddr = "127.0.0.1:32013".parse().unwrap();

    // 2. Controlled initial time: seed qualified states
    let base_time_ms = pm_obs.net_time_ms();
    let fifty_nine_days_ms = 59 * 86_400 * 1000;
    let fifty_nine_days_ago_ms = base_time_ms.saturating_sub(fifty_nine_days_ms);
    let age_59d = Duration::from_secs(59 * 86_400 + 25 * 3600);

    // Origin: last seen 59 days ago
    pm_obs.seed_persisted_ticket_state_with_last_seen(
        *origin.node_pubkey(),
        *origin.hrw_routing_id(),
        age_59d,
        true,
        fifty_nine_days_ago_ms,
    );
    pm_obs
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *origin.node_pubkey(),
            *origin.hrw_routing_id(),
            origin_addr,
            1,
            Some(sender_addr),
            origin.work_score(),
            true,
        )
        .await;
    pm_obs
        .set_last_seen_for_test(
            origin.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(59 * 86_400),
        )
        .await;

    // Retained peer: 57 days ago (< 60d after +2d)
    let fifty_seven_days_ms = 57 * 86_400 * 1000;
    let fifty_seven_days_ago_ms = base_time_ms.saturating_sub(fifty_seven_days_ms);
    let age_57d = Duration::from_secs(57 * 86_400 + 25 * 3600);
    pm_obs.seed_persisted_ticket_state_with_last_seen(
        *retained_peer.node_pubkey(),
        *retained_peer.hrw_routing_id(),
        age_57d,
        true,
        fifty_seven_days_ago_ms,
    );
    pm_obs
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *retained_peer.node_pubkey(),
            *retained_peer.hrw_routing_id(),
            retained_addr,
            1,
            Some(sender_addr),
            retained_peer.work_score(),
            true,
        )
        .await;
    pm_obs
        .set_last_seen_for_test(
            retained_peer.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(57 * 86_400),
        )
        .await;

    // Direct friend: 65 days ago (>60d, <365d)
    let sixty_five_days_ms = 65 * 86_400 * 1000;
    let sixty_five_days_ago_ms = base_time_ms.saturating_sub(sixty_five_days_ms);
    let age_65d = Duration::from_secs(65 * 86_400 + 25 * 3600);
    pm_obs.seed_persisted_ticket_state_with_last_seen(
        *direct_friend_peer.node_pubkey(),
        *direct_friend_peer.hrw_routing_id(),
        age_65d,
        true,
        sixty_five_days_ago_ms,
    );
    pm_obs
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *direct_friend_peer.node_pubkey(),
            *direct_friend_peer.hrw_routing_id(),
            friend_addr,
            0,
            None,
            direct_friend_peer.work_score(),
            true,
        )
        .await;
    pm_obs
        .set_last_seen_for_test(
            direct_friend_peer.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(65 * 86_400),
        )
        .await;

    // Observed peer: 10 days ago
    let ten_days_ms = 10 * 86_400 * 1000;
    let ten_days_ago_ms = base_time_ms.saturating_sub(ten_days_ms);
    let age_10d = Duration::from_secs(10 * 86_400 + 25 * 3600);
    pm_obs.seed_persisted_ticket_state_with_last_seen(
        *observed_peer.node_pubkey(),
        *observed_peer.hrw_routing_id(),
        age_10d,
        true,
        ten_days_ago_ms,
    );
    pm_obs
        .learn_node_from_gossip_with_hrw_work_and_auth(
            *observed_peer.node_pubkey(),
            *observed_peer.hrw_routing_id(),
            observed_addr,
            1,
            Some(sender_addr),
            observed_peer.work_score(),
            true,
        )
        .await;
    pm_obs
        .set_last_seen_for_test(
            observed_peer.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(10 * 86_400),
        )
        .await;

    // 3. Execute periodic maintenance persistence tick
    pm_obs
        .persist_periodic_ticket_observations(storage.clone(), None)
        .await
        .expect("persist observations");

    // S06-11 Invariant: on-disk last_seen_ms in RedbStorage must NOT be artificially advanced to ticker execution time!
    let records = storage
        .all_ticket_observations()
        .expect("read all observations");
    let origin_record = records
        .iter()
        .find(|(pk, ..)| pk == origin.node_pubkey())
        .expect("origin ticket record in storage");
    let origin_disk_last_seen = origin_record.3;
    assert!(
        origin_disk_last_seen <= fifty_nine_days_ago_ms + 1000,
        "S06-11: On-disk last_seen_ms must NOT be artificially advanced to ticker execution time! Got {}, expected <= {}",
        origin_disk_last_seen,
        fifty_nine_days_ago_ms + 1000
    );

    // 4. Close and reopen RedbStorage, advance controlled network time by 2 days (actual absence = 61 days > 60d)
    cancel.cancel();
    receiver.close();
    receiver.drain_tasks().await;
    sender.close();
    sender.drain_tasks().await;
    drop(receiver);
    drop(sender);
    drop(pm_obs);
    drop(obs_engine);
    drop(storage);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cancel2 = CancellationToken::new();
    let reopened_storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (reopened_engine, _) = DualTierEngine::new(reopened_storage.clone());
    let pm_obs2 = Arc::new(PeerManager::with_f2f(
        vec![],
        vec![*relay.node_pubkey(), *direct_friend_peer.node_pubkey()],
    ));
    pm_obs2.set_storage(Arc::downgrade(&reopened_storage));
    pm_obs2.set_engine(&reopened_engine);
    pm_obs2.set_min_work_floor_for_test(1);

    // Advance controlled time by 2 days
    let two_days_ms = 2 * 86_400 * 1000;
    pm_obs2.clock().advance_time_for_test(two_days_ms);
    let boot_now_ms = pm_obs2.net_time_ms();

    // Restore via restore_persisted_ticket_observations
    pm_obs2
        .restore_persisted_ticket_observations(&reopened_storage, boot_now_ms, None)
        .await
        .expect("restore observations");

    // Rebind QUIC for delivery
    let receiver2 = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &observer,
        pm_obs2.clone(),
        Arc::new(NodeRequestHandler::with_peer_manager(
            reopened_engine.clone(),
            reopened_storage.clone(),
            observer.clone(),
            pm_obs2.clone(),
        )),
        cancel2.clone(),
    )
    .expect("bind receiver2");

    let sender2 = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &relay,
        pm_rel.clone(),
        Arc::new(DefaultRequestHandler),
        cancel2.clone(),
    )
    .expect("bind sender2");

    let receiver2_addr = receiver2.local_addr().unwrap();
    let sender2_addr = sender2.local_addr().unwrap();
    pm_obs2.register_f2f_friend(*relay.node_pubkey(), Some(sender2_addr)).await;
    pm_rel.register_f2f_friend(*observer.node_pubkey(), Some(receiver2_addr)).await;

    receiver2.spawn_accept_loop();
    sender2.spawn_accept_loop();
    let conn2 = sender2.connect_peer_unchecked(receiver2_addr).await.expect("connect2");

    // Deliver 1 fresh origin-signed heartbeat over real QUIC through relay
    let mut hb_origin = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *origin.node_pubkey(),
        addr: origin_addr,
        timestamp_ms: pm_obs2.net_time_ms(),
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: origin.nonce(),
        hrw_routing_id: *origin.hrw_routing_id(),
        ticket_epoch_t0: origin.t0(),
        ttl: 15,
    };
    hb_origin.sign_origin(&origin, pm_obs2.net_time_ms(), humoco_sim_core::types::NetworkId::Mainnet);
    let bytes_orig = bincode::serialize(&hb_origin).unwrap();
    let mut hdr_orig = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bytes_orig.len() as u32);
    hdr_orig.reserved = 1; // relayed
    sender2.send_unidirectional(&conn2, &hdr_orig, &bytes_orig).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    // S06-11 Invariant: Returning expired remote identity (61 days absence) must NOT reuse prior qualification!
    assert!(
        !pm_obs2.is_hrw_eligible(origin.node_pubkey()).await,
        "S06-11: Returning remote non-friend absent for 61d (>60d retention) must NOT reuse prior qualification after 1 heartbeat"
    );

    // Control 1: Retained-history control within 60 days (57d + 2d = 59d)
    let mut hb_retained = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *retained_peer.node_pubkey(),
        addr: retained_addr,
        timestamp_ms: pm_obs2.net_time_ms(),
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: retained_peer.nonce(),
        hrw_routing_id: *retained_peer.hrw_routing_id(),
        ticket_epoch_t0: retained_peer.t0(),
        ttl: 15,
    };
    hb_retained.sign_origin(&retained_peer, pm_obs2.net_time_ms(), humoco_sim_core::types::NetworkId::Mainnet);
    let bytes_ret = bincode::serialize(&hb_retained).unwrap();
    let mut hdr_ret = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, bytes_ret.len() as u32);
    hdr_ret.reserved = 1;
    sender2.send_unidirectional(&conn2, &hdr_ret, &bytes_ret).await.unwrap();

    let deadline_ret = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline_ret {
        if pm_obs2.is_hrw_eligible(retained_peer.node_pubkey()).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        pm_obs2.is_hrw_eligible(retained_peer.node_pubkey()).await,
        "Control 1: Remote peer within 60-day retention (59d) must retain qualification upon fresh heartbeat"
    );

    // Control 2: Direct-friend control (>60d, <365d -> 67d)
    let mut hb_friend = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *direct_friend_peer.node_pubkey(),
        addr: friend_addr,
        timestamp_ms: pm_obs2.net_time_ms(),
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: direct_friend_peer.nonce(),
        hrw_routing_id: *direct_friend_peer.hrw_routing_id(),
        ticket_epoch_t0: direct_friend_peer.t0(),
        ttl: 15,
    };
    hb_friend.sign_origin(&direct_friend_peer, pm_obs2.net_time_ms(), humoco_sim_core::types::NetworkId::Mainnet);
    let bytes_fr = bincode::serialize(&hb_friend).unwrap();
    let mut hdr_fr = WireHeader::new(MsgType::Heartbeat as u16, 3, 0, 0, bytes_fr.len() as u32);
    hdr_fr.reserved = 1;
    sender2.send_unidirectional(&conn2, &hdr_fr, &bytes_fr).await.unwrap();

    let deadline_fr = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline_fr {
        if pm_obs2.is_hrw_eligible(direct_friend_peer.node_pubkey()).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        pm_obs2.is_hrw_eligible(direct_friend_peer.node_pubkey()).await,
        "Control 2: Direct friend within 365-day retention (67d) must retain qualification"
    );

    // Control 3: Genuine accepted observation control legitimately advances last_seen_ms
    let fresh_obs_time_ms = pm_obs2.net_time_ms();
    let mut hb_obs = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *observed_peer.node_pubkey(),
        addr: observed_addr,
        timestamp_ms: fresh_obs_time_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: observed_peer.nonce(),
        hrw_routing_id: *observed_peer.hrw_routing_id(),
        ticket_epoch_t0: observed_peer.t0(),
        ttl: 15,
    };
    hb_obs.sign_origin(&observed_peer, fresh_obs_time_ms, humoco_sim_core::types::NetworkId::Mainnet);
    let bytes_obs = bincode::serialize(&hb_obs).unwrap();
    let mut hdr_obs = WireHeader::new(MsgType::Heartbeat as u16, 4, 0, 0, bytes_obs.len() as u32);
    hdr_obs.reserved = 1;
    sender2.send_unidirectional(&conn2, &hdr_obs, &bytes_obs).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    pm_obs2
        .persist_periodic_ticket_observations(reopened_storage.clone(), None)
        .await
        .expect("persist observations after fresh observation");

    let recs_after = reopened_storage
        .all_ticket_observations()
        .expect("read all observations after fresh");
    let obs_rec = recs_after
        .iter()
        .find(|(pk, ..)| pk == observed_peer.node_pubkey())
        .expect("observed peer record");
    let obs_disk_last_seen = obs_rec.3;
    assert!(
        obs_disk_last_seen >= fresh_obs_time_ms.saturating_sub(1000)
            && obs_disk_last_seen <= fresh_obs_time_ms.saturating_add(1000),
        "Control 3: Genuine accepted observation must legitimately advance last_seen_ms on persistence tick! Got {}, expected around {}",
        obs_disk_last_seen,
        fresh_obs_time_ms
    );

    cancel2.cancel();
}

#[tokio::test]
async fn test_s06_16_annual_friendship_expiry_deactivation_restart_and_reactivation() {
    let cancel = CancellationToken::new();
    let receiver_id = NodeIdentity::generate();
    let expired_friend_id = NodeIdentity::generate();
    let valid_friend_id = NodeIdentity::generate();

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("f2f_test.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());

    let receiver_pm = Arc::new(PeerManager::with_f2f(
        vec![],
        vec![*expired_friend_id.node_pubkey(), *valid_friend_id.node_pubkey()],
    ));
    receiver_pm.set_simulation_mode(true);
    receiver_pm.set_storage(Arc::downgrade(&storage));

    let receiver_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &receiver_id,
        receiver_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let receiver_addr = receiver_transport.local_addr().unwrap();
    receiver_transport.spawn_accept_loop();

    let expired_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*receiver_id.node_pubkey()]));
    expired_pm.set_simulation_mode(true);
    let expired_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &expired_friend_id,
        expired_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let expired_addr = expired_transport.local_addr().unwrap();
    expired_transport.spawn_accept_loop();

    let valid_pm = Arc::new(PeerManager::with_f2f(vec![], vec![*receiver_id.node_pubkey()]));
    valid_pm.set_simulation_mode(true);
    let valid_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &valid_friend_id,
        valid_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let valid_addr = valid_transport.local_addr().unwrap();
    valid_transport.spawn_accept_loop();

    receiver_pm
        .register_f2f_friend(*expired_friend_id.node_pubkey(), Some(expired_addr))
        .await;
    receiver_pm
        .register_f2f_friend(*valid_friend_id.node_pubkey(), Some(valid_addr))
        .await;
    expired_pm
        .register_f2f_friend(*receiver_id.node_pubkey(), Some(receiver_addr))
        .await;
    valid_pm
        .register_f2f_friend(*receiver_id.node_pubkey(), Some(receiver_addr))
        .await;

    // Both peers learned
    receiver_pm
        .learn_node_from_gossip_with_hrw(
            *expired_friend_id.node_pubkey(),
            *expired_friend_id.hrw_routing_id(),
            expired_addr,
            0,
            None,
        )
        .await;
    receiver_pm
        .learn_node_from_gossip_with_hrw(
            *valid_friend_id.node_pubkey(),
            *valid_friend_id.hrw_routing_id(),
            valid_addr,
            0,
            None,
        )
        .await;

    // Set Friend A inactive by > 365 days (366 days ago)
    let one_year_plus = humoco_node::network::manager::DIRECT_FRIEND_RETENTION
        + Duration::from_secs(86400);
    receiver_pm
        .set_last_seen_for_test(
            expired_friend_id.node_pubkey(),
            std::time::Instant::now() - one_year_plus,
        )
        .await;

    // Control Friend B active (10 minutes ago)
    receiver_pm
        .set_last_seen_for_test(
            valid_friend_id.node_pubkey(),
            std::time::Instant::now() - Duration::from_secs(600),
        )
        .await;

    // Prune dormant nodes
    receiver_pm
        .prune_dormant_known_nodes(std::time::Instant::now())
        .await;

    // S06-16 / INV-0705: Friend A must be DEACTIVATED across authorization
    assert!(
        !receiver_pm.is_f2f_friend(expired_friend_id.node_pubkey()).await,
        "Expired friend >365 days must return is_f2f_friend == false"
    );
    assert!(
        !receiver_pm
            .can_accept_gossip(&expired_addr, Some(expired_friend_id.node_pubkey()))
            .await,
        "Expired friend edge must not accept gossip"
    );
    assert!(
        !receiver_pm
            .can_authorize_direct_rpc(&expired_addr, Some(expired_friend_id.node_pubkey()))
            .await,
        "Expired friend edge must not authorize direct RPC"
    );

    // Valid friend control must remain active
    assert!(
        receiver_pm.is_f2f_friend(valid_friend_id.node_pubkey()).await,
        "Valid friend control must remain active"
    );
    assert!(
        receiver_pm
            .can_accept_gossip(&valid_addr, Some(valid_friend_id.node_pubkey()))
            .await,
        "Valid friend control must accept gossip"
    );

    // Real QUIC verification: Expired friend heartbeat must be rejected by Gossip Barrier
    let expired_conn = expired_transport
        .connect_peer_unchecked(receiver_addr)
        .await
        .unwrap();
    let mut hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *expired_friend_id.node_pubkey(),
        addr: expired_addr,
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: *expired_friend_id.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 1,
    };
    hb.sign_origin(
        &expired_friend_id,
        receiver_pm.net_time_ms(),
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let bytes = bincode::serialize(&hb).unwrap();
    let mut header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bytes.len() as u32);
    header.reserved = 1;
    let _ = expired_transport
        .send_unidirectional(&expired_conn, &header, &bytes)
        .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Known node info for expired friend must not be learned from gossip
    assert!(
        receiver_pm
            .get_known_node_info(expired_friend_id.node_pubkey())
            .await
            .is_none(),
        "Expired friend heartbeat must be rejected and not re-learned via gossip"
    );

    // Valid friend heartbeat over real QUIC must succeed and update known node info
    let valid_conn = valid_transport
        .connect_peer_unchecked(receiver_addr)
        .await
        .unwrap();
    let mut hb_valid = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *valid_friend_id.node_pubkey(),
        addr: valid_addr,
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: *valid_friend_id.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 1,
    };
    hb_valid.sign_origin(
        &valid_friend_id,
        receiver_pm.net_time_ms(),
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let bytes_valid = bincode::serialize(&hb_valid).unwrap();
    let mut header_valid =
        WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bytes_valid.len() as u32);
    header_valid.reserved = 1;
    let _ = valid_transport
        .send_unidirectional(&valid_conn, &header_valid, &bytes_valid)
        .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        receiver_pm
            .get_known_node_info(valid_friend_id.node_pubkey())
            .await
            .is_some(),
        "Valid friend heartbeat must be accepted over real QUIC"
    );

    // Restart test: create new PeerManager loading same storage with configured friend
    let restarted_pm = Arc::new(PeerManager::with_f2f(
        vec![(Some(*expired_friend_id.node_pubkey()), expired_addr)],
        vec![*expired_friend_id.node_pubkey()],
    ));
    restarted_pm.set_simulation_mode(true);
    let restored = restarted_pm.restore_deactivated_friends(&storage).await.unwrap();
    assert!(restored >= 1);
    assert!(
        !restarted_pm.is_f2f_friend(expired_friend_id.node_pubkey()).await,
        "Expired friend must remain deactivated after restart"
    );

    // Explicit operator reactivation:
    receiver_pm
        .register_f2f_friend(*expired_friend_id.node_pubkey(), Some(expired_addr))
        .await;
    assert!(
        receiver_pm.is_f2f_friend(expired_friend_id.node_pubkey()).await,
        "Friend must be active after explicit operator reactivation"
    );
    assert!(
        receiver_pm
            .can_accept_gossip(&expired_addr, Some(expired_friend_id.node_pubkey()))
            .await,
        "Gossip must be accepted after explicit reactivation"
    );

    cancel.cancel();
    receiver_transport.close();
    expired_transport.close();
    valid_transport.close();
    receiver_transport.drain_tasks().await;
    expired_transport.drain_tasks().await;
    valid_transport.drain_tasks().await;
}

