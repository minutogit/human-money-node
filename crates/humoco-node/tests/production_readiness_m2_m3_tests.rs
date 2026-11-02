//! Production Readiness Integration Tests for Milestones M2, M3, and M4.
//!
//! Covers:
//! - M2: Advertised address propagation over real QUIC heartbeats.
//! - M2: Dual-stack IPv6 ([::]:0) endpoint dialing an IPv4 peer over real QUIC.
//! - M3: Shard readiness merge invalidation preserving in-flight syncs.
//! - M4: Control server refusal to unlink an active daemon's control socket.

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
    network::{BoxFuture, DefaultRequestHandler, PeerManager, QuicTransport, RequestHandler},
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
    let (peer_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .unwrap();
    let now_ms: u64 = 1_750_000_000_000;
    let mature_seen_ms = now_ms - (25 * 3600 * 1000); // observed 25h ago

    {
        let storage = RedbStorage::open(&db_path).expect("open redb");
        let inserted = storage
            .record_ticket_observations_if_absent(&[
                (
                    *local_id.node_pubkey(),
                    *local_id.hrw_routing_id(),
                    mature_seen_ms,
                ),
                (
                    *peer_id.node_pubkey(),
                    *peer_id.hrw_routing_id(),
                    mature_seen_ms,
                ),
            ])
            .expect("persist ticket observations");
        assert_eq!(inserted, 2);

        // Re-recording with a newer timestamp must preserve the original first_seen_ms.
        let inserted_again = storage
            .record_ticket_observations_if_absent(&[(
                *peer_id.node_pubkey(),
                *peer_id.hrw_routing_id(),
                now_ms,
            )])
            .expect("idempotent re-record");
        assert_eq!(inserted_again, 0);
    }

    // Simulate daemon restart: reopen RedbStorage and seed a fresh PeerManager (production 24h mode)
    let storage = RedbStorage::open(&db_path).expect("reopen redb");
    let pm = PeerManager::new(vec![]);
    for (pk, hrw, seen_ms) in storage
        .all_ticket_observations()
        .expect("load observations")
    {
        let age = Duration::from_millis(now_ms.saturating_sub(seen_ms));
        pm.seed_persisted_ticket_age(pk, hrw, age);
        if pk == *local_id.node_pubkey() && hrw == *local_id.hrw_routing_id() {
            pm.seed_local_ticket_age(pk, hrw, age);
        }
    }

    // Peer reconnects with its existing mature ticket -> immediately HRW-eligible!
    let peer_addr = "127.0.0.1:19991".parse().unwrap();
    pm.learn_node_from_gossip_with_hrw_work_and_auth(
        *peer_id.node_pubkey(),
        *peer_id.hrw_routing_id(),
        peer_addr,
        0,
        Some(peer_addr),
        1,
        true,
    )
    .await;

    let (committee, _, total) = pm
        .shard_committee(*local_id.node_pubkey(), *local_id.hrw_routing_id(), 42)
        .await;
    assert_eq!(
        total, 2,
        "Both restarted mature nodes must immediately re-enter HRW"
    );
    assert_eq!(committee.len(), 2);

    // Anti-shard-hopping invariant: if peer re-mines a brand-new HrwRoutingId, it MUST incubate for 24h!
    let fresh_peer_ticket = [0xABu8; 32];
    pm.learn_node_from_gossip_with_hrw_work_and_auth(
        *peer_id.node_pubkey(),
        fresh_peer_ticket,
        peer_addr,
        0,
        Some(peer_addr),
        10,
        true,
    )
    .await;
    assert!(
        pm.hrw_incubation_remaining(peer_id.node_pubkey())
            .await
            .is_some(),
        "Newly mined replacement ticket must enter 24h pending incubation"
    );
}
