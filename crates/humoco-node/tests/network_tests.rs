use humoco_node::network::{
    BoxFuture, DefaultRequestHandler, PeerManager, PeerStatus, QuicTransport, RequestHandler,
};
use humoco_node::NodeIdentity;
use humoco_sim_core::wire::{MsgType, WireHeader};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct EchoHandler {
    received_requests: Arc<AtomicUsize>,
    received_unidirectional: Arc<AtomicUsize>,
}

impl EchoHandler {
    fn new() -> Self {
        Self {
            received_requests: Arc::new(AtomicUsize::new(0)),
            received_unidirectional: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl RequestHandler for EchoHandler {
    fn handle(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::NodeError>> {
        self.received_requests.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let resp_type = match header.msg_type {
                x if x == MsgType::LockVerifyRequest as u16 => MsgType::LockVerifyResponse as u16,
                x if x == MsgType::Heartbeat as u16 => MsgType::HeartbeatAck as u16,
                x if x == MsgType::ActiveSyncRequest as u16 => MsgType::ActiveSyncDone as u16,
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

    fn handle_unidirectional(
        &self,
        _header: WireHeader,
        _payload: Vec<u8>,
    ) -> BoxFuture<Result<(), humoco_node::NodeError>> {
        self.received_unidirectional.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(()) })
    }
}

#[tokio::test]
async fn test_quic_p2p_handshake_and_frame_exchange() {
    let cancel_token = CancellationToken::new();

    let id_a = NodeIdentity::generate();
    let id_b = NodeIdentity::generate();

    let node_b_handler = Arc::new(EchoHandler::new());
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &id_b,
        Arc::new(PeerManager::new(vec![])),
        node_b_handler.clone(),
        cancel_token.clone(),
    )
    .expect("Bind node B");

    let addr_b = transport_b.local_addr().expect("Local addr B");
    let accept_handle_b = transport_b.spawn_accept_loop();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &id_a,
        Arc::new(PeerManager::new(vec![addr_b])),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("Bind node A");

    let addr_a = transport_a.local_addr().expect("Local addr A");
    transport_b
        .peer_manager()
        .register_f2f_friend(*id_a.node_id(), Some(addr_a))
        .await;
    transport_a
        .peer_manager()
        .register_f2f_friend(*id_b.node_id(), Some(addr_b))
        .await;

    let conn_a_to_b = transport_a
        .connect_peer(addr_b)
        .await
        .expect("Connect A -> B");

    let test_payload = b"Lock Verification Spec 10 Payload".to_vec();
    let req_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        100,
        1,
        0,
        test_payload.len() as u32,
    );

    let (resp_header, resp_payload) = transport_a
        .send_request(&conn_a_to_b, &req_header, &test_payload)
        .await
        .expect("Send request & receive response");

    assert_eq!(resp_header.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(resp_header.session_seq, 101);
    assert_eq!(resp_payload, test_payload);
    assert_eq!(node_b_handler.received_requests.load(Ordering::SeqCst), 1);

    // Unidirectional frame
    let uni_header = WireHeader::new(MsgType::Heartbeat as u16, 200, 1, 0, 8);
    let uni_payload = b"gossip12".to_vec();
    transport_a
        .send_unidirectional(&conn_a_to_b, &uni_header, &uni_payload)
        .await
        .expect("Send unidirectional gossip");

    // Allow background task to process unidirectional frame
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert_eq!(
        node_b_handler
            .received_unidirectional
            .load(Ordering::SeqCst),
        1
    );

    cancel_token.cancel();
    transport_a.close();
    transport_b.close();
    let _ = accept_handle_b.await;
}

#[tokio::test]
async fn test_stream_multiplexing_concurrent() {
    let cancel_token = CancellationToken::new();

    let id_server = NodeIdentity::generate();
    let id_client = NodeIdentity::generate();

    let server_handler = Arc::new(EchoHandler::new());
    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &id_server,
        Arc::new(PeerManager::new(vec![])),
        server_handler.clone(),
        cancel_token.clone(),
    )
    .expect("Bind server transport");

    let server_addr = server_transport.local_addr().expect("Server local addr");
    let accept_handle = server_transport.spawn_accept_loop();

    let client_transport = QuicTransport::bind("127.0.0.1:0".parse().unwrap(), &id_client)
        .expect("Bind client transport");

    let client_addr = client_transport.local_addr().expect("Client local addr");
    server_transport
        .peer_manager()
        .register_f2f_friend(*id_client.node_id(), Some(client_addr))
        .await;
    client_transport
        .peer_manager()
        .register_f2f_friend(*id_server.node_id(), Some(server_addr))
        .await;

    let conn = client_transport
        .connect_peer(server_addr)
        .await
        .expect("Connect to server");

    let num_tasks = 20;
    let mut handles = Vec::new();

    for i in 0..num_tasks {
        let transport = client_transport.clone();
        let conn_clone = conn.clone();
        let handle = tokio::spawn(async move {
            let msg_type = if i % 2 == 0 {
                MsgType::LockVerifyRequest as u16
            } else {
                MsgType::ActiveSyncRequest as u16
            };
            let payload = format!("stream-msg-content-{}", i).into_bytes();
            let header = WireHeader::new(msg_type, i as u64, 1, 0, payload.len() as u32);

            let (resp_hdr, resp_payload) = transport
                .send_request(&conn_clone, &header, &payload)
                .await
                .expect("Multiplexed request");

            assert_eq!(resp_payload, payload);
            if msg_type == MsgType::LockVerifyRequest as u16 {
                assert_eq!(resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);
            } else {
                assert_eq!(resp_hdr.msg_type, MsgType::ActiveSyncDone as u16);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("task finish");
    }

    assert_eq!(
        server_handler.received_requests.load(Ordering::SeqCst),
        num_tasks
    );

    cancel_token.cancel();
    client_transport.close();
    server_transport.close();
    let _ = accept_handle.await;
}

#[tokio::test]
async fn test_peer_lifecycle_and_suspension() {
    let addr: SocketAddr = "127.0.0.1:4499".parse().unwrap();
    let peer_manager = PeerManager::new(vec![addr]);

    // Initial state: Degrading (unconnected)
    let peer = peer_manager.get_peer(&addr).await.expect("Peer exists");
    assert_eq!(peer.status, PeerStatus::Degrading);
    assert_eq!(peer.missing_count, 0);

    // Failures leading up to Degrading (threshold 2, spaced by >=60s to pass debouncing)
    let t0 = std::time::Instant::now();
    peer_manager.record_failure_at(addr, t0).await;
    peer_manager
        .record_failure_at(addr, t0 + std::time::Duration::from_secs(60))
        .await;

    let peer = peer_manager.get_peer(&addr).await.unwrap();
    assert_eq!(peer.missing_count, 2);
    assert_eq!(peer.status, PeerStatus::Degrading);

    // Failure reaching Suspension threshold (3 per AGENTS.md / Spec 15)
    peer_manager
        .record_failure_at(addr, t0 + std::time::Duration::from_secs(120))
        .await;

    let peer = peer_manager.get_peer(&addr).await.unwrap();
    assert_eq!(peer.missing_count, 3);
    assert_eq!(peer.status, PeerStatus::Suspended);
    assert!(peer.is_suspended());

    // Phase 8 (Spec 15/19): a pure handshake must NOT reset the malus —
    // only genuinely performed shard work decays it.
    let node_id = [42u8; 32];
    peer_manager.record_success(addr, Some(node_id), None).await;

    let peer = peer_manager.get_peer(&addr).await.unwrap();
    assert_eq!(peer.missing_count, 3);
    assert!(peer.is_suspended());
    assert_eq!(peer.node_id, Some(node_id));

    // Tier-2 15s idle timeout is normal and never a failure (TODO-ARCH-02)
    peer_manager.note_idle_close(&addr).await;
    let peer = peer_manager.get_peer(&addr).await.unwrap();
    assert_eq!(peer.missing_count, 3);

    // Auto-recovery only via genuine shard work (decays step by step)
    peer_manager.record_shard_work(addr).await;
    let peer = peer_manager.get_peer(&addr).await.unwrap();
    assert_eq!(peer.missing_count, 2);
    assert!(!peer.is_suspended());
    peer_manager.record_shard_work(addr).await;
    peer_manager.record_shard_work(addr).await;
    let peer = peer_manager.get_peer(&addr).await.unwrap();
    assert_eq!(peer.missing_count, 0);
    assert_eq!(peer.node_id, Some(node_id));
}

#[tokio::test]
async fn test_dns_peer_periodic_resolution() {
    use humoco_node::config::PeerConfigEntry;

    let pk = [0x42u8; 32];
    let dns_entry = PeerConfigEntry::new(Some(pk), "localhost:9090");
    let pm = PeerManager::with_f2f_and_dns(vec![], vec![], vec![dns_entry]);

    let list = pm.list_dns_peers().await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].entry.raw_endpoint, "localhost:9090");
    assert!(list[0].current_addr.is_none());

    // Run resolution
    pm.check_and_resolve_dns_peers().await;

    let updated_list = pm.list_dns_peers().await;
    assert_eq!(updated_list.len(), 1);
    assert!(updated_list[0].current_addr.is_some());
    let resolved_addr = updated_list[0].current_addr.unwrap();
    assert_eq!(resolved_addr.port(), 9090);

    // Verify peer is registered in peers and f2f_friends
    let peer = pm.get_peer(&resolved_addr).await;
    assert!(peer.is_some());
    assert_eq!(peer.unwrap().node_id, Some(pk));
    assert!(pm.is_f2f_friend(&pk).await);
}

#[tokio::test]
async fn test_a03_01_handler_cancellation_and_clean_drain_tasks() {
    struct HangingHandler;
    impl RequestHandler for HangingHandler {
        fn handle(
            &self,
            _header: WireHeader,
            _payload: Vec<u8>,
        ) -> BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::NodeError>> {
            Box::pin(async move {
                // Simulates a hanging or slow handler (e.g. 60s)
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                Ok((WireHeader::new(MsgType::StatusResponse as u16, 1, 0, 0, 0), vec![]))
            })
        }
    }

    let cancel_token = CancellationToken::new();
    let server_id = NodeIdentity::generate();
    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        Arc::new(PeerManager::new(vec![])),
        Arc::new(HangingHandler),
        cancel_token.clone(),
    )
    .expect("Bind server");

    let server_addr = server_transport.local_addr().expect("Local addr");
    let _accept_loop = server_transport.spawn_accept_loop();

    let client_id = NodeIdentity::generate();
    let client_cancel = CancellationToken::new();
    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        Arc::new(PeerManager::new(vec![])),
        Arc::new(DefaultRequestHandler),
        client_cancel,
    )
    .expect("Bind client");

    let conn = client_transport
        .connect_peer_unchecked(server_addr)
        .await
        .expect("Connect to server");

    // Send a bi-stream request to server to trigger the hanging handler
    let (mut send, _recv) = conn.open_bi().await.expect("Open bi-stream");
    let req_header = WireHeader::new(
        MsgType::StatusQuery as u16,
        1,
        0,
        0,
        0,
    );
    humoco_node::network::framing::write_frame(&mut send, &req_header, &[])
        .await
        .expect("Write frame");

    // Give server a moment to read frame and enter the hanging handler
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Trigger shutdown cancellation
    cancel_token.cancel();

    // A03-01: drain_tasks() must finish promptly (within grace period ~100ms) and NOT hang for 60s
    let drain_result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server_transport.drain_tasks(),
    )
    .await;

    assert!(
        drain_result.is_ok(),
        "drain_tasks() must cleanly complete within grace period on cancellation"
    );
}

#[tokio::test]
async fn test_a11_01_heartbeat_freshness_window_drop() {
    let cancel_token = CancellationToken::new();
    let id_a = NodeIdentity::generate();
    let id_b = NodeIdentity::generate();

    let pm_a = Arc::new(PeerManager::with_f2f(vec![], vec![*id_b.node_id()]));

    // Seed Node A's clock with 10 quorum samples so has_quorum_samples() is true
    let local_base = pm_a.net_time_ms();
    for i in 0..10 {
        let mut friend = [0x99u8; 32];
        friend[0] = i as u8;
        pm_a.clock().record_sample_for_peer(friend, true, local_base, local_base);
    }
    assert!(pm_a.clock().has_quorum_samples());

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &id_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    let pm_b = Arc::new(PeerManager::with_f2f(vec![], vec![*id_a.node_id()]));
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &id_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("Bind transport B");
    let addr_b = transport_b.local_addr().unwrap();

    pm_a.register_f2f_friend(*id_b.node_id(), Some(addr_b)).await;
    pm_b.register_f2f_friend(*id_a.node_id(), Some(addr_a)).await;

    let conn_b_to_a = transport_b.connect_peer_unchecked(addr_a).await.unwrap();

    // Node B sends a heartbeat with timestamp +600s in the future (> 60s freshness window)
    let hb_future = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *id_b.node_id(),
        addr: addr_b,
        timestamp_ms: local_base + 600_000, // +10 minutes
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *id_b.node_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    let payload = bincode::serialize(&hb_future).unwrap();
    let mut header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    header.reserved = 0; // hops = 0

    transport_b.send_unidirectional(&conn_b_to_a, &header, &payload).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Node A must NOT have incorporated the stale/future heartbeat into clock:
    assert_eq!(
        pm_a.clock().sample_count(),
        10,
        "Heartbeat deviating by >60s must be dropped at ingress and not recorded in clock"
    );
}
