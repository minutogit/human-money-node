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
                Ok((
                    WireHeader::new(MsgType::StatusResponse as u16, 1, 0, 0, 0),
                    vec![],
                ))
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
    let req_header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 0, 0);
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
        pm_a.clock()
            .record_sample_for_peer(friend, true, local_base, local_base);
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

    pm_a.register_f2f_friend(*id_b.node_id(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*id_a.node_id(), Some(addr_a))
        .await;

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

    transport_b
        .send_unidirectional(&conn_b_to_a, &header, &payload)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Node A must NOT have incorporated the stale/future heartbeat into clock:
    assert_eq!(
        pm_a.clock().sample_count(),
        10,
        "Heartbeat deviating by >60s must be dropped at ingress and not recorded in clock"
    );
}

#[tokio::test]
async fn test_s04_05_shard_bucket_range_amplification_and_bounds() {
    const MAX_SHARD_BUCKET_RANGE_COUNT: u16 = 1024;
    let cancel = CancellationToken::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(humoco_node::storage::RedbStorage::open(&temp.path().join("s04_05.redb")).expect("open redb"));
    let (engine, _worker) = humoco_node::storage::DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let pm_server = Arc::new(PeerManager::new(Vec::new()));
    let handler = Arc::new(
        humoco_node::network::NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_server.clone(),
        ),
    );

    let transport_server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        handler.clone(),
        cancel.clone(),
    )
    .expect("bind server");
    let server_addr = transport_server.local_addr().unwrap();
    transport_server.spawn_accept_loop();

    let client_id = NodeIdentity::generate();
    let pm_client = Arc::new(PeerManager::new(Vec::new()));
    let transport_client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind client");
    let client_addr = transport_client.local_addr().unwrap();
    transport_client.spawn_accept_loop();

    // Authorize client as F2F friend so direct RPC is allowed
    pm_server.register_f2f_friend(*client_id.node_pubkey(), Some(client_addr)).await;
    pm_client.register_f2f_friend(*server_id.node_pubkey(), Some(server_addr)).await;

    let conn = transport_client.connect_peer(server_addr).await.expect("connect client");

    // 1. Send ShardBucketRangeRequest with bucket_count = u16::MAX (65535) -> must be rejected
    let req_max = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id: 0,
        start_bucket: 0,
        bucket_count: u16::MAX,
    };
    let payload_max = bincode::serialize(&req_max).unwrap();
    let hdr_max = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 1, 0, 0, payload_max.len() as u32);
    let res_max = transport_client.send_request(&conn, &hdr_max, &payload_max).await;
    assert!(
        res_max.is_err() || res_max.as_ref().unwrap().0.msg_type != MsgType::ShardBucketRangeResponse as u16,
        "Request with bucket_count = u16::MAX must be rejected promptly"
    );

    // 2. Send malformed payload -> must be rejected promptly, NOT deserialized to default
    let malformed_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let hdr_malformed = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 2, 0, 0, malformed_payload.len() as u32);
    let res_malformed = transport_client.send_request(&conn, &hdr_malformed, &malformed_payload).await;
    assert!(
        res_malformed.is_err() || res_malformed.as_ref().unwrap().0.msg_type != MsgType::ShardBucketRangeResponse as u16,
        "Malformed ShardBucketRangeRequest must be rejected, not defaulted"
    );

    // 3. Small legitimate range positive control: bucket_count = 5
    let req_small = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id: 0,
        start_bucket: 10,
        bucket_count: 5,
    };
    let payload_small = bincode::serialize(&req_small).unwrap();
    let hdr_small = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 3, 0, 0, payload_small.len() as u32);
    let (resp_hdr_small, resp_bytes_small) = transport_client.send_request(&conn, &hdr_small, &payload_small).await.expect("small request");
    assert_eq!(resp_hdr_small.msg_type, MsgType::ShardBucketRangeResponse as u16);
    let resp_small: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes_small).expect("deserialize small resp");
    assert_eq!(resp_small.buckets.len(), 5);

    // 4. Largest supported valid bucket_count: 1024 (MAX_SHARD_BUCKET_RANGE_COUNT)
    let req_max_valid = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id: 0,
        start_bucket: 0,
        bucket_count: MAX_SHARD_BUCKET_RANGE_COUNT,
    };
    let payload_max_valid = bincode::serialize(&req_max_valid).unwrap();
    let hdr_max_valid = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 4, 0, 0, payload_max_valid.len() as u32);
    let (resp_hdr_max_valid, resp_bytes_max_valid) = transport_client.send_request(&conn, &hdr_max_valid, &payload_max_valid).await.expect("max valid request");
    assert_eq!(resp_hdr_max_valid.msg_type, MsgType::ShardBucketRangeResponse as u16);
    assert!(
        resp_bytes_max_valid.len() <= 65_536,
        "Response payload for MAX_SHARD_BUCKET_RANGE_COUNT must be <= 64 KiB (was {})",
        resp_bytes_max_valid.len()
    );
    let resp_max_valid: humoco_sim_core::types::ShardBucketRangeResponse = bincode::deserialize(&resp_bytes_max_valid).expect("deserialize max valid resp");
    assert_eq!(resp_max_valid.buckets.len(), MAX_SHARD_BUCKET_RANGE_COUNT as usize);

    cancel.cancel();
    transport_server.close();
    transport_client.close();
}

#[tokio::test]
async fn test_s04_05_rejection_precedes_storage_read() {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(humoco_node::storage::RedbStorage::open(&temp.path().join("s04_05_struct.redb")).expect("open redb"));
    let (engine, _worker) = humoco_node::storage::DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::new(Vec::new()));
    let handler = humoco_node::network::NodeRequestHandler::with_peer_manager(
        engine,
        storage,
        server_id,
        pm,
    );

    // Case 1: Malformed payload must fail directly on deserialization, NEVER return Ok default!
    let malformed_hdr = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 1, 0, 0, 3);
    let malformed_res = handler.handle_authenticated(malformed_hdr, vec![1, 2, 3], None).await;
    assert!(
        malformed_res.is_err(),
        "Malformed payload must return an Err, not default to 288 buckets"
    );

    // Case 2: Excessive bucket_count must fail upfront validation before storage read
    let excessive_req = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id: 0,
        start_bucket: 0,
        bucket_count: u16::MAX,
    };
    let excessive_payload = bincode::serialize(&excessive_req).unwrap();
    let excessive_hdr = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 2, 0, 0, excessive_payload.len() as u32);
    let excessive_res = handler.handle_authenticated(excessive_hdr, excessive_payload, None).await;
    assert!(
        excessive_res.is_err(),
        "Excessive bucket_count must return Err before storage read"
    );

    // Case 3: Zero bucket_count must fail upfront validation
    let zero_req = humoco_sim_core::types::ShardBucketRangeRequest {
        shard_id: 0,
        start_bucket: 0,
        bucket_count: 0,
    };
    let zero_payload = bincode::serialize(&zero_req).unwrap();
    let zero_hdr = WireHeader::new(MsgType::ShardBucketRangeRequest as u16, 3, 0, 0, zero_payload.len() as u32);
    let zero_res = handler.handle_authenticated(zero_hdr, zero_payload, None).await;
    assert!(
        zero_res.is_err(),
        "Zero bucket_count must return Err"
    );
}

#[tokio::test]
async fn test_s04_07_real_quic_rejects_unsupported_crypto_suites_before_handler() {
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
    let _accept_handle_b = transport_b.spawn_accept_loop();

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

    // 1. Unsupported suites (0, 2, 3, 255) must be rejected before handler invocation
    for unsupported_suite in [0u8, 2u8, 3u8, 255u8] {
        let mut req_header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            100,
            1,
            0,
            test_payload.len() as u32,
        );
        req_header.crypto_suite = unsupported_suite;

        let res = transport_a
            .send_request(&conn_a_to_b, &req_header, &test_payload)
            .await;

        assert!(
            res.is_err(),
            "Request with unsupported crypto suite {unsupported_suite} must be rejected over QUIC"
        );
        assert_eq!(
            node_b_handler.received_requests.load(Ordering::SeqCst),
            0,
            "Handler must NEVER be invoked for unsupported crypto suite {unsupported_suite}"
        );
    }

    // 2. Canonical suite 1 (Ed25519Blake3) must succeed and invoke handler
    let mut valid_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        101,
        1,
        0,
        test_payload.len() as u32,
    );
    valid_header.crypto_suite = 1;

    let (resp_header, resp_payload) = transport_a
        .send_request(&conn_a_to_b, &valid_header, &test_payload)
        .await
        .expect("Canonical suite 1 must succeed");

    assert_eq!(resp_header.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(resp_payload, test_payload);
    assert_eq!(
        node_b_handler.received_requests.load(Ordering::SeqCst),
        1,
        "Handler must be invoked exactly once for valid suite 1"
    );

    cancel_token.cancel();
    transport_a.close();
    transport_b.close();
}

#[tokio::test]
async fn test_s04_07_real_quic_shard_digest_rejects_unsupported_crypto_suites_before_storage() {
    let cancel = CancellationToken::new();

    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        humoco_node::storage::RedbStorage::open(&temp.path().join("s04_07_digest.redb"))
            .expect("open redb"),
    );
    let (engine, _worker) = humoco_node::storage::DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let pm_server = Arc::new(PeerManager::new(Vec::new()));
    let handler = Arc::new(
        humoco_node::network::NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_server.clone(),
        ),
    );

    let transport_server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        handler.clone(),
        cancel.clone(),
    )
    .expect("bind server");
    let server_addr = transport_server.local_addr().unwrap();
    transport_server.spawn_accept_loop();

    let client_id = NodeIdentity::generate();
    let pm_client = Arc::new(PeerManager::new(Vec::new()));
    let transport_client = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind client");
    let client_addr = transport_client.local_addr().unwrap();
    transport_client.spawn_accept_loop();

    // Authorize client as F2F friend so direct RPC is allowed
    pm_server
        .register_f2f_friend(*client_id.node_pubkey(), Some(client_addr))
        .await;
    pm_client
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = transport_client
        .connect_peer(server_addr)
        .await
        .expect("connect to server");

    let payload = 0u16.to_le_bytes().to_vec();

    // 1. ShardDigestRequest with unsupported suites (0, 2, 3, 255) must be rejected
    // before committed_shard_digest execution or response release
    for unsupported_suite in [0u8, 2u8, 3u8, 255u8] {
        let mut hdr = WireHeader::new(
            MsgType::ShardDigestRequest as u16,
            10,
            0,
            0,
            payload.len() as u32,
        );
        hdr.crypto_suite = unsupported_suite;

        let res = transport_client.send_request(&conn, &hdr, &payload).await;
        assert!(
            res.is_err(),
            "ShardDigestRequest with unsupported crypto suite {unsupported_suite} must be rejected over QUIC"
        );
    }

    // 2. Canonical suite 1 (Ed25519Blake3) must succeed and return the 40-byte digest response
    let mut valid_hdr = WireHeader::new(
        MsgType::ShardDigestRequest as u16,
        11,
        0,
        0,
        payload.len() as u32,
    );
    valid_hdr.crypto_suite = 1;

    let (resp_hdr, resp_payload) = transport_client
        .send_request(&conn, &valid_hdr, &payload)
        .await
        .expect("ShardDigestRequest with suite 1 must succeed");

    assert_eq!(resp_hdr.msg_type, MsgType::ShardDigestResponse as u16);
    assert_eq!(
        resp_payload.len(),
        40,
        "ShardDigestResponse must contain 40-byte committed shard digest and timestamp"
    );

    cancel.cancel();
    transport_server.close();
    transport_client.close();
}

