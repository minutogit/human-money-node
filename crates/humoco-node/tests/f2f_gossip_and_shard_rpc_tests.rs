use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use humoco_node::identity::NodeIdentity;
use humoco_node::network::{DefaultRequestHandler, PeerManager, QuicTransport};
use humoco_sim_core::wire::{MsgType, WireHeader};

#[tokio::test]
async fn test_f2f_gossip_and_shard_direct_contact_lifecycle() {
    // 1. Setup Node A (Local Node)
    let identity_a = NodeIdentity::generate();
    let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_a = CancellationToken::new();

    // 2. Setup Node B (Friend of A)
    let identity_b = NodeIdentity::generate();
    let addr_b: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_b = CancellationToken::new();

    // 3. Setup Node C (Stranger to A, later learned via gossip)
    let identity_c = NodeIdentity::generate();
    let addr_c: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_c = CancellationToken::new();

    // Node A configures Node B as an F2F friend
    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));

    // Node B configures Node A as an F2F friend
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));

    // Node C is a stranger (no friends yet)
    let pm_c = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let actual_addr_a = transport_a.local_addr().expect("addr A");
    transport_a.spawn_accept_loop();

    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    let actual_addr_b = transport_b.local_addr().expect("addr B");
    transport_b.spawn_accept_loop();

    let transport_c = QuicTransport::bind_with_options(
        addr_c,
        &identity_c,
        pm_c.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_c.clone(),
    )
    .expect("Bind transport C");
    let actual_addr_c = transport_c.local_addr().expect("addr C");
    transport_c.spawn_accept_loop();

    // Register friend addresses in PeerManager
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(actual_addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(actual_addr_a))
        .await;

    // --- TEST 1: F2F Gossip is accepted between friends (A and B) ---
    let conn_b_to_a = transport_b
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("B connects to A");

    // B sends a Heartbeat advertising Node C's existence to A
    let hb_payload = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *identity_c.node_id(),
        addr: actual_addr_c,
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *identity_c.node_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    let heartbeat_payload = bincode::serialize(&hb_payload).expect("serialize heartbeat");
    let mut heartbeat_hdr = WireHeader::new(
        MsgType::Heartbeat as u16,
        1,
        0,
        0,
        heartbeat_payload.len() as u32,
    );
    heartbeat_hdr.reserved = 1;

    transport_b
        .send_unidirectional(&conn_b_to_a, &heartbeat_hdr, &heartbeat_payload)
        .await
        .expect("Send heartbeat");

    // Wait a brief moment for A to process the heartbeat and learn C
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Check that A learned C via F2F gossip:
    assert!(pm_a.is_known_node(identity_c.node_id()).await);
    assert_eq!(
        pm_a.get_known_node_addr(identity_c.node_id()).await,
        Some(actual_addr_c)
    );

    // --- TEST 2: Gossip Barrier rejects gossip from non-friends ---
    // Stranger C connects to A unchecked and tries to send gossip
    let conn_c_to_a = transport_c
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("C connects to A");

    let fake_node_id = [0x99u8; 32];
    let fake_addr: SocketAddr = "1.2.3.4:9090".parse().unwrap();
    let fake_gossip_payload = bincode::serialize(&(fake_node_id, fake_addr)).unwrap();
    let fake_gossip_hdr = WireHeader::new(
        MsgType::Heartbeat as u16,
        2,
        0,
        0,
        fake_gossip_payload.len() as u32,
    );

    transport_c
        .send_unidirectional(&conn_c_to_a, &fake_gossip_hdr, &fake_gossip_payload)
        .await
        .expect("Send fake gossip");

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // A MUST NOT have learned fake_node_id because C is not an F2F friend!
    assert!(!pm_a.is_known_node(&fake_node_id).await);

    // --- TEST 3: Direct Shard-RPC is authorized because A learned C via gossip ---
    // Node C also knows Node A from network gossip:
    pm_c.learn_node_from_gossip(*identity_a.node_id(), actual_addr_a, 1, None)
        .await;

    // A now connects directly to C (using connect_peer, which enforces the check)
    let conn_a_to_c = transport_a
        .connect_peer(actual_addr_c)
        .await
        .expect("A connects to learned Shard node C");

    let lock_verify_hdr = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, 0);
    let (resp_hdr, _) = transport_a
        .send_request(&conn_a_to_c, &lock_verify_hdr, b"")
        .await
        .expect("LockVerifyRequest to C");

    // Since DefaultRequestHandler responds to LockVerifyRequest with LockVerifyResponse:
    assert_eq!(resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);

    // Clean shutdown
    cancel_a.cancel();
    cancel_b.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_b.close();
    transport_c.close();
}

#[tokio::test]
async fn test_unauthorized_direct_connection_refused() {
    let identity_a = NodeIdentity::generate();
    let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_a = CancellationToken::new();
    let pm_a = Arc::new(PeerManager::new(Vec::new()));

    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &identity_a,
        pm_a,
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");

    // Trying to connect to a foreign address that is neither an F2F friend nor gossip-learned fails:
    let unknown_addr: SocketAddr = "192.0.2.1:9090".parse().unwrap();
    let err = transport_a.connect_peer(unknown_addr).await;
    assert!(err.is_err());
    let err_msg = err.err().unwrap().to_string();
    assert!(err_msg.contains("peer is neither an F2F friend nor known via F2F gossip"));

    cancel_a.cancel();
    transport_a.close();
}

#[tokio::test]
async fn test_unauthorized_active_sync_and_shard_digest_rejected() {
    let identity_a = NodeIdentity::generate();
    let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_a = CancellationToken::new();
    let pm_a = Arc::new(PeerManager::new(Vec::new()));

    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let actual_addr_a = transport_a.local_addr().expect("addr A");
    transport_a.spawn_accept_loop();

    // Node C is an unauthorized stranger (not F2F friend, not gossip-learned)
    let identity_c = NodeIdentity::generate();
    let addr_c: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_c = CancellationToken::new();
    let pm_c = Arc::new(PeerManager::new(Vec::new()));

    let transport_c = QuicTransport::bind_with_options(
        addr_c,
        &identity_c,
        pm_c,
        Arc::new(DefaultRequestHandler),
        cancel_c.clone(),
    )
    .expect("Bind transport C");
    transport_c.spawn_accept_loop();

    // Stranger C connects unchecked to A
    // Phase 10: unauthorized QUIC connections are actively terminated with
    // connection.close() instead of being kept half-open for per-stream
    // "unauthorized" responses (resource exhaustion protection).
    let conn_c_to_a = transport_c
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("C connects unchecked to A");

    // Give the accept loop a moment to evaluate authorization and close.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 1. ActiveSyncRequest from stranger -> connection MUST be closed.
    // (Legacy per-stream "unauthorized" payload is replaced by active close.)
    let sync_req_hdr = WireHeader::new(MsgType::ActiveSyncRequest as u16, 1, 0, 0, 0);
    let send_res = transport_c
        .send_request(&conn_c_to_a, &sync_req_hdr, b"")
        .await;
    match send_res {
        Ok((resp_hdr, resp_payload)) => {
            // Race window: if the request raced the close, a per-stream
            // rejection is still acceptable — but never a successful sync.
            assert_eq!(resp_hdr.msg_type, MsgType::StatusResponse as u16);
            assert_eq!(&resp_payload, b"unauthorized");
        }
        Err(_) => {
            // Expected path: server actively closed the unauthorized connection.
        }
    }
    // The server side must have terminated the connection.
    assert!(
        conn_c_to_a.close_reason().is_some(),
        "Unauthorized QUIC connection must be actively closed by the server"
    );

    // 2. ShardDigestRequest from stranger -> needs a fresh connection attempt,
    // which is likewise terminated while still unauthorized.
    let conn_c_to_a_2 = transport_c
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("C reconnects unchecked to A");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let digest_req_hdr = WireHeader::new(MsgType::ShardDigestRequest as u16, 2, 0, 0, 0);
    let send_res = transport_c
        .send_request(&conn_c_to_a_2, &digest_req_hdr, b"")
        .await;
    if let Ok((resp_hdr, resp_payload)) = send_res {
        assert_eq!(resp_hdr.msg_type, MsgType::StatusResponse as u16);
        assert_eq!(&resp_payload, b"unauthorized");
    }
    assert!(
        conn_c_to_a_2.close_reason().is_some(),
        "Unauthorized QUIC connection must be actively closed by the server"
    );

    // 3. Authorize C by registering it as a learned gossip node
    pm_a.learn_node_from_gossip(*identity_c.node_id(), conn_c_to_a.remote_address(), 1, None)
        .await;

    // Now a fresh request on a new connection must succeed (no unauthorized).
    let conn_c_to_a_3 = transport_c
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("C reconnects after authorization");
    let (resp_hdr, resp_payload) = transport_c
        .send_request(&conn_c_to_a_3, &digest_req_hdr, b"")
        .await
        .expect("send authorized ShardDigestRequest");
    assert_ne!(&resp_payload, b"unauthorized");
    assert_eq!(resp_hdr.msg_type, MsgType::ShardDigestResponse as u16);

    cancel_a.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_c.close();
}

#[tokio::test]
async fn test_f2f_multihop_gossip_forwarding_and_incubation() {
    // 3 Nodes in a line: A <-> B <-> C (A friends B, B friends C; A and C are NOT direct friends)
    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();
    let cancel_c = CancellationToken::new();

    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let identity_c = NodeIdentity::generate();

    let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let addr_c: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let pm_a = Arc::new(PeerManager::with_f2f(vec![], vec![*identity_b.node_id()]));
    let pm_b = Arc::new(PeerManager::with_f2f(
        vec![],
        vec![*identity_a.node_id(), *identity_c.node_id()],
    ));
    let pm_c = Arc::new(PeerManager::with_f2f(vec![], vec![*identity_b.node_id()]));

    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .unwrap();
    let actual_addr_a = transport_a.local_addr().unwrap();
    let _accept_a = transport_a.spawn_accept_loop();

    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .unwrap();
    let actual_addr_b = transport_b.local_addr().unwrap();
    let _accept_b = transport_b.spawn_accept_loop();

    let transport_c = QuicTransport::bind_with_options(
        addr_c,
        &identity_c,
        pm_c.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_c.clone(),
    )
    .unwrap();
    let actual_addr_c = transport_c.local_addr().unwrap();
    let _accept_c = transport_c.spawn_accept_loop();

    // Register friend addresses
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(actual_addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(actual_addr_a))
        .await;
    pm_b.register_f2f_friend(*identity_c.node_id(), Some(actual_addr_c))
        .await;
    pm_c.register_f2f_friend(*identity_b.node_id(), Some(actual_addr_b))
        .await;

    // Connect friends
    let _conn_a_b = transport_a
        .connect_peer_unchecked(actual_addr_b)
        .await
        .unwrap();
    let _conn_b_c = transport_b
        .connect_peer_unchecked(actual_addr_c)
        .await
        .unwrap();

    // Node A sends Heartbeat with TTL=16 and Argon2d routing ID
    let hb_a = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *identity_a.node_id(),
        addr: actual_addr_a,
        timestamp_ms: 50_000,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *identity_a.node_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    let payload = bincode::serialize(&hb_a).unwrap();
    let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    hdr.reserved = 0; // hops = 0

    let conn_a_to_b = transport_a
        .connect_peer_unchecked(actual_addr_b)
        .await
        .unwrap();
    transport_a
        .send_unidirectional(&conn_a_to_b, &hdr, &payload)
        .await
        .unwrap();

    // Wait for multi-hop gossip propagation: A -> B -> C
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Node B must have learned A (direct, hops=0)
    assert!(pm_b.is_known_node(identity_a.node_id()).await);
    let info_at_b = pm_b
        .get_known_node_info(identity_a.node_id())
        .await
        .unwrap();
    assert_eq!(info_at_b.min_hops(), 0);

    // Node C must have learned A through multi-hop forwarding from B (hops=1)
    assert!(
        pm_c.is_known_node(identity_a.node_id()).await,
        "Node C must have learned Node A via F2F multi-hop gossip"
    );
    let info_at_c = pm_c
        .get_known_node_info(identity_a.node_id())
        .await
        .unwrap();
    assert_eq!(info_at_c.min_hops(), 1);

    // Verify 24h incubation wall: Node A is newly learned, so is_immature() must be true, cannot be HRW eligible yet!
    assert!(
        info_at_c.is_immature(),
        "Newly learned node must be IMMATURE under 24h incubation wall"
    );
    assert!(
        !info_at_c.is_hrw_eligible(),
        "Newly learned node must NOT be HRW eligible yet"
    );

    // Clean up
    cancel_a.cancel();
    cancel_b.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_b.close();
    transport_c.close();
}
