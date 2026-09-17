use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use humoco_node::identity::NodeIdentity;
use humoco_node::network::{
    DefaultRequestHandler, PeerManager, QuicTransport,
};
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
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(actual_addr_b)).await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(actual_addr_a)).await;

    // --- TEST 1: F2F Gossip is accepted between friends (A and B) ---
    let conn_b_to_a = transport_b
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("B connects to A");

    // B sends a Heartbeat advertising Node C's existence to A
    let hb_payload = humoco_node::network::framing::HeartbeatWirePayload {
        node_id: *identity_c.node_id(),
        addr: actual_addr_c,
        timestamp_ms: 0,
        supported_suites_mask: 0,
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
    pm_c.learn_node_from_gossip(*identity_a.node_id(), actual_addr_a, 1, None).await;

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
    let conn_c_to_a = transport_c
        .connect_peer_unchecked(actual_addr_a)
        .await
        .expect("C connects unchecked to A");

    // 1. ActiveSyncRequest from stranger -> MUST be rejected with "unauthorized"
    let sync_req_hdr = WireHeader::new(MsgType::ActiveSyncRequest as u16, 1, 0, 0, 0);
    let (resp_hdr, resp_payload) = transport_c
        .send_request(&conn_c_to_a, &sync_req_hdr, b"")
        .await
        .expect("send ActiveSyncRequest");
    assert_eq!(resp_hdr.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(&resp_payload, b"unauthorized");

    // 2. ShardDigestRequest from stranger -> MUST be rejected with "unauthorized"
    let digest_req_hdr = WireHeader::new(MsgType::ShardDigestRequest as u16, 2, 0, 0, 0);
    let (resp_hdr, resp_payload) = transport_c
        .send_request(&conn_c_to_a, &digest_req_hdr, b"")
        .await
        .expect("send ShardDigestRequest");
    assert_eq!(resp_hdr.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(&resp_payload, b"unauthorized");

    // 3. Authorize C by registering it as a learned gossip node
    pm_a.learn_node_from_gossip(*identity_c.node_id(), conn_c_to_a.remote_address(), 1, None).await;

    // Now request should NOT be rejected with unauthorized
    let (resp_hdr, resp_payload) = transport_c
        .send_request(&conn_c_to_a, &digest_req_hdr, b"")
        .await
        .expect("send authorized ShardDigestRequest");
    assert_ne!(&resp_payload, b"unauthorized");
    assert_eq!(resp_hdr.msg_type, MsgType::ShardDigestResponse as u16);

    cancel_a.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_c.close();
}

struct TrackingHandler {
    tx: tokio::sync::mpsc::UnboundedSender<(WireHeader, Vec<u8>)>,
}

impl humoco_node::network::RequestHandler for TrackingHandler {
    fn handle(
        &self,
        header: WireHeader,
        _payload: Vec<u8>,
    ) -> humoco_node::network::BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::NodeError>> {
        let resp = WireHeader::new(MsgType::StatusResponse as u16, header.session_seq + 1, 0, 0, 0);
        Box::pin(async move { Ok((resp, Vec::new())) })
    }

    fn handle_unidirectional(
        &self,
        header: WireHeader,
        payload: Vec<u8>,
    ) -> humoco_node::network::BoxFuture<Result<(), humoco_node::NodeError>> {
        let tx = self.tx.clone();
        Box::pin(async move {
            let _ = tx.send((header, payload));
            Ok(())
        })
    }
}

#[tokio::test]
async fn test_dunbar_gossip_forwarding_and_seen_cache_dedup() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("node_b.redb");
    let storage_b = Arc::new(humoco_node::storage::RedbStorage::open(&db_path).unwrap());
    let (engine_b, _flush_handle) = humoco_node::storage::DualTierEngine::new(storage_b.clone());

    let identity_a = NodeIdentity::generate();
    let addr_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_a = CancellationToken::new();

    let identity_b = NodeIdentity::generate();
    let addr_b: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_b = CancellationToken::new();

    let identity_c = NodeIdentity::generate();
    let addr_c: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cancel_c = CancellationToken::new();

    // Setup F2F relationships:
    // A and B are F2F friends
    // B and C are F2F friends
    // A and C are NOT directly connected (B acts as Dunbar gossip relay)
    let pm_a = Arc::new(PeerManager::with_f2f(Vec::new(), vec![*identity_b.node_id()]));
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id(), *identity_c.node_id()],
    ));
    let pm_c = Arc::new(PeerManager::with_f2f(Vec::new(), vec![*identity_b.node_id()]));

    let (c_rx_tx, mut c_rx) = tokio::sync::mpsc::unbounded_channel();
    let handler_c = Arc::new(TrackingHandler { tx: c_rx_tx });

    let handler_b = Arc::new(humoco_node::network::NodeRequestHandler::with_peer_manager(
        engine_b.clone(),
        storage_b,
        identity_b.clone(),
        pm_b.clone(),
    ));

    let transport_a = QuicTransport::bind_with_options(
        addr_a,
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("bind A");
    let actual_addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    let transport_b = QuicTransport::bind_with_options(
        addr_b,
        &identity_b,
        pm_b.clone(),
        handler_b,
        cancel_b.clone(),
    )
    .expect("bind B");
    let actual_addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    let transport_c = QuicTransport::bind_with_options(
        addr_c,
        &identity_c,
        pm_c.clone(),
        handler_c,
        cancel_c.clone(),
    )
    .expect("bind C");
    let actual_addr_c = transport_c.local_addr().unwrap();
    transport_c.spawn_accept_loop();

    // Register friend addresses
    pm_a.register_f2f_friend(*identity_b.node_id(), Some(actual_addr_b)).await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(actual_addr_a)).await;
    pm_b.register_f2f_friend(*identity_c.node_id(), Some(actual_addr_c)).await;
    pm_c.register_f2f_friend(*identity_b.node_id(), Some(actual_addr_b)).await;

    // Node B connects to Node C so an active QUIC connection exists
    let _ = transport_b.connect_peer(actual_addr_c).await.expect("B connects to C");
    // Node A connects to Node B
    let conn_a_to_b = transport_a.connect_peer(actual_addr_b).await.expect("A connects to B");

    // Create a new valid LockRecord
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let lock = humoco_sim_core::types::LockRecord::new(
        [0xAA; 32],
        [0xBB; 32],
        b"dunbar_gossip_test".to_vec(),
        humoco_sim_core::types::SimTime(now_ms),
        humoco_sim_core::types::SimTime(now_ms + 60_000),
    );
    let root_valid_until = now_ms + 60_000;
    let gossip_payload = bincode::serialize(&(lock.clone(), root_valid_until)).unwrap();
    let gossip_header = WireHeader::new(
        MsgType::GossipAnnounce as u16,
        1,
        0,
        0,
        gossip_payload.len() as u32,
    );

    // Node A gossips to Node B with hop=0
    transport_a
        .send_unidirectional(&conn_a_to_b, &gossip_header, &gossip_payload)
        .await
        .expect("A sends GossipAnnounce to B");

    // Node C must receive the forwarded GossipAnnounce from B
    let (received_hdr, received_payload) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        c_rx.recv(),
    )
    .await
    .expect("Timeout waiting for gossip forward to C")
    .expect("C receiver stream open");

    assert_eq!(received_hdr.msg_type, MsgType::GossipAnnounce as u16);
    // Hop count was incremented from 0 to 1
    assert_eq!(received_hdr.reserved, 1);
    let (received_lock, _) = bincode::deserialize::<(humoco_sim_core::types::LockRecord, u64)>(&received_payload).unwrap();
    assert_eq!(received_lock.id, lock.id);

    // Node B's seen cache now contains the lock
    assert!(pm_b.has_seen_gossip(&lock.id));

    // REPLAY / ECHO TEST:
    // If A re-transmits the exact same gossip to B:
    transport_a
        .send_unidirectional(&conn_a_to_b, &gossip_header, &gossip_payload)
        .await
        .expect("A re-sends duplicate GossipAnnounce to B");

    // Node B must detect it in seen_gossip_locks and DROP it (no forward to C)
    let extra_msg = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        c_rx.recv(),
    )
    .await;
    assert!(extra_msg.is_err(), "Duplicate echo was forwarded to C instead of being dropped by seen cache!");

    cancel_a.cancel();
    cancel_b.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_b.close();
    transport_c.close();
}
