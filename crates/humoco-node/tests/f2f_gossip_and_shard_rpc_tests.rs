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
    pm_a.set_simulation_mode(true);

    // Node B configures Node A as an F2F friend
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));
    pm_b.set_simulation_mode(true);

    // Node C is a stranger (no friends yet)
    let pm_c = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    pm_c.set_simulation_mode(true);

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

    // B sends a Heartbeat advertising Node C's existence to A (origin signed by Node C)
    let mut hb_payload = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *identity_c.node_pubkey(),
        addr: actual_addr_c,
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *identity_c.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_payload.sign_origin(&identity_c, 0, humoco_sim_core::types::NetworkId::default());
    let heartbeat_payload = bincode::serialize(&hb_payload).expect("serialize heartbeat");
    let mut heartbeat_hdr = WireHeader::new(
        MsgType::Heartbeat as u16,
        1,
        0,
        0,
        heartbeat_payload.len() as u32,
    );
    heartbeat_hdr.reserved = 1;

    // An authentic origin signature from another network must not become local presence.
    let mut foreign = hb_payload.clone();
    foreign.sign_origin(&identity_c, 0, humoco_sim_core::types::NetworkId::Testnet);
    let foreign_payload = bincode::serialize(&foreign).unwrap();
    let mut foreign_header = heartbeat_hdr;
    foreign_header.payload_len = foreign_payload.len() as u32;
    transport_b.send_unidirectional(&conn_b_to_a, &foreign_header, &foreign_payload).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert!(!pm_a.is_known_node(identity_c.node_id()).await, "cross-network origin must be rejected before learning and dedup");

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
    pm_a.set_simulation_mode(true);

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
    pm_a.set_simulation_mode(true);
    let pm_b = Arc::new(PeerManager::with_f2f(
        vec![],
        vec![*identity_a.node_id(), *identity_c.node_id()],
    ));
    pm_b.set_simulation_mode(true);
    let pm_c = Arc::new(PeerManager::with_f2f(vec![], vec![*identity_b.node_id()]));
    pm_c.set_simulation_mode(true);

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

    // Node A sends Heartbeat with TTL=16 and Argon2d routing ID (origin signed by Node A)
    let mut hb_a = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *identity_a.node_pubkey(),
        addr: actual_addr_a,
        timestamp_ms: 50_000,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *identity_a.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_a.sign_origin(&identity_a, 50_000, humoco_sim_core::types::NetworkId::default());
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

#[tokio::test]
async fn test_s04_01_connect_peer_identity_validation() {
    let cancel = CancellationToken::new();

    // Client node C
    let identity_c = NodeIdentity::generate();
    let pm_c = Arc::new(PeerManager::new(Vec::new()));
    pm_c.set_simulation_mode(true);
    let transport_c = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_c,
        pm_c.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("Bind client C");
    let addr_c = transport_c.local_addr().unwrap();
    transport_c.spawn_accept_loop();

    // Node A is expected at server_addr
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();

    // Server runs with identity B
    let pm_b = Arc::new(PeerManager::new(Vec::new()));
    pm_b.set_simulation_mode(true);
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("Bind server B");
    let server_addr = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    // Server B authorizes client C (F2F friend or known)
    pm_b.register_f2f_friend(*identity_c.node_pubkey(), Some(addr_c)).await;

    // --- (a) Unknown B: Client C knows node A at server_addr, but B is completely unknown ---
    pm_c.learn_node_from_gossip(*identity_a.node_pubkey(), server_addr, 0, None).await;

    let res_a = transport_c.connect_peer(server_addr).await;
    assert!(
        res_a.is_err(),
        "connect_peer must reject when server presents unknown identity B instead of expected identity A"
    );
    // PeerManager must NOT have published B or connection for B/server_addr
    assert!(
        pm_c.get_peer(&server_addr).await.and_then(|p| p.node_id) != Some(*identity_b.node_pubkey()),
        "PeerManager must not publish identity B for server_addr"
    );
    assert!(
        pm_c.get_connection(&server_addr).await.is_none(),
        "PeerManager must not publish a connection for unauthorized identity B"
    );

    // --- (b) Known-but-different B: Client C knows B at another address ---
    let other_addr: SocketAddr = "192.0.2.1:9090".parse().unwrap();
    pm_c.learn_node_from_gossip(*identity_b.node_pubkey(), other_addr, 0, None).await;

    let res_b = transport_c.connect_peer(server_addr).await;
    assert!(
        res_b.is_err(),
        "connect_peer must reject when server presents different identity B for an endpoint authorized only for A"
    );
    assert!(
        pm_c.get_connection(&server_addr).await.is_none(),
        "PeerManager must still not have an active connection for server_addr"
    );

    // --- (c) Cached-connection branch: Evict/discard mismatched cached connection ---
    // Establish a connection directly to server_addr (holding B's identity) and insert into pm_c
    let unauth_conn = transport_c
        .endpoint()
        .connect(server_addr, humoco_node::network::transport::P2P_QUIC_SNI)
        .unwrap()
        .await
        .unwrap();
    pm_c.set_connection(server_addr, unauth_conn).await;
    assert!(pm_c.get_connection(&server_addr).await.is_some(), "Prerequisite: connection cached in PeerManager");

    let res_c = transport_c.connect_peer(server_addr).await;
    assert!(
        res_c.is_err(),
        "connect_peer must not return cached connection presenting mismatching identity B"
    );
    assert!(
        pm_c.get_connection(&server_addr).await.is_none(),
        "Mismatched cached connection must be evicted from PeerManager"
    );

    // --- (d) Normal endpoint migration retaining A's key (positive control) ---
    // Node A actually starts on a new address and authorizes client C
    let pm_a = Arc::new(PeerManager::new(Vec::new()));
    pm_a.set_simulation_mode(true);
    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("Bind server A");
    let migrated_addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();
    pm_a.register_f2f_friend(*identity_c.node_pubkey(), Some(addr_c)).await;

    // Client C learns A's updated address via signed heartbeat/gossip
    pm_c.learn_node_from_gossip(*identity_a.node_pubkey(), migrated_addr_a, 0, None).await;

    let res_d = transport_c.connect_peer(migrated_addr_a).await;
    assert!(
        res_d.is_ok(),
        "connect_peer must succeed when server presents expected identity A at its migrated endpoint"
    );

    cancel.cancel();
    transport_c.close();
    transport_b.close();
    transport_a.close();
}

#[tokio::test]
async fn test_s04_03_bidirectional_and_unidirectional_gossip_barrier() {
    use ed25519_dalek::Signer;
    let cancel = CancellationToken::new();
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(humoco_node::storage::RedbStorage::open(&temp.path().join("s04_03.redb")).expect("open redb"));
    let (engine, _worker) = humoco_node::storage::DualTierEngine::new(storage.clone());

    let server_id = NodeIdentity::generate();
    let pm_s = Arc::new(PeerManager::new(Vec::new()));
    pm_s.set_simulation_mode(true);
    let handler = Arc::new(
        humoco_node::network::NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm_s.clone(),
        )
        .with_network_id(humoco_sim_core::types::NetworkId::Mainnet),
    );

    let transport_s = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_s.clone(),
        handler,
        cancel.clone(),
    )
    .expect("bind server");
    let server_addr = transport_s.local_addr().unwrap();
    transport_s.spawn_accept_loop();

    // 1. Client 1 is admitted SOLELY as a learned non-F2F node (hops = 1, not in f2f_friends)
    let non_f2f_id = NodeIdentity::generate();
    let pm_non_f2f = Arc::new(PeerManager::new(Vec::new()));
    pm_non_f2f.set_simulation_mode(true);
    let transport_non_f2f = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &non_f2f_id,
        pm_non_f2f.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind client non-f2f");
    let non_f2f_addr = transport_non_f2f.local_addr().unwrap();
    transport_non_f2f.spawn_accept_loop();

    // Server learns non-f2f node via gossip (hops = 1), so direct RPC is authorized, but GOSSIP IS FORBIDDEN!
    pm_s.learn_node_from_gossip(*non_f2f_id.node_pubkey(), non_f2f_addr, 1, None).await;
    pm_non_f2f.learn_node_from_gossip(*server_id.node_pubkey(), server_addr, 0, None).await;

    let conn_non_f2f = transport_non_f2f.connect_peer(server_addr).await.expect("connect non-f2f to server");

    // Construct genuine Mainnet EquivocationProof
    let offender_key = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x11u8; 32];
    let lock_a = [0x22u8; 32];
    let lock_b = [0x33u8; 32];

    let sign_att = |k: &ed25519_dalek::SigningKey, p: &[u8; 32], l: &[u8; 32], dom: &[u8], st: u8| {
        let payload = humoco_sim_core::crypto::compute_attestation_payload_digest(p, l);
        let shard = u16::from_be_bytes([p[0], p[1]]);
        let digest = humoco_sim_core::crypto::compute_sig_digest(dom, 0, 0, 0, shard, st, &payload);
        let pubkey = k.verifying_key().to_bytes();
        let node_u16 = u16::from_le_bytes([pubkey[0], pubkey[1]]);
        humoco_sim_core::types::Attestation {
            node_id: node_u16,
            lock_id: *l,
            parent_lock: *p,
            timestamp: humoco_sim_core::types::SimTime(1_000),
            signature: k.sign(&digest).to_bytes(),
            shard_id: shard,
        }
    };

    let att_a = sign_att(&offender_key, &parent, &lock_a, humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET, 0);
    let att_b = sign_att(&offender_key, &parent, &lock_b, humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET, 1);
    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(att_a, att_b, offender_pub);
    assert!(proof.verify_network(humoco_sim_core::types::NetworkId::Mainnet));

    let proof_payload = bincode::serialize(&proof).unwrap();
    let evidence_hash = *blake3::hash(&proof_payload).as_bytes();

    // 1a. Submit EquivocationProof over BIDIRECTIONAL real QUIC stream from learned non-F2F peer
    let hdr_bidi = WireHeader::new(MsgType::EquivocationProof as u16, 1, 0, 0, proof_payload.len() as u32);
    let (resp_hdr, _resp_bytes) = transport_non_f2f.send_request(&conn_non_f2f, &hdr_bidi, &proof_payload).await.expect("send request");
    assert_ne!(
        resp_hdr.msg_type,
        MsgType::EquivocationAck as u16,
        "Bidirectional EquivocationProof from non-F2F learned peer must NOT be acknowledged with EquivocationAck"
    );

    // Assert: No RAM ban, No PeerManager ban, No durable ban, No evidence entry
    assert!(!engine.is_node_banned(&offender_pub).await, "Offender must not be banned in engine RAM");
    assert!(!pm_s.is_banned(&offender_pub).await, "Offender must not be banned in PeerManager");
    assert!(!storage.is_node_banned(&offender_pub).unwrap(), "Offender must not be banned in redb");
    assert!(storage.get_evidence(&evidence_hash).unwrap().is_none(), "Evidence must not be committed");

    // 1b. Submit EquivocationProof over UNIDIRECTIONAL real QUIC stream from learned non-F2F peer
    let hdr_uni = WireHeader::new(MsgType::EquivocationProof as u16, 2, 0, 0, proof_payload.len() as u32);
    transport_non_f2f.send_unidirectional(&conn_non_f2f, &hdr_uni, &proof_payload).await.expect("send unidirectional");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert!(!engine.is_node_banned(&offender_pub).await, "Offender must not be banned after uni stream from non-F2F");
    assert!(!pm_s.is_banned(&offender_pub).await, "Offender must not be banned in PeerManager after uni stream from non-F2F");
    assert!(!storage.is_node_banned(&offender_pub).unwrap(), "Offender must not be banned in redb after uni stream from non-F2F");
    assert!(storage.get_evidence(&evidence_hash).unwrap().is_none(), "Evidence must not be committed after uni stream from non-F2F");

    // 2. Positive Control: Direct F2F friend submits EquivocationProof over bidirectional stream
    let f2f_id = NodeIdentity::generate();
    let pm_f2f = Arc::new(PeerManager::new(Vec::new()));
    let transport_f2f = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &f2f_id,
        pm_f2f.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind f2f client");
    let f2f_addr = transport_f2f.local_addr().unwrap();
    transport_f2f.spawn_accept_loop();

    pm_s.register_f2f_friend(*f2f_id.node_pubkey(), Some(f2f_addr)).await;
    pm_f2f.register_f2f_friend(*server_id.node_pubkey(), Some(server_addr)).await;

    let conn_f2f = transport_f2f.connect_peer(server_addr).await.expect("connect f2f to server");

    // Different offender for positive control
    let offender_key_2 = ed25519_dalek::SigningKey::from_bytes(&[0x88u8; 32]);
    let offender_pub_2 = offender_key_2.verifying_key().to_bytes();
    let att_2a = sign_att(&offender_key_2, &parent, &lock_a, humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET, 0);
    let att_2b = sign_att(&offender_key_2, &parent, &lock_b, humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET, 1);
    let proof_2 = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(att_2a, att_2b, offender_pub_2);
    let proof_payload_2 = bincode::serialize(&proof_2).unwrap();
    let evidence_hash_2 = *blake3::hash(&proof_payload_2).as_bytes();

    let hdr_f2f = WireHeader::new(MsgType::EquivocationProof as u16, 3, 0, 0, proof_payload_2.len() as u32);
    let (resp_f2f, _) = transport_f2f.send_request(&conn_f2f, &hdr_f2f, &proof_payload_2).await.expect("send f2f request");
    assert_eq!(resp_f2f.msg_type, MsgType::EquivocationAck as u16, "F2F friend must receive EquivocationAck");

    assert!(engine.is_node_banned(&offender_pub_2).await, "Offender 2 must be banned in engine RAM");
    assert!(pm_s.is_banned(&offender_pub_2).await, "Offender 2 must be banned in PeerManager");
    assert!(storage.is_node_banned(&offender_pub_2).unwrap(), "Offender 2 must be banned in redb");
    assert!(storage.get_evidence(&evidence_hash_2).unwrap().is_some(), "Evidence 2 must be committed");

    cancel.cancel();
    transport_s.close();
    transport_non_f2f.close();
    transport_f2f.close();
}

#[tokio::test]
async fn test_s06_01_real_quic_initial_admission_hourly_observations_gate() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{DefaultRequestHandler, QuicTransport};
    use humoco_sim_core::wire::{MsgType, WireHeader};
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    let cancel = CancellationToken::new();
    let (server_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();
    let (relay_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();
    let (newcomer_c, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*relay_id.node_pubkey()],
    ));
    assert!(pm_server.effective_incubation_duration().as_secs() >= 86400);

    let pm_relay = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_pubkey()],
    ));

    let transport_s = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind server");
    let addr_s = transport_s.local_addr().unwrap();
    transport_s.spawn_accept_loop();

    let transport_r = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &relay_id,
        pm_relay.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind relay");
    let addr_r = transport_r.local_addr().unwrap();
    transport_r.spawn_accept_loop();

    pm_server
        .register_f2f_friend(*relay_id.node_pubkey(), Some(addr_r))
        .await;
    pm_relay
        .register_f2f_friend(*server_id.node_pubkey(), Some(addr_s))
        .await;

    let conn_r_to_s = transport_r
        .connect_peer(addr_s)
        .await
        .expect("connect relay to server");

    let t0_ms = pm_server.net_time_ms();
    let addr_c: SocketAddr = "127.0.0.1:39999".parse().unwrap();

    // Relay sends newcomer C's valid heartbeat at t0 (hops = 1)
    let mut hb_c = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *newcomer_c.node_pubkey(),
        addr: addr_c,
        timestamp_ms: t0_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: newcomer_c.nonce(),
        hrw_routing_id: *newcomer_c.hrw_routing_id(),
        ticket_epoch_t0: newcomer_c.t0(),
        ttl: 16,
    };
    hb_c.sign_origin(&newcomer_c, t0_ms, humoco_sim_core::types::NetworkId::default());
    let payload = bincode::serialize(&hb_c).unwrap();
    let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    hdr.reserved = 1; // hops = 1 (relayed)

    transport_r
        .send_unidirectional(&conn_r_to_s, &hdr, &payload)
        .await
        .expect("send heartbeat");
    for _ in 0..20 {
        if pm_server.is_known_node(newcomer_c.node_pubkey()).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(pm_server.is_known_node(newcomer_c.node_pubkey()).await);

    // Advance C's observed age to 25h while presence goes stale
    pm_server
        .set_first_seen_for_test(
            newcomer_c.node_pubkey(),
            Instant::now() - Duration::from_secs(25 * 3600),
        )
        .await;
    pm_server
        .set_last_seen_for_test(
            newcomer_c.node_pubkey(),
            Instant::now() - Duration::from_secs(4 * 3600),
        )
        .await;

    // Advance server clock by 25h
    pm_server.clock().advance_time_for_test(25 * 3600 * 1000);
    let t25_ms = pm_server.net_time_ms();

    // Relay sends 1 fresh heartbeat for C at t0 + 25h
    hb_c.timestamp_ms = t25_ms;
    hb_c.sign_origin(&newcomer_c, t25_ms, humoco_sim_core::types::NetworkId::default());
    let payload2 = bincode::serialize(&hb_c).unwrap();
    let mut hdr2 =
        WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, payload2.len() as u32);
    hdr2.reserved = 1;
    transport_r
        .send_unidirectional(&conn_r_to_s, &hdr2, &payload2)
        .await
        .expect("send second heartbeat");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if pm_server.get_known_node_info(newcomer_c.node_pubkey()).await
                .is_some_and(|node| node.is_presence_fresh()) { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("second authenticated ticket must refresh presence after CPU-worker completion");


    // Core Assertion S06-01: C has >=24h observed age AND fresh presence,
    // but only 1 hourly observation in the 24h window (the t0 observation fell out!).
    // Must NOT be in shard_committee or active_hrw_nodes!
    let (committee, _, _) = pm_server
        .shard_committee(
            *server_id.node_pubkey(),
            *server_id.hrw_routing_id(),
            42,
        )
        .await;
    assert!(
        !committee
            .iter()
            .any(|m| m.node_pubkey == *newcomer_c.node_pubkey()),
        "S06-01 QUIC: Newcomer with only 1 hourly observation must NOT be in shard_committee"
    );

    let active_hrw = pm_server.active_hrw_nodes().await;
    assert!(
        !active_hrw
            .iter()
            .any(|(hrw, _)| hrw == newcomer_c.hrw_routing_id()),
        "S06-01 QUIC: Newcomer with only 1 hourly observation must NOT be in active_hrw_nodes"
    );

    // Provide remaining 7 distinct hourly observations (total 8 in the 24h window)
    for hour in 18..=24 {
        let obs_ms = t0_ms + hour * 3_600_000;
        pm_server
            .record_heartbeat_hourly_observation(
                *newcomer_c.node_pubkey(),
                *newcomer_c.hrw_routing_id(),
                obs_ms,
            )
            .await;
    }

    let committee_admitted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let (committee, _, _) = pm_server.shard_committee(
                *server_id.node_pubkey(), *server_id.hrw_routing_id(), 42,
            ).await;
            if committee.iter().any(|member| member.node_pubkey == *newcomer_c.node_pubkey()) { break committee; }
            tokio::task::yield_now().await;
        }
    }).await.expect("authenticated current hourly observation must finish admission");
    assert!(
        committee_admitted
            .iter()
            .any(|m| m.node_pubkey == *newcomer_c.node_pubkey()),
        "S06-01 QUIC: Newcomer with >=24h age AND >=8 hourly observations MUST be admitted to shard_committee"
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_s06_03_unmined_pow_shortcuts_rejected_in_production() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{DefaultRequestHandler, QuicTransport};
    use humoco_sim_core::wire::{MsgType, WireHeader};
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    let cancel = CancellationToken::new();
    let (server_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();
    let (relay_id, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();
    let (friend_direct, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*relay_id.node_pubkey(), *friend_direct.node_pubkey()],
    ));
    assert!(pm_server.effective_incubation_duration().as_secs() >= 86400); // simulation_mode == false

    let pm_relay = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_pubkey()],
    ));
    let pm_direct = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_pubkey()],
    ));

    let transport_s = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind server");
    let addr_s = transport_s.local_addr().unwrap();
    transport_s.spawn_accept_loop();

    let transport_r = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &relay_id,
        pm_relay.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind relay");
    let addr_r = transport_r.local_addr().unwrap();
    transport_r.spawn_accept_loop();

    let transport_d = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &friend_direct,
        pm_direct.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind direct");
    let addr_d = transport_d.local_addr().unwrap();
    transport_d.spawn_accept_loop();

    pm_server
        .register_f2f_friend(*relay_id.node_pubkey(), Some(addr_r))
        .await;
    pm_relay
        .register_f2f_friend(*server_id.node_pubkey(), Some(addr_s))
        .await;
    pm_server
        .register_f2f_friend(*friend_direct.node_pubkey(), Some(addr_d))
        .await;
    pm_direct
        .register_f2f_friend(*server_id.node_pubkey(), Some(addr_s))
        .await;

    let conn_r_to_s = transport_r
        .connect_peer(addr_s)
        .await
        .expect("connect relay to server");
    let conn_d_to_s = transport_d
        .connect_peer(addr_s)
        .await
        .expect("connect direct to server");

    let now_ms = pm_server.net_time_ms();

    // Shortcut 1: hrw_routing_id = BLAKE3(pubkey) with pow_nonce=0, t0=0 via relay
    let unmined_1 = NodeIdentity::generate();
    let blake_hrw = *blake3::hash(unmined_1.node_pubkey()).as_bytes();
    let mut hb_1 = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *unmined_1.node_pubkey(),
        addr: "127.0.0.1:38001".parse().unwrap(),
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: blake_hrw,
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_1.sign_origin(&unmined_1, now_ms, humoco_sim_core::types::NetworkId::default());
    let payload_1 = bincode::serialize(&hb_1).unwrap();
    let mut hdr_1 =
        WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload_1.len() as u32);
    hdr_1.reserved = 1; // relayed
    transport_r
        .send_unidirectional(&conn_r_to_s, &hdr_1, &payload_1)
        .await
        .unwrap();

    // Shortcut 2: hrw_routing_id = pubkey with pow_nonce=0, t0=0 via relay
    let unmined_2 = NodeIdentity::generate();
    let mut hb_2 = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *unmined_2.node_pubkey(),
        addr: "127.0.0.1:38002".parse().unwrap(),
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *unmined_2.node_pubkey(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_2.sign_origin(&unmined_2, now_ms, humoco_sim_core::types::NetworkId::default());
    let payload_2 = bincode::serialize(&hb_2).unwrap();
    let mut hdr_2 =
        WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, payload_2.len() as u32);
    hdr_2.reserved = 1;
    transport_r
        .send_unidirectional(&conn_r_to_s, &hdr_2, &payload_2)
        .await
        .unwrap();

    // Shortcut 3: hrw_routing_id = [0u8; 32] with pow_nonce=0, t0=0 via relay
    let unmined_3 = NodeIdentity::generate();
    let mut hb_3 = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *unmined_3.node_pubkey(),
        addr: "127.0.0.1:38003".parse().unwrap(),
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: [0u8; 32],
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_3.sign_origin(&unmined_3, now_ms, humoco_sim_core::types::NetworkId::default());
    let payload_3 = bincode::serialize(&hb_3).unwrap();
    let mut hdr_3 =
        WireHeader::new(MsgType::Heartbeat as u16, 3, 0, 0, payload_3.len() as u32);
    hdr_3.reserved = 1;
    transport_r
        .send_unidirectional(&conn_r_to_s, &hdr_3, &payload_3)
        .await
        .unwrap();

    // Direct-origin shortcut (hops == 0) with pow_nonce=0, t0=0
    let mut hb_direct = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *friend_direct.node_pubkey(),
        addr: addr_d,
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *friend_direct.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_direct.sign_origin(&friend_direct, now_ms, humoco_sim_core::types::NetworkId::default());
    let payload_d = bincode::serialize(&hb_direct).unwrap();
    let mut hdr_d =
        WireHeader::new(MsgType::Heartbeat as u16, 4, 0, 0, payload_d.len() as u32);
    hdr_d.reserved = 0; // hops == 0
    transport_d
        .send_unidirectional(&conn_d_to_s, &hdr_d, &payload_d)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Simulate 25h maturation and 8 hourly observations for all shortcut candidates
    for unmined in [&unmined_1, &unmined_2, &unmined_3, &friend_direct] {
        pm_server
            .set_first_seen_for_test(
                unmined.node_pubkey(),
                Instant::now() - Duration::from_secs(25 * 3600),
            )
            .await;
        pm_server
            .set_last_seen_for_test(unmined.node_pubkey(), Instant::now())
            .await;
        for hour in 18..=25 {
            pm_server
                .record_heartbeat_hourly_observation(
                    *unmined.node_pubkey(),
                    *unmined.hrw_routing_id(),
                    now_ms + hour * 3_600_000,
                )
                .await;
        }
    }

    // Core S06-03 Assertion: NONE of the zero-work / unmined shortcut nodes may yield an admissible HRW ticket!
    let active_hrw = pm_server.active_hrw_nodes().await;
    let (committee, _, _) = pm_server
        .shard_committee(
            *server_id.node_pubkey(),
            *server_id.hrw_routing_id(),
            42,
        )
        .await;

    assert!(
        !active_hrw
            .iter()
            .any(|(hrw, _)| hrw == unmined_1.hrw_routing_id()),
        "S06-03: BLAKE3(pubkey) shortcut must NOT produce an admissible HRW ticket in production"
    );
    assert!(
        !active_hrw
            .iter()
            .any(|(hrw, _)| hrw == unmined_2.node_pubkey()),
        "S06-03: pubkey shortcut must NOT produce an admissible HRW ticket in production"
    );
    assert!(
        !active_hrw
            .iter()
            .any(|(hrw, _)| hrw == &[0u8; 32]),
        "S06-03: [0; 32] shortcut must NOT produce an admissible HRW ticket in production"
    );
    assert!(
        !committee
            .iter()
            .any(|m| m.node_pubkey == *unmined_1.node_pubkey()),
        "S06-03: BLAKE3 shortcut identity must NOT enter shard_committee in production"
    );
    assert!(
        !committee
            .iter()
            .any(|m| m.node_pubkey == *unmined_2.node_pubkey()),
        "S06-03: pubkey shortcut identity must NOT enter shard_committee in production"
    );
    assert!(
        !committee
            .iter()
            .any(|m| m.node_pubkey == *unmined_3.node_pubkey()),
        "S06-03: [0; 32] shortcut identity must NOT enter shard_committee in production"
    );

    // Positive Control: Genuinely mined Argon2d ticket over real QUIC
    let (mined_positive, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_700_000_000, Some(50))
        .unwrap();
    let pos_ms = pm_server.net_time_ms();
    let mut hb_pos = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *mined_positive.node_pubkey(),
        addr: "127.0.0.1:38009".parse().unwrap(),
        timestamp_ms: pos_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: mined_positive.nonce(),
        hrw_routing_id: *mined_positive.hrw_routing_id(),
        ticket_epoch_t0: mined_positive.t0(),
        ttl: 16,
    };
    hb_pos.sign_origin(&mined_positive, pos_ms, humoco_sim_core::types::NetworkId::default());
    let payload_pos = bincode::serialize(&hb_pos).unwrap();
    let mut hdr_pos =
        WireHeader::new(MsgType::Heartbeat as u16, 6, 0, 0, payload_pos.len() as u32);
    hdr_pos.reserved = 1;
    let conn_pos = transport_r
        .connect_peer(addr_s)
        .await
        .expect("connect relay to server for positive control");
    let mut foreign = hb_pos.clone();
    foreign.sign_origin(&mined_positive, pos_ms, humoco_sim_core::types::NetworkId::Testnet);
    let foreign_payload = bincode::serialize(&foreign).unwrap();
    let mut foreign_header = hdr_pos;
    foreign_header.payload_len = foreign_payload.len() as u32;
    transport_r.send_unidirectional(&conn_pos, &foreign_header, &foreign_payload).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pm_server.is_known_node(mined_positive.node_pubkey()).await,
        "a genuinely mined foreign-network origin must not enter the production mesh");
    transport_r
        .send_unidirectional(&conn_pos, &hdr_pos, &payload_pos)
        .await
        .unwrap();

    for _ in 0..300 {
        if pm_server.is_known_node(mined_positive.node_pubkey()).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(pm_server.is_known_node(mined_positive.node_pubkey()).await);

    // Mature positive control with 24h age + 8 hourly observations
    pm_server
        .set_first_seen_for_test(
            mined_positive.node_pubkey(),
            Instant::now() - Duration::from_secs(25 * 3600),
        )
        .await;
    pm_server
        .set_last_seen_for_test(mined_positive.node_pubkey(), Instant::now())
        .await;
    for hour in 18..=25 {
        pm_server
            .record_heartbeat_hourly_observation(
                *mined_positive.node_pubkey(),
                *mined_positive.hrw_routing_id(),
                now_ms + hour * 3_600_000,
            )
            .await;
    }

    let (committee_after_pos, _, _) = pm_server
        .shard_committee(
            *server_id.node_pubkey(),
            *server_id.hrw_routing_id(),
            42,
        )
        .await;
    assert!(
        committee_after_pos
            .iter()
            .any(|m| m.node_pubkey == *mined_positive.node_pubkey()),
        "S06-03 Positive Control: Genuinely mined Argon2d ticket MUST be admitted after maturation"
    );

    cancel.cancel();
}


