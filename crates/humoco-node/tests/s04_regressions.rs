//! Regression tests for Slice S04 (S04-R1, S04-R2, S04-R3, S04-R5).
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use humoco_node::identity::{build_self_revocation_fraud_proof, NodeIdentity};
use humoco_node::network::transport::verify_equivocation_first_party_network;
use humoco_node::network::{
    build_quinn_server_config_with_network, send_unidirectional_frame, DefaultRequestHandler,
    HeartbeatWirePayload, NodeRequestHandler, PeerManager, QuicTransport, RequestHandler,
};
use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_POW_OUTDATED};

/// S04-R1: FLAG_POW_OUTDATED in HeartbeatAck may ONLY be processed as feedback
/// from authenticated direct F2F friends.
#[tokio::test]
async fn test_s04_r1_heartbeat_ack_pow_outdated_f2f_barrier() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate(); // F2F friend
    let identity_c = NodeIdentity::generate(); // Non-F2F shard peer

    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    assert!(
        !pm_a.is_ticket_outdated(),
        "initial ticket_outdated must be false"
    );

    // --- 1. Non-F2F peer C sends HeartbeatAck with FLAG_POW_OUTDATED ---
    let pm_c = Arc::new(PeerManager::new(Vec::new()));
    pm_c.set_simulation_mode(true);
    let cancel_c = CancellationToken::new();
    let transport_c = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_c,
        pm_c.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_c.clone(),
    )
    .expect("Bind transport C");
    let addr_c = transport_c.local_addr().unwrap();
    transport_c.spawn_accept_loop();

    // Node A knows Node C from network gossip (it is a shard peer, but NOT an F2F friend)
    pm_a.learn_node_from_gossip_with_hrw(*identity_c.node_id(), *identity_c.hrw_routing_id(), addr_c, 1, None)
        .await;

    let conn_c_to_a = transport_c
        .connect_peer_unchecked(addr_a)
        .await
        .expect("C connects to A");

    let ack_hdr_c = WireHeader::new(MsgType::HeartbeatAck as u16, 1, 0, FLAG_POW_OUTDATED, 0);
    transport_c
        .send_unidirectional(&conn_c_to_a, &ack_hdr_c, &[])
        .await
        .expect("C sends HeartbeatAck to A");

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        !pm_a.is_ticket_outdated(),
        "S04-R1 VIOLATION: Non-F2F peer C must NOT be allowed to set ticket_outdated to true!"
    );

    // --- 2. Authenticated direct F2F friend B sends HeartbeatAck with FLAG_POW_OUTDATED ---
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));
    pm_b.set_simulation_mode(true);
    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    let addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a))
        .await;

    let conn_b_to_a = transport_b
        .connect_peer_unchecked(addr_a)
        .await
        .expect("B connects to A");

    let ack_hdr_b = WireHeader::new(MsgType::HeartbeatAck as u16, 2, 0, FLAG_POW_OUTDATED, 0);
    transport_b
        .send_unidirectional(&conn_b_to_a, &ack_hdr_b, &[])
        .await
        .expect("B sends HeartbeatAck to A");

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        pm_a.is_ticket_outdated(),
        "Authenticated direct F2F friend B MUST set ticket_outdated to true"
    );

    cancel_a.cancel();
    cancel_b.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_b.close();
    transport_c.close();
}

/// S04-R1: NodeRequestHandler::handle_unidirectional_authenticated MUST also enforce
/// authenticated direct F2F friendship before processing FLAG_POW_OUTDATED.
#[tokio::test]
async fn test_s04_r1_handle_unidirectional_authenticated_direct_f2f_check() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test.redb");
    let db = Arc::new(humoco_node::storage::RedbStorage::open(&db_path).unwrap());
    let cancel = CancellationToken::new();
    let (engine, _) =
        humoco_node::storage::DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate(); // F2F friend
    let identity_c = NodeIdentity::generate(); // Non-F2F stranger
    let pm = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));
    pm.set_simulation_mode(true);
    let handler = NodeRequestHandler::with_peer_manager(engine, db, identity_a, pm.clone());

    let ack_hdr = WireHeader::new(MsgType::HeartbeatAck as u16, 1, 0, FLAG_POW_OUTDATED, 0);

    // 1. None sender -> ticket_outdated remains false
    pm.set_ticket_outdated(false);
    handler
        .handle_unidirectional_authenticated(ack_hdr, vec![], None)
        .await
        .unwrap();
    assert!(
        !pm.is_ticket_outdated(),
        "S04-R1 VIOLATION: Anonymous/unauthenticated sender must not set ticket_outdated"
    );

    // 2. Non-F2F sender C -> ticket_outdated remains false
    pm.set_ticket_outdated(false);
    handler
        .handle_unidirectional_authenticated(ack_hdr, vec![], Some(*identity_c.node_id()))
        .await
        .unwrap();
    assert!(
        !pm.is_ticket_outdated(),
        "S04-R1 VIOLATION: Non-F2F sender must not set ticket_outdated"
    );

    // 3. Authenticated direct F2F sender B -> ticket_outdated becomes true
    pm.set_ticket_outdated(false);
    handler
        .handle_unidirectional_authenticated(ack_hdr, vec![], Some(*identity_b.node_id()))
        .await
        .unwrap();
    assert!(
        pm.is_ticket_outdated(),
        "Authenticated direct F2F sender must set ticket_outdated"
    );
}

/// S04-R2: Incomplete unidirectional streams occupying the uni admission semaphore MUST NOT
/// starve reserved shard RPCs or sync/repair RPCs.
#[tokio::test]
async fn test_s04_r2_incomplete_uni_streams_do_not_starve_shard_or_sync_rpcs() {
    let identity_a = NodeIdentity::generate();
    let pm_a = Arc::new(PeerManager::new(Vec::new()));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    // Node B will connect and open incomplete unidirectional streams
    let identity_b = NodeIdentity::generate();
    let pm_b = Arc::new(PeerManager::new(Vec::new()));
    pm_b.set_simulation_mode(true);
    let cancel_b = CancellationToken::new();
    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    transport_b.spawn_accept_loop();

    // Authorize B so its connections are admitted
    pm_a.learn_node_from_gossip_with_hrw(
        *identity_b.node_id(),
        *identity_b.hrw_routing_id(),
        "127.0.0.1:9091".parse().unwrap(),
        1,
        None,
    )
    .await;

    // Establish multiple connections from B to A and flood with incomplete uni streams
    // (each stream writes only 1 byte, never completing the 32-byte WireHeader).
    // In Quinn, each connection can negotiate ~100 concurrent streams.
    // We open 11 connections * 95 streams = 1045 streams (> 1024 global stream_semaphore).
    let mut streams = Vec::new();
    let mut conns = Vec::new();
    for _ in 0..11 {
        let conn = transport_b.connect_peer_unchecked(addr_a).await.unwrap();
        for _ in 0..95 {
            if let Ok(mut uni_send) = conn.open_uni().await {
                // Write 1 byte to start frame reading on server side without completing header
                if uni_send.write_all(&[0x48]).await.is_ok() {
                    streams.push(uni_send);
                }
            }
        }
        conns.push(conn);
    }

    assert!(
        streams.len() >= 1000,
        "Should have saturated at least 1000 incomplete uni streams, got {}",
        streams.len()
    );

    // Give server a moment to accept uni streams and acquire permits
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Node C is an honest shard peer
    let identity_c = NodeIdentity::generate();
    let pm_c = Arc::new(PeerManager::new(Vec::new()));
    pm_c.set_simulation_mode(true);
    let cancel_c = CancellationToken::new();
    let transport_c = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_c,
        pm_c.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_c.clone(),
    )
    .expect("Bind transport C");
    let addr_c = transport_c.local_addr().unwrap();
    transport_c.spawn_accept_loop();

    pm_a.learn_node_from_gossip_with_hrw(*identity_c.node_id(), *identity_c.hrw_routing_id(), addr_c, 1, None)
        .await;
    pm_c.learn_node_from_gossip_with_hrw(*identity_a.node_id(), *identity_a.hrw_routing_id(), addr_a, 1, None)
        .await;

    let conn_c_to_a = transport_c
        .connect_peer(addr_a)
        .await
        .expect("C connects to A");

    // (a) Verify protected honest Shard RPC (LockVerifyRequest) succeeds promptly
    let lock_hdr = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, 0);
    let shard_res = tokio::time::timeout(
        Duration::from_secs(2),
        transport_c.send_request(&conn_c_to_a, &lock_hdr, b""),
    )
    .await;

    assert!(
        shard_res.is_ok(),
        "S04-R2 VIOLATION: Honest Shard RPC timed out due to stalled uni streams starving stream_semaphore!"
    );
    let (resp_hdr, _) = shard_res.unwrap().expect("Shard RPC response");
    assert_eq!(resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);

    // (b) Verify bounded Sync/Repair RPC (ShardDigestRequest) remains available and succeeds promptly
    let sync_hdr = WireHeader::new(MsgType::ShardDigestRequest as u16, 2, 0, 0, 0);
    let sync_res = tokio::time::timeout(
        Duration::from_secs(2),
        transport_c.send_request(&conn_c_to_a, &sync_hdr, b""),
    )
    .await;

    assert!(
        sync_res.is_ok(),
        "S04-R2 VIOLATION: Sync/Repair RPC timed out due to stalled uni streams starving stream_semaphore!"
    );
    let (sync_resp_hdr, _) = sync_res.unwrap().expect("Sync RPC response");
    assert_eq!(sync_resp_hdr.msg_type, MsgType::ShardDigestResponse as u16);

    drop(streams);
    drop(conns);
    cancel_a.cancel();
    cancel_b.cancel();
    cancel_c.cancel();
    transport_a.close();
    transport_b.close();
    transport_c.close();
}

/// S04-R3: Over real QUIC connections, test outbound uni operations under:
/// (a) missing stream credit (peer negotiates 0 uni streams) -> fails within bounded timeout.
/// (b) blocked data drain (peer has tiny receive window and never reads) -> fails within bounded timeout.
#[tokio::test]
async fn test_s04_r3_outbound_uni_missing_credit_and_blocked_drain_timeout() {
    let identity_a = NodeIdentity::generate();
    let pm_a = Arc::new(PeerManager::new(Vec::new()));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    transport_a.spawn_accept_loop();

    // --- (a) Stalled peer with 0 max_concurrent_uni_streams ---
    let identity_stalled = NodeIdentity::generate();
    let mut server_config_stalled = build_quinn_server_config_with_network(
        &identity_stalled,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config_stalled = quinn::TransportConfig::default();
    transport_config_stalled.max_concurrent_uni_streams(0u32.into());
    server_config_stalled.transport_config(Arc::new(transport_config_stalled));
    let endpoint_stalled =
        quinn::Endpoint::server(server_config_stalled, "127.0.0.1:0".parse().unwrap()).unwrap();
    let stalled_addr = endpoint_stalled.local_addr().unwrap();

    let (_held_tx, mut _held_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(32);
    let stalled_endpoint_clone = endpoint_stalled.clone();
    tokio::spawn(async move {
        while let Some(inc) = stalled_endpoint_clone.accept().await {
            if let Ok(c) = inc.await {
                let _ = _held_tx.send(c).await;
            }
        }
    });

    let conn_stalled = transport_a
        .connect_peer_unchecked(stalled_addr)
        .await
        .unwrap();

    let header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, 4);
    let payload = b"test";

    let start = std::time::Instant::now();
    let res_stalled = send_unidirectional_frame(&conn_stalled, &header, payload).await;
    let elapsed = start.elapsed();

    assert!(
        res_stalled.is_err(),
        "S04-R3: Outbound uni to peer with 0 stream credit must return an Err, not hang or succeed"
    );
    assert!(
        elapsed <= Duration::from_secs(6),
        "S04-R3 VIOLATION: send_unidirectional_frame took too long ({:?}), must fail within bounded timeout",
        elapsed
    );

    // --- (b) Stalled peer with tiny receive window and blocked data drain ---
    let identity_drain = NodeIdentity::generate();
    let mut server_config_drain = build_quinn_server_config_with_network(
        &identity_drain,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config_drain = quinn::TransportConfig::default();
    transport_config_drain.stream_receive_window(256u32.into());
    transport_config_drain.receive_window(256u32.into());
    server_config_drain.transport_config(Arc::new(transport_config_drain));
    let endpoint_drain =
        quinn::Endpoint::server(server_config_drain, "127.0.0.1:0".parse().unwrap()).unwrap();
    let drain_addr = endpoint_drain.local_addr().unwrap();

    let (_drain_tx, mut _drain_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(32);
    let endpoint_drain_clone = endpoint_drain.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint_drain_clone.accept().await {
            if let Ok(conn) = incoming.await {
                let _ = _drain_tx.send(conn.clone()).await;
                tokio::spawn(async move {
                    while let Ok(_stream) = conn.accept_uni().await {
                        // Intentionally do not read from stream, keep open
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                });
            }
        }
    });

    let conn_drain = transport_a
        .connect_peer_unchecked(drain_addr)
        .await
        .unwrap();
    let big_payload = vec![0xABu8; 64 * 1024]; // 64 KB > 256 bytes window
    let header_drain =
        WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, big_payload.len() as u32);

    let start_drain = std::time::Instant::now();
    let res_drain = send_unidirectional_frame(&conn_drain, &header_drain, &big_payload).await;
    let elapsed_drain = start_drain.elapsed();

    assert!(
        res_drain.is_err(),
        "S04-R3: Outbound uni to peer with blocked data drain must return an Err, not hang or succeed"
    );
    assert!(
        elapsed_drain <= Duration::from_secs(6),
        "S04-R3 VIOLATION: send_unidirectional_frame with blocked drain took too long ({:?}), must fail within bounded timeout",
        elapsed_drain
    );

    cancel_a.cancel();
    transport_a.close();
}

/// S04-R3: Tracked Heartbeat & Fraud (EquivocationProof) forwarder tasks stuck on stalled peers
/// release completely and promptly when transport cancellation triggers (drain_tasks).
#[tokio::test]
async fn test_s04_r3_forwarder_tasks_drain_promptly_on_cancellation() {
    let identity_a = NodeIdentity::generate();
    let identity_stalled = NodeIdentity::generate();
    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_stalled.node_id()],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    // Peer with 0 max_concurrent_uni_streams that will cause open_uni to hang
    let mut server_config_stalled = build_quinn_server_config_with_network(
        &identity_stalled,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config_stalled = quinn::TransportConfig::default();
    transport_config_stalled.max_concurrent_uni_streams(0u32.into());
    server_config_stalled.transport_config(Arc::new(transport_config_stalled));
    let endpoint_stalled =
        quinn::Endpoint::server(server_config_stalled, "127.0.0.1:0".parse().unwrap()).unwrap();
    let stalled_addr = endpoint_stalled.local_addr().unwrap();

    let (_held_tx, mut _held_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(32);
    let stalled_endpoint_clone = endpoint_stalled.clone();
    tokio::spawn(async move {
        while let Some(inc) = stalled_endpoint_clone.accept().await {
            if let Ok(c) = inc.await {
                let _ = _held_tx.send(c).await;
            }
        }
    });

    pm_a.register_f2f_friend(*identity_stalled.node_id(), Some(stalled_addr))
        .await;

    // Trigger fraud proof broadcast (spawns forwarder task targeted at stalled friend)
    let ev_a = humoco_sim_core::fraud::IngressEnvelopeEvidence::default();
    let ev_b = humoco_sim_core::fraud::IngressEnvelopeEvidence {
        epoch_seq: 1,
        ..Default::default()
    };
    let fraud_proof =
        humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(ev_a, ev_b);
    transport_a
        .broadcast_equivocation_proof_to_f2f(&fraud_proof)
        .await;

    // Trigger heartbeat forwarding (spawns forwarder task targeted at stalled friend)
    let hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: [0x77; 32],
        addr: "127.0.0.1:9099".parse().unwrap(),
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0x77; 32],
        ticket_epoch_t0: 0,
        ttl: 4,
    };
    transport_a.forward_heartbeat_gossip(&hb, 1, addr_a).await;

    // Give tasks a moment to spawn and become stuck waiting on the stalled peer
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Trigger cancellation via CancellationToken (WITHOUT closing endpoint socket)
    cancel_a.cancel();

    // drain_tasks MUST complete promptly (< 500ms), proving the forwarder tasks were aborted by cancellation token
    let drain_res =
        tokio::time::timeout(Duration::from_millis(500), transport_a.drain_tasks()).await;
    assert!(
        drain_res.is_ok(),
        "S04-R3 VIOLATION: drain_tasks timed out! Stalled forwarder tasks did not release upon cancellation token trigger!"
    );
}

/// S04-R5: Equivocation fraud proofs have dedicated priority forwarding capacity over heartbeat gossip (Spec 10).
/// When all 256 heartbeat forwarding slots are occupied, verified fraud proofs MUST still be forwarded
/// to reachable F2F neighbors with priority, causing receiver-side revocation/ban.
#[tokio::test]
async fn test_s04_r5_fraud_forwarding_priority_under_heartbeat_saturation() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate(); // Reachable honest F2F neighbor

    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    // Node B with real DualTierEngine and RedbStorage to verify receiver-side slashing & ban
    let temp_b = tempfile::tempdir().unwrap();
    let db_b = Arc::new(RedbStorage::open(&temp_b.path().join("db_b.redb")).unwrap());
    let (engine_b, worker_b) = DualTierEngine::new(db_b.clone());
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));
    pm_b.set_simulation_mode(true);
    let cancel_b = CancellationToken::new();
    let handler_b = Arc::new(NodeRequestHandler::with_peer_manager(
        engine_b.clone(),
        db_b.clone(),
        identity_b.clone(),
        pm_b.clone(),
    ));

    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        handler_b,
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    let addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a))
        .await;

    // 1. Fully saturate / occupy all 256 heartbeat forwarding permits on Node A
    let mut held_hb_permits = Vec::new();
    while let Ok(permit) = transport_a
        .outbound_forwarder_semaphore()
        .clone()
        .try_acquire_owned()
    {
        held_hb_permits.push(permit);
    }
    assert_eq!(
        held_hb_permits.len(),
        256,
        "Must occupy all 256 heartbeat forwarding permits"
    );
    assert_eq!(
        transport_a
            .outbound_forwarder_semaphore()
            .available_permits(),
        0,
        "Heartbeat forwarder capacity must be completely exhausted"
    );

    // Verify that heartbeat forwarding would fail to acquire permits
    let hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: [0x88; 32],
        addr: "127.0.0.1:9098".parse().unwrap(),
        timestamp_ms: 100,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0x88; 32],
        ticket_epoch_t0: 0,
        ttl: 4,
    };
    transport_a.forward_heartbeat_gossip(&hb, 1, addr_a).await;

    // 2. Generate a genuine cryptographically signed equivocation fraud proof
    let victim = NodeIdentity::generate();
    let fraud_proof = build_self_revocation_fraud_proof(
        &victim,
        humoco_sim_core::types::NetworkId::default(),
        2000,
    );
    assert!(verify_equivocation_first_party_network(
        humoco_sim_core::types::NetworkId::default(),
        victim.verifying_key(),
        &fraud_proof
    ));

    // 3. Broadcast fraud proof on Node A despite complete heartbeat forwarder saturation
    transport_a
        .broadcast_equivocation_proof_to_f2f(&fraud_proof)
        .await;

    // 4. Assert bounded priority delivery to Node B and receiver-side revocation / ban
    let start = std::time::Instant::now();
    let mut banned = false;
    while start.elapsed() < Duration::from_secs(3) {
        if engine_b.is_node_banned(victim.node_pubkey()).await
            && db_b.is_node_banned(victim.node_pubkey()).unwrap_or(false)
        {
            banned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        banned,
        "S04-R5 VIOLATION: Fraud proof was dropped or starved under heartbeat saturation! Offender was not banned on neighbor Node B"
    );

    drop(held_hb_permits);
    cancel_a.cancel();
    cancel_b.cancel();
    transport_a.close();
    transport_b.close();
    transport_a.drain_tasks().await;
    transport_b.drain_tasks().await;
    worker_b.abort();
    let _ = worker_b.await;
}

/// S04-R5: Boundedness & retryability when fraud forwarding capacity itself is exhausted.
/// When a proof receives zero forwarding admissions due to capacity exhaustion, it MUST NOT
/// be committed in the dedup cache, allowing subsequent retries to deliver once capacity recovers.
/// Conversely, once forwarded, it IS deduplicated to prevent loops and storms.
#[tokio::test]
async fn test_s04_r5_fraud_forwarder_exhaustion_retryability_and_dedup() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate(); // Reachable honest F2F neighbor

    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    let temp_b = tempfile::tempdir().unwrap();
    let db_b = Arc::new(RedbStorage::open(&temp_b.path().join("db_b_retry.redb")).unwrap());
    let (engine_b, worker_b) = DualTierEngine::new(db_b.clone());
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));
    pm_b.set_simulation_mode(true);
    let cancel_b = CancellationToken::new();
    let handler_b = Arc::new(NodeRequestHandler::with_peer_manager(
        engine_b.clone(),
        db_b.clone(),
        identity_b.clone(),
        pm_b.clone(),
    ));

    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        handler_b,
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    let addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a))
        .await;

    // 1. Generate genuine fraud proof for victim
    let victim = NodeIdentity::generate();
    let proof = build_self_revocation_fraud_proof(
        &victim,
        humoco_sim_core::types::NetworkId::default(),
        3000,
    );
    let hash = PeerManager::fraud_proof_dedup_hash(&proof);

    // 2. Fully exhaust fraud forwarder capacity itself (all 256 permits)
    let mut held_fraud_permits = Vec::new();
    while let Ok(permit) = transport_a
        .fraud_forwarder_semaphore()
        .clone()
        .try_acquire_owned()
    {
        held_fraud_permits.push(permit);
    }
    assert_eq!(
        held_fraud_permits.len(),
        256,
        "Must occupy all 256 fraud forwarder permits"
    );
    assert_eq!(
        transport_a.fraud_forwarder_semaphore().available_permits(),
        0,
        "Fraud forwarder capacity must be completely exhausted"
    );

    // 3. Attempt to broadcast proof while capacity is exhausted
    transport_a
        .broadcast_equivocation_proof_to_f2f(&proof)
        .await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Assert: Proof was NOT committed in dedup cache on Node A because 0 admissions occurred
    assert!(
        !pm_a.has_fraud_proof(&hash).await,
        "S04-R5 VIOLATION: Proof must NOT be committed in dedup cache when 0 admissions occurred due to capacity exhaustion!"
    );
    assert!(
        !engine_b.is_node_banned(victim.node_pubkey()).await,
        "Offender must not be banned yet since proof was not forwarded"
    );

    // 4. Recover capacity
    drop(held_fraud_permits);
    assert_eq!(
        transport_a.fraud_forwarder_semaphore().available_permits(),
        256,
        "All 256 fraud forwarder permits must be restored"
    );

    // 5. Retry submitting the exact same proof
    transport_a
        .broadcast_equivocation_proof_to_f2f(&proof)
        .await;

    // Assert: Retried proof is delivered and offender is banned on Node B
    let start = std::time::Instant::now();
    let mut banned = false;
    while start.elapsed() < Duration::from_secs(3) {
        if engine_b.is_node_banned(victim.node_pubkey()).await
            && db_b.is_node_banned(victim.node_pubkey()).unwrap_or(false)
        {
            banned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        banned,
        "S04-R5 VIOLATION: Retried fraud proof was not delivered after capacity recovered!"
    );

    // 6. Assert deduplication once forwarded
    assert!(
        pm_a.has_fraud_proof(&hash).await,
        "Proof MUST be committed in dedup cache once forwarding admission succeeded"
    );

    // Re-broadcasting duplicate proof must be rejected immediately by dedup cache
    let available_before = transport_a.fraud_forwarder_semaphore().available_permits();
    transport_a
        .broadcast_equivocation_proof_to_f2f(&proof)
        .await;
    let available_after = transport_a.fraud_forwarder_semaphore().available_permits();
    assert_eq!(
        available_before, available_after,
        "Duplicate proof must be deduplicated without consuming forwarder permits"
    );

    cancel_a.cancel();
    cancel_b.cancel();
    transport_a.close();
    transport_b.close();
    transport_a.drain_tasks().await;
    transport_b.drain_tasks().await;
    worker_b.abort();
    let _ = worker_b.await;
}

/// S04-14: Bounded outbound requests under zero bidirectional stream credit
/// and blocked request consumption (stream-credit starvation and blocked transmission).
/// Asserts a structured timeout covering the entire operation and prompt termination on transport cancellation.
#[tokio::test]
async fn test_s04_14_outbound_request_zero_bidi_credit_and_blocked_consumption() {
    let identity_a = NodeIdentity::generate();
    let pm_a = Arc::new(PeerManager::new(Vec::new()));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    transport_a.spawn_accept_loop();

    // --- (a1) Peer with 0 max_concurrent_bidi_streams -> structured timeout ---
    let identity_stalled = NodeIdentity::generate();
    let mut server_config_stalled = build_quinn_server_config_with_network(
        &identity_stalled,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config_stalled = quinn::TransportConfig::default();
    transport_config_stalled.max_concurrent_bidi_streams(0u8.into());
    server_config_stalled.transport_config(Arc::new(transport_config_stalled));
    let endpoint_stalled =
        quinn::Endpoint::server(server_config_stalled, "127.0.0.1:0".parse().unwrap()).unwrap();
    let stalled_addr = endpoint_stalled.local_addr().unwrap();

    let (_held_tx, mut _held_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(32);
    let stalled_endpoint_clone = endpoint_stalled.clone();
    tokio::spawn(async move {
        while let Some(inc) = stalled_endpoint_clone.accept().await {
            if let Ok(c) = inc.await {
                let _ = _held_tx.send(c).await;
            }
        }
    });

    let conn_stalled = transport_a
        .connect_peer_unchecked(stalled_addr)
        .await
        .unwrap();

    let header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 0, 4);
    let payload = b"test";

    let start = std::time::Instant::now();
    let res_stalled = tokio::time::timeout(
        Duration::from_secs(6),
        transport_a.send_request(&conn_stalled, &header, payload),
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        res_stalled.is_ok(),
        "S04-14 VIOLATION: send_request timed out after 6s because open_bi hung without bounded deadline"
    );
    let inner_stalled = res_stalled.unwrap();
    assert!(
        inner_stalled.is_err(),
        "S04-14: Outbound request to peer with 0 bidi stream credit must fail, not succeed"
    );
    let err_str = inner_stalled.unwrap_err().to_string();
    assert!(
        err_str.to_lowercase().contains("timeout"),
        "S04-14: Error must be a structured timeout, got: {}",
        err_str
    );
    assert!(
        elapsed <= Duration::from_secs(6),
        "S04-14 VIOLATION: send_request took {:?}, must fail within bounded timeout",
        elapsed
    );

    // --- (a2) Peer with tiny receive window and blocked data drain -> structured timeout ---
    let identity_drain = NodeIdentity::generate();
    let mut server_config_drain = build_quinn_server_config_with_network(
        &identity_drain,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config_drain = quinn::TransportConfig::default();
    transport_config_drain.stream_receive_window(256u32.into());
    transport_config_drain.receive_window(256u32.into());
    server_config_drain.transport_config(Arc::new(transport_config_drain));
    let endpoint_drain =
        quinn::Endpoint::server(server_config_drain, "127.0.0.1:0".parse().unwrap()).unwrap();
    let drain_addr = endpoint_drain.local_addr().unwrap();

    let (_drain_tx, mut _drain_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(32);
    let endpoint_drain_clone = endpoint_drain.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint_drain_clone.accept().await {
            if let Ok(conn) = incoming.await {
                let _ = _drain_tx.send(conn.clone()).await;
                tokio::spawn(async move {
                    while let Ok(_bi) = conn.accept_bi().await {
                        // Intentionally do not read request or send response
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                });
            }
        }
    });

    let conn_drain = transport_a
        .connect_peer_unchecked(drain_addr)
        .await
        .unwrap();
    let big_payload = vec![0xABu8; 64 * 1024]; // 64 KB > 256 bytes window
    let header_drain =
        WireHeader::new(MsgType::StatusQuery as u16, 2, 0, 0, big_payload.len() as u32);

    let start_drain = std::time::Instant::now();
    let res_drain = tokio::time::timeout(
        Duration::from_secs(6),
        transport_a.send_request(&conn_drain, &header_drain, &big_payload),
    )
    .await;
    let elapsed_drain = start_drain.elapsed();

    assert!(
        res_drain.is_ok(),
        "S04-14 VIOLATION: send_request with blocked drain timed out after 6s because write_frame hung"
    );
    let inner_drain = res_drain.unwrap();
    assert!(
        inner_drain.is_err(),
        "S04-14: Outbound request with blocked data drain must fail, not succeed"
    );
    let err_drain_str = inner_drain.unwrap_err().to_string();
    assert!(
        err_drain_str.to_lowercase().contains("timeout"),
        "S04-14: Error must be a structured timeout, got: {}",
        err_drain_str
    );
    assert!(
        elapsed_drain <= Duration::from_secs(6),
        "S04-14 VIOLATION: send_request with blocked drain took {:?}, must fail within bounded timeout",
        elapsed_drain
    );

    cancel_a.cancel();
    transport_a.close();
}

/// S04-14: Prompt termination on transport cancellation across stream acquisition
/// and frame transmission.
#[tokio::test]
async fn test_s04_14_outbound_request_cancellation_prompt_termination() {
    let identity_a = NodeIdentity::generate();
    let pm_a = Arc::new(PeerManager::new(Vec::new()));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    transport_a.spawn_accept_loop();

    // 1. Peer with 0 bidi credit
    let identity_stalled = NodeIdentity::generate();
    let mut server_config_stalled = build_quinn_server_config_with_network(
        &identity_stalled,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config_stalled = quinn::TransportConfig::default();
    transport_config_stalled.max_concurrent_bidi_streams(0u8.into());
    server_config_stalled.transport_config(Arc::new(transport_config_stalled));
    let endpoint_stalled =
        quinn::Endpoint::server(server_config_stalled, "127.0.0.1:0".parse().unwrap()).unwrap();
    let stalled_addr = endpoint_stalled.local_addr().unwrap();

    let (_held_tx, mut _held_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(32);
    let stalled_endpoint_clone = endpoint_stalled.clone();
    tokio::spawn(async move {
        while let Some(inc) = stalled_endpoint_clone.accept().await {
            if let Ok(c) = inc.await {
                let _ = _held_tx.send(c).await;
            }
        }
    });

    let conn_stalled = transport_a
        .connect_peer_unchecked(stalled_addr)
        .await
        .unwrap();

    let header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 0, 4);
    let payload = b"test";

    let t_clone = transport_a.clone();
    let c_clone = conn_stalled.clone();
    let task = tokio::spawn(async move {
        t_clone.send_request(&c_clone, &header, payload).await
    });

    // Let task enter open_bi wait
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Trigger transport cancellation
    cancel_a.cancel();

    let res = tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .expect("S04-14 VIOLATION: send_request task did not terminate promptly on transport cancellation")
        .unwrap();

    assert!(res.is_err(), "Must return Err on cancellation");
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.to_lowercase().contains("cancel"),
        "Error must indicate cancellation, got: {}",
        err_str
    );

    transport_a.close();
}

/// S04-15: Forwarder cancellation covers connection establishment.
/// When forwarders dial a locally bound UDP socket that discards QUIC Initial packets,
/// triggering cancellation must allow drain_tasks() to complete within 500 ms without
/// closing the endpoint first, and forwarding permits must recover.
#[tokio::test]
async fn test_s04_15_forwarders_drain_promptly_when_dialing_discarding_udp_socket() {
    let identity_a = NodeIdentity::generate();
    let identity_blackhole = NodeIdentity::generate();

    // Bind a raw UDP socket that discards all incoming packets
    let blackhole_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole_addr = blackhole_socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while blackhole_socket.recv_from(&mut buf).await.is_ok() {}
    });

    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_blackhole.node_id()],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    pm_a.register_f2f_friend(*identity_blackhole.node_id(), Some(blackhole_addr))
        .await;

    // Trigger fraud proof broadcast (spawns forwarder task dialing blackhole)
    let ev_a = humoco_sim_core::fraud::IngressEnvelopeEvidence::default();
    let ev_b = humoco_sim_core::fraud::IngressEnvelopeEvidence {
        epoch_seq: 1,
        ..Default::default()
    };
    let fraud_proof =
        humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(ev_a, ev_b);
    transport_a
        .broadcast_equivocation_proof_to_f2f(&fraud_proof)
        .await;

    // Trigger heartbeat forwarding (spawns forwarder task dialing blackhole)
    let hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: [0x88; 32],
        addr: "127.0.0.1:9097".parse().unwrap(),
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0x88; 32],
        ticket_epoch_t0: 0,
        ttl: 4,
    };
    transport_a.forward_heartbeat_gossip(&hb, 1, addr_a).await;

    // Give tasks a moment to spawn and start dialing the blackhole UDP socket
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Observe that forwarder permits were acquired
    assert!(
        transport_a.fraud_forwarder_semaphore().available_permits() < 256,
        "Fraud forwarder permit must have been acquired"
    );
    assert!(
        transport_a.outbound_forwarder_semaphore().available_permits() < 256,
        "Heartbeat forwarder permit must have been acquired"
    );

    // Cancel WITHOUT closing the endpoint
    cancel_a.cancel();

    // drain_tasks() MUST complete promptly (< 500 ms)
    let drain_res =
        tokio::time::timeout(Duration::from_millis(500), transport_a.drain_tasks()).await;
    assert!(
        drain_res.is_ok(),
        "S04-15 VIOLATION: drain_tasks() timed out! Forwarder dialing blackhole did not release upon cancellation token trigger!"
    );

    // Verify forwarding permits recover
    assert_eq!(
        transport_a.fraud_forwarder_semaphore().available_permits(),
        256,
        "Fraud forwarder permits must be restored after drain"
    );
    assert_eq!(
        transport_a.outbound_forwarder_semaphore().available_permits(),
        256,
        "Heartbeat forwarder permits must be restored after drain"
    );
}

/// S04-Controls: Normal round-trip request/response and successful-handshake forwarding
/// operate correctly and release permits.
#[tokio::test]
async fn test_s04_controls_normal_roundtrip_and_forwarding() {
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();

    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_b.node_id()],
    ));
    pm_a.set_simulation_mode(true);
    let cancel_a = CancellationToken::new();

    let transport_a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_a,
        pm_a.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_a.clone(),
    )
    .expect("Bind transport A");
    let addr_a = transport_a.local_addr().unwrap();
    transport_a.spawn_accept_loop();

    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_id()],
    ));
    pm_b.set_simulation_mode(true);
    let cancel_b = CancellationToken::new();

    let transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_b.clone(),
    )
    .expect("Bind transport B");
    let addr_b = transport_b.local_addr().unwrap();
    transport_b.spawn_accept_loop();

    pm_a.register_f2f_friend(*identity_b.node_id(), Some(addr_b)).await;
    pm_b.register_f2f_friend(*identity_a.node_id(), Some(addr_a)).await;

    // Normal round-trip send_request
    let conn = transport_a.connect_peer_unchecked(addr_b).await.unwrap();
    let req_header = WireHeader::new(MsgType::StatusQuery as u16, 42, 0, 0, 4);
    let (resp_header, resp_payload) = transport_a
        .send_request(&conn, &req_header, b"ping")
        .await
        .expect("send_request round-trip must succeed");
    assert_eq!(resp_header.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(resp_header.session_seq, 42);
    assert_eq!(resp_payload, b"");

    // Normal heartbeat forwarding
    let hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: [0x99; 32],
        addr: "127.0.0.1:9096".parse().unwrap(),
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0x99; 32],
        ticket_epoch_t0: 0,
        ttl: 4,
    };
    transport_a.forward_heartbeat_gossip(&hb, 1, addr_a).await;

    // Wait briefly for forwarder to finish
    let start = std::time::Instant::now();
    while transport_a.outbound_forwarder_semaphore().available_permits() < 256 {
        if start.elapsed() > Duration::from_secs(3) {
            panic!("Forwarder permit was not returned in normal transmission");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    cancel_a.cancel();
    cancel_b.cancel();
    transport_a.close();
    transport_b.close();
    transport_a.drain_tasks().await;
    transport_b.drain_tasks().await;
}

fn zero_credit_client(identity: &NodeIdentity) -> quinn::Endpoint {
    let mut client_config = humoco_node::network::build_quinn_client_config_with_identity_and_network(
        identity,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.stream_receive_window(0u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_millis(50)));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

fn normal_credit_client(identity: &NodeIdentity) -> quinn::Endpoint {
    let client_config = humoco_node::network::build_quinn_client_config_with_identity_and_network(
        identity,
        humoco_sim_core::types::NetworkId::default(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

fn make_test_heartbeat(node_id: [u8; 32]) -> (WireHeader, Vec<u8>) {
    let hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id,
        addr: "127.0.0.1:9099".parse().unwrap(),
        timestamp_ms: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0x55; 32],
        ticket_epoch_t0: 0,
        ttl: 4,
    };
    let payload = bincode::serialize(&hb).unwrap();
    let header = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    (header, payload)
}

fn make_test_direct_rpc() -> (WireHeader, Vec<u8>) {
    let header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 0, 4);
    let payload = b"ping".to_vec();
    (header, payload)
}

/// S04-16: Zero-credit authorization refusals (Branch 1 gossip refusal and Branch 2 direct-RPC refusal)
/// must obey transport cancellation and release stream permits and connection leases during drain_tasks.
#[tokio::test]
async fn test_s04_16_zero_credit_refusal_cancellation_and_resource_release() {
    for branch in ["gossip_refusal", "direct_rpc_refusal"] {
        let identity_server = NodeIdentity::generate();
        let pm_server = Arc::new(PeerManager::new(Vec::new()));
        pm_server.set_simulation_mode(true);
        let cancel_server = CancellationToken::new();

        let transport_server = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &identity_server,
            pm_server.clone(),
            Arc::new(DefaultRequestHandler),
            cancel_server.clone(),
        )
        .expect("Bind server");
        let server_addr = transport_server.local_addr().unwrap();
        transport_server.spawn_accept_loop();

        let identity_client = NodeIdentity::generate();
        let client_ep = zero_credit_client(&identity_client);

        // Learn client via gossip initially so QUIC connection handshake is admitted
        pm_server
            .learn_node_from_gossip_with_hrw(
                *identity_client.node_id(),
                *identity_client.hrw_routing_id(),
                "127.0.0.1:9099".parse().unwrap(),
                0,
                None,
            )
            .await;

        let conn = client_ep
            .connect(server_addr, humoco_node::network::transport::P2P_QUIC_SNI)
            .unwrap()
            .await
            .expect("client connects to server");

        // Wait until server accept loop has processed handshake and recorded success
        let client_local = client_ep.local_addr().unwrap();
        let admit_start = std::time::Instant::now();
        while pm_server.get_connection(&client_local).await.is_none() {
            if admit_start.elapsed() > Duration::from_secs(3) {
                panic!("Server did not admit connection for {branch}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if branch == "direct_rpc_refusal" {
            // Remove from known nodes so it is an unauthorized stranger for direct-RPC
            pm_server.unlearn_node_for_test(identity_client.node_id()).await;
        }

        let (header, payload) = if branch == "gossip_refusal" {
            make_test_heartbeat(*identity_client.node_id())
        } else {
            make_test_direct_rpc()
        };

        let (mut send, _recv) = conn.open_bi().await.expect("client opens bi-stream");
        humoco_node::network::write_frame(&mut send, &header, &payload)
            .await
            .expect("client writes request");
        send.finish().expect("client finishes send");

        // Wait deterministically until the server task has acquired a stream permit
        let start = std::time::Instant::now();
        while transport_server.stream_semaphore_available_for_test()
            == humoco_node::network::transport::STREAM_CONCURRENCY_LIMIT
        {
            if start.elapsed() > Duration::from_secs(3) {
                panic!("Server did not acquire stream permit for {branch}");
            }
            tokio::task::yield_now().await;
        }

        // Trigger transport cancellation
        cancel_server.cancel();

        // drain_tasks() MUST complete promptly (< 500 ms)
        let drain_res =
            tokio::time::timeout(Duration::from_millis(500), transport_server.drain_tasks()).await;
        assert!(
            drain_res.is_ok(),
            "S04-16 VIOLATION: drain_tasks() timed out under zero-credit refusal on {branch}"
        );

        // Verify bi-stream permit is restored
        assert_eq!(
            transport_server.stream_semaphore_available_for_test(),
            humoco_node::network::transport::STREAM_CONCURRENCY_LIMIT,
            "Stream permit must be released after cancellation on {branch}"
        );

        transport_server.close();
        client_ep.close(0u32.into(), b"done");
    }
}

/// S04-16: Zero-credit authorization refusals must obey handler deadlines and release resources
/// without hanging, even when transport is NOT cancelled.
#[tokio::test]
async fn test_s04_16_zero_credit_refusal_deadline_expiry_and_resource_release() {
    for branch in ["gossip_refusal", "direct_rpc_refusal"] {
        let identity_server = NodeIdentity::generate();
        let pm_server = Arc::new(PeerManager::new(Vec::new()));
        pm_server.set_simulation_mode(true);
        let cancel_server = CancellationToken::new();

        let transport_server = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &identity_server,
            pm_server.clone(),
            Arc::new(DefaultRequestHandler),
            cancel_server.clone(),
        )
        .expect("Bind server");
        // Set short handler deadline (150ms) for deterministic test execution
        transport_server.set_handler_timeout_for_test(Duration::from_millis(150));
        let server_addr = transport_server.local_addr().unwrap();
        transport_server.spawn_accept_loop();

        let identity_client = NodeIdentity::generate();
        let client_ep = zero_credit_client(&identity_client);

        // Learn client via gossip initially so QUIC connection handshake is admitted
        pm_server
            .learn_node_from_gossip_with_hrw(
                *identity_client.node_id(),
                *identity_client.hrw_routing_id(),
                "127.0.0.1:9099".parse().unwrap(),
                0,
                None,
            )
            .await;

        let conn = client_ep
            .connect(server_addr, humoco_node::network::transport::P2P_QUIC_SNI)
            .unwrap()
            .await
            .expect("client connects to server");

        // Wait until server accept loop has processed handshake and recorded success
        let client_local = client_ep.local_addr().unwrap();
        let admit_start = std::time::Instant::now();
        while pm_server.get_connection(&client_local).await.is_none() {
            if admit_start.elapsed() > Duration::from_secs(3) {
                panic!("Server did not admit connection for {branch}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if branch == "direct_rpc_refusal" {
            // Remove from known nodes so it is an unauthorized stranger for direct-RPC
            pm_server.unlearn_node_for_test(identity_client.node_id()).await;
        }

        let (header, payload) = if branch == "gossip_refusal" {
            make_test_heartbeat(*identity_client.node_id())
        } else {
            make_test_direct_rpc()
        };

        let (mut send, _recv) = conn.open_bi().await.expect("client opens bi-stream");
        humoco_node::network::write_frame(&mut send, &header, &payload)
            .await
            .expect("client writes request");
        send.finish().expect("client finishes send");

        // Wait until server acquires permit
        let start = std::time::Instant::now();
        while transport_server.stream_semaphore_available_for_test()
            == humoco_node::network::transport::STREAM_CONCURRENCY_LIMIT
        {
            if start.elapsed() > Duration::from_secs(3) {
                panic!("Server did not acquire stream permit for {branch}");
            }
            tokio::task::yield_now().await;
        }

        // Wait without cancelling; the handler deadline MUST expire and release the permit
        let deadline_wait = tokio::time::timeout(Duration::from_secs(2), async {
            while transport_server.stream_semaphore_available_for_test()
                < humoco_node::network::transport::STREAM_CONCURRENCY_LIMIT
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;

        assert!(
            deadline_wait.is_ok(),
            "S04-16 VIOLATION: Handler deadline did not expire and release permit for {branch}"
        );
        assert_eq!(
            transport_server.stream_semaphore_available_for_test(),
            humoco_node::network::transport::STREAM_CONCURRENCY_LIMIT,
            "Permit must be fully returned to STREAM_CONCURRENCY_LIMIT after deadline expiry on {branch}"
        );

        cancel_server.cancel();
        transport_server.close();
        let _ = transport_server.drain_tasks().await;
        client_ep.close(0u32.into(), b"done");
    }
}

/// S04-16 Positive Control: Normal-credit peers receive the expected FLAG_UNAUTHORIZED
/// refusal response frame and payload on both refusal branches.
#[tokio::test]
async fn test_s04_16_normal_credit_positive_control() {
    let identity_server = NodeIdentity::generate();
    let pm_server = Arc::new(PeerManager::new(Vec::new()));
    pm_server.set_simulation_mode(true);
    let cancel_server = CancellationToken::new();

    let transport_server = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity_server,
        pm_server.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_server.clone(),
    )
    .expect("Bind server");
    let server_addr = transport_server.local_addr().unwrap();
    transport_server.spawn_accept_loop();

    let identity_client = NodeIdentity::generate();
    let client_ep = normal_credit_client(&identity_client);

    // 1. Branch 1: Gossip Refusal (learned via gossip, but not F2F friend)
    pm_server
        .learn_node_from_gossip_with_hrw(
            *identity_client.node_id(),
            *identity_client.hrw_routing_id(),
            "127.0.0.1:9099".parse().unwrap(),
            0,
            None,
        )
        .await;

    let conn = client_ep
        .connect(server_addr, humoco_node::network::transport::P2P_QUIC_SNI)
        .unwrap()
        .await
        .expect("client connects");

    let (hb_hdr, hb_payload) = make_test_heartbeat(*identity_client.node_id());
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    humoco_node::network::write_frame(&mut send, &hb_hdr, &hb_payload).await.unwrap();
    send.finish().unwrap();

    let (resp_hdr, resp_payload) = humoco_node::network::read_frame(&mut recv).await.unwrap();
    assert_eq!(resp_hdr.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(
        resp_hdr.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED,
        humoco_sim_core::wire::FLAG_UNAUTHORIZED,
        "Gossip refusal must respond with FLAG_UNAUTHORIZED"
    );
    assert_eq!(resp_payload, b"unauthorized gossip: F2F only");

    // 2. Branch 2: Direct-RPC Refusal from unknown peer
    let identity_unknown = NodeIdentity::generate();
    let unknown_ep = normal_credit_client(&identity_unknown);
    pm_server
        .learn_node_from_gossip_with_hrw(
            *identity_unknown.node_id(),
            *identity_unknown.hrw_routing_id(),
            "127.0.0.1:9098".parse().unwrap(),
            0,
            None,
        )
        .await;
    let unknown_conn = unknown_ep
        .connect(server_addr, humoco_node::network::transport::P2P_QUIC_SNI)
        .unwrap()
        .await
        .expect("unknown client connects");

    let client_local2 = unknown_ep.local_addr().unwrap();
    let admit_start2 = std::time::Instant::now();
    while pm_server.get_connection(&client_local2).await.is_none() {
        if admit_start2.elapsed() > Duration::from_secs(3) {
            panic!("Server did not admit connection for direct_rpc_refusal");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    pm_server.unlearn_node_for_test(identity_unknown.node_id()).await;

    let (rpc_hdr, rpc_payload) = make_test_direct_rpc();
    let (mut send2, mut recv2) = unknown_conn.open_bi().await.unwrap();
    humoco_node::network::write_frame(&mut send2, &rpc_hdr, &rpc_payload).await.unwrap();
    send2.finish().unwrap();

    let (resp_hdr2, resp_payload2) = humoco_node::network::read_frame(&mut recv2).await.unwrap();
    assert_eq!(resp_hdr2.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(
        resp_hdr2.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED,
        humoco_sim_core::wire::FLAG_UNAUTHORIZED,
        "Direct-RPC refusal must respond with FLAG_UNAUTHORIZED"
    );
    assert_eq!(resp_payload2, b"unauthorized");

    cancel_server.cancel();
    transport_server.close();
    transport_server.drain_tasks().await;
    client_ep.close(0u32.into(), b"done");
    unknown_ep.close(0u32.into(), b"done");
}
