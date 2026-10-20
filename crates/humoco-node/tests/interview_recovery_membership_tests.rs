//! Adversarial regressions for interview recovery and passive membership gates.
use humoco_node::daemon::{sync_single_shard, ShardReadinessManager};
use humoco_node::identity::NodeIdentity;
use humoco_node::network::{DefaultRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[test]
fn readiness_admission_is_bounded_deduplicated_and_fail_closed() {
    let cancel = CancellationToken::new();
    let manager = ShardReadinessManager::with_cancel_token(cancel.clone());
    assert!(!manager.is_shard_ready(17));
    for shard in 0..32 {
        assert!(manager.request_sync(shard));
    }
    assert!(!manager.request_sync(0));
    assert!(!manager.request_sync(32));
    manager.mark_shard_ready(17);
    assert!(manager.is_shard_ready(17));
    manager.set_storage_healthy(false);
    assert!(!manager.is_shard_ready(17));
    assert!(!manager.request_sync(18));
    manager.set_storage_healthy(true);
    assert!(!manager.is_shard_ready(17));
    manager.mark_shard_ready(17);
    cancel.cancel();
    assert!(!manager.is_shard_ready(17));
    assert!(!manager.request_sync(18));
}

#[tokio::test]
async fn peerless_recovery_never_authorizes_empty_state() {
    let temp = tempfile::tempdir().expect("temp directory");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("recovery.redb")).expect("storage"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let manager = Arc::new(PeerManager::new(Vec::new()));
    let cancel = CancellationToken::new();
    let transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("address"),
        &identity,
        manager.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("transport");
    let readiness = Arc::new(ShardReadinessManager::with_cancel_token(cancel.clone()));
    assert!(readiness.request_sync(42));
    let ready = sync_single_shard(
        42, &transport, &manager, &engine, &storage, &identity, &readiness, &cancel,
    )
    .await
    .expect("recovery attempt");
    assert!(!ready);
    assert!(!readiness.is_shard_ready(42));
    cancel.cancel();
}

#[tokio::test]
async fn committee_uses_three_missed_heartbeats_not_rpc_failure_score() {
    let manager = PeerManager::new(Vec::new());
    let remote = NodeIdentity::generate();
    let local = NodeIdentity::generate();
    let addr = "127.0.0.1:31415".parse().expect("address");
    manager
        .learn_node_from_gossip_with_hrw(
            *remote.node_pubkey(),
            *remote.hrw_routing_id(),
            addr,
            0,
            None,
        )
        .await;
    manager
        .set_first_seen_for_test(
            remote.node_pubkey(),
            Instant::now() - Duration::from_secs(25 * 3600),
        )
        .await;
    manager
        .set_last_seen_for_test(
            remote.node_pubkey(),
            Instant::now() - Duration::from_secs(2 * 3600 + 60),
        )
        .await;
    let selected = manager
        .shard_committee(*local.node_pubkey(), *local.hrw_routing_id(), 42)
        .await
        .0;
    assert!(selected
        .iter()
        .any(|m| m.node_pubkey == *remote.node_pubkey()));
    assert!(
        !selected
            .iter()
            .any(|m| m.node_pubkey == *local.node_pubkey()),
        "self ticket must not bypass incubation"
    );
    let now = Instant::now();
    for seconds in [0, 61, 122] {
        manager
            .record_failure_at(addr, now + Duration::from_secs(seconds))
            .await;
    }
    let selected = manager
        .shard_committee(*local.node_pubkey(), *local.hrw_routing_id(), 42)
        .await
        .0;
    assert!(
        selected
            .iter()
            .any(|m| m.node_pubkey == *remote.node_pubkey()),
        "RPC misses are not passive presence misses"
    );
    manager
        .set_last_seen_for_test(
            remote.node_pubkey(),
            Instant::now() - Duration::from_secs(3 * 3600 + 1),
        )
        .await;
    let selected = manager
        .shard_committee(*local.node_pubkey(), *local.hrw_routing_id(), 42)
        .await
        .0;
    assert!(!selected
        .iter()
        .any(|m| m.node_pubkey == *remote.node_pubkey()));
}

#[tokio::test]
async fn direct_peer_identity_cannot_substitute_for_a_mature_ticket() {
    let manager = PeerManager::new(Vec::new());
    let remote = NodeIdentity::generate();
    let local = NodeIdentity::generate();
    let addr = "127.0.0.1:31416".parse().expect("address");
    manager
        .register_f2f_friend(*remote.node_pubkey(), Some(addr))
        .await;
    manager
        .record_success(addr, Some(*remote.node_pubkey()), None)
        .await;
    assert!(manager
        .shard_committee(*local.node_pubkey(), *local.hrw_routing_id(), 42)
        .await
        .0
        .is_empty());
}

#[tokio::test]
async fn unknown_shard_is_rejected_over_real_quic_despite_global_readiness() {
    use humoco_node::network::NodeRequestHandler;
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_NOT_READY};
    let temp = tempfile::tempdir().expect("temp");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("wire.redb")).expect("storage"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let client_id = NodeIdentity::generate();
    let cancel = CancellationToken::new();
    let pm_server = Arc::new(PeerManager::new(Vec::new()));
    let pm_client = Arc::new(PeerManager::new(Vec::new()));
    let readiness = Arc::new(ShardReadinessManager::with_cancel_token(cancel.clone()));
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage,
            server_id.clone(),
            pm_server.clone(),
        )
        .with_sync_ready(Arc::new(std::sync::atomic::AtomicBool::new(true)))
        .with_readiness_manager(readiness.clone()),
    );
    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("address"),
        &server_id,
        pm_server.clone(),
        handler,
        cancel.clone(),
    )
    .expect("bind server");
    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("address"),
        &client_id,
        pm_client.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind client");
    let server_addr = server_transport.local_addr().expect("server address");
    let client_addr = client_transport.local_addr().expect("client address");
    // Explicitly authenticate the edge and arrange a mature committee fixture.
    // This does not model a completed recovery or certify source coverage.
    pm_server
        .register_f2f_friend(*client_id.node_pubkey(), Some(client_addr))
        .await;
    pm_client
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;
    pm_server
        .learn_node_from_gossip_with_hrw(
            *server_id.node_pubkey(),
            *server_id.hrw_routing_id(),
            server_addr,
            0,
            None,
        )
        .await;
    pm_server
        .set_first_seen_for_test(
            server_id.node_pubkey(),
            Instant::now() - Duration::from_secs(25 * 3600),
        )
        .await;
    server_transport.spawn_accept_loop();
    client_transport.spawn_accept_loop();
    let conn = client_transport
        .connect_peer(server_addr)
        .await
        .expect("QUIC connect");
    let now_ms = pm_server.net_time_ms();
    let root_valid_until = now_ms + 600_000;
    let mut hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *client_id.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "barrier_test_voucher".into(),
        ds_tag: None,
        transaction_hash: [0x55; 32],
        is_genesis: true,
        sender_ephemeral_pub: *client_id.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now_ms,
        deletable_at: Some(root_valid_until.to_string()),
        privacy_guard: None,
    };
    {
        use ed25519_dalek::Signer;
        let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&hmc_req);
        hmc_req.layer2_signature = client_id.signing_key().sign(&payload_hash).to_bytes();
    }
    let entry = humoco_node::api::hmc::L2LockEntry::from(&hmc_req);
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(600);
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        client_id.node_pubkey(),
        0,
        0,
        now_ms,
        0,
        0,
        footprint,
        false,
        &entry.t_id,
    );
    use ed25519_dalek::Signer;
    let sig = client_id.signing_key().sign(&digest).to_bytes();
    let wire = humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req,
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: *client_id.node_pubkey(),
        sender_signature: sig,
        timestamp_ms: now_ms,
    };
    let raw_payload = bincode::serialize(&wire).unwrap();

    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        raw_payload.len() as u32,
    );
    let (response, bytes) = client_transport
        .send_request(&conn, &header, &raw_payload)
        .await
        .expect("QUIC response");
    assert_ne!(response.flags & FLAG_NOT_READY, 0);
    assert!(
        bytes.is_empty(),
        "no binding vote may escape an unknown shard"
    );
    assert!(engine.hmc_ram.read().await.locks.is_empty());
    cancel.cancel();
}
