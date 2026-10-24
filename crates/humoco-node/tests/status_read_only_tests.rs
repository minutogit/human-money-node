//! Real-QUIC regressions: ordinary status is an observation, never an approval.
//! Ticket maturity/trust are explicit fixtures; they do not prove bootstrap.
#[path = "common/recovery.rs"]
mod recovery;

use ed25519_dalek::Signer;
use humoco_node::{
    api::{build_router, dto::AttestationDto, hmc::L2LockEntry, AppState},
    ingress::{PowEngine, TierController},
    network::framing::{StatusObservation, StatusQueryPayload},
};
use humoco_sim_core::{
    types::{LockRecord, SimTime},
    wire::{MsgType, WireHeader},
};
use std::sync::{atomic::Ordering, Arc};

fn payload(reader: &recovery::RecoveryPeer, row: &LockRecord, shard: u16, legacy: bool) -> Vec<u8> {
    if legacy {
        return bincode::serialize(&(row.id, row.parent_lock, shard)).unwrap();
    }
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let now = reader.manager.net_time_ms() + seq;
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        reader.identity.node_pubkey(),
        0,
        0,
        now,
        0,
        seq,
        0,
        true,
        &row.id,
    );
    bincode::serialize(&StatusQueryPayload {
        lock_id: row.id,
        parent_lock: row.parent_lock,
        shard_id: shard,
        sender_pubkey: *reader.identity.node_pubkey(),
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: seq,
        timestamp_ms: now,
        sender_signature: reader.identity.signing_key().sign(&digest).to_bytes(),
    })
    .unwrap()
}

async fn observe(
    reader: &recovery::RecoveryPeer,
    source: &recovery::RecoveryPeer,
    bytes: &[u8],
    flags: u32,
) -> Vec<u8> {
    let conn = reader
        .network
        .connect_peer(source.network.local_addr().unwrap())
        .await
        .unwrap();
    let (header, reply) = reader
        .network
        .send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 1, 0, flags, bytes.len() as u32),
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(header.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(header.flags, 0);
    assert!(
        AttestationDto::from_wire_bytes(&reply).is_none(),
        "status must not release an original approval"
    );
    reply
}

#[tokio::test]
async fn status_formats_flags_and_signing_gates_cannot_mint_originals() {
    let peers = recovery::recovery_peers(2).await;
    let (reader, source) = (&peers[0], &peers[1]);
    let now = source.manager.net_time_ms();
    let row = LockRecord::new(
        [7; 32],
        [8; 32],
        vec![9],
        SimTime(now),
        SimTime(now + 600_000),
    );
    let shard = u16::from_be_bytes([7, 7]);
    source
        .engine
        .ram
        .write()
        .await
        .insert_recovered(row.clone(), SimTime(now + 600_000));
    assert!(source.db.get_lock(&row.parent_lock).unwrap().is_none());
    for unhealthy in [true, false] {
        source
            .engine
            .stats
            .signing_failed
            .store(unhealthy, Ordering::Release);
        for ready in [false, true] {
            if ready {
                source.readiness.mark_shard_ready(shard);
            } else {
                source.readiness.invalidate_shard(shard);
            }
            // Even ready+healthy cannot turn a two-node view into FINAL authority.
            for legacy in [true, false] {
                let bytes = payload(reader, &row, shard, legacy);
                for flags in [0, 1, 2, 3, 0xff, u32::MAX] {
                    let reply = observe(reader, source, &bytes, flags).await;
                    let observation: StatusObservation = bincode::deserialize(&reply).unwrap();
                    assert_eq!(
                        (
                            observation.version,
                            observation.lock_id,
                            observation.parent_lock,
                            observation.shard_id
                        ),
                        (1, row.id, row.parent_lock, shard)
                    );
                }
                let wrong_shard = payload(reader, &row, shard + 1, legacy);
                assert!(observe(reader, source, &wrong_shard, 1).await.is_empty());
            }
        }
    }
    let checkpoint =
        humoco_node::network::framing::SigningCheckpoint::signed(&source.identity, 0, 1, [17; 32]);
    let heartbeat = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        node_id: *reader.identity.node_pubkey(),
        addr: reader.network.local_addr().unwrap(),
        timestamp_ms: reader.manager.net_time_ms(),
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: *reader.identity.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
        signing_checkpoint: Some(checkpoint),
    };
    let bytes = bincode::serialize(&heartbeat).unwrap();
    let conn = reader
        .network
        .connect_peer(source.network.local_addr().unwrap())
        .await
        .unwrap();
    reader
        .network
        .send_unidirectional(
            &conn,
            &WireHeader::new(MsgType::Heartbeat as u16, 10, 0, 0, bytes.len() as u32),
            &bytes,
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while source.db.is_signing_history_healthy() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!source.engine.is_signing_healthy());
    for legacy in [true, false] {
        let reply = observe(reader, source, &payload(reader, &row, shard, legacy), 1).await;
        assert_eq!(
            bincode::deserialize::<StatusObservation>(&reply)
                .unwrap()
                .lock_id,
            row.id
        );
    }
    assert!(source.db.get_lock(&row.parent_lock).unwrap().is_none());
    assert!(source
        .db
        .own_signing_choice(source.identity.node_pubkey(), &hex::encode(row.parent_lock))
        .unwrap()
        .is_none());
    recovery::stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn canonical_replacement_status_preserves_exact_retained_original() {
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let peers = recovery::recovery_peers(2).await;
    let (reader, source) = (&peers[0], &peers[1]);
    let now = source.manager.net_time_ms();
    let first = LockRecord::new(
        [7; 32],
        [8; 32],
        vec![9],
        SimTime(now),
        SimTime(now + 600_000),
    );
    let other = LockRecord::new(
        [7; 32],
        [9; 32],
        vec![10],
        SimTime(now),
        SimTime(now + 600_000),
    );
    let shard = u16::from_be_bytes([7, 7]);
    let att = humoco_node::api::routes::create_attestation_for_network(
        &source.identity,
        first.id,
        first.parent_lock,
        shard,
        1,
        now,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let exact = bincode::serialize(&att).unwrap();
    source
        .db
        .commit_original_record_approval(
            &first,
            now + 600_000,
            source.identity.node_pubkey(),
            &exact,
            1,
        )
        .unwrap();
    // Prepare the lawful merged canonical state, independently of the immutable own choice.
    source.db.put_lock(&other, now + 600_000).unwrap();
    source
        .engine
        .ram
        .write()
        .await
        .insert_recovered(other.clone(), SimTime(now + 600_000));
    source
        .engine
        .stats
        .signing_failed
        .store(true, Ordering::Release);
    for legacy in [true, false] {
        let reply = observe(reader, source, &payload(reader, &other, shard, legacy), 1).await;
        let observation: StatusObservation = bincode::deserialize(&reply).unwrap();
        assert_eq!(observation.lock_id, other.id);
        assert!(
            observe(reader, source, &payload(reader, &first, shard, legacy), 1)
                .await
                .is_empty()
        );
    }
    let pow = Arc::new(PowEngine::new(*source.identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(source.db.clone(), pow.clone()));
    let state = AppState::new(
        source.engine.clone(),
        source.db.clone(),
        source.identity.clone(),
        tiers,
        pow,
    );
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/retained-choice/{}",
                    hex::encode(first.parent_lock)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let json: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["final_approval"], hex::encode(&exact));
    assert_eq!(json["child"], hex::encode(first.id));
    let sig: [u8; 64] = hex::decode(&att.signature).unwrap().try_into().unwrap();
    let digest =
        humoco_proto::live::original_approval_digest(0, shard, 1, &first.parent_lock, &first.id)
            .unwrap();
    source
        .identity
        .verifying_key()
        .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
    let retained = source
        .db
        .own_signing_choice(
            source.identity.node_pubkey(),
            &hex::encode(first.parent_lock),
        )
        .unwrap()
        .unwrap();
    assert_eq!(retained.approvals[1], Some(exact));
    assert_eq!(retained.child, first.id);
    recovery::stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn hmc_tag_and_exact_diagnostics_return_no_new_node_signature() {
    let peers = recovery::recovery_peers(2).await;
    let (reader, source) = (&peers[0], &peers[1]);
    let now = source.manager.net_time_ms();
    let tag = "diagnostic-parent";
    let parent = *blake3::hash(tag.as_bytes()).as_bytes();
    let shard = u16::from_be_bytes([parent[0], parent[1]]);
    let entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "diagnostic-voucher".into(),
        t_id: [42; 32],
        sender_ephemeral_pub: [4; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [5; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    source
        .engine
        .hmc_ram
        .write()
        .await
        .locks
        .insert(tag.into(), entry.clone());
    source
        .engine
        .stats
        .signing_failed
        .store(true, Ordering::Release);
    let exact = bincode::serialize(&(entry.t_id, parent, shard)).unwrap();
    let reply = observe(reader, source, &exact, 1).await;
    assert_eq!(
        bincode::deserialize::<StatusObservation>(&reply)
            .unwrap()
            .lock_id,
        entry.t_id
    );
    let tag_only = bincode::serialize(&([0u8; 32], parent, shard)).unwrap();
    let reply = observe(reader, source, &tag_only, 1).await;
    let observed: L2LockEntry = serde_json::from_slice(&reply).unwrap();
    assert_eq!(
        serde_json::to_vec(&observed).unwrap(),
        serde_json::to_vec(&entry).unwrap()
    );
    assert!(source
        .db
        .own_signing_choice(source.identity.node_pubkey(), tag)
        .unwrap()
        .is_none());
    recovery::stop_recovery_peers(peers).await;
}

#[tokio::test]
async fn pending_worker_then_late_commit_never_turns_status_into_an_original() {
    use humoco_node::{
        daemon::ShardReadinessManager,
        identity::NodeIdentity,
        network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport},
        storage::{engine::PersistenceStats, DualTierEngine, IngressOrigin, RedbStorage},
    };
    use tokio::sync::RwLock;
    use tokio_util::sync::CancellationToken;
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("pending.redb")).unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(humoco_sim_core::storage::RamIndex::new())),
        Arc::new(RwLock::new(humoco_node::storage::HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    let server = NodeIdentity::generate();
    let client = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::new(vec![]));
    let cm = Arc::new(PeerManager::new(vec![]));
    let cancel = CancellationToken::new();
    let readiness = Arc::new(ShardReadinessManager::new());
    let receiver = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        pm.clone(),
        Arc::new(
            NodeRequestHandler::with_peer_manager(
                engine.clone(),
                db.clone(),
                server.clone(),
                pm.clone(),
            )
            .with_readiness_manager(readiness.clone()),
        ),
        cancel.clone(),
    )
    .unwrap();
    let sender = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client,
        cm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    pm.register_f2f_friend(*client.node_pubkey(), Some(sender.local_addr().unwrap()))
        .await;
    cm.register_f2f_friend(*server.node_pubkey(), Some(receiver.local_addr().unwrap()))
        .await;
    receiver.spawn_accept_loop();
    sender.spawn_accept_loop();
    let now = pm.net_time_ms();
    let row = LockRecord::new(
        [7; 32],
        [8; 32],
        vec![9],
        SimTime(now),
        SimTime(now + 600_000),
    );
    let shard = u16::from_be_bytes([7, 7]);
    // Reservation-first production ingress queues the write; withholding the
    // worker is the controlled persistence barrier, not a sleep-based race.
    engine
        .ingress_lock_with_origin(
            row.clone(),
            SimTime(now),
            SimTime(now + 600_000),
            IngressOrigin::ClientApi,
        )
        .await
        .unwrap();
    readiness.mark_shard_ready(shard);
    let conn = sender
        .connect_peer(receiver.local_addr().unwrap())
        .await
        .unwrap();
    let bytes = bincode::serialize(&(row.id, row.parent_lock, shard)).unwrap();
    let header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 1, bytes.len() as u32);
    assert!(db.get_lock(&row.parent_lock).unwrap().is_none());
    let (_, pending) = sender.send_request(&conn, &header, &bytes).await.unwrap();
    assert!(AttestationDto::from_wire_bytes(&pending).is_none());
    assert_eq!(
        bincode::deserialize::<StatusObservation>(&pending)
            .unwrap()
            .lock_id,
        row.id
    );
    let worker = DualTierEngine::spawn_flush_worker(
        rx,
        db.clone(),
        Arc::new(PersistenceStats::default()),
        cancel.clone(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while db.get_lock(&row.parent_lock).unwrap().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (_, committed) = sender.send_request(&conn, &header, &bytes).await.unwrap();
    assert_eq!(pending, committed);
    assert!(db
        .own_signing_choice(server.node_pubkey(), &hex::encode(row.parent_lock))
        .unwrap()
        .is_none());
    cancel.cancel();
    receiver.close();
    sender.close();
    receiver.drain_tasks().await;
    sender.drain_tasks().await;
    worker.await.unwrap();
}

#[tokio::test]
async fn gateway_full_entry_lookup_works_and_rejects_legacy_original_as_entry() {
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use humoco_node::{
        api::hmc::{L2AuthPayload, L2ResponseEnvelope, L2StatusQuery, L2Verdict},
        network::{BoxFuture, PeerManager, QuicTransport, RequestHandler},
    };
    use tower::ServiceExt;
    struct LegacyOriginal {
        bytes: Vec<u8>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl RequestHandler for LegacyOriginal {
        fn handle(
            &self,
            header: WireHeader,
            _payload: Vec<u8>,
        ) -> BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::error::NodeError>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let bytes = self.bytes.clone();
            Box::pin(async move {
                Ok((
                    WireHeader::new(
                        MsgType::StatusResponse as u16,
                        header.session_seq + 1,
                        0,
                        0,
                        bytes.len() as u32,
                    ),
                    bytes,
                ))
            })
        }
    }
    let peers = recovery::recovery_peers(2).await;
    let (reader, source) = (&peers[0], &peers[1]);
    let now = source.manager.net_time_ms();
    let voucher = "remote-only-voucher";
    let shard = humoco_sim_core::types::voucher_shard_id(voucher);
    let tag = "remote-only-parent";
    let mut anchor = [0; 32];
    anchor[..2].copy_from_slice(&shard.to_be_bytes());
    source
        .engine
        .record_hmc_voucher_genesis_parent(voucher, anchor)
        .await;
    let entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher.into(),
        t_id: [42; 32],
        sender_ephemeral_pub: [4; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [5; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    source
        .engine
        .hmc_ram
        .write()
        .await
        .locks
        .insert(tag.into(), entry.clone());
    let pow = Arc::new(PowEngine::new(*reader.identity.node_id(), 8));
    let tiers = Arc::new(TierController::new(reader.db.clone(), pow.clone()));
    let mut state = AppState::new(
        reader.engine.clone(),
        reader.db.clone(),
        reader.identity.clone(),
        tiers,
        pow,
    );
    // Only one eligible remote: assert the actual stateless gateway->QUIC path.
    let routing = Arc::new(PeerManager::new(vec![]));
    routing
        .learn_node_from_gossip_with_hrw(
            *source.identity.node_pubkey(),
            *source.identity.hrw_routing_id(),
            source.network.local_addr().unwrap(),
            0,
            None,
        )
        .await;
    routing
        .set_first_seen_for_test(
            source.identity.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    state.peer_manager = Some(routing.clone());
    state.transport = Some(reader.network.clone());
    let query = L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [1; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher.into(),
        challenge_ds_tag: tag.into(),
        locator_prefixes: vec![],
        read_quorum: 1,
    };
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/status")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&query).unwrap()))
            .unwrap()
    };
    let response = build_router(state.clone())
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let envelope: L2ResponseEnvelope =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(envelope.quorum_certificate.is_none());
    assert!(matches!(envelope.verdict,L2Verdict::Verified {lock_entry} if lock_entry==entry));
    // A genuine old original is still not the requested complete voucher entry.
    let att = humoco_node::api::routes::create_attestation_for_network(
        &source.identity,
        entry.t_id,
        *blake3::hash(tag.as_bytes()).as_bytes(),
        shard,
        1,
        now,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let fake_cancel = tokio_util::sync::CancellationToken::new();
    let fake = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &source.identity,
        source.manager.clone(),
        Arc::new(LegacyOriginal {
            bytes: bincode::serialize(&att).unwrap(),
            calls: calls.clone(),
        }),
        fake_cancel.clone(),
    )
    .unwrap();
    fake.spawn_accept_loop();
    reader
        .manager
        .register_f2f_friend(
            *source.identity.node_pubkey(),
            Some(fake.local_addr().unwrap()),
        )
        .await;
    routing
        .learn_node_from_gossip_with_hrw(
            *source.identity.node_pubkey(),
            *source.identity.hrw_routing_id(),
            fake.local_addr().unwrap(),
            0,
            None,
        )
        .await;
    let response = build_router(state).oneshot(request()).await.unwrap();
    let envelope: L2ResponseEnvelope =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(
        calls.load(Ordering::Relaxed) > 0,
        "negative must reach the malicious remote"
    );
    assert!(matches!(envelope.verdict, L2Verdict::UnknownVoucher));
    assert!(envelope.quorum_certificate.is_none());
    fake_cancel.cancel();
    fake.close();
    fake.drain_tasks().await;
    recovery::stop_recovery_peers(peers).await;
}
