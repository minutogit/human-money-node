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
use humoco_sim_core::wire::{MsgType, WireHeader};
use std::sync::{atomic::Ordering, Arc};

fn make_hmc_entry(id: [u8; 32], voucher_id: &str, now: u64) -> L2LockEntry {
    L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher_id.into(),
        t_id: id,
        sender_ephemeral_pub: [4; 32],
        layer2_signature: [5; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    }
}

fn payload(
    reader: &recovery::RecoveryPeer,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard: u16,
    legacy: bool,
) -> Vec<u8> {
    if legacy {
        return bincode::serialize(&(lock_id, parent_lock, shard)).unwrap();
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
        &lock_id,
    );
    bincode::serialize(&StatusQueryPayload {
        lock_id,
        parent_lock,
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
    let result = reader
        .network
        .send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 1, 0, flags, bytes.len() as u32),
            bytes,
        )
        .await;
    if flags & !1 != 0 {
        assert!(result.is_err(), "unsupported status flags must fail before processing");
        return Vec::new();
    }
    let (header, reply) = result.unwrap();
    if bytes.len() == 66 {
        assert_eq!(header.flags, humoco_sim_core::wire::FLAG_UNAUTHORIZED, "old tuple queries must be refused");
        assert!(reply.is_empty());
        return reply;
    }
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
    let row = make_hmc_entry([7; 32], "voucher-1", now);
    let tag = "spend-parent";
    let parent_lock = *blake3::hash(tag.as_bytes()).as_bytes();
    let shard = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    source
        .engine
        .hmc_ram
        .write()
        .await
        .insert_lock_for_test(tag.to_string(), row.clone());
    assert!(source.db.get_hmc_lock(tag).unwrap().is_none());
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
                let bytes = payload(reader, row.t_id, parent_lock, shard, legacy);
                for flags in [0, 1, 2, 3, 0xff, u32::MAX] {
                    let reply = observe(reader, source, &bytes, flags).await;
                    if legacy || flags & !1 != 0 { assert!(reply.is_empty()); continue; }
                    let observation: StatusObservation = bincode::deserialize(&reply).unwrap();
                    assert_eq!(
                        (
                            observation.version,
                            observation.lock_id,
                            observation.parent_lock,
                            observation.shard_id
                        ),
                        (1, row.t_id, parent_lock, shard)
                    );
                }
                let wrong_shard = payload(reader, row.t_id, parent_lock, shard + 1, legacy);
                assert!(observe(reader, source, &wrong_shard, 1).await.is_empty());
            }
        }
    }
    let checkpoint =
        humoco_node::network::framing::SigningCheckpoint::signed(&source.identity, 0, 1, [17; 32]);
    let mut heartbeat = humoco_node::network::framing::HeartbeatWirePayload {
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
    heartbeat.sign_origin(&reader.identity, heartbeat.timestamp_ms, humoco_sim_core::types::NetworkId::Mainnet);
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
        let reply = observe(reader, source, &payload(reader, row.t_id, parent_lock, shard, legacy), 1).await;
        if legacy { assert!(reply.is_empty()); continue; }
        assert_eq!(
            bincode::deserialize::<StatusObservation>(&reply)
                .unwrap()
                .lock_id,
            row.t_id
        );
    }
    assert!(source.db.get_hmc_lock(tag).unwrap().is_none());
    assert!(source
        .db
        .own_signing_choice(source.identity.node_pubkey(), tag)
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
    let root = make_hmc_entry([41; 32], "voucher-1", now);
    let root_tag = bs58::encode(root.t_id).into_string();
    source.db.put_hmc_lock(&root_tag, &root).unwrap();
    let first = make_hmc_entry([7; 32], "voucher-1", now);
    let other = make_hmc_entry([9; 32], "voucher-1", now);
    let tag = "spend-parent";
    let parent_lock = *blake3::hash(tag.as_bytes()).as_bytes();
    let shard = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    let att = humoco_node::api::routes::create_attestation_for_network(
        &source.identity,
        first.t_id,
        parent_lock,
        shard,
        1,
        now,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let exact = bincode::serialize(&att).unwrap();
    source
        .db
        .commit_original_approval(
            tag,
            &first,
            source.identity.node_pubkey(),
            &exact,
            1,
            now + 600_000,
        )
        .unwrap();
    // Prepare the lawful merged canonical state, independently of the immutable own choice.
    source.db.put_hmc_lock(tag, &other).unwrap();
    source
        .engine
        .hmc_ram
        .write()
        .await
        .insert_lock_for_test(tag.to_string(), other.clone());
    source
        .engine
        .stats
        .signing_failed
        .store(true, Ordering::Release);
    for legacy in [true, false] {
        let reply = observe(reader, source, &payload(reader, other.t_id, parent_lock, shard, legacy), 1).await;
        if legacy { assert!(reply.is_empty()); continue; }
        let observation: StatusObservation = bincode::deserialize(&reply).unwrap();
        assert_eq!(observation.lock_id, other.t_id);
        assert!(
            observe(reader, source, &payload(reader, first.t_id, parent_lock, shard, legacy), 1)
                .await
                .is_empty()
        );
    }
    let pow = Arc::new(PowEngine::new(8));
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
                    tag
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
    assert_eq!(json["child"], hex::encode(first.t_id));
    let sig: [u8; 64] = hex::decode(&att.signature).unwrap().try_into().unwrap();
    let digest =
        humoco_proto::live::original_approval_digest(0, shard, 1, &parent_lock, &first.t_id)
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
            tag,
        )
        .unwrap()
        .unwrap();
    assert_eq!(retained.approvals[1], Some(exact));
    assert_eq!(retained.child, first.t_id);
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
        layer2_signature: [5; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    let root = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "diagnostic-voucher".into(),
        t_id: [41; 32],
        sender_ephemeral_pub: [4; 32],
        layer2_signature: [5; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    let root_tag = bs58::encode(root.t_id).into_string();
    source.db.put_hmc_lock(&root_tag, &root).unwrap();
    source.db.put_hmc_lock(tag, &entry).unwrap();
    source
        .engine
        .recover_from_disk(humoco_sim_core::types::SimTime(now))
        .await
        .unwrap();
    let mut anchor = [0; 32];
    anchor[..2].copy_from_slice(&shard.to_be_bytes());
    source
        .engine
        .record_hmc_voucher_genesis_parent("diagnostic-voucher", anchor)
        .await;
    source.readiness.mark_shard_ready(shard);

    source
        .engine
        .stats
        .signing_failed
        .store(true, Ordering::Release);
    let exact = payload(reader, entry.t_id, parent, shard, false);
    let reply = observe(reader, source, &exact, 1).await;
    assert_eq!(
        bincode::deserialize::<StatusObservation>(&reply)
            .unwrap()
            .lock_id,
        entry.t_id
    );
    let tag_only = payload(reader, [0u8;32], parent, shard, false);
    let conn = reader
        .network
        .connect_peer(source.network.local_addr().unwrap())
        .await
        .unwrap();
    let (header, _) = reader
        .network
        .send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 1, tag_only.len() as u32),
            &tag_only,
        )
        .await
        .unwrap();
    assert_eq!(header.flags, humoco_sim_core::wire::FLAG_NOT_READY);

    source
        .engine
        .stats
        .signing_failed
        .store(false, Ordering::Release);
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
    let root = make_hmc_entry([41; 32], "voucher-1", now);
    let root_tag = bs58::encode(root.t_id).into_string();
    db.put_hmc_lock(&root_tag, &root).unwrap();
    let row = make_hmc_entry([7; 32], "voucher-1", now);
    let tag = "spend-parent";
    let parent_lock = *blake3::hash(tag.as_bytes()).as_bytes();
    let shard = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    engine
        .hmc_ram
        .write()
        .await
        .insert_voucher_root_for_test("voucher-1".into(), now + 600_000);
    // Reservation-first production ingress queues the write; withholding the
    // worker is the controlled persistence barrier, not a sleep-based race.
    let (_verdict, is_new) = engine
        .ingress_hmc_lock_with_origin(
            tag.to_string(),
            row.clone(),
            IngressOrigin::ClientApi,
            Some(now),
        )
        .await;
    assert!(is_new);
    readiness.mark_shard_ready(shard);
    let conn = sender
        .connect_peer(receiver.local_addr().unwrap())
        .await
        .unwrap();
    let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        client.node_pubkey(), 0, 0, now, 0, 0, 0, true, &row.t_id,
    );
    let bytes = bincode::serialize(&StatusQueryPayload {
        lock_id: row.t_id, parent_lock, shard_id: shard,
        sender_pubkey: *client.node_pubkey(), declared_write_ema_micro_bj: 0,
        current_read_ema_credits: 0, timestamp_ms: now,
        sender_signature: client.signing_key().sign(&digest).to_bytes(),
    }).unwrap();
    let header = WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 1, bytes.len() as u32);
    assert!(db.get_hmc_lock(tag).unwrap().is_none());
    let (_, pending) = sender.send_request(&conn, &header, &bytes).await.unwrap();
    assert!(AttestationDto::from_wire_bytes(&pending).is_none());
    assert_eq!(
        bincode::deserialize::<StatusObservation>(&pending)
            .unwrap()
            .lock_id,
        row.t_id
    );
    let worker = DualTierEngine::spawn_flush_worker(
        rx,
        db.clone(),
        Arc::new(PersistenceStats::default()),
        cancel.clone(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while db.get_hmc_lock(tag).unwrap().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (_, committed) = sender.send_request(&conn, &header, &bytes).await.unwrap();
    assert_eq!(pending, committed);
    assert!(db
        .own_signing_choice(server.node_pubkey(), tag)
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
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use humoco_node::{
        api::hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2LockRequest, L2ResponseEnvelope,
            L2StatusQuery, L2Verdict,
        },
        network::{BoxFuture, PeerManager, QuicTransport, RequestHandler},
    };
    use sha2::{Digest as _, Sha256};
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
    let owner = SigningKey::from_bytes(&[38; 32]);
    let sender_pub = owner.verifying_key().to_bytes();
    let root_tx_hash = *blake3::hash(b"remote-only-canonical-root").as_bytes();
    let del_str = (now + 600_000).to_string();
    let mut id_hasher = Sha256::new();
    id_hasher.update(root_tx_hash);
    id_hasher.update(sender_pub);
    id_hasher.update(del_str.as_bytes());
    let voucher = hex::encode(id_hasher.finalize());
    let mut root_proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher.clone(),
        transaction_id: root_tx_hash,
        state_hash: root_tx_hash,
        sender_pubkey: sender_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    root_proof.signature = owner.sign(&root_proof.digest().unwrap()).to_bytes();
    let mut root_req = L2LockRequest {
        causal_output: Some(root_proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher.clone(),
        ds_tag: None,
        transaction_hash: root_tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    root_req.layer2_signature = owner.sign(&calculate_l2_payload_hash(&root_req)).to_bytes();
    let root = L2LockEntry::from(&root_req);
    let root_tag = bs58::encode(root.t_id).into_string();
    let canonical_shard = humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
    );
    assert_ne!(
        canonical_shard,
        humoco_sim_core::types::voucher_shard_id(&voucher),
        "canonical genesis shard must differ from voucher_shard_id guess"
    );
    source.db.put_hmc_lock(&root_tag, &root).unwrap();

    let tag = "remote-only-parent";
    let mut spend_req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher.clone(),
        ds_tag: Some(tag.into()),
        transaction_hash: [42; 32],
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: None,
        privacy_guard: None,
    };
    spend_req.layer2_signature = owner
        .sign(&calculate_l2_payload_hash(&spend_req))
        .to_bytes();
    let entry = L2LockEntry::from(&spend_req);
    source.db.put_hmc_lock(tag, &entry).unwrap();
    source
        .engine
        .recover_from_disk(humoco_sim_core::types::SimTime(now))
        .await
        .unwrap();
    source.readiness.mark_shard_ready(canonical_shard);
    let pow = Arc::new(PowEngine::new(8));
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
    routing.set_simulation_mode(true);
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
        layer2_voucher_id: voucher.clone(),
        challenge_ds_tag: tag.into(),
        locator_prefixes: vec![],
        read_quorum: 1,
        root_context: Some(root.clone()),
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
    assert!(matches!(envelope.verdict, L2Verdict::Verified { lock_entry } if lock_entry == entry));
    // A genuine old original is still not the requested complete voucher entry.
    let att = humoco_node::api::routes::create_attestation_for_network(
        &source.identity,
        entry.t_id,
        *blake3::hash(tag.as_bytes()).as_bytes(),
        canonical_shard,
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

#[tokio::test]
async fn cold_and_root_only_gateways_route_canonical_shard_to_single_custodian() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use humoco_node::{
        api::hmc::{
            calculate_l2_payload_hash, L2AuthPayload, L2LockRequest, L2ResponseEnvelope,
            L2StatusQuery, L2Verdict,
        },
        daemon::ShardReadinessManager,
        identity::NodeIdentity,
        network::{
            BoxFuture, DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport,
            RequestHandler,
        },
        storage::{DualTierEngine, IngressOrigin, RedbStorage},
    };
    use sha2::{Digest as _, Sha256};
    use sha3::Sha3_256;
    use std::sync::atomic::AtomicUsize;
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;

    struct CountingCustodianHandler {
        inner: Arc<NodeRequestHandler>,
        status_queries: Arc<AtomicUsize>,
    }
    impl RequestHandler for CountingCustodianHandler {
        fn handle(
            &self,
            header: WireHeader,
            payload: Vec<u8>,
        ) -> BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::error::NodeError>> {
            if header.msg_type == MsgType::StatusQuery as u16 {
                self.status_queries.fetch_add(1, Ordering::Relaxed);
            }
            self.inner.handle(header, payload)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let gw_identity = NodeIdentity::generate();
    let gw_db = Arc::new(RedbStorage::open(&dir.path().join("gateway.redb")).unwrap());
    let (gw_engine, gw_worker) = DualTierEngine::new_with_token(gw_db.clone(), cancel.clone());
    let gw_pm = Arc::new(PeerManager::new(vec![]));
    gw_pm.set_simulation_mode(true);
    let gw_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gw_identity,
        gw_pm.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    gw_transport.spawn_accept_loop();

    let now = gw_pm.net_time_ms();
    let owner = SigningKey::from_bytes(&[38; 32]);
    let sender_pub = owner.verifying_key().to_bytes();
    let root_tx_hash = *blake3::hash(b"cold-gateway-audit").as_bytes();
    let del_str = (now + 600_000).to_string();
    let mut id_hash = Sha256::new();
    id_hash.update(root_tx_hash);
    id_hash.update(sender_pub);
    id_hash.update(del_str.as_bytes());
    let voucher_id = hex::encode(id_hash.finalize());

    let mut root_proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: voucher_id.clone(),
        transaction_id: root_tx_hash,
        state_hash: root_tx_hash,
        sender_pubkey: sender_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    root_proof.signature = owner.sign(&root_proof.digest().unwrap()).to_bytes();
    let mut root_req = L2LockRequest {
        causal_output: Some(root_proof),
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: None,
        transaction_hash: root_tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    root_req.layer2_signature = owner.sign(&calculate_l2_payload_hash(&root_req)).to_bytes();
    let root_entry = L2LockEntry::from(&root_req);
    let root_tag = bs58::encode(root_req.transaction_hash).into_string();
    let canonical_shard = humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
    );
    let guessed_shard = humoco_sim_core::types::voucher_shard_id(&voucher_id);
    assert_ne!(canonical_shard, guessed_shard);

    let mut ds_hasher = Sha3_256::new();
    ds_hasher.update(32u32.to_le_bytes());
    ds_hasher.update(root_req.transaction_hash);
    ds_hasher.update(32u32.to_le_bytes());
    ds_hasher.update(sender_pub);
    let spend_tag = bs58::encode(ds_hasher.finalize()).into_string();
    let mut spend_req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.clone(),
        ds_tag: Some(spend_tag.clone()),
        transaction_hash: [0xAC; 32],
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: None,
        privacy_guard: None,
    };
    spend_req.layer2_signature = owner
        .sign(&calculate_l2_payload_hash(&spend_req))
        .to_bytes();
    let spend_entry = L2LockEntry::from(&spend_req);

    // Spawn 3 real QUIC custodians serving production NodeRequestHandler.
    let mut custodians = Vec::new();
    let mut counters = Vec::new();
    for idx in 0..3usize {
        let cust_id = NodeIdentity::generate();
        let cust_db =
            Arc::new(RedbStorage::open(&dir.path().join(format!("cust_{idx}.redb"))).unwrap());
        let (cust_engine, cust_worker) =
            DualTierEngine::new_with_token(cust_db.clone(), cancel.clone());
        let cust_pm = Arc::new(PeerManager::new(vec![]));
        cust_pm.set_simulation_mode(true);
        let readiness = Arc::new(ShardReadinessManager::new());
        readiness.mark_shard_ready(canonical_shard);

        let (v_root, _) = cust_engine
            .ingress_hmc_lock_durable(
                root_tag.clone(),
                root_entry.clone(),
                IngressOrigin::ClientApi,
                Some(now),
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(v_root, L2Verdict::Verified { .. }));
        let (v_spend, _) = cust_engine
            .ingress_hmc_lock_durable(
                spend_tag.clone(),
                spend_entry.clone(),
                IngressOrigin::ClientApi,
                Some(now),
                None,
                None,
                None,
            )
            .await;
        assert!(matches!(v_spend, L2Verdict::Verified { .. }));

        let counter = Arc::new(AtomicUsize::new(0));
        let prod_handler = Arc::new(
            NodeRequestHandler::with_peer_manager(
                cust_engine.clone(),
                cust_db,
                cust_id.clone(),
                cust_pm.clone(),
            )
            .with_readiness_manager(readiness)
            .with_sync_ready(Arc::new(std::sync::atomic::AtomicBool::new(true))),
        );
        let cust_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &cust_id,
            cust_pm.clone(),
            Arc::new(CountingCustodianHandler {
                inner: prod_handler,
                status_queries: counter.clone(),
            }),
            cancel.clone(),
        )
        .unwrap();
        cust_transport.set_sync_ready(true);
        cust_transport.spawn_accept_loop();

        let cust_addr = cust_transport.local_addr().unwrap();
        cust_pm
            .register_f2f_friend(
                *gw_identity.node_pubkey(),
                Some(gw_transport.local_addr().unwrap()),
            )
            .await;
        gw_pm
            .register_f2f_friend(*cust_id.node_pubkey(), Some(cust_addr))
            .await;
        gw_pm
            .learn_node_from_gossip_with_hrw(
                *cust_id.node_pubkey(),
                *cust_id.hrw_routing_id(),
                cust_addr,
                0,
                None,
            )
            .await;
        gw_pm
            .set_first_seen_for_test(
                cust_id.node_pubkey(),
                std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
            )
            .await;

        counters.push(counter);
        custodians.push((cust_transport, cust_worker));
    }

    let pow = Arc::new(PowEngine::new(0));
    let tiers = Arc::new(TierController::new(gw_db.clone(), pow.clone()));
    let mut state = AppState::new(
        gw_engine.clone(),
        gw_db.clone(),
        gw_identity.clone(),
        tiers,
        pow,
    );
    state.peer_manager = Some(gw_pm.clone());
    state.transport = Some(gw_transport.clone());
    let app = build_router(state);

    let post_status = |q: &L2StatusQuery| {
        let app = app.clone();
        let body = serde_json::to_vec(q).unwrap();
        async move {
            let res = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/status")
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = res.status();
            let env: L2ResponseEnvelope =
                serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            (status, env)
        }
    };

    // 1. Cold gateway lacking root WITHOUT root_context -> explicit routing unavailability (503), never false UnknownVoucher.
    let unroutable_query = L2StatusQuery {
        auth: root_req.auth.clone(),
        layer2_voucher_id: voucher_id.clone(),
        challenge_ds_tag: spend_tag.clone(),
        locator_prefixes: vec![],
        read_quorum: 1,
        root_context: None,
    };
    let (st_unroutable, env_unroutable) = post_status(&unroutable_query).await;
    assert_eq!(st_unroutable, StatusCode::SERVICE_UNAVAILABLE);
    assert!(matches!(env_unroutable.verdict, L2Verdict::Rejected { .. }));
    assert_eq!(
        counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<usize>(),
        0
    );

    // 2. Forged root_context signature -> 400 BAD_REQUEST + Rejected.
    let mut forged_root = root_entry.clone();
    forged_root.layer2_signature[0] ^= 0xFF;
    let forged_query = L2StatusQuery {
        root_context: Some(forged_root),
        ..unroutable_query.clone()
    };
    let (st_forged, env_forged) = post_status(&forged_query).await;
    assert_eq!(st_forged, StatusCode::BAD_REQUEST);
    assert!(matches!(env_forged.verdict, L2Verdict::Rejected { .. }));
    assert_eq!(
        counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<usize>(),
        0
    );

    // 3. Cold gateway WITH authenticated root_context (S01-04 + INV-0310):
    // Routes to canonical shard, queries exactly 1 custodian, retrieves exact durable spend, zero gateway writes.
    let cold_query = L2StatusQuery {
        root_context: Some(root_entry.clone()),
        ..unroutable_query.clone()
    };
    let (st_cold, env_cold) = post_status(&cold_query).await;
    assert_eq!(st_cold, StatusCode::OK);
    assert!(
        matches!(env_cold.verdict, L2Verdict::Verified { ref lock_entry } if lock_entry == &spend_entry),
        "cold gateway must retrieve exact durable spend, got {:?}",
        env_cold.verdict
    );
    assert_eq!(
        counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<usize>(),
        1,
        "INV-0310: ordinary lookup must query exactly one selected custodian"
    );
    assert!(
        gw_db.voucher_root(&voucher_id).unwrap().is_none(),
        "status read must not persist root to disk"
    );
    assert!(
        gw_engine
            .get_hmc_voucher_genesis_shard(&voucher_id)
            .await
            .is_none(),
        "status read must not mutate gateway RAM root routing"
    );

    // 4. Warm gateway storing ONLY the root (S01-05):
    // Local HmcRamIndex produces MissingLocks { sync_point: "genesis" }; gateway lacks authoritative
    // shard state, routes MissingLocks to 1 custodian on canonical shard, and retrieves exact spend.
    let (v_gw_root, _) = gw_engine
        .ingress_hmc_lock_durable(
            root_tag,
            root_entry,
            IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(v_gw_root, L2Verdict::Verified { .. }));
    assert!(matches!(
        gw_engine
            .hmc_ram
            .read()
            .await
            .query_status(&voucher_id, &spend_tag, &[]),
        L2Verdict::MissingLocks { .. }
    ));

    let (st_warm, env_warm) = post_status(&unroutable_query).await;
    assert_eq!(st_warm, StatusCode::OK);
    assert!(
        matches!(env_warm.verdict, L2Verdict::Verified { ref lock_entry } if lock_entry == &spend_entry),
        "root-only gateway must route MissingLocks to custodian and retrieve spend, got {:?}",
        env_warm.verdict
    );
    assert_eq!(
        counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<usize>(),
        2,
        "INV-0310: second ordinary lookup must query exactly one selected custodian"
    );

    cancel.cancel();
    gw_transport.close();
    gw_transport.drain_tasks().await;
    let _ = gw_worker.await;
    for (transport, worker) in custodians {
        transport.close();
        transport.drain_tasks().await;
        let _ = worker.await;
    }
}
