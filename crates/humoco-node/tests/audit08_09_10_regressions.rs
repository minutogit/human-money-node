//! Integration and regression tests for Audit 08, 09, and 10 (Stufe 5 Sanierung).
//!
//! Covers:
//! - A08-01: Origin-authenticated heartbeat gossip & routing poisoning protection
//! - A09-01: True Ed25519 first-party self-revocation proof generation
//! - A09-02: Control socket revocation and locked-database error propagation
//! - A10-01: Atomic slashing persistence & ban survival across worker closures/restarts
//! - A10-02: Automatic ShardEquivocation detection for conflicting original attestations

use ed25519_dalek::Signer;
use humoco_node::{
    config::NodeConfig,
    control::ControlServer,
    network::{
        DefaultRequestHandler, HeartbeatWirePayload, NodeRequestHandler, PeerManager, QuicTransport,
    },
    storage::{DualTierEngine, RedbStorage},
    NodeIdentity,
};
use humoco_sim_core::wire::{MsgType, WireHeader};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

async fn relay_probe(signed: bool) {
    let cancel = CancellationToken::new();
    let attacker = NodeIdentity::generate();
    let recipient = NodeIdentity::generate();
    let victim = NodeIdentity::generate();
    let ma = Arc::new(PeerManager::new(vec![]));
    let mb = Arc::new(PeerManager::new(vec![]));
    let a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &attacker,
        ma.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &recipient,
        mb.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let aa = a.local_addr().unwrap();
    let ba = b.local_addr().unwrap();
    ma.register_f2f_friend(*recipient.node_pubkey(), Some(ba))
        .await;
    mb.register_f2f_friend(*attacker.node_pubkey(), Some(aa))
        .await;
    let real = "127.0.0.1:31337".parse().unwrap();
    let forged = "127.0.0.1:31338".parse().unwrap();
    mb.learn_node_from_gossip(*victim.node_pubkey(), real, 0, None)
        .await;
    a.spawn_accept_loop();
    b.spawn_accept_loop();
    let conn = a.connect_peer(ba).await.unwrap();
    let time = mb.net_time_ms();
    let signature = if signed {
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            victim.node_pubkey(),
            0,
            0,
            time,
            0,
            0,
            0,
            false,
            &[0; 32],
        );
        victim.signing_key().sign(&digest).to_bytes()
    } else {
        [0; 64]
    };
    let hb = HeartbeatWirePayload {
        node_id: *victim.node_pubkey(),
        addr: forged,
        timestamp_ms: time,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature,
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0; 32],
        ticket_epoch_t0: 0,
        ttl: 1,
        signing_checkpoint: None,
        gateway_advertisement: None,
    };
    let payload = bincode::serialize(&hb).unwrap();
    let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload.len() as u32);
    hdr.reserved = 1;
    a.send_unidirectional(&conn, &hdr, &payload).await.unwrap();
    let changed = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if mb.get_known_node_addr(victim.node_pubkey()).await == Some(forged) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();
    let actual = mb.get_known_node_addr(victim.node_pubkey()).await;
    eprintln!("signed={signed} overwritten={changed} actual={actual:?}");
    cancel.cancel();
    a.close();
    b.close();
    a.drain_tasks().await;
    b.drain_tasks().await;
    assert!(
        !changed,
        "relay must not replace victim address without origin-authenticated address binding"
    );
}

#[tokio::test]
async fn a08_unsigned_relay_cannot_overwrite_known_identity() {
    relay_probe(false).await;
}

#[tokio::test]
async fn a08_signed_relay_cannot_tamper_origin_address() {
    relay_probe(true).await;
}

#[tokio::test]
async fn a09_cli_revoke_must_produce_peer_acceptable_self_evidence() {
    use redb::ReadableTable;
    let temp = tempfile::tempdir().unwrap();
    let identity = NodeIdentity::generate();
    let mut cfg = NodeConfig::default();
    cfg.identity.key_path = temp.path().join("node.key");
    cfg.storage.data_dir = temp.path().join("data");
    std::fs::create_dir_all(&cfg.storage.data_dir).unwrap();
    identity.save_to_file(&cfg.identity.key_path).unwrap();
    let cfg_path = temp.path().join("humoco.toml");
    cfg.save_to_file(&cfg_path).unwrap();
    let db_path = cfg.storage.data_dir.join("humoco.redb");
    drop(RedbStorage::open(&db_path).unwrap());

    humoco_node::cli::execute_revoke(Some(cfg_path), Some("DELETE".into()))
        .await
        .unwrap();

    let db = RedbStorage::open(&db_path).unwrap();
    let local_ban = db.is_node_banned(identity.node_pubkey()).unwrap();
    let raw = {
        let tx = db.raw_database_for_test().begin_read().unwrap();
        let table = tx
            .open_table(humoco_node::storage::db::TABLE_SLASHING_EVIDENCE)
            .unwrap();
        let (_, value) = table.iter().unwrap().next().unwrap().unwrap();
        value.value().to_vec()
    };
    let proof: humoco_sim_core::fraud::FraudProofPayload = bincode::deserialize(&raw).unwrap();
    let strict = humoco_node::network::transport::verify_equivocation_first_party(
        identity.verifying_key(),
        &proof,
    );
    let matches_key = proof.perpetrator_node_id == *identity.node_pubkey();

    let observer = NodeIdentity::generate();
    let mb = Arc::new(PeerManager::new(vec![]));
    let ma = Arc::new(PeerManager::new(vec![]));
    let cancel = CancellationToken::new();
    let observer_db = Arc::new(RedbStorage::open(&temp.path().join("observer.redb")).unwrap());
    let (engine, worker) = DualTierEngine::new(observer_db.clone());
    let handler = Arc::new(NodeRequestHandler::with_peer_manager(
        engine.clone(),
        observer_db,
        observer.clone(),
        mb.clone(),
    ));
    let a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &identity,
        ma.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &observer,
        mb.clone(),
        handler,
        cancel.clone(),
    )
    .unwrap();
    ma.register_f2f_friend(*observer.node_pubkey(), Some(b.local_addr().unwrap()))
        .await;
    mb.register_f2f_friend(*identity.node_pubkey(), Some(a.local_addr().unwrap()))
        .await;
    a.spawn_accept_loop();
    b.spawn_accept_loop();
    let conn = a.connect_peer(b.local_addr().unwrap()).await.unwrap();
    a.send_request(
        &conn,
        &WireHeader::new(MsgType::EquivocationProof as u16, 1, 0, 0, raw.len() as u32),
        &raw,
    )
    .await
    .unwrap();
    let remote_ban = engine.is_node_banned(identity.node_pubkey()).await;

    cancel.cancel();
    a.close();
    b.close();
    a.drain_tasks().await;
    b.drain_tasks().await;
    worker.abort();
    let _ = worker.await;

    assert!(local_ban);
    assert!(
        strict && matches_key && remote_ban,
        "CLI success must not claim network revocation from rejected simulator evidence"
    );
}

#[tokio::test]
async fn a09_revoke_with_active_daemon_via_control_socket() {
    let temp = tempfile::tempdir().unwrap();
    let identity = NodeIdentity::generate();
    let mut cfg = NodeConfig::default();
    cfg.identity.key_path = temp.path().join("node.key");
    cfg.storage.data_dir = temp.path().join("data");
    cfg.network.control_socket = Some(temp.path().join("control.sock"));
    std::fs::create_dir_all(&cfg.storage.data_dir).unwrap();
    identity.save_to_file(&cfg.identity.key_path).unwrap();
    let cfg_path = temp.path().join("humoco.toml");
    cfg.save_to_file(&cfg_path).unwrap();

    let db_path = cfg.storage.data_dir.join("humoco.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, worker) = DualTierEngine::new(storage.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(pm.clone()).await;

    let cancel = CancellationToken::new();
    let server = ControlServer::new(
        cfg.control_socket_path(),
        storage.clone(),
        engine.clone(),
        pm.clone(),
        identity.clone(),
        cfg.storage.data_dir.clone(),
        cancel.clone(),
    );
    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Wait for socket to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Execute revoke while daemon control socket is active
    humoco_node::cli::execute_revoke(Some(cfg_path), Some("DELETE".into()))
        .await
        .unwrap();

    // Verify local ban was committed in daemon's database
    assert!(storage.is_node_banned(identity.node_pubkey()).unwrap());
    assert!(engine.is_node_banned(identity.node_pubkey()).await);

    cancel.cancel();
    server_handle.abort();
    let _ = server_handle.await;
    worker.abort();
    let _ = worker.await;
}

#[tokio::test]
async fn a09_revoke_must_not_report_success_when_database_is_locked() {
    let temp = tempfile::tempdir().unwrap();
    let identity = NodeIdentity::generate();
    let mut cfg = NodeConfig::default();
    cfg.identity.key_path = temp.path().join("node.key");
    cfg.storage.data_dir = temp.path().join("data");
    std::fs::create_dir_all(&cfg.storage.data_dir).unwrap();
    identity.save_to_file(&cfg.identity.key_path).unwrap();
    let path = temp.path().join("node.toml");
    cfg.save_to_file(&path).unwrap();

    // Lock the database by opening it without running a control server
    let db = RedbStorage::open(&cfg.storage.data_dir.join("humoco.redb")).unwrap();
    let result = humoco_node::cli::execute_revoke(Some(path), Some("DELETE".into())).await;
    let banned = db.is_node_banned(identity.node_pubkey()).unwrap();
    eprintln!(
        "cli_ok={} local_ban_with_active_database={banned}",
        result.is_ok()
    );
    assert!(
        result.is_err() || banned,
        "successful revoke must persist its local sanction even while the daemon owns the database"
    );
}

#[cfg(unix)]
#[test]
fn a09_new_key_permissions_are_0600() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fresh.key");
    let id = NodeIdentity::generate();
    id.save_to_file(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let reloaded = NodeIdentity::load_from_file(&path).unwrap();
    assert_eq!(reloaded.node_pubkey(), id.node_pubkey());
}

#[tokio::test]
async fn a10_verified_ban_must_survive_closed_persistence_worker() {
    let temp = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&temp.path().join("ban.redb")).unwrap());
    let (engine, worker) = DualTierEngine::new(db.clone());
    worker.abort();
    let _ = worker.await;

    let cancel = CancellationToken::new();
    let sender = NodeIdentity::generate();
    let receiver = NodeIdentity::generate();
    let victim = NodeIdentity::generate();
    let ma = Arc::new(PeerManager::new(vec![]));
    let mb = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(mb.clone()).await;

    let a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &sender,
        ma.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let handler = Arc::new(NodeRequestHandler::with_peer_manager(
        engine.clone(),
        db.clone(),
        receiver.clone(),
        mb.clone(),
    ));
    let b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &receiver,
        mb.clone(),
        handler,
        cancel.clone(),
    )
    .unwrap();

    ma.register_f2f_friend(*receiver.node_pubkey(), Some(b.local_addr().unwrap()))
        .await;
    mb.register_f2f_friend(*sender.node_pubkey(), Some(a.local_addr().unwrap()))
        .await;
    a.spawn_accept_loop();
    b.spawn_accept_loop();
    let conn = a.connect_peer(b.local_addr().unwrap()).await.unwrap();

    let proof = humoco_node::identity::build_self_revocation_fraud_proof(
        &victim,
        humoco_sim_core::types::NetworkId::Mainnet,
        1000,
    );
    assert!(proof.verify());
    assert!(
        humoco_node::network::transport::verify_equivocation_first_party(
            victim.verifying_key(),
            &proof
        )
    );

    let payload = bincode::serialize(&proof).unwrap();
    let reply = a
        .send_request(
            &conn,
            &WireHeader::new(
                MsgType::EquivocationProof as u16,
                1,
                0,
                0,
                payload.len() as u32,
            ),
            &payload,
        )
        .await
        .unwrap();
    assert_eq!(reply.0.msg_type, MsgType::EquivocationAck as u16);

    let ram_ban = engine.is_node_banned(victim.node_pubkey()).await;
    let disk_ban = db.is_node_banned(victim.node_pubkey()).unwrap();
    let evidence = db
        .get_evidence(blake3::hash(&payload).as_bytes())
        .unwrap()
        .is_some();
    let (reloaded, new_worker) = DualTierEngine::new(db.clone());
    let restart_ban = reloaded.is_node_banned(victim.node_pubkey()).await;

    new_worker.abort();
    let _ = new_worker.await;
    cancel.cancel();
    a.close();
    b.close();
    a.drain_tasks().await;
    b.drain_tasks().await;

    assert!(ram_ban);
    assert!(evidence);
    assert!(
        disk_ban && restart_ban,
        "verified permanent ban must persist or evidence must be replayed before restart admission"
    );
}

#[test]
fn a10_fourteen_colluders_can_create_conflicting_quorum_proofs() {
    use humoco_proto::{verify_quorum_proof, AttestationVote, QuorumProof};
    let keys: Vec<_> = (1u8..=20)
        .map(|i| ed25519_dalek::SigningKey::from_bytes(&[i; 32]))
        .collect();
    let members: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    for digest in [[1u8; 32], [2u8; 32]] {
        let proof = QuorumProof {
            shard_id: 1,
            votes: keys
                .iter()
                .take(14)
                .map(|k| AttestationVote {
                    signer_pubkey: k.verifying_key().to_bytes(),
                    signature: k.sign(&digest).to_bytes(),
                })
                .collect(),
        };
        assert!(verify_quorum_proof(&proof, &digest, &members, 14).is_ok());
    }
    assert_eq!(
        members[..14]
            .iter()
            .filter(|key| members[6..20].contains(key))
            .count(),
        8
    );
}

#[tokio::test]
async fn a10_conflicting_original_attestations_trigger_automatic_shard_equivocation_proof() {
    use humoco_sim_core::crypto::{
        compute_attestation_payload_digest, compute_sig_digest, HUMOCO_V1_APPROVE_PROV_MAINNET,
    };
    use humoco_sim_core::types::{Attestation, NetworkId, SimTime};

    let temp = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&temp.path().join("cartel.redb")).unwrap());
    let (engine, worker) = DualTierEngine::new(db.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(pm.clone()).await;

    let mal_signer = NodeIdentity::generate();
    let parent_lock = [0x77u8; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    let node_id = mal_signer.node_id_u16();

    let sign_att = |lock_id: [u8; 32]| -> Attestation {
        let payload = compute_attestation_payload_digest(&parent_lock, &lock_id);
        let digest = compute_sig_digest(
            HUMOCO_V1_APPROVE_PROV_MAINNET,
            0,
            0,
            0,
            shard_id,
            0,
            &payload,
        );
        Attestation {
            lock_id,
            parent_lock,
            node_id,
            timestamp: SimTime(1000),
            signature: mal_signer.signing_key().sign(&digest).to_bytes(),
            shard_id,
        }
    };

    let att1 = sign_att([1u8; 32]);
    let att1_retry = sign_att([1u8; 32]);
    let att2_conflict = sign_att([2u8; 32]);

    // Vote 1: legitimate, no fraud
    let res1 = pm.observe_verified_original_attestation(
        *mal_signer.node_pubkey(),
        att1,
        NetworkId::Mainnet,
    );
    assert!(res1.is_none());
    assert!(!db.is_node_banned(mal_signer.node_pubkey()).unwrap());

    // Identical retry: no fraud
    let res_retry = pm.observe_verified_original_attestation(
        *mal_signer.node_pubkey(),
        att1_retry,
        NetworkId::Mainnet,
    );
    assert!(res_retry.is_none());
    assert!(!db.is_node_banned(mal_signer.node_pubkey()).unwrap());

    // Diverging vote for same parent_lock: automatically detected, committed and banned!
    let res2 = pm.observe_verified_original_attestation(
        *mal_signer.node_pubkey(),
        att2_conflict,
        NetworkId::Mainnet,
    );
    assert!(res2.is_some());
    let proof = res2.unwrap();
    assert_eq!(proof.perpetrator_node_id, *mal_signer.node_pubkey());

    // Check durable ban in redb and RAM
    assert!(db.is_node_banned(mal_signer.node_pubkey()).unwrap());
    let mut ram_banned = false;
    for _ in 0..20 {
        if engine.is_node_banned(mal_signer.node_pubkey()).await {
            ram_banned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        ram_banned,
        "engine RAM ban must be populated asynchronously"
    );

    worker.abort();
    let _ = worker.await;
}

#[tokio::test]
async fn a08_legacy_unsigned_tuple_relay_must_never_learn_or_authorize_third_party() {
    use std::net::SocketAddr;
    let cancel = CancellationToken::new();
    let attacker = NodeIdentity::generate();
    let recipient = NodeIdentity::generate();
    let unseen_victim = NodeIdentity::generate();
    let ma = Arc::new(PeerManager::new(vec![]));
    ma.set_simulation_mode(true);
    let mb = Arc::new(PeerManager::new(vec![]));
    mb.set_simulation_mode(true);

    let a = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &attacker,
        ma.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &recipient,
        mb.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .unwrap();
    let aa = a.local_addr().unwrap();
    let ba = b.local_addr().unwrap();

    ma.register_f2f_friend(*recipient.node_pubkey(), Some(ba)).await;
    mb.register_f2f_friend(*attacker.node_pubkey(), Some(aa)).await;

    a.spawn_accept_loop();
    b.spawn_accept_loop();

    let conn = a.connect_peer(ba).await.unwrap();

    let unseen_addr: SocketAddr = "127.0.0.1:31339".parse().unwrap();
    assert!(!mb.is_known_node(unseen_victim.node_pubkey()).await);

    // Attacker sends legacy unsigned tuple ([u8; 32], SocketAddr) with hops = 1 (reserved = 1)
    let legacy_payload = bincode::serialize(&(*unseen_victim.node_pubkey(), unseen_addr)).unwrap();
    let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, legacy_payload.len() as u32);
    hdr.reserved = 1; // hops = 1 (relayed)

    a.send_unidirectional(&conn, &hdr, &legacy_payload).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Assert: NO entry, NO address, NO liveness refresh, NO clock sample, and NO direct-RPC authorization
    assert!(
        !mb.is_known_node(unseen_victim.node_pubkey()).await,
        "Relayed legacy unsigned tuple must never insert node into known_network_nodes"
    );
    assert_eq!(
        mb.get_known_node_addr(unseen_victim.node_pubkey()).await,
        None,
        "Relayed legacy unsigned tuple must not create address mapping"
    );
    assert!(
        !mb.can_authorize_direct_rpc(&unseen_addr, Some(unseen_victim.node_pubkey())).await,
        "Relayed legacy unsigned tuple must not authorize direct RPC by pubkey"
    );
    assert!(
        !mb.can_authorize_direct_rpc(&unseen_addr, None).await,
        "Relayed legacy unsigned tuple must not authorize direct RPC by address"
    );
    assert!(
        mb.get_peer(&unseen_addr).await.is_none(),
        "Relayed legacy unsigned tuple must not create or refresh peer info"
    );
    assert_eq!(
        mb.clock().sample_count(),
        0,
        "Relayed legacy unsigned tuple must not contribute clock samples"
    );

    // Positive Control: Valid origin-signed relay is learned
    let legit_relayed = NodeIdentity::generate();
    let legit_addr: SocketAddr = "127.0.0.1:31340".parse().unwrap();
    let time = mb.net_time_ms();
    let mut legit_hb = HeartbeatWirePayload {
        node_id: *legit_relayed.node_pubkey(),
        addr: legit_addr,
        timestamp_ms: time,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: 0,
        hrw_routing_id: [0; 32],
        ticket_epoch_t0: 0,
        ttl: 2,
        signing_checkpoint: None,
        gateway_advertisement: None,
    };
    legit_hb.sign_origin(&legit_relayed, time);
    assert!(legit_hb.verify_origin_address_binding());

    let legit_payload = bincode::serialize(&legit_hb).unwrap();
    let mut legit_hdr = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, legit_payload.len() as u32);
    legit_hdr.reserved = 1; // hops = 1

    a.send_unidirectional(&conn, &legit_hdr, &legit_payload).await.unwrap();


    let learned = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if mb.is_known_node(legit_relayed.node_pubkey()).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or(false);

    assert!(learned, "Valid origin-signed relayed heartbeat must be accepted and learned");

    cancel.cancel();
    a.close();
    b.close();
    a.drain_tasks().await;
    b.drain_tasks().await;
}

