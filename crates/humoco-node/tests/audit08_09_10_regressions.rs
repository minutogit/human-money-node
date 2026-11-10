//! Integration and regression tests for Audit 08, 09, and 10 (Stufe 5 Sanierung).
//!
//! Covers:
//! - A08-01: Origin-authenticated heartbeat gossip & routing poisoning protection
//! - A09-01: True Ed25519 first-party self-revocation proof generation
//! - A09-02: Control socket revocation and locked-database error propagation
//! - A10-01: Atomic slashing persistence & ban survival across worker closures/restarts
//! - A10-02: Automatic ShardEquivocation detection for conflicting original attestations

use ed25519_dalek::Signer;
use redb::ReadableTable;
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
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
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
    mb.learn_node_from_gossip_with_hrw(
        *victim.node_pubkey(),
        *victim.hrw_routing_id(),
        real,
        0,
        None,
    )
    .await;
    a.spawn_accept_loop();
    b.spawn_accept_loop();
    let conn = a.connect_peer(ba).await.unwrap();
    let time = mb.net_time_ms();
    let signature = if signed {
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::Mainnet,
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
    let strict = humoco_node::network::transport::verify_equivocation_first_party_network(
        humoco_sim_core::types::NetworkId::Mainnet,
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
        humoco_node::network::transport::verify_equivocation_first_party_network(
            humoco_sim_core::types::NetworkId::Mainnet,
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
    let res1 = pm
        .observe_verified_original_attestation(
            *mal_signer.node_pubkey(),
            att1,
            NetworkId::Mainnet,
        )
        .await
        .unwrap();
    assert!(res1.is_none());
    assert!(!db.is_node_banned(mal_signer.node_pubkey()).unwrap());

    // Identical retry: no fraud
    let res_retry = pm
        .observe_verified_original_attestation(
            *mal_signer.node_pubkey(),
            att1_retry,
            NetworkId::Mainnet,
        )
        .await
        .unwrap();
    assert!(res_retry.is_none());
    assert!(!db.is_node_banned(mal_signer.node_pubkey()).unwrap());

    // Diverging vote for same parent_lock: automatically detected, committed and banned!
    let res2 = pm
        .observe_verified_original_attestation(
            *mal_signer.node_pubkey(),
            att2_conflict,
            NetworkId::Mainnet,
        )
        .await
        .unwrap();
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
    legit_hb.sign_origin(&legit_relayed, time, humoco_sim_core::types::NetworkId::default());
    assert!(legit_hb.verify_origin_address_binding(humoco_sim_core::types::NetworkId::default()));

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

#[derive(Clone, Debug)]
struct FaultBackend {
    inner: Arc<redb::backends::InMemoryBackend>,
    fail_write: Arc<AtomicBool>,
}

impl redb::StorageBackend for FaultBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        self.inner.len()
    }
    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.inner.set_len(len)
    }
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, std::io::Error> {
        self.inner.read(offset, len)
    }
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected storage write fault"));
        }
        self.inner.write(offset, data)
    }
    fn sync_data(&self, eventual: bool) -> Result<(), std::io::Error> {
        if self.fail_write.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("injected storage sync fault"));
        }
        self.inner.sync_data(eventual)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_s06_12_contention_and_guard_non_retention() {
    let temp = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&temp.path().join("contention.redb")).unwrap());
    let (engine, worker) = DualTierEngine::new(db.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(pm.clone()).await;

    let mal_signer = NodeIdentity::generate();
    let unrelated_signer = NodeIdentity::generate();
    let parent_lock = [0x77u8; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);

    let unrelated_parent = [0x88u8; 32];
    let unrelated_shard = u16::from_be_bytes([unrelated_parent[0], unrelated_parent[1]]);

    let now_ms = pm.net_time_ms();
    let att1 = humoco_node::api::routes::create_attestation_for_network(
        &mal_signer,
        [0x01; 32],
        parent_lock,
        shard_id,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let att2_conflict = humoco_node::api::routes::create_attestation_for_network(
        &mal_signer,
        [0x02; 32],
        parent_lock,
        shard_id,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let unrelated_att = humoco_node::api::routes::create_attestation_for_network(
        &unrelated_signer,
        [0x33; 32],
        unrelated_parent,
        unrelated_shard,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );

    // Initial valid attestation
    assert!(
        humoco_node::api::routes::verify_peer_attestation(
            &pm,
            &att1,
            ([0x01; 32], parent_lock),
            shard_id,
            0,
            humoco_sim_core::types::NetworkId::Mainnet,
            Some(*mal_signer.node_pubkey()),
        )
        .await
        .unwrap()
    );

    // Hold a redb write transaction in a separate OS thread for 250 ms
    let db_clone = db.clone();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let write_txn = db_clone.raw_database_for_test().begin_write().unwrap();
        let _ = held_tx.send(());
        std::thread::sleep(Duration::from_millis(250));
        drop(write_txn);
    });
    held_rx.await.unwrap();

    // Now spawn the conflicting attestation verification which must persist to redb
    let pm_clone = pm.clone();
    let mal_pk = *mal_signer.node_pubkey();
    let conflict_handle = tokio::spawn(async move {
        humoco_node::api::routes::verify_peer_attestation(
            &pm_clone,
            &att2_conflict,
            ([0x02; 32], parent_lock),
            shard_id,
            0,
            humoco_sim_core::types::NetworkId::Mainnet,
            Some(mal_pk),
        )
        .await
    });

    // Let the conflict task enter verify_peer_attestation and attempt to persist
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Assert that an unrelated cache observation progresses and completes promptly (< 80 ms)
    let unrelated_start = tokio::time::Instant::now();
    let unrelated_ok = humoco_node::api::routes::verify_peer_attestation(
        &pm,
        &unrelated_att,
        ([0x33; 32], unrelated_parent),
        unrelated_shard,
        0,
        humoco_sim_core::types::NetworkId::Mainnet,
        Some(*unrelated_signer.node_pubkey()),
    )
    .await
    .unwrap();
    let unrelated_elapsed = unrelated_start.elapsed();

    // And assert independent Tokio runtime timer progresses promptly (< 80 ms)
    let timer_start = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let timer_elapsed = timer_start.elapsed();

    let conflict_res = conflict_handle.await.unwrap().unwrap();
    assert!(!conflict_res, "Conflicting attestation must be rejected");

    assert!(timer_elapsed < Duration::from_millis(80), "Independent Tokio timer must not be starved, took {:?}", timer_elapsed);
    assert!(
        unrelated_elapsed < Duration::from_millis(80),
        "Unrelated cache observation must complete promptly (< 80 ms) while redb writer is blocked, took {:?}",
        unrelated_elapsed
    );
    assert!(unrelated_ok);
    assert!(db.is_node_banned(mal_signer.node_pubkey()).unwrap());

    worker.abort();
    let _ = worker.await;
}

#[tokio::test]
async fn test_s06_13_storage_write_failure_retains_evidence_and_flushes_durable() {
    let fail_write = Arc::new(AtomicBool::new(false));
    let backend = FaultBackend {
        inner: Arc::new(redb::backends::InMemoryBackend::new()),
        fail_write: fail_write.clone(),
    };
    let db = Arc::new(RedbStorage::open_with_backend(backend.clone(), std::path::Path::new("/tmp/test_fault.redb")).unwrap());
    let (engine, worker) = DualTierEngine::new(db.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(pm.clone()).await;

    let mal_signer = NodeIdentity::generate();
    let parent_lock = [0x55; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    let now_ms = pm.net_time_ms();
    let att1 = humoco_node::api::routes::create_attestation_for_network(
        &mal_signer,
        [0x01; 32],
        parent_lock,
        shard_id,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let att2_conflict = humoco_node::api::routes::create_attestation_for_network(
        &mal_signer,
        [0x02; 32],
        parent_lock,
        shard_id,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );

    // Saturate forwarding channel with sentinel (channel capacity = 1)
    let (fraud_tx, mut fraud_rx) = tokio::sync::mpsc::channel(1);
    let sentinel = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att1.to_core().unwrap(),
        att1.to_core().unwrap(),
        [0xAA; 32],
    );
    fraud_tx.try_send((sentinel, None)).unwrap();
    pm.set_fraud_proof_tx(fraud_tx).await;

    // Initial valid attestation
    assert!(
        humoco_node::api::routes::verify_peer_attestation(
            &pm,
            &att1,
            ([0x01; 32], parent_lock),
            shard_id,
            0,
            humoco_sim_core::types::NetworkId::Mainnet,
            Some(*mal_signer.node_pubkey()),
        )
        .await
        .unwrap()
    );

    // Inject storage write failure
    fail_write.store(true, Ordering::SeqCst);

    // Feed conflicting attestation
    let verify_res = humoco_node::api::routes::verify_peer_attestation(
        &pm,
        &att2_conflict,
        ([0x02; 32], parent_lock),
        shard_id,
        0,
        humoco_sim_core::types::NetworkId::Mainnet,
        Some(*mal_signer.node_pubkey()),
    )
    .await;

    // Requirement 1: Observable failure from the observer/verifier when persistence fails
    assert!(
        verify_res.is_err(),
        "Must return observable failure when storage persistence fails"
    );

    // Requirement 2: Justified local RAM containment (is_banned == true) immediately active
    assert!(
        pm.is_banned(mal_signer.node_pubkey()).await,
        "PeerManager must have offender banned in RAM immediately"
    );
    assert!(
        engine.is_node_banned(mal_signer.node_pubkey()).await,
        "DualTierEngine must have offender banned in RAM immediately"
    );

    // Storage write failed, so node is NOT banned in redb yet
    assert!(!db.is_node_banned(mal_signer.node_pubkey()).unwrap());

    // Requirement 3: Retained evidence ownership in memory even though redb commit and try_send failed
    // Clear storage fault and drain sentinel from forwarding channel
    fail_write.store(false, Ordering::SeqCst);
    let drained_sentinel = fraud_rx.try_recv().unwrap();
    assert_eq!(drained_sentinel.0.perpetrator_node_id, [0xAA; 32]);

    // Reopen clean storage on the same backend to clear redb's poisoned PreviousIo state
    let reopened = Arc::new(RedbStorage::open_with_backend(backend.clone(), std::path::Path::new("/tmp/test_fault.redb")).unwrap());
    pm.set_storage(Arc::downgrade(&reopened));

    // Requirement 4: After clearing storage fault and freeing channel, retrying/flushing pending evidence
    // succeeds without needing remote resubmission of the conflicting vote!
    let flush_res = pm.flush_pending_slashing_evidence().await;
    assert!(flush_res.is_ok(), "Flush must succeed once fault is cleared: {:?}", flush_res.err());
    assert_eq!(flush_res.unwrap(), 1, "Exactly 1 evidence item flushed");

    // Forwarding queue now received the forwarded proof!
    let forwarded_proof = fraud_rx.try_recv().expect("Fraud proof must be queued for forwarding");
    assert_eq!(forwarded_proof.0.perpetrator_node_id, *mal_signer.node_pubkey());

    // Reopening RedbStorage confirms durable persistence
    assert!(
        reopened.is_node_banned(mal_signer.node_pubkey()).unwrap(),
        "Reopened storage must confirm offender is durably banned"
    );

    // Check TABLE_SLASHING_EVIDENCE contains the proof
    let read_txn = reopened.raw_database_for_test().begin_read().unwrap();
    let table = read_txn.open_table(humoco_node::storage::db::TABLE_SLASHING_EVIDENCE).unwrap();
    assert_eq!(table.iter().unwrap().count(), 1, "Slashing evidence table must contain persisted proof");

    worker.abort();
    let _ = worker.await;
}

#[tokio::test]
async fn test_s06_commit_control_and_cancellation_safety() {
    let temp = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&temp.path().join("control.redb")).unwrap());
    let (engine, worker) = DualTierEngine::new(db.clone());
    let pm = Arc::new(PeerManager::new(vec![]));
    engine.set_peer_manager(pm.clone()).await;

    let mal_signer = NodeIdentity::generate();
    let parent_lock = [0x66; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    let now_ms = pm.net_time_ms();
    let att1 = humoco_node::api::routes::create_attestation_for_network(
        &mal_signer,
        [0x01; 32],
        parent_lock,
        shard_id,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    let att2_conflict = humoco_node::api::routes::create_attestation_for_network(
        &mal_signer,
        [0x02; 32],
        parent_lock,
        shard_id,
        0,
        now_ms,
        humoco_sim_core::types::NetworkId::Mainnet,
    );

    let (fraud_tx, mut fraud_rx) = tokio::sync::mpsc::channel(10);
    pm.set_fraud_proof_tx(fraud_tx).await;

    // Healthy commit control:
    // 1. Initial vote
    assert!(
        humoco_node::api::routes::verify_peer_attestation(
            &pm,
            &att1,
            ([0x01; 32], parent_lock),
            shard_id,
            0,
            humoco_sim_core::types::NetworkId::Mainnet,
            Some(*mal_signer.node_pubkey()),
        )
        .await
        .unwrap()
    );

    // 2. Conflict detected -> persisted to redb, banned in RAM, queued for forwarding
    let conflict_res = humoco_node::api::routes::verify_peer_attestation(
        &pm,
        &att2_conflict,
        ([0x02; 32], parent_lock),
        shard_id,
        0,
        humoco_sim_core::types::NetworkId::Mainnet,
        Some(*mal_signer.node_pubkey()),
    )
    .await
    .unwrap();
    assert!(!conflict_res);

    assert!(db.is_node_banned(mal_signer.node_pubkey()).unwrap());
    assert!(pm.is_banned(mal_signer.node_pubkey()).await);
    assert!(engine.is_node_banned(mal_signer.node_pubkey()).await);

    let forwarded = fraud_rx.try_recv().unwrap();
    assert_eq!(forwarded.0.perpetrator_node_id, *mal_signer.node_pubkey());

    // Cancellation safety: aborting tasks does not poison mutex or lose pending state
    let pm_clone = pm.clone();
    let task = tokio::spawn(async move {
        let _ = pm_clone.flush_pending_slashing_evidence().await;
    });
    task.abort();
    let _ = task.await;

    // Mutex remains healthy and unpoisoned
    assert_eq!(pm.flush_pending_slashing_evidence().await.unwrap(), 0);

    worker.abort();
    let _ = worker.await;
}

struct EquivocationMockHandler {
    peer_identity: NodeIdentity,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
}

impl humoco_node::network::RequestHandler for EquivocationMockHandler {
    fn handle(
        &self,
        _header: humoco_sim_core::wire::WireHeader,
        _payload: Vec<u8>,
    ) -> humoco_node::network::BoxFuture<Result<(humoco_sim_core::wire::WireHeader, Vec<u8>), humoco_node::NodeError>> {
        let lock_id = self.lock_id;
        let parent_lock = self.parent_lock;
        let shard_id = self.shard_id;
        let peer_identity = self.peer_identity.clone();

        Box::pin(async move {
            let att = humoco_node::api::routes::create_attestation_for_network(
                &peer_identity,
                lock_id,
                parent_lock,
                shard_id,
                0,
                1000,
                humoco_sim_core::types::NetworkId::Mainnet,
            );
            let wire_bytes = bincode::serialize(&att)
                .map_err(|e| humoco_node::NodeError::Network(e.to_string()))?;
            let resp_header = humoco_sim_core::wire::WireHeader::new(
                humoco_sim_core::wire::MsgType::LockVerifyResponse as u16,
                1,
                0,
                0,
                wire_bytes.len() as u32,
            );
            Ok((resp_header, wire_bytes))
        })
    }
}

#[tokio::test]
async fn test_s06_real_quic_collector_equivocation_and_storage_fault_isolation() {
    let fail_write = Arc::new(AtomicBool::new(false));
    let backend = FaultBackend {
        inner: Arc::new(redb::backends::InMemoryBackend::new()),
        fail_write: fail_write.clone(),
    };
    let client_db = Arc::new(RedbStorage::open_with_backend(backend.clone(), std::path::Path::new("/tmp/client_fault.redb")).unwrap());
    let (client_engine, worker) = DualTierEngine::new(client_db.clone());

    let client_id = NodeIdentity::generate();
    let client_cancel = CancellationToken::new();
    let client_pm = Arc::new(PeerManager::new(Vec::new()));
    client_pm.set_simulation_mode(true);
    client_engine.set_peer_manager(client_pm.clone()).await;

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        client_pm.clone(),
        Arc::new(humoco_node::network::DefaultRequestHandler),
        client_cancel.clone(),
    )
    .unwrap();
    let client_addr = client_transport.local_addr().unwrap();
    client_transport.set_sync_ready(true);
    client_transport.spawn_accept_loop();

    let peer_id = NodeIdentity::generate();
    let peer_cancel = CancellationToken::new();
    let peer_pm = Arc::new(PeerManager::new(Vec::new()));
    peer_pm.set_simulation_mode(true);
    let parent_lock = [0x78; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);

    let mock_handler = Arc::new(EquivocationMockHandler {
        peer_identity: peer_id.clone(),
        lock_id: [0x02; 32], // Peer will respond with lock_id 0x02
        parent_lock,
        shard_id,
    });

    let peer_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &peer_id,
        peer_pm.clone(),
        mock_handler,
        peer_cancel.clone(),
    )
    .unwrap();
    let peer_addr = peer_transport.local_addr().unwrap();
    peer_transport.set_sync_ready(true);
    peer_transport.spawn_accept_loop();

    // Mutual F2F registration
    client_pm.register_f2f_friend(*peer_id.node_pubkey(), Some(peer_addr)).await;
    peer_pm.register_f2f_friend(*client_id.node_pubkey(), Some(client_addr)).await;

    // Client previously observed peer's approval for lock_id 0x01 on parent_lock
    let prior_att = humoco_node::api::routes::create_attestation_for_network(
        &peer_id,
        [0x01; 32],
        parent_lock,
        shard_id,
        0,
        1000,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    assert!(
        humoco_node::api::routes::verify_peer_attestation(
            &client_pm,
            &prior_att,
            ([0x01; 32], parent_lock),
            shard_id,
            0,
            humoco_sim_core::types::NetworkId::Mainnet,
            Some(*peer_id.node_pubkey()),
        )
        .await
        .unwrap()
    );

    // Initial peer status: zero failures
    let initial_peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
    assert_eq!(initial_peer.missing_count, 0);

    // CASE 1: Client has local storage fault (fail_write == true)
    fail_write.store(true, Ordering::SeqCst);

    let candidates = [(*peer_id.node_pubkey(), peer_addr)];
    let expected_members = [*peer_id.node_pubkey()];
    let query_payload = [0u8; 32];

    let mut collected = Vec::new();
    let query = humoco_node::PeerAttestationQuery {
        transport: &client_transport,
        peer_mgr: &client_pm,
        candidate_nodes: &candidates,
        expected_members: Some(&expected_members),
        parent_lock,
        lookup_tag: None,
        voucher_id: None,
        msg_type: MsgType::LockVerifyRequest,
        resp_msg_type: MsgType::LockVerifyResponse,
        payload: &query_payload,
        lock_id: [0x02; 32],
        target_status: 0,
        shard_id,
        required_q: 1,
        shard_query_depth: 1,
        my_load: 0,
        quota_limit: 10_000,
        network_id: humoco_sim_core::types::NetworkId::Mainnet,
        checkout_deadline: None,
    };

    let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;

    // Crucial Invariant: Offender is immediately held in RAM containment and suspended
    assert!(client_pm.is_banned(peer_id.node_pubkey()).await);
    let peer_after_fault = client_pm.get_peer(&peer_addr).await.expect("peer present");
    assert_eq!(peer_after_fault.status, humoco_node::PeerStatus::Suspended);
    assert_eq!(
        peer_after_fault.missing_count,
        humoco_node::network::peer::FAILURE_THRESHOLD_SUSPENDED,
        "Offender is marked suspended via ban_node containment"
    );

    // CASE 2: Fault cleared -> Flush pending evidence durably persists
    fail_write.store(false, Ordering::SeqCst);
    let reopened = Arc::new(RedbStorage::open_with_backend(backend, std::path::Path::new("/tmp/client_fault.redb")).unwrap());
    client_pm.set_storage(Arc::downgrade(&reopened));
    let flushed = client_pm.flush_pending_slashing_evidence().await.unwrap();
    assert!(flushed >= 1);

    // Reopening storage confirms durable ban
    assert!(reopened.is_node_banned(peer_id.node_pubkey()).unwrap());

    client_cancel.cancel();
    peer_cancel.cancel();
    client_transport.close();
    peer_transport.close();
    client_transport.drain_tasks().await;
    peer_transport.drain_tasks().await;

    worker.abort();
    let _ = worker.await;
}

fn s06_14_evidence_fixture(seed: u8) -> humoco_node::network::manager::PendingSlashingEvidence {
    let identity = NodeIdentity::generate();
    let parent = [seed; 32];
    let shard = u16::from_be_bytes([seed, seed]);
    let a = humoco_node::api::routes::create_attestation_for_network(
        &identity,
        [1; 32],
        parent,
        shard,
        0,
        1000,
        Default::default(),
    )
    .to_core()
    .unwrap();
    let b = humoco_node::api::routes::create_attestation_for_network(
        &identity,
        [2; 32],
        parent,
        shard,
        0,
        1000,
        Default::default(),
    )
    .to_core()
    .unwrap();
    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        a,
        b,
        *identity.node_pubkey(),
    );
    assert!(
        humoco_node::network::transport::verify_equivocation_first_party_network(
            Default::default(),
            identity.verifying_key(),
            &proof
        )
    );
    let proof_bytes = bincode::serialize(&proof).unwrap();
    let evidence_hash = *blake3::hash(&proof_bytes).as_bytes();
    humoco_node::network::manager::PendingSlashingEvidence {
        proof_bytes,
        proof,
        evidence_hash,
        offender: *identity.node_pubkey(),
        detected_ms: 1000,
        durable_committed: false,
        forward_queued: false,
    }
}

#[tokio::test]
async fn test_s06_14_pending_saturation_ownership_and_monotonicity() {
    let mut cache = humoco_node::network::manager::ObservedVoteCache::new(2);
    let ev1 = s06_14_evidence_fixture(10);
    let ev2 = s06_14_evidence_fixture(20);
    let ev3 = s06_14_evidence_fixture(30);

    let off1 = ev1.offender;
    let off2 = ev2.offender;
    let off3 = ev3.offender;

    // 1. Insert 2 unsettled proofs into capacity-2 cache
    assert!(cache.insert_pending_evidence(ev1.clone()).is_ok());
    assert!(cache.insert_pending_evidence(ev2.clone()).is_ok());
    assert_eq!(cache.pending_count(), 2);

    // Both ev1 and ev2 must be present
    assert!(cache.find_pending_for_offender(&off1).is_some());
    assert!(cache.find_pending_for_offender(&off2).is_some());

    // S06-14 / INV-1402: Attempting to insert a 3rd proof when all capacity is occupied
    // by unsettled proofs MUST NOT evict unsettled proofs; must return explicit backpressure.
    let res = cache.insert_pending_evidence(ev3.clone());
    assert!(res.is_err(), "Must apply bounded backpressure when saturated with unsettled proofs");
    assert_eq!(cache.pending_count(), 2);
    assert!(
        cache.find_pending_for_offender(&off1).is_some(),
        "unsettled ev1 must not be evicted at capacity"
    );
    assert!(
        cache.find_pending_for_offender(&off2).is_some(),
        "unsettled ev2 must not be evicted at capacity"
    );

    // 2. Monotonic completion flags:
    cache.mark_durable_committed(&ev1.evidence_hash);
    let item = cache.find_pending_for_offender(&off1).unwrap();
    assert!(item.durable_committed);
    assert!(!item.forward_queued);

    // Duplicate insertion of ev1 with durable_committed: false must NOT reset durable_committed!
    assert!(cache.insert_pending_evidence(ev1.clone()).is_ok());
    let item_after = cache.find_pending_for_offender(&off1).unwrap();
    assert!(item_after.durable_committed, "durable_committed flag must be monotonic");

    // 3. Settled item eviction:
    // Mark ev1 as forwarded as well (now fully settled: durable_committed && forward_queued)
    cache.mark_forward_queued(&ev1.evidence_hash);

    // Inserting ev3 now reclaims the settled slot from ev1 while preserving unsettled ev2!
    assert!(cache.insert_pending_evidence(ev3.clone()).is_ok());
    assert_eq!(cache.pending_count(), 2);
    assert!(
        cache.find_pending_for_offender(&off2).is_some(),
        "unsettled ev2 must still be retained"
    );
    assert!(
        cache.find_pending_for_offender(&off3).is_some(),
        "ev3 must be successfully inserted into reclaimed settled slot"
    );
}

#[tokio::test]
async fn test_s06_15_autonomous_retry_lifecycle_real_quic_storage_and_forwarding() {
    let fail_write = Arc::new(AtomicBool::new(false));
    let backend = FaultBackend {
        inner: Arc::new(redb::backends::InMemoryBackend::new()),
        fail_write: fail_write.clone(),
    };
    let client_db = Arc::new(
        RedbStorage::open_with_backend(backend.clone(), std::path::Path::new("/tmp/retry_fault.redb"))
            .unwrap(),
    );
    let (client_engine, worker) = DualTierEngine::new(client_db.clone());

    let client_id = NodeIdentity::generate();
    let client_cancel = CancellationToken::new();
    let client_pm = Arc::new(PeerManager::new(Vec::new()));
    client_pm.set_simulation_mode(true);
    client_engine.set_peer_manager(client_pm.clone()).await;

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        client_pm.clone(),
        Arc::new(DefaultRequestHandler),
        client_cancel.clone(),
    )
    .unwrap();
    let client_addr = client_transport.local_addr().unwrap();
    client_transport.set_sync_ready(true);
    client_transport.spawn_accept_loop();

    let peer_id = NodeIdentity::generate();
    let peer_cancel = CancellationToken::new();
    let peer_pm = Arc::new(PeerManager::new(Vec::new()));
    peer_pm.set_simulation_mode(true);
    let parent_lock = [0x99; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);

    let mock_handler = Arc::new(EquivocationMockHandler {
        peer_identity: peer_id.clone(),
        lock_id: [0x02; 32],
        parent_lock,
        shard_id,
    });

    let peer_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &peer_id,
        peer_pm.clone(),
        mock_handler,
        peer_cancel.clone(),
    )
    .unwrap();
    let peer_addr = peer_transport.local_addr().unwrap();
    peer_transport.set_sync_ready(true);
    peer_transport.spawn_accept_loop();

    client_pm
        .register_f2f_friend(*peer_id.node_pubkey(), Some(peer_addr))
        .await;
    peer_pm
        .register_f2f_friend(*client_id.node_pubkey(), Some(client_addr))
        .await;

    // Prior vote for lock_id 0x01
    let prior_att = humoco_node::api::routes::create_attestation_for_network(
        &peer_id,
        [0x01; 32],
        parent_lock,
        shard_id,
        0,
        1000,
        humoco_sim_core::types::NetworkId::Mainnet,
    );
    assert!(
        humoco_node::api::routes::verify_peer_attestation(
            &client_pm,
            &prior_att,
            ([0x01; 32], parent_lock),
            shard_id,
            0,
            humoco_sim_core::types::NetworkId::Mainnet,
            Some(*peer_id.node_pubkey()),
        )
        .await
        .unwrap()
    );

    // Inject storage write failure
    fail_write.store(true, Ordering::SeqCst);

    let candidates = [(*peer_id.node_pubkey(), peer_addr)];
    let expected_members = [*peer_id.node_pubkey()];
    let query_payload = [0u8; 32];
    let mut collected = Vec::new();
    let query = humoco_node::PeerAttestationQuery {
        transport: &client_transport,
        peer_mgr: &client_pm,
        candidate_nodes: &candidates,
        expected_members: Some(&expected_members),
        parent_lock,
        lookup_tag: None,
        voucher_id: None,
        msg_type: MsgType::LockVerifyRequest,
        resp_msg_type: MsgType::LockVerifyResponse,
        payload: &query_payload,
        lock_id: [0x02; 32],
        target_status: 0,
        shard_id,
        required_q: 1,
        shard_query_depth: 1,
        my_load: 0,
        quota_limit: 10_000,
        network_id: humoco_sim_core::types::NetworkId::Mainnet,
        checkout_deadline: None,
    };
    let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;

    // Offender is immediately banned in RAM
    assert!(client_pm.is_banned(peer_id.node_pubkey()).await);
    // But NOT yet durably banned due to injected fault
    assert!(!client_db.is_node_banned(peer_id.node_pubkey()).unwrap());

    // Clear the fault
    fail_write.store(false, Ordering::SeqCst);
    let reopened = Arc::new(
        RedbStorage::open_with_backend(backend, std::path::Path::new("/tmp/retry_fault.redb"))
            .unwrap(),
    );
    client_pm.set_storage(Arc::downgrade(&reopened));

    // S06-15: We do NOT send any new attestation from offender, and do NOT manually call flush.
    // The autonomous lifecycle must detect the unsettled evidence and flush it!
    let mut durably_persisted = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if reopened.is_node_banned(peer_id.node_pubkey()).unwrap() {
            durably_persisted = true;
            break;
        }
    }
    assert!(
        durably_persisted,
        "S06-15 regression: autonomous retry failed to durably persist evidence without manual flush"
    );

    client_cancel.cancel();
    peer_cancel.cancel();
    client_transport.close();
    peer_transport.close();
    client_transport.drain_tasks().await;
    peer_transport.drain_tasks().await;
    worker.abort();
    let _ = worker.await;
}

