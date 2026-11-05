#![forbid(unsafe_code)]

//! Audit 02 & Audit 20 permanent real-QUIC regression suite:
//! - A02-01: Network-aware first-party verification for Testnet/Mainnet EquivocationProofs
//!   (bi- and unidirectional real-QUIC, Mainnet controls, forged proofs, and mixed-network pairs)
//! - A20-01: Atomic persistence of slashing evidence + ban (`RedbStorage::commit_slashing_evidence_and_ban`)
//!   and boot reconstruction of missing bans from evidence under worker abort & process reopen.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::identity::NodeIdentity;
use humoco_node::network::pool::PeerConnectionLease;
use humoco_node::network::{DefaultRequestHandler, NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::types::{Attestation, NetworkId, SimTime};
use humoco_sim_core::wire::{MsgType, WireHeader};

/// Signs an attestation for a descendant voucher where the authenticated voucher genesis shard
/// is decoupled from the arbitrary parent double-spend tag digest prefix.
fn sign_attestation_with_shard(
    key: &SigningKey,
    parent: &[u8; 32],
    lock_id: &[u8; 32],
    domain: &[u8],
    status: u8,
    shard_id: u16,
) -> Attestation {
    let payload = humoco_sim_core::crypto::compute_attestation_payload_digest(parent, lock_id);
    let digest =
        humoco_sim_core::crypto::compute_sig_digest(domain, 0, 0, 0, shard_id, status, &payload);
    let pubkey = key.verifying_key().to_bytes();
    let node_u16 = u16::from_le_bytes([pubkey[0], pubkey[1]]);
    Attestation {
        node_id: node_u16,
        lock_id: *lock_id,
        parent_lock: *parent,
        timestamp: SimTime(1_000),
        signature: key.sign(&digest).to_bytes(),
        shard_id,
    }
}

/// Signs an attestation for a root voucher where the parent lock digest's prefix matches the voucher genesis shard.
fn sign_attestation(
    key: &SigningKey,
    parent: &[u8; 32],
    lock_id: &[u8; 32],
    domain: &[u8],
    status: u8,
) -> Attestation {
    let shard = u16::from_be_bytes([parent[0], parent[1]]);
    sign_attestation_with_shard(key, parent, lock_id, domain, status, shard)
}

async fn setup_server(
    network_id: NetworkId,
) -> (
    Arc<RedbStorage>,
    DualTierEngine,
    tokio::task::JoinHandle<()>,
    Arc<PeerManager>,
    NodeIdentity,
    QuicTransport,
    std::net::SocketAddr,
    CancellationToken,
) {
    let server_id = NodeIdentity::generate();
    let server_cancel = CancellationToken::new();
    let pm = Arc::new(PeerManager::new(Vec::new()));
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("a02_a20.redb")).expect("open redb"));
    let (engine, worker) = DualTierEngine::new(storage.clone());
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            server_id.clone(),
            pm.clone(),
        )
        .with_network_id(network_id),
    );
    let transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &server_id,
        pm.clone(),
        handler,
        server_cancel.clone(),
    )
    .expect("bind server");
    let addr = transport.local_addr().expect("addr");
    transport.spawn_accept_loop();
    (
        storage,
        engine,
        worker,
        pm,
        server_id,
        transport,
        addr,
        server_cancel,
    )
}

async fn setup_client(
    server_addr: std::net::SocketAddr,
    server_pubkey: [u8; 32],
    server_pm: &PeerManager,
) -> (QuicTransport, PeerConnectionLease, CancellationToken) {
    let client_id = NodeIdentity::generate();
    let client_cancel = CancellationToken::new();
    let client_pm = Arc::new(PeerManager::new(Vec::new()));
    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_id,
        client_pm.clone(),
        Arc::new(DefaultRequestHandler),
        client_cancel.clone(),
    )
    .expect("bind client");
    let client_addr = client_transport.local_addr().expect("client addr");
    client_transport.spawn_accept_loop();

    server_pm
        .register_f2f_friend(*client_id.node_pubkey(), Some(client_addr))
        .await;
    client_pm
        .register_f2f_friend(server_pubkey, Some(server_addr))
        .await;

    let conn = client_transport
        .connect_peer(server_addr)
        .await
        .expect("connect client to server");

    (client_transport, conn, client_cancel)
}

// ---------------------------------------------------------------------------
// A02-01: Genuine Testnet Equivocation (Bidirectional Real QUIC)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a02_01_bidi_testnet_equivocation_slashes_offender() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Testnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x55u8; 32];
    let lock_a = [0xAAu8; 32];
    let lock_b = [0xBBu8; 32];

    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_TESTNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(
        proof.verify(),
        "Testnet proof must pass generic verify (A02-01)"
    );
    assert!(
        proof.verify_network(NetworkId::Testnet),
        "Testnet proof must pass Testnet verify"
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send equivocation proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Verify offender is permanently banned in RAM and disk
    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Offender must be banned in engine"
    );
    assert!(
        pm.is_banned(&offender_pub).await,
        "Offender must be banned in PeerManager"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Offender must be banned in redb"
    );

    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(storage
        .get_evidence(&evidence_hash)
        .expect("get evidence")
        .is_some());

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// A02-01: Genuine Testnet Equivocation (Unidirectional Real QUIC)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a02_01_uni_testnet_equivocation_slashes_offender() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Testnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0x43u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x56u8; 32];
    let lock_a = [0x11u8; 32];
    let lock_b = [0x22u8; 32];

    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_TESTNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        2,
        0,
        0,
        payload.len() as u32,
    );

    client_transport
        .send_unidirectional(&conn, &hdr, &payload)
        .await
        .expect("send uni equivocation proof");

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Offender must be banned in engine (uni)"
    );
    assert!(
        pm.is_banned(&offender_pub).await,
        "Offender must be banned in PeerManager (uni)"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Offender must be banned in redb (uni)"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// A02-01: Mainnet Control (Bidirectional Real QUIC)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a02_01_mainnet_control_slashes_offender() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0x44u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x57u8; 32];
    let lock_a = [0x33u8; 32];
    let lock_b = [0x44u8; 32];

    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify(), "Mainnet proof must pass generic verify");
    assert!(
        proof.verify_network(NetworkId::Mainnet),
        "Mainnet proof must pass Mainnet verify"
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        3,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send mainnet equivocation proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Mainnet offender banned in engine"
    );
    assert!(
        pm.is_banned(&offender_pub).await,
        "Mainnet offender banned in PeerManager"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Mainnet offender banned in redb"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// A02-01: Mixed-Network Pair Rejected Without Mutation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a02_01_mixed_network_pair_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Testnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0x45u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let parent = [0x58u8; 32];
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];

    // Mixed pair: att_a is Mainnet, att_b is Testnet
    let att_a = sign_attestation(
        &victim_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
    );
    let att_b = sign_attestation(
        &victim_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
    );

    let mixed = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a, att_b, victim_pub,
    );

    assert!(!mixed.verify(), "Mixed-network proof must fail verify");
    assert!(
        !mixed.verify_network(NetworkId::Testnet),
        "Mixed-network proof must fail Testnet verify"
    );
    assert!(
        !mixed.verify_network(NetworkId::Mainnet),
        "Mixed-network proof must fail Mainnet verify"
    );

    let payload = bincode::serialize(&mixed).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        4,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send mixed proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Victim must NOT be banned, and no evidence persisted
    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Victim must not be banned in engine on mixed proof"
    );
    assert!(
        !pm.is_banned(&victim_pub).await,
        "Victim must not be banned in PeerManager on mixed proof"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Victim must not be banned in redb"
    );

    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(storage
        .get_evidence(&evidence_hash)
        .expect("get evidence")
        .is_none());

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// A02-01: Forged Simulator Proof Rejected Without Mutation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a02_01_forged_proof_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Testnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0x46u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let victim_u16 = u16::from_le_bytes([victim_pub[0], victim_pub[1]]);
    let parent = [0x59u8; 32];
    let lock_a = [0x77u8; 32];
    let lock_b = [0x88u8; 32];

    // Simulator BLAKE3 attestations framing the victim
    let att_a = humoco_sim_core::crypto::sign_lock_attestation(
        victim_u16,
        &lock_a,
        &parent,
        SimTime(1_000),
    );
    let att_b = humoco_sim_core::crypto::sign_lock_attestation(
        victim_u16,
        &lock_b,
        &parent,
        SimTime(1_000),
    );

    let mut forged =
        humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation(att_a, att_b);
    forged.perpetrator_node_id = victim_pub;

    let payload = bincode::serialize(&forged).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        5,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send forged proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Victim must not be banned on forged proof"
    );
    assert!(
        !pm.is_banned(&victim_pub).await,
        "Victim must not be banned in PeerManager"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Victim must not be banned in redb"
    );

    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(storage
        .get_evidence(&evidence_hash)
        .expect("get evidence")
        .is_none());

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

/// A blocked durable fraud commit must not block a single-thread Tokio runtime.
#[tokio::test(flavor = "current_thread")]
async fn fraud_commit_worker_keeps_independent_quic_requests_responsive() {
    let (storage, _, _, pm, server_id, server, addr, cancel) = setup_server(NetworkId::Mainnet).await;
    let (client, conn, client_cancel) = setup_client(addr, *server_id.node_pubkey(), &pm).await;
    let key = SigningKey::from_bytes(&[0x61;32]);
    let parent = [0x60;32];
    let a = sign_attestation(&key, &parent, &[1;32], humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET, 0);
    let b = sign_attestation(&key, &parent, &[2;32], humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET, 0);
    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(a,b,key.verifying_key().to_bytes());
    let bytes = bincode::serialize(&proof).unwrap();
    let header = WireHeader::new(MsgType::EquivocationProof as u16, 1,0,0,bytes.len() as u32);
    let txn = storage.raw_database_for_test().begin_write().unwrap();
    let (release, held) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let _ = held.recv_timeout(std::time::Duration::from_secs(2));
        drop(txn);
    });
    let requester = client.clone();
    let request_conn = conn.clone();
    let request = tokio::spawn(async move { requester.send_request(&request_conn, &header, &bytes).await });
    let started = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!request.is_finished(), "fraud acknowledgment must await durable commit");
    let probe = WireHeader::new(MsgType::LatencyProbe as u16, 2,0,0,0);
    client.send_request(&conn, &probe, &[]).await.unwrap();
    assert!(started.elapsed() < std::time::Duration::from_millis(500), "blocked fraud commit must yield the runtime");
    release.send(()).unwrap();
    blocker.join().unwrap();
    let (ack, _) = request.await.unwrap().unwrap();
    assert_eq!(ack.msg_type, MsgType::EquivocationAck as u16);
    assert!(storage.is_node_banned(&key.verifying_key().to_bytes()).unwrap());
    cancel.cancel(); client_cancel.cancel(); server.close(); client.close();
}

// ---------------------------------------------------------------------------
// A20-01: Atomic Persistence with Aborted Worker
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a20_01_atomic_persistence_with_aborted_worker() {
    let (storage, engine, worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;

    // Fault injection: abort the flush worker completely
    worker.abort();
    let _ = worker.await;

    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0x47u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x60u8; 32];
    let lock_a = [0x99u8; 32];
    let lock_b = [0x00u8; 32];

    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );
    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        6,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send proof with aborted worker");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // RAM ban
    assert!(engine.is_node_banned(&offender_pub).await);
    assert!(pm.is_banned(&offender_pub).await);

    // CRITICAL (A20-01): The ban and evidence MUST be persisted synchronously/atomically
    // to redb despite the flush worker being aborted!
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Ban must be durably committed despite aborted worker"
    );
    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(
        storage
            .get_evidence(&evidence_hash)
            .expect("check evidence")
            .is_some(),
        "Evidence must be durably committed"
    );

    // CRITICAL: A newly constructed engine on the same storage MUST have the offender banned immediately
    let (new_engine, _new_worker) = DualTierEngine::new(storage.clone());
    assert!(
        new_engine.is_node_banned(&offender_pub).await,
        "Newly constructed engine must load the persisted ban"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// A20-01: Boot Reconstruction from Durable Evidence
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a20_01_boot_reconstruction_from_durable_evidence() {
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("reconstruction.redb")).expect("open redb"));

    let offender_key = SigningKey::from_bytes(&[0x48u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x61u8; 32];
    let lock_a = [0x12u8; 32];
    let lock_b = [0x34u8; 32];

    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );
    let payload = bincode::serialize(&proof).expect("serialize");
    let evidence_hash = *blake3::hash(&payload).as_bytes();

    // Manually write ONLY evidence to redb, simulating a node that crashed before ban insertion
    storage
        .put_evidence(&evidence_hash, &payload)
        .expect("put evidence");

    // Before boot reconstruction, ban does not exist in redb
    assert!(!storage.is_node_banned(&offender_pub).expect("check ban"));

    // Now construct DualTierEngine (simulating node boot)
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    // CRITICAL: Boot reconstruction MUST have reconstructed the missing ban from the valid evidence!
    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Engine must have offender banned via boot reconstruction"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Storage must now contain the reconstructed ban"
    );
}

// ---------------------------------------------------------------------------
// A20-01: Boot Reconstruction Rejects Forged Evidence (Anti-Framing)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a20_01_boot_reconstruction_rejects_forged_evidence() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(
        RedbStorage::open(&temp.path().join("anti_framing_reconstruction.redb"))
            .expect("open redb"),
    );

    let victim_key = SigningKey::from_bytes(&[0x49u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let victim_u16 = u16::from_le_bytes([victim_pub[0], victim_pub[1]]);
    let parent = [0x62u8; 32];
    let lock_a = [0x56u8; 32];
    let lock_b = [0x78u8; 32];

    // Forged simulator attestations framing the victim
    let att_a = humoco_sim_core::crypto::sign_lock_attestation(
        victim_u16,
        &lock_a,
        &parent,
        SimTime(1_000),
    );
    let att_b = humoco_sim_core::crypto::sign_lock_attestation(
        victim_u16,
        &lock_b,
        &parent,
        SimTime(1_000),
    );

    let mut forged =
        humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation(att_a, att_b);
    forged.perpetrator_node_id = victim_pub;

    let payload = bincode::serialize(&forged).expect("serialize");
    let evidence_hash = *blake3::hash(&payload).as_bytes();

    // Store forged evidence in storage
    storage
        .put_evidence(&evidence_hash, &payload)
        .expect("put forged evidence");

    // Boot the engine
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    // CRITICAL: Boot reconstruction MUST NOT ban the framed victim from forged evidence!
    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Victim must NOT be banned by forged evidence at boot"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Storage must NOT contain ban for framed victim"
    );
}

#[tokio::test]
async fn test_a02_01_mainnet_rejects_testnet_equivocation_proof() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0x91u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x71u8; 32];
    let lock_a = [0x81u8; 32];
    let lock_b = [0x82u8; 32];

    // Genuine Testnet-only attestations
    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_TESTNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify_network(NetworkId::Testnet));
    assert!(!proof.verify_network(NetworkId::Mainnet));

    let payload = bincode::serialize(&proof).expect("serialize");
    let evidence_hash = *blake3::hash(&payload).as_bytes();
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send equivocation proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Assert: NO RAM ban, NO durable ban, NO evidence entry
    assert!(
        !engine.is_node_banned(&offender_pub).await,
        "Mainnet node must NOT ban offender in engine RAM for Testnet proof"
    );
    assert!(
        !pm.is_banned(&offender_pub).await,
        "Mainnet node must NOT ban offender in PeerManager for Testnet proof"
    );
    assert!(
        !storage.is_node_banned(&offender_pub).expect("check ban"),
        "Mainnet node must NOT ban offender in redb for Testnet proof"
    );
    assert!(
        storage.get_evidence(&evidence_hash).expect("get evidence").is_none(),
        "Mainnet node must NOT store slashing evidence for Testnet proof"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_a02_01_testnet_rejects_mainnet_equivocation_proof() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Testnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0x92u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let parent = [0x72u8; 32];
    let lock_a = [0x83u8; 32];
    let lock_b = [0x84u8; 32];

    // Genuine Mainnet-only attestations
    let att_a = sign_attestation(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
    );
    let att_b = sign_attestation(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify_network(NetworkId::Mainnet));
    assert!(!proof.verify_network(NetworkId::Testnet));

    let payload = bincode::serialize(&proof).expect("serialize");
    let evidence_hash = *blake3::hash(&payload).as_bytes();
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        1,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send equivocation proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Assert: NO RAM ban, NO durable ban, NO evidence entry
    assert!(
        !engine.is_node_banned(&offender_pub).await,
        "Testnet node must NOT ban offender in engine RAM for Mainnet proof"
    );
    assert!(
        !pm.is_banned(&offender_pub).await,
        "Testnet node must NOT ban offender in PeerManager for Mainnet proof"
    );
    assert!(
        !storage.is_node_banned(&offender_pub).expect("check ban"),
        "Testnet node must NOT ban offender in redb for Mainnet proof"
    );
    assert!(
        storage.get_evidence(&evidence_hash).expect("get evidence").is_none(),
        "Testnet node must NOT store slashing evidence for Mainnet proof"
    );


    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// S04-06: Genuine Conflicting Originals with Shard Differing from Parent Prefix (Bidi QUIC)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s04_06_bidi_different_shard_than_parent_prefix_slashes_offender() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Testnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0xA1u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    // Consumed parent prefix is 0x7777, but signed voucher-genesis shard is 0x1234
    let mut parent = [0x77u8; 32];
    parent[0] = 0x77;
    parent[1] = 0x77;
    let lock_a = [0x11u8; 32];
    let lock_b = [0x22u8; 32];
    let explicit_shard = 0x1234u16;

    // Mixed provisional and final originals
    let att_a = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_TESTNET,
        0,
        explicit_shard,
    );
    let att_b = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
        explicit_shard,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify(), "Proof must verify under generic verifier");
    assert!(proof.verify_network(NetworkId::Testnet), "Proof must verify under Testnet");

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        10,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send equivocation proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Offender must be banned in RAM and durable redb, and evidence persisted
    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Offender must be banned in engine RAM"
    );
    assert!(
        pm.is_banned(&offender_pub).await,
        "Offender must be banned in PeerManager"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Offender must be banned in redb"
    );

    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(
        storage
            .get_evidence(&evidence_hash)
            .expect("get evidence")
            .is_some(),
        "Slashing evidence must be persisted"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// S04-06: Genuine Conflicting Originals with Shard Differing from Parent Prefix (Uni QUIC, Mainnet, Both Final)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s04_06_uni_different_shard_than_parent_prefix_slashes_offender() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0xA2u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let mut parent = [0x88u8; 32];
    parent[0] = 0x88;
    parent[1] = 0x88;
    let lock_a = [0x33u8; 32];
    let lock_b = [0x44u8; 32];
    let explicit_shard = 0x5678u16;

    // Both final originals
    let att_a = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
        explicit_shard,
    );
    let att_b = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
        explicit_shard,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify_network(NetworkId::Mainnet));

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        11,
        0,
        0,
        payload.len() as u32,
    );

    client_transport
        .send_unidirectional(&conn, &hdr, &payload)
        .await
        .expect("send uni proof");

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Offender must be banned in engine RAM (uni)"
    );
    assert!(
        pm.is_banned(&offender_pub).await,
        "Offender must be banned in PeerManager (uni)"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Offender must be banned in redb (uni)"
    );

    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(
        storage
            .get_evidence(&evidence_hash)
            .expect("get evidence")
            .is_some()
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// S04-06: Explicit Shard Zero with Non-Zero Parent Prefix (Both Prov, Mainnet)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s04_06_explicit_shard_zero_with_nonzero_parent_prefix_slashes_offender() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0xA3u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let mut parent = [0x77u8; 32];
    parent[0] = 0x77;
    parent[1] = 0x77;
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];
    // Explicit shard 0x0000, parent prefix 0x7777
    let explicit_shard = 0x0000u16;

    // Both provisional originals
    let att_a = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        explicit_shard,
    );
    let att_b = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        explicit_shard,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify_network(NetworkId::Mainnet));

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        12,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        engine.is_node_banned(&offender_pub).await,
        "Offender must be banned in RAM for valid explicit shard 0x0000"
    );
    assert!(
        pm.is_banned(&offender_pub).await,
        "Offender must be banned in PeerManager for valid explicit shard 0x0000"
    );
    assert!(
        storage.is_node_banned(&offender_pub).expect("check ban"),
        "Offender must be banned in redb for valid explicit shard 0x0000"
    );

    let evidence_hash = *blake3::hash(&payload).as_bytes();
    assert!(
        storage
            .get_evidence(&evidence_hash)
            .expect("get evidence")
            .is_some(),
        "Slashing evidence must be persisted for valid explicit shard 0x0000"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// S04-06 Negative Tests: Tampered metadata, differing contexts, forged signature
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s04_06_tampered_shard_after_signing_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0xA4u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let parent = [0x77u8; 32];
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];

    // Signed for shard 0x1234
    let mut att_a = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        0x1234,
    );
    let mut att_b = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
        0x1234,
    );

    // Tamper shard_id in att_a and att_b to 0x5678 after signing
    att_a.shard_id = 0x5678;
    att_b.shard_id = 0x5678;

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        victim_pub,
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        13,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send tampered proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Victim must not be banned when shard_id is tampered"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Victim must not be banned in storage when shard_id is tampered"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_s04_06_tampered_nonzero_shard_to_zero_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0xA5u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let parent = [0x77u8; 32];
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];

    // Signed for shard 0x1234
    let mut att_a = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        0x1234,
    );
    let mut att_b = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
        0x1234,
    );

    // Tamper shard_id from signed 0x1234 to 0x0000
    att_a.shard_id = 0x0000;
    att_b.shard_id = 0x0000;

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        victim_pub,
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        14,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Tampering non-zero shard to zero must be rejected without ban"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Tampering non-zero shard to zero must not persist ban"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_s04_06_differing_shards_between_originals_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0xA6u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let parent = [0x77u8; 32];
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];

    // att_a signed for shard 0x1234, att_b signed for shard 0x5678
    let att_a = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        0x1234,
    );
    let att_b = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
        0x5678,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        victim_pub,
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        15,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Differing shard contexts between originals must not ban"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Differing shard contexts between originals must not persist ban"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_s04_06_forged_signature_with_diff_shard_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0xA7u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let parent = [0x77u8; 32];
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];

    let mut att_a = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        0x1234,
    );
    let att_b = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_MAINNET,
        1,
        0x1234,
    );

    // Corrupt signature of att_a
    att_a.signature[0] ^= 0xFF;

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        victim_pub,
    );

    let payload = bincode::serialize(&proof).expect("serialize");
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        16,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Forged signature must not ban"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Forged signature must not persist ban"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// S04-06: Foreign-Network Pair with Non-Prefix Voucher Shard Rejected (Testnet on Mainnet Server)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s04_06_foreign_network_pair_diff_shard_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let offender_key = SigningKey::from_bytes(&[0xA8u8; 32]);
    let offender_pub = offender_key.verifying_key().to_bytes();
    let mut parent = [0x77u8; 32];
    parent[0] = 0x77;
    parent[1] = 0x77;
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];
    let explicit_shard = 0x1234u16;

    // Both signed for Testnet, but submitted to a Mainnet server
    let att_a = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_TESTNET,
        0,
        explicit_shard,
    );
    let att_b = sign_attestation_with_shard(
        &offender_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
        explicit_shard,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        offender_pub,
    );

    assert!(proof.verify_network(NetworkId::Testnet));
    assert!(!proof.verify_network(NetworkId::Mainnet));

    let payload = bincode::serialize(&proof).expect("serialize");
    let evidence_hash = *blake3::hash(&payload).as_bytes();
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        17,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send foreign proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    // Foreign-network pair must produce NO RAM ban, NO durable ban, and NO stored evidence
    assert!(
        !engine.is_node_banned(&offender_pub).await,
        "Mainnet node must not ban offender in engine RAM for Testnet proof with explicit shard"
    );
    assert!(
        !pm.is_banned(&offender_pub).await,
        "Mainnet node must not ban offender in PeerManager for Testnet proof with explicit shard"
    );
    assert!(
        !storage.is_node_banned(&offender_pub).expect("check ban"),
        "Mainnet node must not ban offender in redb for Testnet proof with explicit shard"
    );
    assert!(
        storage.get_evidence(&evidence_hash).expect("get evidence").is_none(),
        "Mainnet node must not persist evidence for Testnet proof with explicit shard"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

// ---------------------------------------------------------------------------
// S04-06: Mixed-Network Pair with Non-Prefix Voucher Shard Rejected (One Mainnet, One Testnet)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_s04_06_mixed_network_pair_diff_shard_rejected_without_mutation() {
    let (storage, engine, _worker, pm, server_id, server_transport, server_addr, server_cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client_transport, conn, client_cancel) =
        setup_client(server_addr, *server_id.node_pubkey(), &pm).await;

    let victim_key = SigningKey::from_bytes(&[0xA9u8; 32]);
    let victim_pub = victim_key.verifying_key().to_bytes();
    let mut parent = [0x77u8; 32];
    parent[0] = 0x77;
    parent[1] = 0x77;
    let lock_a = [0x55u8; 32];
    let lock_b = [0x66u8; 32];
    let explicit_shard = 0x1234u16;

    // Mixed: att_a is Mainnet, att_b is Testnet
    let att_a = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_a,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET,
        0,
        explicit_shard,
    );
    let att_b = sign_attestation_with_shard(
        &victim_key,
        &parent,
        &lock_b,
        humoco_sim_core::crypto::HUMOCO_V1_APPROVE_FINAL_TESTNET,
        1,
        explicit_shard,
    );

    let proof = humoco_sim_core::fraud::FraudProofPayload::new_shard_equivocation_with_pubkey(
        att_a,
        att_b,
        victim_pub,
    );

    assert!(!proof.verify(), "Mixed-network proof must fail verify");
    assert!(!proof.verify_network(NetworkId::Mainnet), "Mixed-network proof must fail Mainnet verify");
    assert!(!proof.verify_network(NetworkId::Testnet), "Mixed-network proof must fail Testnet verify");

    let payload = bincode::serialize(&proof).expect("serialize");
    let evidence_hash = *blake3::hash(&payload).as_bytes();
    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        18,
        0,
        0,
        payload.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &payload)
        .await
        .expect("send mixed proof");

    assert_eq!(resp_hdr.msg_type, MsgType::EquivocationAck as u16);

    assert!(
        !engine.is_node_banned(&victim_pub).await,
        "Victim must not be banned in engine RAM for mixed-network proof"
    );
    assert!(
        !pm.is_banned(&victim_pub).await,
        "Victim must not be banned in PeerManager for mixed-network proof"
    );
    assert!(
        !storage.is_node_banned(&victim_pub).expect("check ban"),
        "Victim must not be banned in redb for mixed-network proof"
    );
    assert!(
        storage.get_evidence(&evidence_hash).expect("get evidence").is_none(),
        "Mixed-network proof must not persist evidence"
    );

    server_cancel.cancel();
    server_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_s04_06_originals_require_explicit_shard_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    use humoco_sim_core::fraud::{decode_attestation, FraudProofPayload};

    let (storage, engine, worker, pm, server_id, server, addr, cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client, conn, client_cancel) = setup_client(addr, *server_id.node_pubkey(), &pm).await;
    let identity = NodeIdentity::generate();
    // Match the parent prefix deliberately: the obsolete decoder otherwise
    // reconstructs exactly the signed shard and accepts truncated evidence.
    let original = |lock| {
        humoco_node::api::routes::create_attestation_for_network(
            &identity,
            lock,
            [0x77; 32],
            0x7777,
            0,
            1_000,
            NetworkId::Mainnet,
        )
        .to_core()
        .ok_or("invalid original approval DTO")
    };
    let mut proof = FraudProofPayload::try_new_shard_equivocation_with_pubkey(
        original([1; 32])?,
        original([2; 32])?,
        *identity.node_pubkey(),
    )?;
    assert_eq!(proof.evidence_packet_a.len(), 140);
    assert!(proof.verify_network(NetworkId::Mainnet));
    let canonical = proof.evidence_packet_a.clone();
    assert!(decode_attestation(&proof.evidence_packet_a).is_some());
    proof.evidence_packet_a.truncate(138);
    proof.evidence_packet_b.truncate(138);
    let bytes = bincode::serialize(&proof)?;
    let hash = *blake3::hash(&bytes).as_bytes();
    let header = WireHeader::new(
        MsgType::EquivocationProof as u16,
        100,
        0,
        0,
        u32::try_from(bytes.len())?,
    );
    client.send_request(&conn, &header, &bytes).await?;
    assert!(!engine.is_node_banned(identity.node_pubkey()).await);
    assert!(!pm.is_banned(identity.node_pubkey()).await);
    assert!(!storage.is_node_banned(identity.node_pubkey())?);
    assert!(storage.get_evidence(&hash)?.is_none());
    for length in [0, 138, 139, 141] {
        let mut bytes = canonical.clone();
        bytes.resize(length, 0);
        assert!(
            decode_attestation(&bytes).is_none(),
            "noncanonical length {length}"
        );
    }
    cancel.cancel();
    client_cancel.cancel();
    server.close();
    client.close();
    worker.abort();
    server.drain_tasks().await;
    client.drain_tasks().await;
    Ok(())
}

#[tokio::test]
async fn test_s04_06_parent_signer_and_purpose_must_match() -> Result<(), Box<dyn std::error::Error>>
{
    use humoco_sim_core::fraud::FraudProofPayload;

    let (storage, engine, worker, pm, server_id, server, addr, cancel) =
        setup_server(NetworkId::Mainnet).await;
    let (client, conn, client_cancel) = setup_client(addr, *server_id.node_pubkey(), &pm).await;
    let key = SigningKey::from_bytes(&[0xb1; 32]);
    let other = SigningKey::from_bytes(&[0xb2; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let domain = humoco_sim_core::crypto::HUMOCO_V1_APPROVE_PROV_MAINNET;
    let original = |key, parent, lock, domain| {
        sign_attestation_with_shard(key, parent, lock, domain, 0, 0x1234)
    };
    for case in ["parent", "signer", "purpose"] {
        let a = original(&key, &[0x77; 32], &[1; 32], domain);
        let mut b = match case {
            "parent" => original(&key, &[0x88; 32], &[2; 32], domain),
            "signer" => original(&other, &[0x77; 32], &[2; 32], domain),
            _ => original(
                &key,
                &[0x77; 32],
                &[2; 32],
                humoco_sim_core::crypto::HUMOCO_V1_HEARTBEAT_MAINNET,
            ),
        };
        // Even a colliding short identifier cannot make another full key's
        // genuine signature evidence against the accused permanent identity.
        b.node_id = a.node_id;
        let proof = FraudProofPayload::try_new_shard_equivocation_with_pubkey(a, b, pubkey)?;
        let bytes = bincode::serialize(&proof)?;
        let hash = *blake3::hash(&bytes).as_bytes();
        let header = WireHeader::new(
            MsgType::EquivocationProof as u16,
            101,
            0,
            0,
            u32::try_from(bytes.len())?,
        );
        client.send_request(&conn, &header, &bytes).await?;
        assert!(!engine.is_node_banned(&pubkey).await, "{case}");
        assert!(!pm.is_banned(&pubkey).await, "{case}");
        assert!(!storage.is_node_banned(&pubkey)?, "{case}");
        assert!(storage.get_evidence(&hash)?.is_none(), "{case}");
    }
    cancel.cancel();
    client_cancel.cancel();
    server.close();
    client.close();
    worker.abort();
    server.drain_tasks().await;
    client.drain_tasks().await;
    Ok(())
}
