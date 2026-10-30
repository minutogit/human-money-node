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

fn sign_attestation(
    key: &SigningKey,
    parent: &[u8; 32],
    lock_id: &[u8; 32],
    domain: &[u8],
    status: u8,
) -> Attestation {
    let payload = humoco_sim_core::crypto::compute_attestation_payload_digest(parent, lock_id);
    let shard = u16::from_be_bytes([parent[0], parent[1]]);
    let digest =
        humoco_sim_core::crypto::compute_sig_digest(domain, 0, 0, 0, shard, status, &payload);
    let pubkey = key.verifying_key().to_bytes();
    let node_u16 = u16::from_le_bytes([pubkey[0], pubkey[1]]);
    Attestation {
        node_id: node_u16,
        lock_id: *lock_id,
        parent_lock: *parent,
        timestamp: SimTime(1_000),
        signature: key.sign(&digest).to_bytes(),
        shard_id: shard,
    }
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
    forged.perpetrator = victim_u16;

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
    forged.perpetrator = victim_u16;

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
