#![forbid(unsafe_code)]

//! Integration tests for Anti-Self-Slashing on Live Wire (AGENTS.md, Spec 10, Pillar 1).
//!
//! Validates that a shard node processing `LockVerifyRequest` over the live QUIC wire:
//! 1. Accepts Lock A for parent P and returns a cryptographically signed Attestation.
//! 2. When colliding Lock B is sent for the same parent P (with diverging t_id), the shard
//!    node returns `FLAG_COLLISION_DETECTED` with the existing lock payload and
//!    **NEVER returns or signs an attestation for Lock B**.
//! 3. This checks refusal of this conflicting request after one durable original approval;
//!    fixture readiness does not establish safe recovery or the general Byzantine bound.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::api::dto::AttestationDto;
use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest};
use humoco_node::identity::NodeIdentity;
use humoco_node::network::framing::LockWirePayload;
use humoco_node::network::{NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_COLLISION_DETECTED};

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_hmc_spend(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(parent_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_hmc_genesis(
    parent_hex: &str,
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{parent_hex}"),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

#[tokio::test]
async fn test_shard_node_never_signs_conflicting_attestation_on_live_wire() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("anti_slash.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let shard_identity = NodeIdentity::generate();
    let client_identity = NodeIdentity::generate();

    let shard_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let shard_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    shard_pm.set_simulation_mode(true);
    let client_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    client_pm.set_simulation_mode(true);

    // Authorize client as F2F friend on shard node (authorizes restricted LockVerifyRequest)
    shard_pm
        .register_f2f_friend(
            *client_identity.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

    // Explicit single-member fixture readiness and mature ticket; this is not recovery evidence.
    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    shard_pm
        .learn_node_from_gossip_with_hrw(
            *shard_identity.node_pubkey(),
            *shard_identity.hrw_routing_id(),
            "127.0.0.1:1".parse().unwrap(),
            0,
            None,
        )
        .await;
    shard_pm
        .set_first_seen_for_test(
            shard_identity.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            shard_identity.clone(),
            shard_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(readiness.clone()),
    );

    let shard_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &shard_identity,
        shard_pm.clone(),
        handler,
        shard_cancel.clone(),
    )
    .expect("bind shard transport");
    shard_transport.set_sync_ready(true);
    let shard_addr = shard_transport.local_addr().expect("shard local addr");
    shard_transport.spawn_accept_loop();

    let client_dummy_handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            client_identity.clone(),
            client_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_identity,
        client_pm.clone(),
        client_dummy_handler,
        client_cancel.clone(),
    )
    .expect("bind client transport");
    let client_addr = client_transport.local_addr().expect("client local addr");
    client_transport.spawn_accept_loop();

    // Shard learns client's actual bound address
    shard_pm
        .register_f2f_friend(*client_identity.node_pubkey(), Some(client_addr))
        .await;
    // Client authorizes shard
    client_pm
        .register_f2f_friend(*shard_identity.node_pubkey(), Some(shard_addr))
        .await;

    let conn = client_transport
        .connect_peer(shard_addr)
        .await
        .expect("connect client to shard");

    // -----------------------------------------------------------------------
    // Anchor genesis lock on shard first so voucher root is established
    // -----------------------------------------------------------------------
    let sender_key = SigningKey::from_bytes(&[1u8; 32]);
    let now = test_now_ms();
    let genesis_req = make_hmc_genesis("anti_slash_genesis", now + 1_000_000, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let (v_gen, is_new_gen) = engine
        .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
        .await;
    assert!(is_new_gen);
    assert!(matches!(
        v_gen,
        humoco_node::api::hmc::L2Verdict::Verified { .. }
    ));

    // -----------------------------------------------------------------------
    // Step 1: Send Lock A for parent P over QUIC wire
    // -----------------------------------------------------------------------
    let parent_hex = hex::encode([0x77u8; 32]);
    let tx_hash_a = *blake3::hash(b"lock_a_payload_tx_hash").as_bytes();
    let lock_a_req = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex,
        tx_hash_a,
        now + 900_000,
        &sender_key,
    );

    let sender_pubkey = *client_identity.node_pubkey();
    let root_valid_until = now + 1_000_000;
    let ttl_s = root_valid_until.saturating_sub(now) / 1000;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

    let digest_a = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        0,
        now,
        0,
        0,
        footprint,
        false,
        &tx_hash_a,
    );
    let sender_sig_a = client_identity.signing_key().sign(&digest_a).to_bytes();

    let wire_payload_a = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_a_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey,
        sender_signature: sender_sig_a,
        timestamp_ms: now,
    })
    .expect("serialize wire payload a");

    let header_a = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        wire_payload_a.len() as u32,
    );

    let (resp_hdr_a, resp_payload_a) = client_transport
        .send_request(&conn, &header_a, &wire_payload_a)
        .await
        .expect("send lock a request");

    assert_eq!(
        resp_hdr_a.msg_type,
        MsgType::LockVerifyResponse as u16,
        "Response must be LockVerifyResponse"
    );
    assert_eq!(
        resp_hdr_a.flags & FLAG_COLLISION_DETECTED,
        0,
        "Lock A must be accepted without collision flag"
    );

    let att_a = AttestationDto::from_wire_bytes(&resp_payload_a)
        .expect("Response payload must be valid AttestationDto for Lock A");
    assert_eq!(
        att_a.lock_id,
        hex::encode(tx_hash_a),
        "Attestation lock_id must match Lock A tx_hash"
    );
    assert_eq!(
        att_a.node_pubkey_bytes(),
        Some(*shard_identity.node_pubkey()),
        "Attestation must be signed by the shard node"
    );

    // Verify attestation signature cryptographically
    {
        use ed25519_dalek::Signature;
        let domain_tag = humoco_sim_core::crypto::domain_approve_prov(
            humoco_sim_core::types::NetworkId::Mainnet,
        );
        let parent_bytes = *blake3::hash(parent_hex.as_bytes()).as_bytes();
        let payload_digest =
            humoco_sim_core::crypto::compute_attestation_payload_digest(&parent_bytes, &tx_hash_a);
        let sig_digest = humoco_sim_core::crypto::compute_sig_digest(
            domain_tag,
            0,
            0,
            0,
            att_a.shard_id,
            0,
            &payload_digest,
        );
        let sig_bytes: [u8; 64] = hex::decode(&att_a.signature)
            .expect("hex")
            .try_into()
            .expect("64 bytes");
        let sig = Signature::from_bytes(&sig_bytes);
        shard_identity
            .verifying_key()
            .verify_strict(&sig_digest, &sig)
            .expect("Shard attestation signature for Lock A must be cryptographically valid");
    }

    // -----------------------------------------------------------------------
    // Step 2: Idempotent retry of Lock A succeeds and re-attests
    // -----------------------------------------------------------------------
    let digest_a_retry = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        1,
        now,
        footprint,
        0,
        footprint,
        false,
        &tx_hash_a,
    );
    let sender_sig_a_retry = client_identity
        .signing_key()
        .sign(&digest_a_retry)
        .to_bytes();

    let wire_payload_a_retry = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_a_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: footprint,
        declared_read_ema_credits: 0,
        sender_pubkey,
        sender_signature: sender_sig_a_retry,
        timestamp_ms: now,
    })
    .expect("serialize wire payload a retry");

    let header_a_retry = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        2,
        0,
        0,
        wire_payload_a_retry.len() as u32,
    );

    let (resp_hdr_a_retry, resp_payload_a_retry) = client_transport
        .send_request(&conn, &header_a_retry, &wire_payload_a_retry)
        .await
        .expect("send lock a retry");
    assert_eq!(
        resp_hdr_a_retry.flags & FLAG_COLLISION_DETECTED,
        0,
        "Idempotent retry of Lock A must succeed without collision flag"
    );
    let att_a_retry = AttestationDto::from_wire_bytes(&resp_payload_a_retry)
        .expect("Idempotent retry must return signed attestation for Lock A");
    assert_eq!(att_a_retry.lock_id, hex::encode(tx_hash_a));

    // -----------------------------------------------------------------------
    // Step 3: Send Colliding Lock B on the SAME parent P (parent_hex)
    // -----------------------------------------------------------------------
    let tx_hash_b = *blake3::hash(b"colliding_lock_b_payload_tx_hash").as_bytes();
    assert_ne!(tx_hash_a, tx_hash_b, "Lock B must have different t_id");

    let lock_b_req = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex, // EXACT SAME PARENT TAG P!
        tx_hash_b,
        now + 900_000,
        &sender_key,
    );

    let digest_b = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        2,
        now,
        footprint.saturating_mul(2),
        0,
        footprint,
        false,
        &tx_hash_b,
    );
    let sender_sig_b = client_identity.signing_key().sign(&digest_b).to_bytes();

    let wire_payload_b = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_b_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 2,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: footprint.saturating_mul(2),
        declared_read_ema_credits: 0,
        sender_pubkey,
        sender_signature: sender_sig_b,
        timestamp_ms: now,
    })
    .expect("serialize wire payload b");

    let header_b = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        3,
        0,
        0,
        wire_payload_b.len() as u32,
    );

    let (resp_hdr_b, resp_payload_b) = client_transport
        .send_request(&conn, &header_b, &wire_payload_b)
        .await
        .expect("send lock b request");

    // CRITICAL SECURITY ASSERTIONS (Anti-Self-Slashing Invariant):
    // 1. Shard node must set FLAG_COLLISION_DETECTED
    assert_eq!(
        resp_hdr_b.msg_type,
        MsgType::LockVerifyResponse as u16,
        "Response must be LockVerifyResponse"
    );
    assert_ne!(
        resp_hdr_b.flags & FLAG_COLLISION_DETECTED,
        0,
        "CRITICAL: Shard node MUST return FLAG_COLLISION_DETECTED for colliding Lock B"
    );

    // 2. Response payload contains existing lock (Lock A) as first-party double-spend evidence
    let existing_lock: L2LockEntry = bincode::deserialize::<L2LockEntry>(&resp_payload_b)
        .expect("Collision response payload must deserialize as the existing L2LockEntry");
    assert_eq!(
        existing_lock.t_id, tx_hash_a,
        "Existing lock in collision evidence must be Lock A (tx_hash_a)"
    );

    // 3. Shard node NEVER returned or signed an attestation for Lock B!
    let forged_attestation_b = AttestationDto::from_wire_bytes(&resp_payload_b);
    assert!(
        forged_attestation_b.is_none(),
        "CRITICAL: Shard node must NEVER return or sign an attestation for colliding Lock B"
    );

    // 4. Shard node banned the equivocating sender
    let wallet_sender_pub = sender_key.verifying_key().to_bytes();
    assert!(
        engine.is_node_banned(&wallet_sender_pub).await,
        "Shard node must ban the double-spending sender"
    );

    // -----------------------------------------------------------------------
    // Step 4: Repeating Lock B is still strictly rejected
    // -----------------------------------------------------------------------
    let digest_b_retry = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pubkey,
        0,
        3,
        now,
        footprint.saturating_mul(3),
        0,
        footprint,
        false,
        &tx_hash_b,
    );
    let sender_sig_b_retry = client_identity
        .signing_key()
        .sign(&digest_b_retry)
        .to_bytes();

    let wire_payload_b_retry = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_b_req.clone(),
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 3,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: footprint.saturating_mul(3),
        declared_read_ema_credits: 0,
        sender_pubkey,
        sender_signature: sender_sig_b_retry,
        timestamp_ms: now,
    })
    .expect("serialize wire payload b retry");

    let header_b_retry = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        4,
        0,
        0,
        wire_payload_b_retry.len() as u32,
    );

    let (resp_hdr_b_retry, resp_payload_b_retry) = client_transport
        .send_request(&conn, &header_b_retry, &wire_payload_b_retry)
        .await
        .expect("send lock b retry");
    assert!(
        (resp_hdr_b_retry.flags & FLAG_COLLISION_DETECTED) != 0
            || (resp_hdr_b_retry.flags & humoco_sim_core::wire::FLAG_PEER_SUSPENDED) != 0,
        "Repeated Lock B must return FLAG_COLLISION_DETECTED or FLAG_PEER_SUSPENDED"
    );
    assert!(
        AttestationDto::from_wire_bytes(&resp_payload_b_retry).is_none(),
        "Repeated Lock B must NEVER receive an attestation"
    );

    // Shard RAM index strictly preserves Lock A only
    let ram_lock = engine.get_hmc_ram_lock(&parent_hex).await;
    assert_eq!(
        ram_lock.map(|e| e.t_id),
        Some(tx_hash_a),
        "Shard RAM index must still hold Lock A, never Lock B"
    );

    // Cleanup
    shard_cancel.cancel();
    shard_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_s07_01_wire_high_bit_mutated_proof_rejected_honest_subject_unbanned() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("s07_01.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let shard_identity = NodeIdentity::generate();
    let client_identity = NodeIdentity::generate();
    let honest_subject = NodeIdentity::generate();

    let shard_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let shard_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    shard_pm.set_simulation_mode(true);
    let client_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    client_pm.set_simulation_mode(true);

    // Register client as F2F friend on shard
    shard_pm
        .register_f2f_friend(
            *client_identity.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

    // Honest subject is known and active in shard_pm
    shard_pm
        .learn_node_from_gossip_with_hrw(
            *honest_subject.node_pubkey(),
            *honest_subject.hrw_routing_id(),
            "127.0.0.1:2".parse().unwrap(),
            0,
            None,
        )
        .await;
    shard_pm
        .set_first_seen_for_test(
            honest_subject.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;

    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            shard_identity.clone(),
            shard_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(readiness.clone()),
    );

    let shard_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &shard_identity,
        shard_pm.clone(),
        handler,
        shard_cancel.clone(),
    )
    .expect("bind shard transport");
    let shard_addr = shard_transport.local_addr().expect("shard local addr");
    shard_transport.spawn_accept_loop();

    let client_dummy_handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            client_identity.clone(),
            client_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_identity,
        client_pm.clone(),
        client_dummy_handler,
        client_cancel.clone(),
    )
    .expect("bind client transport");
    let client_addr = client_transport.local_addr().expect("client local addr");
    client_transport.spawn_accept_loop();

    shard_pm
        .register_f2f_friend(*client_identity.node_pubkey(), Some(client_addr))
        .await;
    client_pm
        .register_f2f_friend(*shard_identity.node_pubkey(), Some(shard_addr))
        .await;

    let conn = client_transport
        .connect_peer(shard_addr)
        .await
        .expect("connect client to shard");

    // Construct V2 envelopes for honest subject, then high-bit mutate p1's epoch_seq
    let now = test_now_ms();
    let p1 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        honest_subject.signing_key(),
        1,
        10,
        now,
        50_000,
        0,
        100,
        false,
        [0x11; 32],
    );
    let p2 = humoco_sim_core::fraud::sign_ingress_evidence_with_key(
        honest_subject.signing_key(),
        1,
        11,
        now + 10,
        40_000,
        0,
        100,
        false,
        [0x22; 32],
    );

    let mut p1_high_bit = p1;
    p1_high_bit.epoch_seq = (1u64 << 32) + 1;

    let forged_proof = humoco_sim_core::fraud::FraudProofPayload::new_ingress_counter_conflict(
        p1_high_bit,
        p2,
    );
    let proof_bytes = bincode::serialize(&forged_proof).expect("serialize proof");
    let evidence_hash = *blake3::hash(&proof_bytes).as_bytes();

    let hdr = WireHeader::new(
        MsgType::EquivocationProof as u16,
        1,
        0,
        0,
        proof_bytes.len() as u32,
    );

    let (resp_hdr, _) = client_transport
        .send_request(&conn, &hdr, &proof_bytes)
        .await
        .expect("send equivocation proof");

    assert_eq!(
        resp_hdr.msg_type,
        MsgType::EquivocationAck as u16,
        "Transport layer acknowledges receipt of proof message"
    );

    // CRITICAL ASSERTIONS:
    // 1. Honest subject remains unbanned
    assert!(
        !engine.is_node_banned(honest_subject.node_pubkey()).await,
        "Honest subject must not be banned in engine"
    );
    assert!(
        !shard_pm.is_banned(honest_subject.node_pubkey()).await,
        "Honest subject must not be banned in PeerManager"
    );
    assert!(
        !storage
            .is_node_banned(honest_subject.node_pubkey())
            .expect("check ban"),
        "Honest subject must not be banned in storage"
    );

    // 2. Routing identity remains eligible
    assert!(
        !shard_pm.is_banned(honest_subject.node_pubkey()).await,
        "Honest subject routing identity must remain eligible"
    );

    // 3. No accepted fraud evidence is committed to storage
    assert!(
        storage
            .get_evidence(&evidence_hash)
            .expect("get evidence")
            .is_none(),
        "Mutated fraud proof must not be committed to redb storage"
    );

    shard_cancel.cancel();
    shard_transport.close();
    client_cancel.cancel();
    client_transport.close();
}

#[tokio::test]
async fn test_s07_02_wire_quic_v2_ingress_accounting_refusal_vs_under_reporting_fraud() {
    let temp = tempdir().expect("tempdir");
    let storage = Arc::new(RedbStorage::open(&temp.path().join("s07_02.redb")).expect("open redb"));
    let (engine, _worker) = DualTierEngine::new(storage.clone());

    let pow = Arc::new(humoco_node::ingress::PowEngine::new([0x42; 32], 8));
    let tier_controller = Arc::new(humoco_node::ingress::TierController::new(
        storage.clone(),
        pow,
    ));

    let shard_identity = NodeIdentity::generate();
    let fraud_client = NodeIdentity::generate();
    let quota_client = NodeIdentity::generate();

    let shard_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let shard_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    shard_pm.set_simulation_mode(true);
    let client_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    client_pm.set_simulation_mode(true);

    shard_pm
        .register_f2f_friend(
            *fraud_client.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;
    shard_pm
        .register_f2f_friend(
            *quota_client.node_pubkey(),
            Some("127.0.0.1:2".parse().expect("addr")),
        )
        .await;

    let readiness = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    shard_pm
        .learn_node_from_gossip_with_hrw(
            *shard_identity.node_pubkey(),
            *shard_identity.hrw_routing_id(),
            "127.0.0.1:1".parse().unwrap(),
            0,
            None,
        )
        .await;
    shard_pm
        .set_first_seen_for_test(
            shard_identity.node_pubkey(),
            std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
        )
        .await;

    let handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            shard_identity.clone(),
            shard_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true)))
        .with_readiness_manager(readiness.clone())
        .with_tier_controller(tier_controller.clone()),
    );

    let shard_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &shard_identity,
        shard_pm.clone(),
        handler,
        shard_cancel.clone(),
    )
    .expect("bind shard transport");
    let shard_addr = shard_transport.local_addr().expect("shard local addr");
    shard_transport.spawn_accept_loop();

    let client_dummy_handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            fraud_client.clone(),
            client_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &fraud_client,
        client_pm.clone(),
        client_dummy_handler,
        client_cancel.clone(),
    )
    .expect("bind client transport");
    let client_addr = client_transport.local_addr().expect("client local addr");
    client_transport.spawn_accept_loop();

    shard_pm
        .register_f2f_friend(*fraud_client.node_pubkey(), Some(client_addr))
        .await;
    client_pm
        .register_f2f_friend(*shard_identity.node_pubkey(), Some(shard_addr))
        .await;

    let conn = client_transport
        .connect_peer(shard_addr)
        .await
        .expect("connect client to shard");

    // Anchor genesis lock on shard
    let sender_key = SigningKey::from_bytes(&[3u8; 32]);
    let now = test_now_ms();
    let genesis_req = make_hmc_genesis("v2_accounting_genesis", now + 1_000_000, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let (_v_gen, _) = engine
        .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
        .await;

    // -----------------------------------------------------------------------
    // Part 1: Proven Incompatible Under-Reporting Claim -> Slashing / Ban
    // -----------------------------------------------------------------------
    let parent_hex_1 = hex::encode([0x81u8; 32]);
    let tx_hash_1 = *blake3::hash(b"tx_hash_honest_1").as_bytes();
    let lock_1 = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex_1,
        tx_hash_1,
        now + 900_000,
        &sender_key,
    );
    let root_valid_until = now + 1_000_000;
    let ttl_s = root_valid_until.saturating_sub(now) / 1000;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

    // Initial valid sequenced envelope for fraud_client
    let fraud_pub = *fraud_client.node_pubkey();
    let digest_1 = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &fraud_pub,
        1,
        1,
        now,
        50_000,
        0,
        footprint,
        false,
        &tx_hash_1,
    );
    let sig_1 = fraud_client.signing_key().sign(&digest_1).to_bytes();
    let wire_payload_1 = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_1,
        chain: None,
        root_valid_until,
        epoch_day: 1,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 50_000,
        declared_read_ema_credits: 0,
        sender_pubkey: fraud_pub,
        sender_signature: sig_1,
        timestamp_ms: now,
    })
    .expect("serialize wire payload 1");

    let hdr_1 = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, wire_payload_1.len() as u32);
    let (resp_hdr_1, _) = client_transport.send_request(&conn, &hdr_1, &wire_payload_1).await.expect("send req 1");
    assert_eq!(resp_hdr_1.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0);

    // Second request: under-reporting claim (epoch_seq = 2, now + 10_000ms, declared_write_ema = 1000 << 50_000)
    let parent_hex_2 = hex::encode([0x82u8; 32]);
    let tx_hash_2 = *blake3::hash(b"tx_hash_under_report_2").as_bytes();
    let lock_2 = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex_2,
        tx_hash_2,
        now + 900_000,
        &sender_key,
    );
    let ttl_s_2 = root_valid_until.saturating_sub(now + 10_000) / 1000;
    let footprint_2 = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s_2);
    let digest_2 = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &fraud_pub,
        1,
        2,
        now + 10_000,
        1_000,
        0,
        footprint_2,
        false,
        &tx_hash_2,
    );
    let sig_2 = fraud_client.signing_key().sign(&digest_2).to_bytes();
    let wire_payload_2 = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_2,
        chain: None,
        root_valid_until,
        epoch_day: 1,
        epoch_seq: 2,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 1_000,
        declared_read_ema_credits: 0,
        sender_pubkey: fraud_pub,
        sender_signature: sig_2,
        timestamp_ms: now + 10_000,
    })
    .expect("serialize wire payload 2");

    let hdr_2 = WireHeader::new(MsgType::LockVerifyRequest as u16, 2, 0, 0, wire_payload_2.len() as u32);
    let (resp_hdr_2, _) = client_transport.send_request(&conn, &hdr_2, &wire_payload_2).await.expect("send req 2");

    // Under-reporting MUST set FLAG_QUOTA_FRAUD, FLAG_PEER_SUSPENDED, and ban the sender
    assert_ne!(
        resp_hdr_2.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD,
        0,
        "Under-reporting must set FLAG_QUOTA_FRAUD"
    );
    assert_ne!(
        resp_hdr_2.flags & humoco_sim_core::wire::FLAG_PEER_SUSPENDED,
        0,
        "Under-reporting must set FLAG_PEER_SUSPENDED"
    );
    assert!(
        engine.is_node_banned(&fraud_pub).await,
        "Perpetrator of under-reporting must be banned in engine"
    );
    assert!(
        shard_pm.is_banned(&fraud_pub).await,
        "Perpetrator of under-reporting must be banned in PeerManager"
    );

    // -----------------------------------------------------------------------
    // Part 2: Neutral Quota Refusal (Exceeded Daily Budget, No Fraud Claim)
    // -----------------------------------------------------------------------
    let quota_pub = *quota_client.node_pubkey();
    let epoch_day = tier_controller.current_epoch_day_at(now);
    // Exhaust quota_client's daily write allowance in tier_controller
    let daily_limit = tier_controller.calculate_daily_quota(humoco_sim_core::MAX_WHALE_MULTIPLIER, 1.0);
    tier_controller
        .evaluate_node_write_quota(&quota_pub, daily_limit, epoch_day)
        .expect("initial quota reservation");

    // Quota client sends honest envelope with legitimate sequence progression (no under-reporting)
    let parent_hex_3 = hex::encode([0x83u8; 32]);
    let tx_hash_3 = *blake3::hash(b"tx_hash_honest_quota_exceeded").as_bytes();
    let lock_3 = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex_3,
        tx_hash_3,
        now + 900_000,
        &sender_key,
    );
    let digest_3 = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &quota_pub,
        1,
        1,
        now,
        50_000,
        0,
        footprint,
        false,
        &tx_hash_3,
    );
    let sig_3 = quota_client.signing_key().sign(&digest_3).to_bytes();
    let wire_payload_3 = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_3,
        chain: None,
        root_valid_until,
        epoch_day: 1,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 50_000,
        declared_read_ema_credits: 0,
        sender_pubkey: quota_pub,
        sender_signature: sig_3,
        timestamp_ms: now,
    })
    .expect("serialize wire payload 3");

    // Client sends request using quota_client identity
    let quota_client_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    quota_client_pm.set_simulation_mode(true);
    quota_client_pm
        .register_f2f_friend(*shard_identity.node_pubkey(), Some(shard_addr))
        .await;

    let client_dummy_handler_q = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            quota_client.clone(),
            quota_client_pm.clone(),
        )
        .with_sync_ready(Arc::new(AtomicBool::new(true))),
    );
    let quota_client_cancel = CancellationToken::new();
    let quota_client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &quota_client,
        quota_client_pm.clone(),
        client_dummy_handler_q,
        quota_client_cancel.clone(),
    )
    .expect("bind quota client");
    let quota_addr = quota_client_transport.local_addr().expect("quota client addr");
    quota_client_transport.spawn_accept_loop();
    shard_pm.register_f2f_friend(quota_pub, Some(quota_addr)).await;

    let conn_q = quota_client_transport
        .connect_peer(shard_addr)
        .await
        .expect("connect quota client to shard");

    let hdr_3 = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, wire_payload_3.len() as u32);
    let (resp_hdr_3, _) = quota_client_transport.send_request(&conn_q, &hdr_3, &wire_payload_3).await.expect("send req 3");

    // Neutral quota refusal:
    // 1. FLAG_QUOTA_EXCEEDED is set
    assert_ne!(
        resp_hdr_3.flags & humoco_sim_core::wire::FLAG_QUOTA_EXCEEDED,
        0,
        "Neutral quota refusal must set FLAG_QUOTA_EXCEEDED"
    );
    // 2. FLAG_QUOTA_FRAUD and FLAG_PEER_SUSPENDED are NOT set
    assert_eq!(
        resp_hdr_3.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD,
        0,
        "Neutral quota refusal must NOT set FLAG_QUOTA_FRAUD"
    );
    assert_eq!(
        resp_hdr_3.flags & humoco_sim_core::wire::FLAG_PEER_SUSPENDED,
        0,
        "Neutral quota refusal must NOT set FLAG_PEER_SUSPENDED"
    );
    // 3. Sender is NOT banned
    assert!(
        !engine.is_node_banned(&quota_pub).await,
        "Neutral quota refusal must NOT ban the sender in engine"
    );
    assert!(
        !shard_pm.is_banned(&quota_pub).await,
        "Neutral quota refusal must NOT ban the sender in PeerManager"
    );
    assert!(
        !storage.is_node_banned(&quota_pub).expect("check ban"),
        "Neutral quota refusal must NOT ban the sender in storage"
    );

    shard_cancel.cancel();
    shard_transport.close();
    client_cancel.cancel();
    client_transport.close();
    quota_client_cancel.cancel();
    quota_client_transport.close();
}
