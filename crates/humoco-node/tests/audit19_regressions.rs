#![forbid(unsafe_code)]

//! Audit 19 Regressions (Wire-level Quota and Adversarial Verification)
//!
//! Covers:
//! - A19-01: Root-derived receiver accounting (P2)
//! - A19-03: Neutral quota feedback without peer presence penalty (P2)
//! - A19-02: QUIC receiver coverage for quota, declared limits, identity binding, and framing (P2)
//! - W4: P2P quota isolation by full NodePubKey (P2)

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest};
use humoco_node::daemon::ShardReadinessManager;
use humoco_node::identity::NodeIdentity;
use humoco_node::ingress::{PowEngine, TierController};
use humoco_node::network::framing::LockWirePayload;
use humoco_node::network::pool::PeerConnectionLease;
use humoco_node::network::{NodeRequestHandler, PeerManager, QuicTransport};
use humoco_node::storage::{DualTierEngine, RedbStorage};
use humoco_sim_core::fraud::sign_ingress_evidence_with_key;
use humoco_sim_core::quota::ByteYears;
use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_QUOTA_EXCEEDED, FLAG_UNAUTHORIZED};

fn test_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_test_genesis(
    voucher_id: &str,
    valid_until_ms: u64,
    signing_key: &SigningKey,
) -> L2LockRequest {
    let pubkey = signing_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(voucher_id.as_bytes()).as_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: pubkey,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: pubkey,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = signing_key.sign(&payload_hash).to_bytes();
    req
}

fn make_test_spend(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    valid_until_ms: u64,
    signing_key: &SigningKey,
) -> L2LockRequest {
    let pubkey = signing_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: pubkey,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(parent_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: pubkey,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = signing_key.sign(&payload_hash).to_bytes();
    req
}

/// Helper to set up a QUIC shard node with TierController attached.
async fn setup_quic_shard_and_client() -> (
    Arc<DualTierEngine>,
    Arc<TierController>,
    Arc<ShardReadinessManager>,
    NodeIdentity,
    QuicTransport,
    std::net::SocketAddr,
    NodeIdentity,
    QuicTransport,
    PeerConnectionLease,
    CancellationToken,
    CancellationToken,
) {
    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("audit19.redb")).expect("open redb"));
    let (engine_raw, _worker) = DualTierEngine::new(storage.clone());
    let engine = Arc::new(engine_raw);
    let pow = Arc::new(PowEngine::new([0x42; 32], 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow));

    let shard_identity = NodeIdentity::generate();
    let client_identity = NodeIdentity::generate();

    let shard_cancel = CancellationToken::new();
    let client_cancel = CancellationToken::new();

    let shard_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let client_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));

    // Authorize client on shard node
    shard_pm
        .register_f2f_friend(
            *client_identity.node_pubkey(),
            Some("127.0.0.1:1".parse().expect("addr")),
        )
        .await;

    let readiness = Arc::new(ShardReadinessManager::new());
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
            (*engine).clone(),
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
    shard_transport.set_sync_ready(true);
    let shard_addr = shard_transport.local_addr().expect("shard local addr");
    shard_transport.spawn_accept_loop();

    let client_dummy_handler = Arc::new(
        NodeRequestHandler::with_peer_manager(
            (*engine).clone(),
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

    (
        engine,
        tier_controller,
        readiness,
        shard_identity,
        shard_transport,
        shard_addr,
        client_identity,
        client_transport,
        conn,
        shard_cancel,
        client_cancel,
    )
}

// ---------------------------------------------------------------------------
// A19-01: Root-derived receiver accounting over QUIC
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a19_01_root_derived_receiver_accounting_over_quic() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        engine,
        _tier_controller,
        readiness,
        _shard_id,
        _shard_trans,
        _shard_addr,
        client_id,
        client_trans,
        conn,
        _sc,
        _cc,
    ) = setup_quic_shard_and_client().await;

    let voucher_id = "v_audit19_01";
    let now = test_now_ms();
    // Genuine voucher root expires in 100,000 seconds (~28h)
    let auth_root_valid_until = now + 100_000_000;
    let sender_key = SigningKey::from_bytes(&[7u8; 32]);

    // 1. Anchor genuine genesis voucher root on shard
    let genesis_req = make_test_genesis(voucher_id, auth_root_valid_until, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let (v, is_new) = engine
        .ingress_hmc_lock_durable(
            genesis_tag.clone(),
            L2LockEntry::from(&genesis_req),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;
    assert!(is_new, "genesis anchor must succeed");
    assert!(matches!(
        v,
        humoco_node::api::hmc::L2Verdict::Verified { .. }
    ));

    // Verify stored root validity is exact
    let stored_root = engine.get_hmc_voucher_root_valid(voucher_id).await;
    assert_eq!(stored_root, Some(auth_root_valid_until));

    // 2. Prepare child spend on parent genesis_tag
    let child_key = SigningKey::from_bytes(&[8u8; 32]);
    let child_req = make_test_spend(
        voucher_id,
        &genesis_tag,
        [0x99; 32],
        auth_root_valid_until,
        &child_key,
    );

    // Case A: Positive control - matching wire lifetime and sufficient budget
    {
        let ttl_s = auth_root_valid_until.saturating_sub(now) / 1000;
        let base_fp = ByteYears::micro_from_ttl_seconds(ttl_s);
        let evidence = sign_ingress_evidence_with_key(
            client_id.signing_key(),
            0,
            1,
            now,
            0,
            0,
            base_fp,
            false,
            child_req.transaction_hash,
        );

        let payload = bincode::serialize(&LockWirePayload::Hmc {
            req: child_req.clone(),
            chain: None,
            root_valid_until: auth_root_valid_until, // Exactly matches authenticated root
            epoch_day: 0,
            epoch_seq: 1,
            cumulative_micro_byte_years: 0,
            prev_day_final_bytes: 0,
            current_anl_24h: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            sender_pubkey: *client_id.node_pubkey(),
            sender_signature: evidence.signature,
            timestamp_ms: now,
        })
        .unwrap();

        let req_header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            0,
            0,
            payload.len() as u32,
        );
        let (resp_header, _resp_bytes) = client_trans
            .send_request(&conn, &req_header, &payload)
            .await
            .expect("send request");
        assert_eq!(
            resp_header.flags, 0,
            "Positive control with matching lifetime must be accepted (flags 0)"
        );
    }

    // Case B: A19-01 defect assertion - gateway claims shortened lifetime (e.g. now + 10s)
    // while spending from the 100,000s root.
    // In unfixed code: this is accepted (flags 0), evading Byte-Years accounting!
    // In fixed code: receiver MUST reject this mismatch with FLAG_UNAUTHORIZED.
    {
        let voucher_id_b = "v_audit19_01_b";
        let genesis_req_b = make_test_genesis(voucher_id_b, auth_root_valid_until, &sender_key);
        let genesis_tag_b = bs58::encode(&genesis_req_b.transaction_hash).into_string();
        let parent_b = *blake3::hash(genesis_tag_b.as_bytes()).as_bytes();
        let shard_b = humoco_sim_core::types::extract_shard_id(&parent_b);
        engine
            .record_hmc_voucher_genesis_parent(&genesis_req_b.layer2_voucher_id, parent_b)
            .await;
        readiness.mark_shard_ready(shard_b);

        let (v_b, is_new_b) = engine
            .ingress_hmc_lock_durable(
                genesis_tag_b.clone(),
                L2LockEntry::from(&genesis_req_b),
                humoco_node::storage::IngressOrigin::ClientApi,
                Some(now),
                None,
                None,
                None,
            )
            .await;
        assert!(is_new_b);
        assert!(matches!(
            v_b,
            humoco_node::api::hmc::L2Verdict::Verified { .. }
        ));

        let child_key_b = SigningKey::from_bytes(&[9u8; 32]);
        let child_req_b = make_test_spend(
            voucher_id_b,
            &genesis_tag_b,
            [0x88; 32],
            auth_root_valid_until,
            &child_key_b,
        );
        let fake_short_valid_until = now + 10_000; // Only 10s claimed on wire!
        let fake_ttl_s = fake_short_valid_until.saturating_sub(now) / 1000;
        let fake_fp = ByteYears::micro_from_ttl_seconds(fake_ttl_s);
        let evidence = sign_ingress_evidence_with_key(
            client_id.signing_key(),
            0,
            2,
            now,
            0,
            0,
            fake_fp,
            false,
            child_req_b.transaction_hash,
        );

        let payload = bincode::serialize(&LockWirePayload::Hmc {
            req: child_req_b.clone(),
            chain: None,
            root_valid_until: fake_short_valid_until, // Undercharging lifetime claim!
            epoch_day: 0,
            epoch_seq: 2,
            cumulative_micro_byte_years: 0,
            prev_day_final_bytes: 0,
            current_anl_24h: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            sender_pubkey: *client_id.node_pubkey(),
            sender_signature: evidence.signature,
            timestamp_ms: now,
        })
        .unwrap();

        let req_header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            2,
            0,
            0,
            payload.len() as u32,
        );
        let (resp_header, _resp_bytes) = client_trans
            .send_request(&conn, &req_header, &payload)
            .await
            .expect("send request");
        assert_ne!(
            resp_header.flags, 0,
            "A19-01 RED check: Shortened wire lifetime claim MUST NOT be accepted (must not have flags 0)"
        );
        assert!(
            (resp_header.flags & FLAG_UNAUTHORIZED) != 0,
            "Shortened wire lifetime must be rejected with FLAG_UNAUTHORIZED, got flags {:x}",
            resp_header.flags
        );
    }
}

// ---------------------------------------------------------------------------
// A19-03 & A07-02: Neutral quota and readiness feedback via real QUIC collector
// (FLAG_QUOTA_EXCEEDED in all 3 zones + merge moratorium and FLAG_NOT_READY
// remain strictly neutral with missing_count == 0, is_suspended == false,
// while a forged signature triggers missing_count == 1 as control case).
// ---------------------------------------------------------------------------
struct QuotaCollectorMockHandler {
    mode: std::sync::atomic::AtomicU8,
    peer_identity: NodeIdentity,
    lock_id: [u8; 32],
    parent_lock: [u8; 32],
    shard_id: u16,
}

impl QuotaCollectorMockHandler {
    const MODE_QUOTA_EXCEEDED: u8 = 0;
    const MODE_NOT_READY: u8 = 1;
    const MODE_FORGED_SIGNATURE: u8 = 2;
}

impl humoco_node::network::RequestHandler for QuotaCollectorMockHandler {
    fn handle_authenticated(
        &self,
        _header: WireHeader,
        _payload: Vec<u8>,
        _peer_identity: Option<[u8; 32]>,
    ) -> humoco_node::network::BoxFuture<Result<(WireHeader, Vec<u8>), humoco_node::NodeError>>
    {
        let mode = self.mode.load(std::sync::atomic::Ordering::SeqCst);
        let peer_pubkey = *self.peer_identity.node_pubkey();
        let lock_id = self.lock_id;
        let parent_lock = self.parent_lock;
        let shard_id = self.shard_id;
        Box::pin(async move {
            match mode {
                Self::MODE_QUOTA_EXCEEDED => {
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        1,
                        0,
                        FLAG_QUOTA_EXCEEDED,
                        0,
                    );
                    Ok((resp_header, Vec::new()))
                }
                Self::MODE_NOT_READY => {
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        1,
                        0,
                        humoco_sim_core::wire::FLAG_NOT_READY,
                        0,
                    );
                    Ok((resp_header, Vec::new()))
                }
                Self::MODE_FORGED_SIGNATURE => {
                    let fake_att = humoco_node::AttestationDto {
                        lock_id: hex::encode(lock_id),
                        parent_lock: hex::encode(parent_lock),
                        node_id: u16::from_le_bytes([peer_pubkey[0], peer_pubkey[1]]),
                        node_pubkey: hex::encode(peer_pubkey),
                        timestamp: 1_000,
                        signature: hex::encode([0xee; 64]), // forged invalid signature
                        shard_id,
                    };
                    let wire_bytes = bincode::serialize(&fake_att)
                        .map_err(|e| humoco_node::NodeError::Network(e.to_string()))?;
                    let resp_header = WireHeader::new(
                        MsgType::LockVerifyResponse as u16,
                        1,
                        0,
                        0,
                        wire_bytes.len() as u32,
                    );
                    Ok((resp_header, wire_bytes))
                }
                _ => Err(humoco_node::NodeError::Network("unsupported mode".into())),
            }
        })
    }
}

#[tokio::test]
async fn test_a19_03_neutral_quota_feedback_does_not_penalize_peer() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let client_id = NodeIdentity::generate();
    let client_cancel = CancellationToken::new();
    let client_pm = Arc::new(PeerManager::new(Vec::new()));
    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &client_id,
        client_pm.clone(),
        Arc::new(humoco_node::network::DefaultRequestHandler),
        client_cancel.clone(),
    )
    .expect("bind client transport");
    let client_addr = client_transport.local_addr().expect("client addr");
    client_transport.set_sync_ready(true);
    client_transport.spawn_accept_loop();

    let peer_id = NodeIdentity::generate();
    let peer_cancel = CancellationToken::new();
    let peer_pm = Arc::new(PeerManager::new(Vec::new()));
    let parent_lock = [0x22; 32];
    let lock_id = [0x33; 32];
    let shard_id = u16::from_be_bytes([parent_lock[0], parent_lock[1]]);
    let mock_handler = Arc::new(QuotaCollectorMockHandler {
        mode: std::sync::atomic::AtomicU8::new(QuotaCollectorMockHandler::MODE_QUOTA_EXCEEDED),
        peer_identity: peer_id.clone(),
        lock_id,
        parent_lock,
        shard_id,
    });
    let peer_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().expect("addr"),
        &peer_id,
        peer_pm.clone(),
        mock_handler.clone(),
        peer_cancel.clone(),
    )
    .expect("bind peer transport");
    let peer_addr = peer_transport.local_addr().expect("peer addr");
    peer_transport.set_sync_ready(true);
    peer_transport.spawn_accept_loop();

    // Mutual F2F friendship enables TLS-authenticated QUIC connection
    client_pm
        .register_f2f_friend(*peer_id.node_pubkey(), Some(peer_addr))
        .await;
    peer_pm
        .register_f2f_friend(*client_id.node_pubkey(), Some(client_addr))
        .await;

    // Verify initial peer failure metrics
    let initial_peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
    assert_eq!(initial_peer.missing_count, 0);
    assert!(!initial_peer.is_suspended());

    let dummy_req = make_test_genesis(
        "v_quota_test",
        test_now_ms() + 10_000_000,
        &SigningKey::from_bytes(&[12u8; 32]),
    );
    let dummy_payload = bincode::serialize(&LockWirePayload::Hmc {
        req: dummy_req,
        chain: None,
        root_valid_until: test_now_ms() + 10_000_000,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: [0u8; 32],
        sender_signature: [0u8; 64],
        timestamp_ms: 0,
    })
    .expect("payload serialize");

    let candidates = [(*peer_id.node_pubkey(), peer_addr)];
    let expected_members = [*peer_id.node_pubkey()];

    // 1. Zone 1: Apparent under-load / FraudulentRejection outside merge moratorium
    // my_load = 100 < 75% of 10_000 -> evaluate_quota_exceeded_claim yields FraudulentRejection
    mock_handler.mode.store(
        QuotaCollectorMockHandler::MODE_QUOTA_EXCEEDED,
        std::sync::atomic::Ordering::SeqCst,
    );
    {
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
            payload: &dummy_payload,
            target_status: 1,
            lock_id,
            shard_id,
            required_q: 1,
            shard_query_depth: 1,
            my_load: 100,
            quota_limit: 10_000,
            network_id: humoco_sim_core::types::NetworkId::Testnet,
            checkout_deadline: None,
        };
        let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;
        let peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
        assert_eq!(
            peer.missing_count, 0,
            "Zone 1 (FraudulentRejection): quota feedback must remain strictly neutral"
        );
        assert!(!peer.is_suspended());
    }

    // 2. Zone 2: BoundaryCutoff (75%..125% of quota_limit)
    // my_load = 8_000 (80% of 10_000) -> evaluate_quota_exceeded_claim yields BoundaryCutoff
    {
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
            payload: &dummy_payload,
            target_status: 1,
            lock_id,
            shard_id,
            required_q: 1,
            shard_query_depth: 1,
            my_load: 8_000,
            quota_limit: 10_000,
            network_id: humoco_sim_core::types::NetworkId::Testnet,
            checkout_deadline: None,
        };
        let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;
        let peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
        assert_eq!(
            peer.missing_count, 0,
            "Zone 2 (BoundaryCutoff): quota feedback must remain strictly neutral"
        );
        assert!(!peer.is_suspended());
    }

    // 3. Zone 3: LegitimateOverload (> 125% of quota_limit)
    // my_load = 15_000 (150% of 10_000) -> evaluate_quota_exceeded_claim yields LegitimateOverload
    {
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
            payload: &dummy_payload,
            target_status: 1,
            lock_id,
            shard_id,
            required_q: 1,
            shard_query_depth: 1,
            my_load: 15_000,
            quota_limit: 10_000,
            network_id: humoco_sim_core::types::NetworkId::Testnet,
            checkout_deadline: None,
        };
        let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;
        let peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
        assert_eq!(
            peer.missing_count, 0,
            "Zone 3 (LegitimateOverload): quota feedback must remain strictly neutral"
        );
        assert!(!peer.is_suspended());
    }

    // 4. Merge-Moratorium: 24h window post-partition-merge (INV-0908)
    client_pm.note_merge_detected(client_pm.net_time_ms());
    assert!(
        client_pm.is_in_merge_hysteresis(client_pm.net_time_ms()),
        "Merge moratorium must be active"
    );
    {
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
            payload: &dummy_payload,
            target_status: 1,
            lock_id,
            shard_id,
            required_q: 1,
            shard_query_depth: 1,
            my_load: 100,
            quota_limit: 10_000,
            network_id: humoco_sim_core::types::NetworkId::Testnet,
            checkout_deadline: None,
        };
        let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;
        let peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
        assert_eq!(
            peer.missing_count, 0,
            "Merge Moratorium: quota rejection must not penalize peer"
        );
        assert!(!peer.is_suspended());
    }

    // 5. FLAG_NOT_READY: Shard is recovering or unready (neutral abstention)
    mock_handler.mode.store(
        QuotaCollectorMockHandler::MODE_NOT_READY,
        std::sync::atomic::Ordering::SeqCst,
    );
    {
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
            payload: &dummy_payload,
            target_status: 1,
            lock_id,
            shard_id,
            required_q: 1,
            shard_query_depth: 1,
            my_load: 100,
            quota_limit: 10_000,
            network_id: humoco_sim_core::types::NetworkId::Testnet,
            checkout_deadline: None,
        };
        let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;
        let peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
        assert_eq!(
            peer.missing_count, 0,
            "FLAG_NOT_READY must remain strictly neutral (missing_count == 0)"
        );
        assert!(!peer.is_suspended());
    }

    // 6. Control Case: Forged signature MUST trigger record_failure -> missing_count == 1
    mock_handler.mode.store(
        QuotaCollectorMockHandler::MODE_FORGED_SIGNATURE,
        std::sync::atomic::Ordering::SeqCst,
    );
    {
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
            payload: &dummy_payload,
            target_status: 1,
            lock_id,
            shard_id,
            required_q: 1,
            shard_query_depth: 1,
            my_load: 100,
            quota_limit: 10_000,
            network_id: humoco_sim_core::types::NetworkId::Testnet,
            checkout_deadline: None,
        };
        let _ = humoco_node::collect_peer_attestations(query, &mut collected).await;
        let peer = client_pm.get_peer(&peer_addr).await.expect("peer present");
        assert_eq!(
            peer.missing_count, 1,
            "Control case: forged signature MUST increment missing_count to 1"
        );
        assert!(!peer.is_suspended());
    }
}

// ---------------------------------------------------------------------------
// A19-02: QUIC receiver coverage for declared limits and TLS identity binding
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a19_02_quic_receiver_declared_limit_and_identity_binding() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        _engine,
        _tier_controller,
        _readiness,
        _shard_id,
        _shard_trans,
        _shard_addr,
        client_id,
        client_trans,
        conn,
        _sc,
        _cc,
    ) = setup_quic_shard_and_client().await;

    let now = test_now_ms();
    let sender_key = SigningKey::from_bytes(&[11u8; 32]);
    let req = make_test_genesis("v_audit19_02", now + 10_000_000, &sender_key);

    // Subtest 1: Declared write EMA exceeds 5x Whale Brake
    // write_limit is 5.0 * ncb_eff (960_000 * 5 = 4_800_000)
    // declared daily rate = ema / 1_000_000
    // If declared_write_ema = 15_000_000_000_000 -> declared daily rate = 15_000_000 > 4_800_000
    {
        let excessive_ema = 15_000_000_000_000u64;
        let payload = bincode::serialize(&LockWirePayload::Hmc {
            req: req.clone(),
            chain: None,
            root_valid_until: now + 10_000_000,
            epoch_day: 0,
            epoch_seq: 1,
            cumulative_micro_byte_years: 0,
            prev_day_final_bytes: 0,
            current_anl_24h: excessive_ema,
            declared_write_ema_micro_bj: excessive_ema,
            declared_read_ema_credits: 0,
            sender_pubkey: *client_id.node_pubkey(),
            sender_signature: [0u8; 64],
            timestamp_ms: now,
        })
        .unwrap();

        let req_header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            10,
            0,
            0,
            payload.len() as u32,
        );
        let (resp_header, _resp_bytes) = client_trans
            .send_request(&conn, &req_header, &payload)
            .await
            .expect("send request");
        assert!(
            (resp_header.flags & FLAG_QUOTA_EXCEEDED) != 0,
            "Excessive declared rate must be rejected with FLAG_QUOTA_EXCEEDED, got {:x}",
            resp_header.flags
        );
    }

    // Subtest 2: TLS Sender Binding - claimed sender_pubkey does not match authenticated peer
    {
        let imposter_key = SigningKey::from_bytes(&[0x55u8; 32]);
        let imposter_pubkey = imposter_key.verifying_key().to_bytes();
        let evidence = sign_ingress_evidence_with_key(
            &imposter_key,
            0,
            2,
            now,
            0,
            0,
            0,
            false,
            req.transaction_hash,
        );

        let payload = bincode::serialize(&LockWirePayload::Hmc {
            req: req.clone(),
            chain: None,
            root_valid_until: now + 10_000_000,
            epoch_day: 0,
            epoch_seq: 2,
            cumulative_micro_byte_years: 0,
            prev_day_final_bytes: 0,
            current_anl_24h: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            sender_pubkey: imposter_pubkey, // Does not match client's TLS identity!
            sender_signature: evidence.signature,
            timestamp_ms: now,
        })
        .unwrap();

        let req_header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            11,
            0,
            0,
            payload.len() as u32,
        );
        let (resp_header, _resp_bytes) = client_trans
            .send_request(&conn, &req_header, &payload)
            .await
            .expect("send request");
        assert!(
            (resp_header.flags & FLAG_UNAUTHORIZED) != 0,
            "Claimed sender pubkey mismatching TLS identity must be rejected with FLAG_UNAUTHORIZED, got {:x}",
            resp_header.flags
        );
    }
}

// ---------------------------------------------------------------------------
// W4: P2P quota isolation by full NodePubKey (not truncated 16-bit prefix)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_w4_p2p_quota_isolation_by_full_nodepubkey() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let temp = tempdir().expect("tempdir");
    let storage =
        Arc::new(RedbStorage::open(&temp.path().join("w4_quota.redb")).expect("open redb"));
    let pow = Arc::new(PowEngine::new([0x42; 32], 8));
    let controller = TierController::new(storage, pow);

    // Two distinct valid 32-byte public keys sharing the first 2 bytes [0xAA, 0xBB]
    let mut key_a = [0x11u8; 32];
    key_a[0] = 0xAA;
    key_a[1] = 0xBB;

    let mut key_b = [0x22u8; 32];
    key_b[0] = 0xAA;
    key_b[1] = 0xBB;

    assert_ne!(key_a, key_b);
    assert_eq!(key_a[0..2], key_b[0..2]);

    let epoch_day = controller.current_epoch_day();
    let daily_quota = controller.calculate_daily_quota(5.0, 1.0);

    // Node A consumes its full daily quota
    let res_a = controller.evaluate_node_write_quota(&key_a, daily_quota, epoch_day);
    assert!(
        res_a.is_ok(),
        "Node A first write within budget must succeed"
    );

    // Node A is now at quota limit
    let res_a_exceeded = controller.evaluate_node_write_quota(&key_a, 10, epoch_day);
    assert!(
        res_a_exceeded.is_err(),
        "Node A additional write must exceed quota"
    );

    // Node B with same 16-bit prefix attempts a write within its own quota
    // On unfixed code: shared 16-bit key causes Node B to be blocked by Node A's usage!
    // On fixed code: P2P quota is isolated by full 32-byte NodePubKey, so Node B succeeds!
    let res_b = controller.evaluate_node_write_quota(&key_b, 100, epoch_day);
    assert!(
        res_b.is_ok(),
        "W4 RED check: Node B must NOT be blocked by Node A's quota despite sharing 16-bit prefix: got {:?}",
        res_b
    );
}

// ---------------------------------------------------------------------------
// A19-R1: Ordinary reordered and concurrent reads over QUIC never ban honest peer
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a19_r1_quic_reordered_and_concurrent_reads_never_ban() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        engine,
        _tier_controller,
        readiness,
        _shard_id,
        _shard_trans,
        _shard_addr,
        client_id,
        client_trans,
        conn,
        _sc,
        _cc,
    ) = setup_quic_shard_and_client().await;

    let now = test_now_ms();
    let auth_root_valid_until = now + 100_000_000;
    let sender_key = SigningKey::from_bytes(&[12u8; 32]);
    let genesis_req = make_test_genesis("v_a19_r1", auth_root_valid_until, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let _ = engine
        .ingress_hmc_lock_durable(
            genesis_tag.clone(),
            L2LockEntry::from(&genesis_req),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now),
            None,
            None,
            None,
        )
        .await;

    let lock_id_a = genesis_req.transaction_hash;
    let lock_id_b = *blake3::hash(b"different_lock_id_b").as_bytes();

    // 1. Send status read at T = now
    let ev1 = sign_ingress_evidence_with_key(
        client_id.signing_key(),
        0,
        0,
        now,
        0,
        0,
        0,
        true,
        lock_id_a,
    );
    let sq1 = humoco_node::network::framing::StatusQueryPayload {
        lock_id: lock_id_a,
        parent_lock: parent,
        shard_id: shard,
        sender_pubkey: *client_id.node_pubkey(),
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: 0,
        timestamp_ms: now,
        sender_signature: ev1.signature,
    };
    let payload1 = sq1.to_bytes().unwrap();
    let (resp1, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 1, 0, 0, payload1.len() as u32),
            &payload1,
        )
        .await
        .expect("send read 1");
    assert_eq!(resp1.flags, 0, "first read should succeed without error");
    assert!(!engine.is_node_banned(client_id.node_pubkey()).await);

    // 2. Send status read for a different lock at T = now - 1ms (reordered packet arrival)
    let ev2_reordered = sign_ingress_evidence_with_key(
        client_id.signing_key(),
        0,
        0,
        now.saturating_sub(1),
        0,
        0,
        0,
        true,
        lock_id_b,
    );
    let sq2 = humoco_node::network::framing::StatusQueryPayload {
        lock_id: lock_id_b,
        parent_lock: parent,
        shard_id: shard,
        sender_pubkey: *client_id.node_pubkey(),
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: 0,
        timestamp_ms: now.saturating_sub(1),
        sender_signature: ev2_reordered.signature,
    };
    let payload2 = sq2.to_bytes().unwrap();
    let (resp2, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 2, 0, 0, payload2.len() as u32),
            &payload2,
        )
        .await
        .expect("send read 2");
    assert_eq!(
        resp2.flags, 0,
        "reordered read must NOT trigger fraud ban flags (got {:x})",
        resp2.flags
    );
    assert!(
        !engine.is_node_banned(client_id.node_pubkey()).await,
        "honest sender must not be banned on reordered read"
    );

    // 3. Send concurrent status read at T = now for different lock
    let ev3_concurrent = sign_ingress_evidence_with_key(
        client_id.signing_key(),
        0,
        0,
        now,
        0,
        0,
        0,
        true,
        lock_id_b,
    );
    let sq3 = humoco_node::network::framing::StatusQueryPayload {
        lock_id: lock_id_b,
        parent_lock: parent,
        shard_id: shard,
        sender_pubkey: *client_id.node_pubkey(),
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: 0,
        timestamp_ms: now,
        sender_signature: ev3_concurrent.signature,
    };
    let payload3 = sq3.to_bytes().unwrap();
    let (resp3, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(MsgType::StatusQuery as u16, 3, 0, 0, payload3.len() as u32),
            &payload3,
        )
        .await
        .expect("send read 3");
    assert_eq!(resp3.flags, 0);
    assert!(!engine.is_node_banned(client_id.node_pubkey()).await);
}

// ---------------------------------------------------------------------------
// A19-R2: Exact wire retries succeed idempotently and are not charged repeatedly
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a19_r2_exact_wire_retry_at_quota_boundary() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        engine,
        tier_controller,
        readiness,
        _shard_id,
        _shard_trans,
        _shard_addr,
        client_id,
        client_trans,
        conn,
        _sc,
        _cc,
    ) = setup_quic_shard_and_client().await;

    let now = test_now_ms();
    let auth_root_valid_until = now + 100_000_000;
    let sender_key = SigningKey::from_bytes(&[15u8; 32]);
    let genesis_req = make_test_genesis("v_a19_r2", auth_root_valid_until, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let ttl_s = auth_root_valid_until.saturating_sub(now) / 1000;
    let op_by = ByteYears::from_ttl_seconds(ttl_s);
    let daily_limit = tier_controller.calculate_daily_quota(5.0, 1.0);
    let epoch_day = tier_controller.current_epoch_day_at(now);

    // Pre-seed sender usage to limit minus exactly one operation
    let initial_usage = daily_limit.saturating_sub(op_by);
    let _ = tier_controller.evaluate_node_write_quota(
        client_id.node_pubkey(),
        initial_usage,
        epoch_day,
    );

    let fp = ByteYears::micro_from_ttl_seconds(ttl_s);
    let ev = sign_ingress_evidence_with_key(
        client_id.signing_key(),
        epoch_day as u32,
        1,
        now,
        0,
        0,
        fp,
        false,
        genesis_req.transaction_hash,
    );

    let payload = bincode::serialize(&LockWirePayload::Hmc {
        req: genesis_req.clone(),
        chain: None,
        root_valid_until: auth_root_valid_until,
        epoch_day: epoch_day as u32,
        epoch_seq: 1,
        cumulative_micro_byte_years: fp,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: *client_id.node_pubkey(),
        sender_signature: ev.signature,
        timestamp_ms: now,
    })
    .unwrap();

    // First attempt: should succeed and consume the remaining budget
    let (resp1, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(
                MsgType::LockVerifyRequest as u16,
                1,
                0,
                0,
                payload.len() as u32,
            ),
            &payload,
        )
        .await
        .expect("first send");
    assert_eq!(resp1.flags, 0, "first write within limit must succeed");

    // Identical retry: should succeed idempotently without FLAG_QUOTA_EXCEEDED
    let (resp2, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(
                MsgType::LockVerifyRequest as u16,
                2,
                0,
                0,
                payload.len() as u32,
            ),
            &payload,
        )
        .await
        .expect("retry send");
    assert_eq!(
        resp2.flags, 0,
        "exact idempotent wire retry must succeed with flags 0 even at limit"
    );

    // Now try a different operation: budget is exhausted, so this MUST be rejected with FLAG_QUOTA_EXCEEDED
    let genesis_req_2 = make_test_genesis("v_a19_r2_second", auth_root_valid_until, &sender_key);
    let genesis_tag_2 = bs58::encode(&genesis_req_2.transaction_hash).into_string();
    let parent_2 = *blake3::hash(genesis_tag_2.as_bytes()).as_bytes();
    let shard_2 = humoco_sim_core::types::extract_shard_id(&parent_2);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req_2.layer2_voucher_id, parent_2)
        .await;
    readiness.mark_shard_ready(shard_2);

    let ev2 = sign_ingress_evidence_with_key(
        client_id.signing_key(),
        epoch_day as u32,
        2,
        now,
        0,
        0,
        fp,
        false,
        genesis_req_2.transaction_hash,
    );
    let payload_new = bincode::serialize(&LockWirePayload::Hmc {
        req: genesis_req_2,
        chain: None,
        root_valid_until: auth_root_valid_until,
        epoch_day: epoch_day as u32,
        epoch_seq: 2,
        cumulative_micro_byte_years: fp * 2,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: *client_id.node_pubkey(),
        sender_signature: ev2.signature,
        timestamp_ms: now,
    })
    .unwrap();

    let (resp3, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(
                MsgType::LockVerifyRequest as u16,
                3,
                0,
                0,
                payload_new.len() as u32,
            ),
            &payload_new,
        )
        .await
        .expect("new spend send");
    assert_ne!(
        resp3.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "new operation exceeding quota must be rejected with FLAG_QUOTA_EXCEEDED"
    );
}

// ---------------------------------------------------------------------------
// A19-R3: Full QUIC write budget exhaustion before database mutation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a19_r3_quic_write_budget_exhaustion_before_mutation() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let (
        engine,
        tier_controller,
        readiness,
        _shard_id,
        _shard_trans,
        _shard_addr,
        client_id,
        client_trans,
        conn,
        _sc,
        _cc,
    ) = setup_quic_shard_and_client().await;

    let now = test_now_ms();
    let auth_root_valid_until = now + 100_000_000;
    let sender_key = SigningKey::from_bytes(&[19u8; 32]);
    let genesis_req = make_test_genesis("v_a19_r3", auth_root_valid_until, &sender_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();
    let parent = *blake3::hash(genesis_tag.as_bytes()).as_bytes();
    let shard = humoco_sim_core::types::extract_shard_id(&parent);
    engine
        .record_hmc_voucher_genesis_parent(&genesis_req.layer2_voucher_id, parent)
        .await;
    readiness.mark_shard_ready(shard);

    let epoch_day = tier_controller.current_epoch_day_at(now);
    let daily_limit = tier_controller.calculate_daily_quota(5.0, 1.0);

    // Completely exhaust sender's observed write budget
    let _ =
        tier_controller.evaluate_node_write_quota(client_id.node_pubkey(), daily_limit, epoch_day);

    let ttl_s = auth_root_valid_until.saturating_sub(now) / 1000;
    let fp = ByteYears::micro_from_ttl_seconds(ttl_s);
    let ev = sign_ingress_evidence_with_key(
        client_id.signing_key(),
        epoch_day as u32,
        1,
        now,
        0,
        0,
        fp,
        false,
        genesis_req.transaction_hash,
    );

    let payload = bincode::serialize(&LockWirePayload::Hmc {
        req: genesis_req.clone(),
        chain: None,
        root_valid_until: auth_root_valid_until,
        epoch_day: epoch_day as u32,
        epoch_seq: 1,
        cumulative_micro_byte_years: fp,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: *client_id.node_pubkey(),
        sender_signature: ev.signature,
        timestamp_ms: now,
    })
    .unwrap();

    let (resp, _) = client_trans
        .send_request(
            &conn,
            &WireHeader::new(
                MsgType::LockVerifyRequest as u16,
                1,
                0,
                0,
                payload.len() as u32,
            ),
            &payload,
        )
        .await
        .expect("send request");
    assert_ne!(
        resp.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "must be rejected with FLAG_QUOTA_EXCEEDED"
    );

    // Assert that the database remains unmutated (Reservation-First)
    let stored = engine
        .get_hmc_voucher_root_valid(&genesis_req.layer2_voucher_id)
        .await;
    assert_eq!(
        stored, None,
        "RAM index and database must remain unmutated after quota denial"
    );
}
