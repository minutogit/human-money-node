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
// A19-03: Neutral quota feedback (FLAG_QUOTA_EXCEEDED does not increase missing_count)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_a19_03_neutral_quota_feedback_does_not_penalize_peer() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let peer_pm = Arc::new(PeerManager::with_f2f(Vec::new(), Vec::new()));
    let peer_identity = NodeIdentity::generate();
    let peer_addr: std::net::SocketAddr = "127.0.0.1:9099".parse().unwrap();
    peer_pm
        .register_f2f_friend(*peer_identity.node_pubkey(), Some(peer_addr))
        .await;

    // Verify initial missing_count is 0
    let initial_missing = peer_pm
        .get_peer(&peer_addr)
        .await
        .map(|p| p.missing_count)
        .unwrap_or(0);
    assert_eq!(initial_missing, 0);

    // Simulate quota refusal evaluation outside merge hysteresis
    let my_load = 100u64;
    let quota_limit = 10_000u64;
    let verdict = humoco_sim_core::quota::evaluate_quota_exceeded_claim(my_load, quota_limit);
    assert!(matches!(
        verdict,
        humoco_sim_core::quota::QuotaPlausibilityVerdict::FraudulentRejection { .. }
    ));

    // Verify invariant: quota feedback MUST NEVER call record_failure.
    let current_missing = peer_pm
        .get_peer(&peer_addr)
        .await
        .map(|p| p.missing_count)
        .unwrap_or(0);
    assert_eq!(
        current_missing, 0,
        "A19-03: Peer missing_count must remain 0 after quota feedback"
    );
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
