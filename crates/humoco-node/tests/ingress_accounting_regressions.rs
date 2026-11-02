//! Regression tests for Slice S05 (S05-01 through S05-05) verified reliability defects.
//!
//! Covers:
//! - S05-01: Concurrent rollover & stale-timestamp sequence uniqueness + real QUIC no-slashing
//! - S05-02: Idempotent VIP registration, cold hydration race & topup preservation
//! - S05-03: VIP 5x daily allowance enforcement without credit burn
//! - S05-04: Full 32-byte client accounting & cross-tier namespace isolation
//! - S05-05: Hard-bounded auth failure tracker & unspoofable operator source IP

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use humoco_node::{
    api::{
        auth::{
            AdminAuthRateLimiter, AdminTokenManager, AUTH_RATE_LIMIT_WINDOW,
            MAX_AUTH_FAILURES_PER_WINDOW, MAX_TRACKED_AUTH_IPS,
        },
        build_router,
        hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockRequest},
        routes::build_operator_router,
        AppState,
    },
    control::parse_account_tag,
    daemon::ShardReadinessManager,
    identity::NodeIdentity,
    ingress::{tier::is_valid_client_token, IngressError, IngressTier, PowEngine, TierController},
    network::{
        framing::LockWirePayload, DefaultRequestHandler, NodeRequestHandler, PeerManager,
        QuicTransport,
    },
    storage::{DualTierEngine, RedbStorage},
};
use humoco_sim_core::{
    fraud::{compute_ingress_envelope_digest, compute_ingress_envelope_digest_v2, FraudProofPayload, IngressEnvelopeEvidence},
    wire::{MsgType, WireHeader},
};

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn authenticate_root_fixture(req: &mut L2LockRequest, key: &SigningKey) {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(req.transaction_hash);
    hash.update(req.sender_ephemeral_pub);
    if let Some(receiver) = req.receiver_ephemeral_pub_hash {
        hash.update(receiver);
    }
    hash.update(req.deletable_at.as_deref().unwrap().as_bytes());
    req.layer2_voucher_id = hex::encode(hash.finalize());
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: req.layer2_voucher_id.clone(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: req.sender_ephemeral_pub,
        receiver_pubkey_hash: req.receiver_ephemeral_pub_hash,
        change_pubkey_hash: req.change_ephemeral_pub_hash,
        root_valid_until_ms: req.deletable_at.as_ref().unwrap().parse().unwrap(),
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(req)).to_bytes();
}

fn make_test_hmc_genesis(
    parent_bytes: [u8; 32],
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(&parent_bytes).as_bytes();
    let del_str = valid_until_ms.to_string();

    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{}", hex::encode(parent_bytes)),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: Some(del_str),
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    authenticate_root_fixture(&mut req, sender_key);
    req
}

fn setup_test_app_pair() -> (
    axum::Router,
    axum::Router,
    Arc<RedbStorage>,
    NodeIdentity,
    Arc<TierController>,
    Arc<PowEngine>,
    AppState,
) {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_api.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(*identity.node_id(), 0)); // difficulty 0 for instant tests
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    );
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    let operator = build_operator_router(state.clone());
    let router = build_router(state.clone());
    (
        router,
        operator,
        storage,
        identity,
        tier_controller,
        pow_engine,
        state,
    )
}

// ===========================================================================
// S05-01: Concurrent rollover & stale-timestamp sequence uniqueness + QUIC
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_s05_01_concurrent_rollover_and_stale_timestamp_sequence_uniqueness() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("test_s05_01.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new([0x11; 32], 0));
    let controller = Arc::new(TierController::new(storage, pow));

    // Base day: day 100
    let day_ms = 86_400_000u64;
    let base_t = 100 * day_ms;

    // We spawn 8 threads calling record_declared_usage across Day 100, Day 101, Day 102,
    // plus threads with stale timestamps from Day 100 while Day 101/102 is active.
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let results = Arc::new(Mutex::new(Vec::<(u32, u64, u64, u64, u64)>::new()));

    let mut handles = Vec::new();
    for thread_idx in 0..num_threads {
        let b = barrier.clone();
        let tc = controller.clone();
        let res = results.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..25 {
                let now_ms = match (thread_idx % 4, i) {
                    (0, _) => base_t + 1_000 + i * 10,                 // Day 100
                    (1, _) => base_t + day_ms + 2_000 + i * 10,        // Day 101
                    (2, _) => base_t + 2 * day_ms + 3_000 + i * 10,    // Day 102
                    (3, _) => base_t + 500, // Stale timestamp: Day 100 (delayed request)
                    _ => unreachable!(),
                };
                let footprint = 100;
                let (day, seq, cum, prev) = tc.record_declared_usage(now_ms, footprint);
                res.lock().push((day, seq, cum, prev, now_ms));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let records = results.lock().clone();
    assert_eq!(records.len(), num_threads * 25);

    // 1. Assert every returned (day, seq) pair is strictly unique!
    let mut seen_pairs = HashSet::new();
    for &(day, seq, _, _, _) in &records {
        assert!(
            seen_pairs.insert((day, seq)),
            "Duplicate (day, seq) detected: ({}, {})",
            day,
            seq
        );
    }

    // 2. Per-day sequences start at 1 and increment without duplicates
    let mut day_seqs: HashMap<u32, Vec<u64>> = HashMap::new();
    for &(day, seq, _, _, _) in &records {
        day_seqs.entry(day).or_default().push(seq);
    }
    for (day, mut seqs) in day_seqs {
        seqs.sort_unstable();
        assert_eq!(
            seqs[0], 1,
            "Day {} sequences must start at 1, found {}",
            day, seqs[0]
        );
        for window in seqs.windows(2) {
            assert_eq!(
                window[1],
                window[0] + 1,
                "Day {} sequences have gap or duplicate: {} -> {}",
                day,
                window[0],
                window[1]
            );
        }
    }

    // 3. Cumulative usage never rolls back within the same day
    let mut day_records: HashMap<u32, Vec<(u64, u64)>> = HashMap::new(); // seq -> cum
    for &(day, seq, cum, _, _) in &records {
        day_records.entry(day).or_default().push((seq, cum));
    }
    for (day, mut list) in day_records {
        list.sort_by_key(|&(seq, _)| seq);
        for window in list.windows(2) {
            let (seq1, cum1) = window[0];
            let (seq2, cum2) = window[1];
            assert!(
                cum2 >= cum1,
                "Day {} cumulative usage rolled back from seq {} (cum {}) to seq {} (cum {})",
                day,
                seq1,
                cum1,
                seq2,
                cum2
            );
        }
    }

    // 4. Feeding emitted records into FraudProofPayload::new_ingress_counter_conflict
    // / verify_ingress_counter_conflict NEVER triggers a sequence-fork or rollback fraud proof!
    let signing_key = SigningKey::from_bytes(&[0x22; 32]);
    let gateway_pubkey = signing_key.verifying_key().to_bytes();

    let evidences: Vec<IngressEnvelopeEvidence> = records
        .iter()
        .map(|&(day, seq, cum, prev, ts)| {
            let op_hash = *blake3::hash(&seq.to_le_bytes()).as_bytes();
            let digest = compute_ingress_envelope_digest(
                &gateway_pubkey,
                day,
                seq as u32,
                cum,
                prev,
                0,
                ts,
                &op_hash,
            );
            let signature = signing_key.sign(&digest).to_bytes();
            IngressEnvelopeEvidence {
                gateway_pubkey,
                epoch_day: day,
                epoch_seq: seq,
                cumulative_micro_byte_years: cum,
                prev_day_final_bytes: prev,
                current_anl_24h: 0,
                timestamp_ms: ts,
                declared_write_ema_micro_bj: 0,
                declared_read_ema_credits: 0,
                footprint_micro_bj: 100,
                is_read: false,
                op_hash,
                lock_hash: op_hash,
                signature,
            }
        })
        .collect();

    // Cross-verify all pairs of emitted envelopes: NONE should be deemed fraudulent!
    for (i, ev_a) in evidences.iter().enumerate() {
        for ev_b in evidences.iter().skip(i + 1) {
            let proof =
                FraudProofPayload::new_ingress_counter_conflict(ev_a.clone(), ev_b.clone());
            assert!(
                !proof.verify_ingress_counter_conflict(),
                "False-positive fraud detected between honest envelopes! A: day={}, seq={}, cum={} vs B: day={}, seq={}, cum={}",
                ev_a.epoch_day,
                ev_a.epoch_seq,
                ev_a.cumulative_micro_byte_years,
                ev_b.epoch_day,
                ev_b.epoch_seq,
                ev_b.cumulative_micro_byte_years
            );
        }
    }
}

#[tokio::test]
async fn test_s05_01_real_quic_honest_rollover_no_slashing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("humoco_node=debug")
        .with_test_writer()
        .try_init();

    let temp = tempdir().unwrap();
    let db_path = temp.path().join("server.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    let readiness = Arc::new(ShardReadinessManager::new());
    for shard in 0..=u16::MAX {
        readiness.mark_shard_ready(shard);
    }

    let handler = NodeRequestHandler::with_peer_manager(
        engine.clone(),
        storage.clone(),
        server_id.clone(),
        server_peer_mgr.clone(),
    )
    .with_readiness_manager(readiness);

    let cancel_token = CancellationToken::new();

    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        server_peer_mgr.clone(),
        Arc::new(handler),
        cancel_token.clone(),
    )
    .expect("bind server QUIC");
    let server_addr = server_transport.local_addr().unwrap();
    let _server_accept = server_transport.spawn_accept_loop();

    let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
    let gateway_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway_id,
        gw_peer_mgr.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("bind gateway QUIC");
    let _gw_accept = gateway_transport.spawn_accept_loop();

    // Register mutual F2F friendship so QUIC connection is authorized
    server_peer_mgr
        .register_f2f_friend(gateway_pubkey, Some(gateway_transport.local_addr().unwrap()))
        .await;
    gw_peer_mgr
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = gateway_transport
        .connect_peer(server_addr)
        .await
        .expect("connect gateway to server QUIC");

    // Gateway setup with TierController
    let gw_db_path = temp.path().join("gw.redb");
    let gw_storage = Arc::new(RedbStorage::open(&gw_db_path).unwrap());
    let gw_pow = Arc::new(PowEngine::new(*gateway_id.node_id(), 0));
    let gw_tier = Arc::new(TierController::new(gw_storage, gw_pow));

    let day_ms = 86_400_000u64;
    let base_t = 100 * day_ms;

    // Send honest requests across rollover (Day 100, then rollover to Day 101)
    let timestamps = [
        base_t + 1_000,
        base_t + 2_000,
        base_t + day_ms + 100, // Day 101 transition
        base_t + day_ms + 500, // Day 101 forward
    ];

    for (seq_idx, &now_ms) in timestamps.iter().enumerate() {
        let footprint = 100u64;
        let (epoch_day, epoch_seq, cum, prev) = gw_tier.record_declared_usage(now_ms, footprint);

        let parent = [0x50 + seq_idx as u8; 32];
        let root_valid = now_ms + 100_000;
        let lock_req = make_test_hmc_genesis(parent, root_valid, gateway_id.signing_key());
        let tx_hash = lock_req.transaction_hash;

        let digest = compute_ingress_envelope_digest_v2(
            &gateway_pubkey,
            epoch_day,
            epoch_seq,
            now_ms,
            0,
            0,
            footprint,
            false,
            &tx_hash,
        );
        let sender_sig = gateway_id.signing_key().sign(&digest).to_bytes();

        let wire_payload = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req,
            chain: None,
            root_valid_until: root_valid,
            epoch_day,
            epoch_seq,
            cumulative_micro_byte_years: cum,
            prev_day_final_bytes: prev,
            current_anl_24h: 0,
            declared_write_ema_micro_bj: 0,
            declared_read_ema_credits: 0,
            sender_pubkey: gateway_pubkey,
            sender_signature: sender_sig,
            timestamp_ms: now_ms,
        })
        .expect("serialize LockWirePayload");

        let header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            (seq_idx + 1) as u64,
            0,
            0,
            wire_payload.len() as u32,
        );

        let (resp_hdr, _) = gateway_transport
            .send_request(&conn, &header, &wire_payload)
            .await
            .expect("send LockVerifyRequest over QUIC");

        assert_eq!(
            resp_hdr.msg_type,
            MsgType::LockVerifyResponse as u16,
            "Response must be LockVerifyResponse"
        );
    }

    // Assert the receiver has NOT banned the honest gateway!
    assert!(
        !server_peer_mgr.is_banned(&gateway_pubkey).await,
        "Honest gateway across day rollover must NOT be banned by receiver"
    );
}

// ===========================================================================
// S05-02: Idempotent VIP registration, cold hydration race & topup preservation
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_s05_02_idempotent_vip_registration_and_topup_preservation() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("vip_s05_02.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let account_tag = [0x77u8; 32];

    // 1. Initial persisted balance = 100
    storage.set_quota(&account_tag, 100).unwrap();

    let pow = Arc::new(PowEngine::new([0x01; 32], 0));
    let controller = TierController::new(storage.clone(), pow);

    // Initial cache should have 100
    assert_eq!(controller.get_cached_vip_quota(&account_tag), Some(100));

    // 2. Debit 10 in RAM: balance becomes 90
    let rem = controller
        .try_charge_vip_in_memory(&account_tag, 10)
        .expect("charge in memory");
    assert_eq!(rem, 90);
    assert_eq!(controller.get_cached_vip_quota(&account_tag), Some(90));

    // 3. Re-register VIP tag (simulating re-registration or redundant registration)
    controller.register_vip_tag(account_tag);

    // Assert RAM balance was NOT clobbered back to 100!
    assert_eq!(
        controller.get_cached_vip_quota(&account_tag),
        Some(90),
        "register_vip_tag must be idempotent and NEVER overwrite mutated RAM balance with stale disk balance!"
    );

    // 4. Top up +5: new balance MUST be 95 (90 + 5), NOT 105 (100 + 5)!
    let topped = controller
        .topup_vip_quota(account_tag, 5)
        .expect("topup quota");
    assert_eq!(
        topped, 95,
        "RAM balance after topup must be 95, not 105 (debits must not be erased!)"
    );
    assert_eq!(controller.get_cached_vip_quota(&account_tag), Some(95));

    // 5. Test hydrate_vip_quota idempotence: must also preserve cached balance
    let hydrated = controller
        .hydrate_vip_quota(&account_tag)
        .expect("hydrate");
    assert_eq!(
        hydrated, 95,
        "hydrate_vip_quota must preserve cached balance"
    );
    assert_eq!(controller.get_cached_vip_quota(&account_tag), Some(95));

    // 6. Yield/flush persistence worker and assert disk reflects 95 as well
    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        if storage.get_quota(&account_tag).unwrap_or(0) == 95 {
            break;
        }
    }
    assert_eq!(
        storage.get_quota(&account_tag).unwrap(),
        95,
        "Disk quota must also reflect 95 after persistence worker drains"
    );
}

#[tokio::test]
async fn test_s05_02_control_server_topup_preserves_debits() {
    let account_tag = [0x88u8; 32];
    let tag_hex = hex::encode(account_tag);

    let (_router, _operator, storage, _identity, tiers, _pow, _state) = setup_test_app_pair();
    tiers.register_vip_token(&tag_hex, account_tag);
    tiers.topup_vip_quota(account_tag, 200).unwrap();

    // Debit 50 in RAM before async persistence worker drains
    let rem = tiers.try_charge_vip_in_memory(&account_tag, 50).unwrap();
    assert_eq!(rem, 150);

    // Exercise topup sequence matching control server / dashboard handler:
    // (which calls register_vip_token and register_vip_tag before topup_vip_quota)
    let tag_bytes = parse_account_tag(&tag_hex);
    tiers.register_vip_token(tag_hex.clone(), tag_bytes);
    tiers.register_vip_tag(tag_bytes);
    let new_bal = tiers.topup_vip_quota(tag_bytes, 10).unwrap();

    // Must be 160 (150 + 10), NOT 210!
    assert_eq!(
        new_bal, 160,
        "Topup must preserve prior debits and equal 160, not 210!"
    );
    assert_eq!(tiers.get_cached_vip_quota(&account_tag), Some(160));

    // Verify disk also catches up
    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        if storage.get_quota(&account_tag).unwrap_or(0) == 160 {
            break;
        }
    }
    assert_eq!(storage.get_quota(&account_tag).unwrap(), 160);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_s05_02_cold_hydration_race_preserves_mutations() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("cold_race.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new([0x02; 32], 0));
    let controller = Arc::new(TierController::new(storage.clone(), pow));

    // Initially cold: set quota on disk AFTER controller creation so it's not in in-memory cache
    let cold_tag = [0x55u8; 32];
    storage.set_quota(&cold_tag, 200).unwrap();
    assert_eq!(controller.get_cached_vip_quota(&cold_tag), None);

    // Concurrently race cold hydration and topup across multiple tasks
    let c1 = controller.clone();
    let h1 = tokio::spawn(async move {
        c1.ensure_vip_quota_cached(&cold_tag).await.unwrap();
    });

    let c2 = controller.clone();
    let h2 = tokio::spawn(async move {
        c2.topup_vip_quota(cold_tag, 50).unwrap();
    });

    let (r1, r2) = tokio::join!(h1, h2);
    r1.unwrap();
    r2.unwrap();

    // Final RAM balance must be 250 (200 initial + 50 topup)
    assert_eq!(
        controller.get_cached_vip_quota(&cold_tag),
        Some(250),
        "Cold hydration race must preserve topup addition without clobbering!"
    );

    // Wait for persistence worker to commit
    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        if storage.get_quota(&cold_tag).unwrap_or(0) == 250 {
            break;
        }
    }
    assert_eq!(
        storage.get_quota(&cold_tag).unwrap(),
        250,
        "Disk quota must reflect 250 after cold hydration and topup"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_s05_02_operator_http_topup_after_unpersisted_debit() {
    let (_router, _operator, storage, _identity, tiers, _pow, state) = setup_test_app_pair();
    let auth = Arc::new(AdminTokenManager::with_token("test_admin_topup_secret", false));
    let state = state.with_auth(auth);
    let operator_router = build_operator_router(state);

    let account_tag = [0x33u8; 32];
    let tag_hex = hex::encode(account_tag);
    tiers.register_vip_token(&tag_hex, account_tag);

    // Initial quota = 200
    tiers.topup_vip_quota(account_tag, 200).unwrap();

    // Unpersisted debit of 50 in RAM -> 150
    let rem = tiers.try_charge_vip_in_memory(&account_tag, 50).unwrap();
    assert_eq!(rem, 150);

    // Invoke operator HTTP endpoint POST /dashboard/admin/quota with +30 BY
    let payload = serde_json::json!({
        "account_tag": tag_hex,
        "byte_years": 30
    });

    let req = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/quota")
        .header("content-type", "application/json")
        .header("authorization", "Bearer test_admin_topup_secret")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let resp = operator_router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let topup_resp: humoco_node::api::dashboard::TopupQuotaResponse =
        serde_json::from_slice(&body_bytes).unwrap();

    // 150 (unpersisted debit balance) + 30 (topup) = 180!
    assert_eq!(
        topup_resp.new_balance, 180,
        "HTTP topup response must be 180 (initial 200 - debit 50 + topup 30)"
    );
    assert_eq!(
        tiers.get_cached_vip_quota(&account_tag),
        Some(180),
        "RAM balance must be 180"
    );

    // Wait for persistence worker to commit to disk
    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        if storage.get_quota(&account_tag).unwrap_or(0) == 180 {
            break;
        }
    }
    assert_eq!(
        storage.get_quota(&account_tag).unwrap(),
        180,
        "Disk quota must also reflect 180 after HTTP topup"
    );
}

// ===========================================================================
// S05-03: VIP 5x daily allowance enforcement without credit burn
// ===========================================================================

#[tokio::test]
async fn test_s05_03_vip_daily_allowance_enforcement_without_credit_burn() {
    let (router, _operator, storage, identity, tier_controller, _pow, _state) = setup_test_app_pair();

    let account_tag = [0x99u8; 32];
    let token = "vip_whale_token_test";
    tier_controller.register_vip_token(token, account_tag);

    // 1. Give plenty of purchased Byte-Years credit: 50,000 BY
    tier_controller.set_cached_vip_quota(account_tag, 50_000);
    storage.set_quota(&account_tag, 50_000).unwrap();

    let now_ms = test_now_ms();
    let epoch_day = tier_controller.current_epoch_day_at(now_ms);
    // Daily quota with 5x Whale Brake:
    let daily_limit = tier_controller.calculate_daily_quota(5.0, 1.0);
    assert!(daily_limit > 0);

    // Exhaust daily quota directly
    tier_controller
        .evaluate_vip_quota(&account_tag, daily_limit, epoch_day, 5.0)
        .expect("first VIP quota must be admitted up to daily limit");

    let balance_before = tier_controller
        .get_cached_vip_quota(&account_tag)
        .unwrap();
    let writes_today_before = tier_controller.tier_counters().0;

    // 2. Now attempt another write via evaluate_and_charge_with_time: MUST BE REJECTED with QuotaExceeded
    let res = tier_controller
        .evaluate_and_charge_with_time(
            Some(token),
            None,
            None,
            None,
            31_536_000, // 1 year = 192 BY
            None,
            Some(now_ms),
        )
        .await;

    assert!(
        matches!(res, Err(IngressError::QuotaExceeded { .. })),
        "VIP request exceeding 5x daily allowance must be rejected with QuotaExceeded, got {:?}",
        res
    );

    // Assert ZERO partial mutation: purchased balance, writes_today remain unchanged!
    let balance_after = tier_controller
        .get_cached_vip_quota(&account_tag)
        .unwrap();
    assert_eq!(
        balance_after, balance_before,
        "Purchased VIP balance must NOT be burned when daily allowance is exceeded!"
    );
    let writes_today_after = tier_controller.tier_counters().0;
    assert_eq!(
        writes_today_after, writes_today_before,
        "vip_writes_today must not increment on rejection!"
    );

    // 3. Test HTTP POST /v1/lock endpoint rejection
    let root = make_test_hmc_genesis([0x99; 32], now_ms + 100_000, identity.signing_key());
    let req_body = serde_json::to_vec(&root).unwrap();

    let http_res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        http_res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "HTTP POST /v1/lock must return 429 Too Many Requests when VIP daily cap is reached"
    );

    // Assert balance is STILL unchanged
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(balance_before),
        "Purchased VIP balance must remain completely untouched after HTTP 429 rejection"
    );

    // 4. Verify retry remains idempotent
    let _retry_res = tier_controller
        .evaluate_and_charge_with_time_and_retry(
            Some(token),
            None,
            None,
            None,
            31_536_000,
            None,
            Some(now_ms),
            true, // is_retry = true
        )
        .await;
    // When retry is evaluated, does not burn balance
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(balance_before)
    );

    // 5. Next-day (epoch_day + 1, advancing now_ms by 86_400_000) VIP admission succeeds again!
    let next_day_ms = now_ms + 86_400_000;
    let next_day_res = tier_controller
        .evaluate_and_charge_with_time(
            Some(token),
            None,
            None,
            None,
            31_536_000,
            None,
            Some(next_day_ms),
        )
        .await;

    assert!(
        matches!(next_day_res, Ok(IngressTier::Tier1Vip)),
        "VIP request on next epoch day must succeed after daily limit resets, got {:?}",
        next_day_res
    );
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(balance_before - 192),
        "Purchased balance must be debited by 192 for successful next-day write"
    );
}

#[tokio::test]
async fn test_s05_03_vip_persistence_channel_full_leaves_state_untouched() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("persist_full.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow_engine = Arc::new(PowEngine::new([0x33; 32], 0));

    // Create TierController with persist capacity = 1
    let controller = Arc::new(TierController::new_with_persist_capacity(
        storage.clone(),
        pow_engine,
        1,
    ));

    let account_tag = [0x77u8; 32];
    let token = "vip_persist_test_token";
    controller.register_vip_token(token, account_tag);
    controller.set_cached_vip_quota(account_tag, 10_000);
    storage.set_quota(&account_tag, 10_000).unwrap();

    let now_ms = test_now_ms();

    // Fill the channel permit so try_reserve() fails with QuotaPersistenceUnavailable
    let held_permit = controller
        .reserve_persist_permit_for_test()
        .expect("should reserve the single available permit");

    // Attempt VIP write: must fail with QuotaPersistenceUnavailable
    let res = controller
        .evaluate_and_charge_with_time(
            Some(token),
            None,
            None,
            None,
            31_536_000,
            None,
            Some(now_ms),
        )
        .await;

    assert!(
        matches!(res, Err(IngressError::QuotaPersistenceUnavailable)),
        "Expected QuotaPersistenceUnavailable, got {:?}",
        res
    );

    // Verify balance is completely unchanged (10,000)
    assert_eq!(
        controller.get_cached_vip_quota(&account_tag),
        Some(10_000),
        "Purchased balance must NOT be debited when persistence channel is full!"
    );

    // Verify daily usage is completely unchanged (0)
    let (_usage_day, usage_bytes) = controller.vip_daily_usage_for_test(&account_tag);
    assert_eq!(
        usage_bytes, 0,
        "Daily usage must NOT be recorded when persistence channel is full!"
    );
    let writes_today = controller.tier_counters().0;
    assert_eq!(
        writes_today, 0,
        "VIP writes today counter must NOT increment on persistence failure!"
    );

    // Release the permit
    drop(held_permit);

    // Now write must succeed
    let res_ok = controller
        .evaluate_and_charge_with_time(
            Some(token),
            None,
            None,
            None,
            31_536_000,
            None,
            Some(now_ms),
        )
        .await;

    assert!(
        matches!(res_ok, Ok(IngressTier::Tier1Vip)),
        "Write should succeed after permit is released, got {:?}",
        res_ok
    );
    assert_eq!(
        controller.get_cached_vip_quota(&account_tag),
        Some(10_000 - 192)
    );
    assert_eq!(controller.tier_counters().0, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_s05_03_concurrent_vip_allowance_contention() {
    let (_router, _operator, storage, _identity, tiers, _pow, _state) = setup_test_app_pair();
    let account_tag = [0x66u8; 32];
    let token = "vip_contention_token";
    tiers.register_vip_token(token, account_tag);

    // Initial purchased balance: generous amount
    tiers.set_cached_vip_quota(account_tag, 50_000);
    storage.set_quota(&account_tag, 50_000).unwrap();

    let now_ms = test_now_ms();
    let epoch_day = tiers.current_epoch_day_at(now_ms);

    // 1 year TTL = 192 Byte-Years
    let req_by = 192u64;
    let daily_limit = tiers.calculate_daily_quota(5.0, 1.0);

    // Consume all but exactly 3 * 192 of the daily allowance
    assert!(daily_limit > 3 * req_by);
    let pre_consume = daily_limit - 3 * req_by;
    tiers
        .evaluate_vip_quota(&account_tag, pre_consume, epoch_day, 5.0)
        .expect("pre-consume quota");

    let bal_before = tiers.get_cached_vip_quota(&account_tag).unwrap();

    // Spawn 10 concurrent tasks each trying to spend 192 BY on the same epoch day
    let num_contenders = 10;
    let barrier = Arc::new(tokio::sync::Barrier::new(num_contenders));
    let mut tasks = Vec::new();

    for _ in 0..num_contenders {
        let b = barrier.clone();
        let tc = tiers.clone();
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            tc.evaluate_and_charge_with_time(
                Some(token),
                None,
                None,
                None,
                31_536_000,
                None,
                Some(now_ms),
            )
            .await
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(IngressTier::Tier1Vip) => successes += 1,
            Err(IngressError::QuotaExceeded { .. }) => failures += 1,
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    assert_eq!(
        successes, 3,
        "Exactly 3 writes should succeed within remaining allowance, found {}",
        successes
    );
    assert_eq!(
        failures, 7,
        "Exactly 7 writes should be rejected with QuotaExceeded, found {}",
        failures
    );

    let bal_after = tiers.get_cached_vip_quota(&account_tag).unwrap();
    assert_eq!(
        bal_after,
        bal_before - 3 * req_by,
        "Purchased balance must decrease by strictly 3 * required_byte_years"
    );
}

// ===========================================================================
// S05-04: Full 32-byte client accounting & cross-tier namespace isolation
// ===========================================================================

#[tokio::test]
async fn test_s05_04_full_32byte_client_accounting_and_tier_isolation() {
    let (router, _operator, _storage, identity, tier_controller, _pow, _state) =
        setup_test_app_pair();

    // Two valid friend credentials that both share the 16-bit BLAKE3 prefix [0x06, 0xad]
    let token_1 = "f2f_0000000000000000000000000000008e";
    let token_2 = "f2f_000000000000000000000000000000ec";

    assert!(is_valid_client_token(token_1));
    assert!(is_valid_client_token(token_2));

    let hash_1 = *blake3::hash(token_1.as_bytes()).as_bytes();
    let hash_2 = *blake3::hash(token_2.as_bytes()).as_bytes();

    // Verify they collide on 16-bit prefix [0x06, 0xad]
    assert_eq!(
        [hash_1[0], hash_1[1]],
        [0x06, 0xad],
        "Token 1 must start with 0x06ad"
    );
    assert_eq!(
        [hash_2[0], hash_2[1]],
        [0x06, 0xad],
        "Token 2 must start with 0x06ad"
    );
    assert_ne!(hash_1, hash_2, "Full 32-byte hashes must be distinct!");

    tier_controller.register_f2f_client(token_1, Some("Friend-1"));
    tier_controller.register_f2f_client(token_2, Some("Friend-2"));

    let daily_limit = tier_controller.calculate_daily_quota(1.0, 1.0);
    let now_ms = test_now_ms();
    let epoch_day = tier_controller.current_epoch_day_at(now_ms);

    // 1. Exhaust ONLY Friend 1's daily quota
    tier_controller
        .evaluate_f2f_quota(token_1, daily_limit, epoch_day)
        .expect("friend 1 quota must be admitted up to limit");

    // Friend 1 should now be rejected
    let f1_second = tier_controller.evaluate_f2f_quota(token_1, 1, epoch_day);
    assert!(
        matches!(f1_second, Err(IngressError::QuotaExceeded { .. })),
        "Friend 1 must be rejected after exhausting daily quota"
    );

    // 2. Send Friend 2's first request: MUST SUCCEED (no 16-bit truncation aliasing!)
    let f2_res = tier_controller
        .evaluate_and_charge_with_time(
            None,
            Some(token_2),
            None,
            None,
            31_536_000,
            None,
            Some(now_ms),
        )
        .await;

    assert!(
        matches!(f2_res, Ok(IngressTier::Tier2F2F)),
        "Friend 2 must succeed independently despite colliding 16-bit prefix! Got {:?}",
        f2_res
    );

    // 3. Verify via HTTP POST /v1/lock that Friend 2 succeeds over HTTP
    let root = make_test_hmc_genesis(
        [0x06, 0xad, 0x55, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        now_ms + 600_000,
        identity.signing_key(),
    );
    let req_body = serde_json::to_vec(&root).unwrap();

    let http_res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("x-peer-token", token_2)
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        http_res.status().is_success(),
        "HTTP POST /v1/lock with Friend 2 must succeed! Got status {}",
        http_res.status()
    );

    // 4. Test cross-tier namespace isolation:
    // A Free/Public parent_lock starting with [0x06, 0xad, ...]
    // A P2P node write sender_pubkey starting with [0x06, 0xad, ...]
    // A VIP account_tag starting with [0x06, 0xad, ...]
    let mut colliding_32 = [0u8; 32];
    colliding_32[0] = 0x06;
    colliding_32[1] = 0xad;
    colliding_32[2] = 0x99;

    tier_controller
        .evaluate_node_write_quota(&colliding_32, 100, epoch_day)
        .expect("P2P node write must succeed");

    tier_controller.register_vip_token("vip_colliding_tag", colliding_32);
    tier_controller.set_cached_vip_quota(colliding_32, 10_000);
    tier_controller
        .evaluate_vip_quota(&colliding_32, 100, epoch_day, 5.0)
        .expect("VIP write must succeed");

    // 5. Assert list_f2f_clients reports each friend's own independent usage accurately
    let now_ms = epoch_day * 86_400_000 + 2_000;
    let client_dtos = tier_controller.list_f2f_clients(now_ms, epoch_day);
    assert_eq!(client_dtos.len(), 2);

    let f1_dto = client_dtos.iter().find(|c| c.label == "Friend-1").unwrap();
    let f2_dto = client_dtos.iter().find(|c| c.label == "Friend-2").unwrap();

    assert!(
        f1_dto.whale_brake_active,
        "Friend 1 whale brake must be active"
    );
    assert!(
        f1_dto.writes_today >= daily_limit,
        "Friend 1 writes_today must reflect its own usage"
    );

    // Friend 2 used 1 write (via evaluate_and_charge_with_time) + 1 write (via HTTP lock)
    assert!(
        !f2_dto.whale_brake_active,
        "Friend 2 whale brake must NOT be active"
    );
    assert!(
        f2_dto.writes_today < daily_limit,
        "Friend 2 usage must not be contaminated by Friend 1 or VIP/P2P usage! Got writes_today={}",
        f2_dto.writes_today
    );

    // 6. Next-day reset verification
    let next_day = epoch_day + 1;
    let next_day_dtos = tier_controller.list_f2f_clients(next_day * 86_400_000, next_day);
    let next_f1 = next_day_dtos.iter().find(|c| c.label == "Friend-1").unwrap();
    assert_eq!(
        next_f1.writes_today, 0,
        "Usage must reset to 0 on next epoch day"
    );
    assert!(
        !next_f1.whale_brake_active,
        "Whale brake must reset on next epoch day"
    );
}

// ===========================================================================
// S05-05: Hard-bounded auth failure tracker & unspoofable operator source IP
// ===========================================================================

#[test]
fn test_s05_05_auth_tracker_bounds_and_overflow_throttling() {
    let mgr = AdminAuthRateLimiter::with_token("test_admin_token", false);

    // 1. Record failed auth attempts for 1,024 distinct non-expired identities
    for i in 0..MAX_TRACKED_AUTH_IPS {
        let ip = format!("10.0.{}.{}", i / 256, i % 256);
        mgr.record_failure(&ip);
    }

    assert_eq!(
        mgr.tracked_ip_count_for_test(),
        MAX_TRACKED_AUTH_IPS,
        "Should have exactly 1,024 entries"
    );

    // 2. Submit 100 additional distinct identities
    for i in 0..100 {
        let ip = format!("192.168.1.{}", i);
        mgr.record_failure(&ip);
    }

    // Assert internal tracking map size NEVER exceeds 1,024!
    assert!(
        mgr.tracked_ip_count_for_test() <= MAX_TRACKED_AUTH_IPS,
        "Internal tracking map size must NEVER exceed 1,024! Found: {}",
        mgr.tracked_ip_count_for_test()
    );

    // 3. Assert per-identity failure timestamp storage never exceeds MAX_AUTH_FAILURES_PER_WINDOW
    let single_ip = "10.0.0.1";
    for _ in 0..20 {
        mgr.record_failure(single_ip);
    }
    assert!(
        mgr.failure_count_for_ip_for_test(single_ip) <= MAX_AUTH_FAILURES_PER_WINDOW,
        "Per-identity timestamp list must be capped at MAX_AUTH_FAILURES_PER_WINDOW (5), found {}",
        mgr.failure_count_for_ip_for_test(single_ip)
    );

    // 4. Assert callers beyond 1,024th during saturation do NOT bypass authentication throttling!
    let overflow_ip = "172.16.0.99";
    for _ in 0..MAX_AUTH_FAILURES_PER_WINDOW {
        mgr.record_failure(overflow_ip);
    }
    // After MAX_AUTH_FAILURES_PER_WINDOW failures, overflow caller MUST be blocked!
    assert!(
        !mgr.check_rate_limit(overflow_ip),
        "Overflow caller during table saturation must NOT bypass authentication rate limiting!"
    );

    // 5. Expiry & recovery after AUTH_RATE_LIMIT_WINDOW + 1s (0ms test using _at)
    let t0 = Instant::now();
    let timed_mgr = AdminAuthRateLimiter::with_token("test_admin_token", false);

    // Saturate table at t0
    for i in 0..MAX_TRACKED_AUTH_IPS {
        let ip = format!("10.1.{}.{}", i / 256, i % 256);
        for _ in 0..MAX_AUTH_FAILURES_PER_WINDOW {
            timed_mgr.record_failure_at(&ip, t0);
        }
        assert!(!timed_mgr.check_rate_limit_at(&ip, t0), "IP must be blocked at t0");
    }

    // Overflow IP at t0
    let overflow_timed = "172.31.0.1";
    for _ in 0..MAX_AUTH_FAILURES_PER_WINDOW {
        timed_mgr.record_failure_at(overflow_timed, t0);
    }
    assert!(!timed_mgr.check_rate_limit_at(overflow_timed, t0), "Overflow must be blocked at t0");

    // Advance time past AUTH_RATE_LIMIT_WINDOW (60s + 1s)
    let t_expired = t0 + AUTH_RATE_LIMIT_WINDOW + Duration::from_secs(1);

    // Previously throttled IPs must now be allowed
    assert!(
        timed_mgr.check_rate_limit_at("10.1.0.0", t_expired),
        "Previously throttled IP must recover after window expires"
    );
    assert!(
        timed_mgr.check_rate_limit_at(overflow_timed, t_expired),
        "Overflow IP must recover after window expires"
    );

    // New IP arriving at t_expired: expired entries are cleaned up and new IP is admitted & allowed
    let new_ip = "192.168.200.50";
    timed_mgr.record_failure_at(new_ip, t_expired);
    assert!(
        timed_mgr.check_rate_limit_at(new_ip, t_expired),
        "New IP with 1 failure must be allowed after saturation recovery"
    );

    // 6. Concurrent multi-threaded failed auth attempts staying strictly bounded
    let concurrent_mgr = Arc::new(AdminAuthRateLimiter::with_token("concurrent_secret", false));
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for thread_idx in 0..num_threads {
        let b = barrier.clone();
        let m = concurrent_mgr.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..50 {
                // Total 400 distinct IPs across threads, some overlapping
                let ip = format!("10.2.{}.{}", thread_idx, i);
                for _ in 0..7 {
                    m.record_failure(&ip);
                }
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert!(
        concurrent_mgr.tracked_ip_count_for_test() <= MAX_TRACKED_AUTH_IPS,
        "Concurrent tracking map size must never exceed 1,024, found {}",
        concurrent_mgr.tracked_ip_count_for_test()
    );

    // Any hammered IP must be throttled
    assert!(!concurrent_mgr.check_rate_limit("10.2.0.0"));
    assert!(
        concurrent_mgr.failure_count_for_ip_for_test("10.2.0.0") <= MAX_AUTH_FAILURES_PER_WINDOW,
        "Per-IP timestamp list must stay capped at 5"
    );
}

#[tokio::test]
async fn test_s05_05_real_tcp_operator_http_unspoofable_source_ip() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("operator_tcp.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _flush) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(*identity.node_id(), 0));
    let tiers = Arc::new(TierController::new(storage.clone(), pow.clone()));

    let auth = Arc::new(AdminTokenManager::with_token("correct_secret_token", false));
    let event_log = Arc::new(humoco_node::api::events::EventLog::default());

    let mut state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tiers.clone(),
        pow.clone(),
    );
    state = state.with_auth(auth).with_event_log(event_log);

    let app = build_operator_router(state);

    // Bind real TCP listener on loopback
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP listener");
    let local_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let client = reqwest::Client::new();
    let verify_url = format!("http://{}/dashboard/admin/verify-token", local_addr);

    // Attempt 5 failed requests from the same real TCP client, but rotating X-Forwarded-For and X-Real-IP
    for i in 0..5 {
        let fake_ip = format!("198.51.100.{}", i + 1);
        let resp = client
            .post(&verify_url)
            .header("Authorization", "Bearer wrong_token")
            .header("X-Forwarded-For", &fake_ip)
            .header("X-Real-IP", &fake_ip)
            .send()
            .await
            .expect("send failed verify request");

        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "First 5 attempts should return 401 Unauthorized"
        );
    }

    // 6th attempt: rotating to yet another fake IP
    let resp = client
        .post(&verify_url)
        .header("Authorization", "Bearer wrong_token")
        .header("X-Forwarded-For", "203.0.113.99")
        .header("X-Real-IP", "203.0.113.99")
        .send()
        .await
        .expect("send 6th verify request");

    // Must be throttled with HTTP 429 Too Many Requests because the real TCP client IP is rate-limited!
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "Real TCP client IP must be throttled with 429 on attempt > 5; header rotation must NOT bypass rate limiting!"
    );

    server_handle.abort();
}

#[tokio::test]
async fn test_s05_05_public_vs_operator_router_boundary() {
    let (_, _, _, _, _, _, state) = setup_test_app_pair();
    let auth = Arc::new(AdminTokenManager::with_token("test_admin_secret", false));
    let state = state.with_auth(auth);
    let operator = build_operator_router(state.clone());
    let public = build_router(state);

    // Verify operator router serves /dashboard/admin/verify-token
    let op_res = operator
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/admin/verify-token")
                .header("Authorization", "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(op_res.status(), StatusCode::UNAUTHORIZED);

    // Verify public router DOES NOT expose /dashboard/admin/verify-token
    let pub_res = public
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/admin/verify-token")
                .header("Authorization", "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        pub_res.status(),
        StatusCode::NOT_FOUND,
        "Public router must NOT expose operator admin verify endpoint!"
    );
}
