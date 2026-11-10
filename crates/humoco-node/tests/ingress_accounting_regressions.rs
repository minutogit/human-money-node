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
use std::sync::atomic::Ordering;
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
        hmc::{calculate_l2_payload_hash, L2AuthPayload, L2ChainLockRequest, L2LockEntry, L2LockRequest, L2Verdict},
        routes::build_operator_router,
        AppState,
    },
    config::NodeConfig,
    control::parse_account_tag,
    daemon::{BoundAddrs, NodeDaemon, ShardReadinessManager},
    identity::NodeIdentity,
    ingress::{
        pow::{self, count_leading_zero_bits, hash_work, PowError},
        tier::is_valid_client_token,
        IngressError, IngressTier, PowEngine, StorageCharge, TierController,
    },
    network::{
        framing::{HeartbeatWirePayload, LockWirePayload}, DefaultRequestHandler, NodeRequestHandler, PeerManager,
        QuicTransport,
    },
    storage::{DualTierEngine, PersistedIngressAccountingState, RedbStorage},
};
use humoco_sim_core::{
    fraud::{compute_ingress_envelope_digest, FraudProofPayload, IngressEnvelopeEvidence},
    wire::{MsgType, WireHeader, FLAG_QUOTA_EXCEEDED},
};
use sha3::Digest;

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
    hash.update(req.deletable_at.as_deref().unwrap().as_bytes());
    req.layer2_voucher_id = hex::encode(hash.finalize());
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: req.layer2_voucher_id.clone(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: req.sender_ephemeral_pub,
        receiver_pubkey_hash: None,
        change_pubkey_hash: None,
        root_valid_until_ms: req.deletable_at.as_ref().unwrap().parse().unwrap(),
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(proof);
    req.layer2_signature = key.sign(&calculate_l2_payload_hash(req)).to_bytes();
}

fn authenticate_root_fixture_with_receiver(
    req: &mut L2LockRequest,
    key: &SigningKey,
    receiver_pubkey_hash: Option<[u8; 32]>,
) {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(req.transaction_hash);
    hash.update(req.sender_ephemeral_pub);
    if let Some(receiver) = receiver_pubkey_hash {
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
        receiver_pubkey_hash,
        change_pubkey_hash: None,
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

fn make_test_hmc_spend(
    voucher_id: &str,
    ds_tag: &str,
    tx_hash: [u8; 32],
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
        ds_tag: Some(ds_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: test_now_ms(),
        deletable_at: None,
        privacy_guard: None,
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_test_causal_spend(
    previous: &L2LockRequest,
    sender_key: &SigningKey,
    next_receiver_hash: Option<[u8; 32]>,
    tx_hash: [u8; 32],
    created_at_ms: u64,
) -> L2LockRequest {
    use sha3::{Digest as _, Sha3_256};
    let proof = previous.causal_output.as_ref().unwrap();
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update(proof.state_hash);
    hash.update(32u32.to_le_bytes());
    hash.update(sender_key.verifying_key().as_bytes());
    let ds_tag = bs58::encode(hash.finalize()).into_string();

    let sender_pub = sender_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: previous.layer2_voucher_id.clone(),
        ds_tag: Some(ds_tag),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms,
        deletable_at: None,
        privacy_guard: None,
    };
    let mut output_proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: req.layer2_voucher_id.clone(),
        transaction_id: req.transaction_hash,
        state_hash: req.transaction_hash,
        sender_pubkey: req.sender_ephemeral_pub,
        receiver_pubkey_hash: next_receiver_hash,
        change_pubkey_hash: None,
        root_valid_until_ms: proof.root_valid_until_ms,
        is_root: false,
        signature: [0; 64],
    };
    output_proof.signature = sender_key.sign(&output_proof.digest().unwrap()).to_bytes();
    req.causal_output = Some(output_proof);
    req.layer2_signature = sender_key.sign(&calculate_l2_payload_hash(&req)).to_bytes();
    req
}

#[allow(clippy::type_complexity)]
fn setup_test_app_with_clock() -> (
    axum::Router,
    axum::Router,
    Arc<RedbStorage>,
    NodeIdentity,
    Arc<TierController>,
    Arc<PowEngine>,
    AppState,
    Arc<PeerManager>,
) {
    let temp = tempdir().expect("tempdir");
    let db_path = temp.path().join("test_s05_18_clock.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pm = Arc::new(PeerManager::new(vec![]));
    pm.set_simulation_mode(true);
    pm.seed_local_ticket_age(
        *identity.node_pubkey(),
        *identity.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
    let pow_engine = Arc::new(PowEngine::new(0).with_clock(pm.clock().clone()));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));

    let state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow_engine.clone(),
    )
    .with_peer_manager(pm.clone());
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
        pm,
    )
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
    let pow_engine = Arc::new(PowEngine::new(0)); // difficulty 0 for instant tests
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
    let pow = Arc::new(PowEngine::new(0));
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
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
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
                let alloc = rt.block_on(tc.record_declared_usage(now_ms, footprint)).unwrap();
                let (day, seq, cum, prev) = (alloc.epoch_day, alloc.epoch_seq, alloc.cumulative_micro_byte_years, alloc.prev_day_final_bytes);
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
        .map(|&(day, seq, cum, _prev, ts)| {
            let op_hash = *blake3::hash(&seq.to_le_bytes()).as_bytes();
            let digest = compute_ingress_envelope_digest(
                humoco_sim_core::types::NetworkId::default(),
                &gateway_pubkey,
                day,
                seq,
                ts,
                cum,
                0,
                100,
                false,
                &op_hash,
            );
            let signature = signing_key.sign(&digest).to_bytes();
            IngressEnvelopeEvidence {
                network_id: humoco_sim_core::types::NetworkId::Mainnet,
                gateway_pubkey,
                epoch_day: day,
                epoch_seq: seq,
                timestamp_ms: ts,
                declared_write_ema_micro_bj: cum,
                declared_read_ema_credits: 0,
                footprint_micro_bj: 100,
                is_read: false,
                op_hash,
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
                !proof.verify_ingress_counter_conflict_network(humoco_sim_core::types::NetworkId::Mainnet),
                "False-positive fraud detected between honest envelopes! A: day={}, seq={} vs B: day={}, seq={}",
                ev_a.epoch_day,
                ev_a.epoch_seq,
                ev_b.epoch_day,
                ev_b.epoch_seq
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
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
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
    let gw_pow = Arc::new(PowEngine::new(0));
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
        let alloc = gw_tier.record_declared_usage(now_ms, footprint).await.unwrap();
        let (epoch_day, epoch_seq, cum, prev) = (alloc.epoch_day, alloc.epoch_seq, alloc.cumulative_micro_byte_years, alloc.prev_day_final_bytes);

        let parent = [0x50 + seq_idx as u8; 32];
        let root_valid = now_ms + 100_000;
        let lock_req = make_test_hmc_genesis(parent, root_valid, gateway_id.signing_key());
        let tx_hash = lock_req.transaction_hash;

        let digest = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
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

    let pow = Arc::new(PowEngine::new(0));
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

    let vip_token = format!("vip_{tag_hex}");
    let (_router, _operator, storage, _identity, tiers, _pow, _state) = setup_test_app_pair();
    tiers.register_vip_token(&vip_token, account_tag);
    tiers.topup_vip_quota(account_tag, 200).unwrap();

    // Debit 50 in RAM before async persistence worker drains
    let rem = tiers.try_charge_vip_in_memory(&account_tag, 50).unwrap();
    assert_eq!(rem, 150);

    // Exercise topup sequence matching control server / dashboard handler:
    // (which calls register_vip_tag before topup_vip_quota)
    let tag_bytes = parse_account_tag(&tag_hex);
    tiers.register_vip_token(&vip_token, tag_bytes);
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
    let pow = Arc::new(PowEngine::new(0));
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
    let vip_token = format!("vip_{tag_hex}");
    tiers.register_vip_token(&vip_token, account_tag);

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
    for _ in 0..50 {
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
    // Daily quota with 5x Whale Brake:
    let daily_limit = tier_controller.calculate_daily_quota(5.0, 1.0);
    assert!(daily_limit > 0);

    // Exhaust daily quota directly
    tier_controller
        .evaluate_vip_quota(&account_tag, daily_limit, now_ms, 5.0)
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
            StorageCharge::single(31_536_000), // 1 year = 192 BY
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

    // 3. Test HTTP POST /v1/lock endpoint rejection (1 day TTL = 1 Byte-Year)
    let root = make_test_hmc_genesis([0x99; 32], now_ms + 86_400_000, identity.signing_key());
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
    let retry_res = tier_controller
        .evaluate_and_charge_with_time_and_retry(
            Some(token),
            None,
            None,
            None,
            StorageCharge::single(31_536_000),
            None,
            Some(now_ms),
            true, // is_retry = true
        )
        .await;
    assert_eq!(
        retry_res.as_ref().ok(),
        Some(&IngressTier::Tier1Vip),
        "Idempotent retry must succeed even when VIP daily cap is reached"
    );
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
            StorageCharge::single(31_536_000),
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
    let pow_engine = Arc::new(PowEngine::new(0));

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
            StorageCharge::single(31_536_000),
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
    let usage_bytes = controller.vip_rolling_usage_at_for_test(&account_tag, now_ms);
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
            StorageCharge::single(31_536_000),
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

    // 1 year TTL = 192 Byte-Years
    let req_by = 192u64;
    let daily_limit = tiers.calculate_daily_quota(5.0, 1.0);

    // Consume all but exactly 3 * 192 of the daily allowance
    assert!(daily_limit > 3 * req_by);
    let pre_consume = daily_limit - 3 * req_by;
    tiers
        .evaluate_vip_quota(&account_tag, pre_consume, now_ms, 5.0)
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
                StorageCharge::single(31_536_000),
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
        .evaluate_f2f_quota(token_1, daily_limit, now_ms)
        .expect("friend 1 quota must be admitted up to limit");

    // Friend 1 should now be rejected
    let f1_second = tier_controller.evaluate_f2f_quota(token_1, 1, now_ms);
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
            StorageCharge::single(31_536_000),
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
        .evaluate_node_write_quota(&colliding_32, 100, now_ms)
        .expect("P2P node write must succeed");

    tier_controller.register_vip_token("vip_colliding_tag", colliding_32);
    tier_controller.set_cached_vip_quota(colliding_32, 10_000);
    tier_controller
        .evaluate_vip_quota(&colliding_32, 100, now_ms, 5.0)
        .expect("VIP write must succeed");

    // 5. Assert list_f2f_clients reports each friend's own independent usage accurately
    let client_dtos = tier_controller.list_f2f_clients(now_ms);
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

    // 6. Next-day rolling decay verification
    let next_day = epoch_day + 1;
    let next_day_dtos = tier_controller.list_f2f_clients(next_day * 86_400_000);
    let next_f1 = next_day_dtos.iter().find(|c| c.label == "Friend-1").unwrap();
    assert!(
        next_f1.writes_today < daily_limit,
        "Usage must decay over time: got {}",
        next_f1.writes_today
    );
    assert!(
        !next_f1.whale_brake_active,
        "Whale brake must reset on next day due to rolling decay"
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
    let pow = Arc::new(PowEngine::new(0));
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

// ===========================================================================
// S05-06: Public Tier-3 shared rolling pool & constant memory (zero bypass)
// ===========================================================================

#[tokio::test]
async fn test_s05_06_public_tier3_shared_rolling_budget_and_constant_memory() {
    let (router, _operator, _storage, _identity, tier_controller, _pow, _state) =
        setup_test_app_pair();

    let daily_limit = tier_controller.calculate_daily_quota(1.0, 1.0);
    assert_eq!(daily_limit, 960_000);

    let now_ms = test_now_ms();
    let parent_1 = [0x11u8; 32];
    let parent_2 = [0x22u8; 32];
    let parent_3 = [0x33u8; 32];

    // 1. First anonymous write for parent_1 consumes 960,000 BY (full daily quota)
    // 5,000 years * 192 = 960,000 BY
    let ttl_full = 5_000 * 31_536_000;
    let res_1 = tier_controller
        .evaluate_and_charge_with_time(
            None,
            None,
            None,
            None,
            StorageCharge::single(ttl_full),
            Some(&parent_1),
            Some(now_ms),
        )
        .await;
    assert_eq!(
        res_1.as_ref().ok(),
        Some(&IngressTier::Tier3Public),
        "Initial anonymous Tier-3 write up to daily quota must succeed"
    );

    // 2. Second anonymous write with DISTINCT parent_lock (parent_2) MUST BE REJECTED
    // Fixes S05-06: Shared O(1) RollingQuotaCounter prevents distinct parent_lock quota bypass!
    let ttl_extra = 31_536_000; // 1 year = 192 BY
    let res_2 = tier_controller
        .evaluate_and_charge_with_time(
            None,
            None,
            None,
            None,
            StorageCharge::single(ttl_extra),
            Some(&parent_2),
            Some(now_ms),
        )
        .await;
    assert!(
        matches!(res_2, Err(IngressError::QuotaExceeded { available, required }) if available == 0 && required == 192),
        "S05-06: Distinct parent_2 MUST NOT bypass public Tier-3 quota; shared rolling counter required: got {:?}",
        res_2
    );

    // 3. Third anonymous write with parent_3 also rejected
    let res_3 = tier_controller
        .evaluate_and_charge_with_time(
            None,
            None,
            None,
            None,
            StorageCharge::single(ttl_extra),
            Some(&parent_3),
            Some(now_ms),
        )
        .await;
    assert!(
        matches!(res_3, Err(IngressError::QuotaExceeded { .. })),
        "Parent 3 must also be rejected by shared pool"
    );

    // 4. HTTP layer verification: POST /v1/lock with another distinct parent returns HTTP 429
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let http_now = test_now_ms();
    let req_http = make_test_hmc_genesis(
        [0x99u8; 32],
        http_now + 31_536_000 * 1000,
        &client_key,
    );
    let http_res = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_http).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        http_res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "HTTP POST /v1/lock must return 429 Too Many Requests when Tier-3 shared rolling pool is full"
    );
}

// ===========================================================================
// S05-07: Consensus time propagation for PoW and TierController
// ===========================================================================

#[tokio::test]
async fn test_s05_07_consensus_time_propagation_for_pow_and_tiers() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_07.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());

    // Attached NetworkClock shifted +3,600,000 ms ahead (+1 hour)
    let clock = Arc::new(humoco_node::network::NetworkClock::new());
    clock.fast_reseed_on_merge(3_600_000);

    let pow = Arc::new(PowEngine::new(8).with_clock(clock.clone()));
    let controller = Arc::new(TierController::new(storage, pow.clone()));

    let parent = [0x77u8; 32];

    // 1. When now_ms is None, pow.now_ms() / controller.effective_now_ms(None) queries NetworkClock (+3,600,000 ms)
    let net_time_sec = clock.net_time_ms() / 1000;
    let net_slot = pow.current_epoch_slot(net_time_sec);
    let net_challenge = pow::compute_stateless_challenge(&parent, net_slot);
    let net_challenge_hex = hex::encode(net_challenge);

    // Unshifted OS-clock slot
    let os_time_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let os_slot = os_time_sec / 600;
    let os_challenge = pow::compute_stateless_challenge(&parent, os_slot);
    let os_challenge_hex = hex::encode(os_challenge);

    let net_nonce = (0..50_000)
        .find(|&n| count_leading_zero_bits(&hash_work(&parent, net_slot, n)) >= 8)
        .expect("solve net PoW");

    // NetworkClock challenge must be accepted when now_ms is None
    let accept_net = controller
        .evaluate_and_charge_with_time(
            None,
            None,
            Some(&net_challenge_hex),
            Some(net_nonce),
            StorageCharge::single(60),
            Some(&parent),
            None,
        )
        .await;
    assert_eq!(
        accept_net.as_ref().ok(),
        Some(&IngressTier::Tier3Public),
        "Challenge derived from NetworkClock must be accepted when now_ms is None"
    );

    // OS-clock challenge must be rejected by consensus time
    if os_slot != net_slot {
        let reject_os = controller
            .evaluate_and_charge_with_time(
                None,
                None,
                Some(&os_challenge_hex),
                Some(0),
                StorageCharge::single(60),
                Some(&parent),
                None,
            )
            .await;
        assert!(
            matches!(reject_os, Err(IngressError::InvalidPoW(PowError::InvalidFormat))),
            "OS-clock challenge must be rejected by NetworkClock consensus time"
        );
    }

    // 2. Explicit now_ms (+7,200,000 ms, +2 hours) overrides NetworkClock
    let explicit_now_ms = clock.net_time_ms() + 3_600_000;
    let explicit_now_sec = explicit_now_ms / 1000;
    let explicit_slot = pow.current_epoch_slot(explicit_now_sec);
    let explicit_challenge = pow::compute_stateless_challenge(&parent, explicit_slot);
    let explicit_challenge_hex = hex::encode(explicit_challenge);

    let explicit_nonce = (0..50_000)
        .find(|&n| count_leading_zero_bits(&hash_work(&parent, explicit_slot, n)) >= 8)
        .expect("solve explicit PoW");

    let accept_explicit = controller
        .evaluate_and_charge_with_time(
            None,
            None,
            Some(&explicit_challenge_hex),
            Some(explicit_nonce),
            StorageCharge::single(60),
            Some(&parent),
            Some(explicit_now_ms),
        )
        .await;
    assert_eq!(
        accept_explicit.as_ref().ok(),
        Some(&IngressTier::Tier3Public),
        "Challenge aligned to explicit now_ms must be accepted"
    );

    // NetworkClock challenge must be rejected when evaluated against explicit_now_ms
    let reject_net_on_explicit = controller
        .evaluate_and_charge_with_time(
            None,
            None,
            Some(&net_challenge_hex),
            Some(net_nonce),
            StorageCharge::single(60),
            Some(&parent),
            Some(explicit_now_ms),
        )
        .await;
    assert!(
        matches!(reject_net_on_explicit, Err(IngressError::InvalidPoW(PowError::InvalidFormat))),
        "Older NetworkClock challenge must be rejected when caller provides explicit now_ms"
    );
}

// ===========================================================================
// S05-08: PoW zero TTL, overflow, difficulty bounds and no legacy fallback
// ===========================================================================

#[tokio::test]
async fn test_s05_08_pow_zero_ttl_overflow_difficulty_bounds_and_no_legacy_fallback() {
    let pow = PowEngine::new(252).with_ttl(0);

    // 1. Clamped TTL >= 1 prevents division by zero and saturates cleanly on u64::MAX
    assert_eq!(pow.current_epoch_slot(0), 0);
    assert_eq!(pow.current_epoch_slot(u64::MAX), u64::MAX);

    let (chal, diff, exp) = pow.generate_challenge_for_parent_at(&[0u8; 32], u64::MAX);
    assert_eq!(diff, 252);
    assert_eq!(exp, u64::MAX);
    assert_eq!(chal.len(), 64);

    // 2. Difficulty bounds and safe non-finite float handling:
    // 252 + 8 = 260 -> capped at 256
    assert_eq!(pow.required_difficulty_for_load(0.95), 256);
    assert_eq!(pow.required_difficulty_for_load(1.0), 256);
    // 252 + 4 = 256
    assert_eq!(pow.required_difficulty_for_load(0.6), 256);
    // <= 0.5 -> baseline 252
    assert_eq!(pow.required_difficulty_for_load(0.5), 252);
    assert_eq!(pow.required_difficulty_for_load(0.1), 252);
    // NaN and infinities return baseline 252 safely
    assert_eq!(pow.required_difficulty_for_load(f64::NAN), 252);
    assert_eq!(pow.required_difficulty_for_load(f64::INFINITY), 252);
    assert_eq!(pow.required_difficulty_for_load(f64::NEG_INFINITY), 252);

    // 3. solve_blake3_hashcash returns None for non-zero-parent or unknown challenges
    let custom_parent = [0x55u8; 32];
    let custom_chal = pow::compute_stateless_challenge(&custom_parent, 42);
    let custom_chal_hex = hex::encode(custom_chal);
    assert_eq!(
        pow::solve_blake3_hashcash(&custom_chal_hex, 4, 100),
        None,
        "Unknown/non-zero-parent challenge must return None without legacy compute_solution_hash fallback loop"
    );
}

// ===========================================================================
// S05-09: Rolling EMA quota recovery, exact retry, VIP latch & QUIC node quota
// ===========================================================================

#[tokio::test]
async fn test_s05_09_rolling_ema_quota_exact_limit_retry_vip_latch_and_quic_node_quota() {
    let (router, _operator, storage, _identity, tier_controller, _pow, _state) =
        setup_test_app_pair();

    let account_tag = [0x88u8; 32];
    let token = "vip_rolling_test_token";
    tier_controller.register_vip_token(token, account_tag);
    tier_controller.set_cached_vip_quota(account_tag, 20_000_000);
    storage.set_quota(&account_tag, 20_000_000).unwrap();

    let f2f_token = "f2f_0123456789abcdef0123456789abcdef";
    tier_controller.register_f2f_peer(f2f_token);

    let vip_limit = tier_controller.calculate_daily_quota(5.0, 1.0);
    assert_eq!(vip_limit, 4_800_000);

    // -----------------------------------------------------------------------
    // (a) Smooth physical recovery via 24h-half-life EMA
    // -----------------------------------------------------------------------
    let t0_ms = 1_000_000_000_000u64;
    // Consume 100% of VIP daily quota at t0
    tier_controller
        .evaluate_vip_quota(&account_tag, vip_limit, t0_ms, 5.0)
        .expect("VIP quota first consume up to limit");

    // Attempting 1 more unit at t0 is rejected
    let vip_rej = tier_controller.evaluate_vip_quota(&account_tag, 1, t0_ms, 5.0);
    assert!(matches!(vip_rej, Err(IngressError::QuotaExceeded { .. })));

    // UTC midnight boundary test: 86_399_999 ms -> 86_400_001 ms (2 ms difference)
    let t_midnight_1 = 86_399_999u64;
    let t_midnight_2 = 86_400_001u64;
    let mid_tag = [0x79u8; 32];
    tier_controller.register_vip_token("mid_token", mid_tag);
    tier_controller.set_cached_vip_quota(mid_tag, 20_000_000);
    storage.set_quota(&mid_tag, 20_000_000).unwrap();
    tier_controller
        .evaluate_vip_quota(&mid_tag, vip_limit, t_midnight_1, 5.0)
        .expect("consume at 23:59:59");
    // At 00:00:00 (2 ms later), continuous EMA does NOT reset to 0!
    let burst_res = tier_controller.evaluate_vip_quota(&mid_tag, vip_limit, t_midnight_2, 5.0);
    assert!(
        matches!(burst_res, Err(IngressError::QuotaExceeded { .. })),
        "S05-09: Quota must NOT burst-reset across UTC midnight cliff: got {:?}",
        burst_res
    );

    // 50% recovery after 24h (+86_400_000 ms)
    let t_24h_ms = t0_ms + 86_400_000;
    let usage_after_24h = tier_controller.vip_rolling_usage_at_for_test(&account_tag, t_24h_ms);
    assert!(
        usage_after_24h <= vip_limit / 2 + 10,
        "Usage after 24h must decay to ~50%: got {}",
        usage_after_24h
    );
    // Exactly 50% (2,400,000 BY) can now be spent
    let half_spend = tier_controller.evaluate_vip_quota(&account_tag, 2_400_000, t_24h_ms, 5.0);
    assert!(half_spend.is_ok(), "50% recovered quota must be spendable after 24h");

    // Out-of-order older timestamp never rolls back usage
    let t_older_ms = t0_ms - 1_000_000;
    let older_usage = tier_controller.vip_rolling_usage_at_for_test(&account_tag, t_older_ms);
    assert!(older_usage >= 2_400_000, "Older timestamp must not roll back or erase recorded usage");

    // -----------------------------------------------------------------------
    // (b) Exact idempotent retry returns 200 OK even at 100% quota
    // -----------------------------------------------------------------------
    // Commit a lock via POST /v1/lock using client_key
    let http_now_ms = test_now_ms();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let req_genesis = make_test_hmc_genesis(
        [0x44u8; 32],
        http_now_ms + 86_400_000,
        &client_key,
    );

    // First POST /v1/lock succeeds (difficulty 0)
    let res_post_1 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_genesis).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_post_1.status(), StatusCode::CREATED);

    // Exhaust remaining Public quota to 100%
    tier_controller.exhaust_public_quota_for_test(http_now_ms);

    // A brand new lock is now rejected with 429
    let req_other = make_test_hmc_genesis(
        [0x99u8; 32],
        http_now_ms + 86_400_000,
        &client_key,
    );
    let res_other = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_other).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_other.status(), StatusCode::TOO_MANY_REQUESTS);

    // Exact idempotent retry of committed lock returns 200 OK even at 100% quota!
    let res_retry = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_genesis).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res_retry.status(),
        StatusCode::OK,
        "Idempotent retry of committed lock must succeed with 200 OK at 100% quota"
    );

    // Direct unit check on evaluate_and_charge_with_time_and_retry with is_retry = true
    let vip_retry_res = tier_controller
        .evaluate_and_charge_with_time_and_retry(
            Some(token),
            None,
            None,
            None,
            StorageCharge::single(31_536_000),
            None,
            Some(t0_ms),
            true,
        )
        .await;
    assert_eq!(vip_retry_res.as_ref().ok(), Some(&IngressTier::Tier1Vip));

    let f2f_retry_res = tier_controller
        .evaluate_and_charge_with_time_and_retry(
            None,
            Some(f2f_token),
            None,
            None,
            StorageCharge::single(31_536_000),
            None,
            Some(t0_ms),
            true,
        )
        .await;
    assert_eq!(f2f_retry_res.as_ref().ok(), Some(&IngressTier::Tier2F2F));

    // -----------------------------------------------------------------------
    // (c) VIP persistence fail-closed latch
    // -----------------------------------------------------------------------
    tier_controller
        .quota_worker_failure_handle()
        .store(true, Ordering::Release);

    let topup_err = tier_controller.topup_vip_quota(account_tag, 100);
    assert!(
        matches!(topup_err, Err(IngressError::QuotaPersistenceUnavailable)),
        "topup_vip_quota must fail closed when vip_persist_failed is latched"
    );

    let charge_err = tier_controller.try_charge_vip_in_memory(&account_tag, 10);
    assert!(
        matches!(charge_err, Err(IngressError::QuotaPersistenceUnavailable)),
        "try_charge_vip_in_memory must fail closed when vip_persist_failed is latched"
    );

    let debit_err = tier_controller
        .evaluate_and_charge_with_time(
            Some(token),
            None,
            None,
            None,
            StorageCharge::single(60),
            None,
            Some(t0_ms),
        )
        .await;
    assert!(
        matches!(debit_err, Err(IngressError::QuotaPersistenceUnavailable)),
        "evaluate_and_charge VIP debit must fail closed when vip_persist_failed is latched"
    );

    // -----------------------------------------------------------------------
    // (d) Real QUIC node quota: write & read rate enforcement over QUIC
    // -----------------------------------------------------------------------
    let quic_temp = tempdir().unwrap();
    let q_storage = Arc::new(RedbStorage::open(&quic_temp.path().join("q_server.redb")).unwrap());
    let (q_engine, _q_worker) = DualTierEngine::new(q_storage.clone());
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
    let readiness = Arc::new(ShardReadinessManager::new());
    for shard in 0..=u16::MAX {
        readiness.mark_shard_ready(shard);
    }

    let q_pow = Arc::new(PowEngine::new(0));
    let server_tc = Arc::new(TierController::new(q_storage.clone(), q_pow));

    let handler = NodeRequestHandler::with_peer_manager(
        q_engine.clone(),
        q_storage.clone(),
        server_id.clone(),
        server_peer_mgr.clone(),
    )
    .with_readiness_manager(readiness)
    .with_tier_controller(server_tc.clone());

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

    server_peer_mgr
        .register_f2f_friend(gateway_pubkey, Some(gateway_transport.local_addr().unwrap()))
        .await;
    gw_peer_mgr
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = gateway_transport
        .connect_peer(server_addr)
        .await
        .expect("connect QUIC peer");

    let quic_now_ms = test_now_ms();

    // Exhaust gateway node write quota (pre-seed with +5s margin against 1-second wall clock decay)
    let daily_node_limit = server_tc.calculate_daily_quota(5.0, 1.0);
    server_tc
        .evaluate_node_write_quota(&gateway_pubkey, daily_node_limit, quic_now_ms + 5_000)
        .expect("initial node write consume");

    // LockVerifyRequest over QUIC with a 5-year voucher (960 Byte-Years) receives FLAG_QUOTA_EXCEEDED
    let ttl_s = 5 * 31_536_000u64;
    let root_valid_until = quic_now_ms + ttl_s * 1000;
    let lock_req = make_test_hmc_genesis([0x66u8; 32], root_valid_until, gateway_id.signing_key());
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let digest = compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        &gateway_pubkey,
        0,
        1,
        quic_now_ms,
        0,
        0,
        footprint,
        false,
        &lock_req.transaction_hash,
    );
    let sender_sig = gateway_id.signing_key().sign(&digest).to_bytes();

    let wire_payload = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_req,
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: gateway_pubkey,
        sender_signature: sender_sig,
        timestamp_ms: quic_now_ms,
    })
    .unwrap();
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        wire_payload.len() as u32,
    );

    let (resp_hdr, _) = gateway_transport
        .send_request(&conn, &header, &wire_payload)
        .await
        .expect("send QUIC request");

    assert_eq!(
        resp_hdr.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "LockVerifyRequest over QUIC must return FLAG_QUOTA_EXCEEDED when node write quota is exhausted"
    );

    // Exhaust gateway node read quota (pre-seed with +5s margin against 1-second wall clock decay)
    let daily_node_read_limit = server_tc.calculate_daily_read_quota(5.0, 1.0);
    server_tc
        .evaluate_node_read_quota(&gateway_pubkey, daily_node_read_limit, quic_now_ms + 5_000)
        .expect("initial node read consume");

    // StatusQuery over QUIC receives FLAG_QUOTA_EXCEEDED
    let query_lock_id = [0x77u8; 32];
    let query_digest = compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        &gateway_pubkey,
        0,
        0,
        quic_now_ms,
        0,
        0,
        0,
        true,
        &query_lock_id,
    );
    let query_sig = gateway_id.signing_key().sign(&query_digest).to_bytes();

    let status_payload = bincode::serialize(&humoco_node::network::framing::StatusQueryPayload {
        lock_id: query_lock_id,
        parent_lock: [0x88u8; 32],
        shard_id: 1,
        sender_pubkey: gateway_pubkey,
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: 0,
        timestamp_ms: quic_now_ms,
        sender_signature: query_sig,
    })
    .unwrap();
    let status_hdr = WireHeader::new(
        MsgType::StatusQuery as u16,
        2,
        0,
        0,
        status_payload.len() as u32,
    );

    let (status_resp_hdr, _) = gateway_transport
        .send_request(&conn, &status_hdr, &status_payload)
        .await
        .expect("send QUIC status query");

    assert_eq!(
        status_resp_hdr.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "StatusQuery over QUIC must return FLAG_QUOTA_EXCEEDED when node read quota is exhausted"
    );
}

// ===========================================================================
// S05-10: Auth expired map eviction, key bounds, empty file & Bearer casing
// ===========================================================================

#[tokio::test]
async fn test_s05_10_auth_expired_map_eviction_key_bounds_empty_file_and_bearer_case() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_10.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let controller = TierController::new(storage, pow);

    // 1. Bearer casing and trimming in resolve_account_tag
    let vip_tag = [0x99u8; 32];
    controller.register_vip_token("my_vip_token", vip_tag);

    assert_eq!(
        controller.resolve_account_tag("BEARER my_vip_token").as_ref().ok(),
        Some(&vip_tag),
        "BEARER uppercase prefix must resolve account tag"
    );
    assert_eq!(
        controller.resolve_account_tag("bearer my_vip_token").as_ref().ok(),
        Some(&vip_tag),
        "bearer lowercase prefix must resolve account tag"
    );
    assert_eq!(
        controller.resolve_account_tag("  Bearer   my_vip_token   ").as_ref().ok(),
        Some(&vip_tag),
        "Bearer with extra surrounding and interior whitespace must resolve account tag"
    );
    assert_eq!(
        controller.resolve_account_tag("my_vip_token").as_ref().ok(),
        Some(&vip_tag),
        "Raw token without Bearer prefix must resolve account tag"
    );
    assert!(
        controller.resolve_account_tag("BEARER").is_err(),
        "Bare BEARER string must be rejected"
    );
    assert!(
        controller.resolve_account_tag("Bearer ").is_err(),
        "Bare Bearer prefix without token must be rejected"
    );

    // 2. AdminTokenManager Bearer casing and trimming
    let admin_mgr = AdminTokenManager::with_token("admin_secret_42", false);
    assert!(admin_mgr.verify_token(Some("BEARER admin_secret_42")));
    assert!(admin_mgr.verify_token(Some("bearer admin_secret_42")));
    assert!(admin_mgr.verify_token(Some("  Bearer   admin_secret_42  ")));
    assert!(admin_mgr.verify_token(Some("admin_secret_42")));
    assert!(!admin_mgr.verify_token(Some("BEARER")));
    assert!(!admin_mgr.verify_token(Some("bearer")));
    assert!(!admin_mgr.verify_token(Some("Bearer ")));
    assert!(!admin_mgr.verify_token(Some("wrong_token")));
    assert!(!admin_mgr.verify_token(None));

    // 3. Expired map eviction at 1,024 IPs
    let t0 = Instant::now();
    let expired_time = t0 - Duration::from_secs(120); // > 60s window
    for i in 0..1024 {
        let ip = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        admin_mgr.record_failure_at(&ip, expired_time);
    }
    // Now at current time t0, checking rate limit for a new IP triggers eviction of all expired IPs!
    assert!(
        admin_mgr.check_rate_limit_at("192.168.1.100", t0),
        "Rate limit check must succeed and evict expired entries"
    );

    // 4. Oversized IP handling
    let oversized_ip = "192.168.1.".to_string() + &"9".repeat(200);
    assert!(admin_mgr.check_rate_limit(&oversized_ip));
    admin_mgr.record_failure(&oversized_ip);

    // 5. Empty admin.token file rejection
    let empty_dir = tempdir().unwrap();
    std::fs::write(empty_dir.path().join("admin.token"), b"  \n\r\n  ").unwrap();
    let load_res = AdminTokenManager::load_or_create(empty_dir.path(), false);
    assert!(
        load_res.is_err(),
        "Empty admin.token file must be rejected with InvalidData error"
    );
    assert_eq!(
        load_res.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

// ===========================================================================
// S05-11 & S05-12: Ingress Accounting Durability & VIP Bearer Separation
// ===========================================================================

#[tokio::test]
async fn test_s05_11_restart_preserves_ingress_accounting_monotonicity() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("ingress_monotonic.redb");
    let day_ms = 86_400_000u64;

    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let boot_day = pow.now_ms() / day_ms;
    let base_t = boot_day * day_ms;

    let alloc2_seq;
    {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

        let alloc1 = tc.record_declared_usage(base_t + 1_000, 100).await.unwrap();
        assert_eq!(alloc1.epoch_day, boot_day as u32);
        assert_eq!(alloc1.epoch_seq, 1);
        assert_eq!(alloc1.cumulative_micro_byte_years, 100);
        assert_eq!(alloc1.prev_day_final_bytes, 0);

        let alloc2 = tc.record_declared_usage(base_t + 2_000, 200).await.unwrap();
        assert_eq!(alloc2.epoch_day, boot_day as u32);
        assert_eq!(alloc2.epoch_seq, 2);
        assert_eq!(alloc2.cumulative_micro_byte_years, 300);
        assert_eq!(alloc2.prev_day_final_bytes, 0);
        alloc2_seq = alloc2.epoch_seq;
        tc.wait_for_accounting_drain().await.unwrap();
    }

    // Node restart: re-instantiate TierController against intact storage (reloads from disk)
    {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

        let alloc3 = tc.record_declared_usage(base_t + 3_000, 150).await.unwrap();
        assert_eq!(alloc3.epoch_day, boot_day as u32);
        assert!(
            alloc3.epoch_seq > alloc2_seq,
            "Sequence must continue monotonically from persisted state (post_seq > pre_seq), not reset to 1!"
        );
        assert_eq!(alloc3.cumulative_micro_byte_years, 450);
        assert_eq!(alloc3.prev_day_final_bytes, 0);
    }
}

#[tokio::test]
async fn test_s05_11_allocation_persistence_failure_fail_closed() {
    let (router, _operator, storage, identity, tier_controller, _pow, _state) = setup_test_app_pair();

    // 1. Initial valid genesis registration succeeds (root anchor has no ingress envelope)
    let now_ms = test_now_ms();
    let root = make_test_hmc_genesis([0x77; 32], now_ms + 100_000, identity.signing_key());
    let root_entry = humoco_node::api::hmc::L2LockEntry::from(&root);
    let root_tag = bs58::encode(root_entry.t_id).into_string();
    storage.put_hmc_lock(&root_tag, &root_entry).unwrap();

    // 2. Fail persistence explicitly -> record_declared_usage fails closed immediately
    tier_controller.fail_accounting_persistence_for_test();
    let res = tier_controller.record_declared_usage(test_now_ms(), 100).await;
    assert!(
        matches!(res, Err(IngressError::AccountingPersistenceUnavailable)),
        "Must return AccountingPersistenceUnavailable when persistence is broken"
    );

    // 3. HTTP POST /v1/lock spend submission must return 503 Service Unavailable when persistence fails
    let spend_key = SigningKey::from_bytes(&[0x88; 32]);
    let spend = make_test_hmc_spend(&root.layer2_voucher_id, "spent_tag_503", [0x99; 32], &spend_key);
    let req_body = serde_json::to_vec(&spend).unwrap();

    let http_res = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        http_res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "HTTP POST /v1/lock spend must fail closed with 503 Service Unavailable when persistence fails"
    );

    // 3. Queue saturation: create controller with small capacity (e.g. capacity 1)
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("sat.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let bounded_tc = Arc::new(TierController::new_with_persist_capacity(storage, pow, 1));

    // Fill channel capacity
    let _held_permit = bounded_tc.reserve_accounting_permit_for_test().expect("reserve permit");
    let sat_res = bounded_tc.record_declared_usage(test_now_ms(), 50).await;
    assert!(
        matches!(sat_res, Err(IngressError::AccountingPersistenceUnavailable)),
        "Must fail closed when persistence channel is saturated"
    );
}

#[tokio::test]
async fn test_s05_11_calendar_day_rollover_and_restart() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("rollover_restart.redb");
    let day_ms = 86_400_000u64;

    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let boot_day = pow.now_ms() / day_ms;
    let base_t = boot_day * day_ms;

    let alloc3_seq;
    {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

        // Day usage
        let alloc1 = tc.record_declared_usage(base_t + 1_000, 500).await.unwrap();
        assert_eq!(alloc1.epoch_day, boot_day as u32);
        assert_eq!(alloc1.epoch_seq, 1);
        assert_eq!(alloc1.cumulative_micro_byte_years, 500);
        assert_eq!(alloc1.prev_day_final_bytes, 0);

        let alloc2 = tc.record_declared_usage(base_t + 2_000, 300).await.unwrap();
        assert_eq!(alloc2.epoch_day, boot_day as u32);
        assert_eq!(alloc2.epoch_seq, 2);
        assert_eq!(alloc2.cumulative_micro_byte_years, 800);
        assert_eq!(alloc2.prev_day_final_bytes, 0);

        // Day rollover
        let alloc3 = tc.record_declared_usage(base_t + day_ms + 100, 200).await.unwrap();
        assert_eq!(alloc3.epoch_day, (boot_day + 1) as u32);
        assert_eq!(alloc3.epoch_seq, 1, "epoch_seq resets to 1 on calendar day rollover");
        assert_eq!(alloc3.cumulative_micro_byte_years, 200);
        assert_eq!(
            alloc3.prev_day_final_bytes, 800,
            "prev_day_final_bytes must preserve final cumulative bytes of Day 100"
        );
        alloc3_seq = alloc3.epoch_seq;
        tc.wait_for_accounting_drain().await.unwrap();
    }

    // Node restarts on next day against intact storage
    {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

        let alloc4 = tc.record_declared_usage(base_t + day_ms + 500, 150).await.unwrap();
        assert_eq!(alloc4.epoch_day, (boot_day + 1) as u32);
        assert!(
            alloc4.epoch_seq > alloc3_seq,
            "epoch_seq must continue monotonically on Day 101 after restart (post_seq > pre_seq)"
        );
        assert_eq!(alloc4.cumulative_micro_byte_years, 350);
        assert_eq!(
            alloc4.prev_day_final_bytes, 800,
            "prev_day_final_bytes must remain intact across restart on Day 101"
        );
    }
}

#[tokio::test]
async fn test_s05_11_day_rollover_after_high_sequence_lease() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("high_lease_rollover.redb");
    let day_ms = 86_400_000u64;

    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let boot_day = pow.now_ms() / day_ms;
    let base_t = boot_day * day_ms;

    let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

    // 1. Day D: perform allocations exceeding INGRESS_SEQ_LEASE_BLOCK (1024), e.g. 1025 allocations,
    // to trigger a higher sequence lease (> 1024, namely 2048).
    for i in 1..=1025 {
        let alloc = tc.record_declared_usage(base_t + i, 1).await.unwrap();
        assert_eq!(alloc.epoch_day, boot_day as u32);
        assert_eq!(alloc.epoch_seq, i);
    }
    tc.wait_for_accounting_drain().await.unwrap();

    let persisted_d = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(persisted_d.current_day, boot_day);
    assert_eq!(persisted_d.last_epoch_seq, 1025);
    assert_eq!(
        persisted_d.reserved_epoch_seq, 2048,
        "Day D reserved_epoch_seq must reflect second lease block (2048)"
    );

    // 2. Rollover to Day D+1: allocate seq 1 on Day D+1
    let next_day_t = base_t + day_ms + 100;
    let alloc_next_1 = tc.record_declared_usage(next_day_t, 1).await.unwrap();
    assert_eq!(alloc_next_1.epoch_day, (boot_day + 1) as u32);
    assert_eq!(alloc_next_1.epoch_seq, 1);

    tc.wait_for_accounting_drain().await.unwrap();
    let persisted_d1 = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(persisted_d1.current_day, boot_day + 1);
    assert_eq!(persisted_d1.last_epoch_seq, 1);
    assert_eq!(
        persisted_d1.reserved_epoch_seq,
        humoco_node::ingress::tier::INGRESS_SEQ_LEASE_BLOCK,
        "Day D+1 initial reserved_epoch_seq must start at INGRESS_SEQ_LEASE_BLOCK (1024), NOT Day D's high reserved_epoch_seq ({})",
        persisted_d.reserved_epoch_seq
    );

    // 3. Advance properly past INGRESS_SEQ_LEASE_BLOCK on Day D+1
    for i in 2..=1025 {
        let alloc = tc.record_declared_usage(next_day_t + i, 1).await.unwrap();
        assert_eq!(alloc.epoch_day, (boot_day + 1) as u32);
        assert_eq!(alloc.epoch_seq, i);
    }
    tc.wait_for_accounting_drain().await.unwrap();

    let persisted_d1_high = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(persisted_d1_high.current_day, boot_day + 1);
    assert_eq!(persisted_d1_high.last_epoch_seq, 1025);
    assert_eq!(
        persisted_d1_high.reserved_epoch_seq, 2048,
        "Day D+1 reserved_epoch_seq must advance properly past 1024 to 2048 once allocations exceed 1024"
    );
}

#[tokio::test]
async fn test_s05_11_real_quic_restart_regression() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("server.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
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

    let gw_db_path = temp.path().join("gw.redb");
    let gw_storage = Arc::new(RedbStorage::open(&gw_db_path).unwrap());
    let gw_pow = Arc::new(PowEngine::new(0));

    let base_t = server_peer_mgr.net_time_ms();
    let now_ms_1 = base_t;
    let now_ms_2 = base_t + 1_000;

    // Phase 1: Gateway boots, acquires seq 1, sends LockVerifyRequest over QUIC
    {
        let gw_tier = Arc::new(TierController::new(gw_storage.clone(), gw_pow.clone()));

        let gw_cancel = CancellationToken::new();
        let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
        let gw_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &gateway_id,
            gw_peer_mgr.clone(),
            Arc::new(DefaultRequestHandler),
            gw_cancel.clone(),
        )
        .expect("bind gw QUIC");
        let _gw_accept = gw_transport.spawn_accept_loop();

        server_peer_mgr
            .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
            .await;
        gw_peer_mgr
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
            .await;

        let conn = gw_transport.connect_peer(server_addr).await.unwrap();

        for _ in 0..10 {
            gw_tier
                .evaluate_and_charge_with_time_and_retry(
                    None,
                    None,
                    None,
                    None,
                    StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                    Some(&[0x11; 32]),
                    Some(now_ms_1),
                    false,
                )
                .await
                .expect("admission 1");
        }

        let ttl_s = 100u64;
        let root_valid = now_ms_1 + ttl_s * 1000;
        let fp1 = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

        let alloc1 = gw_tier.record_declared_usage(now_ms_1, fp1).await.unwrap();
        assert_eq!(alloc1.epoch_seq, 1);
        assert!(alloc1.declared_write_ema_micro_bj > 0, "Phase 1 write EMA must be nonzero");

        let parent1 = [0x71; 32];
        let lock_req1 = make_test_hmc_genesis(parent1, root_valid, gateway_id.signing_key());
        let tx_hash1 = lock_req1.transaction_hash;
        let digest1 = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
            &gateway_pubkey,
            alloc1.epoch_day,
            alloc1.epoch_seq,
            now_ms_1,
            alloc1.declared_write_ema_micro_bj,
            alloc1.declared_read_ema_credits,
            fp1,
            false,
            &tx_hash1,
        );
        let sender_sig1 = gateway_id.signing_key().sign(&digest1).to_bytes();

        let wire_payload1 = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req1,
            chain: None,
            root_valid_until: root_valid,
            epoch_day: alloc1.epoch_day,
            epoch_seq: alloc1.epoch_seq,
            cumulative_micro_byte_years: alloc1.cumulative_micro_byte_years,
            prev_day_final_bytes: alloc1.prev_day_final_bytes,
            current_anl_24h: alloc1.declared_write_ema_micro_bj,
            declared_write_ema_micro_bj: alloc1.declared_write_ema_micro_bj,
            declared_read_ema_credits: alloc1.declared_read_ema_credits,
            sender_pubkey: gateway_pubkey,
            sender_signature: sender_sig1,
            timestamp_ms: now_ms_1,
        })
        .unwrap();

        let header1 = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            0,
            0,
            wire_payload1.len() as u32,
        );

        let (resp_hdr1, _) = gw_transport
            .send_request(&conn, &header1, &wire_payload1)
            .await
            .expect("send 1st LockVerifyRequest over QUIC");
        assert_eq!(resp_hdr1.msg_type, MsgType::LockVerifyResponse as u16);
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0, "Phase 1 signature must be valid");
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED, 0);
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0);
        assert!(
            server_peer_mgr.get_node_write_evidence(&gateway_pubkey).await.is_some(),
            "Receiver must durably record write evidence for Phase 1"
        );

        gw_tier.wait_for_accounting_drain().await.unwrap();
        gw_cancel.cancel();
        gw_transport.close();
    }

    // Phase 2: Gateway RESTARTS on the same RedbStorage & same day
    // Verifies it seamlessly picks up seq 2, causing zero fraud flags, zero bans, zero slashes!
    {
        let gw_tier = Arc::new(TierController::new(gw_storage.clone(), gw_pow.clone()));

        let gw_cancel = CancellationToken::new();
        let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
        let gw_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &gateway_id,
            gw_peer_mgr.clone(),
            Arc::new(DefaultRequestHandler),
            gw_cancel.clone(),
        )
        .expect("bind gw QUIC restart");
        let _gw_accept = gw_transport.spawn_accept_loop();

        server_peer_mgr
            .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
            .await;
        gw_peer_mgr
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
            .await;

        let conn = gw_transport.connect_peer(server_addr).await.unwrap();

        gw_tier
            .evaluate_and_charge_with_time_and_retry(
                None,
                None,
                None,
                None,
                StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                Some(&[0x22; 32]),
                Some(now_ms_2),
                false,
            )
            .await
            .expect("admission 2");

        let ttl_s2 = 100u64;
        let root_valid2 = now_ms_2 + ttl_s2 * 1000;
        let fp2 = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s2);

        let alloc2 = gw_tier.record_declared_usage(now_ms_2, fp2).await.unwrap();
        assert!(
            alloc2.epoch_seq > 1,
            "After gateway restart, sequence number must continue monotonically"
        );

        let parent2 = [0x72; 32];
        let lock_req2 = make_test_hmc_genesis(parent2, root_valid2, gateway_id.signing_key());
        let tx_hash2 = lock_req2.transaction_hash;
        let digest2 = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
            &gateway_pubkey,
            alloc2.epoch_day,
            alloc2.epoch_seq,
            alloc2.timestamp_ms,
            alloc2.declared_write_ema_micro_bj,
            alloc2.declared_read_ema_credits,
            fp2,
            false,
            &tx_hash2,
        );
        let sender_sig2 = gateway_id.signing_key().sign(&digest2).to_bytes();

        let wire_payload2 = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req2,
            chain: None,
            root_valid_until: root_valid2,
            epoch_day: alloc2.epoch_day,
            epoch_seq: alloc2.epoch_seq,
            cumulative_micro_byte_years: alloc2.cumulative_micro_byte_years,
            prev_day_final_bytes: alloc2.prev_day_final_bytes,
            current_anl_24h: alloc2.declared_write_ema_micro_bj,
            declared_write_ema_micro_bj: alloc2.declared_write_ema_micro_bj,
            declared_read_ema_credits: alloc2.declared_read_ema_credits,
            sender_pubkey: gateway_pubkey,
            sender_signature: sender_sig2,
            timestamp_ms: alloc2.timestamp_ms,
        })
        .unwrap();

        let header2 = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            2,
            0,
            0,
            wire_payload2.len() as u32,
        );

        let (resp_hdr2, _) = gw_transport
            .send_request(&conn, &header2, &wire_payload2)
            .await
            .expect("send 2nd LockVerifyRequest over QUIC after restart");
        assert_eq!(resp_hdr2.msg_type, MsgType::LockVerifyResponse as u16);
        assert_eq!(resp_hdr2.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0, "Phase 2 signature must be valid");
        assert_eq!(resp_hdr2.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED, 0);
        assert_eq!(
            resp_hdr2.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0,
            "No quota fraud flag on restarted gateway request!"
        );

        gw_cancel.cancel();
        gw_transport.close();
    }

    assert!(
        !server_peer_mgr.is_banned(&gateway_pubkey).await,
        "Honest gateway after restart must NOT be banned by receiver"
    );
    cancel_token.cancel();
    server_transport.close();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_s05_12_vip_credential_separation_and_provisioning() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("vip_cred_sep.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _flush_handle) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow_engine = Arc::new(PowEngine::new(0));
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
    let auth = Arc::new(AdminTokenManager::with_token("admin_secret_sep", false));
    let state = state.with_auth(auth);
    let operator_router = build_operator_router(state.clone());
    let public_router = build_router(state.clone());

    let account_tag = [0x55u8; 32];
    let tag_hex = hex::encode(account_tag);

    // 1. Operator topup via HTTP POST /dashboard/admin/quota (+1000 BY)
    let topup_payload = serde_json::json!({
        "account_tag": tag_hex,
        "byte_years": 1000
    });
    let topup_req = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/quota")
        .header("content-type", "application/json")
        .header("authorization", "Bearer admin_secret_sep")
        .body(Body::from(serde_json::to_vec(&topup_payload).unwrap()))
        .unwrap();
    let topup_resp = operator_router.clone().oneshot(topup_req).await.unwrap();
    assert_eq!(topup_resp.status(), StatusCode::OK);

    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(1000),
        "VIP account balance must be 1000 after topup"
    );

    // 2. Authentication failure: Presenting raw account_tag (NodePubKey hex) as bearer token on /v1/lock MUST FAIL (401)!
    let now_ms = test_now_ms();
    let root_1 = make_test_hmc_genesis([0x81; 32], now_ms + 100_000, identity.signing_key());
    let req_1 = serde_json::to_vec(&root_1).unwrap();

    let fail_auth_req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {tag_hex}"))
        .body(Body::from(req_1))
        .unwrap();
    let fail_auth_resp = public_router.clone().oneshot(fail_auth_req).await.unwrap();
    assert_eq!(
        fail_auth_resp.status(),
        StatusCode::UNAUTHORIZED,
        "Presenting raw account_tag as bearer token on /v1/lock must be rejected with 401 Unauthorized"
    );

    // Assert quota was NOT charged!
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(1000),
        "Quota must NOT be charged on unauthorized attempt"
    );

    // 3. Provision a dedicated VIP credential via POST /dashboard/admin/quota/credentials
    let prov_payload = serde_json::json!({
        "account_tag": tag_hex
    });
    let prov_req = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/quota/credentials")
        .header("content-type", "application/json")
        .header("authorization", "Bearer admin_secret_sep")
        .body(Body::from(serde_json::to_vec(&prov_payload).unwrap()))
        .unwrap();
    let prov_resp = operator_router.clone().oneshot(prov_req).await.unwrap();
    assert_eq!(prov_resp.status(), StatusCode::CREATED);

    let prov_body = axum::body::to_bytes(prov_resp.into_body(), 1024 * 1024).await.unwrap();
    let prov_json: serde_json::Value = serde_json::from_slice(&prov_body).unwrap();
    let http_bearer = prov_json["bearer_token"].as_str().unwrap().to_string();

    assert!(http_bearer.starts_with("vip_"), "Bearer token must start with vip_");
    assert_ne!(http_bearer, tag_hex, "Bearer token must be distinct from account tag");

    // 4. Provision another VIP credential via TierController / UNIX control flow
    let unix_bearer = tier_controller.provision_vip_credential(account_tag).unwrap();
    assert!(unix_bearer.starts_with("vip_"));
    assert_ne!(unix_bearer, http_bearer);

    // 5. Successful lock write on /v1/lock using provisioned VIP token
    let root_2 = make_test_hmc_genesis([0x82; 32], now_ms + 100_000, identity.signing_key());
    let req_2 = serde_json::to_vec(&root_2).unwrap();

    let succ_req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {http_bearer}"))
        .body(Body::from(req_2))
        .unwrap();
    let succ_resp = public_router.clone().oneshot(succ_req).await.unwrap();
    assert_eq!(
        succ_resp.status(),
        StatusCode::CREATED,
        "HTTP POST /v1/lock with valid provisioned VIP token must succeed (201 Created)"
    );

    let charged_bal = tier_controller.get_cached_vip_quota(&account_tag).unwrap();
    assert!(charged_bal < 1000, "Quota must be debited upon successful lock write");

    // 6. Persistence across restart: re-create TierController and AppState against same storage
    {
        let pow_engine = Arc::new(PowEngine::new(0));
        let restarted_tier_controller = Arc::new(TierController::new(storage.clone(), pow_engine.clone()));
        let (restarted_engine, _) = DualTierEngine::new(storage.clone());
        let restarted_state = AppState::new(
            restarted_engine,
            storage.clone(),
            identity.clone(),
            restarted_tier_controller.clone(),
            pow_engine.clone(),
        );
        for shard in 0..=u16::MAX {
            restarted_state.readiness_manager.mark_shard_ready(shard);
        }
        let restarted_public_router = build_router(restarted_state);

        // Submit lock write with unix_bearer on restarted node: must succeed!
        let root_3 = make_test_hmc_genesis([0x83; 32], now_ms + 100_000, identity.signing_key());
        let req_3 = serde_json::to_vec(&root_3).unwrap();

        let succ_req_restarted = Request::builder()
            .method("POST")
            .uri("/v1/lock")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {unix_bearer}"))
            .body(Body::from(req_3))
            .unwrap();
        let succ_resp_restarted = restarted_public_router.oneshot(succ_req_restarted).await.unwrap();
        assert_eq!(
            succ_resp_restarted.status(),
            StatusCode::CREATED,
            "Provisioned VIP credentials must survive daemon restart"
        );
    }
}

// ---------------------------------------------------------------------------
// S08-11: TierController 50,000-credit sequence fractional precision
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_s08_11_production_tier_controller_50k_credit_sequence() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s08_11_tc.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let tc = TierController::new(storage, pow);

    let client_id: u16 = 1234;
    // Consume 50,000 at t = 0
    tc.evaluate_read_quota_with_time(client_id, 50_000, 1.0, Some(0))
        .expect("initial 50,000 consumption");

    let mut accepted = 0u64;
    for t in 1..=10_000u64 {
        let now_ms = t * 1000;
        if tc
            .evaluate_read_quota_with_time(client_id, 1, 1.0, Some(now_ms))
            .is_ok()
        {
            accepted += 1;
        }
    }

    // In pre-fix code, all 10,000 requests are accepted due to integer truncation.
    // In post-fix code, only ~3,989 requests must be accepted!
    assert!(
        accepted < 5_000,
        "TierController accepted count ({accepted}) must NOT accept all 10,000 requests"
    );
    let diff = (accepted as i64 - 4011).abs();
    assert!(
        diff <= 30,
        "Accepted requests ({accepted}) must closely track physical decay (~4011)"
    );
}

#[tokio::test]
async fn test_s08_11_http_read_quota_subsecond_decay_rejection() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s08_11_http.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new(0));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let identity = NodeIdentity::generate();
    let peer_manager = Arc::new(PeerManager::new(vec![]));
    peer_manager.set_simulation_mode(true);
    peer_manager.seed_local_ticket_age(
        *identity.node_pubkey(),
        *identity.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
    let state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow.clone(),
    )
    .with_peer_manager(peer_manager.clone());
    for shard in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(shard);
    }
    let router = build_router(state);

    let voucher_id = "s08_11_voucher_status_test";
    let status_query = humoco_node::api::hmc::L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: [0u8; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        challenge_ds_tag: "test_tag".to_string(),
        locator_prefixes: vec![],
        read_quorum: 1,
        root_context: None,
    };
    let query_body = serde_json::to_vec(&status_query).unwrap();

    let v_hash = *blake3::hash(voucher_id.as_bytes()).as_bytes();
    let client_id = u16::from_be_bytes([v_hash[0], v_hash[1]]);

    let start_now_ms = peer_manager.net_time_ms();
    // Exhaust client read quota at start_now_ms (50,000 reads)
    tier_controller
        .evaluate_read_quota_with_time(client_id, 50_000, 1.0, Some(start_now_ms))
        .expect("exhaust read quota at start_now_ms");

    // Immediate request at start_now_ms must be 429
    let req_0 = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .body(Body::from(query_body.clone()))
        .unwrap();
    let resp_0 = router.clone().oneshot(req_0).await.unwrap();
    assert_eq!(
        resp_0.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "HTTP status query immediately after exhausting read quota must return 429"
    );

    // Advance time deterministically by 1_000 ms:
    // In pre-fix code, decay_integer_ema truncated and gave 1 full credit!
    // In post-fix code, < 1 full credit decayed (~0.401 credit), so still rejected with 429!
    peer_manager.clock().advance_time_for_test(1_000);
    let req_1 = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .body(Body::from(query_body.clone()))
        .unwrap();
    let resp_1 = router.clone().oneshot(req_1).await.unwrap();
    assert_eq!(
        resp_1.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "HTTP status query after 1 second must be rejected with 429 because < 1 full credit decayed"
    );

    // Advance time deterministically by another 2_500 ms (total elapsed 3.5s, allowing >= 1 full credit to decay)
    peer_manager.clock().advance_time_for_test(2_500);
    let req_3 = Request::builder()
        .method("POST")
        .uri("/v1/status")
        .header("content-type", "application/json")
        .body(Body::from(query_body))
        .unwrap();
    let resp_3 = router.clone().oneshot(req_3).await.unwrap();
    assert_eq!(
        resp_3.status(),
        StatusCode::OK,
        "HTTP status query after >= 3.5 seconds must succeed (200 OK) because >= 1 full credit decayed"
    );
}

#[tokio::test]
async fn test_s08_11_quic_receiver_fractional_quota_exceeded() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s08_11_quic.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let (engine, _) = DualTierEngine::new(storage.clone());
    let readiness = Arc::new(ShardReadinessManager::new());
    for s in 0..=u16::MAX {
        readiness.mark_shard_ready(s);
    }

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    let handler = NodeRequestHandler::with_peer_manager(
        engine,
        storage.clone(),
        server_id.clone(),
        server_peer_mgr.clone(),
    )
    .with_readiness_manager(readiness)
    .with_tier_controller(server_tc.clone());

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
    gw_peer_mgr.set_simulation_mode(true);
    let gateway_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway_id,
        gw_peer_mgr.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("bind gateway QUIC");
    let _gw_accept = gateway_transport.spawn_accept_loop();

    server_peer_mgr
        .register_f2f_friend(gateway_pubkey, Some(gateway_transport.local_addr().unwrap()))
        .await;
    gw_peer_mgr
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = gateway_transport
        .connect_peer(server_addr)
        .await
        .expect("connect QUIC peer");

    let quic_now_ms = server_peer_mgr.net_time_ms();
    // Daily node read limit is 250,000 (5.0 * 50,000)
    let daily_read_limit = server_tc.calculate_daily_read_quota(humoco_sim_core::quota::MAX_WHALE_MULTIPLIER, 1.0);
    assert_eq!(daily_read_limit, 250_000);

    // Exhaust gateway node read quota at quic_now_ms
    server_tc
        .evaluate_node_read_quota(&gateway_pubkey, daily_read_limit, quic_now_ms)
        .expect("initial node read consume");

    // Helper closure to send a valid authenticated StatusQuery over QUIC
    let send_status_query = |seq: u64, timestamp_ms: u64| {
        let gt = gateway_transport.clone();
        let c = conn.clone();
        let gid = gateway_id.clone();
        async move {
            let query_lock_id = [0x55u8; 32];
            let query_digest = compute_ingress_envelope_digest(
                humoco_sim_core::types::NetworkId::default(),
                &gateway_pubkey,
                0,
                0,
                timestamp_ms,
                0,
                0,
                0,
                true,
                &query_lock_id,
            );
            let query_sig = gid.signing_key().sign(&query_digest).to_bytes();
            let status_payload =
                bincode::serialize(&humoco_node::network::framing::StatusQueryPayload {
                    lock_id: query_lock_id,
                    parent_lock: [0x55u8; 32],
                    shard_id: 1,
                    sender_pubkey: gateway_pubkey,
                    declared_write_ema_micro_bj: 0,
                    current_read_ema_credits: 0,
                    timestamp_ms,
                    sender_signature: query_sig,
                })
                .unwrap();
            let status_hdr = WireHeader::new(
                MsgType::StatusQuery as u16,
                seq,
                0,
                0,
                status_payload.len() as u32,
            );
            let (resp_hdr, _) = gt
                .send_request(&c, &status_hdr, &status_payload)
                .await
                .expect("send QUIC query");
            resp_hdr
        }
    };

    let resp_hdr = send_status_query(1, quic_now_ms).await;
    assert_eq!(
        resp_hdr.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "StatusQuery immediately at t=0 must receive FLAG_QUOTA_EXCEEDED"
    );

    // Across successive seconds, small positive requests are accepted only up to decayed capacity,
    // and excess requests receive deterministic FLAG_QUOTA_EXCEEDED when fractional capacity is insufficient.
    // 1 second later: ~1.88 credits decayed.
    server_peer_mgr.clock().advance_time_for_test(1_000);
    gw_peer_mgr.clock().advance_time_for_test(1_000);
    let t1 = server_peer_mgr.net_time_ms();
    let resp_1 = send_status_query(2, t1).await;
    assert_eq!(
        resp_1.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "First query after 1s must be accepted within decayed capacity"
    );
    let resp_2 = send_status_query(3, t1).await;
    assert_eq!(
        resp_2.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "Second query after 1s must receive FLAG_QUOTA_EXCEEDED because remaining fractional capacity (~0.88 credit) is insufficient"
    );

    // Another second later: ~1.88 more credits decayed (leaving ~2.76 credits).
    server_peer_mgr.clock().advance_time_for_test(1_000);
    gw_peer_mgr.clock().advance_time_for_test(1_000);
    let t2 = server_peer_mgr.net_time_ms();
    let resp_3 = send_status_query(4, t2).await;
    assert_eq!(
        resp_3.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "Query after 2s must be accepted within newly decayed capacity"
    );
    let resp_4 = send_status_query(5, t2).await;
    assert_eq!(
        resp_4.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "Second query after 2s must be accepted within newly decayed capacity"
    );
    let resp_5 = send_status_query(6, t2).await;
    assert_eq!(
        resp_5.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "Third query after 2s must receive FLAG_QUOTA_EXCEEDED when fractional capacity is exhausted"
    );

    // Verify zero presence penalty and zero identity ban
    let peer = server_peer_mgr
        .get_peer(&gateway_transport.local_addr().unwrap())
        .await
        .expect("peer present");
    assert_eq!(
        peer.missing_count, 0,
        "missing_count must be unchanged (0) on quota exceeded"
    );
    assert!(
        !peer.is_suspended(),
        "peer must not be suspended on quota exceeded"
    );
    assert!(
        !server_peer_mgr.is_banned(&gateway_pubkey).await,
        "peer must not be banned on quota exceeded"
    );
}

// ===========================================================================
// S05-13: Fractional VIP Quota Boundary, Transactional Atomicity & Idempotent Retry
// ===========================================================================

#[tokio::test]
async fn test_s05_13_fractional_vip_boundary_sequence() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_13_fractional.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let controller = TierController::new(storage, pow);

    let vip_tag = [0x5au8; 32];
    controller.set_cached_vip_quota(vip_tag, 10_000);
    let token = controller.provision_vip_credential(vip_tag).unwrap();

    let t0_ms = 1_000_000_000_000u64;
    // Consume 4,800,000 daily limit at t0_ms
    controller
        .evaluate_vip_quota(&vip_tag, 4_800_000, t0_ms, 5.0)
        .expect("initial full quota consumption");

    let t1_ms = t0_ms + 1_000;
    // At t1_ms, observe rounded-down usage u
    let u = controller.vip_rolling_usage_at_for_test(&vip_tag, t1_ms);
    let needed = 4_800_000 - u - 1;
    controller
        .evaluate_vip_quota(&vip_tag, needed, t1_ms, 5.0)
        .expect("consume up to boundary");

    let u_boundary = controller.vip_rolling_usage_at_for_test(&vip_tag, t1_ms);
    assert_eq!(
        u_boundary, 4_799_999,
        "Usage must be exactly 4,799,999 whole units"
    );

    // Canonical evaluate_vip_quota must return Err(QuotaExceeded { available: 0, required: 1 })
    let canon_res = controller.evaluate_vip_quota(&vip_tag, 1, t1_ms, 5.0);
    assert!(
        matches!(
            canon_res,
            Err(IngressError::QuotaExceeded {
                available: 0,
                required: 1
            })
        ),
        "Canonical quota check must report QuotaExceeded {{ available: 0, required: 1 }}, got {:?}",
        canon_res
    );

    let initial_balance = controller.get_cached_vip_quota(&vip_tag).unwrap();
    assert_eq!(initial_balance, 10_000);

    // Call evaluate_and_charge_with_time three times at t1_ms with TTL 60 seconds (1 Byte-Year)
    for i in 0..3 {
        let charge_res = controller
            .evaluate_and_charge_with_time(
                Some(&token),
                None,
                None,
                None,
                StorageCharge::single(60),
                None,
                Some(t1_ms),
            )
            .await;

        assert!(
            matches!(
                charge_res,
                Err(IngressError::QuotaExceeded {
                    available: 0,
                    required: 1
                })
            ),
            "VIP attempt {} must be rejected with QuotaExceeded {{ available: 0, required: 1 }}, got {:?}",
            i,
            charge_res
        );
    }

    // Rejections must leave purchased balance, rolling usage, write counters, and thermometer untouched
    assert_eq!(
        controller.get_cached_vip_quota(&vip_tag),
        Some(10_000),
        "Purchased balance must remain 10,000 without partial credit burn"
    );
    assert_eq!(
        controller.vip_rolling_usage_at_for_test(&vip_tag, t1_ms),
        4_799_999,
        "Rolling usage must remain exactly 4,799,999"
    );
    let (vip_writes, _, _) = controller.tier_counters();
    assert_eq!(
        vip_writes, 0,
        "Write counters must not be incremented on rejection"
    );
    assert_eq!(
        controller.write_ema_micro_bj_at(t1_ms / 1000),
        0,
        "Thermometer EMA must not record rejected write"
    );
}

#[tokio::test]
async fn test_s05_13_transactional_atomicity_insufficient_credit_and_capacity() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_13_atomicity.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));

    // Part A: Insufficient credit balance (balance 0, but rolling quota is completely empty)
    {
        let controller = TierController::new(storage.clone(), pow.clone());
        let vip_tag = [0x5bu8; 32];
        controller.set_cached_vip_quota(vip_tag, 0); // 0 credit
        let token = controller.provision_vip_credential(vip_tag).unwrap();

        let t_ms = 1_000_000_000_000u64;
        let res = controller
            .evaluate_and_charge_with_time(
                Some(&token),
                None,
                None,
                None,
                StorageCharge::single(60), // requires 1 Byte-Year
                None,
                Some(t_ms),
            )
            .await;

        assert!(
            matches!(
                res,
                Err(IngressError::QuotaExceeded {
                    available: 0,
                    required: 1
                })
            ),
            "Must be rejected with QuotaExceeded when credit is 0, got {:?}",
            res
        );

        // Assert zero partial mutations:
        assert_eq!(
            controller.get_cached_vip_quota(&vip_tag),
            Some(0),
            "Balance must remain 0"
        );
        assert_eq!(
            controller.vip_rolling_usage_at_for_test(&vip_tag, t_ms),
            0,
            "Rolling quota must remain 0 (no partial consumption!)"
        );
        let (vip_writes, _, _) = controller.tier_counters();
        assert_eq!(vip_writes, 0, "VIP write counters must remain 0");
        assert_eq!(
            controller.write_ema_micro_bj_at(t_ms / 1000),
            0,
            "Thermometer must remain 0"
        );
    }

    // Part B: Exhausted VIP persistence capacity (channel full)
    {
        let bounded_controller =
            TierController::new_with_persist_capacity(storage.clone(), pow.clone(), 1);
        let vip_tag = [0x5cu8; 32];
        bounded_controller.set_cached_vip_quota(vip_tag, 10_000);
        let token = bounded_controller.provision_vip_credential(vip_tag).unwrap();

        // Hold the single VIP persistence permit to saturate queue
        let _held_permit = bounded_controller
            .reserve_persist_permit_for_test()
            .expect("reserve VIP persist permit");

        let t_ms = 1_000_000_000_000u64;
        let res = bounded_controller
            .evaluate_and_charge_with_time(
                Some(&token),
                None,
                None,
                None,
                StorageCharge::single(60),
                None,
                Some(t_ms),
            )
            .await;

        assert!(
            matches!(res, Err(IngressError::QuotaPersistenceUnavailable)),
            "Must be rejected with QuotaPersistenceUnavailable when channel is saturated, got {:?}",
            res
        );

        // Neither balance nor rolling usage nor thermometer may be partially mutated
        assert_eq!(
            bounded_controller.get_cached_vip_quota(&vip_tag),
            Some(10_000),
            "Balance must remain completely untouched at 10,000"
        );
        assert_eq!(
            bounded_controller.vip_rolling_usage_at_for_test(&vip_tag, t_ms),
            0,
            "Rolling usage must remain untouched at 0"
        );
        let (vip_writes, _, _) = bounded_controller.tier_counters();
        assert_eq!(vip_writes, 0, "Write counters must remain 0");
        assert_eq!(
            bounded_controller.write_ema_micro_bj_at(t_ms / 1000),
            0,
            "Thermometer must remain 0"
        );
    }
}

#[tokio::test]
async fn test_s05_13_http_v1_lock_fractional_exhaustion_and_retry() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_13_http.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _) = DualTierEngine::new(storage.clone());
    let identity = NodeIdentity::generate();
    let pow = Arc::new(PowEngine::new(0));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow.clone()));

    let peer_manager = Arc::new(PeerManager::new(vec![]));
    peer_manager.set_simulation_mode(true);
    peer_manager.seed_local_ticket_age(
        *identity.node_pubkey(),
        *identity.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );

    let state = AppState::new(
        engine,
        storage.clone(),
        identity.clone(),
        tier_controller.clone(),
        pow.clone(),
    )
    .with_peer_manager(peer_manager.clone());
    for s in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(s);
    }
    let router = build_router(state);

    let vip_tag = [0x5du8; 32];
    tier_controller.set_cached_vip_quota(vip_tag, 10_000);
    let bearer = tier_controller.provision_vip_credential(vip_tag).unwrap();

    let start_t = peer_manager.net_time_ms();
    let root_valid = start_t + 60_000; // 60s TTL = 1 Byte-Year

    // Setup and anchor a valid genesis lock root via /v1/lock
    let genesis_key = SigningKey::from_bytes(&[0x31; 32]);
    let root = make_test_hmc_genesis([0x7a; 32], root_valid, &genesis_key);
    let root_bytes = serde_json::to_vec(&root).unwrap();

    let root_res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(root_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        root_res.status(),
        StatusCode::CREATED,
        "Genesis root anchoring must succeed with 201 Created"
    );

    let bal_after_root = tier_controller.get_cached_vip_quota(&vip_tag).unwrap();

    // 1. Initial valid spend succeeds and debits from VIP balance
    let spend_key1 = SigningKey::from_bytes(&[0x32; 32]);
    let spend1 = make_test_hmc_spend(&root.layer2_voucher_id, "spend_1", [0x81; 32], &spend_key1);
    let req1_bytes = serde_json::to_vec(&spend1).unwrap();

    let res1 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(req1_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res1.status(),
        StatusCode::CREATED,
        "Initial valid spend must succeed with 201 Created"
    );
    let bal_after_spend1 = tier_controller.get_cached_vip_quota(&vip_tag).unwrap();
    assert!(
        bal_after_spend1 < bal_after_root,
        "VIP balance must be debited after spend1"
    );

    // 2. Drive VIP quota to fractional exhaustion (< 1 Byte-Year remaining)
    let t_drain = peer_manager.net_time_ms();
    let current_usage = tier_controller.vip_rolling_usage_at_for_test(&vip_tag, t_drain);
    let to_fill = 4_800_000 - current_usage;
    if let Err(IngressError::QuotaExceeded { available, .. }) =
        tier_controller.evaluate_vip_quota(&vip_tag, to_fill, t_drain, 5.0)
    {
        if available > 0 {
            tier_controller
                .evaluate_vip_quota(&vip_tag, available, t_drain, 5.0)
                .expect("fill quota to available limit");
        }
    }

    // Advance physical protocol time by exactly 1,000 ms to induce fractional decay
    peer_manager.clock().advance_time_for_test(1_000);
    let t_now = peer_manager.net_time_ms();
    let u = tier_controller.vip_rolling_usage_at_for_test(&vip_tag, t_now);
    let to_exhaust = 4_800_000 - u - 1;
    if let Err(IngressError::QuotaExceeded { available, .. }) =
        tier_controller.evaluate_vip_quota(&vip_tag, to_exhaust, t_now, 5.0)
    {
        if available > 0 {
            tier_controller
                .evaluate_vip_quota(&vip_tag, available, t_now, 5.0)
                .expect("consume to boundary");
        }
    }
    assert_eq!(
        tier_controller.vip_rolling_usage_at_for_test(&vip_tag, t_now),
        4_799_999,
        "Usage must be exactly 4,799,999 whole units"
    );
    assert!(
        matches!(
            tier_controller.evaluate_vip_quota(&vip_tag, 1, t_now, 5.0),
            Err(IngressError::QuotaExceeded {
                available: 0,
                required: 1
            })
        ),
        "Canonical check must show < 1 whole unit available"
    );

    // 3. New spend submission on /v1/lock must yield HTTP 429 Too Many Requests
    // and leave VIP credits unchanged!
    let spend_key2 = SigningKey::from_bytes(&[0x33; 32]);
    let spend2 = make_test_hmc_spend(&root.layer2_voucher_id, "spend_2", [0x82; 32], &spend_key2);
    let req2_bytes = serde_json::to_vec(&spend2).unwrap();

    let res2 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(req2_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "New spend at fractional exhaustion boundary must return 429 Too Many Requests"
    );
    assert_eq!(
        tier_controller.get_cached_vip_quota(&vip_tag),
        Some(bal_after_spend1),
        "VIP credits must remain unchanged on 429 rejection"
    );

    // 4. Authenticated idempotent retry of spend1 must yield 200 OK and not double-charge!
    let retry_res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/lock")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::from(req1_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        retry_res.status(),
        StatusCode::OK,
        "Authenticated idempotent retry must return 200 OK"
    );
    assert_eq!(
        tier_controller.get_cached_vip_quota(&vip_tag),
        Some(bal_after_spend1),
        "Idempotent retry must not double-charge VIP credits"
    );
}

// ===========================================================================
// S05-14: Ingress Accounting Lease Durability & Crash Interruption Monotonicity
// ===========================================================================

#[tokio::test]
async fn test_s05_14_durable_before_release_on_sequence_lease() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_14_durable.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let base_t = boot_day * day_ms;

    // Part A: Whenever record_declared_usage returns Ok(allocation), underlying redb
    // ALREADY contains persisted cumulative usage and timestamp covering that exact allocation
    // (even on seq 1 inside 1..=1024 lease!).
    {
        let tc = TierController::new(storage.clone(), pow.clone());
        let now_ms = base_t + 1_000;
        let alloc1 = tc
            .record_declared_usage(now_ms, 123)
            .await
            .expect("record seq 1");
        assert_eq!(alloc1.epoch_seq, 1);
        assert_eq!(alloc1.cumulative_micro_byte_years, 123);

        // Immediate inspection of the underlying redb database (without calling wait_for_accounting_drain):
        let persisted = storage
            .load_ingress_accounting_state()
            .unwrap()
            .expect("persisted state in redb");
        assert_eq!(
            persisted.cumulative_micro_byte_years, 123,
            "redb must ALREADY contain cumulative usage 123 covering seq 1 upon return of Ok"
        );
        assert_eq!(persisted.last_timestamp_ms, alloc1.timestamp_ms);
    }

    // Part B: If worker aborts / drops without committing, record_declared_usage MUST return Err
    // and NEVER release the allocation!
    {
        let db_path_b = temp.path().join("s05_14_abort.redb");
        let storage_b = Arc::new(RedbStorage::open(&db_path_b).unwrap());
        let tc_b = TierController::new(storage_b.clone(), pow.clone());

        // Abort worker task immediately
        tc_b.accounting_worker_abort_handle().abort();

        let res = tc_b.record_declared_usage(base_t + 2_000, 50).await;
        assert!(
            matches!(res, Err(IngressError::AccountingPersistenceUnavailable)),
            "record_declared_usage must fail closed with AccountingPersistenceUnavailable if worker aborted, got {:?}",
            res
        );

        // redb must NOT have been updated with the failed allocation
        let st = storage_b.load_ingress_accounting_state().unwrap().unwrap();
        assert_eq!(
            st.cumulative_micro_byte_years, 0,
            "Failed allocation must never be persisted or released"
        );
    }
}

#[tokio::test]
async fn test_s05_14_unclean_interruption_restart_without_drain() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_14_unclean.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let base_t = boot_day * day_ms;

    // 1. Record usage 123 awaiting completion
    let alloc1_seq;
    {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
        let alloc1 = tc
            .record_declared_usage(base_t + 1_000, 123)
            .await
            .expect("record usage 123");
        assert_eq!(alloc1.epoch_seq, 1);
        assert_eq!(alloc1.cumulative_micro_byte_years, 123);
        alloc1_seq = alloc1.epoch_seq;

        // Abrupt interruption without graceful drain: abort worker and drop controller immediately!
        tc.accounting_worker_abort_handle().abort();
        drop(tc);
    }

    // 2. Reopen controller on the same intact redb database and record 7 more units
    {
        let tc2 = Arc::new(TierController::new(storage.clone(), pow.clone()));
        let alloc2 = tc2
            .record_declared_usage(base_t + 2_000, 7)
            .await
            .expect("record usage 7 on reopened controller");

        assert_eq!(
            alloc2.cumulative_micro_byte_years, 130,
            "Cumulative usage must be 130 (123 + 7), NOT regressed to 7!"
        );
        assert!(
            alloc2.epoch_seq > alloc1_seq,
            "Sequence numbers must be strictly monotonic (> 1) across restart without drain"
        );
        assert!(
            alloc2.timestamp_ms >= base_t + 2_000,
            "Timestamp must be monotonic"
        );

        // Verify underlying storage
        let persisted = storage
            .load_ingress_accounting_state()
            .unwrap()
            .expect("persisted state");
        assert_eq!(persisted.cumulative_micro_byte_years, 130);
    }
}

#[tokio::test]
async fn test_s05_14_real_quic_gateway_restart_without_pre_restart_accounting_drain() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("server_s05_14.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
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

    let gw_db_path = temp.path().join("gw_s05_14.redb");
    let gw_storage = Arc::new(RedbStorage::open(&gw_db_path).unwrap());
    let gw_pow = Arc::new(PowEngine::new(0));

    let base_t = server_peer_mgr.net_time_ms();
    let now_ms_1 = base_t;
    let now_ms_2 = base_t + 1_000;

    // Phase 1: Gateway boots, records seq 1 with 123 micro Byte-Years, sends LockVerifyRequest over QUIC
    {
        let gw_tier = Arc::new(TierController::new(gw_storage.clone(), gw_pow.clone()));

        let gw_cancel = CancellationToken::new();
        let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
        let gw_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &gateway_id,
            gw_peer_mgr.clone(),
            Arc::new(DefaultRequestHandler),
            gw_cancel.clone(),
        )
        .expect("bind gw QUIC");
        let _gw_accept = gw_transport.spawn_accept_loop();

        server_peer_mgr
            .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
            .await;
        gw_peer_mgr
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
            .await;

        let conn = gw_transport.connect_peer(server_addr).await.unwrap();

        for _ in 0..10 {
            gw_tier
                .evaluate_and_charge_with_time_and_retry(
                    None,
                    None,
                    None,
                    None,
                    StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                    Some(&[0x33; 32]),
                    Some(now_ms_1),
                    false,
                )
                .await
                .expect("admission 1");
        }

        let ttl_s = 100u64;
        let root_valid = now_ms_1 + ttl_s * 1000;
        let fp1 = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

        let alloc1 = gw_tier.record_declared_usage(now_ms_1, fp1).await.unwrap();
        assert_eq!(alloc1.epoch_seq, 1);
        assert_eq!(alloc1.cumulative_micro_byte_years, fp1);
        assert!(alloc1.declared_write_ema_micro_bj > 0, "Phase 1 write EMA must be nonzero");

        // Abrupt interruption without graceful drain: abort worker immediately after allocation
        gw_tier.accounting_worker_abort_handle().abort();

        let parent1 = [0x73; 32];
        let lock_req1 = make_test_hmc_genesis(parent1, root_valid, gateway_id.signing_key());
        let tx_hash1 = lock_req1.transaction_hash;
        let digest1 = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
            &gateway_pubkey,
            alloc1.epoch_day,
            alloc1.epoch_seq,
            now_ms_1,
            alloc1.declared_write_ema_micro_bj,
            alloc1.declared_read_ema_credits,
            fp1,
            false,
            &tx_hash1,
        );
        let sender_sig1 = gateway_id.signing_key().sign(&digest1).to_bytes();

        let wire_payload1 = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req1,
            chain: None,
            root_valid_until: root_valid,
            epoch_day: alloc1.epoch_day,
            epoch_seq: alloc1.epoch_seq,
            cumulative_micro_byte_years: alloc1.cumulative_micro_byte_years,
            prev_day_final_bytes: alloc1.prev_day_final_bytes,
            current_anl_24h: alloc1.declared_write_ema_micro_bj,
            declared_write_ema_micro_bj: alloc1.declared_write_ema_micro_bj,
            declared_read_ema_credits: alloc1.declared_read_ema_credits,
            sender_pubkey: gateway_pubkey,
            sender_signature: sender_sig1,
            timestamp_ms: now_ms_1,
        })
        .unwrap();

        let header1 = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            0,
            0,
            wire_payload1.len() as u32,
        );

        let (resp_hdr1, _) = gw_transport
            .send_request(&conn, &header1, &wire_payload1)
            .await
            .expect("send 1st LockVerifyRequest over QUIC");
        assert_eq!(resp_hdr1.msg_type, MsgType::LockVerifyResponse as u16);
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0, "Phase 1 signature must be valid");
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED, 0);
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0);
        assert!(
            server_peer_mgr.get_node_write_evidence(&gateway_pubkey).await.is_some(),
            "Receiver must durably record write evidence for Phase 1"
        );

        // NO wait_for_accounting_drain is called here! Abrupt drop/cancel.
        gw_cancel.cancel();
        gw_transport.close();
    }

    // Phase 2: Gateway RESTARTS on the same RedbStorage without pre-restart drain
    {
        let gw_tier = Arc::new(TierController::new(gw_storage.clone(), gw_pow.clone()));

        let gw_cancel = CancellationToken::new();
        let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
        let gw_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &gateway_id,
            gw_peer_mgr.clone(),
            Arc::new(DefaultRequestHandler),
            gw_cancel.clone(),
        )
        .expect("bind gw QUIC restart");
        let _gw_accept = gw_transport.spawn_accept_loop();

        server_peer_mgr
            .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
            .await;
        gw_peer_mgr
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
            .await;

        let conn = gw_transport.connect_peer(server_addr).await.unwrap();

        gw_tier
            .evaluate_and_charge_with_time_and_retry(
                None,
                None,
                None,
                None,
                StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                Some(&[0x44; 32]),
                Some(now_ms_2),
                false,
            )
            .await
            .expect("admission 2");

        let ttl_s2 = 100u64;
        let root_valid2 = now_ms_2 + ttl_s2 * 1000;
        let fp2 = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s2);

        let alloc2 = gw_tier.record_declared_usage(now_ms_2, fp2).await.unwrap();
        assert!(
            alloc2.epoch_seq > 1,
            "After gateway restart, sequence number must continue monotonically"
        );

        let parent2 = [0x74; 32];
        let lock_req2 = make_test_hmc_genesis(parent2, root_valid2, gateway_id.signing_key());
        let tx_hash2 = lock_req2.transaction_hash;
        let digest2 = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
            &gateway_pubkey,
            alloc2.epoch_day,
            alloc2.epoch_seq,
            alloc2.timestamp_ms,
            alloc2.declared_write_ema_micro_bj,
            alloc2.declared_read_ema_credits,
            fp2,
            false,
            &tx_hash2,
        );
        let sender_sig2 = gateway_id.signing_key().sign(&digest2).to_bytes();

        let wire_payload2 = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req2,
            chain: None,
            root_valid_until: root_valid2,
            epoch_day: alloc2.epoch_day,
            epoch_seq: alloc2.epoch_seq,
            cumulative_micro_byte_years: alloc2.cumulative_micro_byte_years,
            prev_day_final_bytes: alloc2.prev_day_final_bytes,
            current_anl_24h: alloc2.declared_write_ema_micro_bj,
            declared_write_ema_micro_bj: alloc2.declared_write_ema_micro_bj,
            declared_read_ema_credits: alloc2.declared_read_ema_credits,
            sender_pubkey: gateway_pubkey,
            sender_signature: sender_sig2,
            timestamp_ms: alloc2.timestamp_ms,
        })
        .unwrap();

        let header2 = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            2,
            0,
            0,
            wire_payload2.len() as u32,
        );

        let (resp_hdr2, _) = gw_transport
            .send_request(&conn, &header2, &wire_payload2)
            .await
            .expect("send 2nd LockVerifyRequest over QUIC after restart");
        assert_eq!(resp_hdr2.msg_type, MsgType::LockVerifyResponse as u16);
        assert_eq!(resp_hdr2.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0, "Phase 2 signature must be valid");
        assert_eq!(resp_hdr2.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED, 0);
        assert_eq!(
            resp_hdr2.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0,
            "No quota fraud flag on restarted gateway request without drain!"
        );

        gw_cancel.cancel();
        gw_transport.close();
    }

    assert!(
        !server_peer_mgr.is_banned(&gateway_pubkey).await,
        "Honest gateway after restart without drain must NOT be banned by receiver"
    );
    cancel_token.cancel();
    server_transport.close();
}

// ===========================================================================
// S08-14: Fractional Quota Retention Across Cleanup Threshold & Real-QUIC
// ===========================================================================

#[tokio::test]
async fn test_s08_14_tier_controller_http_and_p2p_maps_cleanup_retention() {
    use humoco_sim_core::quota::MAX_WHALE_MULTIPLIER;

    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s08_14_tier_maps.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let tc = TierController::new(storage, pow);

    // 1. HTTP/controller read path (evaluate_read_quota_with_time on thermometer)
    // Populate 16,384 distinct client IDs with 1 credit at t = 0
    for id in 0..16_384u16 {
        tc.evaluate_read_quota_with_time(id, 1, 1.0, Some(0))
            .expect("initial client read consumption");
    }

    // At t = 1000ms, client 16,384 arrives and triggers map maintenance
    tc.evaluate_read_quota_with_time(16_384, 1, 1.0, Some(1000))
        .expect("new client read consumption");

    // Client 0 still has positive scaled usage (< 1 credit). Requesting 50,000 under limit 50,000
    // must be rejected with available == 49,999, NOT Ok(())!
    let http_res = tc.evaluate_read_quota_with_time(0, 50_000, 1.0, Some(1000));
    assert!(
        matches!(
            http_res,
            Err(IngressError::ReadQuotaExceeded {
                available: 49_999,
                required: 50_000,
            })
        ),
        "Client 0 must retain fractional usage after cleanup and reject full limit consumption, got {:?}",
        http_res
    );

    // 2. Full-NodePubKey P2P write map (evaluate_node_write_quota)
    let daily_write_quota = tc.calculate_daily_quota(MAX_WHALE_MULTIPLIER, 1.0);
    for i in 0..16_384u32 {
        let mut pk = [0u8; 32];
        pk[0..4].copy_from_slice(&i.to_le_bytes());
        tc.evaluate_node_write_quota(&pk, 1, 0)
            .expect("initial p2p node write consumption");
    }

    // Trigger cleanup with new peer at t = 1000ms
    let mut new_write_pk = [0u8; 32];
    new_write_pk[0..4].copy_from_slice(&16_384u32.to_le_bytes());
    tc.evaluate_node_write_quota(&new_write_pk, 1, 1000)
        .expect("new p2p node write consumption");

    let mut pk0 = [0u8; 32];
    pk0[0..4].copy_from_slice(&0u32.to_le_bytes());
    let write_res = tc.evaluate_node_write_quota(&pk0, daily_write_quota, 1000);
    assert!(
        matches!(
            write_res,
            Err(IngressError::QuotaExceeded {
                available,
                required,
            }) if available == daily_write_quota - 1 && required == daily_write_quota
        ),
        "P2P write peer 0 must retain fractional usage after cleanup and reject full daily quota, got {:?}",
        write_res
    );

    // Far future decay: after 65 half-lives, scaled usage is genuinely 0
    let far_future_ms = (65 * 86_400 + 1) * 1000;
    let mut far_write_pk = [0u8; 32];
    far_write_pk[0..4].copy_from_slice(&16_385u32.to_le_bytes());
    tc.evaluate_node_write_quota(&far_write_pk, 1, far_future_ms)
        .expect("far future cleanup trigger");
    // Peer 0 is now genuinely zeroed and reclaimed, so consuming daily_write_quota succeeds
    assert!(
        tc.evaluate_node_write_quota(&pk0, daily_write_quota, far_future_ms).is_ok(),
        "P2P write peer 0 must be reclaimed once scaled usage has decayed to exact 0"
    );

    // 3. Full-NodePubKey P2P read map (evaluate_node_read_quota)
    let daily_read_quota = tc.calculate_daily_read_quota(MAX_WHALE_MULTIPLIER, 1.0);
    for i in 0..16_384u32 {
        let mut pk = [0x55u8; 32];
        pk[0..4].copy_from_slice(&i.to_le_bytes());
        tc.evaluate_node_read_quota(&pk, 1, 0)
            .expect("initial p2p node read consumption");
    }

    // Trigger cleanup with new peer at t = 1000ms
    let mut new_read_pk = [0x55u8; 32];
    new_read_pk[0..4].copy_from_slice(&16_384u32.to_le_bytes());
    tc.evaluate_node_read_quota(&new_read_pk, 1, 1000)
        .expect("new p2p node read consumption");

    let mut r_pk0 = [0x55u8; 32];
    r_pk0[0..4].copy_from_slice(&0u32.to_le_bytes());
    let read_res = tc.evaluate_node_read_quota(&r_pk0, daily_read_quota, 1000);
    assert!(
        matches!(
            read_res,
            Err(IngressError::ReadQuotaExceeded {
                available,
                required,
            }) if available == daily_read_quota - 1 && required == daily_read_quota
        ),
        "P2P read peer 0 must retain fractional usage after cleanup and reject full daily read quota, got {:?}",
        read_res
    );

    // Far future decay
    let mut far_read_pk = [0x55u8; 32];
    far_read_pk[0..4].copy_from_slice(&16_385u32.to_le_bytes());
    tc.evaluate_node_read_quota(&far_read_pk, 1, far_future_ms)
        .expect("far future read cleanup trigger");
    assert!(
        tc.evaluate_node_read_quota(&r_pk0, daily_read_quota, far_future_ms).is_ok(),
        "P2P read peer 0 must be reclaimed once scaled usage has decayed to exact 0"
    );
}

#[tokio::test]
async fn test_s08_14_quic_receiver_fractional_cleanup_retention() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s08_14_quic.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let (engine, _) = DualTierEngine::new(storage.clone());
    let readiness = Arc::new(ShardReadinessManager::new());
    for s in 0..=u16::MAX {
        readiness.mark_shard_ready(s);
    }

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    let handler = NodeRequestHandler::with_peer_manager(
        engine,
        storage.clone(),
        server_id.clone(),
        server_peer_mgr.clone(),
    )
    .with_readiness_manager(readiness)
    .with_tier_controller(server_tc.clone());

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
    gw_peer_mgr.set_simulation_mode(true);
    let gateway_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway_id,
        gw_peer_mgr.clone(),
        Arc::new(DefaultRequestHandler),
        cancel_token.clone(),
    )
    .expect("bind gateway QUIC");
    let _gw_accept = gateway_transport.spawn_accept_loop();

    server_peer_mgr
        .register_f2f_friend(gateway_pubkey, Some(gateway_transport.local_addr().unwrap()))
        .await;
    gw_peer_mgr
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = gateway_transport
        .connect_peer(server_addr)
        .await
        .expect("connect QUIC peer");

    let quic_now_ms = server_peer_mgr.net_time_ms();
    let daily_read_limit = server_tc.calculate_daily_read_quota(
        humoco_sim_core::quota::MAX_WHALE_MULTIPLIER,
        1.0,
    );
    assert_eq!(daily_read_limit, 250_000);

    // Populate 16,383 background peers with 1 credit at quic_now_ms
    for i in 0..16_383u32 {
        let mut pk = [0xAAu8; 32];
        pk[0..4].copy_from_slice(&i.to_le_bytes());
        server_tc
            .evaluate_node_read_quota(&pk, 1, quic_now_ms)
            .expect("background peer quota populate");
    }

    // Exhaust gateway node read quota at quic_now_ms (total entries = 16,384)
    server_tc
        .evaluate_node_read_quota(&gateway_pubkey, daily_read_limit, quic_now_ms)
        .expect("initial gateway read consume");

    // Helper closure to send a valid authenticated StatusQuery over real QUIC
    let send_status_query = |seq: u64, timestamp_ms: u64| {
        let gt = gateway_transport.clone();
        let c = conn.clone();
        let gid = gateway_id.clone();
        async move {
            let query_lock_id = [0x77u8; 32];
            let query_digest = compute_ingress_envelope_digest(
                humoco_sim_core::types::NetworkId::default(),
                &gateway_pubkey,
                0,
                0,
                timestamp_ms,
                0,
                0,
                0,
                true,
                &query_lock_id,
            );
            let query_sig = gid.signing_key().sign(&query_digest).to_bytes();
            let status_payload =
                bincode::serialize(&humoco_node::network::framing::StatusQueryPayload {
                    lock_id: query_lock_id,
                    parent_lock: [0x77u8; 32],
                    shard_id: 1,
                    sender_pubkey: gateway_pubkey,
                    declared_write_ema_micro_bj: 0,
                    current_read_ema_credits: 0,
                    timestamp_ms,
                    sender_signature: query_sig,
                })
                .unwrap();
            let status_hdr = WireHeader::new(
                MsgType::StatusQuery as u16,
                seq,
                0,
                0,
                status_payload.len() as u32,
            );
            let (resp_hdr, _) = gt
                .send_request(&c, &status_hdr, &status_payload)
                .await
                .expect("send QUIC status query");
            resp_hdr
        }
    };

    // Advance 1 second: ~1.88 credits decayed
    server_peer_mgr.clock().advance_time_for_test(1_000);
    gw_peer_mgr.clock().advance_time_for_test(1_000);
    let t1 = server_peer_mgr.net_time_ms();

    // Query 1 consumes 1 credit, leaving < 1 credit available (~0.88)
    let resp_1 = send_status_query(1, t1).await;
    assert_eq!(
        resp_1.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "First query after 1s must be accepted within decayed capacity"
    );

    // Trigger cleanup threshold with a new peer at t1
    let new_pk = [0xBBu8; 32];
    server_tc
        .evaluate_node_read_quota(&new_pk, 1, t1)
        .expect("new peer read consume triggering cleanup");

    // Background peer 0 had 1 credit at t=0, so at t1 it has positive scaled usage (< 1 credit).
    // In pre-fix code, background peer 0 was erroneously pruned because usage_at was 0!
    // Assert background peer 0 is retained and rejects full daily read quota
    let mut bg0 = [0xAAu8; 32];
    bg0[0..4].copy_from_slice(&0u32.to_le_bytes());
    let bg0_res = server_tc.evaluate_node_read_quota(&bg0, daily_read_limit, t1);
    assert!(
        matches!(
            bg0_res,
            Err(IngressError::ReadQuotaExceeded {
                available,
                required,
            }) if available == daily_read_limit - 1 && required == daily_read_limit
        ),
        "Background peer 0 must NOT be evicted by cleanup while positive scaled usage remains, got {:?}",
        bg0_res
    );

    // Ensure any remaining whole credits for gateway_pubkey are exhausted so < 1 credit remains:
    let now_t = server_peer_mgr.net_time_ms();
    match server_tc.evaluate_node_read_quota(&gateway_pubkey, daily_read_limit, now_t) {
        Err(IngressError::ReadQuotaExceeded { available, .. }) if available > 0 => {
            let _ = server_tc.evaluate_node_read_quota(&gateway_pubkey, available, now_t);
        }
        _ => {}
    }

    // Now send target peer's request over real QUIC when < 1 whole credit remains:
    let resp_2 = send_status_query(2, now_t).await;
    assert_eq!(
        resp_2.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "Second query over real QUIC must receive FLAG_QUOTA_EXCEEDED when remaining fractional capacity is < 1 credit"
    );

    // Verify zero identity ban and zero presence/peer-failure penalty
    let peer = server_peer_mgr
        .get_peer(&gateway_transport.local_addr().unwrap())
        .await
        .expect("peer present");
    assert_eq!(
        peer.missing_count, 0,
        "missing_count must be unchanged (0) on quota exceeded"
    );
    assert!(
        !peer.is_suspended(),
        "peer must not be suspended on quota exceeded"
    );
    assert!(
        !server_peer_mgr.is_banned(&gateway_pubkey).await,
        "peer must not be banned on quota exceeded"
    );

    cancel_token.cancel();
    server_transport.close();
    gateway_transport.close();
}

// ===========================================================================
// S05-15: Ordinary Restart Preserves Signed Write/Read EMA Continuity
// ===========================================================================

#[tokio::test]
async fn test_s05_15_write_ema_restart_continuity() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("write_ema_cont.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let t1 = boot_day * day_ms + 1_000;
    let t2 = t1 + 1_000;

    let (alloc1, pk, sk) = {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
        let id = NodeIdentity::generate();
        let pk = *id.node_pubkey();
        let sk = id.signing_key().clone();

        for _ in 0..10 {
            tc.evaluate_and_charge_with_time_and_retry(
                None,
                None,
                None,
                None,
                StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                Some(&[0x11; 32]),
                Some(t1),
                false,
            )
            .await
            .expect("write admission");
        }

        let alloc1 = tc.record_declared_usage(t1, 100).await.unwrap();
        assert_eq!(alloc1.epoch_seq, 1);
        assert!(
            alloc1.declared_write_ema_micro_bj > 0,
            "Phase 1 write EMA must be nonzero"
        );
        tc.wait_for_accounting_drain().await.unwrap();
        (alloc1, pk, sk)
    };

    // Restart controller against same storage
    let tc2 = Arc::new(TierController::new(storage.clone(), pow.clone()));
    tc2.evaluate_and_charge_with_time_and_retry(
        None,
        None,
        None,
        None,
        StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
        Some(&[0x22; 32]),
        Some(t2),
        false,
    )
    .await
    .expect("write admission 2");

    let alloc2 = tc2.record_declared_usage(t2, 100).await.unwrap();
    assert!(
        alloc2.epoch_seq > alloc1.epoch_seq,
        "Sequence must advance monotonically"
    );

    let min_write = humoco_sim_core::fraud::FraudProofPayload::conservative_min_decayed_ema(
        alloc1.declared_write_ema_micro_bj,
        1,
    );
    assert!(
        alloc2.declared_write_ema_micro_bj >= min_write,
        "Restarted write EMA {} must be >= min decayed EMA {}",
        alloc2.declared_write_ema_micro_bj,
        min_write
    );

    // Verify counter conflict check returns FALSE (no fraud)
    let net = humoco_sim_core::types::NetworkId::default();
    let parent1 = [0x71; 32];
    let parent2 = [0x72; 32];
    let digest1 = compute_ingress_envelope_digest(
        net,
        &pk,
        alloc1.epoch_day,
        alloc1.epoch_seq,
        alloc1.timestamp_ms,
        alloc1.declared_write_ema_micro_bj,
        alloc1.declared_read_ema_credits,
        100,
        false,
        &parent1,
    );
    let sig1 = sk.sign(&digest1).to_bytes();
    let ev1 = IngressEnvelopeEvidence::new(
        net,
        pk,
        alloc1.epoch_day,
        alloc1.epoch_seq,
        alloc1.timestamp_ms,
        alloc1.declared_write_ema_micro_bj,
        alloc1.declared_read_ema_credits,
        100,
        false,
        parent1,
        sig1,
    );

    let digest2 = compute_ingress_envelope_digest(
        net,
        &pk,
        alloc2.epoch_day,
        alloc2.epoch_seq,
        alloc2.timestamp_ms,
        alloc2.declared_write_ema_micro_bj,
        alloc2.declared_read_ema_credits,
        100,
        false,
        &parent2,
    );
    let sig2 = sk.sign(&digest2).to_bytes();
    let ev2 = IngressEnvelopeEvidence::new(
        net,
        pk,
        alloc2.epoch_day,
        alloc2.epoch_seq,
        alloc2.timestamp_ms,
        alloc2.declared_write_ema_micro_bj,
        alloc2.declared_read_ema_credits,
        100,
        false,
        parent2,
        sig2,
    );

    let is_conflict = FraudProofPayload::check_ingress_conflict(net, &ev1, &ev2);
    assert!(
        !is_conflict,
        "Honest restart must NOT trigger ingress counter conflict"
    );
}

#[tokio::test]
async fn test_s05_15_read_ema_restart_continuity() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("read_ema_cont.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let t1 = boot_day * day_ms + 1_000;
    let t2 = t1 + 1_000;

    let (alloc1, pk, sk) = {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
        let id = NodeIdentity::generate();
        let pk = *id.node_pubkey();
        let sk = id.signing_key().clone();

        tc.evaluate_read_quota_with_time(42, 100, 1.0, Some(t1))
            .expect("read admission");

        let alloc1 = tc.record_declared_usage(t1, 50).await.unwrap();
        assert_eq!(alloc1.epoch_seq, 1);
        assert!(
            alloc1.declared_read_ema_credits > 0,
            "Phase 1 read EMA must be nonzero"
        );
        tc.wait_for_accounting_drain().await.unwrap();
        (alloc1, pk, sk)
    };

    // Restart controller against same storage
    let tc2 = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let alloc2 = tc2.record_declared_usage(t2, 50).await.unwrap();
    assert!(
        alloc2.epoch_seq > alloc1.epoch_seq,
        "Sequence must advance monotonically"
    );

    let min_read = humoco_sim_core::fraud::FraudProofPayload::conservative_min_decayed_ema(
        alloc1.declared_read_ema_credits,
        1,
    );
    assert!(
        alloc2.declared_read_ema_credits >= min_read,
        "Restarted read EMA {} must be >= min decayed EMA {}",
        alloc2.declared_read_ema_credits,
        min_read
    );

    let net = humoco_sim_core::types::NetworkId::default();
    let parent1 = [0x81; 32];
    let parent2 = [0x82; 32];
    let digest1 = compute_ingress_envelope_digest(
        net,
        &pk,
        alloc1.epoch_day,
        alloc1.epoch_seq,
        alloc1.timestamp_ms,
        alloc1.declared_write_ema_micro_bj,
        alloc1.declared_read_ema_credits,
        50,
        false,
        &parent1,
    );
    let sig1 = sk.sign(&digest1).to_bytes();
    let ev1 = IngressEnvelopeEvidence::new(
        net,
        pk,
        alloc1.epoch_day,
        alloc1.epoch_seq,
        alloc1.timestamp_ms,
        alloc1.declared_write_ema_micro_bj,
        alloc1.declared_read_ema_credits,
        50,
        false,
        parent1,
        sig1,
    );

    let digest2 = compute_ingress_envelope_digest(
        net,
        &pk,
        alloc2.epoch_day,
        alloc2.epoch_seq,
        alloc2.timestamp_ms,
        alloc2.declared_write_ema_micro_bj,
        alloc2.declared_read_ema_credits,
        50,
        false,
        &parent2,
    );
    let sig2 = sk.sign(&digest2).to_bytes();
    let ev2 = IngressEnvelopeEvidence::new(
        net,
        pk,
        alloc2.epoch_day,
        alloc2.epoch_seq,
        alloc2.timestamp_ms,
        alloc2.declared_write_ema_micro_bj,
        alloc2.declared_read_ema_credits,
        50,
        false,
        parent2,
        sig2,
    );

    let is_conflict = FraudProofPayload::check_ingress_conflict(net, &ev1, &ev2);
    assert!(
        !is_conflict,
        "Honest restart must NOT trigger ingress counter conflict on read EMA"
    );
}

#[tokio::test]
async fn test_s05_15_interruption_without_graceful_drain_write_and_read() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("unclean_cont.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let t1 = boot_day * day_ms + 1_000;
    let t2 = t1 + 2_000;

    let alloc1 = {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

        for _ in 0..5 {
            tc.evaluate_and_charge_with_time_and_retry(
                None,
                None,
                None,
                None,
                StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                Some(&[0x55; 32]),
                Some(t1),
                false,
            )
            .await
            .expect("write admission");
        }
        tc.evaluate_read_quota_with_time(77, 50, 1.0, Some(t1))
            .expect("read admission");

        let alloc1 = tc.record_declared_usage(t1, 200).await.unwrap();
        assert_eq!(alloc1.epoch_seq, 1);
        assert!(alloc1.declared_write_ema_micro_bj > 0);
        assert!(alloc1.declared_read_ema_credits > 0);

        // Abrupt interruption: abort worker immediately without graceful drain
        tc.accounting_worker_abort_handle().abort();
        alloc1
    };

    // Recreate controller on intact db
    let tc2 = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let alloc2 = tc2.record_declared_usage(t2, 100).await.unwrap();
    assert!(alloc2.epoch_seq > alloc1.epoch_seq);

    let min_write = humoco_sim_core::fraud::FraudProofPayload::conservative_min_decayed_ema(
        alloc1.declared_write_ema_micro_bj,
        2,
    );
    let min_read = humoco_sim_core::fraud::FraudProofPayload::conservative_min_decayed_ema(
        alloc1.declared_read_ema_credits,
        2,
    );

    assert!(
        alloc2.declared_write_ema_micro_bj >= min_write,
        "Write EMA must be preserved across abrupt interruption without drain"
    );
    assert!(
        alloc2.declared_read_ema_credits >= min_read,
        "Read EMA must be preserved across abrupt interruption without drain"
    );
}

#[tokio::test]
async fn test_s05_15_fractional_precision_and_decay_continuity() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("frac_cont.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let t1 = boot_day * day_ms + 1_000;

    let (alloc1, _w_ema1) = {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
        tc.evaluate_and_charge_with_time_and_retry(
            None,
            None,
            None,
            None,
            StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
            Some(&[0x66; 32]),
            Some(t1),
            false,
        )
        .await
        .expect("write admission");

        let alloc1 = tc.record_declared_usage(t1, 50).await.unwrap();
        tc.wait_for_accounting_drain().await.unwrap();
        (alloc1.clone(), alloc1.declared_write_ema_micro_bj)
    };

    // Test decay across 60 seconds
    let t2 = t1 + 60_000;
    let tc2 = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let alloc2 = tc2.record_declared_usage(t2, 50).await.unwrap();

    let min_write = humoco_sim_core::fraud::FraudProofPayload::conservative_min_decayed_ema(
        alloc1.declared_write_ema_micro_bj,
        60,
    );
    assert!(
        alloc2.declared_write_ema_micro_bj >= min_write,
        "Write EMA must preserve fractional precision across 60s decay"
    );
}

#[tokio::test]
async fn test_s05_15_calendar_day_rollover_continuous_ema() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("rollover_ema.redb");
    let day_ms = 86_400_000u64;
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let boot_day = pow.now_ms() / day_ms;
    let t1 = boot_day * day_ms + 1_000;

    let alloc1 = {
        let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
        tc.evaluate_and_charge_with_time_and_retry(
            None,
            None,
            None,
            None,
            StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR * 5),
            Some(&[0x77; 32]),
            Some(t1),
            false,
        )
        .await
        .expect("write admission");

        let alloc1 = tc.record_declared_usage(t1, 50).await.unwrap();
        assert_eq!(alloc1.epoch_day, boot_day as u32);
        tc.wait_for_accounting_drain().await.unwrap();
        alloc1
    };

    // Day rollover: advance 24h (86_400s = 1 half-life, so EMA should be ~50%)
    let t2 = t1 + day_ms;
    let tc2 = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let alloc2 = tc2.record_declared_usage(t2, 50).await.unwrap();
    assert_eq!(alloc2.epoch_day, (boot_day + 1) as u32);
    assert_eq!(alloc2.epoch_seq, 1, "Sequence resets to 1 on day rollover");

    // Continuous EMA does NOT reset to 0; it decays continuously (~50% after 24h)
    let min_write = humoco_sim_core::fraud::FraudProofPayload::conservative_min_decayed_ema(
        alloc1.declared_write_ema_micro_bj,
        86_400,
    );
    assert!(
        alloc2.declared_write_ema_micro_bj >= min_write,
        "Day rollover must preserve continuous physical-time EMA decay (~50%), got {} vs min {}",
        alloc2.declared_write_ema_micro_bj,
        min_write
    );
    assert!(
        alloc2.declared_write_ema_micro_bj > 0,
        "EMA must not reset to 0 across calendar day rollover"
    );
}

#[tokio::test]
async fn test_s05_15_real_quic_write_and_read_restart_continuity() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("server_quic_wr.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
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

    let gw_db_path = temp.path().join("gw_quic_wr.redb");
    let gw_storage = Arc::new(RedbStorage::open(&gw_db_path).unwrap());
    let gw_pow = Arc::new(PowEngine::new(0));

    let base_t = server_peer_mgr.net_time_ms();
    let now_ms_1 = base_t;
    let now_ms_2 = base_t + 1_000;
    let ttl_s = 100u64;
    let fp = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

    // Phase 1: Gateway boots, executes both write and read admissions
    {
        let gw_tier = Arc::new(TierController::new(gw_storage.clone(), gw_pow.clone()));
        let gw_cancel = CancellationToken::new();
        let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
        let gw_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &gateway_id,
            gw_peer_mgr.clone(),
            Arc::new(DefaultRequestHandler),
            gw_cancel.clone(),
        )
        .expect("bind gw QUIC");
        let _gw_accept = gw_transport.spawn_accept_loop();

        server_peer_mgr
            .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
            .await;
        gw_peer_mgr
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
            .await;

        let conn = gw_transport.connect_peer(server_addr).await.unwrap();

        for _ in 0..10 {
            gw_tier
                .evaluate_and_charge_with_time_and_retry(
                    None,
                    None,
                    None,
                    None,
                    StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                    Some(&[0x11; 32]),
                    Some(now_ms_1),
                    false,
                )
                .await
                .expect("write admission");
        }
        gw_tier
            .evaluate_read_quota_with_time(999, 100, 1.0, Some(now_ms_1))
            .expect("read admission");

        let alloc1 = gw_tier.record_declared_usage(now_ms_1, fp).await.unwrap();
        assert_eq!(alloc1.epoch_seq, 1);
        assert!(alloc1.declared_write_ema_micro_bj > 0);
        assert!(alloc1.declared_read_ema_credits > 0);

        let parent1 = [0x51; 32];
        let root_valid = now_ms_1 + ttl_s * 1000;
        let lock_req1 = make_test_hmc_genesis(parent1, root_valid, gateway_id.signing_key());
        let tx_hash1 = lock_req1.transaction_hash;
        let digest1 = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
            &gateway_pubkey,
            alloc1.epoch_day,
            alloc1.epoch_seq,
            now_ms_1,
            alloc1.declared_write_ema_micro_bj,
            alloc1.declared_read_ema_credits,
            fp,
            false,
            &tx_hash1,
        );
        let sig1 = gateway_id.signing_key().sign(&digest1).to_bytes();

        let wire1 = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req1,
            chain: None,
            root_valid_until: root_valid,
            epoch_day: alloc1.epoch_day,
            epoch_seq: alloc1.epoch_seq,
            cumulative_micro_byte_years: alloc1.cumulative_micro_byte_years,
            prev_day_final_bytes: alloc1.prev_day_final_bytes,
            current_anl_24h: alloc1.declared_write_ema_micro_bj,
            declared_write_ema_micro_bj: alloc1.declared_write_ema_micro_bj,
            declared_read_ema_credits: alloc1.declared_read_ema_credits,
            sender_pubkey: gateway_pubkey,
            sender_signature: sig1,
            timestamp_ms: now_ms_1,
        })
        .unwrap();

        let hdr1 = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, wire1.len() as u32);
        let (resp_hdr1, _) = gw_transport.send_request(&conn, &hdr1, &wire1).await.unwrap();
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0);
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED, 0);
        assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0);
        assert!(server_peer_mgr.get_node_write_evidence(&gateway_pubkey).await.is_some());

        gw_tier.wait_for_accounting_drain().await.unwrap();
        gw_cancel.cancel();
        gw_transport.close();
    }

    // Phase 2: Gateway restarts on same DB, performs admission 1s later, sends 2nd request
    {
        let gw_tier = Arc::new(TierController::new(gw_storage.clone(), gw_pow.clone()));
        let gw_cancel = CancellationToken::new();
        let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
        let gw_transport = QuicTransport::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            &gateway_id,
            gw_peer_mgr.clone(),
            Arc::new(DefaultRequestHandler),
            gw_cancel.clone(),
        )
        .expect("bind gw QUIC restart");
        let _gw_accept = gw_transport.spawn_accept_loop();

        server_peer_mgr
            .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
            .await;
        gw_peer_mgr
            .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
            .await;

        let conn = gw_transport.connect_peer(server_addr).await.unwrap();

        gw_tier
            .evaluate_and_charge_with_time_and_retry(
                None,
                None,
                None,
                None,
                StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
                Some(&[0x22; 32]),
                Some(now_ms_2),
                false,
            )
            .await
            .expect("admission 2");

        let alloc2 = gw_tier.record_declared_usage(now_ms_2, fp).await.unwrap();
        assert!(alloc2.epoch_seq > 1);

        let parent2 = [0x52; 32];
        let root_valid2 = now_ms_2 + ttl_s * 1000;
        let lock_req2 = make_test_hmc_genesis(parent2, root_valid2, gateway_id.signing_key());
        let tx_hash2 = lock_req2.transaction_hash;
        let digest2 = compute_ingress_envelope_digest(
            humoco_sim_core::types::NetworkId::default(),
            &gateway_pubkey,
            alloc2.epoch_day,
            alloc2.epoch_seq,
            alloc2.timestamp_ms,
            alloc2.declared_write_ema_micro_bj,
            alloc2.declared_read_ema_credits,
            fp,
            false,
            &tx_hash2,
        );
        let sig2 = gateway_id.signing_key().sign(&digest2).to_bytes();

        let wire2 = bincode::serialize(&LockWirePayload::Hmc {
            req: lock_req2,
            chain: None,
            root_valid_until: root_valid2,
            epoch_day: alloc2.epoch_day,
            epoch_seq: alloc2.epoch_seq,
            cumulative_micro_byte_years: alloc2.cumulative_micro_byte_years,
            prev_day_final_bytes: alloc2.prev_day_final_bytes,
            current_anl_24h: alloc2.declared_write_ema_micro_bj,
            declared_write_ema_micro_bj: alloc2.declared_write_ema_micro_bj,
            declared_read_ema_credits: alloc2.declared_read_ema_credits,
            sender_pubkey: gateway_pubkey,
            sender_signature: sig2,
            timestamp_ms: alloc2.timestamp_ms,
        })
        .unwrap();

        let hdr2 = WireHeader::new(MsgType::LockVerifyRequest as u16, 2, 0, 0, wire2.len() as u32);
        let (resp_hdr2, _) = gw_transport.send_request(&conn, &hdr2, &wire2).await.unwrap();
        assert_eq!(resp_hdr2.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0, "Phase 2 signature must be valid");
        assert_eq!(resp_hdr2.flags & humoco_sim_core::wire::FLAG_UNAUTHORIZED, 0);
        assert_eq!(
            resp_hdr2.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0,
            "Restarted gateway MUST NOT trigger FLAG_QUOTA_FRAUD"
        );

        gw_cancel.cancel();
        gw_transport.close();
    }

    assert!(
        !server_peer_mgr.is_banned(&gateway_pubkey).await,
        "Honest gateway MUST NOT be banned after restart"
    );
    cancel_token.cancel();
    server_transport.close();
}


#[tokio::test]
async fn test_s05_15_genuine_inconsistent_counter_control_rejected() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("server_control.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _worker) = DualTierEngine::new(storage.clone());
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
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

    let gw_cancel = CancellationToken::new();
    let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
    let gw_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway_id,
        gw_peer_mgr.clone(),
        Arc::new(DefaultRequestHandler),
        gw_cancel.clone(),
    )
    .expect("bind gw QUIC");
    let _gw_accept = gw_transport.spawn_accept_loop();

    server_peer_mgr
        .register_f2f_friend(gateway_pubkey, Some(gw_transport.local_addr().unwrap()))
        .await;
    gw_peer_mgr
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = gw_transport.connect_peer(server_addr).await.unwrap();

    let now_ms_1 = server_peer_mgr.net_time_ms();
    let now_ms_2 = now_ms_1 + 1_000;
    let ttl_s = 100u64;
    let root_valid = now_ms_1 + ttl_s * 1000;
    let fp = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);

    // Phase 1: High write EMA declared
    let parent1 = [0xA1; 32];
    let lock_req1 = make_test_hmc_genesis(parent1, root_valid, gateway_id.signing_key());
    let tx_hash1 = lock_req1.transaction_hash;
    let digest1 = compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        &gateway_pubkey,
        1,
        1,
        now_ms_1,
        1_920_000_000,
        0,
        fp,
        false,
        &tx_hash1,
    );
    let sig1 = gateway_id.signing_key().sign(&digest1).to_bytes();
    let wire1 = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_req1,
        chain: None,
        root_valid_until: root_valid,
        epoch_day: 1,
        epoch_seq: 1,
        cumulative_micro_byte_years: fp,
        prev_day_final_bytes: 0,
        current_anl_24h: 1_920_000_000,
        declared_write_ema_micro_bj: 1_920_000_000,
        declared_read_ema_credits: 0,
        sender_pubkey: gateway_pubkey,
        sender_signature: sig1,
        timestamp_ms: now_ms_1,
    })
    .unwrap();
    let hdr1 = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, wire1.len() as u32);
    let (resp_hdr1, _) = gw_transport.send_request(&conn, &hdr1, &wire1).await.unwrap();
    assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_SIGNATURE_INVALID, 0);
    assert_eq!(resp_hdr1.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD, 0);
    assert!(server_peer_mgr.get_node_write_evidence(&gateway_pubkey).await.is_some());

    // Phase 2: Attacker deliberately under-reports EMA (e.g. 10 µBJ instead of ~1.9B)
    let parent2 = [0xA2; 32];
    let root_valid2 = now_ms_2 + ttl_s * 1000;
    let fp2 = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let lock_req2 = make_test_hmc_genesis(parent2, root_valid2, gateway_id.signing_key());
    let tx_hash2 = lock_req2.transaction_hash;
    let digest2 = compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        &gateway_pubkey,
        1,
        2,
        now_ms_2,
        10, // Under-reported!
        0,
        fp2,
        false,
        &tx_hash2,
    );
    let sig2 = gateway_id.signing_key().sign(&digest2).to_bytes();
    let wire2 = bincode::serialize(&LockWirePayload::Hmc {
        req: lock_req2,
        chain: None,
        root_valid_until: root_valid2,
        epoch_day: 1,
        epoch_seq: 2,
        cumulative_micro_byte_years: fp + fp2,
        prev_day_final_bytes: 0,
        current_anl_24h: 10,
        declared_write_ema_micro_bj: 10,
        declared_read_ema_credits: 0,
        sender_pubkey: gateway_pubkey,
        sender_signature: sig2,
        timestamp_ms: now_ms_2,
    })
    .unwrap();
    let hdr2 = WireHeader::new(MsgType::LockVerifyRequest as u16, 2, 0, 0, wire2.len() as u32);
    let (resp_hdr2, _) = gw_transport.send_request(&conn, &hdr2, &wire2).await.unwrap();

    // Genuine inconsistent counter MUST be rejected with FLAG_QUOTA_FRAUD and banned!
    assert!(
        resp_hdr2.flags & humoco_sim_core::wire::FLAG_QUOTA_FRAUD != 0,
        "Under-reported EMA MUST trigger FLAG_QUOTA_FRAUD"
    );
    assert!(
        server_peer_mgr.is_banned(&gateway_pubkey).await,
        "Perpetrator under-reporting EMA MUST be permanently banned"
    );

    gw_cancel.cancel();
    gw_transport.close();
    cancel_token.cancel();
    server_transport.close();
}

// ===========================================================================
// S05-16: Required POSIX 0600 token-file protection error propagation
// ===========================================================================

#[test]
fn test_s05_16_token_file_permission_failure_propagates() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().unwrap();
        let token_path = temp.path().join("admin.token");
        std::fs::write(&token_path, "hmc_adm_existing_secret_key\n").expect("write token");
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644))
            .expect("set 0644");

        // When permission enforcement fails (simulating EPERM / PermissionDenied on chmod),
        // load_or_create must return Err and must NOT return a usable manager.
        let _guard = AdminTokenManager::fail_permission_enforcement_for_test();
        let result = AdminTokenManager::load_or_create(temp.path(), false);
        drop(_guard);

        let err = result.expect_err(
            "load_or_create must fail when required permission enforcement fails",
        );
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // Required protection could not be established; file remains 0644
        let meta = std::fs::metadata(&token_path).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);

        // Also test newly created token failure propagation
        let temp_new = tempdir().unwrap();
        let _guard_new = AdminTokenManager::fail_permission_enforcement_for_test();
        let result_new = AdminTokenManager::load_or_create(temp_new.path(), false);
        drop(_guard_new);

        let err_new = result_new.expect_err(
            "load_or_create must fail when new token permission enforcement fails",
        );
        assert_eq!(err_new.kind(), std::io::ErrorKind::PermissionDenied);
    }
}

// ===========================================================================
// S05-17: Durable EMA Persistence Across Restarts & Lifecycles
// ===========================================================================

#[tokio::test]
async fn test_s05_17_genesis_registration_and_rejected_admission_durable_ema() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_17_genesis.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));

    let (engine, _) = DualTierEngine::new(storage.clone());
    let id = NodeIdentity::generate();
    let state = AppState::new(engine, storage.clone(), id.clone(), tc.clone(), pow.clone());
    for s in 0..=u16::MAX {
        state.readiness_manager.mark_shard_ready(s);
    }
    let router = build_router(state);

    let initial = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(initial.write_ema_scaled, 0);

    let now_ms = test_now_ms();
    // 1. Successful authenticated HTTP genesis registration (POST /v1/lock with is_genesis: true)
    let genesis = make_test_hmc_genesis([0x91; 32], now_ms + 100_000, id.signing_key());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&genesis).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let thermo_ema = tc.write_ema_micro_bj_at(now_ms / 1000);
    assert!(thermo_ema > 0, "Genesis registration must mutate thermometer write EMA");

    // 2. Write admission followed by signature rejection (400 Bad Request)
    let mut bad_sig = make_test_hmc_genesis([0x92; 32], now_ms + 100_000, id.signing_key());
    bad_sig.is_genesis = false;
    bad_sig.ds_tag = Some("bad_sig_tag_1".to_string());
    bad_sig.layer2_signature = [0xbb; 64];
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&bad_sig).unwrap()))
        .unwrap();
    let resp2 = router.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

    // 3. Admission followed by cancellation before record_declared_usage
    tc.evaluate_and_charge_with_time_and_retry(
        None,
        None,
        None,
        None,
        StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
        Some(&[0x93; 32]),
        Some(now_ms),
        false,
    )
    .await
    .unwrap();

    // Draining / checkpointing
    tc.wait_for_accounting_drain().await.unwrap();

    // Verify in storage: envelope day, sequence, usage, timestamp unchanged, but write_ema_scaled and anchor are durable!
    let loaded = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(loaded.last_epoch_seq, initial.last_epoch_seq);
    assert_eq!(loaded.cumulative_micro_byte_years, initial.cumulative_micro_byte_years);
    assert_eq!(loaded.last_timestamp_ms, initial.last_timestamp_ms);
    assert!(
        loaded.write_ema_scaled > 0,
        "Durable ingress accounting state must persist updated write_ema_scaled even when envelope sequence and usage are unchanged!"
    );
    assert!(
        loaded.last_write_ema_sec.is_some(),
        "Durable ingress accounting state must persist last_write_ema_sec anchor!"
    );
}

#[tokio::test]
async fn test_s05_17_ema_only_snapshot_drain_and_decay_ordering() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_17_ema_decay.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));
    let day_ms = 86_400_000u64;
    let boot_day = pow.now_ms() / day_ms;
    let t1 = boot_day * day_ms + 5_000;
    let t1_sec = t1 / 1000;

    let tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let initial = storage.load_ingress_accounting_state().unwrap().unwrap();
    let initial_day = initial.current_day;
    let initial_seq = initial.last_epoch_seq;
    let initial_cum = initial.cumulative_micro_byte_years;
    let initial_ts = initial.last_timestamp_ms;

    let (exported_w_scaled, exported_w_sec, exported_r_scaled, exported_r_sec) = {
        // Admit write without record_declared_usage
        tc.evaluate_and_charge_with_time_and_retry(
            None,
            None,
            None,
            None,
            StorageCharge::single(humoco_sim_core::quota::SECONDS_PER_YEAR),
            Some(&[0x44; 32]),
            Some(t1),
            false,
        )
        .await
        .unwrap();

        // Evaluate read quota
        tc.evaluate_read_quota_with_time(42, 500, 1.0, Some(t1)).unwrap();

        let (w_scaled, w_sec, r_scaled, r_sec) = tc
            .thermometer()
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .raw_ema_state();
        assert!(w_scaled > 0);
        assert!(r_scaled > 0);
        assert_eq!(w_sec, Some(t1_sec));
        assert_eq!(r_sec, Some(t1_sec));

        tc.wait_for_accounting_drain().await.unwrap();
        (w_scaled, w_sec, r_scaled, r_sec)
    };

    // Verify envelope remains unchanged on disk while EMA state is durable
    let disk_state = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(disk_state.current_day, initial_day);
    assert_eq!(disk_state.last_epoch_seq, initial_seq);
    assert_eq!(disk_state.cumulative_micro_byte_years, initial_cum);
    assert_eq!(disk_state.last_timestamp_ms, initial_ts);
    assert_eq!(disk_state.write_ema_scaled, exported_w_scaled);
    assert_eq!(disk_state.last_write_ema_sec, exported_w_sec);
    assert_eq!(disk_state.read_ema_scaled, exported_r_scaled);
    assert_eq!(disk_state.last_read_ema_sec, exported_r_sec);

    // Drop storage and reopen to test lifecycle reconstruction
    tc.quota_worker_abort_handle().abort();
    tc.accounting_worker_abort_handle().abort();
    drop(tc);
    drop(storage);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let reopened_storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let tc2 = Arc::new(TierController::new(reopened_storage.clone(), pow.clone()));

    // Verify reconstructed controller has exact fractional EMA state
    let (recon_w_scaled, recon_w_sec, recon_r_scaled, recon_r_sec) = tc2
        .thermometer()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .raw_ema_state();
    assert_eq!(recon_w_scaled, exported_w_scaled);
    assert_eq!(recon_w_sec, exported_w_sec);
    assert_eq!(recon_r_scaled, exported_r_scaled);
    assert_eq!(recon_r_sec, exported_r_sec);

    // Verify elapsed-time physical decay (where raw values lawfully decrease)
    let t2_sec = t1_sec + 30;
    let decayed_w = tc2.write_ema_micro_bj_at(t2_sec);
    let original_w = tc2.write_ema_micro_bj_at(t1_sec);
    assert!(decayed_w > 0, "Decayed write EMA must be non-zero");
    assert!(decayed_w < original_w, "Decayed write EMA must decrease over physical time");
}

#[tokio::test]
async fn test_s05_17_real_quic_direct_friend_heartbeat_continuity() {
    let cancel = CancellationToken::new();

    // 1. Setup Observer
    let observer = NodeIdentity::generate();
    let obs_temp = tempdir().unwrap();
    let obs_db = obs_temp.path().join("obs_hb.redb");
    let obs_storage = Arc::new(RedbStorage::open(&obs_db).unwrap());
    let (obs_engine, _) = DualTierEngine::new(obs_storage.clone());

    // 2. Setup Friend
    let (friend, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine friend");
    let friend_temp = tempdir().unwrap();
    let friend_db = friend_temp.path().join("friend_hb.redb");
    let friend_storage = Arc::new(RedbStorage::open(&friend_db).unwrap());
    let pow = Arc::new(PowEngine::new(0));

    let pm_obs = Arc::new(PeerManager::with_f2f(vec![], vec![*friend.node_pubkey()]));
    pm_obs.set_storage(Arc::downgrade(&obs_storage));
    pm_obs.set_engine(&obs_engine);
    pm_obs.set_min_work_floor_for_test(1);

    let pm_friend = Arc::new(PeerManager::with_f2f(vec![], vec![*observer.node_pubkey()]));
    pm_friend.set_min_work_floor_for_test(1);

    let obs_handler = Arc::new(NodeRequestHandler::with_peer_manager(
        obs_engine.clone(),
        obs_storage.clone(),
        observer.clone(),
        pm_obs.clone(),
    ));

    let receiver = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &observer,
        pm_obs.clone(),
        obs_handler,
        cancel.clone(),
    )
    .expect("bind receiver");

    let sender = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &friend,
        pm_friend.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind sender");

    let receiver_addr = receiver.local_addr().expect("receiver addr");
    let sender_addr = sender.local_addr().expect("sender addr");

    pm_obs.register_f2f_friend(*friend.node_pubkey(), Some(sender_addr)).await;
    pm_friend.register_f2f_friend(*observer.node_pubkey(), Some(receiver_addr)).await;

    receiver.spawn_accept_loop();
    sender.spawn_accept_loop();

    let conn = sender.connect_peer_unchecked(receiver_addr).await.expect("connect");

    // 3. Friend admits write with TTL 31_536_000 without record_declared_usage
    let now_ms = pm_obs.net_time_ms();
    let tc = Arc::new(TierController::new(friend_storage.clone(), pow.clone()));
    tc.evaluate_and_charge_with_time_and_retry(
        None,
        None,
        None,
        None,
        StorageCharge::single(31_536_000),
        Some(&[0x77; 32]),
        Some(now_ms),
        false,
    )
    .await
    .unwrap();
    tc.wait_for_accounting_drain().await.unwrap();

    let w_ema1 = tc.write_ema_micro_bj_at(now_ms / 1000);
    assert!(w_ema1 > 0, "Admitted write must produce non-zero write EMA");

    // Send first signed heartbeat over real QUIC (hops = 0 direct friend)
    let mut hb1 = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *friend.node_pubkey(),
        addr: sender_addr,
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: w_ema1,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: friend.nonce(),
        hrw_routing_id: *friend.hrw_routing_id(),
        ticket_epoch_t0: friend.t0(),
        ttl: 15,
    };
    hb1.sign_origin(&friend, now_ms, humoco_sim_core::types::NetworkId::Mainnet);
    let bytes1 = bincode::serialize(&hb1).unwrap();
    let mut hdr1 = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bytes1.len() as u32);
    hdr1.reserved = 0;
    sender.send_unidirectional(&conn, &hdr1, &bytes1).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if pm_obs.get_node_write_evidence(friend.node_pubkey()).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        pm_obs.get_node_write_evidence(friend.node_pubkey()).await.is_some(),
        "Receiver must record initial write evidence"
    );
    assert!(
        !pm_obs.is_banned(friend.node_pubkey()).await,
        "Friend must not be banned on honest initial heartbeat"
    );

    // 4. Test lifecycle reconstruction:
    // (a) controller reconstruction against same storage
    tc.quota_worker_abort_handle().abort();
    tc.accounting_worker_abort_handle().abort();
    drop(tc);
    let tc_recon = Arc::new(TierController::new(friend_storage.clone(), pow.clone()));
    let recon_w = tc_recon.write_ema_micro_bj_at((now_ms + 1000) / 1000);
    assert!(
        recon_w > 0,
        "Reconstructed controller against same storage must reflect durable write EMA"
    );
    tc_recon.quota_worker_abort_handle().abort();
    tc_recon.accounting_worker_abort_handle().abort();
    drop(tc_recon);

    // (b) database lifecycle reconstruction: drop storage and reopen from disk
    drop(friend_storage);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let reopened_storage = Arc::new(RedbStorage::open(&friend_db).unwrap());
    let tc_reopened = Arc::new(TierController::new(reopened_storage.clone(), pow.clone()));

    // 5. Send second heartbeat 1 second later over real QUIC
    let now_ms_2 = now_ms + 1000;
    let w_ema2 = tc_reopened.write_ema_micro_bj_at(now_ms_2 / 1000);
    assert!(
        w_ema2 > 0,
        "Decayed write EMA after node restart must be non-zero (persisted in storage)"
    );

    let mut hb2 = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *friend.node_pubkey(),
        addr: sender_addr,
        timestamp_ms: now_ms_2,
        declared_write_ema_micro_bj: w_ema2,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: friend.nonce(),
        hrw_routing_id: *friend.hrw_routing_id(),
        ticket_epoch_t0: friend.t0(),
        ttl: 15,
    };
    hb2.sign_origin(&friend, now_ms_2, humoco_sim_core::types::NetworkId::Mainnet);
    let bytes2 = bincode::serialize(&hb2).unwrap();
    let mut hdr2 = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, bytes2.len() as u32);
    hdr2.reserved = 0;
    sender.send_unidirectional(&conn, &hdr2, &bytes2).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !pm_obs.is_banned(friend.node_pubkey()).await,
        "Friend must NOT be banned after restart when sending lawfully decayed EMA"
    );

    // 6. Conflicting evidence control: a malicious node signs high EMA then signs 0 EMA 1s later
    let (bad_node, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine bad_node");
    let bad_addr: SocketAddr = "127.0.0.1:39099".parse().unwrap();
    pm_obs.register_f2f_friend(*bad_node.node_pubkey(), Some(bad_addr)).await;

    let bad_sender = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &bad_node,
        Arc::new(PeerManager::with_f2f(vec![], vec![*observer.node_pubkey()])),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind bad_sender");
    bad_sender.spawn_accept_loop();
    let bad_conn = bad_sender.connect_peer_unchecked(receiver_addr).await.expect("bad connect");

    let mut bad_hb1 = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *bad_node.node_pubkey(),
        addr: bad_addr,
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 50_000_000,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: bad_node.nonce(),
        hrw_routing_id: *bad_node.hrw_routing_id(),
        ticket_epoch_t0: bad_node.t0(),
        ttl: 15,
    };
    bad_hb1.sign_origin(&bad_node, now_ms, humoco_sim_core::types::NetworkId::Mainnet);
    let bad_bytes1 = bincode::serialize(&bad_hb1).unwrap();
    let mut bad_hdr1 = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bad_bytes1.len() as u32);
    bad_hdr1.reserved = 0;
    bad_sender.send_unidirectional(&bad_conn, &bad_hdr1, &bad_bytes1).await.unwrap();

    let deadline_bad = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline_bad {
        if pm_obs.get_node_write_evidence(bad_node.node_pubkey()).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Now send conflicting heartbeat declaring 0 EMA 1 second later
    let mut bad_hb2 = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *bad_node.node_pubkey(),
        addr: bad_addr,
        timestamp_ms: now_ms + 1000,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: vec![],
        pow_nonce: bad_node.nonce(),
        hrw_routing_id: *bad_node.hrw_routing_id(),
        ticket_epoch_t0: bad_node.t0(),
        ttl: 15,
    };
    bad_hb2.sign_origin(&bad_node, now_ms + 1000, humoco_sim_core::types::NetworkId::Mainnet);
    let bad_bytes2 = bincode::serialize(&bad_hb2).unwrap();
    let mut bad_hdr2 = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, bad_bytes2.len() as u32);
    bad_hdr2.reserved = 0;
    bad_sender.send_unidirectional(&bad_conn, &bad_hdr2, &bad_bytes2).await.unwrap();

    let deadline_ban = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline_ban {
        if pm_obs.is_banned(bad_node.node_pubkey()).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        pm_obs.is_banned(bad_node.node_pubkey()).await,
        "Malicious under-reporting node must be banned upon conflicting heartbeat"
    );
}

#[tokio::test]
async fn test_s05_17_stale_concurrent_snapshots_and_persistence_failure_isolation() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_17_stale.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(0));

    // Initial state setup in storage
    let base_state = PersistedIngressAccountingState {
        checkpoint_seq: 10,
        current_day: 100,
        last_epoch_seq: 5,
        reserved_epoch_seq: 1000,
        last_timestamp_ms: 100_000,
        cumulative_micro_byte_years: 500,
        prev_day_final_bytes: 0,
        write_ema_scaled: 100u128 << 32,
        last_write_ema_sec: Some(100),
        read_ema_scaled: 50u128 << 32,
        last_read_ema_sec: Some(100),
    };
    storage.store_ingress_accounting_state(&base_state).unwrap();
    assert_eq!(storage.load_ingress_accounting_state().unwrap().unwrap(), base_state);

    // 1. Identical snapshot -> idempotent Ok(()) no-op
    assert!(!base_state.supersedes(&base_state));
    storage.store_ingress_accounting_state(&base_state).unwrap();
    assert_eq!(storage.load_ingress_accounting_state().unwrap().unwrap(), base_state);

    // 2. Stale concurrent snapshot: lower checkpoint_seq (9 < 10) even with larger write_ema_scaled (200u128 << 32)
    let stale_snapshot = PersistedIngressAccountingState {
        checkpoint_seq: 9,
        current_day: 100,
        last_epoch_seq: 5,
        reserved_epoch_seq: 1000,
        last_timestamp_ms: 100_000,
        cumulative_micro_byte_years: 500,
        prev_day_final_bytes: 0,
        write_ema_scaled: 200u128 << 32,
        last_write_ema_sec: Some(100),
        read_ema_scaled: 50u128 << 32,
        last_read_ema_sec: Some(100),
    };
    assert!(!stale_snapshot.supersedes(&base_state));
    storage.store_ingress_accounting_state(&stale_snapshot).unwrap();
    assert_eq!(
        storage.load_ingress_accounting_state().unwrap().unwrap(),
        base_state,
        "Stale snapshot with lower checkpoint_seq must be rejected"
    );

    // 3. Higher checkpoint_seq (11 > 10) when raw write_ema_scaled lawfully decayed lower (50u128 << 32 < 100u128 << 32) at t=110
    let decayed_snapshot = PersistedIngressAccountingState {
        checkpoint_seq: 11,
        current_day: 100,
        last_epoch_seq: 5,
        reserved_epoch_seq: 1000,
        last_timestamp_ms: 100_000,
        cumulative_micro_byte_years: 500,
        prev_day_final_bytes: 0,
        write_ema_scaled: 50u128 << 32,
        last_write_ema_sec: Some(110),
        read_ema_scaled: 50u128 << 32,
        last_read_ema_sec: Some(110),
    };
    assert!(decayed_snapshot.supersedes(&base_state));
    storage.store_ingress_accounting_state(&decayed_snapshot).unwrap();
    assert_eq!(
        storage.load_ingress_accounting_state().unwrap().unwrap(),
        decayed_snapshot,
        "Higher checkpoint_seq with decayed EMA must supersede base state"
    );

    // 4. Persistence failure & queue saturation isolation
    let tc = Arc::new(TierController::new_with_persist_capacity(storage.clone(), pow.clone(), 1));

    // Simulate failure
    tc.fail_accounting_persistence_for_test();
    let err_durable = tc.durable_ema_snapshot(120_000).await;
    assert!(
        matches!(err_durable, Err(IngressError::AccountingPersistenceUnavailable)),
        "durable_ema_snapshot must fail closed when persistence fails"
    );

    let err_drain = tc.wait_for_accounting_drain().await;
    assert!(
        matches!(err_drain, Err(IngressError::AccountingPersistenceUnavailable)),
        "wait_for_accounting_drain must fail closed when persistence fails"
    );

    // 100% read-service isolation: status_query_emas_at works even when persistence is broken
    let (stat_w, _stat_r) = tc.status_query_emas_at(120_000);
    assert!(stat_w > 0, "status_query_emas_at must decay durable write EMA");
}

#[tokio::test]
async fn test_s05_17_full_daemon_lifecycle_genesis_heartbeat_restart_continuity() {
    let cancel = CancellationToken::new();

    // 1. Setup Observer node
    let observer = NodeIdentity::generate();
    let obs_temp = tempdir().unwrap();
    let obs_db = obs_temp.path().join("obs_daemon.redb");
    let obs_storage = Arc::new(RedbStorage::open(&obs_db).unwrap());
    let (obs_engine, _) = DualTierEngine::new(obs_storage.clone());

    // 2. Setup Friend Node Identity
    let (friend, _) = NodeIdentity::generate()
        .mine_ticket(1, 1_750_000_000, Some(50))
        .expect("mine friend");
    let friend_temp = tempdir().unwrap();
    let friend_data_dir = friend_temp.path().join("friend_data");

    let pm_obs = Arc::new(PeerManager::with_f2f(vec![], vec![*friend.node_pubkey()]));
    pm_obs.set_storage(Arc::downgrade(&obs_storage));
    pm_obs.set_engine(&obs_engine);
    pm_obs.set_min_work_floor_for_test(1);

    let obs_handler = Arc::new(NodeRequestHandler::with_peer_manager(
        obs_engine.clone(),
        obs_storage.clone(),
        observer.clone(),
        pm_obs.clone(),
    ));

    let receiver = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &observer,
        pm_obs.clone(),
        obs_handler,
        cancel.clone(),
    )
    .expect("bind receiver");
    receiver.spawn_accept_loop();
    let receiver_addr = receiver.local_addr().expect("receiver addr");

    // Configure friend's NodeConfig pointing to observer as F2F friend
    let mut config = NodeConfig::default();
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.simulation_mode = true;
    config.storage.data_dir = friend_data_dir.clone();
    let client_token = "f2f_0123456789abcdef0123456789abcdef";
    config.f2f.tokens = vec![client_token.to_string()];
    config.f2f.peers = vec![format!("{}@{}", observer.public_key_hex(), receiver_addr)];
    config.f2f.trusted_pubkeys = vec![observer.public_key_hex()];

    // 3. Full Daemon Lifecycle Phase 1: Boot NodeDaemon 1 with bootstrap_new_region()
    let cancel_d1 = CancellationToken::new();
    let (bound_tx1, bound_rx1) = tokio::sync::oneshot::channel::<BoundAddrs>();
    let daemon1 = NodeDaemon::with_bound_sender(
        config.clone(),
        friend.clone(),
        cancel_d1.clone(),
        bound_tx1,
    )
    .bootstrap_new_region();
    let daemon1_handle = tokio::spawn(async move { daemon1.run().await });
    let bound1 = bound_rx1.await.expect("daemon1 bound");

    // Register friend's actual bound P2P address with the observer
    pm_obs.register_f2f_friend(*friend.node_pubkey(), Some(bound1.p2p_addr)).await;

    // HTTP Genesis Registration via POST /v1/lock with valid client token in X-Peer-Token header
    let now_ms = test_now_ms();
    let genesis = make_test_hmc_genesis([0x88; 32], now_ms + 100_000, friend.signing_key());
    let http_client = reqwest::Client::new();
    let resp = http_client
        .post(format!("http://{}/v1/lock", bound1.rpc_addr))
        .header("X-Peer-Token", client_token)
        .json(&genesis)
        .send()
        .await
        .expect("send genesis request");
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Wait for the running daemon's real QUIC heartbeat to reach the observer
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if pm_obs.get_node_write_evidence(friend.node_pubkey()).await.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ev1 = pm_obs
        .get_node_write_evidence(friend.node_pubkey())
        .await
        .expect("observer must receive initial heartbeat evidence from daemon 1");
    assert!(
        ev1.declared_write_ema_micro_bj > 0,
        "Genesis registration must produce non-zero write EMA in heartbeat"
    );
    assert!(
        !pm_obs.is_banned(friend.node_pubkey()).await,
        "Friend daemon must not be banned on initial heartbeat"
    );

    // 4. Abrupt / cancelled daemon stop
    cancel_d1.cancel();
    let res1 = daemon1_handle.await.expect("join daemon1");
    assert!(res1.is_ok(), "daemon1 shutdown must complete cleanly, got {:?}", res1);

    // 5. Full Daemon Lifecycle Phase 2: Boot new NodeDaemon on reopened DB (no bootstrap_new_region!)
    let cancel_d2 = CancellationToken::new();
    let (bound_tx2, bound_rx2) = tokio::sync::oneshot::channel::<BoundAddrs>();
    let daemon2 = NodeDaemon::with_bound_sender(
        config.clone(),
        friend.clone(),
        cancel_d2.clone(),
        bound_tx2,
    );
    let daemon2_handle = tokio::spawn(async move { daemon2.run().await });
    let bound2 = bound_rx2.await.expect("daemon2 bound");

    // Register friend's new P2P address on observer
    pm_obs.register_f2f_friend(*friend.node_pubkey(), Some(bound2.p2p_addr)).await;

    // Wait for daemon 2 to emit next real QUIC heartbeat with persisted, decayed EMA
    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut ev2 = None;
    while tokio::time::Instant::now() < deadline2 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Some(ev) = pm_obs.get_node_write_evidence(friend.node_pubkey()).await {
            if ev.timestamp_ms > ev1.timestamp_ms {
                ev2 = Some(ev);
                break;
            }
        }
    }
    assert!(
        ev2.is_some(),
        "Observer must receive second heartbeat from restarted daemon 2 on reopened DB"
    );
    assert!(
        !pm_obs.is_banned(friend.node_pubkey()).await,
        "Friend daemon must NOT be banned after restart with decayed EMA from reopened storage"
    );

    cancel_d2.cancel();
    let res2 = daemon2_handle.await.expect("join daemon2");
    assert!(res2.is_ok(), "daemon2 shutdown must complete cleanly, got {:?}", res2);
}

// ===========================================================================
// S05-18: Multi-lock chain aggregate storage charge and bounded accounting
// ===========================================================================

#[tokio::test]
async fn test_s05_18_vip_multi_lock_chain_aggregate_accounting() {
    let (router, _operator, storage, _identity, tier_controller, _pow, state, peer_manager) =
        setup_test_app_with_clock();

    let now_ms = peer_manager.net_time_ms();
    let now_sec = now_ms / 1000;

    // Anchor a root with ~1 year remaining:
    // ttl_seconds = 31_535_999s -> ByteYears = 192, micro_ByteYears = 191_999_994
    let ttl_seconds = 31_535_999u64;
    let root_valid_until = now_ms + ttl_seconds * 1000 + 500;

    let key0 = SigningKey::from_bytes(&[50; 32]);
    let key1 = SigningKey::from_bytes(&[51; 32]);
    let key2 = SigningKey::from_bytes(&[52; 32]);
    let key3 = SigningKey::from_bytes(&[53; 32]);

    let r1 = sha3::Sha3_256::digest(key1.verifying_key().as_bytes()).into();
    let mut root = make_test_hmc_genesis([0x50; 32], root_valid_until, &key0);
    authenticate_root_fixture_with_receiver(&mut root, &key0, Some(r1));

    // Separately anchor the root
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    let (root_verdict, is_new) = state
        .engine
        .ingress_hmc_lock_durable(
            root_tag.clone(),
            L2LockEntry::from(&root),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now_ms),
            Some("Free"),
            Some(0),
            None,
        )
        .await;
    assert!(matches!(root_verdict, L2Verdict::Verified { .. }));
    assert!(is_new);

    // Build 2 valid new spends
    let r2 = sha3::Sha3_256::digest(key2.verifying_key().as_bytes()).into();
    let spend1 = make_test_causal_spend(&root, &key1, Some(r2), [0x51; 32], now_ms);

    let r3 = sha3::Sha3_256::digest(key3.verifying_key().as_bytes()).into();
    let spend2 = make_test_causal_spend(&spend1, &key2, Some(r3), [0x52; 32], now_ms);

    let chain_req = L2ChainLockRequest {
        auth: spend2.auth.clone(),
        layer2_voucher_id: root.layer2_voucher_id.clone(),
        chain: vec![spend1.clone(), spend2.clone()],
    };
    let chain_bytes = serde_json::to_vec(&chain_req).unwrap();

    let account_tag = [0x77u8; 32];
    let vip_token = format!("vip_{}", hex::encode(account_tag));
    tier_controller.register_vip_token(&vip_token, account_tag);

    // Scenario A: With one lock's VIP credit (192 Byte-Years)
    tier_controller.topup_vip_quota(account_tag, 192).unwrap();
    assert_eq!(tier_controller.get_cached_vip_quota(&account_tag), Some(192));

    let http_req = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes.clone()))
        .unwrap();

    let resp = router.clone().oneshot(http_req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Submitting 2-lock chain with only 1 lock VIP credit must return HTTP 429"
    );

    let tag1 = spend1.ds_tag.as_deref().unwrap();
    let tag2 = spend2.ds_tag.as_deref().unwrap();
    assert!(
        !state.engine.is_hmc_entry_durable(tag1, &L2LockEntry::from(&spend1), root_valid_until).await,
        "spend1 must not be committed after 429"
    );
    assert!(
        !state.engine.is_hmc_entry_durable(tag2, &L2LockEntry::from(&spend2), root_valid_until).await,
        "spend2 must not be committed after 429"
    );

    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(192),
        "VIP credit must not be debited on 429"
    );
    assert_eq!(
        tier_controller.vip_rolling_usage_at_for_test(&account_tag, now_ms),
        0,
        "VIP rolling usage must remain 0 on 429"
    );
    assert_eq!(
        tier_controller.write_ema_micro_bj_at(now_sec),
        0,
        "Write EMA must remain 0 on 429"
    );

    // Scenario B: With sufficient aggregate credit (384 Byte-Years)
    tier_controller.topup_vip_quota(account_tag, 192).unwrap();
    assert_eq!(tier_controller.get_cached_vip_quota(&account_tag), Some(384));

    let http_req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes.clone()))
        .unwrap();

    let resp2 = router.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::CREATED,
        "Submitting 2-lock chain with sufficient aggregate VIP credit must return HTTP 201"
    );

    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(0),
        "VIP credit must be debited by 384 Byte-Years"
    );
    assert_eq!(
        tier_controller.vip_rolling_usage_at_for_test(&account_tag, now_ms),
        384,
        "Rolling VIP usage must be 384 Byte-Years"
    );
    assert_eq!(
        tier_controller.write_ema_micro_bj_at(now_sec),
        383_999_988,
        "Write EMA must match aggregate micro Byte-Years"
    );

    tier_controller.wait_for_accounting_drain().await.unwrap();
    let persisted = storage.load_ingress_accounting_state().unwrap().unwrap();
    assert_eq!(
        persisted.cumulative_micro_byte_years,
        383_999_988,
        "Persisted cumulative micro Byte-Years must be 383_999_988"
    );

    assert!(
        state.engine.is_hmc_entry_durable(tag1, &L2LockEntry::from(&spend1), root_valid_until).await,
        "spend1 must be committed after 201"
    );
    assert!(
        state.engine.is_hmc_entry_durable(tag2, &L2LockEntry::from(&spend2), root_valid_until).await,
        "spend2 must be committed after 201"
    );
}

#[tokio::test]
async fn test_s05_18_friends_and_public_multi_lock_chain_budget_boundaries() {
    let (router, _operator, _storage, _identity, tier_controller, _pow, state, peer_manager) =
        setup_test_app_with_clock();

    let now_ms = peer_manager.net_time_ms();
    let ttl_seconds = 31_535_999u64;
    let root_valid_until = now_ms + ttl_seconds * 1000 + 500;

    let key0 = SigningKey::from_bytes(&[60; 32]);
    let key1 = SigningKey::from_bytes(&[61; 32]);
    let key2 = SigningKey::from_bytes(&[62; 32]);

    let r1 = sha3::Sha3_256::digest(key1.verifying_key().as_bytes()).into();
    let mut root = make_test_hmc_genesis([0x60; 32], root_valid_until, &key0);
    authenticate_root_fixture_with_receiver(&mut root, &key0, Some(r1));

    state
        .engine
        .ingress_hmc_lock_durable(
            bs58::encode(root.transaction_hash).into_string(),
            L2LockEntry::from(&root),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now_ms),
            Some("Free"),
            Some(0),
            None,
        )
        .await;

    let r2 = sha3::Sha3_256::digest(key2.verifying_key().as_bytes()).into();
    let spend1 = make_test_causal_spend(&root, &key1, Some(r2), [0x61; 32], now_ms);
    let spend2 = make_test_causal_spend(&spend1, &key2, None, [0x62; 32], now_ms);

    let chain_req = L2ChainLockRequest {
        auth: spend2.auth.clone(),
        layer2_voucher_id: root.layer2_voucher_id.clone(),
        chain: vec![spend1.clone(), spend2.clone()],
    };
    let chain_bytes = serde_json::to_vec(&chain_req).unwrap();

    // 1. Friends (f2f_) test:
    let peer_token = "f2f_test_friend_token_s05_18";
    tier_controller.register_f2f_peer(peer_token);

    // Consume friend daily budget so available is exactly 192 Byte-Years (< 384)
    let daily_quota = tier_controller.calculate_daily_quota(1.0, 1.0);
    tier_controller
        .evaluate_f2f_quota(peer_token, daily_quota - 192, now_ms)
        .expect("consume initial friend quota");

    let http_req = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("x-peer-token", peer_token)
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes.clone()))
        .unwrap();

    let resp = router.clone().oneshot(http_req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Friends budget sufficing for only 1 lock must reject 2-lock chain with 429"
    );
    let tag1 = spend1.ds_tag.as_deref().unwrap();
    let tag2 = spend2.ds_tag.as_deref().unwrap();
    assert!(!state.engine.is_hmc_entry_durable(tag1, &L2LockEntry::from(&spend1), root_valid_until).await);
    assert!(!state.engine.is_hmc_entry_durable(tag2, &L2LockEntry::from(&spend2), root_valid_until).await);

    // 2. Friends sufficient budget test with a fresh friend token
    let peer_token_2 = "f2f_test_friend_token_2_s05_18";
    tier_controller.register_f2f_peer(peer_token_2);

    let http_req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("x-peer-token", peer_token_2)
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes.clone()))
        .unwrap();

    let resp2 = router.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CREATED);
    assert!(state.engine.is_hmc_entry_durable(tag1, &L2LockEntry::from(&spend1), root_valid_until).await);
    assert!(state.engine.is_hmc_entry_durable(tag2, &L2LockEntry::from(&spend2), root_valid_until).await);

    // 3. Public Tier test:
    // Create new voucher chain for public test
    let mut root_pub = make_test_hmc_genesis([0x65; 32], root_valid_until, &key0);
    authenticate_root_fixture_with_receiver(&mut root_pub, &key0, Some(r1));
    state
        .engine
        .ingress_hmc_lock_durable(
            bs58::encode(root_pub.transaction_hash).into_string(),
            L2LockEntry::from(&root_pub),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now_ms),
            Some("Free"),
            Some(0),
            None,
        )
        .await;

    let spend1_pub = make_test_causal_spend(&root_pub, &key1, Some(r2), [0x66; 32], now_ms);
    let spend2_pub = make_test_causal_spend(&spend1_pub, &key2, None, [0x67; 32], now_ms);
    let chain_pub = L2ChainLockRequest {
        auth: spend2_pub.auth.clone(),
        layer2_voucher_id: root_pub.layer2_voucher_id.clone(),
        chain: vec![spend1_pub.clone(), spend2_pub.clone()],
    };
    let chain_pub_bytes = serde_json::to_vec(&chain_pub).unwrap();

    // Exhaust public pool for test (0 remaining)
    tier_controller.exhaust_public_quota_for_test(now_ms);

    let pub_req = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .body(Body::from(chain_pub_bytes.clone()))
        .unwrap();

    let pub_resp = router.clone().oneshot(pub_req).await.unwrap();
    assert_eq!(
        pub_resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Public pool with insufficient budget must reject 2-lock chain with 429"
    );
    let pub_tag1 = spend1_pub.ds_tag.as_deref().unwrap();
    let pub_tag2 = spend2_pub.ds_tag.as_deref().unwrap();
    assert!(!state.engine.is_hmc_entry_durable(pub_tag1, &L2LockEntry::from(&spend1_pub), root_valid_until).await);
    assert!(!state.engine.is_hmc_entry_durable(pub_tag2, &L2LockEntry::from(&spend2_pub), root_valid_until).await);
}

#[tokio::test]
async fn test_s05_18_exact_authenticated_idempotent_chain_retries() {
    let (router, _operator, _storage, _identity, tier_controller, _pow, state, peer_manager) =
        setup_test_app_with_clock();

    let now_ms = peer_manager.net_time_ms();
    let now_sec = now_ms / 1000;
    let ttl_seconds = 31_535_999u64;
    let root_valid_until = now_ms + ttl_seconds * 1000 + 500;

    let key0 = SigningKey::from_bytes(&[80; 32]);
    let key1 = SigningKey::from_bytes(&[81; 32]);
    let key2 = SigningKey::from_bytes(&[82; 32]);

    let r1 = sha3::Sha3_256::digest(key1.verifying_key().as_bytes()).into();
    let mut root = make_test_hmc_genesis([0x80; 32], root_valid_until, &key0);
    authenticate_root_fixture_with_receiver(&mut root, &key0, Some(r1));

    state
        .engine
        .ingress_hmc_lock_durable(
            bs58::encode(root.transaction_hash).into_string(),
            L2LockEntry::from(&root),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now_ms),
            Some("Free"),
            Some(0),
            None,
        )
        .await;

    let r2 = sha3::Sha3_256::digest(key2.verifying_key().as_bytes()).into();
    let spend1 = make_test_causal_spend(&root, &key1, Some(r2), [0x81; 32], now_ms);
    let spend2 = make_test_causal_spend(&spend1, &key2, None, [0x82; 32], now_ms);

    let chain_req = L2ChainLockRequest {
        auth: spend2.auth.clone(),
        layer2_voucher_id: root.layer2_voucher_id.clone(),
        chain: vec![spend1.clone(), spend2.clone()],
    };
    let chain_bytes = serde_json::to_vec(&chain_req).unwrap();

    let account_tag = [0x88u8; 32];
    let vip_token = format!("vip_{}", hex::encode(account_tag));
    tier_controller.register_vip_token(&vip_token, account_tag);
    tier_controller.topup_vip_quota(account_tag, 500).unwrap();

    // First attempt: succeeds with 201 Created
    let http_req1 = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes.clone()))
        .unwrap();

    let resp1 = router.clone().oneshot(http_req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);

    let bal_after_1 = tier_controller.get_cached_vip_quota(&account_tag).unwrap();
    let usage_after_1 = tier_controller.vip_rolling_usage_at_for_test(&account_tag, now_ms);
    let ema_after_1 = tier_controller.write_ema_micro_bj_at(now_sec);

    // Second attempt: identical retry must succeed with HTTP 200 without double-charging
    let http_req2 = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes.clone()))
        .unwrap();

    let resp2 = router.clone().oneshot(http_req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "Idempotent retry of identical multi-lock chain must succeed with HTTP 200"
    );

    let bal_after_2 = tier_controller.get_cached_vip_quota(&account_tag).unwrap();
    let usage_after_2 = tier_controller.vip_rolling_usage_at_for_test(&account_tag, now_ms);
    let ema_after_2 = tier_controller.write_ema_micro_bj_at(now_sec);

    assert_eq!(bal_after_1, bal_after_2, "VIP credit balance must not be charged on retry");
    assert_eq!(usage_after_1, usage_after_2, "Rolling VIP usage must not increase on retry");
    assert!(ema_after_2 <= ema_after_1, "Write EMA must not increase on retry");
}

#[tokio::test]
async fn test_s05_18_single_lock_root_spend_and_genesis_spend_chain_consistency() {
    let (router, _operator, _storage, _identity, tier_controller, _pow, _state, peer_manager) =
        setup_test_app_with_clock();

    let now_ms = peer_manager.net_time_ms();
    let ttl_seconds = 31_535_999u64;
    let root_valid_until = now_ms + ttl_seconds * 1000 + 500;

    let key0 = SigningKey::from_bytes(&[90; 32]);
    let key1 = SigningKey::from_bytes(&[91; 32]);
    let account_tag = [0x99u8; 32];
    let vip_token = format!("vip_{}", hex::encode(account_tag));
    tier_controller.register_vip_token(&vip_token, account_tag);

    // 1. Single-lock genesis root registration via POST /v1/lock charges 192 Byte-Years
    tier_controller.topup_vip_quota(account_tag, 192).unwrap();
    let r1 = sha3::Sha3_256::digest(key1.verifying_key().as_bytes()).into();
    let mut root = make_test_hmc_genesis([0x90; 32], root_valid_until, &key0);
    authenticate_root_fixture_with_receiver(&mut root, &key0, Some(r1));

    let root_req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&root).unwrap()))
        .unwrap();

    let root_resp = router.clone().oneshot(root_req).await.unwrap();
    assert_eq!(root_resp.status(), StatusCode::CREATED);
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(0),
        "Single root anchor registration must charge 192 Byte-Years"
    );

    // 2. Single-lock spend via POST /v1/lock charges 192 Byte-Years
    tier_controller.topup_vip_quota(account_tag, 192).unwrap();
    let spend1 = make_test_causal_spend(&root, &key1, None, [0x91; 32], now_ms);
    let spend_req = Request::builder()
        .method("POST")
        .uri("/v1/lock")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&spend1).unwrap()))
        .unwrap();

    let spend_resp = router.clone().oneshot(spend_req).await.unwrap();
    assert_eq!(spend_resp.status(), StatusCode::CREATED);
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(0),
        "Single lock spend must charge 192 Byte-Years"
    );

    // 3. Chain [genesis, spend] via POST /v1/lock/chain:
    // Requires 384 Byte-Years for the 2 locks
    let key0_b = SigningKey::from_bytes(&[92; 32]);
    let key1_b = SigningKey::from_bytes(&[93; 32]);
    let r1_b = sha3::Sha3_256::digest(key1_b.verifying_key().as_bytes()).into();
    let mut root_b = make_test_hmc_genesis([0x92; 32], root_valid_until, &key0_b);
    authenticate_root_fixture_with_receiver(&mut root_b, &key0_b, Some(r1_b));
    let spend_b = make_test_causal_spend(&root_b, &key1_b, None, [0x93; 32], now_ms);

    let chain_gen_spend = L2ChainLockRequest {
        auth: spend_b.auth.clone(),
        layer2_voucher_id: root_b.layer2_voucher_id.clone(),
        chain: vec![root_b.clone(), spend_b.clone()],
    };
    let chain_gen_bytes = serde_json::to_vec(&chain_gen_spend).unwrap();

    // 3a. With 192 Byte-Years: must reject with 429
    tier_controller.topup_vip_quota(account_tag, 192).unwrap();
    let http_req_insufficient = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_gen_bytes.clone()))
        .unwrap();

    let resp_insufficient = router.clone().oneshot(http_req_insufficient).await.unwrap();
    assert_eq!(
        resp_insufficient.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Chain [genesis, spend] with only 1 lock budget must return 429"
    );

    // 3b. With 384 Byte-Years: succeeds with 201 Created
    tier_controller.topup_vip_quota(account_tag, 192).unwrap();
    assert_eq!(tier_controller.get_cached_vip_quota(&account_tag), Some(384));

    let http_req_sufficient = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_gen_bytes.clone()))
        .unwrap();

    let resp_sufficient = router.clone().oneshot(http_req_sufficient).await.unwrap();
    assert_eq!(resp_sufficient.status(), StatusCode::CREATED);
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(0),
        "Chain [genesis, spend] must debit 384 Byte-Years"
    );
}

#[tokio::test]
async fn test_s05_18_bounded_chain_length_and_capacity_refusal() {
    let (router, _operator, _storage, _identity, tier_controller, _pow, state, peer_manager) =
        setup_test_app_with_clock();

    let now_ms = peer_manager.net_time_ms();
    let key1 = SigningKey::from_bytes(&[101; 32]);

    // 1. Empty chain rejected with HTTP 400
    let empty_chain = L2ChainLockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: [0x33; 32],
            auth_signature: None,
        },
        layer2_voucher_id: "test_voucher_empty".into(),
        chain: vec![],
    };
    let http_req_empty = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&empty_chain).unwrap()))
        .unwrap();
    let resp_empty = router.clone().oneshot(http_req_empty).await.unwrap();
    assert_eq!(resp_empty.status(), StatusCode::BAD_REQUEST);

    // 2. Chain > 256 locks rejected with HTTP 400 before PoW/storage mutation
    let mut large_hops = Vec::with_capacity(257);
    for _i in 0..257u16 {
        let mut hop = make_test_hmc_spend("v", "t", [0x01; 32], &key1);
        hop.trap_r = None;
        hop.trap_s = None;
        hop.created_at_ms = now_ms;
        large_hops.push(hop);
    }
    let large_chain = L2ChainLockRequest {
        auth: large_hops[0].auth.clone(),
        layer2_voucher_id: "v".into(),
        chain: large_hops,
    };
    let http_req_large = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&large_chain).unwrap()))
        .unwrap();
    let resp_large = router
        .clone()
        .oneshot(http_req_large)
        .await
        .unwrap();
    assert_eq!(
        resp_large.status(),
        StatusCode::BAD_REQUEST,
        "Chain length > 256 must be rejected with 400 Bad Request before PoW/storage"
    );

    // 3. Capacity refusal: when persistence is unavailable
    let account_tag = [0xaa; 32];
    let vip_token = format!("vip_{}", hex::encode(account_tag));
    tier_controller.register_vip_token(&vip_token, account_tag);
    tier_controller.topup_vip_quota(account_tag, 1000).unwrap();

    let root_valid_until = now_ms + 31_535_999 * 1000 + 500;
    let mut root_cap = make_test_hmc_genesis([0x03; 32], root_valid_until, &key1);
    let r1 = sha3::Sha3_256::digest(key1.verifying_key().as_bytes()).into();
    authenticate_root_fixture_with_receiver(&mut root_cap, &key1, Some(r1));
    state
        .engine
        .ingress_hmc_lock_durable(
            bs58::encode(root_cap.transaction_hash).into_string(),
            L2LockEntry::from(&root_cap),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(now_ms),
            Some("VIP"),
            Some(192),
            None,
        )
        .await;

    let single_hop = make_test_causal_spend(&root_cap, &key1, None, [0x04; 32], now_ms);
    let test_chain = L2ChainLockRequest {
        auth: single_hop.auth.clone(),
        layer2_voucher_id: root_cap.layer2_voucher_id.clone(),
        chain: vec![single_hop],
    };
    let chain_bytes = serde_json::to_vec(&test_chain).unwrap();

    tier_controller
        .quota_worker_failure_handle()
        .store(true, Ordering::Release);

    let http_req_cap = Request::builder()
        .method("POST")
        .uri("/v1/lock/chain")
        .header("authorization", format!("Bearer {vip_token}"))
        .header("content-type", "application/json")
        .body(Body::from(chain_bytes))
        .unwrap();

    let resp_cap = router.clone().oneshot(http_req_cap).await.unwrap();
    assert_eq!(
        resp_cap.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "When quota persistence is unavailable, must refuse with 503 Service Unavailable"
    );
    assert_eq!(
        tier_controller.get_cached_vip_quota(&account_tag),
        Some(1000),
        "VIP quota must not be debited on persistence capacity refusal"
    );
}

#[tokio::test]
async fn test_s05_18_real_quic_gateway_to_receiver_aggregate_accounting() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("s05_18_server.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new(0));
    let server_tc = Arc::new(TierController::new(storage.clone(), pow.clone()));
    let server_id = NodeIdentity::generate();
    let gateway_id = NodeIdentity::generate();
    let gateway_pubkey = *gateway_id.node_pubkey();

    let server_peer_mgr = Arc::new(PeerManager::new(vec![]));
    server_peer_mgr.set_simulation_mode(true);
    server_peer_mgr.seed_local_ticket_age(
        *server_id.node_pubkey(),
        *server_id.hrw_routing_id(),
        std::time::Duration::from_secs(86_400),
    );
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
    .with_readiness_manager(readiness)
    .with_tier_controller(server_tc.clone());

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

    let gw_cancel = CancellationToken::new();
    let gw_peer_mgr = Arc::new(PeerManager::new(vec![server_addr]));
    let gateway_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway_id,
        gw_peer_mgr.clone(),
        Arc::new(DefaultRequestHandler),
        gw_cancel.clone(),
    )
    .expect("bind gateway QUIC");
    let _gw_accept = gateway_transport.spawn_accept_loop();

    server_peer_mgr
        .register_f2f_friend(gateway_pubkey, Some(gateway_transport.local_addr().unwrap()))
        .await;
    gw_peer_mgr
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn = gateway_transport
        .connect_peer(server_addr)
        .await
        .expect("connect QUIC peer");

    let quic_now_ms = test_now_ms();
    let ttl_s = 31_535_999u64;
    let root_valid_until = quic_now_ms + ttl_s * 1000 + 500;

    let key0 = SigningKey::from_bytes(&[70; 32]);
    let key1 = SigningKey::from_bytes(&[71; 32]);
    let key2 = SigningKey::from_bytes(&[72; 32]);

    let r1 = sha3::Sha3_256::digest(key1.verifying_key().as_bytes()).into();
    let mut root = make_test_hmc_genesis([0x70; 32], root_valid_until, &key0);
    authenticate_root_fixture_with_receiver(&mut root, &key0, Some(r1));

    engine
        .ingress_hmc_lock_durable(
            bs58::encode(root.transaction_hash).into_string(),
            L2LockEntry::from(&root),
            humoco_node::storage::IngressOrigin::ClientApi,
            Some(quic_now_ms),
            Some("Free"),
            Some(0),
            None,
        )
        .await;

    let r2 = sha3::Sha3_256::digest(key2.verifying_key().as_bytes()).into();
    let spend1 = make_test_causal_spend(&root, &key1, Some(r2), [0x71; 32], quic_now_ms);
    let spend2 = make_test_causal_spend(&spend1, &key2, None, [0x72; 32], quic_now_ms);

    let chain_req = L2ChainLockRequest {
        auth: spend2.auth.clone(),
        layer2_voucher_id: root.layer2_voucher_id.clone(),
        chain: vec![spend1.clone(), spend2.clone()],
    };

    let base_fp = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let total_fp = base_fp * 2;

    let last_hop = spend2.clone();
    let digest = compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        &gateway_pubkey,
        0,
        1,
        quic_now_ms,
        0,
        0,
        total_fp,
        false,
        &last_hop.transaction_hash,
    );
    let sender_sig = gateway_id.signing_key().sign(&digest).to_bytes();

    let wire_payload = bincode::serialize(&LockWirePayload::Hmc {
        req: last_hop.clone(),
        chain: Some(chain_req.clone()),
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: gateway_pubkey,
        sender_signature: sender_sig,
        timestamp_ms: quic_now_ms,
    })
    .unwrap();
    let header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        wire_payload.len() as u32,
    );

    // 1. Consume gateway node write quota on server such that remaining quota is 192 Byte-Years (< 384)
    let daily_node_limit = server_tc.calculate_daily_quota(5.0, 1.0);
    server_tc
        .evaluate_node_write_quota(&gateway_pubkey, daily_node_limit - 192, quic_now_ms + 5_000)
        .expect("consume node write quota");

    let (resp_hdr, _) = gateway_transport
        .send_request(&conn, &header, &wire_payload)
        .await
        .expect("send QUIC request");

    assert_eq!(
        resp_hdr.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "Multi-lock chain request over QUIC when budget suffices for only 1 lock must return FLAG_QUOTA_EXCEEDED"
    );

    let tag1 = spend1.ds_tag.as_deref().unwrap();
    let tag2 = spend2.ds_tag.as_deref().unwrap();
    assert!(!engine.is_hmc_entry_durable(tag1, &L2LockEntry::from(&spend1), root_valid_until).await);
    assert!(!engine.is_hmc_entry_durable(tag2, &L2LockEntry::from(&spend2), root_valid_until).await);

    // 2. Gateway 2 with fresh / full budget sends identical 2-lock chain over QUIC:
    let gw_cancel2 = CancellationToken::new();
    let gateway_id2 = NodeIdentity::generate();
    let gateway_pubkey2 = *gateway_id2.node_pubkey();
    let gw_peer_mgr2 = Arc::new(PeerManager::new(vec![server_addr]));
    let gateway_transport2 = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &gateway_id2,
        gw_peer_mgr2.clone(),
        Arc::new(DefaultRequestHandler),
        gw_cancel2.clone(),
    )
    .expect("bind gateway 2 QUIC");
    let _gw_accept2 = gateway_transport2.spawn_accept_loop();

    server_peer_mgr
        .register_f2f_friend(gateway_pubkey2, Some(gateway_transport2.local_addr().unwrap()))
        .await;
    gw_peer_mgr2
        .register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn2 = gateway_transport2
        .connect_peer(server_addr)
        .await
        .expect("connect QUIC peer 2");

    let digest2 = compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        &gateway_pubkey2,
        0,
        1,
        quic_now_ms,
        0,
        0,
        total_fp,
        false,
        &last_hop.transaction_hash,
    );
    let sender_sig2 = gateway_id2.signing_key().sign(&digest2).to_bytes();

    let wire_payload2 = bincode::serialize(&LockWirePayload::Hmc {
        req: last_hop.clone(),
        chain: Some(chain_req.clone()),
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 1,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: 0,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        sender_pubkey: gateway_pubkey2,
        sender_signature: sender_sig2,
        timestamp_ms: quic_now_ms,
    })
    .unwrap();
    let header2 = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        wire_payload2.len() as u32,
    );

    let (resp_hdr2, _) = gateway_transport2
        .send_request(&conn2, &header2, &wire_payload2)
        .await
        .expect("send QUIC request 2");

    assert_eq!(
        resp_hdr2.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "Multi-lock chain request over QUIC when budget suffices must succeed without FLAG_QUOTA_EXCEEDED"
    );
    assert!(engine.is_hmc_entry_durable(tag1, &L2LockEntry::from(&spend1), root_valid_until).await);
    assert!(engine.is_hmc_entry_durable(tag2, &L2LockEntry::from(&spend2), root_valid_until).await);
}

#[tokio::test]
async fn test_s05_19_canonical_friends_credential_domain_separation_e2e() {
    let (_router, _operator, _storage, _identity, tier_controller, _pow, state) =
        setup_test_app_pair();

    let admin_secret = "admin_secret_s05_19";
    let auth = Arc::new(AdminTokenManager::with_token(admin_secret, false));
    let state = state.with_auth(auth);
    let operator_router = build_operator_router(state.clone());

    let token = "f2f_0123456789abcdef0123456789abcdef";
    assert!(is_valid_client_token(token));

    // 1. Independently compute canonical Friends hash vector (Spec 13 section 3 / AGENTS Rule 5)
    // Layout: BLAKE3( [tag.len() as u8] || tag || token.trim() )
    let domain_tag = b"HUMOCO_V1_FRIENDS_BEARER_TOKEN";
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[domain_tag.len() as u8]);
    hasher.update(domain_tag);
    hasher.update(token.trim().as_bytes());
    let expected_hash_bytes = *hasher.finalize().as_bytes();
    let expected_hash_hex = hex::encode(expected_hash_bytes);

    // Verify it is strictly domain-separated and distinct from bare BLAKE3
    let bare_hash = *blake3::hash(token.as_bytes()).as_bytes();
    assert_ne!(
        expected_hash_bytes, bare_hash,
        "Canonical Friends token hash MUST NOT match bare BLAKE3(token)"
    );

    let now_ms = 1_700_000_000_000u64;

    // 2. Registration and Listing
    tier_controller.register_f2f_client(token, Some("Kasse-S05-19"));
    let clients = tier_controller.list_f2f_clients(now_ms);
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].label, "Kasse-S05-19");
    assert_eq!(
        clients[0].token_hash, expected_hash_hex,
        "Registered client must be listed with canonical domain-separated hash"
    );

    // 3. Quota attribution & rolling EMA usage
    tier_controller
        .evaluate_f2f_quota(token, 150, now_ms)
        .expect("admission under daily quota");
    let clients_after_quota = tier_controller.list_f2f_clients(now_ms);
    assert_eq!(clients_after_quota[0].writes_today, 150);

    // 4. Activity attribution via evaluate_and_charge_with_time
    let charge = StorageCharge::single(31_536_000);
    let charge_res = tier_controller
        .evaluate_and_charge_with_time(
            None,
            Some(token),
            None,
            None,
            charge,
            None,
            Some(now_ms + 5_000),
        )
        .await;
    assert!(
        matches!(charge_res, Ok(IngressTier::Tier2F2F)),
        "Friends token admission must succeed"
    );
    let clients_after_charge = tier_controller.list_f2f_clients(now_ms + 10_000);
    assert_eq!(
        clients_after_charge[0].last_active_sec,
        Some(5),
        "Last active must be recorded on evaluate_and_charge"
    );

    // 5. Revocation by domain-separated hash
    assert!(
        tier_controller.remove_f2f_client(&expected_hash_hex),
        "Removal by canonical domain-separated hash must succeed"
    );
    assert_eq!(
        tier_controller.list_f2f_clients(now_ms).len(),
        0,
        "Client list must be empty after revocation"
    );

    // 6. Private operator HTTP routes: POST and DELETE
    let http_token = "f2f_9876543210abcdef9876543210abcdef";
    let post_req = Request::builder()
        .method("POST")
        .uri("/dashboard/admin/ingress/clients")
        .header("Authorization", format!("Bearer {}", admin_secret))
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "token": http_token,
                "label": "HTTP-Operator-Client"
            }))
            .unwrap(),
        ))
        .unwrap();

    let post_resp = operator_router.clone().oneshot(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::OK);

    // Independently compute hash for http_token
    let mut http_hasher = blake3::Hasher::new();
    http_hasher.update(&[domain_tag.len() as u8]);
    http_hasher.update(domain_tag);
    http_hasher.update(http_token.trim().as_bytes());
    let http_expected_hash_hex = hex::encode(http_hasher.finalize().as_bytes());

    let clients_http = tier_controller.list_f2f_clients(now_ms);
    let registered_op_client = clients_http
        .iter()
        .find(|c| c.label == "HTTP-Operator-Client")
        .expect("registered operator client found in list");
    assert_eq!(
        registered_op_client.token_hash, http_expected_hash_hex,
        "Operator-registered client must have canonical domain-separated hash"
    );

    // Delete client via operator route with canonical token hash
    let del_req = Request::builder()
        .method("DELETE")
        .uri(format!(
            "/dashboard/admin/ingress/clients/{}",
            http_expected_hash_hex
        ))
        .header("Authorization", format!("Bearer {}", admin_secret))
        .body(Body::empty())
        .unwrap();

    let del_resp = operator_router.oneshot(del_req).await.unwrap();
    assert_eq!(del_resp.status(), StatusCode::OK);
    let clients_final = tier_controller.list_f2f_clients(now_ms);
    assert!(
        !clients_final.iter().any(|c| c.label == "HTTP-Operator-Client"),
        "Client must be removed via operator route"
    );
}






