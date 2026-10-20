//! # Phase 4 clock/quota handler integration tests
//! Direct handler calls exercise authentication context and exact wire flags.
//! Real QUIC receiver coverage is maintained in the transport integration suites.
//!
//! Verifies:
//! 1. P2P Network-Adjusted Time (`net_time_ms`):
//!    - F2F median calculation over >= 10 samples
//!    - Skew threshold of 45s before adjustment
//!    - Strict Clamping to +/- 15 minutes (900_000 ms)
//!    - Strict Monotonicity (`net_time = max(net_time, last_seen + 1 ms)`)
//!    - WoT-Gating: Non-F2F samples are strictly rejected
//! 2. Spec 09 Network Thermometer & Dynamic Quotas:
//!    - 28-day slotted ring buffer inertia and daily updates
//!    - Hard floor baseline guarantee (960_000 Byte-Years/day)
//!    - Fast re-seed on network merge and coldstart peer seeding
//!    - Whale brake enforcement (K <= 5.0)

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

use humoco_node::ingress::pow::PowEngine;
use humoco_node::ingress::tier::{IngressError, IngressTier, TierController};
use humoco_node::network::clock::{
    MAX_TIME_OFFSET_CLAMP_MS, NetworkClock,
};
use humoco_node::network::manager::PeerManager;
use humoco_node::storage::RedbStorage;
use humoco_sim_core::quota::ByteYears;

#[test]
fn test_phase4_network_clock_f2f_median_and_wot_gating() {
    let clock = NetworkClock::new();
    let local_base = 1_700_000_000_000u64;

    // 1. WoT-Gating: Reject non-F2F heartbeats
    for i in 0..20 {
        let fake_time = local_base + 60_000 + i;
        let accepted = clock.record_sample(false, fake_time, local_base);
        assert!(!accepted, "Non-F2F heartbeat must be rejected by WoT barrier");
    }
    assert_eq!(clock.sample_count(), 0);
    assert_eq!(clock.logical_offset_ms(), 0);

    // 2. F2F Heartbeats: Collect < 10 samples -> no offset adjustment yet
    for i in 0..9 {
        let peer_time = local_base + 60_000 + (i * 100);
        let accepted = clock.record_sample(true, peer_time, local_base);
        assert!(accepted);
    }
    assert_eq!(clock.sample_count(), 9);
    assert_eq!(clock.current_median_offset(), None);
    assert_eq!(clock.logical_offset_ms(), 0);

    // 3. 10th F2F sample triggers median calculation
    clock.record_sample(true, local_base + 60_000, local_base);
    assert_eq!(clock.sample_count(), 10);
    assert!(clock.current_median_offset().is_some());
    let median = clock.current_median_offset().unwrap();
    assert!(median >= 60_000);

    // Because |median| > 45_000 ms, logical offset must adapt towards target
    assert!(clock.logical_offset_ms() > 0);
    assert!(clock.logical_offset_ms() <= median);
}

#[test]
fn test_phase4_network_clock_clamping_and_monotonicity() {
    let clock = NetworkClock::new();
    let local_base = 1_700_000_000_000u64;

    // Feed extreme clock skew (+5 hours = +18_000_000 ms)
    for _ in 0..25 {
        clock.record_sample(true, local_base + 18_000_000, local_base);
        clock.step_adjustment();
    }

    // Must be clamped to exactly 15 minutes (900_000 ms)
    assert_eq!(clock.logical_offset_ms(), MAX_TIME_OFFSET_CLAMP_MS);
    assert_eq!(clock.logical_offset_ms(), 900_000);

    // Monotonicity: successive calls must never decrease
    let mut prev = clock.net_time_ms();
    for _ in 0..10_000 {
        let cur = clock.net_time_ms();
        assert!(
            cur >= prev,
            "Monotonicity violated: cur ({cur}) < prev ({prev})"
        );
        prev = cur;
    }

    // Rapid queries in tight loop must NOT inflate consensus time
    let start = clock.net_time_ms();
    for _ in 0..20_000 {
        clock.net_time_ms();
    }
    let end = clock.net_time_ms();
    assert!(
        end.saturating_sub(start) < 500,
        "20,000 queries must not inflate time by seconds (was {} ms)",
        end - start
    );

    // Even if local clock jumps backwards drastically (-15 minutes clamp)
    clock.set_offset_for_testing(-900_000);
    let after_backwards = clock.net_time_ms();
    assert!(
        after_backwards >= prev,
        "Monotonicity must survive backwards time jumps"
    );
}

/// Fixture membership is explicit and mature; this is no transfer/activation proof.
async fn admit_mature_local(pm: &humoco_node::network::PeerManager, identity: &humoco_node::identity::NodeIdentity) {
    pm.learn_node_from_gossip_with_hrw(*identity.node_pubkey(), *identity.hrw_routing_id(),
        "127.0.0.1:9999".parse().unwrap(), 0, None).await;
    pm.set_first_seen_for_test(identity.node_pubkey(),
        std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600)).await;
}

fn isolated_ready() -> Arc<humoco_node::daemon::ShardReadinessManager> {
    let ready = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    for shard in 0..=u16::MAX { ready.mark_shard_ready(shard); }
    ready
}

#[tokio::test]
async fn test_phase4_peer_manager_clock_integration() {
    let friend_pubkey = [0x42u8; 32];
    let socket_addr = "127.0.0.1:9099".parse().unwrap();

    let pm = PeerManager::with_f2f(
        vec![(Some(friend_pubkey), socket_addr)],
        vec![friend_pubkey],
    );

    // PeerManager exposes clock and net_time_ms
    let now = pm.net_time_ms();
    assert!(now > 0);

    // Direct F2F check
    assert!(pm.is_f2f_friend(&friend_pubkey).await);

    // Check heartbeat record integration via clock
    let is_friend = pm.is_f2f_friend(&friend_pubkey).await;
    let local_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Heartbeat from friend recorded into clock
    let ok = pm.clock().record_sample(is_friend, local_now + 50_000, local_now);
    assert!(ok);
    assert_eq!(pm.clock().sample_count(), 1);
}

#[tokio::test]
async fn test_phase4_spec_09_slotted_median_and_dynamic_quotas() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("spec09_test.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new([0x33; 32], 8));
    let controller = TierController::new(storage.clone(), pow);

    // 1. Initial State: Hard Floor Baseline
    assert_eq!(controller.effective_ncb(), 960_000);

    // 2. Kaltstart Seed from Peers
    controller.seed_from_peers(3_000_000);
    assert_eq!(controller.effective_ncb(), 3_000_000);

    // 3. Fast Re-Seed on Merge
    controller.fast_reseed_on_merge(12_000_000);
    assert_eq!(controller.effective_ncb(), 12_000_000);

    // 4. Whale Brake: K=1.0 vs K=5.0 vs K=8.0 (clamped)
    let quota_standard = controller.calculate_daily_quota(1.0, 1.0);
    assert_eq!(quota_standard, 12_000_000);

    let quota_k5 = controller.calculate_daily_quota(5.0, 1.0);
    assert_eq!(quota_k5, 12_000_000 * 5);

    let quota_clamped = controller.calculate_daily_quota(8.0, 1.0);
    assert_eq!(quota_clamped, 12_000_000 * 5);

    // 5. Dynamic Quota Enforcement in TierController
    let peer_token = "friend_cluster_token_99";
    controller.register_f2f_peer(peer_token);

    // F2F Access via evaluate_and_charge within budget
    let access = controller
        .evaluate_and_charge(None, Some(peer_token), None, None, 86_400, None)
        .await;
    assert!(access.is_ok());
    assert_eq!(access.unwrap(), IngressTier::Tier2F2F);

    // Exceeding remaining budget (budget is 12_000_000)
    let huge_ttl_seconds = 100 * 31_536_000; // 100 years = 19_200 byte-years
    let huge_by = ByteYears::from_ttl_seconds(huge_ttl_seconds);
    let exceed_res = controller.evaluate_f2f_quota(peer_token, huge_by * 1000, controller.current_epoch_day()); // 19_200_000 > 12_000_000
    assert!(matches!(exceed_res, Err(IngressError::QuotaExceeded { .. })));
}

#[tokio::test]
async fn test_phase4_wire_level_quota_rejection_and_3zone_plausibility() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{NodeRequestHandler, RequestHandler};
    use humoco_node::storage::DualTierEngine;
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_QUOTA_EXCEEDED};

    let temp = tempdir().unwrap();
    let db_path = temp.path().join("wire_quota.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _drain) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(PowEngine::new([0x44; 32], 8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow));

    // NCB_eff hard floor is 960_000, 5.0 * 960_000 = 4_800_000
    let identity_shard = NodeIdentity::generate();
    let identity_client = NodeIdentity::generate();

    let pm_shard = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_client.node_pubkey()],
    ));
    pm_shard.learn_node_from_gossip(*identity_client.node_pubkey(), "127.0.0.1:9001".parse().unwrap(), 0, None).await;

    admit_mature_local(&pm_shard, &identity_shard).await;
    let handler_shard = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            identity_shard.clone(),
            pm_shard.clone(),
        )
        .with_tier_controller(tier_controller.clone()).with_readiness_manager(isolated_ready()),
    );

    // 1. Send LockVerifyRequest with declared write load exceeding 5.0 * ncb_eff
    let declared_write_ema = 15_000_000_000_000u64; // >> 4_800_000 daily rate
    let hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_client.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "test_voucher".into(),
        ds_tag: None,
        transaction_hash: [1; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_client.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let hmc_payload = bincode::serialize(&humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req,
        chain: None,
        root_valid_until: 86_400_000,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: declared_write_ema,
        declared_write_ema_micro_bj: declared_write_ema,
        declared_read_ema_credits: 0,
        sender_pubkey: *identity_client.node_pubkey(),
        sender_signature: [0; 64],
        timestamp_ms: 1000,
    }).unwrap();

    let req_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        hmc_payload.len() as u32,
    );

    let (resp_header, resp_payload) = handler_shard.handle_authenticated(req_header, hmc_payload, Some(*identity_client.node_pubkey())).await.expect("handle");
    assert_eq!(resp_header.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(resp_header.flags & FLAG_QUOTA_EXCEEDED, FLAG_QUOTA_EXCEEDED, "Shard must return FLAG_QUOTA_EXCEEDED when write load > 5x limit");
    assert!(resp_payload.is_empty(), "Payload must be empty on quota rejection");

    // 2. StatusQuery exceeding read limit (5.0 * 50_000 = 250_000)
    let status_query = humoco_node::network::framing::StatusQueryPayload {
        lock_id: [0x77; 32],
        parent_lock: [0x88; 32],
        shard_id: 42,
        sender_pubkey: *identity_client.node_pubkey(),
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: 500_000, // declared daily rate = 500_000 * 0.693 = 346_573 > 250_000
        timestamp_ms: 1000,
        sender_signature: [0; 64],
    };
    let status_payload = bincode::serialize(&status_query).unwrap();
    let status_req_header = WireHeader::new(
        MsgType::StatusQuery as u16,
        2,
        0,
        0,
        status_payload.len() as u32,
    );
    let (status_resp_header, status_resp_payload) = handler_shard.handle_authenticated(status_req_header, status_payload, Some(*identity_client.node_pubkey())).await.expect("handle status query");
    assert_eq!(status_resp_header.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(status_resp_header.flags & FLAG_QUOTA_EXCEEDED, FLAG_QUOTA_EXCEEDED, "Shard must return FLAG_QUOTA_EXCEEDED when read load > 5x limit");
    assert!(status_resp_payload.is_empty(), "Payload must be empty on read quota rejection");

    // 3. 3-Zone Plausibility Check verification
    let quota_limit = 4_800_000u64;
    // Zone 1: My load is 2_000_000 (< 75% = 3_600_000). Shard claimed QuotaExceeded -> Fraud / Malice!
    let v_zone1 = humoco_sim_core::quota::evaluate_quota_exceeded_claim(2_000_000, quota_limit);
    assert!(matches!(v_zone1, humoco_sim_core::quota::QuotaPlausibilityVerdict::FraudulentRejection { .. }));

    // Zone 2: My load is 4_000_000 (between 75% and 125%). Honest frontrunner -> No penalty
    let v_zone2 = humoco_sim_core::quota::evaluate_quota_exceeded_claim(4_000_000, quota_limit);
    assert!(matches!(v_zone2, humoco_sim_core::quota::QuotaPlausibilityVerdict::BoundaryCutoff { .. }));

    // Zone 3: My load is 7_000_000 (> 125%). Legitimate overload -> No penalty
    let v_zone3 = humoco_sim_core::quota::evaluate_quota_exceeded_claim(7_000_000, quota_limit);
    assert!(matches!(v_zone3, humoco_sim_core::quota::QuotaPlausibilityVerdict::LegitimateOverload { .. }));
}

#[tokio::test]
async fn test_phase4_under_reporting_fraud_detection_and_gossip_slashing() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{NodeRequestHandler, RequestHandler, PeerManager};
    use humoco_node::storage::{DualTierEngine, RedbStorage};
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_QUOTA_EXCEEDED, FLAG_PEER_SUSPENDED, FLAG_QUOTA_FRAUD};
    use ed25519_dalek::Signer;

    let temp = tempdir().unwrap();
    let db_path = temp.path().join("fraud_test.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _drain) = DualTierEngine::new(storage.clone());

    let identity_shard = NodeIdentity::generate();
    let identity_client = NodeIdentity::generate();

    let pm_shard = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_client.node_pubkey()],
    ));
    pm_shard.learn_node_from_gossip(*identity_client.node_pubkey(), "127.0.0.1:9001".parse().unwrap(), 0, None).await;

    admit_mature_local(&pm_shard, &identity_shard).await;
    let handler_shard = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            identity_shard.clone(),
            pm_shard.clone(),
        ).with_readiness_manager(isolated_ready()),
    );

    // 1. Initial Heartbeat anchors write EMA at 10_000_000 (epoch-bound, 30s freshness)
    let t1 = pm_shard.net_time_ms();
    let initial_write_ema = 10_000_000u64;
    let digest1 = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        identity_client.node_pubkey(),
        0,
        0,
        t1,
        initial_write_ema,
        1000,
        0,
        false,
        &[0u8; 32],
    );
    let sig1 = identity_client.signing_key().sign(&digest1).to_bytes();
    let hb_wire = humoco_node::network::framing::HeartbeatWirePayload {
        node_id: *identity_client.node_pubkey(),
        addr: "127.0.0.1:9001".parse().unwrap(),
        timestamp_ms: t1,
        declared_write_ema_micro_bj: initial_write_ema,
        declared_read_ema_credits: 1000,
        signature: sig1,
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *identity_client.node_pubkey(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    let hb_payload = bincode::serialize(&hb_wire).unwrap();
    let hb_hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, hb_payload.len() as u32);
    handler_shard.handle_unidirectional_authenticated(hb_hdr, hb_payload, Some(*identity_client.node_pubkey())).await.expect("handle hb");

    // Verify evidence anchored in KnownNodeInfo
    let ev = pm_shard.get_node_write_evidence(identity_client.node_pubkey()).await;
    assert!(ev.is_some(), "Evidence must be recorded from heartbeat");
    assert_eq!(ev.unwrap().declared_write_ema_micro_bj, initial_write_ema);

    // 2. Under-reporting attack:
    // Client sends LockVerifyRequest shortly after (delta ~ 10ms ~ 0s).
    // Decayed threshold is ~ 10_000_000 + footprint.
    // Client falsely reports declared_write_ema = 1_000_000 (< threshold)!
    let t2 = t1 + 10;
    let fraudulent_write_ema = 1_000_000u64;
    let hmc_req = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_client.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "fraud_voucher".into(),
        ds_tag: None,
        transaction_hash: [2; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_client.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let entry = humoco_node::api::hmc::L2LockEntry::from(&hmc_req);
    let root_valid_until = t2 + 86_400_000;
    let ttl_s = 86_400;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let digest2 = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        identity_client.node_pubkey(),
        0,
        0,
        t2,
        fraudulent_write_ema,
        0,
        footprint,
        false,
        &entry.t_id,
    );
    let sig2 = identity_client.signing_key().sign(&digest2).to_bytes();

    let lock_wire = humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req,
        chain: None,
        root_valid_until,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: fraudulent_write_ema,
        declared_write_ema_micro_bj: fraudulent_write_ema,
        declared_read_ema_credits: 0,
        sender_pubkey: *identity_client.node_pubkey(),
        sender_signature: sig2,
        timestamp_ms: t2,
    };
    let lock_payload = bincode::serialize(&lock_wire).unwrap();
    let lock_hdr = WireHeader::new(MsgType::LockVerifyRequest as u16, 2, 0, 0, lock_payload.len() as u32);

    let (resp_hdr, _) = handler_shard.handle_authenticated(lock_hdr, lock_payload, Some(*identity_client.node_pubkey())).await.expect("handle lock");
    assert_eq!(resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);
    let expected_flags = FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD;
    assert_eq!(resp_hdr.flags & expected_flags, expected_flags, "Must return FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD");

    // 3. Perpetrator must now be banned locally in both engine and peer manager!
    assert!(engine.is_node_banned(identity_client.node_pubkey()).await, "Engine must ban fraudster");
    assert!(pm_shard.is_banned(identity_client.node_pubkey()).await, "PeerManager must ban fraudster");
}

#[tokio::test]
async fn test_phase4_piggyback_heartbeat_cross_shard_silo_defense() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{NodeRequestHandler, RequestHandler, PeerManager};
    use humoco_node::storage::{DualTierEngine, RedbStorage};
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_QUOTA_EXCEEDED, FLAG_PEER_SUSPENDED, FLAG_QUOTA_FRAUD};
    use ed25519_dalek::Signer;

    let temp_a = tempdir().unwrap();
    let db_path_a = temp_a.path().join("shard_a.redb");
    let storage_a = Arc::new(RedbStorage::open(&db_path_a).unwrap());
    let (engine_a, _drain_a) = DualTierEngine::new(storage_a.clone());

    let temp_b = tempdir().unwrap();
    let db_path_b = temp_b.path().join("shard_b.redb");
    let storage_b = Arc::new(RedbStorage::open(&db_path_b).unwrap());
    let (engine_b, _drain_b) = DualTierEngine::new(storage_b.clone());

    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let identity_g = NodeIdentity::generate();

    // Node A setup
    let pm_a = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_g.node_pubkey()],
    ));
    pm_a.learn_node_from_gossip(*identity_g.node_pubkey(), "127.0.0.1:9001".parse().unwrap(), 0, None).await;
    admit_mature_local(&pm_a, &identity_a).await;
    let handler_a = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_a.clone(),
            storage_a.clone(),
            identity_a.clone(),
            pm_a.clone(),
        ).with_readiness_manager(isolated_ready()),
    );

    // Node B setup with fraud proof listener
    let (fraud_tx, mut fraud_rx) = tokio::sync::mpsc::channel(16);
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_pubkey()],
    ));
    pm_b.set_fraud_proof_tx(fraud_tx).await;
    pm_b.learn_node_from_gossip(*identity_a.node_pubkey(), "127.0.0.1:9002".parse().unwrap(), 0, None).await;
    admit_mature_local(&pm_b, &identity_b).await;
    let handler_b = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_b.clone(),
            storage_b.clone(),
            identity_b.clone(),
            pm_b.clone(),
        ).with_readiness_manager(isolated_ready()),
    );

    // 1. Gateway G interacts with Shard Node A with high load (10_000_000 micro BJ)
    let t1 = pm_a.net_time_ms();
    let high_write_ema = 10_000_000u64;
    let hmc_req_a = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_g.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "voucher_high_load".into(),
        ds_tag: None,
        transaction_hash: [10; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_g.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let entry_a = humoco_node::api::hmc::L2LockEntry::from(&hmc_req_a);
    let root_valid_until_a = t1 + 86_400_000;
    let ttl_s = 86_400;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let digest_a = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        identity_g.node_pubkey(),
        0,
        0,
        t1,
        high_write_ema,
        0,
        footprint,
        false,
        &entry_a.t_id,
    );
    let sig_a = identity_g.signing_key().sign(&digest_a).to_bytes();
    let lock_wire_a = humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req_a,
        chain: None,
        root_valid_until: root_valid_until_a,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: high_write_ema,
        declared_write_ema_micro_bj: high_write_ema,
        declared_read_ema_credits: 0,
        sender_pubkey: *identity_g.node_pubkey(),
        sender_signature: sig_a,
        timestamp_ms: t1,
    };
    let lock_payload_a = bincode::serialize(&lock_wire_a).unwrap();
    let lock_hdr_a = WireHeader::new(MsgType::LockVerifyRequest as u16, 1, 0, 0, lock_payload_a.len() as u32);
    let (resp_hdr_a, _) = handler_a.handle_authenticated(lock_hdr_a, lock_payload_a, Some(*identity_g.node_pubkey())).await.expect("handle lock A");
    assert_eq!(resp_hdr_a.msg_type, MsgType::LockVerifyResponse as u16);

    // Node A records evidence and samples it
    let sampled = pm_a.sample_piggyback_evidences(2).await;
    assert_eq!(sampled.len(), 1, "Node A must have recorded 1 observed evidence");
    assert_eq!(sampled[0].gateway_pubkey, *identity_g.node_pubkey());
    assert_eq!(sampled[0].declared_write_ema_micro_bj, high_write_ema);

    // 2. Shard Node A sends Heartbeat with piggyback_observations to Node B
    let hb_wire = humoco_node::network::framing::HeartbeatWirePayload {
        node_id: *identity_a.node_pubkey(),
        addr: "127.0.0.1:9002".parse().unwrap(),
        timestamp_ms: t1 + 5,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0; 64],
        supported_suites_mask: 0,
        piggyback_observations: sampled,
        pow_nonce: 0,
        hrw_routing_id: *identity_a.node_pubkey(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    let hb_payload = bincode::serialize(&hb_wire).unwrap();
    let hb_hdr = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, hb_payload.len() as u32);
    handler_b.handle_unidirectional_authenticated(hb_hdr, hb_payload, Some(*identity_a.node_pubkey())).await.expect("handle hb at B");

    // Node B receives the Heartbeat, verifies piggyback, and stores in KnownNodeInfo
    let ev_at_b = pm_b.get_node_write_evidence(identity_g.node_pubkey()).await;
    assert!(ev_at_b.is_some(), "Node B must store piggybacked evidence in KnownNodeInfo");
    assert_eq!(ev_at_b.unwrap().declared_write_ema_micro_bj, high_write_ema);

    // 3. Gateway G subsequently tries to submit a Lock to Node B claiming low load (100_000 micro BJ)
    let t2 = t1 + 10;
    let fraudulent_low_ema = 100_000u64;
    let hmc_req_b = humoco_node::api::hmc::L2LockRequest {
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_g.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "voucher_low_load".into(),
        ds_tag: None,
        transaction_hash: [20; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_g.node_pubkey(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let entry_b = humoco_node::api::hmc::L2LockEntry::from(&hmc_req_b);
    let root_valid_until_b = t2 + 86_400_000;
    let digest_b = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        identity_g.node_pubkey(),
        0,
        0,
        t2,
        fraudulent_low_ema,
        0,
        footprint,
        false,
        &entry_b.t_id,
    );
    let sig_b = identity_g.signing_key().sign(&digest_b).to_bytes();
    let lock_wire_b = humoco_node::network::framing::LockWirePayload::Hmc {
        req: hmc_req_b,
        chain: None,
        root_valid_until: root_valid_until_b,
        epoch_day: 0,
        epoch_seq: 0,
        cumulative_micro_byte_years: 0,
        prev_day_final_bytes: 0,
        current_anl_24h: fraudulent_low_ema,
        declared_write_ema_micro_bj: fraudulent_low_ema,
        declared_read_ema_credits: 0,
        sender_pubkey: *identity_g.node_pubkey(),
        sender_signature: sig_b,
        timestamp_ms: t2,
    };
    let lock_payload_b = bincode::serialize(&lock_wire_b).unwrap();
    let lock_hdr_b = WireHeader::new(MsgType::LockVerifyRequest as u16, 3, 0, 0, lock_payload_b.len() as u32);
    let (resp_hdr_b, _) = handler_b.handle_authenticated(lock_hdr_b, lock_payload_b, Some(*identity_g.node_pubkey())).await.expect("handle lock B");

    // Node B detects under-reporting against piggybacked evidence and rejects with FLAG_QUOTA_FRAUD
    assert_eq!(resp_hdr_b.msg_type, MsgType::LockVerifyResponse as u16);
    let expected_flags = FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD;
    assert_eq!(
        resp_hdr_b.flags & expected_flags,
        expected_flags,
        "Node B must reject with FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD"
    );

    // 4. Node B bans Gateway G in engine and peer manager
    assert!(engine_b.is_node_banned(identity_g.node_pubkey()).await, "Engine B must ban Gateway G");
    assert!(pm_b.is_banned(identity_g.node_pubkey()).await, "PeerManager B must ban Gateway G");

    // 5. Fraud proof was broadcast (Phase 10: channel carries (proof, sender))
    let (broadcasted_proof, _sender) = fraud_rx.try_recv().expect("Fraud proof must be broadcast");
    assert_eq!(broadcasted_proof.perpetrator_node_id, *identity_g.node_pubkey());
    assert!(broadcasted_proof.verify(), "Broadcasted proof must be cryptographically valid");
}

