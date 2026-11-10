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
use humoco_node::ingress::tier::{IngressError, IngressTier, StorageCharge, TierController};
use humoco_node::network::clock::{NetworkClock, MAX_TIME_OFFSET_CLAMP_MS};
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
        assert!(
            !accepted,
            "Non-F2F heartbeat must be rejected by WoT barrier"
        );
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
async fn admit_mature_local(
    pm: &humoco_node::network::PeerManager,
    identity: &humoco_node::identity::NodeIdentity,
) {
    pm.set_simulation_mode(true);
    pm.learn_node_from_gossip_with_hrw(
        *identity.node_pubkey(),
        *identity.hrw_routing_id(),
        "127.0.0.1:9999".parse().unwrap(),
        0,
        None,
    )
    .await;
    pm.set_first_seen_for_test(
        identity.node_pubkey(),
        std::time::Instant::now() - std::time::Duration::from_secs(25 * 3600),
    )
    .await;
}

fn isolated_ready() -> Arc<humoco_node::daemon::ShardReadinessManager> {
    let ready = Arc::new(humoco_node::daemon::ShardReadinessManager::new());
    for shard in 0..=u16::MAX {
        ready.mark_shard_ready(shard);
    }
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
    let ok = pm
        .clock()
        .record_sample(is_friend, local_now + 50_000, local_now);
    assert!(ok);
    assert_eq!(pm.clock().sample_count(), 1);
}

#[tokio::test]
async fn test_phase4_spec_09_slotted_median_and_dynamic_quotas() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("spec09_test.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let pow = Arc::new(PowEngine::new(8));
    let controller = TierController::new(storage.clone(), pow);

    // 1. Initial State: Hard Floor Baseline
    assert_eq!(controller.effective_ncb(), 960_000);

    // 2. Kaltstart Seed from Peers
    controller.seed_from_peers(3_000_000);
    assert_eq!(controller.effective_ncb(), 3_000_000);

    // 3. Fast Re-Seed on Merge
    controller.fast_reseed_on_merge(Some(12_000_000), None);
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
        .evaluate_and_charge(
            None,
            Some(peer_token),
            None,
            None,
            StorageCharge::single(86_400),
            None,
        )
        .await;
    assert!(access.is_ok());
    assert_eq!(access.unwrap(), IngressTier::Tier2F2F);

    // Exceeding remaining budget (budget is 12_000_000)
    let huge_ttl_seconds = 100 * 31_536_000; // 100 years = 19_200 byte-years
    let huge_by = ByteYears::from_ttl_seconds(huge_ttl_seconds);
    let exceed_res =
        controller.evaluate_f2f_quota(peer_token, huge_by * 1000, controller.now_ms()); // 19_200_000 > 12_000_000
    assert!(matches!(
        exceed_res,
        Err(IngressError::QuotaExceeded { .. })
    ));
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
    let pow = Arc::new(PowEngine::new(8));
    let tier_controller = Arc::new(TierController::new(storage.clone(), pow));

    // NCB_eff hard floor is 960_000, 5.0 * 960_000 = 4_800_000
    let identity_shard = NodeIdentity::generate();
    let identity_client = NodeIdentity::generate();

    let pm_shard = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_client.node_pubkey()],
    ));
    pm_shard
        .learn_node_from_gossip(
            *identity_client.node_pubkey(),
            "127.0.0.1:9001".parse().unwrap(),
            0,
            None,
        )
        .await;

    admit_mature_local(&pm_shard, &identity_shard).await;
    let handler_shard = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            identity_shard.clone(),
            pm_shard.clone(),
        )
        .with_tier_controller(tier_controller.clone())
        .with_readiness_manager(isolated_ready()),
    );

    // 1. Send LockVerifyRequest with declared write load exceeding 5.0 * ncb_eff
    let declared_write_ema = 15_000_000_000_000u64; // >> 4_800_000 daily rate
    let hmc_req = humoco_node::api::hmc::L2LockRequest {
        causal_output: None,
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_client.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "test_voucher".into(),
        ds_tag: None,
        transaction_hash: [1; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_client.node_pubkey(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
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
    })
    .unwrap();

    let req_header = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        hmc_payload.len() as u32,
    );

    let (resp_header, resp_payload) = handler_shard
        .handle_authenticated(
            req_header,
            hmc_payload,
            Some(*identity_client.node_pubkey()),
        )
        .await
        .expect("handle");
    assert_eq!(resp_header.msg_type, MsgType::LockVerifyResponse as u16);
    assert_eq!(
        resp_header.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "Shard must return FLAG_QUOTA_EXCEEDED when write load > 5x limit"
    );
    assert!(
        resp_payload.is_empty(),
        "Payload must be empty on quota rejection"
    );

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
    let (status_resp_header, status_resp_payload) = handler_shard
        .handle_authenticated(
            status_req_header,
            status_payload,
            Some(*identity_client.node_pubkey()),
        )
        .await
        .expect("handle status query");
    assert_eq!(status_resp_header.msg_type, MsgType::StatusResponse as u16);
    assert_eq!(
        status_resp_header.flags & FLAG_QUOTA_EXCEEDED,
        FLAG_QUOTA_EXCEEDED,
        "Shard must return FLAG_QUOTA_EXCEEDED when read load > 5x limit"
    );
    assert!(
        status_resp_payload.is_empty(),
        "Payload must be empty on read quota rejection"
    );

    // 3. 3-Zone Plausibility Check verification
    let quota_limit = 4_800_000u64;
    // Zone 1: My load is 2_000_000 (< 75% = 3_600_000). Shard claimed QuotaExceeded -> EarlyRefusal
    let v_zone1 = humoco_sim_core::quota::evaluate_quota_exceeded_claim(2_000_000, quota_limit);
    assert_eq!(
        v_zone1,
        humoco_sim_core::quota::QuotaPlausibilityVerdict::EarlyRefusal
    );

    // Zone 2: My load is 4_000_000 (between 75% and 125%). Honest frontrunner -> BoundaryCutoff
    let v_zone2 = humoco_sim_core::quota::evaluate_quota_exceeded_claim(4_000_000, quota_limit);
    assert_eq!(
        v_zone2,
        humoco_sim_core::quota::QuotaPlausibilityVerdict::BoundaryCutoff
    );

    // Zone 3: My load is 7_000_000 (> 125%). Legitimate overload -> OverloadIndication
    let v_zone3 = humoco_sim_core::quota::evaluate_quota_exceeded_claim(7_000_000, quota_limit);
    assert_eq!(
        v_zone3,
        humoco_sim_core::quota::QuotaPlausibilityVerdict::OverloadIndication
    );
}

#[tokio::test]
async fn test_phase4_adversarial_5x_whale_limit_flooding() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{NodeRequestHandler, RequestHandler};
    use humoco_node::DualTierEngine;
    use humoco_sim_core::wire::{MsgType, FLAG_QUOTA_EXCEEDED};

    let temp = tempdir().unwrap();
    let db_path = temp.path().join("adversarial_whale.redb");
    let storage = Arc::new(RedbStorage::open(&db_path).unwrap());
    let (engine, _drain) = DualTierEngine::new(storage.clone());
    let pow = Arc::new(humoco_node::ingress::pow::PowEngine::new(8));
    let tier_controller = Arc::new(humoco_node::ingress::tier::TierController::new(
        storage.clone(),
        pow,
    ));

    let identity_shard = NodeIdentity::generate();
    let identity_client = NodeIdentity::generate();

    let pm_shard = Arc::new(humoco_node::network::manager::PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_client.node_pubkey()],
    ));
    pm_shard
        .learn_node_from_gossip(
            *identity_client.node_pubkey(),
            "127.0.0.1:9001".parse().unwrap(),
            0,
            None,
        )
        .await;

    admit_mature_local(&pm_shard, &identity_shard).await;
    let handler_shard = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            identity_shard.clone(),
            pm_shard.clone(),
        )
        .with_tier_controller(tier_controller.clone())
        .with_readiness_manager(isolated_ready()),
    );

    // The hard floor NCB_eff is 960_000, so 5.0 * 960_000 = 4_800_000 is the 5x whale brake
    let _quota_limit = 4_800_000u64;

    // Flood the shard with LockVerifyRequests having extremely high declared write EMA,
    // far exceeding the 5x whale brake limit. Each request should be rejected with FLAG_QUOTA_EXCEEDED.
    for attempt in 0..10u32 {
        // Use EMA value that guarantees daily rate > 5.0 * ncb_eff (4.8M).
        // From quota.rs: Rate = (EMA * 693_147) / 1_000_000, then / 1_000_000 for daily rate.
        // For daily_rate > 4_800_000: need EMA > ~3.5 * 10^15
        let extremely_high_ema = 50_000_000_000_000u64; // 50 trillion µBJ → daily rate >> 4.8M

        let hmc_req = humoco_node::api::hmc::L2LockRequest {
            causal_output: None,
            auth: humoco_node::api::hmc::L2AuthPayload {
                ephemeral_pubkey: *identity_client.node_pubkey(),
                auth_signature: None,
            },
            layer2_voucher_id: "test_voucher_flood".into(),
            ds_tag: None,
            transaction_hash: [1; 32],
            is_genesis: true,
            sender_ephemeral_pub: *identity_client.node_pubkey(),
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            deletable_at: None,
            privacy_guard: None,
        };

        let hmc_payload =
            bincode::serialize(&humoco_node::network::framing::LockWirePayload::Hmc {
                req: hmc_req,
                chain: None,
                root_valid_until: 86_400_000,
                epoch_day: 0,
                epoch_seq: 0,
                cumulative_micro_byte_years: 0,
                prev_day_final_bytes: 0,
                current_anl_24h: extremely_high_ema,
                declared_write_ema_micro_bj: extremely_high_ema,
                declared_read_ema_credits: 0,
                sender_pubkey: *identity_client.node_pubkey(),
                sender_signature: [0; 64],
                timestamp_ms: 1000,
            })
            .unwrap();

        let req_header = humoco_sim_core::WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            0,
            0,
            hmc_payload.len() as u32,
        );

        let (resp_header, resp_payload) = handler_shard
            .handle_authenticated(
                req_header,
                hmc_payload,
                Some(*identity_client.node_pubkey()),
            )
            .await
            .expect("handle");

        assert_eq!(
            resp_header.msg_type,
            MsgType::LockVerifyResponse as u16,
            "Attempt {}: expected LockVerifyResponse",
            attempt
        );
        assert_eq!(
            resp_header.flags & FLAG_QUOTA_EXCEEDED,
            FLAG_QUOTA_EXCEEDED,
            "Attempt {}: shard must return FLAG_QUOTA_EXCEEDED when write load far exceeds 5x whale brake", attempt
        );
        assert!(
            resp_payload.is_empty(),
            "Attempt {}: payload must be empty on quota rejection",
            attempt
        );
    }
}

#[tokio::test]
async fn test_phase4_under_reporting_fraud_detection_and_gossip_slashing() {
    use ed25519_dalek::Signer;
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{NodeRequestHandler, PeerManager, RequestHandler};
    use humoco_node::storage::{DualTierEngine, RedbStorage};
    use humoco_sim_core::wire::{
        MsgType, WireHeader, FLAG_PEER_SUSPENDED, FLAG_QUOTA_EXCEEDED, FLAG_QUOTA_FRAUD,
    };

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
    pm_shard
        .learn_node_from_gossip(
            *identity_client.node_pubkey(),
            "127.0.0.1:9001".parse().unwrap(),
            0,
            None,
        )
        .await;

    admit_mature_local(&pm_shard, &identity_shard).await;
    let handler_shard = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            identity_shard.clone(),
            pm_shard.clone(),
        )
        .with_readiness_manager(isolated_ready()),
    );

    // 1. Initial Heartbeat anchors write EMA at 10_000_000 (epoch-bound, 30s freshness)
    let t1 = pm_shard.net_time_ms();
    let initial_write_ema = 10_000_000u64;
    let mut hb_wire = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *identity_client.node_pubkey(),
        addr: "127.0.0.1:9001".parse().unwrap(),
        timestamp_ms: t1,
        declared_write_ema_micro_bj: initial_write_ema,
        declared_read_ema_credits: 1000,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *identity_client.node_pubkey(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_wire.sign_origin(&identity_client, t1, humoco_sim_core::types::NetworkId::default());
    let hb_payload = bincode::serialize(&hb_wire).unwrap();
    let hb_hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, hb_payload.len() as u32);
    handler_shard
        .handle_unidirectional_authenticated(
            hb_hdr,
            hb_payload,
            Some(*identity_client.node_pubkey()),
        )
        .await
        .expect("handle hb");

    // Verify evidence anchored in KnownNodeInfo
    let ev = pm_shard
        .get_node_write_evidence(identity_client.node_pubkey())
        .await;
    assert!(ev.is_some(), "Evidence must be recorded from heartbeat");
    assert_eq!(ev.unwrap().declared_write_ema_micro_bj, initial_write_ema);

    // 2. Under-reporting attack:
    // Client sends LockVerifyRequest shortly after (delta ~ 10ms ~ 0s).
    // Decayed threshold is ~ 10_000_000 + footprint.
    // Client falsely reports declared_write_ema = 1_000_000 (< threshold)!
    let t2 = t1 + 10;
    let fraudulent_write_ema = 1_000_000u64;
    let hmc_req = humoco_node::api::hmc::L2LockRequest {
        causal_output: None,
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_client.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "fraud_voucher".into(),
        ds_tag: None,
        transaction_hash: [2; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_client.node_pubkey(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        deletable_at: None,
        privacy_guard: None,
    };
    let entry = humoco_node::api::hmc::L2LockEntry::from(&hmc_req);
    let root_valid_until = t2 + 86_400_000;
    let ttl_s = 86_400;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let digest2 = humoco_sim_core::fraud::compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::Mainnet,
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
    let lock_hdr = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        2,
        0,
        0,
        lock_payload.len() as u32,
    );

    let (resp_hdr, _) = handler_shard
        .handle_authenticated(lock_hdr, lock_payload, Some(*identity_client.node_pubkey()))
        .await
        .expect("handle lock");
    assert_eq!(resp_hdr.msg_type, MsgType::LockVerifyResponse as u16);
    let expected_flags = FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD;
    assert_eq!(
        resp_hdr.flags & expected_flags,
        expected_flags,
        "Must return FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD"
    );

    // 3. Perpetrator must now be banned locally in both engine and peer manager!
    assert!(
        engine.is_node_banned(identity_client.node_pubkey()).await,
        "Engine must ban fraudster"
    );
    assert!(
        pm_shard.is_banned(identity_client.node_pubkey()).await,
        "PeerManager must ban fraudster"
    );
}

#[tokio::test]
async fn test_phase4_piggyback_heartbeat_cross_shard_silo_defense() {
    use ed25519_dalek::Signer;
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{NodeRequestHandler, PeerManager, RequestHandler};
    use humoco_node::storage::{DualTierEngine, RedbStorage};
    use humoco_sim_core::wire::{
        MsgType, WireHeader, FLAG_PEER_SUSPENDED, FLAG_QUOTA_EXCEEDED, FLAG_QUOTA_FRAUD,
    };

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
    pm_a.learn_node_from_gossip(
        *identity_g.node_pubkey(),
        "127.0.0.1:9001".parse().unwrap(),
        0,
        None,
    )
    .await;
    admit_mature_local(&pm_a, &identity_a).await;
    let handler_a = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_a.clone(),
            storage_a.clone(),
            identity_a.clone(),
            pm_a.clone(),
        )
        .with_readiness_manager(isolated_ready()),
    );

    // Node B setup with fraud proof listener
    let (fraud_tx, mut fraud_rx) = tokio::sync::mpsc::channel(16);
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*identity_a.node_pubkey()],
    ));
    pm_b.set_fraud_proof_tx(fraud_tx).await;
    pm_b.learn_node_from_gossip(
        *identity_a.node_pubkey(),
        "127.0.0.1:9002".parse().unwrap(),
        0,
        None,
    )
    .await;
    admit_mature_local(&pm_b, &identity_b).await;
    let handler_b = Arc::new(
        NodeRequestHandler::with_peer_manager(
            engine_b.clone(),
            storage_b.clone(),
            identity_b.clone(),
            pm_b.clone(),
        )
        .with_readiness_manager(isolated_ready()),
    );

    // 1. Gateway G interacts with Shard Node A with high load (10_000_000 micro BJ)
    let t1 = pm_a.net_time_ms();
    let high_write_ema = 10_000_000u64;
    let hmc_req_a = humoco_node::api::hmc::L2LockRequest {
        causal_output: None,
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_g.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "voucher_high_load".into(),
        ds_tag: None,
        transaction_hash: [10; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_g.node_pubkey(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        deletable_at: None,
        privacy_guard: None,
    };
    let entry_a = humoco_node::api::hmc::L2LockEntry::from(&hmc_req_a);
    let root_valid_until_a = t1 + 86_400_000;
    let ttl_s = 86_400;
    let footprint = humoco_sim_core::quota::ByteYears::micro_from_ttl_seconds(ttl_s);
    let digest_a = humoco_sim_core::fraud::compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::Mainnet,
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
    let lock_hdr_a = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        1,
        0,
        0,
        lock_payload_a.len() as u32,
    );
    let (resp_hdr_a, _) = handler_a
        .handle_authenticated(lock_hdr_a, lock_payload_a, Some(*identity_g.node_pubkey()))
        .await
        .expect("handle lock A");
    assert_eq!(resp_hdr_a.msg_type, MsgType::LockVerifyResponse as u16);

    // Node A records evidence and samples it
    let sampled = pm_a.sample_piggyback_evidences(2).await;
    assert_eq!(
        sampled.len(),
        1,
        "Node A must have recorded 1 observed evidence"
    );
    assert_eq!(sampled[0].gateway_pubkey, *identity_g.node_pubkey());
    assert_eq!(sampled[0].declared_write_ema_micro_bj, high_write_ema);

    // 2. Shard Node A sends Heartbeat with piggyback_observations to Node B
    let mut hb_wire = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
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
    hb_wire.sign_origin(&identity_a, t1 + 5, humoco_sim_core::types::NetworkId::Mainnet);
    let hb_payload = bincode::serialize(&hb_wire).unwrap();
    let hb_hdr = WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, hb_payload.len() as u32);
    handler_b
        .handle_unidirectional_authenticated(hb_hdr, hb_payload, Some(*identity_a.node_pubkey()))
        .await
        .expect("handle hb at B");

    // Node B receives the Heartbeat, verifies piggyback, and stores in KnownNodeInfo
    let ev_at_b = pm_b.get_node_write_evidence(identity_g.node_pubkey()).await;
    assert!(
        ev_at_b.is_some(),
        "Node B must store piggybacked evidence in KnownNodeInfo"
    );
    assert_eq!(ev_at_b.unwrap().declared_write_ema_micro_bj, high_write_ema);

    // 3. Gateway G subsequently tries to submit a Lock to Node B claiming low load (100_000 micro BJ)
    let t2 = t1 + 10;
    let fraudulent_low_ema = 100_000u64;
    let hmc_req_b = humoco_node::api::hmc::L2LockRequest {
        causal_output: None,
        auth: humoco_node::api::hmc::L2AuthPayload {
            ephemeral_pubkey: *identity_g.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "voucher_low_load".into(),
        ds_tag: None,
        transaction_hash: [20; 32],
        is_genesis: true,
        sender_ephemeral_pub: *identity_g.node_pubkey(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        deletable_at: None,
        privacy_guard: None,
    };
    let entry_b = humoco_node::api::hmc::L2LockEntry::from(&hmc_req_b);
    let root_valid_until_b = t2 + 86_400_000;
    let digest_b = humoco_sim_core::fraud::compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::Mainnet,
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
    let lock_hdr_b = WireHeader::new(
        MsgType::LockVerifyRequest as u16,
        3,
        0,
        0,
        lock_payload_b.len() as u32,
    );
    let (resp_hdr_b, _) = handler_b
        .handle_authenticated(lock_hdr_b, lock_payload_b, Some(*identity_g.node_pubkey()))
        .await
        .expect("handle lock B");

    // Node B detects under-reporting against piggybacked evidence and rejects with FLAG_QUOTA_FRAUD
    assert_eq!(resp_hdr_b.msg_type, MsgType::LockVerifyResponse as u16);
    let expected_flags = FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD;
    assert_eq!(
        resp_hdr_b.flags & expected_flags,
        expected_flags,
        "Node B must reject with FLAG_QUOTA_EXCEEDED | FLAG_PEER_SUSPENDED | FLAG_QUOTA_FRAUD"
    );

    // 4. Node B bans Gateway G in engine and peer manager
    assert!(
        engine_b.is_node_banned(identity_g.node_pubkey()).await,
        "Engine B must ban Gateway G"
    );
    assert!(
        pm_b.is_banned(identity_g.node_pubkey()).await,
        "PeerManager B must ban Gateway G"
    );

    // 5. Fraud proof was broadcast (Phase 10: channel carries (proof, sender))
    let (broadcasted_proof, _sender) = fraud_rx.try_recv().expect("Fraud proof must be broadcast");
    assert_eq!(
        broadcasted_proof.perpetrator_node_id,
        *identity_g.node_pubkey()
    );
    assert!(
        broadcasted_proof.verify_network(humoco_sim_core::types::NetworkId::Mainnet),
        "Broadcasted proof must be cryptographically valid"
    );
}

#[tokio::test]
async fn test_s06_02_clock_sample_revocation_on_friend_removal_and_ban() {
    use humoco_node::identity::NodeIdentity;

    // Create 10 trusted friend identities
    let friends: Vec<_> = (0..10).map(|_| NodeIdentity::generate()).collect();
    let friend_keys: Vec<[u8; 32]> = friends.iter().map(|f| *f.node_pubkey()).collect();
    let endpoints: Vec<(Option<[u8; 32]>, std::net::SocketAddr)> = friends
        .iter()
        .enumerate()
        .map(|(i, f)| {
            (
                Some(*f.node_pubkey()),
                format!("127.0.0.1:{}", 35000 + i).parse().unwrap(),
            )
        })
        .collect();

    let pm = Arc::new(PeerManager::with_f2f(endpoints.clone(), friend_keys.clone()));
    let local_now = pm.clock().physical_now_ms();

    // 1. Record clock samples for all 10 friends with positive offsets
    for (i, friend) in friends.iter().enumerate() {
        let offset: u64 = 50_000 + (i as u64) * 1_000;
        let ok = pm
            .clock()
            .record_peer_heartbeat(*friend.node_pubkey(), true, local_now + offset);
        assert!(ok, "Friend sample must be accepted");
    }

    // Confirm initial quorum
    assert_eq!(pm.clock().sample_count(), 10);
    assert!(pm.clock().has_quorum_samples());
    assert!(pm.clock().current_median_offset().is_some());
    assert!(pm.clock().is_time_corroborated(50_000));
    let time_with_offset = pm.net_time_ms();

    // 2. Revoke/remove through EACH supported friendship-removal path:
    // Path 1: remove_trusted_f2f_peer
    pm.remove_trusted_f2f_peer(friends[0].node_pubkey()).await;
    assert_eq!(
        pm.clock().sample_count(),
        9,
        "remove_trusted_f2f_peer must revoke clock sample"
    );

    // Path 2: remove_peer_by_spec with public key
    pm.remove_peer_by_spec(Some(*friends[1].node_pubkey()), None)
        .await;
    assert_eq!(
        pm.clock().sample_count(),
        8,
        "remove_peer_by_spec with pubkey must revoke clock sample"
    );

    // Path 3: operator peer removal by endpoint
    let endpoint_str = format!("127.0.0.1:{}", 35000 + 2);
    pm.remove_peer_by_spec(None, Some(&endpoint_str)).await;
    assert_eq!(
        pm.clock().sample_count(),
        7,
        "operator removal by endpoint must revoke clock sample"
    );

    // Path 4: permanent ban
    pm.ban_node(friends[3].node_pubkey()).await;
    assert_eq!(
        pm.clock().sample_count(),
        6,
        "ban_node must revoke clock sample"
    );

    // With 6 samples (< 10 threshold), quorum is lost and logical offset is cleared
    assert!(!pm.clock().has_quorum_samples());
    assert_eq!(pm.clock().current_median_offset(), None);
    assert!(!pm.clock().is_time_corroborated(50_000));
    assert_eq!(
        pm.clock().logical_offset_ms(),
        0,
        "Logical offset must be cleared when samples drop below MIN_SAMPLES_FOR_MEDIAN"
    );

    // Monotonicity check: net_time_ms() never steps backward when offset drops
    let time_after_drop = pm.net_time_ms();
    assert!(
        time_after_drop >= time_with_offset,
        "Monotonicity invariant: issued net_time must never step backward (after: {}, before: {})",
        time_after_drop,
        time_with_offset
    );

    // Repeated removal (idempotent)
    pm.remove_trusted_f2f_peer(friends[0].node_pubkey()).await;
    assert_eq!(
        pm.clock().sample_count(),
        6,
        "Repeated removal must be idempotent"
    );

    // Revoke remaining friends so all original poisoned friends are cleared
    for f in &friends[4..10] {
        pm.remove_trusted_f2f_peer(f.node_pubkey()).await;
    }
    assert_eq!(pm.clock().sample_count(), 0);
    assert!(!pm.clock().has_quorum_samples());
    assert_eq!(pm.clock().current_median_offset(), None);
    assert_eq!(pm.clock().logical_offset_ms(), 0);

    // Register 10 fresh honest trusted friends with +4_000 ms offset
    let fresh_friends: Vec<_> = (0..10).map(|_| NodeIdentity::generate()).collect();
    for f in &fresh_friends {
        pm.register_f2f_friend(*f.node_pubkey(), None).await;
        let fresh_now = pm.clock().physical_now_ms();
        let ok = pm
            .clock()
            .record_peer_heartbeat(*f.node_pubkey(), true, fresh_now + 4_000);
        assert!(ok, "Fresh honest friend sample must be accepted");
    }

    assert_eq!(pm.clock().sample_count(), 10);
    assert!(pm.clock().has_quorum_samples(), "Must regain quorum with 10 fresh friends");
    assert_eq!(
        pm.clock().current_median_offset(),
        Some(4_000),
        "Median offset must reflect the new honest friends (+4_000 ms)"
    );
    assert_eq!(
        pm.clock().logical_offset_ms(),
        0,
        "Logical offset adjusts cleanly without dominated stale state"
    );

    // Preserved unrelated honest friends:
    // Create clock with 10 honest friends (+0s) and 2 poisoned friends (+60s)
    let clean_clock = NetworkClock::new();
    let honest_friends: Vec<_> = (0..10).map(|_| NodeIdentity::generate()).collect();
    let poisoned_friends: Vec<_> = (0..2).map(|_| NodeIdentity::generate()).collect();
    let base_t = clean_clock.physical_now_ms();

    for h in &honest_friends {
        clean_clock.record_peer_heartbeat(*h.node_pubkey(), true, base_t);
    }
    for p in &poisoned_friends {
        clean_clock.record_peer_heartbeat(*p.node_pubkey(), true, base_t + 60_000);
    }
    assert_eq!(clean_clock.sample_count(), 12);

    // Revoke the 2 poisoned friends
    assert!(clean_clock.revoke_peer_sample(poisoned_friends[0].node_pubkey()));
    assert!(clean_clock.revoke_peer_sample(poisoned_friends[1].node_pubkey()));
    assert_eq!(clean_clock.sample_count(), 10);
    assert_eq!(
        clean_clock.current_median_offset(),
        Some(0),
        "Removing poisoned friends must leave remaining 10 honest friends median clean at 0"
    );
}

#[tokio::test]
async fn test_s06_02_real_quic_clock_sample_revocation_and_equivocation_ban() {
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::{DefaultRequestHandler, QuicTransport};
    use humoco_sim_core::wire::{MsgType, WireHeader};
    use tokio_util::sync::CancellationToken;

    let cancel = CancellationToken::new();
    let server_id = NodeIdentity::generate();
    let friend_b = NodeIdentity::generate();
    let friend_c = NodeIdentity::generate();

    let pm_server = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*friend_b.node_pubkey(), *friend_c.node_pubkey()],
    ));
    let pm_b = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*server_id.node_pubkey()],
    ));

    let server_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &server_id,
        pm_server.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind server");
    let server_addr = server_transport.local_addr().unwrap();
    server_transport.spawn_accept_loop();

    let client_transport_b = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &friend_b,
        pm_b.clone(),
        Arc::new(DefaultRequestHandler),
        cancel.clone(),
    )
    .expect("bind client b");
    let addr_b = client_transport_b.local_addr().unwrap();
    client_transport_b.spawn_accept_loop();

    pm_server
        .register_f2f_friend(*friend_b.node_pubkey(), Some(addr_b))
        .await;
    pm_b.register_f2f_friend(*server_id.node_pubkey(), Some(server_addr))
        .await;

    let conn_b = client_transport_b
        .connect_peer_unchecked(server_addr)
        .await
        .expect("B connects to Server");

    // 1. Friend B sends genuine origin-signed heartbeat over real QUIC
    let now_ms = pm_server.net_time_ms();
    let mut hb_b = humoco_node::network::framing::HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *friend_b.node_pubkey(),
        addr: addr_b,
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 0,
        declared_read_ema_credits: 0,
        signature: [0u8; 64],
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *friend_b.hrw_routing_id(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    hb_b.sign_origin(&friend_b, now_ms, humoco_sim_core::types::NetworkId::default());
    let payload_b = bincode::serialize(&hb_b).unwrap();
    let mut hdr_b = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, payload_b.len() as u32);
    hdr_b.reserved = 0; // hops = 0 (direct)

    client_transport_b
        .send_unidirectional(&conn_b, &hdr_b, &payload_b)
        .await
        .expect("Send heartbeat");
    for _ in 0..20 {
        if pm_server.clock().sample_count() > 0 {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
    }

    // Verify sample was recorded
    assert_eq!(
        pm_server.clock().sample_count(),
        1,
        "Direct friend heartbeat must record clock sample"
    );

    // 2. Revoke friendship of B
    pm_server
        .remove_trusted_f2f_peer(friend_b.node_pubkey())
        .await;
    assert_eq!(
        pm_server.clock().sample_count(),
        0,
        "Revoking friendship must purge friend B's clock sample"
    );

    // Friend B sends another heartbeat over QUIC — must NOT be accepted into clock
    let fresh_now = pm_server.net_time_ms();
    hb_b.timestamp_ms = fresh_now;
    hb_b.sign_origin(&friend_b, fresh_now, humoco_sim_core::types::NetworkId::default());
    let payload_b2 = bincode::serialize(&hb_b).unwrap();
    let mut hdr_b2 =
        WireHeader::new(MsgType::Heartbeat as u16, 2, 0, 0, payload_b2.len() as u32);
    hdr_b2.reserved = 0;
    client_transport_b
        .send_unidirectional(&conn_b, &hdr_b2, &payload_b2)
        .await
        .expect("Send second heartbeat");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    assert_eq!(
        pm_server.clock().sample_count(),
        0,
        "Heartbeat from former friend must not contribute to clock"
    );

    // 3. Separately test ban_node purging clock sample
    // Add sample for friend C
    pm_server
        .clock()
        .record_peer_heartbeat(*friend_c.node_pubkey(), true, now_ms);
    assert_eq!(pm_server.clock().sample_count(), 1);

    // Ban friend C
    pm_server.ban_node(friend_c.node_pubkey()).await;
    assert_eq!(
        pm_server.clock().sample_count(),
        0,
        "ban_node must purge friend C's clock sample"
    );

    cancel.cancel();
}

#[tokio::test]
async fn test_s08_15_delayed_peer_evidence_completes_cold_start_via_daemon_ticker_real_quic() {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio_util::sync::CancellationToken;

    use ed25519_dalek::Signer;
    use humoco_node::config::NodeConfig;
    use humoco_node::daemon::{BoundAddrs, NodeDaemon};
    use humoco_node::identity::NodeIdentity;
    use humoco_node::network::framing::{HeartbeatWirePayload, StatusQueryPayload};
    use humoco_node::network::manager::PeerManager;
    use humoco_node::network::{DefaultRequestHandler, QuicTransport};
    use humoco_sim_core::wire::{MsgType, WireHeader, FLAG_QUOTA_EXCEEDED};

    let temp = tempdir().expect("tempdir");
    let mut config = NodeConfig::default();
    config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
    config.network.simulation_mode = true;
    config.network.fast_ticker_interval_secs = Some(1);
    config.storage.data_dir = temp.path().join("data");

    let daemon_id = NodeIdentity::generate();
    let daemon_cancel = CancellationToken::new();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel::<BoundAddrs>();
    let (engine_tx, engine_rx) = tokio::sync::oneshot::channel();
    let (tc_tx, tc_rx) = tokio::sync::oneshot::channel();

    let daemon = NodeDaemon::with_bound_sender(
        config,
        daemon_id.clone(),
        daemon_cancel.clone(),
        bound_tx,
    )
    .with_engine_sender(engine_tx)
    .with_tier_controller_sender(tc_tx)
    .bootstrap_new_region();

    let daemon_handle = tokio::spawn(async move { daemon.run().await });
    let bound = bound_rx.await.expect("daemon bound");
    let engine = engine_rx.await.expect("engine received");
    let tc = tc_rx.await.expect("tier_controller received");
    let pm = engine
        .peer_manager_rwlock_for_test()
        .read()
        .await
        .clone()
        .expect("pm attached");
    pm.set_simulation_mode(true);

    // Client QUIC transport connected to daemon
    let client_id = NodeIdentity::generate();
    let client_cancel = CancellationToken::new();
    let client_pm = Arc::new(PeerManager::with_f2f(
        Vec::new(),
        vec![*daemon_id.node_pubkey()],
    ));
    client_pm.set_simulation_mode(true);

    let client_transport = QuicTransport::bind_with_options(
        "127.0.0.1:0".parse().unwrap(),
        &client_id,
        client_pm.clone(),
        Arc::new(DefaultRequestHandler),
        client_cancel.clone(),
    )
    .expect("bind client");
    client_transport.spawn_accept_loop();

    let client_addr = client_transport.local_addr().unwrap();
    pm.register_f2f_friend(*client_id.node_pubkey(), Some(client_addr))
        .await;

    let conn = client_transport
        .connect_peer_unchecked(bound.p2p_addr)
        .await
        .expect("connect to daemon");

    // 1. Join with an initial observation set of 20 mature remote identities (total size = 21) that initially lacks load evidence.
    let mut remote_peers: Vec<NodeIdentity> = Vec::with_capacity(20);
    remote_peers.push(client_id.clone());
    for _ in 1..20 {
        remote_peers.push(NodeIdentity::generate());
    }

    let now_instant = std::time::Instant::now();
    let mature_offset = Duration::from_secs(86400 * 2);
    for (i, peer) in remote_peers.iter().enumerate() {
        let dummy_addr: SocketAddr = if i == 0 {
            client_addr
        } else {
            format!("127.0.0.1:{}", 42000 + i).parse().unwrap()
        };
        pm.learn_node_from_gossip_with_hrw(
            *peer.node_pubkey(),
            *peer.hrw_routing_id(),
            dummy_addr,
            if i == 0 { 0 } else { 1 },
            None,
        )
        .await;
        pm.set_first_seen_for_test(peer.node_pubkey(), now_instant - mature_offset)
            .await;
    }

    assert_eq!(
        pm.total_network_size().await,
        21,
        "Total network size must be 21 (20 remote + 1 local)"
    );

    // 2. Deliver an invalid (bad-signature) evidence over real QUIC
    let now_ms = pm.net_time_ms();
    let bad_hb = HeartbeatWirePayload {
        gateway_advertisement: None,
        signing_checkpoint: None,
        node_id: *remote_peers[1].node_pubkey(),
        addr: "127.0.0.1:42001".parse().unwrap(),
        timestamp_ms: now_ms,
        declared_write_ema_micro_bj: 2_885_390_753_978,
        declared_read_ema_credits: 721_348,
        signature: [0xee; 64], // corrupted/invalid signature
        supported_suites_mask: 0,
        piggyback_observations: Vec::new(),
        pow_nonce: 0,
        hrw_routing_id: *remote_peers[1].node_pubkey(),
        ticket_epoch_t0: 0,
        ttl: 16,
    };
    let bad_payload = bincode::serialize(&bad_hb).unwrap();
    let mut bad_hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 0, 0, bad_payload.len() as u32);
    bad_hdr.reserved = 1;
    let _ = client_transport.send_unidirectional(&conn, &bad_hdr, &bad_payload).await;

    // Allow daemon maintenance ticker to fire
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Verify that absent or invalid (bad-signature) evidence does not initialize the buffers
    // and that initial effective baselines reflect the hard floors (960_000 write, 50_000 read)
    // rather than bogus write / 5 = 192_000 reseeding when no evidence exists.
    assert_eq!(
        tc.effective_ncb(),
        960_000,
        "Write baseline must reflect hard floor (960_000) when evidence is absent/invalid"
    );
    assert_eq!(
        tc.effective_read_ncb(),
        50_000,
        "Read baseline must reflect hard floor (50_000) rather than bogus 192_000 reseeding when evidence is absent/invalid"
    );

    // 3. Deliver eligible signed checkpoints (both write and read load evidence) later over real QUIC
    // without changing network size (size remains 21).
    // Write median = 2_000_000 (declared EMA = 2_885_390_753_978)
    // Read median = 500_000 (declared EMA = 721_348)
    let fresh_now_ms = pm.net_time_ms() + 1000;
    for (i, peer) in remote_peers.iter().enumerate() {
        let peer_addr = if i == 0 {
            client_addr
        } else {
            format!("127.0.0.1:{}", 42000 + i).parse().unwrap()
        };
        let mut hb = HeartbeatWirePayload {
            gateway_advertisement: None,
            signing_checkpoint: None,
            node_id: *peer.node_pubkey(),
            addr: peer_addr,
            timestamp_ms: fresh_now_ms,
            declared_write_ema_micro_bj: 2_885_390_753_978,
            declared_read_ema_credits: 721_348,
            signature: [0u8; 64],
            supported_suites_mask: 0,
            piggyback_observations: Vec::new(),
            pow_nonce: 0,
            hrw_routing_id: *peer.node_pubkey(),
            ticket_epoch_t0: 0,
            ttl: 16,
        };
        hb.sign_origin(peer, fresh_now_ms, humoco_sim_core::types::NetworkId::default());
        let payload = bincode::serialize(&hb).unwrap();
        let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, (i + 10) as u64, 0, 0, payload.len() as u32);
        hdr.reserved = if i == 0 { 0 } else { 1 };
        client_transport
            .send_unidirectional(&conn, &hdr, &payload)
            .await
            .expect("deliver eligible signed heartbeat");
    }

    // Wait for the evidence to be ingested by the daemon's QUIC uni-stream handlers
    let wait_ev = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < wait_ev {
        if pm.get_node_write_evidence(remote_peers[0].node_pubkey()).await.is_some()
            && pm.get_node_write_evidence(remote_peers[1].node_pubkey()).await.is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Network size must remain 21
    assert_eq!(
        pm.total_network_size().await,
        21,
        "Network size must remain unchanged at 21"
    );

    // 4. Exercise the actual autonomous daemon maintenance ticker (wait for the ticker to fire, do NOT call manual seed helpers!).
    let ticker_deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    let mut initialized = false;
    while tokio::time::Instant::now() < ticker_deadline {
        if tc.effective_ncb() >= 1_990_000 && tc.effective_read_ncb() >= 490_000 {
            initialized = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        initialized,
        "Autonomous daemon ticker must initialize both 28-day buffers from eligible peer medians! Got write={}, read={}",
        tc.effective_ncb(),
        tc.effective_read_ncb()
    );

    // 5. Subsequent real-QUIC request with daily read rate ~1_000_000 (which failed at 192_000 / 50_000 baseline) now succeeds
    let sq_time = pm.net_time_ms();
    let lock_id = [0x55; 32];
    let sq_read_ema = 1_442_696u64; // ema_to_daily_rate(1_442_696) == 1_000_000
    let sq_digest = humoco_sim_core::fraud::compute_ingress_envelope_digest(
        humoco_sim_core::types::NetworkId::default(),
        client_id.node_pubkey(),
        0,
        0,
        sq_time,
        0,
        sq_read_ema,
        0,
        true,
        &lock_id,
    );
    let sq_sig = client_id.signing_key().sign(&sq_digest).to_bytes();
    let sq_payload = StatusQueryPayload {
        lock_id,
        parent_lock: [0; 32],
        shard_id: 0,
        sender_pubkey: *client_id.node_pubkey(),
        declared_write_ema_micro_bj: 0,
        current_read_ema_credits: sq_read_ema,
        timestamp_ms: sq_time,
        sender_signature: sq_sig,
    };
    let sq_bytes = bincode::serialize(&sq_payload).unwrap();
    let sq_hdr = WireHeader::new(MsgType::StatusQuery as u16, 999, 0, 0, sq_bytes.len() as u32);
    let (resp_hdr, _) = client_transport
        .send_request(&conn, &sq_hdr, &sq_bytes)
        .await
        .expect("send StatusQuery over real QUIC");

    assert_eq!(
        resp_hdr.flags & FLAG_QUOTA_EXCEEDED,
        0,
        "StatusQuery with daily read rate ~1_000_000 must succeed under 500_000 median (cap 2_500_000)"
    );

    // evaluate_read_quota_with_time for 192_001 succeeding
    let eval_res = tc.evaluate_read_quota_with_time(
        1u16,
        192_001,
        1.0,
        Some(sq_time),
    );
    assert!(
        eval_res.is_ok(),
        "evaluate_read_quota_with_time for 192_001 must succeed under initialized 500_000 baseline"
    );

    // 6. Verify one-time initialization: delivering higher peer medians later at unchanged network size
    // does NOT continually overwrite the established 28-day history on subsequent daemon ticks.
    let higher_now_ms = pm.net_time_ms() + 5000;
    for (i, peer) in remote_peers.iter().enumerate() {
        let peer_addr = if i == 0 {
            client_addr
        } else {
            format!("127.0.0.1:{}", 42000 + i).parse().unwrap()
        };
        let mut hb = HeartbeatWirePayload {
            gateway_advertisement: None,
            signing_checkpoint: None,
            node_id: *peer.node_pubkey(),
            addr: peer_addr,
            timestamp_ms: higher_now_ms,
            declared_write_ema_micro_bj: 7_213_476_884_945, // daily rate ~5_000_000
            declared_read_ema_credits: 2_885_392, // daily rate ~2_000_000
            signature: [0u8; 64],
            supported_suites_mask: 0,
            piggyback_observations: Vec::new(),
            pow_nonce: 0,
            hrw_routing_id: *peer.node_pubkey(),
            ticket_epoch_t0: 0,
            ttl: 16,
        };
        hb.sign_origin(peer, higher_now_ms, humoco_sim_core::types::NetworkId::default());
        let payload = bincode::serialize(&hb).unwrap();
        let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, (i + 100) as u64, 0, 0, payload.len() as u32);
        hdr.reserved = if i == 0 { 0 } else { 1 };
        let _ = client_transport.send_unidirectional(&conn, &hdr, &payload).await;
    }

    // Wait for another daemon tick
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Effective medians must remain intact (one-time initialization)
    assert!(
        tc.effective_ncb() <= 2_100_000,
        "Established 28-day write history must not be overwritten by higher peer medians at unchanged size, got {}",
        tc.effective_ncb()
    );
    assert!(
        tc.effective_read_ncb() <= 510_000,
        "Established 28-day read history must not be overwritten by higher peer medians at unchanged size, got {}",
        tc.effective_read_ncb()
    );

    // 7. Verify subsequent daily rotation: advancing epoch day rotates 1 slot normally without wiping
    // the remaining 27 slots of initialized history.
    let rotated = tc.advance_epoch_day(pm.net_time_ms() + 86_400_000);
    assert!(rotated.is_some(), "advancing epoch day must rotate a day");

    // After 1 day rotation out of 28:
    // 27 slots remain 2_000_000 / 500_000, 1 slot is the local rate.
    // Average must still be >= (27 * 2_000_000) / 28 = ~1_928_571 and read >= (27 * 500_000) / 28 = ~482_142.
    assert!(
        tc.effective_ncb() >= 1_900_000 && tc.effective_ncb() <= 2_100_000,
        "Rotating 1 slot out of 28 must preserve the other 27 slots of write history, got {}",
        tc.effective_ncb()
    );
    assert!(
        tc.effective_read_ncb() >= 480_000 && tc.effective_read_ncb() <= 520_000,
        "Rotating 1 slot out of 28 must preserve the other 27 slots of read history, got {}",
        tc.effective_read_ncb()
    );

    client_cancel.cancel();
    daemon_cancel.cancel();
    let _ = daemon_handle.await;
}

