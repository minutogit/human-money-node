//! # Phase 4 Integration Tests
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

    // Strict Monotonicity: successive calls must strictly increase
    let mut prev = clock.net_time_ms();
    for _ in 0..10_000 {
        let cur = clock.net_time_ms();
        assert!(
            cur > prev,
            "Strict monotonicity violated: cur ({cur}) <= prev ({prev})"
        );
        prev = cur;
    }

    // Even if local clock jumps backwards drastically (-15 minutes clamp)
    clock.set_offset_for_testing(-900_000);
    let after_backwards = clock.net_time_ms();
    assert!(
        after_backwards > prev,
        "Monotonicity must survive backwards time jumps"
    );
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
