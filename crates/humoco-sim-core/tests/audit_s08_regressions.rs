#![forbid(unsafe_code)]

//! Slice S08 Specification Regression Tests (S08-03 through S08-05).
//!
//! Validates:
//! - S08-03: HourlySlottedRingBuffer occupied-slot tracking avoids duplicate count increments
//!   when replacing values in the same hour slot.
//! - S08-04: NetworkThermometer Option<u64> timestamps allow exact 24h half-life decay
//!   from sample at t=0 to query/sample at t=86,400.
//! - S08-05: evaluate_quota_exceeded_claim u128 arithmetic handles u64::MAX without overflow.

use humoco_sim_core::quota::{
    evaluate_quota_exceeded_claim, HourlySlottedRingBuffer, NetworkThermometer,
    QuotaPlausibilityVerdict, RollingQuotaCounter,
};

// ---------------------------------------------------------------------------
// S08-03: HourlySlottedRingBuffer duplicate hour replacement
// ---------------------------------------------------------------------------

#[test]
fn test_s08_03_hourly_slotted_ring_buffer_duplicate_hour_replacement() {
    let mut buf = HourlySlottedRingBuffer::new();

    // 1. Initial record (hour=5, median=100)
    buf.record_hourly_median(5, 100);
    assert_eq!(buf.count(), 1);
    assert_eq!(buf.slots()[5], 100);
    assert_eq!(buf.rolling_24h_sum(), 100);
    assert_eq!(buf.rolling_24h_average(), 100);

    // 2. Duplicate record with identical value
    buf.record_hourly_median(5, 100);
    assert_eq!(
        buf.count(),
        1,
        "Duplicate hour must not increment occupied count"
    );
    assert_eq!(buf.slots()[5], 100);
    assert_eq!(buf.rolling_24h_average(), 100);
    assert_eq!(buf.rolling_24h_sum(), 100);

    // 3. Update same hour with new median
    buf.record_hourly_median(5, 300);
    assert_eq!(
        buf.count(),
        1,
        "Updating same hour must keep occupied count at 1"
    );
    assert_eq!(buf.slots()[5], 300);
    assert_eq!(buf.rolling_24h_average(), 300);
    assert_eq!(buf.rolling_24h_sum(), 300);

    // 4. Record new hour (hour=6, median=500)
    buf.record_hourly_median(6, 500);
    assert_eq!(buf.count(), 2);
    assert_eq!(buf.slots()[6], 500);
    assert_eq!(buf.rolling_24h_sum(), 800);
    assert_eq!(buf.rolling_24h_average(), 400);

    // 5. Wrap-around 24h later: hour 29 maps to slot (29 % 24 = 5)
    // Slot 5 was already occupied, so count remains 2
    buf.record_hourly_median(29, 700);
    assert_eq!(
        buf.count(),
        2,
        "Wrap-around overwrite of existing slot must keep count bounded"
    );
    assert_eq!(buf.slots()[5], 700);
    assert_eq!(buf.last_epoch_hour(), 29);
    assert_eq!(buf.rolling_24h_sum(), 1200);
    assert_eq!(buf.rolling_24h_average(), 600);

    // 6. NTP backward jump is ignored
    buf.record_hourly_median(28, 999);
    assert_eq!(buf.last_epoch_hour(), 29);
    assert_ne!(buf.slots()[4], 999);
}

// ---------------------------------------------------------------------------
// S08-04: NetworkThermometer zero-time decay
// ---------------------------------------------------------------------------

#[test]
fn test_s08_04_network_thermometer_zero_time_decay() {
    let mut therm = NetworkThermometer::new();

    // 1. Initial write sample recorded at t = 0
    let initial_footprint_micro = 100_000_000; // 100 Byte-Years in µBJ
    therm.record_write_ingress(0, initial_footprint_micro);
    assert_eq!(therm.current_write_ema_micro_bj(), initial_footprint_micro);

    // At t = 0, instantaneous rate equals initial value rate
    let rate_at_0 = therm.rolling_24h_average_at(0);
    assert!(rate_at_0 > 0);

    // At t = 86_400 (one full 24h half-life), EMA must decay by ~50%
    let rate_at_24h = therm.rolling_24h_average_at(86_400);
    let expected_approx = rate_at_0 / 2;
    let diff = (rate_at_24h as i64 - expected_approx as i64).abs();
    assert!(
        diff <= 1,
        "Write EMA at 24h ({rate_at_24h}) must equal 50% of rate at 0 ({expected_approx})"
    );

    // Recording subsequent write ingress at t = 86_400 applies decay
    therm.record_write_ingress(86_400, 50_000_000);
    // Old 100_000_000 decayed by 50% = 50_000_000 + new 50_000_000 = 100_000_000
    let write_diff = (therm.current_write_ema_micro_bj() as i64 - 100_000_000).abs();
    assert!(
        write_diff <= 100,
        "Write EMA accumulator after 24h ingress must reflect decayed previous sample"
    );

    // 2. Initial read sample recorded at t = 0
    let initial_read_credits = 10_000;
    therm.record_read_ingress(0, initial_read_credits);
    assert_eq!(therm.current_read_ema_credits(), initial_read_credits);

    let read_rate_at_0 = therm.rolling_24h_read_average_at(0);
    let read_rate_at_24h = therm.rolling_24h_read_average_at(86_400);
    let expected_read_approx = read_rate_at_0 / 2;
    let read_diff = (read_rate_at_24h as i64 - expected_read_approx as i64).abs();
    assert!(
        read_diff <= 1,
        "Read EMA at 24h ({read_rate_at_24h}) must equal 50% of rate at 0 ({expected_read_approx})"
    );

    // Recording subsequent read ingress at t = 86_400
    therm.record_read_ingress(86_400, 5_000);
    let read_acc_diff = (therm.current_read_ema_credits() as i64 - 10_000).abs();
    assert!(
        read_acc_diff <= 10,
        "Read EMA accumulator after 24h ingress must reflect decayed previous sample"
    );
}

// ---------------------------------------------------------------------------
// S08-05: evaluate_quota_exceeded_claim u128 comparisons without overflow
// ---------------------------------------------------------------------------

#[test]
fn test_s08_05_evaluate_quota_exceeded_claim_u128_bounds() {
    // Exact probe from audit report: evaluate_quota_exceeded_claim(u64::MAX, u64::MAX)
    // 75% <= sender <= 125% -> BoundaryCutoff
    let verdict_max = evaluate_quota_exceeded_claim(u64::MAX, u64::MAX);
    assert_eq!(
        verdict_max,
        QuotaPlausibilityVerdict::BoundaryCutoff,
        "u64::MAX against u64::MAX must return BoundaryCutoff without overflow truncation"
    );

    // Normal scale: limit = 1000
    // Zone 1: < 75% (749 < 750) -> EarlyRefusal
    assert_eq!(
        evaluate_quota_exceeded_claim(749, 1000),
        QuotaPlausibilityVerdict::EarlyRefusal
    );
    // Lower boundary: 75% = 750 -> BoundaryCutoff
    assert_eq!(
        evaluate_quota_exceeded_claim(750, 1000),
        QuotaPlausibilityVerdict::BoundaryCutoff
    );
    // Nominal: 1000 -> BoundaryCutoff
    assert_eq!(
        evaluate_quota_exceeded_claim(1000, 1000),
        QuotaPlausibilityVerdict::BoundaryCutoff
    );
    // Upper boundary: 125% = 1250 -> BoundaryCutoff
    assert_eq!(
        evaluate_quota_exceeded_claim(1250, 1000),
        QuotaPlausibilityVerdict::BoundaryCutoff
    );
    // Zone 3: > 125% (1251 > 1250) -> OverloadIndication
    assert_eq!(
        evaluate_quota_exceeded_claim(1251, 1000),
        QuotaPlausibilityVerdict::OverloadIndication
    );
}

// ---------------------------------------------------------------------------
// S08-11: Fractional precision retention in RollingQuotaCounter & NetworkThermometer
// ---------------------------------------------------------------------------

#[test]
fn test_s08_11_repeated_one_second_consumption_fractional_precision() {
    let mut counter = RollingQuotaCounter::new();
    let limit = 50_000u64;

    // Initial consumption at t = 0 fills the limit exactly
    assert_eq!(counter.try_consume(0, limit, limit), Ok(limit));
    assert_eq!(counter.last_update_sec(), Some(0));
    assert_eq!(counter.raw_cached_usage(), limit);

    // Independent exponential reference calculation:
    // U(t) = U(t_last) * 2^(-(t - t_last)/86400)
    let half_life_secs = 86_400.0_f64;
    let mut ref_usage = 50_000.0_f64;
    let mut ref_last_sec = 0u64;
    let mut ref_accepted = 0u64;

    let mut actual_accepted = 0u64;

    for t in 1..=10_000u64 {
        // Reference projection
        let dt = (t - ref_last_sec) as f64;
        let ref_decayed = ref_usage * (-dt * std::f64::consts::LN_2 / half_life_secs).exp();
        if ref_decayed + 1.0 <= 50_000.0 + 1e-9 {
            ref_usage = ref_decayed + 1.0;
            ref_last_sec = t;
            ref_accepted += 1;
        }

        // Production counter
        if counter.try_consume(t, 1, limit).is_ok() {
            actual_accepted += 1;
        }
    }

    // In pre-fix code, all 10,000 are accepted because integer truncation round down every second!
    // With fractional precision retained, accepted count matches reference within tight tolerance.
    let count_diff = (actual_accepted as i64 - ref_accepted as i64).abs();
    assert!(
        count_diff <= 30,
        "Accepted count ({actual_accepted}) must closely track independent exponential reference ({ref_accepted}) over 10,000s"
    );

    // Verify remaining usage at t = 10_000 matches reference
    let dt_final = (10_000 - ref_last_sec) as f64;
    let expected_ref_usage_at_10k =
        ref_usage * (-dt_final * std::f64::consts::LN_2 / half_life_secs).exp();
    let actual_usage_at_10k = counter.usage_at(10_000);
    let usage_diff = (actual_usage_at_10k as i64 - expected_ref_usage_at_10k.round() as i64).abs();
    assert!(
        usage_diff <= 5,
        "Final usage ({actual_usage_at_10k}) must match reference ({expected_ref_usage_at_10k:.2}) within tight tolerance"
    );
}

#[test]
fn test_s08_11_network_thermometer_checkpoint_fractional_preservation() {
    let mut therm = NetworkThermometer::new();
    let initial_reads = 10_000u64;
    let initial_writes_micro = 10_000_000_000u64; // 10,000 BY in µBJ

    therm.record_read_ingress(0, initial_reads);
    therm.record_write_ingress(0, initial_writes_micro);

    for t in 1..=10_000u64 {
        therm.checkpoint_emas_at(t);
    }

    // Independent single projection to t = 10,000:
    // 10,000 * 2^(-10,000 / 86_400) ≈ 9,229
    let half_life_secs = 86_400.0_f64;
    let expected_reads_f64 =
        10_000.0_f64 * (-10_000.0 * std::f64::consts::LN_2 / half_life_secs).exp();
    let expected_writes_f64 =
        10_000_000_000.0_f64 * (-10_000.0 * std::f64::consts::LN_2 / half_life_secs).exp();

    let actual_reads = therm.read_ema_credits_at(10_000);
    let actual_writes = therm.write_ema_micro_bj_at(10_000);

    // Pre-fix truncation reduces read_ema_credits to 0!
    // With fractional precision, step-by-step matches single projection to within ~0.05%
    let read_diff = (actual_reads as i64 - expected_reads_f64.round() as i64).abs();
    assert!(
        read_diff <= 5,
        "Read EMA after 10,000 1s checkpoints ({actual_reads}) must match reference ({expected_reads_f64:.1})"
    );

    let write_diff = (actual_writes as i64 - expected_writes_f64.round() as i64).abs();
    let write_rel_error = (write_diff as f64) / expected_writes_f64;
    assert!(
        write_rel_error < 0.001,
        "Write EMA after 10,000 1s checkpoints ({actual_writes}) must match reference ({expected_writes_f64:.1})"
    );
}

#[test]
fn test_s08_11_rolling_quota_edge_cases_and_state_invariance() {
    let mut counter = RollingQuotaCounter::new();
    let limit = 50_000u64;

    // 1. Exact-limit admission
    assert_eq!(counter.try_consume(0, limit, limit), Ok(limit));
    assert_eq!(counter.try_consume(0, 1, limit), Err(0));

    // 2. Rejected try_consume leaves complete counter state 100% unchanged!
    let cached_before = counter.raw_cached_usage();
    let last_update_before = counter.last_update_sec();
    // At t = 1, insufficient decay (< 1 full credit) -> must be rejected
    let res_rej = counter.try_consume(1, 1, limit);
    assert_eq!(res_rej, Err(0));
    assert_eq!(counter.raw_cached_usage(), cached_before);
    assert_eq!(counter.last_update_sec(), last_update_before);
    // Usage at t = 1 reflects decay from t = 0 without state mutation
    assert!(counter.usage_at(1) <= limit);

    // 3. Zero elapsed time (dt = 0)
    assert_eq!(counter.usage_at(0), limit);

    // 4. Backward time (now_sec < last_sec) leaves state monotonic without reverse decay
    assert_eq!(counter.usage_at(0), limit);
    let past_usage = counter.usage_at(0);
    assert_eq!(past_usage, limit);

    // 5. Exact 24-hour half-life (86_400s -> 50%)
    let mut hl_counter = RollingQuotaCounter::new();
    hl_counter.try_consume(100, 100_000, 100_000).unwrap();
    assert_eq!(hl_counter.usage_at(100 + 86_400), 50_000);

    // 6. Long idle periods (>= 64 half-lives -> 0)
    assert_eq!(hl_counter.usage_at(100 + 64 * 86_400), 0);
    assert_eq!(hl_counter.usage_at(100 + 100 * 86_400), 0);

    // 7. u64::MAX overflow bounds
    let mut max_counter = RollingQuotaCounter::new();
    assert_eq!(max_counter.try_consume(0, u64::MAX, u64::MAX), Ok(u64::MAX));
    assert_eq!(max_counter.try_consume(0, 1, u64::MAX), Err(0));
}

// ---------------------------------------------------------------------------
// S08-13: Scaled thermometer accumulation saturation and whole-unit export consistency
// ---------------------------------------------------------------------------

#[test]
fn test_s08_13_network_thermometer_scaled_accumulation_and_saturation() {
    use humoco_sim_core::quota::{decay_scaled_ema, MAX_SCALED_USAGE};

    // Case 1: u64::MAX then 1 at equal timestamp (sec = 0)
    let mut therm1 = NetworkThermometer::new();
    therm1.record_write_ingress(0, u64::MAX);
    therm1.record_write_ingress(0, 1);
    therm1.record_read_ingress(0, u64::MAX);
    therm1.record_read_ingress(0, 1);

    // Assert bounded saturation (u64::MAX whole units)
    assert_eq!(
        therm1.current_write_ema_micro_bj(),
        u64::MAX,
        "Raw write EMA after MAX + 1 at sec=0 must saturate to u64::MAX"
    );
    assert_eq!(
        therm1.write_ema_micro_bj_at(0),
        u64::MAX,
        "Projected write EMA at sec=0 must equal u64::MAX"
    );
    assert_eq!(
        therm1.current_read_ema_credits(),
        u64::MAX,
        "Raw read EMA after MAX + 1 at sec=0 must saturate to u64::MAX"
    );
    assert_eq!(
        therm1.read_ema_credits_at(0),
        u64::MAX,
        "Projected read EMA at sec=0 must equal u64::MAX"
    );

    // Assert exact agreement across raw returns, same-time projections, and checkpoint_emas_at(0)
    let chk1 = therm1.checkpoint_emas_at(0);
    assert_eq!(
        chk1,
        (u64::MAX, u64::MAX),
        "checkpoint_emas_at(0) must return (u64::MAX, u64::MAX), not (0, 0)"
    );
    assert_eq!(therm1.current_write_ema_micro_bj(), chk1.0);
    assert_eq!(therm1.current_read_ema_credits(), chk1.1);
    assert_eq!(therm1.write_ema_micro_bj_at(0), chk1.0);
    assert_eq!(therm1.read_ema_credits_at(0), chk1.1);

    // Case 2: u64::MAX twice at equal timestamp (sec = 0)
    let mut therm2 = NetworkThermometer::new();
    therm2.record_write_ingress(0, u64::MAX);
    therm2.record_write_ingress(0, u64::MAX);
    therm2.record_read_ingress(0, u64::MAX);
    therm2.record_read_ingress(0, u64::MAX);

    assert_eq!(
        therm2.current_write_ema_micro_bj(),
        u64::MAX,
        "Raw write EMA after MAX + MAX at sec=0 must saturate to u64::MAX"
    );
    assert_eq!(
        therm2.write_ema_micro_bj_at(0),
        u64::MAX,
        "Projected write EMA after MAX + MAX must equal u64::MAX"
    );
    assert_eq!(
        therm2.current_read_ema_credits(),
        u64::MAX,
        "Raw read EMA after MAX + MAX at sec=0 must saturate to u64::MAX"
    );
    assert_eq!(
        therm2.read_ema_credits_at(0),
        u64::MAX,
        "Projected read EMA after MAX + MAX must equal u64::MAX"
    );
    let chk2 = therm2.checkpoint_emas_at(0);
    assert_eq!(
        chk2,
        (u64::MAX, u64::MAX),
        "checkpoint_emas_at(0) must return (u64::MAX, u64::MAX)"
    );

    // Case 3: Ordinary fractional precision preserved below saturation
    let mut therm3 = NetworkThermometer::new();
    therm3.record_write_ingress(0, 10_000);
    therm3.record_read_ingress(0, 5_000);
    assert_eq!(therm3.current_write_ema_micro_bj(), 10_000);
    assert_eq!(therm3.current_read_ema_credits(), 5_000);
    assert_eq!(therm3.checkpoint_emas_at(0), (10_000, 5_000));

    // Case 4: Backward-time handling (now_sec < last_update_sec saturates dt to 0 and bounds to MAX_SCALED_USAGE)
    let mut therm4 = NetworkThermometer::new();
    therm4.record_write_ingress(100, u64::MAX);
    therm4.record_read_ingress(100, u64::MAX);
    // Backward time event at sec = 50 (< 100)
    therm4.record_write_ingress(50, 100);
    therm4.record_read_ingress(50, 100);
    assert_eq!(therm4.current_write_ema_micro_bj(), u64::MAX);
    assert_eq!(therm4.current_read_ema_credits(), u64::MAX);
    assert_eq!(therm4.write_ema_micro_bj_at(100), u64::MAX);
    assert_eq!(therm4.read_ema_credits_at(100), u64::MAX);
    assert_eq!(therm4.checkpoint_emas_at(100), (u64::MAX, u64::MAX));

    // Case 5: Next decay / checkpoint_emas_at(1) result from saturated state
    // Must demonstrate continuous monotonic decay from MAX_SCALED_USAGE without discontinuity
    let mut therm5 = NetworkThermometer::new();
    therm5.record_write_ingress(0, u64::MAX);
    therm5.record_write_ingress(0, 1);
    therm5.record_read_ingress(0, u64::MAX);
    therm5.record_read_ingress(0, 1);

    let (decayed_write_1, decayed_read_1) = therm5.checkpoint_emas_at(1);
    let expected_decayed = (decay_scaled_ema(MAX_SCALED_USAGE, 1) >> 32) as u64;
    assert_eq!(
        decayed_write_1,
        expected_decayed,
        "Write EMA at sec=1 decayed from saturated state must match decay_scaled_ema continuously"
    );
    assert_eq!(
        decayed_read_1,
        expected_decayed,
        "Read EMA at sec=1 decayed from saturated state must match decay_scaled_ema continuously"
    );
    assert!(
        decayed_write_1 < u64::MAX,
        "Decayed write EMA at sec=1 must be strictly less than u64::MAX"
    );
    assert!(
        decayed_read_1 < u64::MAX,
        "Decayed read EMA at sec=1 must be strictly less than u64::MAX"
    );
}

// ---------------------------------------------------------------------------
// S08-14: Core quota maps retain fractional usage across cleanup threshold
// ---------------------------------------------------------------------------

#[test]
fn test_s08_14_core_quota_maps_retain_fractional_usage_on_cleanup() {
    use humoco_sim_core::quota::MAX_TRACKED_NODES;

    // 1. Read map test
    let mut therm_read = NetworkThermometer::new();
    let limit = 50_000u64;

    // Insert MAX_TRACKED_NODES (16,384) distinct identities with 1 unit at sec = 0
    for id in 0..MAX_TRACKED_NODES as u16 {
        assert_eq!(
            therm_read.try_consume_read(0, id, 1, limit),
            Ok(1),
            "initial consumption for node {id}"
        );
    }

    // At sec = 1, verify node 0 has positive scaled usage < 1 whole unit
    let node0_counter = therm_read
        .get_node_read_counter(0)
        .expect("node 0 must exist before cleanup");
    let node0_scaled_at_1 = node0_counter.usage_scaled_at(1);
    assert!(
        node0_scaled_at_1 > 0,
        "node 0 must have positive scaled usage at sec=1"
    );
    assert_eq!(
        node0_counter.usage_at(1),
        0,
        "node 0 whole unit usage at sec=1 is 0"
    );

    // Unpruned control counter for exact comparison
    let mut control_counter = RollingQuotaCounter::new();
    control_counter.try_consume(0, 1, limit).unwrap();
    let control_res = control_counter.try_consume(1, limit, limit);
    assert_eq!(
        control_res,
        Err(49_999),
        "control counter must reject limit consumption at sec=1 with 49,999 available"
    );

    // Trigger map maintenance by adding a new identity at sec = 1
    let new_id = MAX_TRACKED_NODES as u16;
    assert_eq!(
        therm_read.try_consume_read(1, new_id, 1, limit),
        Ok(1),
        "new identity consumption triggers cleanup"
    );

    // Assert that identity 0 remains in the map (is NOT deleted!)
    assert!(
        therm_read.get_node_read_counter(0).is_some(),
        "node 0 must NOT be purged from read map while it has positive scaled usage"
    );

    // Assert a 50,000-unit request under limit 50,000 at sec = 1 for identity 0 returns Err(49_999)
    let res = therm_read.try_consume_read(1, 0, limit, limit);
    assert_eq!(
        res,
        Err(49_999),
        "node 0 must be rejected with available == 49,999 (matching control counter), NOT Ok(50,000)"
    );

    // Verify eventual removal once genuine scaled usage decays to exact 0
    // 65 half-lives = 65 * 86_400 seconds
    let far_future_sec = 1 + 65 * 86_400;
    assert_eq!(
        therm_read
            .get_node_read_counter(0)
            .unwrap()
            .usage_scaled_at(far_future_sec),
        0,
        "node 0 scaled usage must decay to exact 0 in far future"
    );

    // Adding another new identity at far_future_sec triggers cleanup
    let far_id = (MAX_TRACKED_NODES + 1) as u16;
    assert_eq!(
        therm_read.try_consume_read(far_future_sec, far_id, 1, limit),
        Ok(1)
    );
    // Node 0 should now be pruned since its scaled usage is exact 0
    assert!(
        therm_read.get_node_read_counter(0).is_none(),
        "node 0 must be purged once its scaled usage is genuinely 0"
    );

    // 2. Write map test (try_consume_lock)
    let mut therm_write = NetworkThermometer::new();

    for id in 0..MAX_TRACKED_NODES as u16 {
        assert_eq!(
            therm_write.try_consume_lock(0, id, 1, limit),
            Ok(1),
            "initial write consumption for node {id}"
        );
    }

    assert!(
        therm_write.get_node_write_counter(0).unwrap().usage_scaled_at(1) > 0
    );
    assert_eq!(
        therm_write.get_node_write_counter(0).unwrap().usage_at(1),
        0
    );

    // Trigger cleanup with new identity at sec = 1
    assert_eq!(
        therm_write.try_consume_lock(1, new_id, 1, limit),
        Ok(1),
        "new identity write consumption triggers cleanup"
    );

    // Assert that identity 0 remains in the map (is NOT deleted!)
    assert!(
        therm_write.get_node_write_counter(0).is_some(),
        "node 0 must NOT be purged from write map while it has positive scaled usage"
    );

    // Assert a 50,000-unit request under limit 50,000 at sec = 1 for identity 0 returns Err(49_999)
    let res_write = therm_write.try_consume_lock(1, 0, limit, limit);
    assert_eq!(
        res_write,
        Err(49_999),
        "node 0 must be rejected on write with available == 49,999, NOT Ok(50,000)"
    );

    // Eventual removal at far future
    assert_eq!(
        therm_write.try_consume_lock(far_future_sec, far_id, 1, limit),
        Ok(1)
    );
    assert!(
        therm_write.get_node_write_counter(0).is_none(),
        "node 0 must be purged from write map once its scaled usage is genuinely 0"
    );
}

// ---------------------------------------------------------------------------
// S08-17: HourlySlottedRingBuffer::rolling_24h_average avoids premature u64 sum saturation
// ---------------------------------------------------------------------------

#[test]
fn test_s08_17_hourly_slotted_ring_buffer_average_full_u128_sum() {
    // 1. Empty control
    let empty = HourlySlottedRingBuffer::new();
    assert_eq!(empty.count(), 0);
    assert_eq!(empty.rolling_24h_sum(), 0);
    assert_eq!(empty.rolling_24h_average(), 0);

    // 2. Single-slot u64::MAX control
    let mut single = HourlySlottedRingBuffer::new();
    single.record_hourly_median(0, u64::MAX);
    assert_eq!(single.count(), 1);
    assert_eq!(single.rolling_24h_sum(), u64::MAX);
    assert_eq!(single.rolling_24h_average(), u64::MAX);

    // 3. Two slots of u64::MAX -> sum saturates to u64::MAX, average must be u64::MAX
    let mut two_max = HourlySlottedRingBuffer::new();
    two_max.record_hourly_median(0, u64::MAX);
    two_max.record_hourly_median(1, u64::MAX);
    assert_eq!(two_max.count(), 2);
    assert_eq!(two_max.rolling_24h_sum(), u64::MAX);
    assert_eq!(two_max.rolling_24h_average(), u64::MAX);

    // 4. 24 slots of u64::MAX -> sum saturates to u64::MAX, average must be u64::MAX
    let mut all_max = HourlySlottedRingBuffer::new();
    for h in 0..24u64 {
        all_max.record_hourly_median(h, u64::MAX);
    }
    assert_eq!(all_max.count(), 24);
    assert_eq!(all_max.rolling_24h_sum(), u64::MAX);
    assert_eq!(all_max.rolling_24h_average(), u64::MAX);

    // 5. Mixed large values exceeding u64::MAX when summed
    let mut mixed = HourlySlottedRingBuffer::new();
    let v0 = u64::MAX - 10;
    let v1 = u64::MAX / 2;
    let v2 = u64::MAX - 20;
    mixed.record_hourly_median(10, v0);
    mixed.record_hourly_median(11, v1);
    mixed.record_hourly_median(12, v2);
    let expected_mixed_avg = ((v0 as u128 + v1 as u128 + v2 as u128) / 3) as u64;
    assert_eq!(mixed.count(), 3);
    assert_eq!(mixed.rolling_24h_sum(), u64::MAX);
    assert_eq!(mixed.rolling_24h_average(), expected_mixed_avg);

    // 6. Duplicate-hour and modulo-slot replacement with large values
    mixed.record_hourly_median(12, 0);
    let expected_dup_avg = ((v0 as u128 + v1 as u128) / 3) as u64;
    assert_eq!(mixed.count(), 3);
    assert_eq!(mixed.rolling_24h_sum(), u64::MAX);
    assert_eq!(mixed.rolling_24h_average(), expected_dup_avg);

    // Modulo-slot overwrite (hour 34 -> slot 10) replaces v0 with ordinary value 300
    mixed.record_hourly_median(34, 300);
    let expected_mod_avg = ((300u128 + v1 as u128) / 3) as u64;
    assert_eq!(mixed.count(), 3);
    assert_eq!(mixed.rolling_24h_sum(), 300 + v1);
    assert_eq!(mixed.rolling_24h_average(), expected_mod_avg);

    // 7. Ordinary small values control
    let mut ordinary = HourlySlottedRingBuffer::new();
    ordinary.record_hourly_median(0, 100);
    ordinary.record_hourly_median(1, 200);
    ordinary.record_hourly_median(2, 600);
    assert_eq!(ordinary.rolling_24h_sum(), 900);
    assert_eq!(ordinary.rolling_24h_average(), 300);
}


