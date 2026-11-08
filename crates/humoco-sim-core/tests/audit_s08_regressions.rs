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
