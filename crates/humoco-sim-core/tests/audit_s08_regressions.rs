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
    QuotaPlausibilityVerdict,
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
    // 75% <= sender <= 125% -> BoundaryCutoff { malus_increment: 0 }
    let verdict_max = evaluate_quota_exceeded_claim(u64::MAX, u64::MAX);
    assert_eq!(
        verdict_max,
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 },
        "u64::MAX against u64::MAX must return BoundaryCutoff without overflow truncation"
    );

    // Normal scale: limit = 1000
    // Zone 1: < 75% (749 < 750) -> FraudulentRejection
    assert_eq!(
        evaluate_quota_exceeded_claim(749, 1000),
        QuotaPlausibilityVerdict::FraudulentRejection { malus_increment: 8 }
    );
    // Lower boundary: 75% = 750 -> BoundaryCutoff
    assert_eq!(
        evaluate_quota_exceeded_claim(750, 1000),
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    );
    // Nominal: 1000 -> BoundaryCutoff
    assert_eq!(
        evaluate_quota_exceeded_claim(1000, 1000),
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    );
    // Upper boundary: 125% = 1250 -> BoundaryCutoff
    assert_eq!(
        evaluate_quota_exceeded_claim(1250, 1000),
        QuotaPlausibilityVerdict::BoundaryCutoff { malus_increment: 0 }
    );
    // Zone 3: > 125% (1251 > 1250) -> LegitimateOverload
    assert_eq!(
        evaluate_quota_exceeded_claim(1251, 1000),
        QuotaPlausibilityVerdict::LegitimateOverload { malus_increment: 0 }
    );
}
