//! Mutant kill tests for Audit 12 (M1-O5, M1-O7, M1-O8)
//! These tests are designed to fail if specific mutants survive.

use humoco_sim_core::quota::{ByteYears, HourlySlottedRingBuffer, NetworkThermometer};

// ---------------------------------------------------------------------------
// M1-O5: ByteYears::from_ttl_seconds(0) must return 1 (commercial rounding)
// Mutant: remove `if ttl_seconds == 0 { return 1; }` -> would return 0
// ---------------------------------------------------------------------------
#[test]
fn test_mutant_m1o5_byteyears_zero_ttl_is_one() {
    // 0 seconds must still cost 1 Byte-Year (non-zero floor)
    assert_eq!(
        ByteYears::from_ttl_seconds(0),
        1,
        "0s TTL must be 1 Byte-Year (floor)"
    );

    // 1 second also must be at least 1
    assert_eq!(ByteYears::from_ttl_seconds(1), 1);

    // Small TTL that would round to 0 without max(1) must still be 1
    // 1 day = 86400s -> (192*86400)/31536000 = 0.525 -> rounds to 1 with max(1)
    assert_eq!(ByteYears::from_ttl_seconds(86_400), 1);

    // 30 days -> 16 confirmed
    assert_eq!(ByteYears::from_ttl_days(30), 16);

    // 5 years -> 960
    assert_eq!(ByteYears::from_ttl_years(5.0), 960);
}

// ---------------------------------------------------------------------------
// M1-O7: NetworkThermometer::try_accept_lock uses <= for exact boundary
// Mutant: `new_usage <= quota` -> `new_usage < quota` would reject exactly 100%
// ---------------------------------------------------------------------------
#[test]
fn test_mutant_m1o7_quota_exact_boundary_le() {
    let mut thermo = NetworkThermometer::new();
    let node: u16 = 1;
    let epoch_day = 0;
    let quota = 100u64;

    // Exactly consume quota in one go -> must be accepted (<=)
    let accepted = thermo.try_accept_lock(epoch_day, node, 100, quota);
    assert!(
        accepted,
        "exact quota boundary (100/100) must be accepted with <="
    );
    assert_eq!(thermo.get_node_usage(node), 100);

    // One more byte-year must be rejected
    let rejected = thermo.try_accept_lock(epoch_day, node, 1, quota);
    assert!(!rejected, "over quota by 1 must be rejected");

    // Read quota exact boundary as well
    let mut thermo2 = NetworkThermometer::new();
    let read_quota = 50u64;
    let ok = thermo2.try_accept_read(epoch_day, node, 50, read_quota);
    assert!(ok, "exact read quota boundary must be accepted");
    assert_eq!(thermo2.get_node_read_usage(node), 50);
    let over = thermo2.try_accept_read(epoch_day, node, 1, read_quota);
    assert!(!over);
}

#[test]
fn test_mutant_m1o7_quota_split_exact_boundary() {
    // Split across multiple calls that sum exactly to quota
    let mut thermo = NetworkThermometer::new();
    let node: u16 = 42;
    let epoch_day = 5;
    let quota = 10u64;

    assert!(thermo.try_accept_lock(epoch_day, node, 4, quota));
    assert!(thermo.try_accept_lock(epoch_day, node, 3, quota));
    // Now usage = 7, remaining 3 -> exact fit must succeed
    assert!(thermo.try_accept_lock(epoch_day, node, 3, quota));
    assert_eq!(thermo.get_node_usage(node), 10);
    // Next must fail
    assert!(!thermo.try_accept_lock(epoch_day, node, 1, quota));
}

// ---------------------------------------------------------------------------
// M1-O8: HourlySlottedRingBuffer duplicate epoch_hour overwrite
// Mutant: missing `self.slots.set_slot(idx, median)` overwrite -> stale value
// ---------------------------------------------------------------------------
#[test]
fn test_mutant_m1o8_epoch_hour_duplicate_overwrite() {
    let mut buf = HourlySlottedRingBuffer::new();

    // Record hour 5 with 1000
    buf.record_hourly_median(5, 1_000);
    assert_eq!(buf.count(), 1);
    assert_eq!(buf.slots()[5], 1_000);
    assert_eq!(buf.rolling_24h_sum(), 1_000);

    // Overwrite same epoch_hour 5 with 9_999 -> slot must be updated, count unchanged
    buf.record_hourly_median(5, 9_999);
    assert_eq!(buf.count(), 1, "count must remain 1 after duplicate hour");
    assert_eq!(
        buf.slots()[5],
        9_999,
        "duplicate epoch_hour must overwrite slot"
    );
    assert_eq!(buf.rolling_24h_sum(), 9_999);
    assert_eq!(buf.rolling_24h_average(), 9_999);

    // Record a different hour to ensure normal path increments count
    buf.record_hourly_median(6, 2_000);
    assert_eq!(buf.count(), 2);
    assert_eq!(buf.slots()[6], 2_000);
    assert_eq!(buf.rolling_24h_sum(), 11_999);
}

#[test]
fn test_mutant_m1o8_epoch_hour_same_slot_modulo_overwrite() {
    let mut buf = HourlySlottedRingBuffer::new();
    // Hours 5 and 29 map to same slot (29 %24 =5) but are different epoch_hours
    // Each should overwrite same physical slot
    buf.record_hourly_median(5, 111);
    assert_eq!(buf.slots()[5], 111);
    buf.record_hourly_median(29, 222);
    assert_eq!(
        buf.slots()[5],
        222,
        "modulo slot must be overwritten by later epoch"
    );
    assert_eq!(buf.last_epoch_hour(), 29);
}
