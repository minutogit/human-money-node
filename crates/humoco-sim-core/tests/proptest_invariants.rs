#![allow(clippy::unwrap_used, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    unused_variables,
    unused_mut,
    dead_code,
    unused_imports,
    unused_comparisons
)]
//! Property-Based Testing (`proptest`) for Consensus and Protocol Invariants
//!
//! Scope of Work:
//! 1. WireHeader Safe Framing & Serialization Round-Trip (`INV-1001`)
//! 2. Slotted RingBuffer & NetworkThermometer Bounds & Monotonicity
//!
//! Run with: `cargo test --test proptest_invariants`

use humoco_sim_core::quota::{
    HourlySlottedRingBuffer, NetworkThermometer, HARD_FLOOR_BASELINE_DAILY,
    HARD_FLOOR_READ_BASELINE_DAILY,
};
use humoco_sim_core::wire::{WireHeader, CURRENT_PROTOCOL_VERSION, WIRE_MAGIC};
use proptest::prelude::*;

fn arb_hash256() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

// ---------------------------------------------------------------------------
// Property 3: WireHeader Safe Framing & Serialization Round-Trip (INV-1001)
// ---------------------------------------------------------------------------

proptest! {
    /// Property 3A: Panic-Freedom and Safe Framing for Arbitrary 32-Byte Sequences
    /// For any arbitrary 32-byte sequence: WireHeader::from_bytes(&buf) must never panic
    /// and must only return is_valid_magic() == true if magic bytes match WIRE_MAGIC.
    #[test]
    fn prop_wire_header_from_bytes_never_panics(
        raw_bytes in arb_hash256()
    ) {
        let header = WireHeader::from_bytes(&raw_bytes);

        // Verification of magic validity
        let expected_valid_magic = raw_bytes[0..4] == WIRE_MAGIC;
        prop_assert_eq!(
            header.is_valid_magic(),
            expected_valid_magic,
            "is_valid_magic() must strictly match WIRE_MAGIC check"
        );

        // Bijective roundtrip of raw bytes
        let serialized = header.to_bytes();
        prop_assert_eq!(serialized, raw_bytes, "to_bytes must losslessly mirror from_bytes for 32-byte headers");
    }

    /// Property 3B: Valid WireHeader Serialization Round-Trip
    /// For any valid WireHeader with valid magic, arbitrary msg_type, flags, session_seq,
    /// epoch_id, and payload_len <= 16MB: WireHeader::from_bytes(&header.to_bytes())
    /// must succeed and yield the identical struct.
    #[test]
    fn prop_wire_header_valid_roundtrip(
        msg_type in any::<u16>(),
        session_seq in any::<u64>(),
        epoch_id in any::<u32>(),
        flags in any::<u32>(),
        payload_len in 0u32..=16_777_216u32, // up to 16 MiB
        crypto_suite in any::<u8>(),
        reserved_ver in any::<u8>(),
        reserved in any::<u16>(),
    ) {
        let mut header = WireHeader::new(msg_type, session_seq, epoch_id, flags, payload_len);
        header.crypto_suite = crypto_suite;
        header.reserved_ver = reserved_ver;
        header.reserved = reserved;

        prop_assert!(header.is_valid_magic());
        prop_assert_eq!(header.magic, WIRE_MAGIC);
        prop_assert_eq!(header.protocol_version, CURRENT_PROTOCOL_VERSION);

        let wire_bytes = header.to_bytes();
        prop_assert_eq!(wire_bytes.len(), WireHeader::SIZE);
        prop_assert_eq!(wire_bytes.len(), 32);

        let decoded = WireHeader::from_bytes(&wire_bytes);
        prop_assert_eq!(decoded, header);
        prop_assert!(decoded.is_valid_magic());
        prop_assert_eq!(decoded.magic, WIRE_MAGIC);
        prop_assert_eq!(decoded.protocol_version, CURRENT_PROTOCOL_VERSION);
        prop_assert_eq!(decoded.msg_type, msg_type);
        prop_assert_eq!(decoded.session_seq, session_seq);
        prop_assert_eq!(decoded.epoch_id, epoch_id);
        prop_assert_eq!(decoded.flags, flags);
        prop_assert_eq!(decoded.payload_len, payload_len);
        prop_assert_eq!(decoded.crypto_suite, crypto_suite);
        prop_assert_eq!(decoded.reserved_ver, reserved_ver);
        prop_assert_eq!(decoded.reserved, reserved);

        // Double round-trip stability
        prop_assert_eq!(decoded.to_bytes(), wire_bytes);
    }
}

// ---------------------------------------------------------------------------
// Property 4: Slotted RingBuffer & NetworkThermometer Bounds
// ---------------------------------------------------------------------------

proptest! {
    /// Property 4A: HourlySlottedRingBuffer Invariants over Arbitrary Additions
    /// For any sequence of up to 100 random additions to HourlySlottedRingBuffer:
    /// Values remain within proper mathematical bounds.
    #[test]
    fn prop_hourly_slotted_ring_buffer_bounds(
        entries in prop::collection::vec((0u64..10_000u64, 0u64..100_000_000u64), 1..=100)
    ) {
        let mut ring = HourlySlottedRingBuffer::new();
        prop_assert_eq!(ring.count(), 0);
        prop_assert_eq!(ring.rolling_24h_sum(), 0);
        prop_assert_eq!(ring.rolling_24h_average(), 0);

        for (epoch_hour, median) in entries {
            let prev_count = ring.count();
            let prev_last_hour = ring.last_epoch_hour();

            ring.record_hourly_median(epoch_hour, median);

            if epoch_hour < prev_last_hour {
                // NTP backward protection: no mutation allowed
                prop_assert_eq!(ring.count(), prev_count);
                prop_assert_eq!(ring.last_epoch_hour(), prev_last_hour);
            } else {
                prop_assert!(ring.last_epoch_hour() >= prev_last_hour);
                prop_assert!(ring.count() <= 24);
                prop_assert!(ring.count() >= prev_count.min(24));
            }

            // Invariant: sum is accurately reflected
            let sum = ring.rolling_24h_sum();
            let avg = ring.rolling_24h_average();

            if ring.count() == 0 {
                prop_assert_eq!(sum, 0);
                prop_assert_eq!(avg, 0);
            } else {
                prop_assert_eq!(avg, sum / (ring.count() as u64));
                prop_assert!(avg <= sum);
            }
        }
    }

    /// Property 4B: Fast Reseed on Merge Maintains >= HARD_FLOOR Guarantees
    /// For any arbitrary global_median (even 0 or huge numbers),
    /// fast_reseed_on_merge and fast_reseed_read_on_merge guarantee
    /// effective_ncb >= HARD_FLOOR_BASELINE_DAILY and effective_read_ncb >= HARD_FLOOR_READ_BASELINE_DAILY.
    #[test]
    fn prop_network_thermometer_reseed_hard_floor_guarantees(
        global_median in any::<u64>()
    ) {
        let mut thermometer = NetworkThermometer::new();

        // Initial state before seed must guarantee hard floors
        prop_assert!(thermometer.effective_ncb() >= HARD_FLOOR_BASELINE_DAILY);
        prop_assert!(thermometer.effective_read_ncb() >= HARD_FLOOR_READ_BASELINE_DAILY);

        // Fast reseed on merge
        thermometer.fast_reseed_on_merge(global_median);
        prop_assert!(
            thermometer.effective_ncb() >= HARD_FLOOR_BASELINE_DAILY,
            "effective_ncb must be >= HARD_FLOOR_BASELINE_DAILY"
        );
        prop_assert!(
            thermometer.effective_read_ncb() >= HARD_FLOOR_READ_BASELINE_DAILY,
            "effective_read_ncb must be >= HARD_FLOOR_READ_BASELINE_DAILY"
        );

        // Explicit read reseed
        thermometer.fast_reseed_read_on_merge(global_median);
        prop_assert!(
            thermometer.effective_read_ncb() >= HARD_FLOOR_READ_BASELINE_DAILY,
            "effective_read_ncb must be >= HARD_FLOOR_READ_BASELINE_DAILY after read reseed"
        );
    }

    /// Property 4C: Quota Calculation Monotonicity
    /// For any thermometer state, calculate_daily_quota and calculate_daily_read_quota
    /// are monotonically non-decreasing with respect to k_multiplier and spread_damper,
    /// and never undercut hard floor limits under standard active settings.
    #[test]
    fn prop_quota_calculation_monotonicity(
        global_median in 0u64..100_000_000u64,
        k1 in 0.0f64..=10.0f64,
        k2 in 0.0f64..=10.0f64,
        damper1 in 0.0f64..=1.5f64,
        damper2 in 0.0f64..=1.5f64,
    ) {
        let mut thermometer = NetworkThermometer::new();
        thermometer.fast_reseed_on_merge(global_median);

        let (k_low, k_high) = if k1 <= k2 { (k1, k2) } else { (k2, k1) };
        let (d_low, d_high) = if damper1 <= damper2 { (damper1, damper2) } else { (damper2, damper1) };

        // Monotonicity over k_multiplier (for fixed damper)
        let q_k_low = thermometer.calculate_daily_quota(k_low, d_low);
        let q_k_high = thermometer.calculate_daily_quota(k_high, d_low);
        prop_assert!(q_k_low <= q_k_high, "quota must be monotonic in k_multiplier");

        let rq_k_low = thermometer.calculate_daily_read_quota(k_low, d_low);
        let rq_k_high = thermometer.calculate_daily_read_quota(k_high, d_low);
        prop_assert!(rq_k_low <= rq_k_high, "read quota must be monotonic in k_multiplier");

        // Monotonicity over spread_damper (for fixed k)
        let q_d_low = thermometer.calculate_daily_quota(k_low, d_low);
        let q_d_high = thermometer.calculate_daily_quota(k_low, d_high);
        prop_assert!(q_d_low <= q_d_high, "quota must be monotonic in spread_damper");

        let rq_d_low = thermometer.calculate_daily_read_quota(k_low, d_low);
        let rq_d_high = thermometer.calculate_daily_read_quota(k_low, d_high);
        prop_assert!(rq_d_low <= rq_d_high, "read quota must be monotonic in spread_damper");

        // Monotonicity with respect to higher network median
        let mut higher_thermometer = NetworkThermometer::new();
        let higher_median = global_median.saturating_add(5_000_000);
        higher_thermometer.fast_reseed_on_merge(higher_median);

        prop_assert!(
            thermometer.calculate_daily_quota(k_high, d_high)
                <= higher_thermometer.calculate_daily_quota(k_high, d_high),
            "higher network median must yield greater or equal daily quota"
        );
        prop_assert!(
            thermometer.calculate_daily_read_quota(k_high, d_high)
                <= higher_thermometer.calculate_daily_read_quota(k_high, d_high),
            "higher network median must yield greater or equal daily read quota"
        );
    }
}
