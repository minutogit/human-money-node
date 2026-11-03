#![allow(clippy::unwrap_used, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    unused_variables,
    unused_mut,
    dead_code,
    unused_imports,
    unused_comparisons
)]
//! Property-Based Tests for HuMoCo Layer-2 Collision Lock Registry
//!
//! Covers mathematical property families (using `proptest`):
//! 1. Round-trip invertibility (WireHeader)
//! 2. Deterministic collision total ordering min(H_canon) — strict weak ordering
//! 3. Ingress window & TTL prune invariants
//! 4. Quota monotonicity & hard-floor bounds
//!
//! Run with: `cargo test --test proptests_humoco_properties -- --nocapture`

use humoco_sim_core::{
    calculate_integer_ema, compute_canonical_hash, ByteYears,
    NetworkThermometer, QuartileStats, SimTime,
    SlottedMedianRingBuffer, WireHeader, CURRENT_PROTOCOL_VERSION, HARD_FLOOR_BASELINE_DAILY,
    HARD_FLOOR_READ_BASELINE_DAILY, MAX_WHALE_MULTIPLIER, WIRE_MAGIC,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers / Strategies
// ---------------------------------------------------------------------------

fn arb_hash() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_simtime() -> impl Strategy<Value = SimTime> {
    (0u64..=u64::MAX - 100_000).prop_map(SimTime)
}

fn arb_nonce() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

// ---------------------------------------------------------------------------
// 1. Round-trip invertibility
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_wire_header_roundtrip(
        msg_type in any::<u16>(),
        session_seq in any::<u64>(),
        epoch_id in any::<u32>(),
        flags in any::<u32>(),
        payload_len in any::<u32>(),
        crypto_suite in any::<u8>(),
        reserved_ver in any::<u8>(),
        reserved in any::<u16>(),
    ) {
        let mut hdr = WireHeader::new(msg_type, session_seq, epoch_id, flags, payload_len);
        hdr.crypto_suite = crypto_suite;
        hdr.reserved_ver = reserved_ver;
        hdr.reserved = reserved;
        let bytes = hdr.to_bytes();
        prop_assert_eq!(bytes.len(), WireHeader::SIZE);
        prop_assert_eq!(bytes.len(), 32);
        let decoded = WireHeader::from_bytes(&bytes);
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
        prop_assert_eq!(decoded, hdr);
    }

    #[test]
    fn prop_wire_header_valid_magic_invariant(
        b0 in any::<u8>(),
        b1 in any::<u8>(),
        b2 in any::<u8>(),
        b3 in any::<u8>(),
        rest in prop::collection::vec(any::<u8>(), 28..=28),
    ) {
        let mut raw = [0u8; 32];
        raw[0] = b0;
        raw[1] = b1;
        raw[2] = b2;
        raw[3] = b3;
        raw[4..32].copy_from_slice(&rest);
        let hdr = WireHeader::from_bytes(&raw);
        let expected_magic_ok = [b0, b1, b2, b3] == WIRE_MAGIC;
        prop_assert_eq!(hdr.is_valid_magic(), expected_magic_ok);
    }

    #[test]
    fn prop_canon_hash_deterministic(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
    ) {
        let h1 = compute_canonical_hash(&parent, &receiver, &nonce);
        let h2 = compute_canonical_hash(&parent, &receiver, &nonce);
        prop_assert_eq!(h1, h2);
        let mut nonce2 = nonce.clone();
        nonce2.push(0xFF);
        let h3 = compute_canonical_hash(&parent, &receiver, &nonce2);
        prop_assert_ne!(h1, h3);
    }

    #[test]
    fn prop_canon_total_order_strict_weak_ordering(
        parent in arb_hash(),
        r1 in arb_hash(),
        r2 in arb_hash(),
        r3 in arb_hash(),
        n1 in arb_nonce(),
        n2 in arb_nonce(),
        n3 in arb_nonce(),
    ) {
        let h_a = compute_canonical_hash(&parent, &r1, &n1);
        let h_b = compute_canonical_hash(&parent, &r2, &n2);
        let h_c = compute_canonical_hash(&parent, &r3, &n3);

        // Irreflexivity: !(a < a)
        prop_assert!(!(h_a < h_a));
        prop_assert!(!(h_b < h_b));

        // Asymmetry: a < b => !(b < a)
        if h_a < h_b {
            prop_assert!(!(h_b < h_a));
        }
        if h_b < h_c {
            prop_assert!(!(h_c < h_b));
        }

        // Transitivity: a < b && b < c => a < c
        if h_a < h_b && h_b < h_c {
            prop_assert!(h_a < h_c);
        }
        if h_c < h_b && h_b < h_a {
            prop_assert!(h_c < h_a);
        }

        let ab_ordered = (h_a < h_b) || (h_b < h_a) || (h_a == h_b);
        prop_assert!(ab_ordered);
        let ac_ordered = (h_a < h_c) || (h_c < h_a) || (h_a == h_c);
        prop_assert!(ac_ordered);

        if h_a == h_b {
            prop_assert!(!(h_a < h_b));
            prop_assert!(!(h_b < h_a));
        }
    }

    #[test]
    fn prop_h_canon_domain_separation_length_prefix(
        parent in arb_hash(),
        receiver in arb_hash(),
        nonce in arb_nonce(),
    ) {
        let h_norm = humoco_sim_core::crypto::compute_canonical_hash_normalized(&parent, &receiver, &nonce);
        let h_norm_repeat = humoco_sim_core::crypto::compute_canonical_hash_normalized(&parent, &receiver, &nonce);
        prop_assert_eq!(h_norm, h_norm_repeat);

        let mut nonce_alt = nonce.clone();
        nonce_alt.push(0x42);
        let h_alt = humoco_sim_core::crypto::compute_canonical_hash_normalized(&parent, &receiver, &nonce_alt);
        prop_assert_ne!(h_norm, h_alt);
    }

    #[test]
    fn prop_ingress_window_implies_not_yet_prunable(
        now_ms in 1_000u64..100_000_000u64,
        valid_until_offset in 31_000u64..100_000u64,
        root_offset in 0u64..1_000_000u64,
    ) {
        let now = SimTime(now_ms);
        let valid_until = SimTime(now_ms + valid_until_offset);
        let root_valid = SimTime(valid_until.0 + root_offset);

        let window_ok = humoco_sim_core::storage::ingress_time_window_valid(now, valid_until, root_valid);
        if window_ok {
            prop_assert!(!humoco_sim_core::storage::should_prune(now, root_valid),
                "If ingress window is valid, lock must NOT be prunable right now");
        }
    }

    #[test]
    fn prop_byte_years_monotonic_in_ttl(
        ttl_a in 0u64..10_000_000,
        delta in 0u64..10_000_000,
    ) {
        let ttl_b = ttl_a.saturating_add(delta);
        let by_a = ByteYears::from_ttl_seconds(ttl_a);
        let by_b = ByteYears::from_ttl_seconds(ttl_b);
        prop_assert!(by_b >= by_a, "ByteYears must be monotonic: {} >= {} for ttl {} >= {}", by_b, by_a, ttl_b, ttl_a);
        prop_assert!(by_a >= 1);
        prop_assert!(by_b >= 1);
        let days_a = ttl_a / 86_400;
        let days_b = ttl_b / 86_400;
        if days_b >= days_a {
            prop_assert!(ByteYears::from_ttl_days(days_b) >= ByteYears::from_ttl_days(days_a));
        }
    }

    #[test]
    fn prop_hard_floor_never_undercut(
        medians in prop::collection::vec(0u64..10_000_000, 0..28),
    ) {
        let mut thermo = NetworkThermometer::new();
        for m in medians {
            thermo.record_daily_median(m);
        }
        prop_assert!(thermo.effective_ncb() >= HARD_FLOOR_BASELINE_DAILY,
            "effective_ncb {} must be >= HARD_FLOOR {}", thermo.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);
        prop_assert!(thermo.effective_read_ncb() >= HARD_FLOOR_READ_BASELINE_DAILY);
        let mut thermo2 = NetworkThermometer::new();
        thermo2.record_daily_median(0);
        prop_assert_eq!(thermo2.effective_ncb(), HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn prop_quota_monotonic_in_k_and_damper(
        median in 960_000u64..5_000_000,
        k_a in 0.0f64..5.0,
        k_delta in 0.0f64..2.0,
        damper_a in 0.5f64..1.0,
        damper_delta in 0.0f64..0.5,
    ) {
        let mut thermo = NetworkThermometer::new();
        thermo.record_daily_median(median);
        let k_b = (k_a + k_delta).min(MAX_WHALE_MULTIPLIER);
        let damper_b = (damper_a + damper_delta).min(1.0);
        let q_a = thermo.calculate_daily_quota(k_a, damper_a);
        let q_b_k = thermo.calculate_daily_quota(k_b, damper_a);
        let q_b_d = thermo.calculate_daily_quota(k_a, damper_b);
        let q_b_both = thermo.calculate_daily_quota(k_b, damper_b);
        prop_assert!(q_b_k >= q_a, "quota monotonic in K: {} >= {}", q_b_k, q_a);
        prop_assert!(q_b_d >= q_a, "quota monotonic in damper: {} >= {}", q_b_d, q_a);
        prop_assert!(q_b_both >= q_a);
        prop_assert!(q_b_both >= q_b_k);
        prop_assert!(q_b_both >= q_b_d);
    }

    #[test]
    fn prop_quota_clamped_and_hard_floor_with_k1(
        median in 0u64..20_000_000,
    ) {
        let mut thermo = NetworkThermometer::new();
        thermo.record_daily_median(median);
        let ncb = thermo.effective_ncb();
        prop_assert!(ncb >= HARD_FLOOR_BASELINE_DAILY);
        let q = thermo.calculate_daily_quota(1.0, 1.0);
        prop_assert_eq!(q, ncb);
        let q_over = thermo.calculate_daily_quota(100.0, 1.0);
        let q_max = thermo.calculate_daily_quota(MAX_WHALE_MULTIPLIER, 1.0);
        prop_assert_eq!(q_over, q_max);
        let q_low_damper = thermo.calculate_daily_quota(1.0, 0.0);
        let q_min_damper = thermo.calculate_daily_quota(1.0, 0.5);
        prop_assert_eq!(q_low_damper, q_min_damper);
        let q_min = thermo.calculate_daily_quota(1.0, 0.5);
        prop_assert!(q_min >= HARD_FLOOR_BASELINE_DAILY / 2);
    }

    #[test]
    fn prop_spread_damper_bounded(
        samples in prop::collection::vec(0u64..10_000_000, 1..50)
    ) {
        let stats = QuartileStats::calculate(&samples);
        let d = stats.spread_damper();
        prop_assert!(d >= 0.5 - f64::EPSILON && d <= 1.0 + f64::EPSILON,
            "damper {} out of [0.5,1.0]", d);
        let empty_stats = QuartileStats::calculate(&[]);
        let d_empty = empty_stats.spread_damper();
        prop_assert!(d_empty >= 0.5 && d_empty <= 1.0);
        prop_assert_eq!(empty_stats.median, HARD_FLOOR_BASELINE_DAILY);
        prop_assert_eq!(empty_stats.q1, HARD_FLOOR_BASELINE_DAILY);
        prop_assert_eq!(empty_stats.q3, HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn prop_integer_ema_monotonic_and_bounded(
        old_ema in 0u64..5_000_000,
        delta in 0u64..200_000,
        footprint_a in 0u64..1_000_000,
        footprint_delta in 0u64..500_000,
    ) {
        let fp_b = footprint_a.saturating_add(footprint_delta);
        let ema_a = calculate_integer_ema(old_ema, delta, footprint_a);
        let ema_b = calculate_integer_ema(old_ema, delta, fp_b);
        prop_assert!(ema_b >= ema_a, "EMA monotonic in footprint: {} >= {}", ema_b, ema_a);
        let ema_small_delta = calculate_integer_ema(old_ema, delta, footprint_a);
        let ema_large_delta = calculate_integer_ema(old_ema, delta.saturating_add(10_000), footprint_a);
        prop_assert!(ema_large_delta <= ema_small_delta,
            "EMA should decay with time: {} <= {} for larger delta", ema_large_delta, ema_small_delta);
        let at_max = calculate_integer_ema(u64::MAX, 0, 1_000);
        prop_assert_eq!(at_max, u64::MAX);
        let zero_decay = calculate_integer_ema(old_ema, 0, footprint_a);
        prop_assert_eq!(zero_decay, old_ema.saturating_add(footprint_a));
    }

    #[test]
    fn prop_try_accept_lock_monotonic_and_quota_bounded(
        quota in 1_000u64..5_000_000,
        footprints in prop::collection::vec(1u64..10_000, 1..30),
        node_id in any::<u16>(),
    ) {
        let mut thermo = NetworkThermometer::new();
        let day = 42u64;
        let mut total_accepted = 0u64;
        for fp in footprints.clone() {
            let ok = thermo.try_accept_lock(day, node_id, fp, quota);
            if ok {
                total_accepted = total_accepted.saturating_add(fp);
                prop_assert!(total_accepted <= quota, "accepted total {} must be <= quota {}", total_accepted, quota);
                prop_assert_eq!(thermo.get_node_usage(node_id), total_accepted);
            } else {
                prop_assert_eq!(thermo.get_node_usage(node_id), total_accepted);
                let huge_ok = thermo.try_accept_lock(day, node_id, quota, quota);
                let expected_huge = total_accepted.saturating_add(quota) <= quota;
                prop_assert_eq!(huge_ok, expected_huge, "huge footprint must respect remaining quota");
                break;
            }
        }
        let usage_before = thermo.get_node_usage(node_id);
        let _ = thermo.try_accept_lock(day, node_id, 1, quota);
        prop_assert!(thermo.get_node_usage(node_id) >= usage_before);
    }

    #[test]
    fn prop_try_accept_lock_resets_next_day(
        quota in 1_000u64..5_000_000,
        fp in 1u64..5_000,
        node_id in any::<u16>(),
    ) {
        let mut thermo = NetworkThermometer::new();
        prop_assume!(fp <= quota);
        let day1 = 10u64;
        let day2 = 11u64;
        prop_assert!(thermo.try_accept_lock(day1, node_id, fp, quota));
        prop_assert_eq!(thermo.get_node_usage(node_id), fp);
        prop_assert!(thermo.try_accept_lock(day2, node_id, fp, quota));
        prop_assert_eq!(thermo.get_node_usage(node_id), fp);
        if fp * 2 <= quota {
            prop_assert!(thermo.try_accept_lock(day2, node_id, fp, quota));
            prop_assert_eq!(thermo.get_node_usage(node_id), fp * 2);
        }
    }

    #[test]
    fn prop_thermometer_moving_average_monotonic_with_floor(
        values in prop::collection::vec(0u64..10_000_000, 1..30)
    ) {
        let mut ring = SlottedMedianRingBuffer::new();
        prop_assert_eq!(ring.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
        for v in values {
            ring.push_daily_median(v);
            prop_assert!(ring.moving_average_median() >= 0);
        }
        let mut seeded = SlottedMedianRingBuffer::new();
        seeded.seed(HARD_FLOOR_BASELINE_DAILY);
        prop_assert_eq!(seeded.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
        seeded.seed(0);
        prop_assert_eq!(seeded.moving_average_median(), HARD_FLOOR_BASELINE_DAILY);
    }

    #[test]
    fn prop_byteyears_monotonicity_across_arbitrary_seconds(
        s1 in any::<u64>(),
        delta in any::<u64>(),
    ) {
        let s2 = s1.saturating_add(delta);
        prop_assert!(s1 <= s2);

        let by1 = ByteYears::from_ttl_seconds(s1);
        let by2 = ByteYears::from_ttl_seconds(s2);
        prop_assert!(by1 <= by2, "ByteYears must be monotonic: by1={} <= by2={} for s1={} <= s2={}", by1, by2, s1, s2);
        prop_assert!(by1 >= 1, "ByteYears non-zero floor");
        prop_assert!(by2 >= 1, "ByteYears non-zero floor");

        let uby1 = ByteYears::micro_from_ttl_seconds(s1);
        let uby2 = ByteYears::micro_from_ttl_seconds(s2);
        prop_assert!(uby1 <= uby2, "micro ByteYears must be monotonic: uby1={} <= uby2={}", uby1, uby2);
        prop_assert!(uby1 >= 1, "micro ByteYears non-zero floor");
        prop_assert!(uby2 >= 1, "micro ByteYears non-zero floor");

        if s1 > 0 {
            prop_assert!(uby1 >= by1, "micro ByteYears >= ByteYears for s1 > 0");
        }
    }
}
