#![allow(clippy::unwrap_used, clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(unused_variables, unused_mut, dead_code, unused_imports, unused_comparisons)]
//! Property-Based Testing (`proptest`) for Consensus and Protocol Invariants
//!
//! Scope of Work:
//! 1. Canonical Resolver Commutativity & Invariance (`min(H_canon)`)
//! 2. Equivocation Proof Symmetry & Collision Resistance
//! 3. WireHeader Safe Framing & Serialization Round-Trip (`INV-1001`)
//! 4. Slotted RingBuffer & NetworkThermometer Bounds & Monotonicity
//!
//! Run with: `cargo test --test proptest_invariants`

use humoco_sim_core::crypto::{
    compute_canonical_hash, compute_canonical_hash_with_sig, create_equivocation_proof,
    DOMAIN_CANON_RESOLVER, DOMAIN_EQUIVOCATION,
};
use humoco_sim_core::quota::{
    HourlySlottedRingBuffer, NetworkThermometer, HARD_FLOOR_BASELINE_DAILY,
    HARD_FLOOR_READ_BASELINE_DAILY, MAX_WHALE_MULTIPLIER, READ_TO_WRITE_RATIO,
};
use humoco_sim_core::resolver::{
    resolve_split_brain, resolve_split_brain_canonical, ResolutionResult,
};
use humoco_sim_core::types::{Hash256, LockRecord, LockStatus, NodeId, SimTime};
use humoco_sim_core::wire::{WireHeader, CURRENT_PROTOCOL_VERSION, WIRE_MAGIC};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Custom Strategies
// ---------------------------------------------------------------------------

fn arb_hash256() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_sig64() -> impl Strategy<Value = [u8; 64]> {
    any::<[u8; 64]>()
}

fn arb_nonce() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

fn arb_lock_pair() -> impl Strategy<
    Value = (
        [u8; 32],            // parent_lock
        [u8; 32],            // receiver_a
        [u8; 32],            // receiver_b
        Vec<u8>,             // nonce_a
        Vec<u8>,             // nonce_b
        Option<[u8; 64]>,    // sig_a
        Option<[u8; 64]>,    // sig_b
        u64,                 // created_ms
        u64,                 // ttl_ms
    ),
> {
    (
        arb_hash256(),
        arb_hash256(),
        arb_hash256(),
        arb_nonce(),
        arb_nonce(),
        prop::option::of(arb_sig64()),
        prop::option::of(arb_sig64()),
        0u64..1_000_000_000u64,
        1_000u64..100_000_000u64,
    )
}

// ---------------------------------------------------------------------------
// Property 1: Canonical Resolver Commutativity & Invariance (min(H_canon))
// ---------------------------------------------------------------------------

proptest! {
    /// Property 1A: Canonical Resolver Commutativity and Winner Consistency
    /// For any arbitrary random parent_lock, receiver_pub (A & B), nonce (A & B),
    /// and optional signatures (A & B):
    /// Resolving (A, B) vs (B, A) must choose the exact same winning payload/lock_id
    /// and mark the loser as Void.
    #[test]
    fn prop_canonical_resolver_commutativity(
        (parent_lock, receiver_a, receiver_b, nonce_a, nonce_b, sig_a, sig_b, created_ms, ttl_ms) in arb_lock_pair()
    ) {
        let created_at = SimTime(created_ms);
        let valid_until = SimTime(created_ms.saturating_add(ttl_ms).saturating_add(30_000));

        let lock_a_orig = LockRecord::new(
            parent_lock,
            receiver_a,
            nonce_a.clone(),
            created_at,
            valid_until,
        );
        let lock_b_orig = LockRecord::new(
            parent_lock,
            receiver_b,
            nonce_b.clone(),
            created_at,
            valid_until,
        );

        let mut lock_a_fwd = lock_a_orig.clone();
        let mut lock_b_fwd = lock_b_orig.clone();

        let mut lock_b_rev = lock_b_orig.clone();
        let mut lock_a_rev = lock_a_orig.clone();

        let res_fwd = resolve_split_brain_canonical(
            &mut lock_a_fwd,
            &mut lock_b_fwd,
            sig_a.as_ref(),
            sig_b.as_ref(),
        );

        let res_rev = resolve_split_brain_canonical(
            &mut lock_b_rev,
            &mut lock_a_rev,
            sig_b.as_ref(),
            sig_a.as_ref(),
        );

        if lock_a_orig.id == lock_b_orig.id {
            // Idempotent duplicate: Identical in both orientations
            prop_assert_eq!(res_fwd, ResolutionResult::Identical);
            prop_assert_eq!(res_rev, ResolutionResult::Identical);
            prop_assert!(!lock_a_fwd.status.is_void());
            prop_assert!(!lock_b_fwd.status.is_void());
            prop_assert!(!lock_a_rev.status.is_void());
            prop_assert!(!lock_b_rev.status.is_void());
        } else {
            // Compute expected canonical hashes
            let h_a = match sig_a.as_ref() {
                Some(sig) => compute_canonical_hash_with_sig(&parent_lock, &receiver_a, sig),
                None => compute_canonical_hash(&parent_lock, &receiver_a, &nonce_a),
            };
            let h_b = match sig_b.as_ref() {
                Some(sig) => compute_canonical_hash_with_sig(&parent_lock, &receiver_b, sig),
                None => compute_canonical_hash(&parent_lock, &receiver_b, &nonce_b),
            };

            match res_fwd {
                ResolutionResult::WinnerA { winner_hash, loser_hash } => {
                    prop_assert_eq!(winner_hash, h_a);
                    prop_assert_eq!(loser_hash, h_b);
                    prop_assert!(h_a < h_b);

                    // Winner A untouched, Loser B marked Void
                    prop_assert!(!lock_a_fwd.status.is_void());
                    prop_assert!(lock_b_fwd.status.is_void());

                    // In reverse call (B, A), A is second arg so A winning corresponds to WinnerB
                    prop_assert_eq!(
                        res_rev,
                        ResolutionResult::WinnerB {
                            winner_hash: h_a,
                            loser_hash: h_b,
                        }
                    );
                    prop_assert!(!lock_a_rev.status.is_void());
                    prop_assert!(lock_b_rev.status.is_void());
                }
                ResolutionResult::WinnerB { winner_hash, loser_hash } => {
                    prop_assert_eq!(winner_hash, h_b);
                    prop_assert_eq!(loser_hash, h_a);
                    prop_assert!(h_b <= h_a);

                    // Winner B untouched, Loser A marked Void
                    prop_assert!(lock_a_fwd.status.is_void());
                    prop_assert!(!lock_b_fwd.status.is_void());

                    // In reverse call (B, A), B is first arg so B winning corresponds to WinnerA
                    prop_assert_eq!(
                        res_rev,
                        ResolutionResult::WinnerA {
                            winner_hash: h_b,
                            loser_hash: h_a,
                        }
                    );
                    prop_assert!(lock_a_rev.status.is_void());
                    prop_assert!(!lock_b_rev.status.is_void());
                }
                _ => {
                    prop_assert!(false, "Different locks on same parent must result in WinnerA or WinnerB");
                }
            }
        }
    }

    /// Property 1B: NoConflict on Distinct Parent Locks
    /// If parent_a != parent_b, resolving them always results in NoConflict,
    /// and neither lock is marked Void.
    #[test]
    fn prop_canonical_resolver_no_conflict_on_distinct_parents(
        parent_a in arb_hash256(),
        parent_b in arb_hash256(),
        receiver_a in arb_hash256(),
        receiver_b in arb_hash256(),
        nonce_a in arb_nonce(),
        nonce_b in arb_nonce(),
    ) {
        prop_assume!(parent_a != parent_b);

        let mut lock_a = LockRecord::new(
            parent_a,
            receiver_a,
            nonce_a,
            SimTime(100),
            SimTime(10_000),
        );
        let mut lock_b = LockRecord::new(
            parent_b,
            receiver_b,
            nonce_b,
            SimTime(100),
            SimTime(10_000),
        );

        let mut lock_a_rev = lock_a.clone();
        let mut lock_b_rev = lock_b.clone();

        let res_fwd = resolve_split_brain(&mut lock_a, &mut lock_b);
        let res_rev = resolve_split_brain(&mut lock_b_rev, &mut lock_a_rev);

        prop_assert_eq!(res_fwd, ResolutionResult::NoConflict);
        prop_assert_eq!(res_rev, ResolutionResult::NoConflict);
        prop_assert!(!lock_a.status.is_void());
        prop_assert!(!lock_b.status.is_void());
        prop_assert!(!lock_a_rev.status.is_void());
        prop_assert!(!lock_b_rev.status.is_void());
    }

    /// Property 1C: Identical Locks Yield Identical Resolution
    /// If lock_a.id == lock_b.id, resolving them always returns Identical,
    /// and neither lock is mutated to Void.
    #[test]
    fn prop_canonical_resolver_identical_locks(
        parent in arb_hash256(),
        receiver in arb_hash256(),
        nonce in arb_nonce(),
        created_ms in any::<u64>(),
        ttl_ms in 1_000u64..100_000_000u64,
    ) {
        let created_at = SimTime(created_ms);
        let valid_until = SimTime(created_ms.saturating_add(ttl_ms));

        let mut lock_a = LockRecord::new(
            parent,
            receiver,
            nonce,
            created_at,
            valid_until,
        );
        let mut lock_b = lock_a.clone();

        let res = resolve_split_brain(&mut lock_a, &mut lock_b);
        prop_assert_eq!(res, ResolutionResult::Identical);
        prop_assert!(!lock_a.status.is_void());
        prop_assert!(!lock_b.status.is_void());
    }
}

// ---------------------------------------------------------------------------
// Property 2: Equivocation Proof Symmetry & Collision Resistance
// ---------------------------------------------------------------------------

proptest! {
    /// Property 2A: Equivocation Proof Perfect Symmetry
    /// For any random node_id: u16 and random [u8; 32] hashes h1, h2:
    /// create_equivocation_proof(node_id, &h1, &h2) == create_equivocation_proof(node_id, &h2, &h1).
    #[test]
    fn prop_equivocation_proof_symmetry(
        node_id in any::<NodeId>(),
        h1 in arb_hash256(),
        h2 in arb_hash256(),
    ) {
        let proof_fwd = create_equivocation_proof(node_id, &h1, &h2);
        let proof_rev = create_equivocation_proof(node_id, &h2, &h1);
        prop_assert_eq!(proof_fwd, proof_rev, "create_equivocation_proof must be symmetric");
    }

    /// Property 2B: Equivocation Proof Collision Resistance across Node IDs
    /// Different node_ids produce strictly different proof digests.
    #[test]
    fn prop_equivocation_proof_node_id_collision_resistance(
        node_id_a in any::<NodeId>(),
        node_id_b in any::<NodeId>(),
        h1 in arb_hash256(),
        h2 in arb_hash256(),
    ) {
        prop_assume!(node_id_a != node_id_b);

        let proof_a = create_equivocation_proof(node_id_a, &h1, &h2);
        let proof_b = create_equivocation_proof(node_id_b, &h1, &h2);
        prop_assert_ne!(proof_a, proof_b, "different node_ids must produce different equivocation proofs");
    }

    /// Property 2C: Equivocation Proof Collision Resistance across Distinct Hash Sets
    /// Different sets of conflicting hashes {h1, h2} != {h3, h4} produce strictly different digests.
    #[test]
    fn prop_equivocation_proof_hash_set_collision_resistance(
        node_id in any::<NodeId>(),
        h1 in arb_hash256(),
        h2 in arb_hash256(),
        h3 in arb_hash256(),
        h4 in arb_hash256(),
    ) {
        let set_a = if h1 <= h2 { (h1, h2) } else { (h2, h1) };
        let set_b = if h3 <= h4 { (h3, h4) } else { (h4, h3) };
        prop_assume!(set_a != set_b);

        let proof_a = create_equivocation_proof(node_id, &h1, &h2);
        let proof_b = create_equivocation_proof(node_id, &h3, &h4);
        prop_assert_ne!(proof_a, proof_b, "different conflicting hash pairs must produce different equivocation proofs");
    }
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
        min_compat_ver in any::<u8>(),
        reserved in any::<u16>(),
    ) {
        let mut header = WireHeader::new(msg_type, session_seq, epoch_id, flags, payload_len);
        header.crypto_suite = crypto_suite;
        header.min_compat_ver = min_compat_ver;
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
        prop_assert_eq!(decoded.min_compat_ver, min_compat_ver);
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

        let mut current_last_hour = 0u64;

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
