#![forbid(unsafe_code)]

//! Slice S08 Specification Regression Tests (S08-01 through S08-06).
//!
//! Validates:
//! - S08-01: DualTierStorage recovery restores retained locks within root grace period
//!   without wrongly enforcing the fresh-ingress 30-second lead-time gate.
//! - S08-02: DualRamIndex::promote_to_final non-mutating validation on collision/expiry,
//!   preserves both tiers on error, and promotes retained locks with <30s lead-time.
//! - S08-03: HourlySlottedRingBuffer occupied-slot tracking avoids duplicate count increments
//!   when replacing values in the same hour slot.
//! - S08-04: NetworkThermometer Option<u64> timestamps allow exact 24h half-life decay
//!   from sample at t=0 to query/sample at t=86,400.
//! - S08-05: evaluate_quota_exceeded_claim u128 arithmetic handles u64::MAX without overflow.
//! - S08-06: ConsensusBloomFilter fixed 2048-byte typed array shape with safe TryFrom conversions.
//! - Authentic 14-of-20 EpochCertificate and NewViewCertificate quorum verifications.

use ed25519_dalek::SigningKey;
use humoco_sim_core::ceh::*;
use humoco_sim_core::client_flow::{
    ConsensusBloomFilter, ConsensusBloomFilterError, CONSENSUS_FILTER_BYTES,
};
use humoco_sim_core::quota::{
    evaluate_quota_exceeded_claim, HourlySlottedRingBuffer, NetworkThermometer,
    QuotaPlausibilityVerdict,
};
use humoco_sim_core::storage::{DualRamIndex, DualTierStorage, IngressVerdictLow, LockTier};
use humoco_sim_core::types::{Hash256, HrwRoutingId, LockRecord, NodePubKey, SimTime};

fn generate_keypair(seed: u8) -> (SigningKey, NodePubKey) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();
    (signing_key, pubkey)
}

fn generate_committee(
    start_seed: u8,
) -> (
    [SigningKey; CEH_COMMITTEE_SIZE],
    [NodePubKey; CEH_COMMITTEE_SIZE],
) {
    let mut signers = Vec::with_capacity(CEH_COMMITTEE_SIZE);
    let mut pubkeys = Vec::with_capacity(CEH_COMMITTEE_SIZE);
    for i in 0..CEH_COMMITTEE_SIZE {
        let (sk, pk) = generate_keypair(start_seed.wrapping_add(i as u8));
        signers.push(sk);
        pubkeys.push(pk);
    }
    (
        signers
            .try_into()
            .map_err(|_| ())
            .expect("committee signers"),
        pubkeys
            .try_into()
            .map_err(|_| ())
            .expect("committee pubkeys"),
    )
}

// ---------------------------------------------------------------------------
// S08-01: DualTierStorage recovery without fresh-ingress 30s lead-time gate
// ---------------------------------------------------------------------------

#[test]
fn test_s08_01_dual_tier_storage_recovery_retains_locks_without_lead_time_gate() {
    let mut storage = DualTierStorage::new();
    let parent1: Hash256 = [0x11; 32];
    let parent2: Hash256 = [0x22; 32];

    // rec1: valid_until = 60_000, root_valid_until = 120_000
    // Inserted at t = 0 (lead time is 60s >= 30s, so accepted)
    let rec1 = LockRecord::new(
        parent1,
        [0xAA; 32],
        vec![1],
        SimTime(0),
        SimTime(60_000),
    );
    let insert_res = storage.ingress(rec1.clone(), SimTime(0), SimTime(120_000));
    assert_eq!(insert_res, Ok(IngressVerdictLow::AcceptedNew));

    // Flush WAL to disk
    assert_eq!(storage.persist_flush(), 1);
    assert_eq!(storage.disk_len(), 1);

    // Simulate crash and restart/recovery at t = 40_000 ms.
    // At t = 40_000, rec1 has remaining validity = 20_000 ms (< 30s lead time).
    // Under the old bug, try_insert was invoked during recovery which rejected rec1.
    // Under S08-01, insert_recovered is used and rec1 must be restored into RAM.
    storage.crash();
    assert_eq!(storage.ram_len(), 0);

    storage.recover(SimTime(40_000));
    assert_eq!(
        storage.ram_len(),
        1,
        "Retained lock with <30s remaining must be restored into RAM on recovery"
    );
    assert!(
        storage.ram.get(&parent1).is_some(),
        "parent1 must be present in RAM after recovery"
    );

    // Now test recovery within root grace retention window when voucher is expired:
    // rec2: valid_until = 60_000, root_valid_until = 120_000.
    // Retained until root_valid_until + 30s = 150_000 ms.
    let rec2 = LockRecord::new(
        parent2,
        [0xBB; 32],
        vec![2],
        SimTime(0),
        SimTime(60_000),
    );
    let insert_res2 = storage.ingress(rec2.clone(), SimTime(0), SimTime(120_000));
    assert_eq!(insert_res2, Ok(IngressVerdictLow::AcceptedNew));
    storage.persist_flush();

    // Crash and recover at t = 80_000 ms (rec2.valid_until 60_000 < 80_000, but within 150_000 ms grace)
    storage.crash();
    storage.recover(SimTime(80_000));
    assert_eq!(
        storage.ram_len(),
        2,
        "Expired voucher locks within root retention window must be restored on recovery"
    );
    assert!(storage.ram.get(&parent2).is_some());

    // Beyond root retention threshold (150_001 ms): both locks pruned
    storage.crash();
    storage.recover(SimTime(150_001));
    assert_eq!(
        storage.ram_len(),
        0,
        "Locks past root_valid_until + 30s grace must be pruned on recovery"
    );
}

// ---------------------------------------------------------------------------
// S08-02: DualRamIndex::promote_to_final collision and expiry guards
// ---------------------------------------------------------------------------

#[test]
fn test_s08_02_promote_to_final_non_mutating_collision_and_expiry() {
    let mut dual_ram = DualRamIndex::new();
    let parent: Hash256 = [0x33; 32];
    let now = SimTime(1000);
    let valid_until = SimTime(50_000);
    let root_valid_until = SimTime(100_000);

    // 1. Causal predecessor not final (for non-root)
    let orphan_parent: Hash256 = [0x44; 32];
    let orphan_rec = LockRecord::new(orphan_parent, [0x01; 32], vec![1], now, valid_until);
    dual_ram
        .insert_provisional(orphan_rec.clone(), now, root_valid_until)
        .expect("insert provisional");

    let orphan_res = dual_ram.promote_to_final(&orphan_parent, now, root_valid_until, false);
    assert_eq!(
        orphan_res,
        Err(CehError::CausalPredecessorNotFinal(orphan_parent))
    );
    assert!(
        dual_ram.is_provisional(&orphan_parent),
        "Failed promotion must leave lock in provisional_index"
    );
    assert!(
        !dual_ram.is_final(&orphan_parent),
        "Failed promotion must not mutate final_index"
    );

    // 2. LockExpired: promotion after root prune threshold
    let expired_res = dual_ram.promote_to_final(
        &orphan_parent,
        SimTime(130_001), // root_valid_until(100_000) + 30_000 = 130_000
        root_valid_until,
        true,
    );
    assert_eq!(expired_res, Err(CehError::LockExpired(orphan_parent)));
    assert!(
        dual_ram.is_provisional(&orphan_parent),
        "Expired promotion must leave lock in provisional_index"
    );
    assert!(!dual_ram.is_final(&orphan_parent));

    // 3. LockExpired: rec.valid_until > root_valid_until
    let invalid_time_parent: Hash256 = [0x55; 32];
    let invalid_time_rec = LockRecord::new(
        invalid_time_parent,
        [0x02; 32],
        vec![2],
        now,
        SimTime(200_000), // > root_valid_until
    );
    dual_ram
        .insert_provisional(invalid_time_rec.clone(), now, SimTime(300_000))
        .expect("insert provisional");
    let invalid_time_res =
        dual_ram.promote_to_final(&invalid_time_parent, now, SimTime(150_000), true);
    assert_eq!(
        invalid_time_res,
        Err(CehError::LockExpired(invalid_time_parent))
    );
    assert!(dual_ram.is_provisional(&invalid_time_parent));
    assert!(!dual_ram.is_final(&invalid_time_parent));

    // 4. LockCollision: conflicting lock in final_index with different ID
    let rec_final = LockRecord::new(parent, [0xAA; 32], vec![1], now, valid_until);
    dual_ram
        .insert_final(rec_final.clone(), now, root_valid_until, true)
        .expect("insert final");
    assert!(dual_ram.is_final(&parent));

    // Provisional lock with same parent but different ID
    let rec_prov = LockRecord::new(parent, [0xBB; 32], vec![2], now, valid_until);
    assert_ne!(rec_final.id, rec_prov.id);
    dual_ram
        .insert_provisional(rec_prov.clone(), now, root_valid_until)
        .expect("insert provisional");
    assert!(dual_ram.is_provisional(&parent));

    // Promotion must detect collision, return LockCollision, and NOT overwrite final_index
    let collision_res = dual_ram.promote_to_final(&parent, now, root_valid_until, true);
    assert_eq!(collision_res, Err(CehError::LockCollision(parent)));

    // Verify neither index was modified by the failed promotion
    let final_entry = dual_ram.get(&parent);
    assert_eq!(
        final_entry,
        Some((&rec_final, LockTier::Final)),
        "Final index must not be overwritten on collision"
    );
    assert!(
        dual_ram.is_provisional(&parent),
        "Provisional index must not be removed on collision"
    );

    // 5. Clean promotion of retained lock with < 30s remaining
    let retained_parent: Hash256 = [0x66; 32];
    let retained_rec = LockRecord::new(
        retained_parent,
        [0xCC; 32],
        vec![3],
        SimTime(0),
        SimTime(50_000),
    );
    dual_ram
        .insert_provisional(retained_rec.clone(), SimTime(0), SimTime(100_000))
        .expect("insert provisional");

    // Promote at t = 40_000 ms (remaining valid = 10_000 ms < 30s)
    let promote_ok =
        dual_ram.promote_to_final(&retained_parent, SimTime(40_000), SimTime(100_000), true);
    assert!(
        promote_ok.is_ok(),
        "Retained lock with <30s remaining must promote cleanly"
    );
    assert!(dual_ram.is_final(&retained_parent));
    assert!(!dual_ram.is_provisional(&retained_parent));

    // 6. Idempotent re-promotion with same ID returns Ok
    // Insert into provisional again with the same record
    dual_ram
        .insert_provisional(retained_rec.clone(), SimTime(0), SimTime(100_000))
        .expect("insert provisional");
    let re_promote =
        dual_ram.promote_to_final(&retained_parent, SimTime(40_000), SimTime(100_000), true);
    assert_eq!(re_promote.map(|r| r.id), Ok(retained_rec.id));
    assert!(!dual_ram.is_provisional(&retained_parent));
}

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

// ---------------------------------------------------------------------------
// S08-06: ConsensusBloomFilter fixed 2048-byte typed array shape
// ---------------------------------------------------------------------------

#[test]
fn test_s08_06_consensus_bloom_filter_typed_shape_and_conversions() {
    let filter = ConsensusBloomFilter::new();
    assert_eq!(filter.bits.len(), CONSENSUS_FILTER_BYTES);
    assert_eq!(filter.as_slice().len(), CONSENSUS_FILTER_BYTES);
    assert_eq!(filter.popcount(), 0);

    // TryFrom error on empty slice
    let empty_res = ConsensusBloomFilter::try_from(&[][..]);
    assert_eq!(
        empty_res,
        Err(ConsensusBloomFilterError::InvalidLength {
            expected: CONSENSUS_FILTER_BYTES,
            got: 0,
        })
    );

    // TryFrom error on short slice (100 bytes)
    let short_bytes = vec![0u8; 100];
    let short_res = ConsensusBloomFilter::try_from(short_bytes.as_slice());
    assert_eq!(
        short_res,
        Err(ConsensusBloomFilterError::InvalidLength {
            expected: CONSENSUS_FILTER_BYTES,
            got: 100,
        })
    );

    // TryFrom error on oversized vector (2049 bytes)
    let over_bytes = vec![0u8; 2049];
    let over_res = ConsensusBloomFilter::try_from(over_bytes);
    assert_eq!(
        over_res,
        Err(ConsensusBloomFilterError::InvalidLength {
            expected: CONSENSUS_FILTER_BYTES,
            got: 2049,
        })
    );

    // TryFrom success on exact 2048-byte vector
    let exact_bytes = vec![0xAAu8; CONSENSUS_FILTER_BYTES];
    let exact_res = ConsensusBloomFilter::try_from(exact_bytes.clone());
    assert!(exact_res.is_ok());
    let exact_filter = exact_res.unwrap();
    assert_eq!(exact_filter.as_slice(), exact_bytes.as_slice());

    // Display implementation check
    let err = ConsensusBloomFilterError::InvalidLength {
        expected: 2048,
        got: 42,
    };
    let err_msg = format!("{err}");
    assert!(err_msg.contains("2048"));
    assert!(err_msg.contains("42"));

    // Membership verification
    let mut test_filter = ConsensusBloomFilter::new();
    let hrw_id: HrwRoutingId = [0x55; 32];
    let pub_key: NodePubKey = [0x77; 32];
    let other_hrw_id: HrwRoutingId = [0x99; 32];

    assert!(!test_filter.contains_identity(&hrw_id, &pub_key));
    test_filter.insert_identity(&hrw_id, &pub_key);
    assert!(test_filter.contains_identity(&hrw_id, &pub_key));
    assert!(!test_filter.contains_identity(&other_hrw_id, &pub_key));
    assert!(test_filter.popcount() > 0);
}

// ---------------------------------------------------------------------------
// Authentic 14-of-20 EpochCertificate and NewViewCertificate Quorum Checks
// ---------------------------------------------------------------------------

#[test]
fn test_s08_07_ceh_primitives_authentic_quorums() {
    let (signers, committee) = generate_committee(40);
    let shard_id = 12;
    let epoch = 5;

    // 1. EpochCertificate quorum check (13 fails, 14 succeeds)
    let mut cert = EpochCertificate::new(
        shard_id,
        epoch,
        0,
        [0x01; 32],
        [0x02; 32],
        committee,
    );

    // 13 signatures: sub-quorum
    for sk in signers.iter().take(13) {
        let (pk, sig) = sign_epoch_certificate(sk, &cert);
        cert.add_signature(pk, sig);
    }
    assert_eq!(
        cert.verify(&committee),
        Err(CehError::QuorumNotReached {
            have: 13,
            required: 14
        })
    );

    // 14th signature: quorum reached
    let (pk14, sig14) = sign_epoch_certificate(&signers[13], &cert);
    cert.add_signature(pk14, sig14);
    assert!(cert.verify(&committee).is_ok());

    // 2. NewViewCertificate quorum check (13 fails, 14 succeeds)
    let mut nvc = NewViewCertificate::new(shard_id, epoch, 1);
    for sk in signers.iter().take(13) {
        let rc = sign_round_change(sk, shard_id, epoch, 0, 1, None);
        nvc.add_message(rc);
    }
    assert_eq!(
        verify_new_view_certificate(&nvc, &committee, CEH_BFT_QUORUM),
        Err(CehError::QuorumNotReached {
            have: 13,
            required: 14
        })
    );

    let rc14 = sign_round_change(&signers[13], shard_id, epoch, 0, 1, None);
    nvc.add_message(rc14);
    assert!(verify_new_view_certificate(&nvc, &committee, CEH_BFT_QUORUM).is_ok());
    assert!(nvc.verify(&committee).is_ok());
}
