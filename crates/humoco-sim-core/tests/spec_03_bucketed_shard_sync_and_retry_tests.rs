#![forbid(unsafe_code)]

//! Integration and verification tests for 5-minute bucketed shard sync,
//! timestamp determinism, and gateway retry/triple-send invariants.
//!
//! References: docs/PLAN_BUCKETED_SHARD_SYNC.md

use humoco_sim_core::crypto::compute_shard_bucket_digest;
use humoco_sim_core::types::{
    is_bucket_sealed, timestamp_to_bucket_id, BUCKET_DURATION_MS,
    LockRecord, LockStatus, SimTime,
};

fn create_mock_lock(parent: [u8; 32], id: [u8; 32], created_at_ms: u64, valid_until_ms: u64) -> LockRecord {
    LockRecord {
        id,
        parent_lock: parent,
        receiver_pub: [0x42; 32],
        nonce: vec![1, 2, 3],
        created_at: SimTime(created_at_ms),
        valid_until: SimTime(valid_until_ms),
        status: LockStatus::Pending,
        signers: Default::default(),
    }
}

#[test]
fn test_timestamp_to_bucket_id_and_sealing() {
    let t0 = 0u64;
    assert_eq!(timestamp_to_bucket_id(t0), 0);
    assert_eq!(timestamp_to_bucket_id(BUCKET_DURATION_MS - 1), 0);
    assert_eq!(timestamp_to_bucket_id(BUCKET_DURATION_MS), 1);
    assert_eq!(timestamp_to_bucket_id(BUCKET_DURATION_MS * 10 + 500), 10);

    // Sealing check: bucket 0 ends at 300_000ms. With 30_000ms grace, it seals at 330_000ms.
    assert!(!is_bucket_sealed(0, 300_000));
    assert!(!is_bucket_sealed(0, 329_999));
    assert!(is_bucket_sealed(0, 330_000));
    assert!(is_bucket_sealed(0, 500_000));

    // Bucket 1 ends at 600_000ms, seals at 630_000ms.
    assert!(!is_bucket_sealed(1, 629_999));
    assert!(is_bucket_sealed(1, 630_000));
}

#[test]
fn test_bucket_digest_determinism_across_arrival_order() {
    let shard_id = 1u16;
    let mut parent_a = [0u8; 32];
    parent_a[0] = 0;
    parent_a[1] = 1; // shard_id 1
    parent_a[2] = 0xAA;

    let mut parent_b = [0u8; 32];
    parent_b[0] = 0;
    parent_b[1] = 1; // shard_id 1
    parent_b[2] = 0xBB;

    let lock_a = create_mock_lock(parent_a, [0x01; 32], 100_000, 1_000_000);
    let lock_b = create_mock_lock(parent_b, [0x02; 32], 150_000, 1_000_000);

    // Both are in bucket 0 (100_000 / 300_000 = 0)
    let list_1 = vec![lock_a.clone(), lock_b.clone()];
    let list_2 = vec![lock_b.clone(), lock_a.clone()];

    let digest_1 = compute_shard_bucket_digest(shard_id, 0, &list_1);
    let digest_2 = compute_shard_bucket_digest(shard_id, 0, &list_2);

    assert_eq!(digest_1, digest_2, "Bucket digest must be order-invariant (sorted by parent/id)");
}

#[test]
fn test_bucket_isolation_between_time_windows() {
    let shard_id = 0u16;
    let mut parent = [0u8; 32];
    parent[0] = 0;
    parent[1] = 0;

    // Lock in bucket 0 (created at 100_000ms)
    let lock_b0 = create_mock_lock(parent, [0x01; 32], 100_000, 2_000_000);
    // Lock in bucket 1 (created at 350_000ms)
    let lock_b1 = create_mock_lock(parent, [0x02; 32], 350_000, 2_000_000);

    let all_locks = vec![lock_b0.clone(), lock_b1.clone()];

    // Bucket 0 should only contain lock_b0
    let digest_b0_from_all = compute_shard_bucket_digest(shard_id, 0, &all_locks);
    let digest_b0_isolated = compute_shard_bucket_digest(shard_id, 0, &[lock_b0]);
    assert_eq!(digest_b0_from_all, digest_b0_isolated, "Bucket 0 must not be contaminated by Bucket 1 locks");

    // Bucket 1 should only contain lock_b1
    let digest_b1_from_all = compute_shard_bucket_digest(shard_id, 1, &all_locks);
    let digest_b1_isolated = compute_shard_bucket_digest(shard_id, 1, &[lock_b1]);
    assert_eq!(digest_b1_from_all, digest_b1_isolated, "Bucket 1 must not be contaminated by Bucket 0 locks");
}

#[test]
fn test_gateway_retry_payload_identity_invariance() {
    // Verifies that a retry with identical timestamp_ms, epoch_seq and payload
    // produces an exact identical wire payload digest, whereas a mutated timestamp diverges.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let sender_pub = signing_key.verifying_key().to_bytes();
    let op_hash = [0x55; 32];

    let t0 = 1_000_000u64;
    let epoch_day = 12u32;
    let epoch_seq = 42u64;
    let declared_write_ema = 5_000u64;
    let declared_read_ema = 100u64;
    let footprint = 144u64;

    // 1st Send at T0
    let digest_attempt_1 = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pub,
        epoch_day,
        epoch_seq,
        t0,
        declared_write_ema,
        declared_read_ema,
        footprint,
        false,
        &op_hash,
    );

    // 2nd Send (Retry) with IDENTICAL T0
    let digest_retry_identical = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pub,
        epoch_day,
        epoch_seq,
        t0, // Same T0!
        declared_write_ema,
        declared_read_ema,
        footprint,
        false,
        &op_hash,
    );

    assert_eq!(
        digest_attempt_1, digest_retry_identical,
        "Retrying with identical timestamp produces identical cryptographic digest"
    );

    // Forbidden retry: changing timestamp (T0 + 500ms)
    let digest_forbidden_retry = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
        &sender_pub,
        epoch_day,
        epoch_seq,
        t0 + 500, // Regenerated timestamp
        declared_write_ema,
        declared_read_ema,
        footprint,
        false,
        &op_hash,
    );

    assert_ne!(
        digest_attempt_1, digest_forbidden_retry,
        "Regenerating timestamp produces divergent digest and breaks bucket mapping"
    );
}

#[test]
fn test_triple_send_packet_loss_probability_bound() {
    // Mathematical verification of the triple-send heuristic (PLAN_BUCKETED_SHARD_SYNC.md)
    let p_loss = 0.01f64; // 1% packet loss per attempt
    let p_loss_single = p_loss;
    let p_loss_double = p_loss * p_loss;
    let p_loss_triple = p_loss * p_loss * p_loss;

    assert!((p_loss_single - 0.01).abs() < 1e-6);
    assert!((p_loss_double - 0.0001).abs() < 1e-6);
    assert!((p_loss_triple - 0.000001).abs() < 1e-8); // 1 in 1,000,000 (0.0001%)

    let delivery_prob = 1.0 - p_loss_triple;
    assert!(delivery_prob > 0.99999); // > 99.999% delivery guarantee
}
