use humoco_sim_core::crypto::sign_lock_attestation;
use humoco_sim_core::state_machine::{apply_attestation, promote_to_final_if_eligible, StateError};
use humoco_sim_core::types::{LockRecord, LockStatus, SimTime};

#[test]
fn test_lock_lifecycle_provisional_transition_7_nodes() {
    let parent = [0x11; 32];
    let receiver = [0x22; 32];
    let nonce = b"test_salt".to_vec();
    let created = SimTime(0);
    let valid_until = SimTime(10_000);

    let mut record = LockRecord::new(parent, receiver, nonce, created, valid_until);
    assert_eq!(record.status, LockStatus::Pending);

    let active_nodes = 7; // Quorum required = floor(2/3 * 7) + 1 = 4 + 1 = 5

    // Add 4 attestations -> still Pending
    for node_id in 0..4 {
        let att = sign_lock_attestation(node_id, &record.id, &record.parent_lock, SimTime(100 + node_id as u64));
        let status = apply_attestation(&mut record, att, active_nodes).unwrap();
        assert_eq!(status, LockStatus::Pending);
    }

    // 5th attestation reaches quorum -> PROVISIONAL
    let att5 = sign_lock_attestation(4, &record.id, &record.parent_lock, SimTime(200));
    let status5 = apply_attestation(&mut record, att5, active_nodes).unwrap();
    assert_eq!(
        status5,
        LockStatus::Provisional {
            sigs: 5,
            required: 5
        }
    );
    assert!(record.status.is_active());
    assert!(!record.status.is_final());
}

#[test]
fn test_lock_lifecycle_final_transition_20_nodes() {
    let parent = [0x33; 32];
    let receiver = [0x44; 32];
    let nonce = b"final_salt".to_vec();
    let created = SimTime(0);
    let valid_until = SimTime(10_000);

    let mut record = LockRecord::new(parent, receiver, nonce, created, valid_until);
    assert_eq!(record.status, LockStatus::Pending);

    let active_nodes = 20; // Required for FINAL = 14

    for node_id in 0..13 {
        let att = sign_lock_attestation(node_id, &record.id, &record.parent_lock, SimTime(100 + node_id as u64));
        let status = apply_attestation(&mut record, att, active_nodes).unwrap();
        assert_eq!(status, LockStatus::Pending);
    }

    // 14th attestation -> FINAL
    let att14 = sign_lock_attestation(13, &record.id, &record.parent_lock, SimTime(300));
    let status14 = apply_attestation(&mut record, att14, active_nodes).unwrap();
    assert_eq!(status14, LockStatus::Final { sigs: 14 });
    assert!(record.status.is_final());
}

#[test]
fn test_lock_promotion_from_provisional_to_final() {
    let parent = [0x55; 32];
    let receiver = [0x66; 32];
    let nonce = b"upgrade_salt".to_vec();
    let mut record = LockRecord::new(parent, receiver, nonce, SimTime(0), SimTime(10_000));

    // Phase 1: Small village net (N=10, Quorum = 7)
    let active_nodes_village = 10;
    for node_id in 0..7 {
        let att = sign_lock_attestation(node_id, &record.id, &record.parent_lock, SimTime(50 * node_id as u64));
        apply_attestation(&mut record, att, active_nodes_village).unwrap();
    }
    assert_eq!(
        record.status,
        LockStatus::Provisional {
            sigs: 7,
            required: 7
        }
    );

    // Merge into World Net (N=20). More nodes attest to reach 14
    let active_nodes_world = 20;
    for node_id in 7..14 {
        let att = sign_lock_attestation(node_id, &record.id, &record.parent_lock, SimTime(50 * node_id as u64));
        apply_attestation(&mut record, att, active_nodes_world).unwrap();
    }

    let promoted = promote_to_final_if_eligible(&mut record, active_nodes_world).unwrap();
    assert!(promoted);
    assert_eq!(record.status, LockStatus::Final { sigs: 14 });
    assert!(record.status.is_final());
}

#[test]
fn test_reject_duplicate_attestation_and_expired_lock() {
    let parent = [0x77; 32];
    let receiver = [0x88; 32];
    let mut record = LockRecord::new(parent, receiver, vec![], SimTime(0), SimTime(500));

    let att1 = sign_lock_attestation(1, &record.id, &record.parent_lock, SimTime(100));
    apply_attestation(&mut record, att1.clone(), 10).unwrap();

    // Duplicate
    let err_dup = apply_attestation(&mut record, att1, 10).unwrap_err();
    assert_eq!(err_dup, StateError::DuplicateAttestation { node_id: 1 });

    // Expired
    let att_expired = sign_lock_attestation(2, &record.id, &record.parent_lock, SimTime(600));
    let err_exp = apply_attestation(&mut record, att_expired, 10).unwrap_err();
    assert!(matches!(err_exp, StateError::LockExpired { .. }));
}
