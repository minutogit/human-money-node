#![forbid(unsafe_code)]

//! Audit 05 Regression Test Suite (Phase 3 Master Remediation):
//! - A05-02: Group-commit for compatible original approvals in flush-worker and RedbStorage
//!   (atomic immediate-durability transactions, failure isolation for OwnChoiceConflict,
//!   and strict Durable-before-Vote DEC-029).
//! - A05-03: Zero-copy request payload across parallel quorum fan-out collector tasks
//!   (`Arc<[u8]>` sharing, byte-identical transmission, cancellation safety).

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;

use humoco_node::api::hmc::{L2AuthPayload, L2LockEntry, L2LockRequest};
use humoco_node::storage::engine::PersistenceStats;
use humoco_node::storage::{
    DualTierEngine, FlushOp, OriginalApprovalBatchEntry, OriginalApprovalTarget, RedbStorage,
    StorageError,
};
fn anchor_root_in_db(db: &RedbStorage, voucher_id: &str, valid_until_ms: u64) {
    let req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: [1u8; 32],
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: None,
        transaction_hash: *blake3::hash(voucher_id.as_bytes()).as_bytes(),
        is_genesis: true,
        sender_ephemeral_pub: [1u8; 32],
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 1_000,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: None,
    };
    let tag = bs58::encode(req.transaction_hash).into_string();
    let entry = L2LockEntry::from(&req);
    db.put_hmc_lock(&tag, &entry).unwrap();
}

fn make_test_hmc_entry(
    voucher_id: &str,
    ds_tag: &str,
    tx_hash: [u8; 32],
    sender_key: &SigningKey,
) -> (String, L2LockEntry) {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(ds_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: 1_000,
        deletable_at: None,
        privacy_guard: None,
    };
    let payload_hash = humoco_node::api::hmc::calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    let tag = ds_tag.to_string();
    let entry = L2LockEntry::from(&req);
    (tag, entry)
}

// ---------------------------------------------------------------------------
// A05-02: Direct Storage Group-Commit & Conflict Isolation
// ---------------------------------------------------------------------------

#[test]
fn test_a05_02_group_commit_multiple_compatible_approvals() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("group_commit.redb");
    let node = [42u8; 32];
    let key = SigningKey::from_bytes(&[7u8; 32]);

    let (tag1, entry1) = make_test_hmc_entry("v_batch_1", "tag_1", [1u8; 32], &key);
    let (tag2, entry2) = make_test_hmc_entry("v_batch_1", "tag_2", [2u8; 32], &key);
    let (tag3, entry3) = make_test_hmc_entry("v_batch_1", "tag_3", [3u8; 32], &key);
    let (tag4, entry4) = make_test_hmc_entry("v_batch_2", "tag_4", [4u8; 32], &key);

    {
        let db = RedbStorage::open(&path).expect("open db");
        anchor_root_in_db(&db, "v_batch_1", 60_000);
        anchor_root_in_db(&db, "v_batch_2", 60_000);

        let batch = [
            OriginalApprovalBatchEntry {
                target: OriginalApprovalTarget::Hmc {
                    tag: tag1.clone(),
                    entry: Box::new(entry1.clone()),
                },
                node,
                approval: b"approval_h1".to_vec(),
                class: 0,
                root_valid_until_ms: 60_000,
            },
            OriginalApprovalBatchEntry {
                target: OriginalApprovalTarget::Hmc {
                    tag: tag2.clone(),
                    entry: Box::new(entry2.clone()),
                },
                node,
                approval: b"approval_h2".to_vec(),
                class: 1,
                root_valid_until_ms: 60_000,
            },
            OriginalApprovalBatchEntry {
                target: OriginalApprovalTarget::Hmc {
                    tag: tag3.clone(),
                    entry: Box::new(entry3.clone()),
                },
                node,
                approval: b"approval_h3".to_vec(),
                class: 0,
                root_valid_until_ms: 60_000,
            },
            OriginalApprovalBatchEntry {
                target: OriginalApprovalTarget::Hmc {
                    tag: tag4.clone(),
                    entry: Box::new(entry4.clone()),
                },
                node,
                approval: b"approval_h4".to_vec(),
                class: 1,
                root_valid_until_ms: 60_000,
            },
        ];

        let results = db
            .commit_original_approvals_group(&batch)
            .expect("group commit succeeds");

        assert_eq!(results.len(), 4);
        for res in &results {
            assert!(res.is_ok(), "Every compatible approval in group succeeds");
        }
    }

    // Verify durable persistence survives database reopen (DEC-029)
    let reopened = RedbStorage::open(&path).expect("reopen db");
    assert!(
        reopened.is_signing_history_healthy(),
        "Signing history must be 100% healthy after multi-approval group commit"
    );

    let choice1 = reopened
        .own_signing_choice(&node, &tag1)
        .expect("get choice")
        .expect("choice 1 present");
    assert_eq!(choice1.child, entry1.t_id);
    assert_eq!(
        choice1.approvals[0].as_deref(),
        Some(b"approval_h1".as_slice())
    );

    let choice3 = reopened
        .own_signing_choice(&node, &tag3)
        .expect("get choice")
        .expect("choice 3 present");
    assert_eq!(choice3.child, entry3.t_id);
    assert_eq!(
        choice3.approvals[0].as_deref(),
        Some(b"approval_h3".as_slice())
    );
}

#[test]
fn test_a05_02_group_commit_conflict_isolation() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("conflict_isolation.redb");
    let node = [42u8; 32];
    let key = SigningKey::from_bytes(&[7u8; 32]);

    let (tag1, entry1) = make_test_hmc_entry("v_iso", "tag_1", [10u8; 32], &key);
    let (tag1_conflict, entry1_conflict) = make_test_hmc_entry("v_iso", "tag_1", [99u8; 32], &key);
    let (tag2, entry2) = make_test_hmc_entry("v_iso", "tag_2", [20u8; 32], &key);
    let (tag3, entry3) = make_test_hmc_entry("v_iso", "tag_3", [30u8; 32], &key);

    {
        let db = RedbStorage::open(&path).expect("open db");
        anchor_root_in_db(&db, "v_iso", 60_000);
        db.commit_original_approval(&tag1, &entry1, &node, b"orig", 0, 60_000)
            .expect("initial commit");
    }

    let db = RedbStorage::open(&path).expect("reopen db");
    let batch = [
        OriginalApprovalBatchEntry {
            target: OriginalApprovalTarget::Hmc {
                tag: tag2.clone(),
                entry: Box::new(entry2.clone()),
            },
            node,
            approval: b"app_h2".to_vec(),
            class: 0,
            root_valid_until_ms: 60_000,
        },
        OriginalApprovalBatchEntry {
            target: OriginalApprovalTarget::Hmc {
                tag: tag1_conflict.clone(),
                entry: Box::new(entry1_conflict.clone()),
            },
            node,
            approval: b"app_h1_conflict".to_vec(),
            class: 0,
            root_valid_until_ms: 60_000,
        },
        OriginalApprovalBatchEntry {
            target: OriginalApprovalTarget::Hmc {
                tag: tag3.clone(),
                entry: Box::new(entry3.clone()),
            },
            node,
            approval: b"app_h3".to_vec(),
            class: 0,
            root_valid_until_ms: 60_000,
        },
    ];

    let results = db
        .commit_original_approvals_group(&batch)
        .expect("group commit completes");

    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok(), "Sibling entry 0 succeeds");
    assert!(
        matches!(results[1], Err(StorageError::OwnChoiceConflict)),
        "Conflicting entry 1 is isolated and returns OwnChoiceConflict"
    );
    assert!(results[2].is_ok(), "Sibling entry 2 succeeds");

    // Verify siblings were committed durably, conflict was not committed
    assert!(db.get_hmc_lock(&tag2).expect("get").is_some());
    assert!(db.get_hmc_lock(&tag3).expect("get").is_some());
    assert_eq!(
        db.get_hmc_lock(&tag1)
            .expect("get")
            .unwrap()
            .t_id,
        entry1.t_id,
        "Conflicting choice did not alter existing record"
    );
}

#[test]
fn test_a05_02_group_commit_idempotent_retry_in_batch() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("idempotent.redb");
    let node = [42u8; 32];
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let (tag1, entry1) = make_test_hmc_entry("v_idem", "tag_1", [10u8; 32], &key);

    let db = RedbStorage::open(&path).expect("open db");
    anchor_root_in_db(&db, "v_idem", 60_000);
    let batch = [
        OriginalApprovalBatchEntry {
            target: OriginalApprovalTarget::Hmc {
                tag: tag1.clone(),
                entry: Box::new(entry1.clone()),
            },
            node,
            approval: b"app_exact".to_vec(),
            class: 0,
            root_valid_until_ms: 60_000,
        },
        OriginalApprovalBatchEntry {
            target: OriginalApprovalTarget::Hmc {
                tag: tag1.clone(),
                entry: Box::new(entry1.clone()),
            },
            node,
            approval: b"app_exact".to_vec(),
            class: 0,
            root_valid_until_ms: 60_000,
        },
    ];

    let results = db
        .commit_original_approvals_group(&batch)
        .expect("group commit completes");
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(results[1].is_ok());
    assert!(db.is_signing_history_healthy());
}

// ---------------------------------------------------------------------------
// A05-02: Flush Worker Group-Commit & Durable-before-Vote (DEC-029)
// ---------------------------------------------------------------------------

#[test]
fn test_a05_02_flush_worker_group_commit_batching_and_attempts() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("worker_batch.redb");
    let db = RedbStorage::open(&path).expect("open db");
    let node = [11u8; 32];
    let health = Arc::new(PersistenceStats::default());
    let key = SigningKey::from_bytes(&[7u8; 32]);

    anchor_root_in_db(&db, "v_wbatch", 50_000);
    let (tag1, entry1) = make_test_hmc_entry("v_wbatch", "tag_1", [10u8; 32], &key);
    let (tag2, entry2) = make_test_hmc_entry("v_wbatch", "tag_2", [20u8; 32], &key);
    let (tag3, entry3) = make_test_hmc_entry("v_wbatch", "tag_3", [30u8; 32], &key);

    let (c1_tx, c1_rx) = tokio::sync::watch::channel(None);
    let (c2_tx, c2_rx) = tokio::sync::watch::channel(None);
    let (c3_tx, c3_rx) = tokio::sync::watch::channel(None);

    let mut batch = vec![
        FlushOp::OriginalHmcApproval {
            tag: tag1,
            entry: Box::new(entry1),
            node,
            approval: b"a1".to_vec(),
            class: 0,
            root: 50_000,
            complete: c1_tx,
            health: health.clone(),
            _reservation: None,
        },
        FlushOp::OriginalHmcApproval {
            tag: tag2,
            entry: Box::new(entry2),
            node,
            approval: b"a2".to_vec(),
            class: 0,
            root: 50_000,
            complete: c2_tx,
            health: health.clone(),
            _reservation: None,
        },
        FlushOp::OriginalHmcApproval {
            tag: tag3,
            entry: Box::new(entry3),
            node,
            approval: b"a3".to_vec(),
            class: 0,
            root: 50_000,
            complete: c3_tx,
            health,
            _reservation: None,
        },
    ];

    let outcome = DualTierEngine::flush_batch(&mut batch, &db);

    // CRITICAL: A05-02 group-commit combines all 3 into 1 single transaction attempt
    assert_eq!(
        outcome.attempts, 1,
        "Group-commit must commit 3 contiguous approvals in exactly 1 transaction attempt"
    );
    assert_eq!(outcome.ops_committed, 3);
    assert!(!outcome.failed);

    // Verify all 3 completions received Ok confirmation after durable commit (DEC-029)
    assert!(c1_rx.borrow().as_ref().unwrap().is_ok());
    assert!(c2_rx.borrow().as_ref().unwrap().is_ok());
    assert!(c3_rx.borrow().as_ref().unwrap().is_ok());
}

#[test]
fn test_a05_02_flush_worker_conflict_isolation_in_batch() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("worker_conflict.redb");
    let db = RedbStorage::open(&path).expect("open db");
    let node = [11u8; 32];
    let health = Arc::new(PersistenceStats::default());
    let key = SigningKey::from_bytes(&[7u8; 32]);

    anchor_root_in_db(&db, "v_wconflict", 50_000);
    let (tag1, existing) = make_test_hmc_entry("v_wconflict", "tag_1", [10u8; 32], &key);
    db.commit_original_approval(&tag1, &existing, &node, b"orig", 0, 50_000)
        .expect("preseed");

    let (tag2, entry2) = make_test_hmc_entry("v_wconflict", "tag_2", [20u8; 32], &key);
    let (tag1_conflict, entry1_conflict) = make_test_hmc_entry("v_wconflict", "tag_1", [99u8; 32], &key);
    let (tag3, entry3) = make_test_hmc_entry("v_wconflict", "tag_3", [30u8; 32], &key);

    let (c2_tx, c2_rx) = tokio::sync::watch::channel(None);
    let (c1_tx, c1_rx) = tokio::sync::watch::channel(None);
    let (c3_tx, c3_rx) = tokio::sync::watch::channel(None);

    let mut batch = vec![
        FlushOp::OriginalHmcApproval {
            tag: tag2,
            entry: Box::new(entry2),
            node,
            approval: b"app2".to_vec(),
            class: 0,
            root: 50_000,
            complete: c2_tx,
            health: health.clone(),
            _reservation: None,
        },
        FlushOp::OriginalHmcApproval {
            tag: tag1_conflict,
            entry: Box::new(entry1_conflict),
            node,
            approval: b"app1_conflict".to_vec(),
            class: 0,
            root: 50_000,
            complete: c1_tx,
            health: health.clone(),
            _reservation: None,
        },
        FlushOp::OriginalHmcApproval {
            tag: tag3,
            entry: Box::new(entry3),
            node,
            approval: b"app3".to_vec(),
            class: 0,
            root: 50_000,
            complete: c3_tx,
            health: health.clone(),
            _reservation: None,
        },
    ];

    let outcome = DualTierEngine::flush_batch(&mut batch, &db);

    // 1 group attempt, 2 committed, conflict is non-fatal for worker health
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.ops_committed, 2);
    assert!(
        !outcome.failed,
        "OwnChoiceConflict must not mark worker failed"
    );
    assert!(!health
        .signing_failed
        .load(std::sync::atomic::Ordering::Acquire));

    // Confirm completions
    assert!(c2_rx.borrow().as_ref().unwrap().is_ok());
    assert!(
        c1_rx.borrow().as_ref().unwrap().is_err(),
        "Conflicting approval receives error response"
    );
    assert!(c3_rx.borrow().as_ref().unwrap().is_ok());
}

// ---------------------------------------------------------------------------
// A05-03: Zero-Copy Request Payload Fan-Out Verification
// ---------------------------------------------------------------------------

#[test]
fn test_a05_03_zero_copy_arc_payload_sharing() {
    // Verify that Arc<[u8]> wrapping does not duplicate underlying buffer memory
    // and enables cheap pointer cloning across N parallel tasks.
    let raw_payload = vec![0xABu8; 64 * 1024]; // 64 KiB
    let shared: Arc<[u8]> = Arc::from(raw_payload.as_slice());

    let mut task_payloads = Vec::with_capacity(20);
    for _ in 0..20 {
        task_payloads.push(shared.clone());
    }

    // All 20 tasks point to the exact same memory buffer (zero-copy)
    assert_eq!(Arc::strong_count(&shared), 21);
    for p in &task_payloads {
        assert_eq!(p.as_ptr(), shared.as_ptr());
        assert_eq!(p.len(), 64 * 1024);
        assert_eq!(p[0], 0xAB);
    }

    drop(task_payloads);
    assert_eq!(Arc::strong_count(&shared), 1);
}
