//! Durable original decisions are private node state, independent of merged locks.
use humoco_node::storage::engine::PersistenceStats;
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage, StorageError};
use humoco_sim_core::{
    storage::RamIndex,
    types::{LockRecord, SimTime},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

fn record(parent: u8, receiver: u8) -> LockRecord {
    LockRecord::new(
        [parent; 32],
        [receiver; 32],
        vec![1, 2, 3],
        SimTime(1_000),
        SimTime(50_000),
    )
}

#[test]
fn own_choice_survives_merge_restart_and_same_child_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("choices.redb");
    let first = record(1, 2);
    let other = record(1, 3);
    let node = [7; 32];
    {
        let db = RedbStorage::open(&path).unwrap();
        db.commit_original_record_approval(&first, 50_000, &node, b"exact provisional", 0)
            .unwrap();
        db.commit_original_record_approval(&first, 50_000, &node, b"exact final", 1)
            .unwrap();
        // A lawful objective-state merge does not erase private original choices.
        db.put_lock(&other, 50_000).unwrap();
    }
    let db = RedbStorage::open(&path).unwrap();
    let choice = db
        .own_signing_choice(&node, &hex::encode(first.parent_lock))
        .unwrap()
        .unwrap();
    assert_eq!(choice.child, first.id);
    assert_eq!(
        choice.approvals,
        [
            Some(b"exact provisional".to_vec()),
            Some(b"exact final".to_vec())
        ]
    );
    assert!(matches!(
        db.commit_original_record_approval(&other, 50_000, &node, b"conflict", 1),
        Err(StorageError::OwnChoiceConflict)
    ));
    assert_eq!(
        db.get_lock(&first.parent_lock).unwrap().unwrap().0.id,
        other.id
    );
    db.prune_expired_buckets(80).unwrap();
    assert!(db
        .own_signing_choice(&node, &hex::encode(first.parent_lock))
        .unwrap()
        .is_some());
    db.prune_expired_buckets(81).unwrap();
    assert!(db
        .own_signing_choice(&node, &hex::encode(first.parent_lock))
        .unwrap()
        .is_none());
}

#[test]
fn consistent_backup_includes_private_own_choices() {
    let dir = tempfile::tempdir().unwrap();
    let db = RedbStorage::open(&dir.path().join("source.redb")).unwrap();
    let first = record(1, 2);
    db.commit_original_record_approval(&first, 50_000, &[7; 32], b"exact", 0)
        .unwrap();
    let destination = dir.path().join("backup.redb");
    db.create_backup(&destination).unwrap();
    let restored = RedbStorage::open(&destination).unwrap();
    assert_eq!(
        restored
            .own_signing_choice(&[7; 32], &hex::encode(first.parent_lock))
            .unwrap()
            .unwrap()
            .child,
        first.id
    );
}

#[tokio::test]
async fn timed_out_original_keeps_late_commit_and_retry_protection() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("late.redb")).unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(RamIndex::new())),
        Arc::new(RwLock::new(humoco_node::storage::HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    let first = record(1, 2);
    engine
        .ingress_lock_with_origin(
            first.clone(),
            SimTime(1_000),
            SimTime(50_000),
            IngressOrigin::ClientApi,
        )
        .await
        .unwrap();
    // Worker intentionally not running: no durable result can be announced.
    let result = engine
        .persist_original_record_approval(
            first.clone(),
            SimTime(50_000),
            [7; 32],
            b"exact".to_vec(),
            0,
            1_000,
        )
        .await;
    assert!(result.is_err());
    assert!(db
        .own_signing_choice(&[7; 32], &hex::encode(first.parent_lock))
        .unwrap()
        .is_none());
    let cancel = CancellationToken::new();
    let worker = DualTierEngine::spawn_flush_worker(
        rx,
        db.clone(),
        Arc::new(PersistenceStats::default()),
        cancel.clone(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if db
                .own_signing_choice(&[7; 32], &hex::encode(first.parent_lock))
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        engine
            .persist_original_record_approval(
                first,
                SimTime(50_000),
                [7; 32],
                b"retry".to_vec(),
                0,
                1_000
            )
            .await
            .unwrap(),
        b"exact"
    );
    cancel.cancel();
    worker.await.unwrap();
}

fn signed_hop(genesis: bool, child: u8, stamp: u128) -> humoco_node::api::hmc::L2LockRequest {
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_node::api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockRequest};
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut hop = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: key.verifying_key().to_bytes(),
            auth_signature: None,
        },
        layer2_voucher_id: "prefix-voucher".into(),
        ds_tag: (!genesis).then(|| "spend-tag".into()),
        transaction_hash: [child; 32],
        is_genesis: genesis,
        sender_ephemeral_pub: key.verifying_key().to_bytes(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: stamp,
        created_at_ms: 1_000,
        deletable_at: genesis.then(|| "50000".into()),
        privacy_guard: None,
    };
    use sha3::{Digest, Sha3_256};
    if !genesis {
        let mut hash = Sha3_256::new(); hash.update(32u32.to_le_bytes()); hash.update([1; 32]); hash.update(32u32.to_le_bytes()); hash.update(key.verifying_key().as_bytes());
        hop.ds_tag = Some(bs58::encode(hash.finalize()).into_string());
    }
    let mut proof = humoco_proto::causal::CausalOutputProof { version: 1, voucher_id: hop.layer2_voucher_id.clone(), transaction_id: hop.transaction_hash, state_hash: hop.transaction_hash, sender_pubkey: hop.sender_ephemeral_pub, receiver_pubkey_hash: Some(Sha3_256::digest(key.verifying_key().as_bytes()).into()), change_pubkey_hash: None, root_valid_until_ms: 50_000, is_root: genesis, signature: [0; 64] };
    proof.signature = key.sign(&proof.digest().unwrap()).to_bytes();
    hop.causal_output = Some(proof);
    hop.layer2_signature = key.sign(&calculate_l2_payload_hash(&hop)).to_bytes();
    hop
}

#[tokio::test]
async fn invalid_suffix_preserves_durable_prefix_and_never_returns_terminal_success() {
    use humoco_node::api::hmc::{L2ChainLockRequest, L2Verdict};
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("prefix.redb")).unwrap());
    let cancel = CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    let genesis = signed_hop(true, 1, 1);
    let mut bad = signed_hop(false, 2, 2);
    bad.layer2_signature = [0; 64];
    let request = L2ChainLockRequest {
        auth: genesis.auth.clone(),
        layer2_voucher_id: genesis.layer2_voucher_id.clone(),
        chain: vec![genesis.clone(), bad],
    };
    let (verdict, changed) = engine
        .ingress_hmc_chain_lock_durable(request, IngressOrigin::ClientApi, Some(1_000))
        .await;
    assert!(matches!(verdict, L2Verdict::Rejected { .. }));
    assert!(changed, "accepted prefix must be reported as progress");
    assert!(db
        .get_hmc_lock(&bs58::encode(genesis.transaction_hash).into_string())
        .unwrap()
        .is_none());
    assert!(db.voucher_root(&genesis.layer2_voucher_id).unwrap().is_some());
    assert!(db.get_hmc_locks_for_voucher(&genesis.layer2_voucher_id).unwrap().is_empty());
    cancel.cancel();
    worker.await.unwrap();
}

#[tokio::test]
async fn identical_pending_root_retries_wait_for_durable_barrier() {
    use humoco_node::api::hmc::{L2LockEntry, L2Verdict};
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("pending.redb")).unwrap());
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(RamIndex::new())),
        Arc::new(RwLock::new(humoco_node::storage::HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    let hop = signed_hop(true, 1, 1);
    let tag = bs58::encode(hop.transaction_hash).into_string();
    let entry = L2LockEntry::from(&hop);
    let submit = |engine: DualTierEngine, tag: String, entry: L2LockEntry| {
        tokio::spawn(async move {
            engine
                .ingress_hmc_lock_durable(
                    tag,
                    entry,
                    IngressOrigin::ClientApi,
                    Some(1_000),
                    None,
                    None,
                    None,
                )
                .await
        })
    };
    let first = submit(engine.clone(), tag.clone(), entry.clone());
    tokio::time::timeout(std::time::Duration::from_millis(100), async {
        while !engine.hmc_ram.read().await.root_anchors.contains_key("prefix-voucher") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let second = submit(engine.clone(), tag.clone(), entry);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!first.is_finished());
    assert!(
        !second.is_finished(),
        "RAM duplicate must not bypass durable acknowledgment"
    );
    assert!(db.get_hmc_lock(&tag).unwrap().is_none());
    let cancel = CancellationToken::new();
    let worker =
        DualTierEngine::spawn_flush_worker(rx, db.clone(), engine.stats.clone(), cancel.clone());
    assert!(matches!(first.await.unwrap().0, L2Verdict::Verified { .. }));
    assert!(matches!(
        second.await.unwrap().0,
        L2Verdict::Verified { .. }
    ));
    assert!(db.get_hmc_lock(&tag).unwrap().is_none());
    assert!(db.voucher_root("prefix-voucher").unwrap().is_some());
    cancel.cancel();
    worker.await.unwrap();
}

#[test]
fn abrupt_process_exit_after_commit_retains_original_choice() {
    const CHILD_PATH: &str = "HUMOCO_TEST_COMMITTED_CHOICE_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let db = RedbStorage::open(std::path::Path::new(&path)).unwrap();
        db.commit_original_record_approval(
            &record(1, 2),
            50_000,
            &[7; 32],
            b"released-original",
            0,
        )
        .unwrap();
        // Immediate exit skips Rust destructors and graceful worker drain.
        // This tests a process crash after commit, not hardware power-loss durability.
        std::process::exit(74);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.redb");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "abrupt_process_exit_after_commit_retains_original_choice",
        ])
        .env(CHILD_PATH, &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(74));
    let db = RedbStorage::open(&path).unwrap();
    let retained = db
        .own_signing_choice(&[7; 32], &hex::encode([1; 32]))
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.approvals[0].as_deref(),
        Some(b"released-original".as_slice())
    );
    assert!(matches!(
        db.commit_original_record_approval(&record(1, 3), 50_000, &[7; 32], b"contradiction", 0),
        Err(StorageError::OwnChoiceConflict)
    ));
}

#[test]
fn ram_expiry_pass_has_a_hard_examined_entry_limit() {
    let mut ram = RamIndex::new();
    for value in 0..700u32 {
        let mut parent = [0; 32];
        parent[..4].copy_from_slice(&value.to_le_bytes());
        let lock = LockRecord::new(parent, [2; 32], vec![], SimTime(1_000), SimTime(50_000));
        ram.insert_recovered(lock, SimTime(50_000));
    }
    assert_eq!(ram.prune_expired_bounded(SimTime(82_000), 256), 256);
    assert_eq!(ram.len(), 444);
    assert_eq!(ram.prune_expired_bounded(SimTime(82_000), 256), 256);
    assert_eq!(ram.prune_expired_bounded(SimTime(82_000), 256), 188);
    assert!(ram.is_empty());
}
