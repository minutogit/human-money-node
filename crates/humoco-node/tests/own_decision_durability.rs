//! Durable original decisions are private node state, independent of merged locks.
use humoco_node::storage::engine::PersistenceStats;
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage, StorageError};
use humoco_sim_core::types::SimTime;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

fn setup_voucher_root(db: &RedbStorage, voucher: &str) {
    let root = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher.to_string(),
        t_id: *blake3::hash(voucher.as_bytes()).as_bytes(),
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("50000".to_string()),
        privacy_guard: None,
    };
    let tag = bs58::encode(root.t_id).into_string();
    db.put_hmc_lock(&tag, &root).unwrap();
}

fn hmc_record(voucher: &str, t_id: u8) -> humoco_node::api::hmc::L2LockEntry {
    humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        layer2_voucher_id: voucher.to_string(),
        t_id: [t_id; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    }
}

#[test]
fn own_choice_survives_merge_restart_and_same_child_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("choices.redb");
    let tag = "spend-tag-1";
    let first = hmc_record("v-1", 2);
    let other = hmc_record("v-1", 3);
    let node = [7; 32];
    {
        let db = RedbStorage::open(&path).unwrap();
        setup_voucher_root(&db, "v-1");
        db.commit_original_approval(tag, &first, &node, b"exact provisional", 0, 50_000)
            .unwrap();
        db.commit_original_approval(tag, &first, &node, b"exact final", 1, 50_000)
            .unwrap();
        // A lawful objective-state merge does not erase private original choices.
        db.put_hmc_lock(tag, &other).unwrap();
    }
    let db = RedbStorage::open(&path).unwrap();
    let choice = db
        .own_signing_choice(&node, tag)
        .unwrap()
        .unwrap();
    assert_eq!(choice.child, first.t_id);
    assert_eq!(
        choice.approvals,
        [
            Some(b"exact provisional".to_vec()),
            Some(b"exact final".to_vec())
        ]
    );
    assert!(matches!(
        db.commit_original_approval(tag, &other, &node, b"conflict", 1, 50_000),
        Err(StorageError::OwnChoiceConflict)
    ));
    assert_eq!(
        db.get_hmc_lock(tag).unwrap().unwrap().t_id,
        other.t_id
    );
    db.prune_expired_buckets(80).unwrap();
    assert!(db
        .own_signing_choice(&node, tag)
        .unwrap()
        .is_some());
    db.prune_expired_buckets(81).unwrap();
    assert!(db
        .own_signing_choice(&node, tag)
        .unwrap()
        .is_none());
}

#[test]
fn consistent_backup_includes_private_own_choices() {
    let dir = tempfile::tempdir().unwrap();
    let db = RedbStorage::open(&dir.path().join("source.redb")).unwrap();
    setup_voucher_root(&db, "v-1");
    let first = hmc_record("v-1", 2);
    let tag = "spend-tag-1";
    db.commit_original_approval(tag, &first, &[7; 32], b"exact", 0, 50_000)
        .unwrap();
    let destination = dir.path().join("backup.redb");
    db.create_backup(&destination).unwrap();
    let restored = RedbStorage::open(&destination).unwrap();
    assert_eq!(
        restored
            .own_signing_choice(&[7; 32], tag)
            .unwrap()
            .unwrap()
            .child,
        first.t_id
    );
}

#[tokio::test]
async fn timed_out_original_keeps_late_commit_and_retry_protection() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("late.redb")).unwrap());
    setup_voucher_root(&db, "v-1");
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(humoco_node::storage::engine::HmcRamIndex::new())),
        db.clone(),
        tx,
    );
    let root = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "v-1".to_string(),
        t_id: *blake3::hash(b"v-1").as_bytes(),
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("50000".to_string()),
        privacy_guard: None,
    };
    let root_tag = bs58::encode(root.t_id).into_string();
    engine.hmc_ram.write().await.insert_recovered(root_tag, root);

    let first = hmc_record("v-1", 2);
    let tag = "spend-tag-1".to_string();
    engine
        .ingress_hmc_lock_with_origin(
            tag.clone(),
            first.clone(),
            IngressOrigin::ClientApi,
            None,
        )
        .await;
    // Worker intentionally not running: no durable result can be announced.
    let result = engine
        .persist_original_approval(
            tag.clone(),
            first.clone(),
            [7; 32],
            b"exact".to_vec(),
            0,
            1_000,
        )
        .await;
    assert!(result.is_err());
    assert!(db
        .own_signing_choice(&[7; 32], &tag)
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
                .own_signing_choice(&[7; 32], &tag)
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
            .persist_original_approval(
                tag.clone(),
                first,
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
        let mut hash = Sha3_256::new();
        hash.update(32u32.to_le_bytes());
        hash.update([1; 32]);
        hash.update(32u32.to_le_bytes());
        hash.update(key.verifying_key().as_bytes());
        hop.ds_tag = Some(bs58::encode(hash.finalize()).into_string());
    }
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: hop.layer2_voucher_id.clone(),
        transaction_id: hop.transaction_hash,
        state_hash: hop.transaction_hash,
        sender_pubkey: hop.sender_ephemeral_pub,
        receiver_pubkey_hash: Some(Sha3_256::digest(key.verifying_key().as_bytes()).into()),
        change_pubkey_hash: None,
        root_valid_until_ms: 50_000,
        is_root: genesis,
        signature: [0; 64],
    };
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
    assert!(db
        .voucher_root(&genesis.layer2_voucher_id)
        .unwrap()
        .is_some());
    assert!(db
        .get_hmc_locks_for_voucher(&genesis.layer2_voucher_id)
        .unwrap()
        .is_empty());
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
        Arc::new(RwLock::new(humoco_node::storage::engine::HmcRamIndex::new())),
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
        while !engine
            .hmc_ram
            .read()
            .await
            .root_anchors()
            .contains_key("prefix-voucher")
        {
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
        setup_voucher_root(&db, "v-1");
        let first = hmc_record("v-1", 2);
        let tag = "spend-tag-1";
        db.commit_original_approval(
            tag,
            &first,
            &[7; 32],
            b"released-original",
            0,
            50_000,
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
        .own_signing_choice(&[7; 32], "spend-tag-1")
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.approvals[0].as_deref(),
        Some(b"released-original".as_slice())
    );
    let other = hmc_record("v-1", 3);
    assert!(matches!(
        db.commit_original_approval("spend-tag-1", &other, &[7; 32], b"contradiction", 0, 50_000),
        Err(StorageError::OwnChoiceConflict)
    ));
}

#[test]
fn ram_expiry_pass_has_a_hard_examined_entry_limit() {
    let mut ram = humoco_node::storage::engine::HmcRamIndex::new();
    let root = humoco_node::api::hmc::L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "test-v".into(),
        t_id: [0x50; 32],
        sender_ephemeral_pub: [0x22; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x33; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some("50000".to_string()),
        privacy_guard: None,
    };
    let root_tag = bs58::encode(root.t_id).into_string();
    ram.insert_recovered(root_tag, root);

    for value in 0..700u32 {
        let entry = humoco_node::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-v".into(),
            t_id: [value as u8; 32],
            sender_ephemeral_pub: [0x22; 32],
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0x33; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 0,
            deletable_at: None,
            privacy_guard: None,
        };
        ram.insert_recovered(format!("tag-{}", value), entry);
    }
    assert_eq!(ram.prune_expired(SimTime(82_000)), 256);
    assert_eq!(ram.len(), 444);
    assert_eq!(ram.prune_expired(SimTime(82_000)), 256);
    assert_eq!(ram.prune_expired(SimTime(82_000)), 188);
    assert!(ram.is_empty());
}
