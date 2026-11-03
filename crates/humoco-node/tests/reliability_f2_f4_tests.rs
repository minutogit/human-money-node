#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::{mpsc, RwLock};

use humoco_node::api::hmc::{
    calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest, L2Verdict,
};
use humoco_node::storage::db::RedbStorage;
use humoco_node::storage::engine::{DualTierEngine, HmcRamIndex, IngressOrigin};
use humoco_sim_core::types::SimTime;

fn make_test_genesis(
    voucher_id: &str,
    tx_hash: [u8; 32],
    valid_until: u64,
    key: &SigningKey,
) -> L2LockEntry {
    let pubkey = key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: pubkey,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: pubkey,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: 1000,
        deletable_at: Some(valid_until.to_string()),
        privacy_guard: Some("none".into()),
    };
    let hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = key.sign(&hash).to_bytes();
    L2LockEntry::from(&req)
}

fn make_test_spend(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    valid_until: u64,
    key: &SigningKey,
) -> L2LockEntry {
    let pubkey = key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: pubkey,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(parent_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: pubkey,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: 1000,
        deletable_at: Some(valid_until.to_string()),
        privacy_guard: Some("none".into()),
    };
    let hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = key.sign(&hash).to_bytes();
    L2LockEntry::from(&req)
}

/// 1. `cancelled_request_still_publishes_late_commit`:
/// Queue spend via `ingress_hmc_lock_durable`, receive `op` on `rx`, abort the spawned
/// ingress task, run `DualTierEngine::flush_batch` via `spawn_blocking`, verify `!outcome.failed`,
/// `engine.is_hmc_entry_durable("parent-A", &spend, root).await == true`, and
/// `engine.hmc_ram.read().await.query_status("voucher-A", "parent-A", &[])` returns `L2Verdict::Verified`.
#[tokio::test]
async fn cancelled_request_still_publishes_late_commit() {
    let dir = tempdir().expect("tempdir");
    let db = Arc::new(RedbStorage::open(&dir.path().join("test_f2_1.redb")).expect("open redb"));
    let (tx, mut rx) = mpsc::channel(100);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );

    let key = SigningKey::from_bytes(&[1u8; 32]);
    let root_valid_until = 100_000u64;
    let gen_entry = make_test_genesis("voucher-A", [10u8; 32], root_valid_until, &key);
    let gen_tag = bs58::encode(gen_entry.t_id).into_string();

    let (verdict, _) = engine
        .ingress_hmc_lock(gen_tag.clone(), gen_entry.clone())
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));
    let root_op = rx.recv().await.expect("genesis flush op");
    let db_clone = db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut batch = vec![root_op];
        DualTierEngine::flush_batch(&mut batch, &db_clone)
    })
    .await
    .expect("flush genesis");
    assert!(!outcome.failed);

    let spend = make_test_spend("voucher-A", "parent-A", [11u8; 32], root_valid_until, &key);

    let engine_clone = engine.clone();
    let spend_clone = spend.clone();
    let ingress_task = tokio::spawn(async move {
        engine_clone
            .ingress_hmc_lock_durable(
                "parent-A".to_string(),
                spend_clone,
                IngressOrigin::ClientApi,
                None,
                None,
                None,
                Some("voucher-A".to_string()),
            )
            .await
    });

    let op = rx.recv().await.expect("spend flush op");
    ingress_task.abort();

    let db_clone = db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut batch = vec![op];
        DualTierEngine::flush_batch(&mut batch, &db_clone)
    })
    .await
    .expect("flush spend");

    assert!(!outcome.failed);
    assert!(
        engine
            .is_hmc_entry_durable("parent-A", &spend, root_valid_until)
            .await,
        "Spend must be published durable in RAM even when original ingress future was cancelled"
    );
    let status = engine
        .hmc_ram
        .read()
        .await
        .query_status("voucher-A", "parent-A", &[]);
    assert!(
        matches!(status, L2Verdict::Verified { .. }),
        "Status query must return Verified for late committed spend"
    );
}

/// 2. `cancelled_request_late_commit_does_not_authorize_intervening_replacement`:
/// If `hmc_ram` replaces the entry at `"parent-A"` (e.g. higher confirmation class displacement)
/// before the late `flush_batch` finishes, the late commit of the old entry MUST NOT mark
/// the replacement entry durable.
#[tokio::test]
async fn cancelled_request_late_commit_does_not_authorize_intervening_replacement() {
    let dir = tempdir().expect("tempdir");
    let db = Arc::new(RedbStorage::open(&dir.path().join("test_f2_2.redb")).expect("open redb"));
    let (tx, mut rx) = mpsc::channel(100);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );

    let key1 = SigningKey::from_bytes(&[1u8; 32]);
    let key2 = SigningKey::from_bytes(&[2u8; 32]);
    let root_valid_until = 100_000u64;
    let gen_entry = make_test_genesis("voucher-A", [10u8; 32], root_valid_until, &key1);
    let gen_tag = bs58::encode(gen_entry.t_id).into_string();

    let (verdict, _) = engine
        .ingress_hmc_lock(gen_tag.clone(), gen_entry.clone())
        .await;
    assert!(matches!(verdict, L2Verdict::Verified { .. }));
    let root_op = rx.recv().await.expect("genesis flush op");
    let db_clone = db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut batch = vec![root_op];
        DualTierEngine::flush_batch(&mut batch, &db_clone)
    })
    .await
    .expect("flush genesis");
    assert!(!outcome.failed);

    let spend_1 = make_test_spend("voucher-A", "parent-A", [11u8; 32], root_valid_until, &key1);
    let spend_2 = make_test_spend("voucher-A", "parent-A", [12u8; 32], root_valid_until, &key2);

    let engine_clone = engine.clone();
    let spend_1_clone = spend_1.clone();
    let ingress_task = tokio::spawn(async move {
        engine_clone
            .ingress_hmc_lock_durable(
                "parent-A".to_string(),
                spend_1_clone,
                IngressOrigin::ClientApi,
                None,
                None,
                None,
                Some("voucher-A".to_string()),
            )
            .await
    });

    let op1 = rx.recv().await.expect("spend_1 flush op");
    ingress_task.abort();

    // Intervening replacement: spend_2 displaces spend_1 in RAM with higher confirmation class (class 2 = Final)
    {
        let mut ram = engine.hmc_ram.write().await;
        let (verdict, _) = ram.insert_or_check_with_class(
            "parent-A".to_string(),
            spend_2.clone(),
            IngressOrigin::PartitionSync,
            None,
            2,
        );
        assert!(matches!(verdict, L2Verdict::Verified { .. }));
    }

    // Now late flush of op1 (which was for spend_1) commits to disk
    let db_clone = db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut batch = vec![op1];
        DualTierEngine::flush_batch(&mut batch, &db_clone)
    })
    .await
    .expect("flush spend_1 late");
    assert!(!outcome.failed);

    // CRITICAL: The late commit of spend_1 MUST NOT mark the replacement spend_2 durable!
    assert!(
        !engine
            .is_hmc_entry_durable("parent-A", &spend_2, root_valid_until)
            .await,
        "Replacement entry spend_2 must NOT be marked durable by the late commit of spend_1"
    );
    // And spend_1 is not active in RAM, so it is not durable either
    assert!(
        !engine
            .is_hmc_entry_durable("parent-A", &spend_1, root_valid_until)
            .await,
        "Displaced entry spend_1 must NOT be marked durable"
    );
}

/// 3. `failed_commit_never_marks_entry_durable`:
/// When `flush_batch` fails to commit (e.g., spend for a voucher whose root is missing on disk
/// so `apply_flush_batch_atomic` fails after retries), `is_hmc_entry_durable` remains `false`.
#[tokio::test]
async fn failed_commit_never_marks_entry_durable() {
    let dir = tempdir().expect("tempdir");
    let db = Arc::new(RedbStorage::open(&dir.path().join("test_f2_3.redb")).expect("open redb"));
    let (tx, mut rx) = mpsc::channel(100);
    let engine = DualTierEngine::from_parts(
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx,
    );

    let key = SigningKey::from_bytes(&[3u8; 32]);
    let root_valid_until = 100_000u64;

    // Anchor voucher root ONLY in RAM, NOT on disk in RedbStorage TABLE_VOUCHER_ROOTS
    engine
        .hmc_ram
        .write()
        .await
        .insert_voucher_root_for_test("voucher-missing".to_string(), root_valid_until);

    let spend = make_test_spend(
        "voucher-missing",
        "parent-missing",
        [21u8; 32],
        root_valid_until,
        &key,
    );

    let engine_clone = engine.clone();
    let spend_clone = spend.clone();
    let ingress_task = tokio::spawn(async move {
        engine_clone
            .ingress_hmc_lock_durable(
                "parent-missing".to_string(),
                spend_clone,
                IngressOrigin::ClientApi,
                None,
                None,
                None,
                Some("voucher-missing".to_string()),
            )
            .await
    });

    let op = rx.recv().await.expect("spend flush op");
    ingress_task.abort();

    // flush_batch fails because the voucher root is missing on disk in redb
    let db_clone = db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut batch = vec![op];
        DualTierEngine::flush_batch(&mut batch, &db_clone)
    })
    .await
    .expect("flush task");

    assert!(
        outcome.failed,
        "Flush outcome must be failed when root anchor is missing on disk"
    );
    assert!(
        !engine
            .is_hmc_entry_durable("parent-missing", &spend, root_valid_until)
            .await,
        "Failed commit must NEVER mark entry durable in RAM"
    );
}

/// 4. `status_never_returns_another_vouchers_entry`:
/// Populate `voucher-A` (root only or root + own spend) and `voucher-B` (root + `"parent-B"` spend),
/// recover from disk, verify `query_status("voucher-A", "parent-B", &[])` does NOT return `Verified`.
#[tokio::test]
async fn status_never_returns_another_vouchers_entry() {
    let dir = tempdir().expect("tempdir");
    let db = Arc::new(RedbStorage::open(&dir.path().join("test_f4.redb")).expect("open redb"));

    let key_a = SigningKey::from_bytes(&[10u8; 32]);
    let key_b = SigningKey::from_bytes(&[11u8; 32]);
    let root_valid_until = 100_000u64;

    // 1. Genesis A
    let gen_entry_a = make_test_genesis("voucher-A", [0x01; 32], root_valid_until, &key_a);
    let gen_tag_a = bs58::encode(gen_entry_a.t_id).into_string();
    db.put_hmc_lock(&gen_tag_a, &gen_entry_a)
        .expect("anchor gen_a");

    // 2. Genesis B and Spend B
    let gen_entry_b = make_test_genesis("voucher-B", [0x02; 32], root_valid_until, &key_b);
    let gen_tag_b = bs58::encode(gen_entry_b.t_id).into_string();
    db.put_hmc_lock(&gen_tag_b, &gen_entry_b)
        .expect("anchor gen_b");

    let spend_b = make_test_spend(
        "voucher-B",
        "parent-B",
        [0x03; 32],
        root_valid_until,
        &key_b,
    );
    db.put_hmc_lock("parent-B", &spend_b).expect("put spend_b");

    // Test Case 4a: voucher-A has root anchor only (no spends in vouchers yet)
    let (tx_a, _rx_a) = mpsc::channel(16);
    let engine_a = DualTierEngine::from_parts(
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx_a,
    );
    engine_a
        .recover_from_disk(SimTime(1000))
        .await
        .expect("recover");

    {
        let ram_a = engine_a.hmc_ram.read().await;
        // Direct query of voucher-A with parent-B (from voucher-B) MUST NOT return Verified
        let status = ram_a.query_status("voucher-A", "parent-B", &[]);
        assert!(
            !matches!(status, L2Verdict::Verified { .. }),
            "query_status for voucher-A with parent-B must NOT return Verified when voucher-A only has root anchor, got: {:?}",
            status
        );
        // Direct query of voucher-B with parent-B MUST return Verified
        let status_b = ram_a.query_status("voucher-B", "parent-B", &[]);
        assert!(
            matches!(status_b, L2Verdict::Verified { .. }),
            "query_status for voucher-B with parent-B must return Verified"
        );
        // Unknown voucher must return UnknownVoucher
        let status_unknown = ram_a.query_status("voucher-unknown", "parent-B", &[]);
        assert!(matches!(status_unknown, L2Verdict::UnknownVoucher));
    }

    // Test Case 4b: voucher-A ALSO has its own spend "parent-A1"
    let spend_a1 = make_test_spend(
        "voucher-A",
        "parent-A1",
        [0x04; 32],
        root_valid_until,
        &key_a,
    );
    db.put_hmc_lock("parent-A1", &spend_a1)
        .expect("put spend_a1");

    let (tx_b, _rx_b) = mpsc::channel(16);
    let engine_b = DualTierEngine::from_parts(
        Arc::new(RwLock::new(HmcRamIndex::new())),
        db.clone(),
        tx_b,
    );
    engine_b
        .recover_from_disk(SimTime(1000))
        .await
        .expect("recover");

    {
        let ram_b = engine_b.hmc_ram.read().await;
        // Querying voucher-A with foreign parent-B MUST NOT return Verified!
        let status = ram_b.query_status("voucher-A", "parent-B", &[]);
        assert!(
            !matches!(status, L2Verdict::Verified { .. }),
            "query_status for voucher-A with parent-B must NOT return Verified when voucher-A has own spends, got: {:?}",
            status
        );

        // Querying voucher-A with its own spend "parent-A1" MUST return Verified
        let status_own = ram_b.query_status("voucher-A", "parent-A1", &[]);
        assert!(
            matches!(status_own, L2Verdict::Verified { .. }),
            "query_status for voucher-A with its own spend parent-A1 must return Verified"
        );

        // Querying voucher-A with locator prefix for "parent-A1" must match MissingLocks { sync_point }
        let prefix = "parent-A"[..8].to_string();
        let status_locator = ram_b.query_status(
            "voucher-A",
            "non-existent-challenge",
            std::slice::from_ref(&prefix),
        );
        assert!(
            matches!(&status_locator, L2Verdict::MissingLocks { sync_point, .. } if sync_point == &prefix),
            "query_status with locator prefix matching parent-A1 must return MissingLocks with sync_point, got: {:?}",
            status_locator
        );

        // Querying voucher-B with parent-B still works
        let status_b = ram_b.query_status("voucher-B", "parent-B", &[]);
        assert!(
            matches!(status_b, L2Verdict::Verified { .. }),
            "query_status for voucher-B with parent-B must return Verified"
        );
    }
}
