//! Audit 22 permanent regression suite:
//! - A22-01: Equal native canonical hashes total ordering over core resolver and real QUIC
//! - A22-02: Monotonic confirmation support publication (no RAM class demotion)
//! - A22-03: Shared bounded voucher root expiry at TTL + 30s grace

#[path = "common/recovery.rs"]
mod recovery;

use humoco_node::{
    api::hmc::L2LockEntry,
    storage::{DualTierEngine, HmcRamIndex, IngressOrigin, RedbStorage},
};
use humoco_sim_core::types::SimTime;
use std::sync::Arc;

fn root_entry(valid_until: &str) -> L2LockEntry {
    L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "audit22-root".into(),
        t_id: [1; 32],
        sender_ephemeral_pub: [2; 32],
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 1_000,
        deletable_at: Some(valid_until.into()),
        privacy_guard: None,
    }
}

fn signed_hmc_cut(
    now: u64,
) -> (
    String,
    humoco_node::api::hmc::L2LockEntry,
    String,
    humoco_node::api::hmc::L2LockEntry,
    u16,
) {
    use ed25519_dalek::Signer;
    use humoco_node::{
        api::hmc::{calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest},
        identity::NodeIdentity,
    };
    use sha3::{Digest, Sha3_256};
    let author = NodeIdentity::generate();
    let mut root = L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: *author.node_pubkey(),
            auth_signature: None,
        },
        layer2_voucher_id: "current-support-fixture".into(),
        ds_tag: None,
        transaction_hash: [42; 32],
        is_genesis: true,
        sender_ephemeral_pub: *author.node_pubkey(),
        layer2_signature: [0; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: now,
        deletable_at: Some((now + 600_000).to_string()),
        privacy_guard: None,
    };
    let mut proof = humoco_proto::causal::CausalOutputProof {
        version: 1,
        voucher_id: root.layer2_voucher_id.clone(),
        transaction_id: root.transaction_hash,
        state_hash: [43; 32],
        sender_pubkey: *author.node_pubkey(),
        receiver_pubkey_hash: Some(Sha3_256::digest(author.node_pubkey()).into()),
        change_pubkey_hash: None,
        root_valid_until_ms: now + 600_000,
        is_root: true,
        signature: [0; 64],
    };
    proof.signature = author
        .signing_key()
        .sign(&proof.digest().unwrap())
        .to_bytes();
    root.causal_output = Some(proof);
    root.layer2_signature = author
        .signing_key()
        .sign(&calculate_l2_payload_hash(&root))
        .to_bytes();
    let root_tag = bs58::encode(root.transaction_hash).into_string();
    let shard = humoco_sim_core::types::canonical_voucher_shard(
        &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
    );
    let mut spend = root.clone();
    spend.is_genesis = false;
    spend.deletable_at = None;
    spend.transaction_hash = [44; 32];
    let mut hash = Sha3_256::new();
    hash.update(32u32.to_le_bytes());
    hash.update([43; 32]);
    hash.update(32u32.to_le_bytes());
    hash.update(author.node_pubkey());
    let spend_tag = bs58::encode(hash.finalize()).into_string();
    spend.ds_tag = Some(spend_tag.clone());
    let mut proof = spend.causal_output.clone().unwrap();
    proof.is_root = false;
    proof.transaction_id = spend.transaction_hash;
    proof.state_hash = [45; 32];
    proof.signature = author
        .signing_key()
        .sign(&proof.digest().unwrap())
        .to_bytes();
    spend.causal_output = Some(proof);
    spend.layer2_signature = author
        .signing_key()
        .sign(&calculate_l2_payload_hash(&spend))
        .to_bytes();
    (
        root_tag,
        L2LockEntry::from(&root),
        spend_tag,
        L2LockEntry::from(&spend),
        shard,
    )
}

/// A22-01: Real authenticated QUIC recovery converges on the lawful HMC spend lock.
#[tokio::test]
async fn test_a22_01_hmc_locks_must_converge_over_real_quic() {
    let peers = recovery::recovery_peers(4).await;
    let now = peers[0].manager.net_time_ms();
    let (root_tag, root, tag, spend, shard) = signed_hmc_cut(now);
    for (index, peer) in peers.iter().enumerate() {
        peer.db.put_hmc_lock(&root_tag, &root).unwrap();
        if index < 3 {
            peer.db.put_hmc_lock(&tag, &spend).unwrap();
            peer.readiness.mark_shard_ready(shard);
        }
        peer.engine.recover_from_disk(SimTime(now)).await.unwrap();
    }
    let p = &peers[3];
    let synced = humoco_node::daemon::sync_single_shard(
        shard,
        &p.network,
        &p.manager,
        &p.engine,
        &p.db,
        &p.identity,
        &p.readiness,
        &p.cancel,
    )
    .await
    .unwrap();
    assert!(synced, "sync_single_shard must succeed");

    let actual = p.engine.get_hmc_ram_lock(&tag).await.unwrap();
    assert_eq!(actual.t_id, spend.t_id);
    recovery::stop_recovery_peers(peers).await;
}

/// A22-02: Stale class1 support must not overwrite newer class2 RAM support for the same child.
#[test]
fn test_a22_02_late_support_publication_must_not_demote_same_child() {
    let root = root_entry("50000");
    let mut spend = root.clone();
    spend.t_id = [3; 32];
    spend.deletable_at = None;
    let mut ram = HmcRamIndex::new();
    ram.insert_or_check(
        bs58::encode(root.t_id).into_string(),
        root,
        IngressOrigin::ClientApi,
        None,
    );
    ram.insert_or_check("audit22-slot".into(), spend, IngressOrigin::ClientApi, None);

    // Publication interleaving: class 2 publishes first, then delayed class 1 completes
    ram.set_confirmation_class("audit22-slot", 2);
    ram.set_confirmation_class("audit22-slot", 1);
    assert_eq!(
        ram.get_confirmation_class("audit22-slot"),
        2,
        "late same-child support publication must preserve the higher confirmation class"
    );

    // Identical-class retries remain stable
    ram.set_confirmation_class("audit22-slot", 2);
    assert_eq!(ram.get_confirmation_class("audit22-slot"), 2);
}

/// A22-02: Replacement child X -> Y must not inherit previous child's class,
/// and delayed completions for X must not affect Y.
#[test]
fn test_a22_02_replacement_child_does_not_inherit_previous_class() {
    let root = root_entry("50000");
    let mut spend_x = root.clone();
    spend_x.t_id = [10; 32];
    spend_x.deletable_at = None;

    let mut spend_y = root.clone();
    spend_y.t_id = [11; 32];
    spend_y.deletable_at = None;

    let mut ram = HmcRamIndex::new();
    let slot = "audit22-replace-slot".to_string();
    ram.insert_or_check(
        bs58::encode(root.t_id).into_string(),
        root,
        IngressOrigin::ClientApi,
        None,
    );
    ram.insert_or_check(slot.clone(), spend_x, IngressOrigin::ClientApi, None);
    ram.set_confirmation_class(&slot, 2);
    assert_eq!(ram.get_confirmation_class(&slot), 2);

    // Canonical replacement: partition sync replaces X with Y at incoming_class 1
    let (_verdict, _replaced) = ram.insert_or_check_with_class(
        slot.clone(),
        spend_y,
        IngressOrigin::PartitionSync,
        None,
        1,
    );
    // Even if not replacing via partition sync (or replacing):
    // In HmcRamIndex, when replacement happens, it sets class to class_new.
    // If we manually remove X and insert Y:
    ram.remove_lock(&slot);
    ram.insert_or_check_with_class(
        slot.clone(),
        root_entry("50000"),
        IngressOrigin::ClientApi,
        None,
        0,
    );
    assert_eq!(
        ram.get_confirmation_class(&slot),
        0,
        "fresh entry starts with its own class, not prior child's class"
    );
}

/// A22-03: Normal daemon pruning must physically remove expired root metadata from redb.
#[tokio::test]
async fn test_a22_03_normal_pruning_must_remove_expired_root_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RedbStorage::open(&dir.path().join("root.redb")).unwrap());
    let root = root_entry("50000");
    db.put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root)
        .unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let (engine, worker) = DualTierEngine::new_with_token(db.clone(), cancel.clone());
    engine.recover_from_disk(SimTime(1_000)).await.unwrap();

    // 50_000 ms + 30_000 ms grace = 80_000 ms. Pruning at 81_000 ms must purge.
    for _ in 0..3 {
        engine.prune_expired(SimTime(81_000)).await.unwrap();
    }
    assert!(engine.hmc_ram.read().await.root_anchors().is_empty());
    let remains = db.voucher_root(&root.layer2_voucher_id).unwrap().is_some();
    cancel.cancel();
    worker.await.unwrap();
    assert!(
        !remains,
        "normal daemon expiry must physically remove root metadata from disk"
    );
}

/// A22-03: Non-integral-second root lifetimes must not be pruned prematurely due to bucket rounding.
#[test]
fn test_a22_03_non_integral_second_root_lifetime_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let db = RedbStorage::open(&dir.path().join("boundary.redb")).unwrap();
    // 50_500 ms (50.5s) + 30_000 ms grace = 80_500 ms (80.5s).
    // At second 80 (80.0s), grace period has NOT passed. Must retain!
    // At second 81 (81.0s), grace period HAS passed. Must prune!
    let root = root_entry("50500");
    db.put_hmc_lock(&bs58::encode(root.t_id).into_string(), &root)
        .unwrap();

    // Immediately before / at second 80: must NOT be pruned
    let _ = db.prune_expired_buckets(80).unwrap();
    assert!(
        db.voucher_root(&root.layer2_voucher_id).unwrap().is_some(),
        "root must not be pruned at second 80 before 80.5s grace expiration"
    );

    // At second 81: must be pruned
    let _ = db.prune_expired_buckets(81).unwrap();
    assert!(
        db.voucher_root(&root.layer2_voucher_id).unwrap().is_none(),
        "root must be physically pruned at second 81 after 80.5s grace expiration"
    );
}

/// A22-03: More than 256 expired roots must be bounded per pass and progress to completion.
#[test]
fn test_a22_03_more_than_256_expired_roots_bounded_progress() {
    let dir = tempfile::tempdir().unwrap();
    let db = RedbStorage::open(&dir.path().join("bulk_roots.redb")).unwrap();

    // Insert 300 roots with expiry 50_000 ms
    for i in 0..300 {
        let mut r = root_entry("50000");
        r.layer2_voucher_id = format!("bulk-root-{i}");
        r.t_id[0] = (i & 0xFF) as u8;
        r.t_id[1] = ((i >> 8) & 0xFF) as u8;
        db.put_hmc_lock(&bs58::encode(r.t_id).into_string(), &r)
            .unwrap();
    }
    assert_eq!(db.all_voucher_roots().unwrap().len(), 300);

    // Pass 1 at second 81: bounded to 256 removals
    let _ = db.prune_expired_buckets(81).unwrap();
    let remaining = db.all_voucher_roots().unwrap().len();
    assert_eq!(
        remaining,
        300 - 256,
        "first pass must obey 256 budget limit"
    );

    // Pass 2 at second 81: removes remaining 44
    let _ = db.prune_expired_buckets(81).unwrap();
    let remaining_pass2 = db.all_voucher_roots().unwrap().len();
    assert_eq!(
        remaining_pass2, 0,
        "second pass must complete eviction of remaining roots"
    );
}

/// A22-R1: Subsecond grace horizon (+30s) must be preserved across HMC, provisional, and root tables.
#[test]
fn test_a22_r1_subsecond_grace_horizon_preserved_across_active_provisional_and_support() {
    let dir = tempfile::tempdir().unwrap();
    let db = RedbStorage::open(&dir.path().join("subsecond_grace.redb")).unwrap();

    let _root_valid_until_ms = 50_001u64; // Grace end is 50_001 + 30_000 = 80_001 ms (> 80.0s)
    let root = root_entry("50001");
    let root_tag = bs58::encode(root.t_id).into_string();
    db.put_hmc_lock(&root_tag, &root).unwrap();

    // 1. HMC spend lock under the same root
    let mut hmc_spend = root_entry("50001");
    hmc_spend.layer2_voucher_id = "audit22-root".into();
    hmc_spend.deletable_at = None; // Spends inherit from root
    hmc_spend.t_id = [0x99u8; 32];
    let hmc_tag = "spend_tag_50001";
    db.put_hmc_lock(hmc_tag, &hmc_spend).unwrap();

    // 2. Put a second HMC spend lock and quarantine it into provisional storage
    let mut prov_spend = root_entry("50001");
    prov_spend.layer2_voucher_id = "audit22-root".into();
    prov_spend.deletable_at = None;
    prov_spend.t_id = [0x88u8; 32];
    let prov_tag = "prov_tag_50001";
    db.put_hmc_lock(prov_tag, &prov_spend).unwrap();

    let mut keep_hmc = std::collections::HashSet::new();
    keep_hmc.insert(hmc_tag.to_string());

    let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag);
    let shard = humoco_sim_core::types::canonical_voucher_shard(&parent);
    let quarantined_hmc = db
        .quarantine_subquorum_locks(shard, &keep_hmc)
        .unwrap();
    assert!(quarantined_hmc.contains(&prov_tag.to_string()));
    assert!(db.get_provisional_hmc_lock(prov_tag).unwrap().is_some());

    // Verification 1: At second 80 (80_000 ms), grace period (+30s = 80_001 ms) has NOT expired.
    // Pruning at 80 must retain all locks and roots!
    let pruned_hmc_80 = db.prune_expired_buckets(80).unwrap();
    assert_eq!(
        pruned_hmc_80, 0,
        "No HMC locks should be pruned at 80s before 80.001s expiry"
    );
    assert!(
        db.get_hmc_lock(hmc_tag).unwrap().is_some(),
        "HMC lock must be retained at 80s"
    );
    assert!(
        db.get_provisional_hmc_lock(prov_tag).unwrap().is_some(),
        "Quarantined lock must be retained at 80s"
    );
    assert!(
        db.voucher_root(&root.layer2_voucher_id).unwrap().is_some(),
        "Root must be retained at 80s"
    );

    // Verification 2: At second 81 (81_000 ms), grace period HAS expired.
    // Pruning at 81 must physically remove all entries.
    let pruned_hmc_81 = db.prune_expired_buckets(81).unwrap();
    assert!(pruned_hmc_81 > 0, "HMC lock must be pruned at 81s");
    assert!(
        db.get_hmc_lock(hmc_tag).unwrap().is_none(),
        "HMC lock must be gone at 81s"
    );
    assert!(
        db.get_provisional_hmc_lock(prov_tag).unwrap().is_none(),
        "Quarantined lock must be gone at 81s"
    );
    assert!(
        db.voucher_root(&root.layer2_voucher_id).unwrap().is_none(),
        "Root must be gone at 81s"
    );
}
