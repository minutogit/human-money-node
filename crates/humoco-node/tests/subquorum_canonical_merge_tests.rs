#![forbid(unsafe_code)]
#![allow(clippy::needless_range_loop)]

//! Integration tests for Subquorum Canonical Merge via min(H_canon) (Spec 02, 08, Pillar 4).
//!
//! Validates:
//! 1. Asymmetric sub-quorum partition split:
//!    - 7 nodes hold Lock A (minority branch)
//!    - 13 nodes hold Lock B (majority branch, but 13 < 14 so neither reached BFT finality)
//!    - Canonical hash of Lock A is strictly smaller than Lock B: H_canon(A) < H_canon(B).
//! 2. During P2P sync (IngressOrigin::PartitionSync):
//!    - Physics trumps negotiation: all 20 nodes deterministically converge to Lock A via min(H_canon).
//!    - Lock B becomes VOID and is displaced from RAM.
//!    - The double-spending sender is banned network-wide for equivocation.
//! 3. Also validates simulation core LockRecord split-brain convergence (13 vs 7).

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;

use humoco_node::api::hmc::{
    calculate_l2_payload_hash, L2AuthPayload, L2LockEntry, L2LockRequest,
};
use humoco_node::storage::engine::compute_hmc_canonical_hash;
use humoco_node::storage::{DualTierEngine, IngressOrigin, RedbStorage};
use humoco_sim_core::crypto::compute_canonical_hash;
use humoco_sim_core::types::{Hash256, LockRecord, LockStatus, SimTime};
use humoco_sim_core::IngressVerdictLow;

fn test_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_hmc_spend(
    voucher_id: &str,
    parent_tag: &str,
    tx_hash: [u8; 32],
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let mut req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: voucher_id.to_string(),
        ds_tag: Some(parent_tag.to_string()),
        transaction_hash: tx_hash,
        is_genesis: false,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

fn make_hmc_genesis(
    parent_hex: &str,
    valid_until_ms: u64,
    sender_key: &SigningKey,
) -> L2LockRequest {
    let sender_pub = sender_key.verifying_key().to_bytes();
    let tx_hash = *blake3::hash(parent_hex.as_bytes()).as_bytes();
    let mut req = L2LockRequest {
        auth: L2AuthPayload {
            ephemeral_pubkey: sender_pub,
            auth_signature: None,
        },
        layer2_voucher_id: format!("voucher_{parent_hex}"),
        ds_tag: None,
        transaction_hash: tx_hash,
        is_genesis: true,
        sender_ephemeral_pub: sender_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".into()),
        trap_s: Some("none".into()),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: Some(valid_until_ms.to_string()),
        privacy_guard: Some("none".into()),
    };
    let payload_hash = calculate_l2_payload_hash(&req);
    req.layer2_signature = sender_key.sign(&payload_hash).to_bytes();
    req
}

#[tokio::test]
async fn test_subquorum_hmc_13_vs_7_minority_with_lower_hash_prevails() {
    let temp = tempdir().expect("tempdir");

    // Initialize 20 independent shard nodes (Partition A = nodes 0..7, Partition B = nodes 7..20)
    let mut engines = Vec::with_capacity(20);
    let mut _workers = Vec::with_capacity(20);

    for i in 0..20 {
        let db_path = temp.path().join(format!("node_{i}.redb"));
        let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
        let (engine, worker) = DualTierEngine::new(storage);
        engines.push(engine);
        _workers.push(worker);
    }

    let genesis_key = SigningKey::from_bytes(&[42u8; 32]);
    let now = test_now_ms();
    let root_valid_until = now + 1_000_000;
    let genesis_req = make_hmc_genesis("subquorum_voucher", root_valid_until, &genesis_key);
    let genesis_tag = bs58::encode(&genesis_req.transaction_hash).into_string();

    // Anchor genesis lock on all 20 nodes
    for engine in &engines {
        let (verdict, is_new) = engine
            .ingress_hmc_lock(genesis_tag.clone(), L2LockEntry::from(&genesis_req))
            .await;
        assert!(is_new);
        assert!(matches!(verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }));
    }

    // Prepare double-spending wallet on the same parent tag
    let wallet_key = SigningKey::from_bytes(&[88u8; 32]);
    let wallet_pub = wallet_key.verifying_key().to_bytes();
    let parent_hex = hex::encode([0x33u8; 32]);
    let parent_bytes = *blake3::hash(parent_hex.as_bytes()).as_bytes();

    // Generate two candidate transactions and find which has lower H_canon
    let mut candidate_1_tx = *blake3::hash(b"candidate_tx_one").as_bytes();
    let mut candidate_2_tx = *blake3::hash(b"candidate_tx_two").as_bytes();

    let mut h1 = compute_hmc_canonical_hash(&parent_bytes, &wallet_pub, &candidate_1_tx);
    let mut h2 = compute_hmc_canonical_hash(&parent_bytes, &wallet_pub, &candidate_2_tx);

    // Swap if needed so candidate 1 is strictly smaller (Lock A = candidate 1, Lock B = candidate 2)
    if h1 > h2 {
        std::mem::swap(&mut candidate_1_tx, &mut candidate_2_tx);
        std::mem::swap(&mut h1, &mut h2);
    }
    assert!(h1 < h2, "H_canon(A) must be strictly less than H_canon(B)");

    let tx_hash_a = candidate_1_tx;
    let tx_hash_b = candidate_2_tx;

    let lock_a_req = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex,
        tx_hash_a,
        now + 800_000,
        &wallet_key,
    );
    let lock_b_req = make_hmc_spend(
        &genesis_req.layer2_voucher_id,
        &parent_hex,
        tx_hash_b,
        now + 800_000,
        &wallet_key,
    );

    let lock_a_entry = L2LockEntry::from(&lock_a_req);
    let lock_b_entry = L2LockEntry::from(&lock_b_req);

    // -----------------------------------------------------------------------
    // Split Partition:
    // Partition A (minority: 7 nodes) ingests Lock A via ClientApi
    // -----------------------------------------------------------------------
    for i in 0..7 {
        let (verdict, is_new) = engines[i]
            .ingress_hmc_lock_with_origin(
                parent_hex.clone(),
                lock_a_entry.clone(),
                IngressOrigin::ClientApi,
                Some(now),
            )
            .await;
        assert!(is_new);
        assert!(matches!(verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }));
        assert_eq!(
            engines[i].get_hmc_ram_lock(&parent_hex).await.map(|e| e.t_id),
            Some(tx_hash_a)
        );
    }

    // -----------------------------------------------------------------------
    // Partition B (majority: 13 nodes) ingests Lock B via ClientApi
    // -----------------------------------------------------------------------
    for i in 7..20 {
        let (verdict, is_new) = engines[i]
            .ingress_hmc_lock_with_origin(
                parent_hex.clone(),
                lock_b_entry.clone(),
                IngressOrigin::ClientApi,
                Some(now),
            )
            .await;
        assert!(is_new);
        assert!(matches!(verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }));
        assert_eq!(
            engines[i].get_hmc_ram_lock(&parent_hex).await.map(|e| e.t_id),
            Some(tx_hash_b)
        );
    }

    // Verify asymmetric partition state before sync
    // 7 nodes hold Lock A, 13 nodes hold Lock B. Neither reached 14 (sub-quorum).
    for i in 0..7 {
        assert_eq!(
            engines[i].get_hmc_ram_lock(&parent_hex).await.map(|e| e.t_id),
            Some(tx_hash_a)
        );
    }
    for i in 7..20 {
        assert_eq!(
            engines[i].get_hmc_ram_lock(&parent_hex).await.map(|e| e.t_id),
            Some(tx_hash_b)
        );
    }

    // -----------------------------------------------------------------------
    // P2P Sync: Network heals and exchanges locks across partition boundary
    // -----------------------------------------------------------------------
    // 1. Partition B (nodes 7..20) receives Lock A from Partition A via PartitionSync
    for i in 7..20 {
        let (verdict, _is_new) = engines[i]
            .ingress_hmc_lock_with_origin(
                parent_hex.clone(),
                lock_a_entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
            )
            .await;
        // WinnerB (Lock A) replaces Lock B in RAM!
        assert!(
            matches!(verdict, humoco_node::api::hmc::L2Verdict::Verified { .. }),
            "Node {i} in Partition B must accept Lock A as winner over Lock B"
        );
    }

    // 2. Partition A (nodes 0..7) receives Lock B from Partition B via PartitionSync
    for i in 0..7 {
        let (verdict, is_new) = engines[i]
            .ingress_hmc_lock_with_origin(
                parent_hex.clone(),
                lock_b_entry.clone(),
                IngressOrigin::PartitionSync,
                Some(now),
            )
            .await;
        // WinnerA (Lock A) wins, Lock B is rejected as conflict / void!
        assert!(!is_new);
        assert!(
            matches!(verdict, humoco_node::api::hmc::L2Verdict::Conflict { .. }),
            "Node {i} in Partition A must retain Lock A and reject Lock B"
        );
    }

    // -----------------------------------------------------------------------
    // Post-Convergence Invariant Checks:
    // -----------------------------------------------------------------------
    // Invariant 1: 100% of all 20 nodes deterministically hold Lock A
    for (i, engine) in engines.iter().enumerate() {
        let ram_lock = engine
            .get_hmc_ram_lock(&parent_hex)
            .await
            .expect("Lock must exist in RAM");
        assert_eq!(
            ram_lock.t_id, tx_hash_a,
            "Node {i} MUST hold winning Lock A after P2P sync convergence"
        );
        assert_ne!(
            ram_lock.t_id, tx_hash_b,
            "Node {i} MUST NOT hold losing Lock B"
        );
    }

    // Invariant 2: The equivocating wallet sender is banned on all 20 nodes
    for (i, engine) in engines.iter().enumerate() {
        assert!(
            engine.is_node_banned(&wallet_pub).await,
            "Node {i} MUST have banned the double-spending sender"
        );
    }
}

#[tokio::test]
async fn test_subquorum_core_lock_record_13_vs_7_minority_with_lower_hash_prevails() {
    let temp = tempdir().expect("tempdir");

    // Initialize 20 nodes for core LockRecord domain
    let mut engines = Vec::with_capacity(20);
    let mut _workers = Vec::with_capacity(20);

    for i in 0..20 {
        let db_path = temp.path().join(format!("core_node_{i}.redb"));
        let storage = Arc::new(RedbStorage::open(&db_path).expect("open redb"));
        let (engine, worker) = DualTierEngine::new(storage);
        engines.push(engine);
        _workers.push(worker);
    }

    let parent_lock: Hash256 = [0x55u8; 32];
    let receiver_pub: Hash256 = [0x66u8; 32];
    let now = SimTime(100_000);
    let valid_until = SimTime(200_000);
    let root_valid_until = SimTime(300_000);

    // Pick two nonces such that H_canon(A) < H_canon(B)
    let mut nonce_1: Hash256 = [0x11u8; 32];
    let mut nonce_2: Hash256 = [0x22u8; 32];

    let mut h1 = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_1);
    let mut h2 = compute_canonical_hash(&parent_lock, &receiver_pub, &nonce_2);

    if h1 > h2 {
        std::mem::swap(&mut nonce_1, &mut nonce_2);
        std::mem::swap(&mut h1, &mut h2);
    }
    assert!(h1 < h2);

    let id_a = {
        let mut hasher = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_LOCK_ID";
        hasher.update(&[tag.len() as u8]);
        hasher.update(tag);
        hasher.update(&parent_lock);
        hasher.update(&receiver_pub);
        hasher.update(&nonce_1);
        hasher.update(&now.0.to_le_bytes());
        hasher.update(&valid_until.0.to_le_bytes());
        *hasher.finalize().as_bytes()
    };

    let id_b = {
        let mut hasher = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_LOCK_ID";
        hasher.update(&[tag.len() as u8]);
        hasher.update(tag);
        hasher.update(&parent_lock);
        hasher.update(&receiver_pub);
        hasher.update(&nonce_2);
        hasher.update(&now.0.to_le_bytes());
        hasher.update(&valid_until.0.to_le_bytes());
        *hasher.finalize().as_bytes()
    };

    let mut lock_a = LockRecord::new(parent_lock, receiver_pub, nonce_1.to_vec(), now, valid_until);
    lock_a.status = LockStatus::Provisional { sigs: 7, required: 14 };

    let mut lock_b = LockRecord::new(parent_lock, receiver_pub, nonce_2.to_vec(), now, valid_until);
    lock_b.status = LockStatus::Provisional { sigs: 13, required: 14 };

    // Partition A (7 nodes) ingests Lock A
    for i in 0..7 {
        let res = engines[i]
            .ingress_lock_with_origin(lock_a.clone(), now, root_valid_until, IngressOrigin::ClientApi)
            .await;
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
        assert_eq!(engines[i].get_ram_lock(&parent_lock).await.map(|r| r.id), Some(id_a));
    }

    // Partition B (13 nodes) ingests Lock B
    for i in 7..20 {
        let res = engines[i]
            .ingress_lock_with_origin(lock_b.clone(), now, root_valid_until, IngressOrigin::ClientApi)
            .await;
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
        assert_eq!(engines[i].get_ram_lock(&parent_lock).await.map(|r| r.id), Some(id_b));
    }

    // P2P PartitionSync:
    // Partition B receives Lock A
    for i in 7..20 {
        let res = engines[i]
            .ingress_lock_with_origin(lock_a.clone(), now, root_valid_until, IngressOrigin::PartitionSync)
            .await;
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew), "Node {i} must replace Lock B with winning Lock A");
    }

    // Partition A receives Lock B
    for i in 0..7 {
        let res = engines[i]
            .ingress_lock_with_origin(lock_b.clone(), now, root_valid_until, IngressOrigin::PartitionSync)
            .await;
        assert_eq!(res, Err(IngressVerdictLow::RejectedCollision), "Node {i} must reject losing Lock B");
    }

    // All 20 nodes deterministically hold Lock A
    for (i, engine) in engines.iter().enumerate() {
        let rec = engine.get_ram_lock(&parent_lock).await.expect("record must exist");
        assert_eq!(rec.id, id_a, "Node {i} must hold Lock A");
        assert_ne!(rec.id, id_b, "Node {i} must not hold Lock B");
    }
}
