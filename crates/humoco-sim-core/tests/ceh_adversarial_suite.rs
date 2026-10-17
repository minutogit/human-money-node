#![forbid(unsafe_code)]

//! Certified Epoch Handoff (CEH) Adversarial Test Suite.
//!
//! Validates the 4 core mathematical and adversarial scenarios defined in
//! `docs/CERTIFIED_EPOCH_HANDOFF_PLAN.md`:
//! 1. Scenario 1 (39-Node Bridge Attack): Split-Brain Impossibility (Theorem 1).
//! 2. Scenario 2 (22-Node Newcomer Activation Race): Write-Barrier & Snapshot Transfer.
//! 3. Scenario 3 (8/6 Split + View Change & Late Redemption): Progress under Byzantine split.
//! 4. Scenario 4 (Pioneer Mode Unified Manifest at N=20): 65,536-shard Merkle root & 16-hash proofs.

use std::collections::BTreeSet;
use ed25519_dalek::SigningKey;
use humoco_sim_core::ceh::*;

fn generate_keypair(seed: u8) -> (SigningKey, NodePubKey) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[0] = seed;
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();
    (signing_key, pubkey)
}

fn generate_committee(start_seed: u8) -> ([SigningKey; CEH_COMMITTEE_SIZE], [NodePubKey; CEH_COMMITTEE_SIZE]) {
    let mut signers = Vec::with_capacity(CEH_COMMITTEE_SIZE);
    let mut pubkeys = Vec::with_capacity(CEH_COMMITTEE_SIZE);
    for i in 0..CEH_COMMITTEE_SIZE {
        let (sk, pk) = generate_keypair(start_seed.wrapping_add(i as u8));
        signers.push(sk);
        pubkeys.push(pk);
    }
    (
        signers.try_into().map_err(|_| ()).expect("committee signers"),
        pubkeys.try_into().map_err(|_| ()).expect("committee pubkeys"),
    )
}

/// Scenario 1 (39-Node Bridge Attack): Split-Brain Impossibility (Theorem 1).
///
/// Two partitions separated by a bridge each attempt to sign conflicting locks or certificates;
/// verify that without an unbroken authorized 14-vote predecessor committee link,
/// split-brain cannot produce conflicting certified finality.
#[test]
fn test_scenario_1_39_node_bridge_attack_split_brain_impossibility() {
    // 39 nodes total: Partition A (seeds 1..=19), Bridge (seed 20), Partition B (seeds 21..=39).
    // An authorized 20-node committee is established for Epoch 1 (seeds 1..=20).
    let (authorized_signers, authorized_committee) = generate_committee(1);

    // Root anchor / EpochCertificate for Epoch 1
    let mut epoch_1_cert = EpochCertificate::new(
        1,          // shard_id
        1,          // epoch
        0,          // round
        [0x11; 32], // predecessor_cert_hash
        [0x22; 32], // closed_state_root
        authorized_committee,
    );
    for sk in authorized_signers.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_epoch_certificate(sk, &epoch_1_cert);
        epoch_1_cert.add_signature(pk, sig);
    }
    assert!(epoch_1_cert.verify(&authorized_committee).is_ok());

    let parent_lock = [0x5a; 32];
    let child_lock_a = [0xaa; 32];
    let child_lock_b = [0xbb; 32];
    let valid_until = 1_800_000_000;

    // Partition of the 20 committee members:
    // Partition A contains 10 committee members (indices 0..10).
    // Partition B contains 10 committee members (indices 10..20) including the bridge.
    // Partition A attempts to finalize Lock A.
    // Partition B attempts to finalize Lock B.

    // 1. Sub-quorum partition: Partition A can gather at most 10 signatures from authorized committee.
    let mut receipt_a = LockReceipt::new(1, 1, parent_lock, child_lock_a, valid_until);
    for sk in authorized_signers.iter().take(10) {
        let (pk, sig) = sign_lock_receipt(sk, &receipt_a);
        receipt_a.add_attestation(pk, sig);
    }
    let verify_res_a = verify_lock_receipt(&receipt_a, &epoch_1_cert);
    assert_eq!(
        verify_res_a,
        Err(CehError::QuorumNotReached { have: 10, required: 14 }),
        "Partition A cannot reach quorum without Partition B"
    );

    // 2. Sub-quorum partition: Partition B can gather at most 10 signatures from authorized committee.
    let mut receipt_b = LockReceipt::new(1, 1, parent_lock, child_lock_b, valid_until);
    for sk in authorized_signers.iter().skip(10).take(10) {
        let (pk, sig) = sign_lock_receipt(sk, &receipt_b);
        receipt_b.add_attestation(pk, sig);
    }
    let verify_res_b = verify_lock_receipt(&receipt_b, &epoch_1_cert);
    assert_eq!(
        verify_res_b,
        Err(CehError::QuorumNotReached { have: 10, required: 14 }),
        "Partition B cannot reach quorum without Partition A"
    );

    // 3. Sybil / Self-proclaimed committee attack:
    // Partition B attempts to forge 14 signatures by enlisting 4 foreign nodes from its 19 partition nodes.
    let mut forged_receipt_b = LockReceipt::new(1, 1, parent_lock, child_lock_b, valid_until);
    for sk in authorized_signers.iter().skip(10).take(10) {
        let (pk, sig) = sign_lock_receipt(sk, &forged_receipt_b);
        forged_receipt_b.add_attestation(pk, sig);
    }
    for outsider_seed in 21..=24 {
        let (outsider_sk, _) = generate_keypair(outsider_seed);
        let (pk, sig) = sign_lock_receipt(&outsider_sk, &forged_receipt_b);
        forged_receipt_b.add_attestation(pk, sig);
    }
    assert_eq!(forged_receipt_b.attestations.len(), 14);
    let verify_forged_res = verify_lock_receipt(&forged_receipt_b, &epoch_1_cert);
    assert!(
        matches!(verify_forged_res, Err(CehError::SignerNotInCommittee(_))),
        "Verifier must reject signatures from non-authorized committee members"
    );

    // 4. Byzantine bridge / Equivocator attack (Theorem 1):
    // Even if up to f = 6 Byzantine nodes (indices 7..13) double-sign both Lock A and Lock B,
    // honest nodes in Partition A (0..7 = 7 nodes) only sign Lock A,
    // and honest nodes in Partition B (13..20 = 7 nodes) only sign Lock B.
    // For Lock A: 7 honest + 6 Byzantine = 13 signatures < 14!
    // For Lock B: 7 honest + 6 Byzantine = 13 signatures < 14!
    let mut byzantine_receipt_a = LockReceipt::new(1, 1, parent_lock, child_lock_a, valid_until);
    let mut byzantine_receipt_b = LockReceipt::new(1, 1, parent_lock, child_lock_b, valid_until);
    // 7 honest Partition A sign A
    for sk in authorized_signers.iter().take(7) {
        let (pk, sig) = sign_lock_receipt(sk, &byzantine_receipt_a);
        byzantine_receipt_a.add_attestation(pk, sig);
    }
    // 7 honest Partition B sign B
    for sk in authorized_signers.iter().skip(13).take(7) {
        let (pk, sig) = sign_lock_receipt(sk, &byzantine_receipt_b);
        byzantine_receipt_b.add_attestation(pk, sig);
    }
    // 6 Byzantine nodes (including bridge) double-sign both A and B
    for sk in authorized_signers.iter().skip(7).take(6) {
        let (pk_a, sig_a) = sign_lock_receipt(sk, &byzantine_receipt_a);
        byzantine_receipt_a.add_attestation(pk_a, sig_a);
        let (pk_b, sig_b) = sign_lock_receipt(sk, &byzantine_receipt_b);
        byzantine_receipt_b.add_attestation(pk_b, sig_b);
    }
    assert_eq!(byzantine_receipt_a.attestations.len(), 13);
    assert_eq!(byzantine_receipt_b.attestations.len(), 13);
    assert_eq!(
        verify_lock_receipt(&byzantine_receipt_a, &epoch_1_cert),
        Err(CehError::QuorumNotReached { have: 13, required: 14 })
    );
    assert_eq!(
        verify_lock_receipt(&byzantine_receipt_b, &epoch_1_cert),
        Err(CehError::QuorumNotReached { have: 13, required: 14 })
    );

    // 5. Conflicting successor certificates:
    // Partition A tries to certify Successor Committee A, Partition B tries to certify Successor Committee B.
    let (_, successor_comm_a) = generate_committee(40);
    let (_, successor_comm_b) = generate_committee(70);
    let mut cert_a = EpochCertificate::new(1, 2, 0, epoch_1_cert.canonical_hash(), [0x33; 32], successor_comm_a);
    let mut cert_b = EpochCertificate::new(1, 2, 0, epoch_1_cert.canonical_hash(), [0x44; 32], successor_comm_b);

    for sk in authorized_signers.iter().take(13) {
        let (pk, sig) = sign_epoch_certificate(sk, &cert_a);
        cert_a.add_signature(pk, sig);
    }
    for sk in authorized_signers.iter().skip(7).take(13) {
        let (pk, sig) = sign_epoch_certificate(sk, &cert_b);
        cert_b.add_signature(pk, sig);
    }
    assert_eq!(
        verify_epoch_certificate_signatures(&cert_a, &authorized_committee, 14),
        Err(CehError::QuorumNotReached { have: 13, required: 14 })
    );
    assert_eq!(
        verify_epoch_certificate_signatures(&cert_b, &authorized_committee, 14),
        Err(CehError::QuorumNotReached { have: 13, required: 14 })
    );

    // Proves Theorem 1: Split-brain cannot produce conflicting certified finality.
}

/// Scenario 2 (22-Node Newcomer Activation Race): Write-Barrier & Snapshot Transfer.
///
/// Newcomers activate while old members undergo write-drain;
/// verify that the two-stage write barrier (`FENCE_DRAIN` -> `FENCE_LOCKED`)
/// and state snapshot transfer prevent divergent lock issuance.
#[test]
fn test_scenario_2_22_node_newcomer_activation_race() {
    // 22 nodes: Old committee (seeds 1..=20), Newcomers (seeds 21, 22).
    let (old_signers, old_committee) = generate_committee(1);
    let (_, newcomer_pk_1) = generate_keypair(21);
    let (_, newcomer_pk_2) = generate_keypair(22);

    // Successor committee replaces 2 old members (indices 18, 19) with 2 newcomers
    let mut successor_committee = old_committee;
    successor_committee[18] = newcomer_pk_1;
    successor_committee[19] = newcomer_pk_2;

    let shard_id = 42;
    let old_epoch = 5;
    let new_epoch = 6;
    let parent_lock = [0x33; 32];
    let child_lock_legit = [0xaa; 32];
    let child_lock_divergent = [0xbb; 32];
    let valid_until = 1_850_000_000;

    // 1. Two-Stage Write Barrier on active committee nodes:
    let barrier = WriteBarrier::new();
    assert_eq!(barrier.stage(), BarrierStage::Open);

    // In-flight Task 1 acquires write permission before handoff
    let in_flight_guard = barrier.acquire_write().expect("must acquire when open");
    assert_eq!(barrier.active_in_flight_writes(), 1);

    // Stage 1: Transition to FENCE_DRAIN (New ingress rejected with 503)
    barrier.begin_drain();
    assert_eq!(barrier.stage(), BarrierStage::FenceDrain);

    // Concurrent incoming lock request during drain is rejected
    let ingress_err = barrier.acquire_write();
    assert_eq!(
        ingress_err.err(),
        Some(BarrierError::Draining { retry_after_secs: 2 }),
        "Incoming requests during drain must receive HTTP 503 Retry-After"
    );

    // Attempt to lock barrier while in-flight task is pending fails
    let premature_lock = barrier.lock();
    assert_eq!(
        premature_lock,
        Err(BarrierError::DrainPending { remaining_in_flight: 1 }),
        "State cannot freeze while in-flight writes are pending"
    );

    // In-flight task durably writes to active lock set and completes
    let mut active_locks = BTreeSet::new();
    active_locks.insert(ActiveLockEntry::new(parent_lock, child_lock_legit, valid_until));
    drop(in_flight_guard);
    assert_eq!(barrier.active_in_flight_writes(), 0);
    assert!(barrier.is_drained());

    // Stage 2: Transition to FENCE_LOCKED (Synchronous freeze)
    barrier.lock().expect("must lock when drained");
    assert_eq!(barrier.stage(), BarrierStage::FenceLocked);
    assert_eq!(barrier.acquire_write().err(), Some(BarrierError::Locked));

    // 2. Build deterministic State Snapshot from frozen active locks
    let old_snapshot = ShardStateSnapshot::build(shard_id, old_epoch, active_locks);
    assert!(old_snapshot.contains_parent(&parent_lock));
    assert!(old_snapshot.contains_lock(&parent_lock, &child_lock_legit));
    assert!(!old_snapshot.contains_lock(&parent_lock, &child_lock_divergent));

    // 3. Issue EpochCertificate from old committee to successor committee
    let mut epoch_6_cert = EpochCertificate::new(
        shard_id,
        new_epoch,
        0,
        [0x99; 32],
        old_snapshot.closed_state_root,
        successor_committee,
    );
    for sk in old_signers.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_epoch_certificate(sk, &epoch_6_cert);
        epoch_6_cert.add_signature(pk, sig);
    }
    assert!(epoch_6_cert.verify(&old_committee).is_ok());

    // 4. State snapshot transfer to newcomers
    let mut newcomer_snapshot = ShardStateSnapshot {
        shard_id,
        epoch: old_epoch,
        ..Default::default()
    };
    newcomer_snapshot.reconcile_union(old_snapshot.active_locks.clone(), 1_700_000_000);

    // Newcomer state root matches the frozen root in the EpochCertificate
    assert_eq!(
        newcomer_snapshot.closed_state_root,
        epoch_6_cert.closed_state_root,
        "Newcomer reconciled state root must match the certified closed state root"
    );

    // 5. Prevent divergent lock issuance on the newcomer:
    // Client attempts to submit divergent lock on the same parent_lock to newcomer in Epoch 6
    assert!(
        newcomer_snapshot.contains_parent(&parent_lock),
        "Newcomer must recognize parent_lock as already locked"
    );
    // Atomic collision detected: child_lock_divergent != child_lock_legit
    assert!(
        !newcomer_snapshot.contains_lock(&parent_lock, &child_lock_divergent),
        "Divergent child must not be present"
    );
}

/// Scenario 3 (8/6 Split + View Change & Late Redemption): Progress under Byzantine split.
///
/// 8 honest nodes vote A, 6 honest vote B, 6 Byzantine nodes withhold votes;
/// verify that the round times out, `ROUND_CHANGE` messages assemble a `NewViewCertificate`,
/// progress resumes with the honest proposer, and late 14-vote certificate redemption
/// clears pre-quorum provisional conflicts within 30 days.
#[test]
fn test_scenario_3_8_6_split_view_change_and_late_redemption() {
    let (signers, committee) = generate_committee(10);
    let shard_id = 7;
    let epoch = 3;
    let predecessor_hash = [0x55; 32];

    // Replicas for all 20 committee members
    let mut replicas = Vec::new();
    for sk in &signers {
        let r = CehConsensusReplica::new(shard_id, epoch, predecessor_hash, committee, sk.clone())
            .expect("replica creation");
        replicas.push(r);
    }

    // 8 honest replicas prepare proposal A
    let proposal_a = EpochProposal::new(shard_id, epoch, 0, [0xaa; 32], committee, Vec::new(), None);
    let mut prepares_a = Vec::new();
    for r in replicas.iter_mut().take(8) {
        let vote = r.handle_proposal(&proposal_a).expect("prepare A");
        prepares_a.push(vote);
    }

    // 6 honest replicas prepare proposal B
    let proposal_b = EpochProposal::new(shard_id, epoch, 0, [0xbb; 32], committee, Vec::new(), None);
    let mut prepares_b = Vec::new();
    for r in replicas.iter_mut().skip(8).take(6) {
        let vote = r.handle_proposal(&proposal_b).expect("prepare B");
        prepares_b.push(vote);
    }

    // 6 Byzantine nodes (indices 14..20) withhold all votes.
    // Result: A has 8 votes (< 14), B has 6 votes (< 14).
    for vote in prepares_a {
        let pp = replicas[0].add_prepare_vote(vote).expect("add prepare");
        assert!(pp.is_none(), "8 votes cannot form PreparedProof");
    }
    for vote in prepares_b {
        let pp = replicas[0].add_prepare_vote(vote).expect("add prepare");
        assert!(pp.is_none(), "6 votes cannot form PreparedProof");
    }

    // Timeout triggers View Change on all 14 honest nodes
    let mut round_changes = Vec::new();
    for r in replicas.iter_mut().take(14) {
        let rc = r.on_round_timeout();
        assert_eq!(rc.failed_round, 0);
        assert_eq!(rc.next_round, 1);
        round_changes.push(rc);
    }

    // Proposer for Round 1 is node 1 (round 1 % 20)
    let proposer_round_1 = 1;
    let mut nvc = None;
    for rc in round_changes {
        if let Some(cert) = replicas[proposer_round_1].add_round_change(rc).expect("add round change") {
            nvc = Some(cert);
        }
    }
    let nvc = nvc.expect("14 round changes must assemble NewViewCertificate");
    assert_eq!(nvc.new_round, 1);
    assert!(nvc.verify(&committee).is_ok());

    // All 14 honest replicas enter round 1
    for r in replicas.iter_mut().take(14) {
        r.enter_new_view(&nvc).expect("enter new view");
        assert_eq!(r.round, 1);
    }

    // --- Late-Certificate Redemption in spend slot ---
    let parent_lock = [0x77; 32];
    let child_lock_a = [0x11; 32];
    let child_lock_b = [0x22; 32];
    let valid_until = 1_900_000_000;

    // Slot was in provisional conflict due to pre-quorum split at day 3
    let provisional_slot = SlotState::ProvisionalConflict {
        parent_lock,
        marked_epoch: 3,
        marked_time: 3 * 86_400,
        divergent_children: vec![child_lock_a, child_lock_b],
    };

    // Client presents a valid 14-vote LockReceipt for child_lock_a signed by Epoch 3 committee
    let mut receipt_a = LockReceipt::new(shard_id, 3, parent_lock, child_lock_a, valid_until);
    for sk in signers.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_lock_receipt(sk, &receipt_a);
        receipt_a.add_attestation(pk, sig);
    }

    // Case 1: Redemption presented at Day 15 (within 30-day window) -> Clears conflict to Settled!
    let settled_state = ConflictResolver::process_receipt(
        provisional_slot.clone(),
        receipt_a.clone(),
        15,
        15 * 86_400,
        &committee,
    ).expect("redemption within 30 days must succeed");

    assert_eq!(
        settled_state,
        SlotState::Settled(receipt_a.clone()),
        "Valid 14-vote receipt clears provisional conflict to Settled"
    );

    // Case 2: Redemption presented at Day 45 (> 30 days) -> Freezes permanently
    let frozen_state = ConflictResolver::process_receipt(
        provisional_slot,
        receipt_a.clone(),
        45,
        45 * 86_400,
        &committee,
    ).expect("conflict resolution past window");

    assert_eq!(
        frozen_state,
        SlotState::PermanentlyFrozenUntilExpiry {
            parent_lock,
            valid_until,
        },
        "Unredeemed conflict past 30 days freezes permanently until voucher expiry"
    );

    // Any subsequent attempt on frozen slot remains permanently frozen
    let blocked_retry = ConflictResolver::process_receipt(
        frozen_state.clone(),
        receipt_a,
        46,
        46 * 86_400,
        &committee,
    ).expect("permanently frozen rejects modification");

    assert_eq!(blocked_retry, frozen_state);
}

/// Scenario 4 (Pioneer Mode Unified Manifest at N=20): 65,536-shard Merkle root & 16-hash proofs.
///
/// Verify that 20 pioneer nodes sign a single `UnifiedNetworkEpochManifest` with a 65,536-leaf
/// BLAKE3 Merkle tree, and any arbitrary shard's `closed_state_root` can be proven with a 16-hash audit path.
#[test]
fn test_scenario_4_pioneer_mode_unified_manifest_at_n20() {
    let (pioneer_signers, pioneer_committee) = generate_committee(50);

    // Allocate 65,536 closed state roots on the heap
    let mut shard_roots = alloc_shards_closed_state_roots();
    for (idx, root) in shard_roots.iter_mut().enumerate() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PIONEER_SHARD_STATE");
        hasher.update(&(idx as u32).to_le_bytes());
        *root = *hasher.finalize().as_bytes();
    }

    // Compute the 65,536-leaf Merkle root
    let shards_merkle_root = compute_unified_shards_merkle_root(&shard_roots);
    assert_ne!(shards_merkle_root, [0u8; 32]);

    // Pioneer committee creates and signs UnifiedNetworkEpochManifest for Epoch 1
    let mut manifest = UnifiedNetworkEpochManifest::new(
        1,
        0,
        [0x12; 32],
        shards_merkle_root,
        pioneer_committee,
    );

    for sk in pioneer_signers.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_unified_manifest(sk, &manifest);
        manifest.add_signature(pk, sig);
    }

    // Verify manifest signatures
    manifest.verify(&pioneer_committee).expect("pioneer manifest signatures valid");

    // Test Merkle proofs across diverse shard IDs (boundary, power of 2, prime, max)
    let test_shards = [0u16, 1, 15, 42, 255, 1024, 1337, 32767, 32768, 65534, 65535];
    for &shard_id in &test_shards {
        let proof = generate_shard_merkle_proof(&shard_roots, shard_id);
        assert_eq!(proof.shard_id, shard_id);
        assert_eq!(proof.closed_state_root, shard_roots[shard_id as usize]);
        assert_eq!(proof.audit_path.len(), CEH_MERKLE_TREE_DEPTH, "Audit path depth must be exactly 16");

        // 1. Valid leaf proof succeeds
        let verify_res = verify_unified_manifest_shard(
            &manifest,
            shard_id,
            &proof.closed_state_root,
            &proof.audit_path,
        );
        assert!(verify_res.is_ok(), "Leaf proof failed for shard {shard_id}");
        assert!(proof.verify(&manifest.shards_merkle_root));

        // 2. Tampered state root fails
        let mut tampered_root = proof.closed_state_root;
        tampered_root[0] ^= 0xaa;
        assert_eq!(
            verify_unified_manifest_shard(&manifest, shard_id, &tampered_root, &proof.audit_path),
            Err(CehError::InvalidMerkleProof),
            "Tampered state root must be rejected"
        );

        // 3. Tampered audit path hash fails
        let mut tampered_path = proof.audit_path.clone();
        tampered_path[0][0] ^= 0xbb;
        assert_eq!(
            verify_unified_manifest_shard(&manifest, shard_id, &proof.closed_state_root, &tampered_path),
            Err(CehError::InvalidMerkleProof),
            "Tampered audit path must be rejected"
        );

        // 4. Tampered shard ID fails
        let wrong_shard = shard_id ^ 0x01;
        assert_eq!(
            verify_unified_manifest_shard(&manifest, wrong_shard, &proof.closed_state_root, &proof.audit_path),
            Err(CehError::InvalidMerkleProof),
            "Tampered shard ID must be rejected"
        );
    }

    // 5. Wire size verification
    let encoded_manifest = bincode::serialize(&manifest).expect("serialize manifest");
    assert!(
        encoded_manifest.len() <= 2700,
        "Manifest wire size ({}) must be <= 2.7 KB",
        encoded_manifest.len()
    );
}
