#![forbid(unsafe_code)]

//! Certified Epoch Handoff (CEH) Dual-Store Isolation and Genesis Handshake Guard Tests.
//!
//! Validates:
//! - INV-CEH-01: Dual-store zero contamination (provisional locks never leak into finalized state roots).
//! - INV-CEH-02: Causal completeness for finality (predecessors must be finalized before children).
//! - INV-CEH-03: Atomic promotion from provisional to final tier.
//! - INV-CEH-04: Incompatible genesis handshake rejection.
//! - INV-CEH-05: Island node pioneer genesis adoption under 14/20 quorum.

use ed25519_dalek::SigningKey;
use humoco_sim_core::ceh::*;
use humoco_sim_core::storage::{DualRamIndex, IngressVerdictLow, LockTier};
use humoco_sim_core::types::{LockRecord, NodePubKey, SimTime};

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
        signers.try_into().map_err(|_| ()).expect("committee signers"),
        pubkeys.try_into().map_err(|_| ()).expect("committee pubkeys"),
    )
}

fn snapshot_from_records<'a>(
    records: impl Iterator<Item = &'a LockRecord>,
    shard_id: u16,
    epoch: u64,
) -> HierarchicalShardSnapshot {
    let mut snapshot = HierarchicalShardSnapshot::new(shard_id, epoch);
    for rec in records {
        let hop = VoucherHop::direct(rec.parent_lock, rec.id, rec.valid_until.0);
        let mut tree = VoucherSplitTree::new(rec.parent_lock);
        tree.add_hop(hop);
        snapshot.insert_tree(tree);
    }
    snapshot
}

/// Test 1: Zero Contamination
///
/// Insert 20 final locks into `DualRamIndex`, build `HierarchicalShardSnapshot` from `final_records()`,
/// compute `closed_state_root`. Insert 50 provisional locks. Recompute `closed_state_root`
/// from `final_records()`. Assert hashes match 100% byte-for-byte.
#[test]
fn test_inv_ceh_01_dual_store_zero_contamination() {
    let mut dual_ram = DualRamIndex::new();
    let now = SimTime(1000);
    let root_valid_until = SimTime(1_000_000);
    let valid_until = SimTime(500_000);

    // Insert 20 final locks
    for i in 1..=20u8 {
        let mut parent = [0u8; 32];
        parent[0] = i;
        let rec = LockRecord::new(parent, [0xAA; 32], vec![i], now, valid_until);
        let res = dual_ram.insert_final(rec, now, root_valid_until, true);
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
    }
    assert_eq!(dual_ram.final_len(), 20);
    assert_eq!(dual_ram.provisional_len(), 0);

    // Snapshot from finalized records and initial closed state root
    let snap_before = snapshot_from_records(dual_ram.final_records(), 0, 1);
    let root_before = snap_before.compute_hierarchical_closed_state_root();

    // Insert 50 provisional locks
    for j in 1..=50u8 {
        let mut parent = [0u8; 32];
        parent[0] = 100 + j;
        let rec = LockRecord::new(parent, [0xBB; 32], vec![j], now, valid_until);
        let res = dual_ram.insert_provisional(rec, now, root_valid_until);
        assert_eq!(res, Ok(IngressVerdictLow::AcceptedNew));
    }
    assert_eq!(dual_ram.final_len(), 20);
    assert_eq!(dual_ram.provisional_len(), 50);

    // Recompute state root from finalized records
    let snap_after = snapshot_from_records(dual_ram.final_records(), 0, 1);
    let root_after = snap_after.compute_hierarchical_closed_state_root();

    // Verify 100% byte-for-byte state root isolation
    assert_eq!(
        root_before, root_after,
        "Provisional locks must not contaminate finalized closed state root"
    );
}

/// Test 2: Causal Completeness for Finality
///
/// Insert parent L1 into `provisional_index`.
/// Attempt to insert child L2 into `final_index` with `is_root = false` -> must fail with `CausalPredecessorNotFinal`.
/// Promote L1 to final with `is_root = true` -> succeeds.
/// Now insert child L2 into `final_index` with `is_root = false` -> succeeds!
#[test]
fn test_inv_ceh_02_causal_completeness_for_finality() {
    let mut dual_ram = DualRamIndex::new();
    let now = SimTime(1000);
    let root_valid_until = SimTime(1_000_000);
    let valid_until = SimTime(500_000);

    // Parent L1
    let parent_l1 = [0x11; 32];
    let l1 = LockRecord::new(parent_l1, [0x01; 32], vec![1], now, valid_until);
    let verdict = dual_ram.insert_provisional(l1.clone(), now, root_valid_until);
    assert_eq!(verdict, Ok(IngressVerdictLow::AcceptedNew));
    assert!(dual_ram.is_provisional(&parent_l1));
    assert!(!dual_ram.is_final(&parent_l1));

    // Child L2 spending L1
    let l2_parent = l1.id;
    let l2 = LockRecord::new(l2_parent, [0x02; 32], vec![2], now, valid_until);

    // Attempt to insert child L2 into final_index with is_root = false -> must fail with CausalPredecessorNotFinal
    let res = dual_ram.insert_final(l2.clone(), now, root_valid_until, false);
    assert_eq!(res, Err(CehError::CausalPredecessorNotFinal(l2_parent)));
    assert!(!dual_ram.is_final(&l2_parent));

    // Promote L1 to final with is_root = true -> succeeds
    let promoted = dual_ram.promote_to_final(&parent_l1, now, root_valid_until, true);
    assert!(promoted.is_ok());
    assert_eq!(promoted.unwrap().id, l1.id);
    assert!(dual_ram.is_final(&parent_l1));
    assert!(!dual_ram.is_provisional(&parent_l1));

    // Now insert child L2 into final_index with is_root = false -> succeeds!
    let res2 = dual_ram.insert_final(l2.clone(), now, root_valid_until, false);
    assert_eq!(res2, Ok(IngressVerdictLow::AcceptedNew));
    assert!(dual_ram.is_final(&l2_parent));
}

/// Test 3: Atomic Promotion
///
/// Test provisional insertion, followed by promotion, verifying `is_final` becomes true
/// and `is_provisional` becomes false.
#[test]
fn test_inv_ceh_03_atomic_promotion() {
    let mut dual_ram = DualRamIndex::new();
    let now = SimTime(1000);
    let root_valid_until = SimTime(1_000_000);
    let valid_until = SimTime(500_000);

    let parent = [0x42; 32];
    let rec = LockRecord::new(parent, [0x99; 32], vec![42], now, valid_until);

    // Provisional insertion
    let verdict = dual_ram.insert_provisional(rec.clone(), now, root_valid_until);
    assert_eq!(verdict, Ok(IngressVerdictLow::AcceptedNew));

    assert!(dual_ram.is_provisional(&parent));
    assert!(!dual_ram.is_final(&parent));
    assert_eq!(dual_ram.get(&parent), Some((&rec, LockTier::Provisional)));

    // Promotion to final
    let promoted = dual_ram
        .promote_to_final(&parent, now, root_valid_until, true)
        .expect("promotion succeeds");
    assert_eq!(promoted.id, rec.id);

    // Verify is_final becomes true and is_provisional becomes false
    assert!(dual_ram.is_final(&parent));
    assert!(!dual_ram.is_provisional(&parent));
    assert_eq!(dual_ram.get(&parent), Some((&rec, LockTier::Final)));
}

/// Test 4: Incompatible Genesis Handshake Reject
///
/// Two distinct `GenesisManifest`s with different committees.
/// `verify_handshake_genesis(Some(&g1), Some(&g2))` returns `Err(CehError::IncompatibleGenesisManifest { .. })`.
#[test]
fn test_inv_ceh_04_genesis_handshake_incompatible_reject() {
    let (_, comm1) = generate_committee(1);
    let (_, comm2) = generate_committee(21);

    let g1 = GenesisManifest::new(1, [0x01; 32], 1_700_000_000, comm1);
    let g2 = GenesisManifest::new(1, [0x02; 32], 1_700_000_000, comm2);

    let res = verify_handshake_genesis(Some(&g1), Some(&g2));
    assert_eq!(
        res,
        Err(CehError::IncompatibleGenesisManifest {
            local: g1.canonical_hash(),
            remote: g2.canonical_hash(),
        })
    );

    // Same manifests must succeed with Ok(None)
    assert_eq!(verify_handshake_genesis(Some(&g1), Some(&g1)), Ok(None));
}

/// Test 5: Genesis Pioneer Adoption
///
/// Island node (`local = None`), remote has valid `GenesisManifest` with 14 pioneer signatures.
/// `verify_handshake_genesis(None, Some(&pioneer_g))` returns `Ok(Some(pioneer_g))`.
#[test]
fn test_inv_ceh_05_genesis_pioneer_adoption() {
    let (signers, committee) = generate_committee(10);
    let mut pioneer_g = GenesisManifest::new(1, [0xAA; 32], 1_700_000_000, committee);

    // 14 pioneer signatures (CEH_BFT_QUORUM)
    for sk in signers.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_genesis_manifest(sk, &pioneer_g);
        pioneer_g.add_signature(pk, sig);
    }

    // Island node (local = None), remote has valid pioneer_g
    let res = verify_handshake_genesis(None, Some(&pioneer_g));
    assert_eq!(res, Ok(Some(pioneer_g.clone())));

    // Counter-test: fewer than 14 signatures fails quorum
    let mut insufficient_g = pioneer_g.clone();
    insufficient_g.genesis_signatures.truncate(CEH_BFT_QUORUM - 1);
    let res_fail = verify_handshake_genesis(None, Some(&insufficient_g));
    assert!(matches!(
        res_fail,
        Err(CehError::QuorumNotReached { have: 13, required: 14 })
    ));

    // Both None -> Ok(None)
    assert_eq!(verify_handshake_genesis(None, None), Ok(None));

    // Local Some, remote None -> Ok(None)
    assert_eq!(verify_handshake_genesis(Some(&pioneer_g), None), Ok(None));
}

/// Test 6: Complete Network Progression & Phase Transition (19 -> 20 -> 21 Nodes)
///
/// Validates:
/// 1. $N = 19$: All nodes start unanchored (`network_id = 0`, `manifest = None`).
///    Handshakes among 19 nodes succeed freely (`verify_handshake_genesis(None, None) == Ok(None)`).
/// 2. $N = 20$: Pioneer Activation Ceremony. The 20 nodes co-sign `GenesisManifest` with 14/20 BFT quorum.
///    The network seals its non-zero `NetworkGenesisFingerprint`.
/// 3. $N = 21$: Node 21 starts unanchored (`manifest = None`), connects to the federation,
///    and adopts the sealed manifest via Pioneer Adoption.
/// 4. Incompatibility Defense: An independently grown second 20-node Federation B is strictly rejected.
#[test]
fn test_inv_ceh_06_phase_transition_19_to_20_to_21_nodes() {
    // -------------------------------------------------------------------------
    // Phase 1: N = 19 Unanchored Community Mesh (network_id = 0, manifest = None)
    // -------------------------------------------------------------------------
    let mut node_manifests: Vec<Option<GenesisManifest>> = vec![None; 19];

    // Any two island nodes can peer without restriction
    for i in 0..19 {
        let peer_j = (i + 1) % 19;
        assert_eq!(
            verify_handshake_genesis(node_manifests[i].as_ref(), node_manifests[peer_j].as_ref()),
            Ok(None),
            "Unanchored nodes below N=20 must peer freely with Ok(None)"
        );
    }

    // -------------------------------------------------------------------------
    // Phase 2: N = 20 Transition — Federation Activation Ceremony
    // -------------------------------------------------------------------------
    // A 20th node joins; the 20 nodes form the pioneer committee
    let (signers_20, committee_20) = generate_committee(50);
    let mut federation_manifest = GenesisManifest::new(1, [0x42; 32], 1_700_000_000, committee_20);

    // 14 pioneer signatures (CEH_BFT_QUORUM) seal the manifest
    for sk in signers_20.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_genesis_manifest(sk, &federation_manifest);
        federation_manifest.add_signature(pk, sig);
    }

    // All 20 nodes adopt the sealed manifest (network_id transitions from 0 to fingerprint)
    let fingerprint = federation_manifest.canonical_hash();
    assert_ne!(fingerprint, [0u8; 32], "Fingerprint must be non-zero");

    node_manifests.push(None); // Node 20 joined
    assert_eq!(node_manifests.len(), 20);

    // 20 nodes update their local manifest to the sealed Federation Genesis
    for node_m in node_manifests.iter_mut() {
        *node_m = Some(federation_manifest.clone());
    }

    // Peering within the established federation is strictly verified and compatible
    for i in 0..20 {
        let peer_j = (i + 1) % 20;
        assert_eq!(
            verify_handshake_genesis(node_manifests[i].as_ref(), node_manifests[peer_j].as_ref()),
            Ok(None),
            "Peers within same federation must succeed with Ok(None)"
        );
    }

    // -------------------------------------------------------------------------
    // Phase 3: N = 21 Node Joins via Pioneer Adoption
    // -------------------------------------------------------------------------
    // Node 21 boots fresh: unanchored (network_id = 0, manifest = None)
    let mut node_21_manifest: Option<GenesisManifest> = None;

    // Node 21 handshakes with federation Node 0
    let handshake_res = verify_handshake_genesis(node_21_manifest.as_ref(), node_manifests[0].as_ref())
        .expect("Pioneer adoption handshake must succeed");

    // Node 21 adopts the remote federation manifest
    assert_eq!(handshake_res, Some(federation_manifest.clone()));
    node_21_manifest = handshake_res;

    // Node 21 is now a fully anchored federation member!
    assert_eq!(node_21_manifest.as_ref().unwrap().canonical_hash(), fingerprint);

    // Subsequent handshakes with another federation member (e.g. Node 15) succeed as peers
    assert_eq!(
        verify_handshake_genesis(node_21_manifest.as_ref(), node_manifests[15].as_ref()),
        Ok(None)
    );

    // -------------------------------------------------------------------------
    // Phase 4: Collision Defense — Separate Independent Federation B Rejected
    // -------------------------------------------------------------------------
    let (signers_b, committee_b) = generate_committee(100);
    let mut federation_b = GenesisManifest::new(1, [0x99; 32], 1_700_000_000, committee_b);
    for sk in signers_b.iter().take(CEH_BFT_QUORUM) {
        let (pk, sig) = sign_genesis_manifest(sk, &federation_b);
        federation_b.add_signature(pk, sig);
    }

    // Handshake between Federation A and Federation B must fail with IncompatibleGenesisManifest
    let reject_res = verify_handshake_genesis(node_21_manifest.as_ref(), Some(&federation_b));
    assert_eq!(
        reject_res,
        Err(CehError::IncompatibleGenesisManifest {
            local: fingerprint,
            remote: federation_b.canonical_hash(),
        })
    );
}

/// Test 7: INV-1106 Cryptographic Gossip Domain Separation (Heartbeat Zero-Trust Isolation)
///
/// Proves that even if malicious friend nodes tunnel heartbeats across networks,
/// honest peers strictly reject foreign heartbeats at the signature layer without growing wire size.
#[test]
fn test_inv_1106_heartbeat_cryptographic_domain_isolation() {
    use humoco_sim_core::fraud::{
        compute_heartbeat_digest, verify_heartbeat_signature_strict, IngressEnvelopeEvidence,
    };
    use humoco_sim_core::types::NetworkId;
    use ed25519_dalek::Signer;

    let (sk, pk) = generate_keypair(77);
    let now_ms = 1_700_000_123u64;

    // 1. Node signs heartbeat under Mainnet domain
    let digest_mainnet = compute_heartbeat_digest(
        NetworkId::Mainnet,
        &pk,
        0,
        0,
        now_ms,
        5_000_000,
        1_000,
        0,
        false,
        &[0u8; 32],
    );
    let sig_mainnet = sk.sign(&digest_mainnet).to_bytes();

    let mut hb_evidence = IngressEnvelopeEvidence::new_v2(
        pk,
        0,
        0,
        now_ms,
        5_000_000,
        1_000,
        0,
        false,
        [0u8; 32],
        sig_mainnet,
    );

    // 2. Honest Mainnet peer verifies successfully
    assert!(
        verify_heartbeat_signature_strict(NetworkId::Mainnet, &hb_evidence),
        "Mainnet peer must accept authentic Mainnet heartbeat"
    );

    // 3. Rogue peer tunnels this heartbeat to Testnet peer
    // Honest Testnet peer verifies with NetworkId::Testnet:
    assert!(
        !verify_heartbeat_signature_strict(NetworkId::Testnet, &hb_evidence),
        "INV-1106: Testnet peer MUST strictly reject Mainnet heartbeat at signature layer!"
    );

    // 4. Counter-test: Sign under Testnet, verify on Mainnet must also fail
    let digest_testnet = compute_heartbeat_digest(
        NetworkId::Testnet,
        &pk,
        0,
        0,
        now_ms,
        5_000_000,
        1_000,
        0,
        false,
        &[0u8; 32],
    );
    hb_evidence.signature = sk.sign(&digest_testnet).to_bytes();

    assert!(
        verify_heartbeat_signature_strict(NetworkId::Testnet, &hb_evidence),
        "Testnet peer accepts authentic Testnet heartbeat"
    );
    assert!(
        !verify_heartbeat_signature_strict(NetworkId::Mainnet, &hb_evidence),
        "INV-1106: Mainnet peer MUST strictly reject Testnet heartbeat at signature layer!"
    );
}

