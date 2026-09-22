//! Spec 03 – Shard Baton Handover and Network Growth Test Suite
//!
//! Validates the Baton Principle (Staffelstab-Prinzip) under evolutionary network growth:
//! 1. Genesis & initial voucher locks on a specific target shard.
//! 2. Progressive network growth (N=20 -> N=40 -> N=60) with HRW rank shifting.
//! 3. Newly promoted Top-20 shard custodians successfully PULL sync the shard state
//!    via 2-phase digest clustering (evaluate_digest_clusters >= 14/20).
//! 4. Decommissioning of old generation nodes without loss of availability.
//! 5. Seamless causal succession: Child locks referencing earlier parent locks
//!    are verified and committed by the new generation custodians.
//! 6. Byzantine resilience during baton handover (filtering fake digests).

use std::collections::BTreeMap;

use humoco_sim_core::crypto::compute_shard_digest;
use humoco_sim_core::types::{
    evaluate_digest_clusters, required_quorum, select_shard_candidates, ClusterResult, Hash256,
    LockRecord, NodeId, ShardDigestResponse, ShardId, SimTime,
};

const TARGET_SHARD: ShardId = 1337;

/// Helper to generate a chain of locks for a specific voucher root.
fn make_test_voucher_locks(count: usize) -> Vec<LockRecord> {
    let mut locks = Vec::with_capacity(count);
    let mut prev_parent = [0x42u8; 32];
    for i in 0..count {
        let mut receiver = [0x55u8; 32];
        receiver[0] = i as u8;
        let nonce = format!("voucher_tx_seq_{}", i).into_bytes();
        let lock = LockRecord::new(
            prev_parent,
            receiver,
            nonce,
            SimTime(0),
            SimTime(100_000), // well within validity window
        );
        prev_parent = lock.id;
        locks.push(lock);
    }
    locks
}

#[test]
fn test_shard_baton_handover_multi_generation_growth() {
    // =========================================================================
    // Generation 1: Initial N=20 network
    // =========================================================================
    let gen1_nodes: Vec<NodeId> = (0..20).collect();
    let initial_locks = make_test_voucher_locks(5);
    let d_gen1 = compute_shard_digest(TARGET_SHARD, &initial_locks);

    // Initial Top-20 ranking for TARGET_SHARD among N=20
    let gen1_top20 = select_shard_candidates(&gen1_nodes, TARGET_SHARD, 20);
    assert_eq!(gen1_top20.len(), 20, "All 20 nodes are in Top-20 for N=20");

    // All Gen 1 nodes store the initial locks in their local RAM index
    let mut node_storage: BTreeMap<NodeId, BTreeMap<Hash256, LockRecord>> = BTreeMap::new();
    for &node_id in &gen1_nodes {
        let mut ram: BTreeMap<Hash256, LockRecord> = BTreeMap::new();
        for l in &initial_locks {
            ram.insert(l.id, l.clone());
        }
        node_storage.insert(node_id, ram);
    }

    // Verify all Gen 1 nodes produce identical digest
    for &node_id in &gen1_nodes {
        let locks: Vec<LockRecord> = node_storage[&node_id].values().cloned().collect();
        let digest = compute_shard_digest(TARGET_SHARD, &locks);
        assert_eq!(digest, d_gen1);
    }

    // =========================================================================
    // Generation 2: Network grows to N=40 (Nodes 0..40)
    // =========================================================================
    let gen2_all_nodes: Vec<NodeId> = (0..40).collect();
    let gen2_top20 = select_shard_candidates(&gen2_all_nodes, TARGET_SHARD, 20);

    // Identify newly promoted nodes in Gen 2 that were not in Gen 1 top-20 (i.e. node_id >= 20)
    let newly_promoted_gen2: Vec<NodeId> = gen2_top20
        .iter()
        .copied()
        .filter(|&nid| nid >= 20)
        .collect();

    assert!(
        !newly_promoted_gen2.is_empty(),
        "Network growth to N=40 must naturally promote new nodes into Top-20"
    );

    // Newly promoted nodes perform Digest-First PULL Sync from incumbent peers
    for &new_node in &newly_promoted_gen2 {
        // Phase 1: Query ShardDigest from incumbent Top-20 peers
        let mut responses = Vec::new();
        for &peer_id in &gen1_top20 {
            if let Some(peer_ram) = node_storage.get(&peer_id) {
                let peer_locks: Vec<LockRecord> = peer_ram.values().cloned().collect();
                let peer_digest = compute_shard_digest(TARGET_SHARD, &peer_locks);
                responses.push(ShardDigestResponse {
                    peer_id,
                    digest: peer_digest,
                    lock_count: peer_locks.len() as u32,
                });
            }
        }

        // Phase 2: BFT Majority Clustering (evaluate_digest_clusters)
        let cluster = evaluate_digest_clusters(&responses, 20);
        let dominant_digest = match cluster {
            ClusterResult::DominantQuorum {
                digest,
                votes,
                peers,
            } => {
                let (needed, is_final) = required_quorum(20);
                assert!(is_final);
                assert!(
                    votes >= needed,
                    "Votes {} must satisfy required quorum {}",
                    votes,
                    needed
                );
                assert_eq!(digest, d_gen1, "Dominant digest must match Gen 1 state");
                assert_eq!(peers.len(), 20);
                digest
            }
            ClusterResult::InsufficientQuorum { .. } => {
                panic!("Expected DominantQuorum during baton sync")
            }
        };

        // Phase 3 & 4: Stream locks from a dominant peer & commit to local RAM
        let sync_source_node = gen1_top20[0];
        let synced_locks: Vec<LockRecord> = node_storage[&sync_source_node]
            .values()
            .cloned()
            .collect();
        let stream_digest = compute_shard_digest(TARGET_SHARD, &synced_locks);
        assert_eq!(stream_digest, dominant_digest);

        let mut new_ram = BTreeMap::new();
        for l in synced_locks {
            new_ram.insert(l.id, l);
        }
        node_storage.insert(new_node, new_ram);
    }

    // =========================================================================
    // Phase 3: Decommissioning of old Gen-1 nodes that fell out of Top-20
    // =========================================================================
    let demoted_gen1_nodes: Vec<NodeId> = gen1_nodes
        .iter()
        .copied()
        .filter(|nid| !gen2_top20.contains(nid))
        .collect();

    assert!(
        !demoted_gen1_nodes.is_empty(),
        "Some Gen 1 nodes must be demoted"
    );

    // Decommission / remove demoted nodes from active storage
    for &demoted in &demoted_gen1_nodes {
        node_storage.remove(&demoted);
    }

    // Verify: All current Gen 2 Top-20 nodes hold identical state and digest
    for &top_node in &gen2_top20 {
        assert!(
            node_storage.contains_key(&top_node),
            "Top-20 node {} must hold active shard state",
            top_node
        );
        let locks: Vec<LockRecord> = node_storage[&top_node].values().cloned().collect();
        assert_eq!(compute_shard_digest(TARGET_SHARD, &locks), d_gen1);
    }

    // =========================================================================
    // Generation 3: Further Growth to N=60 (Nodes 0..60)
    // =========================================================================
    let gen3_all_nodes: Vec<NodeId> = (0..60).collect();
    let gen3_top20 = select_shard_candidates(&gen3_all_nodes, TARGET_SHARD, 20);

    let newly_promoted_gen3: Vec<NodeId> = gen3_top20
        .iter()
        .copied()
        .filter(|&nid| !node_storage.contains_key(&nid))
        .collect();

    // Gen 3 newly promoted nodes sync from Gen 2 Top-20
    for &new_node in &newly_promoted_gen3 {
        let mut responses = Vec::new();
        for &peer_id in &gen2_top20 {
            if let Some(peer_ram) = node_storage.get(&peer_id) {
                let peer_locks: Vec<LockRecord> = peer_ram.values().cloned().collect();
                let peer_digest = compute_shard_digest(TARGET_SHARD, &peer_locks);
                responses.push(ShardDigestResponse {
                    peer_id,
                    digest: peer_digest,
                    lock_count: peer_locks.len() as u32,
                });
            }
        }

        let cluster = evaluate_digest_clusters(&responses, 20);
        let dominant_digest = match cluster {
            ClusterResult::DominantQuorum { digest, votes, .. } => {
                assert!(votes >= 14);
                assert_eq!(digest, d_gen1);
                digest
            }
            ClusterResult::InsufficientQuorum { .. } => panic!("Expected DominantQuorum in Gen 3"),
        };

        let sync_peer = gen2_top20
            .iter()
            .find(|p| node_storage.contains_key(p))
            .copied()
            .expect("active peer available");
        let synced_locks: Vec<LockRecord> =
            node_storage[&sync_peer].values().cloned().collect();
        assert_eq!(
            compute_shard_digest(TARGET_SHARD, &synced_locks),
            dominant_digest
        );

        let mut new_ram = BTreeMap::new();
        for l in synced_locks {
            new_ram.insert(l.id, l);
        }
        node_storage.insert(new_node, new_ram);
    }

    // =========================================================================
    // Phase 4: Kausale Folge-Transaktion (Child-Lock Ingress) on Gen 3
    // =========================================================================
    // Create a new child lock that spends the last initial lock
    let last_gen1_lock = initial_locks.last().unwrap();
    let parent_id = last_gen1_lock.id;
    let child_lock = LockRecord::new(
        parent_id,
        [0x99u8; 32],
        b"child_spend_gen3".to_vec(),
        SimTime(100),
        SimTime(100_000),
    );
    let child_lock_id = child_lock.id;

    // Send child lock to Gen 3 Top-20 nodes:
    // They must verify that parent_id exists in RAM and hasn't been spent yet.
    let mut attestations = 0;
    for &node_id in &gen3_top20 {
        let ram = node_storage.get_mut(&node_id).expect("Gen 3 node exists");
        assert!(
            ram.contains_key(&parent_id),
            "Gen 3 node must know parent_lock from baton handover"
        );
        // Verify no collision on parent_lock
        let collision = ram.values().any(|l| l.parent_lock == parent_id);
        assert!(!collision, "No double spend on parent");

        ram.insert(child_lock_id, child_lock.clone());
        attestations += 1;
    }

    assert_eq!(attestations, 20);

    // Verify all Gen 3 Top-20 nodes converged to new shard digest including child lock
    let all_current_locks: Vec<LockRecord> = {
        let mut v = initial_locks;
        v.push(child_lock);
        v
    };
    let expected_d_gen3 = compute_shard_digest(TARGET_SHARD, &all_current_locks);

    for &node_id in &gen3_top20 {
        let locks: Vec<LockRecord> = node_storage[&node_id].values().cloned().collect();
        assert_eq!(compute_shard_digest(TARGET_SHARD, &locks), expected_d_gen3);
    }
}

#[test]
fn test_shard_baton_handover_byzantine_noise_filtering() {
    let initial_locks = make_test_voucher_locks(3);
    let genuine_digest = compute_shard_digest(TARGET_SHARD, &initial_locks);

    let fake_digest_1 = {
        let mut h = blake3::Hasher::new();
        h.update(b"byzantine_fake_1");
        *h.finalize().as_bytes()
    };
    let fake_digest_2 = {
        let mut h = blake3::Hasher::new();
        h.update(b"byzantine_fake_2");
        *h.finalize().as_bytes()
    };

    // 14 honest nodes returning genuine_digest
    // 3 Byzantine nodes returning fake_digest_1
    // 2 Byzantine nodes returning fake_digest_2
    // 1 Offline / non-responding node
    let mut responses = Vec::new();
    for i in 0..14 {
        responses.push(ShardDigestResponse {
            peer_id: i,
            digest: genuine_digest,
            lock_count: 3,
        });
    }
    for i in 14..17 {
        responses.push(ShardDigestResponse {
            peer_id: i,
            digest: fake_digest_1,
            lock_count: 10,
        });
    }
    for i in 17..19 {
        responses.push(ShardDigestResponse {
            peer_id: i,
            digest: fake_digest_2,
            lock_count: 99,
        });
    }
    // peer 19 dropped / timed out

    let cluster = evaluate_digest_clusters(&responses, 20);
    match cluster {
        ClusterResult::DominantQuorum {
            digest,
            votes,
            peers,
        } => {
            assert_eq!(digest, genuine_digest, "Genuine digest must win BFT cluster");
            assert_eq!(votes, 14, "Dominant cluster must have 14 votes");
            assert_eq!(peers.len(), 14);
            for p in &peers {
                assert!(*p < 14, "Only honest peers in dominant cluster");
            }
        }
        ClusterResult::InsufficientQuorum { .. } => {
            panic!("Expected DominantQuorum despite Byzantine noise");
        }
    }
}
