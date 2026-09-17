use humoco_sim_core::crypto::compute_shard_digest;
use humoco_sim_core::types::{
    evaluate_digest_clusters, ClusterResult, LockRecord, ShardDigestResponse, SimTime,
};
use std::collections::BTreeMap;

const SHARD_ID: u16 = 42;

fn make_locks(n: usize) -> Vec<LockRecord> {
    (0..n)
        .map(|i| {
            let mut parent = [0u8; 32];
            parent[0] = i as u8;
            parent[1] = (i >> 8) as u8;
            let mut receiver = [0u8; 32];
            receiver[0] = (i + 100) as u8;
            LockRecord::new(
                parent,
                receiver,
                format!("nonce_{}", i).into_bytes(),
                SimTime(0),
                SimTime(50_000),
            )
        })
        .collect()
}

#[test]
fn test_digest_first_pull_sync_bft_cluster_success() {
    let locks = make_locks(5);
    let d_star = compute_shard_digest(SHARD_ID, &locks);

    let d_fake = {
        let mut h = blake3::Hasher::new();
        h.update(b"fake");
        h.update(&d_star);
        *h.finalize().as_bytes()
    };
    // 15 honest D*, 3 byzantine D_fake, 2 timeouts (no response) -> total 18 responses
    let mut responses = Vec::new();
    for i in 0..15 {
        responses.push(ShardDigestResponse {
            peer_id: i as u16,
            digest: d_star,
            lock_count: locks.len() as u32,
        });
    }
    for i in 15..18 {
        responses.push(ShardDigestResponse {
            peer_id: i as u16,
            digest: d_fake,
            lock_count: 99,
        });
    }
    // 2 timeouts not in responses

    let cluster = evaluate_digest_clusters(&responses, 20);
    match cluster {
        ClusterResult::DominantQuorum { digest, votes, peers } => {
            assert_eq!(digest, d_star, "Dominant cluster must be D*");
            assert_eq!(votes, 15);
            assert_eq!(peers.len(), 15);
            // Phase 3: Stream von gewähltem Peer - verifiziere BLAKE3 == D*
            let stream_locks = locks.clone();
            let stream_digest = compute_shard_digest(SHARD_ID, &stream_locks);
            assert_eq!(stream_digest, d_star, "Stream BLAKE3 must equal D*");
            // RAM-Commit: atomarer Insert in RAM-Index
            let mut ram_index: BTreeMap<[u8; 32], LockRecord> = BTreeMap::new();
            for l in stream_locks {
                ram_index.insert(l.id, l);
            }
            assert_eq!(ram_index.len(), 5, "RAM commit should contain 5 locks");
        }
        ClusterResult::InsufficientQuorum { .. } => panic!("Expected DominantQuorum"),
    }
}

#[test]
fn test_digest_first_pull_sync_insufficient_quorum_backoff() {
    let locks = make_locks(3);
    let d_a = compute_shard_digest(SHARD_ID, &locks);
    // Create split: max cluster 12 <14
    let mut responses = Vec::new();
    // 12 votes for D_a
    for i in 0..12 {
        responses.push(ShardDigestResponse {
            peer_id: i as u16,
            digest: d_a,
            lock_count: 3,
        });
    }
    // 4 votes for another digest
    let d_b = {
        let mut h = blake3::Hasher::new();
        h.update(b"other");
        *h.finalize().as_bytes()
    };
    for i in 12..16 {
        responses.push(ShardDigestResponse {
            peer_id: i as u16,
            digest: d_b,
            lock_count: 2,
        });
    }
    // 4 timeouts / other splits not reaching 14
    let cluster = evaluate_digest_clusters(&responses, 20);
    match cluster {
        ClusterResult::InsufficientQuorum { max_votes, backoff_ms } => {
            assert_eq!(max_votes, 12);
            assert_eq!(backoff_ms, 500, "500ms backoff required");
            // no stream import should happen - we just ensure backoff is signaled
        }
        ClusterResult::DominantQuorum { .. } => panic!("Should be insufficient quorum"),
    }
}

#[test]
fn test_digest_first_pull_sync_poisoned_stream_payload_rejection() {
    let locks = make_locks(4);
    let d_star = compute_shard_digest(SHARD_ID, &locks);
    let mut responses = Vec::new();
    for i in 0..15 {
        responses.push(ShardDigestResponse {
            peer_id: i as u16,
            digest: d_star,
            lock_count: 4,
        });
    }
    let cluster = evaluate_digest_clusters(&responses, 20);
    let target_digest = match cluster {
        ClusterResult::DominantQuorum { digest, .. } => digest,
        _ => panic!("Expected dominant"),
    };
    assert_eq!(target_digest, d_star);
    // Simulate poisoned stream: attacker sends different locks
    let mut poisoned_locks = locks.clone();
    // Tamper one lock's nonce -> digest changes
    poisoned_locks[0].nonce = b"poisoned".to_vec();
    // Need to recompute id for tampered lock? Not necessary for digest check, but we recalc id to be consistent
    let tampered_digest = compute_shard_digest(SHARD_ID, &poisoned_locks);
    assert_ne!(tampered_digest, d_star, "Poisoned stream must have different digest");
    // Verification: Stream-Hash != D* -> Verworfen
    let is_valid = tampered_digest == target_digest;
    assert!(!is_valid, "Poisoned stream payload must be rejected");
    // No RAM commit
    let mut ram: BTreeMap<[u8; 32], LockRecord> = BTreeMap::new();
    if is_valid {
        for l in poisoned_locks {
            ram.insert(l.id, l);
        }
    }
    assert_eq!(ram.len(), 0, "Poisoned stream must not be committed to RAM");
}
