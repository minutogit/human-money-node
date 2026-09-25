use crate::types::{
    Attestation, Hash256, LockId, LockRecord, NetworkId, NodeId, NodePubKey, ShardId, SimTime,
};

pub const DOMAIN_CANON_RESOLVER: &[u8] = b"HUMOCO_V1_CANON_RESOLVER";
pub const DOMAIN_EQUIVOCATION: &[u8] = b"HUMOCO_V1_EQUIVOCATION";
pub const HUMOCO_V1_APPROVE_PROV_MAINNET: &[u8] = b"HUMOCO_V1_APPROVE_PROV_MAINNET";
pub const HUMOCO_V1_APPROVE_PROV_TESTNET: &[u8] = b"HUMOCO_V1_APPROVE_PROV_TESTNET";
pub const HUMOCO_V1_APPROVE_FINAL_MAINNET: &[u8] = b"HUMOCO_V1_APPROVE_FINAL_MAINNET";
pub const HUMOCO_V1_APPROVE_FINAL_TESTNET: &[u8] = b"HUMOCO_V1_APPROVE_FINAL_TESTNET";
pub const HUMOCO_V1_ATTESTATION_MAINNET: &[u8] = b"HUMOCO_V1_ATTESTATION_MAINNET";
pub const HUMOCO_V1_ATTESTATION_TESTNET: &[u8] = b"HUMOCO_V1_ATTESTATION_TESTNET";
/// Backward-compatible aliases (point to Mainnet)
pub const DOMAIN_ATTESTATION: &[u8] = HUMOCO_V1_ATTESTATION_MAINNET;
pub const DOMAIN_APPROVE_PROV: &[u8] = HUMOCO_V1_APPROVE_PROV_MAINNET;
pub const DOMAIN_APPROVE_FINAL: &[u8] = HUMOCO_V1_APPROVE_FINAL_MAINNET;
pub const DOMAIN_GENESIS: &[u8] = b"HUMOCO_V1_GENESIS";
pub const DOMAIN_INGRESS_DECL: &[u8] = b"HUMOCO_V1_INGRESS_DECL";
pub const DOMAIN_BRIDGE_LOCK: &[u8] = b"HUMOCO_V1_BRIDGE_LOCK";
pub const DOMAIN_HYBRID_NODE_ID: &[u8] = b"HUMOCO_V2_HYBRID_NODE_ID";
pub const DOMAIN_HRW_ROUTING_TICKET: &[u8] = b"HUMOCO_V1_HRW_ROUTING_TICKET";

/// Computes the deterministic work score W from a 32-byte PoW proof hash.
///
/// Uses leading zeros and the top 64-bit prefix for O(1) arithmetic without big-int crates.
/// Guarantees panic-freedom, monotonicity, and non-zero positive work (minimum floor >= 1).
pub fn compute_work_from_hash(hash: &[u8; 32]) -> u64 {
    let mut prefix_bytes = [0u8; 8];
    prefix_bytes.copy_from_slice(&hash[0..8]);
    let prefix = u64::from_be_bytes(prefix_bytes);

    if prefix == 0 {
        // Hash has at least 64 leading zero bits -> saturated maximum work
        return u64::MAX;
    }

    // W = 2^64 / (prefix + 1)
    let work = ((1u128 << 64) / ((prefix as u128) + 1)) as u64;
    work.max(1)
}

/// Computes the uniform 256-bit HrwRoutingId via BLAKE3 domain separation (Whitening).
///
/// WhitenedId = BLAKE3(len || DOMAIN_HRW_ROUTING_TICKET || NodePubKey || Nonce_LE || T0_LE || PoW_Proof)
pub fn compute_whitened_hrw_id(
    node_pubkey: &[u8; 32],
    nonce: u64,
    t0: u64,
    pow_proof: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_HRW_ROUTING_TICKET.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_HRW_ROUTING_TICKET);
    hasher.update(node_pubkey);
    hasher.update(&nonce.to_le_bytes());
    hasher.update(&t0.to_le_bytes());
    hasher.update(pow_proof);
    *hasher.finalize().as_bytes()
}

/// Returns the domain tag for provisional quorum certificates for the given network.
pub fn domain_approve_prov(network_id: NetworkId) -> &'static [u8] {
    match network_id {
        NetworkId::Mainnet => HUMOCO_V1_APPROVE_PROV_MAINNET,
        NetworkId::Testnet => HUMOCO_V1_APPROVE_PROV_TESTNET,
    }
}

/// Returns the domain tag for final quorum certificates for the given network.
pub fn domain_approve_final(network_id: NetworkId) -> &'static [u8] {
    match network_id {
        NetworkId::Mainnet => HUMOCO_V1_APPROVE_FINAL_MAINNET,
        NetworkId::Testnet => HUMOCO_V1_APPROVE_FINAL_TESTNET,
    }
}

/// Returns the domain tag for attestations for the given network.
pub fn domain_attestation(network_id: NetworkId) -> &'static [u8] {
    match network_id {
        NetworkId::Mainnet => HUMOCO_V1_ATTESTATION_MAINNET,
        NetworkId::Testnet => HUMOCO_V1_ATTESTATION_TESTNET,
    }
}

/// Computes the deterministic root hash of the network (definition genesis, docs/04:255, docs/10:191)
/// GenesisRoot = BLAKE3(len || "HUMOCO_V1_GENESIS" || protocol_version_le || t0_unix_sec_le)
pub fn compute_genesis_root(protocol_version: u32, t0_unix_sec: u64) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_GENESIS.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_GENESIS);
    hasher.update(&protocol_version.to_le_bytes());
    hasher.update(&t0_unix_sec.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the canonical hash for the deterministic resolver (docs/02:97, Spec 02, 08)
/// H_canon(Lock) = BLAKE3(len || "HUMOCO_V1_CANON_RESOLVER" || Parent_Hash || Receiver_Pub || Sig/Witness)
///
/// # Architectural Invariant & Design Note:
/// - `min(H_canon)` is a purely deterministic tie-breaker on network merges (order-independent), NOT a proof-of-work.
/// - Security against double-spending relies on the irrefutable EquivocationProof (`HUMOCO_V1_EQUIVOCATION`),
///   which permanently bans the offending node identity (`NodePubKey`), revokes the shard ticket (`HrwRoutingId`),
///   and severs all Web-of-Trust edges.
/// - The `nonce` parameter takes the 64-byte Ed25519 signature entropy or transaction witness slice.
pub fn compute_canonical_hash(
    parent_lock: &Hash256,
    receiver_pub: &Hash256,
    nonce: &[u8],
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_CANON_RESOLVER.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_CANON_RESOLVER);
    hasher.update(parent_lock);
    hasher.update(receiver_pub);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// Computes the canonical hash with the Ed25519 signature as entropy source (docs/02:97)
pub fn compute_canonical_hash_with_sig(
    parent_lock: &Hash256,
    receiver_pub: &Hash256,
    sig: &[u8; 64],
) -> Hash256 {
    compute_canonical_hash(parent_lock, receiver_pub, sig)
}

/// Normalized canonical hash with witness separation:
/// BLAKE3(receiver) and BLAKE3(sig) are pre-hashed before being folded into the canonical hash.
pub fn compute_canonical_hash_normalized(
    parent_lock: &[u8; 32],
    receiver_bytes: &[u8],
    sig_bytes: &[u8],
) -> [u8; 32] {
    let receiver_hash = blake3::hash(receiver_bytes);
    let sig_hash = blake3::hash(sig_bytes);
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_CANON_RESOLVER.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_CANON_RESOLVER);
    hasher.update(parent_lock);
    hasher.update(receiver_hash.as_bytes());
    hasher.update(sig_hash.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Single source of truth preimage hashing with length prefix (docs/04:276, docs/10:193)
/// SigDigest = BLAKE3(len || DOMAIN_TAG || epoch_id_le || session_seq_le || flags_le || shard_id_le || status_tag || payload_digest)
pub fn compute_sig_digest(
    domain_tag: &[u8],
    epoch_id: u32,
    session_seq: u64,
    flags: u32,
    shard_id: ShardId,
    status_tag: u8,
    payload_digest: &[u8; 32],
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    let tag_len = domain_tag.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(domain_tag);
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&session_seq.to_le_bytes());
    hasher.update(&flags.to_le_bytes());
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&[status_tag]);
    hasher.update(payload_digest);
    *hasher.finalize().as_bytes()
}

/// Creates a deterministic test signature for a shard node for a specific network
pub fn sign_lock_attestation_for_network(
    node_id: NodeId,
    lock_id: &LockId,
    parent_lock: &Hash256,
    timestamp: SimTime,
    network_id: NetworkId,
) -> Attestation {
    let domain = domain_attestation(network_id);
    let mut hasher = blake3::Hasher::new();
    let tag_len = domain.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(domain);
    hasher.update(&node_id.to_le_bytes());
    hasher.update(lock_id);
    hasher.update(parent_lock);
    hasher.update(&timestamp.0.to_le_bytes());
    let digest = hasher.finalize();

    // 64-byte deterministic signature: [digest (32B) || node_id (2B) || padding (30B)]
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(digest.as_bytes());
    signature[32..34].copy_from_slice(&node_id.to_le_bytes());

    Attestation {
        lock_id: *lock_id,
        parent_lock: *parent_lock,
        node_id,
        timestamp,
        signature,
    }
}

/// Creates a deterministic test signature for a shard node (defaults to Mainnet)
pub fn sign_lock_attestation(
    node_id: NodeId,
    lock_id: &LockId,
    parent_lock: &Hash256,
    timestamp: SimTime,
) -> Attestation {
    sign_lock_attestation_for_network(node_id, lock_id, parent_lock, timestamp, NetworkId::Mainnet)
}

/// Verifies the deterministic attestation signature for a specific network
pub fn verify_attestation_for_network(
    attestation: &Attestation,
    network_id: NetworkId,
) -> bool {
    let domain = domain_attestation(network_id);
    let mut hasher = blake3::Hasher::new();
    let tag_len = domain.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(domain);
    hasher.update(&attestation.node_id.to_le_bytes());
    hasher.update(&attestation.lock_id);
    hasher.update(&attestation.parent_lock);
    hasher.update(&attestation.timestamp.0.to_le_bytes());
    let digest = hasher.finalize();

    let sig_prefix = &attestation.signature[..32];
    let sig_node_id = u16::from_le_bytes([attestation.signature[32], attestation.signature[33]]);

    sig_prefix == digest.as_bytes() && sig_node_id == attestation.node_id
}

/// Verifies the deterministic attestation signature (defaults to Mainnet)
pub fn verify_attestation(attestation: &Attestation) -> bool {
    verify_attestation_for_network(attestation, NetworkId::Mainnet)
}

/// Creates a deterministic signature for a (PubKey, LockId) pair
/// Semantically decoupled: signature is based on the permanent Ed25519 identity NodePubKey
pub fn sign_deterministic_sig(pub_key: &NodePubKey, lock_id: &LockId) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_ATTESTATION.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_ATTESTATION);
    hasher.update(pub_key);
    hasher.update(lock_id);
    let digest = hasher.finalize();

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(digest.as_bytes());
    signature[32..64].copy_from_slice(pub_key);
    signature
}

/// Verifies a deterministic signature against the public key and lock ID
pub fn verify_deterministic_sig(pub_key: &NodePubKey, lock_id: &LockId, signature: &[u8; 64]) -> bool {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_ATTESTATION.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_ATTESTATION);
    hasher.update(pub_key);
    hasher.update(lock_id);
    let digest = hasher.finalize();

    let sig_digest = &signature[..32];
    let sig_pubkey = &signature[32..64];
    sig_digest == digest.as_bytes() && sig_pubkey == pub_key
}

/// Computes the shard digest for the 2-phase pull sync (spec_03)
/// ShardDigest(S) = BLAKE3(0x01 || shard_id.to_le_bytes() || lock_1 || ... || lock_m)
/// over all active locks (valid_until > now, !status.is_void()), lexicographically sorted by parent_lock.
pub fn compute_shard_digest(shard_id: ShardId, locks: &[LockRecord]) -> Hash256 {
    compute_shard_digest_at(shard_id, locks, SimTime(0))
}

/// # Architectural Invariant: BFT Shard-Digest Pull vs. Random Storage Polling (Spec 03 & KISS)
///
/// This function is the cryptographic core of the **2-phase BFT digest-pull sync**.
/// Phase 1 compares the compact `ShardDigest(S)` (this hash) across shard peers; Phase 2
/// pulls the full lock set only on divergence (`evaluate_digest_clusters` / dominant quorum).
/// The digest is computed over all active locks (`valid_until > now`, `!is_void`), sorted
/// by `parent_lock` and hashed as `BLAKE3(0x01 || shard_id || lock_1 || ... || lock_m)`.
///
/// Why polling is avoided (KISS & Spec 03): Continuous random storage polling (e.g. picking
/// random `parent_lock` keys and comparing single records) is probabilistically complete
/// only after O(N) round trips, creates unpredictable disk I/O on the hot-path, and cannot
/// prove convergence in bounded time. In contrast, the 2-phase digest pull is
/// **mathematically sufficient**: equality of the canonical digest proves equality of the
/// entire sorted active set under the collision-resistant BLAKE3; a single 32-byte hash
/// per shard replaces unbounded random probes. The periodic 60s ticker plus event-driven
/// `sync_notifier` (see `daemon::run_shard_digest_pull_sync`) therefore guarantees deterministic
/// catch-up after partitions without any continuous random polling overhead.
///
/// Variant with explicit time filter (for real valid_until checks)
pub fn compute_shard_digest_at(shard_id: ShardId, locks: &[LockRecord], now: SimTime) -> Hash256 {
    let mut active: Vec<&LockRecord> = locks
        .iter()
        .filter(|l| !l.status.is_void() && l.valid_until > now)
        .collect();
    active.sort_by(|a, b| a.parent_lock.cmp(&b.parent_lock));
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(&shard_id.to_le_bytes());
    for lock in active {
        hasher.update(&lock.parent_lock);
        hasher.update(&lock.receiver_pub);
        hasher.update(&lock.nonce);
        hasher.update(&lock.id);
    }
    *hasher.finalize().as_bytes()
}

/// Creates a deterministic equivocation proof hash
pub fn create_equivocation_proof(node_id: NodeId, lock_a: &Hash256, lock_b: &Hash256) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[DOMAIN_EQUIVOCATION.len() as u8]);
    hasher.update(DOMAIN_EQUIVOCATION);
    hasher.update(&node_id.to_le_bytes());
    if lock_a <= lock_b {
        hasher.update(lock_a);
        hasher.update(lock_b);
    } else {
        hasher.update(lock_b);
        hasher.update(lock_a);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_hash_determinism() {
        let parent = [1u8; 32];
        let receiver = [2u8; 32];
        let nonce = b"test_salt";

        let h1 = compute_canonical_hash(&parent, &receiver, nonce);
        let h2 = compute_canonical_hash(&parent, &receiver, nonce);
        assert_eq!(h1, h2);

        let h3 = compute_canonical_hash(&parent, &receiver, b"different_salt");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_attestation_signing_and_verification() {
        let node_id = 42;
        let lock_id = [7u8; 32];
        let parent_lock = [3u8; 32];
        let time = SimTime(1000);

        let att = sign_lock_attestation(node_id, &lock_id, &parent_lock, time);
        assert!(verify_attestation(&att));

        let mut tampered = att.clone();
        tampered.lock_id[0] ^= 0xFF;
        assert!(!verify_attestation(&tampered));
    }

    #[test]
    fn test_network_domain_separation_prevents_cross_replay() {
        let node_id = 42;
        let lock_id = [7u8; 32];
        let parent_lock = [3u8; 32];
        let time = SimTime(1000);

        // Sign an attestation specifically for Testnet
        let testnet_att = sign_lock_attestation_for_network(
            node_id,
            &lock_id,
            &parent_lock,
            time,
            NetworkId::Testnet,
        );

        // It must be valid in Testnet
        assert!(verify_attestation_for_network(&testnet_att, NetworkId::Testnet));

        // It MUST FAIL when submitted to Mainnet (Cross-Network Replay Protection!)
        assert!(!verify_attestation_for_network(&testnet_att, NetworkId::Mainnet));
        assert!(!verify_attestation(&testnet_att));

        // Check the quorum domain tags as well
        assert_ne!(
            domain_approve_prov(NetworkId::Mainnet),
            domain_approve_prov(NetworkId::Testnet)
        );
        assert_ne!(
            domain_approve_final(NetworkId::Mainnet),
            domain_approve_final(NetworkId::Testnet)
        );
    }

    #[test]
    fn test_equivocation_proof_symmetry_and_determinism() {
        let node_id = 42;
        let mut lock_a = [0x11u8; 32];
        let mut lock_b = [0x22u8; 32];

        // lock_a < lock_b
        let p1 = create_equivocation_proof(node_id, &lock_a, &lock_b);
        let p2 = create_equivocation_proof(node_id, &lock_b, &lock_a);
        assert_eq!(p1, p2, "create_equivocation_proof must be symmetric");

        // lock_a == lock_b
        let p3 = create_equivocation_proof(node_id, &lock_a, &lock_a);
        assert_ne!(p1, p3);

        // Different node_id
        let p4 = create_equivocation_proof(node_id + 1, &lock_a, &lock_b);
        assert_ne!(p1, p4);

        // Manual verification of wire format and length prefix
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[DOMAIN_EQUIVOCATION.len() as u8]);
        hasher.update(DOMAIN_EQUIVOCATION);
        hasher.update(&node_id.to_le_bytes());
        hasher.update(&lock_a);
        hasher.update(&lock_b);
        assert_eq!(p1, *hasher.finalize().as_bytes());

        // Test branch when lock_a > lock_b explicitly
        lock_a[0] = 0xFF;
        lock_b[0] = 0x01;
        let p_gt1 = create_equivocation_proof(node_id, &lock_a, &lock_b);
        let p_gt2 = create_equivocation_proof(node_id, &lock_b, &lock_a);
        assert_eq!(p_gt1, p_gt2);
    }

    #[test]
    fn test_compute_shard_digest_at_exact_boundaries() {
        let shard_id = 7u16;
        let now = SimTime(100);

        // Lock 1: valid_until == now (100) -> EXCLUDED (must be strictly > now)
        let lock_at_now = LockRecord::new(
            [1u8; 32],
            [10u8; 32],
            b"nonce1".to_vec(),
            SimTime(50),
            SimTime(100),
        );

        // Lock 2: valid_until == now + 1 (101) -> INCLUDED
        let lock_after_now = LockRecord::new(
            [2u8; 32],
            [20u8; 32],
            b"nonce2".to_vec(),
            SimTime(50),
            SimTime(101),
        );

        // Lock 3: valid_until == now - 1 (99) -> EXCLUDED
        let lock_before_now = LockRecord::new(
            [3u8; 32],
            [30u8; 32],
            b"nonce3".to_vec(),
            SimTime(50),
            SimTime(99),
        );

        // Lock 4: valid_until == 200 (> now), but status is VOID -> EXCLUDED
        let mut lock_void = LockRecord::new(
            [4u8; 32],
            [40u8; 32],
            b"nonce4".to_vec(),
            SimTime(50),
            SimTime(200),
        );
        lock_void.status = crate::types::LockStatus::Void {
            reason: "collision".into(),
        };

        let locks = vec![
            lock_at_now.clone(),
            lock_after_now.clone(),
            lock_before_now.clone(),
            lock_void.clone(),
        ];

        let digest_multi = compute_shard_digest_at(shard_id, &locks, now);
        // Only lock_after_now is active; digest should match single active lock
        let digest_single = compute_shard_digest_at(shard_id, &[lock_after_now.clone()], now);
        assert_eq!(digest_multi, digest_single);

        // Active locks with identical parent_lock order & lexicographical sorting
        let mut lock_p1_a = LockRecord::new(
            [5u8; 32],
            [50u8; 32],
            b"nonce_a".to_vec(),
            SimTime(50),
            SimTime(200),
        );
        lock_p1_a.parent_lock = [0xAA; 32];

        let mut lock_p1_b = LockRecord::new(
            [6u8; 32],
            [60u8; 32],
            b"nonce_b".to_vec(),
            SimTime(50),
            SimTime(200),
        );
        lock_p1_b.parent_lock = [0xBB; 32];

        // Passed in reverse order: [B, A]
        let digest_sorted1 = compute_shard_digest_at(
            shard_id,
            &[lock_p1_b.clone(), lock_p1_a.clone()],
            now,
        );
        // Passed in order: [A, B]
        let digest_sorted2 = compute_shard_digest_at(
            shard_id,
            &[lock_p1_a.clone(), lock_p1_b.clone()],
            now,
        );
        assert_eq!(digest_sorted1, digest_sorted2);

        // Test compute_shard_digest (defaults to SimTime(0))
        let digest_zero = compute_shard_digest(shard_id, &[lock_at_now.clone()]);
        let digest_zero_explicit = compute_shard_digest_at(shard_id, &[lock_at_now.clone()], SimTime(0));
        assert_eq!(digest_zero, digest_zero_explicit);
    }

    #[test]
    fn test_compute_canonical_hash_normalized() {
        let parent_lock = [0x42u8; 32];
        let receiver_bytes = b"receiver_pubkey_bytes_test";
        let sig_bytes = b"signature_bytes_test_64_bytes_entropy_seed";

        let hash_norm = compute_canonical_hash_normalized(&parent_lock, receiver_bytes, sig_bytes);

        // Exact manual hash derivation step-by-step
        let rec_hash = blake3::hash(receiver_bytes);
        let s_hash = blake3::hash(sig_bytes);
        let mut hasher = blake3::Hasher::new();
        let tag_len = DOMAIN_CANON_RESOLVER.len() as u8;
        hasher.update(&[tag_len]);
        hasher.update(DOMAIN_CANON_RESOLVER);
        hasher.update(&parent_lock);
        hasher.update(rec_hash.as_bytes());
        hasher.update(s_hash.as_bytes());
        let expected = *hasher.finalize().as_bytes();

        assert_eq!(hash_norm, expected);

        // Perturbation tests
        let hash_diff_parent = compute_canonical_hash_normalized(&[0x43u8; 32], receiver_bytes, sig_bytes);
        assert_ne!(hash_norm, hash_diff_parent);

        let hash_diff_rec = compute_canonical_hash_normalized(&parent_lock, b"other_receiver", sig_bytes);
        assert_ne!(hash_norm, hash_diff_rec);

        let hash_diff_sig = compute_canonical_hash_normalized(&parent_lock, receiver_bytes, b"other_sig");
        assert_ne!(hash_norm, hash_diff_sig);
    }

    #[test]
    fn test_compute_sig_digest_comprehensive() {
        let domain_tag = b"HUMOCO_V1_TEST_DOMAIN";
        let epoch_id = 42u32;
        let session_seq = 1001u64;
        let flags = 0x07u32;
        let shard_id = 15u16;
        let status_tag = 0x02u8;
        let payload_digest = [0x99u8; 32];

        let digest = compute_sig_digest(
            domain_tag,
            epoch_id,
            session_seq,
            flags,
            shard_id,
            status_tag,
            &payload_digest,
        );

        // Exact manual step-by-step
        let mut hasher = blake3::Hasher::new();
        let tag_len = domain_tag.len() as u8;
        hasher.update(&[tag_len]);
        hasher.update(domain_tag);
        hasher.update(&epoch_id.to_le_bytes());
        hasher.update(&session_seq.to_le_bytes());
        hasher.update(&flags.to_le_bytes());
        hasher.update(&shard_id.to_le_bytes());
        hasher.update(&[status_tag]);
        hasher.update(&payload_digest);
        let expected = *hasher.finalize().as_bytes();

        assert_eq!(digest, expected);

        // Field sensitivity checks
        assert_ne!(
            digest,
            compute_sig_digest(b"OTHER_DOMAIN", epoch_id, session_seq, flags, shard_id, status_tag, &payload_digest)
        );
        assert_ne!(
            digest,
            compute_sig_digest(domain_tag, epoch_id + 1, session_seq, flags, shard_id, status_tag, &payload_digest)
        );
        assert_ne!(
            digest,
            compute_sig_digest(domain_tag, epoch_id, session_seq + 1, flags, shard_id, status_tag, &payload_digest)
        );
        assert_ne!(
            digest,
            compute_sig_digest(domain_tag, epoch_id, session_seq, flags ^ 1, shard_id, status_tag, &payload_digest)
        );
        assert_ne!(
            digest,
            compute_sig_digest(domain_tag, epoch_id, session_seq, flags, shard_id + 1, status_tag, &payload_digest)
        );
        assert_ne!(
            digest,
            compute_sig_digest(domain_tag, epoch_id, session_seq, flags, shard_id, status_tag ^ 1, &payload_digest)
        );
        assert_ne!(
            digest,
            compute_sig_digest(domain_tag, epoch_id, session_seq, flags, shard_id, status_tag, &[0xAAu8; 32])
        );
    }

    #[test]
    fn test_compute_genesis_root_and_sig_helpers() {
        let genesis_root = compute_genesis_root(1, 1_700_000_000);
        let mut hasher = blake3::Hasher::new();
        let tag_len = DOMAIN_GENESIS.len() as u8;
        hasher.update(&[tag_len]);
        hasher.update(DOMAIN_GENESIS);
        hasher.update(&1u32.to_le_bytes());
        hasher.update(&1_700_000_000u64.to_le_bytes());
        assert_eq!(genesis_root, *hasher.finalize().as_bytes());

        // Sensitivity
        assert_ne!(genesis_root, compute_genesis_root(2, 1_700_000_000));
        assert_ne!(genesis_root, compute_genesis_root(1, 1_700_000_001));

        // Deterministic signature roundtrip
        let pub_key = [0x55u8; 32];
        let lock_id = [0x77u8; 32];
        let sig = sign_deterministic_sig(&pub_key, &lock_id);
        assert!(verify_deterministic_sig(&pub_key, &lock_id, &sig));

        // Wrong pubkey or lock_id
        let wrong_pub = [0x56u8; 32];
        let wrong_lock = [0x78u8; 32];
        assert!(!verify_deterministic_sig(&wrong_pub, &lock_id, &sig));
        assert!(!verify_deterministic_sig(&pub_key, &wrong_lock, &sig));

        // Tampered signature prefix vs pubkey suffix
        let mut tampered_sig = sig;
        tampered_sig[0] ^= 0xFF;
        assert!(!verify_deterministic_sig(&pub_key, &lock_id, &tampered_sig));
        let mut tampered_sig2 = sig;
        tampered_sig2[32] ^= 0xFF;
        assert!(!verify_deterministic_sig(&pub_key, &lock_id, &tampered_sig2));

        // Canonical hash with signature
        let parent = [0x12u8; 32];
        let receiver = [0x34u8; 32];
        let sig64 = [0x56u8; 64];
        let h_with_sig = compute_canonical_hash_with_sig(&parent, &receiver, &sig64);
        let h_direct = compute_canonical_hash(&parent, &receiver, &sig64);
        assert_eq!(h_with_sig, h_direct);

        // Network domain getters
        assert_eq!(domain_attestation(NetworkId::Mainnet), HUMOCO_V1_ATTESTATION_MAINNET);
        assert_eq!(domain_attestation(NetworkId::Testnet), HUMOCO_V1_ATTESTATION_TESTNET);
    }

    #[test]
    fn test_compute_work_from_hash_determinism_and_boundaries() {
        // 0 leading zero bits (all 0xFF) -> work = 1
        let max_hash = [0xFFu8; 32];
        assert_eq!(compute_work_from_hash(&max_hash), 1);

        // 8 leading zero bits (first byte 0x00, rest 0xFF) -> work = 256
        let mut hash_8zeros = [0xFFu8; 32];
        hash_8zeros[0] = 0x00;
        assert_eq!(compute_work_from_hash(&hash_8zeros), 256);

        // 16 leading zero bits (first 2 bytes 0x00, rest 0xFF) -> work = 65536
        let mut hash_16zeros = [0xFFu8; 32];
        hash_16zeros[0] = 0x00;
        hash_16zeros[1] = 0x00;
        assert_eq!(compute_work_from_hash(&hash_16zeros), 65536);

        // Boundary: all zeros -> u64::MAX
        let zero_hash = [0x00u8; 32];
        assert_eq!(compute_work_from_hash(&zero_hash), u64::MAX);

        // Monotonicity: smaller hash value => higher work
        let mut smaller_hash = hash_16zeros;
        smaller_hash[2] = 0x7F;
        assert!(compute_work_from_hash(&smaller_hash) > compute_work_from_hash(&hash_16zeros));
    }

    #[test]
    fn test_compute_whitened_hrw_id_uniformity() {
        let pubkey = [0x42u8; 32];
        let nonce = 12345u64;
        let t0 = 1_700_000_000u64;

        // Even with a pow_proof that has 32 zero bytes (leading zeros)
        let pow_proof = [0x00u8; 32];
        let whitened = compute_whitened_hrw_id(&pubkey, nonce, t0, &pow_proof);

        // Whitened ID must NOT have leading zero bytes (full 256-bit entropy)
        assert_ne!(whitened, [0u8; 32]);
        assert_ne!(whitened[0], 0x00);

        // Deterministic
        let whitened2 = compute_whitened_hrw_id(&pubkey, nonce, t0, &pow_proof);
        assert_eq!(whitened, whitened2);

        // Domain tag length prefix verification
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[DOMAIN_HRW_ROUTING_TICKET.len() as u8]);
        hasher.update(DOMAIN_HRW_ROUTING_TICKET);
        hasher.update(&pubkey);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&t0.to_le_bytes());
        hasher.update(&pow_proof);
        assert_eq!(whitened, *hasher.finalize().as_bytes());
    }
}

