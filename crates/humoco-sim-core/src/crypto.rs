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

/// Computes the canonical hash for the deterministic resolver (docs/02:97)
/// H_canon(Lock) = BLAKE3(len || "HUMOCO_V1_CANON_RESOLVER" || Parent_Hash || Receiver_Pub || Sig/Nonce)
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
}

