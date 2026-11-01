//! Cryptographic hashing primitives and domain separators for HuMoCo Layer 2.
//!
//! Provides deterministic canonical digest computation for lock attestations,
//! status query attestations, and equivocation proofs with length-prefixed domain tags.

/// Domain tag for Layer 2 write/lock attestation digests.
pub const DOMAIN_L2_WRITE: &[u8] = b"HUMOCO_V1_L2_WRITE";

/// Domain tag for Layer 2 status query attestation digests.
pub const DOMAIN_L2_STATUS_QUERY: &[u8] = b"HUMOCO_V1_L2_STATUS";

/// Domain tag for Layer 2 equivocation proofs.
pub const DOMAIN_L2_EQUIVOCATION: &[u8] = b"HUMOCO_V1_EQUIVOCATION";

/// Computes the 32-byte BLAKE3 attestation digest for a Layer 2 lock write operation.
///
/// Preimage layout:
/// `BLAKE3( [tag_len] || DOMAIN_L2_WRITE || parent_lock || child_lock || epoch_day_le || created_at_ms_le )`
pub fn compute_lock_attestation_digest(
    parent_lock: &[u8; 32],
    child_lock: &[u8; 32],
    epoch_day: u64,
    created_at_ms: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_L2_WRITE.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_L2_WRITE);
    hasher.update(parent_lock);
    hasher.update(child_lock);
    hasher.update(&epoch_day.to_le_bytes());
    hasher.update(&created_at_ms.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the 32-byte BLAKE3 attestation digest for a Layer 2 status query response.
///
/// Preimage layout:
/// `BLAKE3( [tag_len] || DOMAIN_L2_STATUS_QUERY || lookup_tag || challenge_nonce || [status_code] || timestamp_ms_le )`
pub fn compute_status_attestation_digest(
    lookup_tag: &[u8; 32],
    challenge_nonce: &[u8; 32],
    status_code: u8,
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = DOMAIN_L2_STATUS_QUERY.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(DOMAIN_L2_STATUS_QUERY);
    hasher.update(lookup_tag);
    hasher.update(challenge_nonce);
    hasher.update(&[status_code]);
    hasher.update(&timestamp_ms.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Domain separator tag for SST V4 Layer-1 and Layer-2 transaction authorization signatures.
pub const HMC_TX_AUTH_V4_DOMAIN: &[u8] = b"HMC_TX_AUTH_V4";

/// Sentinel placeholder string denoting the absence of a Shared-Signature Trap.
pub const TRAP_NONE_PLACEHOLDER: &str = "none";

/// Domain tag for canonical stateless BLAKE3 Hashcash proof-of-work.
pub const STATELESS_POW_DOMAIN: &[u8] = b"HUMOCO_V1_POW_STATELESS";

/// Default epoch duration in seconds (10 minutes) for stateless PoW time-windows.
pub const DEFAULT_POW_EPOCH_DURATION_SEC: u64 = 600;

/// Computes the 32-byte BLAKE3 challenge for stateless proof-of-work.
///
/// Preimage layout:
/// `BLAKE3( [tag_len] || STATELESS_POW_DOMAIN || parent_lock || epoch_slot_le )`
pub fn compute_stateless_pow_challenge(parent_lock: &[u8; 32], epoch_slot: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = STATELESS_POW_DOMAIN.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(STATELESS_POW_DOMAIN);
    hasher.update(parent_lock);
    hasher.update(&epoch_slot.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the 32-byte BLAKE3 work hash for a candidate nonce.
///
/// Preimage layout:
/// `BLAKE3( [tag_len] || STATELESS_POW_DOMAIN || parent_lock || epoch_slot_le || nonce_le )`
pub fn compute_stateless_pow_work(parent_lock: &[u8; 32], epoch_slot: u64, nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag_len = STATELESS_POW_DOMAIN.len() as u8;
    hasher.update(&[tag_len]);
    hasher.update(STATELESS_POW_DOMAIN);
    hasher.update(parent_lock);
    hasher.update(&epoch_slot.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Counts the number of leading zero bits in a 32-byte hash.
///
/// Iterates through the hash byte-by-byte, accumulating leading zero bits
/// and terminating at the first byte with fewer than 8 leading zero bits.
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for &byte in hash {
        let lz = byte.leading_zeros();
        zeros += lz;
        if lz < 8 {
            break;
        }
    }
    zeros
}

/// Verifies whether the provided hash satisfies the minimum leading zero bits difficulty.
pub fn check_pow_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    count_leading_zero_bits(hash) >= difficulty
}

/// Searches for a valid proof-of-work nonce that satisfies the required difficulty.
///
/// Iterates nonces from `start_nonce` over up to `max_iterations` steps using wrapping addition,
/// returning the first nonce whose work hash meets or exceeds `difficulty`.
pub fn solve_stateless_pow(
    parent_lock: &[u8; 32],
    epoch_slot: u64,
    difficulty: u32,
    start_nonce: u64,
    max_iterations: u64,
) -> Option<u64> {
    for i in 0..max_iterations {
        let nonce = start_nonce.wrapping_add(i);
        let work = compute_stateless_pow_work(parent_lock, epoch_slot, nonce);
        if check_pow_difficulty(&work, difficulty) {
            return Some(nonce);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separators_unique_and_non_empty() {
        assert!(!DOMAIN_L2_WRITE.is_empty());
        assert!(!DOMAIN_L2_STATUS_QUERY.is_empty());
        assert!(!DOMAIN_L2_EQUIVOCATION.is_empty());

        assert_ne!(DOMAIN_L2_WRITE, DOMAIN_L2_STATUS_QUERY);
        assert_ne!(DOMAIN_L2_WRITE, DOMAIN_L2_EQUIVOCATION);
        assert_ne!(DOMAIN_L2_STATUS_QUERY, DOMAIN_L2_EQUIVOCATION);
    }

    #[test]
    fn test_lock_attestation_digest_determinism() {
        let parent = [1u8; 32];
        let child = [2u8; 32];
        let epoch = 100u64;
        let created_at = 1_700_000_000_000u64;

        let d1 = compute_lock_attestation_digest(&parent, &child, epoch, created_at);
        let d2 = compute_lock_attestation_digest(&parent, &child, epoch, created_at);
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }

    #[test]
    fn test_lock_attestation_digest_avalanche() {
        let parent = [1u8; 32];
        let child = [2u8; 32];
        let epoch = 100u64;
        let created_at = 1_700_000_000_000u64;
        let base = compute_lock_attestation_digest(&parent, &child, epoch, created_at);

        // Bit flipped parent
        let mut parent_mod = parent;
        parent_mod[0] ^= 1;
        assert_ne!(
            base,
            compute_lock_attestation_digest(&parent_mod, &child, epoch, created_at)
        );

        // Bit flipped child
        let mut child_mod = child;
        child_mod[31] ^= 1;
        assert_ne!(
            base,
            compute_lock_attestation_digest(&parent, &child_mod, epoch, created_at)
        );

        // Changed epoch
        assert_ne!(
            base,
            compute_lock_attestation_digest(&parent, &child, epoch + 1, created_at)
        );

        // Changed timestamp
        assert_ne!(
            base,
            compute_lock_attestation_digest(&parent, &child, epoch, created_at + 1)
        );
    }

    #[test]
    fn test_status_attestation_digest_determinism() {
        let tag = [10u8; 32];
        let nonce = [20u8; 32];
        let code = 1u8;
        let ts = 1_700_000_500_000u64;

        let d1 = compute_status_attestation_digest(&tag, &nonce, code, ts);
        let d2 = compute_status_attestation_digest(&tag, &nonce, code, ts);
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }

    #[test]
    fn test_status_attestation_digest_avalanche() {
        let tag = [10u8; 32];
        let nonce = [20u8; 32];
        let code = 1u8;
        let ts = 1_700_000_500_000u64;
        let base = compute_status_attestation_digest(&tag, &nonce, code, ts);

        // Bit flipped tag
        let mut tag_mod = tag;
        tag_mod[0] ^= 0x80;
        assert_ne!(
            base,
            compute_status_attestation_digest(&tag_mod, &nonce, code, ts)
        );

        // Bit flipped nonce
        let mut nonce_mod = nonce;
        nonce_mod[15] ^= 0x01;
        assert_ne!(
            base,
            compute_status_attestation_digest(&tag, &nonce_mod, code, ts)
        );

        // Changed status code
        assert_ne!(
            base,
            compute_status_attestation_digest(&tag, &nonce, code + 1, ts)
        );

        // Changed timestamp
        assert_ne!(
            base,
            compute_status_attestation_digest(&tag, &nonce, code, ts + 1)
        );
    }

    #[test]
    fn test_auth_constants_and_pow_domain() {
        assert_eq!(HMC_TX_AUTH_V4_DOMAIN, b"HMC_TX_AUTH_V4");
        assert_eq!(TRAP_NONE_PLACEHOLDER, "none");
        assert_eq!(STATELESS_POW_DOMAIN, b"HUMOCO_V1_POW_STATELESS");
        assert_eq!(DEFAULT_POW_EPOCH_DURATION_SEC, 600);
    }

    #[test]
    fn test_count_leading_zero_bits() {
        assert_eq!(count_leading_zero_bits(&[0u8; 32]), 256);
        assert_eq!(count_leading_zero_bits(&[0xffu8; 32]), 0);
        assert_eq!(count_leading_zero_bits(&[0x7fu8; 32]), 1);
        assert_eq!(count_leading_zero_bits(&[0x01u8; 32]), 7);

        let mut hash = [0u8; 32];
        hash[0] = 0x00;
        hash[1] = 0x0f; // 8 + 4 = 12 leading zeros
        assert_eq!(count_leading_zero_bits(&hash), 12);
        assert!(check_pow_difficulty(&hash, 12));
        assert!(check_pow_difficulty(&hash, 11));
        assert!(!check_pow_difficulty(&hash, 13));
    }

    #[test]
    fn test_stateless_pow_determinism_and_avalanche() {
        let parent = [42u8; 32];
        let epoch_slot = 12345u64;
        let nonce = 98765u64;

        let ch1 = compute_stateless_pow_challenge(&parent, epoch_slot);
        let ch2 = compute_stateless_pow_challenge(&parent, epoch_slot);
        assert_eq!(ch1, ch2);

        let w1 = compute_stateless_pow_work(&parent, epoch_slot, nonce);
        let w2 = compute_stateless_pow_work(&parent, epoch_slot, nonce);
        assert_eq!(w1, w2);

        // Avalanche: flip bit in parent
        let mut parent_mod = parent;
        parent_mod[0] ^= 1;
        assert_ne!(ch1, compute_stateless_pow_challenge(&parent_mod, epoch_slot));
        assert_ne!(w1, compute_stateless_pow_work(&parent_mod, epoch_slot, nonce));

        // Avalanche: alter epoch_slot
        assert_ne!(ch1, compute_stateless_pow_challenge(&parent, epoch_slot + 1));
        assert_ne!(w1, compute_stateless_pow_work(&parent, epoch_slot + 1, nonce));

        // Avalanche: alter nonce
        assert_ne!(w1, compute_stateless_pow_work(&parent, epoch_slot, nonce + 1));
    }

    #[test]
    fn test_solve_stateless_pow_roundtrip() {
        let parent = [0x55u8; 32];
        let epoch_slot = 100u64;
        let difficulty = 8; // 8 bits is fast to find (< ~256 tries on average)

        let found_nonce = solve_stateless_pow(&parent, epoch_slot, difficulty, 0, 100_000)
            .expect("should find nonce for 8-bit difficulty");

        let work = compute_stateless_pow_work(&parent, epoch_slot, found_nonce);
        assert!(check_pow_difficulty(&work, difficulty));
        assert!(count_leading_zero_bits(&work) >= difficulty);

        // Wrapping start nonce test
        let start = u64::MAX - 5;
        let found_wrapped = solve_stateless_pow(&parent, epoch_slot, 4, start, 100)
            .expect("should find nonce with wrapping addition");
        let work_wrapped = compute_stateless_pow_work(&parent, epoch_slot, found_wrapped);
        assert!(check_pow_difficulty(&work_wrapped, 4));

        // Exhaustion returns None
        let impossible = solve_stateless_pow(&parent, epoch_slot, 256, 0, 10);
        assert_eq!(impossible, None);
    }
}
