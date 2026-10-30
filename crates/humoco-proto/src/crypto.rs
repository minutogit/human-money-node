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
}
