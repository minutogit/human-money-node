//! Client flow helpers and HRW scoring.

use crate::types::HrwRoutingId;

/// Computes the HRW score of a node for a shard as f64 [0.0, 1.0]
/// Semantically decoupled: based on HrwRoutingId (Argon2d ticket), not on NodePubKey
pub fn compute_hrw_score_f64(hrw_id: &HrwRoutingId, shard_id: u16) -> f64 {
    crate::types::hrw_score_32_normalized(hrw_id, shard_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hrw_score_f64_bounds() {
        let hrw_id: HrwRoutingId = [0x55; 32];
        let score = compute_hrw_score_f64(&hrw_id, 1);
        assert!((0.0..=1.0).contains(&score));
    }
}
