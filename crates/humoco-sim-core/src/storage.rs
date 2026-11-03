use crate::types::SimTime;

/// Maximum voucher and lock validity duration: 11 years (10 years standard range max + 1 year buffer)
/// Reconciles with L1 voucher standard max issuance (10Y) + rounding & grace periods.
/// Protects L2 RAM index against permanent state bloat and eternal griefing attacks.
pub const MAX_LOCK_TTL_YEARS: u64 = 11;
pub const MAX_LOCK_TTL_SECONDS: u64 = MAX_LOCK_TTL_YEARS * crate::quota::SECONDS_PER_YEAR; // 346_896_000 seconds
pub const MAX_LOCK_TTL_MS: u64 = MAX_LOCK_TTL_SECONDS * 1_000; // 346_896_000_000 ms

/// Ingress time window: now+30s < valid_until <= root.valid_until <= now + MAX_LOCK_TTL_MS (INV-1202)
pub fn ingress_time_window_valid(
    now: SimTime,
    valid_until: SimTime,
    root_valid_until: SimTime,
) -> bool {
    // valid_until must be strictly > now + 30s, <= root_valid_until, and root_valid_until <= now + 11 years
    let min_valid = now.0.saturating_add(30_000);
    let max_valid = now.0.saturating_add(MAX_LOCK_TTL_MS);
    valid_until.0 > min_valid
        && valid_until.0 <= root_valid_until.0
        && root_valid_until.0 <= max_valid
}

/// Should prune if now > root.valid_until + 30s grace (INV-1203)
pub fn should_prune(now: SimTime, root_valid_until: SimTime) -> bool {
    let prune_threshold = root_valid_until.0.saturating_add(30_000);
    now.0 > prune_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SimTime;
    #[test]
    fn test_window_and_prune() {
        let now = SimTime(1000);
        let rv = SimTime(60000);
        assert!(!ingress_time_window_valid(now, SimTime(31000), rv)); // need > now+30s = 31000 -> > not >=, so 31000 fails
        assert!(ingress_time_window_valid(now, SimTime(31001), rv));
        assert!(!ingress_time_window_valid(now, SimTime(61000), rv)); // > rv fails

        assert!(!should_prune(SimTime(90000), rv)); // 90000 == 60000+30000 not >, so false
        assert!(should_prune(SimTime(90001), rv));
    }
}
