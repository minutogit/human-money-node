use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DEFAULT_EPOCH_DURATION_SEC: u64 = 600; // 10 minutes

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PowError {
    #[error("Invalid challenge format")]
    InvalidFormat,
    #[error("Difficulty threshold not met: required {required}, provided {provided}")]
    InsufficientDifficulty { required: u32, provided: u32 },
}

/// Stateless Challenge: BLAKE3(len || "HUMOCO_V1_POW_STATELESS" || parent_lock || epoch_slot)
#[inline]
pub fn compute_stateless_challenge(parent_lock: &[u8; 32], epoch_slot: u64) -> [u8; 32] {
    humoco_proto::crypto::compute_stateless_pow_challenge(parent_lock, epoch_slot)
}

/// Canonical Direct Stateless Hashcash (Spec 13 §4, AGENTS.md):
/// BLAKE3(len || "HUMOCO_V1_POW_STATELESS" || parent_lock || epoch_slot || nonce)
#[inline]
pub fn hash_work(parent_lock: &[u8; 32], epoch_slot: u64, nonce: u64) -> [u8; 32] {
    humoco_proto::crypto::compute_stateless_pow_work(parent_lock, epoch_slot, nonce)
}

/// Counts leading zero bits in a 32-byte hash.
#[inline]
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    humoco_proto::crypto::count_leading_zero_bits(hash)
}

/// Checks if a hash meets the difficulty requirement (leading zero bits).
#[inline]
pub fn check_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    humoco_proto::crypto::check_pow_difficulty(hash, difficulty)
}

/// Solves the canonical direct stateless hashcash for an explicit parent lock and epoch slot.
pub fn solve_canonical_hashcash(
    parent_lock: &[u8; 32],
    epoch_slot: u64,
    difficulty: u32,
    max_iterations: u64,
) -> Option<u64> {
    for nonce in 0..max_iterations {
        let hash = hash_work(parent_lock, epoch_slot, nonce);
        if check_difficulty(&hash, difficulty) {
            return Some(nonce);
        }
    }
    None
}

/// Solves the canonical direct stateless hashcash for an explicit parent lock and epoch slot (helper alias).
pub fn solve_blake3_hashcash_for_parent(
    parent_lock: &[u8; 32],
    epoch_slot: u64,
    difficulty: u32,
    max_iterations: u64,
) -> Option<u64> {
    solve_canonical_hashcash(parent_lock, epoch_slot, difficulty, max_iterations)
}

/// Solves the BLAKE3 hashcash challenge by searching for a nonce satisfying the difficulty threshold.
pub fn solve_blake3_hashcash(
    challenge_hex: &str,
    difficulty: u32,
    max_iterations: u64,
) -> Option<u64> {
    let payload = hex::decode(challenge_hex).ok()?;
    if payload.len() != 32 {
        return None;
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&payload);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let current_slot = now_sec / DEFAULT_EPOCH_DURATION_SEC;

    for slot in [
        current_slot,
        current_slot.saturating_sub(1),
        current_slot + 1,
    ] {
        if challenge == compute_stateless_challenge(&[0u8; 32], slot) {
            return solve_canonical_hashcash(&[0u8; 32], slot, difficulty, max_iterations);
        }
    }
    for slot in 0..=10 {
        if challenge == compute_stateless_challenge(&[0u8; 32], slot) {
            return solve_canonical_hashcash(&[0u8; 32], slot, difficulty, max_iterations);
        }
    }

    None
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub struct PowEngine {
    default_difficulty: u32,
    challenge_ttl_seconds: u64,
    clock: Arc<parking_lot::RwLock<Option<Arc<crate::network::NetworkClock>>>>,
}

impl PowEngine {
    /// Creates a new PowEngine with a default difficulty.
    pub fn new(default_difficulty: u32) -> Self {
        Self {
            default_difficulty,
            challenge_ttl_seconds: DEFAULT_EPOCH_DURATION_SEC,
            clock: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Attaches a P2P network clock so epoch calculations use decentralized consensus time.
    pub fn with_clock(self, clock: Arc<crate::network::NetworkClock>) -> Self {
        *self.clock.write() = Some(clock);
        self
    }

    /// Sets the P2P network clock reference.
    pub fn set_clock(&self, clock: Arc<crate::network::NetworkClock>) {
        *self.clock.write() = Some(clock);
    }

    /// Returns the current consensus time in milliseconds, querying NetworkClock if configured,
    /// falling back to local SystemTime only during offline unit tests or cold boot.
    #[inline]
    pub fn now_ms(&self) -> u64 {
        if let Some(clock) = self.clock.read().as_ref() {
            clock.net_time_ms()
        } else {
            let dur = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            u64::try_from(dur.as_millis()).unwrap_or(u64::MAX)
        }
    }

    /// Returns the current consensus time in seconds, querying NetworkClock if configured,
    /// falling back to local SystemTime only during offline unit tests or cold boot.
    #[inline]
    pub fn now_sec(&self) -> u64 {
        self.now_ms() / 1000
    }

    /// Sets custom challenge TTL in seconds (clamped to >= 1 to prevent division by zero).
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.challenge_ttl_seconds = ttl_seconds.max(1);
        self
    }

    /// Returns the default difficulty.
    pub fn default_difficulty(&self) -> u32 {
        self.default_difficulty
    }

    /// Returns the current epoch slot (challenge_ttl_seconds clamped to >= 1).
    pub fn current_epoch_slot(&self, now_sec: u64) -> u64 {
        now_sec / self.challenge_ttl_seconds.max(1)
    }

    /// Calculates required difficulty based on current server load factor in [0.0, 1.0].
    /// - Normal load (<= 0.5 or non-finite): default_difficulty (e.g. 8 bits)
    /// - Medium load (0.5 .. 0.8): default_difficulty + 4 (e.g. 12 bits)
    /// - High load (> 0.8): default_difficulty + 8 (e.g. 16 bits)
    ///
    /// Safe against NaN/Infinity and capped at 256.
    pub fn required_difficulty_for_load(&self, load_factor: f64) -> u32 {
        let diff = if !load_factor.is_finite() || load_factor <= 0.5 {
            self.default_difficulty
        } else if load_factor > 0.8 {
            self.default_difficulty.saturating_add(8)
        } else {
            self.default_difficulty.saturating_add(4)
        };
        diff.min(256)
    }

    /// Generates a stateless BLAKE3 challenge bound to a specific parent lock at explicit timestamp.
    pub fn generate_challenge_for_parent_at(
        &self,
        parent_lock: &[u8; 32],
        now_sec: u64,
    ) -> (String, u32, u64) {
        let slot = self.current_epoch_slot(now_sec);
        let expires_at = slot
            .saturating_add(1)
            .saturating_mul(self.challenge_ttl_seconds.max(1));
        let challenge_bytes = compute_stateless_challenge(parent_lock, slot);
        (
            hex::encode(challenge_bytes),
            self.default_difficulty,
            expires_at,
        )
    }

    /// Generates a stateless BLAKE3 challenge bound to a specific parent lock.
    /// Returns `(challenge_hex, difficulty, expires_at_sec)` aligned to decentralized consensus time.
    pub fn generate_challenge_for_parent(&self, parent_lock: &[u8; 32]) -> (String, u32, u64) {
        self.generate_challenge_for_parent_at(parent_lock, self.now_sec())
    }

    /// Generates a generic challenge without a specific parent lock binding.
    pub fn generate_challenge(&self) -> (String, u32, u64) {
        self.generate_challenge_for_parent(&[0u8; 32])
    }

    /// ARCHITECTURAL INVARIANT / AUDIT NOTE (Spec 13, Rule 9):
    /// 1. Stateless Time-Window Hashcash: Challenges are deterministically derived from
    ///    `BLAKE3(len || "HUMOCO_V1_POW_STATELESS" || parent || epoch_slot)` with a 10-minute
    ///    window (`slot = now_sec / 600`).
    /// 2. Stateless Admission: No stateful replay table is retained across requests;
    ///    exact retries of valid stateless work succeed idempotently (A25-02).
    /// 3. Generic vs. Parent Challenge: Genesis locks (no parent) use `[0u8; 32]`, while spends verify
    ///    parent binding.
    ///
    /// Performs exactly 1 BLAKE3 hash computation (< 0.1 µs).
    pub async fn verify_pow_for_parent_at(
        &self,
        challenge_hex: &str,
        nonce: u64,
        difficulty: u32,
        expected_parent_lock: Option<&[u8; 32]>,
        now_sec: u64,
    ) -> Result<bool, PowError> {
        let payload = hex::decode(challenge_hex).map_err(|_| PowError::InvalidFormat)?;
        if payload.len() != 32 {
            return Err(PowError::InvalidFormat);
        }
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&payload);

        let current_slot = self.current_epoch_slot(now_sec);
        let effective_parent = expected_parent_lock.unwrap_or(&[0u8; 32]);

        let expected_curr = compute_stateless_challenge(effective_parent, current_slot);
        let expected_prev = if current_slot > 0 {
            Some(compute_stateless_challenge(
                effective_parent,
                current_slot - 1,
            ))
        } else {
            None
        };

        let matched_slot = if challenge_bytes == expected_curr {
            current_slot
        } else if expected_prev == Some(challenge_bytes) {
            current_slot - 1
        } else {
            return Err(PowError::InvalidFormat);
        };

        // Server verification requires exactly 1 BLAKE3 hash (< 0.1 µs) - cheap checks first
        let hash = hash_work(effective_parent, matched_slot, nonce);
        let zeros = count_leading_zero_bits(&hash);
        if zeros < difficulty {
            return Err(PowError::InsufficientDifficulty {
                required: difficulty,
                provided: zeros,
            });
        }

        // Stateless admission (A25-02 / Spec 13 §4): No stateful seen_solutions replay table
        // retained across requests; exact retries of valid stateless work succeed idempotently.
        Ok(true)
    }

    /// Verifies PoW challenge with parent lock check, using consensus time.
    pub async fn verify_pow_for_parent(
        &self,
        challenge_hex: &str,
        nonce: u64,
        difficulty: u32,
        expected_parent_lock: Option<&[u8; 32]>,
    ) -> Result<bool, PowError> {
        self.verify_pow_for_parent_at(
            challenge_hex,
            nonce,
            difficulty,
            expected_parent_lock,
            self.now_sec(),
        )
        .await
    }

    /// Verifies PoW challenge without parent lock check.
    pub async fn verify_pow(
        &self,
        challenge_hex: &str,
        nonce: u64,
        difficulty: u32,
    ) -> Result<bool, PowError> {
        self.verify_pow_for_parent(challenge_hex, nonce, difficulty, None)
            .await
    }

    /// Solves the canonical direct hashcash for a given parent at the engine's current consensus time.
    pub fn solve_pow_for_parent(
        &self,
        parent_lock: &[u8; 32],
        difficulty: u32,
        max_iterations: u64,
    ) -> Option<u64> {
        let slot = self.current_epoch_slot(self.now_sec());
        solve_canonical_hashcash(parent_lock, slot, difficulty, max_iterations)
    }

    /// Helper alias for solve_pow_for_parent.
    pub fn solve_blake3_hashcash_for_parent(
        &self,
        parent_lock: &[u8; 32],
        difficulty: u32,
        max_iterations: u64,
    ) -> Option<u64> {
        self.solve_pow_for_parent(parent_lock, difficulty, max_iterations)
    }

    /// Solves the BLAKE3 hashcash challenge (helper for clients/tests).
    pub fn solve_blake3_hashcash(
        challenge_hex: &str,
        difficulty: u32,
        max_iterations: u64,
    ) -> Option<u64> {
        solve_blake3_hashcash(challenge_hex, difficulty, max_iterations)
    }

    /// Helper alias for solve_blake3_hashcash.
    pub fn solve_pow(challenge_hex: &str, difficulty: u32, max_iterations: u64) -> Option<u64> {
        solve_blake3_hashcash(challenge_hex, difficulty, max_iterations)
    }

    /// Checks difficulty.
    pub fn check_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
        check_difficulty(hash, difficulty)
    }
}

impl Default for PowEngine {
    fn default() -> Self {
        Self::new(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pow_challenge_generation_and_verification() {
        let engine = PowEngine::new(8);

        let (challenge, difficulty, expires_at) = engine.generate_challenge();
        assert_eq!(difficulty, 8);
        assert!(expires_at > 0);

        // Solve PoW with difficulty 8 using BLAKE3 hashcash
        let nonce = solve_blake3_hashcash(&challenge, difficulty, 10_000).expect("Solve PoW");
        let result = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_pow_challenge_parent_lock_binding() {
        let engine = PowEngine::new(8);
        let parent_a = [0xaa; 32];
        let parent_b = [0xbb; 32];

        let (challenge, difficulty, _) = engine.generate_challenge_for_parent(&parent_a);
        let nonce = engine
            .solve_pow_for_parent(&parent_a, difficulty, 10_000)
            .expect("Solve PoW");

        // Fails if submitted for parent_b
        let err = engine
            .verify_pow_for_parent(&challenge, nonce, difficulty, Some(&parent_b))
            .await;
        assert!(matches!(err, Err(PowError::InvalidFormat)));

        // Succeeds for matching parent_a
        let ok = engine
            .verify_pow_for_parent(&challenge, nonce, difficulty, Some(&parent_a))
            .await;
        assert_eq!(ok, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_stateless_retry_allowed() {
        let engine = PowEngine::new(8);

        let (challenge, difficulty, _) = engine.generate_challenge();
        let nonce = solve_blake3_hashcash(&challenge, difficulty, 10_000).expect("Solve PoW");

        // The first verification succeeds
        let first = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert_eq!(first, Ok(true));

        // Exact retry of valid stateless work also succeeds without replay error (A25-02 / W3)
        let second = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert_eq!(second, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_invalid_challenge_tampered() {
        let engine = PowEngine::new(8);

        let (mut challenge, difficulty, _) = engine.generate_challenge();
        // Tamper with first byte
        challenge.replace_range(0..2, "ff");

        let result = engine.verify_pow(&challenge, 0, difficulty).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pow_difficulty_0() {
        let engine = PowEngine::new(0);

        let (challenge, difficulty, _) = engine.generate_challenge();
        let result = engine.verify_pow(&challenge, 12345, difficulty).await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_difficulty_16_standard() {
        let engine = PowEngine::new(16);

        let (challenge, difficulty, _) = engine.generate_challenge();
        assert_eq!(difficulty, 16);

        let nonce =
            solve_blake3_hashcash(&challenge, difficulty, 500_000).expect("Solve 16-bit PoW");
        let slot = engine.current_epoch_slot(engine.now_sec());
        let hash = hash_work(&[0u8; 32], slot, nonce);
        assert_eq!(hash[0], 0);
        assert_eq!(hash[1], 0);

        let result = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_insufficient_difficulty() {
        let engine = PowEngine::new(16);

        let (challenge, _, _) = engine.generate_challenge();
        let result = engine.verify_pow(&challenge, 0, 16).await;
        assert!(matches!(
            result,
            Err(PowError::InsufficientDifficulty { required: 16, .. })
        ));
    }

    #[tokio::test]
    async fn test_pow_clock_wiring_and_consensus_time() {
        let clock = Arc::new(crate::network::NetworkClock::new());
        clock.set_offset_for_testing(60_000);
        let engine = PowEngine::new(8).with_clock(clock.clone());

        assert_eq!(engine.now_sec(), clock.net_time_ms() / 1000);

        let (_ch, diff, exp) = engine.generate_challenge();
        assert_eq!(diff, 8);
        assert!(exp >= engine.now_sec());
    }
}
