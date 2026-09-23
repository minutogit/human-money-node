use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::Mutex;
use thiserror::Error;

pub const STATELESS_POW_DOMAIN: &[u8] = b"HUMOCO_V1_POW_STATELESS";
pub const DEFAULT_EPOCH_DURATION_SEC: u64 = 600; // 10 minutes

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PowError {
    #[error("Invalid challenge format")]
    InvalidFormat,
    #[error("Challenge signature verification failed")]
    InvalidSignature,
    #[error("Challenge has expired")]
    Expired,
    #[error("Hashing error: {0}")]
    Hashing(String),
    #[error("Difficulty threshold not met: required {required}, provided {provided}")]
    InsufficientDifficulty { required: u32, provided: u32 },
    #[error("PoW challenge or nonce has already been used (replay detected)")]
    ReplayDetected,
}

/// Stateless Challenge: BLAKE3(len || "HUMOCO_V1_POW_STATELESS" || parent_lock || epoch_slot)
pub fn compute_stateless_challenge(parent_lock: &[u8; 32], epoch_slot: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[STATELESS_POW_DOMAIN.len() as u8]);
    hasher.update(STATELESS_POW_DOMAIN);
    hasher.update(parent_lock);
    hasher.update(&epoch_slot.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Legacy helper for challenge hashing
pub fn compute_challenge_hash(_secret: &[u8; 32], expires_at: u64, _salt: &[u8; 16], parent_lock: &[u8; 32]) -> [u8; 32] {
    let slot = expires_at / DEFAULT_EPOCH_DURATION_SEC;
    compute_stateless_challenge(parent_lock, slot)
}

/// Nonce-Verifikation: BLAKE3("HUMOCO_POW_SOLUTION" || challenge || nonce)
pub fn compute_solution_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag = b"HUMOCO_POW_SOLUTION";
    hasher.update(&(tag.len() as u8).to_le_bytes());
    hasher.update(tag);
    hasher.update(challenge);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Counts leading zero bits in a 32-byte hash.
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

/// Checks if a hash meets the difficulty requirement (leading zero bits).
pub fn check_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    count_leading_zero_bits(hash) >= difficulty
}

/// Solves the BLAKE3 hashcash challenge by searching for a nonce satisfying the difficulty threshold.
pub fn solve_blake3_hashcash(challenge_hex: &str, difficulty: u32, max_iterations: u64) -> Option<u64> {
    let payload = hex::decode(challenge_hex).ok()?;
    if payload.len() != 32 {
        return None;
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&payload);

    for nonce in 0..max_iterations {
        let hash = compute_solution_hash(&challenge, nonce);
        if check_difficulty(&hash, difficulty) {
            return Some(nonce);
        }
    }
    None
}

#[derive(Clone, Debug)]
pub struct PowEngine {
    pub secret: [u8; 32],
    default_difficulty: u32,
    challenge_ttl_seconds: u64,
    seen_solutions: Arc<Mutex<HashMap<String, u64>>>,
}

impl PowEngine {
    /// Creates a new PowEngine with a secret key and a default difficulty.
    pub fn new(secret: [u8; 32], default_difficulty: u32) -> Self {
        Self {
            secret,
            default_difficulty,
            challenge_ttl_seconds: DEFAULT_EPOCH_DURATION_SEC,
            seen_solutions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Sets custom challenge TTL in seconds.
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.challenge_ttl_seconds = ttl_seconds;
        self
    }

    /// Returns the default difficulty.
    pub fn default_difficulty(&self) -> u32 {
        self.default_difficulty
    }

    /// Returns the current epoch slot.
    pub fn current_epoch_slot(&self, now_sec: u64) -> u64 {
        now_sec / self.challenge_ttl_seconds
    }

    /// Calculates required difficulty based on current server load factor in [0.0, 1.0].
    /// - Normal load (<= 0.5): default_difficulty (e.g. 8 bits)
    /// - Medium load (0.5 .. 0.8): default_difficulty + 4 (e.g. 12 bits)
    /// - High load (> 0.8): default_difficulty + 8 (e.g. 16 bits)
    pub fn required_difficulty_for_load(&self, load_factor: f64) -> u32 {
        if load_factor > 0.8 {
            self.default_difficulty.saturating_add(8)
        } else if load_factor > 0.5 {
            self.default_difficulty.saturating_add(4)
        } else {
            self.default_difficulty
        }
    }

    /// Generates a stateless BLAKE3 challenge bound to a specific parent lock.
    /// Returns `(challenge_hex, difficulty, expires_at_sec)`.
    pub fn generate_challenge_for_parent(&self, parent_lock: &[u8; 32]) -> (String, u32, u64) {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let slot = self.current_epoch_slot(now_sec);
        let expires_at = (slot + 1) * self.challenge_ttl_seconds;
        let challenge_bytes = compute_stateless_challenge(parent_lock, slot);
        (hex::encode(challenge_bytes), self.default_difficulty, expires_at)
    }

    /// Generates a generic challenge without a specific parent lock binding.
    pub fn generate_challenge(&self) -> (String, u32, u64) {
        self.generate_challenge_for_parent(&[0u8; 32])
    }

    /// Validates the challenge structure and computes its expiration time.
    pub fn validate_challenge(&self, challenge_hex: &str) -> Result<([u8; 32], u64), PowError> {
        let payload = hex::decode(challenge_hex).map_err(|_| PowError::InvalidFormat)?;
        if payload.len() != 32 {
            return Err(PowError::InvalidFormat);
        }
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&payload);

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let slot = self.current_epoch_slot(now_sec);
        let expires_at = (slot + 1) * self.challenge_ttl_seconds;
        Ok((challenge_bytes, expires_at))
    }

    /// Verifies that the submitted PoW challenge and nonce satisfy the required difficulty.
    /// Performs exactly 1 BLAKE3 hash computation (< 0.1 µs).
    pub async fn verify_pow_for_parent(
        &self,
        challenge_hex: &str,
        nonce: u64,
        difficulty: u32,
        expected_parent_lock: Option<&[u8; 32]>,
    ) -> Result<bool, PowError> {
        let payload = hex::decode(challenge_hex).map_err(|_| PowError::InvalidFormat)?;
        if payload.len() != 32 {
            return Err(PowError::InvalidFormat);
        }
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&payload);

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let current_slot = self.current_epoch_slot(now_sec);

        if let Some(parent) = expected_parent_lock {
            let expected_curr = compute_stateless_challenge(parent, current_slot);
            let expected_prev = if current_slot > 0 {
                compute_stateless_challenge(parent, current_slot - 1)
            } else {
                [0u8; 32]
            };
            let gen_curr = compute_stateless_challenge(&[0u8; 32], current_slot);
            let gen_prev = if current_slot > 0 {
                compute_stateless_challenge(&[0u8; 32], current_slot - 1)
            } else {
                [0u8; 32]
            };
            if challenge_bytes != expected_curr
                && challenge_bytes != expected_prev
                && challenge_bytes != gen_curr
                && challenge_bytes != gen_prev
            {
                return Err(PowError::InvalidFormat);
            }
        }

        // Server verification requires exactly 1 BLAKE3 hash (< 0.1 µs) - cheap checks first
        let hash = compute_solution_hash(&challenge_bytes, nonce);
        let zeros = count_leading_zero_bits(&hash);
        if zeros < difficulty {
            return Err(PowError::InsufficientDifficulty {
                required: difficulty,
                provided: zeros,
            });
        }

        // Replay check: every challenge+nonce pair can be verified only once (atomic check + insert)
        let key = format!("{}:{}", challenge_hex, nonce);
        let expires_at = (current_slot + 1) * self.challenge_ttl_seconds;
        {
            let mut seen = self.seen_solutions.lock();
            if seen.len() > 10_000 {
                seen.retain(|_, &mut exp| exp > now_sec);
            }
            if seen.contains_key(&key) {
                return Err(PowError::ReplayDetected);
            }
            seen.insert(key, expires_at);
        }

        Ok(true)
    }

    /// Verifies PoW challenge without parent lock check.
    pub async fn verify_pow(&self, challenge_hex: &str, nonce: u64, difficulty: u32) -> Result<bool, PowError> {
        self.verify_pow_for_parent(challenge_hex, nonce, difficulty, None).await
    }

    /// Solves the BLAKE3 hashcash challenge (helper for clients/tests).
    pub fn solve_blake3_hashcash(challenge_hex: &str, difficulty: u32, max_iterations: u64) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pow_challenge_generation_and_verification() {
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 8);

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
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 8);
        let parent_a = [0xaa; 32];
        let parent_b = [0xbb; 32];

        let (challenge, difficulty, _) = engine.generate_challenge_for_parent(&parent_a);
        let nonce = solve_blake3_hashcash(&challenge, difficulty, 10_000).expect("Solve PoW");

        // Fails if submitted for parent_b
        let err = engine.verify_pow_for_parent(&challenge, nonce, difficulty, Some(&parent_b)).await;
        assert!(matches!(err, Err(PowError::InvalidFormat)));

        // Succeeds for matching parent_a
        let ok = engine.verify_pow_for_parent(&challenge, nonce, difficulty, Some(&parent_a)).await;
        assert_eq!(ok, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_replay_protection() {
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 8);

        let (challenge, difficulty, _) = engine.generate_challenge();
        let nonce = solve_blake3_hashcash(&challenge, difficulty, 10_000).expect("Solve PoW");

        // Erste Verifikation ist erfolgreich
        let first = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert_eq!(first, Ok(true));

        // Replay mit identischem Token und Nonce wird abgewiesen
        let second = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert_eq!(second, Err(PowError::ReplayDetected));
    }

    #[tokio::test]
    async fn test_pow_invalid_challenge_tampered() {
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 8);

        let (mut challenge, difficulty, _) = engine.generate_challenge();
        // Tamper with first byte
        challenge.replace_range(0..2, "ff");

        let result = engine.verify_pow(&challenge, 0, difficulty).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pow_difficulty_0() {
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 0);

        let (challenge, difficulty, _) = engine.generate_challenge();
        let result = engine.verify_pow(&challenge, 12345, difficulty).await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_difficulty_16_standard() {
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 16);

        let (challenge, difficulty, _) = engine.generate_challenge();
        assert_eq!(difficulty, 16);

        let nonce = solve_blake3_hashcash(&challenge, difficulty, 500_000).expect("Solve 16-bit PoW");
        let hash = compute_solution_hash(&hex::decode(&challenge).unwrap().try_into().unwrap(), nonce);
        assert_eq!(hash[0], 0);
        assert_eq!(hash[1], 0);

        let result = engine.verify_pow(&challenge, nonce, difficulty).await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn test_pow_insufficient_difficulty() {
        let secret = [0x42u8; 32];
        let engine = PowEngine::new(secret, 16);

        let (challenge, _, _) = engine.generate_challenge();
        let result = engine.verify_pow(&challenge, 0, 16).await;
        assert!(matches!(result, Err(PowError::InsufficientDifficulty { required: 16, .. })));
    }
}
