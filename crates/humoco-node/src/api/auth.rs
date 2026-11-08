use parking_lot::Mutex;
use rand::RngCore;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum failed login attempts allowed per IP within the rate-limit window.
pub const MAX_AUTH_FAILURES_PER_WINDOW: usize = 5;

/// Sliding window duration for failed login rate limiting (1 minute).
pub const AUTH_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of tracked IP addresses to prevent unbounded RAM usage.
pub const MAX_TRACKED_AUTH_IPS: usize = 1024;

/// Maximum length in bytes for tracked IP addresses to prevent memory exhaustion.
pub const MAX_AUTH_IP_LEN: usize = 128;

#[derive(Debug, Default)]
struct AuthFailureTracker {
    map: HashMap<String, Vec<Instant>>,
    overflow_failures: Vec<Instant>,
}

/// Admin Token Manager responsible for loading or generating the node operator authentication token.
///
/// On initialization, it checks for an existing `admin.token` in `data_dir`. If not found,
/// it generates a 32-byte (64 hex characters) cryptographic token prefixed with `hmc_adm_`
/// and writes it to disk with strict POSIX 0600 permissions.
#[derive(Debug, Clone)]
pub struct AdminTokenManager {
    token: String,
    token_path: Option<PathBuf>,
    auth_disabled: bool,
    failed_attempts: Arc<Mutex<AuthFailureTracker>>,
}

impl AdminTokenManager {
    /// Loads an existing admin token from `data_dir/admin.token` or generates a new one.
    pub fn load_or_create(data_dir: &Path, auth_disabled: bool) -> Result<Self, std::io::Error> {
        let token_path = data_dir.join("admin.token");
        let token = if token_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }

            let content = std::fs::read_to_string(&token_path)?;
            let token_str = content.trim().to_string();
            if token_str.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "admin.token file is empty",
                ));
            }
            token_str
        } else {
            let mut rand_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            let token_str = format!("hmc_adm_{}", hex::encode(rand_bytes));

            // Ensure parent directory exists
            if let Some(parent) = token_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                use std::os::unix::fs::PermissionsExt;

                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&token_path)?;

                file.write_all(token_str.as_bytes())?;
                file.flush()?;

                // Ensure permissions are strictly 0600
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }

            #[cfg(not(unix))]
            {
                std::fs::write(&token_path, token_str.as_bytes())?;
            }

            token_str
        };

        Ok(Self {
            token,
            token_path: Some(token_path),
            auth_disabled,
            failed_attempts: Arc::new(Mutex::new(AuthFailureTracker::default())),
        })
    }

    /// Creates an in-memory `AdminTokenManager` with an explicit token (useful for testing).
    pub fn with_token(token: impl Into<String>, auth_disabled: bool) -> Self {
        Self {
            token: token.into().trim().to_string(),
            token_path: None,
            auth_disabled,
            failed_attempts: Arc::new(Mutex::new(AuthFailureTracker::default())),
        }
    }

    /// Verifies whether the provided HTTP Authorization header contains a valid admin token.
    ///
    /// Accepts case-insensitive `Bearer <token>` and raw `<token>` format.
    /// If `auth_disabled` is true, all requests are authorized immediately.
    pub fn verify_token(&self, auth_header: Option<&str>) -> bool {
        if self.auth_disabled {
            return true;
        }

        let Some(header) = auth_header else {
            return false;
        };

        let trimmed_header = header.trim();
        if trimmed_header.eq_ignore_ascii_case("bearer") {
            return false;
        }

        let provided = if trimmed_header.len() >= 7
            && trimmed_header.as_bytes()[..7].eq_ignore_ascii_case(b"bearer ")
        {
            trimmed_header[7..].trim()
        } else {
            trimmed_header
        };

        if provided.is_empty() || self.token.is_empty() {
            return false;
        }

        // Fixed-digest constant-time comparison to prevent length and timing leakage
        let expected_hash = blake3::hash(self.token.as_bytes());
        let provided_hash = blake3::hash(provided.as_bytes());

        let mut diff = 0u8;
        for (a, b) in expected_hash.as_bytes().iter().zip(provided_hash.as_bytes().iter()) {
            diff |= a ^ b;
        }

        diff == 0
    }

    /// Returns the current admin token string.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the path to the `admin.token` file if persisted.
    pub fn token_path(&self) -> Option<&Path> {
        self.token_path.as_deref()
    }

    /// Returns whether authentication is currently disabled.
    pub fn is_auth_disabled(&self) -> bool {
        self.auth_disabled
    }

    /// Checks whether the specified client IP is currently rate-limited due to excessive failed attempts.
    /// Returns `true` if allowed, `false` if blocked (>= 5 failed attempts in the last 60 seconds).
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        self.check_rate_limit_at(ip, Instant::now())
    }

    /// Checks whether the specified client IP is currently rate-limited at a specific instant in time.
    pub fn check_rate_limit_at(&self, ip: &str, now: Instant) -> bool {
        if self.auth_disabled {
            return true;
        }
        let mut tracker = self.failed_attempts.lock();

        if ip.len() > MAX_AUTH_IP_LEN || ip.trim().is_empty() {
            tracker
                .overflow_failures
                .retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
            return tracker.overflow_failures.len() < MAX_AUTH_FAILURES_PER_WINDOW;
        }

        let mut remove_empty = false;
        if let Some(timestamps) = tracker.map.get_mut(ip) {
            timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
            if timestamps.is_empty() {
                remove_empty = true;
            } else {
                return timestamps.len() < MAX_AUTH_FAILURES_PER_WINDOW;
            }
        }

        if remove_empty {
            tracker.map.remove(ip);
            return true;
        }

        if tracker.map.len() >= MAX_TRACKED_AUTH_IPS {
            tracker.map.retain(|_, timestamps| {
                timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
                !timestamps.is_empty()
            });

            if tracker.map.len() >= MAX_TRACKED_AUTH_IPS {
                tracker
                    .overflow_failures
                    .retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
                if tracker.overflow_failures.len() >= MAX_AUTH_FAILURES_PER_WINDOW {
                    return false;
                }
            }
        }

        true
    }

    /// Records a failed authentication attempt for the given client IP.
    pub fn record_failure(&self, ip: &str) {
        self.record_failure_at(ip, Instant::now());
    }

    /// Records a failed authentication attempt for the given client IP at a specific instant in time.
    pub fn record_failure_at(&self, ip: &str, now: Instant) {
        if self.auth_disabled {
            return;
        }
        let mut tracker = self.failed_attempts.lock();

        if ip.len() > MAX_AUTH_IP_LEN || ip.trim().is_empty() {
            tracker
                .overflow_failures
                .retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
            if tracker.overflow_failures.len() >= MAX_AUTH_FAILURES_PER_WINDOW {
                let excess = tracker
                    .overflow_failures
                    .len()
                    .saturating_sub(MAX_AUTH_FAILURES_PER_WINDOW - 1);
                tracker.overflow_failures.drain(0..excess);
            }
            tracker.overflow_failures.push(now);
            return;
        }

        // 1. Purge expired entries across the map if near capacity
        if tracker.map.len() >= MAX_TRACKED_AUTH_IPS {
            tracker.map.retain(|_, timestamps| {
                timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
                !timestamps.is_empty()
            });
        }

        // 2. If the IP is already tracked or if there is room for a new entry
        if tracker.map.contains_key(ip) || tracker.map.len() < MAX_TRACKED_AUTH_IPS {
            let timestamps = tracker.map.entry(ip.to_string()).or_default();
            timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
            if timestamps.len() >= MAX_AUTH_FAILURES_PER_WINDOW {
                let excess = timestamps
                    .len()
                    .saturating_sub(MAX_AUTH_FAILURES_PER_WINDOW - 1);
                timestamps.drain(0..excess);
            }
            timestamps.push(now);
        } else {
            // Saturated: track in bounded overflow failures to prevent unbounded map growth while enforcing rate limit
            tracker
                .overflow_failures
                .retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
            if tracker.overflow_failures.len() >= MAX_AUTH_FAILURES_PER_WINDOW {
                let excess = tracker
                    .overflow_failures
                    .len()
                    .saturating_sub(MAX_AUTH_FAILURES_PER_WINDOW - 1);
                tracker.overflow_failures.drain(0..excess);
            }
            tracker.overflow_failures.push(now);
        }
    }

    /// Records a successful authentication, clearing any recorded failures for the given client IP.
    pub fn record_success(&self, ip: &str) {
        if self.auth_disabled {
            return;
        }
        let mut tracker = self.failed_attempts.lock();
        if ip.len() <= MAX_AUTH_IP_LEN && !ip.trim().is_empty() {
            tracker.map.remove(ip);
        }
        tracker.overflow_failures.clear();
    }

    /// Returns the number of currently tracked IP addresses (for test assertion).
    pub fn tracked_ip_count_for_test(&self) -> usize {
        self.failed_attempts.lock().map.len()
    }

    /// Returns the number of recorded failure timestamps for a given IP (for test assertion).
    pub fn failure_count_for_ip_for_test(&self, ip: &str) -> usize {
        self.failed_attempts
            .lock()
            .map
            .get(ip)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Returns the number of overflow failure timestamps (for test assertion).
    pub fn overflow_failure_count_for_test(&self) -> usize {
        self.failed_attempts.lock().overflow_failures.len()
    }
}

pub type AdminAuthRateLimiter = AdminTokenManager;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_admin_rate_limiter() {
        let mgr = AdminTokenManager::with_token("secret", false);
        let ip = "192.168.1.100";

        // Initially allowed
        assert!(mgr.check_rate_limit(ip));

        // 4 failures -> still allowed
        for _ in 0..4 {
            mgr.record_failure(ip);
            assert!(mgr.check_rate_limit(ip));
        }

        // 5th failure -> now blocked
        mgr.record_failure(ip);
        assert!(!mgr.check_rate_limit(ip));

        // Another IP is not blocked
        assert!(mgr.check_rate_limit("10.0.0.1"));

        // Success on ip resets the counter
        mgr.record_success(ip);
        assert!(mgr.check_rate_limit(ip));
    }

    #[test]
    fn test_generate_and_persist_admin_token() {
        let dir = tempdir().expect("tempdir");
        let mgr = AdminTokenManager::load_or_create(dir.path(), false).expect("create token");
        assert!(mgr.token().starts_with("hmc_adm_"));
        assert_eq!(mgr.token().len(), 8 + 64); // "hmc_adm_" + 64 hex chars = 72

        let token_path = dir.path().join("admin.token");
        assert!(token_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&token_path).expect("metadata");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Reload existing token
        let mgr2 = AdminTokenManager::load_or_create(dir.path(), false).expect("reload token");
        assert_eq!(mgr.token(), mgr2.token());
    }

    #[test]
    fn test_verify_token_header_formats() {
        let mgr = AdminTokenManager::with_token("hmc_adm_secret123", false);

        // Valid formats
        assert!(mgr.verify_token(Some("Bearer hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("bearer hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("  Bearer hmc_adm_secret123  ")));

        // Invalid
        assert!(!mgr.verify_token(Some("Bearer wrong_token")));
        assert!(!mgr.verify_token(Some("")));
        assert!(!mgr.verify_token(None));

        // Disabled auth
        let disabled_mgr = AdminTokenManager::with_token("hmc_adm_secret123", true);
        assert!(disabled_mgr.verify_token(None));
        assert!(disabled_mgr.verify_token(Some("random_stuff")));
    }

    #[test]
    fn test_evict_expired_map_entries_on_capacity() {
        let mgr = AdminTokenManager::with_token("secret", false);
        let t0 = Instant::now();

        // 1,024 IPs recorded at t0
        for i in 0..1024 {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            mgr.record_failure_at(&ip, t0);
        }
        assert_eq!(mgr.tracked_ip_count_for_test(), 1024);

        // 5 overflow failures at t0 + 50s
        let t_overflow = t0 + Duration::from_secs(50);
        for _ in 0..5 {
            mgr.record_failure_at("198.51.100.1", t_overflow);
        }
        assert_eq!(mgr.overflow_failure_count_for_test(), 5);

        // Untracked IP is blocked during window saturation (t0 + 55s)
        assert!(!mgr.check_rate_limit_at("192.0.2.77", t0 + Duration::from_secs(55)));

        // At t0 + 61s: 1,024 map entries expired (> 60s window), so check_rate_limit_at
        // evicts expired entries and returns true!
        assert!(mgr.check_rate_limit_at("192.0.2.77", t0 + Duration::from_secs(61)));
        assert_eq!(mgr.tracked_ip_count_for_test(), 0);
    }

    #[test]
    fn test_oversized_ip_not_tracked_in_map_and_rate_limited_via_overflow() {
        let mgr = AdminTokenManager::with_token("secret", false);
        let oversized_ip = "x".repeat(MAX_AUTH_IP_LEN + 1);

        assert!(mgr.check_rate_limit(&oversized_ip));

        // 4 failures -> still allowed, 0 map entries allocated
        for _ in 0..4 {
            mgr.record_failure(&oversized_ip);
            assert!(mgr.check_rate_limit(&oversized_ip));
        }
        assert_eq!(mgr.tracked_ip_count_for_test(), 0);
        assert_eq!(mgr.overflow_failure_count_for_test(), 4);

        // 5th failure -> blocked via overflow
        mgr.record_failure(&oversized_ip);
        assert!(!mgr.check_rate_limit(&oversized_ip));
        assert_eq!(mgr.tracked_ip_count_for_test(), 0);
        assert_eq!(mgr.overflow_failure_count_for_test(), 5);

        // Blank/whitespace IP also does not allocate map entries
        let blank_ip = "    ";
        assert_eq!(mgr.failure_count_for_ip_for_test(blank_ip), 0);
        mgr.record_failure(blank_ip);
        assert_eq!(mgr.tracked_ip_count_for_test(), 0);
    }

    #[test]
    fn test_load_or_create_rejects_empty_and_whitespace_token() {
        let dir = tempdir().expect("tempdir");
        let token_path = dir.path().join("admin.token");

        // Empty file
        std::fs::write(&token_path, b"").expect("write empty token");
        let err = AdminTokenManager::load_or_create(dir.path(), false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "admin.token file is empty");

        // Whitespace-only file
        std::fs::write(&token_path, b"  \n\t  \r\n ").expect("write whitespace token");
        let err = AdminTokenManager::load_or_create(dir.path(), false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "admin.token file is empty");
    }

    #[cfg(unix)]
    #[test]
    fn test_load_existing_token_enforces_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let token_path = dir.path().join("admin.token");
        std::fs::write(&token_path, "hmc_adm_validtoken123\n").expect("write token");
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644))
            .expect("set 0644");

        let mgr = AdminTokenManager::load_or_create(dir.path(), false).expect("load token");
        assert_eq!(mgr.token(), "hmc_adm_validtoken123");

        let meta = std::fs::metadata(&token_path).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_verify_token_case_insensitivity_and_constant_time() {
        let mgr = AdminTokenManager::with_token("hmc_adm_secret123", false);

        // Case variations of Bearer
        assert!(mgr.verify_token(Some("BEARER hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("BeArEr   hmc_adm_secret123  ")));
        assert!(mgr.verify_token(Some("bearer hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("Bearer hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("hmc_adm_secret123")));
        assert!(mgr.verify_token(Some("  hmc_adm_secret123  ")));

        // Empty / incomplete Bearer headers
        assert!(!mgr.verify_token(Some("BEARER")));
        assert!(!mgr.verify_token(Some("bearer")));
        assert!(!mgr.verify_token(Some("Bearer ")));
        assert!(!mgr.verify_token(Some("BeArEr   ")));
        assert!(!mgr.verify_token(Some("")));
        assert!(!mgr.verify_token(Some("   ")));
        assert!(!mgr.verify_token(None));

        // Wrong token
        assert!(!mgr.verify_token(Some("BEARER wrong_token")));
        assert!(!mgr.verify_token(Some("wrong_token")));

        // Empty token manager never authorizes non-disabled tokens
        let empty_mgr = AdminTokenManager::with_token("", false);
        assert!(!empty_mgr.verify_token(Some("")));
        assert!(!empty_mgr.verify_token(Some("BEARER ")));
        assert!(!empty_mgr.verify_token(Some("hmc_adm_secret123")));
    }
}
