use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use rand::RngCore;

/// Maximum failed login attempts allowed per IP within the rate-limit window.
pub const MAX_AUTH_FAILURES_PER_WINDOW: usize = 5;

/// Sliding window duration for failed login rate limiting (1 minute).
pub const AUTH_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of tracked IP addresses to prevent unbounded RAM usage.
pub const MAX_TRACKED_AUTH_IPS: usize = 1024;

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
    failed_attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl AdminTokenManager {
    /// Loads an existing admin token from `data_dir/admin.token` or generates a new one.
    pub fn load_or_create(data_dir: &Path, auth_disabled: bool) -> Result<Self, std::io::Error> {
        let token_path = data_dir.join("admin.token");
        let token = if token_path.exists() {
            let content = std::fs::read_to_string(&token_path)?;
            content.trim().to_string()
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
                let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
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
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Creates an in-memory `AdminTokenManager` with an explicit token (useful for testing).
    pub fn with_token(token: impl Into<String>, auth_disabled: bool) -> Self {
        Self {
            token: token.into(),
            token_path: None,
            auth_disabled,
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Verifies whether the provided HTTP Authorization header contains a valid admin token.
    ///
    /// Accepts both `Bearer <token>` and raw `<token>` format.
    /// If `auth_disabled` is true, all requests are authorized immediately.
    pub fn verify_token(&self, auth_header: Option<&str>) -> bool {
        if self.auth_disabled {
            return true;
        }

        let Some(header) = auth_header else {
            return false;
        };

        let trimmed_header = header.trim();
        let provided = if let Some(stripped) = trimmed_header.strip_prefix("Bearer ") {
            stripped.trim()
        } else if let Some(stripped) = trimmed_header.strip_prefix("bearer ") {
            stripped.trim()
        } else {
            trimmed_header
        };

        if provided.is_empty() {
            return false;
        }

        // Constant-time comparison for security
        let token_bytes = self.token.as_bytes();
        let provided_bytes = provided.as_bytes();

        if token_bytes.len() != provided_bytes.len() {
            return false;
        }

        let mut diff = 0u8;
        for (a, b) in token_bytes.iter().zip(provided_bytes.iter()) {
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
        if self.auth_disabled {
            return true;
        }
        let now = Instant::now();
        let mut map = self.failed_attempts.lock();
        if let Some(timestamps) = map.get_mut(ip) {
            timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
            if timestamps.len() >= MAX_AUTH_FAILURES_PER_WINDOW {
                return false;
            }
        }
        true
    }

    /// Records a failed authentication attempt for the given client IP.
    pub fn record_failure(&self, ip: &str) {
        if self.auth_disabled {
            return;
        }
        let now = Instant::now();
        let mut map = self.failed_attempts.lock();
        if map.len() >= MAX_TRACKED_AUTH_IPS {
            map.retain(|_, timestamps| {
                timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
                !timestamps.is_empty()
            });
        }
        let timestamps = map.entry(ip.to_string()).or_default();
        timestamps.retain(|&t| now.saturating_duration_since(t) < AUTH_RATE_LIMIT_WINDOW);
        timestamps.push(now);
    }

    /// Records a successful authentication, clearing any recorded failures for the given client IP.
    pub fn record_success(&self, ip: &str) {
        if self.auth_disabled {
            return;
        }
        let mut map = self.failed_attempts.lock();
        map.remove(ip);
    }
}

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
}
