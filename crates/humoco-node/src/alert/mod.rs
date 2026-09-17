use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::AlertConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertKind {
    OutdatedVersion,
    SunsetApproaching,
}

impl AlertKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertKind::OutdatedVersion => "OutdatedVersion",
            AlertKind::SunsetApproaching => "SunsetApproaching",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AlertKind::OutdatedVersion => "Node version is outdated",
            AlertKind::SunsetApproaching => "Crypto suite sunset approaching",
        }
    }
}

impl std::fmt::Display for AlertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

const COOLDOWN_SECS: u64 = 24 * 60 * 60;
const COOLDOWN_FILE: &str = "alerts_cooldown.json";

pub struct AlertDispatcher {
    config: AlertConfig,
    client: reqwest::Client,
    data_dir: PathBuf,
}

impl AlertDispatcher {
    pub fn new(config: AlertConfig, data_dir: PathBuf) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            config,
            client,
            data_dir,
        }
    }

    pub fn config(&self) -> &AlertConfig {
        &self.config
    }

    pub fn cooldown_path(&self) -> PathBuf {
        self.data_dir.join(COOLDOWN_FILE)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn load_cooldowns(&self) -> HashMap<String, u64> {
        let path = self.cooldown_path();
        Self::load_cooldowns_from_path(&path)
    }

    fn load_cooldowns_from_path(path: &Path) -> HashMap<String, u64> {
        if !path.exists() {
            return HashMap::new();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_cooldowns(&self, map: &HashMap<String, u64>) {
        let path = self.cooldown_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(map) {
            let _ = std::fs::write(&path, json);
        }
    }

    pub fn is_cooldown_expired(&self, kind: AlertKind) -> bool {
        let map = self.load_cooldowns();
        Self::is_cooldown_expired_inner(&map, kind)
    }

    fn is_cooldown_expired_inner(map: &HashMap<String, u64>, kind: AlertKind) -> bool {
        if let Some(last) = map.get(kind.as_str()) {
            let now = Self::now_secs();
            now.saturating_sub(*last) >= COOLDOWN_SECS
        } else {
            true
        }
    }

    fn update_cooldown(&self, kind: AlertKind) {
        let mut map = self.load_cooldowns();
        map.insert(kind.as_str().to_string(), Self::now_secs());
        self.save_cooldowns(&map);
    }

    /// Checks whether the peer upgrade threshold is exceeded given total and upgraded counts.
    /// Returns false if total < min_peers_for_alert.
    pub fn is_threshold_exceeded(&self, total_peers: usize, upgraded_peers: usize) -> bool {
        if total_peers < self.config.min_peers_for_alert {
            return false;
        }
        if total_peers == 0 {
            return false;
        }
        let percent = (upgraded_peers * 100) / total_peers;
        percent >= self.config.peer_upgrade_threshold_percent as usize
    }

    /// Convenience: evaluate outdated version threshold and trigger alert if needed.
    pub async fn check_and_alert_outdated(&self, total_peers: usize, upgraded_peers: usize) {
        if !self.config.notify_on_outdated_version {
            return;
        }
        if !self.is_threshold_exceeded(total_peers, upgraded_peers) {
            return;
        }
        let msg = format!(
            "HuMoCo alert [{}]: {}/{} peers have upgraded (threshold {}%). Local node may be outdated.",
            AlertKind::OutdatedVersion.as_str(),
            upgraded_peers,
            total_peers,
            self.config.peer_upgrade_threshold_percent
        );
        self.send_alert(AlertKind::OutdatedVersion, &msg).await;
    }

    /// Sunset warning alert.
    pub async fn check_and_alert_sunset(&self, message: &str) {
        if !self.config.notify_on_sunset_warning {
            return;
        }
        self.send_alert(AlertKind::SunsetApproaching, message).await;
    }

    /// Core dispatch: checks 24h cooldown, sends to webhook and/or telegram, updates cooldown on success.
    pub async fn send_alert(&self, kind: AlertKind, message: &str) {
        if !self.is_cooldown_expired(kind) {
            tracing::debug!(kind = %kind, "Alert suppressed by 24h cooldown");
            return;
        }

        let has_webhook = self
            .config
            .webhook_url
            .as_ref()
            .is_some_and(|u| !u.trim().is_empty());
        let has_telegram = self
            .config
            .telegram_bot_token
            .as_ref()
            .is_some_and(|t| !t.trim().is_empty())
            && self
                .config
                .telegram_chat_id
                .as_ref()
                .is_some_and(|c| !c.trim().is_empty());

        if !has_webhook && !has_telegram {
            tracing::debug!(kind = %kind, "No alert sink configured (webhook/telegram), skipping send");
            return;
        }

        let mut any_success = false;

        if let Some(webhook_url) = &self.config.webhook_url {
            if !webhook_url.trim().is_empty() {
                let payload = serde_json::json!({
                    "kind": kind.as_str(),
                    "message": message,
                    "timestamp": Self::now_secs(),
                });
                match self.client.post(webhook_url).json(&payload).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            any_success = true;
                            tracing::info!(kind = %kind, url = %webhook_url, "Webhook alert sent successfully");
                        } else {
                            tracing::warn!(kind = %kind, status = %resp.status(), url = %webhook_url, "Webhook alert failed with non-success status");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(kind = %kind, error = %e, url = %webhook_url, "Webhook alert POST failed");
                    }
                }
            }
        }

        if let (Some(token), Some(chat_id)) = (
            &self.config.telegram_bot_token,
            &self.config.telegram_chat_id,
        ) {
            if !token.trim().is_empty() && !chat_id.trim().is_empty() {
                let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
                let payload = serde_json::json!({
                    "chat_id": chat_id,
                    "text": format!("[{}] {}", kind.as_str(), message),
                    "parse_mode": "HTML",
                });
                match self.client.post(&url).json(&payload).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            any_success = true;
                            tracing::info!(kind = %kind, "Telegram alert sent successfully");
                        } else {
                            tracing::warn!(kind = %kind, status = %resp.status(), "Telegram alert failed with non-success status");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(kind = %kind, error = %e, "Telegram alert POST failed");
                    }
                }
            }
        }

        // Update cooldown after any attempt. For strict suppression we update even on failure to avoid spam,
        // but for operational visibility we only update on success. Here we update if we attempted send (success or http success path).
        // To guarantee 24h suppression after a successful send, we update only on success.
        // If all sends failed, do not update cooldown so retry can happen next cycle.
        if any_success {
            self.update_cooldown(kind);
        } else if has_webhook || has_telegram {
            // Still log that we attempted but failed; do not update cooldown so next tick can retry.
            tracing::warn!(kind = %kind, "Alert dispatch attempted but no sink succeeded, cooldown not updated");
        }
    }

    /// For tests: clear cooldown for a kind
    pub fn clear_cooldown(&self, kind: AlertKind) {
        let mut map = self.load_cooldowns();
        map.remove(kind.as_str());
        self.save_cooldowns(&map);
    }

    /// For tests: set last alert timestamp directly (secs since epoch)
    pub fn set_last_alert_secs(&self, kind: AlertKind, secs: u64) {
        let mut map = self.load_cooldowns();
        map.insert(kind.as_str().to_string(), secs);
        self.save_cooldowns(&map);
    }
}
