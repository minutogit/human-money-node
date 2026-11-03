use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::AlertConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertKind {
    OutdatedVersion,
    SunsetApproaching,
    KnotenfreundUnresponsive,
    DirectionalSectorAnomaly,
    KnotenfreundMessageReceived,
}

impl AlertKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertKind::OutdatedVersion => "OutdatedVersion",
            AlertKind::SunsetApproaching => "SunsetApproaching",
            AlertKind::KnotenfreundUnresponsive => "KnotenfreundUnresponsive",
            AlertKind::DirectionalSectorAnomaly => "DirectionalSectorAnomaly",
            AlertKind::KnotenfreundMessageReceived => "KnotenfreundMessageReceived",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AlertKind::OutdatedVersion => "Node version is outdated",
            AlertKind::SunsetApproaching => "Crypto suite sunset approaching",
            AlertKind::KnotenfreundUnresponsive => "Direct F2F friend is unresponsive on Shard-RPCs",
            AlertKind::DirectionalSectorAnomaly => "Directional sector anomaly detected behind F2F friend",
            AlertKind::KnotenfreundMessageReceived => "Direct F2F operator message received",
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

    fn cooldown_key(kind: AlertKind, scope_key: Option<&str>) -> String {
        match scope_key {
            Some(k) if !k.trim().is_empty() => format!("{}:{}", kind.as_str(), k.trim()),
            _ => kind.as_str().to_string(),
        }
    }

    fn cooldown_duration_secs(kind: AlertKind) -> u64 {
        match kind {
            AlertKind::KnotenfreundMessageReceived => 3600, // 1 hour per friend for operator messages
            _ => COOLDOWN_SECS,                             // 24 hours standard
        }
    }

    pub fn is_cooldown_expired(&self, kind: AlertKind) -> bool {
        self.is_cooldown_expired_scoped(kind, None)
    }

    pub fn is_cooldown_expired_scoped(&self, kind: AlertKind, scope_key: Option<&str>) -> bool {
        let map = self.load_cooldowns();
        let key = Self::cooldown_key(kind, scope_key);
        if let Some(last) = map.get(&key) {
            let now = Self::now_secs();
            now.saturating_sub(*last) >= Self::cooldown_duration_secs(kind)
        } else {
            true
        }
    }

    pub fn update_cooldown(&self, kind: AlertKind) {
        self.update_cooldown_scoped(kind, None);
    }

    pub fn update_cooldown_scoped(&self, kind: AlertKind, scope_key: Option<&str>) {
        let mut map = self.load_cooldowns();
        let key = Self::cooldown_key(kind, scope_key);
        map.insert(key, Self::now_secs());
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


    /// Core dispatch: checks 24h cooldown, sends to webhook and/or telegram, updates cooldown on success.
    pub async fn send_alert(&self, kind: AlertKind, message: &str) {
        self.trigger_scoped(kind, None, message).await;
    }

    /// Scoped alert dispatch with per-peer or per-entity key isolation so one friend doesn't silence another.
    pub async fn trigger_scoped(&self, kind: AlertKind, scope_key: Option<&str>, message: &str) {
        match kind {
            AlertKind::OutdatedVersion if !self.config.notify_on_outdated_version => return,
            AlertKind::SunsetApproaching if !self.config.notify_on_sunset_warning => return,
            AlertKind::KnotenfreundMessageReceived if !self.config.notify_on_f2f_messages => return,
            AlertKind::KnotenfreundUnresponsive | AlertKind::DirectionalSectorAnomaly
                if !self.config.notify_on_peer_anomalies =>
            {
                return
            }
            _ => {}
        }

        if !self.is_cooldown_expired_scoped(kind, scope_key) {
            tracing::debug!(
                kind = %kind,
                scope = ?scope_key,
                "Alert suppressed by cooldown"
            );
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
                    "scope": scope_key,
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

        if any_success {
            self.update_cooldown_scoped(kind, scope_key);
        } else if has_webhook || has_telegram {
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

    /// For tests: set scoped last alert timestamp
    pub fn set_last_alert_secs_scoped(&self, kind: AlertKind, scope_key: Option<&str>, secs: u64) {
        let mut map = self.load_cooldowns();
        let key = Self::cooldown_key(kind, scope_key);
        map.insert(key, secs);
        self.save_cooldowns(&map);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoped_cooldown_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let config = AlertConfig::default();
        let dispatcher = AlertDispatcher::new(config, temp.path().to_path_buf());

        let friend_a = "0101010101010101010101010101010101010101010101010101010101010101";
        let friend_b = "0202020202020202020202020202020202020202020202020202020202020202";

        // Initially both expired
        assert!(dispatcher.is_cooldown_expired_scoped(AlertKind::KnotenfreundMessageReceived, Some(friend_a)));
        assert!(dispatcher.is_cooldown_expired_scoped(AlertKind::KnotenfreundMessageReceived, Some(friend_b)));

        // Update friend A
        dispatcher.update_cooldown_scoped(AlertKind::KnotenfreundMessageReceived, Some(friend_a));

        // Friend A is in cooldown, Friend B is NOT silenced!
        assert!(!dispatcher.is_cooldown_expired_scoped(AlertKind::KnotenfreundMessageReceived, Some(friend_a)));
        assert!(dispatcher.is_cooldown_expired_scoped(AlertKind::KnotenfreundMessageReceived, Some(friend_b)));
    }
}
