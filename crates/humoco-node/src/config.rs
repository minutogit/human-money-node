use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::NodeError;

fn default_true() -> bool {
    true
}

fn default_threshold() -> u8 {
    50
}

fn default_min_peers() -> usize {
    3
}

pub const DEFAULT_P2P_LISTEN_ADDR: &str = "0.0.0.0:9090";
pub const DEFAULT_RPC_LISTEN_ADDR: &str = "127.0.0.1:8080";
pub const DEFAULT_BYTE_YEARS: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB-years

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LifecycleConfig {
    #[serde(default)]
    pub supported_suites: Vec<u8>,
    #[serde(default)]
    pub warn_deprecated_suite_after: Option<u64>,
    #[serde(default)]
    pub reject_deprecated_suite_after: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub f2f: F2fConfig,
    #[serde(default)]
    pub quotas: QuotasConfig,
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
    #[serde(default)]
    pub alerts: AlertConfig,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlertConfig {
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub telegram_bot_token: Option<String>,
    #[serde(default)]
    pub telegram_chat_id: Option<String>,
    #[serde(default = "default_true")]
    pub notify_on_outdated_version: bool,
    #[serde(default = "default_threshold")]
    pub peer_upgrade_threshold_percent: u8,
    #[serde(default = "default_min_peers")]
    pub min_peers_for_alert: usize,
    #[serde(default = "default_true")]
    pub notify_on_sunset_warning: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            telegram_bot_token: None,
            telegram_chat_id: None,
            notify_on_outdated_version: true,
            peer_upgrade_threshold_percent: 50,
            min_peers_for_alert: 3,
            notify_on_sunset_warning: true,
        }
    }
}

impl fmt::Debug for AlertConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertConfig")
            .field("webhook_url", &self.webhook_url)
            .field(
                "telegram_bot_token",
                &self.telegram_bot_token.as_deref().map(|_| "[REDACTED]"),
            )
            .field("telegram_chat_id", &self.telegram_chat_id)
            .field(
                "notify_on_outdated_version",
                &self.notify_on_outdated_version,
            )
            .field(
                "peer_upgrade_threshold_percent",
                &self.peer_upgrade_threshold_percent,
            )
            .field("min_peers_for_alert", &self.min_peers_for_alert)
            .field(
                "notify_on_sunset_warning",
                &self.notify_on_sunset_warning,
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub p2p_listen_addr: SocketAddr,
    pub rpc_listen_addr: SocketAddr,
    #[serde(default)]
    pub advertised_addr: Option<SocketAddr>,
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
    #[serde(default)]
    pub network_id: humoco_sim_core::types::NetworkId,
    #[serde(default = "default_shard_query_depth")]
    pub shard_query_depth: usize,
}

fn default_shard_query_depth() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityConfig {
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct F2fConfig {
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub trusted_pubkeys: Vec<String>,
    #[serde(default)]
    pub tokens: Vec<String>,
}

pub type PeerEndpoint = (Option<[u8; 32]>, SocketAddr);

/// Configured peer entry supporting numerical IPs and hostnames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerConfigEntry {
    pub pubkey: Option<[u8; 32]>,
    pub raw_endpoint: String,
}

impl PeerConfigEntry {
    pub fn new(pubkey: Option<[u8; 32]>, raw_endpoint: impl Into<String>) -> Self {
        Self {
            pubkey,
            raw_endpoint: raw_endpoint.into(),
        }
    }

    /// Returns true if raw_endpoint is a hostname (and not an IP literal).
    pub fn is_hostname(&self) -> bool {
        self.raw_endpoint.parse::<SocketAddr>().is_err()
    }
}

impl F2fConfig {
    /// Parses configured peer entries and trusted pubkeys.
    /// Supports both numerical IPs AND hostnames:
    /// - `<pubkey>@<ip:port>` or `<pubkey>@<host:port>` (e.g. `<pubkey>@node.example.com:9090`)
    /// - `<ip:port>` or `<host:port>` (e.g. `alice.duckdns.org:9090`)
    /// - `<pubkey>` (Hex or Base58)
    pub fn parse_peers(&self) -> (Vec<PeerConfigEntry>, Vec<[u8; 32]>) {
        let mut peer_entries = Vec::new();
        let mut trusted = Vec::new();

        for key_str in &self.trusted_pubkeys {
            if let Some(key) = Self::parse_pubkey(key_str) {
                if !trusted.contains(&key) {
                    trusted.push(key);
                }
            }
        }

        for peer_str in &self.peers {
            let peer_str = peer_str.trim();
            if peer_str.is_empty() {
                continue;
            }

            if let Some((key_part, addr_part)) = peer_str.split_once('@') {
                let key_opt = Self::parse_pubkey(key_part);
                if let Some(key) = key_opt {
                    if !trusted.contains(&key) {
                        trusted.push(key);
                    }
                }
                peer_entries.push(PeerConfigEntry {
                    pubkey: key_opt,
                    raw_endpoint: addr_part.trim().to_string(),
                });
            } else if peer_str.contains(':') {
                peer_entries.push(PeerConfigEntry {
                    pubkey: None,
                    raw_endpoint: peer_str.to_string(),
                });
            } else if let Some(key) = Self::parse_pubkey(peer_str) {
                if !trusted.contains(&key) {
                    trusted.push(key);
                }
            }
        }

        (peer_entries, trusted)
    }

    /// Synchronous helper for resolving only numeric IP socket addresses.
    pub fn parse_peer_endpoints_sync(&self) -> (Vec<PeerEndpoint>, Vec<[u8; 32]>) {
        let (entries, trusted) = self.parse_peers();
        let mut endpoints = Vec::new();
        for entry in entries {
            if let Ok(addr) = entry.raw_endpoint.parse::<SocketAddr>() {
                endpoints.push((entry.pubkey, addr));
            }
        }
        (endpoints, trusted)
    }

    /// Asynchronously resolves peer endpoints using tokio::net::lookup_host.
    /// Non-blocking: if a hostname cannot be resolved currently (offline/DNS temporary failure),
    /// logs a warning, does not crash, and omits it from the immediate resolved list.
    pub async fn resolve_peer_endpoints(
        entries: &[PeerConfigEntry],
    ) -> Vec<(Option<[u8; 32]>, SocketAddr)> {
        let mut resolved = Vec::new();
        for entry in entries {
            if let Ok(addr) = entry.raw_endpoint.parse::<SocketAddr>() {
                resolved.push((entry.pubkey, addr));
            } else {
                let endpoint = if entry.raw_endpoint.contains(':') {
                    entry.raw_endpoint.clone()
                } else {
                    format!("{}:9090", entry.raw_endpoint)
                };

                let lookup_res = tokio::net::lookup_host(&endpoint).await;
                match lookup_res {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            tracing::info!(
                                endpoint = %entry.raw_endpoint,
                                resolved_ip = %addr,
                                "Successfully resolved peer hostname"
                            );
                            resolved.push((entry.pubkey, addr));
                        } else {
                            tracing::warn!(
                                endpoint = %entry.raw_endpoint,
                                "DNS resolution yielded no addresses for peer hostname"
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            endpoint = %entry.raw_endpoint,
                            error = %err,
                            "Failed to resolve DNS hostname for peer; marked for background re-resolution"
                        );
                    }
                }
            }
        }
        resolved
    }

    fn parse_pubkey(s: &str) -> Option<[u8; 32]> {
        let s = s.trim();
        if let Ok(vec) = hex::decode(s) {
            if vec.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&vec);
                return Some(arr);
            }
        }
        if let Ok(vec) = bs58::decode(s).into_vec() {
            if vec.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&vec);
                return Some(arr);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotasConfig {
    pub default_byte_years: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            p2p_listen_addr: DEFAULT_P2P_LISTEN_ADDR
                .parse()
                .expect("Valid default P2P socket address"),
            rpc_listen_addr: DEFAULT_RPC_LISTEN_ADDR
                .parse()
                .expect("Valid default RPC socket address"),
            advertised_addr: None,
            control_socket: None,
            network_id: humoco_sim_core::types::NetworkId::default(),
            shard_query_depth: default_shard_query_depth(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        let data_dir = if let Some(env_dir) = std::env::var_os("HUMOCO_DATA_DIR") {
            PathBuf::from(env_dir)
        } else {
            NodeConfig::default_humoco_dir().join("data")
        };
        Self { data_dir }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            key_path: NodeConfig::default_humoco_dir().join("node_key.bin"),
        }
    }
}

impl Default for QuotasConfig {
    fn default() -> Self {
        Self {
            default_byte_years: DEFAULT_BYTE_YEARS,
        }
    }
}

impl NodeConfig {
    /// Returns the default HuMoCo base directory (`~/.humoco` or `.humoco` if home dir cannot be resolved).
    pub fn default_humoco_dir() -> PathBuf {
        directories::BaseDirs::new()
            .map(|dirs| dirs.home_dir().join(".humoco"))
            .unwrap_or_else(|| PathBuf::from(".humoco"))
    }

    /// Returns the default path for `humoco.toml` configuration file.
    pub fn default_config_path() -> PathBuf {
        Self::default_humoco_dir().join("humoco.toml")
    }

    /// Returns the effective path for the Unix domain control socket.
    pub fn control_socket_path(&self) -> PathBuf {
        self.network
            .control_socket
            .clone()
            .unwrap_or_else(|| self.storage.data_dir.join("humoco.sock"))
    }

    /// Loads configuration from a TOML file.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, NodeError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|err| NodeError::IoWithPath {
            path: path.to_path_buf(),
            source: err,
        })?;
        let config: NodeConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Saves configuration to a TOML file, creating parent directories if necessary.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), NodeError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| NodeError::IoWithPath {
                    path: parent.to_path_buf(),
                    source: err,
                })?;
            }
        }
        let serialized = toml::to_string_pretty(self)?;
        std::fs::write(path, serialized).map_err(|err| NodeError::IoWithPath {
            path: path.to_path_buf(),
            source: err,
        })?;
        Ok(())
    }

    /// Generates a documented default TOML template string.
    pub fn default_toml_template() -> String {
        Self::default().generate_toml_template()
    }

    /// Generates a documented default TOML template string (spec alias).
    pub fn generate_default_toml() -> String {
        Self::default_toml_template()
    }

    /// Generates a documented TOML template string customized with this config's settings.
    pub fn generate_toml_template(&self) -> String {
        let adv_line = match self.network.advertised_addr {
            Some(addr) => format!("advertised_addr = \"{}\"", addr),
            None => "# advertised_addr = \"203.0.113.195:9090\"".to_string(),
        };

        format!(
            r#"# HuMoCo Layer-2 Collision Lock Registry Node Configuration
# Automatically generated configuration template

[network]
# P2P Listen address for node-to-node QUIC communication (default: 0.0.0.0:9090)
p2p_listen_addr = "{}"

# Publicly reachable advertised address for NAT / Docker / WAN peering
{}

# RPC Listen address for client ingress / REST API (default: 127.0.0.1:8080)
rpc_listen_addr = "{}"

[storage]
# Directory where local database and state are stored
data_dir = "{}"

[identity]
# Path to the Ed25519 node private key
key_path = "{}"

[f2f]
# List of trusted friend-to-friend peer addresses
# Peer format can be:
# - "<pubkey_hex>@<ip:port>" (recommended, e.g. "e96b1c...@198.51.100.1:9090")
# - "<ip:port>" (e.g. "127.0.0.1:9090")
# - "<pubkey_hex>" (trusted identity only)
peers = [
    # "e96b1c6b8769fdb0b34fbecfdf85c33b053cecad9517e1ab88cba614335775c1@127.0.0.1:9090",
]

[quotas]
# Default byte-years quota per peer
default_byte_years = {}
"#,
            self.network.p2p_listen_addr,
            adv_line,
            self.network.rpc_listen_addr,
            self.storage.data_dir.display(),
            self.identity.key_path.display(),
            self.quotas.default_byte_years
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(
            config.network.p2p_listen_addr,
            DEFAULT_P2P_LISTEN_ADDR.parse().unwrap()
        );
        assert_eq!(
            config.network.rpc_listen_addr,
            DEFAULT_RPC_LISTEN_ADDR.parse().unwrap()
        );
        assert_eq!(config.network.advertised_addr, None);
        assert_eq!(config.quotas.default_byte_years, DEFAULT_BYTE_YEARS);
        assert!(config.f2f.peers.is_empty());
    }

    #[test]
    fn test_toml_serialize_deserialize_roundtrip() {
        let mut config = NodeConfig::default();
        config.network.advertised_addr = Some("203.0.113.195:9090".parse().unwrap());
        config.f2f.peers.push("192.168.1.100:9090".to_string());
        config.quotas.default_byte_years = 500_000_000;

        let toml_str = toml::to_string_pretty(&config).expect("Serialize to TOML");
        let parsed: NodeConfig = toml::from_str(&toml_str).expect("Deserialize from TOML");

        assert_eq!(config, parsed);
    }

    #[test]
    fn test_save_and_load_from_file() {
        let temp = tempdir().expect("Create temp dir");
        let config_path = temp.path().join("sub/dir/humoco.toml");

        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:5555".parse().unwrap();
        config.f2f.peers.push("10.0.0.2:9090".to_string());

        config.save_to_file(&config_path).expect("Save config");
        assert!(config_path.exists());

        let loaded = NodeConfig::load_from_file(&config_path).expect("Load config");
        assert_eq!(config, loaded);
    }

    #[test]
    fn test_default_toml_template_is_valid() {
        let template = NodeConfig::default_toml_template();
        let parsed: NodeConfig = toml::from_str(&template).expect("Parse default TOML template");
        assert_eq!(
            parsed.network.p2p_listen_addr,
            DEFAULT_P2P_LISTEN_ADDR.parse().unwrap()
        );
        assert_eq!(
            parsed.network.rpc_listen_addr,
            DEFAULT_RPC_LISTEN_ADDR.parse().unwrap()
        );
        assert_eq!(NodeConfig::generate_default_toml(), template);
    }

    #[test]
    fn test_parse_peers_numerical_and_hostname() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pk_only = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let config = F2fConfig {
            peers: vec![
                "127.0.0.1:9090".to_string(),
                "alice.duckdns.org:9090".to_string(),
                format!("{}@node.example.com:9090", pk_hex),
                format!("{}@192.168.1.50:9090", pk_hex),
                pk_only.to_string(),
            ],
            trusted_pubkeys: vec![],
            tokens: vec![],
        };

        let (entries, trusted) = config.parse_peers();
        assert_eq!(entries.len(), 4);
        assert_eq!(trusted.len(), 2); // pk_hex and pk_only

        // Entry 1: IP literal
        assert_eq!(entries[0].pubkey, None);
        assert_eq!(entries[0].raw_endpoint, "127.0.0.1:9090");
        assert!(!entries[0].is_hostname());

        // Entry 2: Hostname
        assert_eq!(entries[1].pubkey, None);
        assert_eq!(entries[1].raw_endpoint, "alice.duckdns.org:9090");
        assert!(entries[1].is_hostname());

        // Entry 3: Pubkey @ Hostname
        assert!(entries[2].pubkey.is_some());
        assert_eq!(entries[2].raw_endpoint, "node.example.com:9090");
        assert!(entries[2].is_hostname());

        // Entry 4: Pubkey @ IP literal
        assert!(entries[3].pubkey.is_some());
        assert_eq!(entries[3].raw_endpoint, "192.168.1.50:9090");
        assert!(!entries[3].is_hostname());

        // Test sync parser ignores hostnames and parses numeric endpoints
        let (sync_endpoints, _) = config.parse_peer_endpoints_sync();
        assert_eq!(sync_endpoints.len(), 2);
    }

    #[tokio::test]
    async fn test_resolve_peer_endpoints_and_fallback() {
        let entries = vec![
            PeerConfigEntry::new(None, "127.0.0.1:9090"),
            PeerConfigEntry::new(None, "localhost:9090"),
            // Non-existent domain should gracefully fail without crashing
            PeerConfigEntry::new(None, "non-existent-domain-xyz-123456789.invalid:9090"),
        ];

        let resolved = F2fConfig::resolve_peer_endpoints(&entries).await;
        // At least 127.0.0.1 and localhost should resolve
        assert!(!resolved.is_empty());
        assert_eq!(resolved[0].1.port(), 9090);
        // Ensure invalid domain didn't panic and was omitted
        assert!(resolved.len() <= 2);
    }
}
