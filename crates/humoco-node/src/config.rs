use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

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

fn default_proactive_headroom_pct() -> u32 {
    20
}

fn default_urgent_headroom_pct() -> u32 {
    15
}

fn default_target_headroom_pct() -> u32 {
    50
}

fn default_proactive_sleep_ms() -> u64 {
    2000
}

fn default_urgent_sleep_ms() -> u64 {
    500
}

fn default_emergency_sleep_ms() -> u64 {
    50
}

fn default_check_interval_secs() -> u64 {
    60
}

pub const DEFAULT_P2P_LISTEN_ADDR: &str = "0.0.0.0:9090";
pub const DEFAULT_RPC_LISTEN_ADDR: &str = "127.0.0.1:8080";
pub const DEFAULT_BYTE_YEARS: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB-years

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiningConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_proactive_headroom_pct")]
    pub proactive_headroom_pct: u32,
    #[serde(default = "default_urgent_headroom_pct")]
    pub urgent_headroom_pct: u32,
    #[serde(default = "default_target_headroom_pct")]
    pub target_headroom_pct: u32,
    #[serde(default = "default_proactive_sleep_ms")]
    pub proactive_sleep_ms: u64,
    #[serde(default = "default_urgent_sleep_ms")]
    pub urgent_sleep_ms: u64,
    #[serde(default = "default_emergency_sleep_ms")]
    pub emergency_sleep_ms: u64,
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            proactive_headroom_pct: default_proactive_headroom_pct(),
            urgent_headroom_pct: default_urgent_headroom_pct(),
            target_headroom_pct: default_target_headroom_pct(),
            proactive_sleep_ms: default_proactive_sleep_ms(),
            urgent_sleep_ms: default_urgent_sleep_ms(),
            emergency_sleep_ms: default_emergency_sleep_ms(),
            check_interval_secs: default_check_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LifecycleConfig {
    #[serde(default)]
    pub supported_suites: Vec<u8>,
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
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    #[serde(default)]
    pub ingress: IngressConfig,
    #[serde(default)]
    pub mining: MiningConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IngressConfig {
    #[serde(default)]
    pub tier_shares: Option<TierSharesConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TierSharesConfig {
    pub free: u8,
    pub f2f: u8,
    pub vip: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DiscoveryConfig {
    /// Explicit client HTTP endpoints published by this node, never inferred from P2P ports.
    #[serde(default)]
    pub public_gateway_urls: Vec<String>,
    #[serde(default)]
    pub bootstrap_gateways: Vec<String>,
}

/// Maximum number of gateway candidates published through the public directory.
pub const MAX_PUBLIC_GATEWAY_ENTRIES: usize = 32;

/// Returns true when a gateway URL may be published on a public endpoint:
/// bounded length, plain HTTP(S), and free of credentials, query or fragment.
pub fn is_publishable_gateway_url(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 2048 {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
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
    #[serde(default = "default_true")]
    pub notify_on_f2f_messages: bool,
    #[serde(default = "default_true")]
    pub notify_on_peer_anomalies: bool,
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
            notify_on_f2f_messages: true,
            notify_on_peer_anomalies: true,
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
            .field("notify_on_sunset_warning", &self.notify_on_sunset_warning)
            .field("notify_on_f2f_messages", &self.notify_on_f2f_messages)
            .field("notify_on_peer_anomalies", &self.notify_on_peer_anomalies)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub p2p_listen_addr: SocketAddr,
    pub rpc_listen_addr: SocketAddr,
    /// Optional loopback-only operator listener; disabled unless explicitly configured.
    #[serde(default)]
    pub operator_listen_addr: Option<SocketAddr>,
    /// Absolute internal shutdown budget; supervisors must allow a longer fallback.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    #[serde(default)]
    pub advertised_addr: Option<SocketAddr>,
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
    #[serde(default)]
    pub network_id: humoco_sim_core::types::NetworkId,
    #[serde(default = "default_shard_query_depth")]
    pub shard_query_depth: usize,
    #[serde(default)]
    pub simulation_mode: bool,
    #[serde(default)]
    pub fast_ticker_interval_secs: Option<u64>,
}

fn default_shutdown_timeout_secs() -> u64 {
    10
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct F2fConfig {
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub trusted_pubkeys: Vec<String>,
    #[serde(default)]
    pub tokens: Vec<String>,
    #[serde(default = "default_true")]
    pub share_neighbor_roster: bool,
}

impl Default for F2fConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            trusted_pubkeys: Vec::new(),
            tokens: Vec::new(),
            share_neighbor_roster: true,
        }
    }
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

/// Well-known default P2P listen address (0.0.0.0:9090)
pub const DEFAULT_P2P: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9090);
/// Well-known default RPC listen address (127.0.0.1:8080)
pub const DEFAULT_RPC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            p2p_listen_addr: DEFAULT_P2P,
            rpc_listen_addr: DEFAULT_RPC,
            operator_listen_addr: None,
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            advertised_addr: None,
            control_socket: None,
            network_id: humoco_sim_core::types::NetworkId::default(),
            shard_query_depth: default_shard_query_depth(),
            simulation_mode: false,
            fast_ticker_interval_secs: None,
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
    /// Validates private/public listener separation and finite public advertisements.
    pub fn validate_network_boundaries(&self) -> Result<(), NodeError> {
        if let Some(addr) = self.network.operator_listen_addr {
            if !addr.ip().is_loopback() {
                return Err(NodeError::Daemon(
                    "operator_listen_addr must be loopback; use SSH forwarding for remote access"
                        .into(),
                ));
            }
            if addr.port() != 0 && addr == self.network.rpc_listen_addr {
                return Err(NodeError::Daemon(
                    "operator and public listeners must be separate".into(),
                ));
            }
        }
        if !(1..=300).contains(&self.network.shutdown_timeout_secs) {
            return Err(NodeError::Daemon(
                "shutdown_timeout_secs must be between 1 and 300".into(),
            ));
        }
        if self.discovery.public_gateway_urls.len() > 16 {
            return Err(NodeError::Daemon(
                "at most 16 public HTTP gateway advertisements are allowed".into(),
            ));
        }
        for raw in &self.discovery.public_gateway_urls {
            if !is_publishable_gateway_url(raw) {
                return Err(NodeError::Daemon(
                    "gateway URL must be bounded HTTP(S) without credentials, query or fragment"
                        .into(),
                ));
            }
        }
        Ok(())
    }

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
        config.validate_network_boundaries()?;
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

# Private diagnostics; disabled by default. Remote access uses SSH forwarding.
# operator_listen_addr = "127.0.0.1:9091"
# Internal shutdown budget; configure supervisor timeout above this value.
shutdown_timeout_secs = 10

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

[discovery]
# List of bootstrap gateways for initial discovery and client fallback
# Explicit public HTTP(S) endpoints; never inferred from a P2P/QUIC address.
public_gateway_urls = []
bootstrap_gateways = [
    # "https://gateway1.humoco.org",
]
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
        assert!(!config.network.simulation_mode);
        assert_eq!(config.network.fast_ticker_interval_secs, None);
        assert_eq!(config.quotas.default_byte_years, DEFAULT_BYTE_YEARS);
        assert!(config.f2f.peers.is_empty());
        assert!(config.discovery.bootstrap_gateways.is_empty());
        assert!(config.mining.enabled);
        assert_eq!(config.mining.proactive_headroom_pct, 20);
        assert_eq!(config.mining.urgent_headroom_pct, 15);
        assert_eq!(config.mining.target_headroom_pct, 50);
        assert_eq!(config.mining.proactive_sleep_ms, 2000);
        assert_eq!(config.mining.urgent_sleep_ms, 500);
        assert_eq!(config.mining.emergency_sleep_ms, 50);
        assert_eq!(config.mining.check_interval_secs, 60);
    }

    #[test]
    fn test_mining_config_toml_roundtrip_and_defaults() {
        let toml_empty = "";
        let parsed_empty: MiningConfig = toml::from_str(toml_empty).expect("Parse empty mining config");
        assert_eq!(parsed_empty, MiningConfig::default());

        let toml_custom = r#"
        enabled = false
        proactive_headroom_pct = 30
        urgent_headroom_pct = 10
        target_headroom_pct = 75
        proactive_sleep_ms = 1000
        urgent_sleep_ms = 250
        emergency_sleep_ms = 25
        check_interval_secs = 120
        "#;
        let parsed_custom: MiningConfig = toml::from_str(toml_custom).expect("Parse custom mining config");
        assert!(!parsed_custom.enabled);
        assert_eq!(parsed_custom.proactive_headroom_pct, 30);
        assert_eq!(parsed_custom.urgent_headroom_pct, 10);
        assert_eq!(parsed_custom.target_headroom_pct, 75);
        assert_eq!(parsed_custom.proactive_sleep_ms, 1000);
        assert_eq!(parsed_custom.urgent_sleep_ms, 250);
        assert_eq!(parsed_custom.emergency_sleep_ms, 25);
        assert_eq!(parsed_custom.check_interval_secs, 120);

        let serialized = toml::to_string(&parsed_custom).expect("Serialize custom mining config");
        let parsed_again: MiningConfig = toml::from_str(&serialized).expect("Deserialize custom mining config");
        assert_eq!(parsed_custom, parsed_again);
    }

    #[test]
    fn test_toml_serialize_deserialize_roundtrip() {
        let mut config = NodeConfig::default();
        config.network.advertised_addr = Some("203.0.113.195:9090".parse().unwrap());
        config.f2f.peers.push("192.168.1.100:9090".to_string());
        config.quotas.default_byte_years = 500_000_000;
        config
            .discovery
            .bootstrap_gateways
            .push("https://bootstrap.humoco.org".to_string());

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
    fn test_discovery_config_parsing() {
        let toml_str = r#"
        [discovery]
        bootstrap_gateways = [
            "https://gateway1.humoco.org",
            "https://gateway2.humoco.org"
        ]
        "#;
        let config: NodeConfig = toml::from_str(toml_str).expect("Parse discovery section");
        assert_eq!(config.discovery.bootstrap_gateways.len(), 2);
        assert_eq!(
            config.discovery.bootstrap_gateways[0],
            "https://gateway1.humoco.org"
        );
        assert_eq!(
            config.discovery.bootstrap_gateways[1],
            "https://gateway2.humoco.org"
        );
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
            share_neighbor_roster: true,
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

    #[test]
    fn test_f2f_config_default_and_alerts() {
        let f2f = F2fConfig::default();
        assert!(f2f.share_neighbor_roster);

        let alert = AlertConfig::default();
        assert!(alert.notify_on_f2f_messages);
        assert!(alert.notify_on_peer_anomalies);

        // Deserializing empty TOML table uses defaults
        let parsed_f2f: F2fConfig = toml::from_str("").unwrap();
        assert!(parsed_f2f.share_neighbor_roster);
    }
}
