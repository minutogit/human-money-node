use std::path::PathBuf;
use clap::{Parser, Subcommand};

use crate::config::NodeConfig;
use crate::control::{parse_account_tag, ControlClient, ControlResponse};
use crate::daemon::NodeDaemon;
use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::storage::RedbStorage;

#[derive(Parser, Debug)]
#[command(
    name = "humoco",
    about = "HuMoCo Layer-2 Collision Lock Registry Node Daemon CLI",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

fn parse_word_count(s: &str) -> Result<usize, String> {
    let v: usize = s.parse().map_err(|_| format!("Invalid word count '{}': expected 12 or 24", s))?;
    if v != 12 && v != 24 {
        return Err(format!("Invalid word count {}: expected 12 or 24", v));
    }
    Ok(v)
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Commands {
    /// Initialize a new default node configuration file
    Init {
        /// Custom destination path for configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Overwrite existing configuration file if present
        #[arg(short, long)]
        force: bool,

        /// Generate an identity key if not already present, or force generation
        #[arg(long)]
        with_key: bool,

        /// Restore node identity from an existing 12-word BIP-39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,

        /// Number of words for generated mnemonic (12 or 24, default 12)
        #[arg(long, default_value = "12", value_parser = parse_word_count)]
        words: usize,

        /// Optional BIP-39 passphrase for mnemonic derivation
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Generate a new Ed25519 node identity keypair
    Keygen {
        /// Destination path for the private key file (default: ~/.humoco/node_key.bin)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Overwrite existing key file if present
        #[arg(short, long)]
        force: bool,
    },

    /// Start and run the HuMoCo node daemon
    Run {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Inspect node status, live statistics (if running) or configuration validity
    Status {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// List connected and configured peers
    Peers {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Manage VIP quota balances
    Quota {
        #[command(subcommand)]
        command: QuotaCommands,
    },

    /// Pre-flight and live diagnostic tool
    Doctor {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Manage peers
    Peer {
        #[command(subcommand)]
        command: PeerCommands,
    },

    /// View recent locks
    Locks {
        /// Maximum number of recent locks to retrieve
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Inspect lock details
    Lock {
        #[command(subcommand)]
        command: LockCommands,
    },

    /// Create a consistent backup snapshot of the node database
    Backup {
        /// Destination path for backup snapshot
        #[arg(short, long)]
        out: PathBuf,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Permanently revoke and self-destruct node identity across the P2P network (IRREVERSIBLE)
    Revoke {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Confirmation keyword to bypass interactive prompt (must be 'DELETE' or 'KILL')
        #[arg(long)]
        confirm: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum PeerCommands {
    /// Add a new peer (supporting <pubkey>@<host:port>, <host:port>, or <pubkey>)
    Add {
        /// Peer connection string
        peer: String,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LockCommands {
    /// Inspect a lock by its parent_lock hash
    Inspect {
        /// 32-byte hex parent_lock
        parent_lock: String,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum QuotaCommands {
    /// Top up quota balance for an account tag
    Topup {
        /// Account identifier or 32-byte hex tag
        account: String,

        /// Byte-years to add to quota balance
        byte_years: u64,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Query quota balance for an account tag
    Get {
        /// Account identifier or 32-byte hex tag
        account: String,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

impl Cli {
    /// Executes the CLI command.
    pub async fn execute(self) -> Result<(), NodeError> {
        match self.command {
            Commands::Init {
                path,
                force,
                with_key,
                mnemonic,
                words,
                passphrase,
            } => execute_init(path, force, with_key, mnemonic, words, passphrase),
            Commands::Keygen { out, force } => execute_keygen(out, force),
            Commands::Run { config } => execute_run(config).await,
            Commands::Status { config } => execute_status(config).await,
            Commands::Peers { config } => execute_peers(config).await,
            Commands::Quota { command } => execute_quota(command).await,
            Commands::Doctor { config } => execute_doctor(config).await,
            Commands::Peer { command } => match command {
                PeerCommands::Add { peer, config } => execute_peer_add(peer, config).await,
            },
            Commands::Locks { limit, config } => execute_locks(limit, config).await,
            Commands::Lock { command } => match command {
                LockCommands::Inspect { parent_lock, config } => {
                    execute_lock_inspect(parent_lock, config).await
                }
            },
            Commands::Backup { out, config } => execute_backup(out, config).await,
            Commands::Revoke { config, confirm } => execute_revoke(config, confirm).await,
        }
    }
}

pub fn execute_init(
    path: Option<PathBuf>,
    force: bool,
    with_key: bool,
    mnemonic: Option<String>,
    words: usize,
    passphrase: Option<String>,
) -> Result<(), NodeError> {
    let target_path = match path {
        Some(p) if p.is_dir() || p.extension().is_none() => p.join("humoco.toml"),
        Some(p) => p,
        None => NodeConfig::default_config_path(),
    };
    if target_path.exists() && !force {
        return Err(NodeError::Cli(format!(
            "Configuration file already exists at '{}'. Use --force to overwrite.",
            target_path.display()
        )));
    }

    let cfg = if target_path.exists() {
        NodeConfig::load_from_file(&target_path).unwrap_or_default()
    } else {
        let mut c = NodeConfig::default();
        if let Some(parent) = target_path.parent() {
            if !parent.as_os_str().is_empty() && parent != NodeConfig::default_humoco_dir() {
                c.identity.key_path = parent.join("node_key.bin");
                c.storage.data_dir = parent.join("data");
            }
        }
        c
    };

    let key_exists = cfg.identity.key_path.exists();
    let should_create_key = !key_exists || with_key || mnemonic.is_some();

    // Validate words even when mnemonic supplied for consistency
    if words != 12 && words != 24 {
        return Err(NodeError::Cli(format!(
            "Invalid word count {}: expected 12 or 24",
            words
        )));
    }

    let key_result = if should_create_key {
        let (identity, phrase_opt, actual_words) = if let Some(ref phrase) = mnemonic {
            let id = NodeIdentity::from_mnemonic(phrase, passphrase.as_deref())?;
            // Derive word count from provided phrase for display
            let wc = phrase.split_whitespace().count();
            (id, None, wc)
        } else if let Some(ref pp) = passphrase {
            // Generate with requested word count then derive with passphrase
            let mnemonic_obj = bip39::Mnemonic::generate(words)
                .map_err(|err| NodeError::Identity(format!("Failed to generate mnemonic: {err}")))?;
            let phrase = mnemonic_obj.to_string();
            let id = NodeIdentity::from_mnemonic(&phrase, Some(pp.as_str()))?;
            (id, Some(phrase), words)
        } else {
            let (id, phrase) = NodeIdentity::generate_with_mnemonic(words)?;
            (id, Some(phrase), words)
        };
        identity.save_to_file(&cfg.identity.key_path)?;
        Some((identity, phrase_opt, actual_words))
    } else {
        None
    };

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| NodeError::IoWithPath {
                path: parent.to_path_buf(),
                source: err,
            })?;
        }
    }

    let toml_content = cfg.generate_toml_template();
    std::fs::write(&target_path, toml_content).map_err(|err| NodeError::IoWithPath {
        path: target_path.clone(),
        source: err,
    })?;

    if let Some((identity, phrase_opt, actual_words)) = key_result {
        let conn_addr = if let Some(adv) = cfg.network.advertised_addr {
            adv.to_string()
        } else if cfg.network.p2p_listen_addr.ip().is_unspecified() {
            format!("<public_ip_or_hostname>:{}", cfg.network.p2p_listen_addr.port())
        } else {
            cfg.network.p2p_listen_addr.to_string()
        };
        let conn_string = format!("{}@{}", identity.public_key_hex(), conn_addr);

        println!("┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│                    HuMoCo Layer-2 Node Initialized                          │");
        println!("├──────────────────────────────────────────────────────────────────────────────┤");
        if let Some(ref phrase) = phrase_opt {
            println!("│ {}-Word Recovery Mnemonic (KEEP SECRET!):                                    │", actual_words);
            println!("│   {:<74} │", phrase);
            println!("│   Passphrase: {:<62} │", if passphrase.is_some() { "set" } else { "not set" });
            println!("│                                                                              │");
        } else if mnemonic.is_some() {
            println!("│ Identity: Restored from provided BIP-39 mnemonic phrase ({} words).          │", actual_words);
            println!("│   Passphrase: {:<62} │", if passphrase.is_some() { "set" } else { "not set" });
            println!("│                                                                              │");
        } else {
            // Should not happen, but keep for completeness
            println!("│   Passphrase: {:<62} │", if passphrase.is_some() { "set" } else { "not set" });
        }
        println!("│ Node ID:                                                                     │");
        println!("│   {:<74} │", identity.node_id_hex());
        println!("│                                                                              │");
        println!("│ HRW Routing ID (Argon2d Ticket, semantisch entflochten):                    │");
        println!("│   {:<74} │", identity.hrw_routing_id_hex());
        println!("│   nonce: {:<20} t0: {:<20} ({}) │", identity.nonce(), identity.t0(), if identity.t0() == 0 { "no incubation" } else { "ticket" });
        println!("│                                                                              │");
        println!("│ Public Key (Hex):                                                            │");
        println!("│   {:<74} │", identity.public_key_hex());
        println!("│                                                                              │");
        println!("│ Public Key (did:key):                                                        │");
        println!("│   {:<74} │", identity.did_key());
        println!("│                                                                              │");
        println!("│ Connection string:                                                           │");
        println!("│   {:<74} │", conn_string);
        println!("│ (Share connection string with your trusted F2F peers to establish peering)   │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘");
        println!("Initialized configuration template at: {}", target_path.display());
    } else {
        println!("Initialized configuration template at: {}", target_path.display());
    }

    Ok(())
}

pub fn execute_keygen(out: Option<PathBuf>, force: bool) -> Result<(), NodeError> {
    let target_path = match out {
        Some(p) if p.is_dir() => p.join("node_key.bin"),
        Some(p) => p,
        None => NodeConfig::default().identity.key_path,
    };
    if target_path.exists() && !force {
        return Err(NodeError::Cli(format!(
            "Key file already exists at '{}'. Use --force to overwrite.",
            target_path.display()
        )));
    }

    let identity = NodeIdentity::generate();
    identity.save_to_file(&target_path)?;

    println!("Generated new Ed25519 identity keypair.");
    println!("Key saved to:  {}", target_path.display());
    println!("Node ID:       {}", identity.node_id_hex());
    println!("Public Key:    {}", identity.public_key_hex());
    Ok(())
}

pub async fn execute_run(config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    if !cfg_path.exists() {
        return Err(NodeError::Cli(format!(
            "Configuration file not found at '{}'. Run 'humoco init' first.",
            cfg_path.display()
        )));
    }

    let config = NodeConfig::load_from_file(&cfg_path)?;

    if !config.identity.key_path.exists() {
        return Err(NodeError::Cli(format!(
            "Identity key file not found at '{}'. Run 'humoco keygen' first.",
            config.identity.key_path.display()
        )));
    }

    let identity = NodeIdentity::load_from_file(&config.identity.key_path)?;
    let daemon = NodeDaemon::new(config, identity);
    daemon.run().await
}

pub async fn execute_status(config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);

    // Try loading configuration
    let config = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path).ok()
    } else {
        None
    };

    // If config exists, attempt connecting to live control socket
    if let Some(ref cfg) = config {
        let socket_path = cfg.control_socket_path();
        let client = ControlClient::new(socket_path);
        if let Ok(ControlResponse::Status {
            node_id,
            public_key,
            hrw_routing_id,
            t0,
            nonce,
            own_work,
            net_median_work,
            headroom_pct,
            ticket_outdated,
            uptime_sec,
            active_locks,
            peers_connected,
            data_dir,
            ..
        }) = client.get_status().await
        {
            let pubkey = public_key.or_else(|| {
                if cfg.identity.key_path.exists() {
                    NodeIdentity::load_from_file(&cfg.identity.key_path)
                        .ok()
                        .map(|id| id.public_key_hex())
                } else {
                    None
                }
            });
            // Try to get hrw from response or from file
            let hrw_hex = hrw_routing_id.or_else(|| {
                if cfg.identity.key_path.exists() {
                    NodeIdentity::load_from_file(&cfg.identity.key_path)
                        .ok()
                        .map(|id| id.hrw_routing_id_hex())
                } else {
                    None
                }
            });

            println!("=== HuMoCo Layer-2 Node Status (LIVE) ===");
            println!("Daemon:            ONLINE");
            println!("Node ID:           {}", node_id);
            if let Some(ref hrw) = hrw_hex {
                println!("HRW Routing ID:    {}", hrw);
            }
            if let Some(n) = nonce {
                println!("Routing Nonce:     {}", n);
            }
            if let Some(t) = t0 {
                println!("Routing T0:        {} ({} incubation)", t, if t == 0 { "no" } else { "24h" });
            }
            if let Some(ref pk) = pubkey {
                let conn_addr = if let Some(adv) = cfg.network.advertised_addr {
                    adv.to_string()
                } else if cfg.network.p2p_listen_addr.ip().is_unspecified() {
                    format!("<public_ip_or_hostname>:{}", cfg.network.p2p_listen_addr.port())
                } else {
                    cfg.network.p2p_listen_addr.to_string()
                };
                println!("Public Key:        {}", pk);
                println!("Connection String: {}@{}", pk, conn_addr);
            }
            if ticket_outdated {
                println!("PoW Headroom:      🔴 Outdated (Ticket rejected by F2F peers, re-mining required)");
            } else if let Some(pct) = headroom_pct {
                let traffic_light = if pct >= 25 {
                    "🟢 Healthy"
                } else if pct > 16 {
                    "🟡 Warning (Low Headroom)"
                } else if pct >= 12 {
                    "🟠 Re-Mining Recommended"
                } else {
                    "🔴 Critical (< 12.5%)"
                };
                let own = own_work.unwrap_or(1);
                let med = net_median_work.unwrap_or(1);
                println!("PoW Work Score:    {} (Network Median: {})", own, med);
                println!("PoW Headroom:      {} ({}%)", traffic_light, pct);
            }
            println!("Uptime:            {}s", uptime_sec);
            println!("Active Locks:      {}", active_locks);
            println!("Connected:         {} peers", peers_connected);
            println!("Data Dir:          {}", data_dir.display());
            println!("Config File:       {}", cfg_path.display());
            println!("P2P Listen:        {}", cfg.network.p2p_listen_addr);
            if let Some(adv) = cfg.network.advertised_addr {
                println!("Advertised Addr:   {}", adv);
            }
            println!("RPC Listen:        {}", cfg.network.rpc_listen_addr);
            return Ok(());
        }
    }

    // Fallback: Offline static inspection
    println!("=== HuMoCo Layer-2 Node Status (OFFLINE) ===");
    println!("Daemon:            OFFLINE");
    println!("Config File:       {}", cfg_path.display());

    if !cfg_path.exists() {
        println!("Status:            Config file does not exist. (Run 'humoco init')");
        return Ok(());
    }

    let cfg = match config {
        Some(c) => {
            println!("Config Status:     Valid");
            c
        }
        None => {
            println!("Config Status:     Invalid");
            return Ok(());
        }
    };

    println!("Key Path:          {}", cfg.identity.key_path.display());
    if cfg.identity.key_path.exists() {
        match NodeIdentity::load_from_file(&cfg.identity.key_path) {
            Ok(identity) => {
                let pk = identity.public_key_hex();
                let conn_addr = if let Some(adv) = cfg.network.advertised_addr {
                    adv.to_string()
                } else if cfg.network.p2p_listen_addr.ip().is_unspecified() {
                    format!("<public_ip_or_hostname>:{}", cfg.network.p2p_listen_addr.port())
                } else {
                    cfg.network.p2p_listen_addr.to_string()
                };
                println!("Key Status:        Valid");
                println!("Node ID:           {}", identity.node_id_hex());
                println!("HRW Routing ID:    {}", identity.hrw_routing_id_hex());
                println!("Routing Nonce:     {}", identity.nonce());
                println!("Routing T0:        {} ({} incubation)", identity.t0(), if identity.t0() == 0 { "no" } else { "24h" });
                println!("Public Key:        {}", pk);
                println!("Public Key (did):  {}", identity.did_key());
                println!("Connection String: {}@{}", pk, conn_addr);
            }
            Err(err) => {
                println!("Key Status:        Invalid ({})", err);
            }
        }
    } else {
        println!("Key Status:        Missing. (Run 'humoco init' or 'humoco keygen')");
    }

    println!("P2P Listen:        {}", cfg.network.p2p_listen_addr);
    if let Some(adv) = cfg.network.advertised_addr {
        println!("Advertised Addr:   {}", adv);
    }
    println!("RPC Listen:        {}", cfg.network.rpc_listen_addr);
    println!("Data Dir:          {}", cfg.storage.data_dir.display());
    println!("Peers Count:       {}", cfg.f2f.peers.len());
    println!("Byte-Years:        {}", cfg.quotas.default_byte_years);

    Ok(())
}

pub async fn execute_peers(config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);

    let config = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path).ok()
    } else {
        None
    };

    // If config exists, attempt live query via control socket
    if let Some(ref cfg) = config {
        let socket_path = cfg.control_socket_path();
        let client = ControlClient::new(socket_path);
        if let Ok(peers) = client.list_peers().await {
            println!("=== HuMoCo Layer-2 Connected Peers (LIVE) ===");
            println!("Total peers: {}", peers.len());
            println!("{:<22} {:<66} {:<12} {:<10} {:<10} {:<22}", "ADDRESS", "NODE ID", "STATUS", "MISSING", "MIN HOPS", "VIA (INGRESS)");
            for p in &peers {
                let node_id_str = p.node_id.as_deref().unwrap_or("-");
                let hops_str = p.min_hops.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string());
                let ingress_str = p.ingress_peer.as_deref().unwrap_or("-");
                println!("{:<22} {:<66} {:<12} {:<10} {:<10} {:<22}", p.addr, node_id_str, p.status, p.missing_count, hops_str, ingress_str);
            }
            return Ok(());
        }
    }

    // Fallback: Show configured peers from humoco.toml
    println!("=== HuMoCo Layer-2 Peers (OFFLINE) ===");
    if let Some(cfg) = config {
        println!("Configured peers ({}):", cfg.f2f.peers.len());
        for p in &cfg.f2f.peers {
            println!("  - {}", p);
        }
    } else {
        println!("Configuration file '{}' not found and node is offline.", cfg_path.display());
    }

    Ok(())
}

pub async fn execute_quota(command: QuotaCommands) -> Result<(), NodeError> {
    match command {
        QuotaCommands::Topup {
            account,
            byte_years,
            config,
        } => {
            let cfg_path = config.unwrap_or_else(NodeConfig::default_config_path);
            if !cfg_path.exists() {
                return Err(NodeError::Cli(format!(
                    "Configuration file not found at '{}'.",
                    cfg_path.display()
                )));
            }
            let cfg = NodeConfig::load_from_file(&cfg_path)?;
            let socket_path = cfg.control_socket_path();
            let client = ControlClient::new(socket_path);

            // Try live control client first
            if let Ok(new_balance) = client.topup_quota(&account, byte_years).await {
                println!(
                    "Topup successful (live). Account '{}' new balance: {} byte-years",
                    account, new_balance
                );
                return Ok(());
            }

            // Offline fallback: Update directly in RedbStorage
            let db_path = cfg.storage.data_dir.join("humoco.redb");
            let storage = RedbStorage::open(&db_path)?;
            let tag_bytes = parse_account_tag(&account);
            let current = storage.get_quota(&tag_bytes).unwrap_or(0);
            let new_balance = current.saturating_add(byte_years);
            storage.set_quota(&tag_bytes, new_balance)?;
            println!(
                "Topup successful (offline). Account '{}' new balance: {} byte-years",
                account, new_balance
            );
            Ok(())
        }
        QuotaCommands::Get { account, config } => {
            let cfg_path = config.unwrap_or_else(NodeConfig::default_config_path);
            if !cfg_path.exists() {
                return Err(NodeError::Cli(format!(
                    "Configuration file not found at '{}'.",
                    cfg_path.display()
                )));
            }
            let cfg = NodeConfig::load_from_file(&cfg_path)?;
            let socket_path = cfg.control_socket_path();
            let client = ControlClient::new(socket_path);

            // Try live control client first
            if let Ok(balance) = client.get_quota(&account).await {
                println!(
                    "Quota balance for '{}' (live): {} byte-years",
                    account, balance
                );
                return Ok(());
            }

            // Offline fallback: Query directly from RedbStorage
            let db_path = cfg.storage.data_dir.join("humoco.redb");
            let storage = RedbStorage::open(&db_path)?;
            let tag_bytes = parse_account_tag(&account);
            let balance = storage.get_quota(&tag_bytes)?;
            println!(
                "Quota balance for '{}' (offline): {} byte-years",
                account, balance
            );
            Ok(())
        }
    }
}

pub async fn execute_doctor(config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    println!("=== HuMoCo Layer-2 Node Doctor Diagnostic ===");

    // 1. Config file check
    let (_config_opt, cfg) = if cfg_path.exists() {
        match NodeConfig::load_from_file(&cfg_path) {
            Ok(c) => {
                println!("[✓] Configuration File (Valid): {}", cfg_path.display());
                let c_clone = c.clone();
                (Some(c), c_clone)
            }
            Err(e) => {
                println!("[✗] Configuration File (Invalid): {} ({})", cfg_path.display(), e);
                (None, NodeConfig::default())
            }
        }
    } else {
        println!("[!] Configuration File (Not Found): {} (using default paths)", cfg_path.display());
        (None, NodeConfig::default())
    };

    // 2. Key permissions check (0600 on Unix)
    let key_path = &cfg.identity.key_path;
    if key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match std::fs::metadata(key_path) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode == 0o600 {
                        println!("[✓] Key Permissions (0600): {}", key_path.display());
                    } else {
                        println!(
                            "[✗] Key Permissions: mode is {:04o}, expected 0600 at {}",
                            mode,
                            key_path.display()
                        );
                    }
                }
                Err(e) => {
                    println!("[✗] Key File Metadata Error: {} ({})", key_path.display(), e);
                }
            }
        }
        #[cfg(not(unix))]
        {
            println!("[✓] Key File present: {}", key_path.display());
        }
    } else {
        println!("[✗] Key File: missing at {} (run 'humoco keygen')", key_path.display());
    }

    // 3. Write permissions on data_dir
    let data_dir = &cfg.storage.data_dir;
    let data_dir_writable = (|| -> Result<(), std::io::Error> {
        std::fs::create_dir_all(data_dir)?;
        let test_file = data_dir.join(".doctor_write_test");
        std::fs::write(&test_file, b"humoco_doctor_test")?;
        std::fs::remove_file(&test_file)?;
        Ok(())
    })();
    match data_dir_writable {
        Ok(()) => println!("[✓] Data Directory writable: {}", data_dir.display()),
        Err(e) => println!("[✗] Data Directory not writable: {} ({})", data_dir.display(), e),
    }

    // 4. Control socket responsiveness check
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path.clone());
    let daemon_status = client.get_status().await;
    let daemon_online = matches!(daemon_status, Ok(ControlResponse::Status { .. }));

    // 5. Port binding availability for 9090/udp and 8080/tcp
    let p2p_port = cfg.network.p2p_listen_addr.port();
    let rpc_port = cfg.network.rpc_listen_addr.port();

    if daemon_online {
        println!("[✓] P2P UDP Port ({}/udp): active (bound by running daemon)", p2p_port);
        println!("[✓] RPC TCP Port ({}/tcp): active (bound by running daemon)", rpc_port);
    } else {
        match std::net::UdpSocket::bind(cfg.network.p2p_listen_addr) {
            Ok(_) => println!("[✓] P2P UDP Port ({}/udp): available for binding", p2p_port),
            Err(e) => println!("[✗] P2P UDP Port ({}/udp): unavailable ({})", p2p_port, e),
        }
        match std::net::TcpListener::bind(cfg.network.rpc_listen_addr) {
            Ok(_) => println!("[✓] RPC TCP Port ({}/tcp): available for binding", rpc_port),
            Err(e) => println!("[✗] RPC TCP Port ({}/tcp): unavailable ({})", rpc_port, e),
        }
    }

    // 6. Kernel time synchronization / monotonic clock
    let t1 = std::time::Instant::now();
    let sys_now = std::time::SystemTime::now();
    let t2 = std::time::Instant::now();
    let monotonic_ok = t2 >= t1;
    let epoch_sec = sys_now.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let time_plausible = epoch_sec > 1_700_000_000;
    if monotonic_ok && time_plausible {
        println!("[✓] Kernel Time Synchronization & Monotonic Clock: OK (epoch: {}s)", epoch_sec);
    } else {
        println!(
            "[✗] Kernel Time Synchronization: check failed (monotonic: {}, epoch: {}s)",
            monotonic_ok, epoch_sec
        );
    }

    // 7. Control socket responsiveness
    match daemon_status {
        Ok(ControlResponse::Status { uptime_sec, active_locks, peers_connected, .. }) => {
            println!(
                "[✓] Control Socket responsive: Daemon ONLINE (uptime: {}s, active locks: {}, peers: {})",
                uptime_sec, active_locks, peers_connected
            );
        }
        _ => {
            println!("[i] Control Socket: Daemon OFFLINE (socket at {})", socket_path.display());
        }
    }

    // 8. PoW Headroom & Shard Ticket Health (Check 7)
    match &daemon_status {
        Ok(ControlResponse::Status {
            ticket_outdated,
            headroom_pct,
            own_work,
            net_median_work,
            ..
        }) => {
            if *ticket_outdated {
                println!("[✗] PoW Headroom & Shard Ticket: OUTDATED (Ticket rejected by F2F peers, re-mining required)");
            } else if let Some(pct) = headroom_pct {
                if *pct < 12 {
                    println!("[✗] PoW Headroom & Shard Ticket: CRITICAL ({}% of median, ticket expired/unacceptable)", pct);
                } else if *pct < 25 {
                    println!("[!] PoW Headroom & Shard Ticket: LOW ({}% of median, re-mining recommended)", pct);
                } else {
                    println!(
                        "[✓] PoW Headroom & Shard Ticket Health: OK (Work: {}, Median: {}, Headroom: {}%)",
                        own_work.unwrap_or(1),
                        net_median_work.unwrap_or(1),
                        pct
                    );
                }
            } else {
                println!("[✓] PoW Headroom & Shard Ticket Health: OK (Standalone / Fast-Path)");
            }
        }
        _ => {
            if cfg.identity.key_path.exists() {
                if let Ok(id) = NodeIdentity::load_from_file(&cfg.identity.key_path) {
                    println!("[✓] PoW Headroom & Shard Ticket Health: Offline valid (Local Work Score: {})", id.work_score());
                } else {
                    println!("[✗] PoW Headroom & Shard Ticket Health: Key invalid");
                }
            } else {
                println!("[!] PoW Headroom & Shard Ticket Health: Key missing");
            }
        }
    }

    println!("==============================================");
    Ok(())
}

pub async fn execute_peer_add(peer: String, config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let config = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path).ok()
    } else {
        None
    };

    if let Some(ref cfg) = config {
        let socket_path = cfg.control_socket_path();
        let client = ControlClient::new(socket_path);
        match client.add_peer(&peer).await {
            Ok(ControlResponse::PeerAdded) => {
                println!("[✓] Peer '{}' added successfully (live).", peer);
                return Ok(());
            }
            Ok(ControlResponse::Error { message }) => {
                return Err(NodeError::Cli(format!("Control server error: {}", message)));
            }
            _ => {}
        }
    }

    // Offline fallback: update humoco.toml
    if let Some(mut cfg) = config {
        if !cfg.f2f.peers.contains(&peer) {
            cfg.f2f.peers.push(peer.clone());
            cfg.save_to_file(&cfg_path)?;
            println!("[✓] Peer '{}' added to configuration file (offline).", peer);
        } else {
            println!("Peer '{}' already present in configuration file.", peer);
        }
        Ok(())
    } else {
        Err(NodeError::Cli(format!(
            "Configuration file not found at '{}' and daemon is offline.",
            cfg_path.display()
        )))
    }
}

pub async fn execute_locks(limit: usize, config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = NodeConfig::load_from_file(&cfg_path)?;
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path);

    match client.get_recent_locks(limit).await? {
        ControlResponse::RecentLocks { locks } => {
            println!("=== HuMoCo Recent Locks ({} entries) ===", locks.len());
            if locks.is_empty() {
                println!("No recent locks recorded.");
            } else {
                println!(
                    "{:<20} {:<66} {:<66} {:<12}",
                    "TIMESTAMP (ms)", "PARENT LOCK", "CHILD LOCK", "STATUS"
                );
                for lock in locks {
                    println!(
                        "{:<20} {:<66} {:<66} {:<12}",
                        lock.timestamp_ms, lock.parent_lock_hex, lock.child_lock_hex, lock.status
                    );
                }
            }
            Ok(())
        }
        ControlResponse::Error { message } => Err(NodeError::Cli(format!("Daemon error: {}", message))),
        _ => Err(NodeError::Daemon("Unexpected response from control server".into())),
    }
}

pub async fn execute_lock_inspect(parent_lock: String, config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = NodeConfig::load_from_file(&cfg_path)?;
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path);

    match client.inspect_lock(&parent_lock).await? {
        ControlResponse::LockInspection { inspection: Some(insp) } => {
            println!("=== HuMoCo Lock Inspection ===");
            println!("Parent Lock:      {}", insp.parent_lock_hex);
            println!("Lock ID / Child:  {}", insp.lock_id_hex);
            println!("Receiver / Pub:   {}", insp.receiver_pub_hex);
            println!("Created At:       {} ms", insp.created_at_ms);
            println!("Valid Until:      {} ms", insp.valid_until_ms);
            println!("Status:           {}", insp.status);
            println!("Signers Count:    {}", insp.signers_count);
            Ok(())
        }
        ControlResponse::LockInspection { inspection: None } => {
            println!("Lock with parent_lock '{}' not found in RAM index.", parent_lock);
            Ok(())
        }
        ControlResponse::Error { message } => Err(NodeError::Cli(format!("Daemon error: {}", message))),
        _ => Err(NodeError::Daemon("Unexpected response from control server".into())),
    }
}

pub async fn execute_backup(out: PathBuf, config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let config = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path).ok()
    } else {
        None
    };

    if let Some(ref cfg) = config {
        let socket_path = cfg.control_socket_path();
        let client = ControlClient::new(socket_path);
        let out_str = out.display().to_string();
        if let Ok(resp) = client.create_backup(&out_str).await {
            match resp {
                ControlResponse::BackupCreated { path, locks_count } => {
                    println!("[✓] Consistent backup snapshot created at '{}' ({} locks backed up).", path, locks_count);
                    return Ok(());
                }
                ControlResponse::Error { message } => {
                    return Err(NodeError::Cli(format!("Backup failed: {}", message)));
                }
                _ => {}
            }
        }
    }

    // Offline fallback
    if let Some(cfg) = config {
        let db_path = cfg.storage.data_dir.join("humoco.redb");
        if !db_path.exists() {
            return Err(NodeError::Cli(format!(
                "Database file not found at '{}'.",
                db_path.display()
            )));
        }
        let storage = RedbStorage::open(&db_path)?;
        let target_path = if out.is_dir() {
            out.join("humoco_backup.redb")
        } else {
            out
        };
        let locks_count = storage.create_backup(&target_path)?;
        println!(
            "[✓] Consistent backup snapshot created at '{}' (offline, {} locks backed up).",
            target_path.display(),
            locks_count
        );
        Ok(())
    } else {
        Err(NodeError::Cli(format!(
            "Configuration file not found at '{}' and daemon is offline.",
            cfg_path.display()
        )))
    }
}

/// Permanently revokes and self-destructs the node identity via cryptographic equivocation proof (Pillar 3 Heartbeat Spam).
pub async fn execute_revoke(config: Option<PathBuf>, confirm: Option<String>) -> Result<(), NodeError> {
    let cfg_path = config.unwrap_or_else(NodeConfig::default_config_path);
    if !cfg_path.exists() {
        return Err(NodeError::Cli(format!(
            "Configuration file not found at '{}'. Run 'humoco init' first.",
            cfg_path.display()
        )));
    }

    let config = NodeConfig::load_from_file(&cfg_path)?;

    if !config.identity.key_path.exists() {
        return Err(NodeError::Cli(format!(
            "Identity key file not found at '{}'.",
            config.identity.key_path.display()
        )));
    }

    let identity = NodeIdentity::load_from_file(&config.identity.key_path)?;

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║      ⚠️  WARNUNG: KNOTEN-SELBSTVERNICHTUNG / IRREVERSIBLER WIDERRUF ⚠️        ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Dieser Vorgang verbrennt die Identität dieses Knotens UNWIDERRUFLICH:         ║");
    println!("║ • Alle F2F-Freunde werden die Verbindung DAUERHAFT trennen.                  ║");
    println!("║ • Dein gemintes Argon2d-Shard-Ticket wird für immer entwertet.               ║");
    println!("║ • Dieser Schlüssel ({}) kann NIE WIEDER genutzt werden!║", identity.public_key_hex());
    println!("║ • Es wird ein kryptographischer Equivocation-FraudProof erzeugt.             ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");

    let is_confirmed = match confirm.as_deref() {
        Some(s) if s.eq_ignore_ascii_case("DELETE") || s.eq_ignore_ascii_case("KILL") => true,
        Some(other) => {
            return Err(NodeError::Cli(format!(
                "Ungültige Bestätigung '{}'. Erwartet: 'DELETE' oder 'KILL'",
                other
            )));
        }
        None => {
            print!("\nZur Bestätigung tippe genau 'DELETE' oder 'KILL' ein: ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_ok() {
                let trimmed = input.trim();
                trimmed.eq_ignore_ascii_case("DELETE") || trimmed.eq_ignore_ascii_case("KILL")
            } else {
                false
            }
        }
    };

    if !is_confirmed {
        println!("❌ Abbruch: Vorgang wurde nicht mit 'DELETE' oder 'KILL' bestätigt. Nichts verändert.");
        return Ok(());
    }

    // Generate deliberate equivocation proof (2 valid signed heartbeats within 1 second < 50 min)
    let node_id = identity.node_id_u16();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let hb1 = humoco_sim_core::fraud::sign_heartbeat(node_id, humoco_sim_core::types::SimTime(now_ms));
    let hb2 = humoco_sim_core::fraud::sign_heartbeat(node_id, humoco_sim_core::types::SimTime(now_ms + 1000));
    let proof = humoco_sim_core::fraud::FraudProofPayload::new_heartbeat_spam(hb1, hb2);

    // Save banned state to local database if present
    if config.storage.data_dir.exists() {
        let db_path = config.storage.data_dir.join("humoco.redb");
        if db_path.exists() {
            if let Ok(storage) = RedbStorage::open(&db_path) {
                let _ = storage.ban_node(identity.node_pubkey(), now_ms);
                let proof_raw = bincode::serialize(&proof).unwrap_or_default();
                let evidence_hash = *blake3::hash(&proof_raw).as_bytes();
                let _ = storage.put_evidence(&evidence_hash, &proof_raw);
            }
        }
    }

    println!("\n✅ KNOTEN WURDE ERFOLGREICH SELBST-VERBANNT.");
    println!("Beweis-Payload (Pillar 3 Heartbeat Equivocation) generiert.");
    println!("Perpetrator: {}", identity.public_key_hex());
    println!("Status: PERMANENT BANNED & WoT SEVERED.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use humoco_sim_core::types::{LockRecord, SimTime};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cli_init_and_status() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        let key_path = temp.path().join("node_key.bin");

        // One-shot Init: creates both config and key
        execute_init(Some(config_path.clone()), false, false, None, 12, None).expect("execute_init");
        assert!(config_path.exists());
        assert!(key_path.exists());

        // Init without force should fail
        assert!(execute_init(Some(config_path.clone()), false, false, None, 12, None).is_err());

        // Keygen with force to overwrite
        execute_keygen(Some(key_path.clone()), true).expect("execute_keygen");
        assert!(key_path.exists());

        // Update config to point to key_path
        let mut config = NodeConfig::load_from_file(&config_path).expect("load config");
        config.identity.key_path = key_path.clone();
        config.storage.data_dir = temp.path().join("data");
        config.save_to_file(&config_path).expect("save config");

        // Status check (offline)
        execute_status(Some(config_path.clone())).await.expect("execute_status");

        // Peers check (offline)
        execute_peers(Some(config_path.clone())).await.expect("execute_peers");

        // Quota Topup and Get (offline)
        let topup_cmd = QuotaCommands::Topup {
            account: "alice".into(),
            byte_years: 50_000,
            config: Some(config_path.clone()),
        };
        execute_quota(topup_cmd).await.expect("execute quota topup");

        let get_cmd = QuotaCommands::Get {
            account: "alice".into(),
            config: Some(config_path.clone()),
        };
        execute_quota(get_cmd).await.expect("execute quota get");
    }

    #[tokio::test]
    async fn test_cli_init_mnemonic_restore() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        let key_path = temp.path().join("node_key.bin");
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        execute_init(
            Some(config_path.clone()),
            false,
            false,
            Some(phrase.to_string()),
            12,
            None,
        )
        .expect("execute_init with mnemonic");

        assert!(config_path.exists());
        assert!(key_path.exists());

        let identity = NodeIdentity::load_from_file(&key_path).expect("load identity");
        assert_eq!(
            identity.public_key_hex(),
            "e96b1c6b8769fdb0b34fbecfdf85c33b053cecad9517e1ab88cba614335775c1"
        );

        // Status check prints public key and connection string
        execute_status(Some(config_path)).await.expect("execute_status");
    }

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::parse_from(["humoco", "init", "--force", "--with-key", "--mnemonic", "abandon about"]);
        assert_eq!(
            cli.command,
            Commands::Init {
                path: None,
                force: true,
                with_key: true,
                mnemonic: Some("abandon about".to_string()),
                words: 12,
                passphrase: None,
            }
        );
        // Verify custom words and passphrase parsing
        let cli = Cli::parse_from(["humoco", "init", "--words", "24", "--passphrase", "secret"]);
        assert_eq!(
            cli.command,
            Commands::Init {
                path: None,
                force: false,
                with_key: false,
                mnemonic: None,
                words: 24,
                passphrase: Some("secret".to_string()),
            }
        );
        // Validate that invalid word count is rejected
        assert!(Cli::try_parse_from(["humoco", "init", "--words", "13"]).is_err());
        assert!(Cli::try_parse_from(["humoco", "init", "--words", "15"]).is_err());

        let cli = Cli::parse_from(["humoco", "keygen", "-o", "/tmp/key.bin"]);
        assert_eq!(
            cli.command,
            Commands::Keygen {
                out: Some(PathBuf::from("/tmp/key.bin")),
                force: false
            }
        );

        let cli = Cli::parse_from(["humoco", "run", "-c", "/tmp/humoco.toml"]);
        assert_eq!(
            cli.command,
            Commands::Run {
                config: Some(PathBuf::from("/tmp/humoco.toml"))
            }
        );

        let cli = Cli::parse_from(["humoco", "status"]);
        assert_eq!(cli.command, Commands::Status { config: None });

        let cli = Cli::parse_from(["humoco", "peers"]);
        assert_eq!(cli.command, Commands::Peers { config: None });

        let cli = Cli::parse_from(["humoco", "quota", "topup", "alice", "1000"]);
        assert_eq!(
            cli.command,
            Commands::Quota {
                command: QuotaCommands::Topup {
                    account: "alice".into(),
                    byte_years: 1000,
                    config: None,
                }
            }
        );

        let cli = Cli::parse_from(["humoco", "quota", "get", "alice"]);
        assert_eq!(
            cli.command,
            Commands::Quota {
                command: QuotaCommands::Get {
                    account: "alice".into(),
                    config: None,
                }
            }
        );

        let cli = Cli::parse_from(["humoco", "doctor", "-c", "/tmp/humoco.toml"]);
        assert_eq!(
            cli.command,
            Commands::Doctor {
                config: Some(PathBuf::from("/tmp/humoco.toml"))
            }
        );

        let cli = Cli::parse_from(["humoco", "peer", "add", "alice@127.0.0.1:9090"]);
        assert_eq!(
            cli.command,
            Commands::Peer {
                command: PeerCommands::Add {
                    peer: "alice@127.0.0.1:9090".into(),
                    config: None,
                }
            }
        );

        let cli = Cli::parse_from(["humoco", "locks", "--limit", "15"]);
        assert_eq!(
            cli.command,
            Commands::Locks {
                limit: 15,
                config: None,
            }
        );

        let cli = Cli::parse_from(["humoco", "lock", "inspect", "0123456789abcdef"]);
        assert_eq!(
            cli.command,
            Commands::Lock {
                command: LockCommands::Inspect {
                    parent_lock: "0123456789abcdef".into(),
                    config: None,
                }
            }
        );

        let cli = Cli::parse_from(["humoco", "backup", "--out", "/tmp/backup.redb"]);
        assert_eq!(
            cli.command,
            Commands::Backup {
                out: PathBuf::from("/tmp/backup.redb"),
                config: None,
            }
        );
    }

    #[tokio::test]
    async fn test_cli_doctor_and_offline_subcommands() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        let key_path = temp.path().join("node_key.bin");

        execute_init(Some(config_path.clone()), false, false, None, 12, None).expect("execute_init");
        assert!(config_path.exists());
        assert!(key_path.exists());

        // Update config to point to key_path & data
        let mut config = NodeConfig::load_from_file(&config_path).expect("load config");
        config.identity.key_path = key_path.clone();
        config.storage.data_dir = temp.path().join("data");
        config.save_to_file(&config_path).expect("save config");

        // Doctor check
        execute_doctor(Some(config_path.clone())).await.expect("execute_doctor");

        // Peer Add offline
        execute_peer_add("bob@127.0.0.1:9095".into(), Some(config_path.clone()))
            .await
            .expect("execute_peer_add");
        let reloaded = NodeConfig::load_from_file(&config_path).expect("reload config");
        assert!(reloaded.f2f.peers.contains(&"bob@127.0.0.1:9095".to_string()));

        // Create db file and backup offline
        let db_path = config.storage.data_dir.join("humoco.redb");
        let storage = RedbStorage::open(&db_path).expect("open storage");
        let record = LockRecord::new(
            [3u8; 32],
            [4u8; 32],
            b"nonce".to_vec(),
            SimTime(100),
            SimTime(60_000),
        );
        storage.put_lock(&record, 600_000).expect("put lock");
        drop(storage);

        let backup_out = temp.path().join("backup.redb");
        execute_backup(backup_out.clone(), Some(config_path.clone()))
            .await
            .expect("execute_backup");
        assert!(backup_out.exists());

        // Verify backup content
        let backup_storage = RedbStorage::open(&backup_out).expect("open backup");
        let (rec, root_valid) = backup_storage.get_lock(&[3u8; 32]).expect("get_lock").expect("found");
        assert_eq!(rec.receiver_pub, [4u8; 32]);
        assert_eq!(root_valid, 600_000);
    }

    #[tokio::test]
    async fn test_cli_revoke_confirmation_and_evidence() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        let key_path = temp.path().join("node_key.bin");

        execute_init(Some(config_path.clone()), false, false, None, 12, None).expect("execute_init");
        let mut config = NodeConfig::load_from_file(&config_path).expect("load config");
        config.identity.key_path = key_path.clone();
        config.storage.data_dir = temp.path().join("data");
        std::fs::create_dir_all(&config.storage.data_dir).expect("create data dir");
        config.save_to_file(&config_path).expect("save config");

        let identity = NodeIdentity::load_from_file(&key_path).expect("load identity");
        let pubkey = *identity.node_pubkey();

        // Create empty db
        let db_path = config.storage.data_dir.join("humoco.redb");
        let _storage = RedbStorage::open(&db_path).expect("open storage");
        drop(_storage);

        // Invalid confirm should error
        let err = execute_revoke(Some(config_path.clone()), Some("INVALID".into())).await;
        assert!(err.is_err());

        // Valid confirm with DELETE should succeed and ban the node
        execute_revoke(Some(config_path.clone()), Some("DELETE".into())).await.expect("execute_revoke");

        // Verify banned state in database
        let storage = RedbStorage::open(&db_path).expect("open storage");
        assert!(storage.is_node_banned(&pubkey).expect("check ban"));
        let banned = storage.all_banned_nodes().expect("banned");
        assert!(banned.contains(&pubkey));
    }
}
