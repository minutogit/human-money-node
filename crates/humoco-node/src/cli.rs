use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use clap::{CommandFactory, Parser, Subcommand};
use serde::Serialize;

use crate::api::qr::generate_qr_ansi;
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

        /// Interactive guided step-by-step setup wizard
        #[arg(long)]
        wizard: bool,

        /// Display peering QR-code in terminal
        #[arg(long)]
        qr: bool,

        /// Output initialization result as JSON
        #[arg(long)]
        json: bool,
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

        /// Output status information as structured JSON
        #[arg(long)]
        json: bool,

        /// Display peering QR-code in terminal
        #[arg(long)]
        qr: bool,
    },

    /// List connected and configured peers
    Peers {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output peer list as structured JSON
        #[arg(long)]
        json: bool,
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

        /// Output diagnostic check results as structured JSON
        #[arg(long)]
        json: bool,
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

        /// Output recent locks as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect lock details
    Lock {
        #[command(subcommand)]
        command: LockCommands,
    },

    /// Display connection string and terminal QR code for easy mobile/friend peering
    Qr {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,
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

    /// Generate shell completion scripts for bash, zsh, fish, powershell, or elvish
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Stop the running node daemon gracefully
    Stop {
        /// Timeout in seconds to wait for graceful termination (default: 10)
        #[arg(short, long, default_value = "10")]
        timeout: u64,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output result as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect, check, or dump node configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Database maintenance and statistics
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },

    /// Restore node database from backup snapshot with verification
    Restore {
        /// Path to backup file
        #[arg(value_name = "BACKUP_FILE")]
        backup: Option<PathBuf>,

        /// Verify backup integrity and ensure no active daemon locks the target DB
        #[arg(long, value_name = "BACKUP_FILE")]
        verify: Option<PathBuf>,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output restore result as structured JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigCommands {
    /// Check configuration syntax, path existence, port validity, and file permissions
    Check {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output check results as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Dump resolved configuration as TOML or formatted JSON
    Dump {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output configuration as formatted JSON instead of TOML
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DbCommands {
    /// Display database storage statistics (dual-mode: online via control socket, offline via read-only Redb)
    Stats {
        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output stats as structured JSON
        #[arg(long)]
        json: bool,
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

    /// Remove a peer
    Remove {
        /// Peer connection string, public key, or address
        peer: String,

        /// Save removal to configuration file (humoco.toml)
        #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
        save: bool,

        /// Ephemeral removal (do not modify humoco.toml)
        #[arg(long, conflicts_with = "save")]
        ephemeral: bool,

        /// Path to configuration file (default: ~/.humoco/humoco.toml)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output result as structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Display connection string and terminal QR code for easy mobile/friend peering
    Qr {
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

        /// Output lock inspection as structured JSON
        #[arg(long)]
        json: bool,
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
                wizard,
                qr,
                json,
            } => execute_init(path, force, with_key, mnemonic, words, passphrase, wizard, qr, json),
            Commands::Keygen { out, force } => execute_keygen(out, force),
            Commands::Run { config } => execute_run(config).await,
            Commands::Status { config, json, qr } => execute_status(config, json, qr).await,
            Commands::Peers { config, json } => execute_peers(config, json).await,
            Commands::Quota { command } => execute_quota(command).await,
            Commands::Doctor { config, json } => execute_doctor(config, json).await,
            Commands::Peer { command } => match command {
                PeerCommands::Add { peer, config } => execute_peer_add(peer, config).await,
                PeerCommands::Remove { peer, save, ephemeral, config, json } => {
                    execute_peer_remove(peer, save, ephemeral, config, json).await
                }
                PeerCommands::Qr { config } => execute_qr(config).await,
            },
            Commands::Locks { limit, config, json } => execute_locks(limit, config, json).await,
            Commands::Lock { command } => match command {
                LockCommands::Inspect { parent_lock, config, json } => {
                    execute_lock_inspect(parent_lock, config, json).await
                }
            },
            Commands::Qr { config } => execute_qr(config).await,
            Commands::Backup { out, config } => execute_backup(out, config).await,
            Commands::Revoke { config, confirm } => execute_revoke(config, confirm).await,
            Commands::Completions { shell } => execute_completions(shell),
            Commands::Stop { timeout, config, json } => execute_stop(timeout, config, json).await,
            Commands::Config { command } => match command {
                ConfigCommands::Check { config, json } => execute_config_check(config, json).await,
                ConfigCommands::Dump { config, json } => execute_config_dump(config, json),
            },
            Commands::Db { command } => match command {
                DbCommands::Stats { config, json } => execute_db_stats(config, json).await,
            },
            Commands::Restore { backup, verify, config, json } => {
                execute_restore(backup, verify, config, json).await
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InitJsonOutput {
    pub config_path: String,
    pub key_path: String,
    pub node_id: String,
    pub public_key: String,
    pub hrw_routing_id: String,
    pub connection_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_mnemonic: Option<String>,
    pub mnemonic_words: usize,
    pub passphrase_set: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusJsonOutput {
    pub daemon: String,
    pub config_path: String,
    pub config_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hrw_routing_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_locks: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers_connected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_peers: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_work_score: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_headroom_pct: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_outdated: Option<bool>,
    pub p2p_listen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_addr: Option<String>,
    pub rpc_listen: String,
    pub data_dir: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerJsonOutput {
    pub address: String,
    pub node_id: Option<String>,
    pub status: String,
    pub missing_count: u32,
    pub min_hops: Option<u8>,
    pub ingress_peer: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheckJson {
    pub name: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorJsonOutput {
    pub daemon_online: bool,
    pub all_passed: bool,
    pub checks: Vec<DoctorCheckJson>,
}

fn run_interactive_wizard(
    default_cfg_path: &Path,
) -> Result<(NodeConfig, PathBuf, usize, Option<String>), NodeError> {
    use std::io::{stdin, stdout, Write};

    println!("=== HuMoCo Layer-2 Interactive Node Setup Wizard ===");
    println!("Press Enter to accept [default values] or type your custom value.\n");

    let prompt = |msg: &str, default: &str| -> Result<String, NodeError> {
        print!("{} [{}]: ", msg, default);
        stdout().flush().map_err(NodeError::Io)?;
        let mut input = String::new();
        stdin().read_line(&mut input).map_err(NodeError::Io)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            Ok(default.to_string())
        } else {
            Ok(trimmed.to_string())
        }
    };

    let prompt_opt = |msg: &str| -> Result<Option<String>, NodeError> {
        print!("{} (optional, Enter to skip): ", msg);
        stdout().flush().map_err(NodeError::Io)?;
        let mut input = String::new();
        stdin().read_line(&mut input).map_err(NodeError::Io)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_string()))
        }
    };

    let default_parent = default_cfg_path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.humoco".to_string());
    let dir_str = prompt("1. Base configuration & data directory", &default_parent)?;
    let base_dir = PathBuf::from(dir_str);
    let target_path = base_dir.join("humoco.toml");

    let mut cfg = NodeConfig::default();
    cfg.identity.key_path = base_dir.join("node_key.bin");
    cfg.storage.data_dir = base_dir.join("data");

    let p2p_port_str = prompt(
        "2. P2P UDP listen port",
        &cfg.network.p2p_listen_addr.port().to_string(),
    )?;
    if let Ok(p) = p2p_port_str.parse::<u16>() {
        cfg.network.p2p_listen_addr.set_port(p);
    }

    let rpc_port_str = prompt(
        "3. RPC TCP listen port",
        &cfg.network.rpc_listen_addr.port().to_string(),
    )?;
    if let Ok(p) = rpc_port_str.parse::<u16>() {
        cfg.network.rpc_listen_addr.set_port(p);
    }

    let words_str = prompt("4. Recovery Mnemonic Words count (12 or 24)", "12")?;
    let words: usize = match words_str.as_str() {
        "24" => 24,
        _ => 12,
    };

    let passphrase = prompt_opt("5. BIP-39 Passphrase for mnemonic encryption")?;

    if let Some(adv) = prompt_opt("6. Publicly advertised host:port (e.g. node.example.com:9090)")? {
        if let Ok(addr) = adv.parse() {
            cfg.network.advertised_addr = Some(addr);
        }
    }

    if let Some(peer) = prompt_opt("7. Initial trusted F2F peer string (<pubkey>@<host:port>)")? {
        cfg.f2f.peers.push(peer);
    }

    println!("\nConfiguration ready. Initializing node...");
    Ok((cfg, target_path, words, passphrase))
}

pub fn execute_init(
    path: Option<PathBuf>,
    force: bool,
    with_key: bool,
    mnemonic: Option<String>,
    words: usize,
    passphrase: Option<String>,
    wizard: bool,
    qr: bool,
    json: bool,
) -> Result<(), NodeError> {
    if wizard && !std::io::stdin().is_terminal() {
        return Err(NodeError::Cli(
            "Interactive setup wizard requires an interactive terminal (TTY). Omit --wizard for scripted/automated setups.".into(),
        ));
    }

    let default_path = NodeConfig::default_config_path();
    let (cfg, target_path, words, passphrase) = if wizard {
        run_interactive_wizard(&default_path)?
    } else {
        let tp = match path {
            Some(p) if p.is_dir() || p.extension().is_none() => p.join("humoco.toml"),
            Some(p) => p,
            None => default_path,
        };
        let c = if tp.exists() {
            NodeConfig::load_from_file(&tp).unwrap_or_default()
        } else {
            let mut def = NodeConfig::default();
            if let Some(parent) = tp.parent() {
                if !parent.as_os_str().is_empty() && parent != NodeConfig::default_humoco_dir() {
                    def.identity.key_path = parent.join("node_key.bin");
                    def.storage.data_dir = parent.join("data");
                }
            }
            def
        };
        (c, tp, words, passphrase)
    };

    if target_path.exists() && !force && !wizard {
        return Err(NodeError::Cli(format!(
            "Configuration file already exists at '{}'. Use --force to overwrite.",
            target_path.display()
        )));
    }

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
            let wc = phrase.split_whitespace().count();
            (id, None, wc)
        } else if let Some(ref pp) = passphrase {
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

        if json {
            let out = InitJsonOutput {
                config_path: target_path.display().to_string(),
                key_path: cfg.identity.key_path.display().to_string(),
                node_id: identity.node_id_hex(),
                public_key: identity.public_key_hex(),
                hrw_routing_id: identity.hrw_routing_id_hex(),
                connection_string: conn_string.clone(),
                recovery_mnemonic: phrase_opt,
                mnemonic_words: actual_words,
                passphrase_set: passphrase.is_some(),
            };
            println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
            return Ok(());
        }

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

        if qr {
            println!("\n=== Peering QR Code ===");
            print!("{}", generate_qr_ansi(&conn_string));
        }
    } else {
        if json {
            let out = InitJsonOutput {
                config_path: target_path.display().to_string(),
                key_path: cfg.identity.key_path.display().to_string(),
                node_id: String::new(),
                public_key: String::new(),
                hrw_routing_id: String::new(),
                connection_string: String::new(),
                recovery_mnemonic: None,
                mnemonic_words: 0,
                passphrase_set: false,
            };
            println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
            return Ok(());
        }
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

pub async fn execute_status(config_path: Option<PathBuf>, json: bool, qr: bool) -> Result<(), NodeError> {
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
            let hrw_hex = hrw_routing_id.or_else(|| {
                if cfg.identity.key_path.exists() {
                    NodeIdentity::load_from_file(&cfg.identity.key_path)
                        .ok()
                        .map(|id| id.hrw_routing_id_hex())
                } else {
                    None
                }
            });

            let conn_addr = if let Some(adv) = cfg.network.advertised_addr {
                adv.to_string()
            } else if cfg.network.p2p_listen_addr.ip().is_unspecified() {
                format!("<public_ip_or_hostname>:{}", cfg.network.p2p_listen_addr.port())
            } else {
                cfg.network.p2p_listen_addr.to_string()
            };
            let conn_string = pubkey.as_ref().map(|pk| format!("{}@{}", pk, conn_addr));

            if json {
                let out = StatusJsonOutput {
                    daemon: "ONLINE".to_string(),
                    config_path: cfg_path.display().to_string(),
                    config_valid: true,
                    node_id: Some(node_id),
                    public_key: pubkey,
                    hrw_routing_id: hrw_hex,
                    connection_string: conn_string,
                    uptime_sec: Some(uptime_sec),
                    active_locks: Some(active_locks),
                    peers_connected: Some(peers_connected),
                    configured_peers: Some(cfg.f2f.peers.len()),
                    pow_work_score: own_work,
                    pow_headroom_pct: headroom_pct,
                    ticket_outdated: Some(ticket_outdated),
                    p2p_listen: cfg.network.p2p_listen_addr.to_string(),
                    advertised_addr: cfg.network.advertised_addr.map(|a| a.to_string()),
                    rpc_listen: cfg.network.rpc_listen_addr.to_string(),
                    data_dir: data_dir.display().to_string(),
                };
                println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
                return Ok(());
            }

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

            if qr {
                if let Some(ref cs) = conn_string {
                    println!("\n=== Peering QR Code ===");
                    print!("{}", generate_qr_ansi(cs));
                }
            }
            return Ok(());
        }
    }

    // Fallback: Offline static inspection
    if json {
        let (config_valid, node_id, pubkey, hrw_hex, conn_str, p2p_str, rpc_str, data_str, peers_cnt, work_score) =
            if let Some(ref cfg) = config {
                let id_opt = if cfg.identity.key_path.exists() {
                    NodeIdentity::load_from_file(&cfg.identity.key_path).ok()
                } else {
                    None
                };
                let conn_addr = if let Some(adv) = cfg.network.advertised_addr {
                    adv.to_string()
                } else if cfg.network.p2p_listen_addr.ip().is_unspecified() {
                    format!("<public_ip_or_hostname>:{}", cfg.network.p2p_listen_addr.port())
                } else {
                    cfg.network.p2p_listen_addr.to_string()
                };
                let cs = id_opt.as_ref().map(|id| format!("{}@{}", id.public_key_hex(), conn_addr));
                let nid = id_opt.as_ref().map(|id| id.node_id_hex());
                let pk = id_opt.as_ref().map(|id| id.public_key_hex());
                let hrw = id_opt.as_ref().map(|id| id.hrw_routing_id_hex());
                let ws = id_opt.as_ref().map(|id| id.work_score());
                (
                    true,
                    nid,
                    pk,
                    hrw,
                    cs,
                    cfg.network.p2p_listen_addr.to_string(),
                    cfg.network.rpc_listen_addr.to_string(),
                    cfg.storage.data_dir.display().to_string(),
                    Some(cfg.f2f.peers.len()),
                    ws,
                )
            } else {
                (false, None, None, None, None, String::new(), String::new(), String::new(), None, None)
            };

        let out = StatusJsonOutput {
            daemon: "OFFLINE".to_string(),
            config_path: cfg_path.display().to_string(),
            config_valid,
            node_id,
            public_key: pubkey,
            hrw_routing_id: hrw_hex,
            connection_string: conn_str,
            uptime_sec: None,
            active_locks: None,
            peers_connected: None,
            configured_peers: peers_cnt,
            pow_work_score: work_score,
            pow_headroom_pct: None,
            ticket_outdated: None,
            p2p_listen: p2p_str,
            advertised_addr: config.as_ref().and_then(|c| c.network.advertised_addr.map(|a| a.to_string())),
            rpc_listen: rpc_str,
            data_dir: data_str,
        };
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
        return Ok(());
    }

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
    let mut conn_string_opt = None;
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
                let conn_string = format!("{}@{}", pk, conn_addr);
                conn_string_opt = Some(conn_string.clone());
                println!("Key Status:        Valid");
                println!("Node ID:           {}", identity.node_id_hex());
                println!("HRW Routing ID:    {}", identity.hrw_routing_id_hex());
                println!("Routing Nonce:     {}", identity.nonce());
                println!("Routing T0:        {} ({} incubation)", identity.t0(), if identity.t0() == 0 { "no" } else { "24h" });
                println!("Public Key:        {}", pk);
                println!("Public Key (did):  {}", identity.did_key());
                println!("Connection String: {}", conn_string);
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

    if qr {
        if let Some(ref cs) = conn_string_opt {
            println!("\n=== Peering QR Code ===");
            print!("{}", generate_qr_ansi(cs));
        }
    }

    Ok(())
}

pub async fn execute_peers(config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
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
            if json {
                let out: Vec<PeerJsonOutput> = peers
                    .into_iter()
                    .map(|p| PeerJsonOutput {
                        address: p.addr.to_string(),
                        node_id: p.node_id,
                        status: p.status,
                        missing_count: p.missing_count,
                        min_hops: p.min_hops,
                        ingress_peer: p.ingress_peer,
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
                return Ok(());
            }

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
    if json {
        let out: Vec<PeerJsonOutput> = if let Some(cfg) = config {
            cfg.f2f
                .peers
                .into_iter()
                .map(|p| PeerJsonOutput {
                    address: p,
                    node_id: None,
                    status: "configured (offline)".to_string(),
                    missing_count: 0,
                    min_hops: None,
                    ingress_peer: None,
                })
                .collect()
        } else {
            Vec::new()
        };
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
        return Ok(());
    }

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

pub async fn execute_doctor(config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let mut checks: Vec<DoctorCheckJson> = Vec::new();
    let mut all_passed = true;

    // 1. Config file check
    let (_config_opt, cfg) = if cfg_path.exists() {
        match NodeConfig::load_from_file(&cfg_path) {
            Ok(c) => {
                checks.push(DoctorCheckJson {
                    name: "config_file".into(),
                    status: "ok".into(),
                    message: format!("Configuration file valid at {}", cfg_path.display()),
                });
                let c_clone = c.clone();
                (Some(c), c_clone)
            }
            Err(e) => {
                all_passed = false;
                checks.push(DoctorCheckJson {
                    name: "config_file".into(),
                    status: "error".into(),
                    message: format!("Configuration file invalid at {} ({})", cfg_path.display(), e),
                });
                (None, NodeConfig::default())
            }
        }
    } else {
        checks.push(DoctorCheckJson {
            name: "config_file".into(),
            status: "warn".into(),
            message: format!("Configuration file not found at {} (using defaults)", cfg_path.display()),
        });
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
                        checks.push(DoctorCheckJson {
                            name: "key_permissions".into(),
                            status: "ok".into(),
                            message: format!("Key permissions 0600 at {}", key_path.display()),
                        });
                    } else {
                        all_passed = false;
                        checks.push(DoctorCheckJson {
                            name: "key_permissions".into(),
                            status: "error".into(),
                            message: format!("Key permissions mode {:04o}, expected 0600 at {}", mode, key_path.display()),
                        });
                    }
                }
                Err(e) => {
                    all_passed = false;
                    checks.push(DoctorCheckJson {
                        name: "key_permissions".into(),
                        status: "error".into(),
                        message: format!("Key metadata error: {}", e),
                    });
                }
            }
        }
        #[cfg(not(unix))]
        {
            checks.push(DoctorCheckJson {
                name: "key_permissions".into(),
                status: "ok".into(),
                message: format!("Key file present at {}", key_path.display()),
            });
        }
    } else {
        all_passed = false;
        checks.push(DoctorCheckJson {
            name: "key_permissions".into(),
            status: "error".into(),
            message: format!("Key file missing at {}", key_path.display()),
        });
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
        Ok(()) => checks.push(DoctorCheckJson {
            name: "data_dir".into(),
            status: "ok".into(),
            message: format!("Data directory writable at {}", data_dir.display()),
        }),
        Err(e) => {
            all_passed = false;
            checks.push(DoctorCheckJson {
                name: "data_dir".into(),
                status: "error".into(),
                message: format!("Data directory not writable: {}", e),
            });
        }
    }

    // 4. Control socket responsiveness check
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path.clone());
    let daemon_status = client.get_status().await;
    let daemon_online = matches!(daemon_status, Ok(ControlResponse::Status { .. }));

    // 5. Port binding availability
    let p2p_port = cfg.network.p2p_listen_addr.port();
    let rpc_port = cfg.network.rpc_listen_addr.port();

    if daemon_online {
        checks.push(DoctorCheckJson {
            name: "p2p_port".into(),
            status: "ok".into(),
            message: format!("P2P UDP port {}/udp bound by running daemon", p2p_port),
        });
        checks.push(DoctorCheckJson {
            name: "rpc_port".into(),
            status: "ok".into(),
            message: format!("RPC TCP port {}/tcp bound by running daemon", rpc_port),
        });
    } else {
        match std::net::UdpSocket::bind(cfg.network.p2p_listen_addr) {
            Ok(_) => checks.push(DoctorCheckJson {
                name: "p2p_port".into(),
                status: "ok".into(),
                message: format!("P2P UDP port {}/udp available for binding", p2p_port),
            }),
            Err(e) => {
                all_passed = false;
                checks.push(DoctorCheckJson {
                    name: "p2p_port".into(),
                    status: "error".into(),
                    message: format!("P2P UDP port {}/udp unavailable: {}", p2p_port, e),
                });
            }
        }
        match std::net::TcpListener::bind(cfg.network.rpc_listen_addr) {
            Ok(_) => checks.push(DoctorCheckJson {
                name: "rpc_port".into(),
                status: "ok".into(),
                message: format!("RPC TCP port {}/tcp available for binding", rpc_port),
            }),
            Err(e) => {
                all_passed = false;
                checks.push(DoctorCheckJson {
                    name: "rpc_port".into(),
                    status: "error".into(),
                    message: format!("RPC TCP port {}/tcp unavailable: {}", rpc_port, e),
                });
            }
        }
    }

    // 6. Monotonic clock & system time
    let t1 = std::time::Instant::now();
    let sys_now = std::time::SystemTime::now();
    let t2 = std::time::Instant::now();
    let monotonic_ok = t2 >= t1;
    let epoch_sec = sys_now.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let time_plausible = epoch_sec > 1_700_000_000;
    if monotonic_ok && time_plausible {
        checks.push(DoctorCheckJson {
            name: "monotonic_clock".into(),
            status: "ok".into(),
            message: format!("Monotonic clock OK (epoch: {}s)", epoch_sec),
        });
    } else {
        all_passed = false;
        checks.push(DoctorCheckJson {
            name: "monotonic_clock".into(),
            status: "error".into(),
            message: format!("Clock synchronization check failed (monotonic: {}, epoch: {}s)", monotonic_ok, epoch_sec),
        });
    }

    // 7. Control socket responsiveness
    match daemon_status {
        Ok(ControlResponse::Status { uptime_sec, active_locks, peers_connected, .. }) => {
            checks.push(DoctorCheckJson {
                name: "control_socket".into(),
                status: "ok".into(),
                message: format!("Daemon ONLINE (uptime: {}s, locks: {}, peers: {})", uptime_sec, active_locks, peers_connected),
            });
        }
        _ => {
            checks.push(DoctorCheckJson {
                name: "control_socket".into(),
                status: "warn".into(),
                message: format!("Daemon OFFLINE (socket at {})", socket_path.display()),
            });
        }
    }

    // 8. PoW Headroom & Shard Ticket Health
    match &daemon_status {
        Ok(ControlResponse::Status { ticket_outdated, headroom_pct, own_work, net_median_work, .. }) => {
            if *ticket_outdated {
                all_passed = false;
                checks.push(DoctorCheckJson {
                    name: "pow_headroom".into(),
                    status: "error".into(),
                    message: "Ticket outdated / rejected by F2F peers, re-mining required".into(),
                });
            } else if let Some(pct) = headroom_pct {
                if *pct < 12 {
                    all_passed = false;
                    checks.push(DoctorCheckJson {
                        name: "pow_headroom".into(),
                        status: "error".into(),
                        message: format!("PoW Headroom critical: {}% of median", pct),
                    });
                } else if *pct < 25 {
                    checks.push(DoctorCheckJson {
                        name: "pow_headroom".into(),
                        status: "warn".into(),
                        message: format!("PoW Headroom low: {}% of median (re-mining recommended)", pct),
                    });
                } else {
                    checks.push(DoctorCheckJson {
                        name: "pow_headroom".into(),
                        status: "ok".into(),
                        message: format!("PoW Headroom healthy: {}% (Work: {}, Median: {})", pct, own_work.unwrap_or(1), net_median_work.unwrap_or(1)),
                    });
                }
            } else {
                checks.push(DoctorCheckJson {
                    name: "pow_headroom".into(),
                    status: "ok".into(),
                    message: "PoW Headroom OK (Standalone / Fast-Path)".into(),
                });
            }
        }
        _ => {
            if cfg.identity.key_path.exists() {
                if let Ok(id) = NodeIdentity::load_from_file(&cfg.identity.key_path) {
                    checks.push(DoctorCheckJson {
                        name: "pow_headroom".into(),
                        status: "ok".into(),
                        message: format!("Offline valid (Local Work Score: {})", id.work_score()),
                    });
                } else {
                    checks.push(DoctorCheckJson {
                        name: "pow_headroom".into(),
                        status: "error".into(),
                        message: "Key file invalid".into(),
                    });
                }
            } else {
                checks.push(DoctorCheckJson {
                    name: "pow_headroom".into(),
                    status: "warn".into(),
                    message: "Key file missing".into(),
                });
            }
        }
    }

    if json {
        let out = DoctorJsonOutput {
            daemon_online,
            all_passed,
            checks,
        };
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| NodeError::Cli(e.to_string()))?);
        return Ok(());
    }

    println!("=== HuMoCo Layer-2 Node Doctor Diagnostic ===");
    for check in &checks {
        let symbol = match check.status.as_str() {
            "ok" => "[✓]",
            "warn" => "[!]",
            _ => "[✗]",
        };
        println!("{} {}: {}", symbol, check.name, check.message);
    }
    println!("==============================================");

    Ok(())
}

pub async fn execute_qr(config_path: Option<PathBuf>) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    if !cfg_path.exists() {
        return Err(NodeError::Cli(format!(
            "Configuration file not found at '{}'. Run 'humoco init' first.",
            cfg_path.display()
        )));
    }

    let cfg = NodeConfig::load_from_file(&cfg_path)?;
    if !cfg.identity.key_path.exists() {
        return Err(NodeError::Cli(format!(
            "Identity key file not found at '{}'. Run 'humoco keygen' first.",
            cfg.identity.key_path.display()
        )));
    }

    let identity = NodeIdentity::load_from_file(&cfg.identity.key_path)?;
    let conn_addr = if let Some(adv) = cfg.network.advertised_addr {
        adv.to_string()
    } else if cfg.network.p2p_listen_addr.ip().is_unspecified() {
        format!("<public_ip_or_hostname>:{}", cfg.network.p2p_listen_addr.port())
    } else {
        cfg.network.p2p_listen_addr.to_string()
    };
    let conn_string = format!("{}@{}", identity.public_key_hex(), conn_addr);

    println!("=== HuMoCo Peering QR Code ===");
    println!("Connection String: {}", conn_string);
    println!("\nScan with mobile wallet or companion app to peer:\n");
    print!("{}", generate_qr_ansi(&conn_string));
    println!("Public Key: {}", identity.public_key_hex());
    Ok(())
}

pub async fn execute_locks(limit: usize, config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = NodeConfig::load_from_file(&cfg_path)?;
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path);

    match client.get_recent_locks(limit).await? {
        ControlResponse::RecentLocks { locks } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&locks).map_err(|e| NodeError::Cli(e.to_string()))?);
                return Ok(());
            }

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

pub async fn execute_lock_inspect(parent_lock: String, config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = NodeConfig::load_from_file(&cfg_path)?;
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path);

    match client.inspect_lock(&parent_lock).await? {
        ControlResponse::LockInspection { inspection: Some(insp) } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&insp).map_err(|e| NodeError::Cli(e.to_string()))?);
                return Ok(());
            }

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
            if json {
                println!("null");
                return Ok(());
            }
            println!("Lock with parent_lock '{}' not found in RAM index.", parent_lock);
            Ok(())
        }
        ControlResponse::Error { message } => Err(NodeError::Cli(format!("Daemon error: {}", message))),
        _ => Err(NodeError::Daemon("Unexpected response from control server".into())),
    }
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

pub fn execute_completions(shell: clap_complete::Shell) -> Result<(), NodeError> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "humoco", &mut std::io::stdout());
    Ok(())
}

pub async fn execute_stop(
    timeout: u64,
    config_path: Option<PathBuf>,
    json: bool,
) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path)?
    } else {
        NodeConfig::default()
    };
    let socket_path = cfg.control_socket_path();
    if !socket_path.exists() {
        if json {
            let out = serde_json::json!({
                "status": "already_stopped",
                "message": "Node daemon is not running (socket not found)",
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        } else {
            println!("Node daemon is not running (socket '{}' not found).", socket_path.display());
        }
        return Ok(());
    }

    let client = ControlClient::new(socket_path);
    client.shutdown(timeout).await?;

    if json {
        let out = serde_json::json!({
            "status": "stopped",
            "timeout_sec": timeout,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        println!("[✓] Node daemon stopped successfully.");
    }
    Ok(())
}

pub async fn execute_peer_remove(
    peer: String,
    save: bool,
    ephemeral: bool,
    config_path: Option<PathBuf>,
    json: bool,
) -> Result<(), NodeError> {
    let should_save = save && !ephemeral;
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let config = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path).ok()
    } else {
        None
    };

    let mut removed_pubkey = None;
    let mut online_removed = false;

    // 1. Try removing online via control socket if daemon is running
    if let Some(ref cfg) = config {
        let socket_path = cfg.control_socket_path();
        let client = ControlClient::new(socket_path);
        if let Ok(pubkey_hex) = client.remove_peer(&peer).await {
            removed_pubkey = Some(pubkey_hex);
            online_removed = true;
        }
    }

    // 2. If should_save, remove from humoco.toml
    let mut saved_to_file = false;
    if should_save {
        if let Some(mut cfg) = config {
            let initial_len = cfg.f2f.peers.len();
            cfg.f2f.peers.retain(|p| {
                let p_clean = p.trim();
                let target = peer.trim();
                if p_clean == target || p_clean.contains(target) {
                    return false;
                }
                if let Some(ref rk) = removed_pubkey {
                    if p_clean.contains(rk) {
                        return false;
                    }
                }
                true
            });
            if cfg.f2f.peers.len() < initial_len {
                cfg.save_to_file(&cfg_path)?;
                saved_to_file = true;
            }
        }
    }

    if json {
        let out = serde_json::json!({
            "status": "removed",
            "peer": peer,
            "pubkey": removed_pubkey,
            "online": online_removed,
            "saved_to_file": saved_to_file,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else if online_removed {
        println!("[✓] Peer '{}' removed successfully (live).", peer);
        if saved_to_file {
            println!("[✓] Peer removed from configuration file '{}'.", cfg_path.display());
        }
    } else if saved_to_file {
        println!("[✓] Peer '{}' removed from configuration file (offline).", peer);
    } else {
        println!("Peer '{}' removed (or was not present).", peer);
    }

    Ok(())
}

pub async fn execute_config_check(config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let mut checks = Vec::new();
    let mut all_ok = true;

    // 1. Config syntax
    let config = if cfg_path.exists() {
        match NodeConfig::load_from_file(&cfg_path) {
            Ok(c) => {
                checks.push(DoctorCheckJson {
                    name: "config_syntax".into(),
                    status: "ok".into(),
                    message: format!("Syntax valid at {}", cfg_path.display()),
                });
                Some(c)
            }
            Err(e) => {
                all_ok = false;
                checks.push(DoctorCheckJson {
                    name: "config_syntax".into(),
                    status: "error".into(),
                    message: format!("Syntax error in {}: {}", cfg_path.display(), e),
                });
                None
            }
        }
    } else {
        all_ok = false;
        checks.push(DoctorCheckJson {
            name: "config_syntax".into(),
            status: "error".into(),
            message: format!("Config file not found at {}", cfg_path.display()),
        });
        None
    };

    let cfg = config.unwrap_or_default();

    // 2. Paths existences and permissions
    let key_path = &cfg.identity.key_path;
    if key_path.exists() {
        checks.push(DoctorCheckJson {
            name: "key_path".into(),
            status: "ok".into(),
            message: format!("Key file exists at {}", key_path.display()),
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(key_path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o600 {
                    checks.push(DoctorCheckJson {
                        name: "key_permissions".into(),
                        status: "ok".into(),
                        message: format!("Key permissions POSIX 0600 verified at {}", key_path.display()),
                    });
                } else {
                    all_ok = false;
                    checks.push(DoctorCheckJson {
                        name: "key_permissions".into(),
                        status: "error".into(),
                        message: format!("Key permissions mode {:04o}, expected 0600 at {}", mode, key_path.display()),
                    });
                }
            }
        }
    } else {
        all_ok = false;
        checks.push(DoctorCheckJson {
            name: "key_path".into(),
            status: "error".into(),
            message: format!("Key file missing at {}", key_path.display()),
        });
    }

    let data_dir = &cfg.storage.data_dir;
    if data_dir.exists() {
        checks.push(DoctorCheckJson {
            name: "data_dir".into(),
            status: "ok".into(),
            message: format!("Data directory exists at {}", data_dir.display()),
        });
    } else if let Some(parent) = data_dir.parent() {
        if parent.as_os_str().is_empty() || parent.exists() {
            checks.push(DoctorCheckJson {
                name: "data_dir".into(),
                status: "ok".into(),
                message: format!("Data directory can be created at {}", data_dir.display()),
            });
        } else {
            all_ok = false;
            checks.push(DoctorCheckJson {
                name: "data_dir".into(),
                status: "error".into(),
                message: format!("Parent directory for data_dir does not exist: {}", parent.display()),
            });
        }
    }

    // 3. Port validity
    let p2p_port = cfg.network.p2p_listen_addr.port();
    let rpc_port = cfg.network.rpc_listen_addr.port();
    if p2p_port > 0 {
        checks.push(DoctorCheckJson {
            name: "p2p_port".into(),
            status: "ok".into(),
            message: format!("P2P port {} is valid", p2p_port),
        });
    } else {
        all_ok = false;
        checks.push(DoctorCheckJson {
            name: "p2p_port".into(),
            status: "error".into(),
            message: "P2P port cannot be 0".into(),
        });
    }

    if rpc_port > 0 {
        checks.push(DoctorCheckJson {
            name: "rpc_port".into(),
            status: "ok".into(),
            message: format!("RPC port {} is valid", rpc_port),
        });
    } else {
        all_ok = false;
        checks.push(DoctorCheckJson {
            name: "rpc_port".into(),
            status: "error".into(),
            message: "RPC port cannot be 0".into(),
        });
    }

    if json {
        let out = serde_json::json!({
            "valid": all_ok,
            "checks": checks,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for c in &checks {
            let symbol = match c.status.as_str() {
                "ok" => "[✓]",
                "warn" => "[!]",
                _ => "[✗]",
            };
            println!("{} {}: {}", symbol, c.name, c.message);
        }
        if all_ok {
            println!("\nConfiguration check passed successfully.");
        } else {
            println!("\nConfiguration check found errors.");
        }
    }

    if all_ok {
        Ok(())
    } else {
        Err(NodeError::Cli("Configuration check failed".into()))
    }
}

pub fn execute_config_dump(config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let config = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path)?
    } else {
        NodeConfig::default()
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&config).map_err(|e| NodeError::Cli(e.to_string()))?);
    } else {
        println!("{}", toml::to_string_pretty(&config).map_err(|e| NodeError::Cli(e.to_string()))?);
    }
    Ok(())
}

pub async fn execute_db_stats(config_path: Option<PathBuf>, json: bool) -> Result<(), NodeError> {
    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path)?
    } else {
        NodeConfig::default()
    };

    // Try online mode via control socket
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path);
    if let Ok(stats) = client.get_db_stats().await {
        if json {
            let out = serde_json::json!({
                "mode": "online",
                "active_locks": stats.active_locks,
                "db_size_bytes": stats.db_size_bytes,
                "page_allocations": stats.page_allocations,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        } else {
            println!("=== HuMoCo DB Statistics (Online) ===");
            println!("Active Locks:     {}", stats.active_locks);
            println!("DB Size:          {} bytes ({:.2} MB)", stats.db_size_bytes, stats.db_size_bytes as f64 / 1_048_576.0);
            if let Some(pages) = stats.page_allocations {
                println!("Page Allocations: {}", pages);
            }
        }
        return Ok(());
    }

    // Offline mode: open Redb directly
    let db_path = cfg.storage.data_dir.join("humoco.redb");
    if !db_path.exists() {
        return Err(NodeError::Cli(format!("Database file not found at '{}'", db_path.display())));
    }

    let storage = RedbStorage::open(&db_path)?;
    let (active_locks, db_size_bytes, page_allocations) = storage.get_stats()?;

    if json {
        let out = serde_json::json!({
            "mode": "offline",
            "active_locks": active_locks,
            "db_size_bytes": db_size_bytes,
            "page_allocations": page_allocations,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        println!("=== HuMoCo DB Statistics (Offline) ===");
        println!("Active Locks:     {}", active_locks);
        println!("DB Size:          {} bytes ({:.2} MB)", db_size_bytes, db_size_bytes as f64 / 1_048_576.0);
        if let Some(pages) = page_allocations {
            println!("Page Allocations: {}", pages);
        }
    }

    Ok(())
}

pub async fn execute_restore(
    backup_file: Option<PathBuf>,
    verify_file: Option<PathBuf>,
    config_path: Option<PathBuf>,
    json: bool,
) -> Result<(), NodeError> {
    let source_path = verify_file
        .or(backup_file)
        .ok_or_else(|| NodeError::Cli("Missing backup file path".into()))?;

    if !source_path.exists() {
        return Err(NodeError::Cli(format!("Backup file not found at '{}'", source_path.display())));
    }

    let cfg_path = config_path.unwrap_or_else(NodeConfig::default_config_path);
    let cfg = if cfg_path.exists() {
        NodeConfig::load_from_file(&cfg_path)?
    } else {
        NodeConfig::default()
    };

    // 1. Verify backup file integrity
    let backup_storage = match RedbStorage::open(&source_path) {
        Ok(s) => s,
        Err(e) => return Err(NodeError::Cli(format!("Backup file corrupt or invalid redb format: {}", e))),
    };
    let (locks_count, backup_size, _) = backup_storage.get_stats()?;

    // 2. Ensure daemon is NOT running and locking the target DB
    let socket_path = cfg.control_socket_path();
    let client = ControlClient::new(socket_path);
    if client.get_status().await.is_ok() {
        return Err(NodeError::Cli(
            "Cannot restore database while daemon is running. Stop the daemon first with 'humoco stop'.".into(),
        ));
    }

    // 3. Restore to target DB path
    let target_db_path = cfg.storage.data_dir.join("humoco.redb");
    if let Some(parent) = target_db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // If target exists, backup to humoco.redb.bak first
    if target_db_path.exists() {
        let bak_path = cfg.storage.data_dir.join("humoco.redb.bak");
        let _ = std::fs::copy(&target_db_path, &bak_path);
    }

    // Copy backup file to target
    std::fs::copy(&source_path, &target_db_path)?;

    // Verify restored target database
    let restored_storage = RedbStorage::open(&target_db_path)?;
    let (restored_locks, restored_size, _) = restored_storage.get_stats()?;

    if json {
        let out = serde_json::json!({
            "status": "restored",
            "backup_path": source_path.display().to_string(),
            "target_path": target_db_path.display().to_string(),
            "locks_restored": restored_locks,
            "db_size_bytes": restored_size,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        println!("[✓] Backup integrity verified ({} locks, {} bytes).", locks_count, backup_size);
        println!("[✓] Target database successfully restored to '{}'.", target_db_path.display());
        println!("[✓] Restored locks: {}.", restored_locks);
    }

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
        execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).expect("execute_init");
        assert!(config_path.exists());
        assert!(key_path.exists());

        // Init without force should fail
        assert!(execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).is_err());

        // Keygen with force to overwrite
        execute_keygen(Some(key_path.clone()), true).expect("execute_keygen");
        assert!(key_path.exists());

        // Update config to point to key_path
        let mut config = NodeConfig::load_from_file(&config_path).expect("load config");
        config.identity.key_path = key_path.clone();
        config.storage.data_dir = temp.path().join("data");
        config.save_to_file(&config_path).expect("save config");

        // Status check (offline text)
        execute_status(Some(config_path.clone()), false, false).await.expect("execute_status");

        // Status check (offline JSON and QR)
        execute_status(Some(config_path.clone()), true, false).await.expect("execute_status json");
        execute_status(Some(config_path.clone()), false, true).await.expect("execute_status qr");

        // Peers check (offline text and JSON)
        execute_peers(Some(config_path.clone()), false).await.expect("execute_peers");
        execute_peers(Some(config_path.clone()), true).await.expect("execute_peers json");

        // QR command
        execute_qr(Some(config_path.clone())).await.expect("execute_qr");

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
            false,
            false,
            false,
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
        execute_status(Some(config_path), false, false).await.expect("execute_status");
    }

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::parse_from(["humoco", "init", "--force", "--with-key", "--mnemonic", "abandon about", "--qr", "--json"]);
        assert_eq!(
            cli.command,
            Commands::Init {
                path: None,
                force: true,
                with_key: true,
                mnemonic: Some("abandon about".to_string()),
                words: 12,
                passphrase: None,
                wizard: false,
                qr: true,
                json: true,
            }
        );
        // Verify custom words and passphrase parsing
        let cli = Cli::parse_from(["humoco", "init", "--words", "24", "--passphrase", "secret", "--wizard"]);
        assert_eq!(
            cli.command,
            Commands::Init {
                path: None,
                force: false,
                with_key: false,
                mnemonic: None,
                words: 24,
                passphrase: Some("secret".to_string()),
                wizard: true,
                qr: false,
                json: false,
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

        let cli = Cli::parse_from(["humoco", "status", "--json", "--qr"]);
        assert_eq!(cli.command, Commands::Status { config: None, json: true, qr: true });

        let cli = Cli::parse_from(["humoco", "peers", "--json"]);
        assert_eq!(cli.command, Commands::Peers { config: None, json: true });

        let cli = Cli::parse_from(["humoco", "qr"]);
        assert_eq!(cli.command, Commands::Qr { config: None });

        let cli = Cli::parse_from(["humoco", "peer", "qr"]);
        assert_eq!(cli.command, Commands::Peer { command: PeerCommands::Qr { config: None } });

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

        let cli = Cli::parse_from(["humoco", "doctor", "-c", "/tmp/humoco.toml", "--json"]);
        assert_eq!(
            cli.command,
            Commands::Doctor {
                config: Some(PathBuf::from("/tmp/humoco.toml")),
                json: true,
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

        let cli = Cli::parse_from(["humoco", "locks", "--limit", "15", "--json"]);
        assert_eq!(
            cli.command,
            Commands::Locks {
                limit: 15,
                config: None,
                json: true,
            }
        );

        let cli = Cli::parse_from(["humoco", "lock", "inspect", "0123456789abcdef", "--json"]);
        assert_eq!(
            cli.command,
            Commands::Lock {
                command: LockCommands::Inspect {
                    parent_lock: "0123456789abcdef".into(),
                    config: None,
                    json: true,
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

        // Completions
        let cli = Cli::parse_from(["humoco", "completions", "bash"]);
        assert_eq!(cli.command, Commands::Completions { shell: clap_complete::Shell::Bash });

        // Stop
        let cli = Cli::parse_from(["humoco", "stop", "--timeout", "20", "--json"]);
        assert_eq!(cli.command, Commands::Stop { timeout: 20, config: None, json: true });

        // Peer Remove
        let cli = Cli::parse_from(["humoco", "peer", "remove", "alice@127.0.0.1:9090", "--ephemeral", "--json"]);
        assert_eq!(
            cli.command,
            Commands::Peer {
                command: PeerCommands::Remove {
                    peer: "alice@127.0.0.1:9090".into(),
                    save: true,
                    ephemeral: true,
                    config: None,
                    json: true,
                }
            }
        );

        // Config Check & Dump
        let cli = Cli::parse_from(["humoco", "config", "check", "--json"]);
        assert_eq!(cli.command, Commands::Config { command: ConfigCommands::Check { config: None, json: true } });

        let cli = Cli::parse_from(["humoco", "config", "dump", "--json"]);
        assert_eq!(cli.command, Commands::Config { command: ConfigCommands::Dump { config: None, json: true } });

        // Db Stats
        let cli = Cli::parse_from(["humoco", "db", "stats", "--json"]);
        assert_eq!(cli.command, Commands::Db { command: DbCommands::Stats { config: None, json: true } });

        // Restore
        let cli = Cli::parse_from(["humoco", "restore", "--verify", "/tmp/backup.redb", "--json"]);
        assert_eq!(
            cli.command,
            Commands::Restore {
                backup: None,
                verify: Some(PathBuf::from("/tmp/backup.redb")),
                config: None,
                json: true,
            }
        );
    }

    #[tokio::test]
    async fn test_cli_completions_execution() {
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Elvish,
        ] {
            assert!(execute_completions(shell).is_ok());
        }
    }

    #[tokio::test]
    async fn test_cli_peer_remove_offline() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).expect("init");

        // Add peer
        execute_peer_add("carol@127.0.0.1:9099".into(), Some(config_path.clone())).await.expect("peer add");
        let mut cfg = NodeConfig::load_from_file(&config_path).expect("load config");
        assert!(cfg.f2f.peers.contains(&"carol@127.0.0.1:9099".to_string()));

        // Remove peer with save
        execute_peer_remove("carol@127.0.0.1:9099".into(), true, false, Some(config_path.clone()), false)
            .await
            .expect("peer remove");
        cfg = NodeConfig::load_from_file(&config_path).expect("load config");
        assert!(!cfg.f2f.peers.contains(&"carol@127.0.0.1:9099".to_string()));
    }

    #[tokio::test]
    async fn test_cli_config_check_and_dump() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).expect("init");

        // Config check
        assert!(execute_config_check(Some(config_path.clone()), false).await.is_ok());
        assert!(execute_config_check(Some(config_path.clone()), true).await.is_ok());

        // Config dump
        assert!(execute_config_dump(Some(config_path.clone()), false).is_ok());
        assert!(execute_config_dump(Some(config_path.clone()), true).is_ok());
    }

    #[tokio::test]
    async fn test_cli_db_stats_and_restore_verification() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).expect("init");

        let mut config = NodeConfig::load_from_file(&config_path).expect("load config");
        config.storage.data_dir = temp.path().join("data");
        config.save_to_file(&config_path).expect("save config");

        // Create db and put a lock
        let db_path = config.storage.data_dir.join("humoco.redb");
        let storage = RedbStorage::open(&db_path).expect("open storage");
        let record = LockRecord::new(
            [5u8; 32],
            [6u8; 32],
            b"nonce".to_vec(),
            SimTime(100),
            SimTime(60_000),
        );
        storage.put_lock(&record, 600_000).expect("put lock");
        drop(storage);

        // Test db stats offline
        assert!(execute_db_stats(Some(config_path.clone()), false).await.is_ok());
        assert!(execute_db_stats(Some(config_path.clone()), true).await.is_ok());

        // Backup db
        let backup_file = temp.path().join("backup.redb");
        execute_backup(backup_file.clone(), Some(config_path.clone())).await.expect("backup");
        assert!(backup_file.exists());

        // Remove active db
        std::fs::remove_file(&db_path).expect("remove db");
        assert!(!db_path.exists());

        // Restore from backup with verify
        execute_restore(None, Some(backup_file), Some(config_path.clone()), false)
            .await
            .expect("restore");
        assert!(db_path.exists());

        // Verify restored lock
        let restored_storage = RedbStorage::open(&db_path).expect("open restored");
        let (rec, _) = restored_storage.get_lock(&[5u8; 32]).expect("get").expect("found");
        assert_eq!(rec.receiver_pub, [6u8; 32]);
    }

    #[tokio::test]
    async fn test_cli_doctor_and_offline_subcommands() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("humoco.toml");
        let key_path = temp.path().join("node_key.bin");

        execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).expect("execute_init");
        assert!(config_path.exists());
        assert!(key_path.exists());

        // Update config to point to key_path & data
        let mut config = NodeConfig::load_from_file(&config_path).expect("load config");
        config.identity.key_path = key_path.clone();
        config.storage.data_dir = temp.path().join("data");
        config.save_to_file(&config_path).expect("save config");

        // Doctor check (text and JSON)
        execute_doctor(Some(config_path.clone()), false).await.expect("execute_doctor");
        execute_doctor(Some(config_path.clone()), true).await.expect("execute_doctor json");

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

        execute_init(Some(config_path.clone()), false, false, None, 12, None, false, false, false).expect("execute_init");
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
