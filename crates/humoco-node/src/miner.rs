//! Duty-Cycled Background Ticket Miner (Spec 07 / Phase 6).
//!
//! Autonomous, duty-cycled Argon2d shard routing ticket miner for `humoco-node`.
//! Monitors decentralized network median work and local PoW headroom, dynamically
//! stepping through Idle, Proactive, Urgent, and Emergency duty cycles to maintain
//! healthy shard routing authority while protecting MicroSD flash endurance and
//! bounding CPU consumption.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use rand::Rng;
use tokio_util::sync::CancellationToken;

use crate::config::MiningConfig;
use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::network::PeerManager;
use crate::storage::RedbStorage;

/// State machine governing mining intensity and duty-cycle sleep intervals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningState {
    /// Headroom $H > 20\%$. Node ticket is healthy; checks periodically without mining.
    Idle,
    /// $15\% < H \le 20\%$. Proactive early preparation before any urgency occurs.
    Proactive,
    /// $12.5\% \le H \le 15\%$. Headroom is nearing network admission boundary.
    Urgent,
    /// $H < 12.5\%$ or peer feedback flagged `FLAG_POW_OUTDATED`. Urgent ticket renewal required.
    Emergency,
}

/// Computes the target work score $W_{\text{target}}$:
/// $$W_{\text{target}} = \max\left( \lfloor 1.5 \times W_{\text{active}} \rfloor, \, \lceil (\text{target\_headroom\_pct} / 100.0) \times W_{\text{net\_median}} \rceil, \, W_{\text{min\_floor}} \right)$$
pub fn compute_target_work(
    active_work: u64,
    net_median: u64,
    target_headroom_pct: u32,
    min_floor: u64,
) -> u64 {
    let term1 = ((active_work as f64) * 1.5).floor() as u64;
    let term2 = (((target_headroom_pct as f64) / 100.0) * (net_median as f64)).ceil() as u64;
    term1.max(term2).max(min_floor)
}

/// Atomically persists the private node identity to disk using a temporary file,
/// POSIX 0600 mode, `fsync` (`sync_all()`), and atomic rename.
/// Protects against power cuts and partial writes.
pub fn save_identity_atomic(
    identity: &NodeIdentity,
    path: impl AsRef<Path>,
) -> Result<(), NodeError> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent).map_err(|err| NodeError::IoWithPath {
            path: parent.to_path_buf(),
            source: err,
        })?;
    }

    let key_bytes = identity.signing_key().to_bytes();
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&key_bytes);
    out.extend_from_slice(&identity.nonce().to_le_bytes());
    out.extend_from_slice(&identity.t0().to_le_bytes());
    out.extend_from_slice(identity.hrw_routing_id());

    let temp_name = format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|f| f.to_str()).unwrap_or("key"),
        rand::random::<u64>()
    );
    let temp_path = parent.join(temp_name);

    {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temp_path).map_err(|err| NodeError::IoWithPath {
            path: temp_path.clone(),
            source: err,
        })?;

        file.write_all(&out).map_err(|err| NodeError::IoWithPath {
            path: temp_path.clone(),
            source: err,
        })?;

        file.sync_all().map_err(|err| NodeError::IoWithPath {
            path: temp_path.clone(),
            source: err,
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&temp_path, path).map_err(|err| NodeError::IoWithPath {
        path: path.to_path_buf(),
        source: err,
    })?;

    Ok(())
}

/// Autonomous, duty-cycled background ticket miner.
pub struct BackgroundMiner {
    config: MiningConfig,
    key_path: PathBuf,
    peer_manager: Arc<PeerManager>,
    identity: Arc<RwLock<NodeIdentity>>,
    storage: Option<Arc<RedbStorage>>,
    is_simulation: bool,
    cancel_token: CancellationToken,
}

impl BackgroundMiner {
    pub fn new(
        config: MiningConfig,
        key_path: PathBuf,
        peer_manager: Arc<PeerManager>,
        identity: Arc<RwLock<NodeIdentity>>,
        storage: Option<Arc<RedbStorage>>,
        is_simulation: bool,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            key_path,
            peer_manager,
            identity,
            storage,
            is_simulation,
            cancel_token,
        }
    }

    /// Evaluates current mining state based on active ticket headroom and peer feedback.
    pub fn determine_state(
        &self,
        active_work: u64,
        net_median: u64,
        is_ticket_outdated: bool,
    ) -> MiningState {
        if is_ticket_outdated {
            return MiningState::Emergency;
        }
        if net_median == 0 {
            return MiningState::Idle;
        }
        let headroom_pct = (active_work as f64 / net_median as f64) * 100.0;
        if headroom_pct < 12.5 {
            MiningState::Emergency
        } else if headroom_pct <= self.config.urgent_headroom_pct as f64 {
            MiningState::Urgent
        } else if headroom_pct <= self.config.proactive_headroom_pct as f64 {
            MiningState::Proactive
        } else {
            MiningState::Idle
        }
    }

    /// Returns the duty-cycle sleep duration for a given state.
    pub fn sleep_duration_for_state(&self, state: MiningState) -> Duration {
        if self.is_simulation {
            match state {
                MiningState::Idle => Duration::from_millis(50),
                MiningState::Proactive | MiningState::Urgent | MiningState::Emergency => {
                    Duration::from_millis(2)
                }
            }
        } else {
            match state {
                MiningState::Idle => Duration::from_secs(self.config.check_interval_secs),
                MiningState::Proactive => Duration::from_millis(self.config.proactive_sleep_ms),
                MiningState::Urgent => Duration::from_millis(self.config.urgent_sleep_ms),
                MiningState::Emergency => Duration::from_millis(self.config.emergency_sleep_ms),
            }
        }
    }

    /// Spawns the background miner on the Tokio runtime.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }

    /// Executes the duty-cycled mining loop until cancellation.
    pub async fn run(&self) {
        if !self.config.enabled {
            tracing::info!("Duty-cycled background ticket miner is disabled in configuration.");
            return;
        }

        tracing::info!(
            proactive_headroom = self.config.proactive_headroom_pct,
            urgent_headroom = self.config.urgent_headroom_pct,
            target_headroom = self.config.target_headroom_pct,
            is_simulation = self.is_simulation,
            "Starting duty-cycled background ticket miner"
        );

        // Generate a random 64-bit starting nonce in RAM (Spec 07 / INV-0701)
        let mut nonce: u64 = rand::rngs::OsRng.gen::<u64>();
        if nonce == 0 {
            nonce = 1;
        }

        let mut current_t0 = 0u64;

        loop {
            if self.cancel_token.is_cancelled() {
                break;
            }

            let active_identity = self.identity.read().clone();
            let active_work = active_identity.work_score();
            let net_median = self.peer_manager.calculate_network_median_work();
            let is_outdated = self.peer_manager.is_ticket_outdated();

            let state = self.determine_state(active_work, net_median, is_outdated);

            match state {
                MiningState::Idle => {
                    current_t0 = 0;
                    let sleep_dur = self.sleep_duration_for_state(MiningState::Idle);
                    tokio::select! {
                        _ = self.cancel_token.cancelled() => break,
                        _ = tokio::time::sleep(sleep_dur) => continue,
                    }
                }
                MiningState::Proactive | MiningState::Urgent | MiningState::Emergency => {
                    let min_floor = self.peer_manager.effective_min_work_floor();
                    let target_work = compute_target_work(
                        active_work,
                        net_median,
                        self.config.target_headroom_pct,
                        min_floor,
                    );

                    if current_t0 == 0 {
                        let net_time_sec = self.peer_manager.net_time_ms() / 1000;
                        current_t0 = if net_time_sec > 0 {
                            net_time_sec
                        } else {
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(1)
                        };
                    }

                    let pubkey = *active_identity.node_pubkey();
                    let test_nonce = nonce;
                    let t0 = current_t0;

                    // Single-proof computation in blocking pool to prevent starvation of Tokio runtime
                    let proof_res = tokio::task::spawn_blocking(move || {
                        crate::identity::compute_pow_proof(&pubkey, test_nonce, t0)
                    })
                    .await;

                    let proof = match proof_res {
                        Ok(Ok(p)) => p,
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "compute_pow_proof returned error");
                            nonce = nonce.wrapping_add(1);
                            if nonce == 0 {
                                nonce = 1;
                            }
                            continue;
                        }
                        Err(_) => {
                            // Spawn blocking task was aborted or panicked
                            if self.cancel_token.is_cancelled() {
                                break;
                            }
                            continue;
                        }
                    };

                    let work = humoco_sim_core::crypto::compute_work_from_hash(&proof);
                    nonce = nonce.wrapping_add(1);
                    if nonce == 0 {
                        nonce = 1;
                    }

                    if work >= target_work {
                        // Success! Mined a new ticket meeting target work
                        let signing_key = active_identity.signing_key().clone();
                        let mined_identity = NodeIdentity::from_signing_key_with_pow(
                            signing_key,
                            test_nonce,
                            t0,
                        );
                        let new_hrw = *mined_identity.hrw_routing_id();

                        // Persist atomically to disk
                        if let Err(e) = save_identity_atomic(&mined_identity, &self.key_path) {
                            tracing::error!(
                                error = %e,
                                key_path = %self.key_path.display(),
                                "Failed to atomically persist freshly mined identity ticket to disk"
                            );
                        }

                        // Update in-memory NodeIdentity
                        *self.identity.write() = mined_identity;

                        // Resolve local address or fallback
                        let local_addr = self
                            .peer_manager
                            .get_known_node_info(&pubkey)
                            .await
                            .map(|info| info.addr)
                            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

                        // Update peer_manager ticket and reset outdated flag
                        self.peer_manager
                            .update_routing_ticket_with_work(pubkey, new_hrw, local_addr, work)
                            .await;
                        self.peer_manager
                            .seed_local_ticket_age(pubkey, new_hrw, Duration::ZERO);
                        self.peer_manager.set_ticket_outdated(false);

                        if let Some(storage) = &self.storage {
                            let now_ms = self.peer_manager.net_time_ms();
                            let _ = storage.record_ticket_observations_if_absent(&[(
                                pubkey, new_hrw, now_ms,
                            )]);
                        }

                        tracing::info!(
                            work,
                            nonce = test_nonce,
                            target = target_work,
                            "Mined new Argon2d shard routing ticket successfully"
                        );

                        // Return to Idle
                        current_t0 = 0;
                        continue;
                    }

                    // Did not meet target on this single proof attempt; sleep cooperatively
                    let sleep_dur = self.sleep_duration_for_state(state);
                    tokio::select! {
                        _ = self.cancel_token.cancelled() => break,
                        _ = tokio::time::sleep(sleep_dur) => continue,
                    }
                }
            }
        }

        tracing::info!("Duty-cycled background ticket miner stopped.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_target_work_calculation() {
        // Case 1: active_work = 100, net_median = 1000, target_headroom = 50, floor = 256
        // term1 = floor(100 * 1.5) = 150
        // term2 = ceil(50% * 1000) = 500
        // min_floor = 256
        // target = max(150, 500, 256) = 500
        assert_eq!(compute_target_work(100, 1000, 50, 256), 500);

        // Case 2: active_work = 400, net_median = 500, target_headroom = 50, floor = 256
        // term1 = floor(400 * 1.5) = 600
        // term2 = ceil(0.5 * 500) = 250
        // target = max(600, 250, 256) = 600
        assert_eq!(compute_target_work(400, 500, 50, 256), 600);

        // Case 3: active_work = 0, net_median = 0, target_headroom = 50, floor = 256
        // target = 256
        assert_eq!(compute_target_work(0, 0, 50, 256), 256);

        // Case 4: Simulation mode, floor = 1
        // active_work = 1, net_median = 10, target_headroom = 50, floor = 1
        // term1 = 1, term2 = 5, floor = 1 -> target = 5
        assert_eq!(compute_target_work(1, 10, 50, 1), 5);

        // Case 5: Odd ceiling division check
        // active_work = 0, net_median = 101, target_headroom = 50, floor = 1
        // term2 = ceil(50.5) = 51
        assert_eq!(compute_target_work(0, 101, 50, 1), 51);
    }

    #[test]
    fn test_state_machine_transitions() {
        let config = MiningConfig {
            enabled: true,
            proactive_headroom_pct: 20,
            urgent_headroom_pct: 15,
            target_headroom_pct: 50,
            proactive_sleep_ms: 2000,
            urgent_sleep_ms: 500,
            emergency_sleep_ms: 50,
            check_interval_secs: 60,
        };

        let temp = tempdir().unwrap();
        let key_path = temp.path().join("key.bin");
        let id = NodeIdentity::generate();
        let identity = Arc::new(RwLock::new(id));
        let pm = Arc::new(PeerManager::new(vec![]));
        let cancel = CancellationToken::new();

        let miner = BackgroundMiner::new(
            config,
            key_path,
            pm,
            identity,
            None,
            false,
            cancel,
        );

        // Median = 100
        let median = 100u64;

        // Idle: H = 25% > 20%
        assert_eq!(miner.determine_state(25, median, false), MiningState::Idle);

        // Proactive: 15% < H <= 20% (e.g. 20%, 18%)
        assert_eq!(miner.determine_state(20, median, false), MiningState::Proactive);
        assert_eq!(miner.determine_state(18, median, false), MiningState::Proactive);

        // Urgent: 12.5% <= H <= 15% (e.g. 15%, 13%)
        assert_eq!(miner.determine_state(15, median, false), MiningState::Urgent);
        assert_eq!(miner.determine_state(13, median, false), MiningState::Urgent);

        // Emergency: H < 12.5% (e.g. 12%, 5%, 0%)
        assert_eq!(miner.determine_state(12, median, false), MiningState::Emergency);
        assert_eq!(miner.determine_state(0, median, false), MiningState::Emergency);

        // Emergency override: FLAG_POW_OUTDATED even if work is high
        assert_eq!(miner.determine_state(100, median, true), MiningState::Emergency);

        // Median == 0 (bootstrap) -> Idle
        assert_eq!(miner.determine_state(0, 0, false), MiningState::Idle);
    }

    #[test]
    fn test_sleep_durations() {
        let config = MiningConfig::default();
        let temp = tempdir().unwrap();
        let key_path = temp.path().join("key.bin");
        let id = NodeIdentity::generate();
        let identity = Arc::new(RwLock::new(id));
        let pm = Arc::new(PeerManager::new(vec![]));

        // Production mode sleeps
        let prod_miner = BackgroundMiner::new(
            config.clone(),
            key_path.clone(),
            pm.clone(),
            identity.clone(),
            None,
            false,
            CancellationToken::new(),
        );
        assert_eq!(prod_miner.sleep_duration_for_state(MiningState::Idle), Duration::from_secs(60));
        assert_eq!(prod_miner.sleep_duration_for_state(MiningState::Proactive), Duration::from_millis(2000));
        assert_eq!(prod_miner.sleep_duration_for_state(MiningState::Urgent), Duration::from_millis(500));
        assert_eq!(prod_miner.sleep_duration_for_state(MiningState::Emergency), Duration::from_millis(50));

        // Simulation mode sleeps
        let sim_miner = BackgroundMiner::new(
            config,
            key_path,
            pm,
            identity,
            None,
            true,
            CancellationToken::new(),
        );
        assert_eq!(sim_miner.sleep_duration_for_state(MiningState::Idle), Duration::from_millis(50));
        assert_eq!(sim_miner.sleep_duration_for_state(MiningState::Proactive), Duration::from_millis(2));
        assert_eq!(sim_miner.sleep_duration_for_state(MiningState::Urgent), Duration::from_millis(2));
        assert_eq!(sim_miner.sleep_duration_for_state(MiningState::Emergency), Duration::from_millis(2));
    }

    #[test]
    fn test_atomic_save_and_reload() {
        let temp = tempdir().unwrap();
        let key_path = temp.path().join("sub/dir/test_key.bin");
        let identity = NodeIdentity::generate();

        save_identity_atomic(&identity, &key_path).expect("Atomic save");
        assert!(key_path.exists());

        let loaded = NodeIdentity::load_from_file(&key_path).expect("Load from file");
        assert_eq!(identity.node_pubkey(), loaded.node_pubkey());
        assert_eq!(identity.nonce(), loaded.nonce());
        assert_eq!(identity.t0(), loaded.t0());
        assert_eq!(identity.hrw_routing_id(), loaded.hrw_routing_id());
    }

    #[tokio::test]
    async fn test_simulation_mode_quick_mining() {
        let temp = tempdir().unwrap();
        let key_path = temp.path().join("sim_node_key.bin");
        let initial_id = NodeIdentity::generate();
        initial_id.save_to_file(&key_path).unwrap();

        let identity = Arc::new(RwLock::new(initial_id.clone()));
        let pm = Arc::new(PeerManager::new(vec![]));
        pm.set_simulation_mode(true);

        // Learn a few nodes so network median is 1 (simulation mode floor = 1)
        for i in 1..=5 {
            let mut pk = [0xEE; 32];
            pk[0] = i as u8;
            let addr: SocketAddr = format!("127.0.0.1:{}", 9800 + i).parse().unwrap();
            pm.learn_node_from_gossip_with_hrw_and_work(pk, pk, addr, 0, None, 1).await;
            pm.set_first_seen_for_test(
                &pk,
                std::time::Instant::now() - Duration::from_secs(25 * 3600),
            )
            .await;
        }

        // Mark local ticket outdated to trigger Emergency mining
        pm.set_ticket_outdated(true);
        assert!(pm.is_ticket_outdated());

        let config = MiningConfig {
            target_headroom_pct: 50,
            ..Default::default()
        };

        let cancel = CancellationToken::new();
        let miner = BackgroundMiner::new(
            config,
            key_path.clone(),
            pm.clone(),
            identity.clone(),
            None,
            true, // is_simulation
            cancel.clone(),
        );

        let handle = miner.spawn();

        // Wait for mining to complete (in simulation mode, work >= 1 takes only 1-3 iterations)
        let mut mined_work = 0u64;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let current = identity.read().clone();
            if current.has_valid_pow_ticket() {
                mined_work = current.work_score();
                break;
            }
        }

        cancel.cancel();
        let _ = handle.await;

        assert!(mined_work >= 1, "Miner must find a ticket with work >= 1 in simulation mode");
        assert!(!pm.is_ticket_outdated(), "Ticket outdated flag must be cleared upon mining success");

        // Key on disk must have been updated with the mined ticket
        let reloaded = NodeIdentity::load_from_file(&key_path).unwrap();
        assert_eq!(reloaded.work_score(), mined_work);
        assert_eq!(reloaded.node_pubkey(), initial_id.node_pubkey());
        assert_ne!(reloaded.nonce(), 0);
    }
}
