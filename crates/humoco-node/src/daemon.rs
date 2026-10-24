use humoco_sim_core::types::SimTime;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::identity::NodeIdentity;
use ed25519_dalek::Signer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundAddrs {
    pub rpc_addr: SocketAddr,
    pub p2p_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardStatus {
    Uninitialized,
    Syncing,
    Ready,
}

const MAX_ACTIVE_SHARD_SYNCS: usize = 32;

/// Readiness is scoped to a shard, never inferred from a successful TCP/QUIC transfer.
/// One state lock avoids lock-order inversions between request and completion.
pub struct ShardReadinessManager {
    shard_states: std::sync::Mutex<std::collections::HashMap<u16, ShardStatus>>,
    sync_tx: tokio::sync::mpsc::Sender<u16>,
    sync_rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<u16>>>,
    storage_healthy: std::sync::atomic::AtomicBool,
    cancel: CancellationToken,
    sync_bytes: Arc<tokio::sync::Semaphore>,
    sync_entries: Arc<tokio::sync::Semaphore>,
}

impl ShardReadinessManager {
    pub fn new() -> Self {
        Self::with_cancel_token(CancellationToken::new())
    }

    pub fn with_cancel_token(cancel: CancellationToken) -> Self {
        let (sync_tx, sync_rx) = tokio::sync::mpsc::channel(MAX_ACTIVE_SHARD_SYNCS);
        Self {
            shard_states: std::sync::Mutex::new(std::collections::HashMap::new()),
            sync_tx,
            sync_rx: std::sync::Mutex::new(Some(sync_rx)),
            storage_healthy: std::sync::atomic::AtomicBool::new(true),
            cancel,
            sync_bytes: Arc::new(tokio::sync::Semaphore::new(8 * 1024 * 1024)),
            sync_entries: Arc::new(tokio::sync::Semaphore::new(10_000)),
        }
    }

    pub fn is_shard_ready(&self, shard_id: u16) -> bool {
        !self.cancel.is_cancelled()
            && self
                .storage_healthy
                .load(std::sync::atomic::Ordering::Acquire)
            && self
                .shard_states
                .lock()
                .map(|s| matches!(s.get(&shard_id), Some(ShardStatus::Ready)))
                .unwrap_or(false)
    }

    /// Admission is nonblocking, bounded across distinct shards and deduplicated.
    pub fn request_sync(&self, shard_id: u16) -> bool {
        if self.cancel.is_cancelled()
            || !self
                .storage_healthy
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Ok(mut states) = self.shard_states.lock() else {
            return false;
        };
        if matches!(
            states.get(&shard_id),
            Some(ShardStatus::Syncing | ShardStatus::Ready)
        ) || states
            .values()
            .filter(|s| **s == ShardStatus::Syncing)
            .count()
            >= MAX_ACTIVE_SHARD_SYNCS
        {
            return false;
        }
        if self.sync_tx.try_send(shard_id).is_err() {
            return false;
        }
        states.insert(shard_id, ShardStatus::Syncing);
        true
    }

    pub fn try_trigger_demand_sync(&self, shard_id: u16) -> bool {
        self.request_sync(shard_id)
    }

    fn take_sync_receiver(&self) -> Option<tokio::sync::mpsc::Receiver<u16>> {
        self.sync_rx.lock().ok()?.take()
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn set_storage_healthy(&self, healthy: bool) {
        self.storage_healthy
            .store(healthy, std::sync::atomic::Ordering::Release);
        if !healthy {
            if let Ok(mut states) = self.shard_states.lock() {
                states.clear();
            }
        }
    }

    pub fn invalidate_shard(&self, shard_id: u16) {
        if let Ok(mut states) = self.shard_states.lock() {
            states.remove(&shard_id);
        }
    }

    pub fn mark_shard_ready(&self, shard_id: u16) {
        if self.cancel.is_cancelled()
            || !self
                .storage_healthy
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        if let Ok(mut states) = self.shard_states.lock() {
            states.insert(shard_id, ShardStatus::Ready);
        }
    }

    pub fn mark_sync_failed(&self, shard_id: u16) {
        if let Ok(mut states) = self.shard_states.lock() {
            states.remove(&shard_id);
        }
    }
}

impl Default for ShardReadinessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Owns cancellation and task registrations even if startup returns before the
/// normal teardown block. No database handle or listener outlives a clean exit.
#[derive(Default)]
struct RunCleanup {
    producers: parking_lot::Mutex<Vec<tokio::task::AbortHandle>>,
    transports: parking_lot::Mutex<Vec<crate::network::QuicTransport>>,
    flush: parking_lot::Mutex<Option<(CancellationToken, tokio::task::AbortHandle)>>,
    quota_failed: parking_lot::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
    recovery_work: parking_lot::Mutex<Option<tokio_util::task::TaskTracker>>,
}

impl RunCleanup {
    fn producer<T>(&self, handle: &tokio::task::JoinHandle<T>) {
        self.producers.lock().push(handle.abort_handle());
    }

    async fn finish(&self) -> bool {
        let transports = std::mem::take(&mut *self.transports.lock());
        for transport in &transports {
            transport.close();
        }
        for transport in &transports {
            transport.drain_tasks().await;
        }
        // Drop handler-owned TierController senders before awaiting its FIFO worker.
        drop(transports);
        // Producers may still be completing an acknowledged request. Persistence
        // stays alive until every producer has actually released its resources.
        let producers = self.producers.lock().clone();
        while producers.iter().any(|handle| !handle.is_finished()) {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let recovery_work = self.recovery_work.lock().clone();
        if let Some(work) = recovery_work { work.close(); work.wait().await; }
        let flush = self.flush.lock().clone();
        if let Some((cancel, handle)) = flush {
            cancel.cancel();
            while !handle.is_finished() {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        }
        self.transports.lock().clear();
        self.producers.lock().clear();
        self.flush.lock().take();
        !self
            .quota_failed
            .lock()
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
    }

    fn abort_producers(&self) {
        for transport in self.transports.lock().iter() {
            transport.close();
        }
        for producer in self.producers.lock().iter() {
            producer.abort();
        }
    }
}

pub struct NodeDaemon {
    config: NodeConfig,
    identity: NodeIdentity,
    bootstrap_new_region: bool,
    cancel_token: CancellationToken,
    bound_addr_tx: Mutex<Option<tokio::sync::oneshot::Sender<BoundAddrs>>>,
}

impl NodeDaemon {
    /// Creates a new NodeDaemon instance with a fresh CancellationToken.
    pub fn new(config: NodeConfig, identity: NodeIdentity) -> Self {
        Self {
            config,
            identity,
            bootstrap_new_region: false,
            cancel_token: CancellationToken::new(),
            bound_addr_tx: Mutex::new(None),
        }
    }

    /// Creates a new NodeDaemon instance with an existing CancellationToken.
    pub fn with_cancel_token(
        config: NodeConfig,
        identity: NodeIdentity,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            identity,
            bootstrap_new_region: false,
            cancel_token,
            bound_addr_tx: Mutex::new(None),
        }
    }

    /// Creates a new NodeDaemon instance with cancellation token and bound address notification channel.
    pub fn with_bound_sender(
        config: NodeConfig,
        identity: NodeIdentity,
        cancel_token: CancellationToken,
        tx: tokio::sync::oneshot::Sender<BoundAddrs>,
    ) -> Self {
        Self {
            config,
            identity,
            bootstrap_new_region: false,
            cancel_token,
            bound_addr_tx: Mutex::new(Some(tx)),
        }
    }

    /// Explicit operator authorization to establish a new, empty regional registry.
    /// This never persists readiness: every subsequent normal boot starts closed.
    pub fn bootstrap_new_region(mut self) -> Self {
        self.bootstrap_new_region = true;
        self
    }

    /// Sets the oneshot channel sender for bound address notification.
    pub fn set_bound_sender(&self, tx: tokio::sync::oneshot::Sender<BoundAddrs>) {
        if let Ok(mut lock) = self.bound_addr_tx.try_lock() {
            *lock = Some(tx);
        }
    }

    /// Returns a reference to the active configuration.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns a reference to the node identity.
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// Returns a clone of the cancellation token.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Runs the node daemon, initializing subsystems and waiting for shutdown signal.
    pub async fn run(&self) -> Result<(), NodeError> {
        self.config.validate_network_boundaries()?;
        let lifecycle = Arc::new(crate::control::lifecycle::ShutdownLifecycle::new(
            &self.config.control_socket_path(),
        )?);
        let cleanup = Arc::new(RunCleanup::default());
        let timeout = std::time::Duration::from_secs(self.config.network.shutdown_timeout_secs);
        let mut stop_deadline = None;
        let mut result = {
            let run = self.run_inner(lifecycle.clone(), cleanup.clone());
            tokio::pin!(run);
            tokio::select! {
                result = &mut run => result,
                _ = self.cancel_token.cancelled() => {
                    let deadline = tokio::time::Instant::now() + timeout;
                    stop_deadline = Some(deadline);
                    tokio::time::timeout_at(deadline, &mut run).await
                        .unwrap_or_else(|_| Err(NodeError::Daemon("internal shutdown deadline exceeded; teardown incomplete".into())))
                }
            }
        }; // Drop the startup/run future before waiting for its registered tasks.
        self.cancel_token.cancel();
        let deadline = stop_deadline.unwrap_or_else(|| tokio::time::Instant::now() + timeout);
        let completion = tokio::time::timeout_at(deadline, cleanup.finish()).await;
        if matches!(completion, Ok(false)) {
            result = Err(NodeError::Daemon(
                "VIP quota persistence failed during run or drain".into(),
            ));
        }
        if completion.is_err() {
            cleanup.abort_producers();
            // A blocking filesystem operation cannot be killed or reported as
            // drained. Finish the ordered cleanup asynchronously, while the
            // caller receives an honest bounded incomplete result.
            let remaining_cleanup = cleanup.clone();
            tokio::spawn(async move {
                remaining_cleanup.finish().await;
            });
            result = Err(NodeError::Daemon(
                "internal shutdown deadline exceeded; resources may still be draining".into(),
            ));
        }
        lifecycle.complete(result.is_ok())?;
        result
    }

    async fn run_inner(
        &self,
        lifecycle: Arc<crate::control::lifecycle::ShutdownLifecycle>,
        cleanup: Arc<RunCleanup>,
    ) -> Result<(), NodeError> {
        info!(
            node_id = %self.identity.node_id_hex(),
            public_key = %self.identity.public_key_hex(),
            p2p_addr = %self.config.network.p2p_listen_addr,
            rpc_addr = %self.config.network.rpc_listen_addr,
            data_dir = %self.config.storage.data_dir.display(),
            peers_count = self.config.f2f.peers.len(),
            "Starting HuMoCo Layer-2 node daemon"
        );

        // Ensure data storage directory exists
        if !self.config.storage.data_dir.exists() {
            info!(
                path = %self.config.storage.data_dir.display(),
                "Creating node data directory"
            );
            std::fs::create_dir_all(&self.config.storage.data_dir).map_err(|err| {
                NodeError::IoWithPath {
                    path: self.config.storage.data_dir.clone(),
                    source: err,
                }
            })?;
        }

        info!("Core subsystems initialized successfully. Initializing storage and persistence engine...");

        // Initialize RedbStorage and DualTierEngine
        let db_path = self.config.storage.data_dir.join("humoco.redb");
        if self.bootstrap_new_region {
            // Empty storage cannot prove absence of earlier history (DEC-057).
            // Only explicit operator sovereignty establishes a NEW regional root.
            // A durable one-shot marker also makes interrupted bootstrap fail closed.
            if db_path.exists() {
                return Err(NodeError::Daemon("new-region bootstrap refuses an existing database".into()));
            }
            let marker = self.config.storage.data_dir.join("region-bootstrap-used");
            let reservation = std::fs::OpenOptions::new().write(true).create_new(true)
                .open(&marker).map_err(|source| NodeError::IoWithPath { path: marker, source })?;
            reservation.sync_all()?;
            std::fs::File::open(&self.config.storage.data_dir)?.sync_all()?;
        }
        let storage = std::sync::Arc::new(if self.bootstrap_new_region {
            // create_new owns the file atomically: a concurrent ordinary opener
            // cannot turn an existing populated registry into an empty bootstrap.
            crate::storage::RedbStorage::create_new_region(&db_path)?
        } else {
            crate::storage::RedbStorage::open(&db_path)?
        });
        // Decouple flush worker cancellation from master daemon cancellation so that
        // HTTP/QUIC listeners can finish in-flight requests before the flush worker drains.
        let flush_cancel_token = tokio_util::sync::CancellationToken::new();
        let (engine, flush_handle) = crate::storage::DualTierEngine::new_with_token(
            storage.clone(),
            flush_cancel_token.clone(),
        );
        *cleanup.flush.lock() = Some((flush_cancel_token.clone(), flush_handle.abort_handle()));
        *cleanup.recovery_work.lock() = Some(engine.recovery_work.clone());
        // Cold-boot recovery: Load all records into RAM index without premature pruning.
        // Unverified host SystemTime must not be trusted before P2P median synchronization (Spec 07 / INV-1203).
        engine
            .recover_from_disk(humoco_sim_core::types::SimTime(0))
            .await?;

        // Initialize PoW Engine and 3-Tier Access Controller
        let pow_engine =
            std::sync::Arc::new(crate::ingress::PowEngine::new(*self.identity.node_id(), 8));
        let tier_controller = std::sync::Arc::new(crate::ingress::TierController::new(
            storage.clone(),
            pow_engine.clone(),
        ));
        cleanup
            .producers
            .lock()
            .push(tier_controller.quota_worker_abort_handle());
        *cleanup.quota_failed.lock() = Some(tier_controller.quota_worker_failure_handle());
        for peer in &self.config.f2f.peers {
            tier_controller.register_f2f_peer(peer);
        }
        for token in &self.config.f2f.tokens {
            tier_controller.register_f2f_peer(token);
        }

        // Initialize QUIC P2P PeerManager with F2F friends, resolved endpoints, and known peers
        let (configured_entries, trusted_pubkeys) = self.config.f2f.parse_peers();
        let configured_peers =
            crate::config::F2fConfig::resolve_peer_endpoints(&configured_entries).await;
        let initial_sync_ready = self.bootstrap_new_region;
        let dns_peers: Vec<crate::config::PeerConfigEntry> = configured_entries
            .into_iter()
            .filter(|e| e.is_hostname())
            .collect();
        let peer_manager = std::sync::Arc::new(crate::network::PeerManager::with_f2f_and_dns(
            configured_peers,
            trusted_pubkeys,
            dns_peers,
        ));

        // Phase 8 (Spec 10/19): load persisted permanent bans from redb
        // directly into the PeerManager at boot so equivocation offenders stay
        // banned across restarts (First-Party Evidence, no hearsay re-learning).
        match storage.all_banned_nodes() {
            Ok(banned) => {
                if !banned.is_empty() {
                    let added = peer_manager.import_persisted_bans(&banned).await;
                    info!(
                        persisted = banned.len(),
                        imported = added,
                        "Loaded persisted permanent bans into PeerManager"
                    );
                }
            }
            Err(err) => {
                warn!(error = %err, "Failed to load persisted bans from redb; starting with empty ban set");
            }
        }

        // Wire PeerManager to DualTierEngine and PowEngine for consensus time and ban propagation (Spec 07 / Phase 6)
        engine.set_peer_manager(peer_manager.clone()).await;
        pow_engine.set_clock(peer_manager.clock().clone());
        // Phase 9 P1 (Spec 08): mirror initial sync-readiness into PeerManager so the
        // Provisional -> Final transition stays strictly coupled to Sync-Readiness.
        peer_manager.set_local_sync_ready(initial_sync_ready);

        // Background DNS / DynDNS peer re-resolution task (every 10 minutes)
        let dns_pm = peer_manager.clone();
        let dns_cancel = self.cancel_token.clone();
        let dns_re_resolve_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // Initial tick already resolved at boot
            loop {
                tokio::select! {
                    _ = dns_cancel.cancelled() => {
                        info!("DNS re-resolution ticker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        dns_pm.check_and_resolve_dns_peers().await;
                    }
                }
            }
        });
        cleanup.producer(&dns_re_resolve_handle);

        // Background hourly malus decay ticker (Spec 19: Autonome Peer-Heilung)
        let decay_pm = peer_manager.clone();
        let decay_token = self.cancel_token.clone();
        let malus_decay_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = decay_token.cancelled() => break,
                    _ = interval.tick() => {
                        decay_pm.decay_all_peers().await;
                    }
                }
            }
        });
        cleanup.producer(&malus_decay_handle);

        info!("Initializing QUIC P2P transport...");

        let is_sync_ready =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(initial_sync_ready));
        let readiness_manager = std::sync::Arc::new(ShardReadinessManager::with_cancel_token(
            self.cancel_token.clone(),
        ));

        if self.bootstrap_new_region {
            for shard in 0..=u16::MAX {
                readiness_manager.mark_shard_ready(shard);
            }
        }

        let handler = std::sync::Arc::new(
            crate::network::NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                self.identity.clone(),
                peer_manager.clone(),
            )
            .with_tier_controller(tier_controller.clone())
            .with_sync_ready(is_sync_ready.clone())
            .with_readiness_manager(readiness_manager.clone())
            .with_network_id(self.config.network.network_id)
            .with_gateway_urls(self.config.discovery.public_gateway_urls.clone()),
        );
        let mut transport = crate::network::QuicTransport::bind_with_options_for_network(
            self.config.network.p2p_listen_addr,
            &self.identity,
            peer_manager.clone(),
            handler,
            self.cancel_token.clone(),
            self.config.network.network_id,
        )?;
        transport.set_sync_ready_handle(is_sync_ready.clone());
        transport.set_sync_ready(initial_sync_ready);

        let p2p_bound_addr = transport.local_addr()?;
        cleanup.transports.lock().push(transport.clone());
        let accept_handle = transport.spawn_accept_loop();
        cleanup.producer(&accept_handle);
        info!(
            bound_addr = ?p2p_bound_addr,
            "QUIC P2P transport running."
        );

        // --- Phase 3 Autonomous Background Motors ---
        let is_simulation = self.config.network.simulation_mode
            || self.config.network.fast_ticker_interval_secs.is_some();

        // Phase 9 P1 (Spec 08/09): autonomous thermometer day roll-over + merge-reseed monitor.
        // - Thermometer: `advance_epoch_day()` rotates the 28-day slotted ring buffer on day change.
        // - Merge: abrupt growth (N_new >= 2*N_old or ΔN >= 20, INV-0908) triggers
        //   `fast_reseed_on_merge()` with the fresh global median to prevent quota collapse,
        //   plus a 24h quota moratorium via `PeerManager::note_merge_detected()`.
        // - Phase transition coupling: mirrors shard-sync readiness into PeerManager so
        //   `is_network_stable_ge20_for_24h()` stays gated on mature + presence-fresh + synced state.
        let thermo_tc = tier_controller.clone();
        let thermo_pm = peer_manager.clone();
        let thermo_cancel = self.cancel_token.clone();
        let thermo_sync_flag = is_sync_ready.clone();
        let thermo_interval_secs = if is_simulation { 5 } else { 60 };
        let thermometer_handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(thermo_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            let mut prev_total = thermo_pm.total_network_size().await;
            loop {
                tokio::select! {
                    _ = thermo_cancel.cancelled() => {
                        info!("Thermometer / merge-monitor ticker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let now_ms = thermo_pm.net_time_ms();
                        // Mirror sync-readiness for the Provisional -> Final gate.
                        thermo_pm.set_local_sync_ready(
                            thermo_sync_flag.load(std::sync::atomic::Ordering::SeqCst),
                        );
                        // 1. Daily roll-over of the 28-day ring buffer.
                        if let Some(new_day) = thermo_tc.advance_epoch_day(now_ms) {
                            debug!(new_day, "Network thermometer day rotated into 28-day ring buffer");
                        }
                        // 2. Partition-merge detection on total (incl. immature) size.
                        let cur_total = thermo_pm.total_network_size().await;
                        if crate::network::PeerManager::is_merge_jump(prev_total, cur_total) {
                            let now_sec = now_ms / 1000;
                            let (write_median, _read_median) =
                                thermo_pm.effective_network_medians(now_sec).await;
                            thermo_tc.fast_reseed_on_merge(write_median);
                            thermo_pm.note_merge_detected(now_ms);
                            info!(
                                prev_total,
                                cur_total,
                                write_median,
                                "Partition merge detected: thermometer fast-reseeded, 24h quota moratorium armed"
                            );
                        }
                        prev_total = cur_total;
                    }
                }
            }
        });
        cleanup.producer(&thermometer_handle);

        // 1. F2F Heartbeat-Emitter (hourly with jitter, signed payload)
        let hb_pm = peer_manager.clone();
        let hb_transport = transport.clone();
        let hb_identity = self.identity.clone();
        let hb_cancel = self.cancel_token.clone();
        let hb_local_addr = p2p_bound_addr;
        let hb_sim_mode = is_simulation;
        let hb_tc = tier_controller.clone();
        let heartbeat_handle = tokio::spawn(async move {
            let mut seq: u64 = 0;
            loop {
                let sleep_secs = if hb_sim_mode {
                    rand::thread_rng().gen_range(4..=6)
                } else {
                    crate::network::PeerManager::heartbeat_jitter_secs()
                };
                let sleep_dur = std::time::Duration::from_secs(sleep_secs);
                tokio::select! {
                    _ = hb_cancel.cancelled() => {
                        info!("F2F heartbeat emitter shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(sleep_dur) => {
                        let peers = hb_pm.f2f_peer_addrs().await;
                        if peers.is_empty() {
                            debug!("Heartbeat tick: no F2F friends configured");
                            continue;
                        }
                        let node_id = *hb_identity.node_pubkey();
                        let declared_write_ema = hb_tc.current_write_ema_micro_bj();
                        let declared_read_ema = hb_tc.current_read_ema_credits();
                        let now_ms = hb_pm.net_time_ms();
                        // Epoch-bound envelope (Phase 1 P0); heartbeat carries no
                        // lock epoch state so it binds epoch (0, 0).
                        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
                            &node_id,
                            0,
                            0,
                            now_ms,
                            declared_write_ema,
                            declared_read_ema,
                            0,
                            false,
                            &[0u8; 32],
                        );
                        let signature = hb_identity.signing_key().sign(&digest).to_bytes();
                        let piggyback = hb_pm.sample_piggyback_evidences(2).await;

                        for peer_addr in peers {
                            if hb_cancel.is_cancelled() { break; }
                            seq = seq.wrapping_add(1);
                            match hb_transport.send_heartbeat_to(
                                peer_addr,
                                node_id,
                                hb_local_addr,
                                seq,
                                declared_write_ema,
                                declared_read_ema,
                                signature,
                                now_ms,
                                piggyback.clone(),
                            ).await {
                                Ok(()) => {
                                    debug!(peer=%peer_addr, seq, "F2F heartbeat sent");
                                }
                                Err(e) => {
                                    debug!(peer=%peer_addr, error=%e, "Heartbeat send failed");
                                }
                            }
                        }
                    }
                }
            }
        });
        cleanup.producer(&heartbeat_handle);

        // 2. TTL-Pruning-Ticker (every 30 seconds, Zero State Bloat, Spec 11: net_time_ms)
        let prune_engine = engine.clone();
        let prune_cancel = self.cancel_token.clone();
        let prune_pm = peer_manager.clone();
        let prune_interval_secs = if is_simulation { 2 } else { 30 };
        let ttl_prune_handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(prune_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            // # Architectural Invariant (A03): Cold-Boot Pruning Clock Anchor
            // Initialize anchor immediately to current net time so first tick cannot suffer
            // from uninspected NTP forward jumps without F2F consensus (Spec 07 / INV-1203).
            let mut last_prune_anchor = prune_pm.net_time_ms();
            prune_engine
                .last_prune_anchor
                .store(last_prune_anchor, std::sync::atomic::Ordering::Relaxed);

            loop {
                tokio::select! {
                    _ = prune_cancel.cancelled() => {
                        info!("TTL pruning ticker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        // Cold-start & sync barrier: if boot sync is still pending and the local clock
                        // has not received enough F2F median samples, defer destructive pruning.
                        if !prune_pm.is_local_sync_ready() && !prune_pm.clock().is_time_corroborated(0) {
                            debug!("TTL pruning ticker: deferred during boot sync / uncorroborated clock");
                            continue;
                        }

                        let now_ms = prune_pm.net_time_ms();
                        // Inspect time drift BEFORE mutating the pruning anchor (Spec 07 / INV-1203)
                        if last_prune_anchor > 0 {
                            let jump = now_ms.saturating_sub(last_prune_anchor);
                            if jump > 86_400_000 && !prune_pm.clock().is_time_corroborated(jump) {
                                warn!(
                                    now_ms,
                                    last_prune_anchor,
                                    jump_ms = jump,
                                    "TTL pruning ticker: forward clock jump >24h rejected without F2F consensus (local clock jump protection)"
                                );
                                continue;
                            }
                        }
                        match prune_engine.prune_expired(SimTime(now_ms)).await {
                            Ok(pruned) => {
                                last_prune_anchor = now_ms;
                                if pruned > 0 {
                                    info!(pruned, now_ms, "TTL pruning evicted expired locks");
                                }
                            }
                            Err(e) => {
                                warn!(error=%e, "TTL pruning failed");
                            }
                        }
                    }
                }
            }
        });
        cleanup.producer(&ttl_prune_handle);

        // 3.5 Operator alerts (Telegram & webhook) with 15-minute hysteresis and interval
        let alert_config = self.config.alerts.clone();
        let alert_data_dir = self.config.storage.data_dir.clone();
        let alert_pm = peer_manager.clone();
        let alert_cancel = self.cancel_token.clone();
        let alert_lifecycle = self.config.lifecycle.clone();
        let alert_handle = tokio::spawn(async move {
            // 15-minute startup hysteresis
            tokio::select! {
                _ = alert_cancel.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(15 * 60)) => {}
            }
            if alert_cancel.is_cancelled() {
                return;
            }
            let dispatcher = crate::alert::AlertDispatcher::new(alert_config, alert_data_dir);
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15 * 60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // First tick after hysteresis is immediate; subsequent every 15 min
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = alert_cancel.cancelled() => {
                        info!("Alert check loop shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        // F2F peer check for outdated version
                        let total_peers = alert_pm.list_peers().await.len();
                        // Heuristic: assume all known peers are upgraded candidates.
                        // Real version comparison can be added when peer versions are gossiped.
                        let upgraded_peers = total_peers;
                        dispatcher.check_and_alert_outdated(total_peers, upgraded_peers).await;

                        // Sunset warning check
                        if let Some(warn_after) = alert_lifecycle.warn_deprecated_suite_after {
                            let now_secs = alert_pm.net_time_ms() / 1000;
                            if now_secs >= warn_after {
                                let is_rejected = alert_lifecycle
                                    .reject_deprecated_suite_after
                                    .is_some_and(|reject| now_secs >= reject);
                                if !is_rejected {
                                    let msg = format!(
                                        "HuMoCo sunset warning: suite 1 deprecation active since {} (now {}), migrate to suite 2",
                                        warn_after, now_secs
                                    );
                                    dispatcher.check_and_alert_sunset(&msg).await;
                                }
                            }
                        }
                    }
                }
            }
        });
        cleanup.producer(&alert_handle);

        // 3. Non-blocking recurring shard digest pull sync and bootstrap
        let sync_pm = peer_manager.clone();
        let sync_transport = transport.clone();
        let sync_engine = engine.clone();
        let sync_storage = storage.clone();
        let sync_cancel = self.cancel_token.clone();
        let sync_identity = self.identity.clone();
        let sync_readiness_mgr = readiness_manager.clone();
        let shard_sync_handle = tokio::spawn(async move {
            let Some(mut requests) = sync_readiness_mgr.take_sync_receiver() else {
                return;
            };
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = sync_cancel.cancelled() => { jobs.abort_all(); while jobs.join_next().await.is_some() {} break; }
                    Some(_) = jobs.join_next(), if !jobs.is_empty() => {}
                    request = requests.recv(), if jobs.len() < MAX_ACTIVE_SHARD_SYNCS => {
                        let Some(shard_id) = request else { break; };
                        let transport = sync_transport.clone();
                        let pm = sync_pm.clone();
                        let eng = sync_engine.clone();
                        let stor = sync_storage.clone();
                        let ident = sync_identity.clone();
                        let rm = sync_readiness_mgr.clone();
                        let cancel = sync_cancel.child_token();
                        jobs.spawn(async move {
                            let result = tokio::time::timeout(
                                std::time::Duration::from_secs(30),
                                sync_single_shard(shard_id, &transport, &pm, &eng, &stor, &ident, &rm, &cancel),
                            ).await;
                            if !matches!(result, Ok(Ok(true))) { rm.mark_sync_failed(shard_id); }
                        });
                    }
                }
            }
        });
        cleanup.producer(&shard_sync_handle);
        // Initialize Admin Token Manager
        let admin_token_mgr = Arc::new(
            crate::api::AdminTokenManager::load_or_create(&self.config.storage.data_dir, false)
                .map_err(|err| NodeError::IoWithPath {
                    path: self.config.storage.data_dir.join("admin.token"),
                    source: err,
                })?,
        );
        info!(
            token_path = ?admin_token_mgr.token_path(),
            "Admin token initialized successfully"
        );

        // Initialize System-Observatory Stats Collector & Sparklines Worker
        let node_metrics = std::sync::Arc::new(crate::api::metrics::NodeMetrics::default());
        let system_stats = Arc::new(crate::api::SystemStatsCollector::new(
            &self.config.storage.data_dir,
        ));
        let stats_handle = system_stats.clone().spawn_background_collector(
            node_metrics.clone(),
            Some(peer_manager.clone()),
            self.cancel_token.clone(),
        );
        cleanup.producer(&stats_handle);

        // Initialize History Sampler & Security Event Log (Phase 2 & Phase 5)
        let history_sampler = Arc::new(crate::api::HistorySampler::default());
        if let Err(error) = history_sampler
            .hourly
            .load(&self.config.storage.data_dir.join("metrics-hourly.json"))
        {
            warn!(%error, "Private hourly history unavailable; starting a fresh bounded history");
        }
        let event_log = Arc::new(crate::api::EventLog::default());

        // Load existing audit events on startup (Phase 5)
        match storage.load_recent_audit_events(100) {
            Ok(loaded_events) => {
                if !loaded_events.is_empty() {
                    tracing::info!(
                        "Loaded {} persistent audit events from storage",
                        loaded_events.len()
                    );
                    event_log.populate(loaded_events);
                }
            }
            Err(err) => {
                warn!("Failed to load recent audit events from storage: {}", err);
            }
        }

        // Spawn background audit event persister task (Phase 5)
        let (audit_tx, mut audit_rx) =
            tokio::sync::mpsc::channel::<crate::api::events::EventItem>(100);
        event_log.set_persister(audit_tx);
        let persister_storage = storage.clone();
        let persister_cancel = self.cancel_token.clone();
        let audit_handle = tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    _ = persister_cancel.cancelled() => { audit_rx.close(); audit_rx.recv().await },
                    event = audit_rx.recv() => event,
                };
                let Some(event) = event else {
                    break;
                };
                if let Err(err) = persister_storage.insert_audit_event(&event) {
                    warn!("Failed to persist audit event #{}: {}", event.id, err);
                }
            }
        });
        cleanup.producer(&audit_handle);

        event_log.record(
            crate::api::EventKind::System,
            crate::api::HealthLevel::Ok,
            format!(
                "HuMoCo node daemon started (NodePubKey: {})",
                self.identity.node_id_bs58()
            ),
        );

        // Initialize REST API Router and HTTP Server
        let app_state = crate::api::AppState {
            engine: engine.clone(),
            storage: storage.clone(),
            identity: self.identity.clone(),
            tier_controller: tier_controller.clone(),
            pow_engine,
            peer_manager: Some(peer_manager.clone()),
            transport: Some(transport.clone()),
            start_time: std::time::Instant::now(),
            metrics: node_metrics,
            lifecycle: self.config.lifecycle.clone(),
            network_id: self.config.network.network_id,
            shard_query_depth: self.config.network.shard_query_depth,
            system_stats,
            auth: admin_token_mgr,
            is_simulation,
            config: Arc::new(self.config.clone()),
            history_sampler: history_sampler.clone(),
            event_log: event_log.clone(),
            health_tracker: Arc::new(crate::api::health::HealthStateTracker::default()),
            readiness_manager: readiness_manager.clone(),
            retained_choice_reads: Arc::new(tokio::sync::Semaphore::new(8)),
        };

        // Spawn history sampling task (60s tick in normal mode, 5s in simulation mode)
        let sample_interval = if is_simulation {
            std::time::Duration::from_secs(5)
        } else {
            std::time::Duration::from_secs(60)
        };
        let history_handle = history_sampler.spawn_sampling_task(
            app_state.clone(),
            sample_interval,
            self.cancel_token.clone(),
        );
        cleanup.producer(&history_handle);

        let operator_handle = crate::api::operator::spawn_operator_listener(
            app_state.clone(),
            self.config.network.operator_listen_addr,
            self.cancel_token.clone(),
        )
        .await?;
        if let Some(handle) = &operator_handle {
            cleanup.producer(handle);
        }
        let app = crate::api::build_router(app_state);

        let rpc_listener = tokio::net::TcpListener::bind(self.config.network.rpc_listen_addr)
            .await
            .map_err(|err| NodeError::IoWithPath {
                path: std::path::PathBuf::from(self.config.network.rpc_listen_addr.to_string()),
                source: err,
            })?;
        let rpc_local_addr = rpc_listener.local_addr().map_err(NodeError::Io)?;
        info!(rpc_bound_addr = ?rpc_local_addr, "REST API HTTP server bound successfully");

        // Notify bound addresses if sender channel was provided
        if let Some(tx) = self.bound_addr_tx.lock().await.take() {
            let _ = tx.send(BoundAddrs {
                rpc_addr: rpc_local_addr,
                p2p_addr: p2p_bound_addr,
            });
        }

        let cancel_for_http = self.cancel_token.clone();
        let rpc_server = axum::serve(rpc_listener, app).with_graceful_shutdown(async move {
            cancel_for_http.cancelled().await;
        });
        let cancel_on_http_failure = self.cancel_token.clone();
        let rpc_handle = tokio::spawn(async move {
            let result = rpc_server.await.map_err(NodeError::Io);
            if result.is_err() {
                cancel_on_http_failure.cancel();
            }
            result
        });
        cleanup.producer(&rpc_handle);

        // Initialize Control Socket Server
        let socket_path = self.config.control_socket_path();
        let control_server = crate::control::ControlServer::new(
            socket_path,
            storage.clone(),
            engine.clone(),
            peer_manager.clone(),
            self.identity.clone(),
            self.config.storage.data_dir.clone(),
            self.cancel_token.clone(),
        )
        .with_tier_controller(tier_controller.clone())
        .with_shutdown_lifecycle(lifecycle);
        let cancel_on_control_failure = self.cancel_token.clone();
        let control_handle = tokio::spawn(async move {
            let result = control_server.run().await;
            if result.is_err() {
                cancel_on_control_failure.cancel();
            }
            result
        });
        cleanup.producer(&control_handle);

        // Wait for cancellation token, Ctrl+C (SIGINT), or SIGTERM (Unix)
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(
                    |err| NodeError::Daemon(format!("Failed to register SIGTERM handler: {err}")),
                )?;

            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Shutdown requested via cancellation token");
                }
                res = tokio::signal::ctrl_c() => {
                    match res {
                        Ok(()) => {
                            info!("Shutdown signal (Ctrl+C / SIGINT) received");
                            self.cancel_token.cancel();
                        }
                        Err(err) => {
                            error!(error = %err, "Failed to listen for Ctrl+C signal");
                            return Err(NodeError::Daemon(format!("Signal error: {}", err)));
                        }
                    }
                }
                _ = sigterm.recv() => {
                    info!("Shutdown signal (SIGTERM) received");
                    self.cancel_token.cancel();
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    info!("Shutdown requested via cancellation token");
                }
                res = tokio::signal::ctrl_c() => {
                    match res {
                        Ok(()) => {
                            info!("Shutdown signal (Ctrl+C) received");
                            self.cancel_token.cancel();
                        }
                        Err(err) => {
                            error!(error = %err, "Failed to listen for Ctrl+C signal");
                            return Err(NodeError::Daemon(format!("Signal error: {}", err)));
                        }
                    }
                }
            }
        }

        info!("Shutting down HuMoCo node daemon gracefully...");
        transport.close();
        transport.drain_tasks().await;
        let mut teardown_error = None;
        for handle in [
            accept_handle,
            heartbeat_handle,
            ttl_prune_handle,
            shard_sync_handle,
            thermometer_handle,
            malus_decay_handle,
            dns_re_resolve_handle,
            alert_handle,
            stats_handle,
            history_handle,
            audit_handle,
        ] {
            if let Err(error) = handle.await {
                teardown_error = Some(error.to_string());
            }
        }
        for handle in [Some(rpc_handle), Some(control_handle), operator_handle]
            .into_iter()
            .flatten()
        {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => teardown_error = Some(error.to_string()),
                Err(error) => teardown_error = Some(error.to_string()),
            }
        }
        flush_cancel_token.cancel();
        if let Err(error) = flush_handle.await {
            teardown_error = Some(error.to_string());
        }
        if engine
            .stats
            .flush_errors_total
            .load(std::sync::atomic::Ordering::SeqCst)
            != 0
        {
            teardown_error = Some("persistence failure or incomplete drain recorded".into());
        }
        if let Some(error) = teardown_error {
            return Err(NodeError::Daemon(format!("unclean teardown: {error}")));
        }
        info!("HuMoCo node daemon stopped.");
        Ok(())
    }
}

/// Computes the local digest from committed storage only; pending RAM is not a witness.
async fn compute_local_shard_digest(
    shard_id: u16,
    now_ms: u64,
    engine: &crate::storage::DualTierEngine,
    storage: &std::sync::Arc<crate::storage::RedbStorage>,
) -> Result<[u8; 32], NodeError> {
    let storage = storage.clone();
    let (digest, _) = engine.recovery_work.spawn_blocking(move || storage.committed_shard_digest(shard_id, now_ms)).await
        .map_err(|e| NodeError::Daemon(format!("digest worker: {e}")))??;
    Ok(digest)
}

/// Repairs active state from the frozen current full-key committee on demand.
/// Activates shard readiness when a verified dominant quorum confirms identical state.
/// Safe activation follows Contract G2 (Zero State Bloat, no historical quorum archives).
#[allow(clippy::too_many_arguments)]
pub async fn sync_single_shard(
    shard_id: u16,
    transport: &crate::network::QuicTransport,
    peer_manager: &crate::network::PeerManager,
    engine: &crate::storage::DualTierEngine,
    storage: &std::sync::Arc<crate::storage::RedbStorage>,
    identity: &crate::identity::NodeIdentity,
    readiness_manager: &std::sync::Arc<ShardReadinessManager>,
    cancel_token: &CancellationToken,
) -> Result<bool, NodeError> {
    use crate::storage::db::install::ShardStage;
    use std::collections::{HashMap,HashSet};
    use std::sync::Arc;
    use std::time::{Duration,Instant};
    readiness_manager.invalidate_shard(shard_id);
    if !engine.is_signing_healthy() || !readiness_manager.storage_healthy.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(false);
    }
    let (committee, remote, total) = peer_manager.shard_committee(*identity.node_pubkey(),*identity.hrw_routing_id(),shard_id).await;
    if !committee.iter().any(|member|member.node_pubkey == *identity.node_pubkey()) { return Ok(false); }
    let frozen_keys: Vec<_> = committee.iter().map(|member|member.node_pubkey).collect();
    let (needed,_) = humoco_sim_core::types::required_quorum(total);
    if needed == 0 { return Ok(false); }
    // Freeze in parallel: sequential twenty-peer timeouts cannot consume the
    // absolute no-gap lease before the complete cut is even requested.
    let mut requests = tokio::task::JoinSet::new();
    for (member,addr) in remote {
        let transport = transport.clone();
        requests.spawn(async move {
            let started = Instant::now();
            let conn = transport.connect_peer(addr).await.ok()?;
            let (_,key) = crate::network::tls::extract_peer_identity_from_connection(&conn)?;
            if key.to_bytes() != member.node_pubkey { return None; }
            let reply = transport.request_frozen_shard(&conn,shard_id,1).await.ok()?;
            Some((member.node_pubkey,conn,reply,started+Duration::from_millis(25_000)))
        });
    }
    let mut sources = Vec::new();
    let collect_until = tokio::time::Instant::now()+Duration::from_secs(8);
    while !requests.is_empty() {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            _ = tokio::time::sleep_until(collect_until) => break,
            result = requests.join_next() => {
                if let Some(Ok(Some(source))) = result { sources.push(source); }
            }
        }
    }
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    let result = async {
        if cancel_token.is_cancelled() { return Ok(false); }
        let mut groups: HashMap<[u8;32],HashSet<[u8;32]>> = HashMap::new();
        for (key,_,reply,expires) in &sources {
            if frozen_keys.contains(key) && Instant::now() < *expires { groups.entry(reply.digest).or_default().insert(*key); }
        }
        let Some((digest,witnesses)) = groups.into_iter().find(|(_,keys)|keys.len() >= needed) else { return Ok(false); };
        let witnesses_count = witnesses.len();
        let class = if total >= 20 && peer_manager.is_network_stable_ge20_for_24h(peer_manager.net_time_ms()) { 2 } else { 1 };
        let mut context = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_LIVE_CUT_SUPPORT";
        context.update(&[domain.len() as u8]); context.update(domain);
        context.update(&[match transport.network_id() { humoco_sim_core::types::NetworkId::Mainnet => 0, humoco_sim_core::types::NetworkId::Testnet => 1 }]);
        context.update(&shard_id.to_le_bytes()); context.update(&digest); context.update(&[class]);
        for key in &frozen_keys { context.update(key); }
        let context = *context.finalize().as_bytes();
        let minimum_deadline = sources.iter().filter(|(key,_,_,_)|witnesses.contains(key)).map(|(_,_,_,deadline)|*deadline).min();
        let Some(deadline) = minimum_deadline else { return Ok(false); };
        // Hold only a small cache per disk cut. Page reservations cover wire,
        // deserialization, validation and write buffers BEFORE requesting bytes.
        let Ok(_cache) = readiness_manager.sync_bytes.clone().try_acquire_many_owned(128*1024) else { return Ok(false); };
        for (key,conn,reply,_) in &sources {
            if !witnesses.contains(key) || reply.digest != digest { continue; }
            let now = peer_manager.net_time_ms();
            let stage = Arc::new(engine.recovery_work.spawn_blocking(move ||ShardStage::new(shard_id,now)).await
                .map_err(|e|NodeError::Daemon(format!("staging worker: {e}")))??);
            let mut cursor = 0;
            let mut sequence = 2;
            let mut complete = false;
            loop {
                if cancel_token.is_cancelled() || Instant::now() >= deadline { break; }
                let (Ok(_bytes),Ok(_entries)) = (
                    readiness_manager.sync_bytes.clone().try_acquire_many_owned(512*1024),
                    readiness_manager.sync_entries.clone().try_acquire_many_owned(500)) else { break; };
                let page = match tokio::time::timeout(Duration::from_secs(3),transport.request_active_sync_page_for_shard(conn,sequence,cursor,500,shard_id)).await {
                    Ok(Ok(page)) => page, _ => break,
                };
                sequence += 1;
                let next = page.next_cursor;
                let more = page.has_more;
                let cut = stage.clone();
                let appended = engine.recovery_work.spawn_blocking(move ||cut.append(page.payload)).await
                    .map_err(|e|NodeError::Daemon(format!("staging worker: {e}")))?;
                if appended.is_err() { break; }
                if !more { complete = true; break; }
                match next { Some(next) if next > cursor => cursor = next, _ => break }
            }
            if !complete { continue; }
            let cut = stage.clone();
            if engine.recovery_work.spawn_blocking(move ||cut.digest()).await.map_err(|e|NodeError::Daemon(format!("staging digest: {e}")))?? != digest { continue; }
            let (current,_,_) = peer_manager.shard_committee(*identity.node_pubkey(),*identity.hrw_routing_id(),shard_id).await;
            if current.iter().map(|m|m.node_pubkey).collect::<Vec<_>>() != frozen_keys || cancel_token.is_cancelled() || Instant::now() >= deadline { return Ok(false); }
            let Ok(_installation_memory) = readiness_manager.sync_bytes.clone().try_acquire_many_owned(512*1024) else { return Ok(false); };
            engine.install_shard_snapshot(stage,digest,class,context,witnesses_count).await?;
            if cancel_token.is_cancelled() || Instant::now() >= deadline || !engine.is_signing_healthy() { return Ok(false); }
            let (current,_,_) = peer_manager.shard_committee(*identity.node_pubkey(),*identity.hrw_routing_id(),shard_id).await;
            if current.iter().map(|m|m.node_pubkey).collect::<Vec<_>>() != frozen_keys { return Ok(false); }
            if compute_local_shard_digest(shard_id,peer_manager.net_time_ms(),engine,storage).await? != digest || Instant::now() >= deadline { return Ok(false); }
            // Quorum sources remain fenced THROUGH target publication. No valid
            // quorum can commit an omitted write in the cut-to-activation gap.
            readiness_manager.mark_shard_ready(shard_id);
            return Ok(true);
        }
        Ok(false)
    }.await;
    // Release explicitly on all normal outcomes. Cancellation/disconnect uses
    // the source's absolute expiry; neither retries nor repeated signals renew it.
    for (_,conn,reply,_) in &sources {
        let _ = tokio::time::timeout(Duration::from_millis(100),transport.release_frozen_shard(conn,shard_id,999,reply.token)).await;
    }
    if !matches!(result,Ok(true)) { readiness_manager.mark_sync_failed(shard_id); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_daemon_lifecycle_with_cancel_token() {
        let temp = tempdir().expect("tempdir");
        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.storage.data_dir = temp.path().join("data");
        let identity = NodeIdentity::generate();

        let cancel_token = CancellationToken::new();
        let daemon = NodeDaemon::with_cancel_token(config, identity, cancel_token.clone());

        let handle = tokio::spawn(async move { daemon.run().await });

        // Trigger cancellation
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        cancel_token.cancel();

        let result = handle.await.expect("task join");
        assert!(
            matches!(result, Ok(())),
            "daemon run must be Ok, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_daemon_lifecycle_in_simulation_mode() {
        let temp = tempdir().expect("tempdir");
        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.simulation_mode = true;
        config.network.fast_ticker_interval_secs = Some(1);
        config.storage.data_dir = temp.path().join("data");
        let identity = NodeIdentity::generate();

        let cancel_token = CancellationToken::new();
        let daemon = NodeDaemon::with_cancel_token(config, identity, cancel_token.clone());

        let handle = tokio::spawn(async move { daemon.run().await });

        // Let simulation tickers tick
        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
        cancel_token.cancel();

        let result = handle.await.expect("task join");
        assert!(
            matches!(result, Ok(())),
            "daemon run in simulation mode must be Ok, got {:?}",
            result
        );
    }

    #[test]
    fn test_shard_readiness_manager_lifecycle() {
        let mgr = ShardReadinessManager::new();
        let shard_id = 42u16;

        // 1. Initial state: not ready
        assert!(!mgr.is_shard_ready(shard_id));

        // 2. Trigger demand sync
        assert!(mgr.try_trigger_demand_sync(shard_id));
        // While syncing, not ready
        assert!(!mgr.is_shard_ready(shard_id));
        // Concurrent trigger must return false (already active)
        assert!(!mgr.try_trigger_demand_sync(shard_id));

        // 3. Mark ready upon convergence
        mgr.mark_shard_ready(shard_id);
        assert!(mgr.is_shard_ready(shard_id));

        // 4. Test failure reset
        let other_shard = 99u16;
        assert!(mgr.try_trigger_demand_sync(other_shard));
        mgr.mark_sync_failed(other_shard);
        assert!(!mgr.is_shard_ready(other_shard));
        // After failure reset, active task is cleared so demand sync can be triggered again
        assert!(mgr.try_trigger_demand_sync(other_shard));
    }
}
