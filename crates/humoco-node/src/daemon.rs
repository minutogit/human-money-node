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

    pub fn syncing_count(&self) -> usize {
        let Ok(states) = self.shard_states.lock() else {
            return 0;
        };
        states
            .values()
            .filter(|status| **status == ShardStatus::Syncing)
            .count()
    }

    pub fn invalidate_ready_shards(&self) -> usize {
        let Ok(mut states) = self.shard_states.lock() else {
            return 0;
        };
        let before = states.len();
        states.retain(|_, status| *status != ShardStatus::Ready);
        before.saturating_sub(states.len())
    }

    pub fn is_shard_ready_or_syncing(&self, shard_id: u16) -> bool {
        let Ok(states) = self.shard_states.lock() else {
            return false;
        };
        matches!(
            states.get(&shard_id),
            Some(ShardStatus::Ready | ShardStatus::Syncing)
        )
    }

    pub fn mark_syncing(&self, shard_id: u16) {
        if let Ok(mut states) = self.shard_states.lock() {
            states.insert(shard_id, ShardStatus::Syncing);
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
            if matches!(states.get(&shard_id), Some(ShardStatus::Syncing)) {
                states.remove(&shard_id);
            }
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
        if let Some(work) = recovery_work {
            work.close();
            work.wait().await;
        }
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
                return Err(NodeError::Daemon(
                    "new-region bootstrap refuses an existing database".into(),
                ));
            }
            std::fs::create_dir_all(&self.config.storage.data_dir).map_err(|source| {
                NodeError::IoWithPath {
                    path: self.config.storage.data_dir.clone(),
                    source,
                }
            })?;
            let marker = self.config.storage.data_dir.join("region-bootstrap-used");
            let reservation = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
                .map_err(|source| NodeError::IoWithPath {
                    path: marker,
                    source,
                })?;
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
        // Client friend secrets are strictly decoupled from P2P network peer topology (A25-03).
        // P2P peer keys/endpoints are NEVER registered as HTTP ingress bearer tokens.
        for token in &self.config.f2f.tokens {
            let trimmed = token.trim();
            if crate::ingress::tier::is_valid_client_token(trimmed) {
                tier_controller.register_f2f_peer(trimmed);
            } else {
                tracing::warn!(
                    "Ignored invalid F2F client token in configuration: tokens must match 'f2f_<32 hex digits>'"
                );
            }
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
        peer_manager.set_simulation_mode(self.config.network.simulation_mode);

        // Restore persisted HRW ticket maturation timestamps from redb so restarts do not
        // reset 24h incubation across the cluster, while newly mined tickets still incubate.
        {
            let boot_now_ms = peer_manager.net_time_ms();
            let local_pk = *self.identity.node_pubkey();
            let local_hrw = *self.identity.hrw_routing_id();
            let mut local_prior_age = std::time::Duration::ZERO;
            let sim_mode = self.config.network.simulation_mode;
            match storage.all_ticket_observations() {
                Ok(observations) => {
                    for (pk, hrw, first_seen_ms) in &observations {
                        let is_shortcut = *hrw == *blake3::hash(pk).as_bytes()
                            || *hrw == *pk
                            || *hrw == [0u8; 32];
                        if !sim_mode && is_shortcut {
                            continue;
                        }
                        let age = std::time::Duration::from_millis(
                            boot_now_ms.saturating_sub(*first_seen_ms),
                        );
                        peer_manager.seed_persisted_ticket_age(*pk, *hrw, age);
                        if *pk == local_pk && *hrw == local_hrw {
                            local_prior_age = age;
                        }
                    }
                    if !observations.is_empty() {
                        info!(
                            restored = observations.len(),
                            "Restored persisted HRW ticket observations into PeerManager"
                        );
                    }
                }
                Err(err) => {
                    warn!(error = %err, "Failed to load persisted HRW ticket observations from redb");
                }
            }
            if sim_mode || self.identity.has_valid_pow_ticket() {
                peer_manager.seed_local_ticket_age(local_pk, local_hrw, local_prior_age);
                if let Err(err) =
                    storage.record_ticket_observations_if_absent(&[(local_pk, local_hrw, boot_now_ms)])
                {
                    warn!(error = %err, "Failed to persist initial local HRW ticket observation");
                }
            }
        }

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

        let alert_dispatcher = std::sync::Arc::new(crate::alert::AlertDispatcher::new(
            self.config.alerts.clone(),
            self.config.storage.data_dir.clone(),
        ));
        peer_manager.set_alert_dispatcher(alert_dispatcher.clone());

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
        let thermo_rm = readiness_manager.clone();
        let thermo_engine = engine.clone();
        let thermo_storage = storage.clone();
        let thermo_self_ticket = (
            *self.identity.node_pubkey(),
            *self.identity.hrw_routing_id(),
        );
        let init_bootstrap = self.bootstrap_new_region;
        let thermo_interval_secs = if is_simulation { 5 } else { 60 };
        let thermometer_handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(thermo_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            let mut prev_total = thermo_pm.total_network_size().await;
            let mut max_seen_total = prev_total;
            loop {
                tokio::select! {
                    _ = thermo_cancel.cancelled() => {
                        info!("Thermometer / merge-monitor ticker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let now_ms = thermo_pm.net_time_ms();
                        // Persist observed HRW tickets off the Tokio async worker thread.
                        let mut active_tickets: Vec<([u8; 32], [u8; 32], u64)> = thermo_pm
                            .snapshot_active_tickets()
                            .await
                            .into_iter()
                            .map(|(pk, hrw)| (pk, hrw, now_ms))
                            .collect();
                        active_tickets.push((thermo_self_ticket.0, thermo_self_ticket.1, now_ms));
                        let persist_storage = thermo_storage.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            persist_storage.record_ticket_observations_if_absent(&active_tickets)
                        })
                        .await;
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
                            // Only drop local Ready state when the remote partition alone holds
                            // at least `needed` witnesses (cur_total - prev_total >= needed) so
                            // symmetric merges or 3-node clusters never deadlock with 0 Ready
                            // witnesses, and skip invalidation on the first peer discovery of an
                            // empty newly-bootstrapped region.
                            let (needed, _) = humoco_sim_core::types::required_quorum(cur_total);
                            let remote_dominant_quorum =
                                needed > 0 && cur_total.saturating_sub(prev_total) >= needed;
                            let empty_initial_bootstrap = init_bootstrap
                                && max_seen_total <= 1
                                && thermo_engine.hmc_ram.read().await.locks.is_empty();
                            let invalidated = if remote_dominant_quorum && !empty_initial_bootstrap {
                                thermo_rm.invalidate_ready_shards()
                            } else {
                                0
                            };
                            thermo_pm.notify_sync_trigger();
                            info!(
                                prev_total,
                                cur_total,
                                write_median,
                                invalidated_shards = invalidated,
                                "Partition merge detected: thermometer fast-reseeded, 24h quota moratorium armed"
                            );
                        }
                        prev_total = cur_total;
                        max_seen_total = max_seen_total.max(cur_total);
                    }
                }
            }
        });
        cleanup.producer(&thermometer_handle);

        // 1. F2F Heartbeat-Emitter (hourly with jitter, signed payload)
        let hb_pm = peer_manager.clone();
        let hb_transport = transport.clone();
        let hb_cancel = self.cancel_token.clone();
        let hb_local_addr = if let Some(mut adv) = self.config.network.advertised_addr {
            if adv.port() == 0 {
                adv.set_port(p2p_bound_addr.port());
            }
            adv
        } else {
            p2p_bound_addr
        };
        let hb_sim_mode = is_simulation;
        let hb_tc = tier_controller.clone();

        if !is_simulation
            && hb_local_addr.ip().is_unspecified()
            && !self.config.f2f.peers.is_empty()
        {
            warn!(
                bound_addr = %p2p_bound_addr,
                "Node P2P listen_addr is unspecified (0.0.0.0 / ::) without network.advertised_addr configured; peers on remote hosts will not be able to dial this node via gossiped address"
            );
        }
        let heartbeat_handle = tokio::spawn(async move {
            let mut seq: u64 = 0;
            let mut boot_attempts_left: u8 = 2;
            loop {
                let sleep_dur = if boot_attempts_left == 2 {
                    let ms = if hb_sim_mode {
                        rand::thread_rng().gen_range(300..=600)
                    } else {
                        rand::thread_rng().gen_range(1000..=3000)
                    };
                    std::time::Duration::from_millis(ms)
                } else if boot_attempts_left == 1 {
                    if hb_sim_mode {
                        std::time::Duration::from_millis(800)
                    } else {
                        std::time::Duration::from_secs(5)
                    }
                } else {
                    let sleep_secs = if hb_sim_mode {
                        rand::thread_rng().gen_range(4..=6)
                    } else {
                        crate::network::PeerManager::heartbeat_jitter_secs()
                    };
                    std::time::Duration::from_secs(sleep_secs)
                };
                tokio::select! {
                    _ = hb_cancel.cancelled() => {
                        info!("F2F heartbeat emitter shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(sleep_dur) => {
                        let peers = hb_pm.f2f_peer_addrs().await;
                        if peers.is_empty() {
                            boot_attempts_left = 0;
                            debug!("Heartbeat tick: no F2F friends configured");
                            continue;
                        }
                        let declared_write_ema = hb_tc.current_write_ema_micro_bj();
                        let declared_read_ema = hb_tc.current_read_ema_credits();
                        let now_ms = hb_pm.net_time_ms();
                        let piggyback = hb_pm.sample_piggyback_evidences(2).await;

                        let mut any_failed = false;
                        for peer_addr in peers {
                            if hb_cancel.is_cancelled() { break; }
                            seq = seq.wrapping_add(1);
                            match hb_transport.send_heartbeat_to(
                                peer_addr,
                                hb_local_addr,
                                seq,
                                declared_write_ema,
                                declared_read_ema,
                                now_ms,
                                piggyback.clone(),
                            ).await {
                                Ok(()) => {
                                    debug!(peer=%peer_addr, seq, "F2F heartbeat sent");
                                }
                                Err(e) => {
                                    any_failed = true;
                                    debug!(peer=%peer_addr, error=%e, "Heartbeat send failed");
                                }
                            }
                        }
                        if boot_attempts_left > 0 {
                            if any_failed && boot_attempts_left == 2 {
                                boot_attempts_left = 1;
                            } else {
                                boot_attempts_left = 0;
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
                        if !prune_pm.is_local_sync_ready() && !prune_pm.clock().has_quorum_samples() {
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
        let alert_pm = peer_manager.clone();
        let alert_cancel = self.cancel_token.clone();
        let dispatcher = alert_dispatcher.clone();
        let alert_handle = tokio::spawn(async move {
            // 15-minute startup hysteresis
            tokio::select! {
                _ = alert_cancel.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(15 * 60)) => {}
            }
            if alert_cancel.is_cancelled() {
                return;
            }
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

                        // Check Knotenfreund directional sectors & unresponsiveness (Slice 1)
                        let sectors = alert_pm.compute_knotenfreund_sectors().await;
                        for sector in sectors {
                            let friend_hex = &sector.friend_pubkey;
                            let short_id = if friend_hex.len() >= 12 { &friend_hex[..12] } else { friend_hex.as_str() };
                            if sector.active_non_responder_30m {
                                let msg = format!(
                                    "Knotenfreund {} is actively unresponsive (>30m RPC failures while QUIC connected).",
                                    short_id
                                );
                                dispatcher.trigger_scoped(
                                    crate::alert::AlertKind::KnotenfreundUnresponsive,
                                    Some(friend_hex),
                                    &msg,
                                ).await;
                            }
                            if sector.severity == crate::network::SectorSeverity::Crit {
                                let msg = format!(
                                    "Directional sector behind Knotenfreund {} exhibits critical health anomaly (bad: {}/{}, exclusive bad: {}).",
                                    short_id,
                                    sector.n_bad,
                                    sector.n_tested,
                                    sector.exclusive_bad_count,
                                );
                                dispatcher.trigger_scoped(
                                    crate::alert::AlertKind::DirectionalSectorAnomaly,
                                    Some(friend_hex),
                                    &msg,
                                ).await;
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

        // 3.1 Throttled background shard warmup for assigned HRW committee shards
        let warmup_pm = peer_manager.clone();
        let warmup_rm = readiness_manager.clone();
        let warmup_identity = self.identity.clone();
        let warmup_cancel = self.cancel_token.clone();
        let warmup_notify = peer_manager.sync_notifier();
        let warmup_initial_delay_secs = if is_simulation { 2 } else { 5 };
        let warmup_interval_secs = if is_simulation { 5 } else { 30 };

        let shard_warmup_handle = tokio::spawn(async move {
            // Initial startup settling delay
            tokio::select! {
                _ = warmup_cancel.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(warmup_initial_delay_secs)) => {}
            }
            if warmup_cancel.is_cancelled() {
                return;
            }

            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(warmup_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut next_shard_cursor: u16 = 0;
            const MAX_BACKGROUND_WARMUP_SYNCS: usize = 4;
            const SHARDS_PER_TICK: u16 = 256;
            let self_pubkey = *warmup_identity.node_pubkey();
            let self_hrw = *warmup_identity.hrw_routing_id();

            loop {
                tokio::select! {
                    _ = warmup_cancel.cancelled() => {
                        info!("Shard warmup background worker shutting down");
                        break;
                    }
                    _ = interval.tick() => {}
                    _ = warmup_notify.notified() => {}
                }

                // Only attempt warmup when peer_manager actually has at least 1 connected/active
                // remote peer (if N <= 1 or 0 remote peers, do nothing so G2 empty-network safety holds strictly).
                let total_nodes = warmup_pm.total_network_size().await;
                if total_nodes <= 1 {
                    continue;
                }
                let has_remote = warmup_pm.connected_peer_count().await > 0
                    || !warmup_pm.active_known_nodes().await.is_empty();
                if !has_remote {
                    continue;
                }

                let mut scanned: u16 = 0;
                while scanned < SHARDS_PER_TICK {
                    // Strict throttle: leave 28 of 32 sync slots reserved for live checkout demand sync (DEC-024)
                    if warmup_rm.syncing_count() >= MAX_BACKGROUND_WARMUP_SYNCS {
                        break;
                    }

                    let shard_id = next_shard_cursor;
                    next_shard_cursor = next_shard_cursor.wrapping_add(1);
                    scanned = scanned.saturating_add(1);

                    if warmup_rm.is_shard_ready_or_syncing(shard_id) {
                        continue;
                    }

                    if warmup_pm
                        .is_local_committee_member(self_pubkey, self_hrw, shard_id)
                        .await
                    {
                        if warmup_rm.syncing_count() < MAX_BACKGROUND_WARMUP_SYNCS {
                            if warmup_rm.request_sync(shard_id) {
                                debug!(
                                    shard_id,
                                    "Background warmup sync requested for assigned HRW shard"
                                );
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        });
        cleanup.producer(&shard_warmup_handle);
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
            voucher_root_reads: Arc::new(tokio::sync::Semaphore::new(16)),
            sync_reads: Arc::new(tokio::sync::Semaphore::new(4)),
            mesh_view_cache: Arc::new(parking_lot::RwLock::new(None)),
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
            shard_warmup_handle,
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
    let (digest, _) = engine
        .recovery_work
        .spawn_blocking(move || storage.committed_shard_digest(shard_id, now_ms))
        .await
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
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    readiness_manager.mark_syncing(shard_id);
    if !engine.is_signing_healthy()
        || !readiness_manager
            .storage_healthy
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(false);
    }
    let (committee, remote, total) = peer_manager
        .shard_committee(
            *identity.node_pubkey(),
            *identity.hrw_routing_id(),
            shard_id,
        )
        .await;
    if !committee
        .iter()
        .any(|member| member.node_pubkey == *identity.node_pubkey())
    {
        return Ok(false);
    }
    let frozen_keys: Vec<_> = committee.iter().map(|member| member.node_pubkey).collect();
    let (needed, _) = humoco_sim_core::types::required_quorum(total);
    if needed == 0 {
        return Ok(false);
    }
    if total == 1 && remote.is_empty() {
        readiness_manager.mark_shard_ready(shard_id);
        return Ok(true);
    }
    // Freeze in parallel: sequential twenty-peer timeouts cannot consume the
    // absolute no-gap lease before the complete cut is even requested.
    let mut requests = tokio::task::JoinSet::new();
    for (member, addr) in remote {
        let transport = transport.clone();
        requests.spawn(async move {
            let started = Instant::now();
            let conn = transport.connect_peer(addr).await.ok()?;
            let (_, key) = crate::network::tls::extract_peer_identity_from_connection(&conn)?;
            if key.to_bytes() != member.node_pubkey {
                return None;
            }
            let reply = transport
                .request_frozen_shard(&conn, shard_id, 1)
                .await
                .ok()?;
            Some((
                member.node_pubkey,
                conn,
                reply,
                started + Duration::from_millis(25_000),
            ))
        });
    }
    let mut sources = Vec::new();
    let collect_until = tokio::time::Instant::now() + Duration::from_secs(8);
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
        if cancel_token.is_cancelled() {
            return Ok(false);
        }
        let mut groups: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        for (key, _, reply, expires) in &sources {
            if frozen_keys.contains(key) && Instant::now() < *expires {
                groups.entry(reply.digest).or_default().insert(*key);
            }
        }
        let Some((digest, witnesses)) = groups.into_iter().find(|(_, keys)| keys.len() >= needed)
        else {
            if cancel_token.is_cancelled() {
                return Ok(false);
            }
            let viable: Vec<_> = sources
                .iter()
                .filter(|(key, _, _, expires)| {
                    frozen_keys.contains(key) && Instant::now() < *expires
                })
                .collect();
            if viable.len() < needed {
                return Ok(false);
            }
            let recon_now = peer_manager.net_time_ms();
            let mut download_tasks = tokio::task::JoinSet::new();
            for (_, conn, reply, expires) in viable {
                let conn = conn.clone();
                let reply_digest = reply.digest;
                let expires = *expires;
                let transport = transport.clone();
                let engine_work = engine.recovery_work.clone();
                let readiness_manager = readiness_manager.clone();
                let cancel_token = cancel_token.clone();
                download_tasks.spawn(async move {
                    if Instant::now() >= expires || cancel_token.is_cancelled() {
                        return None;
                    }
                    let stage = Arc::new(
                        engine_work
                            .spawn_blocking(move || ShardStage::new(shard_id, recon_now))
                            .await
                            .ok()?
                            .ok()?,
                    );
                    let mut cursor = 0;
                    let mut sequence = 2;
                    let mut complete = false;
                    loop {
                        if cancel_token.is_cancelled() || Instant::now() >= expires {
                            break;
                        }
                        let permit_deadline = tokio::time::Instant::from_std(expires);
                        let Some(_bytes) = (tokio::select! {
                            _ = cancel_token.cancelled() => None,
                            res = tokio::time::timeout_at(
                                permit_deadline,
                                readiness_manager.sync_bytes.clone().acquire_many_owned(512 * 1024),
                            ) => res.ok().and_then(Result::ok),
                        }) else {
                            break;
                        };
                        let Some(_entries) = (tokio::select! {
                            _ = cancel_token.cancelled() => None,
                            res = tokio::time::timeout_at(
                                permit_deadline,
                                readiness_manager.sync_entries.clone().acquire_many_owned(500),
                            ) => res.ok().and_then(Result::ok),
                        }) else {
                            break;
                        };
                        let page = match tokio::time::timeout(
                            Duration::from_secs(3),
                            transport.request_active_sync_page_for_shard(
                                &conn, sequence, cursor, 500, shard_id,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(page)) => page,
                            _ => break,
                        };
                        sequence += 1;
                        let next = page.next_cursor;
                        let more = page.has_more;
                        let cut = stage.clone();
                        let appended = engine_work
                            .spawn_blocking(move || cut.append(page.payload))
                            .await
                            .ok()?;
                        if appended.is_err() {
                            break;
                        }
                        if !more {
                            complete = true;
                            break;
                        }
                        match next {
                            Some(next) if next > cursor => cursor = next,
                            _ => break,
                        }
                    }
                    if complete && Instant::now() < expires {
                        let cut = stage.clone();
                        let Ok(staged_digest_res) =
                            engine_work.spawn_blocking(move || cut.digest()).await
                        else {
                            return None;
                        };
                        let Ok(staged_digest) = staged_digest_res else {
                            return None;
                        };
                        if staged_digest != reply_digest {
                            return None;
                        }
                        Some((stage, expires))
                    } else {
                        None
                    }
                });
            }
            let mut downloaded = Vec::new();
            let mut downloaded_deadlines = Vec::new();
            while let Some(res) = download_tasks.join_next().await {
                if let Ok(Some((stage, expires))) = res {
                    downloaded.push(stage);
                    downloaded_deadlines.push(expires);
                }
            }
            if downloaded.len() < needed {
                return Ok(false);
            }
            let Some(deadline) = downloaded_deadlines.into_iter().min() else {
                return Ok(false);
            };
            let Ok(_installation_memory) = readiness_manager
                .sync_bytes
                .clone()
                .try_acquire_many_owned(512 * 1024)
            else {
                return Ok(false);
            };
            let target_storage = storage.clone();
            let reconciled = engine
                .recovery_work
                .spawn_blocking(move || {
                    reconcile_distributed_stage(
                        shard_id,
                        recon_now,
                        needed,
                        &downloaded,
                        &target_storage,
                    )
                })
                .await
                .map_err(|e| NodeError::Daemon(format!("reconciliation worker: {e}")))??;
            let Some((stage, digest, witnesses_count)) = reconciled else {
                return Ok(false);
            };
            if cancel_token.is_cancelled() || Instant::now() >= deadline {
                return Ok(false);
            }
            let (current, _, _) = peer_manager
                .shard_committee(
                    *identity.node_pubkey(),
                    *identity.hrw_routing_id(),
                    shard_id,
                )
                .await;
            if current.iter().map(|m| m.node_pubkey).collect::<Vec<_>>() != frozen_keys
                || Instant::now() >= deadline
            {
                return Ok(false);
            }
            let class = if total >= 20
                && peer_manager.is_network_stable_ge20_for_24h(peer_manager.net_time_ms())
            {
                2
            } else {
                1
            };
            let mut context = blake3::Hasher::new();
            let domain = b"HUMOCO_V1_LIVE_CUT_SUPPORT";
            context.update(&[domain.len() as u8]);
            context.update(domain);
            context.update(&[match transport.network_id() {
                humoco_sim_core::types::NetworkId::Mainnet => 0,
                humoco_sim_core::types::NetworkId::Testnet => 1,
            }]);
            context.update(&shard_id.to_le_bytes());
            context.update(&digest);
            context.update(&0u8.to_le_bytes());
            context.update(&[class]);
            for key in &frozen_keys {
                context.update(key);
            }
            let context = *context.finalize().as_bytes();
            engine
                .install_shard_snapshot(
                    stage,
                    digest,
                    class,
                    context,
                    witnesses_count,
                    None,
                    Some(deadline),
                )
                .await?;
            if cancel_token.is_cancelled()
                || Instant::now() >= deadline
                || !engine.is_signing_healthy()
            {
                return Ok(false);
            }
            let (current, _, _) = peer_manager
                .shard_committee(
                    *identity.node_pubkey(),
                    *identity.hrw_routing_id(),
                    shard_id,
                )
                .await;
            if current.iter().map(|m| m.node_pubkey).collect::<Vec<_>>() != frozen_keys {
                return Ok(false);
            }
            if compute_local_shard_digest(shard_id, peer_manager.net_time_ms(), engine, storage)
                .await?
                != digest
                || Instant::now() >= deadline
            {
                return Ok(false);
            }
            readiness_manager.mark_shard_ready(shard_id);
            return Ok(true);
        };
        let witnesses_count = witnesses.len();
        let mut support_groups: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        for (key, _, reply, _) in sources
            .iter()
            .filter(|(key, _, reply, _)| witnesses.contains(key) && reply.digest == digest)
        {
            support_groups
                .entry(reply.support_digest)
                .or_default()
                .insert(*key);
        }
        let mut compatible_supports: Vec<_> = support_groups.keys().copied().collect();
        compatible_supports.sort_unstable();
        let mut qualified_supports: Vec<_> = support_groups
            .iter()
            .filter(|(_, keys)| keys.len() >= needed)
            .map(|(support, _)| *support)
            .collect();
        qualified_supports.sort_unstable();
        let proofs: Vec<_> = sources
            .iter()
            .filter(|(key, _, reply, _)| witnesses.contains(key) && reply.digest == digest)
            .map(|(key, _, reply, _)| (*key, reply.clone()))
            .collect();
        let inherited = crate::storage::db::support::VerifiedInheritedCut::verify(
            transport.network_id(),
            shard_id,
            *identity.node_pubkey(),
            &frozen_keys,
            needed,
            digest,
            &compatible_supports,
            &qualified_supports,
            &proofs,
        )?;
        let class = if total >= 20
            && peer_manager.is_network_stable_ge20_for_24h(peer_manager.net_time_ms())
        {
            2
        } else {
            1
        };
        let mut context = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_LIVE_CUT_SUPPORT";
        context.update(&[domain.len() as u8]);
        context.update(domain);
        context.update(&[match transport.network_id() {
            humoco_sim_core::types::NetworkId::Mainnet => 0,
            humoco_sim_core::types::NetworkId::Testnet => 1,
        }]);
        context.update(&shard_id.to_le_bytes());
        context.update(&digest);
        context.update(&(compatible_supports.len() as u8).to_le_bytes());
        for support in &compatible_supports {
            context.update(support);
        }
        context.update(&[class]);
        for key in &frozen_keys {
            context.update(key);
        }
        let context = *context.finalize().as_bytes();
        let minimum_deadline = sources
            .iter()
            .filter(|(key, _, _, _)| witnesses.contains(key))
            .map(|(_, _, _, deadline)| *deadline)
            .min();
        let Some(deadline) = minimum_deadline else {
            return Ok(false);
        };
        // Hold only a small cache per disk cut. Page reservations cover wire,
        // deserialization, validation and write buffers BEFORE requesting bytes.
        let Ok(_cache) = readiness_manager
            .sync_bytes
            .clone()
            .try_acquire_many_owned(128 * 1024)
        else {
            return Ok(false);
        };
        for (key, conn, reply, _) in &sources {
            if !witnesses.contains(key)
                || reply.digest != digest
                || !compatible_supports.contains(&reply.support_digest)
            {
                continue;
            }
            let now = peer_manager.net_time_ms();
            let stage = Arc::new(
                engine
                    .recovery_work
                    .spawn_blocking(move || ShardStage::new(shard_id, now))
                    .await
                    .map_err(|e| NodeError::Daemon(format!("staging worker: {e}")))??,
            );
            let mut cursor = 0;
            let mut sequence = 2;
            let mut complete = false;
            loop {
                if cancel_token.is_cancelled() || Instant::now() >= deadline {
                    break;
                }
                let (Ok(_bytes), Ok(_entries)) = (
                    readiness_manager
                        .sync_bytes
                        .clone()
                        .try_acquire_many_owned(512 * 1024),
                    readiness_manager
                        .sync_entries
                        .clone()
                        .try_acquire_many_owned(500),
                ) else {
                    break;
                };
                let page = match tokio::time::timeout(
                    Duration::from_secs(3),
                    transport
                        .request_active_sync_page_for_shard(conn, sequence, cursor, 500, shard_id),
                )
                .await
                {
                    Ok(Ok(page)) => page,
                    _ => break,
                };
                sequence += 1;
                let next = page.next_cursor;
                let more = page.has_more;
                let cut = stage.clone();
                let appended = engine
                    .recovery_work
                    .spawn_blocking(move || cut.append(page.payload))
                    .await
                    .map_err(|e| NodeError::Daemon(format!("staging worker: {e}")))?;
                if appended.is_err() {
                    break;
                }
                if !more {
                    complete = true;
                    break;
                }
                match next {
                    Some(next) if next > cursor => cursor = next,
                    _ => break,
                }
            }
            if !complete {
                continue;
            }
            let cut = stage.clone();
            let Ok(staged_digest_res) = engine
                .recovery_work
                .spawn_blocking(move || cut.digest())
                .await
            else {
                continue;
            };
            let Ok(staged_digest) = staged_digest_res else {
                continue;
            };
            if staged_digest != digest {
                continue;
            }
            let (current, _, _) = peer_manager
                .shard_committee(
                    *identity.node_pubkey(),
                    *identity.hrw_routing_id(),
                    shard_id,
                )
                .await;
            if current.iter().map(|m| m.node_pubkey).collect::<Vec<_>>() != frozen_keys
                || cancel_token.is_cancelled()
                || Instant::now() >= deadline
            {
                return Ok(false);
            }
            let Ok(_installation_memory) = readiness_manager
                .sync_bytes
                .clone()
                .try_acquire_many_owned(512 * 1024)
            else {
                return Ok(false);
            };
            let cut = stage.clone();
            let Ok(staged_support_res) = engine
                .recovery_work
                .spawn_blocking(move || cut.support_digest())
                .await
            else {
                continue;
            };
            let Ok(staged_support) = staged_support_res else {
                continue;
            };
            if !compatible_supports.contains(&staged_support) {
                continue;
            }
            if let Err(err) = engine
                .install_shard_snapshot(
                    stage,
                    digest,
                    class,
                    context,
                    witnesses_count,
                    Some(inherited.clone()),
                    Some(deadline),
                )
                .await
            {
                if !engine.is_signing_healthy() {
                    return Err(err.into());
                }
                warn!("Active-sync witness install failed: {err}; trying next witness");
                continue;
            }
            if cancel_token.is_cancelled()
                || Instant::now() >= deadline
                || !engine.is_signing_healthy()
            {
                return Ok(false);
            }
            let (current, _, _) = peer_manager
                .shard_committee(
                    *identity.node_pubkey(),
                    *identity.hrw_routing_id(),
                    shard_id,
                )
                .await;
            if current.iter().map(|m| m.node_pubkey).collect::<Vec<_>>() != frozen_keys {
                return Ok(false);
            }
            if compute_local_shard_digest(shard_id, peer_manager.net_time_ms(), engine, storage)
                .await?
                != digest
                || Instant::now() >= deadline
            {
                return Ok(false);
            }
            // Quorum sources remain fenced THROUGH target publication. No valid
            // quorum can commit an omitted write in the cut-to-activation gap.
            readiness_manager.mark_shard_ready(shard_id);
            return Ok(true);
        }
        Ok(false)
    }
    .await;
    // Release explicitly on all normal outcomes. Cancellation/disconnect uses
    // the source's absolute expiry; neither retries nor repeated signals renew it.
    for (_, conn, reply, _) in &sources {
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            transport.release_frozen_shard(conn, shard_id, 999, reply.token),
        )
        .await;
    }
    if !matches!(result, Ok(true)) {
        readiness_manager.mark_sync_failed(shard_id);
    }
    result
}

type ReconciledRootFacts =
    std::collections::HashMap<(String, [u8; 32]), (crate::api::hmc::L2LockEntry, u32)>;
type ReconciledHmcFacts = std::collections::HashMap<
    (String, [u8; 32]),
    ((String, crate::api::hmc::L2LockEntry, u8), u32),
>;
type ReconciledStage = (
    Arc<crate::storage::db::install::ShardStage>,
    [u8; 32],
    usize,
);

struct ReconciledCutFacts {
    roots: Vec<crate::api::hmc::L2LockEntry>,
    hmc: Vec<(String, crate::api::hmc::L2LockEntry)>,
}

fn read_reconciled_cut_facts(
    storage: &crate::storage::RedbStorage,
    shard: u16,
    now: u64,
) -> Result<ReconciledCutFacts, crate::storage::StorageError> {
    let mut roots = Vec::new();
    for root in storage.all_voucher_roots()? {
        let Ok(validity) = crate::storage::db::roots::root_valid_until(&root) else {
            continue;
        };
        if validity <= now {
            continue;
        }
        let tag = bs58::encode(root.t_id).into_string();
        let parent = humoco_sim_core::types::genesis_parent_bytes_from_tag(&tag);
        if humoco_sim_core::types::canonical_voucher_shard(&parent) != shard {
            continue;
        }
        roots.push(root);
    }
    let hmc = storage.active_hmc_locks_for_shard(shard, now)?;
    Ok(ReconciledCutFacts { roots, hmc })
}

fn append_reconciled_hmc(
    stage: &crate::storage::db::install::ShardStage,
    facts: &[(String, crate::api::hmc::L2LockEntry)],
) -> Result<(), crate::storage::StorageError> {
    use crate::network::framing::SyncPayload;
    let mut batch: Vec<(String, crate::api::hmc::L2LockEntry)> = Vec::new();
    for fact in facts {
        batch.push(fact.clone());
        if bincode::serialized_size(&batch)? > 60 * 1024 {
            if let Some(overflow) = batch.pop() {
                if !batch.is_empty() {
                    stage.append(SyncPayload {
                        hmc_locks: std::mem::take(&mut batch),
                        support: Vec::new(),
                    })?;
                }
                batch.push(overflow);
            }
        }
    }
    if !batch.is_empty() {
        stage.append(SyncPayload {
            hmc_locks: batch,
            support: Vec::new(),
        })?;
    }
    Ok(())
}

/// Rebuilds one shard cut from facts held by at least `needed` members of the
/// frozen committee (remote downloaded source cuts plus `target`'s own committed
/// storage when `target` already holds that exact fact).
fn reconcile_distributed_stage(
    shard_id: u16,
    now: u64,
    needed: usize,
    stages: &[Arc<crate::storage::db::install::ShardStage>],
    target: &Arc<crate::storage::RedbStorage>,
) -> Result<Option<ReconciledStage>, NodeError> {
    use crate::api::hmc::L2LockEntry;
    use std::collections::HashMap;
    let mut root_facts: ReconciledRootFacts = HashMap::new();
    let mut hmc_facts: ReconciledHmcFacts = HashMap::new();
    let ingest = |storage: &crate::storage::RedbStorage,
                  index: usize,
                  root_facts: &mut ReconciledRootFacts,
                  hmc_facts: &mut ReconciledHmcFacts|
     -> Result<(), crate::storage::StorageError> {
        let facts = read_reconciled_cut_facts(storage, shard_id, now)?;
        for root in facts.roots {
            let voucher = &root.layer2_voucher_id;
            if voucher.len() == 64
                && voucher.bytes().all(|b| b.is_ascii_hexdigit())
                && root.causal_output.is_none()
                && target.voucher_root(voucher)?.is_none()
            {
                continue;
            }
            let digest = *blake3::hash(&serde_json::to_vec(&root)?).as_bytes();
            root_facts
                .entry((root.layer2_voucher_id.clone(), digest))
                .or_insert_with(|| (root, 0u32))
                .1 |= 1u32 << (index.min(31));
        }
        for (tag, entry) in facts.hmc {
            let class = storage
                .confirmation_support(&tag)?
                .filter(|s| s.child == entry.t_id)
                .map_or(0, |s| s.class);
            let map_entry = hmc_facts
                .entry((tag.clone(), entry.t_id))
                .or_insert_with(|| ((tag.clone(), entry.clone(), class), 0u32));
            map_entry.0 .2 = map_entry.0 .2.max(class);
            map_entry.1 |= 1u32 << (index.min(31));
        }
        Ok(())
    };
    for (index, stage) in stages.iter().enumerate() {
        ingest(
            &stage.storage,
            index,
            &mut root_facts,
            &mut hmc_facts,
        )?;
    }
    ingest(
        target.as_ref(),
        stages.len(),
        &mut root_facts,
        &mut hmc_facts,
    )?;

    // A21-R2: Cap reconciliation working memory against malicious/unbounded cuts
    const MAX_RECONCILE_ENTRY_CAP: usize = 50_000;
    if root_facts.len() + hmc_facts.len() > MAX_RECONCILE_ENTRY_CAP {
        return Err(NodeError::Storage(
            crate::storage::StorageError::DurableCommitFailed(
                "reconciliation fact memory budget exceeded".into(),
            ),
        ));
    }

    let mut selected_roots: HashMap<String, (L2LockEntry, [u8; 32], usize)> = HashMap::new();
    for ((voucher, digest), (entry, witnesses)) in &root_facts {
        if voucher.len() == 64
            && voucher.bytes().all(|b| b.is_ascii_hexdigit())
            && entry.causal_output.is_none()
            && target.voucher_root(voucher)?.is_none()
        {
            continue;
        }
        let count = witnesses.count_ones() as usize;
        if count < needed {
            continue;
        }
        if let Some((_, existing, _)) = selected_roots.get(voucher) {
            if existing != digest {
                return Ok(None);
            }
        } else {
            selected_roots.insert(voucher.clone(), (entry.clone(), *digest, count));
        }
    }

    let mut selected_hmc: HashMap<String, (String, L2LockEntry, usize, u8)> = HashMap::new();
    for ((tag, _), ((stored_tag, entry, class), witnesses)) in &hmc_facts {
        let count = witnesses.count_ones() as usize;
        if count < needed {
            continue;
        }
        if !selected_roots.contains_key(&entry.layer2_voucher_id) {
            continue;
        }
        if let Some((_, old, _, old_class)) = selected_hmc.get(tag) {
            if *class < *old_class {
                continue;
            } else if *class == *old_class {
                let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                let new_hash = crate::storage::compute_hmc_canonical_hash(
                    &parent,
                    &entry.sender_ephemeral_pub,
                    &entry.t_id,
                );
                let old_hash = crate::storage::compute_hmc_canonical_hash(
                    &parent,
                    &old.sender_ephemeral_pub,
                    &old.t_id,
                );
                if new_hash >= old_hash {
                    continue;
                }
            }
        }
        selected_hmc.insert(
            tag.clone(),
            (stored_tag.clone(), entry.clone(), count, *class),
        );
    }

    if selected_roots.is_empty() && selected_hmc.is_empty() {
        return Ok(None);
    }

    let min_witnesses = selected_hmc
        .values()
        .map(|(_, _, w, _)| *w)
        .chain(selected_roots.values().map(|(_, _, w)| *w))
        .min()
        .unwrap_or(needed);

    let stage = Arc::new(crate::storage::db::install::ShardStage::new(shard_id, now)?);
    let mut roots: Vec<(String, L2LockEntry)> = selected_roots
        .into_values()
        .map(|(entry, _, _)| (bs58::encode(entry.t_id).into_string(), entry))
        .collect();
    roots.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    append_reconciled_hmc(&stage, &roots)?;
    let mut hmc: Vec<(String, L2LockEntry)> = selected_hmc
        .into_values()
        .map(|(tag, entry, _, _)| (tag, entry))
        .collect();
    hmc.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    append_reconciled_hmc(&stage, &hmc)?;
    let digest = stage.digest()?;
    Ok(Some((stage, digest, min_witnesses)))
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

    #[test]
    fn test_reconcile_prefers_higher_confirmation_class_over_lower_hash() {
        use crate::network::framing::SyncPayload;
        use crate::storage::db::install::ShardStage;
        use crate::storage::db::support::ConfirmationSupport;
        use crate::storage::RedbStorage;
        use ed25519_dalek::Signer;

        let temp = tempdir().unwrap();
        let target = Arc::new(RedbStorage::open(&temp.path().join("target.redb")).unwrap());
        let now = 1_000u64;

        let author = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut root = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-voucher-reconcile".into(),
            t_id: [1u8; 32],
            sender_ephemeral_pub: author.verifying_key().to_bytes(),
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 1,
            created_at_ms: now,
            deletable_at: Some("600000".into()),
            privacy_guard: None,
        };
        let root_tag = bs58::encode(root.t_id).into_string();
        root.layer2_signature = author
            .sign(&crate::api::hmc::calculate_l2_payload_hash_for_entry(&root, &root_tag))
            .to_bytes();
        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
        );

        let spend_tag = "test-spend-tag";
        let parent = *blake3::hash(spend_tag.as_bytes()).as_bytes();

        let mut spend_1 = root.clone();
        spend_1.t_id = [2; 32];
        spend_1.deletable_at = None;
        spend_1.layer2_signature = author
            .sign(&crate::api::hmc::calculate_l2_payload_hash_for_entry(&spend_1, spend_tag))
            .to_bytes();

        let mut spend_2 = root.clone();
        spend_2.t_id = [3; 32];
        spend_2.deletable_at = None;
        spend_2.layer2_signature = author
            .sign(&crate::api::hmc::calculate_l2_payload_hash_for_entry(&spend_2, spend_tag))
            .to_bytes();

        let hash_1 = crate::storage::compute_hmc_canonical_hash(
            &parent,
            &spend_1.sender_ephemeral_pub,
            &spend_1.t_id,
        );
        let hash_2 = crate::storage::compute_hmc_canonical_hash(
            &parent,
            &spend_2.sender_ephemeral_pub,
            &spend_2.t_id,
        );

        let (winner_class2, loser_class1) = if hash_1 > hash_2 {
            // spend_1 has higher hash -> give it class 2!
            (spend_1, spend_2)
        } else {
            (spend_2, spend_1)
        };

        // stage_a has class 2 for winner_class2
        let stage_a = Arc::new(ShardStage::new(shard, now).unwrap());
        let fact_a = ConfirmationSupport {
            parent,
            child: winner_class2.t_id,
            class: 2,
            root_valid_until_ms: 600_000,
            verified_context: [77; 32],
        };
        stage_a
            .append(SyncPayload {
                hmc_locks: vec![
                    (root_tag.clone(), root.clone()),
                    (spend_tag.to_string(), winner_class2.clone()),
                ],
                support: vec![(1, spend_tag.to_string(), fact_a)],
            })
            .unwrap();

        // stage_b has class 1 for loser_class1 (which has smaller hash!)
        let stage_b = Arc::new(ShardStage::new(shard, now).unwrap());
        let fact_b = ConfirmationSupport {
            parent,
            child: loser_class1.t_id,
            class: 1,
            root_valid_until_ms: 600_000,
            verified_context: [88; 32],
        };
        stage_b
            .append(SyncPayload {
                hmc_locks: vec![
                    (root_tag.clone(), root.clone()),
                    (spend_tag.to_string(), loser_class1.clone()),
                ],
                support: vec![(1, spend_tag.to_string(), fact_b)],
            })
            .unwrap();

        let stages = vec![stage_a, stage_b];
        let reconciled = reconcile_distributed_stage(shard, now, 1, &stages, &target)
            .unwrap()
            .expect("reconciled stage");
        let (reconciled_stage, _, _) = reconciled;

        // Verify which row was selected: by DEC-064 & DEC-022, Class 2 MUST beat Class 1 regardless of hash!
        let page = reconciled_stage.page(0).unwrap();
        let selected = page
            .payload
            .hmc_locks
            .iter()
            .find(|(tag, _)| tag == spend_tag)
            .expect("spend present");
        assert_eq!(
            selected.1.t_id, winner_class2.t_id,
            "Reconciliation must prefer higher confirmation class over lower canonical hash"
        );
    }

    #[test]
    fn test_unquorated_local_fact_is_not_laundered_into_stage() {
        use crate::network::framing::SyncPayload;
        use crate::storage::db::install::ShardStage;
        use crate::storage::RedbStorage;
        use ed25519_dalek::Signer;

        let temp = tempdir().unwrap();
        let target = Arc::new(RedbStorage::open(&temp.path().join("target.redb")).unwrap());
        let now = 1_000u64;

        let author = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut root = crate::api::hmc::L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test-voucher-reconcile-unquorated".into(),
            t_id: [1u8; 32],
            sender_ephemeral_pub: author.verifying_key().to_bytes(),
            layer2_signature: [0; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 1,
            created_at_ms: now,
            deletable_at: Some("600000".into()),
            privacy_guard: None,
        };
        let root_tag = bs58::encode(root.t_id).into_string();
        root.layer2_signature = author
            .sign(&crate::api::hmc::calculate_l2_payload_hash_for_entry(&root, &root_tag))
            .to_bytes();
        let shard = humoco_sim_core::types::canonical_voucher_shard(
            &humoco_sim_core::types::genesis_parent_bytes_from_tag(&root_tag),
        );

        // Put root into target storage
        target.put_hmc_lock(&root_tag, &root).unwrap();

        // Local node holds a solitary lock that has no remote quorum witnesses
        let local_tag = "local-spend-tag";
        let mut local_spend = root.clone();
        local_spend.t_id = [9u8; 32];
        local_spend.deletable_at = None;
        target.put_hmc_lock(local_tag, &local_spend).unwrap();

        // Remote stages hold a completely different lock with quorum (needed = 2)
        let remote_tag = "remote-spend-tag";
        let mut remote_spend = root.clone();
        remote_spend.t_id = [8u8; 32];
        remote_spend.deletable_at = None;
        remote_spend.layer2_signature = author
            .sign(&crate::api::hmc::calculate_l2_payload_hash_for_entry(&remote_spend, remote_tag))
            .to_bytes();

        let stage_1 = Arc::new(ShardStage::new(shard, now).unwrap());
        stage_1
            .append(SyncPayload {
                hmc_locks: vec![
                    (root_tag.clone(), root.clone()),
                    (remote_tag.to_string(), remote_spend.clone()),
                ],
                support: vec![],
            })
            .unwrap();

        let stage_2 = Arc::new(ShardStage::new(shard, now).unwrap());
        stage_2
            .append(SyncPayload {
                hmc_locks: vec![
                    (root_tag.clone(), root.clone()),
                    (remote_tag.to_string(), remote_spend.clone()),
                ],
                support: vec![],
            })
            .unwrap();

        let stages = vec![stage_1, stage_2];
        let reconciled = reconcile_distributed_stage(shard, now, 2, &stages, &target)
            .unwrap()
            .expect("reconciled stage");
        let (reconciled_stage, _, _) = reconciled;

        let page = reconciled_stage.page(0).unwrap();
        // The quorated remote row MUST be present
        assert!(page
            .payload
            .hmc_locks
            .iter()
            .any(|(tag, _)| tag == remote_tag));
        // The unquorated local row MUST NOT be injected into the network-reconciled stage
        assert!(
            !page
                .payload
                .hmc_locks
                .iter()
                .any(|(tag, _)| tag == local_tag),
            "Unquorated local lock must not be laundered into the quorated stage"
        );
    }
}
