use std::net::SocketAddr;
use humoco_sim_core::types::{ClusterResult, ShardDigestResponse, SimTime};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::storage::IngressOrigin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundAddrs {
    pub rpc_addr: SocketAddr,
    pub p2p_addr: SocketAddr,
}

pub struct NodeDaemon {
    config: NodeConfig,
    identity: NodeIdentity,
    cancel_token: CancellationToken,
    bound_addr_tx: Mutex<Option<tokio::sync::oneshot::Sender<BoundAddrs>>>,
}

impl NodeDaemon {
    /// Creates a new NodeDaemon instance with a fresh CancellationToken.
    pub fn new(config: NodeConfig, identity: NodeIdentity) -> Self {
        Self {
            config,
            identity,
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
            cancel_token,
            bound_addr_tx: Mutex::new(Some(tx)),
        }
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
        let storage = std::sync::Arc::new(crate::storage::RedbStorage::open(&db_path)?);
        let (engine, flush_handle) = crate::storage::DualTierEngine::new_with_token(
            storage.clone(),
            self.cancel_token.clone(),
        );
        // Cold-boot recovery: Load all records into RAM index without premature pruning.
        // Unverified host SystemTime must not be trusted before P2P median synchronization (Spec 07 / INV-1203).
        let _ = engine.recover_from_disk(humoco_sim_core::types::SimTime(0)).await;

        // Initialize PoW Engine and 3-Tier Access Controller
        let pow_engine = std::sync::Arc::new(crate::ingress::PowEngine::new(*self.identity.node_id(), 8));
        let tier_controller = std::sync::Arc::new(crate::ingress::TierController::new(storage.clone(), pow_engine.clone()));
        for peer in &self.config.f2f.peers {
            tier_controller.register_f2f_peer(peer);
        }
        for token in &self.config.f2f.tokens {
            tier_controller.register_f2f_peer(token);
        }

        // Initialize QUIC P2P PeerManager with F2F friends, resolved endpoints, and known peers
        let (configured_entries, trusted_pubkeys) = self.config.f2f.parse_peers();
        let configured_peers = crate::config::F2fConfig::resolve_peer_endpoints(&configured_entries).await;
        let dns_peers: Vec<crate::config::PeerConfigEntry> = configured_entries
            .into_iter()
            .filter(|e| e.is_hostname())
            .collect();
        let peer_manager = std::sync::Arc::new(crate::network::PeerManager::with_f2f_and_dns(
            configured_peers,
            trusted_pubkeys,
            dns_peers,
        ));

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

        info!("Initializing QUIC P2P transport...");

        let handler = std::sync::Arc::new(crate::network::NodeRequestHandler::with_peer_manager(
            engine.clone(),
            storage.clone(),
            self.identity.clone(),
            peer_manager.clone(),
        ));
        let transport = crate::network::QuicTransport::bind_with_options(
            self.config.network.p2p_listen_addr,
            &self.identity,
            peer_manager.clone(),
            handler,
            self.cancel_token.clone(),
        )?;

        let p2p_bound_addr = transport.local_addr()?;
        let accept_handle = transport.spawn_accept_loop();
        info!(
            bound_addr = ?p2p_bound_addr,
            "QUIC P2P transport running."
        );

        // --- Phase 3 Autonomous Background Motors ---

        // 1. F2F Heartbeat-Emitter (hourly with jitter, signed payload)
        let hb_pm = peer_manager.clone();
        let hb_transport = transport.clone();
        let hb_identity = self.identity.clone();
        let hb_cancel = self.cancel_token.clone();
        let hb_local_addr = p2p_bound_addr;
        let heartbeat_handle = tokio::spawn(async move {
            let mut seq: u64 = 0;
            loop {
                let sleep_secs = crate::network::PeerManager::heartbeat_jitter_secs();
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
                        let node_id = *hb_identity.node_id();
                        for peer_addr in peers {
                            if hb_cancel.is_cancelled() { break; }
                            seq = seq.wrapping_add(1);
                            match hb_transport.send_heartbeat_to(peer_addr, node_id, hb_local_addr, seq).await {
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

        // 2. TTL-Pruning-Ticker (every 30 seconds, Zero State Bloat, Spec 11: net_time_ms)
        let prune_engine = engine.clone();
        let prune_cancel = self.cancel_token.clone();
        let prune_pm = peer_manager.clone();
        let ttl_prune_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = prune_cancel.cancelled() => {
                        info!("TTL pruning ticker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let now_ms = prune_pm.net_time_ms();
                        match prune_engine.prune_expired(SimTime(now_ms)).await {
                            Ok(pruned) => {
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

        // 3. Network-Thermometer & Quota Ticker (Spec 09: daily rolling update of 28-day ring buffer)
        let thermo_tier = tier_controller.clone();
        let thermo_storage = storage.clone();
        let thermo_pm = peer_manager.clone();
        let thermo_cancel = self.cancel_token.clone();
        let quota_ticker_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86_400));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // Initial tick
            loop {
                tokio::select! {
                    _ = thermo_cancel.cancelled() => {
                        info!("Network thermometer daily quota ticker shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let now_ms = thermo_pm.net_time_ms();
                        let valid_locks = thermo_storage.all_valid_locks(now_ms).unwrap_or_default();
                        let total_byte_years: u64 = valid_locks.iter()
                            .map(|(rec, _)| {
                                let ttl_sec = rec.valid_until.0.saturating_sub(rec.created_at.0) / 1000;
                                humoco_sim_core::quota::ByteYears::from_ttl_seconds(ttl_sec)
                            })
                            .sum();
                        let daily_median = total_byte_years.max(humoco_sim_core::quota::HARD_FLOOR_BASELINE_DAILY);
                        thermo_tier.record_daily_median(daily_median);
                        let daily_read_median = humoco_sim_core::quota::HARD_FLOOR_READ_BASELINE_DAILY;
                        thermo_tier.record_daily_read_median(daily_read_median);
                        let ncb = thermo_tier.effective_ncb();
                        let ncb_read = thermo_tier.effective_read_ncb();
                        debug!(daily_median, ncb, daily_read_median, ncb_read, "Network thermometer recorded daily medians to 28-day ring buffers");
                    }
                }
            }
        });

        // 3.5 Betreiber-Alerting (Telegram & Webhook) mit 15-min Hysterese und 15-min Intervall
        let alert_config = self.config.alerts.clone();
        let alert_data_dir = self.config.storage.data_dir.clone();
        let alert_pm = peer_manager.clone();
        let alert_cancel = self.cancel_token.clone();
        let alert_lifecycle = self.config.lifecycle.clone();
        let alert_handle = tokio::spawn(async move {
            // 15-Minuten Startup-Hysterese
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

        // 3. Non-blocking Recurring Shard-Digest Pull-Sync & Bootstrap Motor
        let sync_pm = peer_manager.clone();
        let sync_transport = transport.clone();
        let sync_engine = engine.clone();
        let sync_storage = storage.clone();
        let sync_cancel = self.cancel_token.clone();
        let shard_sync_handle = tokio::spawn(async move {
            let sync_notify = sync_pm.sync_notifier();
            let is_syncing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

            // Small initial delay to let accept loop and initial peer connections settle
            tokio::select! {
                _ = sync_cancel.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
            }
            if !sync_cancel.is_cancelled() {
                if let Err(e) = run_shard_digest_pull_sync(&sync_transport, &sync_pm, &sync_engine, &sync_storage, &sync_cancel).await {
                    debug!(error=%e, "Initial shard sync finished with note");
                }
            }

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // consume initial tick

            loop {
                tokio::select! {
                    _ = sync_cancel.cancelled() => {
                        info!("Shard sync motor shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        if !is_syncing.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            let transport = sync_transport.clone();
                            let pm = sync_pm.clone();
                            let eng = sync_engine.clone();
                            let stor = sync_storage.clone();
                            let cancel = sync_cancel.clone();
                            let syncing_flag = is_syncing.clone();
                            tokio::spawn(async move {
                                let _ = run_shard_digest_pull_sync(&transport, &pm, &eng, &stor, &cancel).await;
                                syncing_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                            });
                        }
                    }
                    _ = sync_notify.notified() => {
                        // Debounce window (5s) to coalesce rapid bursts of peer events and prevent thundering herd
                        tokio::select! {
                            _ = sync_cancel.cancelled() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                        }
                        if sync_cancel.is_cancelled() { break; }
                        if !is_syncing.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            let transport = sync_transport.clone();
                            let pm = sync_pm.clone();
                            let eng = sync_engine.clone();
                            let stor = sync_storage.clone();
                            let cancel = sync_cancel.clone();
                            let syncing_flag = is_syncing.clone();
                            tokio::spawn(async move {
                                let _ = run_shard_digest_pull_sync(&transport, &pm, &eng, &stor, &cancel).await;
                                syncing_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                            });
                        }
                    }
                }
            }
        });

        // Initialize REST API Router and HTTP Server
        let app_state = crate::api::AppState {
            engine: engine.clone(),
            storage: storage.clone(),
            identity: self.identity.clone(),
            tier_controller,
            pow_engine,
            peer_manager: Some(peer_manager.clone()),
            transport: Some(transport.clone()),
            start_time: std::time::Instant::now(),
            metrics: std::sync::Arc::new(crate::api::metrics::NodeMetrics::default()),
            lifecycle: self.config.lifecycle.clone(),
            network_id: self.config.network.network_id,
            shard_query_depth: self.config.network.shard_query_depth,
        };
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
        let rpc_handle = tokio::spawn(async move {
            if let Err(err) = rpc_server.await {
                tracing::error!(error = %err, "REST API HTTP server encountered an error");
            }
        });

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
        );
        let control_handle = tokio::spawn(async move {
            if let Err(err) = control_server.run().await {
                tracing::error!(error = %err, "Control socket server encountered an error");
            }
        });

        // Wait for cancellation token, Ctrl+C (SIGINT), or SIGTERM (Unix)
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|err| NodeError::Daemon(format!("Failed to register SIGTERM handler: {err}")))?;

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
        let _ = accept_handle.await;
        let _ = rpc_handle.await;
        let _ = control_handle.await;
        let _ = heartbeat_handle.await;
        let _ = ttl_prune_handle.await;
        let _ = quota_ticker_handle.await;
        let _ = shard_sync_handle.await;
        let _ = malus_decay_handle.await;
        let _ = dns_re_resolve_handle.await;
        let _ = alert_handle.await;
        let _ = flush_handle.await;
        info!("HuMoCo node daemon stopped.");
        Ok(())
    }
}

/// # Architectural Invariant: BFT Shard-Digest Pull vs. Random Storage Polling (Spec 03 & KISS)
///
/// Non-blocking shard digest and bootstrap pull-sync. In small networks (N < 20) or when
/// the local node is empty, pulls active locks directly from candidate peers. In sharded
/// networks (N >= 20), queries known shard peers for `ShardDigestRequest` and pulls data
/// via `ActiveSyncRequest` on divergence.
///
/// Why this 2-phase pull is mathematically sufficient (Spec 03 & KISS): The digest computed
/// by `humoco_sim_core::crypto::compute_shard_digest_at` is a canonical BLAKE3 over the
/// sorted active lock set per shard. Equality of digests proves equality of sets under
/// collision resistance; a single 32-byte comparison per shard replaces unbounded random
/// probing. The daemon therefore avoids continuous random storage polling — which would
/// need O(N) round trips, add non-deterministic disk I/O, and never give a convergence
/// proof — and instead relies on the periodic 60s ticker plus event-driven `sync_notifier`
/// with 5s debounce. This is the KISS-minimal sync that still guarantees deterministic
/// partition healing (dominant-quorum pull) without background polling loops.
async fn run_shard_digest_pull_sync(
    transport: &crate::network::QuicTransport,
    peer_manager: &crate::network::PeerManager,
    engine: &crate::storage::DualTierEngine,
    storage: &std::sync::Arc<crate::storage::RedbStorage>,
    cancel_token: &CancellationToken,
) -> Result<(), NodeError> {
    // Gather candidates
    let candidate_addrs = peer_manager.shard_sync_addrs().await;
    if candidate_addrs.is_empty() {
        debug!("Shard digest sync: no known shard peers, skipping");
        return Ok(());
    }
    let total_known = candidate_addrs.len() + 1; // include self
    let now_ms = peer_manager.net_time_ms();

    let local_valid_locks = storage.all_valid_locks(now_ms).unwrap_or_default();
    let local_valid_hmc = storage.all_valid_hmc_locks(now_ms).unwrap_or_default();
    let ram_locks_count = engine.ram.read().await.len();
    let hmc_ram_count = engine.hmc_ram.read().await.locks.len();
    let is_local_empty = local_valid_locks.is_empty()
        && local_valid_hmc.is_empty()
        && ram_locks_count == 0
        && hmc_ram_count == 0;

    let mut seq: u64 = 1;

    // Bootstrap / Small Network Sync (N < 20 or empty node):
    // In small networks or cold boot, directly pull active locks from available peers (R = N)
    if total_known < 20 || is_local_empty {
        debug!(total_known, is_local_empty, "Performing active sync pull across candidate peers (bootstrap / N < 20 mode)");
        for addr in &candidate_addrs {
            if cancel_token.is_cancelled() {
                return Ok(());
            }
            let conn = match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                transport.connect_peer(*addr),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    debug!(peer=%addr, error=%e, "Bootstrap ActiveSync: connect failed");
                    continue;
                }
                Err(_) => {
                    debug!(peer=%addr, "Bootstrap ActiveSync: connect timeout");
                    continue;
                }
            };

            let sync_payload = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                transport.request_active_sync(&conn, seq),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    debug!(peer=%addr, error=%e, "Bootstrap ActiveSync: request failed");
                    continue;
                }
                Err(_) => {
                    debug!(peer=%addr, "Bootstrap ActiveSync: request timeout");
                    continue;
                }
            };
            seq = seq.wrapping_add(1);
            let now_ms2 = peer_manager.net_time_ms();

            for (rec, root_valid) in sync_payload.locks {
                if cancel_token.is_cancelled() { break; }
                let _ = engine
                    .ingress_lock_with_origin(rec, SimTime(now_ms2), SimTime(root_valid), IngressOrigin::PartitionSync)
                    .await;
            }
            for (tag, entry) in sync_payload.hmc_locks {
                if cancel_token.is_cancelled() { break; }
                let _ = engine
                    .ingress_hmc_lock_with_origin(tag, entry, IngressOrigin::PartitionSync, None)
                    .await;
            }
        }
        info!("Bootstrap active sync pull completed");
        return Ok(());
    }

    // Dominant Quorum Shard Digest Sync (N >= 20):
    // Collect all shard IDs for which the node has local entries (at least 0, plus all shard IDs from local locks and HMC voucher tags)
    let mut shard_ids: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    shard_ids.insert(0);

    for (rec, _) in &local_valid_locks {
        let sid = u16::from_be_bytes([rec.parent_lock[0], rec.parent_lock[1]]);
        shard_ids.insert(sid);
    }
    for (rec, _) in engine.ram.read().await.all_locks() {
        let sid = u16::from_be_bytes([rec.parent_lock[0], rec.parent_lock[1]]);
        shard_ids.insert(sid);
    }

    for (tag, _) in &local_valid_hmc {
        let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
        shard_ids.insert(sid);
    }
    for tag in engine.hmc_ram.read().await.locks.keys() {
        let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
        shard_ids.insert(sid);
    }

    for shard_id in shard_ids {
        if cancel_token.is_cancelled() {
            return Ok(());
        }

        // Compute local digest for comparison for this shard
        let mut locks: Vec<humoco_sim_core::types::LockRecord> = storage
            .all_valid_locks(now_ms)
            .unwrap_or_default()
            .into_iter()
            .map(|(rec, _)| rec)
            .collect();
        for (rec, _) in engine.ram.read().await.all_locks() {
            if !locks.iter().any(|l| l.parent_lock == rec.parent_lock) {
                locks.push(rec);
            }
        }
        let mut hmc_locks_all = storage.all_valid_hmc_locks(now_ms).unwrap_or_default();
        for (tag, entry) in &engine.hmc_ram.read().await.locks {
            if !hmc_locks_all.iter().any(|(t, _)| t == tag) {
                hmc_locks_all.push((tag.clone(), entry.clone()));
            }
        }
        for (tag, entry) in hmc_locks_all {
            let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
            if !locks.iter().any(|l| l.parent_lock == parent_bytes) {
                let valid_until_ms = entry
                    .deletable_at
                    .as_deref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| now_ms + 365 * 24 * 3600 * 1000);
                locks.push(humoco_sim_core::types::LockRecord::new(
                    parent_bytes,
                    entry.sender_ephemeral_pub,
                    entry.t_id.to_vec(),
                    humoco_sim_core::types::SimTime(0),
                    humoco_sim_core::types::SimTime(valid_until_ms),
                ));
            }
        }

        let local_digest = humoco_sim_core::crypto::compute_shard_digest_at(
            shard_id,
            &locks,
            SimTime(now_ms),
        );

        let mut peer_digests: Vec<([u8; 32], SocketAddr, u64)> = Vec::new();

        for addr in &candidate_addrs {
            if cancel_token.is_cancelled() {
                return Ok(());
            }
            // Connect with timeout to avoid blocking
            let conn = match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                transport.connect_peer(*addr),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    debug!(peer=%addr, error=%e, "Shard digest: connect failed");
                    continue;
                }
                Err(_) => {
                    debug!(peer=%addr, "Shard digest: connect timeout");
                    continue;
                }
            };

            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                transport.request_shard_digest(&conn, shard_id, seq),
            )
            .await
            {
                Ok(Ok((digest, count))) => {
                    peer_digests.push((digest, *addr, count));
                }
                Ok(Err(e)) => {
                    debug!(peer=%addr, error=%e, "Shard digest request failed");
                }
                Err(_) => {
                    debug!(peer=%addr, "Shard digest request timeout");
                }
            }
            seq = seq.wrapping_add(1);
        }

        if peer_digests.is_empty() {
            continue;
        }

        let responses: Vec<ShardDigestResponse> = peer_digests
            .iter()
            .enumerate()
            .map(|(idx, (digest, _addr, count))| ShardDigestResponse {
                peer_id: idx as u16,
                digest: *digest,
                lock_count: *count as u32,
            })
            .collect();
        let cluster = humoco_sim_core::types::evaluate_digest_clusters(&responses, total_known);
        let (dominant_digest, dominant_addrs) = match cluster {
            ClusterResult::DominantQuorum { digest, peers: qpeers, .. } => {
                let addrs: Vec<SocketAddr> = qpeers
                    .iter()
                    .filter_map(|pid| {
                        let idx = *pid as usize;
                        peer_digests.get(idx).map(|(_, addr, _)| *addr)
                    })
                    .collect();
                (digest, addrs)
            }
            ClusterResult::InsufficientQuorum { max_votes, backoff_ms } => {
                debug!(shard_id, max_votes, backoff_ms, "Shard digest sync: insufficient quorum, backing off");
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                continue;
            }
        };

        if dominant_digest == local_digest {
            debug!(shard_id, "Shard digest sync: converged via dominant quorum, no pull needed");
            continue;
        }

        info!(shard_id, divergent = dominant_addrs.len(), "Shard digest divergence detected via evaluate_digest_clusters, pulling active sync");

        // Pull missing locks from dominant quorum peers via ActiveSyncRequest
        for addr in dominant_addrs {
            if cancel_token.is_cancelled() {
                break;
            }
            let conn = match transport.connect_peer(addr).await {
                Ok(c) => c,
                Err(e) => {
                    debug!(peer=%addr, error=%e, "ActiveSync connect failed");
                    continue;
                }
            };
            let sync_payload = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                transport.request_active_sync(&conn, seq),
            )
            .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    debug!(peer=%addr, error=%e, "ActiveSync request failed");
                    continue;
                }
                Err(_) => {
                    debug!(peer=%addr, "ActiveSync request timeout");
                    continue;
                }
            };
            seq = seq.wrapping_add(1);
            let now_ms2 = peer_manager.net_time_ms();

            for (rec, root_valid) in sync_payload.locks {
                if cancel_token.is_cancelled() { break; }
                let _ = engine
                    .ingress_lock_with_origin(rec, SimTime(now_ms2), SimTime(root_valid), IngressOrigin::PartitionSync)
                    .await;
            }
            for (tag, entry) in sync_payload.hmc_locks {
                if cancel_token.is_cancelled() { break; }
                let _ = engine
                    .ingress_hmc_lock_with_origin(tag, entry, IngressOrigin::PartitionSync, None)
                    .await;
            }
        }
    }

    info!("Shard digest pull-sync completed");
    Ok(())
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

        let handle = tokio::spawn(async move {
            daemon.run().await
        });

        // Trigger cancellation
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        cancel_token.cancel();

        let result = handle.await.expect("task join");
        assert!(matches!(result, Ok(())), "daemon run must be Ok, got {:?}", result);
    }
}
