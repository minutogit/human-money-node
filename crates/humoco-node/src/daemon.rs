use std::net::SocketAddr;
use std::sync::Arc;
use humoco_sim_core::types::{ClusterResult, ShardDigestResponse, SimTime};
use rand::Rng;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::NodeConfig;
use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::storage::IngressOrigin;
use ed25519_dalek::Signer;

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
        // Decouple flush worker cancellation from master daemon cancellation so that
        // HTTP/QUIC listeners can finish in-flight requests before the flush worker drains.
        let flush_cancel_token = tokio_util::sync::CancellationToken::new();
        let (engine, flush_handle) = crate::storage::DualTierEngine::new_with_token(
            storage.clone(),
            flush_cancel_token.clone(),
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
        let initial_sync_ready = configured_peers.is_empty();
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
                    info!(persisted = banned.len(), imported = added, "Loaded persisted permanent bans into PeerManager");
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

        let is_sync_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(initial_sync_ready));

        let handler = std::sync::Arc::new(
            crate::network::NodeRequestHandler::with_peer_manager(
                engine.clone(),
                storage.clone(),
                self.identity.clone(),
                peer_manager.clone(),
            )
            .with_tier_controller(tier_controller.clone())
            .with_sync_ready(is_sync_ready.clone())
            .with_network_id(self.config.network.network_id),
        );
        let mut transport = crate::network::QuicTransport::bind_with_options(
            self.config.network.p2p_listen_addr,
            &self.identity,
            peer_manager.clone(),
            handler,
            self.cancel_token.clone(),
        )?;
        transport.set_sync_ready_handle(is_sync_ready.clone());
        transport.set_sync_ready(initial_sync_ready);

        let p2p_bound_addr = transport.local_addr()?;
        let accept_handle = transport.spawn_accept_loop();
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

        // 2. TTL-Pruning-Ticker (every 30 seconds, Zero State Bloat, Spec 11: net_time_ms)
        let prune_engine = engine.clone();
        let prune_cancel = self.cancel_token.clone();
        let prune_pm = peer_manager.clone();
        let prune_interval_secs = if is_simulation { 2 } else { 30 };
        let ttl_prune_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(prune_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            // # Architectural Invariant (A03): Cold-Boot Pruning Clock Anchor
            // Initialize anchor immediately to current net time so first tick cannot suffer
            // from uninspected NTP forward jumps without F2F consensus (Spec 07 / INV-1203).
            let mut last_prune_anchor = prune_pm.net_time_ms();
            prune_engine.last_prune_anchor.store(last_prune_anchor, std::sync::atomic::Ordering::Relaxed);

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

        // 3. Non-blocking recurring shard digest pull sync and bootstrap
        let sync_pm = peer_manager.clone();
        let sync_transport = transport.clone();
        let sync_engine = engine.clone();
        let sync_storage = storage.clone();
        let sync_cancel = self.cancel_token.clone();
        let sync_identity = self.identity.clone();
        let sync_ready_flag = is_sync_ready.clone();
        let shard_sync_handle = tokio::spawn(async move {
            let sync_notify = sync_pm.sync_notifier();
            let is_syncing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

            // Small initial delay to let accept loop and initial peer connections settle
            let initial_delay_ms = if is_simulation || initial_sync_ready { 10 } else { 50 };
            tokio::select! {
                _ = sync_cancel.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_millis(initial_delay_ms)) => {}
            }
            if !sync_cancel.is_cancelled() {
                if let Err(e) = run_shard_digest_pull_sync(
                    &sync_transport,
                    &sync_pm,
                    &sync_engine,
                    &sync_storage,
                    &sync_identity,
                    &sync_ready_flag,
                    &sync_cancel,
                )
                .await
                {
                    debug!(error=%e, "Initial shard sync finished with note");
                }
            }

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // consume initial tick

            let mut sync_tasks = tokio::task::JoinSet::new();

            loop {
                // Drain any completed sync tasks to prevent task handle accumulation
                while sync_tasks.try_join_next().is_some() {}

                tokio::select! {
                    _ = sync_cancel.cancelled() => {
                        info!("Shard sync motor shutting down - aborting in-flight sync tasks");
                        sync_tasks.abort_all();
                        break;
                    }
                    _ = interval.tick() => {
                        if !is_syncing.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            let transport = sync_transport.clone();
                            let pm = sync_pm.clone();
                            let eng = sync_engine.clone();
                            let stor = sync_storage.clone();
                            let cancel = sync_cancel.clone();
                            let ident = sync_identity.clone();
                            let ready_flag = sync_ready_flag.clone();
                            let syncing_flag = is_syncing.clone();
                            sync_tasks.spawn(async move {
                                let _ = run_shard_digest_pull_sync(&transport, &pm, &eng, &stor, &ident, &ready_flag, &cancel).await;
                                syncing_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                            });
                        }
                    }
                    _ = sync_notify.notified() => {
                        // Debounce window (5s) to coalesce rapid bursts of peer events and prevent thundering herd
                        tokio::select! {
                            _ = sync_cancel.cancelled() => {
                                sync_tasks.abort_all();
                                break;
                            }
                            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                        }
                        if sync_cancel.is_cancelled() {
                            sync_tasks.abort_all();
                            break;
                        }
                        if !is_syncing.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            let transport = sync_transport.clone();
                            let pm = sync_pm.clone();
                            let eng = sync_engine.clone();
                            let stor = sync_storage.clone();
                            let cancel = sync_cancel.clone();
                            let ident = sync_identity.clone();
                            let ready_flag = sync_ready_flag.clone();
                            let syncing_flag = is_syncing.clone();
                            sync_tasks.spawn(async move {
                                let _ = run_shard_digest_pull_sync(&transport, &pm, &eng, &stor, &ident, &ready_flag, &cancel).await;
                                syncing_flag.store(false, std::sync::atomic::Ordering::SeqCst);
                            });
                        }
                    }
                }
            }
        });

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
        let system_stats = Arc::new(crate::api::SystemStatsCollector::new(&self.config.storage.data_dir));
        let stats_handle = system_stats.clone().spawn_background_collector(
            node_metrics.clone(),
            Some(peer_manager.clone()),
            self.cancel_token.clone(),
        );

        // Initialize History Sampler & Security Event Log (Phase 2 & Phase 5)
        let history_sampler = Arc::new(crate::api::HistorySampler::default());
        let event_log = Arc::new(crate::api::EventLog::default());

        // Load existing audit events on startup (Phase 5)
        match storage.load_recent_audit_events(100) {
            Ok(loaded_events) => {
                if !loaded_events.is_empty() {
                    tracing::info!("Loaded {} persistent audit events from storage", loaded_events.len());
                    event_log.populate(loaded_events);
                }
            }
            Err(err) => {
                warn!("Failed to load recent audit events from storage: {}", err);
            }
        }

        // Spawn background audit event persister task (Phase 5)
        let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel::<crate::api::events::EventItem>(100);
        event_log.set_persister(audit_tx);
        let persister_storage = storage.clone();
        tokio::spawn(async move {
            while let Some(event) = audit_rx.recv().await {
                if let Err(err) = persister_storage.insert_audit_event(&event) {
                    warn!("Failed to persist audit event #{}: {}", event.id, err);
                }
            }
        });

        event_log.record(
            crate::api::EventKind::System,
            crate::api::HealthLevel::Ok,
            format!("HuMoCo node daemon started (NodePubKey: {})", self.identity.node_id_bs58()),
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
        )
        .with_tier_controller(tier_controller.clone());
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
        let _ = shard_sync_handle.await;
        let _ = thermometer_handle.await;
        let _ = malus_decay_handle.await;
        let _ = dns_re_resolve_handle.await;
        let _ = alert_handle.await;
        let _ = stats_handle.await;
        let _ = history_handle.await;
        // Cancel the flush worker only after all listeners have finished in-flight requests,
        // ensuring the flush worker drains remaining operations before shutdown completes.
        flush_cancel_token.cancel();
        let _ = flush_handle.await;
        info!("HuMoCo node daemon stopped.");
        Ok(())
    }
}

/// # Architectural Invariant: BFT Shard Digest Pull vs. Random Storage Polling (Spec 03 & KISS)
///
/// Non-blocking shard digest and bootstrap pull-sync. In small networks (N < 20) or when
/// the local node is empty, pulls active locks directly from candidate peers. In sharded
/// networks (N >= 20), queries known shard peers for `ShardDigestRequest` and pulls data
/// via `ActiveSyncRequest` on divergence.
///
/// The shard digest is compact comparison information over the sorted active-lock
/// projection defined by `humoco_sim_core::crypto::compute_shard_digest_at`.
/// Equal digests compare that projection under collision resistance; they do not
/// prove full record equality, justified membership, preservation of every binding
/// vote, old-write closure or safe successor activation.
///
/// The periodic 60s ticker and event-driven `sync_notifier` with 5s debounce
/// schedule pull attempts without continuous random probing of storage keys.
/// This describes the existing synchronization mechanism, not a completed proof
/// of membership continuity or recovery signing readiness.
async fn run_shard_digest_pull_sync(
    transport: &crate::network::QuicTransport,
    peer_manager: &crate::network::PeerManager,
    engine: &crate::storage::DualTierEngine,
    storage: &std::sync::Arc<crate::storage::RedbStorage>,
    identity: &crate::identity::NodeIdentity,
    is_sync_ready: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancel_token: &CancellationToken,
) -> Result<(), NodeError> {
    // Gather candidates
    let candidate_addrs = peer_manager.shard_sync_addrs().await;
    if candidate_addrs.is_empty() {
        debug!("Shard digest sync: no known shard peers, skipping and marking ready");
        is_sync_ready.store(true, std::sync::atomic::Ordering::SeqCst);
        transport.set_sync_ready(true);
        peer_manager.set_local_sync_ready(true);
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

            let mut cursor: u64 = 0;
            let limit: usize = 500;
            loop {
                if cancel_token.is_cancelled() {
                    return Ok(());
                }
                let page_res = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    transport.request_active_sync_page(&conn, seq, cursor, limit),
                )
                .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        debug!(peer=%addr, error=%e, "Bootstrap ActiveSync page failed");
                        break;
                    }
                    Err(_) => {
                        debug!(peer=%addr, "Bootstrap ActiveSync page timeout");
                        break;
                    }
                };
                debug!(
                    peer = %addr,
                    locks_count = page_res.payload.locks.len(),
                    hmc_count = page_res.payload.hmc_locks.len(),
                    has_more = page_res.has_more,
                    "Bootstrap ActiveSync page received"
                );
                seq = seq.wrapping_add(1);
                let now_ms2 = peer_manager.net_time_ms();

                for (rec, root_valid) in page_res.payload.locks {
                    if cancel_token.is_cancelled() { break; }
                    let _ = engine
                        .ingress_lock_with_origin(rec, SimTime(now_ms2), SimTime(root_valid), IngressOrigin::PartitionSync)
                        .await;
                }
                for (tag, entry) in page_res.payload.hmc_locks {
                    if cancel_token.is_cancelled() { break; }
                    let _ = engine
                        .ingress_hmc_lock_with_origin(tag, entry, IngressOrigin::PartitionSync, None)
                        .await;
                }

                if !page_res.has_more {
                    break;
                }
                if let Some(next) = page_res.next_cursor {
                    if next <= cursor {
                        break;
                    }
                    cursor = next;
                } else {
                    cursor += limit as u64;
                }
            }
        }
        info!("Bootstrap active sync pull completed");
        is_sync_ready.store(true, std::sync::atomic::Ordering::SeqCst);
        transport.set_sync_ready(true);
        peer_manager.set_local_sync_ready(true);
        return Ok(());
    }

    // Dominant Quorum Shard Digest Sync (N >= 20):
    // Collect all candidate shard IDs (local entries, registered active shards, and shard 0)
    let mut candidate_shards: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    candidate_shards.insert(0);

    for (rec, _) in &local_valid_locks {
        let sid = u16::from_be_bytes([rec.parent_lock[0], rec.parent_lock[1]]);
        candidate_shards.insert(sid);
    }
    for (rec, _) in engine.ram.read().await.all_locks() {
        let sid = u16::from_be_bytes([rec.parent_lock[0], rec.parent_lock[1]]);
        candidate_shards.insert(sid);
    }

    for (tag, _) in &local_valid_hmc {
        let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
        candidate_shards.insert(sid);
    }
    for tag in engine.hmc_ram.read().await.locks.keys() {
        let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
        let sid = u16::from_be_bytes([parent_bytes[0], parent_bytes[1]]);
        candidate_shards.insert(sid);
    }

    for sid in peer_manager.get_active_shards().await {
        candidate_shards.insert(sid);
    }

    // Filter to shards where local node is in the Top-20 responsible nodes:
    let mut responsible_shards: Vec<u16> = Vec::new();
    for sid in candidate_shards {
        if peer_manager.is_local_committee_member(*identity.node_pubkey(), *identity.hrw_routing_id(), sid).await {
            responsible_shards.push(sid);
        }
    }

    // # Architectural Invariant: Spec 03, Deterministic Digest Pull-Sync
    //
    // `is_sync_ready` is set ONLY after proven shard-sync convergence (all
    // responsible shards matched the dominant quorum digest, or the divergent
    // pull completed). A premature `true` would open the PoS hot path on stale
    // state. `all_converged` starts true and flips to false on any empty peer
    // set, insufficient quorum, or failed pull page — readiness stays `false`
    // until the next ticker run converges.
    let mut all_converged = true;
    for shard_id in responsible_shards {
        if cancel_token.is_cancelled() {
            return Ok(());
        }
        // Compute local digest strictly for this shard_id
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
        // # Architectural Invariant: Spec 03, Deterministic Digest Pull-Sync
        //
        // HMC follow-up locks carry no own `deletable_at`; their TTL is strictly
        // inherited from the known voucher genesis root (Rule 10, Origin-Lock
        // Mandate). The old fallback `now_ms + 1 year` was wall-clock dependent:
        // two nodes computing the same shard digest at different times produced
        // different `valid_until` values, so digests never converged. Digests
        // MUST be time-independent: inherit deterministically, skip orphans with
        // unknown root (never invent TTL).
        let hmc_root_map: std::collections::HashMap<&str, u64> = {
            let mut m = std::collections::HashMap::new();
            for (_, e) in &hmc_locks_all {
                if let Some(v) = e.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()) {
                    m.entry(e.layer2_voucher_id.as_str()).or_insert(v);
                }
            }
            m
        };
        for (tag, entry) in &hmc_locks_all {
            let parent_bytes = *blake3::hash(tag.as_bytes()).as_bytes();
            if !locks.iter().any(|l| l.parent_lock == parent_bytes) {
                let valid_until_ms = entry
                    .deletable_at
                    .as_deref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| hmc_root_map.get(entry.layer2_voucher_id.as_str()).copied());
                let Some(valid_until_ms) = valid_until_ms else {
                    continue;
                };
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

        // Targeted Co-Shard Sync: query only Top-20 HRW responsible peers for this shard
        let top_peers = peer_manager.get_top_n_shards_for_lock(shard_id, 20).await;
        let query_addrs: Vec<SocketAddr> = if !top_peers.is_empty() {
            let mut addrs: Vec<SocketAddr> = top_peers
                .into_iter()
                .map(|(_, addr)| addr)
                .collect();
            if let Ok(local_addr) = transport.local_addr() {
                addrs.retain(|a| a != &local_addr);
            }
            if addrs.is_empty() {
                candidate_addrs.clone()
            } else {
                addrs
            }
        } else {
            candidate_addrs.clone()
        };

        let mut peer_digests: Vec<([u8; 32], SocketAddr, u64)> = Vec::new();

        for addr in &query_addrs {
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
            all_converged = false;
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
                all_converged = false;
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                continue;
            }
        };

        if dominant_digest == local_digest {
            debug!(shard_id, "Shard digest sync: converged via dominant quorum, no pull needed");
            continue;
        }

        info!(shard_id, divergent = dominant_addrs.len(), "Shard digest divergence detected via evaluate_digest_clusters, pulling bucketted active sync");

        // 5-Minuten Bucket Shard Sync (docs/PLAN_BUCKETED_SHARD_SYNC.md):
        // Statt den gesamten Shard blind herunterzuladen, fragen wir den dominanten Peer
        // nach den Merkle-Roots der 5-Minuten-Buckets der letzten 24h (288 Buckets) ab
        // und ziehen gezielt NUR die abweichenden Buckets nach!
        let mut shard_pull_ok = false;
        let curr_bucket = humoco_sim_core::types::timestamp_to_bucket_id(now_ms);
        let start_bucket = curr_bucket.saturating_sub(humoco_sim_core::types::BUCKETS_PER_DAY as u64);
        let bucket_count = (curr_bucket.saturating_sub(start_bucket) + 1).min(humoco_sim_core::types::BUCKETS_PER_DAY as u64) as u16;

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

            // Versuche zunächst den zielgerichteten Bucket-Range Sync
            let bucket_range_res = transport
                .request_shard_bucket_range(&conn, shard_id, start_bucket, bucket_count, seq)
                .await;
            seq = seq.wrapping_add(1);

            let divergent_buckets: Option<Vec<u64>> = match bucket_range_res {
                Ok(resp) => {
                    let mut diffs = Vec::new();
                    for peer_b in resp.buckets {
                        let local_b_digest = humoco_sim_core::crypto::compute_shard_bucket_digest(shard_id, peer_b.bucket_id, &locks);
                        if local_b_digest != peer_b.digest {
                            diffs.push(peer_b.bucket_id);
                        }
                    }
                    Some(diffs)
                }
                Err(e) => {
                    debug!(peer=%addr, error=%e, "ShardBucketRangeRequest failed, falling back to full shard sync");
                    None
                }
            };

            let buckets_to_sync: Vec<Option<u64>> = match divergent_buckets {
                Some(diffs) if !diffs.is_empty() => diffs.into_iter().map(Some).collect(),
                Some(_) => {
                    // Alle Buckets der letzten 24h stimmen überein
                    shard_pull_ok = true;
                    break;
                }
                None => vec![None], // Fallback auf Gesamtabgleich
            };

            let mut peer_pull_ok = true;
            for target_b in buckets_to_sync {
                let mut cursor: u64 = 0;
                let limit: usize = 500;
                loop {
                    if cancel_token.is_cancelled() { break; }
                    let page_res = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        transport.request_active_sync_page_for_bucket(&conn, seq, cursor, limit, target_b),
                    )
                    .await
                    {
                        Ok(Ok(p)) => p,
                        Ok(Err(e)) => {
                            debug!(peer=%addr, target_b=?target_b, error=%e, "ActiveSync page request failed");
                            peer_pull_ok = false;
                            break;
                        }
                        Err(_) => {
                            debug!(peer=%addr, target_b=?target_b, "ActiveSync page request timeout");
                            peer_pull_ok = false;
                            break;
                        }
                    };
                    seq = seq.wrapping_add(1);
                    let now_ms2 = peer_manager.net_time_ms();

                    for (rec, root_valid) in page_res.payload.locks {
                        if cancel_token.is_cancelled() { break; }
                        let _ = engine
                            .ingress_lock_with_origin(rec, SimTime(now_ms2), SimTime(root_valid), IngressOrigin::PartitionSync)
                            .await;
                    }
                    for (tag, entry) in page_res.payload.hmc_locks {
                        if cancel_token.is_cancelled() { break; }
                        let _ = engine
                            .ingress_hmc_lock_with_origin(tag, entry, IngressOrigin::PartitionSync, None)
                            .await;
                    }

                    if !page_res.has_more {
                        break;
                    }
                    if let Some(next) = page_res.next_cursor {
                        if next <= cursor {
                            break;
                        }
                        cursor = next;
                    } else {
                        cursor += limit as u64;
                    }
                }
                if !peer_pull_ok {
                    break;
                }
            }

            if peer_pull_ok {
                shard_pull_ok = true;
                break;
            }
        }
        if !shard_pull_ok {
            all_converged = false;
        }
    }

    if all_converged {
        is_sync_ready.store(true, std::sync::atomic::Ordering::SeqCst);
        transport.set_sync_ready(true);
        peer_manager.set_local_sync_ready(true);
        info!("Shard digest pull-sync completed (converged)");
    } else {
        info!("Shard digest pull-sync incomplete: convergence pending, is_sync_ready stays false");
    }
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

        let handle = tokio::spawn(async move {
            daemon.run().await
        });

        // Let simulation tickers tick
        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
        cancel_token.cancel();

        let result = handle.await.expect("task join");
        assert!(matches!(result, Ok(())), "daemon run in simulation mode must be Ok, got {:?}", result);
    }
}
