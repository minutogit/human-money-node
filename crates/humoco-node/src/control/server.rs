use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::control::types::{
    parse_account_tag, ControlRequest, ControlResponse, PeerStatusDto, RecentLockSummaryDto,
};
use crate::error::NodeError;
use crate::identity::NodeIdentity;
use crate::network::PeerManager;
use crate::storage::{DualTierEngine, RedbStorage};

#[derive(Clone)]
struct ControlState {
    storage: Arc<RedbStorage>,
    engine: DualTierEngine,
    peer_manager: Arc<PeerManager>,
    identity: NodeIdentity,
    data_dir: PathBuf,
    start_time: std::time::Instant,
    cancel_token: CancellationToken,
    tier_controller: Option<Arc<crate::ingress::TierController>>,
    lifecycle: Option<Arc<super::lifecycle::ShutdownLifecycle>>,
}

pub struct ControlServer {
    socket_path: PathBuf,
    state: ControlState,
}

impl ControlServer {
    pub fn new(
        socket_path: PathBuf,
        storage: Arc<RedbStorage>,
        engine: DualTierEngine,
        peer_manager: Arc<PeerManager>,
        identity: NodeIdentity,
        data_dir: PathBuf,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            socket_path,
            state: ControlState {
                storage,
                engine,
                peer_manager,
                identity,
                data_dir,
                start_time: std::time::Instant::now(),
                cancel_token,
                tier_controller: None,
                lifecycle: None,
            },
        }
    }

    /// Installs the identity of the daemon owning the entire storage lifecycle.
    pub fn with_shutdown_lifecycle(mut self, lifecycle: Arc<super::lifecycle::ShutdownLifecycle>) -> Self {
        self.state.lifecycle = Some(lifecycle);
        self
    }

    pub fn with_tier_controller(mut self, tier_controller: Arc<crate::ingress::TierController>) -> Self {
        self.state.tier_controller = Some(tier_controller);
        self
    }

    pub fn with_start_time(mut self, start_time: std::time::Instant) -> Self {
        self.state.start_time = start_time;
        self
    }

    pub async fn run(&self) -> Result<(), NodeError> {
        // Remove stale socket file if present
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| NodeError::IoWithPath {
                    path: parent.to_path_buf(),
                    source: err,
                })?;
            }
        }

        let listener = UnixListener::bind(&self.socket_path).map_err(|err| {
            NodeError::IoWithPath {
                path: self.socket_path.clone(),
                source: err,
            }
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!(
            socket_path = %self.socket_path.display(),
            "Control RPC Unix domain socket server started"
        );

        let cancel = self.state.cancel_token.clone();

        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = connections.join_next(), if !connections.is_empty() => {}
                _ = cancel.cancelled() => {
                    info!("Control RPC server stopping on cancellation signal");
                    break;
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let state = self.state.clone();
                            if connections.len() >= 64 { continue; }
                            connections.spawn(async move {
                                if let Err(err) = Self::handle_connection(stream, state).await {
                                    debug!(error = %err, "Control connection closed or failed");
                                }
                            });
                        }
                        Err(err) => {
                            warn!(error = %err, "Error accepting control connection");
                        }
                    }
                }
            }
        }

        connections.abort_all();
        while connections.join_next().await.is_some() {}
        // Cleanup socket file on exit
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        Ok(())
    }

    async fn handle_connection(
        stream: tokio::net::UnixStream,
        state: ControlState,
    ) -> Result<(), NodeError> {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = tokio::select! {
                _ = state.cancel_token.cancelled() => {
                    break;
                }
                read_res = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    async {
                        use tokio::io::AsyncReadExt;
                        let mut limited = (&mut buf_reader).take(16 * 1024 + 1);
                        limited.read_line(&mut line).await
                    },
                ) => {
                    match read_res {
                        Ok(Ok(n)) => {
                            if line.len() > 16 * 1024 {
                                tracing::warn!("UDS line limit exceeded (16 KiB), dropping oversized request");
                                // Prevent OOM: clear oversized buffer and close connection
                                line.clear();
                                break;
                            }
                            n
                        },
                        Ok(Err(err)) => return Err(NodeError::Io(err)),
                        Err(_) => {
                            // Timeout waiting for request from client: close connection to prevent zombie tasks
                            break;
                        }
                    }
                }
            };

            if bytes_read == 0 {
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let request: ControlRequest = match serde_json::from_str(trimmed) {
                Ok(req) => req,
                Err(err) => {
                    let err_resp = ControlResponse::Error {
                        message: format!("Malformed request JSON: {}", err),
                    };
                    let mut payload = serde_json::to_string(&err_resp).unwrap_or_default();
                    payload.push('\n');
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        writer.write_all(payload.as_bytes()),
                    )
                    .await;
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        writer.flush(),
                    )
                    .await;
                    continue;
                }
            };

            let response = match request {
                ControlRequest::GetStatus => {
                    let uptime_sec = state.start_time.elapsed().as_secs();
                    let active_locks = state.engine.ram.read().await.len();
                    let peers_connected = state.peer_manager.connected_peer_count().await;
                    let hrw_hex = state.identity.hrw_routing_id_hex();
                    let t0 = state.identity.t0();
                    let nonce = state.identity.nonce();
                    let incubation_until_ms = if t0 == 0 {
                        None
                    } else {
                        Some(t0.saturating_add(24 * 3600).saturating_mul(1000))
                    };
                    let own_work = state.identity.work_score();
                    let net_median = state.peer_manager.calculate_network_median_work();
                    let headroom_pct = if net_median > 0 {
                        let ratio = (own_work as f64) / (net_median as f64);
                        Some((ratio * 100.0).round() as u32)
                    } else {
                        Some(100)
                    };
                    let ticket_outdated = state.peer_manager.is_ticket_outdated();
                    ControlResponse::Status {
                        signing_history_corrupt: !state.storage.is_signing_history_healthy(),
                        node_id: state.identity.node_id_hex(),
                        public_key: Some(state.identity.public_key_hex()),
                        hrw_routing_id: Some(hrw_hex.clone()),
                        routing_id: Some(hrw_hex),
                        t0: Some(t0),
                        nonce: Some(nonce),
                        incubation_until_ms,
                        own_work: Some(own_work),
                        net_median_work: Some(net_median),
                        headroom_pct,
                        ticket_outdated,
                        uptime_sec,
                        active_locks,
                        peers_connected,
                        data_dir: state.data_dir.clone(),
                    }
                }
                ControlRequest::ListPeers => {
                    let peers = state.peer_manager.list_peers().await;
                    let mut peer_dtos = Vec::new();
                    for p in peers {
                        let mut min_hops = None;
                        let mut ingress_peer = None;
                        if let Some(nid) = p.node_id {
                            if let Some(info) = state.peer_manager.get_known_node_info(&nid).await {
                                if info.min_hops != 255 {
                                    min_hops = Some(info.min_hops);
                                    ingress_peer = info.best_ingress_peer.map(|a| a.to_string());
                                }
                            }
                        }
                        let rtt_ms = p.connection.as_ref().map(|c| c.rtt().as_millis() as u32);
                        let last_failure_sec = p.last_failure.map(|t| t.elapsed().as_secs());
                        peer_dtos.push(PeerStatusDto {
                            addr: p.addr.to_string(),
                            node_id: p.node_id.map(hex::encode),
                            status: format!("{:?}", p.status),
                            missing_count: p.missing_count,
                            min_hops,
                            ingress_peer,
                            rtt_ms,
                            last_failure_sec,
                        });
                    }
                    ControlResponse::Peers { peers: peer_dtos }
                }
                ControlRequest::TopupQuota {
                    account_tag,
                    byte_years,
                } => {
                    let tag_bytes = parse_account_tag(&account_tag);
                    if let Some(ref tc) = state.tier_controller {
                        tc.register_vip_token(account_tag.clone(), tag_bytes);
                        tc.register_vip_tag(tag_bytes);
                        match tc.topup_vip_quota(tag_bytes, byte_years) {
                            Ok(new_balance) => ControlResponse::QuotaUpdated { new_balance },
                            Err(err) => ControlResponse::Error {
                                message: format!("Failed to update quota: {}", err),
                            },
                        }
                    } else {
                        let current = state.storage.get_quota(&tag_bytes).unwrap_or(0);
                        let new_balance = current.saturating_add(byte_years);
                        match state.storage.set_quota(&tag_bytes, new_balance) {
                            Ok(()) => ControlResponse::QuotaUpdated { new_balance },
                            Err(err) => ControlResponse::Error {
                                message: format!("Failed to update quota in storage: {}", err),
                            },
                        }
                    }
                }
                ControlRequest::GetQuota { account_tag } => {
                    let tag_bytes = parse_account_tag(&account_tag);
                    if let Some(ref tc) = state.tier_controller {
                        if let Some(balance) = tc.get_cached_vip_quota(&tag_bytes) {
                            ControlResponse::Quota { balance }
                        } else {
                            match state.storage.get_quota(&tag_bytes) {
                                Ok(balance) => ControlResponse::Quota { balance },
                                Err(err) => ControlResponse::Error {
                                    message: format!("Failed to retrieve quota from storage: {}", err),
                                },
                            }
                        }
                    } else {
                        match state.storage.get_quota(&tag_bytes) {
                            Ok(balance) => ControlResponse::Quota { balance },
                            Err(err) => ControlResponse::Error {
                                message: format!("Failed to retrieve quota from storage: {}", err),
                            },
                        }
                    }
                }
                ControlRequest::Shutdown => {
                    let cancel = state.cancel_token.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        cancel.cancel();
                    });
                    match &state.lifecycle {
                        Some(lifecycle) => ControlResponse::ShutdownAccepted { identity: lifecycle.identity.clone() },
                        None => ControlResponse::Ok,
                    }
                }
                ControlRequest::RemovePeer { peer_str } => {
                    match parse_peer_string(&peer_str) {
                        Ok((key_opt, endpoint_opt)) => {
                            let removed_hex = state
                                .peer_manager
                                .remove_peer_by_spec(key_opt, endpoint_opt.as_deref())
                                .await;
                            let pubkey_hex = removed_hex.unwrap_or_else(|| peer_str.clone());
                            ControlResponse::PeerRemoved { pubkey_hex }
                        }
                        Err(err) => ControlResponse::Error {
                            message: format!("Invalid peer specification: {}", err),
                        },
                    }
                }
                ControlRequest::GetDbStats => {
                    let ram_locks = state.engine.ram.read().await.len() as u64;
                    match state.storage.get_stats() {
                        Ok((disk_locks, db_size_bytes, page_allocations)) => {
                            ControlResponse::DbStats {
                                active_locks: ram_locks.max(disk_locks),
                                db_size_bytes,
                                page_allocations,
                            }
                        }
                        Err(err) => ControlResponse::Error {
                            message: format!("Failed to get DB statistics: {}", err),
                        },
                    }
                }
                ControlRequest::AddPeer { peer_str } => {
                    match parse_peer_string(&peer_str) {
                        Ok((key_opt, endpoint_opt)) => {
                            let (addr_opt, is_dns) = if let Some(ref endpoint) = endpoint_opt {
                                if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
                                    state.peer_manager.add_peer(addr).await;
                                    (Some(addr), false)
                                } else {
                                    // Hostname/DNS peer
                                    let entry = crate::config::PeerConfigEntry::new(key_opt, endpoint.clone());
                                    state.peer_manager.add_dns_peer(entry).await;
                                    (None, true)
                                }
                            } else {
                                (None, false)
                            };

                            if let Some(key) = key_opt {
                                state.peer_manager.register_f2f_friend(key, addr_opt).await;
                                if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key) {
                                    let nid = *blake3::hash(vk.as_bytes()).as_bytes();
                                    state.peer_manager.register_verifying_key(nid, vk).await;
                                    state.peer_manager.register_verifying_key(key, vk).await;
                                }
                            }

                            if is_dns {
                                state.peer_manager.check_and_resolve_dns_peers().await;
                            }

                            ControlResponse::PeerAdded
                        }
                        Err(err) => ControlResponse::Error {
                            message: format!("Invalid peer specification: {}", err),
                        },
                    }
                }
                ControlRequest::GetRecentLocks { limit } => {
                    let recent = state.engine.get_recent_locks(limit);
                    let dtos: Vec<RecentLockSummaryDto> = recent.into_iter().map(Into::into).collect();
                    ControlResponse::RecentLocks { locks: dtos }
                }
                ControlRequest::InspectLock { parent_lock } => {
                    if let Ok(bytes) = hex::decode(parent_lock.trim()) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            let insp = state.engine.inspect_lock(&arr).await;
                            ControlResponse::LockInspection {
                                inspection: insp.map(Into::into),
                            }
                        } else {
                            ControlResponse::Error {
                                message: "parent_lock must be a 32-byte (64 hex characters) string".into(),
                            }
                        }
                    } else {
                        ControlResponse::Error {
                            message: "parent_lock must be a valid hex string".into(),
                        }
                    }
                }
                ControlRequest::CreateBackup { destination_path } => {
                    let dest_trimmed = destination_path.trim();
                    if dest_trimmed.is_empty() {
                        ControlResponse::Error {
                            message: "Destination path cannot be empty".to_string(),
                        }
                    } else if std::path::Path::new(dest_trimmed)
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        ControlResponse::Error {
                            message: "Invalid destination path: Path traversal ('..') is strictly forbidden".to_string(),
                        }
                    } else {
                        // Allow pending async flush batch to commit for maximum snapshot consistency
                        for _ in 0..10 {
                            if state.engine.flush_sender_len() == 0 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;
                                break;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
                        }

                        let dest_path = PathBuf::from(dest_trimmed);
                        let target_path = if dest_path.is_dir() {
                            dest_path.join("humoco_backup.redb")
                        } else {
                            dest_path
                        };
                        match state.storage.create_backup(&target_path) {
                            Ok(locks_count) => ControlResponse::BackupCreated {
                                path: target_path.display().to_string(),
                                locks_count,
                            },
                            Err(err) => ControlResponse::Error {
                                message: format!("Failed to create backup: {}", err),
                            },
                        }
                    }
                }
            };

            let mut resp_str = serde_json::to_string(&response).unwrap_or_default();
            resp_str.push('\n');
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                writer.write_all(resp_str.as_bytes()),
            )
            .await;
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                writer.flush(),
            )
            .await;
        }

        Ok(())
    }
}

fn parse_peer_string(peer_str: &str) -> Result<(Option<[u8; 32]>, Option<String>), String> {
    let peer_str = peer_str.trim();
    if peer_str.is_empty() {
        return Err("Peer string is empty".to_string());
    }

    if let Some((key_part, addr_part)) = peer_str.split_once('@') {
        let key_bytes = parse_pubkey_bytes(key_part)
            .ok_or_else(|| format!("Invalid public key in peer string: '{}'", key_part))?;
        let addr_clean = addr_part.trim();
        if addr_clean.is_empty() {
            return Err("Empty address part in peer string".to_string());
        }
        Ok((Some(key_bytes), Some(addr_clean.to_string())))
    } else if peer_str.contains(':') {
        Ok((None, Some(peer_str.to_string())))
    } else if let Some(key_bytes) = parse_pubkey_bytes(peer_str) {
        Ok((Some(key_bytes), None))
    } else {
        Err(format!("Cannot parse peer string: '{}'", peer_str))
    }
}

fn parse_pubkey_bytes(s: &str) -> Option<[u8; 32]> {
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
