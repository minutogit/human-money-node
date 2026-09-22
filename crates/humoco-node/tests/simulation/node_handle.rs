//! SimNodeHandle – lifecycle manager for a real `NodeDaemon`.
//!
//! 100% production components: `NodeDaemon`, `redb`, `Quinn QUIC`, `Axum HTTP`,
//! `HMC V3 Wire-DTOs`. Provides `spawn`, `stop`, `restart`, `http_request`,
//! `post_lock`, `query_status`.

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::StatusCode;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use humoco_node::api::hmc::{L2ChainLockRequest, L2LockRequest, L2ResponseEnvelope, L2StatusQuery};
use humoco_node::config::NodeConfig;
use humoco_node::daemon::{BoundAddrs, NodeDaemon};
use humoco_node::error::NodeError;
use humoco_node::identity::NodeIdentity;

/// Token used for F2F ingress in simulation mesh.
pub const SIM_F2F_TOKEN: &str = "sim_f2f_token";

/// Lifecycle handle for a single production node.
pub struct SimNodeHandle {
    pub id: usize,
    pub identity: NodeIdentity,
    pub config: NodeConfig,
    // Keep TempDir alive for the node's lifetime (data_dir persistence across restart)
    temp_dir: Option<TempDir>,
    pub cancel_token: CancellationToken,
    pub rpc_addr: SocketAddr,
    pub p2p_addr: SocketAddr,
    task_handle: Option<tokio::task::JoinHandle<Result<(), NodeError>>>,
}

impl SimNodeHandle {
    /// Spawns a new isolated node (no peers).
    pub async fn spawn(id: usize) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::spawn_with_peers(id, Vec::new(), Vec::new()).await
    }

    /// Spawns a node with explicit F2F peers and trusted pubkeys.
    /// `peers` are strings like `<pubkey>@<addr>` or `<addr>`.
    /// `trusted` are hex pubkeys.
    pub async fn spawn_with_peers(
        id: usize,
        peers: Vec<String>,
        mut trusted: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let temp = TempDir::new()?;
        let identity = NodeIdentity::generate();
        let key_path = temp.path().join("node_key.bin");
        identity.save_to_file(&key_path)?;

        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.storage.data_dir = temp.path().join("data");
        config.identity.key_path = key_path.clone();
        config.network.control_socket = Some(temp.path().join(format!("humoco_{}.sock", id)));
        config.f2f.peers = peers;
        // Always include our simulation token as F2F token for ingress
        config.f2f.tokens.push(SIM_F2F_TOKEN.to_string());
        // trusted pubkeys
        for t in trusted.drain(..) {
            if !config.f2f.trusted_pubkeys.contains(&t) {
                config.f2f.trusted_pubkeys.push(t);
            }
        }

        let cancel_token = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<BoundAddrs>();
        let daemon = NodeDaemon::with_bound_sender(
            config.clone(),
            identity.clone(),
            cancel_token.clone(),
            tx,
        );
        let handle = tokio::spawn(async move { daemon.run().await });

        let bound = tokio::time::timeout(Duration::from_secs(8), rx)
            .await
            .map_err(|_| format!("node {id} bind timeout"))??;

        let node = Self {
            id,
            identity,
            config,
            temp_dir: Some(temp),
            cancel_token,
            rpc_addr: bound.rpc_addr,
            p2p_addr: bound.p2p_addr,
            task_handle: Some(handle),
        };
        node.wait_ready().await?;
        Ok(node)
    }

    /// Spawns a node re-using an existing identity and data_dir.
    /// Used for deterministic F2F topology construction.
    pub async fn spawn_with_identity(
        id: usize,
        identity: NodeIdentity,
        peers: Vec<String>,
        trusted: Vec<String>,
        data_dir: std::path::PathBuf,
        temp_dir: TempDir,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key_path = temp_dir.path().join("node_key.bin");
        identity.save_to_file(&key_path)?;

        let mut config = NodeConfig::default();
        config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        config.storage.data_dir = data_dir;
        config.identity.key_path = key_path;
        config.network.control_socket = Some(temp_dir.path().join(format!("humoco_{}.sock", id)));
        config.f2f.peers = peers;
        config.f2f.tokens.push(SIM_F2F_TOKEN.to_string());
        for t in trusted {
            if !config.f2f.trusted_pubkeys.contains(&t) {
                config.f2f.trusted_pubkeys.push(t);
            }
        }

        let cancel_token = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<BoundAddrs>();
        let daemon = NodeDaemon::with_bound_sender(
            config.clone(),
            identity.clone(),
            cancel_token.clone(),
            tx,
        );
        let handle = tokio::spawn(async move { daemon.run().await });
        let bound = tokio::time::timeout(Duration::from_secs(8), rx)
            .await
            .map_err(|_| format!("node {id} bind timeout (with_identity)"))??;

        let node = Self {
            id,
            identity,
            config,
            temp_dir: Some(temp_dir),
            cancel_token,
            rpc_addr: bound.rpc_addr,
            p2p_addr: bound.p2p_addr,
            task_handle: Some(handle),
        };
        node.wait_ready().await?;
        Ok(node)
    }

    /// Waits until HTTP readiness (GET /health returns 200).
    pub async fn wait_ready(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for _ in 0..60 {
            if let Ok((status, body)) = self
                .http_request("GET", "/health", None, &[])
                .await
            {
                if status == StatusCode::OK {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                        if v.get("status").and_then(|s| s.as_str()) == Some("ok") {
                            return Ok(());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(format!("node {} failed to become ready at {}", self.id, self.rpc_addr).into())
    }

    /// Stops the daemon gracefully via cancellation token.
    pub async fn stop(&mut self) {
        self.cancel_token.cancel();
        if let Some(h) = self.task_handle.take() {
            // Give daemon up to 3 seconds to shut down, then abort
            let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        }
        // Keep temp_dir alive for possible restart
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// Restarts the node on new ephemeral ports, reusing identity and data_dir.
    pub async fn restart(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Preserve identity and data_dir, drop old handle if still running
        if self.task_handle.is_some() {
            self.stop().await;
        }
        let data_dir = self.config.storage.data_dir.clone();
        // temp_dir must still exist
        let temp_path = self
            .temp_dir
            .as_ref()
            .map(|t| t.path().to_path_buf())
            .ok_or("missing temp_dir for restart")?;

        // Need to keep the TempDir object alive; we will create a new config but keep same temp_dir path.
        // To avoid dropping, we keep self.temp_dir as is and create a new TempDir wrapper via `tempfile::TempDir::new` is not reuse.
        // Instead we construct a new NodeConfig that points to the same data_dir and create a new identity file.
        // The TempDir object remains the same (self.temp_dir), we just write new key file to same path.
        let key_path = temp_path.join("node_key.bin");
        self.identity.save_to_file(&key_path)?;

        let mut new_config = NodeConfig::default();
        new_config.network.p2p_listen_addr = "127.0.0.1:0".parse().unwrap();
        new_config.network.rpc_listen_addr = "127.0.0.1:0".parse().unwrap();
        new_config.storage.data_dir = data_dir.clone();
        new_config.identity.key_path = key_path;
        new_config.network.control_socket =
            Some(temp_path.join(format!("humoco_{}_restart.sock", self.id)));
        // Preserve F2F topology (peers and trusted)
        new_config.f2f = self.config.f2f.clone();
        // Ensure tokens still present
        if !new_config.f2f.tokens.contains(&SIM_F2F_TOKEN.to_string()) {
            new_config.f2f.tokens.push(SIM_F2F_TOKEN.to_string());
        }

        let cancel_token = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<BoundAddrs>();
        let identity_clone = self.identity.clone();
        let daemon = NodeDaemon::with_bound_sender(
            new_config.clone(),
            identity_clone,
            cancel_token.clone(),
            tx,
        );
        let handle = tokio::spawn(async move { daemon.run().await });
        let bound = tokio::time::timeout(Duration::from_secs(8), rx)
            .await
            .map_err(|_| format!("node {} restart bind timeout", self.id))??;

        self.config = new_config;
        self.cancel_token = cancel_token;
        self.rpc_addr = bound.rpc_addr;
        self.p2p_addr = bound.p2p_addr;
        self.task_handle = Some(handle);
        self.wait_ready().await?;
        Ok(())
    }

    /// Raw HTTP request to the node's Axum REST API using a bare TCP stream.
    pub async fn http_request(
        &self,
        method: &str,
        path: &str,
        body_json: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = tokio::net::TcpStream::connect(self.rpc_addr).await?;
        let body_bytes = body_json.map(|s| s.as_bytes()).unwrap_or(&[]);

        let mut req_str = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            method, path, self.rpc_addr, body_bytes.len()
        );
        for (k, v) in headers {
            req_str.push_str(&format!("{}: {}\r\n", k, v));
        }
        req_str.push_str("\r\n");

        stream.write_all(req_str.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(body_bytes).await?;
        }
        stream.flush().await?;

        let mut response_buf = Vec::new();
        stream.read_to_end(&mut response_buf).await?;

        let mut split_idx = None;
        for i in 0..response_buf.len().saturating_sub(3) {
            if &response_buf[i..i + 4] == b"\r\n\r\n" {
                split_idx = Some(i);
                break;
            }
        }
        let (header_part, body_part) = match split_idx {
            Some(idx) => (&response_buf[..idx], &response_buf[idx + 4..]),
            None => (&response_buf[..], &[][..]),
        };

        let header_str = String::from_utf8_lossy(header_part);
        let mut lines = header_str.lines();
        let status_line = lines.next().unwrap_or("");
        let status_code_u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(500);

        let status =
            StatusCode::from_u16(status_code_u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Ok((status, body_part.to_vec()))
    }

    /// Submits an HMC L2 lock request to `POST /lock`.
    pub async fn post_lock(
        &self,
        req: &L2LockRequest,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(req)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/lock",
                Some(&json_body),
                &[
                    ("Content-Type", "application/json"),
                    ("X-Peer-Token", SIM_F2F_TOKEN),
                ],
            )
            .await?;
        let envelope: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, envelope))
    }

    /// Submits an HMC chain lock request to `POST /v1/lock` (also accepts `/lock`).
    pub async fn post_chain_lock(
        &self,
        req: &L2ChainLockRequest,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(req)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/lock",
                Some(&json_body),
                &[
                    ("Content-Type", "application/json"),
                    ("X-Peer-Token", SIM_F2F_TOKEN),
                ],
            )
            .await?;
        let envelope: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, envelope))
    }

    /// Queries voucher status via `POST /status`.
    pub async fn query_status(
        &self,
        query: &L2StatusQuery,
    ) -> Result<(StatusCode, L2ResponseEnvelope), Box<dyn std::error::Error + Send + Sync>> {
        let json_body = serde_json::to_string(query)?;
        let (status, body) = self
            .http_request(
                "POST",
                "/status",
                Some(&json_body),
                &[("Content-Type", "application/json")],
            )
            .await?;
        let envelope: L2ResponseEnvelope = serde_json::from_slice(&body)?;
        Ok((status, envelope))
    }

    /// Returns the node's F2F peer string `<pubkey>@<addr>` for wiring other nodes.
    pub fn f2f_peer_string(&self) -> String {
        format!("{}@{}", self.identity.public_key_hex(), self.p2p_addr)
    }

    /// Returns the hex-encoded public key.
    pub fn pubkey_hex(&self) -> String {
        self.identity.public_key_hex()
    }

    /// Returns the node's socket addresses.
    pub fn addrs(&self) -> (SocketAddr, SocketAddr) {
        (self.rpc_addr, self.p2p_addr)
    }
}

impl Drop for SimNodeHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        if let Some(h) = self.task_handle.take() {
            h.abort();
        }
    }
}
