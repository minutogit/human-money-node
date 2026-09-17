use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::control::types::{ControlRequest, ControlResponse, PeerStatusDto};
use crate::error::NodeError;

#[derive(Clone, Debug)]
pub struct ControlClient {
    socket_path: PathBuf,
}

impl ControlClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    pub async fn send_request(&self, request: ControlRequest) -> Result<ControlResponse, NodeError> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|err| {
            NodeError::IoWithPath {
                path: self.socket_path.clone(),
                source: err,
            }
        })?;

        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        let mut payload = serde_json::to_string(&request)
            .map_err(|err| NodeError::Cli(format!("JSON serialization error: {}", err)))?;
        payload.push('\n');

        writer.write_all(payload.as_bytes()).await.map_err(NodeError::Io)?;
        writer.flush().await.map_err(NodeError::Io)?;

        let mut response_line = String::new();
        let bytes_read = buf_reader.read_line(&mut response_line).await.map_err(NodeError::Io)?;
        if bytes_read == 0 {
            return Err(NodeError::Daemon(
                "Control server closed connection without response".into(),
            ));
        }

        let response: ControlResponse = serde_json::from_str(response_line.trim())
            .map_err(|err| NodeError::Cli(format!("JSON deserialization error: {}", err)))?;

        Ok(response)
    }

    pub async fn get_status(&self) -> Result<ControlResponse, NodeError> {
        self.send_request(ControlRequest::GetStatus).await
    }

    pub async fn list_peers(&self) -> Result<Vec<PeerStatusDto>, NodeError> {
        match self.send_request(ControlRequest::ListPeers).await? {
            ControlResponse::Peers { peers } => Ok(peers),
            ControlResponse::Error { message } => Err(NodeError::Daemon(message)),
            _ => Err(NodeError::Daemon(
                "Unexpected response variant from control server".into(),
            )),
        }
    }

    pub async fn topup_quota(&self, account_tag: &str, byte_years: u64) -> Result<u64, NodeError> {
        match self
            .send_request(ControlRequest::TopupQuota {
                account_tag: account_tag.to_string(),
                byte_years,
            })
            .await?
        {
            ControlResponse::QuotaUpdated { new_balance } => Ok(new_balance),
            ControlResponse::Error { message } => Err(NodeError::Daemon(message)),
            _ => Err(NodeError::Daemon(
                "Unexpected response variant from control server".into(),
            )),
        }
    }

    pub async fn get_quota(&self, account_tag: &str) -> Result<u64, NodeError> {
        match self
            .send_request(ControlRequest::GetQuota {
                account_tag: account_tag.to_string(),
            })
            .await?
        {
            ControlResponse::Quota { balance } => Ok(balance),
            ControlResponse::Error { message } => Err(NodeError::Daemon(message)),
            _ => Err(NodeError::Daemon(
                "Unexpected response variant from control server".into(),
            )),
        }
    }

    pub async fn shutdown(&self) -> Result<(), NodeError> {
        match self.send_request(ControlRequest::Shutdown).await? {
            ControlResponse::Ok => Ok(()),
            ControlResponse::Error { message } => Err(NodeError::Daemon(message)),
            _ => Err(NodeError::Daemon(
                "Unexpected response variant from control server".into(),
            )),
        }
    }

    pub async fn add_peer(&self, peer_str: &str) -> Result<ControlResponse, NodeError> {
        self.send_request(ControlRequest::AddPeer {
            peer_str: peer_str.to_string(),
        })
        .await
    }

    pub async fn get_recent_locks(&self, limit: usize) -> Result<ControlResponse, NodeError> {
        self.send_request(ControlRequest::GetRecentLocks { limit }).await
    }

    pub async fn inspect_lock(&self, parent_lock: &str) -> Result<ControlResponse, NodeError> {
        self.send_request(ControlRequest::InspectLock {
            parent_lock: parent_lock.to_string(),
        })
        .await
    }

    pub async fn create_backup(&self, destination_path: &str) -> Result<ControlResponse, NodeError> {
        self.send_request(ControlRequest::CreateBackup {
            destination_path: destination_path.to_string(),
        })
        .await
    }
}
