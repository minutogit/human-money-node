use serde::{Deserialize, Serialize};
use humoco_sim_core::types::LockRecord;

/// Signed attestation from a consensus or ingress node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationDto {
    pub lock_id: String,
    pub parent_lock: String,
    pub node_id: u16,
    pub timestamp: u64,
    pub signature: String,
}

/// Assembled quorum certificate with partial signatures from shard nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCertificateDto {
    pub lock_id: String,
    pub shard_id: u16,
    /// 0 = PROVISIONAL, 1 = FINAL
    pub status: u8,
    pub active_nodes_count: usize,
    pub signer_count: usize,
    pub signatures: Vec<AttestationDto>,
    #[serde(default)]
    pub signer_bitmap: u32,
}

/// Request for synchronizing missing locks via sparse locators.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncRequest {
    #[serde(default)]
    pub sparse_locators: Vec<String>,
}

/// Detailed DTO for a lock record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockRecordDto {
    pub id: String,
    pub parent_lock: String,
    pub receiver_pub: String,
    pub nonce: String,
    pub created_at: u64,
    pub valid_until: u64,
    pub root_valid_until: u64,
    pub status: String,
    pub signers: Vec<u16>,
}

impl LockRecordDto {
    pub fn from_record(record: &LockRecord, root_valid_until: u64) -> Self {
        Self {
            id: hex::encode(record.id),
            parent_lock: hex::encode(record.parent_lock),
            receiver_pub: hex::encode(record.receiver_pub),
            nonce: hex::encode(&record.nonce),
            created_at: record.created_at.0,
            valid_until: record.valid_until.0,
            root_valid_until,
            status: format!("{:?}", record.status),
            signers: record.signers.iter().copied().collect(),
        }
    }
}

/// Response returned from sync endpoint containing list of active locks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub locks: Vec<LockRecordDto>,
}

/// Response for Proof-of-Work challenge requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallengeResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: u64,
}

/// Node health and operational status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    pub status: String,
    pub node_id: String,
    pub public_key: String,
    pub version: String,
    pub total_locks: usize,
    #[serde(default = "default_network_str")]
    pub network: String,
}

fn default_network_str() -> String {
    "mainnet".to_string()
}

/// Information about an active network peer for client discovery (PEX).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEntryDto {
    pub node_id: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_p2p: Option<String>,
    pub last_seen_epoch: u64,
}

/// Response returned from the PEX discovery endpoint /peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeersResponse {
    pub network: String,
    pub active_nodes_count: usize,
    pub peers: Vec<PeerEntryDto>,
}


/// Generic error response format with optional PoW challenge details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}
