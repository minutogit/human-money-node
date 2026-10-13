use serde::{Deserialize, Serialize};
use humoco_sim_core::types::LockRecord;

/// Signed attestation from a consensus or ingress node.
///
/// # Architectural Invariant: Pillar 3 — Cryptographic Identity Trumps Network Topology
///
/// The permanent signer identity is the full 32-byte Ed25519 `NodePubKey`
/// (`node_pubkey`, hex). The legacy 16-bit `node_id` prefix (first two bytes)
/// stays only for backward compatibility and MUST NEVER be used for key
/// resolution — its 16-bit space collides across nodes and previously allowed
/// `u16_to_vk` overwrite attacks. Verifiers resolve strictly via `node_pubkey`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationDto {
    pub lock_id: String,
    pub parent_lock: String,
    pub node_id: u16,
    /// Full 32-byte Ed25519 NodePubKey of the signer (hex). Empty for legacy payloads.
    #[serde(default)]
    pub node_pubkey: String,
    pub timestamp: u64,
    pub signature: String,
    #[serde(default)]
    pub shard_id: u16,
}

impl AttestationDto {
    /// Decodes the full 32-byte signer NodePubKey, if present and well-formed.
    pub fn node_pubkey_bytes(&self) -> Option<[u8; 32]> {
        if self.node_pubkey.is_empty() {
            return None;
        }
        let raw = hex::decode(&self.node_pubkey).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Some(out)
    }

    /// Wire-tolerant deserialization: accepts both the current 6-field format
    /// (with `node_pubkey`) and the legacy 5-field format (without it).
    /// Legacy payloads upgrade to `node_pubkey == ""` and verify via the
    /// 16-bit fallback path.
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if let Ok(att) = bincode::deserialize::<Self>(bytes) {
            return Some(att);
        }
        #[derive(serde::Deserialize)]
        struct LegacyAttestation {
            lock_id: String,
            parent_lock: String,
            node_id: u16,
            timestamp: u64,
            signature: String,
        }
        bincode::deserialize::<LegacyAttestation>(bytes)
            .ok()
            .map(|l| Self {
                lock_id: l.lock_id,
                parent_lock: l.parent_lock,
                node_id: l.node_id,
                node_pubkey: String::new(),
                timestamp: l.timestamp,
                signature: l.signature,
                shard_id: 0,
            })
    }
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

impl QuorumCertificateDto {
    pub fn is_quorum_reached(&self) -> bool {
        let (required_q, _) = humoco_sim_core::types::required_quorum(self.active_nodes_count);
        self.signatures.len() >= required_q
    }

    pub fn required_quorum(&self) -> usize {
        humoco_sim_core::types::required_quorum(self.active_nodes_count).0
    }
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
    #[serde(default = "default_true")]
    pub free_tier_enabled: bool,
    #[serde(default)]
    pub active_byte_years: u64,
    #[serde(default)]
    pub daily_write_quota_byte_years: u64,
    #[serde(default)]
    pub daily_read_quota: u64,
}

fn default_network_str() -> String {
    "mainnet".to_string()
}

fn default_true() -> bool {
    true
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
