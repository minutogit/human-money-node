use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerStatusDto {
    pub addr: String,
    pub node_id: Option<String>,
    pub status: String,
    pub missing_count: u32,
    #[serde(default)]
    pub min_hops: Option<u8>,
    #[serde(default)]
    pub ingress_peer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload")]
pub enum ControlRequest {
    GetStatus,
    ListPeers,
    TopupQuota {
        account_tag: String,
        byte_years: u64,
    },
    GetQuota {
        account_tag: String,
    },
    Shutdown,
    AddPeer {
        peer_str: String,
    },
    GetRecentLocks {
        limit: usize,
    },
    InspectLock {
        parent_lock: String,
    },
    CreateBackup {
        destination_path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentLockSummaryDto {
    pub parent_lock_hex: String,
    pub child_lock_hex: String,
    pub timestamp_ms: u64,
    pub status: String,
}

impl From<crate::storage::recent::RecentLockSummary> for RecentLockSummaryDto {
    fn from(r: crate::storage::recent::RecentLockSummary) -> Self {
        let status_str = match r.status {
            crate::storage::recent::RecentLockStatus::Verified => "Verified".to_string(),
            crate::storage::recent::RecentLockStatus::Provisional => "Provisional".to_string(),
            crate::storage::recent::RecentLockStatus::Conflict => "Conflict".to_string(),
        };
        Self {
            parent_lock_hex: r.parent_lock_hex,
            child_lock_hex: r.child_lock_hex,
            timestamp_ms: r.timestamp_ms,
            status: status_str,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockInspectionDto {
    pub parent_lock_hex: String,
    pub lock_id_hex: String,
    pub receiver_pub_hex: String,
    pub created_at_ms: u64,
    pub valid_until_ms: u64,
    pub status: String,
    pub signers_count: usize,
}

impl From<crate::storage::recent::LockInspection> for LockInspectionDto {
    fn from(i: crate::storage::recent::LockInspection) -> Self {
        Self {
            parent_lock_hex: i.parent_lock_hex,
            lock_id_hex: i.lock_id_hex,
            receiver_pub_hex: i.receiver_pub_hex,
            created_at_ms: i.created_at_ms,
            valid_until_ms: i.valid_until_ms,
            status: i.status,
            signers_count: i.signers_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload")]
pub enum ControlResponse {
    Status {
        node_id: String,
        #[serde(default)]
        public_key: Option<String>,
        #[serde(default)]
        hrw_routing_id: Option<String>,
        #[serde(default)]
        routing_id: Option<String>,
        #[serde(default)]
        t0: Option<u64>,
        #[serde(default)]
        nonce: Option<u64>,
        #[serde(default)]
        incubation_until_ms: Option<u64>,
        uptime_sec: u64,
        active_locks: usize,
        peers_connected: usize,
        data_dir: PathBuf,
    },
    Peers {
        peers: Vec<PeerStatusDto>,
    },
    QuotaUpdated {
        new_balance: u64,
    },
    Quota {
        balance: u64,
    },
    PeerAdded,
    RecentLocks {
        locks: Vec<RecentLockSummaryDto>,
    },
    LockInspection {
        inspection: Option<LockInspectionDto>,
    },
    BackupCreated {
        path: String,
        locks_count: usize,
    },
    Ok,
    Error {
        message: String,
    },
}

/// Parses an account tag string into a 32-byte array:
/// If it is a 64-character hex string, it is decoded into 32 bytes;
/// otherwise its UTF-8 representation is hashed with BLAKE3.
pub fn parse_account_tag(tag: &str) -> [u8; 32] {
    if tag.len() == 64 {
        if let Ok(bytes) = hex::decode(tag) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return arr;
        }
    }
    *blake3::hash(tag.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_account_tag() {
        let hex_tag = "01".repeat(32);
        let parsed = parse_account_tag(&hex_tag);
        assert_eq!(parsed, [1u8; 32]);

        let plain_tag = "alice";
        let parsed_plain = parse_account_tag(plain_tag);
        assert_eq!(parsed_plain, *blake3::hash(b"alice").as_bytes());
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let req = ControlRequest::TopupQuota {
            account_tag: "bob".into(),
            byte_years: 5000,
        };
        let serialized = serde_json::to_string(&req).expect("serialize req");
        let deserialized: ControlRequest = serde_json::from_str(&serialized).expect("deserialize req");
        assert_eq!(req, deserialized);

        let resp = ControlResponse::Status {
            node_id: "test_node".into(),
            public_key: Some("test_pubkey".into()),
            hrw_routing_id: Some("hrw_test".into()),
            routing_id: Some("hrw_test".into()),
            t0: Some(12345),
            nonce: Some(999),
            incubation_until_ms: Some(12345 + 24 * 3600 * 1000),
            uptime_sec: 42,
            active_locks: 10,
            peers_connected: 2,
            data_dir: PathBuf::from("/tmp/humoco"),
        };
        let serialized_resp = serde_json::to_string(&resp).expect("serialize resp");
        let deserialized_resp: ControlResponse =
            serde_json::from_str(&serialized_resp).expect("deserialize resp");
        assert_eq!(resp, deserialized_resp);

        // Flexibility: old JSON without new fields must still deserialize via default
        let old_json = r#"{"type":"Status","payload":{"node_id":"old_node","uptime_sec":1,"active_locks":0,"peers_connected":0,"data_dir":"/tmp/humoco"}}"#;
        let old_resp: ControlResponse = serde_json::from_str(old_json).expect("deserialize old resp");
        match old_resp {
            ControlResponse::Status {
                node_id,
                public_key,
                hrw_routing_id,
                routing_id,
                t0,
                nonce,
                incubation_until_ms,
                ..
            } => {
                assert_eq!(node_id, "old_node");
                assert_eq!(public_key, None);
                assert_eq!(hrw_routing_id, None);
                assert_eq!(routing_id, None);
                assert_eq!(t0, None);
                assert_eq!(nonce, None);
                assert_eq!(incubation_until_ms, None);
            }
            _ => panic!("expected Status"),
        }

        let backup_resp = ControlResponse::BackupCreated {
            path: "/tmp/backup.redb".into(),
            locks_count: 42,
        };
        let ser_backup = serde_json::to_string(&backup_resp).expect("serialize backup resp");
        let de_backup: ControlResponse = serde_json::from_str(&ser_backup).expect("deserialize backup resp");
        assert_eq!(backup_resp, de_backup);

        let recent_req = ControlRequest::GetRecentLocks { limit: 10 };
        let ser_recent = serde_json::to_string(&recent_req).expect("serialize recent req");
        let de_recent: ControlRequest = serde_json::from_str(&ser_recent).expect("deserialize recent req");
        assert_eq!(recent_req, de_recent);
    }
}
