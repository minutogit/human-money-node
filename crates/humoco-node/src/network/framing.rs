use std::time::Duration;
use humoco_sim_core::wire::{MsgType, WireHeader, CURRENT_PROTOCOL_VERSION, WIRE_MAGIC};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::NodeError;

pub const MAX_STANDARD_FRAME_PAYLOAD_LEN: usize = 64 * 1024; // 64 KiB
pub const MAX_SYNC_FRAME_PAYLOAD_LEN: usize = 4 * 1024 * 1024; // 4 MiB
pub const MAX_FRAME_PAYLOAD_LEN: usize = MAX_SYNC_FRAME_PAYLOAD_LEN;
pub const DEFAULT_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// F2F Heartbeat Wire-Payload carrying node ID, socket address, and monotonic net_time (Spec 11).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeartbeatWirePayload {
    pub node_id: [u8; 32],
    pub addr: std::net::SocketAddr,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub declared_write_ema_micro_bj: u64,
    #[serde(default)]
    pub declared_read_ema_credits: u64,
    #[serde(default = "default_signature", with = "serde_sig_64")]
    pub signature: [u8; 64],
    #[serde(default)]
    pub supported_suites_mask: u8,
    #[serde(default, deserialize_with = "deserialize_piggyback_observations")]
    pub piggyback_observations: Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
    #[serde(default)]
    pub pow_nonce: u64,
    #[serde(default)]
    pub hrw_routing_id: [u8; 32],
    #[serde(default)]
    pub ticket_epoch_t0: u64,
    #[serde(default = "default_heartbeat_ttl")]
    pub ttl: u8,
}

pub fn default_heartbeat_ttl() -> u8 {
    16
}

pub fn deserialize_piggyback_observations<'de, D>(
    deserializer: D,
) -> Result<Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut vec: Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence> =
        serde::Deserialize::deserialize(deserializer)?;
    if vec.len() > 2 {
        vec.truncate(2);
    }
    Ok(vec)
}

impl HeartbeatWirePayload {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if let Ok(hb) = bincode::deserialize::<HeartbeatWirePayload>(bytes) {
            Ok(hb)
        } else {
            #[derive(serde::Deserialize)]
            struct MidHeartbeat {
                node_id: [u8; 32],
                addr: std::net::SocketAddr,
                timestamp_ms: u64,
                #[serde(default)]
                declared_write_ema_micro_bj: u64,
                #[serde(default)]
                declared_read_ema_credits: u64,
                #[serde(default = "default_signature", with = "serde_sig_64")]
                signature: [u8; 64],
                #[serde(default)]
                supported_suites_mask: u8,
                #[serde(default, deserialize_with = "deserialize_piggyback_observations")]
                piggyback_observations: Vec<humoco_sim_core::fraud::IngressEnvelopeEvidence>,
            }
            if let Ok(m) = bincode::deserialize::<MidHeartbeat>(bytes) {
                Ok(HeartbeatWirePayload {
                    node_id: m.node_id,
                    addr: m.addr,
                    timestamp_ms: m.timestamp_ms,
                    declared_write_ema_micro_bj: m.declared_write_ema_micro_bj,
                    declared_read_ema_credits: m.declared_read_ema_credits,
                    signature: m.signature,
                    supported_suites_mask: m.supported_suites_mask,
                    piggyback_observations: m.piggyback_observations,
                    pow_nonce: 0,
                    hrw_routing_id: m.node_id,
                    ticket_epoch_t0: 0,
                    ttl: 16,
                })
            } else {
                #[derive(serde::Deserialize)]
                struct LegacyHeartbeat {
                    node_id: [u8; 32],
                    addr: std::net::SocketAddr,
                    timestamp_ms: u64,
                    #[serde(default)]
                    declared_write_ema_micro_bj: u64,
                    #[serde(default)]
                    declared_read_ema_credits: u64,
                    #[serde(default = "default_signature", with = "serde_sig_64")]
                    signature: [u8; 64],
                    #[serde(default)]
                    supported_suites_mask: u8,
                }
                let l: LegacyHeartbeat = bincode::deserialize(bytes)?;
                Ok(HeartbeatWirePayload {
                    node_id: l.node_id,
                    addr: l.addr,
                    timestamp_ms: l.timestamp_ms,
                    declared_write_ema_micro_bj: l.declared_write_ema_micro_bj,
                    declared_read_ema_credits: l.declared_read_ema_credits,
                    signature: l.signature,
                    supported_suites_mask: l.supported_suites_mask,
                    piggyback_observations: Vec::new(),
                    pow_nonce: 0,
                    hrw_routing_id: l.node_id,
                    ticket_epoch_t0: 0,
                    ttl: 16,
                })
            }
        }
    }
}

pub fn default_signature() -> [u8; 64] {
    [0u8; 64]
}

pub mod serde_sig_64 {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() == 64 {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(v);
                    Ok(arr)
                } else if v.is_empty() {
                    Ok([0u8; 64])
                } else {
                    Err(E::custom(format!("expected 64 bytes, got {}", v.len())))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                let mut idx = 0;
                while let Some(val) = seq.next_element()? {
                    if idx < 64 {
                        arr[idx] = val;
                        idx += 1;
                    }
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

mod hmc_req_json {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(
        data: &crate::api::hmc::L2LockRequest,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw = serde_json::to_vec(data).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&raw)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<crate::api::hmc::L2LockRequest, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        serde_json::from_slice(&bytes).map_err(de::Error::custom)
    }
}

mod hmc_chain_opt_json {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(
        data: &Option<crate::api::hmc::L2ChainLockRequest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(chain) => {
                let raw = serde_json::to_vec(chain).map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&raw)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<crate::api::hmc::L2ChainLockRequest>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
        match opt {
            Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Unified wire payload for lock verification across simulation and HMC domains.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum LockWirePayload {
    Sim(humoco_sim_core::types::LockRecord, u64),
    Hmc {
        #[serde(with = "hmc_req_json")]
        req: crate::api::hmc::L2LockRequest,
        #[serde(default, with = "hmc_chain_opt_json")]
        chain: Option<crate::api::hmc::L2ChainLockRequest>,
        root_valid_until: u64,
        #[serde(default)]
        epoch_day: u32,
        #[serde(default)]
        epoch_seq: u64,
        #[serde(default)]
        cumulative_micro_byte_years: u64,
        #[serde(default)]
        prev_day_final_bytes: u64,
        #[serde(default)]
        current_anl_24h: u64,
        #[serde(default)]
        declared_write_ema_micro_bj: u64,
        #[serde(default)]
        declared_read_ema_credits: u64,
        #[serde(default)]
        sender_pubkey: [u8; 32],
        #[serde(default = "default_signature", with = "serde_sig_64")]
        sender_signature: [u8; 64],
        #[serde(default)]
        timestamp_ms: u64,
    },
}

impl LockWirePayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn declared_write_ema_micro_bj(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { declared_write_ema_micro_bj, .. } => *declared_write_ema_micro_bj,
        }
    }

    pub fn declared_read_ema_credits(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { declared_read_ema_credits, .. } => *declared_read_ema_credits,
        }
    }

    pub fn epoch_day(&self) -> u32 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { epoch_day, .. } => *epoch_day,
        }
    }

    pub fn epoch_seq(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { epoch_seq, .. } => *epoch_seq,
        }
    }

    pub fn cumulative_micro_byte_years(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { cumulative_micro_byte_years, .. } => *cumulative_micro_byte_years,
        }
    }

    pub fn prev_day_final_bytes(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { prev_day_final_bytes, .. } => *prev_day_final_bytes,
        }
    }

    pub fn current_anl_24h(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { current_anl_24h, .. } => *current_anl_24h,
        }
    }

    pub fn chain(&self) -> Option<&crate::api::hmc::L2ChainLockRequest> {
        match self {
            Self::Sim(..) => None,
            Self::Hmc { chain, .. } => chain.as_ref(),
        }
    }

    pub fn sender_pubkey(&self) -> [u8; 32] {
        match self {
            Self::Sim(rec, _) => rec.receiver_pub,
            Self::Hmc { sender_pubkey, req, .. } => {
                if *sender_pubkey != [0u8; 32] {
                    *sender_pubkey
                } else {
                    req.sender_ephemeral_pub
                }
            }
        }
    }

    pub fn sender_signature(&self) -> [u8; 64] {
        match self {
            Self::Sim(..) => [0u8; 64],
            Self::Hmc { sender_signature, .. } => *sender_signature,
        }
    }

    pub fn timestamp_ms(&self) -> u64 {
        match self {
            Self::Sim(..) => 0,
            Self::Hmc { timestamp_ms, .. } => *timestamp_ms,
        }
    }
}

/// Wire payload for StatusQuery carrying lock identifiers and declared read EMA metrics (Spec 09/10).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusQueryPayload {
    pub lock_id: [u8; 32],
    pub parent_lock: [u8; 32],
    pub shard_id: u16,
    #[serde(default)]
    pub sender_pubkey: [u8; 32],
    #[serde(default)]
    pub declared_write_ema_micro_bj: u64,
    #[serde(default)]
    pub current_read_ema_credits: u64,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default = "default_signature", with = "serde_sig_64")]
    pub sender_signature: [u8; 64],
}

impl StatusQueryPayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

mod hmc_locks_json {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(
        data: &[(String, crate::api::hmc::L2LockEntry)],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw = serde_json::to_vec(data).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&raw)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<(String, crate::api::hmc::L2LockEntry)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        serde_json::from_slice(&bytes).map_err(de::Error::custom)
    }
}

/// Unified active sync payload carrying both regular LockRecords and HMC L2LockEntries.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncPayload {
    pub locks: Vec<(humoco_sim_core::types::LockRecord, u64)>,
    #[serde(with = "hmc_locks_json")]
    pub hmc_locks: Vec<(String, crate::api::hmc::L2LockEntry)>,
}

impl SyncPayload {
    pub fn new(
        locks: Vec<(humoco_sim_core::types::LockRecord, u64)>,
        hmc_locks: Vec<(String, crate::api::hmc::L2LockEntry)>,
    ) -> Self {
        Self { locks, hmc_locks }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if let Ok(sp) = bincode::deserialize::<SyncPayload>(bytes) {
            Ok(sp)
        } else {
            let locks: Vec<(humoco_sim_core::types::LockRecord, u64)> = bincode::deserialize(bytes)?;
            Ok(SyncPayload {
                locks,
                hmc_locks: Vec::new(),
            })
        }
    }
}

/// Paginated ActiveSync request payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActiveSyncRequest {
    #[serde(default)]
    pub cursor: u64,
    #[serde(default = "default_sync_limit")]
    pub limit: usize,
    #[serde(default)]
    pub target_bucket_id: Option<u64>,
}

pub fn default_sync_limit() -> usize {
    500
}

impl ActiveSyncRequest {
    pub fn new(cursor: u64, limit: usize) -> Self {
        Self { cursor, limit, target_bucket_id: None }
    }

    pub fn with_bucket(cursor: u64, limit: usize, target_bucket_id: Option<u64>) -> Self {
        Self { cursor, limit, target_bucket_id }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.is_empty() {
            Ok(Self {
                cursor: 0,
                limit: default_sync_limit(),
                target_bucket_id: None,
            })
        } else {
            bincode::deserialize(bytes)
        }
    }
}

/// Paginated ActiveSync response payload.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ActiveSyncResponse {
    pub payload: SyncPayload,
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<u64>,
}

impl ActiveSyncResponse {
    pub fn new(payload: SyncPayload, has_more: bool, next_cursor: Option<u64>) -> Self {
        Self {
            payload,
            has_more,
            next_cursor,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if let Ok(resp) = bincode::deserialize::<ActiveSyncResponse>(bytes) {
            Ok(resp)
        } else {
            // Backward compatibility with raw SyncPayload
            let payload = SyncPayload::from_bytes(bytes)?;
            Ok(ActiveSyncResponse {
                payload,
                has_more: false,
                next_cursor: None,
            })
        }
    }
}

/// Safely converts a payload `usize` length to `u32` for wire framing, preventing truncation.
pub fn checked_payload_len(len: usize) -> Result<u32, NodeError> {
    u32::try_from(len).map_err(|_| {
        NodeError::Network(format!(
            "Payload length {} exceeds maximum u32 wire framing limit",
            len
        ))
    })
}

/// Returns the maximum allowed payload length based on the message type (INV: DoS / OOM protection).
pub fn max_payload_len_for_msg_type(msg_type: u16) -> usize {
    if msg_type == MsgType::ActiveSyncRequest as u16
        || msg_type == MsgType::ActiveSyncDone as u16
    {
        MAX_SYNC_FRAME_PAYLOAD_LEN
    } else {
        MAX_STANDARD_FRAME_PAYLOAD_LEN
    }
}

/// Writes a 32-byte WireHeader followed by the payload to an async writer and flushes.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    header: &WireHeader,
    payload: &[u8],
) -> Result<(), NodeError> {
    if payload.len() != header.payload_len as usize {
        return Err(NodeError::Network(format!(
            "Payload length mismatch: header specifies {} bytes, but payload is {} bytes",
            header.payload_len,
            payload.len()
        )));
    }

    let max_len = max_payload_len_for_msg_type(header.msg_type);
    if payload.len() > max_len {
        return Err(NodeError::Network(format!(
            "Payload length exceeds maximum allowed frame size for msg_type 0x{:04x} ({} > {})",
            header.msg_type,
            payload.len(),
            max_len
        )));
    }

    let header_bytes = header.to_bytes();
    writer.write_all(&header_bytes).await?;

    if !payload.is_empty() {
        writer.write_all(payload).await?;
    }

    writer.flush().await?;
    Ok(())
}

/// Reads a 32-byte WireHeader followed by the payload from an async reader with default 5s timeout.
pub async fn read_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(WireHeader, Vec<u8>), NodeError> {
    read_frame_with_timeout(reader, DEFAULT_STREAM_READ_TIMEOUT).await
}

/// Reads a 32-byte WireHeader followed by the payload from an async reader with timeout (Slowloris protection).
pub async fn read_frame_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    timeout_dur: Duration,
) -> Result<(WireHeader, Vec<u8>), NodeError> {
    tokio::time::timeout(timeout_dur, async {
        let mut header_bytes = [0u8; WireHeader::SIZE];
        reader.read_exact(&mut header_bytes).await?;

        let header = WireHeader::from_bytes(&header_bytes);

        if !header.is_valid_magic() {
            return Err(NodeError::Network(format!(
                "Invalid wire magic: expected {:?}, got {:?}",
                WIRE_MAGIC, header.magic
            )));
        }

        if header.protocol_version != CURRENT_PROTOCOL_VERSION
            && !(header.min_compat_ver != 0
                && u16::from(header.min_compat_ver) <= CURRENT_PROTOCOL_VERSION)
        {
            return Err(NodeError::Network(format!(
                "Unsupported protocol version: expected {}, got {}",
                CURRENT_PROTOCOL_VERSION, header.protocol_version
            )));
        }

        let payload_len = header.payload_len as usize;
        let max_len = max_payload_len_for_msg_type(header.msg_type);
        if payload_len > max_len {
            return Err(NodeError::Network(format!(
                "Frame payload length exceeds maximum limit for msg_type 0x{:04x} ({} > {})",
                header.msg_type, payload_len, max_len
            )));
        }

        let mut payload = Vec::with_capacity(payload_len.min(64 * 1024));
        let mut limited_reader = reader.take(payload_len as u64);
        limited_reader.read_to_end(&mut payload).await?;
        if payload.len() != payload_len {
            return Err(NodeError::Network("Unexpected EOF while reading frame payload".into()));
        }

        Ok((header, payload))
    })
    .await
    .map_err(|_| NodeError::Network("Read timeout exceeded on QUIC stream (Slowloris protection)".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use humoco_sim_core::wire::MsgType;

    #[tokio::test]
    async fn test_frame_write_read_roundtrip() {
        let payload = b"Hello HuMoCo QUIC Layer-2!".to_vec();
        let header = WireHeader::new(
            MsgType::LockVerifyRequest as u16,
            1,
            100,
            0,
            payload.len() as u32,
        );

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &header, &payload)
            .await
            .expect("write frame");

        let mut cursor = std::io::Cursor::new(buffer);
        let (read_hdr, read_payload) = read_frame(&mut cursor).await.expect("read frame");

        assert_eq!(read_hdr, header);
        assert_eq!(read_payload, payload);
    }

    #[tokio::test]
    async fn test_frame_empty_payload() {
        let header = WireHeader::new(MsgType::Heartbeat as u16, 42, 1, 0, 0);

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &header, &[])
            .await
            .expect("write frame");

        let mut cursor = std::io::Cursor::new(buffer);
        let (read_hdr, read_payload) = read_frame(&mut cursor).await.expect("read frame");

        assert_eq!(read_hdr, header);
        assert!(read_payload.is_empty());
    }

    #[tokio::test]
    async fn test_frame_invalid_magic() {
        let mut header = WireHeader::new(MsgType::Heartbeat as u16, 1, 1, 0, 0);
        header.magic = *b"FAIL";

        let mut buffer = Vec::new();
        let header_bytes = header.to_bytes();
        buffer.extend_from_slice(&header_bytes);

        let mut cursor = std::io::Cursor::new(buffer);
        let res = read_frame(&mut cursor).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_frame_size_limit_rejection() {
        // Standard message (Heartbeat) over 64 KiB must be rejected
        let large_payload = vec![0u8; 65 * 1024];
        let header = WireHeader::new(MsgType::Heartbeat as u16, 1, 1, 0, large_payload.len() as u32);
        let mut buffer = Vec::new();
        let err = write_frame(&mut buffer, &header, &large_payload).await;
        assert!(err.is_err(), "Standard frame > 64KiB must be rejected");

        // Sync message (ActiveSyncDone) up to 4 MiB is accepted
        let sync_header = WireHeader::new(MsgType::ActiveSyncDone as u16, 1, 1, 0, 100 * 1024);
        let sync_payload = vec![1u8; 100 * 1024];
        let ok = write_frame(&mut buffer, &sync_header, &sync_payload).await;
        assert!(ok.is_ok(), "Sync frame up to 4MiB must be accepted");
    }

    #[tokio::test]
    async fn test_slowloris_timeout() {
        // A duplex pipe where the writer never writes anything
        let (mut client_stream, _server_stream) = tokio::io::duplex(64);
        let timeout_dur = Duration::from_millis(50);
        let res = read_frame_with_timeout(&mut client_stream, timeout_dur).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Read timeout exceeded"));
    }

    #[test]
    fn test_checked_payload_len() {
        assert_eq!(checked_payload_len(0).unwrap(), 0);
        assert_eq!(checked_payload_len(1024).unwrap(), 1024);
        assert_eq!(checked_payload_len(u32::MAX as usize).unwrap(), u32::MAX);
        #[cfg(target_pointer_width = "64")]
        {
            let oversized = (u32::MAX as usize) + 1;
            assert!(checked_payload_len(oversized).is_err());
        }
    }

    #[test]
    fn test_heartbeat_payload_serde_and_capping() {
        use humoco_sim_core::fraud::IngressEnvelopeEvidence;

        let ev1 = IngressEnvelopeEvidence {
            gateway_pubkey: [1; 32],
            timestamp_ms: 1000,
            declared_write_ema_micro_bj: 500,
            ..Default::default()
        };
        let ev2 = IngressEnvelopeEvidence {
            gateway_pubkey: [2; 32],
            timestamp_ms: 2000,
            declared_write_ema_micro_bj: 600,
            ..Default::default()
        };
        let ev3 = IngressEnvelopeEvidence {
            gateway_pubkey: [3; 32],
            timestamp_ms: 3000,
            declared_write_ema_micro_bj: 700,
            ..Default::default()
        };

        // 1. Serde bincode roundtrip with 3 items capped to 2
        let hb = HeartbeatWirePayload {
            node_id: [9; 32],
            addr: "127.0.0.1:9090".parse().unwrap(),
            timestamp_ms: 12345,
            declared_write_ema_micro_bj: 100,
            declared_read_ema_credits: 200,
            signature: [0; 64],
            supported_suites_mask: 1,
            piggyback_observations: vec![ev1.clone(), ev2.clone(), ev3.clone()],
            pow_nonce: 0,
            hrw_routing_id: [9; 32],
            ticket_epoch_t0: 0,
            ttl: 16,
        };
        let bytes = bincode::serialize(&hb).expect("serialize bincode");
        let decoded = HeartbeatWirePayload::from_bytes(&bytes).expect("deserialize bincode");
        assert_eq!(decoded.piggyback_observations.len(), 2, "Must cap at 2 entries");
        assert_eq!(decoded.piggyback_observations[0].gateway_pubkey, ev1.gateway_pubkey);
        assert_eq!(decoded.piggyback_observations[1].gateway_pubkey, ev2.gateway_pubkey);

        // 2. JSON serde: omitted piggyback_observations defaults to empty Vec
        let json_str = r#"{
            "node_id": [9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
            "addr": "127.0.0.1:9090",
            "timestamp_ms": 12345,
            "declared_write_ema_micro_bj": 100,
            "declared_read_ema_credits": 200,
            "supported_suites_mask": 0
        }"#;
        let decoded_json: HeartbeatWirePayload = serde_json::from_str(json_str).expect("deserialize json");
        assert!(decoded_json.piggyback_observations.is_empty(), "Omitted field defaults to empty Vec");

        // 3. JSON serde with 3 entries caps at 2
        let json_with_3 = serde_json::to_string(&hb).expect("serialize json");
        let decoded_json_3: HeartbeatWirePayload = serde_json::from_str(&json_with_3).expect("deserialize json");
        assert_eq!(decoded_json_3.piggyback_observations.len(), 2, "JSON must cap at 2 entries");
    }
}
