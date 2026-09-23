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
    pub supported_suites_mask: u8,
}

/// Unified wire payload for lock verification across simulation and HMC domains.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LockWirePayload {
    Sim(humoco_sim_core::types::LockRecord, u64),
    Hmc {
        req: Box<crate::api::hmc::L2LockRequest>,
        root_valid_until: u64,
    },
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
}
