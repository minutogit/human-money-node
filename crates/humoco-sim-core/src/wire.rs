//! Spec 10 & 13: Wire Framing Header and Protocol Constants

pub const WIRE_MAGIC: [u8; 4] = *b"HUMO";
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// 32-Byte C-Aligned Framing Header (INV-1001)
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    pub magic: [u8; 4],
    pub protocol_version: u16,
    pub msg_type: u16,
    pub session_seq: u64,
    pub epoch_id: u32,
    pub flags: u32,
    pub payload_len: u32,
    pub crypto_suite: u8,
    pub reserved_ver: u8,
    pub reserved: u16,
}

impl WireHeader {
    pub const SIZE: usize = 32;

    pub fn new(
        msg_type: u16,
        session_seq: u64,
        epoch_id: u32,
        flags: u32,
        payload_len: u32,
    ) -> Self {
        Self {
            magic: WIRE_MAGIC,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            msg_type,
            session_seq,
            epoch_id,
            flags,
            payload_len,
            crypto_suite: 1,
            reserved_ver: 0,
            reserved: 0,
        }
    }

    #[inline(always)]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == WIRE_MAGIC
    }

    #[inline(always)]
    pub fn crypto_suite(&self) -> Option<crate::types::CryptoSuiteId> {
        crate::types::CryptoSuiteId::from_u8(self.crypto_suite)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            protocol_version: u16::from_le_bytes([bytes[4], bytes[5]]),
            msg_type: u16::from_le_bytes([bytes[6], bytes[7]]),
            session_seq: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
            epoch_id: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            flags: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            payload_len: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            crypto_suite: bytes[28],
            reserved_ver: bytes[29],
            reserved: u16::from_le_bytes([bytes[30], bytes[31]]),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.protocol_version.to_le_bytes());
        out[6..8].copy_from_slice(&self.msg_type.to_le_bytes());
        out[8..16].copy_from_slice(&self.session_seq.to_le_bytes());
        out[16..20].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[20..24].copy_from_slice(&self.flags.to_le_bytes());
        out[24..28].copy_from_slice(&self.payload_len.to_le_bytes());
        out[28] = self.crypto_suite;
        out[29] = self.reserved_ver;
        out[30..32].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    StatusQuery = 0x0001,
    StatusResponse = 0x0002,
    LiveStateRequest = 0x0040,
    LiveStateResponse = 0x0041,
    LatencyProbe = 0x0003,
    LatencyProbeAck = 0x0004,
    LockVerifyRequest = 0x0101,
    LockVerifyResponse = 0x0102,
    EquivocationProof = 0x0105,
    EquivocationAck = 0x0106,
    ActiveSyncRequest = 0x0107,
    ActiveSyncDone = 0x0109,
    ShardDigestRequest = 0x010A,
    ShardDigestResponse = 0x010B,
    ShardBucketRangeRequest = 0x010C,
    ShardBucketRangeResponse = 0x010D,
    Heartbeat = 0x0201,
    HeartbeatAck = 0x0202,
    F2fOperatorMessage = 0x0203,
    F2fOperatorMessageAck = 0x0204,
    F2fNeighborRoster = 0x0205,
}

impl MsgType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(MsgType::StatusQuery),
            0x0002 => Some(MsgType::StatusResponse),
            0x0040 => Some(MsgType::LiveStateRequest),
            0x0041 => Some(MsgType::LiveStateResponse),
            0x0003 => Some(MsgType::LatencyProbe),
            0x0004 => Some(MsgType::LatencyProbeAck),
            0x0101 => Some(MsgType::LockVerifyRequest),
            0x0102 => Some(MsgType::LockVerifyResponse),
            0x0105 => Some(MsgType::EquivocationProof),
            0x0106 => Some(MsgType::EquivocationAck),
            0x0107 => Some(MsgType::ActiveSyncRequest),
            0x0109 => Some(MsgType::ActiveSyncDone),
            0x010A => Some(MsgType::ShardDigestRequest),
            0x010B => Some(MsgType::ShardDigestResponse),
            0x010C => Some(MsgType::ShardBucketRangeRequest),
            0x010D => Some(MsgType::ShardBucketRangeResponse),
            0x0201 => Some(MsgType::Heartbeat),
            0x0202 => Some(MsgType::HeartbeatAck),
            0x0203 => Some(MsgType::F2fOperatorMessage),
            0x0204 => Some(MsgType::F2fOperatorMessageAck),
            0x0205 => Some(MsgType::F2fNeighborRoster),
            _ => None,
        }
    }
}

pub const FLAG_PROVISIONAL: u32 = 0x0000_0001;
pub const FLAG_FINAL: u32 = 0x0000_0002;
pub const FLAG_EXPIRED_CLEANUP: u32 = 0x0000_0004;
pub const FLAG_HEDGED: u32 = 0x0000_0008;
pub const FLAG_COMPRESSED: u32 = 0x0000_0010;
pub const FLAG_PEER_SUSPENDED: u32 = 0x0000_0040;
pub const FLAG_POW_OUTDATED: u32 = 0x0000_0080;
pub const FLAG_QUOTA_EXCEEDED: u32 = 0x0000_0100;
pub const FLAG_QUOTA_FRAUD: u32 = 0x0000_0200;
pub const FLAG_NOT_IN_SHARD: u32 = 0x0000_0400;
pub const FLAG_UNAUTHORIZED: u32 = 0x0000_0800;
pub const FLAG_SIGNATURE_INVALID: u32 = 0x0000_1000;
pub const FLAG_NOT_READY: u32 = 0x0000_2000;
/// Durable identical request observed by this custodian.
pub const FLAG_REPLAY: u32 = 0x0000_8000;
pub const FLAG_COLLISION_DETECTED: u32 = 0x0000_4000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_header_size() {
        assert_eq!(std::mem::size_of::<WireHeader>(), 32);
        assert_eq!(WireHeader::SIZE, 32);
        assert_eq!(std::mem::align_of::<WireHeader>(), 8);
    }

    #[test]
    fn test_wire_header_roundtrip() {
        let hdr = WireHeader::new(MsgType::StatusQuery as u16, 42, 1, FLAG_FINAL, 128);
        let bytes = hdr.to_bytes();
        let parsed = WireHeader::from_bytes(&bytes);
        assert_eq!(hdr, parsed);
        assert!(parsed.is_valid_magic());
    }

    #[test]
    fn test_msg_type_from_u16() {
        assert_eq!(MsgType::from_u16(0x0203), Some(MsgType::F2fOperatorMessage));
        assert_eq!(MsgType::from_u16(0x0204), Some(MsgType::F2fOperatorMessageAck));
        assert_eq!(MsgType::from_u16(0x0205), Some(MsgType::F2fNeighborRoster));
        assert_eq!(MsgType::from_u16(0xFFFF), None);
    }
}
