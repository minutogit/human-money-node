//! Spec 10 & 13: Wire Framing, Access Tiering, Rate Limiter
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64};

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
    pub min_compat_ver: u8,
    pub reserved: u16,
}

impl WireHeader {
    pub const SIZE: usize = 32;
    pub fn new(msg_type: u16, session_seq: u64, epoch_id: u32, flags: u32, payload_len: u32) -> Self {
        Self {
            magic: WIRE_MAGIC,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            msg_type,
            session_seq,
            epoch_id,
            flags,
            payload_len,
            crypto_suite: 0,
            min_compat_ver: 0,
            reserved: 0,
        }
    }
    #[inline(always)]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == WIRE_MAGIC
    }
    /// Backward-compatible crypto suite: 0x00 -> Ed25519Blake3 (suite 1)
    #[inline(always)]
    pub fn crypto_suite(&self) -> crate::types::CryptoSuiteId {
        crate::types::CryptoSuiteId::from_u8(self.crypto_suite)
    }
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            protocol_version: u16::from_le_bytes([bytes[4], bytes[5]]),
            msg_type: u16::from_le_bytes([bytes[6], bytes[7]]),
            session_seq: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            epoch_id: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            flags: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            payload_len: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            crypto_suite: bytes[28],
            min_compat_ver: bytes[29],
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
        out[29] = self.min_compat_ver;
        out[30..32].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    StatusQuery = 0x0001,
    StatusResponse = 0x0002,
    LatencyProbe = 0x0003,
    LatencyProbeAck = 0x0004,
    ShardMapPing = 0x0005,
    ShardMapPong = 0x0006,
    LockVerifyRequest = 0x0101,
    LockVerifyResponse = 0x0102,
    MergeLoserBroadcast = 0x0103,
    MergeLoserAck = 0x0104,
    EquivocationProof = 0x0105,
    EquivocationAck = 0x0106,
    ActiveSyncRequest = 0x0107,
    ActiveSyncChunk = 0x0108,
    ActiveSyncDone = 0x0109,
    ShardDigestRequest = 0x010A,
    ShardDigestResponse = 0x010B,
    Heartbeat = 0x0201,
    HeartbeatAck = 0x0202,
    GossipAnnounce = 0x0203,
}

pub const FLAG_PROVISIONAL: u32 = 0x0000_0001;
pub const FLAG_FINAL: u32 = 0x0000_0002;
pub const FLAG_EXPIRED_CLEANUP: u32 = 0x0000_0004;
pub const FLAG_HEDGED: u32 = 0x0000_0008;
pub const FLAG_COMPRESSED: u32 = 0x0000_0010;
pub const FLAG_BRIDGE_LOCK: u32 = 0x0000_0020;

/// Witness-separation LockEnvelope (suite_id + witness-separated fields)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockEnvelope {
    pub suite_id: u8,
    pub parent_lock: [u8; 32],
    pub receiver_data: Vec<u8>,
    pub valid_until: u64,
    pub witness_signature: Vec<u8>,
    pub status: u8,
}

/// 144-Byte LockEntry (INV-1001)
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockEntry144 {
    pub parent_lock: [u8; 32],
    pub receiver_pub: [u8; 32],
    pub valid_until: u64,
    pub owner_signature: [u8; 64],
    pub status: u8,
    pub padding: [u8; 7],
}

impl LockEntry144 {
    pub const SIZE: usize = 144;
    pub fn to_bytes(&self) -> [u8; 144] {
        let mut out = [0u8; 144];
        out[0..32].copy_from_slice(&self.parent_lock);
        out[32..64].copy_from_slice(&self.receiver_pub);
        out[64..72].copy_from_slice(&self.valid_until.to_le_bytes());
        out[72..136].copy_from_slice(&self.owner_signature);
        out[136] = self.status;
        out[137..144].copy_from_slice(&self.padding);
        out
    }
    pub fn from_bytes(bytes: &[u8; 144]) -> Self {
        let mut parent_lock = [0u8; 32];
        parent_lock.copy_from_slice(&bytes[0..32]);
        let mut receiver_pub = [0u8; 32];
        receiver_pub.copy_from_slice(&bytes[32..64]);
        let valid_until = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let mut owner_signature = [0u8; 64];
        owner_signature.copy_from_slice(&bytes[72..136]);
        let status = bytes[136];
        let mut padding = [0u8; 7];
        padding.copy_from_slice(&bytes[137..144]);
        Self {
            parent_lock,
            receiver_pub,
            valid_until,
            owner_signature,
            status,
            padding,
        }
    }
}

/// Zero-copy parser
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    InvalidMagic,
    UnsupportedVersion(u16),
    ZeroRttForbiddenForWrites,
    SequenceGap { expected: u64, got: u64 },
    PayloadTooLarge { limit: u32, got: u32 },
    CorruptedPayload,
}

pub fn parse_wire_header(raw: &[u8; 32], expected_seq: u64, is_0rtt: bool) -> Result<WireHeader, WireError> {
    let header = WireHeader::from_bytes(raw);
    if !header.is_valid_magic() {
        return Err(WireError::InvalidMagic);
    }
    if header.protocol_version != CURRENT_PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(header.protocol_version));
    }
    if is_0rtt {
        let allowed = matches!(
            header.msg_type,
            x if x == MsgType::StatusQuery as u16
                || x == MsgType::LatencyProbe as u16
                || x == MsgType::ShardMapPing as u16
                || x == MsgType::ActiveSyncRequest as u16
        );
        if !allowed {
            return Err(WireError::ZeroRttForbiddenForWrites);
        }
    }
    if header.session_seq != expected_seq {
        return Err(WireError::SequenceGap { expected: expected_seq, got: header.session_seq });
    }
    Ok(header)
}

// ---------------------------------------------------------------------------
// Access Tiering (Spec 13)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTier {
    VipMerchant = 1,
    FriendCommunity = 2,
    LightPublic = 3,
}

pub type AccountTag = [u8; 32];

pub fn derive_account_tag(client_pubkey: &[u8; 32], node_secret: &[u8; 32]) -> AccountTag {
    let mut hasher = blake3::Hasher::new();
    let tag = b"HUMOCO_V1_ACCOUNT_TAG";
    hasher.update(&(tag.len() as u8).to_le_bytes());
    hasher.update(tag);
    hasher.update(client_pubkey);
    hasher.update(node_secret);
    *hasher.finalize().as_bytes()
}

#[repr(C, align(8))]
pub struct IngressAccount {
    pub tag: AccountTag,
    pub tier: AccessTier,
    pub _padding: [u8; 7],
    pub valid_until: u64,
    pub remaining_micro_bj: AtomicU64,
    pub max_locks_per_min: AtomicU32,
    pub current_locks_window: AtomicU32,
}

impl IngressAccount {
    pub fn new(tag: AccountTag, tier: AccessTier, valid_until: u64, quota_micro_bj: u64, max_per_min: u32) -> Self {
        Self {
            tag,
            tier,
            _padding: [0; 7],
            valid_until,
            remaining_micro_bj: AtomicU64::new(quota_micro_bj),
            max_locks_per_min: AtomicU32::new(max_per_min),
            current_locks_window: AtomicU32::new(0),
        }
    }
}

pub struct AccessControl {
    vip_db: HashMap<AccountTag, AccessTier>,
    node_secret: [u8; 32],
}

impl AccessControl {
    pub fn new(node_secret: [u8; 32]) -> Self {
        Self { vip_db: HashMap::new(), node_secret }
    }
    pub fn register(&mut self, tag: AccountTag, tier: AccessTier) {
        self.vip_db.insert(tag, tier);
    }
    pub fn register_pubkey(&mut self, pubkey: [u8; 32], tier: AccessTier) -> AccountTag {
        let tag = derive_account_tag(&pubkey, &self.node_secret);
        self.register(tag, tier);
        tag
    }
    /// Classify incoming request: Tier 1 VIP, Tier 2 Friend, else Tier 3 Public
    pub fn classify(&self, account_tag: Option<AccountTag>) -> AccessTier {
        match account_tag {
            Some(tag) => self.vip_db.get(&tag).copied().unwrap_or(AccessTier::LightPublic),
            None => AccessTier::LightPublic,
        }
    }
    /// Simple Argon2id PoW check (deterministic stand-in): hash(challenge||nonce) < target
    pub fn verify_pow(challenge: &[u8; 32], nonce: u64, difficulty: u8) -> bool {
        // difficulty 0 = always pass, higher = harder (require leading zero bytes)
        if difficulty == 0 {
            return true;
        }
        let mut hasher = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_POW";
        hasher.update(&(tag.len() as u8).to_le_bytes());
        hasher.update(tag);
        hasher.update(challenge);
        hasher.update(&nonce.to_le_bytes());
        // memory-hard simulation: use 64-byte hash and check leading zeros
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        let zero_bytes = (difficulty as usize) / 8;
        let rem_bits = (difficulty as usize) % 8;
        for byte in bytes.iter().take(zero_bytes) {
            if *byte != 0 {
                return false;
            }
        }
        if rem_bits > 0 {
            let mask = (1u8 << (8 - rem_bits)) - 1;
            // Actually check high bits zero: require bytes[zero_bytes] < (1 << (8 - rem_bits))
            if bytes[zero_bytes] & (0xFF << (8 - rem_bits)) != 0 {
                // Simplified: check that high rem_bits are zero => bytes[zero_bytes] >> (8-rem_bits) ==0
                // Implemented via mask
                let _ = mask;
                if bytes[zero_bytes] >> (8 - rem_bits) != 0 {
                    return false;
                }
            }
        }
        true
    }
    pub fn pow_challenge(client_ip_prefix: &[u8], epoch_minute: u32, difficulty: u8, node_secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_CHALLENGE";
        hasher.update(&(tag.len() as u8).to_le_bytes());
        hasher.update(tag);
        hasher.update(client_ip_prefix);
        hasher.update(&epoch_minute.to_le_bytes());
        hasher.update(&[difficulty]);
        hasher.update(node_secret);
        *hasher.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Token Bucket Rate Limiter (INV-1302)
// ---------------------------------------------------------------------------

pub struct TokenBucket {
    pub capacity: u64,
    pub refill_per_sec: u64,
    pub tokens: f64,
    pub last_refill_ms: u64,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_sec: u64, now_ms: u64) -> Self {
        Self { capacity, refill_per_sec, tokens: capacity as f64, last_refill_ms: now_ms }
    }
    fn refill(&mut self, now_ms: u64) {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        if elapsed_ms == 0 {
            return;
        }
        let added = (elapsed_ms as f64 / 1000.0) * self.refill_per_sec as f64;
        self.tokens = (self.tokens + added).min(self.capacity as f64);
        self.last_refill_ms = now_ms;
    }
    /// Try consume n tokens, return true if allowed
    pub fn try_consume(&mut self, n: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
    pub fn available(&mut self, now_ms: u64) -> u64 {
        self.refill(now_ms);
        self.tokens.floor() as u64
    }
}

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
    fn test_lock_entry_144_size() {
        assert_eq!(std::mem::size_of::<LockEntry144>(), 144);
        assert_eq!(LockEntry144::SIZE, 144);
    }
    #[test]
    fn test_token_bucket() {
        let mut tb = TokenBucket::new(10, 10, 0);
        assert!(tb.try_consume(10, 0));
        assert!(!tb.try_consume(1, 0));
        assert!(tb.try_consume(1, 100)); // 0.1 sec -> 1 token
        assert!(!tb.try_consume(10, 100));
        assert!(tb.try_consume(10, 2000)); // 2 sec refill fully
    }
}
