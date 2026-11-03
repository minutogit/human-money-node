use humoco_sim_core::wire::{MsgType, WireHeader, CURRENT_PROTOCOL_VERSION, WIRE_MAGIC};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::NodeError;

pub const MAX_STANDARD_FRAME_PAYLOAD_LEN: usize = 64 * 1024; // 64 KiB
pub const MAX_SYNC_FRAME_PAYLOAD_LEN: usize = MAX_STANDARD_FRAME_PAYLOAD_LEN;
pub const MAX_FRAME_PAYLOAD_LEN: usize = MAX_SYNC_FRAME_PAYLOAD_LEN;
pub const DEFAULT_STREAM_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub const FLAG_AUTHENTICATED_DISCOVERY: u32 = 1 << 16;
pub const MAX_AUTHENTICATED_DISCOVERY_BYTES: usize = 64 * 1024;

/// Pure length-prefixed BLAKE3 digest helper for custodian-authenticated slot discovery.
#[allow(clippy::too_many_arguments)]
pub fn compute_slot_discovery_digest(
    network: u8,
    shard_id: u16,
    request_session_seq: u64,
    parent_lock: &[u8; 32],
    child_lock: &[u8; 32],
    state_digest: &[u8; 32],
    root_valid_until: u64,
    custodian_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tag = b"HUMOCO_V1_LIVE_SLOT_DISCOVERY";
    hasher.update(&(tag.len() as u8).to_le_bytes());
    hasher.update(tag);
    hasher.update(&[network]);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&request_session_seq.to_le_bytes());
    hasher.update(parent_lock);
    hasher.update(child_lock);
    hasher.update(state_digest);
    hasher.update(&root_valid_until.to_le_bytes());
    hasher.update(custodian_pubkey);
    *hasher.finalize().as_bytes()
}

/// Bounded custodian-authenticated rival slot discovery payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatedSlotDiscovery {
    pub entry: crate::api::hmc::L2LockEntry,
    pub root_valid_until: u64,
    pub custodian_pubkey: [u8; 32],
    #[serde(with = "serde_sig_64")]
    pub custodian_signature: [u8; 64],
}

impl AuthenticatedSlotDiscovery {
    pub fn verify_signature(
        &self,
        expected_network: u8,
        shard_id: u16,
        request_session_seq: u64,
        parent_lock: &[u8; 32],
        state_digest: &[u8; 32],
    ) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&self.custodian_pubkey) else {
            return false;
        };
        let digest = compute_slot_discovery_digest(
            expected_network,
            shard_id,
            request_session_seq,
            parent_lock,
            &self.entry.t_id,
            state_digest,
            self.root_valid_until,
            &self.custodian_pubkey,
        );
        key.verify_strict(
            &digest,
            &ed25519_dalek::Signature::from_bytes(&self.custodian_signature),
        )
        .is_ok()
    }
}

/// Optional self-signed signing-history checkpoint, carried on the existing
/// heartbeat stream. It is not a vote, quorum or membership claim.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigningCheckpoint {
    pub network: u8,
    pub node_pubkey: [u8; 32],
    pub generation: u64,
    pub fingerprint: [u8; 32],
    #[serde(with = "serde_sig_64")]
    pub signature: [u8; 64],
}
impl SigningCheckpoint {
    fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        let domain = b"HUMOCO_V1_SIGNING_CHECKPOINT";
        h.update(&[domain.len() as u8]);
        h.update(domain);
        h.update(&[self.network]);
        h.update(&self.node_pubkey);
        h.update(&self.generation.to_le_bytes());
        h.update(&self.fingerprint);
        *h.finalize().as_bytes()
    }
    pub fn signed(
        identity: &crate::identity::NodeIdentity,
        network: u8,
        generation: u64,
        fingerprint: [u8; 32],
    ) -> Self {
        use ed25519_dalek::Signer;
        let mut result = Self {
            network,
            node_pubkey: *identity.node_pubkey(),
            generation,
            fingerprint,
            signature: [0; 64],
        };
        result.signature = identity.signing_key().sign(&result.digest()).to_bytes();
        result
    }
    pub fn verify(&self, expected_key: &[u8; 32], expected_network: u8) -> bool {
        if self.node_pubkey != *expected_key || self.network != expected_network {
            return false;
        }
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(expected_key) else {
            return false;
        };
        key.verify_strict(
            &self.digest(),
            &ed25519_dalek::Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

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
    #[serde(default)]
    pub signing_checkpoint: Option<SigningCheckpoint>,
    #[serde(default)]
    pub gateway_advertisement: Option<crate::network::discovery::GatewayAdvertisement>,
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
        bincode::deserialize(bytes)
    }

    /// Computes the canonical announcement hash binding `(addr, pow_nonce, hrw_routing_id, ticket_epoch_t0)`.
    pub fn compute_announcement_hash(&self) -> [u8; 32] {
        humoco_sim_core::fraud::compute_heartbeat_announcement_hash(
            &self.addr,
            self.pow_nonce,
            &self.hrw_routing_id,
            self.ticket_epoch_t0,
        )
    }

    /// Signs this heartbeat as the origin node, cryptographically binding its announced
    /// endpoint address, PoW parameters, and EMA declarations into `signature`.
    pub fn sign_origin(&mut self, identity: &crate::identity::NodeIdentity, now_ms: u64) {
        use ed25519_dalek::Signer;
        self.node_id = *identity.node_pubkey();
        self.timestamp_ms = now_ms;
        self.pow_nonce = identity.nonce();
        self.hrw_routing_id = *identity.hrw_routing_id();
        self.ticket_epoch_t0 = identity.t0();

        let op_hash = self.compute_announcement_hash();
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            &self.node_id,
            0,
            0,
            self.timestamp_ms,
            self.declared_write_ema_micro_bj,
            self.declared_read_ema_credits,
            0,
            false,
            &op_hash,
        );
        self.signature = identity.signing_key().sign(&digest).to_bytes();
    }

    /// Verifies that the heartbeat signature is valid and strictly binds `self.addr`
    /// (via `op_hash = announcement_hash`). Required for relayed multi-hop gossip (`hops > 0`).
    pub fn verify_origin_address_binding(&self) -> bool {
        if self.signature == [0u8; 64] {
            return false;
        }
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.node_id) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        let op_hash = self.compute_announcement_hash();
        let digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            &self.node_id,
            0,
            0,
            self.timestamp_ms,
            self.declared_write_ema_micro_bj,
            self.declared_read_ema_credits,
            0,
            false,
            &op_hash,
        );
        use ed25519_dalek::Verifier;
        vk.verify(&digest, &sig).is_ok()
    }

    /// Verifies the origin signature with canonical address binding.
    pub fn verify_origin_signature(&self) -> bool {
        self.verify_origin_address_binding()
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

    pub fn deserialize<'de, D>(deserializer: D) -> Result<crate::api::hmc::L2LockRequest, D::Error>
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
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Unified wire payload for lock verification across simulation and HMC domains.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum LockWirePayload {
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
            Self::Hmc {
                declared_write_ema_micro_bj,
                ..
            } => *declared_write_ema_micro_bj,
        }
    }

    pub fn declared_read_ema_credits(&self) -> u64 {
        match self {
            Self::Hmc {
                declared_read_ema_credits,
                ..
            } => *declared_read_ema_credits,
        }
    }

    pub fn epoch_day(&self) -> u32 {
        match self {
            Self::Hmc { epoch_day, .. } => *epoch_day,
        }
    }

    pub fn epoch_seq(&self) -> u64 {
        match self {
            Self::Hmc { epoch_seq, .. } => *epoch_seq,
        }
    }

    pub fn cumulative_micro_byte_years(&self) -> u64 {
        match self {
            Self::Hmc {
                cumulative_micro_byte_years,
                ..
            } => *cumulative_micro_byte_years,
        }
    }

    pub fn prev_day_final_bytes(&self) -> u64 {
        match self {
            Self::Hmc {
                prev_day_final_bytes,
                ..
            } => *prev_day_final_bytes,
        }
    }

    pub fn current_anl_24h(&self) -> u64 {
        match self {
            Self::Hmc {
                current_anl_24h, ..
            } => *current_anl_24h,
        }
    }

    pub fn chain(&self) -> Option<&crate::api::hmc::L2ChainLockRequest> {
        match self {
            Self::Hmc { chain, .. } => chain.as_ref(),
        }
    }

    pub fn sender_pubkey(&self) -> [u8; 32] {
        match self {
            Self::Hmc {
                sender_pubkey, req, ..
            } => {
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
            Self::Hmc {
                sender_signature, ..
            } => *sender_signature,
        }
    }

    pub fn timestamp_ms(&self) -> u64 {
        match self {
            Self::Hmc { timestamp_ms, .. } => *timestamp_ms,
        }
    }
}

/// Versioned, unsigned existence observation for an exact status lookup.
/// This is diagnostic only: it carries no original approval or live-state vote.
/// Tag-only HMC queries retain their full `L2LockEntry` response format.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StatusObservation {
    pub version: u8,
    pub lock_id: [u8; 32],
    pub parent_lock: [u8; 32],
    pub shard_id: u16,
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

/// Active sync payload carrying HMC L2LockEntries and confirmation support.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncPayload {
    #[serde(with = "hmc_locks_json")]
    pub hmc_locks: Vec<(String, crate::api::hmc::L2LockEntry)>,
    pub support: Vec<(u8, String, crate::storage::db::support::ConfirmationSupport)>,
}

impl SyncPayload {
    pub fn new(hmc_locks: Vec<(String, crate::api::hmc::L2LockEntry)>) -> Self {
        Self {
            hmc_locks,
            support: Vec::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Paginated ActiveSync request payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActiveSyncRequest {
    pub version: u8,
    #[serde(default)]
    pub cursor: u64,
    #[serde(default = "default_sync_limit")]
    pub limit: usize,
    #[serde(default)]
    pub target_bucket_id: Option<u64>,
    pub target_shard: Option<u16>,
}

pub fn default_sync_limit() -> usize {
    500
}

impl ActiveSyncRequest {
    pub fn new(cursor: u64, limit: usize) -> Self {
        Self {
            version: 2,
            cursor,
            limit,
            target_bucket_id: None,
            target_shard: None,
        }
    }

    pub fn with_bucket(cursor: u64, limit: usize, target_bucket_id: Option<u64>) -> Self {
        Self {
            version: 2,
            cursor,
            limit,
            target_bucket_id,
            target_shard: None,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        let request: Self = bincode::deserialize(bytes)?;
        if request.version != 2 {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "fixed snapshot protocol version required".into(),
            )));
        }
        Ok(request)
    }
}

/// Paginated ActiveSync response payload.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ActiveSyncResponse {
    pub version: u8,
    pub payload: SyncPayload,
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<u64>,
}

impl ActiveSyncResponse {
    pub fn new(payload: SyncPayload, has_more: bool, next_cursor: Option<u64>) -> Self {
        Self {
            version: 3,
            payload,
            has_more,
            next_cursor,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        let response: Self = bincode::deserialize(bytes)?;
        if response.version != 3 {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "fixed snapshot response required".into(),
            )));
        }
        Ok(response)
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
    if msg_type == MsgType::ActiveSyncRequest as u16 || msg_type == MsgType::ActiveSyncDone as u16 {
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
    let ((header, payload), _permit) = read_frame_admitted(reader, timeout_dur, None).await?;
    Ok((header, payload))
}

/// Class-specific admission happens after the validated header and before reading
/// or allocating the body. The owned permit lives through handler completion.
pub async fn read_frame_admitted<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    timeout_dur: Duration,
    pools: Option<(
        std::sync::Arc<tokio::sync::Semaphore>,
        std::sync::Arc<tokio::sync::Semaphore>,
    )>,
) -> Result<
    (
        (WireHeader, Vec<u8>),
        Option<tokio::sync::OwnedSemaphorePermit>,
    ),
    NodeError,
> {
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

        if header.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(NodeError::Network(format!(
                "Unsupported protocol version: expected {}, got {}",
                CURRENT_PROTOCOL_VERSION, header.protocol_version
            )));
        }

        if header.crypto_suite().is_none() {
            return Err(NodeError::Network(format!(
                "Unsupported crypto suite: {}",
                header.crypto_suite
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

        let permit = if let Some((sync, rpc)) = pools {
            let pool = if header.msg_type == MsgType::ActiveSyncRequest as u16 {
                sync
            } else {
                rpc
            };
            Some(
                pool.try_acquire_owned()
                    .map_err(|_| NodeError::LocalCapacity("wire service admission exhausted"))?,
            )
        } else {
            None
        };
        let mut payload = Vec::with_capacity(payload_len.min(64 * 1024));
        let mut limited_reader = reader.take(payload_len as u64);
        limited_reader.read_to_end(&mut payload).await?;
        if payload.len() != payload_len {
            return Err(NodeError::Network(
                "Unexpected EOF while reading frame payload".into(),
            ));
        }

        Ok(((header, payload), permit))
    })
    .await
    .map_err(|_| {
        NodeError::Network("Read timeout exceeded on QUIC stream (Slowloris protection)".into())
    })?
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
        let header = WireHeader::new(
            MsgType::Heartbeat as u16,
            1,
            1,
            0,
            large_payload.len() as u32,
        );
        let mut buffer = Vec::new();
        let err = write_frame(&mut buffer, &header, &large_payload).await;
        assert!(err.is_err(), "Standard frame > 64KiB must be rejected");

        // Sync frames obey the same ceiling before any payload read.
        let sync_header = WireHeader::new(MsgType::ActiveSyncDone as u16, 1, 1, 0, 100 * 1024);
        let sync_payload = vec![1u8; 100 * 1024];
        let ok = write_frame(&mut buffer, &sync_header, &sync_payload).await;
        assert!(ok.is_err(), "Sync frame >64KiB must be rejected");
    }

    #[tokio::test]
    async fn test_slowloris_timeout() {
        // A duplex pipe where the writer never writes anything
        let (mut client_stream, _server_stream) = tokio::io::duplex(64);
        let timeout_dur = Duration::from_millis(50);
        let res = read_frame_with_timeout(&mut client_stream, timeout_dur).await;
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Read timeout exceeded"));
    }

    #[tokio::test]
    async fn test_read_frame_admitted_rejects_unsupported_crypto_suites_before_body_and_admission() {
        for unsupported_suite in [0u8, 2u8, 3u8, 255u8] {
            let mut hdr = WireHeader::new(MsgType::Heartbeat as u16, 1, 1, 0, 64);
            hdr.crypto_suite = unsupported_suite;

            // We use a duplex pipe where the server writes ONLY the 32-byte header,
            // advertising a 64-byte payload, and keeps the connection open.
            // If read_frame_admitted attempts to read the advertised body bytes,
            // it would block waiting for body data until the 5-second timeout expires.
            // Fast execution strictly proves rejection occurs immediately on the fixed header
            // without waiting for the body and without hitting EOF.
            let (mut client, mut server) = tokio::io::duplex(256);
            server
                .write_all(&hdr.to_bytes())
                .await
                .expect("write header bytes");

            let sync_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
            let rpc_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(10));

            let start = std::time::Instant::now();
            let res = read_frame_admitted(
                &mut client,
                Duration::from_secs(5),
                Some((sync_sem.clone(), rpc_sem.clone())),
            )
            .await;

            let elapsed = start.elapsed();
            assert!(
                elapsed < Duration::from_millis(500),
                "Header rejection must return immediately without waiting for body; elapsed: {elapsed:?}"
            );

            assert!(res.is_err(), "suite {unsupported_suite} must be rejected");
            let err = res.unwrap_err();
            assert!(
                err.to_string().contains("Unsupported crypto suite"),
                "Error must identify unsupported crypto suite, got: {err}"
            );
            assert_eq!(
                rpc_sem.available_permits(),
                10,
                "Service admission permit must not be acquired for unsupported suite {unsupported_suite}"
            );
            assert_eq!(
                sync_sem.available_permits(),
                10,
                "Sync permit must not be acquired for unsupported suite {unsupported_suite}"
            );
        }
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
            signing_checkpoint: None,
            gateway_advertisement: None,
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
        assert_eq!(
            decoded.piggyback_observations.len(),
            2,
            "Must cap at 2 entries"
        );
        assert_eq!(
            decoded.piggyback_observations[0].gateway_pubkey,
            ev1.gateway_pubkey
        );
        assert_eq!(
            decoded.piggyback_observations[1].gateway_pubkey,
            ev2.gateway_pubkey
        );

        // 2. JSON serde: omitted piggyback_observations defaults to empty Vec
        let json_str = r#"{
            "node_id": [9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
            "addr": "127.0.0.1:9090",
            "timestamp_ms": 12345,
            "declared_write_ema_micro_bj": 100,
            "declared_read_ema_credits": 200,
            "supported_suites_mask": 0
        }"#;
        let decoded_json: HeartbeatWirePayload =
            serde_json::from_str(json_str).expect("deserialize json");
        assert!(
            decoded_json.piggyback_observations.is_empty(),
            "Omitted field defaults to empty Vec"
        );

        // 3. JSON serde with 3 entries caps at 2
        let json_with_3 = serde_json::to_string(&hb).expect("serialize json");
        let decoded_json_3: HeartbeatWirePayload =
            serde_json::from_str(&json_with_3).expect("deserialize json");
        assert_eq!(
            decoded_json_3.piggyback_observations.len(),
            2,
            "JSON must cap at 2 entries"
        );
    }

    #[test]
    fn test_heartbeat_origin_signature_and_tamper_detection() {
        let identity = crate::identity::NodeIdentity::generate();
        let addr: std::net::SocketAddr = "127.0.0.1:9090".parse().unwrap();
        let mut hb = HeartbeatWirePayload {
            gateway_advertisement: None,
            signing_checkpoint: None,
            node_id: *identity.node_pubkey(),
            addr,
            timestamp_ms: 12345,
            declared_write_ema_micro_bj: 100,
            declared_read_ema_credits: 200,
            signature: [0; 64],
            supported_suites_mask: 0,
            piggyback_observations: vec![],
            pow_nonce: identity.nonce(),
            hrw_routing_id: *identity.hrw_routing_id(),
            ticket_epoch_t0: identity.t0(),
            ttl: 16,
        };

        // Unsigned initially
        assert!(!hb.verify_origin_address_binding());
        assert!(!hb.verify_origin_signature());

        // Origin-signed
        hb.sign_origin(&identity, 12345);
        assert!(
            hb.verify_origin_address_binding(),
            "Must verify address binding"
        );
        assert!(hb.verify_origin_signature(), "Must verify origin signature");

        // Tamper with address: forged relay attempt
        let mut tampered_addr = hb.clone();
        tampered_addr.addr = "127.0.0.1:31338".parse().unwrap();
        assert!(
            !tampered_addr.verify_origin_address_binding(),
            "Tampered address must fail address binding"
        );

        // Tamper with timestamp
        let mut tampered_ts = hb.clone();
        tampered_ts.timestamp_ms = 99999;
        assert!(
            !tampered_ts.verify_origin_address_binding(),
            "Tampered timestamp must fail"
        );

        // Tamper with EMA
        let mut tampered_ema = hb.clone();
        tampered_ema.declared_write_ema_micro_bj = 9999;
        assert!(
            !tampered_ema.verify_origin_address_binding(),
            "Tampered EMA must fail"
        );

        // Legacy signature with op_hash = [0; 32] without canonical address binding must fail
        use ed25519_dalek::Signer;
        let legacy_digest = humoco_sim_core::fraud::compute_ingress_envelope_digest_v2(
            identity.node_pubkey(),
            0,
            0,
            12345,
            100,
            200,
            0,
            false,
            &[0u8; 32],
        );
        let mut legacy_hb = hb.clone();
        legacy_hb.signature = identity.signing_key().sign(&legacy_digest).to_bytes();
        assert!(
            !legacy_hb.verify_origin_address_binding(),
            "Legacy signature must NOT satisfy address binding"
        );
        assert!(
            !legacy_hb.verify_origin_signature(),
            "Legacy signature without address binding must fail"
        );
    }
}

/// Fresh authenticated no-gap source fence, independent of old quorum bundles.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FrozenShardReply {
    pub version: u8,
    pub token: [u8; 16],
    pub digest: [u8; 32],
    pub lease_ms: u64,
    pub support_digest: [u8; 32],
    pub signature: Vec<u8>,
}

impl FrozenShardReply {
    /// A cold-transfer assertion, never an original approval or checkout proof.
    pub fn signing_digest(
        &self,
        network: humoco_sim_core::types::NetworkId,
        shard: u16,
        source: &[u8; 32],
        receiver: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        let tag = b"HUMOCO_V1_INHERITED_SUPPORT_CUT";
        h.update(&[tag.len() as u8]);
        h.update(tag);
        h.update(&[self.version]);
        h.update(&[match network {
            humoco_sim_core::types::NetworkId::Mainnet => 0,
            humoco_sim_core::types::NetworkId::Testnet => 1,
        }]);
        h.update(&shard.to_le_bytes());
        h.update(source);
        h.update(receiver);
        h.update(&self.token);
        h.update(&self.digest);
        h.update(&self.support_digest);
        h.update(&self.lease_ms.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

pub const MAX_F2F_FRAME_PAYLOAD_LEN: usize = 2048;

/// Direct F2F operator dialogue payload (human text + optional machine-readable trace).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct F2fOperatorMessagePayload {
    pub msg_id: u64,
    pub sender_pubkey: [u8; 32],
    pub timestamp_ms: u64,
    pub text: String,
    pub trace_pubkeys: Vec<[u8; 32]>,
    pub reply_to_msg_id: Option<u64>,
}

impl F2fOperatorMessagePayload {
    pub fn validate(&self) -> Result<(), bincode::Error> {
        if self.text.len() > 500 {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "F2F message text exceeds maximum length of 500 bytes".into(),
            )));
        }
        if self.text.chars().any(|c| c.is_ascii_control() && c != '\n' && c != '\t') {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "F2F message text contains forbidden ASCII control characters".into(),
            )));
        }
        if self.trace_pubkeys.len() > 32 {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "F2F message trace_pubkeys exceeds maximum limit of 32 items".into(),
            )));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        self.validate()?;
        let bytes = bincode::serialize(self)?;
        if bytes.len() > MAX_F2F_FRAME_PAYLOAD_LEN {
            return Err(Box::new(bincode::ErrorKind::Custom(
                format!("Serialized F2fOperatorMessage exceeds {} bytes", MAX_F2F_FRAME_PAYLOAD_LEN),
            )));
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() > MAX_F2F_FRAME_PAYLOAD_LEN {
            return Err(Box::new(bincode::ErrorKind::Custom(
                format!("F2fOperatorMessage payload exceeds {} bytes", MAX_F2F_FRAME_PAYLOAD_LEN),
            )));
        }
        let payload: Self = bincode::deserialize(bytes)?;
        payload.validate()?;
        Ok(payload)
    }
}

/// Delivery acknowledgment for an F2F operator message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct F2fOperatorMessageAckPayload {
    pub msg_id: u64,
    pub receiver_pubkey: [u8; 32],
    pub timestamp_ms: u64,
}

impl F2fOperatorMessageAckPayload {
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        let bytes = bincode::serialize(self)?;
        if bytes.len() > MAX_F2F_FRAME_PAYLOAD_LEN {
            return Err(Box::new(bincode::ErrorKind::Custom(
                format!("Serialized F2fOperatorMessageAck exceeds {} bytes", MAX_F2F_FRAME_PAYLOAD_LEN),
            )));
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() > MAX_F2F_FRAME_PAYLOAD_LEN {
            return Err(Box::new(bincode::ErrorKind::Custom(
                format!("F2fOperatorMessageAck payload exceeds {} bytes", MAX_F2F_FRAME_PAYLOAD_LEN),
            )));
        }
        let payload: Self = bincode::deserialize(bytes)?;
        Ok(payload)
    }
}

/// Direct 1-hop F2F neighbor roster payload for Hop-2 environment transparency.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct F2fNeighborRosterPayload {
    pub sender_pubkey: [u8; 32],
    pub timestamp_ms: u64,
    pub shares_roster: bool,
    pub visible_neighbors: Vec<[u8; 32]>,
    pub hidden_neighbor_count: u16,
}

impl F2fNeighborRosterPayload {
    pub fn validate(&self) -> Result<(), bincode::Error> {
        if self.visible_neighbors.len() > 64 {
            return Err(Box::new(bincode::ErrorKind::Custom(
                "F2F neighbor roster visible_neighbors exceeds maximum limit of 64 items".into(),
            )));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        self.validate()?;
        let bytes = bincode::serialize(self)?;
        if bytes.len() > MAX_F2F_FRAME_PAYLOAD_LEN {
            return Err(Box::new(bincode::ErrorKind::Custom(
                format!("Serialized F2fNeighborRoster exceeds {} bytes", MAX_F2F_FRAME_PAYLOAD_LEN),
            )));
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        if bytes.len() > MAX_F2F_FRAME_PAYLOAD_LEN {
            return Err(Box::new(bincode::ErrorKind::Custom(
                format!("F2fNeighborRoster payload exceeds {} bytes", MAX_F2F_FRAME_PAYLOAD_LEN),
            )));
        }
        let payload: Self = bincode::deserialize(bytes)?;
        payload.validate()?;
        Ok(payload)
    }
}

#[cfg(test)]
mod f2f_payload_tests {
    use super::*;

    #[test]
    fn test_f2f_operator_message_roundtrip_and_validation() {
        let msg = F2fOperatorMessagePayload {
            msg_id: 1001,
            sender_pubkey: [7u8; 32],
            timestamp_ms: 1700000000000,
            text: "Hello friend!\nWorking on server upgrade.\tOK".into(),
            trace_pubkeys: vec![[1u8; 32], [2u8; 32]],
            reply_to_msg_id: Some(999),
        };
        let bytes = msg.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_F2F_FRAME_PAYLOAD_LEN);
        let parsed = F2fOperatorMessagePayload::from_bytes(&bytes).unwrap();
        assert_eq!(msg, parsed);

        // Text > 500 bytes rejected
        let mut oversize_text = msg.clone();
        oversize_text.text = "a".repeat(501);
        assert!(oversize_text.to_bytes().is_err());

        // Control chars other than \n and \t rejected (e.g. \r or \0 or \x1b)
        let mut control_text = msg.clone();
        control_text.text = "Hello\x1b[31mRed\x1b[0m".into();
        assert!(control_text.to_bytes().is_err());

        // Trace > 32 items rejected
        let mut oversize_trace = msg.clone();
        oversize_trace.trace_pubkeys = vec![[0u8; 32]; 33];
        assert!(oversize_trace.to_bytes().is_err());
    }

    #[test]
    fn test_f2f_operator_ack_roundtrip() {
        let ack = F2fOperatorMessageAckPayload {
            msg_id: 1001,
            receiver_pubkey: [9u8; 32],
            timestamp_ms: 1700000001000,
        };
        let bytes = ack.to_bytes().unwrap();
        let parsed = F2fOperatorMessageAckPayload::from_bytes(&bytes).unwrap();
        assert_eq!(ack, parsed);
    }

    #[test]
    fn test_f2f_neighbor_roster_roundtrip_and_validation() {
        let roster = F2fNeighborRosterPayload {
            sender_pubkey: [5u8; 32],
            timestamp_ms: 1700000000000,
            shares_roster: true,
            visible_neighbors: vec![[1u8; 32]; 10],
            hidden_neighbor_count: 2,
        };
        let bytes = roster.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_F2F_FRAME_PAYLOAD_LEN);
        let parsed = F2fNeighborRosterPayload::from_bytes(&bytes).unwrap();
        assert_eq!(roster, parsed);

        // > 64 visible neighbors rejected
        let mut oversize = roster.clone();
        oversize.visible_neighbors = vec![[1u8; 32]; 65];
        assert!(oversize.to_bytes().is_err());
    }
}
