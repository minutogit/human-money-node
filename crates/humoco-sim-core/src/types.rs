use std::fmt;
use std::ops::{Add, AddAssign, Sub};

/// 32-Byte Hash (BLAKE3 Digest)
pub type Hash256 = [u8; 32];

/// Unique identifier of a lock entry (32-byte hash)
pub type LockId = Hash256;

/// Node identifier for lightweight simulation (0..65535)
pub type NodeId = u16;

/// Shard Identifier (0..65535)
pub type ShardId = u16;

/// Ed25519 public key — permanent identity of a node (32 bytes)
pub type NodePubKey = [u8; 32];

/// Argon2d shard ticket — HRW routing identifier of a node (32 bytes, mined via Argon2d)
pub type HrwRoutingId = [u8; 32];

/// Network identifier for domain separation (Mainnet vs Testnet)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Default,
)]
pub enum NetworkId {
    #[default]
    Mainnet,
    Testnet,
}

/// Crypto suite identifier for wire headers
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoSuiteId {
    Ed25519Blake3 = 1,
}

impl CryptoSuiteId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Ed25519Blake3),
            _ => None,
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// 4-byte piggyback bitmask: bit i indicates response from the i-th candidate (among top-20)
pub type SignersBitmask = u32;

/// Failure threshold: after how many consecutive failures a node is suspended
pub const MISSING_COUNT_THRESHOLD: u32 = 3;

pub const FLAG_INBOUND_ACTIVE: u8 = 1 << 0;
pub const FLAG_LAST_FAILED: u8 = 1 << 1;

/// Deterministic discrete simulation time in milliseconds
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct SimTime(pub u64);

impl SimTime {
    pub const ZERO: SimTime = SimTime(0);

    pub fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }
}

impl Add<u64> for SimTime {
    type Output = SimTime;
    fn add(self, rhs: u64) -> Self::Output {
        SimTime(self.0.saturating_add(rhs))
    }
}

impl AddAssign<u64> for SimTime {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.saturating_add(rhs);
    }
}

impl Sub for SimTime {
    type Output = u64;
    fn sub(self, rhs: Self) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}

impl fmt::Display for SimTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// ARCHITECTURAL INVARIANT / AUDIT NOTE (Spec 02, 08):
/// Consensus Finality Thresholds:
/// - N < 20: Provisional (yellow, Q = floor(2R/3) + 1).
/// - N >= 20: Final (green, 14/20 BFT threshold after 24h hysteresis).
/// - High-Assurance (16/20 @ N>=100) was evaluated in `spec_widerspruchs_analyse.md`
///   and INTENTIONALLY OMITTED to keep POS terminals and wallets simple (KISS).
///
/// Shard-node attestation representation used by the simulation model.
/// The `crypto::sign_lock_attestation*` helpers populate deterministic test signatures;
/// a 64-byte field alone does not establish a real Ed25519 signature.
///
/// 📜 ARCHITECTURAL INVARIANT:
/// Node attestations and quorum bundles are ephemeral live-checkout signals ("green light for release").
/// They are NOT currency, NOT negotiable bearer deeds, and are NOT chained into future spend transactions.
/// Downstream recipients verify locks via fresh live queries against the L2 registry; they do not evaluate
/// past attestation bundles, and clients do not need to hoard historical certificates (DEC-055).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub lock_id: LockId,
    pub parent_lock: Hash256,
    pub node_id: NodeId,
    pub timestamp: SimTime,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
    #[serde(default)]
    pub shard_id: u16,
}

pub mod serde_bytes_64 {
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
                } else {
                    Err(E::custom(format!("expected 64 bytes, got {}", v.len())))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for item in &mut arr {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| Error::custom("expected 64 elements"))?;
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

/// Computes the required quorum based on the number of active nodes N
/// Formel (docs/02 & docs/08):
/// - N < 20: Q(N) = floor(2/3 * N) + 1  -> Status PROVISIONAL
/// - N >= 20: Q(N) = 14                 -> Status FINAL
pub fn required_quorum(active_nodes: usize) -> (usize, bool) {
    if active_nodes == 0 {
        return (0, false);
    }
    if active_nodes < 20 {
        let q = (2 * active_nodes) / 3 + 1;
        (q, false)
    } else {
        (14, true)
    }
}


/// Extracts the 16-bit shard ID from a genesis root (docs/04:308, INV-0302)
/// 2-byte big-endian: u16::from_be_bytes([genesis_root[0], genesis_root[1]])
pub fn extract_shard_id(genesis_root: &[u8; 32]) -> ShardId {
    u16::from_be_bytes([genesis_root[0], genesis_root[1]])
}

/// # Architectural Invariant: Option A KISS Canonical Voucher Shard & Origin-Lock Mandate
///
/// Derives the canonical shard ID for a voucher deterministically from the
/// voucher ID itself. If the voucher ID is a valid hex string with >= 2 bytes,
/// the first 2 bytes (big-endian) form the shard ID. Otherwise, BLAKE3 of the
/// voucher ID is used. This ensures all locks of a voucher route to the same
/// shard without requiring genesis parent lookups on the hot path.
pub fn voucher_shard_id(voucher_id: &str) -> ShardId {
    let bytes = voucher_id.as_bytes();
    if bytes.len() >= 4 {
        let decode_nibble = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        if let (Some(n0), Some(n1), Some(n2), Some(n3)) = (
            decode_nibble(bytes[0]),
            decode_nibble(bytes[1]),
            decode_nibble(bytes[2]),
            decode_nibble(bytes[3]),
        ) {
            let b0 = (n0 << 4) | n1;
            let b1 = (n2 << 4) | n3;
            return u16::from_be_bytes([b0, b1]);
        }
    }
    let h = blake3::hash(voucher_id.as_bytes());
    u16::from_be_bytes([h.as_bytes()[0], h.as_bytes()[1]])
}

/// # Architectural Invariant: INV-0302 Trust-Tree Locality (Phase 2 P1)
///
/// All transfers and splits of a voucher remain permanently on the same
/// shard. The canonical shard is derived EXCLUSIVELY from the immutable
/// genesis parent anchor (`BLAKE3(genesis_lookup_tag)`), NEVER from the
/// varying per-spend `ds_tag`. A spend's `ds_tag` changes on every hop
/// (payment, split, change); routing on it would scatter one voucher's
/// trust tree across shards and break quorum convergence. Gateways and
/// shard nodes must resolve `voucher_genesis_parent` first and fall back
/// to a voucher-stable hash only while the genesis is still unknown.
pub fn canonical_voucher_shard(genesis_parent: &[u8; 32]) -> ShardId {
    extract_shard_id(genesis_parent)
}

/// Computes the genesis parent anchor bytes for a lookup tag:
/// `parent_bytes = BLAKE3(lookup_tag)`. For genesis locks the lookup tag
/// is `bs58(transaction_hash)`; the hash of that tag is the trust-tree root.
pub fn genesis_parent_bytes_from_tag(lookup_tag: &str) -> [u8; 32] {
    *blake3::hash(lookup_tag.as_bytes()).as_bytes()
}

/// Simulation-only helper computing HRW score from integer `NodeId` (0..N).
/// Score(Node_i, S) = BLAKE3(NodeID_i || Shard_ID)
///
/// NOTE: For all production routing, client verification, and network decisions, use
/// `select_shard_committee` with the 32-byte cryptographic `HrwRoutingId` (Spec 03, INV-0301).
pub fn hrw_score(node_id: NodeId, shard_id: ShardId) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&node_id.to_le_bytes());
    hasher.update(&shard_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the normalized HRW score in the interval [0.0, 1.0)
pub fn hrw_score_normalized(node_id: NodeId, shard_id: ShardId) -> f64 {
    let hash = hrw_score(node_id, shard_id);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[0..16]);
    let val = u128::from_be_bytes(buf);
    val as f64 / u128::MAX as f64
}

/// Computes the HRW score for a 32-byte routing key (Argon2d shard ticket) and a shard.
/// Semantically decoupled: routing decision is based solely on HrwRoutingId, not on NodePubKey.
/// Score(RoutingId_i, S) = BLAKE3(routing_id || shard_id.to_le_bytes())
pub fn hrw_score_32(routing_id: &HrwRoutingId, shard_id: ShardId) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(routing_id);
    hasher.update(&shard_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the normalized HRW score for HrwRoutingId in the interval [0.0, 1.0)
pub fn hrw_score_32_normalized(routing_id: &HrwRoutingId, shard_id: ShardId) -> f64 {
    let hash = hrw_score_32(routing_id, shard_id);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[0..16]);
    let val = u128::from_be_bytes(buf);
    val as f64 / u128::MAX as f64
}

/// Alias for HRW routing: semantically identical to hrw_score_32, but with explicit routing name
pub fn hrw_score_for_routing(routing_id: &HrwRoutingId, shard_id: ShardId) -> Hash256 {
    hrw_score_32(routing_id, shard_id)
}

pub fn hrw_score_for_routing_normalized(routing_id: &HrwRoutingId, shard_id: ShardId) -> f64 {
    hrw_score_32_normalized(routing_id, shard_id)
}

/// A cryptographic identity and its operator-authorized active shard ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeMember {
    pub node_pubkey: NodePubKey,
    pub hrw_routing_id: HrwRoutingId,
}

/// Selects at most twenty distinct identities by their complete 256-bit HRW hash.
/// Inputs must already contain authenticated, mature, operator-authorized tickets.
/// Conflicting tickets for one identity deterministically choose the smallest ticket;
/// this is canonicalization, not a ticket-authorization or membership proof.
///
/// ⚠️ ARCHITECTURAL INVARIANT: Autonomous Mesh Snapshot vs. Epoch Baton Handover:
/// Committee membership is derived autonomously on demand per routing event / lock request
/// from the living active mesh snapshot. There is NO daily committee tenure, NO 24h predecessor
/// baton handoff requirement (DEC-053/055), and NO static epoch assignment.
pub fn select_shard_committee(
    shard_id: ShardId,
    active: &[CommitteeMember],
) -> Vec<CommitteeMember> {
    let mut identities = std::collections::BTreeMap::new();
    for member in active {
        identities
            .entry(member.node_pubkey)
            .and_modify(|ticket: &mut HrwRoutingId| *ticket = (*ticket).min(member.hrw_routing_id))
            .or_insert(member.hrw_routing_id);
    }
    let mut ranked: Vec<_> = identities
        .into_iter()
        .map(|(node_pubkey, hrw_routing_id)| CommitteeMember {
            node_pubkey,
            hrw_routing_id,
        })
        .collect();
    ranked.sort_by(|a, b| {
        hrw_score_32(&b.hrw_routing_id, shard_id)
            .cmp(&hrw_score_32(&a.hrw_routing_id, shard_id))
            .then_with(|| a.node_pubkey.cmp(&b.node_pubkey))
    });
    ranked.truncate(20);
    ranked
}

/// Checks whether a bit is set in the bitmask for the given index.
pub fn bitmask_has_bit(bitmask: SignersBitmask, index: u32) -> bool {
    if index >= 32 {
        return false;
    }
    (bitmask & (1u32 << index)) != 0
}

/// Counts the number of set bits in the bitmask.
pub fn bitmask_count(bitmask: SignersBitmask) -> u32 {
    bitmask.count_ones()
}

// ---------------------------------------------------------------------------
// Scenario 1: Digest-first pull sync (spec_03)
// ---------------------------------------------------------------------------
// 5-Minuten Bucket Shard Digest (docs/03_statusabgleich_und_sync.md §5)
// ---------------------------------------------------------------------------

/// Standard duration of one time-bucket for shard sync: 5 minutes (300 seconds = 300,000 ms).
pub const BUCKET_DURATION_MS: u64 = 300_000;

/// Grace period before a bucket is sealed and considered immutable: 30 seconds (30,000 ms).
pub const BUCKET_SEAL_GRACE_MS: u64 = 30_000;

/// Maximum number of 5-minute buckets in a 24-hour rotating window (24 * 12 = 288).
pub const BUCKETS_PER_DAY: usize = 288;

/// Computes the linear 5-minute bucket ID from a timestamp in milliseconds.
#[inline]
pub fn timestamp_to_bucket_id(timestamp_ms: u64) -> u64 {
    timestamp_ms / BUCKET_DURATION_MS
}

/// Checks whether a given bucket_id is sealed at the given net_time_ms.
#[inline]
pub fn is_bucket_sealed(bucket_id: u64, now_ms: u64) -> bool {
    let seal_threshold = (bucket_id.saturating_add(1))
        .saturating_mul(BUCKET_DURATION_MS)
        .saturating_add(BUCKET_SEAL_GRACE_MS);
    now_ms >= seal_threshold
}

/// 32-byte Merkle/BLAKE3 fingerprint for a specific 5-minute shard bucket.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardBucketDigest {
    pub bucket_id: u64,
    pub digest: Hash256,
    pub lock_count: u32,
    pub is_sealed: bool,
}

/// Request to fetch bucket digests for a specific shard over a range of buckets.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardBucketRangeRequest {
    pub shard_id: u16,
    pub start_bucket: u64,
    pub bucket_count: u16,
}

/// Response containing the list of bucket digests.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardBucketRangeResponse {
    pub shard_id: u16,
    pub buckets: Vec<ShardBucketDigest>,
}

/// 32-byte fingerprint response from a shard peer (simplified for simulation)
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardDigestResponse {
    pub peer_id: NodeId,
    pub digest: Hash256,
    pub lock_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_calculations() {
        assert_eq!(required_quorum(1), (1, false));
        assert_eq!(required_quorum(2), (2, false));
        assert_eq!(required_quorum(3), (3, false));
        assert_eq!(required_quorum(7), (5, false));
        assert_eq!(required_quorum(10), (7, false));
        assert_eq!(required_quorum(19), (13, false));
        assert_eq!(required_quorum(20), (14, true));
        assert_eq!(required_quorum(100), (14, true));
    }

    #[test]
    fn test_sim_time_arithmetic() {
        let mut t1 = SimTime(100);
        t1 += 50;
        assert_eq!(t1.as_millis(), 150);
        let t2 = t1 + 50;
        assert_eq!(t2.as_millis(), 200);
        assert_eq!(t2 - t1, 50);

        // A13-02: Saturating arithmetic on u64::MAX
        let max_time = SimTime(u64::MAX);
        assert_eq!(max_time + 1, SimTime(u64::MAX));
        let mut t_sat = SimTime(u64::MAX);
        t_sat += 1;
        assert_eq!(t_sat, SimTime(u64::MAX));
    }
}
