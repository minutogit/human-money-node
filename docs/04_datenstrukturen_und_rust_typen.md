# 04. Data Structures & Rust Types (Zero-Copy)

> **Status:** Standard  
> **Model:** Logic & State Graph First  

All data structures in the HuMoCo Layer-2 Collision Lock Registry are optimized for maximum performance (point-of-sale latency $< 1000\,\text{ms}$) and **zero-copy deserialization** (`rkyv` / `#[repr(C)]`).

---

## 1. Core Types of the Lock Registry

```rust
use rkyv::{Archive, Deserialize, Serialize};

pub type Hash32 = [u8; 32];
pub type PubKey32 = [u8; 32];
pub type Sig64 = [u8; 64];

/// The universal lock entry (Chain of Authority UTXO)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C)]
pub struct LockEntry {
    /// Unique hash of the predecessor lock (genesis hash on first issuance)
    pub parent_lock: Hash32,
    
    /// Ephemeral public-key hash of the new owner (stealth output)
    pub receiver_ephemeral_pub_hash: Hash32,
    
    /// Expiry (TTL Unix timestamp in seconds). Lock is purged after expiry.
    pub valid_until: u64,
    
    /// Signature of the previous owner over (parent_lock || receiver_ephemeral_pub_hash || valid_until)
    pub owner_signature: Sig64,
    
    /// Status of the lock (0 = PROVISIONAL, 1 = FINAL, 2 = VOID)
    pub status: u8,
    
    /// Alignment to 64-bit boundary (C padding)
    pub _padding: [u8; 7],
}

/// The quorum certificate of a shard (compact & self-proving via Ed25519 batch verification)
#[derive(Clone, Debug, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct QuorumCertificate {
    /// Hash of the confirmed LockEntry
    pub lock_hash: Hash32,
    
    /// Shard bucket (0..65535)
    pub shard_id: u16,
    
    /// 1-byte status: 0 = PROVISIONAL (Yellow), 1 = FINAL (Green), 2 = HIGH_ASSURANCE (Blue/Gold)
    pub status: u8,
    
    /// 1-byte alignment padding
    pub _padding: u8,
    
    /// Bitmask of signing nodes (Top-20 HRW nodes, bits 0..19)
    /// count_ones() >= 14 and status == 1 => Guaranteed finality
    pub signer_bitmap: u32,
    
    /// Ed25519 quorum partial signatures of the nodes (exactly popcount(signer_bitmap) entries, Ed25519 batch-verifiable)
    pub signatures: Vec<Sig64>,
}

/// Pillar of the mathematical fraud proof (slashing evidence)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum FraudProofPillar {
    ShardEquivocation      = 0x01, // Pillar 1: Double-signing for the same parent_lock
    IngressCounterConflict = 0x02, // Pillar 2: Load counter regression / heartbeat discrepancy
    HeartbeatSpam          = 0x03, // Pillar 3: Heartbeat spam (interval < 50 min)
}

/// The universal fraud proof (statelessly verifiable in O(1))
#[derive(Clone, Debug, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C, align(8))]
pub struct FraudProofPayload {
    /// NodeID / public key of the convicted perpetrator (32 bytes)
    pub perpetrator_node_id: PubKey32,
    
    /// Fraud pillar (1..3)
    pub proof_pillar: FraudProofPillar,
    
    /// 7-byte alignment padding
    pub _padding: [u8; 7],
    
    /// First signed original packet (full wire format)
    pub evidence_packet_a: Vec<u8>,
    
    /// Second signed original packet (full wire format)
    pub evidence_packet_b: Vec<u8>,
    
    /// Optional: NodeID of the discoverer / reporter
    pub reporter_node_id: PubKey32,
    
    /// Signature of the reporter over (perpetrator_node_id || proof_pillar || hash(A) || hash(B))
    pub reporter_signature: Sig64,
}

/// Slot of the 128-slot direct-mapped slashing detector (exactly 112 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C, align(8))]
pub struct HeartbeatSlashingSlot {
    /// NodeID / public key of the node (32 bytes)
    pub node_id: PubKey32,
    /// Unix timestamp of the last valid heartbeat (8 bytes)
    pub timestamp_unix: u64,
    /// PoW nonce of the heartbeat (8 bytes)
    pub pow_nonce: u64,
    /// Signature of the node over the heartbeat (64 bytes)
    pub signature: Sig64,
}

/// Phase 1 of PULL sync: Fingerprint request to incumbent Top-20 shard peers
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C, align(8))]
pub struct ShardDigestRequest {
    /// Requesting node
    pub requester_node_id: PubKey32,
    /// Target shard (0..65535)
    pub shard_id: u16,
    /// 6-byte alignment padding
    pub _padding: [u8; 6],
}

/// Phase 1 of PULL sync: 32-byte fingerprint response
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C, align(8))]
pub struct ShardDigestResponse {
    /// Target shard (0..65535)
    pub shard_id: u16,
    /// 2-byte alignment padding
    pub _padding: [u8; 2],
    /// Number of currently active locks in the shard
    pub lock_count: u32,
    /// Highest valid timestamp / TTL in the shard
    pub max_valid_until: u64,
    /// BLAKE3 shard digest over all active locks
    pub digest: Hash32,
}

/// Phase 2 of PULL sync: Payload stream request
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C, align(8))]
pub struct StreamShardLocksRequest {
    /// Target shard (0..65535)
    pub shard_id: u16,
    /// 6-byte alignment padding
    pub _padding: [u8; 6],
    /// Expected majority digest (TargetDigest D*)
    pub expected_digest: Hash32,
}

/// PULL sync response chunk (zero-copy pagination of pure locks)
#[derive(Clone, Debug, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C, align(8))]
pub struct ActiveSyncChunk {
    /// Shard bucket
    pub shard_id: u16,
    /// Sequential chunk sequence number
    pub chunk_seq: u16,
    /// 1 if this is the last chunk of the sync, else 0
    pub is_last_chunk: u8,
    /// Number of valid entries in this chunk (max. 16)
    pub entry_count: u8,
    /// 2-byte alignment padding
    pub _padding: [u8; 2],
    /// Bounded array of active LockEntries (144 bytes each)
    pub entries: [LockEntry; 16],
}

/// The cryptographic identity and admission proof of a node (Argon2d PoW)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C)]
pub struct NodeProofOfWork {
    /// Permanent Ed25519 public key (identity and friendship anchor)
    pub pubkey: PubKey32,
    /// Found 64-bit nonce
    pub nonce: u64,
    /// Achieved difficulty / PoW score (D_mine)
    pub difficulty_achieved: u32,
    /// Used Argon2d iterations (t >= 120, m=1GB fixed)
    pub t_iterations: u16,
    /// 2-byte alignment padding
    pub _padding: [u8; 2],
}

/// Seamless announcement of a NodeID upgrade (re-mining with PubKey stability)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[repr(C)]
pub struct NodeIDMigrationNotice {
    /// New, stronger proof-of-work
    pub new_pow: NodeProofOfWork,
    /// New derived NodeID
    pub new_node_id: Hash32,
    /// Valid signature of the existing private key over (new_node_id || new_pow.nonce)
    pub migration_signature: Sig64,
}
```

---

## 2. Client-Gateway Wire Protocol (Layer-1 JSON Compatibility)

For communication between the L1 client (`human-money-core`) and the L2 gateway, standardized JSON structures with Base58 encoding for 32/64-byte arrays are used:

```rust
use serde::{Deserialize, Serialize};

/// Status query with thinned locator list (ADR-001)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2StatusQuery {
    pub auth: L2AuthPayload,
    pub layer2_voucher_id: String,           // 64-char hex string
    pub challenge_ds_tag: String,            // Double-spend tag to check (Base58)
    pub locator_prefixes: Vec<String>,       // 10-char Base58 prefixes in reverse
}

/// Binding verdict of the L2 registry
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum L2Verdict {
    Verified { lock_entry: L2LockEntry },
    MissingLocks { sync_point: String },     // 10-char prefix of the Last Common Ancestor
    UnknownVoucher,
    Rejected { reason: String },
    Ok { signature: [u8; 64] },
}

/// Signed response envelope of the L2 gateway
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ResponseEnvelope {
    pub verdict: L2Verdict,
    pub server_signature: [u8; 64],          // Ed25519 signature of the L2 node over the verdict
}
```

---

## 3. Mathematical Helper Functions

```rust
/// Computes the deterministic root hash of the network (definitional genesis)
#[inline(always)]
pub fn calculate_genesis_root(protocol_version: u32, t0_unix_sec: u64) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    let tag = b"HUMOCO_V1_GENESIS";
    hasher.update(&[(tag.len() as u8)]);
    hasher.update(tag);
    hasher.update(&protocol_version.to_le_bytes());
    hasher.update(&t0_unix_sec.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Canonical resolver for split-brain conflicts with domain separation
#[inline(always)]
pub fn canonical_hash(parent: &Hash32, receiver_pub_hash: &Hash32, sig: &Sig64) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    let tag = b"HUMOCO_V1_CANON_RESOLVER";
    hasher.update(&[(tag.len() as u8)]);
    hasher.update(tag);
    hasher.update(parent);
    hasher.update(receiver_pub_hash);
    hasher.update(sig);
    *hasher.finalize().as_bytes()
}

/// Canonical signature digest with domain separation and length prefix (SSOT)
#[inline(always)]
pub fn calculate_signature_digest(
    domain_tag: &[u8],
    epoch_id: u32,
    session_seq: u64,
    flags: u32,
    shard_id: u16,
    status_tag: u8,
    payload_digest: &[u8; 32],
) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain_tag.len() as u8).to_le_bytes());
    hasher.update(domain_tag);
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&session_seq.to_le_bytes());
    hasher.update(&flags.to_le_bytes());
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&[status_tag]);
    hasher.update(payload_digest);
    *hasher.finalize().as_bytes()
}

/// Canonical quorum computation Q(R) = min(R, floor(2R/3) + 1)
#[inline(always)]
pub fn quorum(r: u16) -> u16 {
    if r == 0 {
        return 0;
    }
    std::cmp::min(r, (r * 2) / 3 + 1)
}

/*
| R | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
|---|---|---|---|---|---|---|---|---|---|----|----|----|----|----|----|----|----|----|----|----|
| Q | 1 | 2 | 3 | 3 | 4 | 5 | 5 | 6 | 7 |  7 |  8 |  9 |  9 | 10 | 11 | 11 | 12 | 13 | 13 | 14 |
*/

/// Shard assignment O(1)
#[inline(always)]
pub fn get_shard_id(genesis_hash: &Hash32) -> u16 {
    u16::from_be_bytes([genesis_hash[0], genesis_hash[1]])
}

/// Deterministic exponential decay for telemetry/quotas (halving every 17 hours)
/// Replaces complex Taylor series with O(1) bit shifts
#[inline(always)]
pub fn deterministic_decay(value: u64, delta_hours: u64) -> u64 {
    let halvings = delta_hours / 17;
    if halvings >= 64 {
        0
    } else {
        value >> halvings
    }
}
```

/// Protocol limits & capacity bounds
pub const MAX_LOCATOR_PREFIXES: usize = 16;       // Max. 16 logarithmically thinned 10-char prefixes in cold path (ADR-001)
pub const MAX_BATCH_SIZE: usize = 64;             // Max. 64 locks per L2BatchLockRequest
pub const MAX_EVIDENCE_BYTES: usize = 1024;       // Max. 1024 bytes per evidence packet in FraudProofPayload (INV-1402)

---

## 3. Invariants of Storage Structures

1. **[INV-0401] Fixed Size Without Heaps:** `LockEntry` has a fixed byte size of exactly 144 bytes and requires no heap allocation (`Vec`/`String` forbidden). Locator lists are strictly bounded to `MAX_LOCATOR_PREFIXES = 16` in the cold path, batches to `MAX_BATCH_SIZE = 64`.
2. **[INV-0402] No Economic Data:** Neither amount, currency, nor identities exist in L2 data structures (*Blind Service*).
3. **[INV-0403] Domain Separation:** Every cryptographic hash and signature step enforces a unique prefix (`HUMOCO_V1_*`).
4. **[INV-1402] Bounded Fraud Evidence:** Individual evidence packets (`evidence_packet_a/b`) in `FraudProofPayload` are strictly capped at `MAX_EVIDENCE_BYTES = 1024` bytes.
