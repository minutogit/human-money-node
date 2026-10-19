# 10. P2P Wire Format, Session Framing & 0-RTT Whitelist

> **Status:** Standard  
> **Model:** Logic & State Graph First  

This document specifies the **binary wire format**, the **session framing** over QUIC streams, as well as the cryptographic **domain separation** and **0-RTT whitelist**. It requires safe checked decoding, bounded admission and purpose-bound cryptographic verification. Latency targets and protocol security require separate executed evidence. Final shared DTO/domain integration remains K2.

---

## 1. The 32-Byte C-Aligned `WireHeader`

Every P2P message on a QUIC connection begins with an exactly **32-byte**, 8-byte-aligned header. It strictly separates routing, causality, and framing metadata from the payload (canonically encoded bounded payload).

### 1.1 Binary Byte Layout (Hex / C Layout)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic: "HUMO"                           |  [0..4]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Protocol Version        |          MsgType              |  [4..8]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Session Sequence                        +  [8..16]
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Epoch ID                            |  [16..20]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Flags                              |  [20..24]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Length                        |  [24..28]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Crypto Suite  | Min Compat Ver|           Reserved            |  [28..32]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Payload (bounded, 0..N Bytes)                  |  [32..32+N]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 1.2 Rust Type Definition

```rust
pub const WIRE_MAGIC: [u8; 4] = *b"HUMO";
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// 32-Byte C-Aligned Framing Header
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct WireHeader {
    /// Protocol identifier: Always b"HUMO" (0x48, 0x55, 0x4D, 0x4F)
    pub magic: [u8; 4],
    
    /// Protocol version (currently 1)
    pub protocol_version: u16,
    
    /// Message type (e.g. LOCK_REQUEST, STATUS_QUERY)
    pub msg_type: u16,
    
    /// Monotonically increasing sequence number of the QUIC session (replay & gap detection)
    pub session_seq: u64,
    
    /// Current 24h epoch ID (T_0 reference)
    pub epoch_id: u32,
    
    /// Bitflags for control (FINAL, PROVISIONAL and control, etc.)
    pub flags: u32,
    
    /// Exact byte size of the following bounded payload
    pub payload_len: u32,
    
    /// Crypto suite identifier (0 = Ed25519Blake3 default, 1 = Ed25519Blake3, 2 = Hybrid/PQC)
    pub crypto_suite: u8,

    /// Minimum protocol version compatibility
    pub min_compat_ver: u8,

    /// 8-byte alignment padding / reserved for future protocol extensions
    pub reserved: u16,
}

impl WireHeader {
    pub const SIZE: usize = 32;

    #[inline(always)]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == WIRE_MAGIC
    }
}
```

---

## 2. Message Types & Flag Definitions

### 2.1 Message Types (`msg_type`)

```rust
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    // --- Read operations (0-RTT Whitelist) ---
    StatusQuery          = 0x0001,
    StatusResponse       = 0x0002,
    LatencyProbe         = 0x0003,
    LatencyProbeAck      = 0x0004,

    // --- Write & verification operations (1-RTT Only) ---
    LockVerifyRequest    = 0x0101,
    LockVerifyResponse   = 0x0102,
    EquivocationProof    = 0x0105, // Fraud proof -> leads to permanent server ban
    EquivocationAck      = 0x0106,
    ActiveSyncRequest    = 0x0107, // PULL-sync request for active shard locks (0-RTT whitelisted)
    ActiveSyncDone       = 0x0109, // Completion marker of the PULL-sync
    ShardDigestRequest   = 0x010A, // Shard digest range request
    ShardDigestResponse  = 0x010B, // Shard digest response

    // --- Peer & sync control ---
    Heartbeat            = 0x0201,
    HeartbeatAck         = 0x0202,
}
```

### 2.2 Header Flags (`flags`)

| Bit Mask | Identifier | Meaning |
| :--- | :--- | :--- |
| `0x0000_0001` | `FLAG_PROVISIONAL` | Lock request is in provisional mode ($q_{\text{prov}}$) |
| `0x0000_0002` | `FLAG_FINAL` | Regional FINAL request ($q_{\text{final}} \ge 14/20$) |
| `0x0000_0004` | `FLAG_EXPIRED_CLEANUP` | Marks garbage collection of an expired voucher (Expired Voucher Cleanup) |
| `0x0000_0008` | `FLAG_HEDGED` | Redundant request to backup nodes for latency stabilization |
| `0x0000_0010` | `FLAG_COMPRESSED` | Payload is LZ4/ZSTD-compressed (only for bulk/cold path) |

### 2.3 The 64-Byte `EpochHeartbeat` Payload (`MsgType::Heartbeat`)

Every active node sends exactly one 64-byte heartbeat payload per hour for presence and horizon synchronization:

Heartbeat semantics and passive three-miss presence are defined in
[Spec11](11_organische_praesenz_und_dunbar_gossip.md); a heartbeat timestamp is
network-adjusted time, not unchecked OS time. Argon2d belongs to the admission
ticket. A calendar header epoch is framing/accounting, not a committee tenure.

## 3. Canonical signature domains and context

Use the shared protocol library's exact constants and encodings. Existing source
`humoco-sim-core/src/crypto.rs` distinguishes network-qualified provisional/final,
attestation and heartbeat domains, plus genesis, canonical resolver, ingress and
fraud domains. This source observation is not a complete verifier audit.
The former table's hard-coded tag lengths/one-byte “prefix codes” and third-tier
approval tag are retired; the actual prefix is the length of the registered tag.

`SigDigest = BLAKE3(len(tag) || tag || canonical_context || payload_digest)`.

The canonical context must bind network/version, signature purpose, shard, root
and authenticated lifetime, exact consumed output/target, state/status, justified
frozen committee context and request fields. A live response additionally binds
the recipient's fresh challenge/freshness (Spec03 status/sync). Final field order,
challenge bounds and new live-purpose tag remain a shared K2 integration task;
legacy shorter digest examples cannot justify omitting these bindings.

An original write approval, a later current-state response and sync evidence have
separate purposes. Retain the exact original own decision durably before release;
never reinterpret a lawful merged live observation as a new original choice or
an equivocation. All fourteen counted signatures must verify under distinct full
current authorized keys; bitmap counts/statistical membership are insufficient.

## 4. QUIC early data and authorization

| Operation | 0-RTT rule | Additional gate |
| --- | --- | --- |
| Ordinary status/latency query | Read-only whitelist, bounded replay-safe cost | Read quotas; a replayed old reply cannot satisfy a new recipient challenge. No background presence ping loop. |
| Active-state pull request | Only bounded read-only service | Replayed fetch cannot mutate/sign/activate state; install only after full verified recovery. |
| Lock mutation/original vote | Forbidden | Require completed handshake, learned peer authorization, current responsibility/readiness and durable release. |
| Fraud-proof submission | Forbidden | Authenticate and verify bounded original evidence before mutation/penalty. |

Reject state-changing early data at the receiver, preserving the existing
`ERR_ZERO_RTT_WRITE_FORBIDDEN` rejection contract. Unsupported messages/suites/
versions/flags and malformed framing are structured errors, never panics.
Connection resumption or TLS peer identity does not authenticate a committee.

F2F gossip accepts only direct friends. Shard-direct RPC authenticates full keys
learned through F2F knowledge; unknown internal peers are refused. A learned
gateway can query a shard without being a voting member. Public HTTP clients
remain permissionless and do not inherit internal peering restrictions.

Session sequence rules must be scoped to their declared stream/session and
validated against reordering/resumption behavior. A transport gap alone is not
cryptographic equivocation. Epoch/counter restart and overflow rules remain part
of exact shared framing integration, not an excuse to globally ban on timeout.

## 5. Accounting, first-party evidence and bounded gossip

The receiving shard enforces quotas itself; no auditor jury or lock gossip is
introduced. A signed ingress envelope binds the gateway identity, network, shard,
exact lock digest, accounting day, sequence, cumulative storage-time counter and
required accounting context. Repeated identical forwarding is legal. Use physical
elapsed time for EMA decay; traffic volume must not accelerate it. Quota/capacity
refusal is neutral; diagnostic disagreements are not sanction evidence.

The historical counter checks distinguish identical same-sequence duplicates,
incompatible same-sequence packets, increasing/regressing same-day counters,
packet reordering, adjacent-day carry values and multi-day gaps. Only a proved
incompatibility of two genuine signed statements under the exact same declared
counter/session semantics could be self-evidence. Restart, clock correction,
duplicate heartbeat relay or local counter disagreement cannot by themselves
establish fraud. The exact counter/heartbeat anti-framing argument remains a
proof/integration obligation; old “two packets within50minutes always slash” and
“sequence gap implies fraud” shortcuts are not sufficient acceptance rules.

For shard equivocation verify two incompatible original approvals of the same
full key/network/consumed slot/purpose. Verify both signatures before revocation.
A reporter signature or a losing regional receipt alone is insufficient. Use
bounded original evidence packets (INV-0404,1024 bytes each), checked total envelope
size, full perpetrator key and signed context. The reporter cannot invent proof
by naming a victim. Fraud persistence has its own INV-1402 lifecycle.

The only F2F gossip streams are hourly presence/time and verified first-party
fraud. Locks and sync use direct RPC. Verified fraud has priority, but admission,
verification work, deduplication, queue bytes and forwarding fan-out are bounded;
“high priority” never means unlimited allocations or unthrottled forged evidence.
Local verified node revocation invalidates the ticket and severs WoT edges;
network propagation latency and L1 disposition are not proven by a diagram.

Local collection feedback is diagnostic under INV-0309/1701. No rank21 substitution,
remote missing-signer punishment, heartbeat suppression or presence refresh ping
storm follows from it. Internal shard/sync budgets are protected under INV-1307.
Normal idle close, NOT_READY/NOT_IN_SHARD, capacity refusal and quorum-completion
cancellation are neutral.

### Time and commit ordering

Keep seconds/milliseconds conversions checked and explicit. Protocol time derives
from P2pClock/SimTime, root lifetime and walletT_0 entry freshness; calendar
`epoch_day` is not committee authority. Preserve the selected fixed nominal bucket
seal and entry-only freshness (DEC-059/061/062). Durable-before-release adds the
commit acknowledgment, not a second wallet freshness gate. Root expiry still
blocks a new approval. Clock/entry/insertion/seal composition remains a proof gate;
30s purge grace alone is not its proof.

## 6. Safe fixed-header decoding example

This example demonstrates the existing 32-byte layout, not a complete network
receiver. Fixed offsets never rely on alignment, pointer casts or transmutation.

```rust
impl WireHeader {
    pub fn decode(bytes: &[u8; 32]) -> Self {
        Self {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            protocol_version: u16::from_le_bytes([bytes[4], bytes[5]]),
            msg_type: u16::from_le_bytes([bytes[6], bytes[7]]),
            session_seq: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            epoch_id: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            flags: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            payload_len: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            crypto_suite: bytes[28],
            min_compat_ver: bytes[29],
            reserved: u16::from_le_bytes([bytes[30], bytes[31]]),
        }
    }
}
```

After obtaining exactly 32 header bytes under a bounded timeout, validate magic,
version, message type, suite/compatibility/reserved flags, allowed early-data
operation and payload limit. Convert lengths with `try_from`; use `checked_add`
for total frame size. Read payload incrementally with a fixed chunk bound and
reject excess, truncation and deadline expiry before signature/storage work.
Never `Vec::with_capacity(untrusted_length)`. `decode` alone validates no semantic
field or signature; its safe memory access is not proof of server protection.

## 7. Invariants

1. **[INV-1001] Fixed Encoded Header:** Exactly32 wire bytes with explicit endian decoding. In-memory8-byte alignment grants no permission to cast network buffers.
2. **[INV-1002] Magic Constant:** Validate the four ASCII bytes `b"HUMO"` before payload processing.
3. **[INV-1003] Complete Canonical Domain Binding:** Verify registered length-prefixed network/purpose/status/context domains; changing class or request invalidates the signature.
4. **[INV-1004] No Early-Data Mutation:** Lock votes/mutations and fraud-proof mutation are rejected in0-RTT at the receiving shard.
5. **[INV-1005] Receiver-Enforced Accounting:** Receiving shard enforces bounded ingress/quotas itself; no auditor juries or declaration-only protection.
6. **[INV-1006] Two F2F Gossip Streams:** Hourly presence/time and verified first-party fraud only; locks/sync remain direct RPC.
7. **[INV-1007] Authenticated Ingress Context:** Forwarded envelopes bind full sender/lock/accounting context; only genuinely incompatible signed statements under the same semantics establish self-evidence, not gaps or reordering.
8. **[INV-1008] Bounded Local Reciprocity:** Local scheduling/backoff cannot alter consensus membership, punish neutral responses or suppress heartbeat/fraud gossip. No rank21 replacement.
9. **[INV-1009] Read-Only Replay-Safe Pull:** Whitelisted early-data pull only serves bounded data; replay cannot mutate, install or enable voting. Readiness requires separately verified complete installation.

All wire defenses need actual adversarial receiver-side QUIC verification; see
[Spec16](16_chaos_testing_and_simulation.md) and [the registry](INVARIANT_REGISTRY.md).
No such test execution is claimed by this consolidation.
