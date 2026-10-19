# 04. Canonical Data Contracts, Safe Encoding and Bounds

> Canonical requirements; conceptual interfaces, not a frozen final shared schema
> or a claim about currently implemented DTOs. DEC-038 selects one shared protocol
> library with `human-money-core` domain semantics. See [Spec10](10_p2p_wire_format_und_session_framing.md).

## 1. Data ownership and representations

L1 owns amounts, currency, owner signatures and voucher causality. L2 owns bounded
collision state identifying the network, root, consumed output, exact successor,
receiver/nonce/lock identifier as applicable, and authenticated root.valid_until.
No real names, monetary balances or application-origin whitelist enter L2. Full
node public keys are necessary cryptographic identities; “blind” does not prohibit
those keys or opaque output keys.

The legacy fixed `LockEntry` budget is144 encoded bytes; its illustrative C layout
was32-byte parent,32-byte receiver hash,8-byte validity,64-byte owner signature,
1-byte state and7 padding bytes. It is **not** the HMC variable-nonce DTO, a quorum
proof, an own-choice record, or the total RAM/disk cost. Do not reinterpret a Rust
struct's memory as a network packet. Separate semantic DTOs from canonical encoded
bytes and local storage indexes. `repr(C)` and padding do not define validation,
endianness, authenticated fields or a portable wire format.

## 2. Signature purposes and quorum proof

Keep original write approval, current live-state response, sync-state evidence,
heartbeat and fraud-report signatures distinguishable by canonical domain and
explicit purpose/context. At a minimum a payment/live proof must bind:

| Field group | Required meaning |
| --- | --- |
| Network/version/domain | Prevent cross-network/protocol/purpose replay. |
| Shard/root/lifetime | Authenticate routing and complete root lifetime; callers cannot shorten inherited safety retention or extend validity. |
| Consumed slot/output and exact target | Distinguish split outputs and prevent transplant to another lock. |
| State/status and request context | Bind the actual assertion, not only a floating record hash. Binary PROVISIONAL/FINAL, no third assurance level. |
| Frozen committee context | Identify the same justified current top20 for all counted votes; full-key deduplication. |
| Recipient challenge/freshness | Fresh request-bound live response, consumed only for its checkout context. |

A bitmap is only an index into the authenticated frozen<=20 roster. Bits0–19,
lengths and signature counts must agree; each counted signature must verify under
a distinct full32-byte NodePubKey authorized for this snapshot. Popcount>=14,
short IDs, a gateway `verified` flag or a supplied roster alone do not establish
FINAL. Current authority is a separate proof gate, not a property of this struct.

The old quorum struct containing only lock_hash/shard/status/bitmap/signatures
is incomplete for this contract. Final challenge sizing, field order, versioning,
status/absence encoding and domain tags remain one shared K2 integration task;
do not independently invent incompatible node/client encodings.

## 3. Safe parsing and bounded allocation

Use `from_le_bytes`/`to_le_bytes`, checked slices/`try_from`, explicit discriminant
validation, `checked_add`/`checked_mul` and structured errors. Preserve
`#![forbid(unsafe_code)]`; no pointer casts, transmutation, bytemuck/zerocopy or
unchecked archived-root deserialization is required. Payload encoding does not
waive validation. See the safe header example in Spec10 §6.

Reject unsupported versions/crypto suites/flags/types and impossible lengths
before allocating payloads. Read incrementally in bounded chunks, with bounded
per-message and per-peer bytes/counts/work and timeouts. Never allocate directly
from an attacker-declared wire length. Run cheap framing/rate/PoW checks before
asymmetric signature work and durable storage reservation.

Existing limits are retained:

```rust
pub const MAX_LOCATOR_PREFIXES: usize = 16;
pub const MAX_BATCH_SIZE: usize = 64;
pub const MAX_EVIDENCE_BYTES: usize = 1024; // per original evidence packet
```

Locator prefixes are10 Base58 characters used for bounded cold-path search;
ambiguous prefixes require full-ID validation before accepting causality. Counts
alone are not sufficient aggregate byte/work bounds. Two evidence packets plus
headers/keys/report signatures require a checked aggregate envelope cap. If the
final context encoding cannot fit1024 bytes per evidence packet, report that
schema conflict explicitly rather than truncate signatures or silently enlarge
limits. No numeric buffer/time constants are invented by this consolidation.

## 4. Sync and own-choice records

Active-state digest/stream metadata must bind network, shard, snapshot/cursor,
ordering, all semantic record fields including authenticated lifetime, counts and
termination. Chunk order/duplicates/gaps/changed snapshots must be detected before
installation. Original historical quorum bundles are excluded from shared state.
An unready source may serve retained data without becoming a qualified witness.
Source continuity and complete snapshot+delta coverage remain separate proof gates.

Persist immutable original own decisions keyed by full identity/network/consumed
slot/purpose and exact payload/context, atomically with the lock before release.
Retain exact own approvals through rootTTL+30s; never overwrite them from canonical
sync. These local safety records are not a migrated historical quorum archive.
Fresh live responses use safely installed state and do not create a new original
choice or disk write for each read.

## 5. Mathematical helpers and schema alignment

HRW shard selection, canonical hashing and signature digests use one shared
canonical encoding. Hash domains use an explicit one-byte length prefix and the
registered `HUMOCO_V1_*` domain before the unambiguous fields. Do not cast arbitrary
untrusted domain lengths to u8 without bounds; protocol tags are fixed constants.
`Q(0)=0`; for1<=N<20 use `floor(2N/3)+1`, and FINAL uses14 of 20. Full HRW scores
and deterministic identity tie-breaking are preserved.

Client JSON adapters validate all decoded32/64-byte fields, Base58/hex lengths,
list counts, total bytes and work. An L2Verdict/L2ResponseEnvelope is not paid
unless the consumer verifies the selected full quorum proof and L1 conditions.
Exact shared Rust types and compatibility migration remain delivery work;
examples in old revisions are not authority to omit signed bindings.

## 6. Invariants

1. **[INV-0401] Fixed Legacy Record and Bounded Envelopes:** The 144-byte fixed record budget is separate from variable domain DTOs, proofs and storage overhead. Locator count<=16 and batch count<=64, plus checked byte/work limits; no unbounded wire allocation.
2. **[INV-0402] Blind Economic Domain:** L2 stores no amounts, currencies or real identities; necessary full node keys and opaque output identifiers remain permitted.
3. **[INV-0403] Canonical Purpose Separation:** Length-prefixed registered domains and complete field bindings distinguish signatures, networks, versions and assurance states. Verify the actual signatures.
4. **[INV-0404] Bounded Fraud Evidence:** Each original evidence packet is<=1024 bytes and the aggregate envelope is checked before allocation. This replaces Spec04's former overloaded INV-1402; INV-1402 remains durable fraud-evidence retention in Spec14.
