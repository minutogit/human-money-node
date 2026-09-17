# 14. Node Persistence & redb Storage Architecture

> **Status:** Standard  
> **Model:** Logic & State Graph First  

This document specifies the **persistent disk storage layer** of a Layer-2 shard node. It defines the criteria for separating volatile RAM from NVMe/SSD storage, justifies the choice of the pure-Rust embedded key-value database **`redb`**, and describes the table layouts for **identity, WoT endorsements, ingress accounts, active locks, and slashing proofs (fraud evidence)**.

---

## 1. The Dual-Tier Storage Paradigm

According to the 5 guiding filters (*Guiding Filter 1: Subtraction before Construction & Guiding Filter 4: Lazy Evaluation*) Layer 2 is a blind Collision Lock Registry. Transaction locks are **not written synchronously to disk** in order to deterministically guarantee PoS latency $< 1000\,\text{ms}$ (typically $< 50\,\text{ms}$).

```mermaid
flowchart TD
    subgraph StorageArchitecture["Dual-Tier Storage Architecture"]
        direction TB
        subgraph HotTier["Tier 1: Volatile Hot Path (RAM)"]
            RAMEngine["LockStorageEngine (DashMap Hot Cache)"]
            RAMEngine --> FastLock["First-Seen Collision Check (< 1 µs)<br>Volatile LockEntries (192 Bytes)"]
        end

        subgraph PersistentTier["Tier 2: Persistent Safety & Graph Layer (NVMe / SSD via redb)"]
            RedbEngine["redb (Embedded Pure-Rust ACID KV Store)"]
            RedbEngine --> T1["Table: node_identity (Keypair, Genesis, PoW Proof)"]
            RedbEngine --> T2["Table: peers (F2F Friends, Static Addresses & Age)"]
            RedbEngine --> T3["Table: active_locks (Persisted Locks until root.valid_until)"]
            RedbEngine --> T4["Table: fraud_evidence (Slashing Proofs for L1)"]
            RedbEngine --> T5["Table: ingress_accounts (Hashed AccountTags & VIP Quotas)"]
        end

        FastLock -.->|Asynchronous Streaming| T3
        FastLock -.->|Equivocation Detected! (Asynchronous)| T4
    end
```

---

## 2. Why `redb` as the Persistent Embedded Engine?

In the legacy planning archive *RocksDB* and *Sled* were evaluated. They were discarded for the following reasons:
* **RocksDB:** C++ codebase, binding overhead, compaction stalls, risk of memory bugs.
* **Sled:** Incomplete in the Rust ecosystem and not approved for production use.

### Advantages of `redb` for HuMoCo:
1. **100% Pure Safe Rust:** No C/C++ dependencies, deterministic memory management.
2. **ACID Transactions with MVCC:** Parallel zero-copy read transactions without blocking writers.
3. **Crash Resilience:** Copy-on-Write (CoW) B-Tree prevents corruption on sudden power loss.
4. **Zero-Copy Reads:** Returns native byte slices (`&[u8]`) directly from the memory-mapped image.

---

## 3. The 5 Persistent redb Tables

```rust
use redb::{TableDefinition, Database};

/// 1. Node Identity & Boot Parameters (1 entry)
pub const TABLE_NODE_IDENTITY: TableDefinition<u8, &[u8]> = 
    TableDefinition::new("node_identity");

/// 2. F2F Peers & Friendship Topology
/// Key: 32-byte NodeID | Value: Serialized PeerRecord (Address, Last-Seen, Uptime)
pub const TABLE_PEERS: TableDefinition<&[u8; 32], &[u8]> = 
    TableDefinition::new("peers");

/// 3. Persistent Active Locks (Valid until root.valid_until)
/// Key: 32-byte ParentLockKey | Value: Serialized StoredLock (192 Bytes)
pub const TABLE_ACTIVE_LOCKS: TableDefinition<&[u8; 32], &[u8]> = 
    TableDefinition::new("active_locks");

/// 4. Non-Losable Equivocation Slashing Proofs
/// Key: 32-byte CanonHash | Value: Serialized Fraud Proof (Double Signature for L1)
pub const TABLE_FRAUD_EVIDENCE: TableDefinition<&[u8; 32], &[u8]> = 
    TableDefinition::new("fraud_evidence");

/// 5. Local Ingress Customer and Friend Registry (Blind Hashed)
/// Key: 32-byte AccountTag | Value: IngressAccountRecord
pub const TABLE_INGRESS_ACCOUNTS: TableDefinition<&[u8; 32], &[u8]> = 
    TableDefinition::new("ingress_accounts");
```

---

## 4. Asynchronous Write Path for Locks & Fraud Evidence

When a new lock is accepted in volatile RAM or a double-spend (equivocation) is detected:

```mermaid
flowchart LR
    Detect["RAM First-Seen Engine"] -->|1. RAM Update (< 1 µs)| Index["DashMap Index Update"]
    Detect -->|2. Asynchronous Tokio Channel| PersistWorker["Tokio Background Persistence Worker"]
    PersistWorker -->|3. ACID Write| DiskLocks["redb: TABLE_ACTIVE_LOCKS"]
    PersistWorker -->|4. On Conflict| DiskFraud["redb: TABLE_FRAUD_EVIDENCE"]
    PersistWorker -->|5. P2P Broadcast| UrgentStream["QUIC Stream 2: Fraud Alert Broadcast"]
```

1. The first-seen check in RAM completes the transaction **without disk wait time** in $< 1\,\mu\text{s}$.
2. The record is placed into an internal `tokio::sync::mpsc` channel.
3. A dedicated I/O worker writes the locks and proofs transactionally to `redb`.
4. **Guarantee:** Even on crash, neither existing locks nor slashing proofs are lost.

---

## 5. Crash Recovery & Node Restart

When a node restarts after a failure:
1. **Load Identity:** `TABLE_NODE_IDENTITY` provides the Ed25519 secret key and the genesis $T_0$ parameter.
2. **Restore Topology:** `TABLE_PEERS` restores active F2F friendship and neighborhood connections.
3. **Load Active Locks:** `TABLE_ACTIVE_LOCKS` populates the RAM index with all non-expired locks (`valid_until > now`).
4. **Co-Shard Resync:** As a successor or after prolonged downtime, the node reconciles missed active locks via `SyncActiveLocks` with the remaining 19 co-shard peers.
5. **Submit Pending Fraud Proofs:** All proofs stored in `TABLE_FRAUD_EVIDENCE` are submitted to Layer 1.

---

## 6. Invariants of the Persistence Layer

1. **[INV-1401] Zero Disk I/O on the Lock Hot Path:** Read or write access to `redb` must never block the latency of the `LockStorageEngine`.
2. **[INV-1402] Non-Losability of Slashing Proofs:** Every valid equivocation fraud proof must be persisted to `TABLE_FRAUD_EVIDENCE` before being discarded from RAM.
3. **[INV-1403] Pure-Rust Persistence:** Only safe pure-Rust engines without external native C/C++ libraries are permitted for local data storage.
4. **[INV-1404] Deterministic Restart:** After a restart, the node loads only valid active locks from `TABLE_ACTIVE_LOCKS` and, if necessary, synchronizes with its 19 shard partners before issuing first-seen votes.
