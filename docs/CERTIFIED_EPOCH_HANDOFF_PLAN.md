# HuMoCo Layer 2 – Certified Epoch Handoff Specification (CEH)

> Direction update, 2026-10-17 — DEC-053: this predecessor-certified architecture
> is retained as a historical/alternative candidate. Current P0 investigates regional
> activation from the living mesh without mandatory old-quorum permission, with
> potentially revocable receipts and deterministic merge. See
> [current P0 contract](PARTITION_RESILIENT_REGISTRY_P0.md) and
> [revised work plan](CEH_SECURITY_CLOSURE_WORK_PLAN.md). The older specification
> claims below are not the selected regional-activation contract.

**Deterministic Committee Succession, Hierarchical Voucher Split-Trees & Verified Light-Client Checkpoints**

- **Document Version:** 1.6.0 (Post-Review Consolidation: Voucher Split-Trees, Client-Side Custody & Scale-Free Mesh)
- **Status:** Architectural Specification & Formal Verification Baseline
- **Target Components:** `crates/humoco-node`, `crates/humoco-sim-core`
- **Applicable Specs:** Spec 01, Spec 07, Spec 11, Spec 12, Spec 14, Spec 15
- **Domain Invariant Authority:** `crates/humoco-sim-core/src/storage.rs:7` (`MAX_LOCK_TTL_YEARS = 11`)

---

## 1. Executive Summary & Design Rationale

### 1.1 The Vulnerability of Unconstrained Subjective Discovery
In the baseline design, nodes independently computed the 20-member committee for each shard ($S \in [0, 65535]$) via Rendezvous Hashing (HRW) over their locally discovered, mature F2F peers. This created an open vulnerability under network partitions and organic growth:
1. **Divergent Views (Split-Brain):** Two network partitions (or an organically grown network split by a single bridge) could each discover a distinct 20-member subset, each forming an apparently valid 14-member quorum for the same spend slot.
2. **Concurrent Activation Race:** Newcomers activating after local data copying without an old-write cutoff could join unnotified old members to sign an incompatible lock while an earlier 14-vote certificate was already released.

### 1.2 The Solution: Certified Epoch Handoff (CEH)
CEH replaces continuous, subjective rank recalculation with **discrete, cryptographically chained Epoch Committees**.
- A shard committee consists of exactly 20 distinct `NodePubKey` identities authorized for a fixed **Epoch** ($E$).
- Successor committees for Epoch $E+1$ are **not** self-proclaimed. They are explicitly authorized by a **14-of-20 BFT threshold signature from the predecessor committee** of Epoch $E$.
- The PoS checkout hot-path remains completely decoupled from consensus and state machine replication ($< 1\,\mu\text{s}$ in-RAM CAS, local node time $< 5\,\text{ms}$, end-to-end checkout latency $500\dots1500\,\text{ms}$).
- Committee transition is an infrequent, asynchronous background control-plane event executed via a deadlock-free 2-phase BFT round protocol with proposer fallback, unboundedly growing timeout backoff, and verifiable `NewViewCertificate` proofs.
- In-flight writes are cleanly drained via an atomic write barrier where committed decisions are never discarded (`active_in_flight_writes` barrier).
- **Hierarchical Voucher Split-Trees:** Supports binary tree branching of vouchers (change/split transactions) and linear chains identically. Each voucher has a deterministic `voucher_tree_root`, enabling $O(\log n)$ state difference detection across nodes.
- **Client-Side Custody for Late Receipts:** Eliminates artificial 30-day deadlines. Clients custody their historic `EpochCertificate` ($\approx 2.1\,\text{KB}$) alongside their receipt, preserving 100% voucher usability over 11 years without node state bloat.
- **Scale-Free / Fractal Mesh Operation:** The identical hierarchical Merkle tree engine operates in isolated village networks ($N < 20$, `PROVISIONAL` 🟡) and the federated world network ($N \ge 20$, `FINAL` 🟢) with domain separation.
- **Radical Storage Optimization:** At $N = 20$, a single Unified Network Epoch Manifest with a 65,536-leaf Merkle root commits to all shards in $\approx 2.1\,\text{KB/day}$. For $N \ge 21$, standard HRW applies with a rolling 30-day certificate window, bounding per-node certificate storage realistically (e.g. $\approx 2.59\,\text{GB}$ at $N=41$, $\approx 106\,\text{MB}$ at $N=1,000$).

---

## 2. Core Invariants & Fault Model

1. **Quorum Size ($Q = 14 / 20$):** Every binding decision (payment lock attestation, state closure, and successor handoff) requires at least 14 valid, distinct signatures from the 20 authorized members of that epoch.
2. **No Checkout Signer-Pool Expansion:** The 20-member committee for an epoch is strictly fixed. Dynamically including ranks 21..30 during a checkout vote is mathematically forbidden because quorum intersection collapses to $\le 0$, enabling conflicting quorums without double-signing. Committee member replacement occurs strictly via scheduled `EpochCertificate(E+1)` handoffs.
3. **Fault Bound ($f \le 6$):** Within any authorized 20-member committee, at most $f = 6$ members may be Byzantine (offline, malicious, equivocating, or silent).
4. **Quorum Intersection Property:**
   $$\forall Q_A, Q_B \subset C_E \text{ with } |Q_A| \ge 14, |Q_B| \ge 14, |C_E| = 20:$$
   $$|Q_A \cap Q_B| \ge 14 + 14 - 20 = 8$$
   With at most $f = 6$ Byzantine members, the intersection contains at least:
   $$|Q_A \cap Q_B \cap \text{Honest}| \ge 8 - 6 = 2 \text{ honest members}$$
5. **Durable Sign-Once Mandate (No Equivocation & WAL-Before-Wire):** Honest nodes persist their signing decisions to non-volatile storage (`redb` WAL with `fsync`) *before* releasing signatures over the wire. An honest node never signs two divergent payloads for the same epoch round. Any detected dual signature constitutes irrefutable first-party fraud (`HUMOCO_V1_EQUIVOCATION`) resulting in immediate identity ban and WoT severance.
6. **Decoupled TTL Horizons (Vouchers vs. Certificates):**
   - **Voucher Lock Retention:** Collision locks remain stored in `redb` until the voucher root expires ($T_{\text{max}} = 11\,\text{years} + 30\,\text{s}$ per `crates/humoco-sim-core/src/storage.rs:7`).
   - **Certificate Sliding Window:** Shard nodes and gateways maintain a rolling **30-day verification window** of historical `EpochCertificate`s.
   - **Historical Evidence via Client-Side Custody:** Once a lock is certified, it is permanent local state. If a client presents a late receipt after $> 30$ days to resolve an old `ProvisionalConflict`, the client provides the historic `EpochCertificate` ($\approx 2.1\,\text{KB}$). The node verifies it against its trusted checkpoint, clearing the conflict to `Settled` without requiring 11 years of certificate chains on nodes.
7. **Dual-Store Isolation (`FINAL` vs `PROVISIONAL`):**
   - **Zero Cross-Contamination:** `FINAL` collision locks (14/20 certified) and `PROVISIONAL` locks ($N < 20$ sub-quorum, island meshes, unconfirmed client hints) are physically decoupled in separate storage tables and RAM indices (`TABLE_FINAL_LOCKS` vs `TABLE_PROVISIONAL_LOCKS`).
   - **Pure FINAL State Closure:** The CEH `closed_state_root` and Merkle tree calculation operate **strictly and exclusively** over `TABLE_FINAL_LOCKS`. Provisional locks are quarantined and can never pollute the canonical shard state.
   - **Atomic Promotion:** A lock transitions from provisional to final if and only if an authorized 14/20 BFT committee quorum issues an `Attestation` / `EpochCertificate`.

---

## 3. Data Structures & Wire Formats

All wire encodings use safe, fixed-size standard types with length-prefixed BLAKE3 domain tags (`HUMOCO_V1_CEH_*`).

### 3.1 `GenesisManifest` (The Root Anchor)
Fixed once when the network reaches $N \ge 20$ mature nodes.
```rust
pub struct GenesisManifest {
    pub protocol_version: u32,
    pub network_id: [u8; 32],
    pub genesis_timestamp: u64,
    pub initial_committee: [NodePubKey; 20],
    pub genesis_signatures: Vec<(NodePubKey, [u8; 64])>, // >= 14 valid
}
```

### 3.2 `EpochCertificate` (The Successor Link for Federated Shards)
Issued by the active committee to authorize the next committee.
```rust
pub struct EpochCertificate {
    pub shard_id: u16,
    pub epoch: u64,
    pub round: u32,
    pub predecessor_cert_hash: [u8; 32],
    pub closed_state_root: [u8; 32],
    pub successor_committee: [NodePubKey; 20],
    pub predecessor_signatures: Vec<(NodePubKey, [u8; 64])>, // >= 14 from predecessor committee
}
```

### 3.3 `UnifiedNetworkEpochManifest` (Pioneer Mode at $N=20$)
At $N=20$, all 65,536 shards share the identical 20-node pioneer committee. To prevent 65,536-fold duplication, a single unified manifest is issued daily committing to a 65,536-leaf BLAKE3 Merkle tree:
$$\text{leaf}_i = \text{BLAKE3}(\text{u16::to\_le\_bytes}(i) \parallel \text{closed\_state\_root}_i).$$
```rust
pub struct UnifiedNetworkEpochManifest {
    pub epoch: u64,
    pub round: u32,
    pub predecessor_manifest_hash: [u8; 32],
    pub shards_merkle_root: [u8; 32],
    pub pioneer_committee: [NodePubKey; 20],
    pub pioneer_signatures: Vec<(NodePubKey, [u8; 64])>, // >= 14 from pioneer committee
}
```

### 3.4 `LockReceipt` (The PoS Checkout Evidence)
Presented to the merchant PoS terminal to prove irreversible finality.
```rust
pub struct LockReceipt {
    pub shard_id: u16,
    pub epoch: u64,
    pub parent_lock: [u8; 32],
    pub child_lock: [u8; 32],
    pub valid_until: u64,
    pub attestations: Vec<(NodePubKey, [u8; 64])>, // >= 14 from current epoch committee
}
```

### 3.5 Hierarchical Voucher Split-Trees (`voucher_tree.rs`)
Models both linear voucher transfers (1-to-1) and change/split transactions (1-to-2) as causal binary trees.
```rust
pub struct VoucherHop {
    pub parent_lock: [u8; 32],
    pub children: Vec<[u8; 32]>, // Canonically sorted; 1 child for direct transfer, 2 for split
    pub valid_until: u64,
}

pub struct VoucherSplitTree {
    pub voucher_root: [u8; 32], // Genesis Parent Anchor per INV-0302
    pub hops: BTreeSet<VoucherHop>,
}

pub struct HierarchicalShardSnapshot {
    pub shard_id: u16,
    pub epoch: u64,
    pub voucher_trees: BTreeMap<[u8; 32], VoucherSplitTree>,
}
```

---

## 4. Protocol Lifecycle & Execution Workflows

### 4.1 Cold Bootstrap, Network Scaling & Organic Growth

#### 4.1.1 Network Scaling Boundaries & Phase Transitions
1. **Community-Mesh Phase ($N < 20$):**
   - The network operates in `PROVISIONAL` mode 🟡 with adaptive provisional quorum $Q(N) = \lfloor \frac{2}{3} N \rfloor + 1$.
   - Uses the identical `HierarchicalShardSnapshot` and `VoucherSplitTree` engine under domain tag `HUMOCO_V1_CEH_PROVISIONAL_ROOT`.
   - All nodes validate all 65,536 shards; full local diff-detection and set-union reconciliation operate scale-free.
2. **Transition to Pioneer Mode ($N = 20$):**
   - When the 20th mature F2F identity passes the 24-hour incubation wall, the 20 pioneer nodes construct `GenesisManifest(Epoch = 0)`.
   - At least 14 pioneer nodes sign the manifest. The hash of this manifest becomes the immutable `NetworkAnchor`.
   - While $N = 20$, the network operates in Unified Mode issuing `UnifiedNetworkEpochManifest` ($\approx 2.1\,\text{KB/day}$).
3. **Transition to Federated Sharding ($N \ge 21$):**
   - As soon as $N \ge 21$, standard HRW sharding applies strictly: each shard has its own deterministically computed 20-node committee.
   - Transitions occur per shard via individual `EpochCertificate`s.

#### 4.1.2 Dual Storage & Village Mesh Merge (Zero Cross-Contamination)
- **Physical Separation in Storage:** Nodes maintain two strictly decoupled storage spaces:
  - `FINAL Storage` (`TABLE_FINAL_LOCKS` & `RamIndex`): Exclusively holds locks certified by a 14/20 BFT committee. Only this storage is hashed for the CEH `closed_state_root`.
  - `PROVISIONAL Storage` (`TABLE_PROVISIONAL_LOCKS` & `ProvisionalRamIndex`): Quarantined storage for provisional village locks ($N < 20$) and unconfirmed client submissions.
- **Anti-Spam Isolation:** When an isolated village network ($N < 20$) merges with the federated world network ($N \ge 20$), the world network **does not** automatically take over or bulk-import the village's locks. The world network ignores the village's provisional storage completely.
- **Strict Causal Completeness for FINAL:** A voucher lock can only be promoted to `FINAL` if its entire causal ancestry (from the voucher root to the current hop) is verified and committed to `TABLE_FINAL_LOCKS`. A payment at a world merchant cannot be certified `FINAL` if intermediate hops only exist as unverified provisional records.
- **Client-Side Proof Re-Anchoring:** Clients (wallets / PoS terminals) custodies their own `ProofChain`. When moving to the world network, the wallet submits the causal chain (`valid-prefix causal-path batch`), allowing the 14/20 shard committee to certify each hop directly into `TABLE_FINAL_LOCKS`.

#### 4.1.3 Resolution of Parallel $N \ge 20$ Networks: F2F Handshake Hard-Reject
In the rare event that two independent networks reach $N \ge 20$ in isolation before discovering each other:
1. **F2F Handshake Hard-Reject (`INCOMPATIBLE_GENESIS`):**
   - Mutual P2P handshakes on QUIC port 9090 exchange and verify `genesis_hash`.
   - If both nodes are in $N \ge 20$ mode and `local.genesis_hash != peer.genesis_hash`, the connection is **immediately rejected** (`ConnectionRefused` / `INCOMPATIBLE_GENESIS`).
   - The networks refuse to bridge at the P2P wire level. This eliminates all deep-merge consensus complexity, split-brain risk, and cross-network shard corruption by construction (KISS doctrine).
2. **Administrative Migration (Out-of-Protocol):**
   - If operators of the smaller network choose to unite with the world network, they perform an administrative migration: resetting their node database and joining with the canonical `GenesisManifest`.
   - Clients from the migrating network re-anchor their vouchers via the normal client ingress by submitting their causal proof chains.

#### 4.1.4 Organic Web-of-Trust Growth ("Mund-zu-Mund-Vernetzung")
- **Social F2F Graph Propagation:**
  - P2P admission on QUIC port 9090 is strictly Friend-to-Friend (`f2f.trusted_pubkeys`). A new node can only participate if an existing operator explicitly adds its `NodePubKey`.
  - The project does not use indiscriminate mass-advertising or public cluster broadcasting. Instead, it expands organically through personal word of mouth ("Mund-zu-Mund") within interconnected communities interested in alternative monetary systems.
- **Genesis Propagation during Initial Handshake:**
  - When an existing operator invites a peer, the initial F2F handshake automatically transmits the authentic `GenesisManifest`.
  - All joining nodes are rooted in the single existing `NetworkAnchor`, completely eliminating accidental parallel Genesis formation at the source.



---

### 4.2 Checkout Hot-Path & Gateway Auto-Forwarding

- **Local RAM CAS on Shard Nodes:** $< 1\,\mu\text{s}$.
- **Node Internal Processing SLA:** $< 5\,\text{ms}$ (in-RAM collision check + redb WAL write).
- **End-to-End PoS Checkout Latency:** $500\dots1500\,\text{ms}$ (parallel QUIC network RTTs with an 800 ms collection deadline).
- **Micro-Retry Policy:** At 300 ms, if 13 responses are collected, the gateway fires an immediate micro-retry to the remaining 7 nodes, resolving $>95\%$ of temporary packet drops in 50–80 ms.
- **Gateway Auto-Forwarding on Epoch Transition:**
  If a gateway sends a request for Epoche $E$ after the shard has transitioned to $E+1$, the shard returns `EPOCH_STALE` carrying `EpochCertificate(E+1)`. The gateway updates its pointer and transparently resubmits for $E+1$ within 10–20 ms without user impact.

---

### 4.3 The Transition Protocol: Deadlock-Free BFT Handoff

```mermaid
sequenceDiagram
    autonumber
    participant P as 👑 Round Proposer (Rank r % 20)
    participant C as 👥 Current Committee Members (20 Nodes)
    participant S as 🌟 Successor Committee (20 Nodes)

    Note over C: Trigger: Routine window when candidate ranks shift
    C->>C: Stage 1: FENCE_DRAIN (Reject new ingress with 503; await in-flight task drain)
    C->>C: Stage 2: FENCE_LOCKED (Sync WAL flush; freeze closed_state_root)
    
    Note over P: Round r starts (Timeout: T_r = T_0 * 2^r, unbounded)
    P->>C: Phase 1: PROPOSE(Epoch E+1, Round r, CandidatePool, closed_state_root, Proofs)
    
    loop Phase 1 Validation (Prepare)
        C->>C: Check Lock-on-Prepared: If locked on earlier value V, proposal must carry V
        C->>C: Reconcile missing hops via reconcile_union
        C->>C: Persist PREPARE to redb WAL
    end
    C-->>P: PREPARE(Signature)
    
    Note over P: 14 Prepares collected -> PREPARED CERTIFICATE formed
    P->>C: Phase 2: COMMIT(Epoch E+1, Round r, PreparedProof)
    
    loop Phase 2 Validation (Commit)
        C->>C: PUBLIC VALIDITY: PreparedProof with 14 Prepares forces Commit!
        C->>C: Retain any private uncertified choices locally in redb
        C->>C: Persist COMMIT to redb WAL
    end
    C-->>P: COMMIT(Signature)
    
    Note over P: 14 Commits collected -> EpochCertificate(E+1) complete!
    P->>S: Deliver EpochCertificate(E+1) + Verified Active Locks
    S->>S: Install active locks into redb WAL and RamIndex
    Note over S: Epoch E+1 is now ACTIVE!
```

#### Detailed Protocol Rules:

1. **Causal Barrier Cutoff (No Fragile Clock Timestamps):**
   - The transition is governed by the `FENCE_DRAIN` barrier, not uncoordinated system clocks.
   - In-flight writes that entered before drain complete durably; new writes pause with HTTP 503 `Retry-After: 2s`.
2. **Hierarchical State Closure & Set-Union Reconciliation:**
   - Proposer packages all active voucher split-trees.
   - Members perform `reconcile_union`: any valid unexpired hop present in $\ge 2$ honest nodes is merged.
   - Canonical sorting ensures all nodes compute the exact same 32-byte `closed_state_root`.
3. **Late-Certificate Redemption via Client-Side Custody:**
   - Pre-quorum splits are marked `ProvisionalConflict`.
   - When a valid 14-vote predecessor `LockReceipt` is presented accompanied by its `EpochCertificate`, the successor verifies the certificate against a trusted checkpoint and clears the conflict to `Settled`.
   - Vouchers retain 100% usability over their full 11-year validity without node state bloat.

---

## 5. Security & Robustness Proof Sketches

### Theorem 1: Freedom from Conflicting Certificates (Split-Brain Impossibility)
*Claim:* In any given Epoch $E$, it is impossible for two conflicting payment locks $L_A$ and $L_B$ (or two conflicting successor certificates $C_{E+1}^A$ and $C_{E+1}^B$) to both obtain 14 valid signatures.

*Proof:*
1. Let the authorized committee for Epoch $E$ be $C_E$ with $|C_E| = 20$.
2. Suppose for contradiction that both $L_A$ and $L_B$ achieve 14 distinct valid signatures from $C_E$. Let these signer sets be $Q_A$ and $Q_B$, with $|Q_A| \ge 14$ and $|Q_B| \ge 14$.
3. By the Pigeonhole Principle, the intersection must contain:
   $$|Q_A \cap Q_B| \ge |Q_A| + |Q_B| - |C_E| = 14 + 14 - 20 = 8 \text{ identities}.$$
4. By the fault model, at most $f = 6$ identities in $C_E$ are Byzantine.
5. Therefore, the intersection contains at least $8 - 6 = 2$ honest identities.
6. An honest identity adheres to the Durable Sign-Once rule: it never signs conflicting locks for the same slot.
7. Thus, at least 2 honest identities must have refused to sign the second lock.
8. Contradiction. Hence, two conflicting certificates cannot both reach 14 signatures. $\blacksquare$

---

### Theorem 2: Deadlock-Free Transition under Partial Synchrony & Fault Bound ($f \le 6$)
*Claim:* If up to $f = 6$ committee members are Byzantine, silent, or propose conflicting values, the committee guarantees progress and commits exactly one successor `EpochCertificate(E+1)` after GST.

*Proof:*
1. There are 20 members, of which at least $20 - 6 = 14$ are honest and connected after GST with maximum delay $\Delta < \infty$.
2. If a Byzantine proposer splits votes across different values, no value can gather 14 Prepares.
3. After round timeout $T(r) = T_0 \times 2^r$, the 14 honest members broadcast signed `ROUND_CHANGE` messages.
4. Because $T(r)$ grows unboundedly, there exists a round $r^*$ where $T(r^*) > 2\Delta$, eliminating premature timeouts.
5. Within at most $f+1 \le 7$ rounds, an honest proposer is reached. The honest proposer gathers 14 `ROUND_CHANGE` messages, constructs a valid `NewViewCertificate`, and broadcasts the proposal.
6. If an earlier value $P$ reached 14 Prepares, it is bound by the `NewViewCertificate`. By the Public Validity rule, all 14 honest members commit $P$, regardless of private omission objections.
7. If no prior value reached 14 Prepares, the honest proposer incorporates all active obligations, and all 14 honest members prepare and commit the value.
8. The 14 honest members commit the prepared value, assembling the required 14 signatures for `EpochCertificate(E+1)`. $\blacksquare$

---

### Theorem 3: Resilience under Physical Network Partitions
*Claim:* If the network partitions into arbitrary disconnected subgraphs, no partition can generate an unauthorized certificate.

*Proof:*
1. Let the 20 committee members be partitioned into disconnected components $P_1, P_2, \dots, P_k$.
2. Since $\sum |P_i| = 20$, at most one component can satisfy $|P_m| \ge 14$ (since $14 \times 2 = 28 > 20$).
3. If no component contains $\ge 14$ members, all components halt write progress safely. No payments and no committee handoffs can be certified.
4. If one component contains $\ge 14$ members, that component alone can continue operating. All other components safely reject writes due to lack of quorum.
5. In no case can two partitions simultaneously certify conflicting state. $\blacksquare$

---

### Theorem 4: Invariance under Independent Genesis Networks (Domain Isolation)
*Claim:* Two networks initialized with distinct Genesis Manifests $G_A \neq G_B$ cannot corrupt each other's epoch certificates or closed state roots.

*Proof:*
1. Every epoch certificate $C_E$ carries an unbroken backward hash chain terminating at its specific $G$.
2. The domain-separated hash of an epoch certificate is defined as:
   $$H(C_E) = \text{BLAKE3}(\text{len} \parallel \text{"HUMOCO\_V1\_CEH\_CERT"} \parallel \dots \parallel H(C_{E-1}))$$
   where $H(C_0) = H(G)$.
3. If $G_A \neq G_B$, then $H(G_A) \neq H(G_B)$ with overwhelming probability ($1 - 2^{-256}$).
4. Consequently, no certificate $C_E^B$ can be accepted as an ancestor of $C_E^A$.
5. Shard verification, state roots, and attestations are thus strictly domain-isolated. An honest node adhering to protocol validation rejects certificates rooted in a foreign genesis manifest. $\blacksquare$

---

## 6. Zero State Bloat & Honest Storage Accounting

| Network Size ($N$) | Mean Shards / Node ($\frac{20}{N} \times 65,536$) | 30-Day Certificate Storage / Node | Storage Mode |
| :---: | :---: | :---: | :---: |
| **$N = 20$** | 65,536 (All Shards) | **$\approx 63\,\text{KB}$** | Unified Network Epoch Manifest ($\approx 2.1\,\text{KB/day}$) |
| **$N = 41$** | $\approx 31,968$ | **$\approx 2.59\,\text{GB}$** | Federated HRW Sharding ($2.7\,\text{KB} \times 30\,\text{days}$) |
| **$N = 100$** | $\approx 13,107$ | **$\approx 1.06\,\text{GB}$** | Federated HRW Sharding ($2.7\,\text{KB} \times 30\,\text{days}$) |
| **$N = 1,000$** | $\approx 1,310$ | **$\approx 106\,\text{MB}$** | Federated HRW Sharding ($2.7\,\text{KB} \times 30\,\text{days}$) |
| **$N = 10,000$** | $\approx 131$ | **$\approx 10.6\,\text{MB}$** | Federated HRW Sharding ($2.7\,\text{KB} \times 30\,\text{days}$) |
| **Worst-case single node** | 65,536 (All Shards) | **$\approx 5.3\,\text{GB}$** | Retaining all shards for 30 days |

*Note:* Storage figures cover rolling 30-day certificate history only. Active collision locks are persisted in `redb` until voucher root expiry ($T_{\text{max}} = 11\,\text{years} + 30\,\text{s}$) with fixed binary footprint per lock.
