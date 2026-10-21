# 🧠 HuMoCo Layer 2 – Master Architecture, Coding Rules & System Context

> **Credo:** *"In decentralization there is no trust, only mathematical proofs."*  
> **Doctrine:** *"Subtraction before Construction – Perfection is achieved when there is nothing left to remove."*  
> **Status:** Production-ready consensus core & daemon (`crates/humoco-sim-core` & `crates/humoco-node`).

This document is automatically loaded on every AI agent startup in the workspace. It defines the immutable **Mental Model**, the **2-Tier Network Architecture**, the **Anti-Hallucination Filters**, and the **iron-clad programming rules**.

---

## 🗣️ Bilingual Language Policy & Translation Guide (DE ↔ EN)

> **⚠️ CRITICAL INVARIANT – BILINGUAL POLICY:**
> * **User / Maintainer communication:** The maintainer / user communicates in **German**. Agents **MUST ALWAYS** reply to the user in **German** (`Antworte dem Benutzer immer auf Deutsch`).
> * **Codebase & documentation:** Source code, Rustdoc comments (`///`), Git commits, GitHub issues, pull requests, and official documentation are written in idiomatic **English**.
> * This invariant is non-negotiable and overrides any other language preference.

* **Canonical term mapping:** For user terminology, the dictionary [`docs/TRANSLATION_GLOSSARY.md`](docs/TRANSLATION_GLOSSARY.md) applies strictly:
  * *Sperrregister* $\rightarrow$ `Collision Lock Registry` / `humoco-node` (asynchronous double-spend registry)
  * *Kassenpfad / Hot-Path* $\rightarrow$ `PoS Hot-Path / Checkout Path` (in-RAM filtering $< 1\,\mu\text{s}$, durable commit $< 20\,\text{ms}$)
  * *Gutschein-Wurzel* $\rightarrow$ `Voucher Root Anchor` (`root.valid_until` as TTL anchor)
  * *Dorf-Merge* $\rightarrow$ `Village Merge / Mesh Merge` (deterministic convergence via $\min(H_{\text{canon}})$)
  * *Knoten-Souveränität* $\rightarrow$ `Node Sovereignty` (no auto-update, absolute operator veto)
  * *Netzwerk-Thermometer* $\rightarrow$ `Network Thermometer` (decentralized load measurement & dynamic PoW)
  * *Byte-Jahre* $\rightarrow$ `Byte-Years` ($144\,\text{Bytes} \times \text{TTL}$ Storage-Time Product)
  * *5x Wal-Bremse* $\rightarrow$ `5x Whale Brake` (exponential dampening under mass ingress)
  * *Hörensagen-Verbot* $\rightarrow$ `Anti-Hearsay Principle` / `First-Party Evidence` (ban only on cryptographic self-proof)
  * *Keine Kautionen* $\rightarrow$ `Zero Financial Deposits / No Staking` (penalty via `NodePubKey` ban, shard-ticket loss, and WoT exclusion)

---

## 🏛️ 1. The HuMoCo Mental Model (The 5 Pillars)

1. **Pure Blind Collision Lock Registry (Blind Service) & HMC Coupling:**
   * **The Voucher (L1) is the negotiable instrument (`ProofChain`):** It carries real monetary value, units, transactions, and owner signatures (`human-money-core`).
   * **Layer 2 is 100% BLIND:** It knows neither amounts, nor currencies, nor accounts, nor user identities. It is an asynchronous cryptographic bulletin board for double-spend prevention: `parent_lock -> child_lock`. L2 certificates are NOT currency, but auxiliary clearance receipts ("Unbedenklichkeitsbescheinigung").
   * Domain lock formats originate from `human-money-core` (`L2LockEntry`, `L2Verdict`). `humoco-node` decouples via DTO adapters and enforces strict collision checks on the hot path.
2. **Smart Client, Dumb Server (Client-Side Custody):**
   * The server does not store dead history or transaction logs. The client (wallet / PoS terminal) custodies its own causality chain (`ProofChain`) and presents it on demand.
   * On the hot path the server only checks the atomic collision on `parent_lock` in the RAM index ($< 1\,\mu\text{s}$).
3. **Cryptographic Identity (NodePubKey) vs. Sharding Tickets (HrwRoutingId):**
   * IP addresses and ports are ephemeral, untrusted, and dynamic.
   * Permanent identity anchor for F2F friendship edges and TLS is the **NodePubKey (Ed25519 Public Key)** — immutable and bound to the node for its lifetime.
   * Dynamic **HrwRoutingId (Argon2d Shard Ticket)** `HrwRoutingId = Argon2d(NodePubKey || Nonce || T0)` is used exclusively for HRW scoring (`Score = BLAKE3(HrwRoutingId || Shard_ID)`); it is semantically decoupled and replaceable via re-mining.
   * **24h Incubation Wall for Shard Tickets:** A new HrwRoutingId is gossiped immediately but only counted as active in HRW after a 24h maturation period (prevents shard-hopping / opportunistic grinding).
4. **Physics Trumps Negotiation & Deterministic Convergence:**
   * Partitions and split-brain networks resolve admitted conflicts by justified confirmation class first (class2 > class1 > class0), then $\min(H_{\text{canon}})$ strictly as a tie-breaker within the same confirmed class during an exact stalemate (DEC-064). Unconfirmed singleton/rogue locks (class0) can NEVER displace confirmed locks (class1/2) regardless of hash value (DEC-022). FINAL is regional/revisable (DEC-053).
   * **Sub-Quorum Lock Quarantine on Merge:** During asymmetric merges (e.g. 10 vs 3), nodes adopting a dominant BFT quorum atomically isolate local unconfirmed minority locks into provisional storage (`TABLE_PROVISIONAL_HMC_LOCKS`) so they do not poison the active shard digest (`post_digest == dominant_digest`), preserving them for client reconciliation without data loss.
   * **Zero Financial Deposits / No Staking:** On equivocation (double-signing), offenders are punished atomically via irrefutable proof (`HUMOCO_V1_EQUIVOCATION`): the losing branch becomes VOID via $\min(H_{\text{canon}})$, the node identity (`NodePubKey`) is permanently banned, the mined Argon2d shard ticket (`HrwRoutingId`) is invalidated, and all F2F friendship edges in the Web-of-Trust are severed entirely.
   * **Dynamic Network Scaling:** Sub-quorum networks ($N = 1\dots19$, Island Mesh) operate on adaptive provisional quorums $Q(N) = \lfloor \frac{2}{3} N \rfloor + 1$ (Status `PROVISIONAL` 🟡, all nodes validate all 65,536 shards); from $N \ge 20$ (with 24h stability hysteresis) full federated HRW sharding applies with fixed BFT quorum $14/20$ (Status `FINAL` 🟢).
5. **Dual-Tier Persistence & Strict Durable-before-Vote (DEC-029):**
   * **Tier 1 (RAM):** `RamIndex` with atomic first-seen collision check ($< 1\,\mu\text{s}$).
   * **Tier 2 (Disk):** Strict **Durable-before-Vote** (DEC-029). Atomic `redb` commit before releasing attestation signature, local vote, or response envelope (< 20 ms local durable SLA, within the 800 ms checkout budget). RAM acceptance is pending until durable storage acknowledges commit.
6. **Zero State Bloat & TTL:**
   * Every lock entry is bound to the validity of the Voucher Root (`root.valid_until`). After expiry plus a 30s grace period, the entry is physically purged from RAM and disk. Permanent tombstones are strictly forbidden.

---

## 🌐 2. The 2-Tier Network Architecture & Subjective Local Autonomy

### Tier 1: Public Client Ingress (REST / HTTP Port 8080)
* **Open & Stateless:** Public IPs directly embedded in apps. Gateways are interchangeable, stateless messengers.
* **✍️ Write Ingress (`POST /v1/lock`):**
  - *Free Tier:* Open to everyone, protected by dynamic stateless BLAKE3 Hashcash PoW (*Network Thermometer*).
  - *Friends Tier:* Free & PoW-exempt for own PoS terminals / friends via random 128-bit secret tokens (`f2f_<hex>`). **The node's `NodePubKey` must NEVER be accepted as an ingress token!**
  - *VIP Tier:* Bounded reserved queues and measured service targets via Byte-Years tokens.
* **🔍 Read Ingress (`POST /v1/status`, `GET /v1/node-status`, `GET /v1/pow-challenge`):**
  - Extremely fast RAM-index lookup ($< 1\,\mu\text{s}$), no disk locks, no write-queue reservation.
  - **1-of-20 Shard Randomization (`INV-0310`):** Gateways query exactly 1 deterministically random node from the top-20 shard nodes. Read traffic scales linearly with shard size. Protected by token-bucket rate limits against read DDoS.
* On Tier 1 *every* client is welcome; P2P ban lists or F2F rules do **not** apply here.

### Tier 2: Internal Node P2P Mesh (QUIC Port 9090)
* **Tier 1 (F2F Gossip Tier):** Heartbeats and topology gossip run **exclusively** via direct F2F friends (`f2f.trusted_pubkeys`). Unknown gossip packets are silently discarded.
* **Tier 2 (Shard-Direct Tier):** Shard RPC connections (lock verification, sync) may **only** be established to/from peers previously learned via F2F gossip (`known_network_nodes`). Unknown IPs are hard-rejected (`ConnectionRefused`).
* **Strict 2-Stream Mesh Gossip:** P2P Gossip across F2F edges consists **strictly of exactly two streams**:
  1. *Hourly Heartbeat / Presence Gossip (Spec 11):* 1 packet/hour, $\text{TTL} = 16$, Dunbar fan-out $k = \min(d, \lceil\sqrt{d}\rceil + 1)$. Used for presence discovery, topological awareness, and median clock synchronization.
  2. *Equivocation Proofs (Spec 10):* Cryptographic first-party fraud evidence (`FRAUD_EQUIVOCATION`) forwarded with priority.
* **⚡ Lock Gossip Prohibition:** **Locks are NEVER gossiped across the mesh.** Checkout hot-path is 100% Shard-Direct RPC, 0% Gossip.
* **Connection Pooling ($N \ge 5.000$):** F2F connections hold persistent QUIC sessions with keep-alive. Shard-direct connections run as an ephemeral LRU pool (128–256 sockets) with 15s idle timeout without keep-alive. Idle closes are normal, never peer failures.

### The 3 Golden Rules of Local Autonomy (Spec 11, 15, 19):
1. **Purely Subjective View:** Each node judges *only* its direct edges (`my_peers.get(peer).on_miss()`). There is no network gossip about "bad peers" (prevents Cascading Death Spirals).
2. **First-Party Evidence Doctrine:** A node is banned or slashed network-wide **only** upon irrefutable cryptographic self-proof (`EquivocationProof` with two genuine Ed25519 signatures of the same node for the same slot). Hearsay is forbidden.
3. **Non-Authoritative Telemetry (`INV-1701`):** Telemetry warnings and health probes serve the human operator for diagnosis only. No telemetry metric ever triggers an automated ban (`triggers_auto_ban() == false`).

---

## 🛒 3. PoS Checkout Path, SLA & Quorum Fast-Exit

* **Fixed Checkout Committee:** Each lock request freezes one canonical HRW snapshot of at most 20 distinct `NodePubKey` identities, including self where eligible. FINAL requires 14 distinct votes from that snapshot; no ranks 21–40 may replace unavailable members during checkout. Committee selection uses full 256-bit scores with deterministic identity tie-breaking.
* **Autonomous Living-Mesh Snapshot:** Committee membership is computed autonomously and deterministically per request from the living active mesh (`select_shard_committee`). There is NO daily committee tenure, NO 24-hour baton passing, and NO static epoch assignment.
* **Bounded Write Collection:** Signature collection uses an **800 ms budget** and fails immediately when remaining eligible members cannot supply quorum. `FLAG_NOT_READY`, `FLAG_NOT_IN_SHARD`, and cancellations after quorum completion are neutral outcomes, never peer failures.
* **Internal Node Durable SLA ($< 20\,\text{ms}$):** Sub-microsecond RAM collision check followed by atomic durable `redb` commit before releasing attestation signature, local vote, or response envelope (Durable-before-Vote / DEC-029). Local processing finishes in $< 20\,\text{ms}$.
* **Quorum Fast-Exit ($14/20$):** As soon as 14 shard signatures are present, the gateway sends `200 OK` to the PoS terminal and cleanly aborts stragglers (`join_set.abort_all()`). Aborted tasks are neutral and must never be counted as peer failures.

---

## 🚫 4. Explicit Negative Guard-Rails (Anti-Hallucination Filters)

1. **Zero Financial Deposits / No Staking on Layer 2:** Layer 2 knows no monetary stakes, collateral deposits, or financial bonding. Penalties are purely cryptographic: permanent `NodePubKey` ban, Argon2d ticket invalidation, branch voiding via $\min(H_{\text{canon}})$, and complete Web-of-Trust severance.
2. **Safe Standard Library (`from_le_bytes`) over Unsafe Crates:** Wire header & binary parsing strictly uses safe standard library methods (`from_le_bytes`, `to_le_bytes`, `try_from`, `checked_*`). External transmutation crates (`bytemuck`, `zerocopy`) and unsafe code are forbidden (`#![forbid(unsafe_code)]`).
3. **Ban on 'Dual-Role Ingress':** P2P mesh edges (`f2f_friends`, QUIC port 9090) are purely node-to-node infrastructure. A node's `NodePubKey` must NEVER be registered or accepted as an ingress bearer token on HTTP port 8080. Client friend tokens are strictly random 128-bit secrets (`f2f_<hex>`).
4. **The 4-Fold Epoch Disambiguation (Preventing Agent Hallucinations):**
   * *1. 24h Argon2d Incubation Wall:* Newly mined `HrwRoutingId` shard tickets mature for 24h before being active in HRW ranking (anti-shard-hopping delay for *tickets*, NOT a committee term or liveness delay).
   * *2. Calendar `epoch_day`:* Deterministic calendar integer slot $\lfloor (t_{\text{unix}} - T_0) / 86400 \rfloor$ used strictly for quota accounting, Byte-Years, and EMA decay. Has zero connection to shard committees or consensus tenures!
   * *3. Dynamic Dunbar Presence:* Peer liveness is tracked passively via hourly heartbeats (e.g. 3 missed hours $\to$ `is_suspended`). There is NO 24-hour waiting requirement to detect offline nodes!
   * *4. Autonomous HRW Living Mesh:* Nodes calculate shard committees on demand from active non-suspended peers. Shard leadership is NOT handed down via predecessor epoch certificates ($C_E \to C_{E+1}$, DEC-053/DEC-055).
5. **Ban on Recursive L2 Receipt Chaining & Past Signature Hoarding:**
   * The lock entry `parent_lock -> child_lock` is the physical double-spend barrier. Once synchronized, conflicts fail immediately (`409 Conflict`), independent of which specific nodes attested to it in the past.
   * Shard sync (`compute_shard_digest_at`) synchronizes strictly the objective state (`parent_lock`, `receiver_pub`, `nonce`, `id`), never legacy signatures or historical 896-byte quorum bundles of retired nodes.
   * Old Quorum Certificates have zero spending utility on L2; recipients perform a fresh live check. Clients do not hoard or chain past certificates.
6. **Separation of Consensus Core and Periphery:**
   * Consensus core (`humoco-node`) = QUIC + RAM index + redb + ingress.
   * Administration, hot backups, and dashboards attach externally via the local UNIX control socket (`/tmp/humoco.sock`). The web dashboard is a strictly private operator diagnostic window (< 128 KiB), NOT an operating system terminal or backup orchestrator.

---

## 🚨 5. The 7 Iron-Clad Engineering Rules

1. **⚡ No Blocking I/O or RAM Guards Across Persistence (Durable-before-Vote / DEC-029):**
   * On the PoS lock path (`POST /v1/lock`), never perform unmanaged blocking disk I/O on the runtime thread. Await the persistence worker's exact durable `redb` commit acknowledgment before releasing any binding signature or response envelope (< 20 ms local durable SLA).
   * RAM collision checks use atomic CAS ($< 1\,\mu\text{s}$). Reserve queue capacity (`tx.try_reserve()`) before RAM mutation. No RAM guard is held while awaiting persistence.
   * Background engines (TTL pruning, DB compaction) must never hold locks on the `RamIndex` during a synchronous `fsync` or write operation.
2. **🕰️ No Unsanitized OS System Time on Consensus Path:**
   * Never use `std::time::SystemTime::now()` naively for consensus or ingress decisions.
   * Time windows are validated strictly relative to `root.valid_until` and the decentralized median time derived from F2F neighbors (`P2pClock` / `SimTime` / Spec 07).
3. **🎯 Strict Idempotency & 409 Collision Semantics:**
   * Identical lock (`lock_id` equal) on the same parent $\rightarrow$ `200 OK` (Verified).
   * Diverging lock on the same parent $\rightarrow$ `409 Conflict` (double-spend detected).
   * New lock $\rightarrow$ `201 Created` with signed `Attestation`.
4. **🛡️ Panic Freedom in Libraries (Zero unwrap / expect):**
   * Never use `.unwrap()` or `.expect()` on external network or API input.
   * No unchecked `.partial_cmp().unwrap()` on floating-point numbers (use `total_cmp` or safe fallbacks).
   * Propagate all errors cleanly via structured error types (`NodeError`) as `Result<T, E>`.
5. **🔐 Length-Prefixed BLAKE3 Domain Separation:**
   * Every hash uses canonical length-prefixed domain tags from `humoco-sim-core::crypto`: `hasher.update(&(tag.len() as u8).to_le_bytes()); hasher.update(tag);` (`HUMOCO_V1_*`).
6. **🌊 Streaming Frame Allocation, Stateless Hashcash & Reservation-First:**
   * Never allocate buffers blindly from untrusted header lengths (`Vec::with_capacity(wire_len)` is forbidden).
   * Run cheap filters (stateless BLAKE3 Hashcash, token bucket, quota limits) before expensive operations (Ed25519 signatures, disk lookup).
   * **Stateless Hashcash:** No PoW challenges stored in RAM. PoW is derived from `BLAKE3(len || "HUMOCO_V1_POW_STATELESS" || parent_lock || epoch_slot || nonce)` with a 10-minute time window.
   * **Time-Based EMA:** Moving averages decay strictly as a function of elapsed physical time $\Delta t_{\text{sec}}$, never per event. Under load, gateways push load back via `HTTP 429` with `X-Required-Difficulty: <N>`.
   * **Origin Lock Determines Validity:** Successor locks derive `root_valid_until` and Byte-Years strictly from the signed genesis lock of the root. Unknown root locks are rejected with `400 Bad Request`.
7. **🧪 Mandatory Adversarial Wire-Level P2P Verification:**
   * "Green unit tests in core do not prove server protection." No defense is complete if only verified via in-memory unit tests!
   * Every network invariant (`INV-xxxx`) and server defense MUST have an integration test executing over real QUIC connections in `crates/humoco-node/tests/`: over-quota peers must be rejected, and malformed frames must trigger wire rejections or slashing.

---

## 🗺️ 6. Codebase Map, Specs & Developer Commands

```text
human-money-node/
├── Cargo.toml               # Workspace Manifest
├── AGENTS.md                # THIS DOCUMENT (Canonical System Context)
├── ROADMAP.md               # Phase Plan & Milestones (Phases 0-6: 100% Complete)
│
├── crates/
│   ├── humoco-sim-core/     # Pure mathematics, state machines, determinism
│   │   ├── src/             # crypto, storage (RamIndex), quota, resolver, wire, types
│   │   └── tests/           # Deterministic specification test suites
│   │
│   └── humoco-node/         # Real production daemon
│       ├── src/             # identity, storage (redb DualTierEngine), network (QUIC Quinn),
│       │                    # ingress (3-tier), api (Axum REST), control (UNIX socket), cli
│       └── tests/           # Storage, network, API, control & E2E cluster integration tests
│
├── docs/                    # Numbered specifications 00–20, 99 & INVARIANT_REGISTRY.md
└── prompts/                 # Specialized AI audit prompts (Phases 0-6)
```

### On-Demand Specification Index:
* Detail definitions, proofs, and threat models reside in [`docs/`](docs/):
  * Architecture & Mental Model: [`00_architektur_und_mental_model.md`](docs/00_architektur_und_mental_model.md)
  * Sharding & Living-Mesh Routing: [`03_routing_und_sharding.md`](docs/03_routing_und_sharding.md)
  * Wire Format & Headers: [`10_p2p_wire_format_und_session_framing.md`](docs/10_p2p_wire_format_und_session_framing.md)
  * Persistence & DualTierEngine: [`12_lock_storage_und_ram_index.md`](docs/12_lock_storage_und_ram_index.md) & [`14_node_persistenz_und_redb_speicher.md`](docs/14_node_persistenz_und_redb_speicher.md)
  * Invariant Registry: [`INVARIANT_REGISTRY.md`](docs/INVARIANT_REGISTRY.md)

### Developer Standard Test Commands:
```bash
cargo test-fast        # Fast inner-loop unit/lib tests (< 3s): cargo test --workspace --lib
cargo test-std         # Standard full workspace integration test suite (~12-15s, MANDATORY)
cargo test-deep        # Deep test suite including long-running simulations (-- --ignored)
cargo clippy --workspace --all-targets -- -D warnings
```
