# 🛒 HuMoCo PoS Checkout Trust Architecture: Simplified KISS Plan

**Status:** Approved Architectural Blueprint & Implementation Guide  
**Datum:** 2026-10-23  
**Bezug:** DEC-017, DEC-020, DEC-021, DEC-029, DEC-044, DEC-054, DEC-081, Contracts G1 & G5, Work Packages Z01, Z06  
**Doctrine:** *"Subtraction before Construction – Perfection is achieved when there is nothing left to remove."* & *"In decentralization there is no trust, only mathematical proofs."*

---

## 1. Executive Summary & The KISS Architectural Shift

Earlier proposals for PoS checkout validation explored complex client-side live cross-checks (querying multiple gateways simultaneously during checkout) and client-to-node fraud reporting endpoints (`POST /v1/report-fraud`).

Following a rigorous architectural review under the **"Subtraction before Construction"** doctrine, both modules have been eliminated in favor of a clean, robust, and mathematically sound **KISS (Keep It Simple, Stupid)** design:

1. **No Live Multi-Gateway Cross-Checks on the Hot-Path (Module B Removed):**
   * The PoS checkout hot-path has a strict **800 ms total latency budget**.
   * Live secondary queries introduce network roundtrips, timeouts, and false rejections if secondary nodes are congested.
   * Because Ed25519 signatures are mathematically unforgeable and committee membership is deterministically computed from a locally cached, cold-path synchronized peer roster, a secondary live gateway query provides **zero additional cryptographic security**.

2. **No Client-Facing Fraud-Reporting Endpoints on Tier-1 Ingress (Module C Removed):**
   * In accordance with the **Anti-Hearsay Principle** (Spec 10/11) and DEC-020/DEC-081, node slashing and network-wide bans occur **strictly on first-party cryptographic self-proof** of equivocation (`HUMOCO_V1_EQUIVOCATION`) exchanged directly over Tier-2 QUIC mesh among authenticated peers.
   * Tier-1 HTTP ingress is open and anonymous. Exposing an unauthenticated `/v1/report-fraud` endpoint violates architectural boundaries and creates a dangerous DDoS amplification and spam vector.
   * When a client encounters an invalid certificate from an untrusted gateway, it simply executes **Fail-Closed** locally: the transaction is rejected, goods remain in the store, and the faulty gateway is blacklisted in local client settings.

---

## 2. Cryptographic Ground Truth & Threat Model

```
                    ┌────────────────────────────────────────────────────────┐
                    │                   Cold-Path Sync                       │
                    │   (Periodic background sync from multi-source peers)   │
                    └───────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
┌───────────────────────┐             ┌──────────────────────────────────────┐
│  Customer / Gateway   │             │   Merchant PoS Terminal / App        │
│  (Untrusted Ingress)  │             │   (Local Trust Anchor)               │
└───────────┬───────────┘             └──────────────────┬───────────────────┘
            │                                            │
            │  1. Submit Lock                            │
            │  2. Return Quorum Certificate (14/20)      │
            └───────────────────────────────────────────►│
                                                         │ 3. Hot-Path Local Check:
                                                         │    - Compute HRW Top-20 (<1ms)
                                                         │    - Verify 14 Ed25519 signatures
                                                         │    - Verify Voucher Root & TTL
                                                         ▼
                                              ┌───────────────────────┐
                                              │ Match: Instant Release│
                                              │ Fail:  Fail-Closed ⛔ │
                                              └───────────────────────┘
```

### Threat Analysis & Mathematical Countermeasures

| Threat Scenario | Attack Mechanism | Countermeasure (KISS Ground Truth) | Outcome |
| :--- | :--- | :--- | :--- |
| **1. Roster Fabrication** | Rogue gateway invents 20 ephemeral Ed25519 keys and provides 14 valid signatures. | **Local HRW Committee Computation:** Terminal computes the committee independently from its cold-path roster. Unknown keys are instantly rejected. | **Fail-Closed:** Goods not released. Zero loss. |
| **2. Ephemeral Sybil Attack** | Attacker spins up hundreds of nodes on AWS to capture a shard. | **24h Incubation Wall & Argon2d Tickets:** Shard tickets require PoW and must mature for $\ge 24\,\text{h}$ before being eligible in HRW rankings. | **Fail-Closed:** Unincubated keys excluded from HRW committee. |
| **3. Equivocation (Double-Signing)** | Rogue shard node signs two conflicting locks for the same parent. | **P2P Tier-2 Slashing (`HUMOCO_V1_EQUIVOCATION`):** Honest nodes detecting conflicting signatures propagate proof via QUIC mesh. | Offender node permanently banned; losing branch voided by $\min(H_{\text{canon}})$. |
| **4. Network Partition / Island Mesh** | Local mesh disconnected ($N < 20$). | **Provisional Quorums (DEC-054):** Status is marked `PROVISIONAL` (Class 1), requiring merchant policy approval for large amounts. | Explicit merchant risk sovereignty. |

---

## 3. Two-Path Architecture: Cold-Path Roster vs. Hot-Path Checkout

### 3.1 Cold-Path: Periodic Multi-Source Roster Sync
* **Frequency:** Low frequency (e.g., hourly in background, or upon app initialization).
* **Source:** Multi-source bootstrapping (trusted cooperative seeds, merchant association endpoints, or direct F2F node connections via `GET /v1/gateways` or `/peers`).
* **Validation:**
  1. Verify Argon2d PoW on each `HrwRoutingId`.
  2. Record `first_seen_timestamp` for each identity.
  3. Enforce the **24h Incubation Wall**: only peers with $t_{\text{now}} - t_{\text{seen}} \ge 86.400\,\text{s}$ are eligible for HRW shard rankings.
* **Storage:** Cached in local client storage (SQLite / secure key-value store).

### 3.2 Hot-Path: Local Sub-Millisecond Checkout Verification
* **Latency Budget:** $< 1\,\text{ms}$ CPU time (pure in-memory verification).
* **Network Operations:** Exactly **one** HTTP call (`POST /v1/lock` or receipt of L2 bundle from customer wallet).
* **Deterministic Steps:**
  1. Extract `shard_id` from the target lock.
  2. Compute 256-bit HRW scores: $\text{Score} = \text{BLAKE3}(\text{HrwRoutingId} \parallel \text{Shard\_ID})$ for all mature peers in the cached roster.
  3. Sort deterministically to determine the canonical **Top-20 Committee**.
  4. Verify that the certificate contains $\ge 14$ distinct signatures from this exact Top-20 Committee.
  5. Verify Ed25519 cryptographic signatures on the canonical `L2Verdict`.
  6. **Verdict:**
     * All checks pass $\to$ `can_release_goods_automatically: true`.
     * Any check fails $\to$ `can_release_goods_automatically: false` (Fail-Closed).

---

## 4. Roles & Responsibilities across Repositories

### 4.1 `human-money-core` (Cryptographic Core)
* **Scope:** Pure deterministic business and cryptographic logic (no network or I/O dependencies).
* **Responsibilities:**
  - `calculate_shard_committee(shard_id, &active_peers) -> Vec<NodePubKey>`: Computes 256-bit BLAKE3 HRW rankings with deterministic tie-breaking.
  - `verify_live_checkout_proof(quorum_cert, &expected_committee) -> Result<(), ValidationError>`: Enforces 14-of-20 threshold, signature validity, and committee alignment.
  - Canonical serialization and domain-separated BLAKE3 hashing (`HUMOCO_V1_*`).

### 4.2 `human-money-app` (Client / PoS Terminal)
* **Scope:** Desktop / Mobile GUI application (Tauri / Flutter / Native).
* **Responsibilities:**
  - Maintains persistent local cache of known network roster.
  - Background task: Fetches roster updates on cold-path from configured bootstrap endpoints.
  - Checkout controller: Executes single-gateway lock submission and invokes `human-money-core` verification.
  - Operator UX: Renders clear visual indicators (`FINAL` 🟢 vs. `PROVISIONAL` 🟡 vs. `REJECTED` 🔴).

### 4.3 `humoco-node` (Consensus Daemon & Shard Engine)
* **Scope:** Production L2 node daemon.
* **Responsibilities:**
  - **Tier-1 HTTP Ingress (Port 8080):** High-speed, stateless endpoints (`/v1/lock`, `/v1/status`, `/v1/gateways`).
    * Checks RAM index in $< 1\,\mu\text{s}$.
    * Commits atomically to `redb` under the strict Durable-before-Vote SLA ($< 20\,\text{ms}$).
    * Emits signed attestations and assembled quorum certificates.
    * **Explicit Non-Requirement:** Does NOT expose `/v1/report-fraud` or live cross-check proxies on Tier-1.
  - **Tier-2 QUIC P2P Mesh (Port 9090):** Inter-node mesh for Dunbar presence gossip and direct first-party equivocation slashing (`HUMOCO_V1_EQUIVOCATION`).

---

## 5. Architectural Invariant Registry

* **`INV-POS-01` (Hot-Path Isolation):** The PoS checkout verification must execute entirely offline against locally cached state; no secondary network dependencies may block or gate the 800 ms checkout budget.
* **`INV-POS-02` (Fail-Closed Default):** If fewer than 14 genuine signatures from the deterministically computed Top-20 HRW committee are present, the terminal must reject automatic merchandise release.
* **`INV-POS-03` (Anti-Hearsay Ingress Boundary):** Tier-1 HTTP ingress must never accept third-party fraud complaints or slash peers based on client-submitted reports. All slashing requires Tier-2 first-party cryptographic self-proof.
