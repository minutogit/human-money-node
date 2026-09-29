# 🔍 HuMoCo Layer 2 – Audit 01: Subtraction & Radical Simplification Report

**Datum:** 2026-09-29  
**Audit-ID:** AUDIT-01-SUBTRACTION-SIMPLIFICATION  
**Scope:** `crates/humoco-sim-core` & `crates/humoco-node`  
**Auditor:** Subtraction & Simplification Auditor (Parallel Subagent)  
**Status:** **ANALYZED & PRIORITIZED (5/5 Reduction Filters Evaluated)**

---

## 🏛️ 1. Unnecessary Abstraction Layers (Indirection Bloat)

### 1.1 `RequestHandler` Trait Dynamic Dispatch & Boxing (`crates/humoco-node/src/network/transport.rs:28-43`)
* **Problem:** Dynamic dispatch (`Arc<dyn RequestHandler>`) and heap-allocated `BoxFuture` (`Box::pin(...)`) on incoming QUIC frames.
* **Simplification:** In production there is only `NodeRequestHandler`. Trait object indirection can be parameterized statically or inlined to avoid heap allocation.

### 1.2 DTO Inflation & Hex-String Boxing on Internal P2P Hot-Path (`crates/humoco-node/src/api/dto.rs` vs `humoco-sim-core/src/types.rs`)
* **Problem:** `AttestationDto` contains 3 heap-allocated hex `String`s. `humoco_sim_core::types::Attestation` is already a fixed 144-byte struct with zero heap allocations.
* **Simplification:** Use `Attestation` directly for wire serialization and internal P2P RPCs, converting to DTOs only at public REST boundaries.

### 1.3 Redundant Duplicate & Derivative Fields in `KnownNodeInfo` (`crates/humoco-node/src/network/manager.rs:36-63`)
* **Problem:** `node_id` is an exact alias of `node_pubkey`, `pending_hrw` is duplicate of `pending_hrw_routing_id`, and `incubated_until` is derived deterministically from `pending_since + 24h`.
* **Simplification:** Prune redundant fields and compute expiration on demand.

---

## ⚡ 2. Redundant Clone and Allocation Bloat

### 2.1 Eager Hex Encoding on Ingress Hot-Path (`crates/humoco-node/src/storage/engine.rs:451-516` & `recent.rs:15-21`)
* **Problem:** `parent_lock_hex` and `child_lock_hex` are formatted via `hex::encode(...)` into heap `String`s before CAS validation.
* **Simplification:** Store raw byte arrays `[u8; 32]` inside `RecentLockSummary` and convert to hex lazily on dashboard/status queries.

### 2.2 Base58 String Allocation in `HmcRamIndex::query_status` Loop (`crates/humoco-node/src/storage/engine.rs:218-224`)
* **Problem:** Iteration executes `bs58::encode(&entry.t_id).into_string() == challenge_ds_tag` per lock.
* **Simplification:** Decode `challenge_ds_tag` once upfront into a stack array `[0u8; 32]` and compare bytes directly.

### 2.3 Per-Peer Payload Cloning in Quorum Collection (`crates/humoco-node/src/api/routes.rs:546`)
* **Problem:** Every candidate peer spawned clones `query.payload.to_vec()`.
* **Simplification:** Pass `Bytes` or `Arc<[u8]>` for zero-copy sharing.

---

## 🪓 3. YAGNI Violations & Dead Code

### 3.1 Unused Legacy PoW Hash Function (`crates/humoco-node/src/ingress/pow.rs:37-40`)
* `compute_challenge_hash` is dead code from stateful PoW; stateless PoW uses `compute_stateless_challenge`.

---

## 🎯 4. Top 5 Concrete Reduction Opportunities

1. **Zero-Allocation `RecentLockSummary` on Ingress Hot-Path:** Store raw `[u8; 32]` arrays, eliminate 2 heap allocations per transaction.
2. **Zero-Allocation Fast-Forward Leap Lock Query:** Stack-decode `challenge_ds_tag` in `query_status` upfront ($O(1)$ instead of $O(N)$ allocations).
3. **Prune 3 Duplicate & Derivative Fields in `KnownNodeInfo`:** Remove `node_id`, `pending_hrw`, and `incubated_until`.
4. **Direct Fixed-Array Signature Verification in `verify_peer_attestation`:** Use `hex::decode_to_slice` into stack arrays instead of nested match cascades with `Vec<u8>`.
5. **Prune Dead Legacy PoW Helper:** Delete `compute_challenge_hash`.
