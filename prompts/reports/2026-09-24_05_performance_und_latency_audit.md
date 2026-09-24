# ⚡ Performance, Zero-Copy & Latency Audit Report (2026-09-24)

> **Prompt:** `05_performance_und_latency_audit.md`  
> **Modell:** `opencode/muse-spark-1.2-contributor-free` via KI-Model-Router  
> **Status:** `🟢 Analysiert & Handlungsempfehlungen formuliert`

---

## 📊 Executive Summary

* **Scope:** `crates/humoco-sim-core` und `crates/humoco-node`
* **SLA-Anforderung:** PoS Hot-Path Latenz $< 5\,\text{ms}$, RAM-Index First-Seen Check $< 1\,\mu\text{s}$.
* **Status:** Im Single-Thread Labor erfüllt (`~40ns–80ns` je HashMap-Lookup). Unter hoher Last/Contention drohen jedoch Latenz-Spikes durch JSON-Doppel-Parses, synchrone DB-Operationen im VIP-Tier, Heap-Allokationen (`String`/`Vec`) und `tokio::sync::RwLock`-Serialisierung.

---

## 🔍 Detailbefunde

### 1. Hot-Path Ingress Latenz (< 5ms SLA)
* **Doppel-`serde_json::from_slice`:** In `api/routes.rs:139-143` wird für eingehende JSON-Payloads erst `L2ChainLockRequest` geparst, bei Fehlschlag ein zweites Mal der Standard-Request geparst.
* **VIP-Quota synchrones `spawn_blocking` + Commit:** In `ingress/tier.rs:219-222` wird `check_and_charge_quota` synchron an die redb gebunden.
* **Heap-Allokationen pro Request:** `hex::encode` und `bs58::encode` für Lookup-Tags (`routes.rs:1063`, `engine.rs:354`, etc.) erzeugen vermeidbare Allokationen auf dem Hot-Path.

### 2. RAM-Index & CPU-Cache (< 1µs Target)
* **`RamIndex`:** Verwendet standard `HashMap<Hash256, LockRecord>` mit SipHash. `LockRecord` enthält dynamische Felder (`Vec<u8>`, `BTreeSet`, `String`).
* **Optimierungspotenzial:** Umstellung auf `hashbrown::HashMap` mit `FxHasher` und kompakte Fixed-Size Repräsentationen.

### 3. Zero-Copy Wire Framing & Deserialisierung
* **Framing:** `network/framing.rs:140-187` liest Frames mit Puffer-Allokation. Übergang zu `BytesMut` / `zerocopy` für bit-exakte Casts ohne Pufferkopien.

### 4. Lock-Contention & Concurrency
* **`Arc<RwLock<RamIndex>>` in `engine.rs`:** `tokio::sync::RwLock` verursacht bei Read-DDoS (`/v1/status`) Contention für Schreiber.
* **PoW Replay-Map:** In `ingress/pow.rs:94` iteriert `retain` über `HashMap<String, u64>` unter Lock. Sharded Map mit Key `([u8; 32], u64)` ist allokationsfrei und kontentionsarm.

---

## 🛠️ Priorisierte Tuning-Roadmap

1. **P0:** VIP-Quota RAM-Accounting entkoppeln, JSON Single-Pass Discriminant, PoW Replay-Cache auf `([u8; 32], u64)` umstellen.
2. **P1:** `mimalloc` Allocator aktivieren, Zero-Copy Header Framing verfeinern.
3. **P2:** Sharded RAM-Index / kontentionsfreie Ringpuffer für `recent_locks`.
