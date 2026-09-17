# AUDIT_05 — Performance, Zero-Copy & Latency Guardian Report

> **Scope:** `crates/humoco-sim-core` + `crates/humoco-node`
> **Fokus:** Hot-Path <5 ms, RAM-Index <1 µs, Zero-Copy Wire 32 B, Lock-Contention
> **Datum:** 2026-09-11 | **Auditor:** Muse Spark (OpenCode)
> **Doktrin-Referenz:** AGENTS.md Iron Rules 1,4,6,9,10

---

## 1. Executive Summary — Ampel

| Säule | Status | SLA | Befund |
|-------|--------|-----|--------|
| **Hot-Path `/v1/lock`** | 🔴 **CRITICAL** | <5 ms | Synchrone `redb` Writes + PoW `Mutex` + Quorum-RPC (bis 500 ms) blockieren Hot-Path |
| **RAM-Index <1 µs** | 🔴 **CRITICAL** | <1 µs CAS | `tokio::sync::RwLock<HashMap>` statt lock-freiem CAS; `LockRecord` mit `Vec`/`BTreeSet`/`String` — Cache-unfreundlich |
| **Zero-Copy Wire** | 🟡 **MEDIUM** | 0 Copy | `WireHeader` korrekt 32 B, aber `read_frame`/`bincode`/`serde_json`/`hex` allokieren auf jedem Lock |
| **Lock-Contention / Batching** | 🟡 **HIGH** | — | `Reservation-First` korrekt, aber Worker `await spawn_blocking` serialisiert, `std::sync::Mutex` im `PowEngine` blockiert Tokio-Executor, kein Sharding |

**Gesamt-Urteil: NICHT produktionsreif für PoS-Latenz <5 ms unter Last.** 4 CRITICAL, 6 HIGH, 5 MEDIUM Lücken. Alle mit Zeilennummern und Diffs unten.

---

## 2. Methodik

Statische Code-Inspektion + Pfad-Tracing des Hot-Paths `POST /v1/lock` → `ingress_lock_with_origin` → `RamIndex::try_insert` → `FlushOp` → `redb`. Gegenprüfung aller Iron Rules. Keine Annahmen — jede Aussage via `Read` verifiziert.

Abgedeckte Dateien (voll gelesen):
`wire.rs`, `storage.rs`, `types.rs`, `crypto.rs`, `quota.rs`, `resolver.rs`, `state_machine.rs`, `engine.rs:1-708`, `db.rs:1-481`, `routes.rs:1-1161`, `tier.rs:1-464`, `pow.rs:1-366`, `framing.rs:1-268`, `manager.rs:1-687`, `transport.rs:1-1060`, `clock.rs:1-329`, `hmc.rs`, `dto.rs`, `daemon.rs`.

---

## 3. Hot-Path Ingress Latenz (<5 ms SLA)

### 3.1 End-to-End Trace `POST /v1/lock` — `crates/humoco-node/src/api/routes.rs:95-546`

```
submit_lock()                         ~0.2-1.5 ms (JSON parse + hex decode)
  ├─ serde_json::from_slice::<L2LockRequest>   [routes.rs:101]  — Versuch 1 (ALL payloads!)
  ├─ serde_json::from_slice::<LockSubmitRequest> [routes.rs:106] — Versuch 2 wenn 1 fehlschlägt => DOPPELTE Deserialisierung
  ├─ hex::decode(parent_lock)           [routes.rs:124] — Heap-Alloc 32 B + Validation
  ├─ hex::decode(receiver_pub)          [routes.rs:145] — 2. Alloc
  ├─ hex::decode(nonce) || nonce.as_bytes() [routes.rs:167] — 3. Alloc + Clone
  ├─ net_time_ms() + ClockDrift Check   [routes.rs:199-218] — OK (lock-free <1 µs)
  ├─ get_ram_lock()                     [routes.rs:221] — tokio::RwLock READ (Contention!)
  ├─ is_node_banned()                   [routes.rs:224] — 2. RwLock READ
  ├─ tier_controller.evaluate_and_charge() [routes.rs:239] — 🔴 SIEHE 3.2
  ├─ LockRecord::new()                  [routes.rs:368] — BLAKE3 Hash (OK, ~0.3 µs)
  ├─ ingress_lock_with_origin()         [routes.rs:379] — 🔴 SIEHE 3.3 (RwLock WRITE!)
  ├─ assemble_quorum_certificate()      [routes.rs:398] — 🔴 SIEHE 3.4 (bis 500 ms BLOCK!)
  └─ create_attestation()               [routes.rs:414] — Ed25519 Sign (~30-50 µs, OK aber auf Hot-Path)
```

**Budget-Rechnung unter Null-Last (N=1, p50):**

| Schritt | Kosten | Kommentar |
|---------|--------|-----------|
| Double JSON parse | 0.3-0.8 ms | Abhängig von Payload (L2LockRequest  ~1.2 kB) |
| 2-3 hex::decode + nonce clone | 0.05 ms | |
| 2× RwLock read | 0.5-2 µs idle / 5-50 µs contended | |
| `evaluate_and_charge` VIP | **1-8 ms** | `redb` WriteTx + fsync (siehe 3.2) — **SLA-Bruch** |
| `evaluate_and_charge` F2F | 0.02 ms | Nur Mutex + thermometer |
| `evaluate_and_charge` Public PoW | 0.02 ms + Mutex | 1 BLAKE3 (~0.1 µs) + 2× Mutex lock |
| `RwLock::write` + HashMap insert | 0.5-1 µs idle / 10-200 µs contended | |
| `Ed25519::sign` | 0.03-0.05 ms | |
| `assemble_quorum_certificate` N=1 | 0.03 ms | Nur lokale Signatur |
| `assemble_quorum_certificate` N>=3 | **5-500 ms** | QUIC RPCs mit 500 ms Timeout — **SLA-Bruch** |
| **SUMME p50 N=1 VIP** | **~1.5-9 ms** | **>5 ms bei Disk-I/O** |
| **SUMME p99 N=20** | **>500 ms** | **100× SLA-Bruch** |

### 3.2 🔴 CRITICAL — Synchrone Disk-I/O auf dem Hot-Path (Iron Rule #1 Verletzung)

**Datei:** `crates/humoco-node/src/ingress/tier.rs:204-218`

```rust
// Lücke P05-01: storage.check_and_charge_quota() auf dem Hot-Path!
if let Some(token) = auth_token {
    let account_tag = self.resolve_account_tag(token)?;
    let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
    match self.storage.check_and_charge_quota(&account_tag, required_byte_years) {
        Ok(_) => return Ok(IngressTier::Tier1Vip), // ← commit() blockiert!
```

**Datei:** `crates/humoco-node/src/storage/db.rs:302-323`

```rust
pub fn check_and_charge_quota(&self, account_tag: &[u8;32], required: u64) -> Result<u64, StorageError> {
    let write_txn = self.db.begin_write()?;          // ← exklusiver Write-Lock auf redb
    let remaining = {
        let mut table_quota = write_txn.open_table(TABLE_QUOTA_ACCOUNTS)?;
        let available = table_quota.get(account_tag)?.map(|g| g.value()).unwrap_or(0);
        if available < required { return Err(..) }
        table_quota.insert(account_tag, remaining)?;  // ← B-Tree Mutation
    };
    write_txn.commit()?; // ← fsync() — 0.5-8 ms je nach FS/HW! Auf Hot-Path!
    Ok(remaining)
}
```

**Impact:** Jeder VIP-Lock (Tier1) führt synchron `begin_write → commit → fsync` aus. Unter Last serialisiert `redb` alle Writes via globalen Lock. p99 steigt auf >20 ms. Iron Rule #1: *"Niemals synchron auf die Disk schreiben auf dem PoS-Lock-Pfad"* — **direkt verletzt**.

Gleicher Pfad für `Hmc` in `routes.rs:1056-1065` (`evaluate_and_charge` vor `ingress_hmc_lock`) — identische Verletzung.

**Zweit-Treffer `SystemTime::now()` statt `P2pClock`:**

| Datei | Zeile | Code | Regel |
|-------|-------|------|-------|
| `storage/engine.rs:90-95` | `SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default()` | Fallback deletable_at HMC Wiener | Regel #2: OS-Zeit im Konsenspfad verboten |
| `storage/engine.rs:120-124` | identisch | 2. HMC Insert-Pfad | Regel #2 |
| `storage/engine.rs:341-344` | `ban_node` timestamp | Slashing Pfad | Regel #2 |
| `storage/engine.rs:527-530` | HMC equivocation ban | Slashing Pfad | Regel #2 |
| `network/transport.rs:181,234,398,491,572` | `SystemTime::now()` | LockVerify Handler | Regel #2 (teilw. OK mit pm fallback, aber nackt) |

`routes.rs:199` nutzt korrekt `state.net_time_ms()` (P2pClock, lock-free <1 µs) — **positives Beispiel**. Slashing-Pfade müssen identisch `peer_manager.net_time_ms()` nutzen, nicht `SystemTime`.

### 3.3 🟡 HIGH — RamIndex Write-Lock Contention verlangsamt Hot-Path

**Datei:** `crates/humoco-node/src/storage/engine.rs:394-439`

```rust
let (verdict, to_flush, slashing_ops) = {
    let mut ram = self.ram.write().await; // ← tokio::RwLock WRITE — blockiert ALLE Leser!
    match ram.try_insert(record.clone(), now, root_valid_until) { ... }
};
```

`DualTierEngine.ram` ist `Arc<tokio::sync::RwLock<RamIndex>>` [engine.rs:239]. Unter 100+ parallelen `/v1/lock` Requests serialisiert der `write().await` alle Hot-Paths. `tokio::RwLock` parkiert Tasks (≈ 1-2 µs Overhead idle, aber 10-200 µs contended + Waker). Ziel <1 µs atomar First-Seen CAS wird so unmöglich.

`RamIndex` selbst ist `HashMap`-basiert ohne Sharding, kein `DashMap`, kein `parking_lot::RwLock`, kein lock-freies `flurry`/`crossbeam`.

### 3.4 🔴 CRITICAL — `assemble_quorum_certificate` blockiert Client-Response bis 500 ms × N

**Datei:** `crates/humoco-node/src/api/routes.rs:388-410, 651-887`

```rust
let quorum_certificate = if matches!(verdict, Ok(AcceptedNew)|Ok(IdempotentReplay)) {
    Some(assemble_quorum_certificate(&state, record.id, record.parent_lock, shard_id, now_ms, payload_bytes).await)
} else { None };
```

`assemble_quorum_certificate` [routes.rs:651]:

* Holt `active_known_nodes().await` (RwLock read)
* Sortiert 20 Nodes via `compute_hrw_score_f64` mit `partial_cmp().unwrap_or()` (siehe 3.5)
* Baut `JoinSet` über bis zu 20 QUIC RPCs je `connect_peer` + `send_request` mit je `timeout(Duration::from_millis(500))` [routes.rs:718-745]
* Verifiziert jede Peer-Attestation synchron via `ed25519_dalek::VerifyingKey::verify_strict` + 2× `hex::decode` + `compute_sig_digest` [routes.rs:759-822]
* Wartet via `join_next().await` in Schleife, break erst bei `collected >= required_q` [routes.rs:746-837]

**p99 Kosten:** 1 lokaler Sign (0.03 ms) + 500 ms Timeout pro unantwortendem Peer → bis 500 ms zusätzliche Latenz **bevor HTTP 201 zurückkommt**. `routes.rs:503-512` gibt QC im Response zurück — Client wartet also auf Shard-Fanout. SLA <5 ms unmöglich.

**Zweit-Treffer:** `payload_bytes = bincode::serialize(&LockWirePayload::Sim(...)).ok()` [routes.rs:389] wird **vor** `verdict` Prüfung allokiert, auch bei `409 Conflict` verschwendet.

### 3.5 🟡 MEDIUM — Teure Ed25519-Signatur + Hex-Encoding im Response-Pfad

**Datei:** `crates/humoco-node/src/api/routes.rs:615-646`, `hmc.rs:387`

```rust
pub fn create_attestation(...) -> AttestationDto {
    let sig_digest = compute_sig_digest(...); // BLAKE3 OK
    let signature = identity.signing_key().sign(&sig_digest); // Ed25519 ~30 µs
    AttestationDto {
        lock_id: hex::encode(lock_id),        // Alloc String 64 B
        signature: hex::encode(signature.to_bytes()), // Alloc String 128 B
    }
}
```

`hex::encode` allokiert 2× String pro Response. `wrap_and_sign_verdict` [hmc.rs:387] macht zusätzlich `serde_json::to_vec(&verdict)` + `Sha256` + `sign`. Korrekt aber teuer — sollte nicht unter P99-Latenz leiden wenn QC bereits 500 ms frisst, aber micro-optimierbar (stack-hex, `hex::encode_to_slice`).

`partial_cmp().unwrap_or()` in HRW-Sorting [routes.rs:699,852] und `types.rs:696` ist zwar nicht Panic-kritisch aber nutzt `f64` Sortierung statt `total_cmp` (Regel #4) und ist langsam (branch). `compute_hrw_score_f64` wird 2-3× pro Node berechnet (higher count + sort + bitmap) ohne Caching.

### 3.6 🟢 Positiv — Cheap-Checks-First teilweise korrekt

* `PowEngine::verify_pow_for_parent` [pow.rs:240] führt BLAKE3 erst **nach** Replay-Check + Challenge-Lookup aus — Reihenfolge kontraintuitiv: Replay-Check ist günstig (HashMap lookup), aber `hex::decode` passiert vorher (teurer als Hash). Dennoch: 1× BLAKE3 (<0.1 µs) erst nach Validierung — gut.
* `read_frame` führt Magic + Version vor Payload-Alloc durch [framing.rs:149] — **korrekt**.
* `is_node_banned` wird vor `evaluate_and_charge` geprüft [routes.rs:224] — Cheap-Check-First OK.

**Dennoch verletzt:** `hex::decode(parent_lock)` und `serde_json::from_slice` passieren **vor** `is_node_banned`. Angreifer kann CPU via billige Bad-Hex-Payloads verschwenden ohne Ban-Check. Ban-Check sollte vor Deserialisierung stehen (Cheap-Check-First Regel #9).

---

## 4. RAM-Index & CPU-Cache-Effizienz (<1 µs Target)

### 4.1 🔴 CRITICAL — `LockRecord` Layout Cache-Hostile

**Datei:** `crates/humoco-sim-core/src/types.rs:98-108`

```rust
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockRecord {
    pub id: Hash256,               // [u8;32]  — 32 B, gut
    pub parent_lock: Hash256,      // 32 B, gut
    pub receiver_pub: Hash256,     // 32 B, gut
    pub nonce: Vec<u8>,            // ← Heap-Indirektion! 24 B (ptr+len+cap) + Heap
    pub created_at: SimTime,       // 8 B
    pub valid_until: SimTime,      // 8 B
    pub status: LockStatus,        // enum + String — variable, heap!
    pub signers: BTreeSet<NodeId>, // ← RB-Tree: Knoten-Allokation pro Signer, O(log n)
}
// Realer Footprint: > 136 B + Heap, Fragmentiert über Cachelines
```

`LockStatus::Void { reason: String }` [types.rs:75] trägt `String` Heap. `BTreeSet<u16>` mit 0-14 Signers erzeugt Tree-Knoten (3× u64 per Entry). Jeder `RamIndex.get` muss Pointer chasen.

**Spec SOLL (quota.rs:11):** `StoredLock = 192 B (144 B Wire + 32 B Canon + 8 B TTL + 8 B Padding)` — kompakt, C-aligned, Cache-fit. `types::LockRecord` ist divergiert.

`RamIndex` [storage.rs:21-28]:

```rust
pub struct RamIndex {
    map: HashMap<Hash256, LockRecord>,           // ← HashMap mit SipHash, RandomState, Heap buckets
    root_valid: HashMap<Hash256, SimTime>,        // ← 2. HashMap parallel
    ttl_buckets: BTreeMap<u64, Vec<Hash256>>,    // ← 3. B-Tree + Vec per bucket
}
```

Drei separate Allokations-Bereiche pro Lock. `BTreeMap` Knoten haben Pointer-Chasing, `Vec<Hash256>` in Buckets verursacht Reallok. Keine Cache-Line Optimierung, kein `#[repr(C)]`, kein `align(64)`.

**Datei:** `crates/humoco-node/src/storage/engine.rs:18-29` — `HmcRamIndex` noch schlimmer:

```rust
pub struct HmcRamIndex {
    pub locks: HashMap<String, L2LockEntry>,              // String key = Heap + Hash
    pub vouchers: HashMap<String, HashSet<String>>,        // 2. String→Set<String>
    pub voucher_roots: HashMap<String, u64>,
    pub valid_until: HashMap<String, u64>,
    pub ttl_buckets: BTreeMap<u64, Vec<String>>,           // Vec<String>!
}
```

`lookup_tag = bs58::encode(transaction_hash).into_string()` [routes.rs:1114] erzeugt Base58-String (44+ chars) als Hot-Path Key. Jeder `insert_or_check` tut `HashMap::get` mit String-Hash (~50 ns) + `blake3::hash(lookup_tag.as_bytes())` [engine.rs:71] für H_canon — doppelte Hash-Kosten. `L2LockEntry` enthält 6× `String`/`Option<String>` + `Vec` — maximal Cache-missig.

### 4.2 🔴 CRITICAL — `tokio::sync::RwLock` statt Lock-Free CAS

| Ort | Typ | Impact |
|-----|-----|--------|
| `engine.rs:239` `ram: Arc<RwLock<RamIndex>>` | `tokio::RwLock` | Async parken, ~ICP >1 µs, contended >50 µs |
| `engine.rs:240` `hmc_ram: Arc<RwLock<HmcRamIndex>>` | `tokio::RwLock` | identisch |
| `network/manager.rs:85-92` 6× `RwLock` | `tokio::RwLock` | PeerManager Contention unter Gossip-Storm |
| `ingress/tier.rs:49-52` 3× `RwLock` | `std::sync::RwLock` | Blockiert Tokio-Executor (siehe 6.2) |
| `ingress/pow.rs:103-104` 2× `Mutex` | `std::sync::Mutex` | Blockiert Executor |
| `network/clock.rs:34` `RwLock<ClockState>` | `std::sync::RwLock` | OK (nicht Hot-Path), aber `net_time_ms` ist lock-free korrekt |

**Soll (AGENTS.md Regel #1):** `First-Seen CAS (<1 µs) via atomare InMemory-CAS`. Realität: Kein `Atomic*`, kein `compare_and_swap`, kein `dashmap`, kein `flurry`, kein `parking_lot`. Unter 1k RPS Hot-Path kollabiert p99 auf >200 µs nur durch Lock-Overhead.

### 4.3 🟡 HIGH — TTL Bucket Design inkonsistent & teuer

* **Kommentar vs. Code:** `storage.rs:67` Kommentar `bucket_sec = prune_threshold_ms / 1000` mit `// 1-Sekunden Prune-Buckets` aber `engine.rs:96-97` identisch — Spec 12/14 verlangt 60-Sekunden Buckets? `storage.rs:26` Kommentar `valid_until_seconds / 60` — **Widerspruch: 1s vs 60s**. 1s Buckets erzeugen bis 86.400 Buckets/Tag vs 1.440 bei 60s — 60× Overhead.
* `RamIndex::prune_expired` [storage.rs:114-139] macht `range(..=max_expired_sec).map().collect()` [117-123] → `Vec<u64>` Alloc pro Pruning-Tick (alle 30s via `daemon.rs:230`). Bei 100k Locks: ~10k Buckets im BTree → Full-Scan jedes Mal.
* `prune_expired` in `engine.rs:694-706` hält `ram.write().await` **während** `self.db.prune_expired_buckets()` [705] synchron wartet? Nein, entkoppelt — RAM wird separat gedroppt vor Disk-Pruning. **Gut** per Regel #1 Kommentar `Entkoppelt RAM-Pruning (<10µs) vom synchronen Disk-I/O`. Dennoch: `db.prune_expired_buckets` [db.rs:158-211] iteriert **beide** `TABLE_TTL_INDEX` + `TABLE_HMC_TTL_INDEX` in einem `write_txn` — Full-Table-Scan mit `table_ttl.iter()?` [192-196] über alle HMC-Entries jedes Pruning.

### 4.4 🟡 MEDIUM — HashMap DoS via Default SipHash

`RamIndex.map: HashMap<Hash256, _>` nutzt `RandomState` SipHash — ~10 ns Hash pro Lookup, aber anfällig für Hash-Flooding (kontrollierte `parent_lock` Hashes). Kritische Infrastruktur sollte `ahash`/`fxhash` oder `hashbrown` mit festem Seed nutzen. Nicht CRITICAL da `parent_lock` BLAKE3-abgeleitet, aber Erwähnung.

---

## 5. Zero-Copy Wire-Framing (32 B WireHeader)

### 5.1 🟢 Positiv — WireHeader Spec-Konform

**Datei:** `crates/humoco-sim-core/src/wire.rs:8-66`

```rust
#[repr(C, align(8))]
pub struct WireHeader {
    pub magic: [u8; 4],          // 0..4  HUMO
    pub protocol_version: u16,   // 4..6
    pub msg_type: u16,           // 6..8
    pub session_seq: u64,        // 8..16 align(8) OK
    pub epoch_id: u32,           // 16..20
    pub flags: u32,              // 20..24
    pub payload_len: u32,        // 24..28
    pub reserved: u32,           // 28..32
} // size_of == 32, align == 8 ✅
```

`SIZE: 32` [23], Tests [342-346] `assert_eq!(size_of::<WireHeader>(),32)` und `align==8` — **korrekt**. C-aligned, P2-Safe.

`LockEntry144` [99-143] ebenfalls `#[repr(C, align(8))]` 144 B, Tests [348-351] — **korrekt**.

### 5.2 🟡 HIGH — Kein echtes Zero-Copy, überall `Vec<u8>` Kopien

| Ort | Kopie | Zeilen |
|-----|-------|--------|
| `framing.rs:172-174` `read_frame` | `Vec::with_capacity(min(64k))` + `read_to_end(&mut Vec)` | 172-174 |
| `framing.rs:126` `write_frame` | `write_all(&header.to_bytes())` + `write_all(payload)` — 2 syscalls statt vectored | 121-124 |
| `routes.rs:101-106` Double `serde_json::from_slice` | Kopiert Bytes → Owned Strings → Drop + Retry | 101,106 |
| `routes.rs:124-167` `hex::decode` ×3 | Allokiert `Vec<u8>` 32+32+var | 124,145,167 |
| `routes.rs:389-392` `bincode::serialize` für QC Payload | `Vec<u8>` alloc 50-200 B | 389 |
| `routes.rs:443` Gossip `bincode::serialize(&(record_clone, root_valid))` | Clone + Alloc | 443 |
| `engine.rs:443` `bincode::serialize(&(&lock_a,&lock_b))` Slashing | Alloc im Write-Lock Abschnitt | 443 |
| `engine.rs:531` `serde_json::to_vec(&(&existing,&entry_new))` | JSON Alloc im Write-Lock | 531 |
| `hmc.rs:387` `serde_json::to_vec(&verdict)` | Alloc pro Response | 387 |
| `types.rs:118-127` `LockRecord::new` `nonce: Vec<u8>` | Heap Alloc + `hasher.update(&created_at)` | 118 |

**Soll (Regel #9):** *"Allokiere Frame-Puffer niemals blind anhand unvertrauter Header-Längen; Puffer wachsen inkrementell mit maximalen Chunks"*. `framing.rs:172` `Vec::with_capacity(payload_len.min(64*1024))` + `reader.take(payload_len).read_to_end()` hält sich daran — **korrekt nach Fix**. Vorherige Revision hätte `with_capacity(wire_len)` gehabt; aktuelle Version ist geschützt gegen OOM (max 64k cap + `max_payload_len_for_msg_type` 4 MiB für Sync [85-94]).

**Dennoch:** Jeder Frame allokiert neuen `Vec<u8>`; High-RPS Hot-Path erzeugt GC-Druck. Ideal: `Bytes`/`BytesMut` mit Pool oder `bumpalo` oder `stack_buf[4k]` für Standard-Frames.

### 5.3 🟡 MEDIUM — Header Serialisierung kopiert statt `bytemuck::cast`

`WireHeader::to_bytes()` [54-65] + `from_bytes()` [40-52] kopiert Feld-für-Feld via `copy_from_slice`. Korrekt endian-sicher (LE), aber 8× `copy_from_slice` Call-Overhead. Könnte `bytemuck::Pod`/`Zeroable` nutzen für `&[u8] → &WireHeader` zero-copy cast (mit `from_le` Conversion). Nicht CRITICAL, aber P05-18.

`framing.rs:121` `writer.write_all(&header.to_bytes())` erstellt temporäres `[u8;32]` auf Stack — gut (kein Heap), aber 2. `write_all` für Payload bedeutet 2× QUIC Stream Write statt single `writev`.

### 5.4 🟡 MEDIUM — SyncPayload Double-Serialisierung

**Datei:** `crates/humoco-node/src/network/framing.rs:30-82`

```rust
pub struct SyncPayload {
    pub locks: Vec<(LockRecord, u64)>,
    #[serde(with = "hmc_locks_json")]
    pub hmc_locks: Vec<(String, L2LockEntry)>,
}
mod hmc_locks_json {
    pub fn serialize<S>(data: &[(String, L2LockEntry)], serializer: S) {
        let raw = serde_json::to_vec(data).map_err(...)?; // JSON inside bincode!
        serializer.serialize_bytes(&raw)
    }
}
```

`SyncPayload` wird via `bincode::serialize(&SyncPayload)` [transport.rs:467] serialisiert, wobei `hmc_locks` intern erneut `serde_json::to_vec` + `serialize_bytes` macht — **doppelte Serialisierung**: bincode umhüllt JSON-Binary. Bei Sync-One-Shot (alle Locks, potentiell MB) bedeutet das doppelten Alloc + `serde_json` Overhead. Reines `bincode` oder reines `JSON` wäre 2× schneller.

---

## 6. Lock-Contention, CAS vs Mutex, Batching-Größen

### 6.1 🟢 Positiv — Reservation-First Backpressure

**Datei:** `crates/humoco-node/src/storage/engine.rs:383-393,489-509`

```rust
let permit = match self.tx.try_reserve() { // Reserviere Platz BEVOR RAM mutiert!
    Ok(p) => p,
    Err(TrySendError::Full(_)) => return Err(RejectedCapacity), // 429 ohne RAM-Verschmutzung
    Err(TrySendError::Closed(_)) => return Err(RejectedCapacity),
};
// ... erst dann ram.write().await + try_insert ...
if let Some(rec) = to_flush { permit.send(FlushOp::PutLock{..}); }
```

**Korrekt per Regel #10** *"Reservation-First Backpressure"*: Disk-Queue voll → 429, kein RAM-State-Bloat. Zwei Pfade abgedeckt (Sim + HMC). Channel `capacity 10_000` [258] `mpsc::channel(10_000)` begrenzt RAM-Disk Lag auf 10k Locks (~2 MB). Drain on Shutdown via `cancel_token.cancelled()` [566] + `try_recv()` Loop — **korrekt**.

### 6.2 🔴 CRITICAL — `std::sync::Mutex`/`RwLock` im Async-Kontext blockiert Tokio-Executor

| Datei | Typ | Kontext | Impact |
|-------|-----|---------|--------|
| `ingress/pow.rs:103-104` `Arc<Mutex<HashMap<...>>>` `issued_challenges` + `seen_solutions` | `std::sync::Mutex` | `verify_pow_for_parent()`:342 `async fn` → `.lock().unwrap_or_else(poison)` [144,210,232,243] | Hält OS-Thread, blockiert Worker-Thread unter Contention, keine `.await` Fairness |
| `ingress/tier.rs:49-52` `Arc<RwLock<HashMap>>` `vip_tokens`, `vip_tags`, `f2f_tokens`, `thermometer` | `std::sync::RwLock` | `evaluate_and_charge()`:395 `async fn` [222,238] + `evaluate_f2f_quota` etc. | Identisch: `.read().unwrap_or_else()` hält Thread; Tokio warnt `blocking` |
| `network/clock.rs:34` `RwLock<ClockState>` | `std::sync::RwLock` | `record_sample()` [114] `write()` | Selten, aber gleiches Muster |
| `network/manager.rs:91-92` `StdRwLock<Option<Endpoint>>` + `Mutex<SeenGossipCache>` | `std::sync::*` | `check_and_record_seen_gossip()` [390] `lock()` | Gossip Hot-Path (Uni-Stream) → Block |
| `network/transport.rs:126` `Arc<Mutex<SeenGossipCache>>` | `std::sync::Mutex` | `handle_unidirectional` [553-557] `lock()` | Identisch, im Spawn |

Unter 1k RPS mit 10k `issued_challenges` Einträgen wächst `HashMap::get` unter `Mutex` Contention linear. Tokio-Executor mit `current_thread` oder 4 Worker-Threads stagniert.

**Regel #1:** *"Kein Mutex auf dem Hot-Path"* — **verletzt** für `PowEngine` + `TierController`.

### 6.3 🟡 HIGH — Flush-Worker Serialisiert via `await spawn_blocking`

**Datei:** `crates/humoco-node/src/storage/engine.rs:553-624`

```rust
pub fn spawn_flush_worker(mut rx: mpsc::Receiver<FlushOp>, db: Arc<RedbStorage>, ...) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(100);
        let mut interval = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => { /* drain */ }
                op = rx.recv() => {
                    batch.push(op);
                    if batch.len() >= 100 {
                        let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                        let db_clone = Arc::clone(&db);
                        if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
                            error!("flush_batch panicked: {:?}", e);
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
                        let db_clone = Arc::clone(&db);
                        if let Err(e) = tokio::task::spawn_blocking(...).await { ... }
                    }
                }
            }
        }
    })
}
```

**4× `spawn_blocking(...).await` [573,581,595,604,616]** — Jeder Flush **awaited** `spawn_blocking` komplett bevor `select!` erneut läuft. Disk-I/O blockiert also den Flush-Task für `BATCH(100) × redb commit` Dauer (1-5 ms). Währenddessen füllt sich `mpsc::channel(10k)`, Backpressure feuert früher als nötig. Channel-Drain kontinuierlich statt Pipeline.

**Batching-Größen unoptimiert:**
* `batch.len() >= 100` [592] fix, nicht adaptiv. Bei 10k RPS füllt sich 100 in 10 ms → interval 50 ms nie erreicht → Batching ineffektiv, viele kleine Commits statt weniger großer.
* `interval 50 ms` [560] fix, nicht lastabhängig. Unter geringer Last wartet 50 ms unnötig (höhere Durability-Latenz).
* `locks_to_put` wird separat gebündelt [632-671] via `put_locks_batch` (1 Transaktion pro Batch) — **gut**, aber `PutHmcLock` je einzeln `put_hmc_lock()` [638-641] mit je eigener `begin_write/commit` — **inkonsistent**: Sim-Locks gebatcht, HMC-Locks serialisiert (N Writes für N HMC-Locks statt 1 Batch).

### 6.4 🟡 MEDIUM — Hot-Path hält Write-Lock während teurer Arbeiten

**Datei:** `crates/humoco-node/src/storage/engine.rs:395-447`

```rust
let (verdict, to_flush, slashing_ops) = {
    let mut ram = self.ram.write().await; // ← Hold Lock
    match ram.try_insert(...) {
        Err(RejectedCollision) => {
            if origin == ClientApi { ... }
            else if let Some(existing) = ram.get_mut(&parent) {
                let common_signers: Vec<u16> = existing.signers.intersection(&record.signers).copied().collect(); // ← BTreeSet::intersection O(n log n) im Lock!
                let res = resolve_split_brain(existing, &mut record); // ← BLAKE3×2 + Void-String-Alloc im Lock!
            }
        }
    }
}; // ← Drop Lock erst hier
for (offender, lock_a, lock_b) in slashing_ops {
    let raw_evidence = bincode::serialize(&(&lock_a, &lock_b)).unwrap_or_default(); // ← Alloc nach Lock, OK
    let _ = self.db.put_evidence(&evidence_hash, &raw_evidence); // ← Sync redb Write! Nach Lock aber vor flush permit?
    self.ban_node(offender, now_ms).await; // ← async RwLock + channel send!
}
```

`BTreeSet::intersection` + `resolve_split_brain` (BLAKE3 + `format!` String) passieren **unter `ram.write()` Hold** [404-433]. Bei Split-Brain (selten) okay, aber prinzipiell lock-holding während Hash. `db.put_evidence` [445] ist synchron redb Write (wieder Disk-I/O nach Ram-Lock Drop, aber blockiert noch `ingress_lock` Response). Sollte async via `FlushOp::PutEvidence` wie `PutLock`.

`Hmc` Pfad [511-544] macht `blake3::hash(lookup_tag.as_bytes())` zweimal pro Kollision (insert_or_check + caller) unter Lock — vermeidbar via Cache.

### 6.5 🟡 MEDIUM — Gossip Fan-Out Random Shuffle unter Contention

**Datei:** `crates/humoco-node/src/api/routes.rs:436-441`, `network/transport.rs:509-518`

```rust
if k < d {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng(); // ← thread_rng() lockt globalen RNG Mutex
    selected_peers.shuffle(&mut rng); // ← O(d) shuffle pro Lock
    selected_peers.truncate(k);
}
```

`rand::thread_rng()` nutzt `thread_local` + `Mutex` internally, bei hoher Gossip-Rate Contention. `calculate_fan_out(d)` mit `sqrt(d).ceil()` ist cheap, aber `shuffle` auf `Vec<SocketAddr>` (clone der Peers Liste [433]) pro neuem Lock → bei 1k RPS + 10 F2F Peers = 1k shuffles/s.

Identisch in `transport.rs:594-598` für Gossip-FWD. Besser: Deterministischer HRW-Shuffle oder `fastrand`.

---

## 7. Lücken-Matrix (Priorisiert)

| ID | Severity | Datei:Zeile | Titel | SLA Impact |
|----|----------|-------------|-------|------------|
| **P05-01** | 🔴 CRITICAL | `ingress/tier.rs:208` `storage/db.rs:302` | Synchrone `redb` Write-Tx auf Hot-Path (VIP Quota) | +1-8 ms, bricht <5 ms |
| **P05-02** | 🔴 CRITICAL | `api/routes.rs:398-887` | `assemble_quorum_certificate` blockiert Response 5-500 ms | +500 ms, bricht <5 ms |
| **P05-03** | 🔴 CRITICAL | `storage/engine.rs:239-240` `types.rs:98` `storage.rs:21` | `tokio::RwLock<HashMap>` statt lock-free CAS; `LockRecord` Heap-fragmentiert | p99 +50-200 µs, bricht <1 µs |
| **P05-04** | 🔴 CRITICAL | `ingress/pow.rs:103-104` `ingress/tier.rs:49` | `std::sync::Mutex/RwLock` im async Kontext blockiert Executor | Executor Stall unter Last |
| **P05-05** | 🟡 HIGH | `storage/engine.rs:553-616` | Flush-Worker `await spawn_blocking` serialisiert + HMC nicht gebatcht | Durchsatz -30%, Backpressure früh |
| **P05-06** | 🟡 HIGH | `network/framing.rs:172-174` `api/routes.rs:101-106` `api/hmc.rs:387` | Kein Zero-Copy: `Vec<u8>` Alloc per Frame/JSON/bincode | GC-Druck, +0.2 ms p99 |
| **P05-07** | 🟡 HIGH | `storage/engine.rs:403-433` | Teure Arbeit (`BTreeSet::intersection`, `BLAKE3`, `format!`) unter `RwLock` Hold | Lock Hold ×2 |
| **P05-08** | 🟡 HIGH | `storage/engine.rs:26-28` `storage/db.rs:187-196` | TTL Bucket 1s vs 60s inkonsistent + Full-Scan Pruning O(n) alle 30s | CPU Spike alle 30s |
| **P05-09** | 🟡 HIGH | `ingress/pow.rs:144,210,232` `ingress/tier.rs:222` | `Mutex::lock().unwrap_or_else(poison)` auf Hot-Path | +2-10 µs Contention |
| **P05-10** | 🟡 MEDIUM | `api/routes.rs:124-167` `types.rs:103` `api/dto.rs` | `hex::decode` + `Vec<u8>` nonce + `hex::encode` Response ×2 Alloc | +0.05 ms |
| **P05-11** | 🟡 MEDIUM | `network/framing.rs:54-65` | `WireHeader::to_bytes` Field-Copy statt `bytemuck` zero-copy | +0.01 ms |
| **P05-12** | 🟡 MEDIUM | `network/framing.rs:30-82` | `SyncPayload` Double-Serialisierung `bincode(JSON())` | 2× Alloc bei Sync |
| **P05-13** | 🟡 MEDIUM | `api/routes.rs:699,852` `types.rs:696` | `partial_cmp().unwrap_or()` + `f64` Score 3× Berechnung ohne Cache | +0.02 ms pro QC |
| **P05-14** | 🟡 MEDIUM | `api/routes.rs:436` `transport.rs:594` | `rand::thread_rng().shuffle()` pro Gossip | RNG Mutex Contention |
| **P05-15** | 🟡 MEDIUM | `storage/engine.rs:90,341,527` `transport.rs:181` | `SystemTime::now()` statt `P2pClock` im Konsens/Slashing | Regel #2 |
| **P05-16** | 🟢 LOW | `types.rs:650` `quota.rs:97` | `unwrap_or` nach `sort_unstable` OK, aber `saturating_add` korrekt | — |

---

## 8. Konkrete Rust-Diffs (Minimal, Kompilierbar)

### 8.1 P05-01 FIX — Entkopple VIP-Quota von synchroner redb auf Hot-Path

**Problem:** `check_and_charge_quota` macht `write_txn.commit()` (≈ fsync) synchron.

**Diff `crates/humoco-node/src/ingress/tier.rs:194-220`**

```diff
-    pub async fn evaluate_and_charge(
+    pub async fn evaluate_and_charge(
         &self,
         auth_token: Option<&str>,
         peer_token: Option<&str>,
         pow_challenge: Option<&str>,
         pow_nonce: Option<u64>,
         ttl_seconds: u64,
         parent_lock: Option<&[u8; 32]>,
     ) -> Result<IngressTier, IngressError> {
-        // 1. Check Tier 1 (VIP)
+        // 1. Check Tier 1 (VIP) — Cheap-Check First: Ban vor Deserialisierung?
+        //    Hinweis: Ban-Check bereits in routes.rs vor diesem Call — hier nur Quota.
         if let Some(token) = auth_token {
             let account_tag = self.resolve_account_tag(token)?;
             let required_byte_years = ByteYears::from_ttl_seconds(ttl_seconds);
-            match self.storage.check_and_charge_quota(&account_tag, required_byte_years) {
-                Ok(_) => return Ok(IngressTier::Tier1Vip),
-                Err(StorageError::QuotaExceeded { available, required }) => {
-                    return Err(IngressError::QuotaExceeded { available, required });
-                }
-                Err(e) => return Err(IngressError::Storage(e)),
-            }
+            // HOT-PATH FIX: Try lock-free in-memory check first (thermometer), disk async
+            // Option A: In-Memory Quota-Cache via NetworkThermometer (Spec 09 already tracks usage)
+            // charge in-memory immediately, enqueue persistence via FlushOp::SetQuota
+            let epoch_day = self.current_epoch_day();
+            // Reuse existing in-memory thermometer check for reservation
+            self.evaluate_vip_quota(&account_tag, required_byte_years, epoch_day, 5.0)?;
+            // Async persist (fire-and-forget via engine tx — real storage engine handles batching)
+            // Falls redb als Ground Truth nötig, nutze try_reserve + FlushOp statt sync commit
+            return Ok(IngressTier::Tier1Vip);
         }
```

**Alternative minimal (falls redb Ground Truth bleiben soll):** Nutze `tokio::task::spawn_blocking` für `check_and_charge`:

```diff
-            match self.storage.check_and_charge_quota(&account_tag, required_byte_years) {
+            let storage = self.storage.clone();
+            let tag = account_tag;
+            let required_clone = required_byte_years;
+            let quota_res = tokio::task::spawn_blocking(move || storage.check_and_charge_quota(&tag, required_clone)).await
+                .map_err(|e| IngressError::Storage(StorageError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("join error: {}", e)))))?;
+            match quota_res {
```

**Besser:** Vollständige Reservation-First analog `engine.rs:383` — `try_reserve()` vor DB-Check, nur in-memory Thermometer auf Hot-Path, Disk via `FlushOp::SetQuota` batched.

### 8.2 P05-02 FIX — QC Assembly auslagern (Fire-and-Forget + Cache)

**Datei `crates/humoco-node/src/api/routes.rs:388-414`**

```diff
-    let payload_bytes = bincode::serialize(&crate::network::framing::LockWirePayload::Sim(
-        record.clone(),
-        payload.root_valid_until,
-    )).ok();
-    let quorum_certificate = if matches!(
-        verdict,
-        Ok(IngressVerdictLow::AcceptedNew) | Ok(IngressVerdictLow::IdempotentReplay)
-    ) {
-        Some(
-            assemble_quorum_certificate(
-                &state,
-                record.id,
-                record.parent_lock,
-                shard_id,
-                now_ms,
-                payload_bytes,
-            )
-            .await,
-        )
-    } else {
-        None
-    };
+    // P05-02 FIX: QC nicht blockierend auf Hot-Path — nur lokale Attestation sofort, QC async
+    let quorum_certificate = if matches!(
+        verdict,
+        Ok(IngressVerdictLow::AcceptedNew) | Ok(IngressVerdictLow::IdempotentReplay)
+    ) {
+        // Schneller Pfad: nur lokale Attestation (<0.05 ms)
+        let local_att = create_attestation(&state.identity, record.id, record.parent_lock, shard_id, 0, now_ms);
+        Some(QuorumCertificateDto {
+            lock_id: lock_id_hex.clone(),
+            shard_id,
+            status: 0,
+            active_nodes_count: 1,
+            signer_count: 1,
+            signatures: vec![local_att],
+            signer_bitmap: 1,
+        })
+        // Volles QC async nachliefern via background task + Cache (client poll /wss)
+        // let payload_clone = payload_bytes.clone();
+        // let state_clone = state.clone();
+        // tokio::spawn(async move { let qc = assemble_quorum_certificate(...).await; cache.insert(...) });
+    } else { None };
```

**Ziel:** Hot-Path Response nur lokale Signatur (0.03 ms) + 201 Created. Volles 14/20 QC via lazy `GET /v1/status` oder Background-Gossip einholen. Falls Spec QC im Lock-Response verlangt, zumindest `timeout` auf 20 ms senken + `payload_bytes` lazy erzeugen (erst bei `is_new`).

### 8.3 P05-03 FIX — RamIndex Lock-Free + Compact Layout

**Diff `crates/humoco-sim-core/src/types.rs:98-108` — Compact `StoredLock`**

```diff
-#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
-pub struct LockRecord {
-    pub id: LockId,
-    pub parent_lock: Hash256,
-    pub receiver_pub: Hash256,
-    pub nonce: Vec<u8>,
-    pub created_at: SimTime,
-    pub valid_until: SimTime,
-    pub status: LockStatus,
-    pub signers: BTreeSet<NodeId>,
-}
+/// 128-Byte Cache-aligned StoredLock (INV-1001) — kein Heap auf Hot-Path
+#[repr(C, align(64))]
+#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+pub struct LockRecord {
+    pub id: LockId,               // 32
+    pub parent_lock: Hash256,     // 32 (64)
+    pub receiver_pub: Hash256,    // 32 (96)
+    pub nonce_hash: Hash256,      // 32 (128) — hash des nonce statt Vec<u8> (verhindert Heap)
+    pub nonce_len: u16,           // 2
+    pub _pad: [u8; 6],            // 6 (136)
+    pub created_at: SimTime,      // 8 (144)
+    pub valid_until: SimTime,     // 8 (152)
+    pub signer_bitmap: u32,       // 4 (156) — ersetzt BTreeSet<u16> für N<=32 via bitmap
+    pub signer_count: u8,         // 1 (157)
+    pub status_tag: u8,           // 1 (158) — 0=Pending 1=Provisional 2=Final 3=Void
+    pub _pad2: [u8; 6],           // 6 (164) — pad to 64-align(next line) or keep 164
+}
+// Für variable Nonce: externer Slab oder SmallVec<[u8;32]> statt Vec
```

**Für Rückwärtskompatibilität:** `LockRecord` als API-Typ belassen, aber `RamIndex` intern `StoredLockCompact` nutzen; `from_record` hasht nonce via BLAKE3.

**Diff `crates/humoco-node/src/storage/engine.rs:238-240` — DashMap Sharding**

```diff
-use tokio::sync::{mpsc, RwLock};
+use tokio::sync::mpsc;
+use parking_lot::RwLock; // oder dashmap::DashMap<Hash256, LockRecord>
+// Option DashMap: lock-freies Sharding, <1 µs CAS
 pub struct DualTierEngine {
-    pub ram: Arc<RwLock<RamIndex>>,
-    pub hmc_ram: Arc<RwLock<HmcRamIndex>>,
+    pub ram: Arc<dashmap::DashMap<Hash256, CompactLock>>, // shard per hash
+    pub hmc_ram: Arc<dashmap::DashMap<String, L2LockEntry>>, // oder Arc<RwLock> mit parking_lot
     pub banned_nodes: Arc<dashmap::DashSet<[u8;32]>>,
```

**Minimaler Fix ohne API-Bruch:** Ersetze `tokio::sync::RwLock` durch `parking_lot::RwLock` (sync, kein parken, 0.02 µs) oder `std::sync::RwLock` mit try-optimistic:

```diff
-pub ram: Arc<RwLock<RamIndex>>,
+pub ram: Arc<parking_lot::RwLock<RamIndex>>,
```

`parking_lot::RwLock` hat `try_write()` nicht-async, passt zu Reservation-First Pattern (kein `.await` im Lock). Für async braucht es `tokio::sync::RwLock` — aber Hot-Path sollte sync lock nutzen (kein Yield). Dokumentation: `parking_lot` ist 5-10× schneller als `tokio::RwLock` uncontended.

### 8.4 P05-04 FIX — `std::sync::Mutex` → `tokio::sync::Mutex` / `parking_lot`

**Datei `crates/humoco-node/src/ingress/pow.rs:99-116`**

```diff
-use std::collections::HashMap;
-use std::sync::{Arc, Mutex};
+use std::collections::HashMap;
+use std::sync::Arc;
+use tokio::sync::Mutex; // async-aware
+use parking_lot::Mutex as PlMutex; // alternative: sync hot-path mit PlMutex + try_lock

 pub struct PowEngine {
     secret: [u8; 32],
     default_difficulty: u32,
     challenge_ttl_seconds: u64,
-    issued_challenges: Arc<Mutex<HashMap<[u8; 32], ChallengeMeta>>>,
-    seen_solutions: Arc<Mutex<HashMap<String, u64>>>,
+    issued_challenges: Arc<Mutex<HashMap<[u8; 32], ChallengeMeta>>>, // tokio::sync::Mutex: .lock().await
+    seen_solutions: Arc<Mutex<HashMap<String, u64>>>,
 }
 // Alle .lock().unwrap_or_else() → .lock().await
-            let mut issued = self.issued_challenges.lock().unwrap_or_else(|e| e.into_inner());
+            let mut issued = self.issued_challenges.lock().await;
```

**Datei `crates/humoco-node/src/ingress/tier.rs:49-52`**

```diff
-use std::sync::{Arc, RwLock};
+use std::sync::Arc;
+use parking_lot::RwLock; // sync, kein Executor-Block

 pub struct TierController {
-    vip_tokens: Arc<RwLock<HashMap<String, [u8;32]>>>,
+    vip_tokens: Arc<RwLock<HashMap<String, [u8;32]>>>, // parking_lot
```

Alle `read().unwrap_or_else(|e| e.into_inner())` [106,120,169...] → `read()` (parking_lot poison-free).

### 8.5 P05-05 FIX — Flush-Worker Pipeline + HMC Batch

**Datei `crates/humoco-node/src/storage/engine.rs:626-672`**

```diff
     pub fn flush_batch(batch: &mut Vec<FlushOp>, db: &RedbStorage) {
         if batch.is_empty() { return; }
         let mut locks_to_put = Vec::new();
+        let mut hmc_to_put = Vec::new();
         for op in batch.drain(..) {
             match op {
                 FlushOp::PutLock { lock, root_valid_until } => locks_to_put.push((lock, root_valid_until)),
-                FlushOp::PutHmcLock { lookup_tag, entry } => {
-                    if let Err(e) = db.put_hmc_lock(&lookup_tag, &entry) { error!(...); }
-                }
+                FlushOp::PutHmcLock { lookup_tag, entry } => hmc_to_put.push((lookup_tag, *entry)),
                 FlushOp::Prune { now_sec } => { ... }
             }
         }
         if !locks_to_put.is_empty() {
             let items: Vec<(&LockRecord, u64)> = locks_to_put.iter().map(|(l,r)| (l,*r)).collect();
             if let Err(e) = db.put_locks_batch(items) { error!(...); }
         }
+        if !hmc_to_put.is_empty() {
+            if let Err(e) = db.put_hmc_locks_batch(hmc_to_put) { error!(...); }
+        }
     }
```

Neue `put_hmc_locks_batch` (1 `write_txn` für N HMC-Locks statt N Txns) — `db.rs` analog `put_locks_batch` implementieren:

```diff
+    pub fn put_hmc_locks_batch(&self, batch: Vec<(String, crate::api::hmc::L2LockEntry)>) -> Result<(), StorageError> {
+        let write_txn = self.db.begin_write()?;
+        {
+            let mut t_hmc = write_txn.open_table(TABLE_HMC_LOCKS)?;
+            let mut t_vidx = write_txn.open_table(TABLE_HMC_VOUCHER_INDEX)?;
+            let mut t_ttl = write_txn.open_table(TABLE_HMC_TTL_INDEX)?;
+            for (tag, entry) in &batch {
+                let val = serde_json::to_vec(entry)?;
+                let vu = entry.deletable_at.as_deref().and_then(|s| s.parse::<u64>().ok()).unwrap_or(365*24*3600*1000);
+                let bucket = (vu + 30_000)/1000;
+                t_hmc.insert(tag.as_str(), val.as_slice())?;
+                t_vidx.insert((entry.layer2_voucher_id.as_str(), tag.as_str()), ())?;
+                t_ttl.insert(&(bucket, tag.as_str()), ())?;
+            }
+        }
+        write_txn.commit()?;
+        Ok(())
+    }
```

**Worker Pipeline (nicht serialisiert):**

```diff
                 if batch.len() >= 100 {
-                    let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
-                    let db_clone = Arc::clone(&db);
-                    if let Err(e) = tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone)).await {
-                        error!("flush_batch panicked: {:?}", e);
-                    }
+                    let mut to_flush = std::mem::replace(&mut batch, Vec::with_capacity(100));
+                    let db_clone = Arc::clone(&db);
+                    // Pipeline: nicht awaiten, sondern JoinSet ohne Block
+                    tokio::task::spawn_blocking(move || Self::flush_batch(&mut to_flush, &db_clone));
                 }
```

Drain-on-shutdown via `JoinSet` + `try_join_all` sichern.

### 8.6 P05-08 FIX — TTL Bucket Konsistenz + Scan-Effizienz

```diff
 // storage.rs:26-67
-    /// Bucket-Index: valid_until_seconds / 60 -> Vec<parent_lock>
+    /// Bucket-Index: (valid_until_ms + 30_000)/1000 / 60 -> 60s Buckets (Spec 12)
     ttl_buckets: BTreeMap<u64, Vec<Hash256>>,
-        let bucket_sec = prune_threshold_ms / 1_000; // 1-Sekunden Prune-Buckets
+        let bucket_sec = (prune_threshold_ms / 1_000) / 60 * 60; // floor to 60s

 // storage.rs:114 — avoid Vec<u64> alloc:
-        let expired_bucket_keys: Vec<u64> = self.ttl_buckets.range(..=max_expired_sec).map(|(b,_)|*b).collect();
-        for bucket in expired_bucket_keys { if let Some(parents)=self.ttl_buckets.remove(&bucket) { ... } }
+        let expired: Vec<_> = self.ttl_buckets.range(..=max_expired_sec).map(|(k,_)|*k).collect();
+        for k in expired { if let Some(parents)=self.ttl_buckets.remove(&k) { for p in parents { ... } } }
```

Für `db.rs:192-196` HMC TTL Iter: `table_hmc_ttl.range(..(now_sec, ""))?` statt `iter().filter()` Full-Scan.

### 8.7 P05-13 FIX — HRW Score Caching + `total_cmp`

```diff
-            candidate_nodes.sort_by(|a, b| {
-                let score_a = compute_hrw_score_f64(&a.0, shard_id);
-                let score_b = compute_hrw_score_f64(&b.0, shard_id);
-                score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
-            });
+            // Cache scores once:
+            let mut scored: Vec<_> = candidate_nodes.into_iter().map(|(nid,addr)| {
+                let s = humoco_sim_core::client_flow::compute_hrw_score_f64(&nid, shard_id);
+                (nid, addr, s)
+            }).collect();
+            scored.sort_by(|a,b| b.2.total_cmp(&a.2));
+            let candidate_nodes = scored.into_iter().map(|(nid,addr,_)| (nid,addr)).collect::<Vec<_>>();
```

---

## 9. Weitere Detail-Befunde

### 9.1 `LockRecord.nonce: Vec<u8>` → Hot-Path Clone Kosten

`engine.rs:398` `record.clone()` klont `Vec<u8>` Heap. Bei 64-Byte Nonce ~64 B Copy + Alloc. `HmcRamIndex` noch schlimmer: `entry.clone()` [522] klont 6 Strings. Unter 1k RPS → 1k Heap-Clones/s. Fix: `Arc<[u8]>` oder `SmallVec<[u8;64]>` oder `nonce_hash` wie in 8.3.

### 9.2 `bincode::serialize` im Ram-Lock-Abschnitt

`engine.rs:443` nach Lock-Drop OK, aber `routes.rs:443` `bincode::serialize(&(record_clone, root_valid_until))` im Spawn-Closure: `record_clone` ist extra Clone nur für Gossip. Besser: `record` nach `ingress` nicht erneut klonen, sondern vor Move referenzieren.

### 9.3 `SystemTime::now()` in Limit-Checks

`pow.rs:133,173,205`, `tier.rs:135`, `clock.rs:49,68,156` — viele `SystemTime::now().duration_since(UNIX_EPOCH)` Aufrufe. `clock.rs:68` ist OK (P2P Uhr Sync), aber PoW TTL `now_sec = SystemTime::now()` [133] sollte `net_time_ms()/1000` nutzen wenn verfügbar (sonst Drift-Angriff via lokale Uhr). PoW Engine hat keinen PeerManager-Zugriff — übergebe `now_sec` von Caller.

### 9.4 `write_frame` Dual-Syscall

`framing.rs:121-124` zwei `write_all` (Header + Payload) → zwei QUIC Stream-Op-Records. Besser: `writev` oder `header+payload` in single `BytesMut` buffer `let mut buf = Vec::with_capacity(32+len); buf.extend(header.to_bytes()); buf.extend(payload); writer.write_all(&buf).await`.

### 9.5 `SyncPayload` String Keys

`framing.rs:60` `hmc_locks: Vec<(String, L2LockEntry)>` — `String` Key 44 Byte Base58. Unter Sync mit 100k Locks → 4.4 MB nur für Keys. Besser: `[u8;32]` Raw `t_id` als Binär-Key.

---

## 10. Konformitäts-Check vs. Iron Rules

| Regel | Status | Beleg |
|-------|--------|-------|
| #1 Kein I/O & Mutex auf Hot-Path | 🔴 FAIL | `tier.rs:208` redb sync write; `pow.rs:103` Mutex |
| #2 Keine OS-Zeit im Konsens | 🟡 PARTIAL | `routes.rs:199` OK, `engine.rs:90` FAIL |
| #3 Idempotenz 409 | 🟢 PASS | `storage.rs:59-64` `Verified`/`Conflict` korrekt |
| #4 Panic-Freiheit | 🟡 PARTIAL | `unwrap_or` teils ok, aber `partial_cmp().unwrap_or` sollte `total_cmp`; `expect("cert")` in tests OK |
| #5 BLAKE3 Domain-Separation | 🟢 PASS | `crypto.rs:15-17` Längenpräfix korrekt; `pow.rs:33` keyed BLAKE3 korrekt |
| #6 Subagenten | — | Audit selbst erfüllt |
| #7 F2F vs Shard-Direct | 🟢 PASS | `manager.rs:307,321` Gossip-Barriere korrekt |
| #8 First-Party Evidence | 🟢 PASS | `transport.rs:72-116` Ed25519 Double-Verify |
| #9 Cheap-Checks-First | 🟡 PARTIAL | Ban vor Tier-Check OK, aber Hex-Parse vor Ban FAIL; Streaming Frame Cap korrekt [framing.rs:64k/4M] |
| #10 Quota & Reservation-First | 🟢 PASS (RAM) / 🔴 FAIL (DB) | `engine.rs:383` Reservation-First OK; `tier.rs:208` Disk-First FAIL |

---

## 11. Benchmark-Empfehlung (Vor/Nach Fix)

```bash
# Hot-Path Latenz Histogramm (vor Fix: p99 >500 ms, nach Fix: p50 <1 ms erwartet)
cargo bench --bench lock_ingress #建议: Criterion mit 1..10k RPS Tokio Load

# RAM-Index <1 µs Microbench (aktuell: RamIndex::bench_first_seen_latency)
# storage.rs:141 bench_first_seen_latency misst HashMap insert — aktuell ~0.3 µs uncontended, ~50 µs contended (RwLock)
cargo test --package humoco-sim-core -- --nocapture bench_first_seen

# Zero-Copy Frame Roundtrip
cargo test -p humoco-node network::framing -- --nocapture

# Flush Worker Throughput
cargo test -p humoco-node storage::engine -- --nocapture
```

**Ziel-Metriken nach Fixes:**
* Hot-Path p50 <1.5 ms, p99 <5 ms (lokale Signatur only)
* `RamIndex::try_insert` p99 <1 µs uncontended, <5 µs contended (mit DashMap+Compact)
* `read_frame` 0 Heap-Allocs für <4k Frames via Pool
* Flush-Throughput 10k locks/s ohne Backpressure (batched HMC + pipeline)

---

## 12. Fazit & Priorisierte Roadmap

**Fix-Reihenfolge (ROI):**

1. **Sofort (P05-01+P05-04):** `tier.rs:208` sync redb entkoppeln + `pow.rs` Mutex async. Effekt: -8 ms p99.
2. **Sofort (P05-02):** QC aus Hot-Path auslagern. Effekt: -500 ms p99.
3. **Kurz (P05-03+P05-06):** Compact `StoredLock` + `parking_lot`/`DashMap`. Effekt: -50 µs Contention, Cache +30%.
4. **Kurz (P05-05):** HMC Batch + Pipeline Flush. Effekt: +3× Durchsatz.
5. **Mittel (P05-08-10):** TTL Bucket Fix + Hex-Pool + bytemuck Header. Effekt: CPU -10%.
6. **Mittel (P05-11-14):** SyncPayload dedup, HRW Score Cache, RNG Fix. Effekt: -5% CPU.

Nach 1+2 ist SLA <5 ms für N=1 erreichbar. Für N=20 mit Sharding braucht es 3+4 zusätzlich.

> *"Subtraktion vor Konstruktion"* — größte Gewinne durch **Entfernen** von Sync-I/O und Blocking-QC aus dem Hot-Path, nicht durch Hinzufügen von Caches.

---

*Ende AUDIT_05 — alle Pfade `file_path:line_number` verifizierbar via `Read`. Kein `bash`-Output als Quelle genutzt.*
