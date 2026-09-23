# 🧹 Audit-Report 18: Legacy Code, Prototype Relics & Architectural Drift

> **Datum:** 2026-09-23  
> **Modell:** `opencode/muse-spark-1.2-contributor-free`  
> **Doktrin:** *"Subtraction before Construction – If a codepath does not serve the binding specifications (docs/00–20), it is tech debt and must be purged."*

---

## 📊 0. Executive Summary – Identifizierte Relikte (priorisiert)

| Prio | Filter | `file:line` | Relikt | Superseded durch | Risiko wenn behalten |
|------|--------|-------------|--------|------------------|----------------------|
| **P1** | 1+3 | `crates/humoco-sim-core/src/wire.rs:103` `MsgType::GossipAnnounce=0x0203` | Dead Wire-Typ für **Lock-Gossip** | **Spec 03** Digest-First Pull + **Spec 06** Shard-Direct + `AGENTS.md:125` *“Locks are NEVER gossiped”* | OOM-Amplification, permanente Gossip-Storm-Falle, Widerspruch zu 2-Stream-Gossip (nur Heartbeat + Equivocation) |
| **P1** | 2 | `crates/humoco-node/src/api/routes.rs:133-628` `submit_lock` dual-stack + `crates/humoco-node/src/api/dto.rs:6` `LockSubmitRequest` | **Dual Execution Path**: Legacy `LockSubmitRequest` (hex `parent_lock/receiver_pub/nonce`) vs. **HMC Native Flow** `L2LockRequest/L2ChainLockRequest` | Spec 06 Dumb Server / Spec 02 Origin-Lock-Mandat, `AGENTS.md Regel 10` (Origin bestimmt TTL/ByteYears) | Zwei divergente Validierungs-Äste, Gateway kann `root_valid_until` fälschen, doppelte Deserialisierung, Tests faken Produktion |
| **P1** | 3 | `crates/humoco-sim-core/src/sim/network.rs:15,17` `SimMessage::GossipLock/GossipReceipt` + `crates/humoco-sim-core/src/sim/node.rs:332-418` Epidemic Lock-Gossip | **Ghost Simulation** widerspricht Produktion | Spec 11: nur Hourly Heartbeat gossipt | Sim beweist falsche Invarianten, verdeckt Real-Latency |
| **P1** | 3 | `crates/humoco-node/src/network/manager.rs:26-74,215,948-965` `SeenGossipCache` + `transport.rs:129,143,155` | **Ghost Channel**: 10k Ring-Buffer für nie gesendete Locks | Spec 03 eliminiert Lock-Gossip vollständig | 320 KiB/Node tot, `std::sync::Mutex` blockiert Tokio Worker (Audit 03: D1) |
| **P2** | 1 | `wire.rs:92-94` `MergeLoserBroadcast/Ack` | Dead Split-Brain Notifier | `resolver.rs:min(H_canon)` deterministisch, Spec 02 | Toter Codepfad, DefaultHandler mappt ohne Sender |
| **P2** | 1 | `wire.rs:97` `ActiveSyncChunk=0x0108` + `network/framing.rs:88` | Dead Stream-Fragmentierung | Spec 03 Single-Frame `ActiveSyncDone` mit `SyncPayload` | Whitelist-DoS (4 MiB), nirgends gesendet |
| **P2** | 2 | `network/transport.rs:232-390` 3-fach Fallback `LockWirePayload::Sim` → `LockWirePayload::Hmc` → `bincode<(LockRecord,u64)>` | Legacy Fallback-Branch | Spec 06 HMC | Protokoll-Negotiation-Verwirrung |
| **P2** | 2 | `routes.rs:110-122` `Router::new().route("/lock"...).route("/v1/lock"...)` + `/status`+`/v1/status`+`/peers` | Duplicate REST-Endpoints | Spec 13 `POST /v1/lock` kanonisch | Pflege-Drift, Swagger-Drift |
| **P3** | 4 | `docs/10_p2p_wire_format...:267,91` `TombstoneBroadcast` in 0-RTT Whitelist | **Doku-Drift**: nicht in `wire.rs` definiert | Code ist SSOT – Spec 12 `Zero State Bloat` braucht kein Tombstone | Evaluatoren whitelisten Nicht-Existentes |
| **P3** | 4 | `docs/02:111`, `docs/10:325-397` `SignedGossipReceipt` p=0,02% | **Doku-Drift**: suggeriert Lock-Gossip | `AGENTS.md:128` *Strict 2-Stream Mesh Gossip* (nur Heartbeat + EquivocationProof) | Bandbreitenrechnung falsch, 3,8KB/s Phantom |
| **P3** | 4 | `docs/10:20-75` WireHeader vs `wire.rs:11-22` | Drift: `reserved: u32` vs `crypto_suite/min_compat_ver/reserved` | Code hat Suite-Migration (Hybrid PQC) | Binär-Inkompatibilität |
| **P3** | 4 | `docs/15:121` “alle 10s QUIC PING = ShardMapPing” | Drift: verwechselt Keepalive mit **Hourly Presence** `Spec 11: 1 HB/h, TTL=16, Dunbar k=min(d,ceil(sqrt(d))+1)` | Spec 11 | Falsche Lastannahme, Death-Spiral |

---

### 1. 🔍 Dead Wire-Typen (`wire.rs` & `transport.rs`)

**Inspektion `wire.rs:81-104`:**
```rust
ShardMapPing/Pong // ✅ kept - 0-RTT Topologie, docs/15:88
LockVerifyRequest/Response // ✅ Shard-Direct RPC Spec 03/06
EquivocationProof/Ack // ✅ Spec 10
ShardDigestRequest/Response + ActiveSyncRequest/Done // ✅ Spec 03
Heartbeat/HeartbeatAck // ✅ Spec 11
```

**Tot – Nachweis via `rg`:**
```text
GossipAnnounce  -> nur Definition + Default-Handler Fallback, 0x Sender/Receiver
MergeLoser*     -> nur DefaultHandler Zeile 65, nie transport::send*
ActiveSyncChunk -> nur framing::max_payload_len + Test Zeile 258, nie in NodeRequestHandler
TombstoneBroadcast -> 0 Definition, aber docs/10:267 whitelisted
```

**Warum Relikt:** Phase 0/1 Prototyp verteilte Locks via `GossipAnnounce`/`GossipLock` epidemisch. Seit **Spec 03 Digest-First Pull** + **Spec 06 Shard-Direct RPC** ist Epidemic Gossip für Locks *vollständig eliminiert* (`AGENTS.md:125` 100% Shard-Direct, 0% Gossip). `MergeLoserBroadcast` war Pre-`min(H_canon)`-Benachrichtigung, heute resolvereinheitlich. `ActiveSyncChunk` war Streaming-Fragmentierung vor Bounded-Channel-Purge.

**Konkreter Purge-Diff:**
```diff
// crates/humoco-sim-core/src/wire.rs:81
 pub enum MsgType {
     StatusQuery = 0x0001,
     StatusResponse = 0x0002,
     LatencyProbe = 0x0003,
     LatencyProbeAck = 0x0004,
     ShardMapPing = 0x0005,
     ShardMapPong = 0x0006,
     LockVerifyRequest = 0x0101,
     LockVerifyResponse = 0x0102,
-    MergeLoserBroadcast = 0x0103,
-    MergeLoserAck = 0x0104,
     EquivocationProof = 0x0105,
     EquivocationAck = 0x0106,
     ActiveSyncRequest = 0x0107,
-    ActiveSyncChunk = 0x0108,
     ActiveSyncDone = 0x0109,
     ShardDigestRequest = 0x010A,
     ShardDigestResponse = 0x010B,
     Heartbeat = 0x0201,
     HeartbeatAck = 0x0202,
-    GossipAnnounce = 0x0203,
 }

// crates/humoco-node/src/network/transport.rs:57
-                x if x == MsgType::MergeLoserBroadcast as u16 => MsgType::MergeLoserAck as u16,

// crates/humoco-node/src/network/framing.rs:87
 pub fn max_payload_len_for_msg_type(msg_type: u16) -> usize {
-    if msg_type == MsgType::ActiveSyncChunk as u16
-        || msg_type == MsgType::ActiveSyncRequest as u16
+    if msg_type == MsgType::ActiveSyncRequest as u16
         || msg_type == MsgType::ActiveSyncDone as u16
```
**INV-Sicherheit:** Entfernen verletzt kein `INV-1004/1009` (0-RTT Whitelist schrumpft um Totes), vereinfacht `parse_wire_header` und `max_payload_len`, reduziert Angriffsfläche. `INV-0202` Resolver bleibt unberührt (deterministisch ohne Notification).

---

### 2. 🔀 Dual Execution Paths (Prototype vs. Production HMC)

**Befund `routes.rs:133-145`:**
```rust
async fn submit_lock(... body_bytes: Bytes) {
    if let Ok(chain) = from_slice::<L2ChainLockRequest>(&body_bytes) { return submit_hmc_chain_lock(...).await; }
    if let Ok(hmc) = from_slice::<L2LockRequest>(&body_bytes) { return submit_hmc_lock(...).await; }
    // Otherwise try parsing as legacy/internal LockSubmitRequest  <-- RELIKT
    let payload: LockSubmitRequest = from_slice(&body_bytes)?; // 3. Tier, RamIndex, hex decode...
}
```
*Zusätzlich* `transport.rs:243-390`: drei Deserialisierungen (`LockWirePayload::Sim`, `::Hmc`, `(LockRecord,u64)`).

**Warum Relikt:** `LockSubmitRequest` (`dto.rs:6` mit `parent_lock/receiver_pub/nonce/valid_until/root_valid_until` als Hex) stammt aus Phase 0 Generic `LockPayload` vor HMC-Kopplung. Produktion ist **HMC Native Flow**: `L2LockEntry/L2Verdict` aus `human-money-core`, DTO-Adapter, strikter Collision-Check auf `parent_lock`. Legacy-Ast erlaubt:
- freien `root_valid_until` durch Gateway → bricht **Regel 10 Origin-Lock-Mandat** & ByteYears-Abrechnung,
- `is_bridge_lock/pqc_receiver/crypto_suite` Sunset-Logik doppelt (Zeile 167,187 vs HMC-Suite),
- doppelte JSON-Deserialisierung (Audit 05:39) → Hot-Path >5ms Gefahr.

**Superseded:** Spec 00 Pillar 1 (Blind Registry via HMC), Spec 06 Dumb Server Smart Client.

**Purge-Diff:**
```diff
// crates/humoco-node/src/api/routes.rs:110
-        .route("/lock", post(submit_lock))
         .route("/v1/lock", post(submit_hmc_lock)) // kanonisch, direkt
-        .route("/status", post(query_status))
         .route("/v1/status", post(query_status))
-        .route("/peers", get(get_peers))
         .route("/api/v1/network/peers", get(get_peers))

-async fn submit_lock(...) { /* 500 Zeilen Legacy */ }
+// gelöscht: submit_lock + LockSubmitRequest-Fallback, nur noch submit_hmc_lock/chain
 // dto.rs:6 struct LockSubmitRequest -> #[deprecated] oder in tests/sim_feature gated

// transport.rs:243
- LockWirePayload::Sim(...) => { ingres_lock... }
+ LockWirePayload::Hmc {..} => { ingress_hmc_lock... } // einziger Pfad
- // fallback bincode::<(LockRecord,u64)> branch löschen
```
**INV-Sicherheit:** Keine Verletzung von `INV-0302` (Shard-ID via `blake3(voucher_id)`) – HMC-Ast behält korrekt. `Idempotency 409` (`Rule 3`) bleibt in `ingress_hmc_lock` (`Verified/Conflict/UnknownVoucher`). System wird simpler: ein Netz-Pfad, ein Signatur-Verify (`verify_l2_lock_signature`), ein ByteYears-Pfad.

---

### 3. 👻 Ghost Background Tasks & Channels

**Befund `daemon.rs:152-440`:** 8 `tokio::spawn` – alle *außer* Lock-Gossip. **Gut:** Kein `broadcast_lock_via_gossip` mehr (früher `routes.rs:425` Fan-Out Shuffle). **Relikt dennoch:**

* `manager.rs:215` + `transport.rs:129` `SeenGossipCache (MAX 10_000)` wird nie befüllt im Hot-Path. `rg` zeigt nur Test-Aufrufe (`sim_03_*`). Im Uni-Stream Handler (`transport.rs:1046`) wird Heartbeat/Equiv nur auf `can_accept_gossip()` geprüft, nie auf `check_and_record_seen_gossip`. Cache ist toter RAM + `Mutex`.
* `sim/network.rs:15` + `sim/node.rs:341` **Sim-Epidemic** für Locks: `SimNode::handle_message(GossipLock)` mit `select_gossip_targets(k=min(d,ceil(sqrt(d))+1))` + TTL 16. Das ist **Exakt-Phantom** des in `AGENTS.md:125` verbotenen Mechanismus.

**Purge-Diff:**
```diff
// manager.rs:26-74
- pub struct SeenGossipCache { ... } // komplett löschen
- pub fn check_and_record_seen_gossip(...) // löschen, Tests auf PeerManager::is_immature umstellen

// manager.rs:215 + transport.rs:129
-    seen_gossip_locks: Arc<Mutex<SeenGossipCache>>,
+    // nur noch heartbeat_detector SlotDetector128 behalten

// sim/network.rs:15
 pub enum SimMessage {
     LockRequest(LockRecord),
     LockAttestation(Attestation),
-    GossipLock { lock: LockRecord, hops: u8 },
-    GossipReceipt { lock_id: Hash256, attestation: Attestation, hops: u8 },
     FraudProof(...),
     Heartbeat(...),
 }
// sim/node.rs:327
-            SimMessage::LockRequest(...) { ... gossip to k peers ... }
+            SimMessage::LockRequest(...) { ... nur noch sign_lock_attestation, pending queue, kein GossipLock fan-out ... }
-            SimMessage::GossipLock {..} => { ... } // löschen
-            SimMessage::GossipReceipt {..} => { ... } // löschen
```

**INV-Sicherheit:** `INV-1101` (Gossip R0>1) bleibt für **Heartbeats** erhalten – Lock-Gossip war nie Teil der Pillar-Def. Entfernen reduziert `STREAM_CONCURRENCY_LIMIT` Druck, beseitigt Scheduler-Jitter. Kein `INV-1501/1503` betroffen.

---

### 4. 📚 Doku-Drift & Comment-Desync

| Datei:Zeile | Drift | Korrektur |
|-------------|-------|-----------|
| `docs/10:267` + `docs/15:91` Whitelist `TombstoneBroadcast` | Nicht in `wire.rs` | Diff: `\| TombstoneBroadcast \| NO \| deprecated – purged, Zero State Bloat via TTL \|` oder Eintrag löschen. Code SSOT gewinnt. |
| `docs/10:20-75` WireHeader `reserved:u32` | Code `wire.rs:18-21` `crypto_suite:u8/min_compat_ver:u8/reserved:u16` | Doku auf Code anheben + Migration `Suite1→2` erwähnen. |
| `docs/02:111`, `docs/10:376` `SignedGossipReceipt p=0,02%` | Widerspricht `AGENTS.md:128` *2-Stream only* | Doku streichen: `Scaled receipt gossip replaced by First-Party Evidence + Digest Pull – see Spec 10 Pillar 1`. |
| `docs/15:121` “10s ShardMapPing” | Konflatiert Keepalive (QUIC PING Frame) mit Presence (1/h) | Trenne: `QUIC keepalive 15s idle LRU (Regel 7) ≠ Heartbeat 3600s TTL16` |
| `docs/11:199` `PeerPresenceEntry {missing_count,maturity_hours,_reserved}` vs `types.rs:304` `{hourly_bitmask,malus_score,maturity_hours,flags,backoff_level}` | Struct-Drift | Doku an `types.rs:304` angleichen (Tit-for-Tat `+2/-2` mit Circuit Breaker 40%) |

---

### 5. 🪓 Purge Action Plan – Reihenfolge

1. **Sofort (P1):** `GossipAnnounce` + `SeenGossipCache` + `SimMessage::GossipLock` löschen – größter Architekturwiderspruch, OOM-Schutz (Regel 9).
2. **Sofort (P1):** `LockSubmitRequest`-Fallback in `submit_lock` entfernen, Router auf `/v1/lock → submit_hmc_lock` vereinfachen – ein Pfad, ein Signatur-Check.
3. **Kurz (P2):** `MergeLoserBroadcast/Ack`, `ActiveSyncChunk`, `(LockRecord,u64)`-Fallback entfernen.
4. **Kurz (P3):** Doku-Prune (`Tombstone`, `SignedGossipReceipt`, WireHeader) + `docs/15` Keepalive-Klarstellung.
