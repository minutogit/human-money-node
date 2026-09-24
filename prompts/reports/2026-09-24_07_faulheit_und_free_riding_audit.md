# 🦥 Audit-Bericht 07: Faulheit, Free-Riding & Asymmetrisches Leeching (Spec 03, 09, 13, 17)

**Datum:** 2026-09-24  
**Modell:** `opencode/muse-spark-1.2-contributor-free` (via Model-Router)  
**Status:** `🟢 Analysiert / Härtungen identifiziert`

---

## 🎯 Zusammenfassung der 5 Prüfdimensionen

### 1. 😴 The Silent Signer (Validation Free-Rider)
* **Befund:** Ein Knoten kassiert eigene Merchant-Locks (VIP Ingress), kann aber `LockVerifyRequest` von Fremd-Shards ignorieren (spart Signatur-CPU).
* **Ursache:** `TierController` in `ingress/tier.rs` ist von `PeerManager` entkoppelt. Es prüft VIP-Quoten/PoW, nicht aber `is_hrw_eligible()` oder die Shard-Validierungsrate.
* **Lösung / Härtung H-01:** `TierController::evaluate_and_charge` bindet Ingress-Guthaben an die lokale Shard-Validierungsrate (>=80% nach Spec 17).

### 2. 🕳️ The Forgetful Storage Leech (Storage Leech)
* **Befund:** Ein Knoten speichert nur eigene Locks und löscht Fremd-Locks sofort nach Sync.
* **Ursache:** Bei `StatusQuery` gilt eine leere Antwort ("Not Found") aktuell nicht als Fehler, solange sie pünktlich eintrifft.
* **Lösung / Härtung H-02:** Einführung eines Proof-of-Custody-Stichproben-Audits: Gateways fordern alle 60s zufällige `parent_lock`-Verifikationen an. Bei Mismatch/Missing erfolgt Tit-for-Tat Malus (`record_outbound_failure_damped`).

### 3. 🐌 Faked Latencies & Fast-Drop Excuses
* **Befund:** Künstliche Latenzen (950ms) blockieren Concurrency-Slots, ohne als Timeout gewertet zu werden. 60s-Debounce bei `record_failure` dämpft Strafen übermäßig.
* **Lösung / Härtung H-03 & H-06:** Einführung eines EWMA-Latenz-Trackers (`ewma_latency_ms`). Antworten > 300ms werden als Performance-Degradation gewertet. `FAILURE_DEBOUNCE_SECS` für RPC auf 10s verkürzen.

### 4. 📉 Empty Certificates & Bitmap Tricks
* **Befund:** `verify_quorum_certificate` prüft `bitmap_count == signatures.len()`, aber bindet Bits nicht strikt an die deterministische HRW-Reihenfolge.
* **Lösung / Härtung H-04:** Strikte Bitmap-Positionierung (`hrw_rank_nodes`) und optionale Validierung via `verify_order_statistics_quorum`.

### 5. 💡 Konkrete Härtungsmaßnahmen
* **H-01:** Reziproker Ingress-Credit (Validierungsrate >= 80% für Ingress-Rechte).
* **H-02:** Proof-of-Custody Storage-Audit via zufällige Parent-Lock-Challenges.
* **H-03:** Latenz-SLA (<300ms) mit EWMA-Tracking auf Peer-Ebene.
* **H-04:** Strikte Zuordnung von Bitmap-Bits zu HRW-Rängen im Quorum-Zertifikat.
* **H-05:** Digest-Challenge & Rate-Limiting für `ActiveSync`.
