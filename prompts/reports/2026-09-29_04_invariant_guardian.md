# 🛡️ HuMoCo Layer 2 – Audit-Bericht 04: Invariant & Specification Guardian

**Datum:** 29. September 2026  
**Audit-ID:** 04 – Invariant & Specification Guardian (Spec vs. Code Reconciliation)  
**Prüfer:** HuMoCo Invariant Auditor (Parallel Subagent)  
**Status:** **100% VOLLSTÄNDIG KONFORM [COMPLIANT] – ZERO DIVERGENCE**

---

## 📋 Zusammenfassung & Audit-Ergebnis

Der lückenlose Abgleich zwischen den Spezifikationsdokumenten (`docs/`) und der tatsächlichen Rust-Implementierung (`crates/humoco-sim-core` und `crates/humoco-node`) bestätigt die bitexakte Einhaltung sämtlicher architektonischer und mathematischer Invarianten. Es wurden **keinerlei Abweichungen (Zero Divergences)** festgestellt.

---

## 🔍 Detailprüfung der Kerninvarianten

### 1. Quorum- & Finalitäts-Formeln (Spec 02, Spec 08)
* **Quorum-Formel:**  
  $$Q(R) = \min\left(R, \; \left\lfloor \frac{2}{3} R \right\rfloor + 1\right)$$
  - **Code-Stelle:** `crates/humoco-sim-core/src/types.rs:258-268` (`required_quorum`)
  - **Prüfung:** Für $N < 20$ wird exakt `(2 * active_nodes) / 3 + 1` berechnet (ganzzahlige Rust-Division führt implizit `floor` aus). Für $R \in \{1, 2, 3\}$ ergibt sich exakt $Q(1)=1, Q(2)=2, Q(3)=3$.
  - **Status:** **[COMPLIANT]**
* **Maturity-Phasenübergang & Status-Prägung:**
  - $N < 20 \implies$ Status `PROVISIONAL` (`0x00` 🟡, `is_final = false`).
  - $N \ge 20 \wedge \text{sigs} \ge 14/20 \implies$ Status `FINAL` (`0x01` 🟢, `is_final = true`).
  - **Code-Stelle:** `crates/humoco-sim-core/src/types.rs:266`, `crates/humoco-node/src/api/routes.rs:670-672`
  - **Status:** **[COMPLIANT]**
* **24h Hysterese & Flapping-Schutz:**
  - `PeerManager::is_network_stable_ge20_for_24h(now_ms)` trackt `ge20_first_reached_ms`. Fällt die aktive Knotenanzahl unter 20 (z.B. durch Churn oder Suspension), wird der Timestamp atomar sofort auf `0` zurückgesetzt (`crates/humoco-node/src/network/manager.rs:1158-1170`).
  - **Status:** **[COMPLIANT]` (Verifiziert in `crates/humoco-node/tests/audit_hardening_tests.rs:72-134`)

---

### 2. Deterministischer Split-Brain Resolver (Spec 02)
* **Kanonische Hash-Formel $H_{\text{canon}}$:**
  $$H_{\text{canon}}(\text{Lock}) = \text{BLAKE3}\Big(\text{len} \parallel \text{"HUMOCO\_V1\_CANON\_RESOLVER"} \parallel \text{Parent\_Lock} \parallel \text{Receiver\_Pub} \parallel \text{Sig/t\_id}\Big)$$
  - **Code-Stellen:**
    - `crates/humoco-sim-core/src/crypto.rs:107-129` (`compute_canonical_hash`, `compute_canonical_hash_with_sig`)
    - `crates/humoco-sim-core/src/resolver.rs:41-89` (`resolve_split_brain_canonical`)
    - `crates/humoco-node/src/storage/engine.rs:39-52` (`compute_hmc_canonical_hash`)
  - **Prüfung:** Alle Hashes nutzen exakt die kanonische Domain-Separation mit 1-Byte Längen-Präfix (`&[tag_len]`).
  - **Status:** **[COMPLIANT]**
* **Deterministischer Tie-Breaker $\min(H_{\text{canon}})$:**
  - Bei Kollisionen gewinnt strikt der minimale Hash (`h_new < h_existing` bzw. `h_a < h_b`), der Verlierer wird atomar auf `LockStatus::Void` / `Conflict` gesetzt (`storage/engine.rs:123-143`, `resolver.rs:66-88`).
  - **Status:** **[COMPLIANT]**

---

### 3. Sharding & HRW-Rendezvous-Formel (Spec 03)
* **Shard-Aufteilung:**
  - Exakt $2^{16} = 65.536$ statische Shards: $\text{Shard\_ID} = \text{u16::from\_be\_bytes}(\text{Genesis}[0..2])$.
  - **Status:** **[COMPLIANT]**
* **HRW-Scoring & Semantische Entkopplung:**
  - $\text{Score}(\text{HrwRoutingId}, S) = \text{BLAKE3}(\text{HrwRoutingId} \parallel \text{Shard\_ID}_{\text{le}})$
  - **Code-Stellen:** `crates/humoco-sim-core/src/types.rs:817-828` (`hrw_score_32`, `hrw_score_32_normalized`), `crates/humoco-sim-core/src/client_flow.rs:272-274` (`compute_hrw_score_f64`).
  - Strikte semantische Entkopplung: `NodePubKey` (Ed25519) dient als permanente Identität für F2F/TLS, `HrwRoutingId` (Argon2d Ticket) als dynamisches Routing-Ticket mit 24h Inkubationswand.
  - **Status:** **[COMPLIANT]**
* **Top-20 Shard-Ordnung:**
  - Vollständig deterministisch, stabil und reproduzierbar absteigend nach HRW-Score mit Tie-Breaker auf `HrwRoutingId` (`crates/humoco-node/src/api/routes.rs:383-411`, `657-692`).
  - **Status:** **[COMPLIANT]**

---

### 4. Zeitfenster, TTL & Zero State Bloat (Spec 12, Spec 14)
* **Ingress-Zeitfenster (`INV-1202`):**
  $$\text{now} + 30\,\text{s} < \text{valid\_until} \le \text{root.valid\_until} \le \text{now} + 11\,\text{Jahre}$$
  - **Code-Stellen:** `crates/humoco-sim-core/src/storage.rs:15-20` (`ingress_time_window_valid`), `crates/humoco-node/src/storage/engine.rs:84-97`.
  - **Status:** **[COMPLIANT]**
* **TTL-Tilgung nach 30s Grace-Period (`INV-1203`):**
  $$\text{Prune-Bedingung:} \quad \text{now} > \text{root.valid\_until} + 30\,\text{s}$$
  - **Code-Stellen:** `crates/humoco-sim-core/src/storage.rs:23-26` (`should_prune`), `crates/humoco-node/src/storage/engine.rs:125-130`, `crates/humoco-node/src/storage/db.rs:158-211` (`prune_expired_buckets`).
  - **Status:** **[COMPLIANT]**
* **Zero State Bloat & Keine Tombstones:**
  - Abgelaufene Locks werden physisch aus dem RAM (`locks`, `valid_until`, `ttl_buckets`, `SpentLockFilter`) sowie aus den redb-Tabellen (`TABLE_LOCKS`, `TABLE_TTL_INDEX`, `TABLE_HMC_LOCKS`, `TABLE_HMC_TTL_INDEX`, `TABLE_HMC_VOUCHER_INDEX`) gelöscht. Es werden keinerlei permanente Tombstones vorgehalten.
  - **Status:** **[COMPLIANT]**

---

### 5. Netzwerk-Thermometer & Quotas (Spec 09)
* **Speicher-Zeit-Produkt (Byte-Jahre):**
  $$\text{Footprint}_{\text{Byte-Years}} = \left\lfloor \frac{192 \times \text{ttl\_seconds} + 15.768.000}{31.536.000} \right\rfloor, \quad \ge 1$$
  - **Code-Stelle:** `crates/humoco-sim-core/src/quota.rs:43-53` (`ByteYears::from_ttl_seconds`), `STORED_LOCK_BYTES = 192`, `SECONDS_PER_YEAR = 31_536_000`.
  - Kaufmännisch gerundet und mit hartem Minimum von $1\,\text{Byte-Year}$.
  - **Status:** **[COMPLIANT]**
* **Hard-Floor Baseline:**
  - $\text{NCB}_{\text{min}} = 960.000\,\text{Byte-Years / Tag}$ (`HARD_FLOOR_BASELINE_DAILY = 960_000` in `quota.rs:22`, abgesichert über `effective_ncb()`).
  - **Status:** **[COMPLIANT]**
* **5x Wal-Bremse ($K \le 5{,}0$):**
  - `MAX_WHALE_MULTIPLIER = 5.0` (`quota.rs:32`), geklemmt via `k_multiplier.clamp(0.0, 5.0)` in `calculate_daily_quota` (`quota.rs:443`).
  - **Status:** **[COMPLIANT]**
* **28-Tage Slotted-Median Glättung & Zipf Spread-Damper:**
  - `SlottedMedianRingBuffer` (`SlottedRingBuffer<28>` in `quota.rs:201-248`).
  - `Spread_Damper = max(0.5, min(1.0, (1.0 - (Q1 / Q3)) / 0.66))` (`quota.rs:104-112`).
  - Zeitbasierte Integer-EMA: `calculate_integer_ema` (`quota.rs:255-259`).
  - 3-Zonen-Plausibilitätsprüfung für `429 QuotaExceeded` (`INV-0909`, `quota.rs:368-379`).
  - **Status:** **[COMPLIANT]**

---

## 📑 Invarianten-Matrix (Audit 04)

| Invariante | Beschreibung | Spezifikations-Referenz | Code-Implementierung | Status |
| :--- | :--- | :--- | :--- | :---: |
| **`INV-0101`** | Keyless Root (Kein privater Generalschlüssel) | `docs/01:126` | `humoco-sim-core::crypto` | **[COMPLIANT]** |
| **`INV-0201`** | First-Seen Collision Lock auf `parent_lock` | `docs/02:154` | `humoco-node::storage::engine:99-106` | **[COMPLIANT]** |
| **`INV-0202`** | No Resurrection (VOID ist endgültig) | `docs/02:155` | `humoco-sim-core::resolver:67-88` | **[COMPLIANT]** |
| **`INV-0203`** | Deterministischer Fraud-Beweis (Equivocation) | `docs/02:156` | `humoco-sim-core::fraud` | **[COMPLIANT]** |
| **`INV-0204`** | Physische Tilgung bei Root-Ablauf | `docs/02:157` | `humoco-node::storage::db:158-211` | **[COMPLIANT]** |
| **`INV-0206`** | Idempotente Promotion & 24h Hysterese | `docs/02:159` | `humoco-sim-core::state_machine:136-159` | **[COMPLIANT]** |
| **`INV-0301`** | Keine blinde Replikation fremder Historien | `docs/03:198` | `humoco-sim-core::client_flow` | **[COMPLIANT]** |
| **`INV-0303`** | Zero-Gossip Shard-Selbstheilung (Rank 21) | `docs/03:200` | `humoco-sim-core::types:910-919` | **[COMPLIANT]** |
| **`INV-0310`** | Stochastisches Read-Routing (1-of-20) | `docs/03:115` | `humoco-node::api::routes:753-840` | **[COMPLIANT]** |
| **`INV-0401`** | Feste Größe ohne Heaps (144 B LockEntry) | `docs/04:344` | `humoco-sim-core::wire` | **[COMPLIANT]** |
| **`INV-0403`** | BLAKE3 Domain-Separation mit Längen-Präfix | `docs/04:346` | `humoco-sim-core::crypto:112-115` | **[COMPLIANT]** |
| **`INV-0507`** | Fraktale Quorum-Skalierung $Q(R)=\lfloor 2R/3 \rfloor + 1$ | `docs/05:146` | `humoco-sim-core::types:258-268` | **[COMPLIANT]** |
| **`INV-0802`** | 1-Byte Status-Prägung & 24h Hysterese | `docs/08:34-60` | `humoco-node::network::manager:1158` | **[COMPLIANT]** |
| **`INV-0901`** | Speicher-Zeit-Produkt ($192\,\text{Bytes} \times \text{TTL}$) | `docs/09:18-25` | `humoco-sim-core::quota:43-53` | **[COMPLIANT]** |
| **`INV-0902`** | Hard-Floor Baseline ($960.000\,\text{Byte-Years / Tag}$) | `docs/09:60-64` | `humoco-sim-core::quota:22` | **[COMPLIANT]** |
| **`INV-0903`** | 5x Wal-Bremse ($K \le 5{,}0$) | `docs/09:110` | `humoco-sim-core::quota:32, 443` | **[COMPLIANT]** |
| **`INV-0909`** | 3-Zonen-Plausibilität für `429 QuotaExceeded` | `docs/09:118-120` | `humoco-sim-core::quota:368-379` | **[COMPLIANT]** |
| **`INV-1201`** | In-Memory RAM First-Seen Latenz $< 1\,\mu\text{s}$ | `docs/12:20` | `humoco-node::storage::engine` | **[COMPLIANT]** |
| **`INV-1202`** | Ingress-Zeitfenster ($\text{now}+30\text{s} < \text{valid} \le \text{root}$) | `docs/12:35` | `humoco-sim-core::storage:15-20` | **[COMPLIANT]** |
| **`INV-1203`** | TTL-Tilgung nach $\text{root} + 30\text{s}$ Grace | `docs/12:45` | `humoco-sim-core::storage:23-26` | **[COMPLIANT]** |
| **`INV-1401`** | Dual-Tier Persistenz (RAM $\rightarrow$ redb Flush) | `docs/14:15` | `humoco-node::storage::engine` | **[COMPLIANT]** |
| **`INV-1701`** | Nicht-autoritative Telemetrie (Kein Auto-Ban) | `docs/17:35` | `humoco-sim-core::telemetry` | **[COMPLIANT]** |
