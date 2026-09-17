# ⚖️ HuMoCo Audit Report: Invarianten- & Spezifikations-Wächter

> **Datum:** 2026-09-15  
> **Auditor / Modell:** `opencode/muse-spark-1.2-contributor-free` (via KI-Model-Router)  
> **Prompt-ID:** 04 (`04_invarianten_und_spezifikations_waechter.md`)  
> **Scope:** `docs/00-20`, `crates/humoco-sim-core/src/*`, `crates/humoco-node/src/**/*`.

---

### 1. Quorum & Finality Formeln (Spec 02, 08)

| Invariante | Spec-Soll | Code-Ist | Status |
|---|---|---|---|
| **INV-0202** Quorum | $Q(R) = \min(R, \lfloor \frac{2R}{3} \rfloor + 1)$ | `types.rs:244`: `(2 * active_nodes) / 3 + 1` | **[COMPLIANT]** |
| **INV-0203** Status | $N < 20 \Rightarrow \text{PROVISIONAL}$, $N \ge 20 \land \ge 14/20 \Rightarrow \text{FINAL}$ | `types.rs:244-258`, `state_machine.rs:70-126` | **[COMPLIANT]** |
| **INV-0802** Hysterese | 24h Stabilität für FINAL | Gateway `routes.rs:882`: geprüft; Shard `transport.rs:264`: ungeprüft | **[DIVERGENCE]** (P0) |
| **INV-0206** Flapping-Schutz | Drop unter 20 setzt Hysterese-Timer zurück | `manager.rs:1036`: `ge20_first_reached_ms.store(0)` | **[COMPLIANT]** |

- **Divergenz D1.1 (P0 HOCH): Shard signiert FINAL ohne Hysterese-Check:**
  - `crates/humoco-node/src/network/transport.rs:264`: Shard prüft nur lokale Kardinalität `required_quorum(local_active_count).1`, nicht `is_network_stable_ge20_for_24h(now_ms)`.

---

### 2. Deterministischer Resolver (Spec 02)

| Invariante | Spec-Soll | Code-Ist | Status |
|---|---|---|---|
| **INV-0204** $H_{\text{canon}}$ | $\text{BLAKE3}(\text{len} \parallel \text{"HUMOCO_V1_CANON_RESOLVER"} \parallel \dots)$ | `crypto.rs:60`, `resolver.rs:23`, `engine.rs:34` | **[COMPLIANT]** |
| **INV-0205** $\min(H_{\text{canon}})$ | Minimaler Hash gewinnt strikt, Verlierer VOID | `resolver.rs:58`, `engine.rs:120` | **[COMPLIANT]** |
| **INV-0207** Domain Length-Prefix | Tag mit Längenpräfix | `crypto.rs:70`, `engine.rs:43` | **[COMPLIANT]** |

---

### 3. Sharding & HRW Rendezvous (Spec 03)

| Invariante | Spec-Soll | Code-Ist | Status |
|---|---|---|---|
| **INV-0301** Shard ID | $2^{16}=65536$ Buckets, $\text{BE}(parent[0..1])$ | `types.rs:432`, `transport.rs:262`, `routes.rs:490` | **[COMPLIANT]** |
| **INV-0302** HRW Score | $\text{Score} = \text{BLAKE3}(HrwRoutingId \parallel Shard\_ID)$ | `types.rs:696` in `sim-core` | **[COMPLIANT]** |
| **INV-0701 / INV-0703** Shard Ticket | $HrwRoutingId = \text{Argon2d}(\dots)$, 24h Incubation Wall | Gateway nutzt fälschlich `NodeId` statt `HrwRoutingId` | **[DIVERGENCE]** (P0) |

- **Divergenz D3.1 (P0 KRITISCH): Gateway scored `NodeId` statt `HrwRoutingId`:**
  - `crates/humoco-node/src/api/routes.rs:869,898,1044,1118`: Gateway holt `active_known_nodes` (`NodeId`) statt `active_hrw_nodes` (`HrwRoutingId`). Dadurch greift das Argon2d Shard-Ticket nicht für das HRW-Routing der Gateways.
  - Verwendung von `partial_cmp().unwrap_or(Equal)` statt `total_cmp`.

---

### 4. Time Windows, TTL & Zero State Bloat (Spec 12, 14)

| Invariante | Spec-Soll | Code-Ist | Status |
|---|---|---|---|
| **INV-1202** Ingress | $now + 30s < valid\_until \le root.valid\_until$ | `storage.rs:7`, `engine.rs:88` | **[COMPLIANT]** |
| **INV-1203** Pruning | $now > root.valid\_until + 30s$ | `storage.rs:14` | **[COMPLIANT]** |
| **INV-1204** Zero State Bloat | Physikalisch purgen, keine permanenten Tombstones | `storage.rs:114`, `db.rs:156` | **[COMPLIANT]** |
| **INV-1207** Zeitbasis | `P2pClock` statt unsanitized `SystemTime` | `routes.rs:286`, `manager.rs:1027` | **[COMPLIANT]** Hot-Path |

- **Divergenz D4.1 (P1 HOCH):** In `docs/12_pos_checkout_pfad_und_kassen_latenz.md:17` zeigt das Mermaid-Diagramm versehentlich `now - 30s` statt `now + 30s`.

---

### 5. Netzwerk-Thermometer & Quotas (Spec 09)

| Invariante | Spec-Soll | Code-Ist | Status |
|---|---|---|---|
| **INV-0901** Byte-Years | $(192 \cdot ttl\_sec) / 31_536_000$, kaufmännisch gerundet, min 1 | `quota.rs:42` | **[COMPLIANT]** |
| **INV-0902** Hard-Floor | $960_000$ BJ/Tag ($40k/h$) | `quota.rs:18,364`, `daemon.rs:306` | **[COMPLIANT]** |
| **INV-0905** Whale-Brake | $K \le 5.0$ | `quota.rs:28,378`, `tier.rs:173` | **[COMPLIANT]** |
| **INV-0903** 28-Tage MA | Slotted-Median / Moving Average 28 Tage | `quota.rs:113` | **[COMPLIANT]** |
| **INV-0904** Hourly Ring | 24h Integral | `quota.rs:191` | **[COMPLIANT]** |

---

### Zusammenfassung & Priorisierte Patches

| Priorität | Datei:Line | Fix |
|---|---|---|
| **P0 KRITISCH** | `routes.rs:869-1153` | `active_known_nodes` → `active_hrw_nodes` + `HrwRoutingId` scoring, `partial_cmp` → `total_cmp` |
| **P0 HOCH** | `transport.rs:264` | Hysterese-Check `&& is_network_stable_ge20_for_24h(now_ms)` in Shard-Verifikation nachrüsten |
| **P1 HOCH** | `docs/12:17` | Mermaid Diagramm `now - 30s` → `now + 30s` |
| **P1 MEDIUM** | `storage/engine.rs:34` | SSOT für kanonischen Hash |
| **P1 MEDIUM** | `db.rs:476` | Default TTL im Fallback vereinheitlichen |
