# 🛡️ HuMoCo Audit Report: Sabotage, Zensur, Gaslighting & Eclipse-Angriffe

> **Datum:** 2026-09-15  
> **Auditor / Modell:** `opencode/muse-spark-1.2-contributor-free` (via KI-Model-Router)  
> **Prompt-ID:** 08 (`08_sabotage_zensur_und_eclipse_audit.md`)  
> **Geprüfter Scope:** `crates/humoco-sim-core` und `crates/humoco-node` gegen Spec 05, 06, 07, 11, 15, 17  
> **Status:** Funde erfasst, warten auf Operator-Freigabe vor Patch-Umsetzung.

---

## 📊 Executive Summary

| # | Vektor | Severity | Status Quo im Code |
|---|---|---|---|
| **1** | Eclipse auf PoS / Merchant | **CRITICAL / HIGH** | PEX verteilt unfertige Sybil-Knoten (`is_immature` nicht gefiltert). N=1 Solo-Cert kann von Rogue-Gateway missbraucht werden. |
| **2** | Gaslighting & Cross-Network Replay | **CRITICAL / HIGH** | Domain-Mismatch: Attestations-Verifikation in `routes.rs` nutzt feste Mainnet-Konstanten statt `network_id`. Status-Quorum fehlt 24h-Hysterese. |
| **3** | WoT-Infiltration & Endorsement Bomb | **HIGH / MEDIUM** | Argon2d Fast-Path `nonce==0` in `identity.rs` ungeschützt. PEX-Discovery leakt Nodes in der 24h-Inkubation. |
| **4** | Grey-Hole / Selective Dropping | **HIGH / MEDIUM** | 60s Debounce schützt gezielte Latenz-Saboteure. Rank 21 wird nie befragt, solange Top-20 nur verzögern statt auszufallen. |

---

## 🔍 Detaillierte Befunde & Analyse

### FINDING 1: Domain-Separation Mismatch (Mainnet vs. Testnet) in Quorum-Verifikation [CRITICAL]
* **Ort:** `crates/humoco-node/src/api/routes.rs:995-1008` und `1257-1270`
* **Problem:** Bei der Erzeugung von lokalen Attestationen wird das konfigurierte `state.network_id` verwendet (`domain_approve_final(network_id)`). Bei der Verifikation der eingehenden Signaturen von Remote-Shard-Knoten in `assemble_quorum_certificate` und `assemble_status_quorum_certificate` wird jedoch hardcodiert `DOMAIN_APPROVE_FINAL` bzw. `DOMAIN_APPROVE_PROV` verwendet. Diese Konstanten zeigen statisch immer auf `MAINNET`. Im Testnet schlägt daher die Verifikation fehl bzw. Signaturen zwischen Netzen sind nicht strikt getrennt.
* **Empfohlener Patch:** Verwende in beiden Prüfblöcken `humoco_sim_core::crypto::domain_approve_final(state.network_id)` bzw. `domain_approve_prov(state.network_id)`.

### FINDING 2: Status-Quorum `FINAL` ohne 24h-Hysterese-Check [HIGH]
* **Ort:** `crates/humoco-node/src/api/routes.rs:1134` & `1152-1159`
* **Problem:** In `assemble_status_quorum_certificate` wird `target_status = 1` (`FINAL`) vergeben, sobald $\ge 14$ Signaturen von 20 Nodes vorliegen, **ohne** wie im Schreibpfad (`routes.rs:883`) zu verifizieren, ob das Netzwerk die 24h-Stabilitätsmauer durchschritten hat (`peer_mgr.is_network_stable_ge20_for_24h(now_ms)`). Zudem wird dort noch die veraltete Funktion `create_attestation` (ohne NetworkId) aufgerufen.
* **Empfohlener Patch:** Hysterese-Bedingung `peer_mgr.is_network_stable_ge20_for_24h(now_ms)` einbinden und `create_attestation_for_network(..., state.network_id)` nutzen.

### FINDING 3: PEX Discovery leakt unfertige (`is_immature()`) Sybil-Knoten [HIGH]
* **Ort:** `crates/humoco-node/src/network/manager.rs:1072-1089` (`get_pex_peers`)
* **Problem:** Während `active_hrw_nodes()` und `active_nodes_count()` neu gelernte Knoten innerhalb ihrer 24-stündigen Inkubationszeit (`is_immature()`) korrekt ignorieren, fehlt dieser Filter in `get_pex_peers()`. Ein Angreifer kann viele frische Identitäten announcen, die sofort über den PEX-Endpunkt an Clients und Wallets ausgeliefert werden.
* **Empfohlener Patch:** `if kinfo.is_immature() { continue; }` in `get_pex_peers()` ergänzen.

### FINDING 4: Rank-21 Latenz-Falle bei Grey-Hole Sabotage [HIGH]
* **Ort:** `crates/humoco-node/src/api/routes.rs:897-904`
* **Problem:** Beim Quorum-Sammeln wird die Kandidatenliste starr auf die Top 20 gekürzt (`candidate_nodes.truncate(20)`). Wenn ein böswilliger Knoten auf Rang 1..20 Pakete gezielt um 800–1000 ms verzögert, blockiert er den Hot-Path. Ein ehrlicher Knoten auf Rang 21 wird nie befragt, solange der Verzögerer nicht komplett suspendiert ist.
* **Empfohlener Patch:** Nach einem kurzen Schwellenwert (oder als Hedged Request) Knoten von Rang 21..23 hinzuziehen, sobald 14 Signaturen da sind per Fast-Exit (`join_set.abort_all()`) sofort abschließen.

### FINDING 5: Argon2d Fast-Path `nonce==0` in Produktion [HIGH]
* **Ort:** `crates/humoco-node/src/identity.rs:35-38`
* **Problem:** `compute_hrw_routing_id` besitzt einen Fast-Path `if nonce == 0 && t0 == 0 { return *blake3::hash(node_pubkey).as_bytes(); }`. Dadurch entfällt der Memory-Hard-Aufwand (64 MiB Argon2d) komplett, wenn ein Knoten mit Nonce 0 generiert wird.
* **Empfohlener Patch:** Einschränken auf Testumgebungen (`#[cfg(test)]`) oder eine Validierungsfunktion `verify_hrw_pow()`, die im Produktivbetrieb nur gültige Nonces mit Zeitstempel akzeptiert.
