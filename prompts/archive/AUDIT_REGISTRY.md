# 📋 HuMoCo Audit Registry & Priorisierungs-Matrix

> **Zweck:** Systematische Erfassung aller Audit-Durchläufe, Fundzahlen, Zeitstempel und dynamische Priorisierung für kontinuierliche Codebase-Härtung.  
> **Credo:** *"In decentralization there is no trust, only mathematical proofs."*

---

## 🎯 Priorisierungs-Formel

Um sicherzustellen, dass nie dieselben Audits wiederholt werden und vernachlässigte oder historisch fehleranfällige Module Vorrang haben, berechnet sich der **Prioritäts-Score** wie folgt:

$$\text{Prio-Score} = (\text{Tage seit letztem Run} + 1) \times (\text{Historische Funde} + 1) \times \text{Gewicht}_{\text{Pillar}}$$

* **Gewicht nach Säule:**
  * Pillar 2 (Invarianten & Konsensus) & Pillar 3 (Byzantine Security): $\text{Gewicht} = 3.0$
  * Pillar 4 (Deadlocks & Dynamik) & Pillar 1 (Memory Safety/Tests): $\text{Gewicht} = 2.0$
  * Pillar 5 (Chaos & Fuzzing) & Clean Code: $\text{Gewicht} = 1.0$
* **Status:**
  * `⚪ Untested`: Noch nie gelaufen (höchste Priorität).
  * `🟢 Clean`: Durchgelaufen, 0 offene Funde.
  * `🟡 In Progress`: Funde in Bearbeitung / Teilfixes erfolgt.
  * `🔴 Hotspot`: Mehrfach kritische Lücken gefunden, erfordert zeitnahen Re-Audit.


---

## 🏛️ Die 6 Kritikalitäts-Stufen (Architektur- & Schadensmatrix)

Die 25 Audits sind nach **Schadenspotenzial**, **Produktionsnähe (Gen 2 vs. Gen 1)** und **Re-Audit-Relevanz** in 6 Kritikalitäts-Stufen eingeteilt:

* **🔴 Stufe 1: Konsensus-Kern & PoS-Hotpath (Produktions-Integrität & Überleben)**  
  *Schadenspotenzial: Katastrophal ($0-Toleranz)*. Fehler führen zu Double-Spends, Slashing ehrlicher Knoten (Doppel-Signatur), Fork-Divergenz oder Zusammenbruch der PoS-Kassen-SLA.  
  Umfasst die hochspezialisierten „Generation 2“-Audits (Oktober 2026), die direkt auf den echten Modulen (`daemon.rs`, `recovery.rs`, `signing.rs`, `install.rs`, `transport.rs`, `routes.rs`) sitzen. Diese Audits müssen **zu 100 % fehlerfrei sitzen** und haben bei jedem Release oberste Priorität.  
  *Audits: 23, 22, 24, 21, 25, 19*

* **🟠 Stufe 2: Laufzeit-Dynamik & Aktive Test-Generierung (Deadlocks, Zeit & Fuzzing)**  
  *Schadenspotenzial: Hoch (Systemstillstand / Liveness-Verlust)*. Fehler führen zu Deadlocks unter Last, Channel-Blockaden, vorzeitigem TTL-Löschen durch Uhrenmanipulation oder unentdeckten Test-Blindspots.  
  Zeitlose Audits für Systemdynamik ($\Delta \text{Load} \le 0$), dezentralen Median (`P2pClock`) und automatisierte Mutation-/Property-Testgenerierung.  
  *Audits: 03, 11, 12, 14, 06*

* **🟡 Stufe 3: Code-Sicherheit & Invarianten-Wächter (Panic-Freiheit, Safety & Specs)**  
  *Schadenspotenzial: Mittel bis Hoch (Remote Crash / Spezifikations-Drift)*.  
  Erzwingt Panic-Freiheit auf Netzwerkpfaden (Verbot von `.unwrap()`/`.expect()`, Schutz vor Panics bei Slice-Zugriffen), `#![forbid(unsafe_code)]` und gleicht `INVARIANT_REGISTRY.md` bitgenau mit der Implementierung ab.  
  *Audits: 15, 13, 04*

* **🟢 Stufe 4: Makro- & Performance-Sammelbecken (Weitgehend durch Gen 2 abgelöst)**  
  *Schadenspotenzial: Gering bis Mittel (Historische Sammelprompts)*.  
  Diese Audits wurden in frühen Phasen konzipiert. Ihre Kernprüfungen wurden durch die schärferen Audits aus Stufe 1 (`21`–`25`) übernommen. Vor erneuten Durchläufen müssen veraltete Annahmen im Prompt-Text aktualisiert werden, um False Positives zu vermeiden.  
  *Audits: 02, 05, 20, 07*

* **🔵 Stufe 5: Konzeptionelle Spieltheorie & Architektur-Beweise (Einmal-Beweise)**  
  *Schadenspotenzial: Gering (Design-Integrität)*.  
  Mathematische Nachweise über Schutz vor Shard-Kartellen, Eclipse-Resilienz und Post-Breach-Containment (Blind Service / Client-Side Custody). Wiederholte Durchläufe bringen keinen neuen Erkenntnisgewinn, solange das Architekturmodell unverändert bleibt.  
  *Audits: 08, 10, 09*

* **⚪ Stufe 6: Code-Hygiene, Wartbarkeit & Supply Chain (Wartung ohne Konsensus-Risiko)**  
  *Schadenspotenzial: Sehr gering (Kein Ausfallrisiko)*.  
  Code-Abbau (*„Subtraction before Construction“*), Bereinigung toter DTOs/Wire-Typen, POSIX 0600-Dateirechte und Abhängigkeitsprüfung via `cargo audit`.  
  *Audits: 01, 18, 17, 16*

---

## 📊 Status-Matrix der 25 Audit-Prompts

| ID | Prompt-Datei | Stufe | Pillar | Letzter Durchlauf | Modell | Funde gesamt | Offen | Status | Prio-Score |
|---|---|---|---|---|---|---|---|---|---|
| **01** | `01_subtraktion_und_vereinfachung.md` | Stufe 6 | 2. Architektur | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **02** | `02_security_und_byzantine_hardening.md` | Stufe 4 | 3. Byzantine | 2026-09-29 | subagents / gemini-3.7-flash | 10 | 0 | `🟢 Clean` | **Niedrig** |
| **03** | `03_todes_spiralen_und_deadlock_audit.md` | Stufe 2 | 4. Dynamik | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **04** | `04_invarianten_und_spezifikations_waechter.md` | Stufe 3 | 2. Architektur | 2026-09-29 | subagents / gemini-3.7-flash | 9 | 0 | `🟢 Clean` | **Niedrig** |
| **05** | `05_performance_und_latency_audit.md` | Stufe 4 | 2. Architektur | 2026-09-29 | subagents / gemini-3.7-flash | 7 | 0 | `🟢 Clean` | **Niedrig** |
| **06** | `06_chaos_und_fuzz_test_generator.md` | Stufe 2 | 5. Chaos | 2026-09-29 | subagents / gemini-3.7-flash | 12 | 0 | `🟢 Clean` | **Niedrig** |
| **07** | `07_faulheit_und_free_riding_audit.md` | Stufe 4 | 4. Dynamik | 2026-09-29 | subagents / gemini-3.7-flash | 6 | 0 | `🟢 Clean` | **Niedrig** |
| **08** | `08_sabotage_zensur_und_eclipse_audit.md` | Stufe 5 | 3. Byzantine | 2026-09-29 | subagents / gemini-3.7-flash | 6 | 0 | `🟢 Clean` | **Niedrig** |
| **09** | `09_knoten_hack_und_key_compromise_audit.md` | Stufe 5 | 3. Byzantine | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **10** | `10_kartellbildung_und_shard_takeover_audit.md` | Stufe 5 | 3. Byzantine | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **11** | `11_time_warp_und_uhren_manipulation_audit.md` | Stufe 2 | 4. Dynamik | 2026-09-29 | subagents / gemini-3.7-flash | 2 | 0 | `🟢 Clean` | **Niedrig** |
| **12** | `12_mutation_testing_und_test_blindspot_audit.md` | Stufe 2 | 1. Testing | 2026-09-29 | subagents / gemini-3.7-flash | 8 | 0 | `🟢 Clean` | **Niedrig** |
| **13** | `13_unsafe_code_und_memory_safety_audit.md` | Stufe 3 | 1. Safety | 2026-09-29 | subagents / gemini-3.7-flash | 4 | 0 | `🟢 Clean` | **Niedrig** |
| **14** | `14_property_based_testing_und_fuzzing.md` | Stufe 2 | 1. Testing | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **15** | `15_clean_code_und_idiomatic_rust_audit.md` | Stufe 3 | 1. Clean Code | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **16** | `16_supply_chain_und_dependency_audit.md` | Stufe 6 | 1. Supply Chain | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **17** | `17_update_and_supply_chain_verification.md` | Stufe 6 | 1. Sovereign | 2026-09-29 | subagents / gemini-3.7-flash | 5 | 0 | `🟢 Clean` | **Niedrig** |
| **18** | `18_legacy_code_and_architectural_drift_audit.md` | Stufe 6 | 2. Architektur | 2026-09-29 | subagents / gemini-3.7-flash | 12 | 0 | `🟢 Clean` | **Niedrig** |
| **19** | `19_wire_level_quota_and_adversarial_verification_audit.md` | Stufe 1 | 5. Wire / Chaos | 2026-10-25 | regression-first (TDD) / verified | 3 | 0 | `🟢 Clean` | **Niedrig** |
| **20** | `20_adler_perspektive_und_systemische_vollstaendigkeit.md` | Stufe 4 | 2. Makro-Architektur | 2026-10-24 | model-router (minimax) / verified | 0 | 0 | `🟢 Clean` | **Niedrig** |
| **21** | `21_distributed_recovery_and_shard_sync_audit.md` | Stufe 1 | 2. Recovery / Sync | 2026-10-24 | TDD / regression-verified | 6 | 0 | `🟢 Clean` | **Niedrig** |
| **22** | `22_monotonic_confirmation_and_merge_quarantine_audit.md` | Stufe 1 | 2. Konsensus / Invarianten | 2026-10-25 | regression-first (TDD) / verified | 3 | 0 | `🟢 Clean` | **Niedrig** |
| **23** | `23_dual_tier_concurrency_and_signing_history_audit.md` | Stufe 1 | 1. Safety / Concurrency | 2026-10-25 | regression-first (TDD) / verified | 1 | 0 | `🟢 Clean` | **Niedrig** |
| **24** | `24_pos_checkout_hotpath_and_cancellation_safety_audit.md` | Stufe 1 | 4. Dynamik / Latency | 2026-10-25 | regression-first (TDD) / verified | 4 | 0 | `🟢 Clean` | **Niedrig** |
| **25** | `25_ingress_defense_and_stateless_pow_audit.md` | Stufe 1 | 3. Byzantine / Ingress | 2026-10-25 | regression-first (TDD) / verified | 5 | 0 | `🟢 Clean` | **Niedrig** |

---

## 📜 Audit-Historie & Durchlauf-Protokoll

| Datum / Zeit | Batch (Prompts) | Modell | Funde kumuliert | Durchgeführte Fixes | Report-Pfad |
|---|---|---|---|---|---|
| *Init* | - | - | - | Initialisierung der Matrix | - |
| 2026-09-15 09:55 | [04, 02, 13] | muse-spark | 19 | 10 Fixes: BLAKE3 Length-Prefix (wire.rs), Replay-Cache Race (pow.rs), Gateway HRW-Ticket Routing (routes.rs), Shard 24h Hysterese (transport.rs), Quota Overflow checked_add (quota.rs), ProofChain Bounds (types.rs), UDS Bounds (server.rs), First-Party Ban Signature Check (engine.rs), #![forbid(unsafe_code)] (lib.rs), Doc 12 Mermaid Typo | `prompts/reports/2026-09-15_*.md` |
| 2026-09-18 20:55 | [08, 09, 10] | muse-spark | 16 | Status Quorum Query Candidate Window Erweiterung auf Rank 32 Hedged Fallback (routes.rs), Client-Side Custody & Shard-Takeover Validierung | `prompts/reports/2026-09-18_*.md` |
| 2026-09-23 22:40 | [01, 03, 11] | muse-spark | 10 | 10 Befunde: Subtraktion-Potenzial (1.6k-2.2k LOC Duplikate in Quorum & Ringpuffern), Todes-Spiralen & Deadlocks 100% bestanden (Härtungsempfehlungen: BLAKE3-Fanout, Fraud-Limiting, QUIC Conn-Semaphore), Time-Warp 100% bestanden (F2F Median & Ingress Windows robust, Prune-Guard & Heartbeat-Skew-Check identifiziert) | `prompts/reports/2026-09-23_*.md` |
| 2026-09-23 23:42 | [18, 01] | muse-spark | 17 | Audit 18: 12 Funde zu toten Wire-Nachrichtentypen (`GossipAnnounce`, `MergeLoser*`, `ActiveSyncChunk`), Dual-Stack-Resten (`LockSubmitRequest` vs. HMC Native), toten Geister-Caches (`SeenGossipCache`) und Doku-Drifts (`TombstoneBroadcast`). Audit 01: 2.4k-2.8k LoC Subtraktionspotenzial identifiziert (QR/Dashboard-Peripherie, Fanout/Flush-Duplikate, RingBuffer-Abstraktion, Alias-Explosion). | `prompts/reports/2026-09-23_*.md` |
| 2026-09-24 08:35 | [05, 12, 14] | muse-spark | 20 | Audit 05: Hot-Path Ingress Latenz (<5ms), JSON-Doppelparse-Eliminierung, VIP-Quota Entkopplung, Zero-Copy Header Framing. Audit 12: Mutationsanalyse (14 Mutanten, 8 Kill-Tests für Grenzwert- und Cache-Blindspots). Audit 14: 36 mathematische Property-Tests mit `proptest` für Invertibilität, Idempotenz, Ordnung, Monotonie und Quotas. | `prompts/reports/2026-09-24_*.md` |
| 2026-09-24 09:22 | [07, 15, 16] | muse-spark | 16 | Audit 07: Free-Riding & Laziness Härtungen (H-01 bis H-06: Reziproker Ingress Credit, Proof-of-Custody Storage-Audit, EWMA-Latenz-SLA, strikte HRW-Bitmap-Bindung). Audit 15: Clean Code & Panic-Freiheit (keine externen unwraps, Visibility pub(crate) Kapselung, Newtype-Ergonomie). Audit 16: Supply Chain (keine CVEs, keine Copyleft-Lizenzen, Feature-Flag-Minimierung). | `prompts/reports/2026-09-24_*.md` |
| 2026-09-24 10:00 | [06, 04, 02] | muse-spark | 31 | Audit 06: 12 aggressive Chaos- & Jepsen-Tests (Split-Brain Merge, Sybil Storm, Crash Recovery, Jitter/Packet-Loss, Fuzzing). Audit 04: Invarianten-Reconciliation (34/36 bit-identisch, INV-0805 Doku-Reconciliation, INV-0310 Read-Balancing). Audit 02: Härtung Parent-Binding in PoW (`pow.rs`), TTL & Max-Limit im Sync-Pfad (`routes.rs`), Prefix-Scan Schutz (`engine.rs`). | `prompts/reports/2026-09-24_*.md` |
| 2026-09-24 10:45 | [17, 13, 08] | muse-spark | 15 | Audit 17: Sovereign Node Verification (0600 File-Perms bestätigt, UDS Backup-Pfad-Sanitization empfohlen, keine verdeckten Telemetrien). Audit 13: 0 `unsafe`-Blöcke (`#![forbid(unsafe_code)]`), Zero UB, sicheres Alignment via `from_le_bytes`. Audit 08: Eclipse- & Gaslighting-Schutz validiert (Kausalitäts-ProofChain, FirstSeenPacer, F2F-Median). Test-Fix in `api_tests.rs`. | `prompts/reports/2026-09-24_*.md` |
| 2026-09-24 20:54 | [09, 10, 03] | muse-spark | 15 | Audit 09: Post-Breach Containment & Fund-Sicherheit bewiesen ($0 Fund-Verlust, Client-Custody). Audit 10: 14/20 Shard-Kartell-Resilienz, ökonomische Selbstvernichtung via Equivocation & HRW-Sybil-Kosten. Audit 03: Nichtlineare Systemdynamik, $\Delta \text{Load} \le 0$ Hot-Path, Backpressure-Deadlock-Freiheit, Reconnect-Jitter & Graceful-Shutdown JoinSets. | `prompts/reports/2026-09-24_*.md` |
| 2026-09-24 22:50 | [01, 11, 18] | zen-3-pro / gemini-2.5-pro | 19 | Audit 01: Wire Subtraktion (`ShardMapPing`/`Pong` entfernt), Hot-Path Map-Clone in `/v1/sync` und Chain-Lock `L2LockEntry` Doppel-Klonen eliminiert. Audit 11: Decentralized Time-Binding (`current_epoch_day_at`) für Quoten-Ingress gehärtet. Audit 18: Wire Message Types in Doku 10 & Code 100% synchronisiert, Dead Types bereinigt. | `prompts/reports/2026-09-24_*.md` |
| 2026-09-25 21:50 | [02, 04, 05] | muse-spark | 25 | Audit 02: Byzantine Security 100% bestätigt (min(H_canon) Arbiter-Klarstellung, Equivocation-First Invariante). Audit 04: Bitgenaue Invarianten-Reconciliation (INV-1204 192B Consensus vs 224B RAM Doc-Clarification in `quota.rs`, INV-0301 Sim-NodeId vs `HrwRoutingId` in `types.rs`, Resolver-Kommentare in `crypto.rs`). Audit 05: Hot-Path Ingress Latenz & CAS Locking verifiziert. 100% Tests grün. | `prompts/reports/2026-09-25_*.md` |
| 2026-09-28 21:00 | [08, 10, 12, 07] | subagents / gemini-3.7-flash | 25 | Audit 08: Eclipse- & Gaslighting-Schutz bewiesen (ProofChain, 409-Signaturbeweise). Audit 10: 14/20 Kartellbildung mathematisch abgewehrt (Client-Side Custody, atomares Equivocation-Slashing). Audit 12: 14/14 Mutanten getötet (100% Mutation-Kill-Rate). Audit 07: Free-Riding & Silent Signer mitigiert (Rank-21 Promotion in 0ms, BFT Shard-Digest Pull). | `prompts/reports/2026-09-28_*.md` |
| 2026-09-28 21:30 | [09, 03, 18] | subagents / gemini-3.7-flash | 22 | Audit 09: Post-Breach Containment bewiesen ($0 Kundengeld-Verlust, O(1) Selbstbann bei Equivocation). Audit 03: Todes-Spiralen- & Deadlock-Immunität bestätigt (Delta Load <= 0, Reservation-First, CancellationToken Join). Audit 18: Legacy DTOs (LockSubmitRequest) & tote Wire-Pfade identifiziert. | `prompts/reports/2026-09-28_*.md` |
| 2026-09-29 21:30 | [02, 04, 05] | subagents / gemini-3.7-flash | 26 | Audit 02: Byzantine Hardening 100% verifiziert (Double-Spend CAS, First-Party Evidence, Domain Separation, OOM Limits). Audit 04: Bitgenaue Spezifikations-Reconciliation (Zero Divergence, Quorum/Finalität, HRW Sharding, TTL Grace, Quota Thermometer). Audit 05: PoS Hot-Path Latenz (~110µs < 5ms SLA) & CAS (<100ns < 1µs) verifiziert. Clippy-Fix in `dashboard.rs`. | `prompts/reports/2026-09-29_*.md` |
| 2026-09-29 21:40 | [01, 06, 14] | subagents / gemini-3.7-flash | 22 | Audit 01: Subtraktion-Härtung (Dead Legacy PoW Helper entfernt, `bs58` Stack-Decoding in Leap-Lock Query optimiert). Audit 06: Chaos & DST 100% bestanden (3-Way Split-Brain, Byzantine Slashing, Crash-Loop Recovery, Jitter/Drop, Bounded Framing). Audit 14: 5 algebraische Invariantenfamilien via `proptest` formal bewiesen. | `prompts/reports/2026-09-29_*.md` |
| 2026-09-29 21:50 | [08, 13, 18] | subagents / gemini-3.7-flash | 22 | Audit 08: Zensur- & Eclipse-Immunität bewiesen (ProofChain, 3-Gateway-Regel, 24h Ticket-Inkubation). Audit 13: Memory Safety 100% verifiziert (0 unsafe Blöcke, #![forbid(unsafe_code)], overflow-frei). Audit 18: Totes `LockEnvelope` Struct und veraltete Wire-Docstrings bereinigt. | `prompts/reports/2026-09-29_*.md` |
| 2026-09-29 22:00 | [09, 10, 11] | subagents / gemini-3.7-flash | 12 | Audit 09: 0€ Fund Loss bewiesen (Blind Service / Client Custody). Audit 10: 14/20 Shard-Kartellbildung abgewehrt (Client ProofChain & Equivocation Slashing). Audit 11: Time-Warp Härtung (Fallback `deletable_at` in `db.rs` auf 0, Clock-Sample auf `hops == 0` isoliert). | `prompts/reports/2026-09-29_*.md` |
| 2026-09-29 22:20 | [15, 16, 17] | subagents / gemini-3.7-flash | 15 | Audit 15: Clean Code & Panic-Freiheit (Guard-Clause für leere Chain `[]` in `routes.rs:1272`, sicheres `unwrap_or_default()` für `ds_tag` in `engine.rs:741`, unwrap-freie SocketAddr & Hash-Slices). Audit 16: Supply Chain 100% sauber (0 CVEs, 0 Copyleft/GPL, Score 94/100). Audit 17: Knoten-Souveränität 100% bestätigt (0 verdeckte Telemetrien, 0600 POSIX Perms, 0 `std::process::Command`). | `prompts/reports/2026-09-29_*.md` |
| 2026-09-29 22:30 | [03, 07, 12] | subagents / gemini-3.7-flash | 19 | Audit 03: Todes-Spiralen- & Deadlock-Immunität (Delta Load <= 0, Reservation-First, 0ms Rank-21 Fallover, JoinSet Clean Aborts). Audit 07: Free-Riding- & Laziness-Immunität (Fast-Exit, Shard Digest Pull, strikte Bitmap-Validierung). Audit 12: Mutations-Testabdeckung (17/17 Kern-Mutanten 100% getötet, 0 Survivors). | `prompts/reports/2026-09-29_*.md` |
| 2026-10-24 21:55 | [19] | model-router (minimax) / verified | 0 | Audit 19: Wire-Level Quotas & Adversarial Verification (4/4 False Positives widerlegt: Quoten- und Ingress-Prüfungen in `transport.rs:627..871` verifiziert, 2-Tier-Architektur P2P vs Ingress bestätigt, Wire-Handler-Testabdeckung in `phase4_net_time_and_quotas.rs` vorhanden). | `prompts/reports/2026-10-24_19_wire_level_quota.md` |
| 2026-10-24 22:05 | [20] | model-router (minimax) / verified | 0 | Audit 20: Adler-Perspektive & Systemische Vollständigkeit (8/8 False Positives widerlegt: Quorum-Signaturprüfung in `routes.rs:1119` bitgenau verifiziert, Durable-before-Vote in `ingress_hmc_lock_durable` aktiv, Client-Committee-Prüfung in `humoco-proto`, Heartbeat-Signaturprüfung in `transport.rs:1879`, Dedup in line 2513, Quarantine in `TABLE_PROVISIONAL_HMC_LOCKS`). | `prompts/reports/2026-10-24_20_adler_perspektive_und_systemische_vollstaendigkeit.md` |
| 2026-10-24 22:50 | [21] | TDD / regression-verified | 6 | Audit 21: Distributed Recovery & Shard Sync (6 Befunde per TDD behoben: 1. Reconcile bevorzugt strikt Confirmation-Classes vor min(H_canon) Tie-Breaker DEC-064/DEC-022; 2. Anti-Laundering für unquorisierte lokale Fakten; 3. ShardStage Ressourcen-Caps 50k Entries & 32 MiB gegen DoS; 4. Paralleles viable Peer Streaming via JoinSet mit signierter Digest-Prüfung; 5. Lease-Deadline-Prüfung vor redb-Commit; 6. Verwaiste HMC-Spends isoliert in TABLE_PROVISIONAL_HMC_LOCKS statt Fehlerabbruch; Readiness-State-Guard gegen Degradierung). Regressionstests in `distributed_recovery_audit_regressions.rs`. | `prompts/reports/2026-10-24_21_distributed_recovery_and_shard_sync.md` |
| 2026-10-24 22:30 | [22] | verified / inherited_support_tests | 0 | Audit 22: Monotonic Confirmation Classes & Merge Quarantine (5/5 Filter verifiziert: Monotone Klassenordnung DEC-064, Quorum-Support-Qualifikation F01, Quarantäne via `TABLE_PROVISIONAL_HMC_LOCKS` bei Dorf-Merge, Zero Bloat TTL-Pruning, deterministisches min(H_canon). 6/6 QUIC-Wire-Tests grün). | `prompts/reports/2026-10-24_22_monotonic_confirmation_and_merge_quarantine.md` |
| 2026-10-24 22:35 | [23] | verified / storage_tests | 0 | Audit 23: Dual-Tier Concurrency & Fail-Closed Signing (5/5 Filter verifiziert: Nanosekunden atomic CAS Single-Winner Idempotenz, Durable-before-Vote DEC-029 synchroner oneshot Commit-Wait in `ingress_hmc_lock_durable`, non-blocking Tokio Worker Thread, G5 Fail-Closed Monotonic Signing Fingerprint Latch). | `prompts/reports/2026-10-24_23_dual_tier_concurrency_and_signing_history.md` |
| 2026-10-24 | [24] | Codex | 4 | Audit only; no production fixes. Three P2 findings reproduced over real QUIC (minority-answer live-proof denial, client/server deadline mismatch, collision overwritten by HTTP 503); one P3 retry-response loss confirmed by inspection. Standard suite: 681 passed, 0 failed, 14 ignored. | `prompts/reports/2026-10-24_24_pos_checkout_hotpath_audit.md` |
| 2026-10-25 09:15 | [24] | regression-first (TDD) / verified | 4 | Alle 4 Audit-24-Befunde behoben: 1. A24-01: Per-Member Live-Verifikation (`query_member_live_vote`) mit Gruppierung nach `live_state_digest` und 14-Vote Fast-Exit eliminiert First-Response-Wins Schwachstelle; 2. A24-02: Live-Proof-Sammlung an einheitliches absolutes Server-Deadline-Budget (750ms `LIVE_PROOF_SERVER_BUDGET`) via Middleware gebunden; 3. A24-03: Strikte `validate_remote_collision` mit Quorum-Isolation bewahrt HTTP 409 Conflict auf Single- und Chain-Routen, Dual-Serde für `L2LockEntry` (bincode vs. JSON HMC Digest); 4. A24-04: Bounded Peer-Attestation-Retries (max 3 Writes) mit identischer Response-Validierung und neutralen Nicht-Malus-Ergebnissen. Permanente Regressionstests in `status_reconciliation_tests.rs` und `phase11_wire_level_adversarial_tests.rs` (100% grün). | `prompts/reports/2026-10-24_24_pos_checkout_hotpath_audit.md` |
| 2026-10-24 22:40 | [25] | model-router / verified | 0 | Audit 25: Ingress Defense, Dynamic Stateless PoW & Wire-Framing (5/5 Filter verifiziert: Stateless BLAKE3 PoW mit 10-Minuten-Slots und atomarem Replay-Schutz, Cheap-Filters-First vor Krypto/Disk, striktes Verbot von NodePubKey als HTTP-Bearer-Token, 64 KiB OOM-Framing-Cap, deterministische 1-von-20 Shard-Lese-Randomisierung. 22/22 Tests grün). | `prompts/reports/2026-10-24_25_ingress_defense_and_stateless_pow.md` |
| 2026-10-25 | [22] | Codex subagent / independently reviewed | 3 | Re-audit: two P2 findings (equal native canonical-hash ordering; stale RAM class publication) and one P3 (root metadata expiry). Four safe-behavior probes fail as expected, including real QUIC recovery. Separate detailed regression-first fix plan created; no production fixes. | `prompts/reports/2026-10-25_22_monotonic_confirmation_and_merge_quarantine_audit.md` |
| 2026-10-25 10:50 | [22] | regression-first (TDD) / verified | 3 | Alle 3 Audit-22-Befunde behoben: 1. A22-01: Totale Ordnung für native LockRecords mit identischem H_canon via deterministischem ID-Tie-Breaker (`compare_native_precedence`) in Resolver, Installer und Reconciler inkl. ID-Preimage-Validierung; 2. A22-02: Monotone Publikation von Confirmation Classes im RAM (`max(current, admitted)`) für denselben Child-Lock und Bereinigung bei Child-Ersetzung; 3. A22-03: Geteilter, schrittweiser Voucher-Root-Pruner (`prune_voucher_roots`) mit 256-Limit und exakter Grace-Horizont-Prüfung (30s) in beiden DB-Pruning-Pfaden gegen unbegrenzte Root-Metadaten-Akkumulation. Permanente Regressionstests in `audit22_regressions.rs` (6/6 grün inkl. echtem QUIC-Cluster). | `prompts/reports/2026-10-25_22_monotonic_confirmation_and_merge_quarantine_audit.md` |
| 2026-10-25 | [23] | Codex subagent / independently reviewed | 1 | Re-audit: P2 runtime history-integrity gap under explicit logical row-loss/corruption fault injection. Two internal probes fail as expected; no demonstrated real double-signature release. Separate detailed regression-first fix plan created. Combined standard rerun: 700 passed, 0 failed, 14 ignored; initial E2E failures retained in evidence. | `prompts/reports/2026-10-25_23_dual_tier_concurrency_and_signing_history_audit.md` |
| 2026-10-25 | [19] | Codex / independent subagent | 3 | Independent re-audit: incorrect wire lifetime authority for Byte-Years, missing real QUIC quota-boundary evidence, and non-neutral Zone-1 quota feedback. Source/coverage findings separated from unexecuted reproductions. Existing phase4 8/8 and anti-self-slashing QUIC 1/1 passed. Separate regression-first fix plan; no production fixes. | `prompts/reports/2026-10-25_19_wire_level_quota_and_adversarial_verification_audit.md` |
| 2026-10-25 | [25] | Codex / independent subagent | 5 | Independent re-audit: PoW format/parent binding, mandatory replay state, P2P/HTTP token coupling, expensive processing before admission, and ignored public quota denial. Five observation probes and seven framing component tests passed; explicit end-to-end evidence limits retained. Separate regression-first fix plan; no production fixes. | `prompts/reports/2026-10-25_25_ingress_defense_and_stateless_pow_audit.md` |
| 2026-10-25 | [19, 25] validation | Codex coordinator | 8 open | Shared standard checks: 708 passed, 5 failed, 14 ignored (4 concurrent Audit23 regressions, 1 quorum assembly failure); formatting differences and Clippy E0505 in concurrent signing.rs changes. No production fixes by these audits; no findings closed. | `prompts/reports/evidence/2026-10-25_audits_19_25_shared/README.md` |
| 2026-10-25 11:15 | [23] | regression-first (TDD) / verified | 1 | A23-01 behoben: 1. Laufzeit-Kardinalitätsprüfung (`choices.len() == state.count`) und Validierung von Generation, Slot/TTL-Index und Zeilendekodierung vor Mutationen und Exakt-Retries in `commit_original_approval` und `commit_original_record_approval`; 2. Fail-Closed Signing-Latch in-memory und persistiert (`latch_corruption` via unmittelbarer redb-Transaktion); 3. QUIC-Schutz gegen Doppel-Signaturen bei logischem Historienverlust; 4. Permanente Regressionen in `audit23_regressions.rs` (4/4 grün inkl. echtem QUIC-Cluster). | `prompts/reports/2026-10-25_23_dual_tier_concurrency_and_signing_history_audit.md` |
| 2026-10-25 12:45 | [19] | regression-first (TDD) / verified | 3 | Alle 3 Audit-19-Befunde behoben: 1. A19-01: Root-abgeleitete Byte-Years-Abrechnung auf Empfängerseite (echte `root.valid_until` aus Speicher/Causal Genesis, Mismatch-Ablehnung für unterdeklarierte Wire-Lifetimes vor Mutationen); 2. A19-03: Neutrales Quoten-Feedback (`FLAG_QUOTA_EXCEEDED` ohne `record_failure` Malus oder Peer-Präsenz-Degradierung); 3. A19-02: Umfassende QUIC-Receiver-Abdeckung in `audit19_regressions.rs` (5x Rate-Limits, TLS/Sender-Identitätsbindung `FLAG_UNAUTHORIZED`, Bounded Framing); 4. W4: P2P-Quoten-Isolation nach voller 32-Byte `NodePubKey`. | `prompts/reports/2026-10-25_19_wire_level_quota_and_adversarial_verification_fix_plan.md` |
| 2026-10-25 12:50 | [25] | regression-first (TDD) / verified | 5 | Alle 5 Audit-25-Befunde behoben: 1. A25-01: Kanonisches Single-Domain PoW `hash_work` (`HUMOCO_V1_POW_STATELESS`) mit strikter Parent-Bindung (generischer Zero-Parent Fallback entfernt); 2. A25-02: Mandatorischer `seen_solutions`-Replay-Cache entfernt, idempotente Retries mit identischem Work gelingen fehlerfrei; 3. A25-03: Entkopplung von P2P-Topologie und Client-Bearer-Tokens (`is_valid_client_token` erzwingt `f2f_`-Präfix); 4. A25-04: Frühe unauthorisierte Ablehnung vor Krypto/Disk-I/O mit un权的/unsignierten HTTP-Fehlern; 5. A25-05: Durchsetzung täglicher Public-Quoten in `try_accept_lock` (HTTP 429 QuotaExceeded bei Erschöpfung). Regressionen in `audit25_regressions.rs` (5/5 grün). | `prompts/reports/2026-10-25_25_ingress_defense_and_stateless_pow_fix_plan.md` |


