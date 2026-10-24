# 🔄 Audit-Bericht: Audit 21 – Distributed Recovery, Shard Sync & Fragmented Consensus States

**Datum:** 2026-10-24  
**Audit-ID:** AUDIT-21-DISTRIBUTED-RECOVERY-SHARD-SYNC  
**Scope:** `crates/humoco-node/src/daemon.rs`, `storage/db/install.rs`, `storage/db/snapshot.rs`, `network/framing.rs`  
**Auditor:** Anti-Gravity (Verifikation & Adversarial Probe)  
**Status:** **PASSED / VERIFIED (Alle 5 Prüffelder & Adversarial Probes 100% grün)**

---

## 🔬 Detaillierte Analyse der 5 Prüffelder

### 1. 🧩 Distributed State Reconciliation & Fragmented Fact Quorums (F02 Context)
* **Verifikation in `crates/humoco-node/src/daemon.rs:1461–1560` (`reconcile_distributed_stage`):**
  * Jede Quelle (heruntergeladener ShardStage oder lokaler Speicher) erhält einen eindeutigen Index `0..stages.len()`. Zeugen werden in einem `HashSet<usize>` erfasst. Double-Counting desselben Peers ist unmöglich.
  * Jeder einzelne Fakt (Root, Native Lock, HMC Lock) wird strikt auf `witnesses.len() >= needed` geprüft.
  * Unkonfliktierte lokale Fakten mit bestehender Bestätigungsklasse (`row.status.confirmation_class() > 0`) werden erhalten und nicht verworfen.
  * Deterministische Auflösung via `compute_canonical_hash` / `compute_hmc_canonical_hash` garantiert konvergenten Zustand.
  * **Adversarial Probe:** `docs/evidence/recheck-audit-2026-10-24/probe-distributed-state.sh` besteht mit:
    `F02 VERIFIED: authentic AB8/A6/B6 compatible state reconciles per-fact distributed witnesses and reaches READY`.

### 2. ⏳ Deadline Validation & TOCTOU Race Windows
* **Verifikation in `crates/humoco-node/src/daemon.rs:1220–1278`:**
  * Die minimale Deadline aller Quellen `let Some(deadline) = downloaded_deadlines.into_iter().min() else { return Ok(false); };` wird ermittelt.
  * Vor und nach `spawn_blocking` sowie vor und nach `install_shard_snapshot` und unmittelbar vor `readiness_manager.mark_shard_ready` wird `Instant::now() >= deadline` geprüft.
  * Bei Ablauf bricht der Shard-Sync sauber ab (`Ok(false)`), ohne unvollständige Teil-Commits zu hinterlassen.

### 3. 💾 Multi-Table Atomic Installation & Rollback (`install_shard_snapshot`)
* **Verifikation in `crates/humoco-node/src/storage/db/install.rs:112–270`:**
  * Sämtliche Tabellen (`TABLE_VOUCHER_ROOTS`, `TABLE_LOCKS`, `TABLE_HMC_LOCKS`, `TABLE_CONFIRMATION_SUPPORT`, `TABLE_NATIVE_SUPPORT`, `TABLE_PROVISIONAL_HMC_LOCKS`) werden innerhalb einer einzigen atomaren `redb::WriteTransaction` mit `Durability::Immediate` aktualisiert.
  * Schlägt eine Tabellen-Operation oder Invarianten-Prüfung fehl, wird die Transaktion verworfen (Rollback).
  * **Test-Nachweis:** `confirmed_omission_rolls_back_root_registration_and_all_state` bestätigt sauberen Rollback bei Auslassung.

### 4. 🚰 Resource Pacing, Semaphores & Memory Safety
* **Verifikation in `crates/humoco-node/src/daemon.rs:1228–1232, 1251, 1321–1324`:**
  * Speicher- und Eintragsgrenzen werden über `readiness_manager.sync_bytes` (512 KiB) und `sync_entries` (500) via `try_acquire_many_owned` reserviert.
  * Die Permits sind lexikalisch an den Scope gebunden (`OwnedSemaphorePermit`) und werden bei Timeout, Fehler oder Abbruch garantiert freigegeben.

### 5. 👥 Living-Mesh Committee Freezing Check
* **Verifikation in `crates/humoco-node/src/daemon.rs:1258–1261, 1274–1275, 1342–1344`:**
  * Vor und nach der Snapshot-Installation wird das aktuelle Shard-Committee (`peer_manager.shard_committee`) mit den eingefrorenen Identitäten `frozen_keys` abgeglichen.
  * Bei Topologie-Wechseln ($N < 20 \leftrightarrow N \ge 20$ oder Peer-Suspension) wird die Installation abgebrochen und ein sicherer Retry ausgelöst.

---

## 🏁 Fazit & Status
Distributed Recovery und Shard-Synchronisation genügen den höchsten BFT- und Atomaritätsanforderungen. Audit 21 ist **CLEAN**.
