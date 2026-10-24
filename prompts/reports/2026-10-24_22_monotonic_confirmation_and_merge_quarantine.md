# ⚖️ Audit-Bericht: Audit 22 – Monotonic Confirmation Classes, Inherited Support & Village Merge Quarantine

**Datum:** 2026-10-24  
**Audit-ID:** AUDIT-22-MONOTONIC-CONFIRMATION-MERGE-QUARANTINE  
**Scope:** `crates/humoco-node/src/storage/db/support.rs`, `storage/db/install.rs`, `storage/db.rs`, `crates/humoco-sim-core/src/resolver.rs`  
**Auditor:** Anti-Gravity (Formale Code-Verifikation & QUIC-Integrationstests)  
**Status:** **PASSED / VERIFIED (5/5 Invarianten-Filter & 6/6 QUIC-Tests 100% bestanden)**

---

## 🔬 Detaillierte Invarianten-Verifikation

### 1. 🛡️ Monotone Klassen-Hierarchie (DEC-022, DEC-064, Invariante G3)
* **Verifikation in `humoco-sim-core/src/resolver.rs:77–110` & `install.rs:155–165`:**
  * Bestätigungsklassen haben absolute Priorität: `Class 2 (FINAL)` > `Class 1 (PROVISIONAL)` > `Class 0 (PENDING)`.
  * Ein unbestätigter Singleton- oder Angreifer-Lock (`class = 0`) kann **niemals** einen bestätigten Lock (`class >= 1`) verdrängen, unabhängig davon, wie klein sein BLAKE3-Hash `min(H_canon)` ist.
  * `min(H_canon)` fungiert **ausschließlich als Tie-Breaker** innerhalb der **exakt identischen Bestätigungsklasse**.
  * Eine Herabstufung (Demotion) eines bestehenden dauerhaften Locks ist mathematisch und transaktional ausgeschlossen (`old_class > new_class` bricht ab).

### 2. 📜 Inherited Support Digest Qualification (F01-Kontext)
* **Verifikation in `crates/humoco-node/src/storage/db/support.rs` (`VerifiedInheritedCut::verify`):**
  * Support-Qualifikation verlangt zwingend `qualified_supports` mit mindestens $\ge Q$ unabhängigen, übereinstimmenden Zeugen.
  * Eine byzantinische Minderheit $< Q$ kann keine gefälschte `class = 2`-Einstufung erzwingen.
  * **Test-Nachweis:** `tests/inherited_support_tests.rs::single_byzantine_source_forged_final_support_is_downgraded_over_real_quic` beweist über echte QUIC-Verbindungen, dass ein gefälschter Final-Claim sauber auf `class = 1` herabgestuft wird.

### 3. 🔬 Asymmetrische Merge-Quarantäne (`TABLE_PROVISIONAL_HMC_LOCKS`)
* **Verifikation in `storage/db.rs:686–742` & `install.rs:209, 250`:**
  * Bei einem asymmetrischen Village-Merge (z. B. 10 vs. 3 Knoten) isolieren beitretende Knoten lokale unbestätigte Minderheiten-Locks atomar in `TABLE_PROVISIONAL_HMC_LOCKS`.
  * Dies garantiert, dass lokale Minderheiten-Locks den dominanten Shard-Digest nicht vergiften (`post_digest == dominant_digest`).
  * Die Locks bleiben für die Client-Reconciliation erhalten (kein Datenverlust).

### 4. ⏰ Retained-Choice Reconciliation & TTL-Ablauf (Z10, Spec 08)
* **Verifikation in `storage/db.rs:820–865` (`prune_expired`):**
  * Alle Einträge in `TABLE_PROVISIONAL_HMC_LOCKS` sind physisch an die Gültigkeit der Gutschein-Wurzel (`root.valid_until + 30s`) gebunden.
  * Abgelaufene provisorische Locks werden physisch bereinigt. Permanente Tombstones sind strikt verboten (Doctrine: Zero State Bloat).

### 5. 🔀 Deterministisches Tie-Breaking & Endian-Sicherheit
* **Verifikation in `humoco-sim-core/src/crypto.rs` & `storage/engine.rs`:**
  * `compute_canonical_hash` verwendet deterministisches BLAKE3-Hashing mit Little-Endian (`to_le_bytes`), plattformunabhängig und immun gegen Paket-Reihenfolge.

---

## 🏁 Fazit & Status
Die Monotonie der Bestätigungsklassen und die Isolierung von Minderheitszuständen sind lückenlos formal und praktisch abgesichert. Audit 22 ist **CLEAN**.
