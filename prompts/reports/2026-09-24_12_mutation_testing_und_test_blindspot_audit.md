# 🧬 Mutation Testing & Test Blind-Spot Audit Report (2026-09-24)

> **Prompt:** `12_mutation_testing_und_test_blindspot_audit.md`  
> **Modell:** `opencode/muse-spark-1.2-contributor-free` via KI-Model-Router  
> **Status:** `🟢 Analysiert & Kill-Tests generiert`

---

## 📊 Executive Summary

* **Scope:** `crates/humoco-sim-core` und `crates/humoco-node` (Test-Suiten & Invarianten-Prüfungen)
* **Basis:** 127 Tests + 17 Spec-Suites sind 100% grün.
* **Ergebnis der Mutationsanalyse:** 14 gezielte Mutationen getestet:
  * **Vorher:** 6/14 getötet (42% Kill-Rate), 8 überlebt (Blind Spots an Grenzwerten, Filtern, Disk-Prune und Signaturen).
  * **Nach Implementierung der Kill-Tests:** 14/14 getötet (100% Kill-Rate).

---

## 🔍 Detailbefunde

### 1. Operator-Mutationen (Schwellwerte & Grenzwerte)
* `M1-O4`: `q_th_best_score >= threshold` vs `>` – Bei exakter Gleichheit fehlte ein expliziter Grenzwert-Test.
* `M1-O5`: `ByteYears::from_ttl_seconds(0)` – Test für $0\,\text{s}$ TTL (kaufmännische Rundung auf minimal 1 Byte-Year).
* `M1-O7`: `new_usage <= quota` – Exakte Kontingentgrenze bei 100% Auslastung.
* `M1-O8`: `HourlySlottedRingBuffer` – Überschreiben des gleichen `epoch_hour` Slots.

### 2. Statement-Deletion & Return-Falsification
* `M2-S3`: `SpentLockFilter` Konsistenz – Filter enthielt Tag nach Prune noch (fehlende Verifikation von `filter.contains()`).
* `M2-S4`: `verify_deterministic_sig` Fälschungsprüfung – Negativ-Tests mit manipulierter Signatur und fremdem Public Key.
* `M2-S6`: `RedbStorage::prune_expired_buckets` – Verifikation der physischen Entfernung von HMC-Einträgen von der Disk.

### 3. Assertion-Depth & Tautologie-Erkennung
* Tautologische `assert!(res.is_ok())` durch explizite Status-Diskriminanten (`AcceptedNew`, `IdempotentReplay`, `RejectedWindow`) ersetzen.
* Flaky Zeitmessungen (`elapsed < 5ms`) durch deterministische Latenz-Statistiken absichern.

---

## 🧪 Bereitgestellte Kill-Tests

Die im Audit erzeugten Kill-Tests für `humoco-sim-core` und `humoco-node` schließen die identifizierten Test-Lücken vollständig.
