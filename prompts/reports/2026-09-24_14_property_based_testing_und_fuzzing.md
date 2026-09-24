# 🎲 Property-Based Testing & Algebraic Invariants Audit Report (2026-09-24)

> **Prompt:** `14_property_based_testing_und_fuzzing.md`  
> **Modell:** `opencode/muse-spark-1.2-contributor-free` via KI-Model-Router  
> **Status:** `🟢 Implementiert & Verifiziert (36 Property-Tests)`

---

## 📊 Executive Summary

* **Scope:** Mathematische Invarianten und algebraische Eigenschaften von `crates/humoco-sim-core`.
* **Ergebnis:** 36 property-basierte Testfälle mit dem `proptest`-Framework implementiert in `crates/humoco-sim-core/tests/proptests_humoco_properties.rs`.
* **Verifikation:** Alle Tests kompilieren und bestehen 100% grün unter `cargo test --workspace` und `cargo clippy --workspace --all-targets -- -D warnings`.

---

## 🔍 Detailüberprüfung der 5 mathematischen Eigenschaftsfamilien

### 1. Round-Trip Invertibilität (`decode(encode(x)) == x`)
* `WireHeader::to_bytes` / `from_bytes` (32 Byte C-aligned)
* `LockEntry144` (144 Byte feste Struktur)
* `LockRecord` Serialisierung / Deserialisierung via `bincode`
* `AccountTag` Ableitung und Klassifizierung

### 2. Idempotenz der State Machines (`f(f(x)) == f(x)`)
* `RamIndex::try_insert`: Zweiter Aufruf liefert deterministisch `IdempotentReplay`, `len` bleibt unverändert.
* `apply_attestation`: Duplizierte Attestierung liefert `DuplicateAttestation`, State bleibt invariant.
* `resolve_split_brain`: Wiederholte Auflösung derselben Kollision liefert denselben Gewinner/Verlierer.

### 3. Deterministische totale Ordnung `min(H_canon)`
* Strict weak ordering von `compute_canonical_hash`.
* Permutationsinvarianz: $\min(H_{\text{canon}}(A), H_{\text{canon}}(B)) = \min(H_{\text{canon}}(B), H_{\text{canon}}(A))$.
* Transitivität bei 3-Lock-Kollisionen.

### 4. Monotonie des TTL-Prunings
* Für $t_1 \le t_2$: `prune_expired(t1)` ist Teilmenge von `prune_expired(t2)`.
* Zweiter Aufruf bei gleichem $t$ entfernt genau 0 Elemente (`pruned == 0`).
* Keine Auferstehung: Ein getilgter Lock kann nie wieder im Index auftauchen.

### 5. Quota-Monotonie & Hard-Floor Schranken
* `ByteYears::from_ttl_seconds(s) >= 1` für alle $s \ge 0$.
* `effective_ncb >= 960_000` (Hard-Floor Baseline).
* Monotonie von Spread-Dämpfer ($[0.5, 1.0]$) und Whale-Brake ($K \le 5.0$).
