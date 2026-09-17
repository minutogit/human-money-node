# 🛡️ HuMoCo Audit Report: Byzantine Security & Hardening

> **Datum:** 2026-09-15  
> **Auditor / Modell:** `opencode/muse-spark-1.2-contributor-free` (via KI-Model-Router)  
> **Prompt-ID:** 02 (`02_security_und_byzantine_hardening.md`)  
> **Workspace-Status:** `cargo test --workspace` als Referenz geprüft, Patches gegen Invarianten `INV-0403/1003/1201/1302/1401` validiert.

---

### 1. Double-Spend & CAS Race (Spec 02, 12)

- **[MEDIUM] `crates/humoco-node/src/storage/engine.rs:422-470` + `crates/humoco-node/src/api/routes.rs:308` — TOCTOU Snapshot für PoW-Replay Idempotenz**
  - Vorab-Snapshot in routes.rs:308 bei zwei parallelen QUIC-Requests mit identischem Parent/ID kann zu Race im PoW-Cache führen.
- **[LOW] `crates/humoco-sim-core/src/storage.rs:79-85` + `crates/humoco-node/src/storage/engine.rs:121-126` — TTL-Bucket Bereinigung bei `replace_lock`**
  - Altes Bucket bei `replace_lock` säubern, um Phantom-Einträge zu vermeiden.
- **Positiv:** `DualTierEngine::ingress_lock_with_origin:439` hält `self.ram.write().await` über `try_insert` + `resolve_split_brain` + `replace_lock` → CAS ist `<1µs` atomar. `Reservation-First` via `tx.try_reserve()` verhindert RAM-Verschmutzung bei voller Queue (`RejectedCapacity/429`).

---

### 2. Crypto Domain Separation & Preimage (Spec 04, 10)

- **[CRITICAL] `crates/humoco-sim-core/src/wire.rs:221-227` — `derive_account_tag` ohne Längenpräfix**
  - Aktuell: `hasher.update(b"HUMOCO_V1_ACCOUNT_TAG");` (INV-0403 verletzt).
  - Patch:
    ```rust
    hasher.update(&[b"HUMOCO_V1_ACCOUNT_TAG".len() as u8]);
    hasher.update(b"HUMOCO_V1_ACCOUNT_TAG");
    ```
- **[HIGH] `crates/humoco-sim-core/src/wire.rs:281-320` — `AccessControl::verify_pow` / `pow_challenge` ohne Längenpräfix**
  - `hasher.update(b"HUMOCO_V1_POW");` und `b"HUMOCO_V1_CHALLENGE"` ebenfalls auf Längenpräfix bringen.
- **[MEDIUM] `crates/humoco-node/src/ingress/pow.rs:43-50` — Inkonsistente Längen-Kodierung**
  - `&(tag.len() as u8).to_le_bytes()` vs `&[len]`.

---

### 3. 3-Tier Ingress & Botnet Brake (Spec 13)

- **[CRITICAL] `crates/humoco-node/src/ingress/pow.rs:209-226` — Race im Replay-Cache**
  - Zwei parallele Tasks mit gleichem `challenge:nonce` prüfen `contains_key`, droppen Lock, hashen und inserieren anschließend.
  - Patch: Replay-Cache unter Lock atomar prüfen und inserieren / reservieren.
- **[HIGH] `crates/humoco-node/src/ingress/tier.rs:257` + `crates/humoco-node/src/ingress/pow.rs:128-136` — Schwierigkeits-Bypass**
  - `evaluate_and_charge` verifiziert immer mit `self.pow_engine.default_difficulty()`, dynamische Last-Schwierigkeit (`required_difficulty_for_load`) wird nicht an `verify_pow_for_parent` durchgereicht.
- **[HIGH] `crates/humoco-sim-core/src/quota.rs:412` + `crates/humoco-node/src/ingress/tier.rs:153-165` — Integer Overflow vor Quota-Check**
  - `*current_usage + footprint_byte_years <= quota_byte_years` kann bei `current_usage ≈ u64::MAX` wrappen.
  - Patch: `checked_add`.

---

### 4. DoS & Memory Exhaustion

- **[HIGH] `crates/humoco-node/src/network/framing.rs:87-96` + `crates/humoco-node/src/network/transport.rs:13` — 4 MiB * 1024 Streams = 4 GiB OOM-Potenzial**
  - `MAX_SYNC_FRAME_PAYLOAD_LEN = 4*1024*1024` mit 1024 Streams. Chunks auf z.B. 256 KiB begrenzen oder Framing-Budget drosseln.
- **[HIGH] `crates/humoco-node/src/control/server.rs:129-148` — UDS Slowloris / Unbounded `read_line`**
  - `buf_reader.read_line(&mut line)` liest bis `\n`, Check auf 16 KiB erst danach. Angreifer ohne `\n` kann Puffer aufblähen.
  - Patch: `(&mut buf_reader).take(16 * 1024 + 1).read_line(&mut line)`.

---

### 5. Split-Brain & Equivocation Proofs (Spec 08, 10)

- **[HIGH] `crates/humoco-node/src/storage/engine.rs:558-582` — Ban ohne Signatur-Verifikation (Framing-Risiko)**
  - Bei `ingress_hmc_lock_with_origin` vor Ban beiderseitige Signaturen verifizieren (`verify_l2_lock_signature`), um First-Party Evidence sicherzustellen.
- **[HIGH] `crates/humoco-node/src/network/transport.rs:91-121` — `verify_equivocation_first_party` Fallback auf deterministische Fake-Sig**
  - `|| humoco_sim_core::crypto::verify_attestation(att)` entfernt strikte Ed25519-Signaturprüfung. Strikt echte Ed25519-Signaturen verlangen.

---

### Zusammenfassung & Priorisierung

| Schwere | Datei:Line | Beschreibung |
|---|---|---|
| **CRITICAL** | `wire.rs:221` | Domain-Tag Längenpräfix |
| **CRITICAL** | `pow.rs:209` | Replay-Cache Race |
| **HIGH** | `tier.rs:257` | Dynamische Difficulty Durchreichung |
| **HIGH** | `quota.rs:412` | Checked Add Quota Overflow |
| **HIGH** | `framing.rs:8` | Framing Max Payload Bounds |
| **HIGH** | `control/server.rs:133` | UDS Bounded Line Read |
| **HIGH** | `engine.rs:558` | Ban First-Party Evidence Signature Verification |
| **HIGH** | `transport.rs:117` | Fallback Fake-Sig in Equivocation entfernen |
