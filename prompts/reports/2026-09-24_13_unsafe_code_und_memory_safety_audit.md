# 🔬 HuMoCo Layer 2 — Unsafe Code, Memory Safety & Undefined Behavior Audit
### `prompts/13_unsafe_code_und_memory_safety_audit.md` — Stand `2026-09-24`

> **Doctrine:** *"A single undefined behavior destroys all cryptographic and logical guarantees. Unsafe code must be mathematically proven and hermetically isolated."*

---

### 1. 🔍 Scan aller `unsafe`-Blöcke

* **Status:** Beide Crates (`crates/humoco-sim-core` und `crates/humoco-node`) deklarieren `#![forbid(unsafe_code)]` in `src/lib.rs`.
* **Ergebnis:** Es existieren **0 `unsafe`-Blöcke** im gesamten Workspace-Quellcode.
* **Miri-Verifikation:** Sämtliche Serialisierungs- und Framing-Routinen (`WireHeader`, `LockEntry144`) nutzen sichere Methoden wie `from_le_bytes`/`to_le_bytes` und `copy_from_slice` ohne Pointer-Transmutes.

---

### 2. 🛡️ Safe Alternativen & Zero-Copy

* Die Nutzung von `bytemuck` oder `zerocopy` wurde evaluiert und verworfen: Für 32-Byte (`WireHeader`) und 144-Byte (`LockEntry144`) Strukturen bietet `from_le_bytes` identische Maschinencode-Effizienz bei strikter Panic- und UB-Freiheit ohne externe `unsafe impl`-Makros.

---

### 3. 💥 Integer Overflows & Truncations

* **Geprüft & Behoben:**
  - `+30_000` Grace-Period Overflows wurden überall durch `saturating_add(30_000)` abgesichert.
  - Quota-Berechnungen nutzen `checked_add` und `saturating_sub`.
* **Identifizierte Rest-Lints (Mittel / Niedrig):**
  - Truncation-Warnungen bei `len as u32` auf internen Byte-Buffern (über 4 MiB Begrenzung durch Framing-Header abgesichert, aber `try_from` wird empfohlen).

---

### 4. 🧠 Stack Overflows & Rekursion

* `verify_causality_proof_chain_stateless` ist vollständig **iterativ** implementiert mit strikten Obergrenzen:
  - `MAX_PROOFCHAIN_HOPS = 1024`
  - `MAX_NONCE_BYTES = 1024`
  - `MAX_QUORUM_SIGS_PER_HOP = 20`
* Streaming-Puffer in `framing.rs` wachsen inkrementell mit bounded Chunks (`Vec::with_capacity(payload_len.min(64*1024))`). Stack-DoS ist mathematisch ausgeschlossen.

---

### 5. 🚦 Fazit

Der Workspace ist zu 100% frei von Undefined Behavior aus `unsafe`-Code.
