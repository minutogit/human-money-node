# 🔬 HuMoCo Audit Report: Unsafe Code, Memory Safety & Undefined Behavior

> **Datum:** 2026-09-15  
> **Auditor / Modell:** `opencode/muse-spark-1.2-contributor-free` (via KI-Model-Router)  
> **Prompt-ID:** 13 (`13_unsafe_code_und_memory_safety_audit.md`)  
> **Workspace-Status:** `cargo test --workspace` grün (28 Suites ok).

---

### 1. Scan aller `unsafe`-Blöcke

**Befund: 0 produktive `unsafe`-Blöcke im gesamten Workspace.**

```bash
grep -rn "unsafe" crates --include="*.rs"
# -> nur crates/humoco-sim-core/src/lib.rs:1  #![forbid(unsafe_code)]
grep -P "(unsafe|transmute|copy_nonoverlapping|read_unaligned|\*const|\*mut)" crates/humoco-node/src --include="*.rs"
# -> 0 Treffer
```

| Ort | Status |
|---|---|
| `crates/humoco-sim-core/src/lib.rs:1` | `#![forbid(unsafe_code)]` – jeder zukünftige `unsafe`-Block führt zu Compiler-Fehler. Hermetisch versiegelt. |
| `crates/humoco-sim-core/src/wire.rs:1-386` | **0** `unsafe`. `WireHeader::from_bytes`/`to_bytes` rein safe. |
| `crates/humoco-node/src/lib.rs:1` | **Kein** `forbid(unsafe_code)` – Lücke in Deklarations-Parität. Sonst 0 `unsafe`. |
| `crates/humoco-node/src/network/framing.rs:1-273`, `transport.rs:1-1100`, `storage/engine.rs:1-830` | **0** `unsafe`. |
| `docs/10_p2p_wire_format_und_session_framing.md:548` | Dokumentiertes Anti-Pattern `let header: &WireHeader = unsafe { &*(raw.as_ptr() as *const WireHeader)}` – nicht kompiliert, nur Illustration. |

**Safety-Invarianten-Prüfung:**
- `align_of::<WireHeader>() == 8`: Safe Decoding über `u16::from_le_bytes`/`u64::from_le_bytes` benötigt kein Alignment.
- `copy_from_slice`: Validiert Slice-Längen typbasiert.
- Keine Aliasing-Verletzungen.

---

### 2. Safe Alternativen & Zero-Copy

- Aktuelle Implementierung (`wire.rs:49-78`, `wire.rs:138-167`) ist 100% safe ohne Performanceverlust (`from_le_bytes`, `to_le_bytes`, `copy_from_slice`).
- Keine externen Crates wie `zerocopy` oder `bytemuck` nötig (Subtraktion vor Konstruktion).
- Streaming Frame Allocation: `framing.rs` begrenzt Allokation inkrementell (`min(64*1024)` vor `take`).

---

### 3. Integer Overflows & Truncation

- **T1 – `+30_000`:** Bereits mit `saturating_add` gesichert in `sim-core` und `engine.rs`.
- **T2 – Silent Truncation `len as u32` auf Netzwerk-Pfad (⚠️ Mittel / CWE-197):**
  - Stellen in `crates/humoco-node/src/network/transport.rs` (`resp_bytes.len() as u32`), `crates/humoco-node/src/api/routes.rs`, `crates/humoco-node/src/api/hmc.rs`.
  - Empfehlung: Sicheres Parsing via `u32::try_from(len)`.
- **T3 – `tag.len() as u8`:** Kleiner Clippy-Befund, praktisch unkritisch da statische Konstanten.

---

### 4. Stack Overflows, Rekursion & Amplification

- **Rekursion:** 0 rekursive Aufrufe auf dem Hot Path. ProofChain-Traversierung ist strikt iterativ.
- **Amplification / DoS-Potenzial (CWE-770):**
  - `CausalityProofChain.hops: Vec<ProofChainHop>` hat bisher keine Obergrenze in `verify_causality_proof_chain_stateless`.
  - Empfehlung: Obergrenzen wie `MAX_PROOFCHAIN_HOPS = 128`, `MAX_NONCE_BYTES = 1024` und `MAX_QUORUM_SIGS_PER_HOP = 20`.

---

### 5. Konkrete Maßnahmen

1. `crates/humoco-node/src/lib.rs:1`: `#![forbid(unsafe_code)]` ergänzen.
2. `u32::try_from` bzw. `checked_payload_len` für Payload-Längen statt `len as u32`.
3. Bounded Limits für `ProofChain` in `crates/humoco-sim-core/src/types.rs`.
