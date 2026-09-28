# 🧹 HuMoCo Layer 2 – Architectural Drift & Code Purge Audit-Bericht

> **Datum:** 2026-09-28  
> **Audit:** `18_legacy_code_and_architectural_drift_audit.md`  
> **Status:** `🟢 Clean (Subtraktionspotenzial identifiziert)`

---

## 📊 Zusammenfassung der Ergebnisse

1. **Tote DTOs:**
   - `LockSubmitRequest` und `LockSubmitResponse` in `crates/humoco-node/src/api/dto.rs` sind ungenutzte Phasen-0/1-Relikte und können gefahrlos getilgt werden.

2. **Dual-Path im Transport:**
   - `LockWirePayload::Sim` und rohe Tuple-Deserialisierungen in `transport.rs` sind alte Test-Relikte; die Produktion nutzt ausschließlich `LockWirePayload::Hmc`.

3. **Doku-Synchronisation:**
   - Entfernung alter Erwähnungen von stochastischem Receipt-Gossip ($p=0,02\%$) und Angleichung des `WireHeader`-Layouts in `docs/10`.
