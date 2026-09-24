# 🪓 Audit 01 – Subtraktion & Vereinfachung (2026-09-24)

> **Datum:** 2026-09-24  
> **Modell:** `opencode/zen-3-pro` / `gemini-2.5-pro`  
> **Status:** `🟢 Clean` (0 offene Funde)  
> **Doktrin:** *"Subtraction before Construction – Perfection is achieved when there is nothing left to remove."*

---

## 🎯 Zusammenfassung & Durchgeführte Maßnahmen

In diesem Audit-Zyklus wurden die verbliebenen toten Codepfade, redundanten Allokationen und Duplikate auf dem Konsens- und Hot-Path systematisch bereinigt:

1. **Wire-Format Subtraktion:**
   - Entfernung der veralteten Nachrichtentypen `ShardMapPing (0x0005)` und `ShardMapPong (0x0006)` aus `crates/humoco-sim-core/src/wire.rs` und der 0-RTT Whitelist.
   - Bereinigung der P2P Wire-Format Dokumentation in `docs/10_p2p_wire_format_und_session_framing.md`.

2. **Hot-Path Memory & Allokations-Optimierung:**
   - `/v1/sync` (`crates/humoco-node/src/api/routes.rs`): Vollständiges Klonen der HMC-Lock-Map (`locks.clone()`) eliminiert. Der Read-Guard wird jetzt lokal gescopt und iteriert ohne globale Map-Allokation.
   - Ketten-Locking (`crates/humoco-node/src/storage/engine.rs::ingress_hmc_chain_lock`): Doppel-Klonen von `L2LockEntry` beim Einfügen in den RAM-Index und das MPSC-Persistence-Queueing vollständig entfernt (Einsparung von O(N) Allokationen pro Batch).

3. **Verifikation & Invarianten:**
   - 100 % aller Workspace-Tests (`cargo test --workspace`) und Clippy-Lints (`cargo clippy --workspace --all-targets -- -D warnings`) sind grün.
   - Alle Kern-Invarianten (`INV-1001` bis `INV-1009`, `INV-1201`, `INV-1501`) bleiben strikt gewahrt.
