# 🧹 HuMoCo Layer 2 – Audit 18: Legacy Code, Prototyp-Relikte & Architektur-Drift Report

**Datum:** 2026-09-29  
**Audit-ID:** AUDIT-18-LEGACY-CODE-ARCHITECTURAL-DRIFT  
**Scope:** `crates/humoco-sim-core`, `crates/humoco-node` & `docs/`  
**Auditor:** Legacy Code & Drift Auditor (Parallel Subagent)  
**Status:** **ANALYZED & PURGED (5/5 Drift-Filter Geprüft)**

---

## Executive Summary

Die Prüfung auf veraltete Prototypen, tote Wire-Nachrichten und Dokumentations-Drifts ergab:
- **Konsens & P2P:** Vollständig synchronisiert auf Spec 03 (Digest-Pull Sync) und Spec 06 (Shard-Direct RPC), 0% Lock-Gossip.
- **Identifizierte Relikte:**
  1. Totes Struct `LockEnvelope` in `crates/humoco-sim-core/src/wire.rs` (ungenutzt).
  2. Ungenutzte Wire-Flags (`FLAG_EXPIRED_CLEANUP`, `FLAG_COMPRESSED`, `FLAG_BRIDGE_LOCK`, `FLAG_PEER_SUSPENDED`).
  3. Doppelter Fallback-Pfad `(LockRecord, u64)` in `transport.rs:350-391` zugunsten von `LockWirePayload::Hmc`.
  4. Dokumentations-Drift in `docs/15_p2p_transport_and_connection_management.md` bzgl. altem `ShardMapPing (0x0005)`.

---

## 🪓 Bereinigungs-Maßnahmen
1. **Löschung von `LockEnvelope`:** Entfernen des toten Structs aus `wire.rs`.
2. **Entfernen ungenutzter Flags:** Bereinigen der Flag-Konstanten in `wire.rs`.
3. **Vereinfachung in `transport.rs`:** Bereinigen des 3. Deserialisierungs-Fallbacks.
4. **Dokumentations-Update:** Bereinigen von veralteten Ping/Pong-Referenzen in `docs/15`.
