# 🛡️ HuMoCo Layer 2 – Audit 11: Time-Warp, Uhren-Manipulation & Pruning-Angriffe

**Datum:** 2026-09-29  
**Audit-ID:** AUDIT-11-TIME-WARP-CLOCK-MANIPULATION  
**Scope:** `crates/humoco-sim-core` & `crates/humoco-node`  
**Auditor:** Time-Warp & Clock Auditor (Parallel Subagent)  
**Status:** **PASSED / HARDENED (5/5 Zeit-Szenarien Verifiziert)**

---

## Executive Summary

Die Zeit-Architektur von HuMoCo Layer 2 widersteht deterministisch Zeitmanipulationen, NTP-Hijacking und Pruning-Angriffen.

| # | Bedrohungsszenario | HuMoCo Schutzmechanismus & Invariante | Status |
|---|---|---|:---:|
| **1** | **Vorzeitiger Löschangriff (+1Y)** | Isolierter Self-DoS; ehrliche Shard-Peers lehnen verkürzten Digest ab | ✅ **RESISTENT** |
| **2** | **F2F Median-Clock Schutz** | WoT-Gating, $\pm 15\,\text{min}$-Clamping, lock-freie CAS-Monotonie | ✅ **RESISTENT** |
| **3** | **Ingress Window Bypass** | `now + 30s < valid_until <= root.valid_until <= now + 11Y` (`INV-1202`) | ✅ **RESISTENT** |
| **4** | **Reanimation abgelaufener Locks** | Mathematisch unmöglich, da `root.valid_until` abgelaufen ist | ✅ **UNMÖGLICH** |
| **5** | **Zero State Bloat** | Physische Tilgung nach 30s Grace-Period ohne permanente Tombstones | ✅ **KONFORM** |

---

## 1. Premature Pruning via Clock Fast-Forward
* Ein lokaler Vorwärtssprung der Systemzeit löscht nur den eigenen lokalen Speicherbestand.
* Da kein Lock-Gossip existiert, bleibt das P2P-Netz unberührt. Der Knoten wird beim Digest-Pull (Spec 03) als 1/20-Outlier erkannt.

## 2. F2F Median-Clock Schutz
* `NetworkClock` ignoriert Zeit-Samples von Nicht-F2F-Knoten und clampt logische Offsets auf $\pm 15\,\text{Minuten}$.
* Monotonie-Schutz verhindert Zeitrückwärtssprünge.

## 3. Ingress Window & Reanimationsschutz
* Ingress-Fenster-Validierung (`now + 30s < valid_until <= root.valid_until`) schützt vor manipulierten Client-Zeitstempeln.
* Ein abgelaufener Voucher kann niemals als neuer Lock wiedergeboren werden.
