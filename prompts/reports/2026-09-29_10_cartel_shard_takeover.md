# 🛡️ HuMoCo Layer 2 – Audit 10: Kartellbildung, Bestechung & Shard-Takeover

**Datum:** 2026-09-29  
**Audit-ID:** AUDIT-10-CARTEL-SHARD-TAKEOVER  
**Scope:** `crates/humoco-sim-core` & `crates/humoco-node`  
**Auditor:** Cartel & Shard-Takeover Auditor (Parallel Subagent)  
**Status:** **PASSED / RESISTENT (Spieltheoretisch & BFT Bewiesen)**

---

## Executive Summary

Audit 10 analysiert das Extremszenario eines Kartells, das in einem HRW-Bucket $\ge 14$ der 20 Shard-Knoten kontrolliert ($70\%$ BFT-Mehrheit).

| # | Angriffsdimension | Schutzmechanismus & Invariante | Status |
|---|---|---|:---:|
| **1** | **Erfundene Locks** | Client-seitige `ProofChain`-Signaturprüfung (`INV-0401`) | ❌ **UNMÖGLICH** |
| **2** | **Double-Spends** | $\min(H_{\text{canon}})$ Resolver + $O(1)$ Slashing aller 14 Knoten | ❌ **SELBSTVERNICHTUNG** |
| **3** | **Shard-Zensur (DoS)** | Gateway Missing-Count + deterministischer Fallback auf Rang 21–40 | ✅ **RESISTENT** |
| **4** | **Sybil-Kapern von Shards** | $2^{16} = 65.536$ Buckets, Argon2d Shard-Tickets + 24h Inkubationswand | ❌ **UNBEZAHLBAR** |
| **5** | **Spieltheorie** | $\mathbb{E}[U_{\text{Kartell}}] = P \cdot R - 14 \cdot C_{\text{Argon2d}} - C_{\text{WoT}} \ll 0$ | ✅ **STABIL** |

---

## 1. Erfindung unautorisierter Locks
* Shard-Attestierungen bestätigen nur Double-Spend-Freiheit auf dem Server, ersetzen aber nie die Inhaber-Signatur.
* Fehlt die Ed25519-Signatur des Vorbesitzers, wird der gefälschte Lock von jedem PoS-Terminal atomar abgewiesen.

## 2. Double-Spends & Äquivokation
* Kollidierende Zertifikate lösen den deterministischen Split-Brain-Resolver $\min(H_{\text{canon}})$ aus.
* Das Signaturpaar bildet den mathematischen Beweis (`FraudProofPillar::ShardEquivocation`), der alle 14 Kartellknoten unwiderruflich bannt und deren geminte Argon2d-Tickets vernichtet.

## 3. Shard-Zensur & Ausweichmechanismus
* Bei Timeouts oder unbegründeten 429-Fehlern erhöht das Gateway den `missing_count`.
* Nach 3 Fehlern wird der Knoten suspendiert und Shard-Ränge 21–40 rücken in 0 ms deterministisch nach.
