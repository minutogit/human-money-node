# 🧪 HuMoCo Audit Report: Mutation Testing & Test Blind-Spot Audit

**Audit-ID:** 12 – Mutation Testing & Test Blind-Spot Audit  
**Datum:** 2026-09-29  
**Gegenstand:** `crates/humoco-sim-core/tests` & `crates/humoco-node/tests`  
**Status:** ✅ **BESTANDEN (17/17 Mutanten getötet – 100% KILLED 💀, 0 SURVIVED 🧟)**

---

## 1. 🔀 Operator Mutation (Grenzwerte & Off-By-One)
- Ingress-Fenster (`INV-1202` / `INV-1203`): `valid_until > now + 30s` und `root <= now + 11Y` Off-by-1 Mutanten zu 100% getötet.
- Quorum & BFT ($N<20$ vs $N\ge 20$, $\lfloor 2N/3 \rfloor + 1$): 100% getötet.
- Hard-Floor Baselines (`960_000 Byte-Years`, `50_000 Reads`): 100% getötet.

---

## 2. ✂️ Statement Deletion & Return Falsification
- Falsche Krypto-Signaturen (`verify -> true`): Sofort von negativen Signaturtests abgefangen.
- Atomic CAS Einfügungs-Unterdrückung: Sofort von RAM-Len und Ingress-Tests getötet.
- TTL SpentLockFilter Pruning-Auslassung: Sofort von Filter-Konsistenztests getötet.
- Disk-Pruning-Auslassung: Sofort von Redb-Prune-Tests getötet.

---

## 3. 🔍 Assertion Depth
- Keine Tautologien: Alle Tests prüfen explizite Felder (`id`, `parent_lock`, `receiver_pub`, `valid_until`) und deterministische Error-Enums (`RejectedCollision`, `RejectedCapacity`, `QuotaExceeded`).
