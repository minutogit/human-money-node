# 🧬 HuMoCo Layer 2 – Mutation Testing, Test-Güte & Free-Riding Audit-Bericht

> **Datum:** 2026-09-28  
> **Audits:** `12_mutation_testing_und_test_blindspot_audit.md` & `07_faulheit_und_free_riding_audit.md`  
> **Status:** `🟢 100% Mutation-Kill-Rate (14/14) | Free-Riding mathematisch mitigiert`

---

## 📊 Zusammenfassung der Ergebnisse

1. **Mutation Testing (14/14 getötet):**
   - M1-O1 bis M1-O9: Alle Operator- und Grenzwert-Mutationen (30s TTL Grace, Quorum 14/20, 960k Baseline Floor, Ringpuffer-Overwrites) werden durch Spezifikationstests und `mutant_kills.rs` zuverlässig erkannt und getötet.
   - M2-S1 bis M2-S6: Statement-Deletions (WAL Enqueue, Disk Pruning, Filter Delete, Replay-Cache Insertions) lassen die Testsuite sofort fehlschlagen.

2. **Silent Signers (Validation Free-Rider):**
   - Subjektives Tit-for-Tat setzt die Signer-Maske auf 0.
   - Nach 3 Fehlern wird der Knoten lokal suspendiert und der deterministische **Rang-21-Ersatzkandidat springt mit $0\,\text{ms}$ Latenz ein**.

3. **Storage Leech (Fremd-Locks löschen):**
   - Periodischer BFT 60s Digest-Pull vergleicht den 32-Byte `ShardDigest(S)`. Ein Leech-Knoten mit divergiertem Zustand wird isoliert.

4. **Empty Certificates & Bitmap-Tricks:**
   - Jedes Quorum-Zertifikat wird stateless dedupliziert und jede einzelne Attestierung kryptografisch gegen die Domain-Tags validiert. Leere oder manipulierte Bitmaps scheitern sofort.
