# 🛡️ HuMoCo Layer 2 – Sicherheitsaudit: Node Hack & Post-Breach Containment

> **Datum:** 2026-09-28  
> **Audit:** `09_knoten_hack_und_key_compromise_audit.md`  
> **Status:** `🟢 Clean (Mathematisch $0 Verlust / O(1) Selbstbann)`

---

## 📊 Zusammenfassung der Ergebnisse

1. **Kundengeld-Verlust ($0.00):**
   - Der Server ist semantisch blind (kennt keine Kontostände, Guthaben oder Klarnamen).
   - Locks erfordern die Signatur des Gutscheininhabers (`sender_ephemeral_pub`). Ein gekaperter Knotenschlüssel (`node_key.bin`) kann keine Nutzersignaturen fälschen.

2. **Equivocation-Selbstvernichtung:**
   - Signiert der Angreifer mit dem gestohlenen Schlüssel widersprüchliche Attestationen, erzeugt das Netzwerk via `resolve_split_brain_with_proof` in $O(1)$ einen unbestreitbaren `FraudProofPayload`.
   - Alle QUIC-Verbindungen werden sofort geschlossen, die `NodePubKey` wird netzweit gebannt, das Argon2d-Shard-Ticket entwertet und alle F2F-Kanten gekappt.

3. **Key-Revocation:**
   - Der rechtmäßige Betreiber kann mit seinem Mnemonic-Backup offline einen Selbst-Equivocation-Beweis erstellen und den gekaperten Schlüssel innerhalb von Sekunden unbrauchbar machen.
