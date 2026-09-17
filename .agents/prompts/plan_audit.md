# Plan-Audit & Architektur-Review Prompt

Dieser Prompt kann direkt verwendet werden, um eine KI (bzw. ein Team aus Subagenten) mit einem vollständigen Review der aktuellen Spezifikation zu beauftragen.

---

```markdown
Führe ein tiefgehendes Architektur-, Sicherheits- und Logik-Audit unserer aktuellen Planung durch.

### WICHTIGER SCOPE & ABGRENZUNG:
- **Prüfe ausschließlich die neue Planung** im Verzeichnis `docs/` (sowie die `README.md`).
- **Ignoriere das Verzeichnis `legacy-planing/` vollständig!** Das ist ein altes Referenzarchiv und nicht Teil der aktuellen Spezifikation.

### DEINE AUFGABE & PRÜFFOKUS:
Analysiere die neue Dokumentation entlang der folgenden 4 Kernbereiche:

1. **Radikale Vereinfachung (Occam's Razor & Leitfilter):**
   - Wo existiert noch unnötige Komplexität, Overengineering, redundanter State oder vermeidbarer Netzwerk-Sync?
   - Welche Mechanismen können gestrichen oder vereinfacht werden, ohne die Sicherheit zu gefährden?

2. **Konzeptionelle Lücken & Randfälle (Edge Cases):**
   - Gibt es ungelöste Grenzfälle bei Partitionen, Network Merges, TTL-Ablauf, Offline-Zuständen oder Reconnects?
   - Fehlen Spezifikationen für Fehlerbehandlung oder Timeouts?

3. **Logikfehler & Dokumenten-Inkonsistenzen:**
   - Gibt es Widersprüche zwischen den Dokumenten (z. B. zwischen Lock-Zustandsautomat, Wire-Format, Sharding, Dunbar-Gossip oder Persistenz)?
   - Stimmen die Typdefinitionen, Bit-Größen und Datenflüsse überall überein?

4. **Unbeachtete Angriffsvektoren & Spieltheorie:**
   - Welche byzantinischen Angriffe, Sybil-/Collusion-Szenarien, Timing-Attacks, Griefing- oder DoS-Vektoren wurden noch nicht bedacht?
   - Gibt es Wege, die First-Seen-Rule auszuhebeln oder die Point-of-Sale-Latenz (< 1000ms) zu brechen?

### METHODIK (SUBAGENTEN):
- Spawne/nutze parallele spezialisierte **Subagenten**, um die Themengebiete effizient und unabhängig voneinander zu analysieren (z. B. *Security/Attack-Vector-Auditor*, *Protocol-Logic-Auditor*, *Simplicity-Auditor*).

### ERGEBNIS:
- Konsolidiere alle Erkenntnisse in einem übersichtlichen, priorisierten Markdown-Dokument (`docs/audit_und_optimierungspotenziale.md` oder als Artefakt).
- Strukturiere das Dokument nach Kritikalität (Kritisch, Hoch, Mittel, Optimierung) mit konkreten, umsetzbaren Lösungsvorschlägen für jeden Punkt.
```
