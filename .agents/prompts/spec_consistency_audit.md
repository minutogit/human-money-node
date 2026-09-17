# Spezifikations-Konsistenz & Widerspruchs-Audit Prompt

Dieser Prompt dient dazu, alle Spezifikations-Dokumente im Verzeichnis `docs/` und die Rust-Implementierung in `crates/humoco-sim-core/` regelmäßig auf Widersprüche, veraltete Textstellen und Diskrepanzen zu durchsuchen, um die Spezifikation kontinuierlich zu härten.

---

## 1. Direkter Aufruf über Model-Router (CLI)

```bash
model-router run \
  "[ZIEL]: Analysiere alle Spezifikations-Dokumente im Ordner 'docs/' sowie den Code in 'crates/humoco-sim-core/' auf Widersprueche, Unstimmigkeiten und veraltete Annahmen, die im Laufe der Entwicklung entstanden sind. \
   [AUFGABE]: \
   1. Lies und vergleiche alle Markdown-Dateien in 'docs/' (00 bis 19, 99, etc.) untereinander und mit der tatsaechlichen Rust-Implementierung. \
   2. Identifiziere logische Widersprueche zwischen frueheren Entwuerfen und spaeteren Spezifikationen (z.B. Routing, Quorum, Lock-Lebenszyklus, Admissions/WoT, Ingress, Hysterese, Sharding). \
   3. Finde veraltete Textstellen, deprecated Mechanismen oder ueberholte Konzepte, die bereits geklaert oder durch neuere Loesungen ersetzt wurden. \
   4. Finde Diskrepanzen zwischen der Dokumentation und dem Code. \
   5. Erstelle einen detaillierten, strukturierten Analysebericht auf Deutsch mit genauen Dateiverweisen, Zeilen-/Abschnittsangaben, dem festgestellten Widerspruch und einer Handlungsempfehlung zur Bereinigung." \
  -m muse \
  --dir .
```

---

## 2. Reusable Prompt-Vorlage (für LLM / Subagenten)

```markdown
Führe ein tiefgehendes Konsistenz-, Widerspruchs- und Aktualitäts-Audit unserer Spezifikation und Implementierung durch.

### SCOPE & DATEIEN:
- Alle Dokumente unter `docs/` (`docs/00_...` bis `docs/19_...`, `docs/99_...`, `docs/audit_...`, etc.)
- Die `README.md`
- Die Rust-Referenzimplementierung unter `crates/humoco-sim-core/`

### PRÜFFOKUS:
1. **Widersprüche zwischen Spezifikations-Dokumenten:**
   - Wo widersprechen sich frühe Architektur-Docs (z. B. 00–04) und spätere Vertiefungsdokumente (z. B. 08, 11, 15, 18, 19)?
   - Gibt es uneinheitliche Quorum-Formeln, divergierende Timing-Werte (z. B. PoS-Latenz, TTLs, Heartbeats) oder unterschiedliche Ingress-/Gossip-Regeln?

2. **Veralteter Text & Überholte Konzepte:**
   - Welche Mechanismen wurden in früheren Phasen angedacht, sind aber durch neuere Entscheidungen (z. B. Dumb Server / Smart Client, Asymmetrische Bürgschaften, Hysterese-Merges) überholt?
   - Wurden alte Bezeichnungen oder deprecated Datenstrukturen an manchen Stellen vergessen zu bereinigen?

3. **Diskrepanzen zwischen Spezifikation und Rust-Code:**
   - Stimmen Wire-Formate, Enums, Zustandsautomaten und Struct-Felder in `crates/humoco-sim-core/` 1:1 mit der Doku überein?
   - Wo weicht die tatsächliche Implementierung von der Doku ab (oder umgekehrt)?

4. **Klarheit & Terminologie:**
   - Welche Begriffe werden mehrdeutig oder inkonsistent verwendet?

### ERGEBNIS-FORMAT:
Erstelle einen detaillierten, priorisierten Bericht mit:
- **Betroffene Dateien & Abschnitte** (inkl. Verlinkung / Pfad)
- **Problembeschreibung** (Warum liegt hier ein Widerspruch / veralteter Text vor?)
- **Konkrete Handlungsempfehlung** (Wie der Text bzw. Code exakt angepasst werden sollte)
```
