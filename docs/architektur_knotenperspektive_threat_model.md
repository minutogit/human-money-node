# Architektur- & Bedrohungsmodell-Audit aus Knotenperspektive (Makro / Threat Model & Gap Analysis)

> **Status:** Audit-Bericht — Informativ / Handlungsempfehlend  
> **Scope:** Knoten-Lifecycle (Eintritt → Betrieb → Austritt/Bestrafung → Merge) für HuMoCo Layer-2 Sperrregister  
> **Analysierte Dokumente:** `docs/00` `docs/01` `docs/02` `docs/03` `docs/05` `docs/07` `docs/08` `docs/09` `docs/10` `docs/11` `docs/17` `docs/99` sowie Querverweise `docs/04` `docs/06` `docs/12` `docs/13` `docs/14` `docs/15` und Vor-Audit `docs/audit_und_optimierungspotenziale.md`  
> **Datum:** 2026-08-29 | **Perspektive:** Einzelner Node als autonomer Akteur im P2P-Mesh (kein globaler Observer)  
> **Credo geprüft:** *„In der Dezentralität gibt es kein Vertrauen, nur mathematische Beweise.“*

---

## Inhaltsverzeichnis

1. [Executive Summary](#1-executive-summary)
2. [Methodik & Audit-Prinzipien](#2-methodik--audit-prinzipien)
3. [Knoten-Eintritt & Admission Lifecycle](#3-knoten-eintritt--admission-lifecycle)
4. [Knoten-Betrieb & Shard-Zuständigkeit](#4-knoten-betrieb--shard-zuständigkeit)
5. [Knoten-Austritt, Ausfall & Bestrafung (Churn & Eviction)](#5-knoten-austritt-ausfall--bestrafung-churn--eviction)
6. [Netzwerk-Merge & Split-Brain](#6-netzwerk-merge--split-brain)
7. [Systemische Lücken, Angriffsvektoren & Spezifikationsbedarfe](#7-systemische-lücken-angriffsvektoren--spezifikationsbedarfe)
8. [Priorisierte Handlungsempfehlungen (Roadmap)](#8-priorisierte-handlungsempfehlungen-roadmap)
9. [Anhang A — Invarianten-Mapping](#anhang-a--invarianten-mapping)
10. [Anhang B — Querverweise & File-Line-Index](#anhang-b--querverweise--file-line-index)
11. [Prägnante Zusammenfassung](#prägnante-zusammenfassung)

---

## 1. Executive Summary

Das HuMoCo Layer-2 Sperrregister ist architektonisch ausgereift: **Dumb Server / Smart Client** (`docs/06:10-28`), **statisches HRW-Sharding** (`docs/03:10-27`), **semantische Blindheit** (`docs/00:32-36`), **bio-mimetischer Dunbar-Gossip** (`docs/11`) und **3-Säulen-Slashing** (`docs/10:357-393`, `docs/05:28-38`) bilden ein kohärentes, fraktal skalierendes System (`docs/08:12-26`, `docs/05:94-120`). Die Trennung **F2F-Gossip-Overlay vs. Direct Co-Shard QUIC Mesh** (`docs/01:52-101`) ist eine tragende Sicherheitsentscheidung.

**Kernaussage aus Knotenperspektive:** Der einzelne Knoten ist **nie globaler Schiedsrichter**, sondern lokaler, stochastisch informierter Teilnehmer. Alle kritischen Entscheidungen (Quorum, `FINAL`, Thermometer, Präsenz) müssen daher **lokal deterministisch und partitionstolerant** berechenbar sein — sonst divergieren zwei ehrliche Knoten.

**Gesamtbeurteilung:** 5/5 Kernmechanismen sind robust, aber **4 konsens-kritische Spezifikations-Divergenzen** (Domain-Separation, Signatur-Aggregation, Quorum-Formel, `FINAL`-Hysterese) können bei `N≈10..20` zu divergierenden Implementierungen und damit zu wirtschaftlichem Schaden führen. Dazu kommen **5 Härtungslücken im Churn/Merge-Pfad**, die aus Knotensicht Liveness und Fairness bedrohen.

| Kategorie | Befund | Kritikalität |
| :--- | :--- | :--- |
| **Konsens** | Zwei konkurrierende `SignPreimage`-Definitionen (`docs/10:174` vs `docs/03:177`/`docs/08:59`) — Class-Swapping `PROVISIONAL→FINAL` möglich | **Kritisch** |
| **Konsens** | BLS (96B) vs. Ed25519 (64B) ohne PoP — `signer_bitmap` fälschbar ohne `proof-of-possession` (`docs/04:64`) | **Kritisch** |
| **Konsens** | `Q(R)` divergiert: `floor(2R/3)+1` vs `ceil(2R/3)+1` — 1 Stimme entscheidet bei `R=10` über Gelb/Grün (`README:22` vs `docs/00:96`) | **Kritisch** |
| **Konsens** | `FINAL (0x01)` hat 3 Definitionen: sofort `N≥20 && ≥14` (`docs/02:70`) vs 24h-Hysterese (`docs/08:46-60`) — Hot Path gibt evtl. falsches Grün | **Kritisch** |
| **Routing** | `Shard_ID` Off-by-One `[0..2]` (3 Bytes) vs `u16::from_be_bytes([0],[1])` (`docs/03:14` vs `docs/04:248`) — Gateway und Shard routen auseinander | **Kritisch** |
| **Liveness** | Merge `<500ms` vs reale 8h/24h Präsenz-Hysterese (`docs/08:72` vs `docs/11:171`, `docs/07:58-61`) — falsche PoS-Erwartung | **Hoch** |
| **Liveness** | `IMMATURE 24h + 8 Heartbeats` + Dunbar-RED + `epoch+±60s` Frischefilter → Heartbeat-Zensur überlasteter Brücke möglich | **Hoch** |
| **Liveness** | `DORMANT` Fast-Re-Entry 2 Heartbeats vs Flapping/HRW-Thrashing — kein Rate-Limit | **Hoch** |
| **Sicherheit** | `session_seq` per-Connection ↔ globaler `epoch_seq` Kollision → fälschlicher Säule-1-Beweis bei parallelem Shard-Broadcast (`docs/10:62-64`, `docs/10:295-309`) | **Hoch** |
| **Ressource** | `persist_tx: mpsc::Sender<StoredLock>` unbounded, `TABLE_ACTIVE_LOCKS` ohne TTL-Bucket — OOM/Disk-Stall (`docs/12:83-87`, `docs/14:107-111`) | **Hoch** |
| **Systemisch** | Time-Jacking / NTP-Drift: ±60s Frischefilter + `valid_until -30s` + `current_anl_24h` EMA ohne deterministische Definition (`docs/11:129-132`, `docs/12:40`, `docs/10:312`) | **Mittel-Hoch** |

> Hinweis: Viele dieser Punkte wurden bereits im Vor-Audit `docs/audit_und_optimierungspotenziale.md:22-149` als K-01..H-10 identifiziert. Dieses Dokument vertieft sie **aus Knotenperspektive** und ergänzt Heartbeat-Zensur, Churn-Ökonomie und Merge-Semantik.

---

## 2. Methodik & Audit-Prinzipien

**Makro-/Knotenperspektive** bedeutet: Wir bewerten nicht das „globale Netzwerk“ als Gott-Perspektive, sondern fragen für jede Regel: *Was sieht, speichert und entscheidet ein einzelner Node A mit Grad `d`, lokaler Liste `N_local` und unvollständiger Sicht?*

- **Logic & State Graph First** (`docs/00`-`docs/17` Doktrin): State-Automaten (`NodePresence`, Lock-Automat) vor Code.
- **STRIDE-light pro Lifecycle-Phase:** Spoofing (PoW/WoT), Tampering (Equivocation), Repudiation (Slashing-Beweise), Information Disclosure (Shard/Phoneix), DoS (Dunbar-RED, Argon2-Pool), Elevation (Shard-Preemption).
- **Partition als Normalfall:** Dorf-Merge (`docs/01:40-46`, `docs/08:68-83`) ist kein Edge-Case, sondern Gründungsmodus.
- **Verifikation:** Jede Aussage referenziert `file:line` + `INV-*`. Widersprüche zwischen Dokumenten werden als potenzielle Konsens-Splits gewertet.

---

## 3. Knoten-Eintritt & Admission Lifecycle

### 3.1 Argon2id PoW & Genesis Hash T₀

**Spezifikation:**
- `NodeID = Argon2id(PubKey_Ed25519 || Nonce || T₀)` — `docs/07:14` (`INV-0701`), `GENESIS_ROOT = BLAKE3("HuMoCo-L2" || VERSION_U32 || T₀)` — `docs/01:14`, `docs/04:226-231`.
- Parameter: `1–2 GB, 120–240 Iterationen, p=4, 1–3h` für Node-ID (`docs/07:19-26`), einmalig; Tier-3 Ingress-Challenge `2–4 MB, t=1, p=1, 50–150ms` (`docs/07:23`, `docs/13:114-128`).

**Stärken aus Knotensicht:**
- Hardware-Prägung bindet reale Energie — **HRW-Grinding** (`docs/05:A6`, `docs/99:194-207`) wird astronomisch teuer (10k Versuche = Jahre). Ein ehrlicher Raspi-Betreiber zahlt einmalig 1–3h, danach `O(1)` Verifikation (`<50µs` Ed25519-Vorfilter `docs/13:142`).
- Deterministischer `T₀`-Nullpunkt verhindert „Master-Key“-Zentralisierung (`INV-0101`).

**Lücken & Bedrohungsmodell:**

| ID | Vektor | Beschreibung | Einordnung |
| :--- | :--- | :--- | :--- |
| **E-01** | `T₀` Malleability & Domain-Separation | `calculate_genesis_root` (`docs/04:226`) nutzt `hasher.update(b"HuMoCo-L2")` ohne Längenpräfix. Analog `H_canon = BLAKE3("HUMOCO_V1_CANON_RESOLVER"||...)` (`docs/04:238`). Wie in `audit: K-01` gezeigt, ermöglicht fehlendes `len(domain_tag)` Präfix-Kollisionen. | **Kritisch** — zwei Binaries mit gleichem `T₀` aber unterschiedlicher String-Kodierung divergieren beim `GENESIS_ROOT`. Muss normiert werden: `BLAKE3(len||tag||VERSION_le||T₀_le)` plus Registry `HUMOCO_V1_GENESIS`. |
| **E-02** | Argon2id Parameter-Fixierung | `docs/07:19` gibt Bereich `1–2 GB / 120–240 Iter` an, aber kein kanonischer Wert. Knoten A mit `1 GB` akzeptiert PoW von Knoten B mit `2 GB` — oder umgekehrt? Verifikation muss exakt einen Parametersatz prüfen. | **Hoch** — Implementierungen wählen unterschiedliche `m/t/p` → gültige NodeIDs werden gegenseitig verworfen → Partition. Empfehlung: genau ein kanonisches Profil (z. B. `m=1536 MiB, t=180, p=4`) in `docs/04` normieren, Versionierung via `VERSION_U32` im Preimage. |
| **E-03** | PoW-Verifikation ohne PoP | `QuorumCertificate.aggregate_signature: [u8;96] BLS` (`docs/04:64`) ohne `proof-of-possession` (`audit: K-02`). Angreifer signiert 14× mit selber `sk` über verschiedene `session_seq`. | **Kritisch** — `signer_bitmap.count_ones()>=14` (`INV-0805`) reicht nicht. Für Ed25519: `Vec<Signature>` + Batch-Verify; für BLS: `Sign("HUMOCO_V1_POP", sk)` bei Admission fordern. |
| **E-04** | T₀-Zeitbasis vs physische Uhr | `T₀` ist Unix-Timestamp im Binary, `epoch_id = (unix_sec - T₀)/86400` (`docs/10:299`) bzw. `epoch_day` (`docs/10:299`), aber keine Regel für `T₀` in Zukunft / Vergangenheit / Leap-Second. Node mit falschem Build-`T₀` rechnet andere `epoch_day`. | **Mittel** — Normieren: `T₀` als `u64` Sekunden UTC, `epoch_day = floor((now - T₀)/86400)` mit `now >= T₀`, sonst `InvalidEpoch`. |

**Handlungsempfehlung Eintritt-PoW:**
1. Kanonische `sig_digest()` wie in `audit: K-01` (`len||tag||epoch_id_le||session_seq_le||flags_le||shard_id_le||status_tag||payload_digest`) als SSOT in `docs/04` + `docs/10:3.2` verankern; alle `status_tag`-Preimages (`docs/03:177`, `docs/08:59`) darauf aliasen.
2. Ein einziges Argon2id-Profil + `HUMOCO_V1_GENESIS` Domain-Tag normieren.
3. Signatur-Schema entscheiden (Empfehlung: Ed25519 Batch — einfacher, kein BLS-PoP, kompatibel zu `docs/10:321`).

### 3.2 WoT-Bürgschaften / F2F-Kanten: Bootstrapping & Henne-Ei-Problem

**Spezifikation:**
- Mindestens 1 F2F-Kante zu bestehendem Knoten (`docs/07:30-36`, `INV-0702`), ungebürgt Sandbox `K=0.05` vs volljährig `K=1.0` (`docs/09:98-102`), Wal-Bremse `K≤5.0` (`docs/09:104`). Ingress-Schutz über P2P-Reziprozität (`INV-1306`).

**Stärke:** Radikale Einfachheit — kein Max-Flow, keine Bürgschafts-Listen im Heartbeat (Vermeidung Gossip-Explosion `docs/99:214-242`). Kanten-Drosselung `R_soft` + reine 24h-Bitmasken-Präsenz (`docs/11`) löst Sybil-Besen ohne globale Sicht.

**Henne-Ei-Problem aus Knotensicht — detailliert:**

```
Neuer Betreiber N (1 Gerät, 0 Freunde im Ort)
  → braucht 1 Bürgschaft, um Heartbeats ins Mesh zu bekommen (docs/07:34)
  → findet niemanden, weil Dorf A offline, Dorf B 200km entfernt
  → via Willow/BLE/QR Discovery (docs/01:40) theoretisch möglich,
    aber: F2F-Kante erfordert kryptografisch signierte Bürgschaft (docs/01:73)
    → physisches Treffen + QR-Tausch nötig
  → ohne Kante: Heartbeats werden nirgends eingespeist → IMMATURE forever
```

**Bewertung & zusätzliche Vektoren:**

| ID | Vektor | Beschreibung | Schwere |
| :--- | :--- | :--- | :--- |
| **W-01** | Erstkontakt-Engpass im Insel-Dorf | Bei `d=1` und nur 1 Nachbar `B` — zwar startfähig, aber 100% Abhängigkeit von `B` (`docs/11:101`). Fällt `B` aus, ist `N` isoliert. Kein „weiches“ Admission ohne menschlichen Kontakt. | **Mittel** — Real, aber gewollt (menschliche Eintrittsbarriere). Gap: Es fehlt **temporärer Discovery-Kanal** (z. B. Willow-Relay als ungebürgter Gossip-Injektor mit `K=0.05` + TTL) für den ersten Heartbeat vor der ersten Bürgschaft. Derzeit 100% F2F-Pflicht. |
| **W-02** | Bürgschafts-Entzug & REVOKE-Semantik | `REVOKE(Peer_X)` (`docs/17:65-70`) trennt nur lokale QUIC-Session; keine Spezifikation ob/Wie `wot_peers` (`docs/14:63`) Eintrag getilgt wird, ob andere Pfade die Bürgschaft weiter gossipen, oder ob `HRW-Thrashing` bei Kettentransaktion entsteht (`audit: M-08`). | **Mittel** — Zwar `INV-1703` „Deterministische Verhungerung 8–16h“, aber kein Wire-Format für `REVOKE` (`MsgType` fehlt in `docs/10:98-121`). Implementierungen raten. |
| **W-03** | Sybil-Kette über Tiefe (`M_eff` Lücke) | `INV-0702` limitiert vergebene Masse pro Node auf `1.0` (Stern), aber nicht die Tiefe der Kette `H→B1→B2→...` (`audit: M-08`). Ford-Fulkerson `1.0` gilt nur bei direktem Anker-Schnitt. | **Hoch** — Ein bestochener Bürger `H` kann Kette unendlich verlängern, solange jeder nur `→1` weitergibt. Lösung wie in `audit: M-08`: `M_eff = MaxFlow * γ^{depth}` (`γ=0.9`), Tiefe>3 erfordert zusätzlichen Anker-Pfad. |
| **W-04** | Zwei bestochene Anker → 2.0 Kapazität | `M-08` Szenario: 2 bestochene `H1,H2` injizieren je 1.0 → schleichende Infiltration trotz `K≤5.0`. `R_soft` drosselt zwar pro Kante, aber 2 Kanten → 2× Budget. | **Mittel** — Korrektur via Tiefendämpfung + `popcount(hourly_bitmask) >= 8/24` für `ACTIVE` (`audit: M-08`). |

**Empfehlung WoT:**
- Normiere **einen** Discovery-Bootstrap-Pfad (z. B. Bootstrap-Relay `docs/01:18` als temporärer `UNVERIFIED`-Gossip-Forwarder mit `TTL=1`, `K=0.05`, keine `N_aktiv`-Stimme) und dokumentiere ihn als Ausnahme zu `INV-0103`.
- Definiere `REVOKE` als `MsgType=0x0204` mit Ed25519-Signatur über `(revoker||revokee||epoch_day)`, TTL 16, und Regel: lokale Löschung sofort, globale Verhungerung via Hysterese (`INV-1703`).

### 3.3 Heartbeat-Inkubation (IMMATURE 24h & 8 Heartbeats in 24h → ACTIVE)

**Spezifikation NodePresence-Automat** (`docs/07:40-72`):
- `IMMATURE`: ≥24h seit Erstkontakt + ≥8 gültige stündliche Heartbeats → `ACTIVE`. Sonst Drop nach 48h (`hourly_bitmask ==0`, `docs/11:195`).
- `ACTIVE`: 1 Heartbeat / 60 Min (`docs/11:127`), `TTL_hop=16`, `k(d)=min(d,⌈√d⌉+1)` (`docs/11:150`), `R_soft_hour = max(60, ceil(N_local * (ceil(√d)+1)/d *2.0))` (`docs/11:49`), `R_soft_min = R_soft_hour/60` (`docs/11:50`), `P_drop` (`docs/11:55-59`), Frischefilter `|Δt|≤60s` (`docs/11:129-132`), „Asche“-Deduplikation (`docs/11:134`), `hourly_bitmask` 24h Sliding Window mit `τ_on=8/24`, `τ_off=3/24` (`docs/11:192-194`).

**Stärken:** Stochastische Simulation `N=2000, <d>=10` zeigt `P_reach=99.88%`; Single-Bridge 500 Sybils → 0.00% `ACTIVE` (`docs/11:168-170`). Formal elegant.

**Knotenperspektive — Angriffsfokus: Heartbeat-Zensur durch Relays**

Dies ist der vom Auftraggeber explizit geforderte Fokus. Analyse:

**3.3.1 Kann ein Relay Heartbeats zensieren?**

```
Neuer Node A (1 Freund B, d=1, IMMATURE)
  B ist einziger Uplink zum Mesh (docs/11:101)
  Angenommen B ist byzantinisch und droppt alle Heartbeats von A selektiv,
  leitet aber eigene Heartbeats weiter → bleibt selbst ACTIVE
```

- **Mechanismus 1 — Dunbar-RED greift nicht:** `R_soft` drosselt nur bei Überlast (`r > R_soft`), nicht bei selektivem Drop. Ein Relay, das nur `A` droppt, bleibt unter `R_soft` und wird nicht bestraft (`docs/11:55-59`). Es gibt keine Pflicht, jeden Heartbeat weiterzuleiten; Fan-out `k` wählt subset (`docs/11:150`).
- **Mechanismus 2 — „Asche“ schadet nicht:** Wenn `B` `A`'s Heartbeat nicht weiterleitet, wird `A` für `B` zu „Asche“ in diesem Epoch, aber andere Pfade existieren nicht (nur `B`). Entfernte Knoten `Z` sehen `A` nie.
- **Mechanismus 3 — Zensur bei d=1:** Wenn `A` nur über `B` einspeist und `B` zensiert, erreicht `A`'s Heartbeat `Z` nie → `popcount(hourly_bitmask) = 0 < 8/24` → `is_active=false` (`docs/11:192`).
- **Ergebnis:** **Selektive Heartbeat-Zensur durch den einzigen Freund ist wirksam.** Das ist kein Bug, sondern inhärente Konsequenz der `d=1`-Abhängigkeit (`docs/11:101` „100% von Freund B abhängig“). Die Spec benennt den Anreiz korrekt: Multi-Homing als Selbstschutz.

**3.3.2 Sybil-Stau an Brückenknoten — Korrektur zur Spezifikation**

Der Auftraggeber fragt nach „Sybil-Stau an Brückenknoten“. Die Spec schützt via `R_soft` Kanten-Drosselung:

- **Bei ehrlichem Brückenknoten H:** 10k Bots über 1 Kante → `P_drop≈99.9%` (`docs/05:A4`, `docs/11:69`), `0.8%` qualifiziert (`docs/11:64`). Korrekt — Brücke selbst wird nicht überlastet, Bots verhungern.
- **Bei byzantinischem Brückenknoten H, der Bots priorisiert:** H könnte statt ehrlicher Heartbeats nur Bot-Heartbeats weiterleiten und so ehrliche Knoten verdrängen? Nein — Frischefilter (`|Δt|≤60s` droppt Spam ohne Budget-Verbrauch, `docs/11:132`) + Säule-3-Slashing (`|Timestamp₂-Timestamp₁|<50 Min → FRAUD_HEARTBEAT_SPAM`, `docs/11:134-145`) verhindert Heartbeat-Spam. Bots können nicht schneller als 1/h senden ohne Selbstzerstörung.
- **Schutzlücke:** Ein byzantinischer `B` kann nicht Bots **ein**schleusen (wegen `m≥3`), aber er kann einen **einzelnen ehrlichen Knoten A gezielt isolieren** (selektiver Drop). Das ist der relevante Angriff — nicht Bot-Injektion, sondern **Eclipse via Single-Edge-Zensur**.

**3.3.3 Weitere Inkubations-Lücken**

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **I-01** | Frischefilter vs. NTP-Drift | `|Δt|>60s → silent drop` (`docs/11:129`) verbraucht kein `R_soft` (`docs/11:132`) — gut. Aber ehrlicher Knoten mit 70s NTP-Drift wird 1h lang komplett ignoriert, zählt nicht für `τ_on=8/24`. Bei Dorf mit `d=1` kann das die 24h-Inkubation um Stunden verzögern. Kein NTP-Sync-Protokoll spezifiziert (siehe Kap. 7). |
| **I-02** | 128-Slot Direct-Mapped Detektor Kollision | `Slot = NodeID %128` (`docs/11:138`). Bei `N_local=500` kollidieren ca. 4 Nodes pro Slot. Fall 3 „Slot von anderem frischen Knoten belegt → keine Speicherung“ (`docs/11:145`) bedeutet: Angreifer kann Spam-Slot besetzen und so Detektion für Opfer verhindern (DoS gegen Slashing). Belegter Slot blockiert ehrliche Heartbeat-Spam-Erkennung für andere `NodeID` im selben Slot. |
| **I-03** | `τ_on=8 && τ_off=3` Hysterese-Lücke | Aktivierung braucht 8/24, Deaktivierung erst bei ≤3/24 (`docs/11:192-194`). Knoten mit 4–7 Bits bleibt im alten Zustand (Hysterese) — gut gegen Flapping. Aber: Zwei Knoten mit unterschiedlicher Paketverlust-Historie sehen denselben Peer einmal `ACTIVE`, einmal `DORMANT` → `N_aktiv` divergiert um ±1 → HRW-Thrashing (siehe Kap. 5). |
| **I-04** | 24h vs 8h Inkonsistenz | `docs/07:58` fordert 24h + 8 Heartbeats, `docs/11:192` `popcount≥8/24`, aber `docs/99:194-207` „8 Stunden Heartbeat-Pflicht“ für Sharding-aktiv. Welche Schwelle gilt für `HRW`? `docs/07:58` (`INV-0703`) vs `docs/11:171`. | 

**Empfehlung Inkubation:**
1. **Selektive Zensur explizit adressieren:** Dokumentiere `d=1` als unsicher für Liveness, empfehle `d≥3` als Betriebsempfehlung (Dashboard-Warnung `WARN_SINGLE_BRIDGE_BOTNET` `docs/17:92-100` auf `WARN_SINGLE_EDGE_CENSORSHIP_RISK` erweitern).
2. **Slashing-Detektor auf 1024 Slots oder Cuckoo-Filter** statt 128 direct-mapped — 14 KB vs 112 KB RAM sind bei 5 GB `DashMap` (`audit: M-03`) irrelevant.
3. **NTP:** Fordere `chrony`/`NTS` als Betriebsvoraussetzung, definiere `epoch_day` via `T₀`-Monotonie statt lokaler Uhr, und erlaube `±120s` Frischefilter bei `N<20` (Dorf ohne gutes NTP).

---

## 4. Knoten-Betrieb & Shard-Zuständigkeit

### 4.1 HRW-Rendezvous Sharding (Top-20, Quorum Q = floor(2/3*R)+1)

**Spezifikation:**
- `Shard_ID = u16::from_be_bytes(genesis_hash[0], genesis_hash[1])` (korrekt `docs/04:248`, falsch `genesis_hash[0..2] mod 65536` in `docs/03:14`, `docs/06:77` — `audit: K-06`).
- `Score(Node_i,S) = BLAKE3(NodeID_i || Shard_ID)` (`docs/03:21`), Top-20 deterministisch.
- `R = min(20, N_aktiv)` (`docs/08:14`), `Q(R)=floor(2R/3)+1` (`docs/00:96`, `docs/08:16`) vs `ceil` in `README:22` (`audit: K-03`).
- Tabelle `docs/00:90-93`: `PROVISIONAL` bei `N<20`, `FINAL` bei `N≥20` mit `≥14/20` (70%).

**Knotenperspektive — was rechnet ein Node?**

Jeder Node berechnet **lokal** aus seiner `N_aktiv`-Sicht die Top-20. Bei Rand-Diskrepanz (`N_local=10000 vs 10003`) bleibt HRW zu 99.7% stabil (`docs/11:201`), aber:

| ID | Risiko | Einordnung |
| :--- | :--- | :--- |
| **S-01** | Quorum-Formel-Divergenz bei `R=10` → `7 vs 8` Stimmen (`audit: K-03`) | **Kritisch** — Händler gibt Ware bei Grün/Rot unterschiedlich frei. Fix: SSOT `floor`, Helper `quorum(r)=(r*2)/3+1` in `docs/04`, Testvektoren `R=1..20`. |
| **S-02** | Shard-ID Off-by-One → Gateway routet in anderen Shard als Shard-Node prüft (`audit: K-06`) | **Kritisch** — First-Seen verfehlt, Double-Spend übersehen. Fix: `docs/03:14` + `docs/06:77` korrigieren, Fuzz-Test. |
| **S-03** | HRW-Divergenz bei `N_aktiv`-Drift (`I-03`) | **Mittel** — 1 Node in Top-20-Unterschied führt zu 5% Shard-Stimmen-Divergenz; Client-Hedging (`FLAG_HEDGED` `docs/10:131`, `docs/06:219`) heilt, aber Latenz steigt. Akzeptabel per Design (`docs/11:202-221`). |
| **S-04** | Shard-Preemption / Grinding trotz PoW | `docs/05:A6` argumentiert 1–3h PoW macht Grinding teuer — korrekt für Single-Shard. Aber Angreifer mit 100 Nodes (300h PoW, einmalig) kann via HRW-Rang 21 Nachrücken (`docs/03:87-92`, `docs/07:118-122`) langsam Position gewinnen bei hohem Churn (siehe Kap. 5). | **Mittel** — Kein akuter Angriff, aber Churn-Rate muss unter `1/R` bleiben; sonst „slow bleed“. |

### 4.2 Dual-Plane Architektur (F2F Gossip Overlay vs. Direct Co-Shard QUIC Mesh)

**Spezifikation** (`docs/01:52-101`):
- **F2F-Gossip-Overlay:** Permanente P2P nur zu gebürgten Partnern (`INV-0103`), transportiert Heartbeats 1/h, WoT, Fraud-Alerts via Small-World-Perkolation (`TTL=16`, `k=√d+1`).
- **Direct Co-Shard QUIC Mesh:** Direkte mTLS Ed25519 QUIC-Sessions nur wenn `NodeID ∈ N_aktiv` (PoW+WoT+Heartbeat) **und** `HRW Rank ≤20` für Shard (`docs/01:80-82`). Ephemerer RAM-Sync nur `valid_until>now`.

**Stärke:** Trennung verhindert Eclipse auf Data-Plane (Gossip-Eclipse ≠ Shard-Eclipse). `INV-0104` Autorisierte Co-Shard-Verbindungen ist tragend.

**Knotenperspektive — Lücken:**

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **D-01** | Gate-Bypass bei `N<20` | `INV-0104` fordert Top-20-Check. Bei `N=3` sind alle 3 für alle Shards zuständig (`docs/05:99-100`, `docs/08:20`). Dann ist *jeder* Peer berechtigt — Gate wirkungslos. Korrekt, aber muss explizit als `R<20 → alle N` Ausnahme in `INV-0104` stehen. |
| **D-02** | QUIC Handshake + 0-RTT Whitelist Divergenz | `docs/01:90-101` Sequence zeigt mTLS Check, aber `docs/10:100-122` vs `docs/15:78-88` Whitelist divergiert: Code erlaubt nur 3 Typen, Tabelle erlaubt `ActiveSyncRequest` (`audit: H-02`). Angreifer kann `ShardDigestRequest` via 0-RTT amplifizieren (32B → Stream). |
| **D-03** | Stream-Starvation trotz 4 Streams | `docs/15:38-59` 4 Streams (Data, Gossip, Fraud, WoT) mit Prioritäten. Aber `FraudAlert` ist `Unbounded` (`docs/15:57`) — Spam-Gossip könnte Fraud-Stream fluten. Besser: Fraud `Bounded(100)` + Priority-0 Queue (`docs/10:450-459`). |
| **D-04** | F2F-Overlay Partition ohne Data-Plane Impact? | Gossip-Partition ≠ Shard-Partition: Zwei Dörfer ohne F2F-Kante, aber HRW-Top-20 überlappend → Direct-QUIC trotzdem möglich? Spec verbietet (`docs/01:91` „Nicht in N_aktiv → Close(UnauthorizedShardPeer)“). Korrekt, aber bedeutet: **Gossip-Partition blockiert Data-Plane**, obwohl QUIC technisch ginge — Liveness-Einschränkung. |

**Empfehlung Dual-Plane:**
- Whitelist in `docs/10:100-122` als SSOT, `docs/15:78-88` darauf verweisen, `ShardDigestRequest` + `ActiveSyncRequest` explizit whitelisten **mit** per-IP Rate-Limit (`audit: H-02`).
- `INV-0104` präzisieren: „...oder `R<20` und Peer ∈ `N_aktiv`“.

### 4.3 Netzwerk-Thermometer & Dynamische Quotas

**Spezifikation** (`docs/09`):
- Verrechnung `Byte-Jahre = 192B×Δt_Jahre` (`docs/09:22`), Diskrepanz `192 vs 224` inkl. Overhead (`docs/09:18` vs `docs/12:109`), Hard-Floor `NCB_min=240k BJ/Tag (10k BJ/h)` (`docs/09:60-62` → 333 Fünf-Jahres-Gutscheine/Tag, korrekt 286 bei 224B `audit: H-10`).
- `Q1/Median/Q3` Quartils-Erfassung ab `N≥4` über Dunbar-Gossip (`docs/09:42-54`), 28-Tage Slotted Ringpuffer (`docs/09:68-73`), `Spread_Damper = max(0.5, min(1.0, (1-Q1/Q3)/0.66))` (`docs/09:88`), Tages-Quota `NCB_eff × K(N) × Spread_Damper` mit `K=0.05 / 1.0 / ≤5.0` (`docs/09:98-104`).
- Silent Dropping bei Überlastung (`docs/09:106`, `INV-0906`).

**Knotenperspektive — Thermometer gesehen von Node A:**

Node A misst **lokal** `Q1/Median/Q3` aus empfangenen Heartbeats (die `cumulative_micro_byte_years`, `current_anl_24h` tragen `docs/10:295-313`). Bei Partition sieht Dorf A anderen Thermometer als Dorf B → Quoten divergieren. Nach Merge: Welcher `NCB_eff` gilt?

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **T-01** | Partition-Merge Thermometer-Divergenz | Dorf A (5 Nodes, wenig Traffic) hat `NCB_eff=240k` (Floor), Dorf B (10k Nodes, viel Traffic) hat `NCB_eff=10M`. Nach Merge mischt Ringpuffer — aber 28-Tage-Mittel hinkt. Angreifer könnte in kleinem Netz billig `K=0.05` Locks spammen, die im großen Netz als „unter Quota“ gelten. |
| **T-02** | Byte-Jahre Inkonsistenz 192 vs 224 | `docs/09:22` rechnet 192B, `docs/12:109` schätzt 224B inkl. `DashMap`. Quota 16% zu lax — ehrliches Gateway triggert fälschlich Slashing Klasse 3/4? (`audit: H-03`). |
| **T-03** | Gratis `POST /promote_lock` bricht `INV-0901` | `docs/02:142-148` Promotion kostenlos, aber jeder Lock kostet `µBJ` (`docs/09:20`). Gratis-Loop: Angreifer promoted denselben Lock täglich neu ohne Kosten. (`audit: K-05`) |
| **T-04** | Silent Dropping nicht von Zensur unterscheidbar | `INV-0906` Silent Drop ohne `SignedRejection` → Kartell 6 Nodes kann Händler silencen und als `QuotaExhausted` tarnen (`audit: M-02`). `Receipt-Gossip` nur bei Erfolg (`docs/10:332`) → Gradienten-Prüfung greift nicht. |
| **T-05** | Spec-Inflation O-01 | `Q1/Q3/Spread_Damper/ANL/EMA` Ballast: gleiche Anti-Spam-Wirkung via `144B cap + TTL + M≤1.0` (`audit: O-01`). Jede Formel braucht Toleranz und bricht bei Merge. |

**Empfehlung Thermometer:**
1. **Vereinfachen** (`audit: O-01`): Streiche Zipf-Damper/Q1/Q3/ANL-EMA, behalte nur `NCB_eff = max(NCB_min, 28-Tage-Median)` + `K=0.05/1.0` + `K≤5.0`. Halbiert Wire-Größe und alle Gradient-Proofs.
2. **Quota deterministisch auf 224B** (oder Wire 144B + RAM 192B explizit getrennt) normieren, Rechnung `docs/09:62` neu belegen.
3. **Promotion als Upgrade** (`INV-0206`): `lock_hash` identisch + `status_tag` monoton `0x00<0x01<0x02` ist kein Conflict, nur Upgrade — gratis nur bei identischem `lock_hash` ohne TTL-Verlängerung (`audit: K-05`).
4. **SignedRejection** Pflicht (`audit: M-02`): `HUMOCO_V1_REJECT` + `reject_bitmap` via Piggyback.

---

## 5. Knoten-Austritt, Ausfall & Bestrafung (Churn & Eviction)

### 5.1 Graceful Exit (LEAVE-Nachricht, Replay-Schutz, Timestamp-Validation)

**Spezifikation** (`docs/07:96-122`):
- `LEAVE(NodeID, Timestamp)` signiert an Nachbarn, Peers streichen sofort, HRW-Rang 21 rückt in 0ms nach.

**Lücken aus Knotensicht:**

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **C-01** | LEAVE Wire-Format fehlt | Kein `MsgType::Leave` in `docs/10:98-121`, kein Domain-Tag (`HUMOCO_V1_LEAVE`), keine `epoch_seq`/`timestamp_ms` Validierung. Replay: Angreifer replayt altes LEAVE nach Re-Join → Opfer wird fälschlich entfernt. |
| **C-02** | Timestamp-Validation undefiniert | `valid_until`-Logik hat `now-30s` Toleranz (`docs/12:40`), Heartbeats `±60s` (`docs/11:129`). Für LEAVE fehlt Regel: `|LEAVE.timestamp - now| ≤60s`? Sonst kann Angreifer zukünftiges LEAVE pre-signieren. |
| **C-03** | LEAVE vs DORMANT Race | Node sendet LEAVE, aber 1 Heartbeat war noch unterwegs (TTL 16). Empfänger sieht LEAVE (sofort raus) vs Heartbeat (wieder rein) — Flapping. Braucht Monotonie: `LEAVE.epoch_day > last_heartbeat.epoch_day`. |

**Empfehlung:** `LEAVE` als `MsgType=0x0205`, `DOMAIN_TAG=HUMOCO_V1_LEAVE`, `SigDigest = BLAKE3(len||tag||NodeID||epoch_day||timestamp_ms)`, Re-Entry nur nach 60-Tage Purge oder manuellem Re-Join mit neuer PoW-Nonce.

### 5.2 Silent Dropout (DORMANT nach >24h, Fast Re-Entry nach 2 Heartbeats) — Flapping / HRW-Thrashing

**Spezifikation:**
- `ACTIVE → DORMANT` wenn >24h keine Heartbeats (`docs/07:51`), `DORMANT → ACTIVE` mit ≥2 Heartbeats sofort (`docs/07:53`, `INV-0704`), aber `docs/11:192-194` verlangt `popcount≥8/24 + m≥3` — **Widerspruch!**

**Threat Model Flapping:**

```
Angreifer A (DORMANT-Pool 100 Nodes, je 1-3h PoW einmalig)
  → sendet 2 Bursts à 2 Heartbeats im Abstand 2h → alle 100 werden ACTIVE
  → sofort wieder offline → 24h später DORMANT
  → wieder 2 Heartbeats → ACTIVE
  → HRW R=20 thrashing: jede Flap ändert Top-20 für ~65k Shards
  → Digest-First PULL (`docs/03:125-159`) triggert 500ms Backoff-Loop
  → Liveness-Degradation, nicht Konsens-Bruch (First-Seen bleibt atomar)
```

**Bewertung:**

| ID | Vektor | Schwere |
| :--- | :--- | :--- |
| **F-01** | Fast Re-Entry 2 Heartbeats zu lax | **Hoch** — `INV-0704` „≥2 Heartbeats“ kollidiert mit `INV-0702/1101` `m≥3 && 8/24`. Welches gilt für `N_aktiv`? Zwei Knoten mit unterschiedlicher Auslegung divergieren. |
| **F-02** | HRW-Thrashing bei Churn >5% | **Mittel** — Bei `N=1000`, 5% Churn/Tag → täglich 50 Nodes flappen → HRW ändert ca. `50/1000 *20 =1` Slot pro Shard — verkraftbar. Bei 20% Churn → 4 Slots/Shards thrasht — Digest-Mehrheit `≥14` bricht (`audit: M-05` `11..13` Fenster). |
| **F-03** | Kein Backoff nach Flap | **Mittel** — Spec hat keine „Flap-Penalty“ (z. B. nach 3 Flaps in 7 Tagen → 7 Tage `IMMATURE` erneut). Ermöglicht kostengünstiges Ping-Pong. |

**Empfehlung:**
1. **SSOT für `is_active`:** `docs/11:192` (`8/24 + m`) ist SSOT; `docs/07:53` „2 Heartbeats“ nur für `DORMANT` **nach** bereits einmaliger `ACTIVE`-Phase, aber **zusätzlich** `popcount≥8/24` über letzte 24h (2 Heartbeats allein reichen nicht — braucht 8h Hysterese `docs/05:118`). `INV-0704` präzisieren.
2. **Flap-Dämpfung:** Nach 2× `ACTIVE↔DORMANT` in 7 Tagen → 48h `IMMATURE`-Re-Entry statt 2 Heartbeats.

### 5.3 Purge (60 Tage / 1 Jahr) und Speicheraufwand für Exits/Dormant-Listen

**Spezifikation** (`docs/07:77-83`, `INV-0705`):
- Ferne Knoten: 60 Tage `DORMANT` → Purge.
- Direkte F2F-Freunde: 1 Jahr → deaktiviert, manuelle Reaktivierung.

**Speicheranalyse aus Knotensicht:**

- `NodePresenceTracker: 16 Bytes/Node` (`docs/11:179-187`), `100k Nodes → 1.6 MB` (`docs/11:236`), `1M Nodes → 16 MB` — trivial. Selbst 10M → 160 MB RAM, verkraftbar.
- Problem nicht RAM, sondern **Disk/`redb`**: `TABLE_WOT_PEERS` (`docs/14:63`), `TABLE_ACTIVE_LOCKS` (`docs/14:68`), `TABLE_FRAUD_EVIDENCE` (`docs/14:73`) wachsen unbeschränkt bei `persist_tx` unbounded (`audit: M-03`).

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **P-01** | Exit/Dormant-Listen unbounded | `total_byte_seconds: AtomicU64` ohne Hard Cap (`audit: M-03`). 20 Gateways×333 5-Jahres/Tag → 6.6k/Tag → 10 Jahre 24M Locks → ~5 GB RAM + `redb` Append-Only ohne Compaction → OOM. |
| **P-02** | TTL-Bucket fehlt | `docs/12` Titel verspricht `O(1) TTL-Bucket-Ringpuffer`, implementiert ist `scan TABLE_ACTIVE_LOCKS O(n)` täglich (`audit: H-06`). |
| **P-03** | F2F 1-Jahr manuelle Reaktivierung DoS | Angreifer spammt F2F-Anfragen, Opfer lehnt ab — aber Eintrag bleibt 1 Jahr? Dashboard-Belastung. |

**Empfehlung:**
- `INV-1207` RAM-Hard-Limit `max_ram_locks = max(100k, quota_BJ*2)` + 48h LRU-Eviction nahe `now` (`audit: M-03`).
- `mpsc(10k)` bounded mit `try_send → 429` statt unbounded.
- `TABLE_TTL_BUCKETS: (bucket_id=valid_until/86400 → Vec<ParentLockKey>)` (`audit: H-06`), täglicher `O(1)` Bucket-Drop.
- F2F-Purge nach 1 Jahr + `REVOKE` propagieren, nicht nur lokal deaktivieren.

### 5.4 Equivocation-Bann (ServerBann via Double-Sign-Beweise, DoS-Resilienz der Bannliste)

**Spezifikation** (`docs/02:103-117`, `docs/05:A2`, `docs/07:89-92`, `docs/10:357-393`, `docs/10:398-462`, `docs/15:53`):
- Säule 1: `T₁||T₂` gleicher `signer` + `parent_lock` + `new_lock_hash≠` → `FRAUD_SHARD_EQUIVOCATION`.
- Säule 2: `P₁||P₂` Zähler-Rückschritt/Heartbeat-Diskrepanz → `FRAUD_INGRESS_COUNTER_CONFLICT`.
- Säule 3: `H₁||H₂` `|Δt|<50 Min (3000s)` → `FRAUD_HEARTBEAT_SPAM`.
- `FraudProofPayload` (`docs/10:411-432`, `docs/04:78-102`), Priority-0 Urgency Queue + `k_alert≥3..5` Fan-out + Kantenbudget-Bypass (`docs/10:444-461`), `ERR_NODE_PERMANENTLY_BANNED`.
- DoS-Resilienz: `BannedNodes` O(1) RAM+Disk Sperrfilter (`docs/10:460`).

**Knotenperspektive — DoS gegen Bannliste?**

| ID | Vektor | Bewertung |
| :--- | :--- | :--- |
| **B-01** | Bannlisten-Explosion | Jeder FraudProof ist 32B `NodeID` + 2× Evidence (`Vec<u8>` unbounded `docs/04:92-95`). Angreifer erzeugt 1M fake `FraudProofPayload` mit ungültigen Sigs → `TABLE_FRAUD_EVIDENCE` wächst. Aber: Verifikation `<100µs` (`INV-0501`) verwirft ungültige Proofs sofort, ohne Persistenz — **kein DoS**, solange Verifikation vor Disk-Schreiben. `INV-1402` „zwingend persistent“ gilt nur für **gültige** Proofs. |
| **B-02** | Validierung vor Persistenz Race | `docs/14:97-100` async `mpsc` → Disk. Wenn Angreifer 1M gültige `FRAUD_HEARTBEAT_SPAM` (mit echten 2 Heartbeats `<50 Min`) erzeugt, kostet ihn das 1M× Argon2id PoW (1–3h je Node) — **ökonomisch unmöglich**. |
| **B-03** | `reporter_signature` Spam | `FraudProofPayload.reporter_signature` (`docs/10:431`) über `(perpetrator||pillar||hash(A)||hash(B))`. Fake Reporter-Sigs werden via Ed25519-Vorfilter `50µs` (`docs/13:142`) gedroppt — kein Pool-Saturation (`audit: H-05` gilt hier nicht, da Fraud-Stream `Unbounded` aber Priority-0 + Verifikation billig). |
| **B-04** | Equivocation vs `ConflictWithEvidence` Verwechslung | `docs/02:120-138` + `docs/99:388-417`: `409 ConflictWithEvidence` ist **kein** Server-Fehlverhalten, sondern Whistleblower-Beweis (`INV-0205`). Implementierungsrisiko: Shard-Node, der `ConflictWithEvidence` liefert, darf keine `missing_count` Piggyback-Strafe bekommen (`docs/03:80-87`). Sonst wird Whistleblower als „lazy“ eingestuft und ungerechtfertigt sanktioniert — perverses Incentive. | **Mittel** — Spec muss `signers_bitmask` Regel ergänzen: „`ConflictWithEvidence` zählt als erfolgreiche Teilnahme, nicht als `missing`“. |

**Empfehlung Bannliste:**
- Klarstellen: Nur **verifizierte** (`<100µs`) Proofs persistieren; `FraudProofPayload.evidence_packet_a/b` auf `max 2× 1KB` begrenzen (derzeit `Vec<u8>` unbounded).
- `signers_bitmask` Whistleblower-Ausnahme normieren.

### 5.5 Nachrücker-Sync (Rang 21 rückt nach, RAM-Lock-Sync `valid_until > now`, Kaskadenausfälle)

**Spezifikation** (`docs/07:118-122`, `docs/03:65-92`, `docs/03:125-159`, `docs/14:110-112`):
- Rang 21 rückt in 0ms deterministisch nach, holt aktive RAM-Locks (`valid_until>now`) via Digest-First PULL: Phase 1 `GetShardDigest` 20×32B Fingerabdruck, Phase 2 Mehrheits-Clustering `≥14`/`11..13`/` <11 →500ms Backoff`, Phase 3 `StreamShardLocks` von einem Peer, Phase 4 `BLAKE3(SHARD_ID||Lock₁...||Lockₘ)` lexikografisch sortiert.

**Kaskaden-Szenario aus Knotensicht:**

```
Shard S: Top-20 = Nodes 1..20, Rank21 = Node21
  Node 5,7,12 fallen gleichzeitig aus (Stromausfall Region)
  → R=20 → effektiv 17/20 → noch BFT (14/20 OK, docs/05:32)
  → Rank21,22,23 rücken nach → 3× Digest-First PULL parallel
  → Jeder PULL fragt 20 Peers nach Digest (docs/03:138-142)
  → Bei 3 parallelen PULLs: 60 Anfragen, aber jeder Peer antwortet mit gleichem Digest
  → Kein Problem — aber: Wenn 3 Nodes gleichzeitig PULLen und live Locks eintreffen,
    Digest divergiert → Cluster 11..13 Toleranzfenster (docs/03:152) greift
    → Angreifer mit 13 Nodes könnte Digest-Wahl gewinnen (audit: M-05)
```

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **N-01** | `11..13` In-Flight Fenster bricht BFT | `docs/03:148-149` erlaubt `C_max 11..13` als „Live-Traffic Toleranz“ → 11 statt 14 reicht. Widerspricht `INV-0304` `≥14/20` (`audit: M-05`). **Muss gestrichen werden.** Regel: `≥14` sonst `500ms Backoff & retry` (`docs/03:151`). In-Flight Locks idempotent via offenen QUIC-Ingress nachholen. |
| **N-02** | `ShardDigest` Sortier-CPU-DoS | `BLAKE3(Shard_ID||Lock₁||...||Lockₘ)` lexikografisch sortiert `O(m log m)` jedes Mal (`audit: M-03`). Bei 24M Locks → CPU-DoS. Lösung: Inkrementeller Merkle-Root (Binary Tree) statt Sort. |
| **N-03** | Kaskadenausfall >6 Nodes | `14/20` BFT toleriert 6 Ausfälle. Bei 7 Ausfällen → kein Quorum → `504 Gateway Timeout` (`docs/06:306-318`) → Smart Client Failover zu Backup-Gateway (`docs/05:A3`) heilt, aber Shard ist temporär read-only. Korrekt, aber nicht als „0ms Nachrücken“ verkauft werden. |
| **N-04** | Nachrücker lädt nur `valid_until>now` — Resurrection | `docs/07:122` Filter `valid_until>now` verhindert tote Locks, aber Race: Wallet-Batch `[Tx2,Tx3,Tx4]` mit `valid_until=now+5s` während Node A tilgt, Node B hält noch → beim Merge via Lazy Ingestion (`valid_until>now` Check) kann derselbe Gutschein wiederauferstehen (`audit: H-06`). |

**Empfehlung Nachrücker:**
1. Streiche `11..13` Fenster (`audit: M-05`), fordere `≥14`.
2. `ShardDigest` auf Merkle-Root umstellen.
3. Ingress verschärfen auf `valid_until > now+30s && valid_until ≤ root.valid_until`, Tilgung exklusiv `valid_until+30s grace` (`audit: H-06`).
4. Kaskaden-SLO definieren: `>6 Ausfälle → Degraded (PROVISIONAL)` statt „0ms heilt alles“.

---

## 6. Netzwerk-Merge & Split-Brain

### 6.1 Insel-Netze (Dorf A vs Dorf B), Phasenübergang PROVISIONAL (N<20) → FINAL (N≥20) mit 24h Hysterese

**Spezifikation** (`docs/08:36-60`, `docs/00:89-97`, `docs/02:52-73`):
- `PROVISIONAL (Gelb, 0x00)` bei `N<20 && sigs≥Q(R)`, `FINAL (Grün, 0x01)` bei `N≥20 && ≥14/20` **nach 24h Hysterese** (`docs/08:46-60`). `INV-0802` 1-Byte Status-Prägung, `SignPreimage = BLAKE3(status_tag||lock_hash)` (`docs/08:59`).
- `HIGH_ASSURANCE (Gold, 0x02)` bei `N≥100` gleiches `14/20` (`audit: O-02` ohne Mehrwert).

**Kritischer Widerspruch — aus Knotensicht fatal:**

`docs/02:70` + `docs/06:98` geben `FINAL` sofort bei `N≥20 && ≥14`, `docs/03:178-181` + `docs/08:46-60` verbieten `status_tag=0x01` vor 24h. Im Fenster `0–24h` nach Erreichen von `N=20`:

```
Realität: N=20 erreicht (Dorf A 10 + Dorf B 10 mergen)
  → ehrliche Nodes signieren noch mit 0x00 (Hysterese nicht erfüllt)
  → Gateway sammelt 14 Sigs mit 0x00 → nach docs/02:70 wäre es FINAL
  → nach docs/08:58 ist es noch PROVISIONAL
  → Händler, der docs/02 liest, gibt Ware frei (Grün)
  → Händler, der docs/08 liest, warnt (Gelb)
  → Konsens-Split ohne byzantinischen Täter
```

`audit: K-04` identifiziert dies als kritisch — wir bestätigen aus Knotenperspektive.

**Empfehlung Phasenübergang (zweistufig normieren):**

```rust
// docs/04 SSOT
pub fn quorum_status(n_active: usize, sigs: usize, hysteresis_ok: bool) -> u8 {
    let r = n_active.min(20);
    let q = (r*2)/3 + 1;
    if sigs < q as usize { return 0xFF; } // INVALID
    if n_active >= 20 && sigs >= 14 && hysteresis_ok { 0x01 } // FINAL_stable
    else if n_active >= 20 && sigs >= 14 { 0x00 } // FINAL_candidate (noch Gelb!)
    else { 0x00 } // PROVISIONAL
}
```

- `FINAL_candidate` (14 Sigs, aber `status=0x00` bis Hysterese) vs `FINAL_stable` (0x01) trennen.
- `docs/02:70`, `docs/06:98` um `&& hysteresis_ok` + `status_tag`-Prüfung ergänzen, `INV-0802` dorthin propagieren.
- Neues `GET /network_status { N_aktiv, hysteresis_remaining_sec }` für Wallet-UX statt Rate-Spiel (`audit: K-04`).

### 6.2 Topologie-Merge — Heartbeat-Präsenz vs 500ms Versprechen

**Spezifikation** (`docs/08:68-83`, `docs/01:40-47`):
- Phase 1 P2P Peering `<100ms`, Phase 2 Organische Präsenz `<50ms`, Phase 3 Zero Lock-Dump, Phase 4 Lazy Ingestion.

**Realität aus Knotensicht** (`audit: H-07`):

- Presence braucht `8/24 + m≥3` (`docs/11:192`) + 8h Hysterese (`docs/07:08`) + 1 Heartbeat/h + `TTL=16` → Dorf A+B je `N=5` frühestens nach **Stunden** `ACTIVE` für HRW.
- `docs/08:82` „Zero Lock-Dump“ widerspricht `docs/03:125` Digest-First PULL (echter Sync-Pfad).

**Korrigierte Merge-Zeit:**

| Phase | Dauer | Was passiert |
| :--- | :--- | :--- |
| P2P Peering | `<100ms` | QUIC + GossipHeartbeats Austausch |
| Presence `ACTIVE` | `frühestens 8h` | Erst nach `8/24` Bits + `m≥3` |
| `FINAL` | `frühestens 24h` | Hysterese-Filter |
| PoS First-Seen | `<50ms` | Unabhängig von Presence — nur Shard-Quorum |

**Empfehlung:** Diagramm `docs/08:72` korrigieren, `docs/11` als SSOT für `is_active`, PoS-Latenz nur via First-Seen garantieren — Presence-Merge nicht im Hot Path versprechen.

### 6.3 Konfliktlösung bei Merges mit konkurrierenden PROVISIONAL-Locks

**Spezifikation** (`docs/02:79-102`, `docs/08:114-117`, `docs/03:112-138`, `docs/06:212-218`):
- `H_canon(Lock)=BLAKE3("HUMOCO_V1_CANON_RESOLVER"||Parent||Receiver||Sig)` (`docs/02:97`), `min(H_canon)` entscheidet, Verlierer `VOID` (`INV-0202` keine Wiederauferstehung), `HUMOCO_V1_EQUIVOCATION` Slashing (`INV-0203`).

**Knotenperspektive — PROVISIONAL vs PROVISIONAL Merge:**

Zwei Dörfer `N=5` je `Q=3/5`? Nein, `R=5→Q=4` (`floor(10/3)+1=4`). Beide Dörfer können **gleichzeitig** für denselben `parent_lock P` unterschiedliche `child_lock A vs B` mit `PROVISIONAL (0x00)` bestätigen (lokale BFT). Beim Merge:

```
Dorf A: Lock P→A mit H_canon(A)=0x3f...
Dorf B: Lock P→B mit H_canon(B)=0x1a...
  → min(H_canon)=0x1a → B gewinnt, A → VOID (KollisionsVerlierer docs/02:39-45)
  → Beide Signaturen bilden ProofOfDoubleSpend → L1 Slashing (docs/00:105-110)
```

**Lücken:**

| ID | Lücke | Detail |
| :--- | :--- | :--- |
| **M-01** | `10:10` Split vs `min(H_canon)` Widerspruch | `docs/06:213-218` „10:10 → kein Quorum, beide Kassen verweigern“ vs `docs/02:79` `min(H_canon) in <1ms`. Live-First-Seen vs Merge-Resolver ohne Priorität, Timeout-Fragmentierung 50ms/200ms/600ms (`audit: H-08`). |
| **M-02** | `PROVISIONAL` Promotion Race | Wallet aus Dorf A promoted `PROVISIONAL` Lock via `POST /promote_lock` (`docs/02:142-148`) während Merge `min(H_canon)` denselben Lock zu `VOID` erklärt — Race ohne Idempotenz-Key. |
| **M-03** | Händler-Risiko Gelb vs Grün | `docs/02:70-73` Tabelle: `PROVISIONAL` = Mikro-Transaktionen/Nachbarschaft, `FINAL` = Großbeträge. Aber Händler in Dorf A kann nicht wissen, ob `P` im anderen Dorf bereits `PROVISIONAL` gesperrt wurde — Gelb ist kein Schutz, nur Warnung. | 

**Empfehlung Konfliktlösung:**
1. Automat `docs/02:12-50` vervollständigen: `Pending→Provisional/Final→Void (nur via min(H_canon) oder ConflictWithEvidence)→Expired` (`audit: H-08`).
2. Regel: Live-First-Seen ist Provisorium; endgültiger Konsens immer `min(H_canon)` wenn `ConflictWithEvidence` innerhalb `valid_until` eintrifft.
3. `docs/06:216` korrigieren: `10:10 → 409 ConflictWithEvidence + Resolver-Hinweis`, nicht „kein Quorum“. Timeout `T_quorum=600ms` zentral in `docs/04` verankern.
4. Promotion als `status_tag` monotones Upgrade (`0x00<0x01<0x02` ist kein Conflict) — `INV-0206` (`audit: K-05`).
5. Wallet-Pflicht: Gelb = „Nur bis X €, kein Fernhandel“ explizit in `docs/06` + PoS-UI.

---

## 7. Systemische Lücken, Angriffsvektoren & Spezifikationsbedarfe

### 7.1 Time-Jacking / NTP-Desynchronisation

**Angriffsfläche:**

| Zeitbasis | Nutzung | Toleranz | Folge bei Drift |
| :--- | :--- | :--- | :--- |
| `T₀` Genesis | `epoch_day = (now-T₀)/86400` (`docs/10:299`) | keine | Falsche `epoch_day` → Epoch-Berechnungs-Diskrepanz |
| `timestamp_ms` Envelope | `SignedIngressEnvelope.timestamp_ms` (`docs/10:321`), `cumulative_micro_byte_years` | Sättigungs-Arithmetik (undefiniert) | Klasse 2 Time-Warp/Amnesie False-Positive (`audit: H-03`) |
| `timestamp_unix` Heartbeat | Frischefilter `|Δt|≤60s` (`docs/11:129`) | Silent Drop, kein `R_soft` Verbrauch | Ehrlicher Knoten mit 70s Drift wird 1h ignoriert → `τ_on` verfehlt |
| `valid_until` Lock | Ingress `now-30s < valid_until ≤ root.valid_until` (`docs/12:40`) | `400 Expired` | `valid_until=now+5s` während Merge → Resurrection (`audit: H-06`) |
| `current_anl_24h` EMA | `EMA e^{-Δ/24h}` (`docs/10:359`) vs `deterministic_decay` (`docs/04:254`) | Transzendente vs Bit-Shift Divergenz (`audit: H-03`) | Gradienten-Slashing False-Positive |

**Time-Jacking Vektor:**

Angreifer kontrolliert NTP für Opfer-Node `V` (z. B. via BGP-Hijack `docs/99:163` Seekabel-Bruch-Szenario):
- `V`'s Uhr 2h vor → Heartbeats mit `timestamp = now+2h` → alle Peers droppen wegen `|Δt|>60s` → `V` wird `DORMANT` → aus `N_aktiv` entfernt → Shard `R=19` → HRW-Thrashing.
- `V`'s Uhr 2h zurück → `valid_until` Checks `now-30s` schlägt fehl → frische Locks werden als `Expired` verworfen → `V` zensiert effektiv sich selbst.

**Spezifikationsbedarfe:**

1. **Deterministische Zeitquelle:** `NTS` (`Network Time Security`) als Pflicht für `N≥20` Nodes, `chrony` Empfehlung für Dorf-Nodes. Fallback: `epoch_day` via medianer Heartbeat-Zeit (Byzantine-tolerant) statt lokaler Uhr.
2. **Toleranz vereinheitlichen:** `timestamp_ms` Sättigung definieren (z. B. `saturating_sub` + `30s` Skew-Fenster `INV-1206`), Frischefilter bei `N<20` auf `±120s` erweitern.
3. **EMA deterministisch:** `e^{-Δ/24h}` durch `deterministic_decay` (`value>> (Δ/17h)`) (`docs/04:254`) ersetzen, Integer-EMA `EMA_{t+1}=EMA_t*(1-1/24)+Δ` (`audit: H-03`).
4. **Monotonie-Bindung:** `Lock.valid_until > now+30s && ≤ root.valid_until`, Tilgung `valid_until+30s grace` (`audit: H-06`).

### 7.2 Partitioning & Eclipse auf WoT-Overlay-Ebene

**WoT-Eclipse vs Shard-Eclipse:**

- **Gossip-Eclipse (F2F):** Angreifer isoliert Opfer `V` über `1 Bridge` (einziger Freund `B` byzantinisch). Wie in Kap. 3.3.1 gezeigt: **selektiver Drop wirksam** bei `d=1`. Bei `d≥3` braucht Angreifer 3 Kanten → `m=3` schützt. Dunbar-RED hilft nicht gegen selektiven Drop.
- **Shard-Eclipse (Data-Plane):** Opfer `V` ist Shard-Node für `S`, Angreifer kontrolliert 6/20 Shard-Peers → `14/20` BFT heilt (bis 6 byzantinisch ok `docs/05:A3`). Client-Hedging (`FLAG_HEDGED` `docs/10:131`) kontaktiert Backup-Gateway → Zensur wirkungslos.
- **Kombinierter Angriff:** Gossip-Eclipse + Shard-Eclipse. Angreifer eclipsed `V`'s Gossip, sodass `V` `N_aktiv` falsch berechnet → HRW-Divergenz → `V` glaubt, nicht mehr für `S` zuständig, stellt Signieren ein → `missing_count` Piggyback (`docs/03:80-87`) markiert `V` als lazy → Peer-Backoff greift. Durch Multi-Homing ($m \ge 3$) wird dies verhindert.

**Resilienz-Nachweis aus Knotensicht:**

| Szenario | Schutz | Bewertung |
| :--- | :--- | :--- |
| Single-Bridge Sybil 1k Bots | Dunbar-RED `99.9%` Drop + `m≥3` → `0.1%` qualifiziert (`docs/11:64`) | **Stark** |
| Bestochener Freund 10k Bots | `R_soft≈1–7/min` Flaschenhals (`docs/99:98-107`) | **Stark** |
| Selektive Zensur `d=1` | Kein Schutz — 100% Abhängigkeit (`docs/11:101`) | **Schwachstelle** — nur Multi-Homing hilft |
| `d≥3` Multi-Homing | `m=3` über 3 Kanten, Fan-out `k=√d+1` perkoliert | **Stark** |
| Botnetz-Selbst-Bürgschaft im Kreis | `Sycophant-Isolation` (`docs/07:89`), Kanten-Drosselung | **Stark** |
| Langzeit-Partition Dorf A/B | `PROVISIONAL` Gelb-Warnung + `min(H_canon)` Heilung (`docs/02:79-102`) | **Robust** |

**Spezifikationsbedarfe:**
- `WARN_SINGLE_BRIDGE_BOTNET` (`docs/17:93-99`) auf `WARN_SINGLE_EDGE_CENSORSHIP_RISK` erweitern: Dashboard zeigt `d=1` Risiko + Empfehlung „Verbinde dich mit ≥2 weiteren Freunden“.
- `REVOKE` Wire-Format + Propagation (siehe Kap. 3.2) — sonst kann isolierter Knoten nicht „fliehen“.
- `distinct_edge_mask` eliminiert: Die Präsenzprüfung erfolgt rein über die 24h-Schiebefenster-Bitmaske (`hourly_bitmask`, $\ge 8/24$), wodurch Kantenmasken-Kollisionen vollständig entfallen.

### 7.3 Was fehlt noch? Welche Invarianten oder Edge-Cases müssen präziser spezifiziert werden?

**A) Fehlende / zu präzisierende Invarianten:**

| Lücke | Vorschlag Neue INV | Quelle |
| :--- | :--- | :--- |
| Promotion Idempotenz | `INV-0206 Idempotente Promotion: lock_hash identisch + status_tag monoton ist kein Conflict` | `audit: K-05` |
| Hysterese-Bindung im Zertifikat | `INV-0806 Hysterese-Bindung: FINAL (0x01) nur wenn N_aktiv≥20 seit 24h, via WOT-Multiset beweisbar` | `audit: K-04/H-04` |
| RAM-Hard-Limit | `INV-1207 RAM-Hard-Limit & Bounded persist_tx (10k)` | `audit: M-03` |
| Whistleblower-Schutz | `INV-0305 ConflictWithEvidence zählt nicht als missing_count` | Kap. 5.4 |
| 24h-Präsenz-Invarianz | `INV-0704/1101` präzisieren: Reine 24h-Bitmaske ($\ge 8/24$), kein $m \ge 3$-Pfadzwang | `audit: M-06` |
| 0-RTT Whitelist SSOT | `INV-1004/1009` auf `docs/10:100-122` vereinheitlichen, `ShardDigestRequest`+`ActiveSyncRequest` whitelisten + Rate-Limit | `audit: H-02` |
| Silent Drop → SignedRejection | `INV-0906` ersetzen durch `SignedRejection{reason,current_anl,quota}` Pflicht | `audit: M-02` |
| Digest-Quorum `≥14` | `INV-0304` kodifizieren: `≥14 → D*`, `<11 → backoff`, `11..13` **streichen** | `audit: M-05/H-09` |
| LEAVE Semantik | `INV-0708 LEAVE: Monotonie epoch_day, Replay-Schutz, 60-Tage Re-Join Sperre` | Kap. 5.1 |

**B) Edge-Cases ohne Spezifikation:**

1. **T₀ vor/nach `now` Build:** Was wenn Binary mit `T₀=2026-02-01` am `2026-01-15` gestartet wird? `epoch_day` negativ → `u32` underflow. Norm: `if now<T₀ → epoch_day=0, status=PROVISIONAL`.
2. **`valid_until` Bucket-Rundung:** `docs/09:18` `valid_until` korreliert mit Wert → Traffic-Analyse (`audit: M-04`). Vorschlag: Auf Wochen-Bucket runden + `±1h` Noise.
3. **`AccountTag` Privacy:** `BLAKE3(Client_PubKey||Node_Secret_Salt)` (`docs/13:63`) bei Salt-Leak linkbar. Vorschlag: VRF/Blind Signature (`audit: M-04`).
4. **Cold-Path Locator `max 16` vs `Vec<String>` unbounded** (`docs/00:77` vs `docs/06:204` `audit: M-01`): `max 16` + `max 64` Batch-Locks + `µBJ`-Quota begrenzen.
5. **Offline-Queue:** `docs/06:42` `UNBEKANNT ⚪` Offline-Pending ohne Größe/TTL → Reconnect-Storm. Vorschlag: `max 100 Locks, 7 Tage, FIFO` (`audit: O-03`).
6. **Timeout-Matrix fragmentiert:** `200ms` Hedged, `150ms` Shard Broadcast, `600ms` Quorum, `500ms` PULL Backoff, `20–25s` KeepAlive (`audit: O-03`): Zentrale Tabelle in `docs/04`.

**C) Systemische Angriffsvektoren — konsolidiert:**

| Vektor | Klasse | Status | Restrisiko |
| :--- | :--- | :--- | :--- |
| Shard-Equivocation | A2 | **Abgedeckt** Säule 1 `<50µs` + L1 Slashing | Minimal — nur bei BLS-PoP Lücke |
| Ingress-Counter Betrug | A5 | **Abgedeckt** Säule 2 + Receipt-Gossip `p=0.02%` → `2.2 Min` Detektion | Mittel — aber `timestamp_ms` + EMA Lücken (`H-03`) |
| Heartbeat-Spam | A7 | **Abgedeckt** Säule 3 + 1024-Slot Detektor + `±60s` Drop | Minimal |
| Lazy Node / Sycophant | A1/A4 | **Abgedeckt** Piggyback + Rang21 + Dunbar-RED | Robust |
| Zensur/Drop | A3 | **Abgedeckt** `14/20` BFT + Hedged Failover | Robust, außer Silent-Drop Tarnung (`M-02`) |
| Tier-3 DDoS | B1 | **Teilweise** Ed25519 `50µs` + Bounded Pool `256 MB` | **Hoch** — `audit: H-05`: Keys offline generierbar, Pool saturiert, `/24` Prefix CGNAT-Precomputation |
| Fake Genesis | B2/B3 | **Abgedeckt** Lazy Ingest + `2ms` on-the-fly Verifikation | Robust |
| Hardware Exhaustion | B4 | **Teilweise** `144B` + `µBJ` + TTL | **Hoch** — `M-03` unbounded `DashMap`/`mpsc` |
| Grinding | A6 | **Abgedeckt** `1–3h` PoW + 8h Hysterese | Robust, außer Flapping `F-01` |
| Time-Jacking | — | **Lücke** | **Mittel-Hoch** — kein NTS, EMA nondet. |
| Eclipse `d=1` | A4 | **Lücke** | **Mittel** — Multi-Homing Pflicht fehlt als MUST |

---

## 8. Priorisierte Handlungsempfehlungen (Roadmap)

Basierend auf `audit: Priorisierte Umsetzungs-Roadmap` (`docs/audit_und_optimierungspotenziale.md:240-249`), vertieft um Knotenperspektive:

### P0 — Konsens-kritisch (vor jedem Code-Freeze, 1–2 Tage Spec)

| # | Befund | Aktion | Files |
| :--- | :--- | :--- | :--- |
| **P0-01** | Domain-Separation K-01 | Kanonische `sig_digest()` mit `len\|\|tag` in `docs/04` + `docs/10:3.2` SSOT, alle Preimages aliasen, Registry auf 8 Tags erweitern, `GENESIS_ROOT` normieren | `docs/10:163-193`, `docs/03:177`, `docs/08:59`, `docs/04:226,238` |
| **P0-02** | Signatur-Aggregation K-02 | Entscheiden: **Ed25519 Batch-Verify** (empfohlen) — `BLS 96B` streichen; ShardWorkAttestation ersatzlos streichen zugunsten direkter P2P-Reziprozität | `docs/04:64`, `docs/10:499`, `docs/04:60` |
| **P0-03** | Quorum-Formel K-03 | SSOT `floor(2R/3)+1` (`docs/00:96`), `README:22` + `docs/05:108` korrigieren, Helper `quorum(r)=(r*2)/3+1`, Testvektoren `R=1..20` | `README:22`, `docs/00:96`, `docs/05:108` |
| **P0-04** | FINAL Hysterese K-04/H-04 | Zweistufig `FINAL_candidate` vs `FINAL_stable`, `docs/02:70` + `docs/06:98` um `hysteresis_ok` ergänzen, `GET /network_status` | `docs/02:70`, `docs/03:178`, `docs/08:46-60` |
| **P0-05** | Shard-ID Off-by-One K-06 | `docs/03:14` + `docs/06:77` auf `from_be_bytes([0],[1])` ohne `mod` korrigieren, `INV-0302` ergänzen, Fuzz-Test | `docs/03:14`, `docs/04:248` |

### P1 — Partition & DoS (vor Testnetz, 3–5 Tage)

| # | Befund | Aktion |
| :--- | :--- | :--- |
| **P1-01** | Promotion Race K-05 | `INV-0206` Idempotenz, `lock_hash` identisch → Upgrade kein Conflict, nur `status_tag` monoton, sonst `µBJ` voll, Retry 60s exp max 3, `409` bricht ab |
| **P1-02** | Session/epoch_seq H-01 | `session_seq` per-Connection Gap, applikatorisch nur `epoch_seq` global monoton `(gateway,epoch_day)` validieren, Parallel-Broadcast ≠ Fork |
| **P1-03** | 0-RTT Whitelist H-02 | `ShardDigestRequest` + `ActiveSyncRequest` whitelisten + per-IP token bucket + Bloom Filter global |
| **P1-04** | Argon2 DoS H-05 | Tier-3 Puzzle **vor** Ed25519, token bucket vor Sig, Pool auf `CPU_cores` isoliert (rayon≠Tokio), separate UDP-Ports VIP/Public, volles `/32`+ConnectionID statt `/24` |
| **P1-05** | TTL Resurrection H-06 | `valid_until>now+30s && ≤root.valid_until`, Tilgung `valid_until+30s grace`, `TABLE_TTL_BUCKETS` `O(1)` Bucket-Drop, Batch `min(valid_until)>now+promote_window` |
| **P1-06** | Merge-Zeit H-07 | `docs/08:72` korrigieren: Peering `<100ms`, Presence `≥8h`, FINAL `≥24h`, PoS nur First-Seen `<50ms` |
| **P1-07** | 10:10 Split H-08 | Automat `Pending→Provisional/Final→Void→Expired`, `10:10→409 ConflictWithEvidence+Resolver`, `T_quorum=600ms` zentral |

### P2 — Härtung & Privacy (1 Woche, vor Mainnet)

| # | Befund | Aktion |
| :--- | :--- | :--- |
| **P2-01** | Gradient Proof H-03 | Eine Byte-Jahre Definition (`144B` Wire), `e^{-Δ}` durch `deterministic_decay`, Toleranz ±2%, `timestamp_ms` ±30s Skew |
| **P2-02** | Silent Drop M-02 | `SignedRejection` Pflicht, Receipt-Gossip auch auf Rejections `p=1%` |
| **P2-03** | RAM Hard Limit M-03 | `INV-1207` `max_ram_locks`, `mpsc(10k)` bounded `429`, `ShardDigest` Merkle-Root |
| **P2-04** | Privacy M-04 | `valid_until` Wochen-Bucket+Noise, `AccountTag` VRF, Sharding rotierend oder Onion-Routing |
| **P2-05** | Digest BFT M-05 | `11..13` Fenster streichen, `≥14` sonst Backoff |
| **P2-06** | Dunbar Formel M-06 | `R_soft` kanonisch `docs/11:49`, Receipt `96B` vereinheitlichen |
| **P2-07** | N_aktiv Fragmentierung M-07 | `docs/11:192` SSOT für `is_active`, `15:113` nur KeepAlive, `14:111` `is_active=false` bis `τ_on` |
| **P2-08** | WoT Max-Flow M-08 | Tiefendämpfung `γ=0.9`, Tiefe>3 + Anker-Pfad, 24h-Bitmasken-Präsenz |
| **P2-09** | Heartbeat-Zensur (neu) | `d=1` Risiko-Dashboard, `REVOKE` Wire-Format, Slashing-Detektor 1024 Slots/Cuckoo |
| **P2-10** | Flapping (neu) | `INV-0704` präzisieren, Flap-Dämpfung 2× in 7 Tagen → 48h `IMMATURE` |
| **P2-11** | LEAVE/Purge (neu) | `MsgType::Leave` + Domain-Tag + Replay-Schutz, `TABLE_TTL_BUCKETS`, F2F `REVOKE` Propagation |
| **P2-12** | Time-Jacking (neu) | NTS Pflicht, `±120s` Dorf-Toleranz, EMA deterministisch, Monotonie-Bindung |

### P3 — Simplicity (2 Tage, Ballast abwerfen, `audit: O-01..O-04`)

- `docs/09` auf Hard-Floor + `K=0.05/1.0` kürzen, Zipf/ANL/EMA streichen, `cumulative_micro_byte_years` → `locks_per_day`.
- `HIGH_ASSURANCE 0x02` auf `Q=16/20` anheben oder streichen (`audit: O-02`).
- Zentrale Timeout-Tabelle (`audit: O-03`).
- Attest-Pflicht bei `N<20` aussetzen, Streams 4→2, Tiers 3→2 (`audit: O-04`).

---

## Anhang A — Invarianten-Mapping

| INV | Status | Kommentar |
| :--- | :--- | :--- |
| `INV-0101` Keyless Root | ✅ | T₀-Bindung korrekt, aber `len\|\|tag` ergänzen |
| `INV-0102` Symmetrischer Handshake | ✅ | Fraktal `N=1` identisch — Stärke |
| `INV-0103` Striktes WoT-Gossip-Peering | ⚠️ | Ausnahme für Bootstrap-Relay `UNVERIFIED` nötig |
| `INV-0104` Autorisierte Co-Shard-Verbindungen | ⚠️ | `R<20 → alle N` Ausnahme ergänzen |
| `INV-0201` First-Seen | ✅ | Atomar `<1µs` — tragend |
| `INV-0202` Keine Wiederauferstehung | ⚠️ | Resurrection-Race `H-06` — `+30s grace` nötig |
| `INV-0203` Deterministisches Slashing | ✅ |  |
| `INV-0204` Physische Tilgung | ⚠️ | Bucket-Ringpuffer fehlt |
| `INV-0205` Evidence-gestützter Konfliktmelder | ✅ | Aber Piggyback-Ausnahme fehlt |
| `INV-0301` Kein blindes Replikations-Müll-Syncen | ⚠️ | `H-09`: „Kein proaktiver Push; reaktiver Digest-First PULL selbst-initiiert“ |
| `INV-0302` Trust-Tree-Lokalität | ⚠️ | `K-06`: 2-Byte Big-Endian Präfix präzisieren |
| `INV-0303` Zero-Gossip Shard-Self-Healing | ✅ |  |
| `INV-0304` Quorum-verifizierter PULL-Sync | ⚠️ | `M-05`: `≥14` kodifizieren, `11..13` streichen |
| `INV-0403` Domain-Separation | 🔴 | `K-01`: Zwei Preimages — SSOT nötig |
| `INV-0501` 3-Säulen-Slashing | ✅ | `<100µs` — aber `H-03` Toleranz |
| `INV-0507` Fraktale Bootstrap-Invarianz | ⚠️ | `K-03` `floor` vs `ceil` |
| `INV-0701` Universelle PoW-Prägung | ⚠️ | `E-02` Parameter nicht kanonisch |
| `INV-0702` Menschliche Eintrittsbarriere | ⚠️ | `M-08` Tiefendämpfung fehlt |
| `INV-0703` 24h-Inkubationspflicht | ⚠️ | `I-04` 24h vs 8h Inkonsistenz |
| `INV-0704` Schnelle Reaktivierung | 🔴 | `F-01` 2 Heartbeats vs `8/24+m≥3` |
| `INV-0705` 60-Tage/1-Jahr | ⚠️ | Bounded `mpsc` + Bucket fehlt |
| `INV-0801` Fraktale Shard-Größe | ✅ |  |
| `INV-0802` 1-Byte Status-Prägung | 🔴 | `K-04` 24h Hysterese nicht im Zertifikat beweisbar |
| `INV-0803` Zero Node-to-Node Lock-Replikation | ⚠️ | `H-09`: wie `0301` |
| `INV-0805` Bitmasken-Selbstbeweis | ⚠️ | `K-02` `count_ones` ohne PoP fälschbar |
| `INV-0901` Byte-Jahre | ⚠️ | `H-10` 192 vs 224 |
| `INV-0906` Silent Enforcement | 🔴 | `M-02` → SignedRejection |
| `INV-1003` Domain-Separation | 🔴 | `K-01` |
| `INV-1004` 0-RTT Schreibschutz | ⚠️ | `H-02` Whitelist divergiert |
| `INV-1007` Non-Repudiation Ingress | ⚠️ | `H-01` `epoch_seq` Doppelzählung |
| `INV-1101` Dunbar-RED | ⚠️ | `M-06` `R_soft` Formel divergiert |
| `INV-1703` Deterministische Verhungerung | ✅ | Aber `REVOKE` Wire-Format fehlt |

Neue Invarianten: `INV-0206` (Promotion), `INV-0708` (LEAVE), `INV-0806` (Hysterese-Bindung), `INV-1207` (RAM-Hard-Limit).

---

## Anhang B — Querverweise & File-Line-Index

| Thema | Primär | Sekundär | Audit |
| :--- | :--- | :--- | :--- |
| Genesis & T₀ | `docs/01:14`, `docs/04:226` | `docs/00:11-18` | K-01 |
| PoW Argon2id | `docs/07:14-26` | `docs/13:114-128` | H-05 |
| WoT Bürgschaften | `docs/07:30-36`, `docs/01:73` | `docs/14:63` | M-08 |
| NodePresence Automat | `docs/07:40-72`, `docs/11:171-195` | `docs/07:77-83` | I-04, F-01 |
| Dunbar Gossip | `docs/11:45-236` | `docs/05:A4`, `docs/17:53-70` | M-06 |
| HRW Sharding | `docs/03:10-27`, `docs/04:248` | `docs/08:12-26` | K-03, K-06 |
| Dual-Plane | `docs/01:52-101` | `docs/15:38-59` | D-01..D-04 |
| Lock-Automat | `docs/02:12-50`, `docs/06:212-218` | `docs/12:39-69` | H-08 |
| Resolver min(H_canon) | `docs/02:79-102`, `docs/04:236` | `docs/08:114-117` | — |
| Wire Format | `docs/10:11-86`, `docs/04:64` | `docs/15:78-88` | K-01, K-02, H-02 |
| Thermometer | `docs/09:18-106` | `docs/10:295-313` | O-01, H-10 |
| Ingress Tiers | `docs/13:32-167` | `docs/15:38-59` | H-05, O-04 |
| Storage | `docs/12:39-123`, `docs/14:59-122` | `docs/04:64-179` | M-03, H-06 |
| Merge | `docs/08:68-117` | `docs/03:125-159` | H-07 |
| Social Defense | `docs/17:53-119` | `docs/11:92-170` | M-02 |

---

## Prägnante Zusammenfassung

**Wichtigste Erkenntnisse aus Knotenperspektive:**

1.  **Der Knoten ist souverän, aber blind.** Das Design erzwingt lokale Entscheidungen ohne globale Uhr/Zentralregister — das ist korrekt und alternativlos. Die Kehrseite: Jede Spezifikations-Divergenz zwischen zwei ehrlichen Knoten (Quorum-Formel `floor` vs `ceil` `docs/00:96`/`README:22`, Shard-ID `[0..2]` vs `[0]+[1]` `docs/03:14`/`docs/04:248`, `FINAL` sofort vs 24h Hysterese `docs/02:70`/`docs/08:59`) erzeugt **keinen byzantinischen Angriff**, sondern **ehrlichen Konsens-Split** mit realem wirtschaftlichen Schaden (Händler gibt Ware falsch frei). **Dies sind die vier P0-Blocker.**

2.  **Heartbeat-Zensur ist der unterschätzte Liveness-Angriff.** Bot-Injektion über Brücken ist dank Dunbar-RED (`99.9%` Drop `docs/11:69`) und `m≥3` (`docs/11:78`) praktisch tot. Der reale Angriff ist **selektiver Drop eines einzelnen ehrlichen Knotens durch seinen einzigen Freund** (`d=1`, `docs/11:101` „100% abhängig“). Das ist kein Implementierungsfehler, sondern topologische Realität. **Gegenmittel ist nicht mehr Kryptografie, sondern betriebliches Multi-Homing (`d≥3`) plus Dashboard-Warnung** (`docs/17:92-100` erweitern) und ein definiertes `REVOKE`-Fluchtventil.

3.  **Churn ist billig, Slashing ist teuer — Flapping ist die Grauzone.** `DORMANT→ACTIVE` mit 2 Heartbeats (`INV-0704`) ist zu lax und kollidiert mit `8/24+m≥3` (`docs/11:192`). Ein Angreifer mit 100 `DORMANT`-Nodes (einmalig je 1–3h PoW) kann via 2-Heartbeat-Bursts HRW-Thrashing erzeugen und Digest-First PULLs (`docs/03:145-158`) in den `11..13` Toleranz-Lock treiben — wo 11 statt 14 reicht und BFT bricht (`audit: M-05`). **Fix: SSOT `8/24+m≥3`, Flap-Dämpfung (2× in 7 Tagen → 48h `IMMATURE`), `11..13` Fenster streichen.**

4.  **Time ist der heimliche Single Point of Failure.** `±60s` Frischefilter (`docs/11:129`), `now-30s` Ingress (`docs/12:40`), `timestamp_ms` Sättigung (`docs/10:312` undefiniert) und `e^{-Δ/24h}` EMA (`docs/10:359`) vs `deterministic_decay` (`docs/04:254`) sind vier Uhren mit vier Toleranzen. NTP-Drift von 70s macht einen ehrlichen Dorfknoten für 1h unsichtbar; `valid_until=now+5s` Race ermöglicht Resurrection nach `Zero State Bloat` (`audit: H-06`). **Fix: NTS-Pflicht, `±120s` Dorf-Toleranz, deterministischer `value>> (Δ/17h)`, `valid_until>now+30s` + `+30s grace`.**

5.  **Die Spezifikation ist zu reichhaltig für ihre eigene Sicherheit.** `Q1/Q3/Spread_Damper` (`docs/09:88`), `ANL/EMA` (`docs/10:312`) und `HIGH_ASSURANCE 0x02` (`audit: O-02`) erhöhen die Beweislast (Toleranz, Merge-Divergenz) ohne zusätzliche BFT-Sicherheit — `144B` Cap + `µBJ` + TTL + `M≤1.0` leisten denselben Anti-Spam-Schutz (`audit: O-01`). **Subtraktion ist hier Sicherheitsgewinn:** Hard-Floor `240k BJ/Tag` + `K=0.05/1.0` + `K≤5.0` reicht.

**Handlungsempfehlungen — komprimiert auf 3 Sätze:**

> **Vor Code-Freeze:** Vereinheitliche `sig_digest` mit `len||tag`, entscheide Ed25519 statt BLS, fixiere `Q(R)=floor(2R/3)+1`, `Shard_ID=[0],[1]` und zweistufiges `FINAL` (candidate vs stable) — sonst bauen zwei Teams zwei inkompatible Netze. **Vor Testnetz:** Schließe Flapping (`2 Heartbeats→8/24`), Time-Jacking (deterministischer Decay) und Argon2-Pool-Saturation (Puzzle vor Sig, Bounded `mpsc(10k)` + TTL-Buckets). **Vor Mainnet:** Ersetze Silent Drop durch `SignedRejection`, hebe `d=1` als unsicher ins Dashboard, definiere `LEAVE`/`REVOKE` Wire-Formate und halbiere die Spec (Thermometer-Simplifizierung) — weniger Code, weniger Audit-Fläche, gleiche Sicherheit.

---

*Audit-Methodik: Manuelle Dokumentenanalyse aller `docs/00..17,99` plus konsolidiertes Vor-Audit `docs/audit_und_optimierungspotenziale.md:1-271` (37 Rohbefunde → 28 priorisiert). Verifikation via `file:line` + `INV-*` Querverweis. Reproduktion via `docs/16_chaos_testing_und_simulation.md` DST-Matrizen (Seed `0x42`/`0xDEADBEEF`) für alle neuen Befunde empfohlen (`test_quorum_formula_consistency`, `test_shard_id_routing_determinism`, `test_heartbeat_censorship_single_edge`, `test_flapping_hrw_thrashing`, `test_time_jacking_ntp_drift`).*
