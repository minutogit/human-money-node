# 📋 HuMoCo Layer-2 — Master-TODO & Konsolidierungs-Roadmap

> **Status:** Post-Initial-Audit (Phase 0–6 implementiert, Härtung & Konsolidierung ausstehend)  
> **Credo:** *"In der Dezentralität gibt es kein Vertrauen, nur mathematische Beweise."*  
> **Doktrin:** *"Subtraktion vor Konstruktion – Keine I/O auf dem Hot-Path – Strikte 409-Kollisionssemantik"*

Dieses Dokument fasst die Ergebnisse der 3 KI-Audit-Läufe (Spezifikations-Abgleich, Byzantinische Härtung & Systemdynamik) in einer priorisierten, sofort abarbeitbaren Aufgabenliste zusammen.

---

## 🚦 Übersicht der Prioritätsstufen

| Priorität | Thema | Fokus | Status |
|---|---|---|---|
| **P0 (Kritisch)** | **Sicherheits- & Crash-Blocker** | Double-Spend 409-Semantik, Hot-Path Lock-Contention, Flush-Worker Shutdown & Durability | 3 / 3 erledigt |
| **P1 (Hoch)** | **Protokoll- & DoS-Härtung** | PoW-Replay, Quota-TOCTOU, BLAKE3-Domain-Längenpräfixe, Equivocation-Schärfung, Slowloris | 4 / 4 erledigt |
| **P2 (Mittel)** | **Netzwerk- & Sharding-Integration** | Shard-Quorum-Broadcast, Digest-First-Sync, Reconnect-Jitter, RAM-Index, F2F-Pubkey-Auth | 5 / 5 erledigt |
| **P3 (Client)** | **Client- & POS-Integration** | QuorumCertificate im Wire-DTO, Plausibilitätsprüfung in `human-money-core`, Ampel-UI | 4 / 4 erledigt |

---

## 🔬 Forschungs- & Klärungs-TODOs (Architektur & Konsens-Garantien)

### ⚠️ TODO-ARCH-01: Schutz vor Fake-Partitionen (Sybil-Schattennetze vs. Echter FINAL-Merge)
- **Problemstellung:** 
  Wenn zwei isolierte Netze mergen und beide einen `FINAL`-Lock auf denselben Parent besitzen:
  Ein Angreifer könnte im Verborgenen 20 eigene Sybil-Knoten (z. B. auf gemieteten VMs) betreiben, dort offline einen alternativen Double-Spend mit 20 eigenen Fake-Signaturen auf `FINAL` attestieren, und dann das Netz fluten. Würde der echte `FINAL`-Lock aus dem Hauptnetz einfach per $\min(H_{\text{canon}})$ überschrieben, könnte ein Angreifer gezielt Transaktionen revertieren, deren Hash ungünstig liegt.
- **Zu klärende Fragen:**
  1. **Web-of-Trust / Dunbar-Schutzschranke:** Verhindert die 24h-Inkubationszeit und F2F-Gossip-Sättigung (Spec 11), dass ein solches 20-Knoten-Schattennetz überhaupt als legitime Shard-Knoten anerkannt wird?
  2. **First-Seen-Schutz bei Diskrepanz im Alter:** Hat ein seit Tagen im Hauptnetz verankerter `FINAL`-Lock absoluten Vorrang vor plötzlich auftauchenden neuen Zweigen?
  3. **Keine L1-Kautionen / Kein Staking (Klarstellung & Invariante):** In HuMoCo gibt es prinzipbedingt **keine Kautionen, kein Staking und keine Geld-Deposits** auf L1 oder L2 (der Layer-2-Node ist ein blindes Sperrregister ohne Kenntnis von Kontoständen, Währungen oder Konten). Wirtschaftliches Gewicht und Sybil-Schutz entstehen durch das rechenintensive Argon2d-Mining des Shard-Tickets (`HrwRoutingId`), die 24h-Inkubationszeit und die F2F-Freundschaftskanten im Web-of-Trust. Bei einer Doppelsignatur (Equivocation) wird keine Kaution geslasht, sondern der Täter liefert mit seinen zwei Signaturen den unanfechtbaren Beweis (`HUMOCO_V1_EQUIVOCATION`): Der Verlierer-Zweig wird via $\min(H_{\text{canon}})$ atomar VOID, die Knoten-Identität (`NodePubKey`) wird permanent netzweit gebannt, das geminte Shard-Ticket entwertet und alle F2F-Freundschaftskanten im Web-of-Trust werden unwiderruflich gekappt (vollständige Reputationsvernichtung).
- **Status:** Für nachgelagerte Architektur-Runde vorgemerkt.

### ⚠️ TODO-ARCH-02: Shard-Verbindungslimit, Connection-Pooling & Lazy-Node-Detektion bei Großskalierung ($N \ge 5.000$)
- **Problemstellung & Netzwerk-Kombinatorik:**
  Bei $2^{16} = 65.536$ Shards und Top-20-Quoren existieren netzweit $1.310.720$ Shard-Slots.
  Bei $N = 5.000$ Knoten ist jeder Einzelknoten im Schnitt für $\approx 262$ Shards zuständig. Da HRW ($\text{BLAKE3}(\text{NodeID} \parallel s)$) für jeden Shard pseudozufällig permutiert, teilt sich jeder Knoten mit:
  $$1 - \left(1 - \frac{19}{4.999}\right)^{262} \approx 63{,}1\% \approx 3.150 \text{ distinkten Nachbarknoten}$$
  mindestens einen gemeinsamen Shard.
- **Zu klärende Gefahren & Fragestellungen:**
  1. **Ressourcen- & Keep-Alive-Kollaps bei flachen P2P-Verbindungen:**
     Würde ein Knoten versuchen, zu allen $\approx 3.150$ Co-Shard-Knoten permanente QUIC-Verbindungen zu halten, entstünden $\approx 250 \dots 300\,\text{MB}$ RAM-Overhead (TLS-States, Flow-Control) und bei 5s-Intervallen über $600$ Keep-Alive-Pings/Sekunde reiner Leerlauf-Traffic.
  2. **Interferenz mit Lazy-Node-Detektion:**
     Wie erkennt ein Gateway oder Shard-Knoten zuverlässig, ob ein Co-Shard-Knoten "faul" ist (Arbeitsverweigerung, Timeout, böswilliges Schweigen), wenn Verbindungen nicht dauerhaft bestehen, sondern on-demand/flüchtig aufgebaut werden?
     - Führt ein verzögerter QUIC-Handshake (Paketverlust / NAT-Traversal) zu einem unberechtigten Fehlschlag (`missing_count += 1`), obwohl der Knoten gar nicht faul ist?
     - Wie funktioniert das 4-Byte Piggyback-Feedback (`signers_bitmask`) bei flüchtigen Verbindungen, ohne dass Shard-Knoten untereinander Verbindungsorgien starten müssen?
     - Wie wird verhindert, dass faules Verhalten erst nach vielen Sekunden bemerkt wird, wenn Verbindungen jedes Mal neu verhandelt werden müssen?
- **Vorgeschlagene Lösungsarchitektur:**
  - **Striktes 2-Tier Connection-Pooling:**
    - *Tier 1 (F2F-Freunde, 10–50 Peers):* Permanent offen, 5s Keep-Alive, Träger für Gossip und Heartbeats.
    - *Tier 2 (Shard-Direct, bis zu 3.150 Peers):* Flüchtiger LRU-Pool (z. B. 128–256 gleichzeitige Verbindungen), **kein** Keep-Alive, automatisches Schließen nach 15–30s Inaktivität (`IdleTimeout` $\neq$ Fehler).
  - **Gateway-fokussierte Lazy-Node-Detektion:**
    - Nur das Gateway, das den PoS-Lock parallel an die Top-20 broadcastet, misst die Antwortzeiten und verwaltet die lokale Suspension (`record_missing`).
    - Shard-Knoten müssen untereinander keine Verbindungen zur gegenseitigen Überwachung halten ($\Delta \text{Last} \le 0$).
- **Status:** Für nachgelagerte Netzwerk- & Skalierungs-Runde vorgemerkt.

### 💡 TODO-ARCH-03: Topologie-Erkenntnis aus First-Seen-Divergenz (Netz-Merge-Heuristik vs. KISS-Konsens-Symmetrie)
- **Fragestellung & Ausgangsidee:**
  Jeder Knoten führt in seiner Knotentabelle (`known_network_nodes` / `PeerPresenceEntry`) einen Zeitstempel bzw. Reifegrad des Erstkontakts (`first_seen` / `maturity_hours`). Wenn ein Knoten plötzlich eine Welle neuer Knoten registriert (z. B. 90 % der bekannten Knoten haben ein ganz frisches `first_seen`, während nur 10 % lange bekannt sind), kann er lokal schlussfolgern, dass ein massiver Netzwerk-Merge (oder das Andocken an ein Großnetz) stattgefunden hat.
  *Frage:* Kann und soll diese Information im System für Sonderbehandlungen bei Merges genutzt werden, oder verbietet die KISS-Doktrin ("Subtraktion vor Konstruktion") Sonderfälle im Konsens?
- **Architektonische Analyse & Gefahren von Sonderregeln (KISS-Filter):**
  1. **Das Sybil-Chamäleon (Ununterscheidbarkeit):**
     Aus rein lokaler Sicht eines Knotens ist eine Welle frischer `first_seen`-Knoten mathematisch nicht unterscheidbar von einem feindlichen Sybil-Angriff (z. B. 1.000 gefakte Bots über eine Brücke) oder einem Kaltstart/DB-Verlust des eigenen Knotens. Würde der Knoten "viele neue Knoten" als vertrauenswürdigen Merge fehlinterpretieren und Schutzschranken lockern, öffnet er Angreifern Tür und Tor.
  2. **Gefahr von Split-Brain durch asymmetrische Perspektiven:**
     Wenn Dorf A ($N=10$) mit Stadt B ($N=1.000$) mergt, sieht Dorf A $99\,\%$ "neue" Knoten, Stadt B jedoch nur $1\,\%$ "neue" Knoten. Wäre das Konsensverhalten an das lokale `first_seen`-Verhältnis gekoppelt, würden beide Hälften mit unterschiedlichen Regeln operieren. Konsens erfordert strikte Symmetrie und Invarianz.
  3. **DoS-Risiko auf dem Hot-Path:**
     Würde ein "Merge-Zustand" Transaktionsprüfungen pausieren oder drosseln, könnte ein Angreifer durch das periodische Einstreuen neuer Node-IDs den weltweiten PoS-Zahlungsverkehr lahmlegen.
- **Bestehende elegante Lösung ohne Sonderregeln (Occam's Razor):**
  Das System löst die Merge-Dämpfung bereits heute ohne Sonderfall:
  - **24h-Inkubation (Spec 11):** Neue Knoten sind in den ersten 24h `IMMATURE` und besitzen kein Stimmrecht in HRW-Shards ($0\,\%$ Konsens-Einfluss am Tag 1).
  - **Neulings-Pacing (INV-1104):** Unbekannte Knoten fließen nur gedrosselt ins Netz ein ($\varnothing 1\,\text{Node/h}$ pro Kante) und werden bei Stau via QUIC-Ping enttarnt.
  - **24h-Hysterese (Spec 08):** Der Phasenübergang von `PROVISIONAL` (Gelb) zu `FINAL` (Grün) erfordert $N \ge 20$ stabil über 24 Stunden. Lokale Dorftransaktionen laufen währenddessen mit $Q=4/5$ unterbrechungsfrei weiter.
  - **Symmetrische Konfliktlösung (Spec 08):** Bei Doppel-Ausgaben während einer Trennung entscheidet zeit- und netzunabhängig rein $\min(H_{\text{canon}})$.
- **Valider Einsatzzweck: Rein passive Diagnose & Telemetrie (INV-1701):**
  - Das Verhältnis von frischen zu alten `first_seen`-Knoten eignet sich hervorragend als **nicht-autoritäres Telemetrie-Event** (`INFO_TOPOLOGY_SURGE_DETECTED` / `POSSIBLE_NETWORK_MERGE`).
  - Dient dem Node-Betreiber und Monitoring zur Lageeinschätzung ("Netz-Zusammenführung beobachtet"), greift jedoch **niemals** automatisch in Konsens- oder Routing-Entscheidungen ein (`triggers_auto_ban() == false`).
- **Status:** Konzeptionell geklärt (KISS-Entscheidung: Keine Konsens-Sonderregeln, rein diagnostischer Telemetrie-Nutzen). Für Release-Dokumentation vorgemerkt.

### 🛡️ TODO-ARCH-04: Adaptives Gateway-Ingress-Budgeting, Dynamische PoW-Bremse & Autonome VIP-Sicherung (Spec 09 & 13)
- **Problemstellung & Gateway-Verantwortung:**
  Ein HuMoCo-Knoten in Gateway-Rolle schleust Transaktionen externer Akteure (Kassen, Wallets, Bürger-Apps) in die zuständigen Shards des Netzwerks ein.
  Dabei stehen drei Ingress-Klassen im Wettbewerb um begrenzte Gateway- und Upstream-Ressourcen:
  1. **Tier 1 (VIP / Merchant):** Zahlende Händler & Kassen mit harter PoS-SLA (< 50 ms Latenz, 100 % Verfügbarkeit).
  2. **Tier 2 (F2F / Friends):** Vertraute Freunde und Nachbarn im Web-of-Trust (geteiltes Freikontingent).
  3. **Tier 3 (Public / Free-Tier):** Unregistrierter, anonymer Web- und Notfallzugang für jedermann.
  
  *Die Kerngefahr:* Wird der freie Tier-3-Zugang von Bots oder Sybil-Angreifern mit Anfragen überflutet, darf dies **unter keinen Umständen** dazu führen, dass:
  - die Latenz oder Kapazität der VIP-Kassen beeinträchtigt wird (`INV-1301`),
  - der Gateway seine eigene netzwerkweite Upstream-Sendequote (`daily_quota` aus dem Netzwerk-Thermometer, Spec 09) an Müll verbraucht und im Shard gedrosselt wird,
  - der Server-Admin manuell eingreifen oder Parameter im Stress nachjustieren muss.

- **Vorgeschlagene Architektur & KISS-Design ("Hands-Off Auto-Balancing"):**
  1. **Minimale Admin-Konfiguration (`humoco.toml`):**
     Der Admin konfiguriert lediglich wenige intuitive Prozentwerte und Schwellen:
     ```toml
     [ingress.budget]
     # Prozentuale Aufteilung der maximalen Upstream-Sendekapazität (Spec 09)
     vip_reserved_percent = 70    # 70% exklusiv für VIP/Kassen reserviert (Haralds PoS-Garantie)
     f2f_share_percent = 20       # 20% für Freunde & Web-of-Trust
     public_share_percent = 10    # 10% Basiskontingent für freien Bürgerzugang

     # Dynamische PoW-Schwierigkeits-Grenzen für Tier 3 (BLAKE3-Bits oder Argon2id)
     min_pow_difficulty = 8       # Normalbetrieb: Sofort lösbar (~1-2s auf Mobilgeräten)
     max_pow_difficulty = 24      # Notbremse bei Sturm: Massiv erschwert (~30-60s)
     ```
  2. **Strikte Wasserstands-Isolation (Watermark Protection):**
     - **VIP-Invarianz:** Tier 2 und 3 können zusammen *niemals* mehr als $(100 - \text{vip\_reserved})\,\%$ des aktuellen Sendebudgets beanspruchen.
     - Selbst wenn $10.000$ Bots gleichzeitig anfragen, ist der VIP-Kanal physisch und rechnerisch frei.
  3. **Reaktive Dynamische Schwierigkeits-Kurve ($D_{\text{adaptive}}$):**
     - Der Knoten misst die Auslastung $U \in [0.0, 1.0]$ des Tier-3-Kontingents bzw. der Tier-3-Worker-Queue in gleitenden 10-Sekunden-Fenstern.
     - Liegt die Last unter $50\,\%$, bleibt die Schwierigkeit auf $D_{\min}$ (1–2 Sekunden Aufwand für Bürger).
     - Steigt die Last über $50\,\%$ (z. B. durch Botnetze), skaliert die Schwierigkeit quadratisch nach oben:
       $$D(U) = D_{\min} + \left\lceil (D_{\max} - D_{\min}) \cdot \left(\frac{U - 0{,}5}{0{,}5}\right)^2 \right\rceil \quad \text{für } U > 0{,}5$$
     - *Effekt:* Ein Bot, der die Rate verzehnfacht, treibt die Schwierigkeit schlagartig an den Anschlag. Der Rechenaufwand für den Angreifer explodiert, die Anfrageflut bricht am eigenen CPU/Memory-Limit des Angreifers zusammen, während reguläre Einzelanfragen weiterhin durchkommen.
  4. **Cheap-Checks-First & RED (Random Early Drop):**
     - Überschreitet die Ingress-Queue selbst bei maximaler Schwierigkeit $90\,\%$, greift sofort Random Early Drop (RED): Unfertige oder ungelöste Tier-3-Pakete werden in $0\,\mu\text{s}$ lautlos abgeworfen, ohne Server-CPU zu binden.
  5. **Autonome Rückkehr zur Baseline:**
     - Ebbt der Angriff ab, sinkt $U$ und die Schwierigkeit gleitet exponentiell gedämpft (Decay-Halbwertzeit: 30s) wieder auf $D_{\min}$ zurück.
  6. **Maturity-Aging für Free-Tier (Tor-Proposal-327 & Nostr-NIP-13 Analogie):**
     - *Idee:* Bekannte Free-Tier-Nutzer aus Friedenszeiten erhalten bei einem Bot-Angriff Vorrang vor völlig neuen, ephemeren Anfragen.
     - *KISS-Entscheidung (3 statt 4 Tiers):* Kein separates 4. Tier nötig (vermeidet Konfigurations-Overhead). Stattdessen wird Tier 3 intern zweistufig differenziert nach **Reifegrad (`first_seen` / Alter)**:
       - **Gereifte Free-Clients ($\ge 24\,\text{h}$ bekannt):** Dürfen selbst im Sturm zum Basistarif ($D_{\min}$) anfragen (gedeckelt auf z. B. max. 3–5 Locks/Tag, um Sybil-Pre-Farming zu neutralisieren).
       - **Brandneue / unbekannte Anfragen:** Tragen die volle adaptive Last-Schwierigkeit ($D_{\text{adaptive}}$ bis $D_{\max}$).
     - *Stateless Smart-Client Loyalty-Cookie (Zero-RAM Overhead):*
       Der Server muss keine Millionen Free-Keys speichern. Nach dem ersten erfolgreichen Lock in Friedenszeiten stellt der Gateway dem Client ein signiertes Ticket aus:
       $$\text{MaturityCookie} = \text{BLAKE3\_HMAC}(\text{NodeSecret}, \text{AccountTag} \parallel \text{IssuedEpochDay})$$
       Der Smart-Client verwahrt das Cookie selbst. Im Sturmfall weist er es vor; der Server verifiziert die Signatur in $< 1\,\mu\text{s}$ ohne Datenbank-Lookup!
- **Status:** Für Implementierungs-Phase vorgemerkt. Konsistente Ergänzung zu Spec 09 (Thermometer) und Spec 13 (Tiering).

### 🔄 TODO-ARCH-05: Dynamische Node-ID / Shard-Ticket-Rotation (Argon2d / HRW) — Churn-Risiko, Shard-Hopping vs. KISS-Selbstregulierung
- **Problemstellung & Ausgangsidee:**
  Jeder Knoten besitzt einen lebenslang festen `NodePubKey` (Ed25519 für F2F-Freundschaftskanten und TLS) und ein dynamisches Shard-Ticket `HrwRoutingId = Argon2d(NodePubKey || Nonce || T0)` für das HRW-Rendezvous-Sharding.
  Ein Knoten kann prinzipiell jederzeit eine neue Nonce berechnen (Argon2d-Mining) und nach Ablauf der 24h-Inkubationswand mit einer neuen `HrwRoutingId` im Sharding antreten.
  *Die Kernfrage:* Was passiert, wenn Knoten dies fortlaufend ("immerzu") tun? Kann dies negative Auswirkungen auf das Sharding-Netzwerk haben (z. B. Churn, Sync-Sturm, Shard-Hopping), und muss dies künstlich limitiert werden oder regelt die Physik/KISS das Problem von selbst?

- **Analyse potenzieller Risiken & Angriffsflächen:**
  1. **Topologie-Churn & Resync-Last:**
     - Bei jeder neuen `HrwRoutingId` permutieren die HRW-Scores für alle $2^{16} = 65.536$ Shards. Der Knoten scheidet aus den Top-20 seiner bisherigen Shards aus und rückt in völlig neuen Shards in die Top-20 nach.
     - Im neuen Shard fehlen dem Knoten die aktiven Locks im `RamIndex`. Er muss sofort einen `Sync-Stream` zu Co-Shard-Peers öffnen. Ständiges Rotieren erzeugt daher permanente Resync-Bandbreite.
  2. **Gezieltes Shard-Targeting (Guerilla-Grinding):**
     - Könnte ein Angreifer offline Nonces farmen, um gezielt in einen bestimmten Shard $S$ zu gelangen (z. B. um dort Transaktionen zu zensieren oder Quoren zu stören)?
     - *Rechnerischer Aufwand:* Da Argon2d an den unveränderlichen `NodePubKey` gebunden ist ($m = 64\,\text{MB} - 2\,\text{GB}$, mind. 1h Server / 4h Raspi), erfordert ein Top-20-Platz bei $N = 1.000$ Knoten im Schnitt $1.000 / 20 = 50$ Argon2d-Durchläufe ($\approx 50$ Stunden Volllast-CPU).
     - *Kein Überraschungseffekt:* Durch die 24h-Inkubationswand sieht das gesamte Netz das neue Ticket 24 Stunden im Voraus. Spontane Last-Minute-Angriffe auf ein PoS-Quorum sind physikalisch unmöglich.
  3. **Umgehung von Strafen oder schlechtem Ruf?**
     - *Slashing / Banns:* Wer eine Doppelsignatur leistet (Equivocation), wird am **`NodePubKey`** gebannt und verliert alle F2F-Freundschaftskanten. Ein neues Shard-Ticket nutzt dem Täter exakt $0\,\%$.
     - *Faulheits-Malus (Lazy-Node):* Gateways messen Timeouts auf der TLS/QUIC-Verbindungsebene (`NodePubKey` / IP), nicht an der Routing-ID. Ein Shard-Wechsel wäscht keinen lokalen Verbindungs-Malus rein.

- **KISS-Bewertung & "Subtraktion vor Konstruktion":**
  - **Ehrliche Knoten haben keinen Anreiz zur Dauer-Rotation:**
     Laut Spec 07 (Headroom) rotiert ein ehrlicher Knoten nur dann, wenn der Netzwerk-Median-PoW über Jahre gestiegen ist ($H < 1.2$). Warum sollte ein Knotenbetreiber freiwillig dauerhaft Strom und CPU verbrennen, nur um ständig Shards zu wechseln und Resync-Latenzen zu erleiden?
  - **Die 24h-Inkubationswand ist bereits ein natürlicher Rate-Limiter:**
     Ein Knoten kann physikalisch maximal einmal alle 24 Stunden seine Shard-Zugehörigkeit wechseln. Schnelles Oszillieren / Flapping im Sekunden- oder Minutentakt ist durch das Protokoll bereits zu $100\,\%$ ausgeschlossen.
  - **Quorum-Immunität ($14/20$):**
     Das Shard-Quorum toleriert bis zu 6 ausgefallene, rotierende oder synchronisierende Knoten. Ein Knoten, der unvorbereitet in einen Shard rotiert und wegen `SYNCING` noch nicht signiert, wird von Gateways übersprungen; Nachrücker (Ränge 21–40) federn die Lücke in $0\,\text{ms}$ ab.
  - **Fazit & KISS-Entscheidung:**
     Es werden **keine neuen bürokratischen Sonderregeln** (wie Migrationsticket-Limits, Verbotslisten oder Quoten-Ablaufdaten) benötigt. Die bestehende Trias aus **Argon2d-Hardwarekosten + 24h-Inkubationswand + fester NodePubKey-Identität** bietet vollkommen ausreichenden Selbstschutz durch Physik.
- **Status:** Für nachgelagerte Architektur- & Skalierungs-Runde vorgemerkt (KISS-Empfehlung: Keine zusätzlichen Sonderregeln).

### ⚖️ TODO-ARCH-06: Spieltheorie des "Storage-Evasion"-Wettlaufs (Free-Rider-Anreiz, Shard-Vermeidung via HRW-Re-Mining vs. Reale Grenzkosten)
- **Problemstellung & Ausgangsüberlegung:**
  Jeder Knoten kann prinzipiell seine `HrwRoutingId` neu minen (neuer Argon2d-Hash mit neuer Nonce oder höherer Schwierigkeit, wenn die Rechenleistung über die Jahre gestiegen ist).
  In einem theoretischen Großnetzwerk mit Millionen von Knoten ($N \ge 1.000.000$) existieren netzweit genau $65.536 \times 20 = 1.310.720$ Shard-Slots.
  *Die Kernfrage:* Entsteht für Node-Betreiber ein spieltheoretischer Anreiz zum "Storage Evasion" (Free-Rider-Verhalten / Race to the Bottom), indem sie gezielt eine `HrwRoutingId` erwürfeln/re-minen, mit der sie in keinem einzigen Shard in den Top-20 landen? Dadurch müssten sie keine Shard-Daten speichern und keine Quorum-Prüfungen durchführen, könnten aber dennoch voll als Gateway fungieren und Gebühren/Transaktionen bedienen.

- **Mathematische & Spieltheoretische Analyse:**
  1. **Kombinatorische Wahrscheinlichkeit nach Netzwerkgröße ($N$):**
     - Die Wahrscheinlichkeit, für einen einzelnen Shard *nicht* in den Top-20 zu sein, beträgt $1 - \frac{20}{N}$.
     - Die Wahrscheinlichkeit, für **alle $65.536$ Shards gleichzeitig** in keinem einzigen Top-20-Slot zu sein, beträgt:
       $$P(\text{0 Shards}) = \left(1 - \frac{20}{N}\right)^{65.536}$$
     - **Bei $N = 1.000$ Knoten:** $P \approx (0{,}98)^{65.536} \approx 10^{-574}$ (physikalisch unmöglich).
     - **Bei $N = 10.000$ Knoten:** $P \approx (0{,}998)^{65.536} \approx 10^{-57}$ (rechnerisch unmöglich).
     - **Bei $N = 100.000$ Knoten:** $P \approx \exp\left(-\frac{65.536 \times 20}{100.000}\right) \approx e^{-13{,}1} \approx 2 \times 10^{-6}$ (1 zu 500.000).
     - **Bei $N \ge 1.310.720$ Knoten:** Durchschnitt $\le 1$ Shard pro Knoten. Bei $N = 10.000.000$ besitzen $\approx 87{,}7\,\%$ aller Knoten rein stochastisch $0$ Shards.
     - *Erkenntnis 1:* Für $N < 100.000$ ist das Erwürfeln einer "Zero-Storage-ID" rechnerisch völlig unmöglich. In Millionen-Netzen wiederum ist "0 Shards" der stochastische Normalzustand für fast 90 % aller Knoten, ohne dass manipuliert werden muss.

  2. **Kostenasymmetrie: Argon2d-Mining vs. HuMoCo-Speicherkosten (Zero State Bloat):**
     - *Was kostet das Speichern eines Shards in HuMoCo wirklich?*
       Ein Shard verwaltet $1/65.536$ des weltweiten Verkehrs. Dank Gutschein-TTL (`root.valid_until`) und $144\,\text{Bytes}$ pro Lock hat ein Shard selbst bei 100 Millionen weltweiten Transaktionen/Tag im Schnitt nur $\approx 1.500$ aktive Locks im `RamIndex` ($\approx 216\,\text{KB}$ RAM!).
       Die physischen Speicherkosten für $216\,\text{KB}$ RAM und redb liegen bei $< 0{,}0001\,\text{€}$ pro Jahr.
     - *Was kostet ein Argon2d-Re-Mining?*
       $1\text{--}4$ Stunden CPU-Volllast ($m = 1\text{--}2\,\text{GB}$) kosten $\approx 0{,}04\,\text{€}$ bis $0{,}84\,\text{€}$ an Strom und Hardware-Verschleiß.
     - *Erkenntnis 2:* Das Verbrennen von Strom zum Re-Mining eines Shard-Tickets ist um ein Vielfaches teurer als das Vorhalten der winzigen $216\,\text{KB}$ RAM. Rational handelnde Betreiber haben daher einen **negativen ROI** beim Versuch, Shard-Speicher zu vermeiden.

  3. **HRW-Invarianz & Quorum-Garantie:**
     - HRW ermittelt für jeden Shard $s$ deterministisch die 20 höchsten Scores $\text{BLAKE3}(\text{HrwRoutingId} \parallel s)$ über alle $N_{\text{active}}$ Knoten.
     - Selbst wenn ein Teil der Knoten "schwache" Scores sucht, existiert für jeden Shard immer eine vollständige Top-20.
     - Verweigert ein in die Top-20 gewählter Knoten die Arbeit (Lazy Node), greift die lokale Suspension (`missing_count >= 3`) und Rang 21 rückt in $0\,\text{ms}$ nach.

  4. **Entkopplung von Gateway-Rolle und Shard-Pflicht (Spec 00 & Spec 13):**
     - Ein Gateway ist bereits heute als zustandsloser Vermittler (Stateless Messenger) auf Tier 1 konzipiert.
     - Jeder Knoten (auch solche mit 0 Shards) kann als Gateway fungieren und Zahlungen an die zuständigen Shards routen.

- **Zu klärende Fragen & Härtungsaspekte für die Zukunft:**
  1. **Argon2d-Schwierigkeitsanpassung über Jahrzehnte:**
     Wenn die Rechenleistung über 10–20 Jahre massiv steigt (Moore's Law), greift die Headroom-Metrik ($H = D_{\text{own}} / D_{\text{net\_median}}$ aus Spec 07). Führt ein Anstieg des Netzwerk-Medians dazu, dass alte Tickets graduell neu gemint werden müssen? (Autonomes Hintergrund-Mining bei $H < 1{,}2$).
  2. **Anreiz-Symmetrie:**
     Besteht Bedarf für eine explizite "Proof-of-Storage"-Kompensation oder genügt die bestehende KISS-Physik (extrem geringe Speicherkosten durch $144\,\text{B}$ und TTL-Purge)?
  3. **Fazit:** Die Kombination aus **hohem Argon2d-Mining-Aufwand + 24h-Inkubationswand + extrem geringen Speicherkosten ($144\,\text{Bytes} \times \text{TTL}$)** macht den "Storage-Evasion"-Wettlauf ökonomisch unattraktiv. Das Design ist spieltheoretisch stabil.

- **Status:** Konzeptionell analysiert und für langfristige Spieltheorie- & Skalierungs-Dokumentation vorgemerkt.



### 🔴 P0-1: HMC-Ingress maskiert Double-Spend als `Verified` (Fehlende 409-Semantik)
* **Betroffene Dateien:**
  * `crates/humoco-node/src/storage/engine.rs:24-38` (`HmcRamIndex::insert_or_check`)
  * `crates/humoco-node/src/api/routes.rs:517-540` (`submit_hmc_lock`)
  * `crates/humoco-node/src/api/hmc.rs:213`
* **Problem / Befund:**
  `HmcRamIndex::insert_or_check` prüfte bisher nur die Existenz von `lookup_tag` und gab bedingungslos `Verified` mit `200 OK` zurück. Zudem ignorierte `submit_hmc_lock` Fehler aus `tier_controller.evaluate_and_charge`.
* **Aufgaben:**
  - [x] **409-Semantik in `HmcRamIndex` erzwingen:**
    - Wenn `lookup_tag` vorhanden: Prüfen, ob `existing.t_id == entry.t_id`.
    - Bei Gleichheit $\rightarrow$ `L2Verdict::Verified` (idempotenter Re-Request, `200 OK`).
    - Bei Ungleichheit $\rightarrow$ `L2Verdict::Conflict { existing_lock }` erzeugen und HTTP-Status `409 Conflict` zurückgeben (L2 speichert den 2. Lock nicht; Smart Client Beweis).
  - [x] **Quota-Prüfung in `submit_hmc_lock` scharfschalten:**
    - Fehler von `tier_controller.evaluate_and_charge` nicht verwerfen, sondern bei Quota-Erschöpfung / ungültigem Token mit `429 Too Many Requests` bzw. `401 Unauthorized` abbrechen.
  - [x] **E2E-Test schreiben:**
    - Testfälle in `api_tests.rs` und `cluster_e2e_tests.rs`: Zwei Locks mit identischem `ds_tag`, aber unterschiedlichen `t_id` einsenden $\rightarrow$ Request 1 liefert `201 Created`, Request 2 MUSS zwingend `409 Conflict` mit Evidence liefern.

---

### 🔴 P0-2: Hot-Path Lock-Contention & Deadlock-Gefahr (`RwLock.write().await` über `send().await`)
* **Betroffene Dateien:**
  * `crates/humoco-node/src/storage/engine.rs:143-154` (`ingress_lock`)
  * `crates/humoco-node/src/api/routes.rs:298`
* **Problem / Befund:**
  In `ingress_lock` wurde der exklusive Schreib-Guard des Tokio-RwLocks erworben (`let mut ram = self.ram.write().await;`) und über den asynchronen Flush-Kanal gehalten. Läuft der begrenzte MPSC-Kanal durch langsame Disk-Commits voll, parkte `send().await`, wodurch parallele Ingress-Tasks serialisiert und blockiert wurden.
* **Aufgaben:**
  - [x] **Kritischen Abschnitt minimieren (Lock-Scope verkürzen):**
    - RAM-Prüfung in einem engen synchronen Block gekapselt; Write-Guard wird sofort vor `self.tx.send().await` gedroppt.
  - [x] **Flush-Kanal entkoppeln:**
    - Sowohl in `ingress_lock` als auch in `ingress_hmc_lock` wird der Guard vor dem Channel-Send freigegeben.
  - [x] **Latenz-Benchmark verifiziert:**
    - Keine Deadlock-Gefahr oder unkontrollierte Lock-Inversionen mehr auf dem Hot-Path.

---

### 🔴 P0-3: Durability-Lücke & Flush-Worker Task-Leak im Graceful Shutdown
* **Betroffene Dateien:**
  * `crates/humoco-node/src/daemon.rs:116, 230-235`
  * `crates/humoco-node/src/storage/engine.rs:181-213` (`spawn_flush_worker`)
* **Problem / Befund:**
  Das JoinHandle des Flush-Workers wurde in `daemon.rs` verworfen und beim Shutdown nicht gewartet. Der Flush-Worker besaß keinen `CancellationToken`. Bei `SIGTERM` gingen bis zu 100 unverflushte Locks im Kanal verloren (`INV-1404`).
* **Aufgaben:**
  - [x] **CancellationToken an Flush-Worker übergeben:**
    - `spawn_flush_worker` lauscht auf `cancel_token.cancelled()`.
  - [x] **Finalen Batch-Flush beim Shutdown garantieren:**
    - Bei Abbruchsignal werden alle verbliebenen Ops aus der Queue gedraint (`rx.try_recv()`) und atomar auf Disk geschrieben.
  - [x] **Flush-Handle im Daemon sauber joinen:**
    - `flush_handle` wird im Shutdown-Block ge-`await`ed, bevor der Daemon stoppt.

---

## 🛡️ Priorität P1: Wichtige Protokoll- & Sicherheits-Härtungen

### 🟡 P1-1: Stateless PoW-Replay & TOCTOU-Race bei VIP-Quotas
* **Betroffene Dateien:**
  * `crates/humoco-node/src/ingress/pow.rs:50, 159-167`
  * `crates/humoco-node/src/ingress/tier.rs:88-104`
* **Problem / Befund:**
  1. *PoW-Replay:* `PowEngine::generate_challenge` erzeugt zustandslose Tokens (`expires_at || salt`). Ein Angreifer konnte eine gelöste PoW-Challenge innerhalb der 5 Minuten Gültigkeit tausendfach wiederverwenden (Spam-Verstärkung).
  2. *Quota TOCTOU:* In `TierController::evaluate_and_charge` wurden `get_quota` und `set_quota` in zwei getrennten redb-Transaktionen ausgeführt. Parallele VIP-Anfragen konnten dieselben Byte-Jahre mehrfach ausgeben.
* **Aufgaben:**
  - [x] **Single-Use Replay-Cache für PoW einführen:**
    - `seen_solutions: Arc<Mutex<HashMap<String, u64>>>` in `PowEngine` integriert. Gelöste Nonces werden für denselben Challenge-String sofort mit `PowError::ReplayDetected` abgewiesen.
  - [x] **Atomare Quota-Transaktion in redb:**
    - Lesen, Prüfen und Abbuchen der Byte-Jahre in einer **einzigen** atomaren `write_txn` via `RedbStorage::check_and_charge_quota` zusammengefasst.

---

### 🟡 P1-2: Längen-präfixte BLAKE3 Domain-Separation & P2P Gossip-Validierung
* **Betroffene Dateien:**
  * `crates/humoco-sim-core/src/crypto.rs:46, 76, 97, 113`
  * `crates/humoco-sim-core/src/types.rs:119`
  * `crates/humoco-node/src/network/transport.rs:104-117`
* **Problem / Befund:**
  1. *Domain-Separation:* Eisen-Regel 5 verlangt: `hasher.update(&(tag.len() as u8).to_le_bytes()); hasher.update(tag);`. In `crypto.rs` nutzten `sign_lock_attestation`, `verify_attestation`, `sign_deterministic_sig` und `LockRecord::new` den Tag noch ohne Längenpräfix.
  2. *Ungeprüfter Gossip-Ingress:* Bei `GossipAnnounce` in `transport.rs` wurde der empfangene `LockRecord` mit fester `SimTime(0)` ohne Prüfung der Lock-ID-Integrität und ohne Ingress-Zeitfenster übernommen.
* **Aufgaben:**
  - [x] Alle BLAKE3-Hasher in `crypto.rs` und `types.rs` strikt auf `len || tag` vereinheitlichen.
  - [x] In `NodeRequestHandler::handle_unidirectional` vor `ingress_lock` zwingend die Lock-ID-Integrität verifizieren und Ingress gegen die lokale Netzzeit `SimTime(now_ms)` prüfen.

---

### 🟡 P1-3: Equivocation-Erkennung schärfen & Fraud-Bann enforcen
* **Betroffene Dateien:**
  * `crates/humoco-sim-core/src/fraud.rs:253-283`
  * `crates/humoco-sim-core/src/resolver.rs:127-134`
  * `crates/humoco-sim-core/src/state_machine.rs:168-181`
  * `crates/humoco-node/src/storage/engine.rs`
* **Problem / Befund:**
  `verify_shard_equivocation` vergleicht bisher nur `a.lock_id != b.lock_id && a.node_id == b.node_id`, verlangt aber nicht `a.parent_lock == b.parent_lock`. Zwei legitime Locks auf unterschiedliche Parents könnten fälschlich als Doppelsignatur gewertet werden (Verleumdungsgefahr). Außerdem werden gebannte Nodes aus `TABLE_SLASHING_EVIDENCE` im Ingress bisher nicht abgefragt.
* **Aufgaben:**
  - [x] `verify_shard_equivocation` muss `a.parent_lock == b.parent_lock` strikt voraussetzen.
  - [x] Synthetische Attestations in `resolver.rs` verbieten (First-Party Evidence Doctrine).
  - [x] Ingress-Prüfung: Signaturen von Nodes, die in der Slashing-Tabelle gelistet sind, sofort mit `403 Forbidden` verwerfen.

---

### 🟡 P1-4: Frame-Größenbegrenzung & Slowloris-Schutz auf QUIC-Streams
* **Betroffene Dateien:**
  * `crates/humoco-node/src/network/framing.rs:6, 72`
* **Problem / Befund:**
  `MAX_FRAME_PAYLOAD_LEN` steht pauschal auf 16 MiB. Bei `read_frame` wird `vec![0u8; payload_len]` sofort allokiert. Bei 1.000 unvollständigen Streams kann dies zu unkontrolliertem Speicherverbrauch (OOM) führen. Zudem fehlen Read-Timeouts auf P2P-Streams.
* **Aufgaben:**
  - [x] Frame-Limits differenzieren: 64 KiB für reguläre Lock-Nachrichten, 4 MiB für Sync-Batches.
  - [x] Read-Timeout (z. B. 5 Sekunden) für das Einlesen von Stream-Headern und Payloads etablieren.

---

## 🗺️ Priorität P2: Architektur- & Sharding-Integration

### 🔵 P2-1: Shard-Quorum Broadcast & Assemblierung im HTTP-Ingress
* **Betroffene Dateien:**
  * `crates/humoco-node/src/api/hmc.rs:372`
  * `crates/humoco-node/src/api/routes.rs:460`
  * `crates/humoco-sim-core/src/types.rs:663` (`verify_order_statistics_quorum`)
* **Problem / Befund:**
  Aktuell signiert der Node im PoS-Pfad nur selbst (`server_signature`). Das spezifizierte Shard-Quorum (Broadcast an Top-20 HRW-Nodes, Sammeln von $\ge 14$ Teilsignaturen zu einem `QuorumCertificate`) existiert als Logik in `sim-core`, ist aber im API-Handler noch nicht als QUIC-Fanout verdrahtet.
* **Aufgaben:**
  - [x] `QuorumCertificate` in den API-Antwort-Envelope (`L2ResponseEnvelope`) einbetten.
  - [x] Gateway-Logik in `humoco-node`:
    - Berechnung der Top-20 Shard-Peers via HRW.
    - Paralleler Broadcast via QUIC, Sammeln von $Q$-Signaturen.
    - Assembling des `QuorumCertificate` (Status: `FINAL` oder `PROVISIONAL`).
    - Lokaler Standalone-/Dev-Fallback ($N=1$).

---

### 🔵 P2-2: Shard-Digest Pull-Sync statt Full-Database-Dump
* **Betroffene Dateien:**
  * `crates/humoco-node/src/network/transport.rs:93-119`
  * `crates/humoco-node/src/storage/db.rs:227` (`all_valid_locks`)
* **Problem / Befund:**
  Bei `ActiveSyncRequest` serialisiert der Knoten per `all_valid_locks(0)` unbegrenzt die gesamte Tabelle. Bei vielen Einträgen sprengt dies das 16-MB-Frame-Limit. Spec 03/08 fordert einen 2-Phasen Digest-Pull: Zuerst 32-Byte `ShardDigest` austauschen, nur bei Abweichung fehlende Locks streamen.
* **Aufgaben:**
  - [x] Wire-Nachrichten `GetShardDigest` und `ShardDigest` implementieren.
  - [x] Digest-Clustering (`evaluate_digest_clusters`) aktivieren: Bei $\ge 14/20$ Digest-Übereinstimmung ist der Node synchron; bei Divergenz gezielter Delta-Pull.

---

### 🔵 P2-3: Reconnect-Jitter, Hintergrund-Loops & Lokale Suspension
* **Betroffene Dateien:**
  * `crates/humoco-node/src/network/manager.rs:110-125`
  * `crates/humoco-node/src/network/peer.rs`
* **Problem / Befund:**
  `compute_backoff` (exponentielles Backoff mit Jitter) ist implementiert, hat aber 0 Call-Sites. Nach einem Neustart connecten alle Nodes ohne Jitter (Thundering-Herd). Fehlgeschlagene Verbindungen werden nicht mit einem stündlichen Malus-Abbau (-1) wieder rehabilitiert.
* **Aufgaben:**
  - [x] Hintergrund-Task `reconnect_loop` in `PeerManager` starten.
  - [x] Backoff mit Jitter beim Wiederverbinden anwenden.
  - [x] Stündlichen Malus-Abbau (-1) zur autonomen Peer-Heilung (Spec 19) integrieren.
  - [x] Keine Broadcasts an Peers im Zustand `is_suspended`.

---

### 🔵 P2-4: Vereinheitlichung der RAM-Speicherwelten & Konsistentes TTL-Pruning
* **Betroffene Dateien:**
  * `crates/humoco-node/src/storage/engine.rs`
  * `crates/humoco-node/src/storage/db.rs:100`
  * `crates/humoco-sim-core/src/storage.rs:15`
* **Problem / Befund:**
  `RamIndex` (für binäre Wire-Locks) und `HmcRamIndex` (für Gutschein-Lookup-Tags) laufen parallel mit unterschiedlichen Datenstrukturen. Zudem divergiert die Zeitbasis beim Bucket-Pruning (Sekunden vs. Millisekunden), was zu verfrühtem oder verzögertem State-Pruning führen kann.
* **Aufgaben:**
  - [x] Vereinheitlichung auf den kanonischen 192-Byte `StoredLock` als Single Source of Truth.
  - [x] Zeitbasis beim TTL-Pruning strikt auf Millisekunden vereinheitlichen: Pruning erst nach `now > root.valid_until + 30.000 ms`.

---

### 🔵 P2-5: F2F-Peer-Authentifizierung & Gossip-Barriere (Spec & User-Direktive)
* **Betroffene Dateien:**
  * `crates/humoco-node/src/config.rs` (`F2fConfig`, `trusted_pubkeys`, `parse_peers`)
  * `crates/humoco-node/src/network/peer.rs` (`PeerConnectionType`)
  * `crates/humoco-node/src/network/manager.rs` (`f2f_friends`, `known_network_nodes`, `can_accept_gossip`, `can_authorize_direct_rpc`)
  * `crates/humoco-node/src/network/transport.rs` (Gossip-Barriere, Shard-Direct RPC Autorisierung, bidirektionales Handling)
  * `crates/humoco-node/tests/f2f_gossip_and_shard_rpc_tests.rs`
* **Lösung & Architektur:**
  * **Identitäts-Anker ist der Ed25519 Public Key / Node ID** (IP-Adressen sind flüchtig).
  * `f2f.trusted_pubkeys` und `f2f.peers` definieren direkte F2F-Freunde.
  * **Gossip-Barriere:** Heartbeats und GossipAnnouncements dürfen **ausschließlich** über direkte F2F-Freundesverbindungen empfangen und weitergeleitet werden.
  * **Shard-Direct-Autorisierung:** Direkte P2P-RPC-Verbindungen (z. B. Lock-Verifikation im Shard) dürfen nur zu Knoten aufgebaut und von solchen akzeptiert werden, die der Knoten über F2F-Gossip gelernt hat (`known_network_nodes`).
* **Aufgaben:**
  - [x] `F2fConfig` in `config.rs` auf `trusted_pubkeys: Vec<String>` (Base58 / Hex) und `parse_peers` geschärft.
  - [x] `PeerConnectionType` (`FriendToFriend`, `ShardDirect`, `Untrusted`) implementiert.
  - [x] Gossip-Barriere auf Uni-Streams in `QuicTransport` etabliert (Gossip von Nicht-F2F wird verworfen).
  - [x] Shard-Direct RPC-Autorisierung in `connect_peer` und `handle_connection` verankert.
  - [x] Integration-Testsuite `crates/humoco-node/tests/f2f_gossip_and_shard_rpc_tests.rs` implementiert und 100% verifiziert.


---

## 📱 Priorität P3: Client- & POS-Integration (`human-money-core` / App)

### ⚪ P3-1: QuorumCertificate im Wire-Format (`L2ResponseEnvelope`)
* **Betroffene Crates:** `humoco-node`, `human-money-core::models::layer2_api`
* **Aufgaben:**
  - [x] Ergänzung von `QuorumCertificate` im DTO:
    ```rust
    pub struct QuorumCertificate {
        pub shard_id: u16,
        pub status: u8, // 0 = PROVISIONAL, 1 = FINAL
        pub active_nodes_count: u32,
        pub signers: Vec<[u8; 32]>,
        pub signatures: Vec<[u8; 64]>,
    }
    ```
  - [x] Base58-Vektor-Codec für Teilsignaturen implementieren.

---

### ⚪ P3-2: Plausibilitäts-Engine in `human-money-core`
* **Betroffene Crates:** `human-money-core::services::l2_gateway`
* **Aufgaben:**
  - [x] `verify_quorum_plausibility(certificate, expected_shard_id)` implementiert:
    1. Ableitung der `shard_id = u16::from_be_bytes(genesis_root[0..2])`.
    2. Berechnung der normalisierten HRW-Scores: $\text{BLAKE3}(NodeID_i \parallel \text{shard\_id})$.
    3. Prüfung der Ordnungsstatistik-Schwelle: $\text{Threshold} = \max(0.0, 1.0 - 20.0 / N_{\text{aktiv}})$.
    4. Sicherstellen, dass der $Q$-te beste Signer $\ge \text{Threshold}$ erfüllt.
    5. Deduplizierung der Signer und Status-Prüfung (`FINAL` vs `PROVISIONAL`).

---

### ⚪ P3-3: Reifegrad-Ampel im POS-Workflow
* **Betroffene Crates:** `human-money-core::services::app_service`
* **Aufgaben:**
  - [x] `VerdictAction::ConfirmFinal`: Gutschein global unumkehrbar gesichert (Grüne Ampel).
  - [x] `VerdictAction::ConfirmProvisional`: Vorläufig gesichert (Gelbe Ampel).
  - [x] `VerdictAction::TriggerQuarantine`: Double-Spend erkannt (Rote Ampel).

---

### ⚪ P3-4: UI-Visualisierung (`human-money-app`)
* **Betroffene Crates:** `human-money-app` (Tauri / Frontend)
* **Aufgaben:**
  - [x] UI-Komponente für die Reifegrad-Ampel am Point-of-Sale (Grün / Gelb / Rot / Grau via `L2QuorumBadge.tsx`).
  - [x] Anzeige der Anzahl bestätigender Shard-Knoten ($Q / N$) inklusive Kassierer-Infobox und 100% Vitest-Abdeckung.
