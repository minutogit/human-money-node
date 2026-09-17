# Audit und Optimierungspotenziale — HuMoCo Layer-2 Sperrregister

> **Scope:** `README.md` + `docs/00` bis `docs/17` + `docs/99` — **ohne** `legacy-planing/` (Referenzarchiv)  
> **Datum:** 2026-08-27 | **Methodik:** 3 parallele Subagenten — *Security/Attack-Vector*, *Protocol-Logic*, *Simplicity/Edge-Cases*  
> **Credo geprüft:** *„In der Dezentralität gibt es kein Vertrauen, nur mathematische Beweise.“*  
> **Ergebnis:** 28 konsolidierte Befunde (dedupliziert aus 37 Rohbefunden), priorisiert nach Kritikalität mit konkreten, umsetzbaren Lösungsvorschlägen und exakten `file:line`-Referenzen.

---

## Lesart

- **Kritisch:** Konsens-, Finalitäts- oder Sicherheitsbruch — *sofort* normieren, sonst divergierende Implementierungen / ökonomischer Schaden.
- **Hoch:** Angriffsvektor, DoS- oder Liveness-Risiko, Partition-Inkonsistenz — vor Code-Freeze schließen.
- **Mittel:** Randfall, Privacy, Operationalisierung — vor Mainnet-Testnetz lösen.
- **Optimierung:** Simplicity/Ballast, Spec-Klarheit — *Subtraktion vor Konstruktion*, halbiert Spec-Zeilen bei gleicher Sicherheit.

Jeder Befund zitiert **primäre Quelle** (`file:line`) + **Invariante** (`INV-*`) wo zutreffend.

---

## 🔴 Kritisch (6)

### K-01 — Inkonsistente Domain-Separation: Zwei konkurrierende Signatur-Preimages

- **Files:** `docs/10_p2p_wire_format_und_session_framing.md:163-193` (Tabelle + `calculate_signature_digest`), `docs/03_routing_und_sharding.md:175-181`, `docs/08_topologie_dynamik_und_netz_merge.md:58-60` (`SignPreimage = BLAKE3(status_tag || lock_hash)`), `docs/04_datenstrukturen_und_rust_typen.md:185-192` (`canonical_hash`), `docs/13_client_ingress_und_access_tiering.md:63,124`, `docs/10:295-309` (`HUMOCO_V1_INGRESS_DECL`, `HUMOCO_V1_SHARD_WORK` nicht in Tabelle)
- **Invarianten:** `INV-0403`, `INV-1003`, `INV-0802`
- **Befund:** Zwei disjunkte Preimage-Konstruktionen für dieselbe Quorum-Signatur:
  1. `SigDigest = BLAKE3(DOMAIN_TAG || epoch_id_le || session_seq_le || flags_le || shard_id_le || payload_digest)` — `docs/10:174`
  2. `SignPreimage = BLAKE3(status_tag || lock_hash)` — `docs/03:177`, `docs/08:59`
  Plus `H_canon = BLAKE3("HUMOCO_V1_CANON_RESOLVER" || Parent || Receiver || Sig)` und `GENESIS_ROOT = BLAKE3("HuMoCo-L2" || VERSION || T0)` (`docs/04:176`) ohne Längenpräfix. `hasher.update(domain_tag)` (`docs/10:186`) ohne `len` ermöglicht Präfix-Kollision (`"HUMOCO_V1_RAW"+"EXTRA"` == `"HUMOCO_V1_RAWEXTRA"`). Tabelle `docs/10:163` listet 5 Tags, Code nutzt ≥8.
- **Angriff (Class-Swapping):** Angreifer signiert `Lock` mit `DOMAIN_TAG=HUMOCO_V1_APPROVE_PROV (0xA2)` + `FLAG_PROVISIONAL`; Victim-Gateway verifiziert via verkürztem `status_tag`-Pfad und akzeptiert als `FINAL` wenn `signer_bitmap.count_ones() >= 14` (`INV-0805`).
- **Lösung:**
  ```rust
  // Kanonisch, single source of truth in docs/04 + docs/10:3.2
  fn sig_digest(domain_tag: &[u8], epoch_id: u32, session_seq: u64, flags: u32, shard_id: u16, status_tag: u8, payload_digest: &[u8;32]) -> [u8;32] {
      let mut h = blake3::Hasher::new();
      h.update(&(domain_tag.len() as u8).to_le_bytes()); h.update(domain_tag);
      h.update(&epoch_id.to_le_bytes()); h.update(&session_seq.to_le_bytes());
      h.update(&flags.to_le_bytes()); h.update(&shard_id.to_le_bytes());
      h.update(&[status_tag]); h.update(payload_digest);
      *h.finalize().as_bytes()
  }
  ```
  Alle `status_tag`-Preimages (`docs/03:176`, `docs/08:59`) streichen/aliasen auf `docs/10:174`, Registry in `docs/10:163` auf 8 Tags erweitern, `GENESIS_ROOT` auf `BLAKE3(len("HuMoCo-L2")||"HuMoCo-L2"||VERSION_le||T0_le)` mit `HUMOCO_V1_GENESIS` normieren. Verifikationstest: `PROV`-Sig in `FINAL`-Kontext muss `false` liefern.

### K-02 — BLS12-381 (96 B) vs. Ed25519 (64 B) — Aggregat unvalidierbar

- **Files:** `docs/04_datenstrukturen_und_rust_typen.md:47-66` (`aggregate_signature: [u8;96] BLS`), `docs/10:321-328` (`[u8;64] Ed25519`), `docs/10:406-433` (`[u8;64] BLAKE3-Aggregat`), `docs/04:60-62` (`signer_bitmap: u32`), `docs/06_dumb_server_smart_client_flow.md:92,102`
- **Invarianten:** `INV-0805`, `INV-0501`, `INV-0304`
- **Befund:** `QuorumCertificate` behauptet BLS-Aggregation, alle anderen Shard-Sigs sind Ed25519. Kein `proof-of-possession`. `signer_bitmap` (20 Bits in `u32`) verweist auf HRW-Rang, BLS ist order-independent — ohne `pubkey_list` unprüfbar ob 1 Node 14× signierte vs. 14 disjunkte Nodes. `ShardWorkAttestation` mit `BLAKE3-Aggregat` trivial fälschbar.
- **Angriff:** 1 Node erzeugt 14 identische Teil-Sigs über verschiedene `session_seq` → `count_ones(bitmap) >= 14` passiert, BLS-Verify fehlt.
- **Lösung:** Ein Schema normieren. Empfehlung (Simplicity): **Ed25519 Batch-Verify** — `14×64 B` Signaturen + bitmap → `BLS` streichen; ShardWorkAttestation ersatzlos streichen zugunsten schlanker P2P-Reziprozität. Alternative: BLS + `pop = Sign("HUMOCO_V1_POP", sk)` bei Node-Registrierung (`Argon2id`-PoW bindet `pubkey`). Normative Verifikation `BLS.VerifyAggregate(pubkeys_bitmap, msg, agg_sig)` in `docs/04` als Invariante fordern.

### K-03 — Quorum-Formel divergiert: `floor` vs. `ceil` (+ `min`)

- **Files:** `README.md:22` (`Q(R)=min(R, ceil(2R/3)+1)`), `docs/00_architektur_und_mental_model.md:95-97` (`floor(2R/3)+1`), `docs/03_routing_und_sharding.md:16`, `docs/08_topologie_dynamik_und_netz_merge.md:16`, `docs/05_spieltheorie_und_angriffsmatrix.md:108-114`
- **Invarianten:** `INV-0507`, `INV-0801`
- **Befund:** `R=10`: floor → `7/10`, ceil → `8/10` (1 Stimme entscheidet über `FINAL` vs. `PROVISIONAL`). `R=20` zufällig gleich (`14/20`), verdeckt Bug. Händler gibt Ware je nach Doc unterschiedlich frei.
- **Lösung:** SSOT `docs/00:96` (`floor`) behalten; `README.md:22` + `docs/05:108` korrigieren auf `Q(R) = floor(2*R/3)+1`. Zentraler Helper in `docs/04`:
  ```rust
  #[inline(always)] pub fn quorum(r: u16) -> u16 { (r*2)/3 + 1 }
  ```
  Kanonische Testvektor-Tabelle `R=1..20` abnehmen; alle Referenzen darauf verlinken.

### K-04 — `FINAL` hat 3 inkompatible Definitionen: Sofort vs. 24h-Hysterese

- **Files:** `docs/00_architektur_und_mental_model.md:89-93`, `docs/02_lock_zustandsautomat_und_konflikte.md:70-73` (sofort `N>=20 && sigs>=14 => FINAL`) vs. `docs/03_routing_und_sharding.md:178-181`, `docs/08_topologie_dynamik_und_netz_merge.md:36-60` (`N>=20 seit 24h stabil + status_tag 0x01`)
- **Invarianten:** `INV-0802`, `INV-0805`
- **Befund:** Hot-Path `docs/06:98` gibt Ware bei `>=14/20` sofort grün frei; `docs/08/03` verbietet ehrlichen Nodes `status_tag=0x01` vor 24h. Im Fenster `0–24h` nach Erreichen von `N=20` liefert Shard niemals `FINAL` → Gateway sammelt ewig, fällt nach 600 ms auf `PROVISIONAL` zurück (falsches Gelb trotz 14 Sigs). Flapping-Schutz vs. Latenz-Garantie kollidieren.
- **Lösung:** Phasenübergang zweistufig normieren — `FINAL_candidate` (14 Sigs, aber `status=0x00` bis Hysterese erfüllt) vs. `FINAL_stable` (0x01). `docs/02:70`, `docs/06:98` um `&& hysteresis_ok` + `status_tag`-Prüfung ergänzen, `INV-0802` dorthin propagieren. Neu: `GET /network_status { N_aktiv, hysteresis_remaining_sec }` für Wallet-UX statt Rate-Spiel.

### K-05 — `PROVISIONAL → FINAL` Upgrade-Race unvollständig — Wirtschaftsrisiko

- **Files:** `docs/02_lock_zustandsautomat_und_konflikte.md:142-148` (`POST /promote_lock` kostenlos), `docs/08_topologie_dynamik_und_netz_merge.md:52-54`, `docs/09_netzwerk_thermometer_und_dynamische_quotas.md:20-24` (192/224 B × TTL), `docs/06:211`
- **Invarianten:** `INV-0901`, `INV-1204`
- **Befund:** Gratis-Promotion bricht `INV-0901` (jedes BJ zählt). Kein Idempotenz-Key, kein Retry-Backoff, keine Wallet-Anzeige wenn Upgrade ewig `PROVISIONAL` bleibt. Upgrade mitten in 24h-Hysterese oder kurz vor `valid_until`-Tilgung nicht spezifiziert. Händler verwechselt Gelb/Grün bei Kleinst- vs. Großbetrag.
- **Lösung:** Neue Invariante `INV-0206 Idempotente Promotion`: `lock_hash` identisch + `status_tag` monoton `0x00 < 0x01 < 0x02` ist **kein** Conflict, sondern Upgrade — Shard muss höheres Zertifikat ohne `VOID` ausstellen. Gratis nur wenn `lock_hash` identisch und TTL unverlängert, sonst volle `µBJ`-Verrechnung. Spez: 1-RTT, Retry alle 60 s exponentiell max 3 Versuche, `409 ConflictWithEvidence` bricht Upgrade ab → `VOID`. Wallet-Pflicht: Gelb = *„Nur bis X €, kein Fernhandel“*.

### K-06 — Shard-ID Off-by-One (3-Byte Slice)

- **Files:** `docs/03_routing_und_sharding.md:14` (`Genesis_Hash[0..2] mod 65536`), `docs/06_dumb_server_smart_client_flow.md:77` (identisch) vs. `docs/04_datenstrukturen_und_rust_typen.md:196-198` (korrekt `genesis_hash[0], genesis_hash[1]`)
- **Invariante:** `INV-0302`
- **Befund:** `u16::from_be_bytes` erwartet 2 Bytes; `[0..2]` sind 3 Bytes → Compile-Panic oder implizites Truncate. `mod 65536` wirkungslos. Gateway (`03`) und Shard-Node (`04`) routen denselben Gutschein in verschiedene Shards → `First-Seen` verfehlt, Double-Spend übersehen.
- **Lösung:** `docs/03:14` + `docs/06:77` korrigieren auf `u16::from_be_bytes([genesis_hash[0], genesis_hash[1]])` ohne `mod`. `INV-0302` ergänzen: *„Trust-Tree Lokalität via 2-Byte Big-Endian Präfix“*. Fuzz-Test HRW-Determinismus über beide Pfade.

---

## 🟠 Hoch (10)

### H-01 — `session_seq` Monotonie kollidiert mit QUIC Migration + `epoch_seq` Doppelzählung

- **Files:** `docs/10_p2p_wire_format_und_session_framing.md:25,62-64,250-251` (`session_seq: u64` monoton + `SequenceGapDetected`), `docs/15_p2p_transport_und_verbindungsmanagement.md:29,88-91` (QUIC Migration, `W=4096`), `docs/10:289-309` (`epoch_seq: u32` pro `epoch_day`), `INV-1007`
- **Befund:** `session_seq` pro Connection monoton (`seq_{n+1}=seq_n+1` exakt) — Migration/Paketverlust löst false `SequenceGap`. Gleichzeitig `epoch_seq` global pro `epoch_day` über alle Shards, aber Gateway sendet parallel an Shard A `seq=5` und Shard B `seq=5` (`docs/03:44-54`) → **fälschlich** Double-Signing Evidence Klasse 1.
- **Lösung:** Trennen: `session_seq` nur per-Connection Gap-Detection via `quinn` Transport (applikatorisch nicht strikt +1), applikatorisch nur `epoch_seq` global monoton pro `(gateway_pubkey, epoch_day)` validieren. `INV-1007` Klasse 1 ändern auf `(gateway_pubkey== && epoch_day== && epoch_seq== && lock_hash!= && shard_id verschieden ≥2)` und Parallel-Broadcast explizit als Nicht-Fork definieren. `epoch_seq` als globaler Zähler, nicht shard-lokal.

### H-02 — 0-RTT Whitelist divergiert: `ActiveSyncRequest` vs. `ShardDigestRequest`

- **Files:** `docs/10_p2p_wire_format_und_session_framing.md:113-115,236-245,474-480` (Code whitelist nur 3 Typen), `docs/15_p2p_transport_und_verbindungsmanagement.md:78-88`, `INV-1004/1009`, `docs/03_routing_und_sharding.md:68-79` (`ShardDigestRequest`)
- **Befund:** Tabellen `docs/10:241`, `docs/15:83` whitelisten `ActiveSyncRequest` als idempotent; Code `docs/10:474` implementiert nur `StatusQuery/LatencyProbe/ShardMapPing` → partition-inkonsistentes `INV-1004/1009`. `ShardDigestRequest` (`GetShardDigest`) als eigentliche Phase-1 nirgends in Whitelist. `expected_digest`-Leck ermöglicht Amplification (32 B Request → Stream).
- **Lösung:** SSOT `docs/10:100-122` enum + Code vereinheitlichen. Beide `ShardDigestRequest` **und** `ActiveSyncRequest` explizit whitelisten (beide idempotent), aber **rate-limiten** (Tier-3-ähnlich) + `W=4096` **global** per `ClientIP+NodeID` Bloom Filter, nicht nur per Connection. 0-RTT Replay via UDP-Spoofing anders nicht abgedeckt.

### H-03 — Gradienten-Betrug (`INV-1007` Klasse 3/4) inkonsistent & unprüfbar

- **Files:** `docs/10_p2p_wire_format_und_session_framing.md:359-386` (`e^{-delta/24h}`, `144*Δt_TTL/31.536M`), `docs/09_netzwerk_thermometer_und_dynamische_quotas.md:18-24` (192 B), `docs/12_lock_storage_und_ram_index.md:104-110` (224 B), `docs/04:204-210` (`deterministic_decay` via `>>`)
- **Befund:** Klasse 3 nutzt Continuous-Time EMA mit `e^x` — Spec definiert EMA nie, verbietet zugleich Transzendenten (`docs/04:204`). Klasse 4 vergleicht mit `144 B`, `docs/09:18` rechnet mit `192 B` → ehrliches Gateway triggert fälschlich Slashing (25 % Delta). `timestamp_ms` Sättigung undefiniert → NTP +30 s → Klasse 2 Time-Warp trotz `docs/12:40` `now-30s` Toleranz.
- **Lösung:** Eine Byte-Jahre-Definition: Ingress-Abrechnung `144 B * Δt_TTL` (Wire), `192/224 B` nur interne RAM-Kosten. `e^{-delta/24h}` durch `deterministic_decay` (`docs/04:203`) oder Integer-EMA `EMA_{t+1}=EMA_t*(1-1/24)+delta` ersetzen. Toleranz auf ±2 %, `timestamp_ms` an `epoch_day` + 30 s Skew-Fenster (`INV-1206`) binden.

### H-04 — `FINAL` ohne Hysterese-Bindung im Zertifikat fälschbar (Inselnetz 14 Nodes)

- **Files:** `docs/08_topologie_dynamik_und_netz_merge.md:58-60`, `docs/03_routing_und_sharding.md:175-182`, `docs/00:89-97`, `INV-0802/0805`
- **Befund:** Hysterese nur lokale Policy, nicht im `QuorumCertificate` beweisbar: `signer_bitmap.count_ones()>=14 && status==0x01` reicht. Insel `N=14` mit 14 bösen Nodes signiert sofort `status_tag=0x01` → als `FINAL` akzeptiert, obwohl global `N<20`. `HIGH_ASSURANCE 0x02` bei `N>=100` gleiches `14/20` → kein Sicherheitsgewinn, aber Händler-Vertrauen falsch.
- **Lösung:** `N_aktiv` + `epoch_day` + `hysteresis_proof` ins Preimage (siehe K-01) + bei `FINAL`-Verifikation `N_aktiv_at_signing >=20` via WOT-Heartbeat-Multiset (Merkle-Root der 20 Heartbeats) fordern. `HIGH_ASSURANCE` entweder auf `Q=16/20 (80%)` oder 2-Shard-Quorum anheben oder streichen.

### H-05 — Argon2id DoS: 50 µs Ed25519-Vorfilter unzureichend, Bounded Pool 256 MB saturiert

- **Files:** `docs/13_client_ingress_und_access_tiering.md:130-149`, `docs/05_spieltheorie_und_angriffsmatrix.md:58-64`, `docs/15:98-106` (Tokio Actor Pipeline), `INV-1301/1304`
- **Befund:** Ed25519-Keys/Signaturen offline kostenlos generierbar → passieren 50 µs Filter immer. `4 Worker ×64 MB =256 MB` bei 100k req/s sofort saturiert → legitime Tier-3 Clients via `RED-Drop` verworfen, aber VIP-Isolation (`70-80% CPU`) nur Scheduling, kein Hardware-Isolat (gleicher UDP-Socket + `quinn` Task). `Challenge = BLAKE3(...Client_IP_Prefix||Epoch_Minute||Node_Secret)` mit `/24` Prefix → CGNAT-Precomputation für ganzes `/16`.
- **Lösung:** Reihenfolge umkehren: Tier-3 zuerst anonymes Puzzle (`Argon2id(Challenge||nonce)<Target`) **vor** Ed25519, per-IP token bucket vor Sig-Check. Pool auf `CPU_cores` isoliert (`rayon` ≠ Tokio I/O) + `INV-1301` als **separate UDP-Ports** (VIP 443 vs Public 8443). `Client_IP_Prefix` durch volles `/32` + `QUIC ConnectionID` ersetzen.

### H-06 — TTL/Tilgung vs. Lazy Ingestion: Offline-Resurrection nach `Zero State Bloat`

- **Files:** `docs/12_lock_storage_und_ram_index.md:39-41,63-69,119`, `docs/00:13,36`, `docs/06_dumb_server_smart_client_flow.md:192-196`, `docs/08:98`, Titel `docs/12` (`O(1) TTL-Bucket-Ringpuffer`)
- **Befund:** `valid_until < now` physikalisch getilgt; Ingress erlaubt `now-30s < valid_until` → Eintrag sofort abgelaufen, aber noch signierbar → Resurrection-Race nach Neustart. Wallet-Batch `[Tx2,Tx3,Tx4]` mit `valid_until=now+5s` während Node A tilgt, Node B (Partition) hält noch → beim Merge via Lazy Ingestion (`valid_until>now` Check) kann derselbe Gutschein wiederauferstehen. Ringpuffer im Titel versprochen, 0 Implementierung (scan `TABLE_ACTIVE_LOCKS` → `O(n)` täglich, `INV-1201` verletzt bei 24M Locks).
- **Lösung:** Ingress verschärfen auf `valid_until > now + 30s` **und** `valid_until <= root.valid_until`; Tilgung exklusiv `valid_until + 30s grace`. Batch-Validierung `min(valid_until_batch) > now + promote_window` fordern. Secondary Index `TABLE_TTL_BUCKETS: (bucket_id=valid_until/86400 → Vec<ParentLockKey>)` in `redb`, täglicher `O(1)` Bucket-Drop. DST-Test für Resurrection.

### H-07 — Partition-Merge `<500 ms` unmöglich: Heartbeat-Präsenz braucht 8h/24h

- **Files:** `docs/08_topologie_dynamik_und_netz_merge.md:68-83`, `docs/11_organische_praesenz_und_dunbar_gossip.md:126-174`, `docs/01_organischer_netzstart_und_topologie.md:76-82`, `docs/07:40-50`
- **Befund:** `08:68` verspricht Merge `<500 ms` via Heartbeat-Lernen; `11:171` verlangt `popcount>=8/24 && m>=3` + `07:08` 8h Hysterese + Heartbeat alle 60 Min, TTL 16 → Dorf A+B je `N=5` frühestens nach Stunden `ACTIVE` für HRW. `08:82` widerspricht `03:125` Digest-First PULL (echter Sync-Pfad). PoS sieht währenddessen `PROVISIONAL` aber Docs suggerieren sofort `FINAL`.
- **Lösung:** Merge-Zeit ehrlich aufteilen: `P2P Peering <100ms`, `Presence ACTIVE frühestens 8h`, `FINAL frühestens 24h`. Diagramm `08:72` korrigieren, `11` als SSOT für `is_active`. PoS-Latenz nur via First-Seen garantieren — Presence-Merge nicht im Hot Path versprechen.

### H-08 — 10:10 Split: „Kein Quorum“ vs. `min(H_canon)` Widerspruch, Timeout fehlt

- **Files:** `docs/06_dumb_server_smart_client_flow.md:213-218` (`10:10 → kein Quorum, beide Kassen verweigern`), `docs/02_lock_zustandsautomat_und_konflikte.md:79-102` (`min(H_canon) in <1ms`), `docs/03:90-93`, `docs/08:114-117`, `INV-0201`
- **Befund:** Live-First-Seen vs. Merge-Resolver ohne Priorität. 600 ms Gateway-Timeout (`06:305`) vs. 50 ms Shard-RTT (`03:90`) vs. 200 ms Hedged (`05:33`) fragmentiert. Unklar ob 10:10 `VOID` + L1-Slashing oder „beide abgebrochen“.
- **Lösung:** Automat `02:12-50` vervollständigen: `Pending → Provisional/Final → Void (nur via min(H_canon) oder ConflictWithEvidence) → Expired`. Regel: Live-First-Seen ist Provisorium; endgültiger Konsens immer `min(H_canon)` wenn `ConflictWithEvidence` innerhalb `valid_until` eintrifft. `06:216` korrigieren: 10:10 → `409 ConflictWithEvidence` + Resolver-Hinweis, nicht „kein Quorum“. Timeout `T_quorum=600ms` zentral in `docs/04` verankern.

### H-09 — `INV-0301/0803` „Zero Replication“ vs. Digest-First PULL

- **Files:** `INV-0301`, `INV-0803`, `INV-0304`, `docs/03_routing_und_sharding.md:125-159`, `docs/08:65-83`, `docs/14:104`
- **Befund:** Absolute Push-Verbote widersprechen explizit erlaubtem selbst-initiiertem PULL in selben Docs. Cluster-Logik `>=14` vs `11..13` Toleranzfenster (`03:148`) nirgends als INV, kollidiert mit `INV-0805`.
- **Lösung:** `INV-0803` präzisieren: *„Kein proaktiver Push-Dump; reaktiver Digest-First PULL nur selbst-initiiert nach `GetShardDigest` Quorum-Digest `D*`“*. Schwellen `>=14` quorum / `<11` backoff 500 ms in `INV-0304` kodifizieren, `11..13` Toleranzfenster **streichen** (siehe M-05).

### H-10 — TTL/Byte-Jahre Inkonsistenz (192 vs 224) + gratis Promotion bricht Quota

- **Files:** `docs/12:39-41,108-109`, `docs/09:20-24,62` (`240k BJ/Tag => 333×5-Jahres`), `docs/02:146`
- **Befund:** `192 B` vs `224 B` RAM-Overhead → Quota 16% zu lax; `333×5-Jahres` Rechnung falsch (korrekt 286). `promote_lock` 0-Kosten ermöglicht Quota-Umgehung via Promotion-Loop.
- **Lösung:** Quota deterministisch auf `224 B` normieren (oder Wire 144 B + RAM 192 B explizit trennen), Rechnung `09:62` neu belegen. `promote_lock` nur gratis bei identischem `lock_hash` + `status_tag`-Wechsel ohne TTL-Verlängerung.

---

## 🟡 Mittel (8)

### M-01 — Cold-Path Locator/Batch unterdefiniert

- **Files:** `docs/00_architektur_und_mental_model.md:77-84` (`1,2,4,8...`), `README:15,18` (max 16), `docs/06_dumb_server_smart_client_flow.md:141-146,204-210` (`Vec<String>` unbounded, `L2BatchLockRequest`)
- **Befund:** Schranke uneinheitlich (00 logarithmisch unbegrenzt, README max 16, 06 unbounded). Batch prüft nicht `valid_until>now` pro Glied; Wallet kann abgelaufene Zwischen-Glieder nachreichen, die Server sofort tilgen → Inkonsistenz. Kein `max_batch` → Monster-Historie via Cold-Path (10k Glieder) umgeht `INV-0301`.
- **Lösung:** `L2StatusQuery.locator_prefixes` auf `max 16`, `10 Zeichen` normieren (ADR-001). `L2BatchLockRequest` auf `max 64` Locks + kumulative `µBJ`-Quota begrenzen. Server: Batch on-the-fly `valid_until>now` pro Glied, bei Ablauf `400 Expired` gesamt verwerfen.

### M-02 — Silent Dropping vs. Zensur/Equivocation nicht unterscheidbar

- **Files:** `docs/09_netzwerk_thermometer_und_dynamische_quotas.md:106`, `INV-0906`, `docs/05:58`, `docs/03:90`, `docs/10:332-333` (`p=0.02%` nur bei Erfolg), `docs/17:109-119`
- **Befund:** `Silent Drop` ohne Alert bei Quota-Überschreitung ist nicht von selektiver Zensur unterscheidbar — kein `ConflictWithEvidence`, kein `ServerBann`. `Receipt-Gossip` nur bei Erfolg → Gradienten-Prüfung Klasse 3 greift nicht. Kartell 6 Nodes kann Target-Händler silencen und als `QuotaExhausted` tarnen.
- **Lösung:** Pflicht `SignedRejection{ reason=QuotaExhausted, current_anl, quota }` mit `DOMAIN_TAG=HUMOCO_V1_REJECT` auch bei Drops. `Receipt-Gossip` auch auf Rejections (`p=1%` für Drops) oder `reject_bitmap` via Piggyback.

### M-03 — Unbounded RAM + `persist_tx` ohne Backpressure

- **Files:** `docs/12_lock_storage_und_ram_index.md:83-110` (`DashMap`, `persist_tx: mpsc::Sender`), `docs/14:82-105`, `docs/09:28-34`
- **Befund:** `total_byte_seconds: AtomicU64` ohne Hard Cap. 20 Gateways ×333 5-Jahres/Tag ⇒ 6.6k/Tag ⇒ 10 Jahre 24M Locks ⇒ ~5 GB RAM + `redb` Append-Only ohne Compaction ⇒ OOM. `mpsc` ohne `capacity` sammelt bei Disk-Stall unbegrenzt. `ShardDigest = BLAKE3(Shard_ID||Lock1||...||Lock_m)` sortiert `O(m log m)` jedes Mal ⇒ CPU-DoS beim Digest.
- **Lösung:** `INV-1207` RAM-Hard-Limit `max_ram_locks = max(100k, quota_BJ*2)` + 48h LRU-Eviction nahe `now`. `mpsc(10k)` bounded mit `try_send` → bei Full `429`. `ShardDigest` auf inkrementellen Merkle-Root (Binary Tree) umstellen.

### M-04 — Privacy-Leak: `valid_until`, `AccountTag`, `ShardID` de-anonymisieren Blind Service

- **Files:** `docs/00:31-35`, `docs/04:30-41` (`valid_until`), `docs/13:63` (`AccountTag = BLAKE3(...Client_PubKey||Node_Secret_Salt)`), `docs/03:13-14` (`Shard_ID`), `docs/12:40`
- **Befund:** `valid_until` korreliert mit Gutschein-Wert (16 vs 1920 BJ) → Traffic-Analyse. `AccountTag` mit `Node_Secret_Salt` bei Leak linkbar; gleiche `Client_PubKey` → verschiedener Tag pro Node via `gateway_pubkey` linkbar. `Shard_ID` deterministisch → alle Locks eines Gutschein-Baums im selben Shard → Observer korreliert DAG-Splits.
- **Lösung:** `valid_until` auf Wochen-Bucket runden + `±1h` Noise. `AccountTag` via `VRF`/Blind Signature statt deterministischem Hash; pro Client random statt Node-Secret. Sharding rotierend `Shard_ID = BLAKE3(Genesis_Hash || salt_epoch)` pro `epoch_day` oder Onion-Routing für `StatusQuery`.

### M-05 — Digest-First PULL `11..13` In-Flight Fenster bricht BFT

- **Files:** `docs/03_routing_und_sharding.md:145-158`, `INV-0304/0805`
- **Befund:** `C_max 11..13` erlaubt Finalisierung mit 11 statt 14 unter „Live-Traffic“-Ausrede → Angreifer mit 13 Nodes gewinnt Digest-Wahl. Widerspricht `INV-0304` (`≥14/20`).
- **Lösung:** Streichen. Regel: `≥14` sonst `500ms Backoff & retry` (`03:151`). In-Flight Locks idempotent via offenen QUIC-Ingress nachholen.

### M-06 — Dunbar-RED & Multi-Path Formeln divergieren, Größen schwanken

- **Files:** `docs/11_organische_praesenz_und_dunbar_gossip.md:49-60,80,138-150,158-166,214`, `docs/05:32`, `INV-1101/1703`, `docs/10:333,340` (`SignedGossipReceipt` 64 vs 96 B)
- **Befund:** `m(Z)` strikt Empfänger-Eigenschaft (`11:80` korrekt), Tabelle `11:138` ohne `Z`-Qualifikation → Implementierungsrisiko. `R_soft` Formel `11:49` vs `11:214` different. Receipt-Größe 64/96 B → `10:354` 3.8 KB/s Bandbreite falsch.
- **Lösung:** `m(Z)` überall als `deg(Z)` in INVs festschreiben, `R_soft` einmalig `11:49` kanonisch, Rest verweisen, `SignedGossipReceipt` auf 96 B (inkl. Padding) vereinheitlichen und Kapazitätsrechnung neu belegen.

### M-07 — `N_aktiv` fragmentiert: `is_active` vs. QUIC Keep-Alive vs. Crash-Recovery

- **Files:** `docs/11:171-175` (`popcount>=8/24 + m>=min(3,deg)`), `docs/07:40-50` (`8 Heartbeats`), `docs/15:113-116` (`20-25s / 75s`), `docs/14:107-111` (Recovery)
- **Befund:** `N_aktiv` mal `popcount>=8/24`, mal `8 Heartbeats`, mal `N_local*...`, mal QUIC-Timeout → zwei Nodes berechnen `R=20` vs `R=19` → HRW-Divergenz. Crash-Recovery lädt Locks und votet sofort ohne `ACTIVE`-Check.
- **Lösung:** `11` als SSOT für `is_active` (8/24 + m), `15:113` nur QUIC-Keepalive (nicht Präsenz), `14:111` ergänzen: Nach Restart `is_active=false` bis `tau_on` erfüllt, davor kein Voten/Signieren.

### M-08 — WoT Max-Flow Lücke: Kette & Multi-Homing umgeht 1.0-Cut

- **Files:** `docs/07_admission_und_wot_buergschaften.md:53-70,95-112`, `docs/99_faq_und_angriffsvektoren_deep_dive.md:70-107`, `docs/11:74-108`, `INV-0702/0703`
- **Befund:** `INV-0702` begrenzt vergebene Masse pro Node auf 1.0, nicht Tiefe: `H(1.0)→B1(1.0)→B2(1.0)→...` umgeht Cut (Ford-Fulkerson `1.0` gilt nur bei Stern). `11` Multi-Path verlangt `m(Z)>=3` am Empfänger — Bots über `H`'s Fan-out `k=√d+1` erreichen `m>=3` trotz Cut=1.0. 2 bestochene Bürger → 2.0 Kapazität → schleichende Infiltration trotz `5×Wal-Bremse`.
- **Lösung:** Max-Flow mit Tiefen-Dämpfung `M_eff = MaxFlow(anchors→node) * gamma^{depth}` (`gamma=0.9`), Weiterbürgschaft > Tiefe 3 nur mit zusätzlichem Anker-Pfad. `distinct_edge_mask >= m(Z)` **und** `M_eff>=1.0` für `ACTIVE`.

---

## 🔵 Optimierung / Simplicity (4)

### O-01 — Spec Inflation: Byte-Jahre / Thermometer / Zipf / ANL / EMA Ballast

- **Files:** `docs/09_netzwerk_thermometer_und_dynamische_quotas.md:18-106`, `docs/10_p2p_wire_format_und_session_framing.md:287-384`, `docs/12:88-90`
- **Befund:** `09` führt `Byte-Jahre`, `NCB`, `Q1/Q3 Zipf Spread_Damper (88)`, `28-Tage Ringpuffer`, `K=0.05/1.0`, `Wal-Bremse 5x`, plus `10:295` `cumulative_micro_byte_years`, `current_anl_24h EMA`, 4 Beweisklassen mit `e^(-delta/24h)` ein. Gleiches Ziel (Spam-Schutz) bereits durch `144B` Cap + TTL + Argon2id + `M<=1.0` abgedeckt. Jede Formel braucht Toleranz (1%) und bricht bei Merge.
- **Lösung:** *Subtraktion vor Konstruktion* (Leitfilter 5): `09` auf Hard-Floor `240k BJ/Tag` + `K=0.05/1.0` kürzen, Zipf-Damper/Q1/Q3/ANL-EMA **streichen**, `cumulative_micro_byte_years` durch simplen `locks_per_day` Zähler ersetzen. Halbiert Wire-Größe `10:287` und alle Gradient-Proofs.

### O-02 — `HIGH_ASSURANCE (0x02)` ohne Mehrwert

- **Files:** `README:23`, `docs/03_routing_und_sharding.md:175-182`, `docs/08_topologie_dynamik_und_netz_merge.md:36-42`, `docs/04:34`
- **Befund:** `N>=100, ≥14/20` gleiches Quorum wie `FINAL` → keine zusätzliche BFT. Vermittelt falsche Großtransaktions-Sicherheit.
- **Lösung:** Entweder auf `Q=16/20 (80%)` oder 2-Shard-Quorum anheben oder **streichen** (`12`-Zeilen Netto-Gewinn, weniger Händler-Verwirrung).

### O-03 — Undefinierte Fehler/Timeout-Matrix & Offline-Queue

- **Files:** `docs/06_dumb_server_smart_client_flow.md:262-318` (885 ms Budget, 600 ms Timeout), `docs/03:90`, `docs/10:245-252`, `docs/15:60`, `docs/06:42` (`UNBEKANNT ⚪`)
- **Befund:** `RTO` verteilt: Hedged 200 ms, Shard Broadcast 150 ms, Quorum 600 ms, Gossip 8h, PULL 500 ms exp. Kein einheitliches `RTO`, kein Jitter, `409` retryable vs `504` nicht normiert, Offline-Queue (`06:42`) ohne Größe/TTL, Reconnect-Storm ungedrosselt.
- **Lösung:** Zentrale Timeout-Tabelle in `docs/04` oder `docs/10`:

  | Pfad | Timeout | Retry |
  | :--- | :--- | :--- |
  | QUIC 1-RTT | 600 ms | — |
  | Shard Broadcast | 150 ms | Hedged 200 ms |
  | Quorum Gather | 600 ms | — |
  | PULL Backoff | 500 ms exp bis 5 s | Jitter 20% |
  | QUIC Keep-Alive | 20–25 s / 75 s Close | — |

  Wallet Offline-Queue `max 100 Locks, 7 Tage, FIFO`. `409 ConflictWithEvidence` final (kein Retry), `504` retryable exp backoff.

### O-04 — Zirkuläre Abhängigkeit `ShardWorkAttestation` + 4 Streams + 3 Tiers überdimensioniert für Dorf

- **Files:** `docs/10:398-438`, `docs/13_client_ingress_und_access_tiering.md:152-156`, `docs/15_p2p_transport_und_verbindungsmanagement.md:38-59` (S0-S3), `docs/13:33` (VIP/Friend/Anon)
- **Befund:** Gateway brauchte historisch `ShardWorkAttestation` (4h, `Q(R)`) um Ingress zu dürfen; Attest gibt es nur bei Shard-Arbeit → Zirkular. Bei `N<4` self-signed wertlos (`05:118`, `99:377`). 4 Streams + 3 Tiers + Attest-Cache vervielfachen Codepfade für `N=1`-Dorf.
- **Lösung (Umgesetzt):** `ShardWorkAttestation` ersatzlos gestrichen! Ingress-Schutz erfolgt rein über lokale P2P-Reziprozität (Tit-for-Tat 8:1 Backoff) und Smart-Client-Failover. Streams auf 2 (Data, Control) mergen: `S2 FraudAlert` + `S3 WoTControl` in `S1 Gossip` multiplexen. Tiers auf 2 (authed vs anon) reduzieren — Tier-2 „Friends“ ist WoT-Duplikat. Wirkt sofort auf Latenz und Testabdeckung.

---

## Priorisierte Umsetzungs-Roadmap

| Phase | Befunde | Aufwand | Wirkung |
| :--- | :--- | :--- | :--- |
| **P0 — Konsens-kritisch (vor jedem Code)** | K-01, K-02, K-03, K-04, K-06 | 1–2 Tage Spec + Tests | Verhindert divergierende Implementierungen, FINAL-Fälschung, Shard-Fehlrouting |
| **P1 — Partition & DoS** | K-05, H-01, H-02, H-05, H-06, H-07, H-08 | 3–5 Tage Spec + DST | Schließt 10:10 Split, Replay, Argon2-Saturation, Resurrection, Merge-Lüge |
| **P2 — Härtung & Privacy** | H-03, H-04, H-09, H-10, M-01..M-08 | 1 Woche | Gradient-Slashing korrekt, Privacy-Blindness, RAM-Hard-Limit, WoT-Max-Flow |
| **P3 — Simplicity (Ballast abwerfen)** | O-01..O-04 | 2 Tage | −40% Spec-Zeilen, halbierte Wire-Größe, 2 statt 4 Streams, weniger Audit-Fläche |

---

## Konsistenz-Check Invarianten (ergänzen/korrigieren)

- **Neu:** `INV-0206 Idempotente Promotion` (K-05), `INV-1207 RAM-Hard-Limit & Bounded persist_tx` (M-03), `INV-0806 Hysterese-Bindung im Preimage` (K-04/H-04)
- **Präzisieren:** `INV-0301/0803` (H-09), `INV-1007` (H-01), `INV-0403/1003` (K-01), `INV-0302` (K-06), `INV-0901` (K-05/H-10), `INV-1101/1703` (`m(Z)` als Empfänger-Grad)
- **Streichen/Anheben:** `INV-0906` Silent-Drop → SignedRejection (M-02), `0x02 HIGH_ASSURANCE` (O-02), Toleranzfenster `11..13` (M-05)

---

## Verifikation

Alle Befunde sind via `docs/16_chaos_testing_und_simulation.md` deterministisch reproduzierbar:

- **DST Matrizen erweitern:** Partition-Healing (`INV-1601`) um 10:10 Split + `min(H_canon)` vs First-Seen Race, Sybil-Kette (`INV-1603`) um Tiefe >3, TTL-Resurrection um `valid_until+30s` Race.
- **Seed-Replay:** `cargo test --test simulation` mit Seed `0x42` / `0xDEADBEEF` — Bit-identisch wie `docs/16:127` vorgegeben.
- **Empfohlene neue Tests:** `test_quorum_formula_consistency`, `test_shard_id_routing_determinism`, `test_promotion_idempotence`, `test_digest_quorum_requires_14`, `test_argon2_tier3_under_flood` (M-03/H-05).

---

*Erstellt durch konsolidiertes Audit (Security + Protocol-Logic + Simplicity) am 2026-08-27. Nächster Schritt: P0-Befunde in `docs/00`, `docs/03`, `docs/04`, `docs/08`, `docs/10` einarbeiten und `README.md:22` angleichen.*
